package hubcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// --- fixture language -------------------------------------------------------------------------------------

func obj(kv ...any) *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	for i := 0; i < len(kv); i += 2 {
		k := kv[i].(string)
		o.Keys = append(o.Keys, k)
		switch v := kv[i+1].(type) {
		case string:
			o.Members[k] = canon.String(v)
		case int:
			o.Members[k] = canon.Int(v)
		case bool:
			o.Members[k] = canon.Bool(v)
		case []string:
			a := canon.Array{}
			for _, s := range v {
				a = append(a, canon.String(s))
			}
			o.Members[k] = a
		case canon.Value:
			o.Members[k] = v
		default:
			panic(fmt.Sprintf("obj: %T", v))
		}
	}
	slices.SortFunc(o.Keys, canon.CompareKeys)
	return o
}

func dig(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

type signer struct {
	keys map[string]wire.Key
	head map[string]string
	seq  map[string]int64
}

func newSigner() *signer {
	return &signer{keys: map[string]wire.Key{}, head: map[string]string{}, seq: map[string]int64{}}
}

func (s *signer) key(n string) wire.Key {
	k, ok := s.keys[n]
	if !ok {
		h := sha256.Sum256([]byte("research-commons go test hubcheck key " + n))
		k = wire.Ed25519Key{Seed: h[:]}
		s.keys[n] = k
	}
	return k
}

// sign returns the statement's data-surface path, its bytes and its id.
func (s *signer) sign(n, kind string, body *canon.Object) (string, []byte, string) {
	k := s.key(n)
	q := s.seq[n]
	line, id := wire.Sign(wire.Draft{Kind: kind, Seq: q, Prev: s.head[n], TS: fmt.Sprintf("2026-10-16T05:%02d:%02dZ", q/60%60, q%60), Body: body}, k)
	s.head[n], s.seq[n] = id, q+1
	return gate.StatementPath(k.Signer(), id), line, id
}

func contentOf(b []byte) canon.Value { return obj("digest", dig(b), "size", len(b)) }

// hub is a throwaway git repository shaped like the hub template.
type hub struct {
	t   *testing.T
	dir string
}

const defaultPolicy = `{"blobs":"stored","limits":{},"not_served":[],"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":false}}`

func newHub(t *testing.T, policy string) *hub {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	h := &hub{t: t, dir: t.TempDir()}
	h.git("init", "-q", "-b", "main")
	h.write("rc-store", []byte(gate.LayoutMarker+"\n"))
	h.write("README.md", []byte("# hub\n"))
	if policy != "" {
		h.write(PolicyFile, []byte(policy))
	}
	h.commit("template")
	return h
}

// git runs git in the hub with no system or global configuration (these repositories are throwaway).
func (h *hub) git(args ...string) string {
	h.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", h.dir, "-c", "user.name=test", "-c", "user.email=test@example.invalid"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	out, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (h *hub) write(path string, b []byte) {
	h.t.Helper()
	p := filepath.Join(h.dir, filepath.FromSlash(path))
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *hub) rm(path string) { h.git("rm", "-q", "--", path) }

func (h *hub) commit(msg string) string {
	h.git("add", "-A")
	h.git("commit", "-q", "--allow-empty", "-m", msg)
	return h.git("rev-parse", "HEAD")
}

func (h *hub) branch(name string) { h.git("checkout", "-q", "-b", name) }

func (h *hub) check(base string, opts ...resolve.Option) *Result {
	h.t.Helper()
	res, err := Check(h.dir, Config{Base: base, Resolver: opts})
	if err != nil {
		h.t.Fatal(err)
	}
	return res
}

func verdict(t *testing.T, res *Result, path string) *gate.Result {
	t.Helper()
	r, ok := res.Report.Result(path)
	if !ok {
		t.Fatalf("no verdict for %s\n%s", path, res.Render())
	}
	return r
}

func refusedAs(t *testing.T, res *Result, path string, class refusal.Class, reason string) {
	t.Helper()
	r := verdict(t, res, path)
	if r.Verdict != gate.Refused || r.Refusal.Class != class || r.Refusal.Reason != reason {
		t.Fatalf("%s: want %s/%s, got %s %v\n%s", path, class, reason, r.Verdict, r.Refusal, res.Render())
	}
}

func didNotStart(t *testing.T, err error) *gate.DidNotStart {
	t.Helper()
	var d *gate.DidNotStart
	if !errors.As(err, &d) {
		t.Fatalf("want did-not-start, got %v", err)
	}
	if d.Committed() {
		t.Fatal("did-not-start reports committed")
	}
	return d
}

// --- tests ------------------------------------------------------------------------------------------------

// TestPolicyParser: the rc-hub-policy/1 file is read strictly. The template's example and default files
// parse; an unknown field, a duplicate key, a non-integer, a wrong tag, an undocumented limit name or a bad
// digest are each a did-not-start error, never a partial policy.
func TestPolicyParser(t *testing.T) {
	example := `{"blobs":"stored","limits":{"blob_bytes":104857600},"not_served":[{"digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","reason":"example"}],"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":true}}`
	p, err := gate.ParseHubPolicy([]byte(example), "rev")
	if err != nil {
		t.Fatal(err)
	}
	if p.Limits[gate.LimitBlobBytes] != 104857600 || p.Freeze == nil || len(p.NotServed) != 1 || p.ExternalOnly {
		t.Fatalf("%+v", p)
	}
	if _, err := gate.ParseHubPolicy([]byte(defaultPolicy), "rev"); err != nil {
		t.Fatal(err)
	}
	if p, err := gate.ParseHubPolicy(nil, "rev"); err != nil || !strings.Contains(p.Name, "absent") {
		t.Fatal(err)
	}
	for _, bad := range []string{
		``, `[]`, `{}`, `{"policy":"rc-hub-policy/2"}`,
		`{"policy":"rc-hub-policy/1","trusted_keys":[]}`,
		`{"policy":"rc-hub-policy/1","policy":"rc-hub-policy/1"}`,
		`{"policy":"rc-hub-policy/1","limits":{"blob_bytes":1.5}}`,
		`{"policy":"rc-hub-policy/1","limits":{"blob_bytes":-1}}`,
		`{"policy":"rc-hub-policy/1","limits":{"depth":3}}`,
		`{"policy":"rc-hub-policy/1","blobs":"some"}`,
		`{"policy":"rc-hub-policy/1","not_served":[{"digest":"sha256:AB"}]}`,
		`{"policy":"rc-hub-policy/1","not_served":[{"digest":"` + dig(nil) + `","by":"x"}]}`,
		`{"policy":"rc-hub-policy/1","not_served":[{"digest":"` + dig(nil) + `"},{"digest":"` + dig(nil) + `"}]}`,
		`{"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":"yes"}}`,
		`{"policy":"rc-hub-policy/1","series":{"other":true}}`,
	} {
		_, err := gate.ParseHubPolicy([]byte(bad), "rev")
		d := didNotStart(t, err)
		if d.Scope == "" || d.Next == "" {
			t.Fatalf("%s: %+v", bad, d)
		}
	}
}

// TestDidNotStart: H-10, H-11, H-12. No marker, an unknown marker, a base that is not a commit and an
// unparseable policy at the base each stop the check before any work, with a problem-details error. The
// policy is read from the base: a broken policy on HEAD alone is a control-plane change, not exit 2.
func TestDidNotStart(t *testing.T) {
	conformance.Partial(t, "C-core-133a", "hub check: an unusable policy file at the policy revision, a base that is not a commit, no hub root and an unknown layout are did-not-start errors (committed false) before any work; exit 2, the problem-details JSON and the other commands belong to the command layer")
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	didNotStart(t, func() error { _, err := Check(t.TempDir(), Config{}); return err }())
	h := newHub(t, defaultPolicy)
	_, err := Check(h.dir, Config{Base: "no-such-branch"})
	if d := didNotStart(t, err); d.Scope != "argument --base" {
		t.Fatal(d.Scope)
	}
	_, err = Check(h.dir, Config{Base: "--output=/tmp/x"})
	didNotStart(t, err)

	h.branch("pr")
	h.write(PolicyFile, []byte(`{"policy":"rc-hub-policy/1",`))
	h.commit("broken policy on the branch")
	res := h.check("main")
	if r := verdict(t, res, PolicyFile); r.Verdict != gate.NotApplied || res.Exit(false) != 0 {
		t.Fatalf("%s %v", r.Verdict, r.Refusal)
	}
	// on the base, the same bytes stop the check
	_, err = Check(h.dir, Config{Base: "pr"})
	if d := didNotStart(t, err); !strings.Contains(d.Scope, PolicyFile) {
		t.Fatal(d.Scope)
	}

	u := newHub(t, defaultPolicy)
	u.write("rc-store", []byte(`{"layout":"rc-store/9"}`))
	u.commit("unknown layout")
	_, err = Check(u.dir, Config{})
	didNotStart(t, err)
}

// TestBasePolicy: C-core-115. A pull request that loosens the hub policy (drops a not_served entry) and adds
// the blob only the loosened policy admits: the blob is refused under the base policy, and the policy edit is
// refused as a control-plane change made together with data and not applied (H-32). Split, the policy edit
// alone is reported for maintainer review (H-33), exit 0.
func TestBasePolicy(t *testing.T) {
	conformance.Covers(t, "C-core-115")
	banned := []byte("withheld bytes")
	h := newHub(t, `{"not_served":[{"digest":"`+dig(banned)+`","reason":"takedown"}],"policy":"rc-hub-policy/1"}`)
	h.branch("pr")
	h.write(PolicyFile, []byte(`{"policy":"rc-hub-policy/1"}`))
	h.write(gate.BlobPath(dig(banned)), banned)
	h.commit("loosen and add")
	res := h.check("main")
	refusedAs(t, res, gate.BlobPath(dig(banned)), refusal.Policy, gate.HubRules+": not_served")
	refusedAs(t, res, PolicyFile, refusal.Intrinsic, gate.OutsideSurface)
	if !strings.Contains(res.PolicyName, "at "+res.Base) || res.PolicyRev != res.Base || res.Exit(false) != 1 {
		t.Fatalf("policy from %s (%s), exit %d", res.PolicyRev, res.PolicyName, res.Exit(false))
	}
	if !strings.Contains(res.Render(), "policy hub-policy.json at "+res.Base) {
		t.Fatal(res.Render())
	}
	// control-plane only
	h.git("checkout", "-q", "main")
	h.branch("policy-only")
	h.write(PolicyFile, []byte(`{"policy":"rc-hub-policy/1"}`))
	h.write("docs/notes.md", []byte("x"))
	h.commit("policy only")
	res = h.check("main")
	for _, p := range []string{PolicyFile, "docs/notes.md"} {
		if r := verdict(t, res, p); r.Verdict != gate.NotApplied || !r.HasLabel(gate.LabelControlPlane) {
			t.Fatalf("%s: %s", p, r.Verdict)
		}
	}
	if res.Exit(false) != 0 {
		t.Fatal(res.Render())
	}
}

// TestHostileChange: C-core-114 at a hub gate. One valid observation plus edits to the workflow, the
// policy, a hook path and a stray file: the observation is admitted, every other path refused with its scope,
// and the policy the check applied is the base's (same digest before and after).
func TestHostileChange(t *testing.T) {
	h := newHub(t, defaultPolicy)
	s := newSigner()
	p, line, _ := s.sign("A", "observed", obj("content", contentOf([]byte("r")), "class", "none-yet", "referent", canon.Value(obj()),
		"capture", canon.Value(obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted"))))
	before := h.check("").PolicyDigest
	h.branch("pr")
	h.write(p, line)
	h.write(".github/workflows/hub-check.yml", []byte("on: push\n"))
	h.write(PolicyFile, []byte(`{"policy":"rc-hub-policy/1","blobs":"external-only"}`))
	h.write("hooks/pre-receive", []byte("#!/bin/sh\n"))
	h.commit("hostile")
	res := h.check("main")
	if r := verdict(t, res, p); r.Verdict != gate.Admitted {
		t.Fatal(r.Refusal)
	}
	for _, c := range []string{".github/workflows/hub-check.yml", PolicyFile, "hooks/pre-receive"} {
		refusedAs(t, res, c, refusal.Intrinsic, gate.OutsideSurface)
	}
	if res.PolicyDigest != before {
		t.Fatal("policy digest changed")
	}
}

// TestAppendOnly: H-30. Modifying, deleting or renaming a held statement or blob is refused (held object
// changed); deleting a blob listed in the base policy's not_served is the one deletion admitted.
func TestAppendOnly(t *testing.T) {
	keep, gone := []byte("keep"), []byte("gone")
	h := newHub(t, `{"not_served":[{"digest":"`+dig(gone)+`"}],"policy":"rc-hub-policy/1"}`)
	s := newSigner()
	p, line, _ := s.sign("A", "authored", obj("content", contentOf(keep), "type", "dataset"))
	h.write(p, line)
	h.write(gate.BlobPath(dig(keep)), keep)
	h.write(gate.BlobPath(dig(gone)), gone) // present before the takedown entry took effect
	h.commit("data")
	h.branch("pr")
	h.write(p, append(line, '\n'))
	h.rm(gate.BlobPath(dig(keep)))
	h.rm(gate.BlobPath(dig(gone)))
	h.commit("rewrite history")
	res := h.check("main")
	refusedAs(t, res, p, refusal.Intrinsic, gate.HeldObjectChanged)
	refusedAs(t, res, gate.BlobPath(dig(keep)), refusal.Intrinsic, gate.HeldObjectChanged)
	if r := verdict(t, res, gate.BlobPath(dig(gone))); r.Verdict != gate.Admitted || !r.HasLabel(gate.LabelTakedown) {
		t.Fatalf("%s %v", r.Verdict, r.Labels)
	}
	// a rename is a deletion and an addition
	h.git("checkout", "-q", "main")
	h.branch("rename")
	h.git("mv", gate.BlobPath(dig(keep)), "blobs/sha256/"+strings.Repeat("0", 64))
	h.commit("rename")
	res = h.check("main")
	refusedAs(t, res, gate.BlobPath(dig(keep)), refusal.Intrinsic, gate.HeldObjectChanged)
	refusedAs(t, res, "blobs/sha256/"+strings.Repeat("0", 64), refusal.Intrinsic, gate.HashMismatch)
}

// TestNotServed: C-core-140. The hub drops retracted bytes under its own policy (two merges: the not_served
// entry, then the deletion). The retraction and the authored statement stay; the full check shows the content
// as not held here (policy); nothing claims the artifact is erased.
func TestNotServed(t *testing.T) {
	conformance.Covers(t, "C-core-140")
	bad := []byte("retracted bytes")
	h := newHub(t, defaultPolicy)
	s := newSigner()
	ap, aline, aid := s.sign("A", "authored", obj("content", contentOf(bad), "type", "dataset"))
	rp, rline, _ := s.sign("A", "retracts", obj("of", aid, "reason", "wrong units"))
	h.write(ap, aline)
	h.write(rp, rline)
	h.write(gate.BlobPath(dig(bad)), bad)
	h.commit("publish and retract")
	// merge 1: the policy entry (a control-plane change, merged by the maintainers)
	h.write(PolicyFile, []byte(`{"not_served":[{"digest":"`+dig(bad)+`","reason":"retracted by its author"}],"policy":"rc-hub-policy/1"}`))
	h.commit("not_served entry")
	full := h.check("")
	if r := verdict(t, full, gate.BlobPath(dig(bad))); r.Verdict != gate.Admitted || !r.HasLabel(gate.LabelStillServed) || full.Exit(false) != 0 {
		t.Fatalf("still present: %s %v", r.Verdict, r.Labels)
	}
	// merge 2: the deletion
	h.branch("takedown")
	h.rm(gate.BlobPath(dig(bad)))
	h.commit("remove bytes")
	res := h.check("main")
	if r := verdict(t, res, gate.BlobPath(dig(bad))); r.Verdict != gate.Admitted || !r.HasLabel(gate.LabelTakedown) || res.Exit(false) != 0 {
		t.Fatalf("%s %v", r.Verdict, r.Refusal)
	}
	h.git("checkout", "-q", "main")
	h.git("merge", "-q", "--ff-only", "takedown")
	after := h.check("")
	a := verdict(t, after, ap)
	if a.Verdict != gate.Admitted || !a.HasLabel(gate.LabelNotHeldHere) || a.HasLabel(gate.LabelUnavailable) {
		t.Fatalf("%s %v", a.Verdict, a.Labels)
	}
	if r := verdict(t, after, rp); r.Verdict != gate.Admitted {
		t.Fatal("the retraction is gone")
	}
	if strings.Contains(strings.ToLower(after.Render()), "erased") {
		t.Fatal("a surface claims erasure")
	}
	// re-adding the bytes is refused under the policy
	h.branch("readd")
	h.write(gate.BlobPath(dig(bad)), bad)
	h.commit("re-add")
	refusedAs(t, h.check("main"), gate.BlobPath(dig(bad)), refusal.Policy, gate.HubRules+": not_served")
}

// TestExternalOnly: H-27. A hub with blobs external-only refuses an added blob under reader policy and
// admits the statements (with holds naming external locations) of the same change.
func TestExternalOnly(t *testing.T) {
	h := newHub(t, `{"blobs":"external-only","policy":"rc-hub-policy/1"}`)
	s := newSigner()
	b := []byte("bytes elsewhere")
	hp, hline, _ := s.sign("A", "holds", obj("content", contentOf(b), "locations", []string{"https://bucket.example/x"}))
	h.branch("pr")
	h.write(hp, hline)
	h.write(gate.BlobPath(dig(b)), b)
	h.commit("holds + blob")
	res := h.check("main")
	refusedAs(t, res, gate.BlobPath(dig(b)), refusal.Policy, gate.HubRules+": blobs")
	if r := verdict(t, res, hp); r.Verdict != gate.Admitted || !r.HasLabel(gate.LabelUnavailable) {
		t.Fatalf("%s %v", r.Verdict, r.Labels)
	}
}

// fakeSegments is the reader's segment re-check by member key.
type fakeSegments map[string]resolve.SegmentState

func (f fakeSegments) Segment(m *resolve.Member) resolve.SegmentState {
	if s, ok := f[m.Key]; ok {
		return s
	}
	return resolve.RecordSegments{}.Segment(m)
}

func day(d string) resolve.Boundary { return resolve.Boundary{Unit: "date", Date: d} }

func editionBody(resource string, preds []string, kv ...any) *canon.Object {
	p := slices.Clone(preds)
	slices.Sort(p)
	return obj("resource", resource, "predecessors", p, "contents", obj(kv...))
}

// TestPrematureFreeze: C-core-104 with H-34/H-35. With series.refuse_premature_freeze in the base policy,
// a pushed series edition declaring frozen_before later than the members' computed boundary is refused
// under reader policy, scope that edition; the edition remains a valid statement (the resolver keeps it
// authorized). A boundary the reader cannot compute is could-not-check (exit 3), never a pass. Control: an
// edition the members support is admitted, and without the knob the premature one is admitted.
func TestPrematureFreeze(t *testing.T) {
	conformance.Covers(t, "C-core-104")
	conformance.Partial(t, "C-core-98", "hub check re-applies the named edition as held at the base revision and the current edition, side by side as the hub's computation, the publisher's ok as its word, membership not endorsed; the JSON form of the side-by-side belongs to the command layer")
	knob := `{"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":true}}`
	h := newHub(t, knob)
	s := newSigner()
	gp, gline, g := s.sign("C", "genesis", obj("type", "series", "name", "settlements", "controllers", []string{s.key("C").Signer()}, "rule", obj("any_one", true)))
	h.write(gp, gline)
	segs := canon.Array{}
	f := fakeSegments{}
	for i, m := range []string{"01", "02", "03", "04", "05"} {
		p, line, id := s.sign("O", "observed", obj("content", contentOf([]byte("s"+m)), "class", "none-yet", "referent", canon.Value(obj()),
			"capture", canon.Value(obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted"))))
		h.write(p, line)
		segs = append(segs, obj("statement", id, "role", "segment"))
		final := "final"
		if i >= 3 {
			final = "provisional"
		}
		f[id] = resolve.SegmentState{From: day("2025-" + m + "-01"), Rule: true, Final: final}
	}
	h.commit("series and segments")
	h.branch("premature")
	ep, eline, _ := s.sign("C", "edition", editionBody(g, []string{g}, "members", segs, "frozen_before", obj("date", "2025-06-01")))
	h.write(ep, eline)
	h.commit("premature freeze")
	res := h.check("main", resolve.WithSegments(f))
	refusedAs(t, res, ep, refusal.Policy, gate.HubRules+": series.refuse_premature_freeze")
	r := verdict(t, res, ep)
	if r.Series == nil || r.Series.Comparison != "flagged" || !strings.Contains(r.Refusal.Detail, "scope series edition") || res.Exit(false) != 1 {
		t.Fatalf("%v", r.Refusal)
	}
	// without the reader's re-check, the boundary is unchecked: could not check, exit 3
	res = h.check("main")
	if r := verdict(t, res, ep); r.Verdict != gate.Undecided || res.Exit(false) != 3 {
		t.Fatalf("%s %v\n%s", r.Verdict, r.Refusal, res.Render())
	}
	// control: a supported declaration is admitted
	h.git("checkout", "-q", "main")
	h.branch("supported")
	s2 := *s
	s2.head, s2.seq = maps(s.head), maps64(s.seq)
	s2.head["C"], s2.seq["C"] = g, 1
	sp, sline, _ := s2.sign("C", "edition", editionBody(g, []string{g}, "members", segs, "frozen_before", obj("date", "2025-04-01")))
	h.write(sp, sline)
	h.commit("supported freeze")
	if r := verdict(t, h.check("main", resolve.WithSegments(f)), sp); r.Verdict != gate.Admitted {
		t.Fatalf("%s %v", r.Verdict, r.Refusal)
	}
	// without the knob, the premature edition is admitted
	n := newHub(t, defaultPolicy)
	n.write(gp, gline)
	n.branch("pr")
	n.write(ep, eline)
	n.commit("x")
	if r := verdict(t, n.check("main", resolve.WithSegments(f)), ep); r.Verdict != gate.Admitted {
		t.Fatalf("%s %v", r.Verdict, r.Refusal)
	}
}

func maps(m map[string]string) map[string]string {
	o := map[string]string{}
	for k, v := range m {
		o[k] = v
	}
	return o
}

func maps64(m map[string]int64) map[string]int64 {
	o := map[string]int64{}
	for k, v := range m {
		o[k] = v
	}
	return o
}

// forbid is a one-keyword rule dialect: `FORBID <key>` fails when the candidate's content holds the key.
type forbidDialect struct{}

func (forbidDialect) Name() string { return "rc-test/1" }
func (forbidDialect) Compile(expr string) (resolve.Rule, error) {
	f := strings.Fields(expr)
	if len(f) != 2 || f[0] != "FORBID" {
		return nil, fmt.Errorf("keyword %q", expr)
	}
	return forbid(f[1]), nil
}

type forbid string

func (k forbid) Eval(d *resolve.Domain) (resolve.Outcome, string, []string) {
	units, ok := d.Content("")
	if !ok {
		return resolve.RuleUnchecked, "content not held", nil
	}
	for _, u := range units {
		if strings.Contains(string(u.Data), `"`+string(k)+`"`) {
			return resolve.RuleFail, "forbidden key " + string(k), nil
		}
	}
	return resolve.RuleOK, "", nil
}

// TestForgedIntendedForAtHub: C-core-98 at the hub gate. A statement recording intended_for {R, E2} outcome
// ok over content E2's rules fail is pushed to a hub whose R is at E3. The hub re-applies E2 as held at the
// base revision and E3, both from the base tree's content, shows fail beside fail as its own computation and
// the publisher's ok as its word; the statement is admitted (the field confers nothing) and not endorsed.
func TestForgedIntendedForAtHub(t *testing.T) {
	h := newHub(t, defaultPolicy)
	s := newSigner()
	rule := func(exprs ...string) canon.Array {
		a := canon.Array{}
		for _, e := range exprs {
			a = append(a, obj("dialect", "rc-test/1", "expr", e))
		}
		return a
	}
	gp, gl, g := s.sign("C", "genesis", obj("type", "collection", "name", "r", "controllers", []string{s.key("C").Signer()}, "rule", obj("any_one", true)))
	e2b := editionBody(g, []string{g}, "rules", rule("FORBID secret"))
	e2p, e2l, _ := s.sign("C", "edition", e2b)
	e2 := resolve.EditionID(e2b)
	e3b := editionBody(g, []string{e2}, "rules", rule("FORBID secret", "FORBID password"))
	e3p, e3l, _ := s.sign("C", "edition", e3b)
	e3 := resolve.EditionID(e3b)
	bad := []byte(`{"secret":"***"}`)
	for p, l := range map[string][]byte{gp: gl, e2p: e2l, e3p: e3l, gate.BlobPath(dig(bad)): bad} {
		h.write(p, l)
	}
	h.commit("collection at E3, blob held")
	h.branch("pr")
	fp, fl, _ := s.sign("M", "authored", obj("content", contentOf(bad), "type", "dataset",
		"intended_for", obj("resource", g, "edition", e2, "edition_applied", e2, "outcome", "ok")))
	h.write(fp, fl)
	h.commit("forged")
	res := h.check("main", resolve.WithDialect(forbidDialect{}))
	r := verdict(t, res, fp)
	if r.Verdict != gate.Admitted || r.IntendedFor == nil {
		t.Fatalf("%s %v", r.Verdict, r.Refusal)
	}
	rec := r.IntendedFor
	if rec.Named != resolve.RuleFail || rec.NamedEdition != e2 || rec.Current != resolve.RuleFail || rec.CurrentEdition != e3 || rec.PublisherSaid != "ok" || rec.Endorsed {
		t.Fatalf("%s", rec.Render())
	}
	out := res.Render()
	if !strings.Contains(out, "this receiver's computation") || !strings.Contains(out, "publisher says ok") {
		t.Fatal(out)
	}
}

// TestFullCheck: without --base, every held object is checked and every non-data path outside the control
// plane is refused; the control plane is listed, not checked.
func TestFullCheck(t *testing.T) {
	h := newHub(t, defaultPolicy)
	s := newSigner()
	p, line, _ := s.sign("A", "authored", obj("content", contentOf([]byte("x")), "type", "dataset"))
	h.write(p, line)
	h.write("stray.txt", []byte("x"))
	h.commit("tree")
	res := h.check("")
	if res.Base != "" || res.PolicyRev != res.Head {
		t.Fatal(res.PolicyRev)
	}
	if r := verdict(t, res, p); r.Verdict != gate.Admitted {
		t.Fatal(r.Refusal)
	}
	refusedAs(t, res, "stray.txt", refusal.Intrinsic, gate.OutsideSurface)
	if r := verdict(t, res, "README.md"); r.Verdict != gate.NotApplied {
		t.Fatal(r.Verdict)
	}
	if !strings.Contains(res.Render(), SideEffects) {
		t.Fatal("no side-effects line")
	}
}

// TestRawGitRead: H-03. A .gitattributes in the checked tree that would transcode line endings, and a
// filter the caller's configuration defines, change nothing: objects are read raw, so a CRLF blob keeps its
// bytes and hashes to its name.
func TestRawGitRead(t *testing.T) {
	h := newHub(t, defaultPolicy)
	b := []byte("a\r\nb\r\n")
	h.git("config", "filter.evil.smudge", "tr a X")
	h.git("config", "filter.evil.clean", "cat")
	h.branch("pr")
	h.write(".gitattributes", []byte("* text=auto eol=lf filter=evil\n"))
	h.commit("attributes on their own")
	h.git("checkout", "-q", "main")
	h.git("merge", "-q", "--ff-only", "pr")
	h.branch("data")
	// store the exact bytes (hash-object --no-filters), so the object holds CRLF whatever the attributes say
	tmp := filepath.Join(t.TempDir(), "crlf")
	os.WriteFile(tmp, b, 0o644)
	oid := h.git("hash-object", "-w", "--no-filters", tmp)
	h.git("update-index", "--add", "--cacheinfo", "100644,"+oid+","+gate.BlobPath(dig(b)))
	h.git("commit", "-q", "-m", "crlf blob")
	// the boundary: a reader of the working tree would see filtered bytes and refuse a hash mismatch
	h.git("checkout", "-q", "--", gate.BlobPath(dig(b)))
	if wt, _ := os.ReadFile(filepath.Join(h.dir, filepath.FromSlash(gate.BlobPath(dig(b))))); string(wt) == string(b) {
		t.Fatalf("the smudge filter did not reach the working tree (%q): the test proves nothing", wt)
	}
	res := h.check("main")
	if r := verdict(t, res, gate.BlobPath(dig(b))); r.Verdict != gate.Admitted {
		t.Fatalf("%s %v", r.Verdict, r.Refusal)
	}
}
