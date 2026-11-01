package gate

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/fixture"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

var gates = []string{"pull", "hub check", "push", "pre-pin"}

// forbidDialect is a one-keyword rule dialect for these tests: `FORBID <key>` fails when the candidate's
// content contains the JSON key, and is unchecked when the content is not held.
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
		if bytes.Contains(u.Data, []byte(`"`+string(k)+`"`)) {
			return resolve.RuleFail, "forbidden key " + string(k), nil
		}
	}
	return resolve.RuleOK, "", nil
}

type contentTable map[string][]byte

func (c contentTable) Units(d string) ([]resolve.ContentUnit, bool) {
	b, ok := c[d]
	if !ok {
		return nil, false
	}
	return []resolve.ContentUnit{{Name: d, Data: b}}, true
}

func edition(w *world, by, resource string, preds []string, kv ...any) string {
	p := slices.Clone(preds)
	slices.Sort(p)
	return w.sign(by, "edition", obj("resource", resource, "predecessors", p, "contents", obj(kv...)))
}

func edID(w *world, id string) string {
	st, _ := wire.Read(w.lines[id])
	return resolve.EditionID(st.Body)
}

// crossGateFixture is the hub template's H-20..H-36 situations as one package over one held history.
type crossGateFixture struct {
	w       *world
	pkg     Package
	held    MemHeld
	pol     *Policy
	forged  string // a statement whose intended_for edition's rules fail
	content contentTable
}

func newCrossGateFixture(t *testing.T) crossGateFixture {
	w := newWorld(t)
	f := crossGateFixture{w: w, content: contentTable{}}
	g := w.sign("C", "genesis", obj("type", "collection", "name", "readings", "controllers", []string{w.signer("C")}, "rule", obj("any_one", true)))
	e1 := edition(w, "C", g, []string{g}, "rules", canon.Array{obj("dialect", "rc-test/1", "expr", "FORBID secret")})
	first := w.authored("A", []byte("first"))
	f.held = w.held(g, e1, first)
	f.held.Blobs[blobDigest([]byte("first"))] = true

	valid := w.authored("A", []byte("valid"))
	badBlob := []byte(`{"secret":"x"}`)
	f.content[blobDigest(badBlob)] = badBlob
	f.forged = w.authored("M", badBlob, "intended_for", obj("resource", g, "edition", edID(w, e1), "edition_applied", edID(w, e1), "outcome", "ok"))
	okBlob := []byte(`{"reading":1}`)
	f.content[blobDigest(okBlob)] = okBlob
	compliant := w.authored("N", okBlob, "intended_for", obj("resource", g, "edition", edID(w, e1), "edition_applied", edID(w, e1), "outcome", "ok"))
	k := w.key("A")
	sibLine, sib := wire.Sign(wire.Draft{Kind: "authored", Seq: 1, Prev: first, TS: "2026-10-16T04:00:00Z", Body: obj("content", canon.Value(contentOf([]byte("sib"))), "type", "dataset")}, k)
	w.lines[sib], w.by[sib] = sibLine, "A"
	detLine, det := wire.Sign(wire.Draft{Kind: "authored", Seq: 7, Prev: strings.Repeat("e", 64), TS: "2026-10-16T04:00:00Z", Body: obj("content", canon.Value(contentOf([]byte("det"))), "type", "dataset")}, w.key("D"))
	w.lines[det], w.by[det] = detLine, "D"
	unsLine, uns := wire.Sign(wire.Draft{RC: "rc/9", Kind: "authored", Seq: 0, TS: "2026-10-16T04:00:00Z", Body: obj("x", "y")}, w.key("U"))
	w.lines[uns], w.by[uns] = unsLine, "U"
	other := w.authored("B", []byte("b"))
	sigBad := append([]byte{}, w.lines[w.authored("E", []byte("e"))]...)
	sigBad[bytes.LastIndex(sigBad, []byte(`"sig":"`))+9] ^= 1
	sigSt, _ := wire.Read(w.lines[w.head["E"]])
	big := w.authored("F", []byte("big"), "description", strings.Repeat("d", 4000))

	f.pol = DefaultPolicy()
	f.pol.Limits[LimitStatementBytes] = 3000
	f.pol.Resolver = []resolve.Option{resolve.WithDialect(forbidDialect{}), resolve.WithContent(f.content)}

	f.pkg = Package{Objects: []Object{
		w.object(valid), w.object(f.forged), w.object(compliant), w.object(sib), w.object(det), w.object(uns), w.object(big),
		{Path: StatementPath(w.signer("A"), other), Data: w.lines[other]},                                 // H-21
		{Path: StatementPath(sigSt.Signer, sigSt.ID), Data: sigBad},                                       // H-20 bad sig
		{Path: StatementPath(w.signer("A"), strings.Repeat("a", 64)), Data: w.lines[valid]},               // H-20 id != name
		{Path: StatementPath(w.signer("A"), strings.Repeat("b", 64)), Data: append(w.lines[valid], '\n')}, // H-20 not canonical
		{Path: BlobPath(blobDigest([]byte("valid"))), Data: []byte("valid")},                              // admitted, referenced
		{Path: BlobPath(blobDigest([]byte("orphan"))), Data: []byte("orphan")},                            // H-28
		{Path: BlobPath(blobDigest([]byte("one"))), Data: []byte("two")},                                  // H-26
		{Path: "statements/../../etc/passwd", Data: []byte("x")},                                          // H-31
		{Path: "blobs/sha256/" + strings.ToUpper(strings.Repeat("a", 64)), Data: []byte("x")},             // H-31 upper-case hex
		{Path: "statements/" + strings.ReplaceAll(w.signer("A"), ":", "-") + "/x/y", Data: []byte("x")},   // H-31 wrong depth
	}}
	return f
}

// TestOneValidationCore: C-core-109. One fixture set with a known mix of valid and invalid objects, run
// through pull, hub check, push and the pre-pin check with the same history and policy, gives identical
// per-object verdicts, classes, reasons and labels; the only difference is the pre-pin check's own policy
// on intended_for (it refuses where the named edition's rules fail), which differs by construction.
func TestOneValidationCore(t *testing.T) {
	conformance.Covers(t, "C-core-109")
	f := newCrossGateFixture(t)
	reps := map[string]*Report{}
	for _, g := range gates {
		reps[g] = mustAdmit(t, g, f.pkg, f.held, f.pol, Options{})
	}
	forgedPath := f.w.path(f.forged)
	base := reps["pull"]
	kinds := map[string]bool{}
	for _, r := range base.Results {
		kinds[signature(r)] = true
		for _, g := range gates[1:] {
			o := get(t, reps[g], r.Path)
			if r.Path == forgedPath && g == "pre-pin" {
				if o.Verdict != Refused || o.Refusal.Class != refusal.Policy || o.Refusal.Reason != resolve.RuleFailed {
					t.Fatalf("pre-pin on the forged statement: %s %v", o.Verdict, o.Refusal)
				}
				continue
			}
			if signature(r) != signature(*o) {
				t.Fatalf("%s: pull %q, %s %q", r.Path, signature(r), g, signature(*o))
			}
		}
	}
	// the fixture really is a mix: every situation reached the boundary it names
	want := map[string]string{
		f.w.path(f.forged):     "admitted|intended_for,unavailable",
		f.pkg.Objects[3].Path:  "admitted|FORK,unavailable",
		f.pkg.Objects[4].Path:  "admitted|detached,unavailable",
		f.pkg.Objects[5].Path:  "admitted|unsupported",
		f.pkg.Objects[6].Path:  "refused|operational|size limit|",
		f.pkg.Objects[7].Path:  "refused|intrinsic|line in another key's log|",
		f.pkg.Objects[8].Path:  "refused|intrinsic|bad signature|",
		f.pkg.Objects[9].Path:  "refused|intrinsic|hash mismatch|",
		f.pkg.Objects[10].Path: "refused|intrinsic|not canonical|",
		f.pkg.Objects[11].Path: "admitted|",
		f.pkg.Objects[12].Path: "admitted|unreferenced",
		f.pkg.Objects[13].Path: "refused|intrinsic|hash mismatch|",
		f.pkg.Objects[14].Path: "refused|intrinsic|unsafe path|",
		f.pkg.Objects[15].Path: "refused|intrinsic|outside the data surface|",
		f.pkg.Objects[16].Path: "refused|intrinsic|outside the data surface|",
	}
	for p, s := range want {
		if got := signature(*get(t, base, p)); got != s {
			t.Fatalf("%s: %q, want %q\n%s", p, got, s, base.Render())
		}
	}
	rec := get(t, base, forgedPath).IntendedFor
	if rec == nil || rec.Named != resolve.RuleFail || rec.PublisherSaid != "ok" {
		t.Fatalf("intended_for not re-applied: %+v", rec)
	}
	if r := get(t, reps["pre-pin"], f.pkg.Objects[2].Path); r.Verdict != Admitted {
		t.Fatalf("pre-pin refused a compliant statement: %v", r.Refusal)
	}
}

// concretize turns an abstract fixture into signed lines by key name, with each key's chain in seq order.
func concretize(f fixture.Fixture, keys map[string]wire.Key) (ids []string, lines map[string][]byte, by map[string]string) {
	lines, by = map[string][]byte{}, map[string]string{}
	prev := map[string]string{}
	for _, s := range f.Statements {
		k := keys[s.Signer]
		var b *canon.Object
		c := obj("digest", blobDigest([]byte(s.Blob)), "size", len(s.Blob))
		switch s.Kind {
		case "authored":
			b = obj("content", canon.Value(c), "type", "dataset")
		case "observed":
			b = obj("content", canon.Value(c), "class", "none-yet", "referent", canon.Value(obj()),
				"capture", canon.Value(obj("at", "2026-10-15T00:00:00Z", "evidence", "self-asserted")))
		case "holds":
			b = obj("content", canon.Value(c))
		case "describes":
			b = obj("about", canon.Value(obj("content", blobDigest([]byte(s.Blob)))))
		}
		line, id := wire.Sign(wire.Draft{Kind: s.Kind, Seq: int64(s.Seq), Prev: prev[s.Signer],
			TS: time.Unix(1_790_000_000+int64(s.Time), 0).UTC().Format("2006-01-02T15:04:05Z"), Body: b}, k)
		prev[s.Signer] = id
		ids = append(ids, id)
		lines[id], by[id] = line, s.Signer
	}
	return
}

// TestPropertyNoThirdPartyVeto: P-04. For each gate and each generated state: the verdict on every object of
// key A is the same with and without the statements of the keys that have no authority over it, whether
// those statements come in the same package, are already held, or are hostile copies filed under A's
// directory.
func TestPropertyNoThirdPartyVeto(t *testing.T) {
	conformance.Covers(t, "P-04")
	keys := map[string]wire.Key{"A": testKey("A"), "B": testKey("B"), "C": testKey("C")}
	opts := fixture.Default
	fixture.Check(t, 900, 60, opts, func(f fixture.Fixture) string {
		ids, lines, by := concretize(f, keys)
		var mine, others []Object
		othersHeld := map[string][]byte{}
		for _, id := range ids {
			o := Object{Path: StatementPath(keys[by[id]].Signer(), id), Data: lines[id]}
			if by[id] == "A" {
				mine = append(mine, o)
				continue
			}
			others = append(others, o)
			othersHeld[id] = lines[id]
			// a hostile copy under A's directory
			others = append(others, Object{Path: StatementPath(keys["A"].Signer(), id), Data: lines[id]})
		}
		if len(mine) == 0 {
			return ""
		}
		for _, g := range gates {
			alone, err := admitFn(g)(Package{Objects: mine}, MemHeld{}, nil, Options{})
			if err != nil {
				return err.Error()
			}
			mixed, _ := admitFn(g)(Package{Objects: append(slices.Clone(mine), others...)}, MemHeld{}, nil, Options{})
			heldL, _ := admitFn(g)(Package{Objects: mine}, heldOf(othersHeld), nil, Options{})
			for _, o := range mine {
				a, _ := alone.Result(o.Path)
				m, _ := mixed.Result(o.Path)
				h, _ := heldL.Result(o.Path)
				if signature(*a) != signature(*m) || signature(*a) != signature(*h) {
					return fmt.Sprintf("%s: %s alone %q, with others in the package %q, with others held %q", g, o.Path, signature(*a), signature(*m), signature(*h))
				}
			}
			for _, o := range others {
				if strings.HasPrefix(o.Path, "statements/"+strings.ReplaceAll(keys["A"].Signer(), ":", "-")+"/") {
					if r, _ := mixed.Result(o.Path); r.Verdict != Refused {
						return "hostile copy under A's directory admitted: " + o.Path
					}
				}
			}
		}
		return ""
	})
}

func admitFn(g string) func(Package, Held, *Policy, Options) (*Report, error) {
	switch g {
	case "pull":
		return Pull
	case "push":
		return Push
	case "hub check":
		return HubCheck
	}
	return PrePin
}

// controlPaths are the shapes of control-plane material an incoming tree may try to carry.
var controlPaths = []string{
	"hub-policy.json", ".git/hooks/pre-commit", ".git/config", ".github/workflows/hub-check.yml", "hooks/post-merge",
	"config/commons.toml", ".commons/policy.json", "trust/keys.json", "trusted_keys", "exec-policy.json",
	"registry/peers.json", "lib/commons.py", "bin/commons", ".gitattributes", "rc-store/../hub-policy.json",
	"/etc/commons/policy.json", "statements/../hub-policy.json",
}

// TestPropertyDataNeverCarriesControl: P-05. For any generated incoming tree touching policy files, hooks,
// configuration or trust lists (mixed with valid data): pull leaves the reader's policy byte-identical and
// field-identical, and refuses every control-plane path, naming its scope. The data in the tree gets the
// verdict it gets alone.
func TestPropertyDataNeverCarriesControl(t *testing.T) {
	conformance.Covers(t, "P-05")
	keys := map[string]wire.Key{"A": testKey("A"), "B": testKey("B"), "C": testKey("C")}
	polBytes := []byte(`{"limits":{"blob_bytes":4096},"not_served":[],"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":true}}`)
	fixture.Check(t, 1300, 80, fixture.Default, func(f fixture.Fixture) string {
		pol, err := ParseHubPolicy(polBytes, "reader")
		if err != nil {
			return err.Error()
		}
		pol.ControlPlane = nil
		before := policySnapshot(pol)
		file := slices.Clone(polBytes)
		ids, lines, by := concretize(f, keys)
		var data []Object
		for _, id := range ids {
			data = append(data, Object{Path: StatementPath(keys[by[id]].Signer(), id), Data: lines[id]})
		}
		r := rand.New(rand.NewPCG(f.Seed, 7))
		var control []Object
		for i, n := 0, 1+r.IntN(5); i < n; i++ {
			p := controlPaths[r.IntN(len(controlPaths))]
			if slices.ContainsFunc(control, func(o Object) bool { return o.Path == p }) {
				continue
			}
			payload := []byte(`{"policy":"rc-hub-policy/1","blobs":"external-only","trusted":["` + keys["B"].Signer() + `"]}`)
			mode := Regular
			if r.IntN(4) == 0 {
				mode = Symlink
			}
			control = append(control, Object{Path: p, Data: payload, Mode: mode})
		}
		tree := Package{Objects: append(slices.Clone(data), control...)}
		rep, err := Pull(tree, MemHeld{}, pol, Options{})
		if err != nil {
			return err.Error()
		}
		alone, _ := Pull(Package{Objects: data}, MemHeld{}, pol, Options{})
		if policySnapshot(pol) != before || !bytes.Equal(file, polBytes) {
			return "policy changed"
		}
		for _, c := range control {
			x, _ := rep.Result(c.Path)
			if x.Verdict != Refused || x.Refusal.Class != refusal.Intrinsic || x.Scope != "object "+c.Path || !strings.Contains(x.Refusal.Detail, "scope") {
				return fmt.Sprintf("control path %s: %s %v", c.Path, x.Verdict, x.Refusal)
			}
		}
		for _, d := range data {
			a, _ := alone.Result(d.Path)
			m, _ := rep.Result(d.Path)
			if signature(*a) != signature(*m) {
				return fmt.Sprintf("%s: alone %q, in the hostile tree %q", d.Path, signature(*a), signature(*m))
			}
		}
		return ""
	})
}
