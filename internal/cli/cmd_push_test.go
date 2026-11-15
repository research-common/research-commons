package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/wire"
)

// push --dry-run tests. Every hub is a local bare repository (the remote is a path; nothing is dialled) and every
// calendar a loopback httptest server (cmd_anchor_stamp_test.go). The author's store is a clone of the hub, as the
// hub template's contribute flow has it.

// pushWorld is an author's key and a hub checkout that is the author's store, with a bare hub as origin.
type pushWorld struct {
	*pubWorld
	remote string
}

func newPushWorld(t *testing.T) *pushWorld {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	p := newPubWorld(t)
	os.WriteFile(filepath.Join(p.root, ".gitignore"), []byte("/journal/\n/quarantine/\n/tmp/\n/cache/\n"), 0o644)
	gitIn(t, p.root, "init", "-q", "-b", "main")
	gitIn(t, p.root, "add", "-A")
	gitIn(t, p.root, "commit", "-q", "-m", "template")
	remote := filepath.Join(t.TempDir(), "hub.git")
	gitIn(t, p.root, "init", "-q", "--bare", "-b", "main", remote)
	gitIn(t, p.root, "remote", "add", "origin", remote)
	gitIn(t, p.root, "push", "-q", "origin", "main")
	gitIn(t, p.root, "fetch", "-q", "origin")
	gitIn(t, p.root, "remote", "set-head", "origin", "main")
	gitIn(t, p.root, "checkout", "-q", "-b", "change")
	return &pushWorld{pubWorld: p, remote: remote}
}

// commitAll commits every change of the checkout.
func (p *pushWorld) commitAll(msg string) {
	p.t.Helper()
	gitIn(p.t, p.root, "add", "-A")
	gitIn(p.t, p.root, "commit", "-q", "--allow-empty", "-m", msg)
}

func (p *pushWorld) push(args ...string) result {
	return runIn(p.root, nil, append([]string{"push", "--dry-run", "--json"}, args...)...)
}

func (p *pushWorld) mustPublish(args ...string) string {
	p.t.Helper()
	r := p.publish(args...)
	if r.code != 0 {
		p.t.Fatalf("publish %v: %d %s", args, r.code, r.stdout)
	}
	return idsOf(outObj(p.t.(*testing.T), r))[0]
}

// anchorRow is the anchor_gate row for a statement id.
func anchorRow(t *testing.T, rep *canon.Object, id string) *canon.Object {
	t.Helper()
	for _, x := range rep.Members["anchor_gate"].(canon.Array) {
		o := x.(*canon.Object)
		if o.Members["id"] == canon.String(id) {
			return o
		}
	}
	t.Fatalf("no anchor_gate row for %s: %s", id, canon.Encode(rep.Members["anchor_gate"]))
	return nil
}

func warnings(rep *canon.Object) string {
	if w, ok := rep.Members["warnings"]; ok {
		return string(canon.Encode(w))
	}
	return ""
}

// remoteState is every ref and object of the bare hub: "the remote is unchanged" (C-core-137).
func (p *pushWorld) remoteState() string {
	return gitIn(p.t, p.remote, "for-each-ref") + "\n" + gitIn(p.t, p.remote, "count-objects", "-v") + "\n" + snapshot(p.t, p.remote)
}

// TestPushAnchorGate: C-btc-03c's precondition half through the command (no transport is built). (a) an authored
// without provenance and no anchor is refused, reader policy `anchor required`, scope the statement; (b) after
// `anchor stamp` (a pending proof) and a commit it is covered and the push is clean; (c) an authored with
// provenance, unanchored, is carried with a warning naming the rule; (d) (a) under --anchor-policy none is carried
// with a warning naming the override; (e) (c) under --anchor-policy required is refused; (f) a required statement
// appended after the anchored head is refused while the earlier one stays covered (coverage is per statement); (g)
// a statement on an incoherent line (ts earlier than its predecessor's) covered by an anchor is carried: coverage
// is structural, not a time bound.
func TestPushAnchorGate(t *testing.T) {
	conformance.Partial(t, "C-btc-03c", "the precondition through push --dry-run: uncovered required statements refused (reader policy, anchor required, scope the statement), a pending proof covers, anchor: none carried with a warning naming the rule, --anchor-policy swaps both, coverage per statement and structural; \"nothing is transported\" is vacuous until push transports (L-17)")
	cal := okCal(t)
	stamp := func(p *pushWorld, id string) {
		t.Helper()
		if r := p.stamp(builder(cal), "--calendar", cal.srv.URL, "--allow-private", id); r.code != 0 {
			t.Fatalf("stamp: %d %s", r.code, r.stdout)
		}
	}

	t.Run("a-b required, then stamped", func(t *testing.T) {
		p := newPushWorld(t)
		a := p.mustPublish("--kind", "authored", "--content", p.file("a", "required content"))
		p.commitAll("publish")
		r := p.push()
		rep := jsonOf(t, r)
		row := anchorRow(t, rep, a)
		if r.code != ExitWrong || row.Members["verdict"] != canon.String("refused") || row.Members["class"] != canon.String("reader policy") ||
			row.Members["reason"] != canon.String("anchor required") || row.Members["scope"] != canon.String("statement "+a) ||
			!strings.Contains(string(canon.Encode(row.Members["decided_by"])), "without provenance") ||
			!strings.Contains(string(canon.Encode(row.Members["next"])), "anchor stamp "+a) {
			t.Fatalf("(a) uncovered required: exit %d\n%s", r.code, r.stdout)
		}
		// the gate's own verdict on the same line is admitted: the precondition is not an admission verdict
		if o := objectRow(t, rep, stmtPath(p.signer, a)); o != nil && o.Members["verdict"] == canon.String("refused") {
			t.Fatalf("(a) the anchor precondition leaked into the gate verdict: %s", canon.Encode(o))
		}
		if hc := runIn(p.root, nil, "hub", "check", "--base", "main"); hc.code != ExitOK {
			t.Fatalf("(a) hub check over the same change: exit %d (it must not apply the precondition)\n%s", hc.code, hc.stdout)
		}
		h := runIn(p.root, nil, "push", "--dry-run")
		if h.code != ExitWrong || !strings.Contains(h.stdout, "anchor required") {
			t.Fatalf("(a) human: %d\n%s", h.code, h.stdout)
		}

		stamp(p, a)
		p.commitAll("anchor")
		r = p.push()
		rep = jsonOf(t, r)
		row = anchorRow(t, rep, a)
		if r.code != ExitOK || row.Members["verdict"] != canon.String("admitted") || row.Members["covered_by"] == nil {
			t.Fatalf("(b) a pending proof covers: exit %d\n%s", r.code, r.stdout)
		}
		if w := warnings(rep); strings.Contains(w, "proof not carried") {
			t.Fatalf("(b) the proof travels, yet: %s", w)
		}
	})

	t.Run("c-d-e standings and overrides", func(t *testing.T) {
		p := newPushWorld(t)
		prov := `{"workflow":"` + dig("wf") + `","inputs":[]}`
		a := p.mustPublish("--kind", "authored", "--content", p.file("a", "required content"))
		c := p.mustPublish("--kind", "authored", "--content", p.file("c", "derived content"), "--provenance", prov)
		p.commitAll("publish")
		r := p.push()
		rep := jsonOf(t, r)
		rc := anchorRow(t, rep, c)
		if rc.Members["verdict"] != canon.String("admitted") || rc.Members["standing"] != canon.String("anchor: none") ||
			!strings.Contains(warnings(rep), c) || !strings.Contains(warnings(rep), "authored with provenance") {
			t.Fatalf("(c) anchor: none carried with a warning naming the rule: exit %d\n%s", r.code, r.stdout)
		}
		if r.code != ExitWrong || anchorRow(t, rep, a).Members["verdict"] != canon.String("refused") {
			t.Fatalf("(a) beside (c): exit %d\n%s", r.code, r.stdout)
		}

		r = p.push("--anchor-policy", "none")
		rep = jsonOf(t, r)
		ra := anchorRow(t, rep, a)
		if r.code != ExitOK || ra.Members["verdict"] != canon.String("admitted") || ra.Members["standing"] != canon.String("anchor: none") ||
			!strings.Contains(string(canon.Encode(ra.Members["decided_by"])), "--anchor-policy none") || !strings.Contains(warnings(rep), "--anchor-policy none") {
			t.Fatalf("(d) the override carries the required statement with a warning naming it: exit %d\n%s", r.code, r.stdout)
		}

		r = p.push("--anchor-policy", "required")
		rep = jsonOf(t, r)
		rc = anchorRow(t, rep, c)
		if r.code != ExitWrong || rc.Members["verdict"] != canon.String("refused") || rc.Members["standing"] != canon.String("anchor required") ||
			!strings.Contains(string(canon.Encode(rc.Members["decided_by"])), "--anchor-policy required") {
			t.Fatalf("(e) the override refuses the anchor: none statement: exit %d\n%s", r.code, r.stdout)
		}
	})

	t.Run("f per statement", func(t *testing.T) {
		p := newPushWorld(t)
		a := p.mustPublish("--kind", "authored", "--content", p.file("a", "first required"))
		stamp(p, a)
		b := p.mustPublish("--kind", "authored", "--content", p.file("b", "second required, after the anchored head"))
		p.commitAll("publish")
		r := p.push()
		rep := jsonOf(t, r)
		if r.code != ExitWrong || anchorRow(t, rep, a).Members["verdict"] != canon.String("admitted") ||
			anchorRow(t, rep, b).Members["verdict"] != canon.String("refused") {
			t.Fatalf("(f) the statement after the anchored head is not covered by it: exit %d\n%s", r.code, r.stdout)
		}
		stamp(p, b)
		p.commitAll("anchor b")
		if r := p.push(); r.code != ExitOK {
			t.Fatalf("(f) after stamping b: exit %d\n%s", r.code, r.stdout)
		}
	})

	t.Run("g incoherent line is covered", func(t *testing.T) {
		p := newPushWorld(t)
		p.mustPublish("--kind", "authored", "--content", p.file("a", "first"), "--ts", "2026-10-20T12:00:00Z")
		b := p.mustPublish("--kind", "authored", "--content", p.file("b", "second, ts before its prev"), "--ts", "2026-10-20T11:00:00Z")
		stamp(p, b)
		p.commitAll("publish")
		r := p.push()
		rep := jsonOf(t, r)
		if o := objectRow(t, rep, stmtPath(p.signer, b)); o == nil || !strings.Contains(string(canon.Encode(o.Members["labels"])), `"incoherent"`) {
			t.Fatalf("(g) the fixture line is not incoherent:\n%s", r.stdout)
		}
		if r.code != ExitOK || anchorRow(t, rep, b).Members["verdict"] != canon.String("admitted") || anchorRow(t, rep, b).Members["covered_by"] == nil {
			t.Fatalf("(g) an incoherent line covered by an anchor is carried (coverage is structural): exit %d\n%s", r.code, r.stdout)
		}
	})
}

// TestPushWithheldBytes: the withheld precondition (storage note §3.2 "publish of a withheld artifact"; claims-model
// note §7). The author publishes with availability withheld and --no-holds, stamps it, and commits everything,
// the blob included: push refuses the blob (reader policy `withheld bytes`, scope the blob's path, naming the
// declaring statement) while the statements themselves are carried; without the blob the push is clean; with
// a holds (the reveal) also committed, the blob is carried.
func TestPushWithheldBytes(t *testing.T) {
	conformance.Partial(t, "C-core-148", "push --dry-run only: the refusal, the clean push without the blob and the carried blob after the reveal are asserted; nothing is transported yet, so the transport half waits for push")
	p := newPushWorld(t)
	data := "held-out pool with a 128-bit nonce 4f1c9a2e7b3d5a60c8e1f2a3b4c5d6e7"
	c := p.file("seed", data)
	a := p.mustPublish("--kind", "authored", "--content", c, "--no-holds",
		"--availability", `{"obtainable":false,"redistribution":"withheld","withheld_until":"edition 2"}`)
	cal := okCal(t)
	if r := p.stamp(builder(cal), "--calendar", cal.srv.URL, "--allow-private"); r.code != 0 {
		t.Fatalf("stamp: %d %s", r.code, r.stdout)
	}
	d := dig(data)
	blob := "blobs/sha256/" + strings.TrimPrefix(d, "sha256:")
	p.commitAll("publish, blob included")
	r := p.push()
	rep := jsonOf(t, r)
	wh, _ := rep.Members["withheld"].(canon.Array)
	if r.code != ExitWrong || len(wh) != 1 {
		t.Fatalf("withheld blob carried: exit %d\n%s", r.code, r.stdout)
	}
	row := wh[0].(*canon.Object)
	if row.Members["path"] != canon.String(blob) || row.Members["reason"] != canon.String("withheld bytes") ||
		row.Members["class"] != canon.String("reader policy") || row.Members["scope"] != canon.String("object "+blob) ||
		!strings.Contains(string(canon.Encode(row.Members["declared_by"])), a) {
		t.Fatalf("withheld row: %s", canon.Encode(row))
	}
	if ag := anchorRow(t, rep, a); ag.Members["verdict"] != canon.String("admitted") {
		t.Fatalf("the withheld authored is anchored and must be carried: %s", canon.Encode(ag))
	}
	if h := runIn(p.root, nil, "push", "--dry-run"); h.code != ExitWrong || !strings.Contains(h.stdout, "withheld bytes") {
		t.Fatalf("human: %d\n%s", h.code, h.stdout)
	}

	// drop the blob from the commit (it stays in the store, untracked): clean, and listed as uncommitted
	gitIn(t, p.root, "rm", "-q", "--cached", blob)
	gitIn(t, p.root, "commit", "-q", "-m", "drop the blob")
	r = p.push()
	rep = jsonOf(t, r)
	if r.code != ExitOK || len(rep.Members["withheld"].(canon.Array)) != 0 || !strings.Contains(string(canon.Encode(rep.Members["uncommitted"])), blob) {
		t.Fatalf("without the blob: exit %d\n%s", r.code, r.stdout)
	}

	// the reveal: a holds, then the blob, committed together
	p.mustPublish("--kind", "holds", "--content", c)
	p.commitAll("reveal")
	r = p.push()
	rep = jsonOf(t, r)
	if r.code != ExitOK || len(rep.Members["withheld"].(canon.Array)) != 0 {
		t.Fatalf("after the reveal: exit %d\n%s", r.code, r.stdout)
	}
	if o := objectRow(t, rep, blob); o != nil && o.Members["verdict"] == canon.String("refused") {
		t.Fatalf("the revealed blob: %s", canon.Encode(o))
	}
}

// TestPushProofNotCarried: an anchors line whose proof blob is left out of the commit still covers (the order is in
// the log), and push warns that readers see missing-proof until the proof is held.
func TestPushProofNotCarried(t *testing.T) {
	p := newPushWorld(t)
	a := p.mustPublish("--kind", "authored", "--content", p.file("a", "required content"))
	cal := okCal(t)
	r := p.stamp(builder(cal), "--calendar", cal.srv.URL, "--allow-private")
	if r.code != 0 {
		t.Fatalf("stamp: %d %s", r.code, r.stdout)
	}
	proof := string(outObj(t, r).Members["proof"].(canon.String))
	p.commitAll("publish and anchor")
	gitIn(t, p.root, "rm", "-q", "--cached", "blobs/sha256/"+strings.TrimPrefix(proof, "sha256:"))
	gitIn(t, p.root, "commit", "-q", "-m", "drop the proof")
	r = p.push()
	rep := jsonOf(t, r)
	if r.code != ExitOK || anchorRow(t, rep, a).Members["verdict"] != canon.String("admitted") ||
		!strings.Contains(warnings(rep), "proof not carried") || !strings.Contains(warnings(rep), proof) || !strings.Contains(warnings(rep), "missing-proof") {
		t.Fatalf("proof not carried: exit %d\n%s", r.code, r.stdout)
	}
}

// TestPushDryRunWritesNothing: C-core-137's push half. push --dry-run over a change that would be refused and over one
// that is clean prints its side effects, and a before/after snapshot of the checkout (its .git included) and of the
// bare hub proves nothing changed. Without --dry-run push exits 2 and changes nothing either.
func TestPushDryRunWritesNothing(t *testing.T) {
	conformance.Partial(t, "C-core-137", "push --dry-run states its side effects (no registry change; no fetch; no cache; no transport) and a before/after snapshot of the checkout and the bare hub proves nothing changed; pull is TestPullTrustFloor, fetch TestFetchDryRun")
	p := newPushWorld(t)
	a := p.mustPublish("--kind", "authored", "--content", p.file("a", "required content"))
	p.commitAll("publish")
	p.file("stray", "x")
	for _, args := range [][]string{nil, {"--anchor-policy", "none"}} {
		before, remote := snapshot(t, p.root), p.remoteState()
		r := p.push(args...)
		h := runIn(p.root, nil, append([]string{"push", "--dry-run"}, args...)...)
		if snapshot(t, p.root) != before || p.remoteState() != remote {
			t.Fatalf("push --dry-run %v changed something", args)
		}
		rep := jsonOf(t, r)
		if rep.Members["side_effects"] != canon.String("no registry change; no fetch; no cache; no transport") ||
			!strings.Contains(h.stdout, "no registry change; no fetch; no cache; no transport") {
			t.Fatalf("side effects not stated: %s", r.stdout)
		}
		if want := map[bool]int{true: ExitOK, false: ExitWrong}[args != nil]; r.code != want || h.code != want {
			t.Fatalf("push --dry-run %v: exit %d / %d, want %d\n%s", args, r.code, h.code, want, r.stdout)
		}
	}
	before, remote := snapshot(t, p.root), p.remoteState()
	if r := runIn(p.root, nil, "push", "--json"); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "transport not built yet") {
		t.Fatalf("push without --dry-run: %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before || p.remoteState() != remote {
		t.Fatal("push without --dry-run changed something")
	}
	_ = a
}

// TestPushNeedsAHubCheckout: push reads the change of a git checkout of the hub; a store that is not one, a store
// nested below the checkout's top level, an unknown remote and an unrecorded default branch exit 2 naming the way
// out, and change nothing.
func TestPushNeedsAHubCheckout(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	plain := newPubWorld(t)
	check := func(label, dir string, want string, args ...string) {
		t.Helper()
		before := snapshot(t, dir)
		r := runIn(dir, nil, append([]string{"push", "--dry-run", "--json"}, args...)...)
		if r.code != ExitDidNotStart || !strings.Contains(r.stdout, want) || snapshot(t, dir) != before {
			t.Fatalf("%s: exit %d\n%s", label, r.code, r.stdout)
		}
	}
	check("plain store", plain.root, "not a git checkout")
	outer := t.TempDir()
	gitIn(t, outer, "init", "-q", "-b", "main")
	nested := newPubWorld(t)
	inner := filepath.Join(outer, "store")
	os.Rename(nested.root, inner)
	gitIn(t, outer, "commit", "-q", "--allow-empty", "-m", "x")
	check("nested store", inner, "top level")
	p := newPushWorld(t)
	check("unknown remote", p.root, "no such remote", "--remote", "upstream")
	gitIn(t, p.root, "remote", "set-head", "origin", "--delete")
	check("no default branch", p.root, "default branch", "--remote", "origin")
	if r := p.push("--base", "origin/main"); r.code != ExitOK {
		t.Fatalf("--base names it: %d %s", r.code, r.stdout)
	}
}

// TestPushUnsignedDraft: C-core-108 through the command. Unsigned drafts committed into the checkout where statements
// go (an authored, and an intent naming a task the hub holds) are refused by push --dry-run, intrinsic `unsigned
// draft`, scoped to each file, with a next step that says to sign; the hub is unchanged.
func TestPushUnsignedDraft(t *testing.T) {
	conformance.Partial(t, "C-core-108", "push --dry-run refuses each committed unsigned draft (authored; intent naming a held task), intrinsic, scope the file, next says sign it, the hub unchanged; every kind is TestUnsignedDraftsRefused (gate); the hub's task readiness is unchanged by construction until push transports (L-17)")
	p := newPushWorld(t)
	g := p.sign("T", "K9", "genesis", obj("type", "task", "name", "t", "controllers", []string{p.signer9()}, "rule", obj("any_one", true)))
	p.commitAll("a task")
	gitIn(t, p.root, "push", "-q", "origin", "change:main")
	gitIn(t, p.root, "fetch", "-q", "origin")
	k := p.world.key("B")
	paths := []string{}
	for i, d := range []wire.Draft{
		{Kind: "authored", TS: "2026-10-16T00:00:00Z", Body: obj("content", content("x"), "type", "dataset")},
		{Kind: "intent", TS: "2026-10-16T00:00:00Z", Body: obj("task", g, "edition", g)},
	} {
		rel := gate.StatementPath(k.Signer(), strings.Repeat("0", 63)+strconv.Itoa(i))
		os.MkdirAll(filepath.Dir(filepath.Join(p.root, rel)), 0o755)
		os.WriteFile(filepath.Join(p.root, rel), canon.Encode(d.Envelope(k)), 0o644)
		paths = append(paths, rel)
	}
	p.commitAll("drafts")
	remote := p.remoteState()
	r := p.push()
	rep := jsonOf(t, r)
	if r.code != ExitWrong {
		t.Fatalf("exit %d\n%s", r.code, r.stdout)
	}
	for _, rel := range paths {
		row := objectRow(t, rep, rel)
		if row == nil || row.Members["verdict"] != canon.String("refused") || row.Members["class"] != canon.String("intrinsic") ||
			row.Members["reason"] != canon.String("unsigned draft") || !strings.Contains(string(canon.Encode(row.Members["next"])), "sign") ||
			!strings.Contains(string(canon.Encode(row.Members["scope"])), rel) {
			t.Fatalf("%s: %s", rel, canon.Encode(row))
		}
	}
	if p.remoteState() != remote {
		t.Fatal("the hub changed")
	}
}

// TestPushContested: C-core-135's push half. Two keys claim one blob, each anchored (a pending proof and a parseable
// proof with no backend: no verified bound, so neither is the default author). push --dry-run exits 0 and labels
// both rival lines `contested`, the word list prints for the blob; verify exits 3.
func TestPushContested(t *testing.T) {
	conformance.Partial(t, "C-core-135", "push --dry-run exits 0 and labels each rival authored `contested` (the token list and verify print; verify exits 3); a package containing it is pushed only once push transports (L-17)")
	p := newPushWorld(t)
	data := "rival bytes"
	a := p.mustPublish("--kind", "authored", "--content", p.file("x", data), "--no-holds")
	cal := okCal(t)
	if r := p.stamp(builder(cal), "--calendar", cal.srv.URL, "--allow-private"); r.code != 0 {
		t.Fatalf("stamp: %d %s", r.code, r.stdout)
	}
	b := p.world.authored("rival", "K2", data)
	p.world.anchor("rival anchor", "K2", 800000)
	p.commitAll("two claims")
	if v := p.run("verify", dig(data)); v.code != ExitCouldNot {
		t.Fatalf("verify: exit %d\n%s", v.code, v.stdout)
	}
	if l := p.run("list"); !strings.Contains(l.stdout, "contested") {
		t.Fatalf("list:\n%s", l.stdout)
	}
	r := p.push()
	rep := jsonOf(t, r)
	if r.code != ExitOK {
		t.Fatalf("push: exit %d\n%s", r.code, r.stdout)
	}
	for _, id := range []string{a, b} {
		signer := p.signer
		if id == b {
			signer = p.world.signer("K2")
		}
		row := objectRow(t, rep, stmtPath(signer, id))
		if row == nil || !strings.Contains(string(canon.Encode(row.Members["labels"])), `"contested"`) {
			t.Fatalf("%s not labelled contested:\n%s", id, r.stdout)
		}
	}
	if h := runIn(p.root, nil, "push", "--dry-run"); h.code != ExitOK || strings.Count(h.stdout, "contested") < 2 {
		t.Fatalf("human: %d\n%s", h.code, h.stdout)
	}
}
