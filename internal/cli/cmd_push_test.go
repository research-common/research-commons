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

// push tests. Every hub is a local bare repository (the remote is a path; nothing is dialled) and every
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
	// push runs git in the caller's environment: no system or global configuration reaches the throwaway hub
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
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

// send runs push without --dry-run: the transport runs when the judgement is clean.
func (p *pushWorld) send(args ...string) result {
	return runIn(p.root, nil, append([]string{"push", "--json"}, args...)...)
}

// remoteHas reports whether the bare hub's branch holds path with exactly these bytes.
func (p *pushWorld) remoteHas(branch, path string, want []byte) bool {
	p.t.Helper()
	out, err := exec.Command("git", "-C", p.remote, "cat-file", "blob", "refs/heads/"+branch+":"+path).Output()
	return err == nil && string(out) == string(want)
}

// remoteHead is the bare hub's branch tip ("" when the branch does not exist).
func (p *pushWorld) remoteHead(branch string) string {
	out, err := exec.Command("git", "-C", p.remote, "rev-parse", "--verify", "--quiet", "refs/heads/"+branch).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// sentOK asserts a push that transported the checkout's HEAD to branch.
func (p *pushWorld) sentOK(r result, branch string) *canon.Object {
	p.t.Helper()
	rep := jsonOf(p.t.(*testing.T), r)
	head := gitIn(p.t, p.root, "rev-parse", "HEAD")
	if r.code != ExitOK || rep.Members["transported"] != canon.Bool(true) || rep.Members["pushed"] != canon.String(head) ||
		rep.Members["branch"] != canon.String(branch) || p.remoteHead(branch) != head ||
		rep.Members["side_effects"] != canon.String(PushSentSideEffects) {
		p.t.Fatalf("push did not transport HEAD %s to %s (remote %s): exit %d\n%s", head, branch, p.remoteHead(branch), r.code, r.stdout)
	}
	return rep
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

// TestPushAnchorGate: C-btc-03c through the command. (a) an authored without provenance and no anchor is refused,
// reader policy `anchor required`, scope the statement, and push without --dry-run sends nothing (the bare hub's refs
// and objects are byte-identical); (b) after `anchor stamp` (a pending proof) and a commit it is covered, the push is
// clean, and push sends it: the hub's branch then holds the authored line, the anchors line and the proof blob; (c) an authored with
// provenance, unanchored, is carried with a warning naming the rule; (d) (a) under --anchor-policy none is carried
// with a warning naming the override; (e) (c) under --anchor-policy required is refused; (f) a required statement
// appended after the anchored head is refused while the earlier one stays covered (coverage is per statement); (g)
// a statement on an incoherent line (ts earlier than its predecessor's) covered by an anchor is carried: coverage
// is structural, not a time bound.
func TestPushAnchorGate(t *testing.T) {
	conformance.Covers(t, "C-btc-03c")
	cal := okCal(t)
	stamp := func(p *pushWorld, id string) string {
		t.Helper()
		r := p.stamp(builder(cal), "--calendar", cal.srv.URL, "--allow-private", id)
		if r.code != 0 {
			t.Fatalf("stamp: %d %s", r.code, r.stdout)
		}
		return string(outObj(t, r).Members["proof"].(canon.String))
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
		// (a) without --dry-run: refused, nothing transported
		remote := p.remoteState()
		r = p.send()
		rep = jsonOf(t, r)
		if r.code != ExitWrong || rep.Members["transported"] != canon.Bool(false) || anchorRow(t, rep, a).Members["verdict"] != canon.String("refused") ||
			rep.Members["side_effects"] != canon.String(PushSideEffects) || p.remoteState() != remote {
			t.Fatalf("(a) push sent an uncovered required statement: exit %d\n%s", r.code, r.stdout)
		}

		proof := stamp(p, a)
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
		// (b) without --dry-run: sent; the hub's branch holds the authored line, the anchors line and the proof
		p.sentOK(p.send(), "main")
		cov := row.Members["covered_by"].(canon.Array)
		anc := string(cov[0].(canon.String))
		for _, id := range []string{a, anc} {
			path := stmtPath(p.signer, id)
			b, err := os.ReadFile(filepath.Join(p.root, filepath.FromSlash(path)))
			if err != nil || !p.remoteHas("main", path, b) {
				t.Fatalf("(b) the hub's branch lacks %s: %v", path, err)
			}
		}
		pb, err := os.ReadFile(filepath.Join(p.root, "blobs", "sha256", strings.TrimPrefix(proof, "sha256:")))
		if proof == "" || err != nil || !p.remoteHas("main", "blobs/sha256/"+strings.TrimPrefix(proof, "sha256:"), pb) {
			t.Fatalf("(b) the hub's branch lacks the proof blob %q: %v", proof, err)
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
// declaring statement) while the statements themselves are carried, and push without --dry-run sends nothing;
// without the blob the push is clean and sends the statements, the blob listed as uncommitted and absent from the
// hub; with a holds (the reveal) also committed, the blob is carried and the hub's branch holds it.
func TestPushWithheldBytes(t *testing.T) {
	conformance.Covers(t, "C-core-148")
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
	remote := p.remoteState()
	if r := p.send(); r.code != ExitWrong || jsonOf(t, r).Members["transported"] != canon.Bool(false) || p.remoteState() != remote {
		t.Fatalf("push sent a withheld blob: exit %d\n%s", r.code, r.stdout)
	}

	// drop the blob from the commit (it stays in the store, untracked): clean, and listed as uncommitted
	gitIn(t, p.root, "rm", "-q", "--cached", blob)
	gitIn(t, p.root, "commit", "-q", "-m", "drop the blob")
	r = p.push()
	rep = jsonOf(t, r)
	if r.code != ExitOK || len(rep.Members["withheld"].(canon.Array)) != 0 || !strings.Contains(string(canon.Encode(rep.Members["uncommitted"])), blob) {
		t.Fatalf("without the blob: exit %d\n%s", r.code, r.stdout)
	}
	p.sentOK(p.send(), "main")
	line, _ := os.ReadFile(filepath.Join(p.root, filepath.FromSlash(stmtPath(p.signer, a))))
	if !p.remoteHas("main", stmtPath(p.signer, a), line) || p.remoteHas("main", blob, []byte(data)) {
		t.Fatal("without the blob: the hub's branch should hold the authored line and not the withheld bytes")
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
	p.sentOK(p.send(), "main")
	if !p.remoteHas("main", blob, []byte(data)) {
		t.Fatal("after the reveal the hub's branch lacks the blob")
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
// bare hub proves nothing changed, the clean one included (which push without --dry-run would send).
func TestPushDryRunWritesNothing(t *testing.T) {
	conformance.Partial(t, "C-core-137", "push --dry-run states its side effects (no registry change; no fetch; no cache; no transport) and a before/after snapshot of the checkout and the bare hub proves nothing changed, for a change push would send; pull is TestPullTrustFloor, fetch TestFetchDryRun")
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
		if rep.Members["transported"] != canon.Bool(false) || rep.Members["transport"] != canon.String("none: dry run") ||
			rep.Members["side_effects"] != canon.String("no registry change; no fetch; no cache; no transport") ||
			!strings.Contains(h.stdout, "no registry change; no fetch; no cache; no transport") {
			t.Fatalf("side effects not stated: %s", r.stdout)
		}
		if want := map[bool]int{true: ExitOK, false: ExitWrong}[args != nil]; r.code != want || h.code != want {
			t.Fatalf("push --dry-run %v: exit %d / %d, want %d\n%s", args, r.code, h.code, want, r.stdout)
		}
	}
	// control: the clean change (under --anchor-policy none) is sent by push without --dry-run
	p.sentOK(p.send("--anchor-policy", "none"), "main")
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

// TestPushUnsignedDraft: C-core-108 through the command. An unsigned draft of each statement kind, committed into the
// checkout where a statement would go (the task lifecycle ones naming a task edition the hub holds), is refused by
// push, intrinsic `unsigned draft`, scoped to its file, with a next step that says to sign; push without --dry-run
// exits 1 and sends nothing: the bare hub's refs and objects are byte-identical, and the task as a fresh clone of the
// hub reads it (state and readiness) is unchanged. First-run setup (init) tells the user to generate a key, and a
// signing command with no key generates none (TestFirstRunNoKey holds every signing command).
func TestPushUnsignedDraft(t *testing.T) {
	conformance.Covers(t, "C-core-108")
	p := newPushWorld(t)
	g := p.sign("T", "K9", "genesis", obj("type", "task", "name", "t", "controllers", []string{p.signer9()}, "rule", obj("any_one", true)))
	p.commitAll("a task")
	gitIn(t, p.root, "push", "-q", "origin", "change:main")
	gitIn(t, p.root, "fetch", "-q", "origin")
	k := p.world.key("B")
	paths := []string{}
	ts := "2026-10-16T00:00:00Z"
	for i, d := range []wire.Draft{
		{Kind: "authored", TS: ts, Body: obj("content", content("x"), "type", "dataset")},
		{Kind: "holds", TS: ts, Body: obj("content", content("x"))},
		{Kind: "describes", TS: ts, Body: obj("about", obj("content", dig("x")))},
		{Kind: "retracts", TS: ts, Body: obj("of", g)},
		{Kind: "intent", TS: ts, Body: obj("task", g, "edition", g)},
		{Kind: "submit", TS: ts, Body: obj("task", g, "edition", g, "result", dig("x"))},
		{Kind: "genesis", TS: ts, Body: obj("type", "collection", "name", "c", "controllers", []string{k.Signer()}, "rule", obj("any_one", true))},
	} {
		rel := gate.StatementPath(k.Signer(), strings.Repeat("0", 63)+strconv.Itoa(i))
		os.MkdirAll(filepath.Dir(filepath.Join(p.root, rel)), 0o755)
		os.WriteFile(filepath.Join(p.root, rel), canon.Encode(d.Envelope(k)), 0o644)
		paths = append(paths, rel)
	}
	p.commitAll("drafts")
	remote := p.remoteState()
	task := func() string {
		t.Helper()
		c := filepath.Join(t.TempDir(), "clone")
		gitIn(t, filepath.Dir(c), "clone", "-q", p.remote, c)
		r := runIn(c, nil, "show", g, "--json")
		if r.code != ExitOK || !strings.Contains(r.stdout, `"readiness"`) {
			t.Fatalf("show task in a clone of the hub: %d\n%s", r.code, r.stdout)
		}
		return r.stdout
	}
	taskBefore := task()
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
	s := p.send()
	if s.code != ExitWrong || jsonOf(t, s).Members["transported"] != canon.Bool(false) {
		t.Fatalf("push: exit %d\n%s", s.code, s.stdout)
	}
	if p.remoteState() != remote {
		t.Fatal("push sent unsigned drafts: the hub changed")
	}
	if task() != taskBefore {
		t.Fatal("the task's state or readiness changed at the hub")
	}
	// first-run setup: init names the key step; no key is generated implicitly, there is no default key path
	in := runIn(t.TempDir(), nil, "init", filepath.Join(t.TempDir(), "s"))
	if !strings.Contains(in.stdout, "commons key new --out <file>") || !strings.Contains(in.stdout, KeyEnv) {
		t.Fatalf("init does not tell the user to generate a key:\n%s", in.stdout)
	}
	c := p.file("nokey", "x")
	before := snapshot(t, p.root)
	if r := runIn(p.root, nil, "publish", "--kind", "authored", "--content", c, "--json"); r.code != ExitDidNotStart ||
		!strings.Contains(r.stdout, "commons key new") || snapshot(t, p.root) != before {
		t.Fatalf("publish with no key: exit %d (or it wrote something)\n%s", r.code, r.stdout)
	}
}

// TestPushContested: C-core-135. Two keys claim one blob, each anchored (a pending proof and a parseable proof with
// no backend: no verified bound, so neither is the default author). list shows `contested`; push exits 0, labels
// both rival lines `contested` and sends the package (the hub's branch holds both lines); verify exits 3 with the
// same word. The dry run gives the same answer.
func TestPushContested(t *testing.T) {
	conformance.Covers(t, "C-core-135")
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
	// the push itself: exit 0, the same label, and the package is at the hub
	sent := p.sentOK(p.send(), "main")
	for _, id := range []string{a, b} {
		signer := p.signer
		if id == b {
			signer = p.world.signer("K2")
		}
		path := stmtPath(signer, id)
		row := objectRow(t, sent, path)
		line, _ := os.ReadFile(filepath.Join(p.root, filepath.FromSlash(path)))
		if row == nil || !strings.Contains(string(canon.Encode(row.Members["labels"])), `"contested"`) || !p.remoteHas("main", path, line) {
			t.Fatalf("%s: pushed without the contested label, or not at the hub:\n%s", id, canon.Encode(sent))
		}
	}
	if v := p.run("verify", dig(data)); v.code != ExitCouldNot || !strings.Contains(v.stdout, "contested") {
		t.Fatalf("verify after the push: exit %d\n%s", v.code, v.stdout)
	}
}

// TestPushTransport: the transport's own outcomes through the command, each against a bare hub. (1) An undecided
// object (could not check, exit 3) sends nothing: only a clean judgement is sent. (2) The remote's branch moved on
// while this checkout's view is stale: the judgement is clean, git rejects the non-fast-forward, push exits 3 with
// transported false, git's reason, and the next step "fetch, rebase, push again"; the hub keeps the other commit.
// (3) --branch sends to a branch of its own (the pull-request flow), leaving the hub's default branch alone; a base
// that is not a branch of the remote and no --branch is exit 2 naming --branch, before anything is sent.
func TestPushTransport(t *testing.T) {
	t.Run("undecided sends nothing", func(t *testing.T) {
		p := newPushWorld(t)
		src, _, _ := settlementPackage(t)
		copyData(t, src.root, p.root)
		os.WriteFile(filepath.Join(p.root, PolicyFile), []byte(`{"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":true}}`), 0o644)
		gitIn(t, p.root, "add", PolicyFile)
		gitIn(t, p.root, "commit", "-q", "-m", "policy")
		gitIn(t, p.root, "push", "-q", "origin", "change:main")
		gitIn(t, p.root, "fetch", "-q", "origin")
		p.commitAll("the series")
		remote := p.remoteState()
		r := p.send("--anchor-policy", "none")
		rep := jsonOf(t, r)
		if r.code != ExitCouldNot || rep.Members["transported"] != canon.Bool(false) || !strings.Contains(r.stdout, "judgement is not clean (exit 3)") ||
			p.remoteState() != remote {
			t.Fatalf("an undecided judgement was sent: exit %d\n%s", r.code, r.stdout)
		}
	})

	t.Run("non-fast-forward", func(t *testing.T) {
		p := newPushWorld(t)
		other := filepath.Join(t.TempDir(), "other")
		gitIn(t, filepath.Dir(other), "clone", "-q", p.remote, other)
		gitIn(t, other, "commit", "-q", "--allow-empty", "-m", "theirs")
		gitIn(t, other, "push", "-q", "origin", "HEAD:main")
		theirs := p.remoteHead("main")
		p.mustPublish("--kind", "authored", "--content", p.file("a", "mine"))
		p.commitAll("mine")
		r := p.send("--anchor-policy", "none")
		rep := jsonOf(t, r)
		if r.code != ExitCouldNot || rep.Members["transported"] != canon.Bool(false) || p.remoteHead("main") != theirs ||
			!strings.Contains(string(canon.Encode(rep.Members["update"])), "rejected") ||
			!strings.Contains(string(canon.Encode(rep.Members["next"])), "fetch, rebase your data commits onto the hub, push again") ||
			rep.Members["git"] == nil {
			t.Fatalf("non-fast-forward: exit %d (remote %s, theirs %s)\n%s", r.code, p.remoteHead("main"), theirs, r.stdout)
		}
		// the human surface says the same
		if h := runIn(p.root, nil, "push", "--anchor-policy", "none"); h.code != ExitCouldNot || !strings.Contains(h.stdout, "transported: no") || !strings.Contains(h.stdout, "fetch, rebase") {
			t.Fatalf("human: %d\n%s\n%s", h.code, h.stdout, h.stderr)
		}
	})

	t.Run("branch", func(t *testing.T) {
		p := newPushWorld(t)
		main := p.remoteHead("main")
		p.mustPublish("--kind", "authored", "--content", p.file("a", "mine"))
		p.commitAll("mine")
		rep := p.sentOK(p.send("--anchor-policy", "none", "--branch", "contrib/a"), "contrib/a")
		if p.remoteHead("main") != main || rep.Members["branch_from"] != canon.String("--branch") {
			t.Fatalf("--branch: the default branch moved, or the branch's source is not named\n%s", canon.Encode(rep))
		}
		remote := p.remoteState()
		r := p.send("--anchor-policy", "none", "--base", main)
		if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "--branch") || p.remoteState() != remote {
			t.Fatalf("no branch: exit %d\n%s", r.code, r.stdout)
		}
		// the dry run with the same base needs no branch
		if r := p.push("--anchor-policy", "none", "--base", main); r.code != ExitOK {
			t.Fatalf("dry run without a branch: exit %d\n%s", r.code, r.stdout)
		}
	})
}
