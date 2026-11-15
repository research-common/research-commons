package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
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
