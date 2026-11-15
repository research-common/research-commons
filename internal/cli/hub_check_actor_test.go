package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// TestHubCheckLabelsActor: `hub check` over a change that adds a signed rc/2 act prints the act's actor state as a
// label (human and JSON), the same state, identity, grant and reasons `show` prints for it once it is held; the
// label never changes admission or the exit. The published vectors give the lines: the base holds the worker's
// genesis, the identity and the grant; the change adds the act (eligible), then an act after the root cut the grant (denied); an act whose grant is not held (unknown).
func TestHubCheckLabelsActor(t *testing.T) {
	conformance.Partial(t, "C-id-02", "through the hub check command: the added act reads `actor: eligible` over the base's inception and grant, as show prints it once held; a label only")
	conformance.Partial(t, "C-id-11", "through the hub check command: an added act after the cut of its grant reads `actor: denied` naming cut_excluded; the exit stays 0")
	pos, _ := vectorChain(t, "ed")
	for _, c := range []struct {
		name  string
		base  []string // lines the hub holds at the base
		add   string   // the line the change adds
		state string
		code  string
	}{
		{"eligible", []string{"worker-genesis", "inception", "grant"}, "authored", "eligible", ""},
		// the root cut the grant at the first act; the change adds the act that came after it
		{"cut grant", []string{"worker-genesis", "inception", "grant", "authored", "cut-last-good"}, "authored-amends", "denied", "cut_excluded"},
		{"no grant held", []string{"worker-genesis", "inception"}, "authored", "unknown", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			var base []string
			for _, n := range c.base {
				base = append(base, pos[n].Line)
			}
			w := commitLines(t, base...)
			w.gitHub()
			gitIn(t, w.root, "checkout", "-q", "-b", "change")
			add := pos[c.add]
			rel := stmtPath(add.Signer, add.ID)
			os.MkdirAll(filepath.Dir(filepath.Join(w.root, rel)), 0o755)
			if err := os.WriteFile(filepath.Join(w.root, rel), []byte(add.Line), 0o644); err != nil {
				t.Fatal(err)
			}
			gitIn(t, w.root, "add", "-A")
			gitIn(t, w.root, "commit", "-q", "-m", "an act")

			r := w.run("hub", "check", "--base", "main", "--json")
			if r.code != ExitOK {
				t.Fatalf("exit %d: the actor label changed the exit\n%s", r.code, r.stdout)
			}
			row := objectRow(t, jsonOf(t, r), rel)
			if row == nil || row.Members["verdict"] != canon.String("admitted and labelled") {
				t.Fatalf("the act is not admitted and labelled: %s", canon.Encode(row))
			}
			if !strings.Contains(string(canon.Encode(row.Members["labels"])), "actor: "+c.state) {
				t.Fatalf("labels %s lack actor: %s", canon.Encode(row.Members["labels"]), c.state)
			}
			a, _ := row.Members["actor"].(*canon.Object)
			if a == nil || a.Members["state"] != canon.String(c.state) || a.Members["identity"] != canon.String(pos["inception"].ID) {
				t.Fatalf("actor member: %s", canon.Encode(row.Members["actor"]))
			}
			if c.code != "" && !strings.Contains(string(canon.Encode(a.Members["reasons"])), c.code) {
				t.Fatalf("reasons %s lack %s", canon.Encode(a.Members["reasons"]), c.code)
			}
			if h := w.run("hub", "check", "--base", "main"); h.code != ExitOK || !strings.Contains(h.stdout, "actor: "+c.state) {
				t.Fatalf("human output lacks the label: exit %d\n%s", h.code, h.stdout)
			}

			// once the same line is held, show prints the same actor member
			held := commitLines(t, append(base, add.Line)...)
			s := member(showJSON(t, held, add.ID), "actor").(*canon.Object)
			if s.Members["state"] != a.Members["state"] || s.Members["identity"] != a.Members["identity"] || s.Members["grant"] != a.Members["grant"] {
				t.Fatalf("hub check actor %s differs from show's %s", canon.Encode(a), canon.Encode(s))
			}
		})
	}
}

// TestContestedLabelAcrossGates: C-core-135, C-core-134. The fixture's two rival `authored` lines for one blob make
// it `contested` (exit 3 on verify). A pull of the same data and a `hub check` of the same tree each exit 0 and
// label both lines with the one word `contested`, in JSON (`labels`) and in the human output; the sole author's
// line carries no such label. The word is the token `list` prints for the blob.
func TestContestedLabelAcrossGates(t *testing.T) {
	conformance.Partial(t, "C-core-135", "pull and hub check exit 0 and label each rival authored `contested`, the word list and verify print for the blob (verify exits 3); push --dry-run is TestPushContested")
	w := fixture(t)
	rivals := map[string]bool{
		stmtPath(w.signer("K1"), w.ids["A:contested:1"]): true,
		stmtPath(w.signer("K2"), w.ids["A:contested:2"]): true,
	}
	sole := stmtPath(w.signer("K1"), w.ids["A:sole"])
	if len(rivals) != 2 || sole == "" {
		t.Fatalf("fixture rows: %v %q", rivals, sole)
	}
	if v := w.run("verify", dig("contested")); v.code != ExitCouldNot {
		t.Fatalf("verify: exit %d", v.code)
	}
	if l := w.run("list"); !strings.Contains(l.stdout, "contested") {
		t.Fatal("list does not say contested")
	}

	check := func(gate string, r result, human result) {
		t.Helper()
		if r.code != ExitOK {
			t.Fatalf("%s: exit %d: a label changed the exit\n%s", gate, r.code, r.stdout)
		}
		rep := jsonOf(t, r)
		for p := range rivals {
			row := objectRow(t, rep, p)
			if row == nil || row.Members["verdict"] != canon.String("admitted and labelled") ||
				!strings.Contains(string(canon.Encode(row.Members["labels"])), `"contested"`) {
				t.Fatalf("%s: %s is not labelled contested: %s", gate, p, canon.Encode(row))
			}
		}
		if row := objectRow(t, rep, sole); row != nil && strings.Contains(string(canon.Encode(row.Members["labels"])), "contested") {
			t.Fatalf("%s: the sole author is labelled contested: %s", gate, canon.Encode(row))
		}
		if human.code != ExitOK || strings.Count(human.stdout, "contested") < 2 {
			t.Fatalf("%s human: exit %d\n%s", gate, human.code, human.stdout)
		}
	}

	dst := newWorld(t)
	check("pull", dst.run("pull", w.pkgDir(), "--dry-run", "--json"), newWorld(t).run("pull", w.pkgDir(), "--dry-run"))

	// the fixture is already a hub clone (fixture_test.go)
	check("hub check", w.run("hub", "check", "--json"), w.run("hub", "check"))
}
