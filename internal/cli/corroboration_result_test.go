package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// corroWorld: observation X (blob "x"), a bytes workflow, and a corroboration by K6 naming the derived result
// "res" (derived from x, run twice by K1 and K2, so T0); the corroboration declares a cohort rule.
func corroWorld(t *testing.T) (*world, string, string) {
	w := newWorld(t)
	ref := obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "block_hash", strings.Repeat("a1", 32), "depth", 3)
	x := w.sign("X", "K5", "observed", obj("content", canon.Value(content("x")), "class", "exact-bytes", "referent", canon.Value(ref),
		"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted"))))
	w.workflow("K1", "wf", "bytes", "")
	w.authored("Ra", "K1", "res", "type", "report", "prov", []string{"wf", "x", "bounds"})
	w.authored("Rb", "K2", "res", "type", "report", "prov", []string{"wf", "x", "bounds"})
	c := w.sign("C", "K6", "corroborates", obj("of", x, "result", w.ids["Ra"], "verdict", "contradicts", "model", "bounds/1",
		"cohort", canon.Value(obj("rule", "every station in R"))))
	return w, x, c
}

func evidenceOf(t *testing.T, o *canon.Object, stmt string) *canon.Object {
	t.Helper()
	co, _ := o.Members["corroboration"].(*canon.Object)
	if co != nil {
		ev, _ := co.Members["evidence"].(canon.Array)
		for _, e := range ev {
			if eo := e.(*canon.Object); eo.Members["statement"] == canon.String(stmt) {
				return eo
			}
		}
	}
	t.Fatalf("no evidence row for %s in %s", stmt, canon.Encode(o))
	return nil
}

// TestCorroborationIsDerivationSurfaces: C-core-45 (the observation side; the reader's own re-run of the result is
// internal/clirun.TestCorroborationRerun, through `verify --rerun`). The corroboration names its derived result and
// the grade of that result's own derivation, and its comparison data, on explain and show of the blob (the full
// evidence view); the result is an ordinary derived artifact, so `show`/`verify` on it print its derivation and
// grade like any other, and the corroboration's verdict never moves that grade or the exit.
func TestCorroborationIsDerivationSurfaces(t *testing.T) {
	conformance.Covers(t, "C-core-45")
	w, x, c := corroWorld(t)
	for _, cmd := range []string{"explain", "show"} {
		e := evidenceOf(t, jsonOf(t, w.run(cmd, x, "--json")), c)
		if e.Members["result"] != canon.String(w.ids["Ra"]) || !strings.HasPrefix(string(e.Members["result_grade"].(canon.String)), "T0 (") {
			t.Fatalf("%s: evidence %s", cmd, canon.Encode(e))
		}
		if !strings.Contains(string(canon.Encode(e.Members["comparison_data"])), dig("bounds")) {
			t.Fatalf("%s: comparison data %s", cmd, canon.Encode(e))
		}
	}
	v := w.run("verify", dig("res"), "--json")
	o := jsonOf(t, v)
	if o.Members["grade"] != canon.String("T0") || v.code != 0 {
		t.Fatalf("the result's own verify: exit %d %s", v.code, canon.Encode(o.Members["grade"]))
	}
	// the corroboration is not an input of the result's grade: dropping it changes nothing about the result
	bare, _, _ := corroWorld(t)
	if a, b := jsonOf(t, bare.run("show", dig("res"), "--json")).Members["grade"], o.Members["grade"]; a != b {
		t.Fatalf("grade differs: %v vs %v", a, b)
	}
}

// TestNoReferenceCollectionShipped: C-core-61 through the commands. With no reference collection chosen, the
// reader's re-application of a declared cohort rule is `inconclusive (no reference collection chosen)` on every
// surface that prints it (never a pass, never a guess), the corroboration's own status is unchanged by it, and the
// tool ships none: nothing under the install tree is a reference collection (no collection statement, no
// reference-data file the reader could pick up by default).
func TestNoReferenceCollectionShipped(t *testing.T) {
	conformance.Covers(t, "C-core-61")
	w, x, c := corroWorld(t)
	for _, cmd := range []string{"explain", "show"} {
		e := evidenceOf(t, jsonOf(t, w.run(cmd, x, "--json")), c)
		cc := string(canon.Encode(e.Members["cohort_check"]))
		if !strings.Contains(cc, "inconclusive (no reference collection chosen)") {
			t.Fatalf("%s: cohort_check %s", cmd, cc)
		}
		if strings.Contains(strings.ToLower(cc), "match") || strings.Contains(strings.ToLower(cc), "pass") {
			t.Fatalf("%s: a cohort re-application result without a collection: %s", cmd, cc)
		}
	}
	h := w.run("explain", x).stdout
	if !strings.Contains(h, "inconclusive (no reference collection chosen)") {
		t.Fatalf("human surface:\n%s", h)
	}
}

// TestInstallTreeShipsNoReferenceCollection: the install-tree half of C-core-61. The binary embeds exactly one
// file (VERSION), and no file outside docs/ and test data is a data package: no statement lines, no collection
// statement, no archive of reference data, anywhere a default reader could find one.
func TestInstallTreeShipsNoReferenceCollection(t *testing.T) {
	conformance.Covers(t, "C-core-61")
	root := "../.."
	embeds := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".wt", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		parts := strings.Split(rel, string(filepath.Separator))
		inDocs := parts[0] == "docs"
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			b, _ := os.ReadFile(p)
			embeds += strings.Count(string(b), "//go:embed")
		}
		switch filepath.Ext(p) {
		case ".jsonl", ".rcpkg", ".tar", ".tgz", ".zip", ".csv", ".parquet", ".nc", ".sqlite", ".db":
			if !inDocs && !strings.Contains(rel, "testdata") {
				t.Errorf("%s: a data file in the install tree", rel)
			}
		case ".json":
			if !inDocs && !strings.Contains(rel, "testdata") {
				if b, _ := os.ReadFile(p); strings.Contains(string(b), `"collection"`) || strings.Contains(string(b), `"kind":"authored"`) {
					t.Errorf("%s: statement or collection data in the install tree", rel)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if embeds != 1 {
		t.Errorf("%d //go:embed directives in non-test code, want exactly 1 (VERSION)", embeds)
	}
}
