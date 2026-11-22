package conformance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadPinInputs(t *testing.T) (root string, doc []byte, notes map[string]*Note) {
	t.Helper()
	root, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	doc, err = os.ReadFile(filepath.Join(root, "docs", "CONFORMANCE.md"))
	if err != nil {
		t.Fatal(err)
	}
	notes, problems, err := LoadNotes(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	return root, doc, notes
}

// TestNoteColumnPins: every section, invariant and worked example a case row names exists in the note it
// names, and every quotation is found there.
func TestNoteColumnPins(t *testing.T) {
	root, doc, notes := loadPinInputs(t)
	cases := CaseRows(doc)
	if len(cases) < 200 {
		t.Fatalf("read only %d case rows from CONFORMANCE.md", len(cases))
	}
	for _, p := range LintPins(cases, notes, ClaimsNote) {
		t.Error(p)
	}
	id, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(NoteDocs["fixed-root identity"])))
	if err != nil {
		t.Fatal(err)
	}
	idCases := CaseRows(id)
	if len(idCases) == 0 {
		t.Fatal("read no case rows from the fixed-root identity note")
	}
	for _, p := range LintPins(idCases, notes, "fixed-root identity") {
		t.Error(p)
	}
}

// TestCoverageTables: the coverage tables of CONFORMANCE.md are the ones the case rows generate.
// RC_UPDATE_DOCS=1 rewrites them.
func TestCoverageTables(t *testing.T) {
	root, doc, notes := loadPinInputs(t)
	want, ok := SpliceCoverage(string(doc), CoverageMarkdown(CaseRows(doc), notes))
	if !ok {
		t.Fatalf("CONFORMANCE.md lacks the lines %q and %q, in that order", strings.TrimSpace(CoverageStart), strings.TrimSpace(CoverageEnd))
	}
	p := filepath.Join(root, "docs", "CONFORMANCE.md")
	if os.Getenv("RC_UPDATE_DOCS") == "1" && want != string(doc) {
		if err := os.WriteFile(p, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if want != string(doc) {
		t.Fatal("the coverage tables of docs/CONFORMANCE.md are not the ones its case rows generate; run RC_UPDATE_DOCS=1 go test -run TestCoverageTables ./internal/conformance")
	}
}
