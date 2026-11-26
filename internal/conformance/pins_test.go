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

func TestQuoted(t *testing.T) {
	body := "Exact-bytes observations pin the **block hash** (not height). A fork does not move it.\n" +
		"A fork\nor a vanished API does not make an observation `false`. " + strings.Repeat("filler ", 30) + "The end."
	for _, c := range []struct {
		q    string
		want bool
	}{
		{"block hash (not height)", true},
		{"Block  Hash (not height)", true},                    // case and spacing do not count
		{"an observation false", true},                        // nor do code marks
		{"A fork … does not make an observation false", true}, // the second "A fork" is the one that fits
		{"block hash … not", true},                            // a short omission
		{"block … The end", false},                            // more than MaxOmitted words apart
		{"Exact-bytes … vanished … The end", false},           // every omission is bounded, not only the first
		{"ock hash (not hei", false},                          // inside words
		{"e", false},                                          // a letter of a word is not a word
		{"block hash, not height", false},                     // punctuation counts
		{"…", false},                                          // no words
		{"block hash …", false},                               // an omission with nothing after it
		{"", false},
	} {
		if got := quoted(c.q, body); got != c.want {
			t.Errorf("quoted(%q) = %v, want %v", c.q, got, c.want)
		}
	}
}

func TestParseNoteColumnQuotationMarks(t *testing.T) {
	for _, col := range []string{`§2 (“invented words”)`, `§2 ("not closed)`} {
		if _, problems := ParseNoteColumn(col, ClaimsNote); len(problems) == 0 {
			t.Errorf("%s: no problem reported", col)
		}
	}
	if _, problems := ParseNoteColumn(`§2 ("closed"), I4`, ClaimsNote); len(problems) != 0 {
		t.Errorf("a well-formed column reports %v", problems)
	}
}

// A document that defines no cases writes a case id it restates in code marks, so a line of it is never
// taken for a registration (by a reader, or by a later change to the list of case documents).
func TestRestatedCaseIDsAreInCodeMarks(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	defining := map[string]bool{"docs/CONFORMANCE.md": true}
	for _, n := range ProfileNotes {
		defining[n] = true
	}
	docs, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil || len(docs) < 10 {
		t.Fatalf("found %d documents under docs/ (%v)", len(docs), err)
	}
	for _, p := range docs {
		rel := "docs/" + filepath.Base(p)
		if defining[rel] {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if ids, _ := CaseIDs(b); len(ids) > 0 {
			t.Errorf("%s has %d table rows that open with a bare case id (%s …) and defines no cases: write the id in code marks", rel, len(ids), ids[0])
		}
	}
}
