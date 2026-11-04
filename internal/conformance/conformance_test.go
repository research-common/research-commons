package conformance

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

// TestConformanceCases makes every case in CONFORMANCE.md a subtest. Covered cases pass and name their
// tests; the rest are skipped as pending. `go test -run TestConformanceCases -v ./internal/conformance` is the
// progress report.
func TestConformanceCases(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	ids, home, err := LoadCaseIDs(root)
	if err != nil {
		t.Fatal(err)
	}
	perDoc := map[string]int{}
	for _, f := range home {
		perDoc[f]++
	}
	if perDoc["docs/CONFORMANCE.md"] < 200 {
		t.Fatalf("found only %d case rows in CONFORMANCE.md; the row pattern no longer matches the document", perDoc["docs/CONFORMANCE.md"])
	}
	for _, n := range ProfileNotes {
		if perDoc[n] == 0 {
			t.Fatalf("profile note %s defines no case rows; the row pattern no longer matches it", n)
		}
	}
	cov, part, problems, err := ScanCoverage(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	for _, id := range SortedKeys(cov) {
		if !known[id] {
			t.Errorf("Covers(%q) in %v names a case no case document defines", id, cov[id])
		}
	}
	for _, id := range SortedKeys(part) {
		if !known[id] {
			t.Errorf("Partial(%q) in %v names a case no case document defines", id, part[id])
		}
	}
	covered := map[string]int{}
	partial := map[string]int{}
	total := map[string]int{}
	for _, id := range ids {
		p := Profile(id)
		total[p]++
		t.Run(id, func(t *testing.T) {
			if by := cov[id]; len(by) > 0 {
				covered[p]++
				t.Logf("covered by %s", strings.Join(by, ", "))
				return
			}
			if by := part[id]; len(by) > 0 {
				partial[p]++
				t.Skip("partial: " + strings.Join(by, "; "))
			}
			t.Skip("pending")
		})
	}
	for _, p := range SortedKeys(total) {
		t.Logf("%-8s %3d covered, %3d partial, of %3d cases", p, covered[p], partial[p], total[p])
	}
}

// TestNoEncodingJSON enforces the Go runtime decision: received bytes are never parsed with encoding/json
// (case-insensitive fields, last duplicate wins, invalid UTF-8 repaired). No package in this module imports
// it, test or not; the strict reader in internal/canon is the only JSON parser.
func TestNoEncodingJSON(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if p == "encoding/json" || strings.HasPrefix(p, "encoding/json/") {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s imports %s; use internal/canon", rel, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCaseIDsRefusesDuplicates(t *testing.T) {
	_, err := CaseIDs([]byte("| C-core-01 | a |\n| C-core-01 | b |\n"))
	if err == nil {
		t.Fatal("a duplicated case id was accepted")
	}
	// across documents: a profile note may not redefine a CONFORMANCE.md case, but may restate it in backticks
	_, _, err = CaseIDsAcross(Doc{"a", []byte("| C-btc-01 | x |\n")}, Doc{"b", []byte("| C-btc-01 | y |\n")})
	if err == nil || !strings.Contains(err.Error(), "in a and b") {
		t.Fatalf("an id defined in two documents: %v", err)
	}
	ids, home, err := CaseIDsAcross(Doc{"a", []byte("| C-btc-01 | x |\n")}, Doc{"b", []byte("| `C-btc-01` | restated |\n| C-btc-07 | y |\n")})
	if err != nil || len(ids) != 2 || home["C-btc-07"] != "b" || home["C-btc-01"] != "a" {
		t.Fatalf("restated id: %v %v %v", ids, home, err)
	}
}

func TestVectorsLoad(t *testing.T) {
	v, err := LoadVectors()
	if err != nil {
		t.Fatal(err)
	}
	// Counts as published in wire-format note §9; a change to the file must change this test on purpose.
	if len(v.Positive) != 12 || len(v.Negative) != 13 || len(v.EdPositive) != 2 || len(v.EdNegative) != 13 {
		t.Fatalf("vectors: %d positive, %d negative, %d ed25519 positive, %d ed25519 negative",
			len(v.Positive), len(v.Negative), len(v.EdPositive), len(v.EdNegative))
	}
}

// The row pattern accepts the identity profile's C-id-N ids and nothing that merely looks like them; Profile
// files them under "id", separate from the active profiles.
func TestCaseRowIdentityProfile(t *testing.T) {
	doc := []byte("| C-id-07 | a |\n| C-id-12a | b |\n| ID-07 | handle, not a case |\n| C-ident-1 | no |\n| C-id- | no |\n| `C-id-09` | restated |\n")
	ids, err := CaseIDs(doc)
	if err != nil || len(ids) != 2 || ids[0] != "C-id-07" || ids[1] != "C-id-12a" {
		t.Fatalf("C-id rows: %v %v", ids, err)
	}
	for id, want := range map[string]string{"C-id-07": "id", "C-btc-07": "btc", "C-core-01": "core", "P-03": "property"} {
		if got := Profile(id); got != want {
			t.Errorf("Profile(%q) = %q, want %q", id, got, want)
		}
	}
}

// The identity profile's scenario file (docs/fixed-root-identity.coverage.json) states each handle's case id and
// harness status and lists its tests. Keep it equal to what the tests declare: handle ID-NN is case C-id-NN, its
// "conformance" is covers/partial/pending as the scan finds it, and every test declaring the case is listed.
func TestIdentityCoverageFileMatchesHarness(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "docs", "fixed-root-identity.coverage.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := canon.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	ids, home, err := LoadCaseIDs(root)
	if err != nil {
		t.Fatal(err)
	}
	cov, part, _, err := ScanCoverage(root)
	if err != nil {
		t.Fatal(err)
	}
	str := func(o *canon.Object, k string) string {
		x, _ := o.Get(k)
		s, _ := x.(canon.String)
		return string(s)
	}
	top, _ := v.(*canon.Object)
	sv, _ := top.Get("scenarios")
	rows, _ := sv.(canon.Array)
	seen := map[string]bool{}
	for i, rv := range rows {
		row, _ := rv.(*canon.Object)
		handle, id := str(row, "handle"), str(row, "case")
		if !strings.HasPrefix(handle, "ID-") || id != "C-id-"+strings.TrimPrefix(handle, "ID-") {
			t.Errorf("row %d: handle %q, case %q", i, handle, id)
			continue
		}
		seen[id] = true
		if home[id] != "docs/DESIGN-notes-fixed-root-identity.md" {
			t.Errorf("%s is not defined in the identity profile note", id)
		}
		want := "pending"
		if len(cov[id]) > 0 {
			want = "covers"
		} else if len(part[id]) > 0 {
			want = "partial"
		}
		if got := str(row, "conformance"); got != want {
			t.Errorf("%s: coverage file says %q, the harness says %q", id, got, want)
		}
		listed := map[string]bool{}
		tv, _ := row.Get("isolated_tests")
		ta, _ := tv.(canon.Array)
		for _, x := range ta {
			s, _ := x.(canon.String)
			listed[strings.Replace(string(s), ":", ".", 1)] = true
		}
		var decl []string
		decl = append(decl, cov[id]...)
		for _, p := range part[id] {
			decl = append(decl, p[:strings.Index(p, ": ")])
		}
		for _, d := range decl {
			if !listed[d] {
				t.Errorf("%s: declared by %s, not listed in isolated_tests", id, d)
			}
		}
	}
	for _, id := range ids {
		if Profile(id) == "id" && !seen[id] {
			t.Errorf("%s has no row in the coverage file", id)
		}
	}
}
