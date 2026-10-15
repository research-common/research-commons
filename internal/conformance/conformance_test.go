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
)

// TestConformanceCases makes every case in CONFORMANCE.md a subtest. Covered cases pass and name their
// tests; the rest are skipped as pending. `go test -run TestConformanceCases -v ./internal/conformance` is the
// progress report.
func TestConformanceCases(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join(root, "docs", "CONFORMANCE.md"))
	if err != nil {
		t.Fatal(err)
	}
	ids, err := CaseIDs(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) < 200 {
		t.Fatalf("found only %d case rows in CONFORMANCE.md; the row pattern no longer matches the document", len(ids))
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
			t.Errorf("Covers(%q) in %v names a case CONFORMANCE.md does not define", id, cov[id])
		}
	}
	for _, id := range SortedKeys(part) {
		if !known[id] {
			t.Errorf("Partial(%q) in %v names a case CONFORMANCE.md does not define", id, part[id])
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
}

func TestVectorsLoad(t *testing.T) {
	v, err := LoadVectors()
	if err != nil {
		t.Fatal(err)
	}
	// Counts as published in wire-format note §9; a change to the file must change this test on purpose.
	if len(v.Positive) != 10 || len(v.Negative) != 13 || len(v.EdPositive) != 2 || len(v.EdNegative) != 13 {
		t.Fatalf("vectors: %d positive, %d negative, %d ed25519 positive, %d ed25519 negative",
			len(v.Positive), len(v.Negative), len(v.EdPositive), len(v.EdNegative))
	}
}
