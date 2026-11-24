package conformance

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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

// The identity profiles' scenario files (docs/fixed-root-identity.coverage.json, docs/recoverable-root-identity.coverage.json)
// state each handle's case id and harness status and list its tests. Keep each equal to what the tests declare:
// handle ID-NN is case C-id-NN and handle RR-NN is case C-id-(45+NN), each defined in its own note; a row's
// "conformance" is covers/partial/pending as the scan finds it; every test declaring the case is listed; and every
// `id` case has a row in one of the files.
func TestIdentityCoverageFileMatchesHarness(t *testing.T) {
	root, err := RepoRoot()
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
	seen := map[string]bool{}
	for _, f := range []struct {
		file, prefix, note string
		offset             int
	}{
		{"fixed-root-identity.coverage.json", "ID-", "docs/DESIGN-notes-fixed-root-identity.md", 0},
		{"recoverable-root-identity.coverage.json", "RR-", "docs/DESIGN-notes-recoverable-root-identity.md", 45},
	} {
		raw, err := os.ReadFile(filepath.Join(root, "docs", f.file))
		if err != nil {
			t.Fatal(err)
		}
		v, err := canon.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		top, _ := v.(*canon.Object)
		sv, _ := top.Get("scenarios")
		rows, _ := sv.(canon.Array)
		for i, rv := range rows {
			row, _ := rv.(*canon.Object)
			handle, id := str(row, "handle"), str(row, "case")
			n, err := strconv.Atoi(strings.TrimPrefix(handle, f.prefix))
			if !strings.HasPrefix(handle, f.prefix) || err != nil || id != "C-id-"+fmt.Sprintf("%02d", n+f.offset) {
				t.Errorf("%s row %d: handle %q, case %q", f.file, i, handle, id)
				continue
			}
			seen[id] = true
			if home[id] != f.note {
				t.Errorf("%s is not defined in %s", id, f.note)
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
	}
	for _, id := range ids {
		if Profile(id) == "id" && !seen[id] {
			t.Errorf("%s has no row in a coverage file", id)
		}
	}
}

// A Covers in a test file the default build excludes is never run by `go test ./...`: the scan records it as a
// partial that says so, and a file the default build compiles still covers. Constraints: a tag nobody sets, a
// negated host tag, a tag that is satisfied (the host's GOOS), and an expression mixing them.
func TestScanHonoursBuildConstraints(t *testing.T) {
	dir := t.TempDir()
	write := func(sub, name, header, decl string) {
		t.Helper()
		d := filepath.Join(dir, sub)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		src := header + "package p\n\nimport (\n\t\"testing\"\n\n\t\"github.com/research-common/research-commons/internal/conformance\"\n)\n\nfunc " +
			"TestX(t *testing.T) {\n\t" + decl + "\n}\n"
		if err := os.WriteFile(filepath.Join(d, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	host := runtime.GOOS
	write("plain", "a_test.go", "", `conformance.Covers(t, "C-x-1")`)
	write("tagged", "a_test.go", "//go:build sandbox_oci\n\n", `conformance.Covers(t, "C-x-2")`)
	write("hostok", "a_test.go", "//go:build "+host+"\n\n", `conformance.Covers(t, "C-x-3")`)
	write("nothost", "a_test.go", "//go:build !"+host+"\n\n", `conformance.Covers(t, "C-x-4")`)
	write("mixed", "a_test.go", "//go:build "+host+" && (rc_a || rc_b)\n\n", `conformance.Covers(t, "C-x-5")`)
	write("partial", "a_test.go", "//go:build sandbox_oci\n\n", `conformance.Partial(t, "C-x-6", "the rest")`)
	cov, part, problems, err := ScanCoverage(dir)
	if err != nil || len(problems) != 0 {
		t.Fatalf("scan: %v %v", err, problems)
	}
	for _, id := range []string{"C-x-1", "C-x-3"} {
		if len(cov[id]) != 1 {
			t.Errorf("%s: a file the default build compiles must cover; covers %v, partial %v", id, cov[id], part[id])
		}
	}
	for id, want := range map[string]string{
		"C-x-2": "covered only under build tag sandbox_oci",
		"C-x-4": "covered only under build constraint !" + host,
		"C-x-5": "covered only under build tag rc_a, rc_b",
		"C-x-6": "the default build excludes: build tag sandbox_oci",
	} {
		if len(cov[id]) != 0 || len(part[id]) != 1 || !strings.Contains(part[id][0], want) {
			t.Errorf("%s: want a partial saying %q; covers %v, partial %v", id, want, cov[id], part[id])
		}
	}
}

// The tagged OCI backend tests claim C-exec-10..12. Under the default build alone (no tags) they are partial,
// never covered (F16 of the stage-3 review); they count only because CI runs the tag (ci-tags.txt, kept in step
// with the workflow by TestCITagsMatchWorkflow).
func TestTaggedCoverageIsNotCounted(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	cov, part, _, err := ScanCoverageTags(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"C-exec-10", "C-exec-11", "C-exec-12"} {
		for _, by := range cov[id] {
			if strings.Contains(by, "TestOCI") {
				t.Errorf("%s is counted as covered by %s, a test in a file only `-tags sandbox_oci` builds, with no CI tag listed", id, by)
			}
		}
		if len(part[id]) == 0 {
			t.Errorf("%s has no partial: the tagged test's declaration was dropped", id)
		}
	}
	// with the CI tag listed (as it is in ci-tags.txt), the same declarations are covered and no longer partial
	cov, part, _, err = ScanCoverage(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"C-exec-10", "C-exec-11", "C-exec-12"} {
		if !slices.ContainsFunc(cov[id], func(by string) bool { return strings.Contains(by, "TestOCI") }) {
			t.Errorf("%s is not covered by its OCI test although ci-tags.txt lists the tag: covers %v, partial %v", id, cov[id], part[id])
		}
		for _, p := range part[id] {
			if strings.Contains(p, "covered only under build tag") {
				t.Errorf("%s still reads %q with the tag listed", id, p)
			}
		}
	}
}
