package conformance

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// workflowTags is the build tags the workflow text runs `go test` under: the argument of every `-tags` (or
// `-tags=`) on a `go test` line that is not a comment, split on commas. Plain text: the workflow is not parsed
// as YAML (the module takes no YAML dependency).
func workflowTags(text string) []string {
	re := regexp.MustCompile(`(?:^|\s)-tags(?:=|\s+)["']?([A-Za-z0-9_.,]+)["']?`)
	var tags []string
	for _, l := range strings.Split(text, "\n") {
		t := strings.TrimSpace(l)
		t = strings.TrimSpace(strings.TrimPrefix(t, "- "))
		// a comment or a step/job label is prose, not a command: only a command line runs tests
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, "name:") || !strings.Contains(t, "go test") {
			continue
		}
		if c := strings.Index(t, " #"); c >= 0 {
			t = t[:c]
		}
		for _, m := range re.FindAllStringSubmatch(t, -1) {
			for _, tag := range strings.Split(m[1], ",") {
				if tag != "" && !slices.Contains(tags, tag) {
					tags = append(tags, tag)
				}
			}
		}
	}
	slices.Sort(tags)
	return tags
}

// diffCITags names every disagreement between the allow-list and the workflow, in both directions.
func diffCITags(listed, inWorkflow []string) []string {
	var out []string
	for _, t := range listed {
		if !slices.Contains(inWorkflow, t) {
			out = append(out, "ci-tags.txt lists "+t+" but no `go test -tags "+t+"` runs in the workflow: its tests are counted as run and are not")
		}
	}
	for _, t := range inWorkflow {
		if !slices.Contains(listed, t) {
			out = append(out, "the workflow runs `go test -tags "+t+"` but ci-tags.txt does not list it: the scan reports its tests as never run")
		}
	}
	return out
}

// TestCITagsMatchWorkflow keeps internal/conformance/ci-tags.txt and .github/workflows/go.yml in agreement:
// a tag the scan counts as run must be run by a job, and a tag a job runs must be counted.
func TestCITagsMatchWorkflow(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	listed, err := LoadCITags(root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "go.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) == 0 {
		t.Fatal("ci-tags.txt lists no tag (or is missing): the OCI sandbox tests are counted through it")
	}
	for _, p := range diffCITags(listed, workflowTags(string(b))) {
		t.Error(p)
	}
}

// The comparison fails in both directions, and reads the workflow the way the job writes it. This is the
// mutation check for TestCITagsMatchWorkflow: the real files with the tag dropped from the list, and with the
// job's `go test` line dropped from the workflow, both disagree.
func TestCITagsDiffReachesBothDirections(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	listed, err := LoadCITags(root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "go.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if d := diffCITags(listed, workflowTags(text)); len(d) != 0 {
		t.Fatalf("precondition: the real files disagree: %v", d)
	}
	if d := diffCITags(nil, workflowTags(text)); len(d) == 0 || !strings.Contains(d[0], "does not list it") {
		t.Errorf("tag dropped from the list: %v", d)
	}
	// the job dropped: its whole `test-sandbox-oci` block (up to the next job) is gone, not just a line
	i := strings.Index(text, "  test-sandbox-oci:")
	j := strings.Index(text[i+1:], "\n  python:")
	if i < 0 || j < 0 {
		t.Fatal("the workflow has no test-sandbox-oci job followed by the python job")
	}
	kept := []string{text[:i] + text[i+1+j+1:]}
	if d := diffCITags(listed, workflowTags(strings.Join(kept, "\n"))); len(d) == 0 || !strings.Contains(d[0], "no `go test -tags") {
		t.Errorf("job dropped from the workflow: %v", d)
	}
	for _, c := range []struct {
		name, text string
		want       []string
	}{
		{"flag form", "run: go test -tags sandbox_oci ./...", []string{"sandbox_oci"}},
		{"equals form", "go test -tags=a ./...", []string{"a"}},
		{"comma list", "go test -tags a,b ./...", []string{"a", "b"}},
		{"quoted", `go test -tags "a" ./...`, []string{"a"}},
		{"step name ignored", "      - name: go test -tags a\n", nil},
		{"list item command", "      - run: go test -tags a ./...", []string{"a"}},
		{"comment ignored", "# go test -tags a ./...\n", nil},
		{"trailing comment ignored", "go test ./... # was -tags a\n", nil},
		{"build is not test", "go build -tags a ./...", nil},
		{"no tags", "go test ./...", nil},
	} {
		if got := workflowTags(c.text); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// A tag on the allow-list makes a file whose build expression it satisfies count as run; a tag not on the list,
// or an expression that needs a tag that is not, does not. The allow-list is read from the root by ScanCoverage.
func TestScanCountsCITags(t *testing.T) {
	dir := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	src := func(header, id string) string {
		return header + "package p\n\nimport (\n\t\"testing\"\n\n\t\"github.com/research-common/research-commons/internal/conformance\"\n)\n\nfunc TestX(t *testing.T) {\n\tconformance.Covers(t, \"" + id + "\")\n}\n"
	}
	host := runtime.GOOS
	write("a/a_test.go", src("//go:build rc_a\n\n", "C-x-1"))
	write("b/a_test.go", src("//go:build rc_b\n\n", "C-x-2"))
	write("c/a_test.go", src("//go:build "+host+" && (rc_a || rc_c)\n\n", "C-x-3"))
	write("d/a_test.go", src("//go:build rc_a && rc_b\n\n", "C-x-4"))
	write("e/a_test.go", src("//go:build !rc_a\n\n", "C-x-5"))
	write("internal/conformance/ci-tags.txt", "# header\n\nrc_a  # trailing comment\n")

	cov, part, problems, err := ScanCoverage(dir)
	if err != nil || len(problems) != 0 {
		t.Fatalf("scan: %v %v", err, problems)
	}
	for _, id := range []string{"C-x-1", "C-x-3"} {
		if len(cov[id]) != 1 {
			t.Errorf("%s: its expression is true under rc_a; covers %v, partial %v", id, cov[id], part[id])
		}
	}
	for id, want := range map[string]string{
		"C-x-2": "covered only under build tag rc_b",
		"C-x-4": "covered only under build tag rc_b",
		"C-x-5": "covered only under build constraint !rc_a",
	} {
		if len(cov[id]) != 0 || len(part[id]) != 1 || !strings.Contains(part[id][0], want) {
			t.Errorf("%s: want a partial saying %q; covers %v, partial %v", id, want, cov[id], part[id])
		}
	}
	// the mutation: with the list empty the same files are all partial (the allow-list is what moved C-x-1)
	cov, part, _, err = ScanCoverageTags(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cov["C-x-1"]) != 0 || len(part["C-x-1"]) != 1 || !strings.Contains(part["C-x-1"][0], "covered only under build tag rc_a") {
		t.Errorf("C-x-1 with no CI tags: covers %v, partial %v", cov["C-x-1"], part["C-x-1"])
	}
}

func TestLoadCITagsRejectsNonTags(t *testing.T) {
	for _, bad := range []string{"a b\n", "!a\n", "a && b\n", "-tags a\n"} {
		dir := t.TempDir()
		p := filepath.Join(dir, filepath.FromSlash(CITagsFile))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(bad), 0o644)
		if tags, err := LoadCITags(dir); err == nil {
			t.Errorf("%q accepted as %v", bad, tags)
		}
	}
	if tags, err := LoadCITags(t.TempDir()); err != nil || len(tags) != 0 {
		t.Errorf("a missing file is an empty list: %v %v", tags, err)
	}
}
