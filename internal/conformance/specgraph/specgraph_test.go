package specgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

func build(t *testing.T) (*Graph, string) {
	t.Helper()
	root, err := conformance.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	g, problems, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	return g, root
}

// TestSpecGraphFile: docs/spec-graph.json is the graph the tree generates. RC_UPDATE_DOCS=1 rewrites it.
func TestSpecGraphFile(t *testing.T) {
	g, root := build(t)
	want := g.JSON()
	if _, err := canon.ParseData(want); err != nil {
		t.Fatalf("the generated graph is not JSON the strict reader accepts: %v", err)
	}
	p := filepath.Join(root, filepath.FromSlash(GraphFile))
	if os.Getenv("RC_UPDATE_DOCS") == "1" {
		if err := os.WriteFile(p, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != string(want) {
		t.Fatalf("%s is not the generated graph; run RC_UPDATE_DOCS=1 go test -run TestSpecGraphFile ./internal/conformance/specgraph", GraphFile)
	}
}

// TestSpecGraphReadsEveryTable: the graph reads a pin column and a required outcome for the tables that have
// them, so a renamed column cannot silently empty the graph.
func TestSpecGraphReadsEveryTable(t *testing.T) {
	g, _ := build(t)
	pinned := map[string]int{}
	total := map[string]int{}
	outcome := 0
	for _, c := range g.Cases {
		total[c.DefinedIn]++
		if len(c.Pins) > 0 {
			pinned[c.DefinedIn]++
		}
		if len(c.Tokens)+len(c.Exits) > 0 {
			outcome++
		}
		for _, test := range c.Tests {
			if i := strings.LastIndex(test, "."); !strings.HasPrefix(test[i+1:], "Test") {
				t.Errorf("%s is declared by %s, which is not a test function: a report cannot find its result", c.ID, test)
			}
		}
	}
	// The bitcoin-time note's table has no pin column: its cases are listed without pins.
	for _, doc := range []string{"docs/CONFORMANCE.md", "docs/DESIGN-notes-fixed-root-identity.md"} {
		if pinned[doc] != total[doc] || total[doc] == 0 {
			t.Errorf("%s: %d of %d cases have a pin", doc, pinned[doc], total[doc])
		}
	}
	// Many outcomes are prose with no token in code marks; a quarter is far below today's count and far above zero.
	if outcome < len(g.Cases)/4 {
		t.Errorf("only %d of %d required outcomes name a token or an exit code; the outcome column is no longer read", outcome, len(g.Cases))
	}
}

func TestCaseTables(t *testing.T) {
	doc := "| id | note | scenario | required outcome |\n|---|---|---|---|\n" +
		"| C-core-01 | §2, I4 | s | `contested`, exit 3 |\n\ntext\n\n" +
		"| Id | Scenario | Required outcome |\n|---|---|---|\n| C-btc-07 | s | exits 1 |\n\n" +
		"| C-core-02 | orphan row | x | y |\n"
	rows := caseTables([]byte(doc))
	if r := rows["C-core-01"]; r.pins != "§2, I4" || r.outcome != "`contested`, exit 3" {
		t.Errorf("C-core-01 = %+v", r)
	}
	if r := rows["C-btc-07"]; r.pins != "" || r.outcome != "exits 1" {
		t.Errorf("C-btc-07 = %+v", r)
	}
	if r, ok := rows["C-core-02"]; !ok || r.pins != "" {
		t.Errorf("a row under no header is kept without columns; got %+v, %v", r, ok)
	}
}

const events = `{"Action":"pass","Package":"example.org/m/internal/a","Test":"TestOne"}
{"Action":"pass","Package":"example.org/m/internal/a","Test":"TestOne/sub"}
{"Action":"fail","Package":"example.org/m/internal/a","Test":"TestTwo"}
{"Action":"skip","Package":"example.org/m/internal/b","Test":"TestThree"}
{"Action":"output","Package":"example.org/m/internal/b","Test":"TestThree","Output":"x\n"}
{"Action":"pass","Package":"example.org/m/internal/b"}
`

func TestReport(t *testing.T) {
	g := &Graph{Cases: []Case{
		{ID: "C-core-01", Profile: "core", Status: "covered", Tests: []string{"internal/a.TestOne"}},
		{ID: "C-core-02", Profile: "core", Status: "covered", Tests: []string{"internal/a.TestOne", "internal/a.TestTwo"}},
		{ID: "C-core-03", Profile: "core", Status: "covered", Tests: []string{"internal/a.TestOne", "internal/b.TestThree"}},
		{ID: "C-core-04", Profile: "core", Status: "covered", Tests: []string{"internal/c.TestAbsent"}},
		{ID: "C-exec-01", Profile: "exec", Status: "partial", Remaining: []string{"internal/a.TestOne: the rest"}},
		{ID: "C-exec-02", Profile: "exec", Status: "pending"},
	}}
	run := NewRun("example.org/m")
	if err := run.Read(strings.NewReader(events)); err != nil {
		t.Fatal(err)
	}
	rep := NewReport(g, run, Meta{Revision: "abc"})
	want := []string{Pass, Fail, NotRun, NotRun, "partial", "pending"}
	for i, c := range rep.Cases {
		if c.Result != want[i] {
			t.Errorf("%s: %s, want %s", c.ID, c.Result, want[i])
		}
	}
	if rep.Clean() {
		t.Error("a report with a failed case reads clean")
	}
	// A test skipped in one stream and passed in another (a tagged build) passed; a failure is never undone.
	if err := run.Read(strings.NewReader(`{"Action":"pass","Package":"example.org/m/internal/b","Test":"TestThree"}` + "\n" +
		`{"Action":"pass","Package":"example.org/m/internal/a","Test":"TestTwo"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	rep = NewReport(g, run, Meta{Revision: "abc"})
	if rep.Cases[2].Result != Pass || rep.Cases[1].Result != Fail {
		t.Errorf("after the second stream: %s, %s", rep.Cases[2].Result, rep.Cases[1].Result)
	}
	v, err := canon.ParseData(rep.JSON())
	if err != nil {
		t.Fatalf("the report is not JSON the strict reader accepts: %v", err)
	}
	np, _ := v.(*canon.Object).Get("not_passed")
	if len(np.(canon.Array)) != 4 {
		t.Errorf("not_passed lists %d cases, want 4", len(np.(canon.Array)))
	}
	// A line that is not a test event (a compiler message) makes the run unusable as a record.
	run = NewRun("example.org/m")
	run.Read(strings.NewReader("# example.org/m/internal/a\n" + `{"Action":"pass","Package":"example.org/m/internal/a","Test":"TestOne"}` + "\n"))
	g.Cases = g.Cases[:1]
	if rep = NewReport(g, run, Meta{}); rep.Clean() || rep.Cases[0].Result != Pass {
		t.Errorf("unread line: clean=%v result=%s", rep.Clean(), rep.Cases[0].Result)
	}
}
