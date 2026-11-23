package specgraph

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
)

// ReportFormat names the layout of a conformance report. Like the graph it is outside every format freeze.
const ReportFormat = "conformance-report/0"

// Results of one test in a run, and of one case.
const (
	Pass   = "pass"
	Fail   = "fail"
	Skip   = "skip"
	NotRun = "not run"
)

// Run is what `go test -json` said about top-level tests, keyed "pkg/dir.TestName" as the Covers scan names
// them. Several streams may be read into one Run (the default build, then a tagged build): a test that failed
// in any stream failed; otherwise one that passed in any stream passed.
type Run struct {
	Results map[string]string
	Unread  []string // lines that are not test events (a build failure prints such lines)
	module  string
}

// NewRun starts an empty run for the module whose import path is module.
func NewRun(module string) *Run { return &Run{Results: map[string]string{}, module: module} }

// Read adds one `go test -json` stream.
func (r *Run) Read(in io.Reader) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		v, err := canon.ParseData(line)
		o, ok := v.(*canon.Object)
		if err != nil || !ok {
			r.Unread = append(r.Unread, clip(string(line)))
			continue
		}
		str := func(k string) string {
			x, _ := o.Get(k)
			s, _ := x.(canon.String)
			return string(s)
		}
		action, pkg, test := str("Action"), str("Package"), str("Test")
		if action == "fail" && test == "" && str("FailedBuild") != "" {
			r.Unread = append(r.Unread, "package "+pkg+" did not build")
		}
		if test == "" || strings.Contains(test, "/") {
			continue
		}
		if action != Pass && action != Fail && action != Skip {
			continue
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(pkg, r.module), "/")
		if rel == "" {
			rel = "."
		}
		key := rel + "." + test
		switch old := r.Results[key]; {
		case old == Fail || action == Fail:
			r.Results[key] = Fail
		case old == Pass || action == Pass:
			r.Results[key] = Pass
		default:
			r.Results[key] = Skip
		}
	}
	return sc.Err()
}

func clip(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// Meta is what the caller knows about the run and the report cannot find out.
type Meta struct {
	Revision string   // the commit under test
	Version  string   // the VERSION file
	Go       string   // the toolchain that ran the tests
	Platform string   // GOOS/GOARCH of the run
	Tags     []string // build tags of the streams read, besides the default build
}

// CaseResult is one case in a report.
type CaseResult struct {
	Case
	Result      string      // pass, fail, not run, partial or pending
	TestResults [][2]string // (test, result) for each declaring test
}

// Report joins the graph's cases with a run. A case passes when a test declares it covered and every test
// that declares it passed in the run. A declaring test that failed fails the case; one that was skipped or
// absent leaves it "not run". Partial and pending cases keep those words: no run can pass them.
type Report struct {
	Meta  Meta
	Cases []CaseResult
	Run   *Run
}

// NewReport computes each case's result.
func NewReport(g *Graph, run *Run, meta Meta) *Report {
	rep := &Report{Meta: meta, Run: run}
	for _, c := range g.Cases {
		cr := CaseResult{Case: c, Result: c.Status}
		if c.Status == "covered" {
			cr.Result = Pass
			for _, t := range c.Tests {
				res, ok := run.Results[t]
				if !ok {
					res = NotRun
				}
				cr.TestResults = append(cr.TestResults, [2]string{t, res})
				switch {
				case res == Fail:
					cr.Result = Fail
				case res != Pass && cr.Result != Fail:
					cr.Result = NotRun
				}
			}
		}
		rep.Cases = append(rep.Cases, cr)
	}
	return rep
}

// Count is the number of cases with each result, per profile and in all.
func (r *Report) Count() (per map[string]map[string]int, all map[string]int) {
	per, all = map[string]map[string]int{}, map[string]int{}
	for _, c := range r.Cases {
		if per[c.Profile] == nil {
			per[c.Profile] = map[string]int{}
		}
		per[c.Profile][c.Result]++
		per[c.Profile]["cases"]++
		all[c.Result]++
		all["cases"]++
	}
	return per, all
}

// Clean reports whether the run can stand as a record: no case failed and every line was a test event.
func (r *Report) Clean() bool {
	_, all := r.Count()
	return all[Fail] == 0 && len(r.Run.Unread) == 0
}

var resultOrder = []string{Pass, Fail, NotRun, "partial", "pending"}

func counts(m map[string]int) object {
	o := object{{"cases", m["cases"]}}
	for _, k := range resultOrder {
		o = append(o, member{strings.ReplaceAll(k, " ", "_"), m[k]})
	}
	return o
}

// JSON is the report's bytes.
func (r *Report) JSON() []byte {
	per, all := r.Count()
	var profiles, cases, notPassed []any
	names := make([]string, 0, len(per))
	for p := range per {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		profiles = append(profiles, append(object{{"profile", p}}, counts(per[p])...))
	}
	for _, c := range r.Cases {
		o := object{{"case", c.ID}, {"profile", c.Profile}, {"result", c.Result}}
		if len(c.TestResults) > 0 {
			var ts []any
			for _, t := range c.TestResults {
				ts = append(ts, object{{"test", t[0]}, {"result", t[1]}})
			}
			o = append(o, member{"tests", ts})
		}
		if len(c.Remaining) > 0 {
			o = append(o, member{"remaining", c.Remaining})
		}
		cases = append(cases, o)
		if c.Result != Pass {
			notPassed = append(notPassed, o)
		}
	}
	if notPassed == nil {
		notPassed = []any{}
	}
	return document(object{
		{"format", ReportFormat},
		{"about", "Conformance report of the reference implementation for one revision, written from a `go test -json` run by " +
			"go run ./internal/conformance/report. A case passes when a test declares it covered (conformance.Covers) and every " +
			"declaring test passed in this run. The declaration is a claim reviewed against the case, not a proof that the test " +
			"asserts the whole required outcome. This report does not hold the fixture digests, policy digest, evaluator context " +
			"or invocations that docs/CONFORMANCE.md asks a full record to carry."},
		{"revision", r.Meta.Revision},
		{"version", r.Meta.Version},
		{"go", r.Meta.Go},
		{"platform", r.Meta.Platform},
		{"build_tags", orEmpty(r.Meta.Tags)},
		{"total", counts(all)},
		{"profiles", profiles},
		{"not_passed", notPassed},
		{"unread_lines", orEmpty(r.Run.Unread)},
		{"cases", cases},
	})
}

// Summary is the few lines a person reads: the counts and every case that did not pass.
func (r *Report) Summary() string {
	per, all := r.Count()
	var b strings.Builder
	names := make([]string, 0, len(per))
	for p := range per {
		names = append(names, p)
	}
	sort.Strings(names)
	line := func(name string, m map[string]int) {
		fmt.Fprintf(&b, "%-9s %3d pass, %d fail, %d not run, %d partial, %d pending, of %d\n",
			name, m[Pass], m[Fail], m[NotRun], m["partial"], m["pending"], m["cases"])
	}
	for _, p := range names {
		line(p, per[p])
	}
	line("all", all)
	for _, c := range r.Cases {
		if c.Result == Pass {
			continue
		}
		fmt.Fprintf(&b, "%s: %s", c.ID, c.Result)
		for _, t := range c.TestResults {
			if t[1] != Pass {
				fmt.Fprintf(&b, " [%s: %s]", t[0], t[1])
			}
		}
		b.WriteString("\n")
	}
	for _, u := range r.Run.Unread {
		b.WriteString("not a test event: " + u + "\n")
	}
	return b.String()
}
