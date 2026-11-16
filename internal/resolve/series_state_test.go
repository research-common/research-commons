package resolve

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
)

// TestSeriesComparisonIsTyped: C-core-132 below the CLI. The series boundary comparison is one of its own closed
// set (agrees, flagged, not comparable, unchecked), never the rule triple's `ok`/`fail`, and every state carries a
// `why` in the tool's words. Each state is reached: flagged and agrees on a computed boundary, not comparable
// across units, unchecked with no declaration, with no rule, with no segments, and the bounded-above case where a
// declaration later than the bound is flagged and an earlier one stays unchecked.
func TestSeriesComparisonIsTyped(t *testing.T) {
	conformance.Partial(t, "C-core-132", "the series boundary comparison is its own closed set with a why (this test); printed as a typed member by the CLI (TestSeriesBoundaryIsTyped)")
	closed := []string{SeriesAgrees, SeriesFlagged, SeriesNotComparable, SeriesUnchecked}
	if slices.Contains(closed, "ok") || slices.Contains(closed, "fail") {
		t.Fatal("the comparison's set is not the rule triple")
	}
	w, g, ids, f := seriesWorld(t)
	seen := map[string]bool{}
	check := func(name string, s *Series, want, whyHas string) {
		t.Helper()
		if s == nil {
			t.Fatalf("%s: no series view", name)
		}
		if s.Comparison != want || !slices.Contains(closed, s.Comparison) {
			t.Fatalf("%s: comparison %q, want %q\n%s", name, s.Comparison, want, s.Render())
		}
		if s.ComparisonWhy == "" || !strings.Contains(s.ComparisonWhy, whyHas) {
			t.Fatalf("%s: why %q lacks %q", name, s.ComparisonWhy, whyHas)
		}
		seen[s.Comparison] = true
	}
	prev := g
	next := func(name string, extra ...any) *Series {
		w.editionWith(name, "A", g, []string{prev}, append([]any{"members", segs(ids...)}, extra...)...)
		prev = w.ids[name]
		s, _ := w.store(nil, WithSegments(f)).Series(g, "")
		return s
	}
	check("flagged", next("E1", "frozen_before", obj("date", "2025-06-01")), SeriesFlagged, "later than")
	check("agrees", next("E2", "frozen_before", obj("date", "2025-03-15")), SeriesAgrees, "no later than")
	check("not comparable", next("E3", "frozen_before", obj("height", 900000)), SeriesNotComparable, "never converted")
	check("undeclared", next("E4"), SeriesUnchecked, "no frozen_before")
	// the human line keeps its meaning: it reads the state, it does not replace it
	w.editionWith("E5", "A", g, []string{prev}, "members", segs(ids...), "frozen_before", obj("date", "2025-06-01"))
	s, _ := w.store(nil, WithSegments(f)).Series(g, "")
	if !strings.Contains(s.Line(), "FLAGGED: declared later than computed") {
		t.Fatalf("line: %s", s.Line())
	}
	// no re-check at all (the default reader): the boundary is unchecked, never agreeing, however late the declaration
	s, _ = w.store(nil).Series(g, "")
	check("no re-check", s, SeriesUnchecked, "could not be checked")
	if !strings.Contains(s.ComparisonWhy, NotRechecked) {
		t.Fatalf("no re-check: why %q does not name the shipped reason", s.ComparisonWhy)
	}
	// the bounded-above case: one segment's state cannot be placed; a declaration later than the earliest provisional
	// segment is flagged whatever that segment's state, an earlier one is not decided
	bounded := fakeSegments{}
	for id, st := range f {
		bounded[id] = st
	}
	bounded[ids[0]] = SegmentState{From: day("2025-01-01"), Rule: true, Final: "unchecked", Why: "state not in profile"}
	bounded[ids[len(ids)-1]] = SegmentState{From: day("2025-05-01"), Rule: true, Final: "provisional"}
	w.editionWith("E6", "A", g, []string{w.ids["E5"]}, "members", segs(ids...), "frozen_before", obj("date", "2025-12-01"))
	s, _ = w.store(nil, WithSegments(bounded)).Series(g, "")
	if s.Bound.Unit == "" {
		t.Fatalf("no bound reached:\n%s", s.Render())
	}
	check("bounded, later", s, SeriesFlagged, "bound")
	w.editionWith("E7", "A", g, []string{w.ids["E6"]}, "members", segs(ids...), "frozen_before", obj("date", "2025-01-15"))
	s, _ = w.store(nil, WithSegments(bounded)).Series(g, "")
	check("bounded, earlier", s, SeriesUnchecked, "bounded above")
	for _, c := range closed {
		if !seen[c] {
			t.Errorf("state %q was not reached", c)
		}
	}
	// no segments at all
	w2 := newWorld(t)
	g2 := w2.sign("G", "A", "genesis", obj("type", "series", "name", "s", "controllers", w2.controllers("A"), "rule", obj("any_one", true)))
	w2.editionWith("E1", "A", g2, []string{g2}, "members", segs(), "frozen_before", obj("date", "2025-02-01"))
	s, _ = w2.store(nil).Series(g2, "")
	check("no segments", s, SeriesUnchecked, "no segments")
}
