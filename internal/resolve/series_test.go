package resolve

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
)

// fakeSegments is the reader's re-check of segments, by member key (a stand-in for re-reading the source).
type fakeSegments map[string]SegmentState

func (f fakeSegments) Segment(m *Member) SegmentState {
	if s, ok := f[m.Key]; ok {
		return s
	}
	return RecordSegments{}.Segment(m)
}

func day(d string) Boundary { return Boundary{Unit: "date", Date: d} }

// sourceSegment signs a source-class observation of blob x carrying a finality rule (rule false leaves it out).
func (w *world) sourceSegment(name, n, x string, withRule bool) string {
	ref := obj("endpoint", "https://api.example/settlement", "parameters", obj("period", x), "response_digest", dig(x))
	var kv []any
	if withRule {
		kv = append(kv, "finality", obj("rule", "settlement run >= RF", "state_at_capture", obj("run", "SF")))
	}
	return w.observedRef(name, n, x, "source", ref, kv...)
}

func segs(ids ...string) canon.Array {
	a := canon.Array{}
	for _, id := range ids {
		a = append(a, Entry("statement", id, "segment"))
	}
	return a
}

// seriesWorld: a series of five monthly segments, Jan–Mar final, Apr and May provisional: the members' rules
// compute final to 2025-04-01 with 2 segments provisional (the numbers of C-core-101).
func seriesWorld(t *testing.T) (*world, string, []string, fakeSegments) {
	w := newWorld(t)
	g := w.sign("G", "A", "genesis", obj("type", "series", "name", "settlements", "controllers", w.controllers("A"), "rule", obj("any_one", true)))
	months := []string{"01", "02", "03", "04", "05"}
	var ids []string
	f := fakeSegments{}
	for i, m := range months {
		id := w.sourceSegment("S"+m, "O", "2025-"+m, true)
		ids = append(ids, id)
		final := "final"
		if i >= 3 {
			final = "provisional"
		}
		f[id] = SegmentState{From: day("2025-" + m + "-01"), Rule: true, Final: final}
	}
	return w, g, ids, f
}

// TestSeriesDeclaredBesideComputed: C-core-101. The edition declares frozen_before 2025-06-01; the members'
// rules compute final to 2025-04-01 (April and May provisional). Both are shown, the declared one flagged; the
// declared one is never substituted for the computed one or derived from it. Variant: a height declared while
// the members compute a date is `not comparable`, never converted.
func TestSeriesDeclaredBesideComputed(t *testing.T) {
	conformance.Covers(t, "C-core-101")
	w, g, ids, f := seriesWorld(t)
	w.editionWith("E1", "A", g, []string{g}, "members", segs(ids...), "frozen_before", obj("date", "2025-06-01"))
	s, ok := w.store(nil, WithSegments(f)).Series(g, "")
	if !ok {
		t.Fatal("no series view")
	}
	if got, want := s.Line(), "frozen_before 2025-06-01 (declared) · members final to 2025-04-01 (2 segments provisional) · FLAGGED: declared later than computed"; got != want {
		t.Fatalf("line\n%s\nwant\n%s", got, want)
	}
	if s.Comparison != "flagged" || s.Declared != day("2025-06-01") || s.Computed != day("2025-04-01") || s.Provisional != 2 {
		t.Fatalf("%+v", s)
	}
	// control: a declaration at or before the computed boundary is not flagged
	w.editionWith("E2", "A", g, []string{w.ids["E1"]}, "members", segs(ids...), "frozen_before", obj("date", "2025-03-15"))
	s, _ = w.store(nil, WithSegments(f)).Series(g, "")
	if s.Comparison != "agrees" || strings.Contains(s.Line(), "FLAGGED") || s.Computed != day("2025-04-01") {
		t.Fatalf("control: %s", s.Line())
	}
	// variant: height vs date
	w.editionWith("E3", "A", g, []string{w.ids["E2"]}, "members", segs(ids...), "frozen_before", obj("height", 900000))
	s, _ = w.store(nil, WithSegments(f)).Series(g, "")
	if s.Comparison != "not comparable" || !strings.Contains(s.Line(), "frozen_before height 900000 (declared) · members final to 2025-04-01") ||
		!strings.Contains(s.Render(), "not converted") {
		t.Fatalf("variant: %s", s.Render())
	}
}

// TestSeriesNoRule: C-core-102. Segments carry no finality rule: the computed boundary is `unchecked`, and the
// declared value is still shown. The default reader (no re-check configured) gives the same, and so does a
// re-check that reports the segments final: with no rule, "final" has nothing to be final under.
func TestSeriesNoRule(t *testing.T) {
	conformance.Covers(t, "C-core-102")
	w := newWorld(t)
	g := w.sign("G", "A", "genesis", obj("type", "series", "name", "s", "controllers", w.controllers("A"), "rule", obj("any_one", true)))
	a := w.sourceSegment("S1", "O", "2025-01", false)
	b := w.sourceSegment("S2", "O", "2025-02", false)
	w.editionWith("E1", "A", g, []string{g}, "members", segs(a, b), "frozen_before", obj("date", "2025-02-01"))
	for _, opts := range [][]Option{nil, {WithSegments(fakeSegments{a: {From: day("2025-01-01"), Final: "final"}, b: {From: day("2025-02-01"), Final: "final"}})}} {
		s, _ := w.store(nil, opts...).Series(g, "")
		if s.ComputedState != "unchecked" || s.Comparison != "unchecked" || s.Line() != "frozen_before 2025-02-01 (declared) · members' finality unchecked" {
			t.Fatalf("%s", s.Render())
		}
		has(t, s.Render(), "carries no finality rule")
	}
	// one segment with a rule (re-checked final) and one without: still unchecked
	c := w.sourceSegment("S3", "O", "2025-03", true)
	w.editionWith("E2", "A", g, []string{w.ids["E1"]}, "members", segs(a, c), "frozen_before", obj("date", "2025-02-01"))
	mixed := fakeSegments{a: {From: day("2025-01-01"), Final: "final"}, c: {From: day("2025-03-01"), Rule: true, Final: "final"}}
	if s, _ := w.store(nil, WithSegments(mixed)).Series(g, ""); s.ComputedState != "unchecked" {
		t.Fatalf("mixed: %s", s.Render())
	}
	// with a rule but no re-check configured: still unchecked, never final
	w2, g2, ids, _ := seriesWorld(t)
	w2.editionWith("E1", "A", g2, []string{g2}, "members", segs(ids...), "frozen_before", obj("date", "2025-02-01"))
	s, _ := w2.store(nil).Series(g2, "")
	if s.ComputedState != "unchecked" {
		t.Fatalf("no re-check: %s", s.Render())
	}
}

// TestRevisedFrozen: C-core-103. Edition n declares frozen_before 2025-04-01; edition n+1 replaces the March
// segment. Edition n stays resolvable with its original segment, nothing is removed, and n+1 is shown
// REVISED-FROZEN. Control: edition n+2 replaces a segment after the boundary (May) and is not.
func TestRevisedFrozen(t *testing.T) {
	conformance.Covers(t, "C-core-103")
	w, g, ids, f := seriesWorld(t)
	en := w.editionWith("En", "A", g, []string{g}, "members", segs(ids...), "frozen_before", obj("date", "2025-04-01"))
	march2 := w.sourceSegment("S03b", "O", "2025-03b", true)
	f[march2] = SegmentState{From: day("2025-03-01"), Rule: true, Final: "final"}
	revised := append(append([]string{}, ids[:2]...), march2)
	revised = append(revised, ids[3:]...)
	en1 := w.editionWith("En1", "A", g, []string{en}, "members", segs(revised...), "frozen_before", obj("date", "2025-04-01"))
	may2 := w.sourceSegment("S05b", "O", "2025-05b", true)
	f[may2] = SegmentState{From: day("2025-05-01"), Rule: true, Final: "provisional"}
	later := append(append([]string{}, revised[:4]...), may2)
	en2 := w.editionWith("En2", "A", g, []string{en1}, "members", segs(later...), "frozen_before", obj("date", "2025-04-01"))
	everyOrderSeries(t, w, g, f, func(s *Series) {
		if _, ok := s.Revised[w.ed(en1)]; !ok || len(s.Revised) != 1 {
			t.Fatalf("revisions %v\n%s", s.Revised, s.Render())
		}
		got := s.Revised[w.ed(en1)]
		if len(got) != 2 || !strings.Contains(strings.Join(got, ","), ids[2]) || !strings.Contains(strings.Join(got, ","), march2) {
			t.Fatalf("En1 rewrites %v", got)
		}
		has(t, s.Render(), RevisedFrozen+" "+shortMember(w.ed(en1)))
		hasNot(t, s.Render(), RevisedFrozen+" "+shortMember(w.ed(en2)))
	})
	r := w.store(nil, WithSegments(f))
	old, ok := r.Series(g, w.ed(en))
	if !ok || len(old.Segments) != 5 || old.Segments[2].Member != ids[2] {
		t.Fatalf("edition n not resolvable with its original segment: %+v", old)
	}
	res, _ := r.Resource(g)
	if len(res.Editions) != 3 || editionOf(t, res, en).State != Authorized {
		t.Fatalf("an edition was removed or demoted:\n%s", res.Render())
	}
}

func everyOrderSeries(t *testing.T, w *world, g string, f fakeSegments, check func(*Series)) {
	t.Helper()
	var first string
	for _, o := range append([][]int{nil}, sampleOrders(len(w.lines), 103, 24)...) {
		s, ok := w.store(o, WithSegments(f)).Series(g, "")
		if !ok {
			t.Fatal("no series")
		}
		check(s)
		if out := s.Render(); first == "" {
			first = out
		} else if out != first {
			t.Fatalf("order changed the answer:\n%s\nvs\n%s", out, first)
		}
	}
}

// TestPrematureFreeze: C-core-104, the resolver half (hub CI applying the policy at push is hubcheck's
// TestPrematureFreeze, which declares the case). A reader (hub) whose policy requires declared ≤ computed refuses the series
// of C-core-101 under reader policy, scope this series edition. The edition stays authorized and current in
// every reader's resource view, and a reader without the policy endorses nothing less.
func TestPrematureFreeze(t *testing.T) {
	w, g, ids, f := seriesWorld(t)
	e1 := w.editionWith("E1", "A", g, []string{g}, "members", segs(ids...), "frozen_before", obj("date", "2025-06-01"))
	r := w.store(nil, WithSegments(f))
	s, rf := r.EndorseSeries(g, w.ed(e1), RequireDeclaredNotAfterComputed{})
	if rf == nil || rf.Class != refusal.Policy || rf.Reason != PrematureFreeze || !strings.Contains(rf.Detail, "scope series edition "+shortMember(w.ed(e1))) {
		t.Fatalf("%v", rf)
	}
	if s == nil || s.Comparison != "flagged" {
		t.Fatal("the refusal did not come from the comparison")
	}
	res, _ := r.Resource(g)
	if res.Current != w.ed(e1) || editionOf(t, res, e1).State != Authorized {
		t.Fatalf("the refused edition is not a valid edition:\n%s", res.Render())
	}
	if _, rf := r.EndorseSeries(g, w.ed(e1), nil); rf != nil {
		t.Fatalf("no policy: %v", rf)
	}
	// control: a declaration the members support is endorsed under the same policy
	e2 := w.editionWith("E2", "A", g, []string{e1}, "members", segs(ids...), "frozen_before", obj("date", "2025-04-01"))
	if _, rf := w.store(nil, WithSegments(f)).EndorseSeries(g, w.ed(e2), RequireDeclaredNotAfterComputed{}); rf != nil {
		t.Fatalf("control: %v", rf)
	}
}
