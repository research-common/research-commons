package identitymodel

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/conformance"
)

// scaled builds the fixture plus rootEvents authenticated root events (alternating
// independent inert branches off G and a linear root history) and a linear delegate
// history of delegateEdges data statements after Z. It returns the snapshot and the
// delegate head.
func scaled(t testing.TB, rootEvents, delegateEdges int) (*Snapshot, ID) {
	fs := fixture()
	prev := ID("G")
	for n := 0; n < rootEvents; n++ {
		if n%2 == 0 {
			fs = append(fs, line(ID(fmt.Sprintf("root-branch-%06d", n)), "R", 2, "G", Inert))
			continue
		}
		id := ID(fmt.Sprintf("root-line-%06d", n))
		fs = append(fs, line(id, "R", uint64(n/2+2), prev, Inert))
		prev = id
	}
	head := ID("Z")
	for n := 0; n < delegateEdges; n++ {
		id := ID(fmt.Sprintf("work-%06d", n))
		fs = append(fs, data(id, uint64(n+5), head))
		head = id
	}
	s, err := NewSnapshot(fs)
	if err != nil {
		t.Fatal(err)
	}
	return s, head
}

// At the profile's default caps, a root with far more than 2,048 relevant events and a
// worker with a long linear history are eligible, not unknown (the old 2,048-fact cap
// made such an identity a permanent brick). The memoized walk keeps the work linear.
func TestDefaultCapsAdmitLongLivedIdentity(t *testing.T) {
	conformance.Partial(t, "C-id-39", "model half real (three evaluation caps, deterministic accounting, model_limit naming the cap); exit 3 is end to end through the commands in internal/cli (identity_reader_test.go)")
	s, head := scaled(t, 6000, 5000)
	start := time.Now()
	r, stats := s.evaluate(head, DefaultLimits())
	if r.Status != Eligible {
		t.Fatalf("status %s %+v", r.Status, r.Reasons)
	}
	if r2 := s.Evaluate("A"); r2.Status != Eligible {
		t.Fatalf("early statement: %s %+v", r2.Status, r2.Reasons)
	}
	t.Logf("6000 root events + 5000-edge delegate path: %d dependencies, %d inspections, %v",
		stats.Dependencies, stats.Inspections, time.Since(start))
	// Linear, not quadratic: a small constant number of inspections per fact read.
	if stats.Inspections > 12*stats.Dependencies {
		t.Fatalf("inspections %d not linear in %d dependencies", stats.Inspections, stats.Dependencies)
	}
	// Same evidence, same limits: the same answer and the same accounting.
	r3, stats3 := s.Clone().evaluate(head, DefaultLimits())
	if r3.Status != r.Status || stats3 != stats {
		t.Fatalf("not deterministic: %+v vs %+v", stats3, stats)
	}
}

// The caps are reached by the evidence's shape, not a traversal order: the same
// evidence under the same limits gives the same result whatever the delivery order.
func TestCapHitIsDeliveryOrderIndependent(t *testing.T) {
	s, head := scaled(t, 300, 300)
	lim := Limits{Dependencies: 400}
	want := s.EvaluateWith(head, lim)
	if want.Status != Unknown || !hasReason(want, "model_limit") {
		t.Fatalf("cap not reached: %s %+v", want.Status, want.Reasons)
	}
	fs := make([]Fact, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- {
		fs = append(fs, s.facts[s.order[i]])
		fs = append(fs, s.facts[s.order[i]]) // and every fact delivered twice
	}
	got := snapshot(t, fs).EvaluateWith(head, lim)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("delivery order changed a capped result:\n%+v\n%+v", got, want)
	}
}

func BenchmarkEvaluateDefaultCaps(b *testing.B) {
	for _, size := range []struct{ root, delegate int }{{2000, 2000}, {6000, 5000}, {40000, 40000}} {
		s, head := scaled(b, size.root, size.delegate)
		b.Run(fmt.Sprintf("root%d_delegate%d", size.root, size.delegate), func(b *testing.B) {
			var stats Stats
			for b.Loop() {
				var r Result
				r, stats = s.evaluate(head, DefaultLimits())
				if r.Status != Eligible {
					b.Fatalf("%s %+v", r.Status, r.Reasons[:min(3, len(r.Reasons))])
				}
			}
			b.ReportMetric(float64(stats.Inspections), "inspections")
			b.ReportMetric(float64(stats.Dependencies), "deps")
		})
	}
}

// Which facts a query spends its budget on (profile §7). Facts by other keys are never read: 400 lines by an
// unrelated key Q leave I eligible under a tight cap. The root's own facts are read whether or not they turn out
// relevant (the root scan reads every R fact before placing it), so a rival inception by R with inert events
// under it can exhaust the dependency cap for I; the delegate's own log is inspected in full, so bare seq-0 lines
// by K can exhaust the inspection cap. Both fail closed, and only R or K can author them.
func TestBudgetIsSpentOnlyOnTheRootsAndDelegatesOwnFacts(t *testing.T) {
	stranger := fixture()
	for n := 0; n < 400; n++ {
		stranger = append(stranger, line(ID(fmt.Sprintf("q-%03d", n)), "Q", 0, "", Inert))
	}
	if r := snapshot(t, stranger).EvaluateWith("Z", Limits{Dependencies: 64, Inspections: 300}); r.Status != Eligible {
		t.Fatalf("another key's facts spent I's budget: %s %+v", r.Status, r.Reasons)
	}

	rival := fixture()
	ri := line("rival-I", "R", 0, "", IdentityInception)
	ri.Inception = &Inception{Profile: FixedRoot}
	rival = append(rival, ri)
	prev := ID("rival-I")
	for n := 0; n < 80; n++ {
		id := ID(fmt.Sprintf("rival-%03d", n))
		rival = append(rival, line(id, "R", uint64(n+1), prev, Inert))
		prev = id
	}
	s := snapshot(t, rival)
	if r := s.Evaluate("Z"); r.Status != Eligible {
		t.Fatalf("rival inception at default caps: %s %+v", r.Status, r.Reasons)
	}
	if r := s.EvaluateWith("Z", Limits{Dependencies: 64}); r.Status != Unknown || !limitNamed(r, LimitDependencies) {
		t.Fatalf("R's rival lineage under a 64-dependency cap: %s %+v", r.Status, r.Reasons)
	}

	bare := fixture()
	for n := 0; n < 400; n++ {
		bare = append(bare, line(ID(fmt.Sprintf("k-bare-%03d", n)), "K", 0, "", Inert))
	}
	s = snapshot(t, bare)
	if r := s.Evaluate("Z"); r.Status != Eligible {
		t.Fatalf("bare K lines at default caps: %s %+v", r.Status, r.Reasons)
	}
	if r := s.EvaluateWith("Z", Limits{Inspections: 300}); r.Status != Unknown || !limitNamed(r, LimitInspections) {
		t.Fatalf("K's bare lines under a 300-inspection cap: %s %+v", r.Status, r.Reasons)
	}
}

// "The dependency cap binds first" holds on linear histories only (profile §7). At the default caps, a delegate
// chain of 6,000 statements each merging 200 earlier ones reaches the inspection cap while far under the
// dependency cap (the shape from the profile's first outside review).
func TestMergeDenseLogReachesInspectionsFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("6,000 × 200 merges")
	}
	fs := fixture()
	head := ID("Z")
	var earlier []ID
	for n := 0; n < 6000; n++ {
		id := ID(fmt.Sprintf("w-%05d", n))
		f := data(id, uint64(n+5), head)
		if len(earlier) > 200 {
			f.Merges = slices.Clone(earlier[len(earlier)-201 : len(earlier)-1])
		}
		fs = append(fs, f)
		earlier = append(earlier, id)
		head = id
	}
	r, stats := snapshot(t, fs).evaluate(head, DefaultLimits())
	if r.Status != Unknown || !limitNamed(r, LimitInspections) || stats.Dependencies >= DefaultMaxDependencies {
		t.Fatalf("%s %+v (%d dependencies)", r.Status, r.Reasons, stats.Dependencies)
	}
	t.Logf("merge-dense: inspection cap reached at %d dependencies", stats.Dependencies)
}

func limitNamed(r Result, name string) bool {
	for _, x := range r.Reasons {
		if x.Code == "model_limit" && strings.Contains(x.Detail, name) {
			return true
		}
	}
	return false
}
