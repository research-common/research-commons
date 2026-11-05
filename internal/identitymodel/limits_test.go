package identitymodel

import (
	"fmt"
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
	conformance.Partial(t, "C-id-39", "model half real (three evaluation caps, deterministic accounting, model_limit naming the cap); exit 3 needs a command")
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
