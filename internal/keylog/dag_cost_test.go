package keylog

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/dag"
	"github.com/research-common/research-commons/internal/wire"
)

// These are already-read statements: signing and parsing are not part of View.
// Consecutive diamonds expose repeated graph preparation even though every fork
// clears immediately and the total span output is linear.
func diamondLog(n int) *Log {
	s := NewStore()
	l := s.Log("key")
	add := func(id, prev string, seq int64, merges ...string) {
		l.lines[id] = &wire.Statement{ID: id, Signer: "key", Kind: "holds", Status: wire.Valid, Verified: true, Prev: prev, Seq: seq, Merges: merges}
		s.owner[id] = "key"
	}
	add("root", "", 0)
	prev := "root"
	for i := 0; i < n; i++ {
		a, b, m := fmt.Sprintf("a%06d", i), fmt.Sprintf("b%06d", i), fmt.Sprintf("m%06d", i)
		add(a, prev, int64(2*i+1))
		add(b, prev, int64(2*i+1))
		add(m, a, int64(2*i+2), b)
		prev = m
	}
	return l
}

func TestLogDAGCost(t *testing.T) {
	if testing.Short() {
		t.Skip("cost measurement")
	}
	t.Run("successive cleared forks", func(t *testing.T) {
		build := func(n int) func() {
			l := diamondLog(n)
			return func() {
				v := l.View()
				if len(v.Forks) != n || len(v.Spans) != n {
					t.Fatal("lost forks")
				}
				for i, f := range v.Forks {
					if !f.Cleared() || len(f.Tips) != 1 || len(v.Spans[i]) != 3 {
						t.Fatal("wrong diamond", f)
					}
				}
			}
		}
		logCostRatio(t, build(100), build(800))
	})
	t.Run("membership in a long open span", func(t *testing.T) {
		build := func(n int) func() {
			span := make([]string, n)
			for i := range span {
				span[i] = fmt.Sprintf("%08d", i)
			}
			v := View{Forks: []dag.Fork{{At: "root"}}, Spans: [][]string{span}}
			return func() {
				for _, id := range span {
					if len(v.ForksOn(id)) != 1 {
						t.Fatal("missing membership")
					}
				}
				if len(v.ForksOn("missing")) != 0 {
					t.Fatal("unexpected membership")
				}
			}
		}
		logCostRatio(t, build(1000), build(8000))
	})
}

func TestSharedForkSpans(t *testing.T) {
	v := diamondLog(5).View()
	g := make(map[string]dag.Node)
	for _, ln := range v.Lines {
		var nd dag.Node
		if ln.St.Prev != "" {
			nd.Branch = []string{ln.St.Prev}
		}
		nd.Join = ln.St.Merges
		g[ln.St.ID] = nd
	}
	for i, f := range v.Forks {
		if !slices.Equal(v.Spans[i], dag.Span(g, f)) {
			t.Fatalf("span %d differs", i)
		}
		for _, id := range v.Spans[i] {
			if len(v.ForksOn(id)) == 0 {
				t.Fatalf("missing %s", id)
			}
		}
	}
}

func logCostRatio(t *testing.T, small, large func()) {
	t.Helper()
	best := func(f func()) time.Duration {
		d := time.Duration(1<<63 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			f()
			d = min(d, time.Since(start))
		}
		return d
	}
	for attempt := 0; attempt < 3; attempt++ {
		s, l := best(small), best(large)
		t.Logf("8x size: %s vs %s, ratio %.2f", l, s, float64(l)/float64(s))
		if l <= 20*s {
			return
		}
	}
	t.Fatal("eight times the input took more than twenty times the work")
}

// denseEventView is a wide fork repeatedly merged by one chain, with an event
// at the root. KeyState must mark every other line after that event.
func denseEventView(n, m int) View {
	v := View{Key: "key"}
	add := func(id, prev string, seq int64, merges []string) {
		v.Lines = append(v.Lines, Line{State: Chained, St: &wire.Statement{ID: id, Signer: "key", Kind: "holds", Verified: true, Status: wire.Valid, Seq: seq, Prev: prev, Merges: merges}})
	}
	add("root", "", 0, nil)
	v.Lines[0].St.Kind = "revoke_key"
	v.Lines[0].St.Body = obj("reason", "superseded")
	forks := make([]string, n)
	for i := range forks {
		forks[i] = fmt.Sprintf("f%06d", i)
		add(forks[i], "root", 1, nil)
	}
	prev := forks[0]
	for i := 0; i < m; i++ {
		id := fmt.Sprintf("m%06d", i)
		add(id, prev, int64(i+2), forks[1:])
		prev = id
	}
	return v
}

func BenchmarkDenseKeyEvents(b *testing.B) {
	for _, size := range [][2]int{{40, 100}, {40, 800}, {900, 1300}} {
		b.Run(fmt.Sprintf("%d-forks-%d-merges", size[0], size[1]), func(b *testing.B) {
			v := denseEventView(size[0], size[1])
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				v.KeyState()
			}
		})
	}
}

func TestKeyEventReachabilityMatchesWalk(t *testing.T) {
	v := diamondLog(80).View()
	for i := range v.Lines {
		// Enough events to cross several word boundaries, on sibling branches
		// as well as merged continuations. Detached events never seed ancestry.
		if i%2 == 0 {
			v.Lines[i].St.Kind = "revoke_key"
			v.Lines[i].St.Body = obj("reason", "superseded")
		}
		if i%17 == 0 {
			v.Lines[i].State = Detached
		}
	}
	chained := map[string]*wire.Statement{}
	for _, ln := range v.Lines {
		if ln.State == Chained {
			chained[ln.St.ID] = ln.St
		}
	}
	want := map[string][]string{}
	for id := range chained {
		for a := range ancestorsOf(id, chained) {
			if _, ok := keyEvent(chained[a]); ok {
				want[id] = append(want[id], a)
			}
		}
		if len(want[id]) > 0 {
			slices.Sort(want[id])
		}
	}
	if got := v.KeyState().After; !reflect.DeepEqual(got, want) {
		t.Fatal("event ancestry differs from the original walk")
	}
}

func TestDenseKeyEventCost(t *testing.T) {
	if testing.Short() {
		t.Skip("cost measurement")
	}
	build := func(m int) func() {
		v := denseEventView(40, m)
		return func() {
			ks := v.KeyState()
			if len(ks.After) != len(v.Lines)-1 {
				t.Fatal("missing event descendants")
			}
		}
	}
	logCostRatio(t, build(100), build(800))
}

// Removing the first line makes the same dense log detached. Gap explanations
// are a separate, still walk-based path; keep a reproducible residual benchmark.
func BenchmarkDetachedDenseView(b *testing.B) {
	for _, m := range []int{100, 800} {
		b.Run(fmt.Sprintf("40-forks-%d-merges", m), func(b *testing.B) {
			v := denseEventView(40, m)
			s := NewStore()
			l := s.Log("key")
			for _, ln := range v.Lines[1:] {
				l.lines[ln.St.ID] = ln.St
				s.owner[ln.St.ID] = "key"
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				l.View()
			}
		})
	}
}
