package keylog

import (
	"fmt"
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
