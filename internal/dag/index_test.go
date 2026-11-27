package dag

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"
)

// denseLog models forks at one sequence followed by a chain of merges that
// repeatedly names those same forks. Most of its links are redundant.
func denseLog(n, m int) map[string]Node {
	g := map[string]Node{"root": {}}
	forks := make([]string, n)
	for i := range forks {
		forks[i] = fmt.Sprintf("f%05d", i)
		g[forks[i]] = Node{Branch: []string{"root"}}
	}
	prev := forks[0]
	for i := 0; i < m; i++ {
		id := fmt.Sprintf("m%05d", i)
		g[id] = Node{Branch: []string{prev}, Join: forks[1:]}
		prev = id
	}
	return g
}

func TestIndexedDAGAgreesWithOriginal(t *testing.T) {
	r := rand.New(rand.NewPCG(9182, 716))
	for trial := 0; trial < 800; trial++ {
		g := map[string]Node{}
		for n := 0; n < 2+r.IntN(24); n++ {
			var nd Node
			for edge := 0; edge < r.IntN(9); edge++ {
				p := "missing"
				if n > 0 && r.IntN(5) != 0 {
					p = fmt.Sprint(r.IntN(n))
				}
				if r.IntN(2) == 0 {
					nd.Branch = append(nd.Branch, p)
				} else {
					nd.Join = append(nd.Join, p)
				}
			}
			g[fmt.Sprint(n)] = nd
		}
		checkOriginal(t, g)
	}
	for _, g := range []map[string]Node{
		denseLog(12, 17),
		g("R", "A<R", "B<R", "C+A+B", "D+C", "E+C", "F+D+E"),
		g("A<A", "B<A", "C<A"),
		g("A<B", "B<A", "C<A", "D<A"),
		g("", "A", "B"),
	} {
		checkOriginal(t, g)
	}
}

func checkOriginal(t *testing.T, g map[string]Node) {
	t.Helper()
	if got, want := reduce(g), oldReduce(g); !reflect.DeepEqual(got, want) {
		t.Fatalf("reduction differs for %#v:\ngot %#v\nwant %#v", g, got, want)
	}
	fs, spans := ForksAndSpans(g)
	wantForks := oldForks(g)
	// The old cyclic path chooses by map iteration between equally early
	// candidates in one strongly connected component. Compare that choice's
	// equivalence class, but require exact clearing IDs on every DAG.
	if len(fs) == len(wantForks) {
		reduced := oldReduce(g)
		for i, f := range fs {
			w := wantForks[i].ClearedBy
			if f.ClearedBy != w && f.ClearedBy != "" && w != "" {
				a, b := oldAncestors(f.ClearedBy, reduced), oldAncestors(w, reduced)
				if a[w] && b[f.ClearedBy] && len(a) == len(b) {
					wantForks[i].ClearedBy = f.ClearedBy
				}
			}
		}
	}
	if !reflect.DeepEqual(fs, wantForks) {
		t.Fatalf("forks differ for %#v:\ngot %#v\nwant %#v", g, fs, wantForks)
	}
	if got, want := Tips(g), oldTips(g); !reflect.DeepEqual(got, want) {
		t.Fatalf("tips differ: %v != %v", got, want)
	}
	for i, f := range fs {
		want := oldSpan(g, f)
		if got := Span(g, f); !reflect.DeepEqual(got, want) {
			t.Fatalf("span differs: %v != %v", got, want)
		}
		if !reflect.DeepEqual(spans[i], want) {
			t.Fatalf("shared span differs: %v != %v", spans[i], want)
		}
	}
}

// Scaling merge lines by eight scales the input's links by eight, not by 64.
// Use the existing cost-test convention: allow 2.5 times the linear ratio.
func TestDenseDAGCostIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("cost measurement")
	}
	measure := func(g map[string]Node) time.Duration {
		best := time.Duration(1<<63 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			fs, spans := ForksAndSpans(g)
			elapsed := time.Since(start)
			if len(fs) != 1 || len(spans[0]) != 41 {
				t.Fatalf("unexpected fork result: %v", fs)
			}
			best = min(best, elapsed)
		}
		return best
	}
	small, large := measure(denseLog(40, 100)), measure(denseLog(40, 800))
	t.Logf("100 merges: %s; 800 merges: %s; ratio %.2f", small, large, float64(large)/float64(small))
	if large > 20*small {
		t.Fatalf("eight times the merge links took %.2f times as long", float64(large)/float64(small))
	}
}

func BenchmarkDenseDAG(b *testing.B) {
	for _, size := range [][2]int{{100, 100}, {200, 200}, {20, 2000}, {900, 1300}} {
		b.Run(fmt.Sprintf("%d-forks-%d-merges", size[0], size[1]), func(b *testing.B) {
			g := denseLog(size[0], size[1])
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ForksAndSpans(g)
			}
		})
	}
}

func BenchmarkOriginalDenseDAG(b *testing.B) {
	for _, size := range [][2]int{{40, 100}, {40, 800}, {100, 100}, {200, 200}, {20, 2000}} {
		b.Run(fmt.Sprintf("%d-forks-%d-merges", size[0], size[1]), func(b *testing.B) {
			g := denseLog(size[0], size[1])
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				oldForks(g)
			}
		})
	}
}
