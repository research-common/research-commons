package dag

import (
	"reflect"
	"strings"
	"testing"
)

// g builds a graph from edges: "B<A" = B branches from A (a log's prev, an edition's predecessor);
// "B+A" = B joins A (a log line's merges entry); "A" alone = a root.
func g(edges ...string) map[string]Node {
	m := map[string]Node{}
	for _, e := range edges {
		if i := strings.IndexAny(e, "<+"); i >= 0 {
			n, p := e[:i], e[i+1:]
			nd := m[n]
			if e[i] == '<' {
				nd.Branch = append(nd.Branch, p)
			} else {
				nd.Join = append(nd.Join, p)
			}
			m[n] = nd
		} else if _, ok := m[e]; !ok {
			m[e] = Node{}
		}
	}
	return m
}

func TestForks(t *testing.T) {
	for _, c := range []struct {
		name  string
		graph map[string]Node
		want  []Fork
	}{
		{"chain", g("P", "Q<P", "R<Q"), nil},
		{"fork", g("P", "L<P", "S<P"),
			[]Fork{{At: "P", Branches: []string{"L", "S"}, Tips: []string{"L", "S"}}}},
		{"following one branch does not clear", g("P", "L<P", "S<P", "N<S"),
			[]Fork{{At: "P", Branches: []string{"L", "S"}, Tips: []string{"L", "N"}}}},
		{"merge clears", g("P", "L<P", "S<P", "M<S", "M+L"),
			[]Fork{{At: "P", Branches: []string{"L", "S"}, Tips: []string{"M"}, ClearedBy: "M"}}},
		{"three-way, one merged", g("P", "A<P", "B<P", "C<P", "M<A", "M+B"),
			[]Fork{{At: "P", Branches: []string{"A", "B", "C"}, Tips: []string{"C", "M"}}}},
		// The merge absorbed L1 but not L2, which continues L1: two heads remain, so the fork at P is open,
		// and no fork is drawn at L1 (merges is not a branch).
		{"merging an inner line of a branch whose continuation escapes", g("P", "L1<P", "L2<L1", "S<P", "M<S", "M+L1"),
			[]Fork{{At: "P", Branches: []string{"L1", "S"}, Tips: []string{"L2", "M"}}}},
		{"same, with the continuation merged later", g("P", "L1<P", "L2<L1", "S<P", "M<S", "M+L1", "N<M", "N+L2"),
			[]Fork{{At: "P", Branches: []string{"L1", "S"}, Tips: []string{"N"}, ClearedBy: "N"}}},
		// A new fork below the clearing line is its own fork point and does not reopen the first.
		{"fork after a clear", g("P", "L<P", "S<P", "M<S", "M+L", "X<M", "Y<M"),
			[]Fork{
				{At: "M", Branches: []string{"X", "Y"}, Tips: []string{"X", "Y"}},
				{At: "P", Branches: []string{"L", "S"}, Tips: []string{"X", "Y"}, ClearedBy: "M"},
			}},
		{"merging an ancestor of prev adds nothing", g("P", "Q<P", "R<Q", "R+P"), nil},
		{"edition naming a predecessor and its ancestor", g("P", "Q<P", "R<Q", "R<P"), nil},
		// Editions: every predecessor is a branching link, so a merge edition and a continuation of one
		// branch are two editions with the same predecessor.
		{"edition merge with a branch continued", g("P", "L<P", "S<P", "M<S", "M<L", "L2<L"),
			[]Fork{
				{At: "L", Branches: []string{"L2", "M"}, Tips: []string{"L2", "M"}},
				{At: "P", Branches: []string{"L", "S"}, Tips: []string{"L2", "M"}},
			}},
		{"two roots", g("A", "B"), []Fork{{At: "", Branches: []string{"A", "B"}, Tips: []string{"A", "B"}}}},
		{"unheld predecessor ignored", g("A<X"), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := Forks(c.graph); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestTips(t *testing.T) {
	if got := Tips(g("P", "L<P", "S<P", "M<S", "M+L")); !reflect.DeepEqual(got, []string{"M"}) {
		t.Fatal(got)
	}
}
