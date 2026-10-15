package dag

import (
	"reflect"
	"testing"
)

func g(edges ...string) map[string][]string {
	// "B<A" = B has predecessor A; "A" alone = a root.
	m := map[string][]string{}
	for _, e := range edges {
		n, p := e, ""
		for i := range e {
			if e[i] == '<' {
				n, p = e[:i], e[i+1:]
			}
		}
		if _, ok := m[n]; !ok {
			m[n] = nil
		}
		if p != "" {
			m[n] = append(m[n], p)
		}
	}
	return m
}

func TestForks(t *testing.T) {
	for _, c := range []struct {
		name  string
		graph map[string][]string
		want  []Fork
	}{
		{"chain", g("P", "Q<P", "R<Q"), nil},
		{"fork", g("P", "L<P", "S<P"),
			[]Fork{{At: "P", Branches: []string{"L", "S"}, Tips: []string{"L", "S"}}}},
		{"following one branch does not clear", g("P", "L<P", "S<P", "N<S"),
			[]Fork{{At: "P", Branches: []string{"L", "S"}, Tips: []string{"L", "N"}}}},
		{"merge clears", g("P", "L<P", "S<P", "M<S", "M<L"),
			[]Fork{{At: "P", Branches: []string{"L", "S"}, Tips: []string{"M"}, Cleared: true, ClearedBy: []string{"M"}}}},
		{"three-way, one merged", g("P", "A<P", "B<P", "C<P", "M<A", "M<B"),
			[]Fork{{At: "P", Branches: []string{"A", "B", "C"}, Tips: []string{"C", "M"}}}},
		{"cleared, then a branch continues: a new fork at the merged line",
			g("P", "L<P", "S<P", "M<S", "M<L", "L2<L"),
			[]Fork{
				{At: "L", Branches: []string{"L2", "M"}, Tips: []string{"L2", "M"}},
				{At: "P", Branches: []string{"L", "S"}, Tips: []string{"L2", "M"}, Cleared: true, ClearedBy: []string{"M"}},
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
	if got := Tips(g("P", "L<P", "S<P", "M<S", "M<L")); !reflect.DeepEqual(got, []string{"M"}) {
		t.Fatal(got)
	}
}
