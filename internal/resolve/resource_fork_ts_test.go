package resolve

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/wire"
)

// signAt is sign with an explicit signer timestamp, for the cases that vary it.
func (w *world) signAt(name, n, kind, ts string, body *canon.Object) string {
	k := w.key(n)
	s := w.seq[n]
	line, id := wire.Sign(wire.Draft{Kind: kind, Seq: s, Prev: w.head[n], TS: ts, Body: body}, k)
	w.head[n], w.seq[n] = id, s+1
	w.lines = append(w.lines, line)
	w.ids[name] = id
	w.by[id] = n
	if kind == "edition" {
		w.eid[id] = EditionID(body)
	}
	return id
}

// TestEditionForkIgnoresTimestamps: C-core-84. Two editions with one predecessor, by two controllers and by one
// controller twice, with their signer timestamps tied, skewed (one far before its own predecessor's) and reversed
// relative to file order: the resolver names a FORK over both editions, gives no tip, exits 3 on verify, and
// every delivery order renders the same display. Which edition carries the later timestamp changes nothing.
// The verify exit through the command is internal/cli TestResourceFork.
func TestEditionForkIgnoresTimestamps(t *testing.T) {
	conformance.Covers(t, "C-core-84")
	const (
		t0   = "2026-10-16T01:00:00Z"
		late = "2026-10-16T09:00:00Z"
		old  = "2020-01-01T00:00:00Z"
	)
	for _, c := range []struct{ name, l, r string }{
		{"tied", late, late},
		{"left later", late, t0},
		{"reversed", t0, late},
		{"skewed before its predecessor", t0, old},
		{"both skewed", old, old},
	} {
		for _, twice := range []bool{false, true} {
			t.Run(c.name, func(t *testing.T) {
				w := newWorld(t)
				g := w.genesis("G", "A", 0, "A", "B")
				e1 := w.edition("E1", "A", g, []string{g}, []string{"a"})
				other := "B"
				if twice {
					other = "A"
				}
				left := w.signAt("L", "A", "edition", c.l, w.editionBody(g, []string{e1}, []string{"a", "l"}))
				right := w.signAt("R", other, "edition", c.r, w.editionBody(g, []string{e1}, []string{"a", "r"}))
				everyOrder(t, w, g, func(res *Resource) {
					if res.Current != "" || res.VerifyExit() != 3 {
						t.Fatalf("current %q exit %d under a fork", res.Current, res.VerifyExit())
					}
					if len(res.Forks) != 1 || res.Forks[0].Cleared() || len(res.Forks[0].Branches) != 2 {
						t.Fatalf("forks %+v", res.Forks)
					}
					wantState(t, res, left, Authorized, "")
					wantState(t, res, right, Authorized, "")
					r := res.Render()
					if strings.Count(r, "FORK at") != 1 || !strings.Contains(r, "FORK at") {
						t.Fatalf("render must show one fork:\n%s", r)
					}
				})
			})
		}
	}
}
