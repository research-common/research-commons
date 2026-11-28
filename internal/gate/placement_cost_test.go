package gate

import (
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/dag"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// TestPlacementCostIsLinear isolates placement lookup from signatures, IO and rendering, which
// can mask a repeated scan in an end-to-end command. Constructing the lookup is part of the timer.
func TestPlacementCostIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("cost comparison")
	}
	for _, shape := range []string{"lines", "refusals", "fork"} {
		t.Run(shape, func(t *testing.T) {
			build := func(n int) func() {
				v := keylog.View{}
				statements := make([]*wire.Statement, n)
				for i := range statements {
					st := &wire.Statement{ID: fmt.Sprintf("%064x", i), Status: wire.Valid}
					statements[i] = st
					switch shape {
					case "lines":
						v.Lines = append(v.Lines, keylog.Line{St: st, State: keylog.Chained})
					case "refusals":
						v.Refused = append(v.Refused, keylog.Refused{St: st, Reason: &refusal.Refusal{Detail: "test"}})
					case "fork":
						if i == 0 {
							v.Forks = append(v.Forks, dag.Fork{At: "root"})
						}
						v.Forks[0].Branches = append(v.Forks[0].Branches, st.ID)
					}
				}
				return func() {
					indexed := indexPlacement(v)
					for _, st := range statements {
						r := Result{ID: st.ID, st: st}
						if indexed.refused[r.ID] == nil {
							placeLabels(&r, indexed)
						}
					}
				}
			}
			small, large := build(2000), build(16000)
			best := func(f func()) time.Duration {
				runtime.GC()
				var d time.Duration
				for i := 0; i < 3; i++ {
					start := time.Now()
					f()
					x := time.Since(start)
					if d == 0 || x < d {
						d = x
					}
				}
				return d
			}
			for attempt := 0; attempt < 3; attempt++ {
				a, b := best(small), best(large)
				ratio := float64(b) / float64(a)
				t.Logf("2000=%s 16000=%s ratio=%.2f", a, b, ratio)
				if ratio <= 20 {
					return
				}
			}
			t.Fatal("placement lookup is not linear in the view")
		})
	}
}

// The index must preserve the former walk's exact labels, their order, refusal pointers,
// and the first open fork when a statement occurs in more than one fork.
func TestPlacementIndexMatchesWalk(t *testing.T) {
	v := keylog.View{}
	var statements []*wire.Statement
	for i := 0; i < 40; i++ {
		st := &wire.Statement{ID: fmt.Sprintf("%064x", i), Status: []wire.Status{wire.Valid, wire.Invalid, wire.UnknownKind, wire.Unsupported}[i%4], Why: "detail"}
		if i%3 == 0 {
			st.Unpinned = []string{"a", "b"}
		}
		statements = append(statements, st)
		if i%5 == 0 {
			v.Refused = append(v.Refused, keylog.Refused{St: st, Reason: &refusal.Refusal{Detail: fmt.Sprint(i)}})
		}
		if i%7 != 0 {
			v.Lines = append(v.Lines, keylog.Line{St: st, State: []keylog.State{keylog.Chained, keylog.Detached}[i%2], Incoherent: i%3 == 0, Waiting: keylog.Gap{HasSeq: true, FromSeq: 1, ToSeq: 3, IDs: []string{"absent"}}})
		}
	}
	v.Forks = []dag.Fork{{At: "cleared", Branches: []string{statements[1].ID}, ClearedBy: "merged"}, {At: "first", Branches: []string{statements[1].ID, statements[2].ID}, Tips: []string{statements[3].ID}}, {At: "second", Branches: []string{statements[1].ID, statements[4].ID}}}
	idx := indexPlacement(v)
	for _, st := range statements {
		var wantRefusal *refusal.Refusal
		for _, x := range v.Refused {
			if x.St.ID == st.ID {
				wantRefusal = x.Reason
				break
			}
		}
		if idx.refused[st.ID] != wantRefusal {
			t.Fatal("refusal changed")
		}
		got, want := Result{ID: st.ID, st: st}, Result{ID: st.ID, st: st}
		placeLabels(&got, idx)
		scanPlaceLabels(&want, v)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("placement changed: got %+v want %+v", got, want)
		}
	}
}

func scanPlaceLabels(r *Result, v keylog.View) {
	st := r.st
	for _, ln := range v.Lines {
		if ln.St.ID != st.ID {
			continue
		}
		if ln.State == keylog.Detached {
			r.label(LabelDetached, "waiting for "+gapText(ln.Waiting))
		}
		if ln.Incoherent {
			r.label(LabelIncoherent, "ts earlier than its predecessor's")
		}
	}
	for _, f := range v.Forks {
		if f.ClearedBy == "" && (slices.Contains(f.Branches, st.ID) || slices.Contains(f.Tips, st.ID)) {
			r.label(LabelFork, "at "+keylog.Short(f.At))
			break
		}
	}
	switch st.Status {
	case wire.Unsupported:
		r.label(LabelUnsupported, st.Why)
	case wire.UnknownKind:
		r.label(LabelUnknownKind, st.Why)
	case wire.Invalid:
		r.label(LabelInvalid, st.Why)
	}
	// Schema-level pins only: a method edition's system_keys declaration (a missing declared key is unpinned too)
	// is read by the resolver from the authorized edition the observation pins. The gate resolves no editions,
	// and that unpinned is the reader's computation over what it holds, not an intrinsic property of the line.
	if len(st.Unpinned) > 0 {
		r.label(LabelUnpinned, strings.Join(st.Unpinned, ","))
	}
}
