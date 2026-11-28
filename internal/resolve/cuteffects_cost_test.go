package resolve

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/identity"
)

func TestCutEffectsMatchesWalk(t *testing.T) {
	w := newCtrlWorld(t, "KEY")
	var cuts []string
	for i := 0; i < 8; i++ {
		x := fmt.Sprint(i)
		g := w.genesis2("g"+x, "GEN", 1, "I")
		grant := w.grant("grant"+x, "KEY", g, "edition")
		b := body2(g, []string{g}, obj("members", canon.Array{}))
		approval := w.approve("a"+x, "KEY", b, grant)
		w.approve("b"+x, "KEY", b, grant)
		last := canon.Value(canon.Null{})
		if i%2 == 1 {
			last = canon.String(approval)
		}
		cuts = append(cuts, w.signRC2("cut"+x, "IR", "identity_cut", obj("identity", w.I, "grant", grant, "last_good", last, "reason", "key_compromise"), rc2MarkerOnly, [2]string{}))
	}
	actors, err := identity.NewActors(w.lines)
	if err != nil {
		t.Fatal(err)
	}
	logs := dualStore()
	if n := deliverAll(logs, w.lines); n != 0 {
		t.Fatalf("%d refused", n)
	}
	r := New(logs, WithActorEligibility(actors))
	nonempty := 0
	for _, cut := range append(cuts, "not-held") {
		want := scanCutEffects(r, cut)
		got := r.CutEffects(cut)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("cut %s: got %+v want %+v", cut, got, want)
		}
		if len(got) > 0 {
			nonempty++
			got[0].Resource = "changed"
			got[0].Editions[0] = "changed"
			if !reflect.DeepEqual(r.CutEffects(cut), want) {
				t.Fatal("caller mutated the cached disclosure")
			}
		}
	}
	if nonempty == 0 {
		t.Fatal("no excluded editions reached")
	}
}

// The slow oracle is the original implementation, retained to check every field and ordering.
func scanCutEffects(r *Resolver, cut string) []CutEffect {
	var out []CutEffect
	for _, g := range r.byKind["genesis"] {
		res, ok := r.Resource(g.St.ID)
		if !ok {
			continue
		}
		e := CutEffect{Resource: res.ID, Current: res.Current}
		for _, x := range res.CutExcluded {
			if slices.Contains(x.Cuts, cut) && !slices.Contains(e.Editions, x.Edition) {
				e.Editions = append(e.Editions, x.Edition)
			}
		}
		if len(e.Editions) > 0 {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b CutEffect) int { return strings.Compare(a.Resource, b.Resource) })
	return out
}

// Isolate the repeated resource walk from the identity evaluator: even cuts with no affected
// resource must not rescan the entire store per query. Include a cold index build each time.
func TestCutEffectsCostIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("cost comparison")
	}
	shape := costShape{"cut queries over unrelated resources", func(t *testing.T, n int) func() {
		w := newWorld(t)
		for i := 0; i < n; i++ {
			w.genesis(fmt.Sprint(i), "KEY", 0, "KEY")
		}
		base := w.store(nil)
		return func() {
			r := New(base.logs)
			for i := 0; i < n; i++ {
				if len(r.CutEffects(fmt.Sprint(i))) != 0 {
					t.Fatal("unexpected effect")
				}
			}
		}
	}}
	wantLinear(t, 8, shape.build(t, 64), shape.build(t, 512))
}
