package resolve

import (
	"regexp"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/fixture"
	"github.com/research-common/research-commons/internal/keylog"
)

// P-12 and the resolver half of C-core-01. A reader that was never given a retraction, a contradiction, a
// refutation or a newer edition computes its answer from what it holds. Two things must hold of every surface:
// the status it prints is scoped (corroboration status: "within statements you hold", or "within this hub" for a
// hub that resolves only its own holdings), and nothing it prints claims completeness ("no contradictions",
// "uncontradicted", "complete", "up to date", "no newer edition").

// completenessClaim matches a phrase that asserts absence of what the reader never received. `completeness` as
// a declared selection value is a word of the vocabulary and is not a claim.
var completenessClaim = regexp.MustCompile(`(?i)\b(no (other|more|further|newer|later) (corroborations?|contradictions?|editions?|retractions?|statements?|refutations?)|no contradictions?|uncontradicted|not contradicted|complete|all (corroborations|statements|editions)|none exist|nothing else|up[- ]to[- ]date|is the latest|latest edition)\b`)

// surfaces renders every view the resolver has over a world, one string per surface.
func (pw *propWorld) surfaces(r *Resolver) map[string]string {
	out := map[string]string{}
	for _, x := range pw.blobs {
		a := r.Artifact(dig(x))
		out["artifact "+x] = a.Render()
		for _, o := range r.Observations(dig(x)) {
			out["observation "+keylog.Short(o.Statement)] = o.Render()
		}
	}
	if res, ok := r.Resource(pw.g); ok {
		out["resource"] = res.Render()
		for _, m := range pw.members(r) {
			if mm, ok := r.Membership(pw.g, m); ok {
				out["membership "+keylog.Short(m)] = mm.Render()
			}
		}
		if s, ok := r.Series(pw.g, ""); ok {
			out["series"] = s.Render()
		}
	}
	return out
}

// scopeOf checks every corroboration status of a resolver carries the scope it was given.
func (pw *propWorld) scopeProblem(r *Resolver, scope string) string {
	for _, p := range r.byKind["observed"] {
		o, ok := r.Observation(p.St.ID)
		if !ok {
			continue
		}
		if s := o.Corroboration.Status(); !strings.HasSuffix(s, scope) {
			return keylog.Short(p.St.ID) + " status " + s + " is not scoped " + scope
		}
		if !strings.Contains(o.Render(), scope) {
			return keylog.Short(p.St.ID) + " renders no scope"
		}
	}
	return ""
}

func TestPropertyWithheldStatementsScopeTheStatus(t *testing.T) {
	conformance.Partial(t, "P-12", "corroboration status and every surface's wording over generated worlds, each retraction, contradiction, refutation and edition withheld in turn (and a statement withheld mid-log, which also detaches its signer's later lines); resource `current` and the authorship line carry no scope token (spec finding PROPS-F5), so P-12 is covered for corroboration status only")
	fixture.Check(t, propBaseSeed+7000, 40, fixture.Extended, func(f fixture.Fixture) string {
		pw := concretize(t, f)
		type variant struct {
			name  string
			order []int
		}
		vs := []variant{{"everything held", nil}}
		for i := range pw.lines {
			ln := pw.lines[i]
			st := storeOf(t, [][]byte{ln})
			for _, k := range st.Keys() {
				for _, l := range st.Log(k).View().Lines {
					switch l.St.Kind {
					case "retracts", "refutes", "corroborates", "edition":
						var o []int
						for j := range pw.lines {
							if j != i {
								o = append(o, j)
							}
						}
						vs = append(vs, variant{"without " + l.St.Kind + " " + keylog.Short(l.St.ID), o})
					}
				}
			}
		}
		for _, v := range vs {
			s := storeOf(t, pw.deliver(v.order))
			r := New(s, propOpts()...)
			if p := pw.scopeProblem(r, ScopeHeld); p != "" {
				return v.name + ": " + p
			}
			for name, text := range pw.surfaces(r) {
				if m := completenessClaim.FindString(text); m != "" {
					return v.name + ": " + name + " claims completeness (" + m + "):\n" + text
				}
			}
			// the same holdings under a hub that resolves only its own: the scope is the hub's, never wider
			rh := New(s, append(propOpts(), WithScope(ScopeHub))...)
			if p := pw.scopeProblem(rh, ScopeHub); p != "" {
				return v.name + ": " + p
			}
			for _, p := range rh.byKind["observed"] {
				if o, ok := rh.Observation(p.St.ID); ok && strings.Contains(o.Render(), ScopeHeld) {
					return v.name + ": a hub-scoped view says " + ScopeHeld
				}
			}
		}
		return ""
	})
}

// TestWithheldStatementsAreAbsentNotNonexistent: C-core-01 (resolver half) and P-12, the named cases. Each held
// state is the older answer, scoped; the withheld statement is absent from every surface (not reported as
// nonexistent, not counted as missing); delivering it later changes the answer in the expected direction.
func TestWithheldStatementsAreAbsentNotNonexistent(t *testing.T) {
	conformance.Partial(t, "C-core-01", "resolver half: a retraction, a contradiction, a refutation and a newer edition withheld in turn; the relayer's serving of a history minus statements needs pull, and the counting unit is pending the identity decision")
	w := newWorld(t)
	// an observation corroborated twice, contradicted by a third key, retracted by its observer, refuted by another
	x := w.observed("X", "OX", "X", "phenomenon", obj("instrument", "urn:DEN", "location", "geo:39.7,-105.0", "at", "2026-07-01T12:00:00Z"))
	w.workflow("WA", "W", "bytes", "")
	w.corroborates("S1", "S1", x, w.result("R1", "S1", "v1", "W", "X", "a"), "supports")
	w.corroborates("S2", "S2", x, w.result("R2", "S2", "v2", "W", "X", "b"), "supports")
	w.corroborates("C3", "C3", x, w.result("R3", "C3", "v3", "W", "X", "c"), "contradicts")
	w.sign("RT", "OX", "retracts", obj("of", x))
	w.sign("RF", "RF", "refutes", obj("of", x, "evidence", dig("E")))
	// a resource with a newer edition
	g := w.genesis("G", "A", 0, "A")
	e1 := w.edition("E1", "A", g, []string{g}, []string{"a"})
	e2 := w.edition("E2", "A", g, []string{e1}, []string{"a", "b"})

	without := func(names ...string) []int {
		drop := map[string]bool{}
		for _, n := range names {
			drop[w.ids[n]] = true
		}
		var o []int
		for i, ln := range w.lines {
			if st, _ := storeOfOne(ln); !drop[st] {
				o = append(o, i)
			}
		}
		return o
	}
	obsOf := func(o []int) *Observation { v, _ := w.store(o).Observation(x); return v }
	all := obsOf(nil)
	wantStatus(t, all, "corroborated 2 · contradicted 1 within statements you hold")
	for _, c := range []struct {
		withheld []string
		status   string
		absent   string
	}{
		{[]string{"C3"}, "corroborated 2 within statements you hold", w.ids["C3"]},
		{[]string{"S1", "S2"}, "contradicted 1 within statements you hold", w.ids["S1"]},
		{[]string{"S1", "S2", "C3"}, "unchecked within statements you hold", w.ids["C3"]},
		{[]string{"RT"}, "corroborated 2 · contradicted 1 within statements you hold", w.ids["RT"]},
		{[]string{"RF"}, "corroborated 2 · contradicted 1 within statements you hold", w.ids["RF"]},
	} {
		o := obsOf(without(c.withheld...))
		wantStatus(t, o, c.status)
		out := o.Render()
		hasNot(t, out, keylog.Short(c.absent))
		if m := completenessClaim.FindString(out); m != "" {
			t.Fatalf("withholding %v: claims completeness (%s)\n%s", c.withheld, m, out)
		}
	}
	// a retraction is a held statement: delivered, it is listed, and it is not an input to the status (§6)
	has(t, all.Render(), "retracts")

	// a newer edition withheld: the resource is as of the older one, the newer edition is absent, not "none"
	old, _ := w.store(without("E2")).Resource(g)
	if old.Current != w.ed(e1) {
		t.Fatalf("current %s", old.Render())
	}
	hasNot(t, old.Render(), keylog.Short(w.ed(e2)))
	if m := completenessClaim.FindString(old.Render()); m != "" {
		t.Fatalf("resource claims completeness: %s\n%s", m, old.Render())
	}
	now, _ := w.store(nil).Resource(g)
	if now.Current != w.ed(e2) {
		t.Fatalf("delivered: current %s", now.Render())
	}

	t.Run("finding PROPS-F5: resource and authorship lines are unscoped", func(t *testing.T) {
		if !strings.Contains(old.Render(), "within statements you hold") {
			t.Skip("finding PROPS-F5: `current: <edition>` and `sole author` are printed with no scope token; the corroboration status is the only status that carries one")
		}
	})
}

// storeOfOne returns the statement id of a delivered line.
func storeOfOne(line []byte) (string, error) {
	s := keylog.NewStore()
	return idOf(s, line)
}
