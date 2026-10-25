package resolve

import (
	"fmt"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/fixture"
)

// Item 7: the three property additions proposed beside the case list. None has a case id of its own, so each is
// registered under the case it strengthens (see props-REPORT.md for the proposed ids).

// gradeWorld: a T0 re-derivation RES of observation O (the leaf), run by two keys under a bytes workflow, with a
// chain: FINAL of RES, also re-derived twice, so a mutation upstream has somewhere to propagate.
func gradeWorld(t *testing.T, mutate func(w *world, o *string)) (*Resolver, *world) {
	w := newWorld(t)
	o := w.observed("O", "OX", "OBS", "exact-bytes", chainRef(3), "finality", depthFinality("confirmations ≥ 6", 3))
	w.workflow("WA", "W", "bytes", "")
	w.authored("A1", "A", "RES", "prov", []string{"W", "OBS"}, "licence", "CC0-1.0")
	w.authored("B1", "BB", "RES", "prov", []string{"W", "OBS"}, "licence", "CC0-1.0")
	w.authored("A2", "A", "FINAL", "prov", []string{"W", "RES"}, "licence", "CC0-1.0")
	w.authored("B2", "BB", "FINAL", "prov", []string{"W", "RES"}, "licence", "CC0-1.0")
	if mutate != nil {
		mutate(w, &o)
	}
	return w.store(nil, WithTimeVerifier(newFakeBitcoin(100, 101)), WithFinalityRules(settlementRules{})), w
}

func gradeAndExit(r *Resolver, x string) (string, int) {
	a := r.Artifact(dig(x))
	code, _ := r.Verify(dig(x))
	full, _ := a.VerifyExit()
	return fmt.Sprintf("%s|%s|%d|%d", a.Grade, a.Step, code, full), code
}

// TestPropertyDisclosuresNeverGrade: C-core-65 over the disclosures of the observation, corroboration and
// membership views, which the artifact view's TestDisclosureNeverGrades does not reach: capture evidence,
// corroboration status, selection, referent status and finality. Fix a T0 chain resting on an observation;
// mutate one disclosure at a time across its value set (including missing); the grade and exit of the result
// and of what rests on it never change, and the displayed value does.
func TestPropertyDisclosuresNeverGrade(t *testing.T) {
	conformance.Partial(t, "C-core-65", "capture evidence, corroboration, referent status, finality (observation view) and selection (membership view) beside a T0 chain: grade and exit unchanged, display changed; the artifact disclosures are in TestDisclosureNeverGrades, and `every disclosure is shown beside the grade on each surface` is not checked (the observation and membership views print no grade)")
	base, _ := gradeWorld(t, nil)
	wantGrade, wantCode := gradeAndExit(base, "FINAL")
	if !strings.HasPrefix(wantGrade, "T0|T0|0|0") || wantCode != 0 {
		t.Fatalf("control is not a T0 chain with exit 0: %s", wantGrade)
	}
	type mut struct {
		field string
		apply func(w *world, o *string)
		show  func(r *Resolver, w *world) string
	}
	obsShow := func(f func(o *Observation) string) func(r *Resolver, w *world) string {
		return func(r *Resolver, w *world) string {
			o, _ := r.Observation(w.ids["O"])
			if o == nil {
				return "no observation"
			}
			return f(o)
		}
	}
	resultRender := func(r *Resolver, _ *world) string { return r.Artifact(dig("FINAL")).Render() }
	// the observation is signed once; a mutation re-signs it under a different capture, finality or referent
	// statement by replacing the world's observation: simplest is a fresh world per value
	build := func(kv ...any) *Resolver {
		w := newWorld(t)
		ref := chainRef(3)
		var extra []any
		for i := 0; i < len(kv); i += 2 {
			extra = append(extra, kv[i], kv[i+1])
		}
		w.observed("O", "OX", "OBS", "exact-bytes", ref, extra...)
		w.workflow("WA", "W", "bytes", "")
		w.authored("A1", "A", "RES", "prov", []string{"W", "OBS"}, "licence", "CC0-1.0")
		w.authored("B1", "BB", "RES", "prov", []string{"W", "OBS"}, "licence", "CC0-1.0")
		w.authored("A2", "A", "FINAL", "prov", []string{"W", "RES"}, "licence", "CC0-1.0")
		w.authored("B2", "BB", "FINAL", "prov", []string{"W", "RES"}, "licence", "CC0-1.0")
		return w.store(nil, WithTimeVerifier(newFakeBitcoin(100, 101)), WithFinalityRules(settlementRules{}))
	}
	_ = mut{}
	cases := []struct {
		field  string
		values [][]any
		show   func(r *Resolver) string
	}{
		{"capture evidence", [][]any{
			nil,
			{"evidence", "anchored-at-capture"},
			{"evidence", "witnessed", "capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "witnessed", "witnesses", []string{testKey("WIT").Signer()}))},
			{"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "device-attested", "attestation", obj("format", "x")))},
		}, func(r *Resolver) string {
			var out []string
			for _, p := range r.byKind["observed"] {
				o, _ := r.Observation(p.St.ID)
				out = append(out, o.Capture.Display)
			}
			return strings.Join(out, ",")
		}},
		{"finality", [][]any{
			nil,
			{"finality", depthFinality("confirmations ≥ 6", 3)},
			{"finality", depthFinality("confirmations ≥ 6", 30)},
			{"finality", depthFinality("confirmations ≥ 1", 3)},
			{"finality", runFinality("SF")},
			{"finality", obj("rule", "unknown rule", "state_at_capture", obj("depth", 3))},
		}, func(r *Resolver) string {
			var out []string
			for _, p := range r.byKind["observed"] {
				o, _ := r.Observation(p.St.ID)
				out = append(out, o.ReferentStatus)
			}
			return strings.Join(out, ",")
		}},
		{"licence on the observation", [][]any{nil, {"licence", "CC0-1.0"}, {"licence", "not spdx"}}, func(r *Resolver) string {
			var out []string
			for _, p := range r.byKind["observed"] {
				o, _ := r.Observation(p.St.ID)
				out = append(out, o.Render())
			}
			return strings.Join(out, ",")
		}},
	}
	for _, c := range cases {
		var shown []string
		for _, v := range c.values {
			r := build(v...)
			g, code := gradeAndExit(r, "FINAL")
			if g != wantGrade || code != wantCode {
				t.Fatalf("%s=%v moved the grade or exit: %s (want %s)", c.field, v, g, wantGrade)
			}
			if g, _ := gradeAndExit(r, "RES"); !strings.HasPrefix(g, "T0|T0|0|0") {
				t.Fatalf("%s=%v moved the grade of the direct result: %s", c.field, v, g)
			}
			shown = append(shown, c.show(r))
		}
		distinct := map[string]bool{}
		for _, s := range shown {
			distinct[s] = true
		}
		if len(distinct) < 2 {
			t.Fatalf("%s: the displayed value did not change across %d values: %v", c.field, len(c.values), shown)
		}
	}
	_ = obsShow
	_ = resultRender

	// corroboration status: contradicted, corroborated and unchecked, on the observation the chain rests on
	for name, add := range map[string]func(w *world){
		"unchecked": func(w *world) {},
		"corroborated": func(w *world) {
			w.corroborates("S1", "S1", w.ids["O"], w.result("R1", "S1", "v1", "W", "OBS", "a"), "supports")
		},
		"contradicted": func(w *world) {
			w.corroborates("C1", "C1", w.ids["O"], w.result("R1", "C1", "v1", "W", "OBS", "a"), "contradicts")
			w.corroborates("C2", "C2", w.ids["O"], w.result("R2", "C2", "v2", "W", "OBS", "b"), "contradicts")
		},
	} {
		r, _ := gradeWorld(t, func(w *world, _ *string) { add(w) })
		if g, code := gradeAndExit(r, "FINAL"); g != wantGrade || code != wantCode {
			t.Fatalf("corroboration %s moved the grade or exit: %s", name, g)
		}
	}
	// the reader's re-check of the referent: every outcome
	for _, rc := range []ReCheck{{Outcome: ReSame, State: State{HasDepth: true, Depth: 12}}, {Outcome: ReDifferent}, {Outcome: ReNotCanonical}, {Outcome: ReUnavailable}, {Outcome: ReUnchecked}} {
		r, w := gradeWorld(t, nil)
		r = New(r.logs, WithTimeVerifier(newFakeBitcoin(100, 101)), WithFinalityRules(settlementRules{}), WithReferentChecker(fakeReferents{w.ids["O"]: rc}))
		if g, code := gradeAndExit(r, "FINAL"); g != wantGrade || code != wantCode {
			t.Fatalf("referent re-check %s moved the grade or exit: %s", rc.Outcome, g)
		}
	}
	// selection: every declared value and none
	for _, sel := range []string{"", "curated", "rule-based", "completeness"} {
		w := newWorld(t)
		m := w.authored("M", "M", "m", "licence", "MIT")
		g := w.genesis("G", "A", 0, "A")
		kv := []any{"members", entries(st(m))}
		if sel != "" {
			kv = append(kv, "selection", sel)
		}
		w.editionWith("E1", "A", g, []string{g}, kv...)
		mm, _ := w.store(nil).Membership(g, m)
		if want := map[bool]string{true: "undeclared", false: sel}[sel == ""]; mm.Selection != want {
			t.Fatalf("selection %q shown as %q", sel, mm.Selection)
		}
		if a := w.store(nil).Artifact(dig("m")); a.Grade.Why == "" && a.Grade.Tier != "" {
			t.Fatalf("selection %q reached a grade: %s", sel, a.Grade)
		}
	}
}

// TestPropertyWeakestLinkMonotone: §7 weakest-link rule. For generated derivation chains, a result's grade is
// never stronger than the weakest step it rests on (T0 > T1 > T2 > none), and strengthening one input's step
// never weakens the result's grade (monotone), except under the refutation exemption. Chains are drawn from
// the fixture's seed: each level is run by 1–2 keys under bytes/protocol/undeclared, with outputs that match
// or differ.
func TestPropertyWeakestLinkMonotone(t *testing.T) {
	conformance.Partial(t, "C-core-72", "weakest-link and monotonicity over generated chains of derivation steps (levels re-derived or not, under bytes, protocol-with-comparator and undeclared workflows); the T2 tier needs tasks and the grade of observation leaves is not ranked")
	rank := func(g Grade) int { return g.rank() }
	fixture.Check(t, propBaseSeed+8000, 60, fixture.Extended, func(f fixture.Fixture) string {
		mode := []string{"bytes", "protocol", ""}[f.Seed%3]
		build := func(levels []int) (*Resolver, []Grade) {
			w := newWorld(t)
			cmp := ""
			if mode == "protocol" {
				cmp = "K"
			}
			w.workflow("A", "W", mode, cmp)
			prev := "LEAF"
			w.authored("L", "A", "LEAF", "licence", "MIT")
			var names []string
			for i, lv := range levels {
				x := fmt.Sprint("r", i, "~1")
				y := fmt.Sprint("r", i, "~1")
				switch lv {
				case 1: // re-derived, matching
					y = fmt.Sprint("r", i, "~2")
					if mode == "bytes" {
						y = x
					}
				case 2: // re-derived, diverging
					y = fmt.Sprint("s", i, "~1")
				}
				w.authored(fmt.Sprint("a", i), "A", x, "prov", []string{"W", prev})
				if lv > 0 {
					w.authored(fmt.Sprint("b", i), "BB", y, "prov", []string{"W", prev})
				}
				names = append(names, x)
				prev = x
			}
			var all []string
			for i := range levels {
				all = append(all, fmt.Sprint("r", i, "~1"), fmt.Sprint("r", i, "~2"), fmt.Sprint("s", i, "~1"))
			}
			r := w.store(nil, WithComparator(newFakeComparator(all...)))
			var gs []Grade
			for _, n := range names {
				gs = append(gs, r.Artifact(dig(n)).Grade)
			}
			return r, gs
		}
		n := 2 + int(f.Seed%3)
		levels := make([]int, n)
		for i := range levels {
			levels[i] = int((f.Seed >> (2 * uint(i))) % 3)
		}
		_, gs := build(levels)
		// never stronger than the weakest step beneath: a result's grade is at most the min of its own step and
		// every step before it
		floor := 99
		for i, g := range gs {
			own := Grade{}
			_ = own
			if r := rank(g); r < floor {
				floor = r
			}
			if rank(g) > floor {
				return fmt.Sprintf("level %d grade %s stronger than a step beneath it (floor rank %d) in %v", i, g, floor, levels)
			}
		}
		// monotone: strengthening one level (not re-derived -> re-derived, matching) never weakens any grade
		for i := range levels {
			if levels[i] != 0 {
				continue
			}
			up := append([]int{}, levels...)
			up[i] = 1
			_, gu := build(up)
			for j := range gs {
				if rank(gu[j]) < rank(gs[j]) {
					return fmt.Sprintf("re-deriving level %d weakened level %d from %s to %s (levels %v)", i, j, gs[j], gu[j], levels)
				}
			}
		}
		return ""
	})
}

// TestPropertyNoPriorityInsideAGroup: claims §5.2 (derivation groups). Claimants whose current statements carry
// one provenance are one unit, whatever their anchors: adding any anchor, verified, local or none, to any
// member of a group never makes one member the default author or a later claimant of another, and never makes
// the blob `contested` by itself. Priority is ranked between units only.
func TestPropertyNoPriorityInsideAGroup(t *testing.T) {
	conformance.Partial(t, "C-core-20", "anchors of every quality added to members of one derivation group, bytes and protocol workflows, 2–4 members: one unit, no default among members, no later claimants; priority between a group and a rival unit is C-core-18/19 and covered elsewhere")
	fixture.Check(t, propBaseSeed+9000, 40, fixture.Extended, func(f fixture.Fixture) string {
		w := newWorld(t)
		mode := []string{"bytes", "protocol"}[f.Seed%2]
		cmp := ""
		if mode == "protocol" {
			cmp = "K"
		}
		w.workflow("A", "W", mode, cmp)
		members := []string{"A", "BB", "C", "DD"}[:2+int(f.Seed%3)]
		for _, k := range members {
			out := "X"
			if mode == "protocol" {
				out = "X"
			}
			w.authored(k+"1", k, out, "prov", []string{"W", "I"})
		}
		quality := []string{"btc:100", "btc:101", "btc:102", "local:z", ""}
		for i, k := range members {
			if q := quality[(int(f.Seed)+i*3)%len(quality)]; q != "" {
				w.anchor("anc"+k, k, q)
			}
		}
		for _, opts := range [][]Option{nil, {WithTimeVerifier(newFakeBitcoin(100, 101, 102))}} {
			a := w.store(nil, opts...).Artifact(dig("X"))
			if len(a.Units) != 1 {
				return fmt.Sprintf("a group of %d members is %d units", len(members), len(a.Units))
			}
			if a.State == Priority || a.State == ContestedAuthorship || len(a.Later) > 0 {
				return "priority computed inside a derivation group: " + a.Render()
			}
			if !strings.Contains(a.Render(), "priority is not computed within a derivation group") {
				return "the view does not say priority is not computed inside the group:\n" + a.Render()
			}
		}
		return ""
	})
}
