package resolve

import (
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
)

// profileRun is a finality block under the dialect's ordered-label rule `run >= RF`, citing src, at state run.
func profileRun(src, run string) *canon.Object {
	return obj("rule", "run >= RF", "rule_source", src, "state_at_capture", obj("run", run))
}

// TestObservationThroughSourceProfile: C-core-104a through the observation view, with the production evaluator
// (ProfileRules over the settlement profile P: SF < R1 < R2 < RF < DF, documents T). An observation's rule
// resolves through the profile its rule_source cites, by digest or by document: unmet is provisional with the
// final label, met is `final (as captured, not re-checked)` (never plain `final`: the profile orders the
// observer's asserted state); a label outside P, no matching profile, or two, is `finality unchecked` naming why.
// The reader's own re-check keeps its own state: at a state that meets the rule it is `final`, below it the
// referent is provisional at the re-checked state, whatever the observer asserted.
func TestObservationThroughSourceProfile(t *testing.T) {
	conformance.Covers(t, "C-core-104a")
	p := mustProfile(t, settlementProfileBytes())
	other := mustProfile(t, canon.Encode(obj("profile", SourceProfileTag, "source", "https://api.example/settlement", "dialect", DialectOrderedLabel,
		"labels", []string{"RF", "SF"}, "documents", []string{timetable})))
	rules := WithFinalityRules(NewProfileRules(p))
	under := "under source profile " + keylog.Short(p.Digest)
	for _, tc := range []struct {
		name, src, state string
		opts             []Option
		ref, history     string
		unevaluable      bool
	}{
		{"(a) unmet, by digest", p.Digest, "R2", nil, "provisional (R2; final at RF)", "unmet " + under, false},
		{"(b) met, by document", timetable, "DF", nil, RefFinalCaptured, "meets rule \"run >= RF\" " + under, false},
		{"(a') met at the label", p.Digest, "RF", nil, RefFinalCaptured, under, false},
		{"(c) state not in P", p.Digest, "II", nil, RefRuleUnchecked, `state "II" is not in source profile`, true},
		{"(d) no chosen profile", "https://elsewhere.example/policy", "RF", nil, RefRuleUnchecked, "names no source profile this reader chose", true},
		{"(f) two chosen profiles", timetable, "DF", []Option{WithFinalityRules(NewProfileRules(p, other))}, RefRuleUnchecked, "names 2 source profiles", true},
		{"control: no profiles", p.Digest, "RF", []Option{WithFinalityRules(DepthRules{})}, RefRuleUnchecked, "no source profile for it", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			id := w.observed("A", "O1", "S1", "source", apiRef("https://api.example/settlement"), "finality", profileRun(tc.src, tc.state))
			opts := tc.opts
			if opts == nil {
				opts = []Option{rules}
			}
			o := obsView(t, w, id, opts...)
			wantRef(t, o, tc.ref)
			has(t, o.Render(), tc.history)
			code, why := o.VerifyExit()
			if tc.unevaluable != (code == 3) || tc.unevaluable != (len(why) == 1) {
				t.Fatalf("verify %d %v, want unevaluable %v", code, why, tc.unevaluable)
			}
		})
	}
	// (e) a rule label outside P
	w := newWorld(t)
	id := w.observed("A", "O1", "S1", "source", apiRef("https://api.example/settlement"), "finality",
		obj("rule", "run >= XF", "rule_source", p.Digest, "state_at_capture", obj("run", "DF")))
	o := obsView(t, w, id, rules)
	wantRef(t, o, RefRuleUnchecked)
	has(t, o.Render(), `rule label "XF" is not in source profile`)

	// control: a depth rule needs no profile (the integer-depth dialect), under the same evaluator
	w = newWorld(t)
	id = w.observed("A", "O1", "S1", "source", apiRef("https://api.example/settlement"), "finality",
		obj("rule", "confirmations >= 6", "state_at_capture", obj("depth", 7)))
	wantRef(t, obsView(t, w, id, rules), RefFinalCaptured)

	// the reader's re-check keeps its own state: met there is final; below the rule it is provisional at the
	// re-checked state, though the observer asserted RF
	w = newWorld(t)
	id = w.observed("A", "O1", "S1", "source", apiRef("https://api.example/settlement"), "finality", profileRun(p.Digest, "RF"))
	o = obsView(t, w, id, rules, WithReferentChecker(fakeReferents{id: {Outcome: ReSame, State: State{Run: "DF"}}}))
	wantRef(t, o, RefFinal)
	has(t, o.Render(), "reader re-check: state DF, identical bytes: final (asserted state RF shown beside it)")
	o = obsView(t, w, id, rules, WithReferentChecker(fakeReferents{id: {Outcome: ReSame, State: State{Run: "R1"}}}))
	wantRef(t, o, "provisional (R1; final at RF)")
}

// TestCorroborationThroughSourceProfile: C-core-39, C-core-40 and C-core-41 (and C-core-37 (c)), the finality-aware
// comparisons of §5.3.1, under the production evaluator: two captures of one settlement period are
// ordered by their labels' places in the profile their rule cites. Different bytes before RF at two states are
// `referent revised` (and the earlier referent `revised`); at one state, or both past RF, they contradict; a state
// outside the profile is `not comparable under the rule`, never a revision. A re-capture with identical bytes
// before RF stays under the source-class model; at RF it is an exact-bytes corroboration (class migration by
// rule). Control: the same worlds with no profile configured compare nothing and leave the rule unchecked.
func TestCorroborationThroughSourceProfile(t *testing.T) {
	conformance.Covers(t, "C-core-39", "C-core-40", "C-core-41")
	p := mustProfile(t, settlementProfileBytes())
	rules := WithFinalityRules(NewProfileRules(p))
	src := apiRef("https://api.example/settlement")
	for _, tc := range []struct {
		a, b, want, cause string
	}{
		{"SF", "R1", "unchecked within statements you hold", "(referent revised)"},
		{"R1", "R1", "contradicted 1 within statements you hold", ""},
		{"RF", "DF", "contradicted 1 within statements you hold", ""},
		{"SF", "II", "unchecked within statements you hold", "(" + NotComparableUnderRule + ")"},
	} {
		w := newWorld(t)
		x := w.observed("A", "O1", "S1", "source", src, "finality", profileRun(p.Digest, tc.a))
		y := w.observed("B", "O2", "S2", "source", src, "finality", profileRun(timetable, tc.b), "at", "2026-10-17T00:00:00Z")
		o := obsView(t, w, x, rules)
		wantStatus(t, o, tc.want)
		// symmetric: the other capture reads the same corroboration status
		wantStatus(t, obsView(t, w, y, rules), tc.want)
		if tc.cause != "" {
			has(t, o.Render(), tc.cause)
		}
		if tc.a == "SF" && tc.b == "R1" {
			wantRef(t, o, RefRevised)
		}
		if tc.b == "II" {
			hasNot(t, o.Render(), "referent revised")
			wantRef(t, o, "provisional (SF; final at RF)")
		}
		// control: no profile, nothing ordered, the rule unchecked
		c := obsView(t, w, x)
		wantRef(t, c, RefRuleUnchecked)
		hasNot(t, c.Render(), "contradicted 1")
	}
	// class migration by rule
	w := newWorld(t)
	s1 := w.observed("S1", "O1", "X", "source", src, "finality", profileRun(p.Digest, "SF"))
	w.observed("R1", "O2", "X", "source", src, "finality", profileRun(p.Digest, "R1"), "at", "2026-10-16T00:01:00Z")
	o := obsView(t, w, s1, rules)
	wantStatus(t, o, "unchecked within statements you hold")
	has(t, o.Render(), "source-class model")
	w.observed("R2", "O3", "X", "source", src, "finality", profileRun(p.Digest, "RF"), "at", "2026-10-18T00:00:00Z")
	o = obsView(t, w, s1, rules)
	wantStatus(t, o, "corroborated 1 within statements you hold")
	has(t, o.Render(), "class migration by rule")
	if o.Class != "source" {
		t.Fatalf("class changed: %s", o.Class)
	}
}
