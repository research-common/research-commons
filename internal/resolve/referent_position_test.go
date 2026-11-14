package resolve

import "testing"

// TestPositionReCheckIsNotBytes: a re-check that reads where the pinned block is (a reader's header chain) and never
// its bytes drives the referent status only (claims §5.3.1, "for an exact-bytes referent the rule drives the
// referent status only"): provisional, final or not canonical. It adds no corroboration evidence in any outcome, so
// an observation nobody re-read stays `unchecked` (C-core-29 and C-core-43 need a byte re-read). Control: a byte
// re-check (identical bytes) at the same depth is counted.
func TestPositionReCheckIsNotBytes(t *testing.T) {
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "exact-bytes", chainRef(3), "finality", depthFinality("confirmations ≥ 6", 3))
	pos := func(rc ReCheck) *Observation {
		return obsView(t, w, o1, WithReferentChecker(fakeReferents{o1: rc}))
	}
	cases := []struct {
		name string
		rc   ReCheck
		ref  string
	}{
		{"on the accepted chain, below the rule", ReCheck{Outcome: RePosition, State: State{HasDepth: true, Depth: 4}, Why: "header chain"}, "provisional (4; final at 6)"},
		{"on the accepted chain, meeting the rule", ReCheck{Outcome: RePosition, State: State{HasDepth: true, Depth: 9}, Why: "header chain"}, RefFinal},
		{"held off the accepted chain", ReCheck{Outcome: ReNotCanonical, PositionOnly: true, Why: "block held off the accepted chain"}, RefNotCanonical},
		{"not held", ReCheck{Outcome: ReUnchecked, PositionOnly: true, Why: "block not in this reader's header chain"}, "provisional (3; final at 6)"},
		{"a position re-check claiming bytes", ReCheck{Outcome: ReSame, PositionOnly: true, State: State{HasDepth: true, Depth: 9}}, "provisional (3; final at 6)"},
	}
	for _, c := range cases {
		o := pos(c.rc)
		wantRef(t, o, c.ref)
		if len(o.Corroboration.Evidence) != 0 || o.Corroboration.Corroborated != 0 {
			t.Fatalf("%s: a position re-check added evidence: %+v\n%s", c.name, o.Corroboration.Evidence, o.Render())
		}
		wantStatus(t, o, "unchecked within statements you hold")
		hasNot(t, o.Render(), "identical bytes")
	}
	// the position re-check names itself in the history
	has(t, pos(cases[1].rc).Render(), "reader re-check: depth 9 (header chain; position only, bytes not re-read): final")
	// control: a byte re-read at the same depth counts (the boundary is the outcome, not the depth)
	o := pos(ReCheck{Outcome: ReSame, State: State{HasDepth: true, Depth: 9}})
	wantRef(t, o, RefFinal)
	wantStatus(t, o, "corroborated 1 (reader re-check) within statements you hold")
	// a position re-check without a finality rule: still canonical, no evidence
	w2 := newWorld(t)
	o2 := w2.observed("O2", "O2", "Y", "exact-bytes", chainRef(3))
	v := obsView(t, w2, o2, WithReferentChecker(fakeReferents{o2: {Outcome: RePosition, State: State{HasDepth: true, Depth: 4}}}))
	wantRef(t, v, RefCanonical)
	if len(v.Corroboration.Evidence) != 0 {
		t.Fatalf("no rule: evidence added: %s", v.Render())
	}
}
