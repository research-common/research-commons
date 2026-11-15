package identitymodel

import (
	"slices"
	"testing"
)

// TestGrantState: the grant-level axis of profile §4.1 over the model fixture (R: I -> G to K pinned at D). Each
// state is reached by the evidence the profile names, and the state agrees with what Evaluate says of the acts
// under the grant: open means no root-side reason is added to any act, cut at L means exactly the acts outside
// L's closure gain cut_excluded, cut null means every act is denied. A delegate's own revoke does not move the
// grant (delegate_self_event is a warning on both answers).
func TestGrantState(t *testing.T) {
	acts := []ID{"A", "B", "X", "M", "Z"}
	revoke := line("KR", "K", 5, "Z", RevokeKey)
	retire := line("RR", "R", 2, "G", RevokeKey)
	unsupported := line("RU", "R", 2, "G", Unclassified)
	cases := []struct {
		name     string
		facts    []Fact
		status   GrantStatus
		lastGood []ID
		code     string // a reason the grant answer must carry
		warning  string
	}{
		{"open", fixture(), GrantOpen, nil, "", ""},
		{"cut at B", append(fixture(), cut("C", "B")), GrantCutAt, []ID{"B"}, "", ""},
		{"two cuts at B and X", append(fixture(), cut("C", "B"), cut("CX", "X")), GrantCutAt, []ID{"B", "X"}, "", ""},
		{"cut null", append(fixture(), cut("C", "")), GrantCutNull, nil, "cut_null", ""},
		{"cut null beside missing evidence", without(append(fixture(), cut("C", "")), "D"), GrantCutNull, nil, "cut_null", ""},
		{"root retired", append(fixture(), retire), GrantDenied, nil, "root_retired", ""},
		{"unsupported root event", append(fixture(), unsupported), GrantUnknown, nil, "unsupported_root_event", ""},
		{"no inception held", without(fixture(), "I"), GrantUnknown, nil, "missing_evidence", ""},
		{"no delegate inception held", without(fixture(), "D"), GrantUnknown, nil, "missing_evidence", ""},
		{"cut last_good not held", without(append(fixture(), cut("C", "B")), "B"), GrantUnknown, nil, "missing_evidence", ""},
		{"delegate self-revoke leaves it open", append(fixture(), revoke), GrantOpen, nil, "", "delegate_self_event"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := snapshot(t, tc.facts)
			gs := s.GrantState("G")
			if gs.Status != tc.status || !slices.Equal(gs.LastGood, tc.lastGood) {
				t.Fatalf("status %q last_good %v, want %q %v: %+v", gs.Status, gs.LastGood, tc.status, tc.lastGood, gs)
			}
			if gs.Grant != "G" || gs.Freshness != NotEstablished || gs.EvidenceDigest != s.EvidenceDigest() || gs.EvaluatorVersion != EvaluatorVersion {
				t.Fatalf("missing evidence-relative context: %+v", gs)
			}
			if tc.status != GrantUnknown || tc.name != "no inception held" {
				if gs.Identity != "I" || gs.Delegate != "K" {
					t.Fatalf("grant fields: %+v", gs)
				}
			}
			if tc.code != "" && !slices.ContainsFunc(gs.Reasons, func(r Reason) bool { return r.Code == tc.code }) {
				t.Fatalf("no %s reason: %+v", tc.code, gs.Reasons)
			}
			if tc.warning != "" && !slices.ContainsFunc(gs.Warnings, func(w Warning) bool { return w.Code == tc.warning }) {
				t.Fatalf("no %s warning: %+v", tc.warning, gs.Warnings)
			}
			// agreement with the per-act answers
			for _, a := range acts {
				if _, ok := s.facts[a]; !ok {
					continue
				}
				r := s.Evaluate(a)
				switch gs.Status {
				case GrantOpen:
					if r.Status != Eligible {
						t.Fatalf("open grant, act %s %s: %+v", a, r.Status, r.Reasons)
					}
				case GrantCutNull, GrantDenied:
					if r.Status != Denied {
						t.Fatalf("%s grant, act %s %s", gs.Status, a, r.Status)
					}
				case GrantCutAt:
					// the only thing a cut at L adds to an act is cut_excluded outside L's closure
					if r.Status != Eligible && !hasReason(r, "cut_excluded") {
						t.Fatalf("cut grant, act %s %s without cut_excluded: %+v", a, r.Status, r.Reasons)
					}
				case GrantUnknown:
					if r.Status == Eligible {
						t.Fatalf("unknown grant, act %s eligible", a)
					}
				}
			}
		})
	}
}

// TestGrantStateCapIsUnknown: a cap reached while placing the grant is unknown with model_limit, never open.
func TestGrantStateCapIsUnknown(t *testing.T) {
	s := snapshot(t, fixture())
	gs := s.GrantStateWith("G", Limits{Dependencies: 2})
	if gs.Status != GrantUnknown || !slices.ContainsFunc(gs.Reasons, func(r Reason) bool { return r.Code == "model_limit" }) {
		t.Fatalf("capped: %+v", gs)
	}
}

// TestGrantsTo: a delegate's grants are found by the key they name, whoever signed them; an unauthenticated grant
// is not evidence and is not listed.
func TestGrantsTo(t *testing.T) {
	fs := fixture()
	g2 := line("G2", "R", 2, "G", GrantEvent)
	g2.Grant = &Grant{Identity: "I", Delegate: "K", Inception: "D", Permissions: []Permission{{Kind: Authored, Mode: AnyTarget}}}
	g3 := line("G3", "R", 3, "G2", GrantEvent)
	g3.Grant = &Grant{Identity: "I", Delegate: "K", Inception: "D"}
	g3.Authentication = Unproven
	gOther := line("GO", "R", 4, "G2", GrantEvent)
	gOther.Grant = &Grant{Identity: "I", Delegate: "L", Inception: "D"}
	s := snapshot(t, append(fs, g2, g3, gOther))
	if got := s.GrantsTo("K"); !slices.Equal(got, []ID{"G", "G2"}) {
		t.Fatalf("grants to K: %v", got)
	}
	if got := s.GrantsTo("nobody"); len(got) != 0 {
		t.Fatalf("grants to nobody: %v", got)
	}
}
