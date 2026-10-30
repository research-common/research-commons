package identitymodel

import (
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
)

// All authentication values below are SYNTHETIC ADAPTER ATTESTATIONS. These are
// semantic fixtures, not cryptographic signatures or wire conformance vectors.
func line(id ID, key Key, seq uint64, prev ID, event Event) Fact {
	return Fact{ID: id, Signer: key, Authentication: Authenticated, Validity: Understood,
		Seq: seq, Prev: prev, Event: event}
}

func data(id ID, seq uint64, prev ID) Fact {
	f := line(id, "K", seq, prev, Data)
	f.Actor = &Actor{Identity: "I", Grant: "G"}
	f.Binding = BoundIdentityContext
	f.Operation = &Operation{Kind: Authored, Target: Target{Type: ContentTarget, ID: "content-a"}}
	return f
}

func cut(id, last ID) Fact {
	f := line(id, "R", 2, "G", CutEvent)
	f.Cut = &Cut{Identity: "I", Grant: "G", LastGood: LastGood{Mode: PreserveThrough, ID: last}}
	if last == "" {
		f.Cut.LastGood.Mode = PreserveNone
	}
	return f
}

// D -> A -> B -> M -> Z, with A -> X -> M via M.merges.
// R has I -> G. Cuts added by tests are independent root branches after G.
func fixture() []Fact {
	i := line("I", "R", 0, "", IdentityInception)
	i.Inception = &Inception{Profile: FixedRoot}
	g := line("G", "R", 1, "I", GrantEvent)
	g.Grant = &Grant{Identity: "I", Delegate: "K", Inception: "D", Permissions: []Permission{
		{Kind: Authored, Mode: ExactTargets, Targets: []ID{"content-a", "content-b"}},
	}}
	m := data("M", 3, "B")
	m.Merges = []ID{"X"}
	return []Fact{i, line("D", "K", 0, "", Inert), g, data("A", 1, "D"),
		data("B", 2, "A"), data("X", 2, "A"), m, data("Z", 4, "M")}
}

func mutate(fs []Fact, id ID, fn func(*Fact)) []Fact {
	for i := range fs {
		if fs[i].ID == id {
			fn(&fs[i])
			return fs
		}
	}
	panic("fixture ID not found: " + id)
}

func without(fs []Fact, ids ...ID) []Fact {
	return slices.DeleteFunc(fs, func(f Fact) bool { return slices.Contains(ids, f.ID) })
}

func snapshot(t *testing.T, fs []Fact) *Snapshot {
	t.Helper()
	s, err := NewSnapshot(fs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func hasReason(r Result, code string) bool {
	return slices.ContainsFunc(r.Reasons, func(v Reason) bool { return v.Code == code })
}

func requireStatus(t *testing.T, s *Snapshot, id ID, status Status, code string) Result {
	t.Helper()
	r := s.Evaluate(id)
	if r.Status != status || (code != "" && !hasReason(r, code)) {
		t.Fatalf("%s: got %s, need %s/%s: %+v", id, r.Status, status, code, r)
	}
	if r.Freshness != NotEstablished || r.EvaluatorVersion != EvaluatorVersion || r.EvidenceDigest != s.EvidenceDigest() {
		t.Fatalf("missing evidence-relative explanation: %+v", r)
	}
	return r
}

func TestExactCutClosures(t *testing.T) {
	cases := []struct {
		name string
		cuts []Fact
		want map[ID]Status
	}{
		{"no cuts", nil, map[ID]Status{"A": Eligible, "B": Eligible, "X": Eligible, "M": Eligible, "Z": Eligible}},
		{"inclusive branch", []Fact{cut("C", "B")}, map[ID]Status{"A": Eligible, "B": Eligible, "X": Denied, "M": Denied, "Z": Denied}},
		{"merge includes both", []Fact{cut("C", "M")}, map[ID]Status{"A": Eligible, "B": Eligible, "X": Eligible, "M": Eligible, "Z": Denied}},
		{"intersection siblings", []Fact{cut("C", "B"), cut("CX", "X")}, map[ID]Status{"A": Eligible, "B": Denied, "X": Denied, "M": Denied, "Z": Denied}},
		{"wider cut never reopens", []Fact{cut("C", "B"), cut("CW", "Z")}, map[ID]Status{"A": Eligible, "B": Eligible, "X": Denied, "M": Denied, "Z": Denied}},
		{"explicit null", []Fact{cut("C", "")}, map[ID]Status{"A": Denied, "B": Denied, "X": Denied, "M": Denied, "Z": Denied}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := snapshot(t, append(fixture(), tc.cuts...))
			for id, status := range tc.want {
				r := requireStatus(t, s, id, status, "")
				if r.Actor != (Subject{Kind: IdentitySubject, Identity: "I"}) || r.Grant != "G" || r.Signer != "K" ||
					r.RootLineage != "I" || r.DelegateInception != "D" || len(r.RelevantCuts) != len(tc.cuts) {
					t.Fatalf("wrong authority explanation: %+v", r)
				}
			}
		})
	}
}

func TestMissingInvalidAndUnsupportedEvidence(t *testing.T) {
	cases := []struct {
		name   string
		edit   func([]Fact) []Fact
		status Status
		code   string
	}{
		{"missing statement", func(fs []Fact) []Fact { return without(fs, "A") }, Unknown, "missing_evidence"},
		{"missing identity", func(fs []Fact) []Fact { return without(fs, "I") }, Unknown, "missing_evidence"},
		{"missing grant", func(fs []Fact) []Fact { return without(fs, "G") }, Unknown, "missing_evidence"},
		{"missing delegate inception", func(fs []Fact) []Fact { return without(fs, "D") }, Unknown, "missing_evidence"},
		{"missing last-good", func(fs []Fact) []Fact { return append(fs, cut("C", "absent-L")) }, Unknown, "missing_evidence"},
		{"missing last-good ancestor", func(fs []Fact) []Fact { return append(without(fs, "B"), cut("C", "M")) }, Unknown, "missing_evidence"},
		{"missing merge", func(fs []Fact) []Fact { return append(without(fs, "X"), cut("C", "M")) }, Unknown, "missing_evidence"},
		{"root dependency unresolved", func(fs []Fact) []Fact {
			c := cut("C", "B")
			c.Prev = "root-gap"
			return append(fs, c)
		}, Unknown, "unresolved_root_ancestry"},
		{"invalid last-good signer", func(fs []Fact) []Fact { return append(fs, cut("C", "G")) }, Denied, "wrong_signer"},
		{"last-good rival delegate inception", func(fs []Fact) []Fact {
			return append(fs, line("D-rival", "K", 0, "", Inert), cut("C", "D-rival"))
		}, Denied, "wrong_lineage"},
		{"omitted last-good", func(fs []Fact) []Fact {
			c := cut("C", "B")
			c.Cut.LastGood = LastGood{}
			return append(fs, c)
		}, Denied, "invalid_last_good"},
		{"null with ID", func(fs []Fact) []Fact {
			c := cut("C", "B")
			c.Cut.LastGood.Mode = PreserveNone
			return append(fs, c)
		}, Denied, "invalid_last_good"},
		{"empty inclusive ID", func(fs []Fact) []Fact {
			c := cut("C", "")
			c.Cut.LastGood.Mode = PreserveThrough
			return append(fs, c)
		}, Denied, "invalid_last_good"},
		{"invalid attributable cut", func(fs []Fact) []Fact {
			c := cut("C", "B")
			c.Validity = Invalid
			return append(fs, c)
		}, Denied, "invalid_evidence"},
		{"unsupported attributable cut", func(fs []Fact) []Fact {
			c := cut("C", "B")
			c.Validity = Unsupported
			return append(fs, c)
		}, Unknown, "unsupported_evidence"},
		{"unsupported profile", func(fs []Fact) []Fact {
			return mutate(fs, "I", func(f *Fact) { f.Inception.Profile = UnknownProfile })
		}, Unknown, "unsupported_identity_profile"},
		{"unknown root vocabulary", func(fs []Fact) []Fact { return append(fs, line("U", "R", 2, "G", Unclassified)) }, Unknown, "unsupported_root_event"},
		{"unaddressable authenticated root cut", func(fs []Fact) []Fact {
			return append(fs, line("U", "R", 2, "G", CutEvent))
		}, Unknown, "unaddressable_root_cut"},
		{"unsupported root payload", func(fs []Fact) []Fact {
			f := line("U", "R", 2, "G", GrantEvent)
			f.Validity = Unsupported
			return append(fs, f)
		}, Unknown, "unsupported_root_event"},
		{"unsupported statement", func(fs []Fact) []Fact { return mutate(fs, "A", func(f *Fact) { f.Validity = Unsupported }) }, Unknown, "unsupported_evidence"},
		{"bad signature", func(fs []Fact) []Fact { return mutate(fs, "A", func(f *Fact) { f.Authentication = RejectedSignature }) }, Denied, "signature_rejected"},
		{"unproven statement", func(fs []Fact) []Fact { return mutate(fs, "A", func(f *Fact) { f.Authentication = Unproven }) }, Unknown, "authentication_unproven"},
		{"unproven issuer grant", func(fs []Fact) []Fact { return mutate(fs, "G", func(f *Fact) { f.Authentication = Unproven }) }, Unknown, "authentication_unproven"},
		{"grant wrong root", func(fs []Fact) []Fact { return mutate(fs, "G", func(f *Fact) { f.Signer = "attacker" }) }, Denied, "wrong_signer"},
		{"grant wrong identity", func(fs []Fact) []Fact { return mutate(fs, "G", func(f *Fact) { f.Grant.Identity = "J" }) }, Denied, "wrong_grant_identity"},
		{"grant pins head", func(fs []Fact) []Fact { return mutate(fs, "G", func(f *Fact) { f.Grant.Inception = "B" }) }, Denied, "delegate_pin_not_inception"},
		{"actor no critical binding", func(fs []Fact) []Fact { return mutate(fs, "A", func(f *Fact) { f.Binding = NoIdentityContext }) }, Denied, "invalid_actor_binding"},
		{"actor unsupported binding", func(fs []Fact) []Fact {
			return mutate(fs, "A", func(f *Fact) { f.Binding = UnsupportedIdentityContext })
		}, Unknown, "unsupported_actor_binding"},
		{"empty actor grant", func(fs []Fact) []Fact { return mutate(fs, "A", func(f *Fact) { f.Actor.Grant = "" }) }, Denied, "invalid_actor"},
		{"wrong delegate key", func(fs []Fact) []Fact { return mutate(fs, "G", func(f *Fact) { f.Grant.Delegate = "other" }) }, Denied, "wrong_delegate"},
		{"root as delegate", func(fs []Fact) []Fact { return mutate(fs, "G", func(f *Fact) { f.Grant.Delegate = "R" }) }, Denied, "root_is_delegate"},
		{"inception not own seq zero", func(fs []Fact) []Fact { return mutate(fs, "I", func(f *Fact) { f.Seq = 1 }) }, Denied, "invalid_identity_inception"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { requireStatus(t, snapshot(t, tc.edit(fixture())), "A", tc.status, tc.code) })
	}
}

func TestDenialDoesNotHideUnknown(t *testing.T) {
	r := requireStatus(t, snapshot(t, append(fixture(), cut("C-none", ""), cut("C-gap", "absent"))), "A", Denied, "cut_excluded")
	if !hasReason(r, "missing_evidence") || !slices.ContainsFunc(r.Dependencies, func(d Dependency) bool {
		return d.ID == "absent" && d.NeededBy == "C-gap" && d.Purpose == "cut last-good ancestry"
	}) {
		t.Fatalf("unknown dependency hidden by definite denial: %+v", r)
	}
}

func TestAuthenticatedIssuerBoundaryAndNoninterference(t *testing.T) {
	base := snapshot(t, fixture()).Evaluate("A")
	variants := map[string]Fact{}
	c := cut("forged", "absent")
	c.Authentication = Unproven
	variants["unproven root claim"] = c
	c = cut("bad-sig", "absent")
	c.Authentication = RejectedSignature
	variants["rejected root signature"] = c
	c = cut("unrelated-signer", "absent")
	c.Signer = "attacker"
	variants["authenticated stranger claiming affiliation"] = c
	c = cut("other-grant", "absent")
	c.Cut.Grant = "other-G"
	variants["other grant cutoff"] = c
	for name, f := range variants {
		t.Run(name, func(t *testing.T) {
			r := requireStatus(t, snapshot(t, append(fixture(), f)), "A", Eligible, "")
			if r.Actor != base.Actor || r.Grant != base.Grant || len(r.RelevantCuts) != 0 || len(r.Dependencies) != 0 {
				t.Fatalf("foreign/unproven event interfered: %+v", r)
			}
		})
	}
	// An attacker's opted-in statement with an invented/missing grant has only
	// its OWN unresolved authority. It does not join a global affiliation index.
	attack := data("attack", 1, "attacker-D")
	attack.Signer = "attacker"
	attack.Actor.Grant = "invented-G"
	s := snapshot(t, append(fixture(), line("attacker-D", "attacker", 0, "", Inert), attack))
	requireStatus(t, s, "A", Eligible, "")
	requireStatus(t, s, "attack", Unknown, "missing_evidence")
	// In contrast, the known issuer's signed cut with an unresolved prev is not
	// ignored merely because its lineage has not yet been established.
	c = cut("issuer-cut", "A")
	c.Prev = "missing-root-parent"
	r := requireStatus(t, snapshot(t, append(fixture(), c)), "A", Unknown, "unresolved_root_ancestry")
	if !slices.Contains(r.RelevantCuts, "issuer-cut") || len(r.Dependencies) == 0 {
		t.Fatalf("missing issuer uncertainty: %+v", r)
	}
}

func TestRootTerminalEventsAreLineageScoped(t *testing.T) {
	for _, kind := range []Event{RotateKey, RevokeKey} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			terminal := line("terminal", "R", 2, "G", kind)
			requireStatus(t, snapshot(t, append(fixture(), terminal)), "A", Denied, "root_retired")
			rival := line("rival-I", "R", 0, "", IdentityInception)
			rival.Inception = &Inception{Profile: FixedRoot}
			terminal.Prev, terminal.Seq = "rival-I", 1
			requireStatus(t, snapshot(t, append(fixture(), rival, terminal)), "A", Eligible, "")
			terminal.Prev = "missing-rival-or-root"
			requireStatus(t, snapshot(t, append(fixture(), terminal)), "A", Unknown, "unresolved_root_ancestry")
			terminal.Prev, terminal.Seq, terminal.Validity = "G", 2, Invalid
			r := requireStatus(t, snapshot(t, append(fixture(), terminal)), "A", Eligible, "")
			if len(r.Warnings) == 0 {
				t.Fatal("invalid terminal event silently disappeared")
			}
		})
	}
	// A rival-lineage cut naming I/G is not authority from the pinned inception.
	rival := line("rival-I", "R", 0, "", IdentityInception)
	rival.Inception = &Inception{Profile: FixedRoot}
	c := cut("rival-cut", "")
	c.Prev, c.Seq = "rival-I", 1
	requireStatus(t, snapshot(t, append(fixture(), rival, c)), "A", Eligible, "")
}

func TestRootForkGrantsCoexistAndMergesNeverUncut(t *testing.T) {
	fs := fixture()
	g2 := copyFact(fs[2])
	g2.ID = "G2"
	a2 := data("A2", 1, "D")
	a2.Actor.Grant = "G2"
	c := cut("C", "B")
	c2 := cut("C2", "")
	c2.Cut.Grant = "G2"
	c2.Prev = "G2"
	fs = append(fs, g2, a2, c)
	s := snapshot(t, fs)
	requireStatus(t, s, "A", Eligible, "")
	requireStatus(t, s, "A2", Eligible, "")
	requireStatus(t, s, "X", Denied, "cut_excluded")
	merge := line("root-merge", "R", 3, "C", Inert)
	merge.Merges = []ID{"C2"}
	s = snapshot(t, append(fs, c2, merge))
	requireStatus(t, s, "A", Eligible, "")
	requireStatus(t, s, "A2", Denied, "cut_excluded")
	requireStatus(t, s, "X", Denied, "cut_excluded")
}

func TestDelegateSelfEventsDoNotEraseOptedInHistory(t *testing.T) {
	for _, kind := range []Event{RotateKey, RevokeKey} {
		self := line("self-event", "K", 2, "A", kind)
		after := data("after", 3, "self-event")
		fs := append(fixture(), self, after)
		s := snapshot(t, fs)
		for _, id := range []ID{"A", "after"} {
			r := requireStatus(t, s, id, Eligible, "")
			if !slices.ContainsFunc(r.Warnings, func(w Warning) bool { return w.Code == "delegate_self_event" }) {
				t.Fatalf("self-event not visible: %+v", r)
			}
		}
		s = snapshot(t, append(fs, cut("C", "A")))
		requireStatus(t, s, "A", Eligible, "")
		requireStatus(t, s, "after", Denied, "cut_excluded")
		requireStatus(t, s, "self-event", Denied, "no_identity_actor")
		// A purported rotated successor cannot exercise the old key's grant.
		newKey := data("new-key-action", 1, "new-D")
		newKey.Signer = "new-K"
		requireStatus(t, snapshot(t, append(fs, line("new-D", "new-K", 0, "", Inert), newKey)), "new-key-action", Denied, "wrong_delegate")
	}
}

func TestNoAttributionToBareStatementsOrFallback(t *testing.T) {
	for _, binding := range []ActorBinding{NoIdentityContext, BoundIdentityContext} {
		fs := mutate(fixture(), "A", func(f *Fact) { f.Actor = nil; f.Binding = binding })
		r := requireStatus(t, snapshot(t, fs), "A", Denied, "no_identity_actor")
		if r.Actor != (Subject{Kind: KeySubject, Key: "K"}) || r.Grant != "" {
			t.Fatalf("retroactive attribution: %+v", r)
		}
	}
	r := requireStatus(t, snapshot(t, without(fixture(), "G")), "A", Unknown, "missing_evidence")
	if r.Actor.Kind != IdentitySubject || r.Actor.Identity != "I" {
		t.Fatalf("key fallback: %+v", r)
	}
}

func TestSameWorkerDifferentIdentitiesDoNotInterfere(t *testing.T) {
	fs := fixture()
	j := line("J", "JR", 0, "", IdentityInception)
	j.Inception = &Inception{Profile: FixedRoot}
	g := copyFact(fs[2])
	g.ID, g.Signer, g.Prev, g.Grant.Identity = "JG", "JR", "J", "J"
	a := data("JA", 1, "D")
	a.Actor = &Actor{Identity: "J", Grant: "JG"}
	fs = append(fs, j, g, a, cut("C", ""), line("retire-I", "R", 2, "G", RevokeKey))
	s := snapshot(t, fs)
	requireStatus(t, s, "A", Denied, "root_retired")
	requireStatus(t, s, "JA", Eligible, "")
	bad := cut("J-uncertain", "absent")
	bad.Signer, bad.Prev, bad.Cut.Identity, bad.Cut.Grant = "JR", "JG", "J", "JG"
	r := requireStatus(t, snapshot(t, append(fs, bad)), "A", Denied, "root_retired")
	if len(r.Dependencies) != 0 {
		t.Fatalf("other identity's dependency leaked: %+v", r)
	}
}

func TestAncestryCannotBeInventedByLastGood(t *testing.T) {
	cases := map[string]func([]Fact) []Fact{
		"wrong prev sequence": func(fs []Fact) []Fact { return mutate(fs, "A", func(f *Fact) { f.Seq = 4 }) },
		"cycle":               func(fs []Fact) []Fact { return mutate(fs, "A", func(f *Fact) { f.Prev = "B" }) },
		"self merge":          func(fs []Fact) []Fact { return mutate(fs, "A", func(f *Fact) { f.Merges = []ID{"A"} }) },
		"duplicate merge":     func(fs []Fact) []Fact { return mutate(fs, "M", func(f *Fact) { f.Merges = []ID{"X", "X"} }) },
		"cross-key merge":     func(fs []Fact) []Fact { return mutate(fs, "M", func(f *Fact) { f.Merges = []ID{"G"} }) },
		"other inception through merge": func(fs []Fact) []Fact {
			return append(mutate(fs, "M", func(f *Fact) { f.Merges = []ID{"D2"} }), line("D2", "K", 0, "", Inert))
		},
		"unlinked seq zero": func(fs []Fact) []Fact { return mutate(fs, "D", func(f *Fact) { f.Prev = "A" }) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			requireStatus(t, snapshot(t, append(edit(fixture()), cut("C", "M"))), "A", Denied, "")
		})
	}
	fs := mutate(fixture(), "A", func(f *Fact) { f.Validity = Invalid })
	requireStatus(t, snapshot(t, append(fs, cut("C", "A"))), "A", Denied, "invalid_evidence")
}

func TestSnapshotAndResultsAreDeeplyIsolated(t *testing.T) {
	fs := append(fixture(), cut("C", "M"))
	s := snapshot(t, fs)
	original := s.Evaluate("X")
	clone := s.Clone()
	// Mutate every exported reference-bearing input shape after construction.
	fs[0].Inception.Profile = UnknownProfile
	fs[2].Grant.Permissions[0].Targets[0] = "changed"
	fs[3].Actor.Identity = "changed"
	fs[3].Operation.Target.ID = "changed"
	fs[6].Merges[0] = "changed"
	fs[8].Cut.LastGood.ID = "changed"
	if !reflect.DeepEqual(original, s.Evaluate("X")) || !reflect.DeepEqual(original, clone.Evaluate("X")) {
		t.Fatal("input aliases leaked into immutable snapshot")
	}
	// Package-private adversarial mutation demonstrates Clone has no shared maps,
	// slices or nested grant/cut/actor/operation structures, not just no public setters.
	clone.facts["G"].Grant.Permissions[0].Targets[0] = "changed"
	clone.facts["C"].Cut.LastGood.ID = "changed"
	clone.facts["A"].Actor.Identity = "changed"
	clone.facts["A"].Operation.Target.ID = "changed"
	clone.facts["M"].Merges[0] = "changed"
	clone.facts["I"].Inception.Profile = UnknownProfile
	clone.order[0] = "changed"
	delete(clone.facts, "D")
	if !reflect.DeepEqual(original, s.Evaluate("X")) {
		t.Fatal("clone shares mutable state")
	}
	r := s.Evaluate("X")
	r.Basis[0], r.RelevantCuts[0] = "changed", "changed"
	if !reflect.DeepEqual(original, s.Evaluate("X")) {
		t.Fatal("result aliases snapshot")
	}
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			for range 15 {
				if got := s.Evaluate("X"); !reflect.DeepEqual(original, got) {
					t.Error("concurrent request changed result")
				}
			}
		})
	}
	wg.Wait()
}

func TestSnapshotConstructorAndLimit(t *testing.T) {
	fs := fixture()
	s := snapshot(t, fs)
	if got := snapshot(t, append(fs, copyFact(fs[0]))).EvidenceDigest(); got != s.EvidenceDigest() {
		t.Fatal("duplicate changes set digest")
	}
	bad := copyFact(fs[0])
	bad.Signer = "different"
	if _, err := NewSnapshot(append(fs, bad)); err == nil {
		t.Fatal("conflicting full IDs accepted")
	}
	if _, err := NewSnapshot([]Fact{{}}); err == nil {
		t.Fatal("empty ID accepted")
	}
	for n := 0; n <= MaxTraversalFacts; n++ {
		fs = append(fs, line(ID(fmt.Sprintf("extra-%d", n)), "unused", 0, "", Inert))
		forged := cut(ID(fmt.Sprintf("forged-%d", n)), "missing")
		forged.Authentication = Unproven
		fs = append(fs, forged)
	}
	requireStatus(t, snapshot(t, fs), "A", Eligible, "") // Noise cannot exhaust I's semantic budget.
	requireStatus(t, snapshot(t, nil), "absent", Unknown, "missing_evidence")
}

func TestRelevantTraversalLimitsCannotYieldPartialPass(t *testing.T) {
	fs := fixture()
	for n := 0; n < MaxTraversalFacts; n++ {
		fs = append(fs, line(ID(fmt.Sprintf("root-extra-%d", n)), "R", 2, "G", Inert))
	}
	requireStatus(t, snapshot(t, fs), "A", Unknown, "model_limit")
	fs = fixture()
	prev := ID("Z")
	for n := 5; n <= MaxTraversalFacts+5; n++ {
		id := ID(fmt.Sprintf("long-%d", n))
		fs = append(fs, data(id, uint64(n), prev))
		prev = id
	}
	requireStatus(t, snapshot(t, fs), prev, Unknown, "model_limit")
	requireStatus(t, snapshot(t, append(fs, cut("long-cut", prev))), "A", Unknown, "model_limit")
	fs = fixture()
	prev = "G"
	for n := 2; n <= MaxTraversalFacts+2; n++ {
		id := ID(fmt.Sprintf("root-long-%04d", n))
		fs = append(fs, line(id, "R", uint64(n), prev, Inert))
		prev = id
	}
	requireStatus(t, snapshot(t, fs), "A", Unknown, "model_limit")
}
