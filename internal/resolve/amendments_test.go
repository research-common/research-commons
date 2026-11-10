package resolve

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// amendsBody is the identity marker naming explicit amendment targets (sorted, as the profile requires).
func amendsBody(ids ...string) canon.Value {
	s := append([]string(nil), ids...)
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return obj("amends", s)
}

// identityWorld: three of I's claims on X by two worker keys. The fake evaluator decides who acts for I; the
// lines are bare rc/1 statements carrying the identity marker so the default reader holds them evidence-ready
// (the rc/2 reader that would hold real identity lines is not wired: profile not active).
func identityWorld(t *testing.T) (*world, *actorFake) {
	w := newWorld(t)
	w.authored("A0", "K1", "X", "licence", "MIT")
	f := &actorFake{}
	f.set(w.ids, "A0", policy.ActorEligible)
	return w, f
}

func selectIdentity(t *testing.T, w *world, f *actorFake, check func(*Artifact)) {
	t.Helper()
	sel := pol(t, []*canon.Object{identitySel(dig("X"), policy.RoleAuthorship)}, nil)
	sampledOrderArtifact(t, w, "X", check, WithPolicy(sel), WithActorEligibility(f))
}

// TestIdentityClaimsGroupByExplicitAmendment: identity profile §5.1 through the resolver with a test-only actor
// evaluator. I's claims group only by the explicit I and the explicit `amends` DAG; same-key ancestry amends
// nothing; maximal eligible nodes are current; concurrent cross-key amendments are both current, with no
// sequence, arrival or timestamp tiebreak; an amendment naming both reconciles. Every answer is the same under
// every sampled delivery order.
func TestIdentityClaimsGroupByExplicitAmendment(t *testing.T) {
	conformance.Partial(t, "C-id-21", "the amendment DAG and the contested current view through the resolver with a test-only actor evaluator; the same over signed rc/2 evidence needs the dual-major reader")
	conformance.Partial(t, "C-id-45", "the resolver applies an eligible cross-key, cross-grant amendment of I's claim (breadth is the evaluator's answer); end to end over signed rc/2 evidence needs the dual-major reader")

	// Same-key ancestry alone does not amend an identity claim: both are current, none preferred.
	w, f := identityWorld(t)
	w.authored("A1", "K1", "X", "licence", "CC0-1.0")
	f.set(w.ids, "A1", policy.ActorEligible)
	selectIdentity(t, w, f, func(a *Artifact) {
		wantField(t, a, "licence", FieldContested, "")
		has(t, a.Render(), "2 current claims")
		has(t, a.Render(), "no sequence, arrival or timestamp tiebreak")
	})

	// An explicit amendment by the same key replaces the target.
	w, f = identityWorld(t)
	w.authored("A1", "K1", "X", "licence", "CC0-1.0", wire.IdentityCrit, amendsBody(w.ids["A0"]))
	f.set(w.ids, "A1", policy.ActorEligible)
	selectIdentity(t, w, f, func(a *Artifact) {
		wantField(t, a, "licence", FieldDefault, `"CC0-1.0"`)
		hasNot(t, a.Render(), "current claims")
	})

	// Two concurrent cross-key amendments of A0: both current, contested, neither chosen by order or time.
	w, f = identityWorld(t)
	w.authored("A1", "K1", "X", "licence", "CC0-1.0", wire.IdentityCrit, amendsBody(w.ids["A0"]))
	w.authored("B1", "K2", "X", "licence", "Apache-2.0", wire.IdentityCrit, amendsBody(w.ids["A0"]))
	f.set(w.ids, "A1", policy.ActorEligible)
	f.set(w.ids, "B1", policy.ActorEligible)
	selectIdentity(t, w, f, func(a *Artifact) {
		wantField(t, a, "licence", FieldContested, "")
		if fl := a.Field("licence"); len(fl.From) != 2 {
			t.Fatalf("both concurrent amendments listed: %+v", fl)
		}
		has(t, a.Render(), "2 current claims")
		if a.Selection == nil || a.Selection.State != SelMet || len(a.Selection.Statements) != 2 {
			t.Fatalf("selection: %+v", a.Selection)
		}
	})

	// An eligible amendment naming both reconciles the branches.
	w.authored("C1", "K2", "X", "licence", "CC-BY-4.0", wire.IdentityCrit, amendsBody(w.ids["A1"], w.ids["B1"]))
	f.set(w.ids, "C1", policy.ActorEligible)
	selectIdentity(t, w, f, func(a *Artifact) {
		wantField(t, a, "licence", FieldDefault, `"CC-BY-4.0"`)
		hasNot(t, a.Render(), "current claims")
	})

	// An amendment the evaluator denies (no amend right, or own-mode outside the key's records) is no node:
	// A0 stays current, and the denied act is not substituted.
	w, f = identityWorld(t)
	w.authored("B1", "K2", "X", "licence", "Apache-2.0", wire.IdentityCrit, amendsBody(w.ids["A0"]))
	f.set(w.ids, "B1", policy.ActorDenied)
	selectIdentity(t, w, f, func(a *Artifact) { wantField(t, a, "licence", FieldDefault, `"MIT"`) })
}

// TestIdentityAmendmentTargets: identity profile §5.1 target rules through the resolver. An amendment naming a
// target of another principal, about another blob, or of another kind applies to nothing (the amendment is not a
// claim; the target's own standing is unchanged); an authorized amendment naming a missing target makes I's
// current view unknown, while an exact pin to an individually eligible claim still selects it; an outsider's
// header that binds to nothing changes nothing.
func TestIdentityAmendmentTargets(t *testing.T) {
	conformance.Partial(t, "C-id-22", "wrong principal, wrong content and missing target through the resolver with a test-only actor evaluator; the same over signed rc/2 evidence needs the dual-major reader")
	conformance.Partial(t, "C-id-44", "authorized missing-target amendment makes I's current view unknown (exact pin still met) and an unbound outsider changes nothing, through the resolver with a test-only actor evaluator; signed rc/2 end to end needs the dual-major reader")
	other := strings.Repeat("cd", 32)

	// Wrong principal: the target is J's claim.
	w, f := identityWorld(t)
	w.authored("J0", "K2", "X", "licence", "GPL-3.0")
	f.rows[w.ids["J0"]] = actorRow{other, policy.ActorEligible}
	w.authored("A1", "K1", "X", "licence", "CC0-1.0", wire.IdentityCrit, amendsBody(w.ids["A0"], w.ids["J0"]))
	f.set(w.ids, "A1", policy.ActorEligible)
	selectIdentity(t, w, f, func(a *Artifact) {
		wantField(t, a, "licence", FieldDefault, `"MIT"`)
		has(t, a.Render(), "amends nothing")
		has(t, a.Render(), "is not a claim of identity")
	})

	// Wrong content: the target is I's claim about another blob.
	w, f = identityWorld(t)
	w.authored("Y0", "K1", "Y", "licence", "MIT")
	f.set(w.ids, "Y0", policy.ActorEligible)
	w.authored("A1", "K1", "X", "licence", "CC0-1.0", wire.IdentityCrit, amendsBody(w.ids["Y0"]))
	f.set(w.ids, "A1", policy.ActorEligible)
	selectIdentity(t, w, f, func(a *Artifact) {
		wantField(t, a, "licence", FieldDefault, `"MIT"`)
		has(t, a.Render(), "about another blob")
	})

	// A target that is I's claim in shape but not eligible for I (a cut left it outside last_good): the amendment
	// applies to nothing, and the ineligible target is not current either.
	w, f = identityWorld(t)
	w.authored("A1", "K1", "X", "licence", "CC0-1.0", wire.IdentityCrit, amendsBody(w.ids["A0"]))
	f.set(w.ids, "A1", policy.ActorEligible)
	f.set(w.ids, "A0", policy.ActorDenied)
	selectIdentity(t, w, f, func(a *Artifact) {
		wantField(t, a, "licence", FieldSelectionUnmet, "")
		has(t, a.Render(), SelNone)
		has(t, a.Render(), "is not a claim of identity")
	})

	// Missing target: authorized amendment of I's claims naming A0 and an unheld id. Current view unknown; no
	// claim chosen, A0 not advertised as cleanly current.
	ghost := strings.Repeat("e", 64)
	w, f = identityWorld(t)
	w.authored("A1", "K2", "X", "licence", "CC0-1.0", wire.IdentityCrit, amendsBody(w.ids["A0"], ghost))
	f.set(w.ids, "A1", policy.ActorEligible)
	selectIdentity(t, w, f, func(a *Artifact) {
		wantField(t, a, "licence", FieldSelectionUnmet, "")
		has(t, a.Render(), SelIdentityUnknown)
		has(t, a.Render(), "is not held")
		hasNot(t, a.Render(), "profile not active")
	})
	// ... an exact pin to the individually eligible A0 still selects it.
	pin := pol(t, []*canon.Object{pinSel(dig("X"), policy.RoleAuthorship, w.ids["A0"])}, nil)
	sampledOrderArtifact(t, w, "X", func(a *Artifact) { wantField(t, a, "licence", FieldDefault, `"MIT"`) },
		WithPolicy(pin), WithActorEligibility(f))
	// ... and a target whose eligibility for I the evaluator cannot decide is the same uncertainty (a target of
	// the right kind and blob is itself a candidate, so it is named as undecided).
	w, f = identityWorld(t)
	w.authored("A1", "K1", "X", "licence", "CC0-1.0", wire.IdentityCrit, amendsBody(w.ids["A0"]))
	f.set(w.ids, "A1", policy.ActorEligible)
	f.set(w.ids, "A0", policy.ActorUnknown)
	selectIdentity(t, w, f, func(a *Artifact) {
		wantField(t, a, "licence", FieldSelectionUnmet, "")
		has(t, a.Render(), SelIdentityUnknown)
	})

	// Outsider: a header naming I that binds to nothing (the evaluator answers no identity) changes nothing,
	// even when it names a missing target.
	w, f = identityWorld(t)
	w.authored("S1", "S", "X", "licence", "WTFPL", wire.IdentityCrit, amendsBody(w.ids["A0"], ghost))
	selectIdentity(t, w, f, func(a *Artifact) {
		wantField(t, a, "licence", FieldDefault, `"MIT"`)
		hasNot(t, a.Render(), SelIdentityUnknown)
	})
}
