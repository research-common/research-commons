package resolve

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// unitsOpts is a resolver with a test-only actor evaluator and a fake chain that verifies heights 100…103.
func unitsOpts(f *actorFake) []Option {
	return []Option{WithActorEligibility(f), WithTimeVerifier(newFakeBitcoin(100, 101, 102, 103))}
}

func subjectsOf(u *Unit) []Subject { return u.Subjects() }

// TestIdentityAuthorshipUnits: identity profile §5.1 in artifact authorship, through the resolver with a test-only
// actor evaluator. Statements the evaluator finds eligible for I are one claim of I (never their keys'), whichever
// delegate key signed them; I's unit takes part in priority like a key's; same-key ancestry amends nothing; a
// statement of a key the evaluator binds to no identity stays its key's claim.
func TestIdentityAuthorshipUnits(t *testing.T) {
	conformance.Partial(t, "C-id-21", "artifact authorship groups I's claims by the explicit amendment DAG (concurrent cross-key amendments both current, fields contested, an amendment naming both reconciles) through the resolver with a test-only actor evaluator; signed rc/2 end to end is TestIdentityAuthorshipSignedRC2")
	I := IdentitySubject(actorI)

	// Two delegate keys of I author X: one claim of I, signed by both, sole author.
	w := newWorld(t)
	w.authored("A0", "K1", "X", "licence", "MIT")
	w.authored("B0", "K2", "X", "licence", "MIT")
	f := &actorFake{}
	f.set(w.ids, "A0", policy.ActorEligible)
	f.set(w.ids, "B0", policy.ActorEligible)
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, SoleAuthor)
		if len(a.Claims) != 1 || a.Claims[0].Subject != I || !slices.Equal(a.Claims[0].Signers, slices.Sorted(slices.Values([]string{w.signer("K1"), w.signer("K2")}))) ||
			len(a.Claims[0].Current) != 2 {
			t.Fatalf("one claim of I signed by both keys: %+v %v %v", *a.Claims[0], w.signer("K1"), w.signer("K2"))
		}
		wantField(t, a, "licence", FieldDefault, `"MIT"`)
		has(t, a.Render(), "author identity "+keylog.Short(actorI))
		has(t, a.Render(), "for identity "+keylog.Short(actorI))
	}, unitsOpts(f)...)

	// Same-key ancestry amends nothing for I: both of K1's statements stay current; they disagree, so contested.
	w = newWorld(t)
	w.authored("A0", "K1", "X", "licence", "MIT")
	w.authored("A1", "K1", "X", "licence", "CC0-1.0")
	f = &actorFake{}
	f.set(w.ids, "A0", policy.ActorEligible)
	f.set(w.ids, "A1", policy.ActorEligible)
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, SoleAuthor)
		wantField(t, a, "licence", FieldContested, "")
		has(t, a.Render(), "2 current claims on this blob")
		wantExit(t, a, 3, "field licence: contested")
	}, unitsOpts(f)...)

	// Concurrent cross-key explicit amendments: both current, contested; one naming both reconciles.
	w = newWorld(t)
	w.authored("A0", "K1", "X", "licence", "MIT")
	w.authored("A1", "K1", "X", "licence", "CC0-1.0", wire.IdentityCrit, amendsBody(w.ids["A0"]))
	w.authored("B1", "K2", "X", "licence", "Apache-2.0", wire.IdentityCrit, amendsBody(w.ids["A0"]))
	f = &actorFake{}
	for _, n := range []string{"A0", "A1", "B1"} {
		f.set(w.ids, n, policy.ActorEligible)
	}
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		wantField(t, a, "licence", FieldContested, "")
		if c := a.Claims[0]; len(c.Current) != 2 || len(c.Statements) != 3 || len(c.Amends) != 2 {
			t.Fatalf("concurrent amendments: %+v", c)
		}
	}, unitsOpts(f)...)
	w.authored("C1", "K2", "X", "licence", "CC-BY-4.0", wire.IdentityCrit, amendsBody(w.ids["A1"], w.ids["B1"]))
	f.set(w.ids, "C1", policy.ActorEligible)
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		wantField(t, a, "licence", FieldDefault, `"CC-BY-4.0"`)
		has(t, a.Render(), "(amends "+shorts(slices.Sorted(slices.Values([]string{w.ids["A1"], w.ids["B1"]})))+")")
		wantExit(t, a, 0, "")
	}, unitsOpts(f)...)

	// I against a bare key: I's unit (K1 anchored at 100) has priority over key B (101). B's statement, which the
	// evaluator binds to no identity, is B's own claim.
	w = newWorld(t)
	w.authored("A0", "K1", "X", "licence", "MIT")
	w.anchor("a1", "K1", "btc:100")
	w.authored("B0", "B", "X", "licence", "GPL-3.0")
	w.anchor("b1", "B", "btc:101")
	f = &actorFake{}
	f.set(w.ids, "A0", policy.ActorEligible)
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, Priority)
		if !slices.Equal(subjectsOf(a.Default), []Subject{I}) || !slices.Equal(subjectsOf(a.Later[0]), []Subject{KeySubject(w.signer("B"))}) {
			t.Fatalf("default %v later %v", subjectsOf(a.Default), subjectsOf(a.Later[0]))
		}
		wantField(t, a, "licence", FieldDefault, `"MIT"`)
	}, unitsOpts(f)...)
	// Without the evaluator the same lines are two key claims: today's answer.
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, Priority)
		if !slices.Equal(subjectsOf(a.Default), []Subject{KeySubject(w.signer("K1"))}) {
			t.Fatalf("no evaluator: default %v", subjectsOf(a.Default))
		}
	}, WithTimeVerifier(newFakeBitcoin(100, 101)))
}

// TestIdentityUnitPriorityFollowsAncestry: D-1110-2. An identity unit's bound is the best verified bound among its
// current claims and their explicit eligible amendment ancestry: an amendment by a later key inherits the bound of
// the claim it amends, but a claim of I with another provenance (another claim of I, not in this one's ancestry)
// lends it nothing.
func TestIdentityUnitPriorityFollowsAncestry(t *testing.T) {
	// A0 by K1 at 100, amended by K2's A1 (K2 anchored only at 102). Rival B at 101. I keeps 100 through A0.
	w := newWorld(t)
	w.authored("A0", "K1", "X", "licence", "MIT")
	w.anchor("a1", "K1", "btc:100")
	w.authored("B0", "B", "X")
	w.anchor("b1", "B", "btc:101")
	w.authored("A1", "K2", "X", "licence", "CC0-1.0", wire.IdentityCrit, amendsBody(w.ids["A0"]))
	w.anchor("k2", "K2", "btc:102")
	f := &actorFake{}
	f.set(w.ids, "A0", policy.ActorEligible)
	f.set(w.ids, "A1", policy.ActorEligible)
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, Priority)
		if a.Default.Claims[0].Subject != IdentitySubject(actorI) || a.Default.Bound.Height != 100 {
			t.Fatalf("I's bound through explicit ancestry: %+v\n%s", a.Default.Bound, a.Render())
		}
		wantField(t, a, "licence", FieldDefault, `"CC0-1.0"`)
	}, unitsOpts(f)...)

	// No borrowing: I's early claim P (K1 at 100) is a derivation under wf; its other current claim N (K2 at 102,
	// no provenance) is a separate claim and unit. N's unit has bound 102 and loses to B (101); P's unit is not N's.
	w = newWorld(t)
	w.authored("P", "K1", "X", "prov", []string{"wf", "in"})
	w.anchor("a1", "K1", "btc:100")
	w.authored("B0", "B", "X")
	w.anchor("b1", "B", "btc:101")
	w.authored("N", "K2", "X")
	w.anchor("k2", "K2", "btc:102")
	f = &actorFake{}
	f.set(w.ids, "P", policy.ActorEligible)
	f.set(w.ids, "N", policy.ActorEligible)
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		if len(a.Units) != 3 {
			t.Fatalf("units: %d\n%s", len(a.Units), a.Render())
		}
		for _, u := range a.Units {
			if u.Provenance == nil && u.Claims[0].Subject.Kind == SubjectIdentity && u.Bound.Height != 102 {
				t.Fatalf("I's claim without provenance borrowed a bound: %+v\n%s", u.Bound, a.Render())
			}
		}
		if a.Default == nil || a.Default.Provenance == nil {
			t.Fatalf("the derivation (100) has priority:\n%s", a.Render())
		}
	}, unitsOpts(f)...)
}

// TestIdentityUnitDerivationGroup: an identity's claim with provenance joins the derivation group for that
// provenance exactly as a key's does; the group runs only I's current claims (by explicit amendment).
func TestIdentityUnitDerivationGroup(t *testing.T) {
	w := newWorld(t)
	w.authored("A0", "K1", "X", "prov", []string{"wf", "in"})
	w.authored("C0", "C", "X", "prov", []string{"wf", "in"})
	f := &actorFake{}
	f.set(w.ids, "A0", policy.ActorEligible)
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, Derived)
		if len(a.Units) != 1 || !slices.Equal(subjectsOf(a.Units[0]), []Subject{KeySubject(w.signer("C")), IdentitySubject(actorI)}) {
			t.Fatalf("one derivation group of C and I: %v", subjectsOf(a.Units[0]))
		}
		if a.Group == nil || len(a.Group.Runs) != 2 {
			t.Fatalf("both runs in the group: %+v", a.Group)
		}
	}, unitsOpts(f)...)

	// I's same-key successor does not retire A0 from the group (same-key ancestry amends nothing for I), an
	// explicit amendment does.
	w.authored("A1", "K1", "X", "prov", []string{"wf", "in"})
	f.set(w.ids, "A1", policy.ActorEligible)
	if g := w.store(nil, unitsOpts(f)...).Artifact(dig("X")).Group; g == nil || len(g.Runs) != 3 {
		t.Fatalf("same-key ancestry retired an identity run: %+v", g)
	}
	w.authored("A2", "K2", "X", "prov", []string{"wf", "in"}, wire.IdentityCrit, amendsBody(w.ids["A0"], w.ids["A1"]))
	f.set(w.ids, "A2", policy.ActorEligible)
	if g := w.store(nil, unitsOpts(f)...).Artifact(dig("X")).Group; g == nil || len(g.Runs) != 2 {
		t.Fatalf("explicit amendment did not retire I's amended runs: %+v", g)
	}
}

// TestIdentityUnitUnknownCurrentView: D-1110-3 and C-id-44 in authorship. An authorized amendment of I's claims
// naming a missing target makes I's current view unknown: I's unit still takes part in priority with the bounds
// of its eligible statements, every single-party field from it reads unknown naming the amendment, and verify
// exits 3. An outsider whose header the evaluator binds to no identity changes nothing.
func TestIdentityUnitUnknownCurrentView(t *testing.T) {
	conformance.Partial(t, "C-id-44", "artifact authorship: an authorized missing-target amendment makes I's fields unknown (verify 3) while I keeps its priority; an unbound outsider changes nothing; through the resolver with a test-only actor evaluator; signed rc/2 is TestIdentityAuthorshipSignedRC2")
	ghost := strings.Repeat("e", 64)
	w := newWorld(t)
	w.authored("A0", "K1", "X", "licence", "MIT")
	w.anchor("a1", "K1", "btc:100")
	w.authored("B0", "B", "X", "licence", "GPL-3.0")
	w.anchor("b1", "B", "btc:101")
	w.authored("A1", "K2", "X", "licence", "CC0-1.0", wire.IdentityCrit, amendsBody(w.ids["A0"], ghost))
	f := &actorFake{}
	f.set(w.ids, "A0", policy.ActorEligible)
	f.set(w.ids, "A1", policy.ActorEligible)
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, Priority)
		if a.Default.Claims[0].Subject != IdentitySubject(actorI) || len(a.Default.Claims[0].Unresolved) != 1 {
			t.Fatalf("I keeps priority, view unknown: %+v\n%s", a.Default.Claims[0], a.Render())
		}
		wantField(t, a, "licence", FieldUnknown, "")
		has(t, a.Field("licence").Why, "is not held")
		has(t, a.Render(), "licence: unknown")
		wantExit(t, a, 3, "authorship: unknown")
	}, unitsOpts(f)...)

	// An outsider S whose header the evaluator binds to no identity: its key's own claim, and I is untouched.
	w = newWorld(t)
	w.authored("A0", "K1", "X", "licence", "MIT")
	w.authored("S1", "S", "X", "licence", "WTFPL", wire.IdentityCrit, amendsBody(w.ids["A0"], ghost))
	f = &actorFake{}
	f.set(w.ids, "A0", policy.ActorEligible)
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		for _, u := range a.Units {
			for _, c := range u.Claims {
				if len(c.Unresolved) > 0 {
					t.Fatalf("an outsider stalled I:\n%s", a.Render())
				}
			}
		}
		hasNot(t, a.Render(), "unknown")
	}, unitsOpts(f)...)
}

// TestIdentityUnitNotCounted: statements the evaluator binds to I but denies or cannot decide are listed under I,
// with the gate's reason, and counted toward nothing (never as their keys' claims); an amendment naming another
// principal's claim applies to nothing and is listed, not a claim.
func TestIdentityUnitNotCounted(t *testing.T) {
	other := strings.Repeat("cd", 32)
	w := newWorld(t)
	w.authored("A0", "K1", "X", "licence", "MIT")
	w.authored("D0", "K2", "X", "licence", "GPL-3.0")
	w.authored("U0", "K3", "X", "licence", "WTFPL")
	w.authored("J0", "K4", "X", "licence", "CC0-1.0")
	w.authored("A1", "K1", "X", "licence", "Apache-2.0", wire.IdentityCrit, amendsBody(w.ids["J0"]))
	f := &actorFake{}
	f.set(w.ids, "A0", policy.ActorEligible)
	f.set(w.ids, "D0", policy.ActorDenied)
	f.set(w.ids, "U0", policy.ActorUnknown)
	f.set(w.ids, "A1", policy.ActorEligible)
	f.rows[w.ids["J0"]] = actorRow{other, policy.ActorEligible}
	sampledOrderArtifact(t, w, "X", func(a *Artifact) {
		why := map[string]NotCounted{}
		for _, n := range a.NotCounted {
			why[n.Statement] = n
		}
		for n, want := range map[string]string{"D0": "not eligible for identity", "U0": "is not established", "A1": "amends nothing"} {
			nc, ok := why[w.ids[n]]
			if !ok || nc.Subject != IdentitySubject(actorI) || !strings.Contains(nc.Why, want) {
				t.Fatalf("%s: %+v\n%s", n, nc, a.Render())
			}
		}
		// I's claim is A0 alone; J's claim is J's; neither D0, U0 nor A1 is anyone's
		var subjects []Subject
		for _, c := range a.Claims {
			subjects = append(subjects, c.Subject)
			if slices.ContainsFunc(c.Statements, func(id string) bool { return id == w.ids["D0"] || id == w.ids["U0"] || id == w.ids["A1"] }) {
				t.Fatalf("a not-counted statement is in a claim: %+v", c)
			}
		}
		if !slices.Equal(subjects, []Subject{IdentitySubject(actorI), IdentitySubject(other)}) {
			t.Fatalf("claims %v", subjects)
		}
		has(t, a.Render(), "for identity "+keylog.Short(actorI)+" not counted")
	}, unitsOpts(f)...)
}

// identityAmending incepts identity name (root key root) and grants each worker `authored` with amend:true over any
// content (identity-wide amendment breadth, profile §3). It returns the inception and one grant per worker.
func (w *world) identityAmending(name, root string, workers ...string) (string, map[string]string) {
	w.t.Helper()
	id := w.signRC2(name, root, "identity_inception", obj("profile", wire.FixedRootProfile), rc2MarkerOnly, [2]string{})
	grants := map[string]string{}
	for _, wk := range workers {
		perms := canon.Array{obj("kind", "authored", "targets", obj("any_content", true), "amend", true)}
		grants[wk] = w.signRC2(name+":grant:"+wk, root, "identity_grant", obj("identity", id,
			"delegate", obj("key", w.signer(wk), "inception", w.firstLine(wk)), "permissions", perms), rc2MarkerOnly, [2]string{})
	}
	return id, grants
}

// TestIdentityAuthorshipSignedRC2: the authorship scenarios over signed rc/2 evidence, read by the candidate
// dual-major reader and judged by the real candidate actor evaluator (identity.Actors), no fake. Two delegate keys
// of I: one claim of I; same-key ancestry amends nothing; concurrent cross-key amendments are contested and one
// naming both reconciles; an amendment naming a missing target makes I's fields unknown; an amendment naming
// another principal's claim applies to nothing; an outsider's self-signed header naming I with an invented grant
// changes nothing. Without the evaluator every identity statement counts toward nothing (hook-absent text).
func TestIdentityAuthorshipSignedRC2(t *testing.T) {
	conformance.Partial(t, "C-id-21", "artifact authorship over signed rc/2 lines with the real candidate evaluator under the dual reader: concurrent cross-key amendments contested, reconciliation by an amendment naming both; the profile is not active (no production reader wires the evaluator)")
	conformance.Partial(t, "C-id-22", "artifact authorship over signed rc/2 with the real evaluator: a missing target makes I's fields unknown, another principal's target makes the amendment apply to nothing and not a claim; not active in production")
	conformance.Partial(t, "C-id-44", "artifact authorship over signed rc/2 with the real evaluator: authorized missing-target amendment makes I's fields unknown (verify 3); an outsider's self-signed header with an invented grant changes nothing; not active in production")
	conformance.Partial(t, "C-id-45", "artifact authorship over signed rc/2 with the real evaluator: amend:true lets K2 amend K1's claim of I across keys and grants; not active in production")
	ghost := strings.Repeat("e", 64)
	lic := func(l string) *canon.Object {
		return obj("content", contentOf("X"), "type", "dataset", "licence", l)
	}
	amending := func(l string, targets ...string) *canon.Object {
		return withMember(lic(l), wire.IdentityCrit, amendsBody(targets...))
	}
	build := func() (*world, [2]string, [2]string, string) {
		w := newWorld(t)
		w.authored("K1:0", "K1", "K1-0")
		w.authored("K2:0", "K2", "K2-0")
		w.authored("S:0", "S", "S-0")
		i, g := w.identityAmending("I", "IR", "K1", "K2")
		return w, [2]string{i, g["K1"]}, [2]string{i, g["K2"]}, i
	}
	read := func(w *world, opts ...Option) *Artifact {
		t.Helper()
		var lines [][]byte
		lines = append(lines, w.lines...)
		actors, err := identity.NewActors(lines)
		if err != nil {
			t.Fatal(err)
		}
		return dualResolver(t, w, append([]Option{WithActorEligibility(actors)}, opts...)...).Artifact(dig("X"))
	}

	// two keys of I, then K1 again (same-key successor, no amends): three current claims of I, contested
	w, a1, a2, i := build()
	w.signRC2("A0", "K1", "authored", lic("MIT"), rc2Actor, a1)
	w.signRC2("B0", "K2", "authored", lic("MIT"), rc2Actor, a2)
	a := read(w)
	if a.State != SoleAuthor || len(a.Claims) != 1 || a.Claims[0].Subject != IdentitySubject(i) || len(a.Claims[0].Signers) != 2 {
		t.Fatalf("one claim of I by two keys:\n%s", a.Render())
	}
	wantField(t, a, "licence", FieldDefault, `"MIT"`)
	w.signRC2("A1", "K1", "authored", lic("CC0-1.0"), rc2Actor, a1)
	wantField(t, read(w), "licence", FieldContested, "")

	// cross-key concurrent amendments, then reconciliation (K2 amends K1's claim: amend:true is identity-wide)
	w, a1, a2, _ = build()
	w.signRC2("A0", "K1", "authored", lic("MIT"), rc2Actor, a1)
	w.signRC2("A1", "K1", "authored", amending("CC0-1.0", w.ids["A0"]), rc2Actor, a1)
	w.signRC2("B1", "K2", "authored", amending("Apache-2.0", w.ids["A0"]), rc2Actor, a2)
	a = read(w)
	if len(a.Claims) != 1 || len(a.Claims[0].Current) != 2 {
		t.Fatalf("concurrent amendments both current:\n%s", a.Render())
	}
	wantField(t, a, "licence", FieldContested, "")
	w.signRC2("C1", "K2", "authored", amending("CC-BY-4.0", w.ids["A1"], w.ids["B1"]), rc2Actor, a2)
	a = read(w)
	wantField(t, a, "licence", FieldDefault, `"CC-BY-4.0"`)
	wantExit(t, a, 0, "")

	// a missing target: I's view is unknown, verify 3
	w, a1, a2, _ = build()
	w.signRC2("A0", "K1", "authored", lic("MIT"), rc2Actor, a1)
	w.signRC2("B1", "K2", "authored", amending("CC0-1.0", w.ids["A0"], ghost), rc2Actor, a2)
	a = read(w)
	wantField(t, a, "licence", FieldUnknown, "")
	wantExit(t, a, 3, "authorship: unknown")

	// another principal's target: S's bare-key claim. The amendment applies to nothing and is not a claim of I.
	w, a1, a2, i = build()
	w.signRC2("A0", "K1", "authored", lic("MIT"), rc2Actor, a1)
	w.authored("S1", "S", "X", "licence", "GPL-3.0")
	w.signRC2("B1", "K2", "authored", amending("CC0-1.0", w.ids["S1"]), rc2Actor, a2)
	a = read(w)
	if len(a.NotCounted) != 1 || a.NotCounted[0].Statement != w.ids["B1"] || a.NotCounted[0].Subject != IdentitySubject(i) ||
		!strings.Contains(a.NotCounted[0].Why, "amends nothing") {
		t.Fatalf("wrong-principal amendment:\n%s", a.Render())
	}

	// an outsider S signs a header naming I with an invented grant: not counted, I untouched
	w, a1, _, i = build()
	w.signRC2("A0", "K1", "authored", lic("MIT"), rc2Actor, a1)
	before := read(w)
	w.signRC2("Z", "S", "authored", amending("WTFPL", w.ids["A0"], ghost), rc2Actor, [2]string{i, ghost})
	a = read(w)
	if a.Outcome() != before.Outcome() || len(a.NotCounted) != 1 || a.NotCounted[0].Subject != KeySubject(w.signer("S")) ||
		!strings.Contains(a.NotCounted[0].Why, "binds it to no identity") {
		t.Fatalf("an outsider changed I's answer:\n%s\nvs\n%s", a.Render(), before.Render())
	}

	// no evaluator: identity statements count toward nothing, with the hook-absent text, never as their keys'
	b := dualResolver(t, w).Artifact(dig("X"))
	if b.State != NoClaim || !strings.Contains(b.Render(), "unknown (identity profile not active)") {
		t.Fatalf("hook absent:\n%s", b.Render())
	}
}
