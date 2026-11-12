package resolve

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance/fixture"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/policy"
)

// The counting gate (actorgate.go) across every non-task consumer that decides whether a statement counts toward
// something: membership records, observation others and revisions, member records of edition rules, credit,
// completeness, describes, the corroboration lookups, amendment targets, time anchors, selections and derivation
// groups. With no actor evaluator each answer is exactly the bare-key one; with one, an identity-context statement
// counts by its actor's eligibility (never as its key's evidence), and a consumer that filters by signing key keeps
// that filter.

// gateWorld: dualFallbackWorld's identity I (root IR, worker K) plus, by K for I, a second observation of the base
// observation's bytes (O2), an authored claim on X naming O in its provenance, and an anchor of K's log. Return
// the world and the named ids.
func gateWorld(t *testing.T) (*world, map[string]string) {
	w, ids := dualFallbackWorld(t)
	act := [2]string{ids["I"], ids["G"]}
	w.signRC2("K:observedX", "K", "observed", obj("content", contentOf("X"), "class", "exact-bytes", "referent", chainRef(3),
		"capture", obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted")), rc2Actor, act)
	return w, ids
}

// eligibleFor is a test evaluator that binds each named statement to identity i and answers state.
func eligibleFor(w *world, i, state string, names ...string) *actorFake {
	f := &actorFake{rows: map[string]actorRow{}}
	for _, n := range names {
		f.rows[w.ids[n]] = actorRow{i, state}
	}
	return f
}

// TestGateConsumersNoEvaluator: with no evaluator every consumer gives the bare-key answer, byte for byte: the
// rc/2 actor lines count toward nothing with the hook-absent text in each consumer that shows a cause, and a nil
// evaluator is none.
func TestGateConsumersNoEvaluator(t *testing.T) {
	w, ids := gateWorld(t)
	r := dualResolver(t, w)
	o, _ := r.Observation(ids["O"])
	has(t, strings.Join(o.Others, "\n"), "counts toward nothing: unknown (identity profile not active)")
	x, _ := r.Observation(w.ids["K:observedX"])
	if x.Counts {
		t.Fatalf("an actor observation counted without an evaluator:\n%s", x.Render())
	}
	has(t, x.Render(), "this statement counts toward nothing: unknown (identity profile not active)")
	if a := r.Artifact(dig("Y")); len(a.Holders) != 0 {
		t.Fatalf("actor holds served without an evaluator: %v", a.Holders)
	}
	if c := r.Credit(w.signer("K"), &CreditRule{Name: "all"}); strings.Contains(c.Render(), keylog.Short(w.ids["K:corroborates"])) {
		t.Fatalf("an actor corroboration credited to its key without an evaluator:\n%s", c.Render())
	}
	want := everyView(r, []string{dig("X"), dig("Y"), dig("Z"), dig("U"), dig("V")})
	if got := everyView(dualResolver(t, w, WithActorEligibility(nil)), []string{dig("X"), dig("Y"), dig("Z"), dig("U"), dig("V")}); got != want {
		t.Fatalf("a nil evaluator moved an answer: %s", firstDiff(want, got))
	}
}

// TestGateConsumersWithEvaluator: an evaluator that finds K's lines eligible for I makes them count in every
// consumer (the observation itself, others, holders, credit and reputation by signing key); one that denies or
// cannot decide leaves them out with its own reason, never the hook-absent text; and an actor line is never its
// key's claim for a `{key: K}` selection, whatever the evaluator says.
func TestGateConsumersWithEvaluator(t *testing.T) {
	w, ids := gateWorld(t)
	acts := []string{"K:authored", "K:holds", "K:corroborates", "K:observed", "K:observedX"}
	on := dualResolver(t, w, WithActorEligibility(eligibleFor(w, ids["I"], policy.ActorEligible, acts...)))

	// observation: counts, with no hook-absent text anywhere in its view or in the others of the base observation
	x, _ := on.Observation(w.ids["K:observedX"])
	if !x.Counts {
		t.Fatalf("an eligible actor observation does not count:\n%s", x.Render())
	}
	hasNot(t, x.Render(), "profile not active")
	o, _ := on.Observation(ids["O"])
	others := strings.Join(o.Others, "\n")
	has(t, others, "also observed by "+shortKey(w.signer("K"))+" in "+keylog.Short(w.ids["K:observedX"])+" as exact-bytes")
	hasNot(t, others, "counts toward nothing")
	// holders: an eligible holds serves (holders are listed by key: whose word it is)
	if a := on.Artifact(dig("Y")); len(a.Holders) != 1 || a.Holders[0] != w.signer("K") {
		t.Fatalf("eligible actor holds: %v\n%s", a.Holders, a.Render())
	}
	// credit and reputation keep the signing-key filter: K's record, never I's or another key's
	c := on.Credit(w.signer("K"), &CreditRule{Name: "all"})
	has(t, c.Render(), "corroboration: 1 of")
	if c := on.Credit(w.signer("IR"), &CreditRule{Name: "all"}); strings.Contains(c.Render(), "corroboration: 1 of") {
		t.Fatalf("the root key was credited with its delegate's act:\n%s", c.Render())
	}
	rep, err := on.Reputation(w.signer("K"), ReputationRule{Name: "all", From: "2026-01-01T00:00:00Z", To: "2027-01-01T00:00:00Z"})
	if err != nil || rep.Denominator != 2 {
		t.Fatalf("reputation of K over its eligible observations: %+v %v", rep, err)
	}

	// a key selection never follows K's actor claim, even when it counts (it is I's claim, not K's)
	sel := dualResolver(t, w, WithActorEligibility(eligibleFor(w, ids["I"], policy.ActorEligible, acts...)),
		WithPolicy(pol(t, []*canon.Object{keySel(dig("Y"), policy.RoleAuthorship, w.signer("K"))}, nil))).Artifact(dig("Y"))
	if sel.Selection == nil || sel.Selection.Met() {
		t.Fatalf("a key selection followed an identity claim: %+v\n%s", sel.Selection, sel.Render())
	}

	// denied and undecided: not counted, each with the evaluator's reason; no hook-absent text
	for _, state := range []string{policy.ActorDenied, policy.ActorUnknown} {
		off := dualResolver(t, w, WithActorEligibility(eligibleFor(w, ids["I"], state, acts...)))
		x, _ := off.Observation(w.ids["K:observedX"])
		if x.Counts {
			t.Fatalf("%s: counted:\n%s", state, x.Render())
		}
		o, _ := off.Observation(ids["O"])
		others := strings.Join(o.Others, "\n")
		has(t, others, "counts toward nothing: ")
		hasNot(t, others, "profile not active")
		hasNot(t, x.Render(), "profile not active")
		if a := off.Artifact(dig("Y")); len(a.Holders) != 0 {
			t.Fatalf("%s: holds served: %v", state, a.Holders)
		}
		if rep, _ := off.Reputation(w.signer("K"), ReputationRule{Name: "all", From: "2026-01-01T00:00:00Z", To: "2027-01-01T00:00:00Z"}); rep.Denominator != 0 {
			t.Fatalf("%s: reputation counted %d observations", state, rep.Denominator)
		}
	}
}

// TestGateAnchorsKeyScoped: an anchor bounds only its signer's own log, with or without an evaluator: a root's
// anchor never bounds its delegate's statement (identity profile §4: anchors remain key-local). An identity-context
// anchor of K's own log bounds K's statements while its actor counts and loses the bound when the evaluator
// excludes it, without touching whether the bounded claim counts (C-id-23's shape).
func TestGateAnchorsKeyScoped(t *testing.T) {
	w, ids := gateWorld(t)
	act := [2]string{ids["I"], ids["G"]}
	// the root anchors its own log (verified height 100): it bounds nothing of K's
	w.sign("IR:anchor", "IR", "anchors", obj("covered", w.head["IR"], "proof", dig("btc:100"), "proof_format", "ots-detached-v1"))
	// K anchors its own log for I (verified height 101): it covers K's authored for I
	w.signRC2("K:anchor", "K", "anchors", obj("covered", w.head["K"], "proof", dig("btc:101"), "proof_format", "ots-detached-v1"), rc2Actor, act)
	tv := WithTimeVerifier(newFakeBitcoin(100, 101))
	acts := []string{"K:authored", "K:anchor"}

	bound := func(r *Resolver, name string) Bound {
		p, ok := r.Statement(w.ids[name])
		if !ok {
			t.Fatalf("%s not held", name)
		}
		return r.bound(p.St)
	}
	if b := bound(dualResolver(t, w, tv), "K:authored"); b.Quality != NoBound {
		t.Fatalf("no evaluator: an uncounted actor anchor or the root's anchor bounded K's line: %+v", b)
	}
	on := dualResolver(t, w, tv, WithActorEligibility(eligibleFor(w, ids["I"], policy.ActorEligible, acts...)))
	if b := bound(on, "K:authored"); b.Quality != Bitcoin || b.Height != 101 || b.Anchor != w.ids["K:anchor"] {
		t.Fatalf("eligible: K's own anchor should bound K's line at 101 (never the root's at 100): %+v", b)
	}
	// the evaluator excludes the anchor (as a cut would) and keeps the claim: the bound is lost, the claim counts
	cut := eligibleFor(w, ids["I"], policy.ActorEligible, "K:authored")
	cut.rows[w.ids["K:anchor"]] = actorRow{ids["I"], policy.ActorDenied}
	r := dualResolver(t, w, tv, WithActorEligibility(cut))
	if b := bound(r, "K:authored"); b.Quality != NoBound {
		t.Fatalf("an excluded anchor still bounds: %+v", b)
	}
	if a := r.Artifact(dig("Y")); a.State != SoleAuthor {
		t.Fatalf("the claim lost its authority with its anchor: %s\n%s", a.State, a.Render())
	}
}

// TestGateRecordsAndLookups: member records of edition rules, describes `part of` claims, completeness and the
// derivation group's reproduced runs read the gate: a member statement by K for I is a record only while its
// actor counts, and the record names the evaluator's reason (never the hook-absent text) when it does not.
func TestGateRecordsAndLookups(t *testing.T) {
	w, ids := gateWorld(t)
	g := w.genesis("G", "A", 0, "A")
	m := w.ids["K:authored"]
	w.editionWith("E", "A", g, []string{g}, "members", entries(st(m)), "rules", rules("IN licence CC0-1.0 MIT"))
	view := func(opts ...Option) string {
		r := dualResolver(t, w, append([]Option{dialect}, opts...)...)
		mv, ok := r.Membership(g, m)
		if !ok {
			t.Fatal("no membership view")
		}
		var b strings.Builder
		b.WriteString(mv.Render())
		for _, e := range mv.Evals {
			b.WriteString("missing " + strings.Join(e.Missing, "; ") + "\n")
		}
		return b.String()
	}
	none := view()
	has(t, none, "statement counts toward nothing (unknown (identity profile not active)")
	denied := view(WithActorEligibility(eligibleFor(w, ids["I"], policy.ActorDenied, "K:authored")))
	has(t, denied, "statement counts toward nothing (not eligible for identity "+keylog.Short(ids["I"]))
	hasNot(t, denied, "profile not active")
	eligible := view(WithActorEligibility(eligibleFor(w, ids["I"], policy.ActorEligible, "K:authored")))
	hasNot(t, eligible, "counts toward nothing")
	has(t, eligible, "member (endorsed)")
}

// TestGateNoEvaluatorDifferential: the shared fixture worlds (the P-01 property fixtures, rc/1 only, and the
// mixed-major genRC2 corpora) read the same with no evaluator and with an evaluator that binds nothing to an
// identity (denies every statement as bare): every view of every held id, byte for byte. A bare-key statement's
// gate is Counts whatever the evaluator; only an identity-context line can move, and the rc/1 fixtures have none.
func TestGateNoEvaluatorDifferential(t *testing.T) {
	bare := &actorFake{rows: map[string]actorRow{}} // every statement: ("", denied, no_identity_actor)
	fixture.Check(t, propBaseSeed+9100, 12, fixture.Extended, func(f fixture.Fixture) string {
		pw := concretize(t, f)
		lines := pw.deliver(nil)
		var ds []string
		for _, x := range pw.blobs {
			ds = append(ds, dig(x))
		}
		var out []string
		for _, opts := range [][]Option{propOpts(), append(propOpts(), WithActorEligibility(bare))} {
			s := keylog.NewStore()
			deliverAll(s, lines)
			r := New(s, opts...)
			out = append(out, pw.snapshot(r, s)+everyView(r, ds))
		}
		if out[0] != out[1] {
			return "a bare-only evaluator moved an rc/1 answer: " + firstDiff(out[0], out[1])
		}
		return ""
	})
	// mixed majors: the real candidate evaluator binds the rc/2 actor lines; an rc/1-only corpus is unmoved by it
	fixture.Check(t, propBaseSeed+9200, 4, fixture.Extended, func(f fixture.Fixture) string {
		pw := concretize(t, f)
		actors, err := identity.NewActors(pw.lines)
		if err != nil {
			t.Fatal(err)
		}
		var ds []string
		for _, x := range pw.blobs {
			ds = append(ds, dig(x))
		}
		var out []string
		for _, opts := range [][]Option{propOpts(), append(propOpts(), WithActorEligibility(actors))} {
			s := dualStore()
			deliverAll(s, pw.lines)
			r := New(s, opts...)
			out = append(out, pw.snapshot(r, s)+everyView(r, ds))
		}
		if out[0] != out[1] {
			return "the real evaluator moved an rc/1-only answer: " + firstDiff(out[0], out[1])
		}
		return ""
	})
}

// TestGateR5NoHookAbsentTextWithEvaluator: Gate R5 as a test. Over the mixed-major corpora (genRC2), with no
// evaluator the hook-absent answer appears wherever an identity-context line is read (it is the fallback); with
// the real candidate evaluator or one that answers every actor line unknown, no view of any held id says
// "identity profile not active" or "no identity profile is active/registered": every consumer asked the evaluator.
func TestGateR5NoHookAbsentTextWithEvaluator(t *testing.T) {
	hookAbsent := []string{"profile not active", "no identity profile is active", "no identity profile is registered", "identity profile is not active"}
	sawFallback := false
	fixture.Check(t, propBaseSeed+5000, 16, fixture.Extended, func(f fixture.Fixture) string {
		rw := genRC2(t, concretize(t, f), f.Seed)
		lines := rw.all()
		actors, err := identity.NewActors(lines)
		if err != nil {
			t.Fatal(err)
		}
		unknown := &actorFake{rows: map[string]actorRow{}}
		for _, n := range rw.acts {
			unknown.rows[rw.ids[n]] = actorRow{rw.ids["I"], policy.ActorUnknown}
		}
		if none := rw.rc2Answers(t, lines); strings.Contains(none, hookAbsent[0]) {
			sawFallback = true
		}
		for name, ev := range map[string]ActorEligibility{"real": actors, "unknown": unknown} {
			got := rw.rc2Answers(t, lines, WithActorEligibility(ev))
			for _, s := range hookAbsent {
				if i := strings.Index(got, s); i >= 0 {
					return name + " evaluator: hook-absent text in a view: " + got[max(0, i-200):min(len(got), i+120)]
				}
			}
		}
		return ""
	})
	if !sawFallback {
		t.Fatal("no fixture reached the hook-absent fallback without an evaluator: the corpus no longer tests the gate")
	}
}
