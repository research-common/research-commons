package resolve

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// actorFake is a test-only ActorEligibility, keyed by statement id. It reads no grant, root or log: the tests
// say what it answers. A statement it has no row for is a bare-key statement: no identity, denied. No
// production code implements the hook.
type actorFake struct {
	rows  map[string]actorRow
	calls []string
}

type actorRow struct{ id, state string }

var actorI = strings.Repeat("ab", 32) // the identity identitySel names

func (f *actorFake) Eligible(st *wire.Statement) (string, string, []string) {
	f.calls = append(f.calls, st.ID)
	if r, ok := f.rows[st.ID]; ok {
		return r.id, r.state, []string{"fake: " + r.state}
	}
	return "", policy.ActorDenied, []string{"no_identity_actor"}
}

func (f *actorFake) set(ids map[string]string, name, state string) {
	if f.rows == nil {
		f.rows = map[string]actorRow{}
	}
	f.rows[ids[name]] = actorRow{actorI, state}
}

func trustIdentity(purposes []string, contents ...string) *canon.Object {
	tg := obj("any_content", true)
	if len(contents) > 0 {
		tg = obj("contents", contents)
	}
	return obj("principal", obj("identity", actorI), "purposes", purposes, "targets", tg)
}

// evidenceOf is the counted flag and cause of the corroboration evidence row for statement id.
func evidenceOf(t *testing.T, o *Observation, id string) Evidence {
	t.Helper()
	for _, e := range o.Corroboration.Evidence {
		if e.Statement == id {
			return e
		}
	}
	t.Fatalf("no evidence row for %s\n%s", id, o.Render())
	return Evidence{}
}

// TestActorTrustSeam: the trust seam through the resolver, with a test-only actor evaluator. Corroboration
// counts a statement an `{identity: I}` entry trusts only when the evaluator calls that statement eligible for
// I; a denied, unknown or bare statement by the same worker key is shown and not counted, each with its cause;
// the reader's attestation line asks the same question; with no hook every answer is what it was.
func TestActorTrustSeam(t *testing.T) {
	conformance.Partial(t, "C-id-33", "the resolver's trust seam through a test-only actor evaluator: corroboration and attestation trust of an identity, purpose and target separation, bare worker-key statements never I's; the real evaluator adapter and received-policy injection remain")
	w, x := hotReading(t)
	// S1's key also signs a second supports as a bare statement: its key is the worker key of the identity's
	// eligible statement and nothing more
	bare := w.corroborates("S1b", "S1", x, w.result("R1b", "S1", "v1b", "W", "X", "a"), "supports")
	X := dig("X")
	p := pol(t, nil, []*canon.Object{trustIdentity([]string{"corroboration"}, X)})
	fake := &actorFake{}
	fake.set(w.ids, "S1", policy.ActorEligible)
	fake.set(w.ids, "S2", policy.ActorDenied)
	fake.set(w.ids, "C3", policy.ActorUnknown)

	base := obsView(t, w, x, WithPolicy(p))
	has(t, base.Render(), "identity profile is not active")
	wantStatus(t, base, "unchecked within statements you hold") // hook absent: nobody is trusted

	o := obsView(t, w, x, WithPolicy(p), WithActorEligibility(fake))
	wantStatus(t, o, "corroborated 1 within statements you hold")
	if e := evidenceOf(t, o, w.ids["S1"]); !e.Counted {
		t.Fatalf("eligible statement not counted: %+v", e)
	}
	for name, why := range map[string]string{"S2": "not eligible for identity", "C3": "acts for it is not established"} {
		e := evidenceOf(t, o, w.ids[name])
		if e.Counted || !strings.Contains(e.Cause, why) {
			t.Errorf("%s: counted %v, cause %q, want %q", name, e.Counted, e.Cause, why)
		}
	}
	if e := evidenceOf(t, o, bare); e.Counted || !strings.Contains(e.Cause, "no identity actor is eligible") {
		t.Fatalf("a bare statement by I's worker key counted: %+v", e)
	}
	has(t, o.Render(), "(1 trusted, 2 not trusted for corroboration")
	// with a hook no site falls back to the not-active wording (Gate R5's grep: only hook-absent fallbacks remain)
	hasNot(t, o.Render(), "profile is not active")
	hasNot(t, o.Render(), "profile not active")

	// purposes and targets stay separate: an entry for another content, or another identity, trusts nobody for
	// this one; an entry for another purpose leaves corroboration unconfigured (every statement counted, as with
	// no policy), never trusted
	for name, q := range map[string]*policy.Policy{
		"another content":  pol(t, nil, []*canon.Object{trustIdentity([]string{"corroboration"}, dig("elsewhere"))}),
		"another identity": pol(t, nil, []*canon.Object{obj("principal", obj("identity", strings.Repeat("cd", 32)), "purposes", []string{"corroboration"}, "targets", obj("any_content", true))}),
	} {
		n := obsView(t, w, x, WithPolicy(q), WithActorEligibility(fake))
		wantStatus(t, n, "unchecked within statements you hold")
		if e := evidenceOf(t, n, w.ids["S1"]); e.Counted {
			t.Errorf("%s: counted the eligible statement", name)
		}
	}
	other := obsView(t, w, x, WithPolicy(pol(t, nil, []*canon.Object{trustIdentity([]string{"attestation"}, X)})), WithActorEligibility(fake))
	has(t, other.Render(), "your trust in these keys: not configured (every counted statement is counted)")
	wantStatus(t, other, obsView(t, w, x).Corroboration.Status())

	// a key entry still decides by the signer, and the hook is never asked when a key entry matches
	fake.calls = nil
	k := pol(t, nil, []*canon.Object{trustKey(w.signer("S1"), []string{"corroboration"}), trustIdentity([]string{"corroboration"}, X)})
	ko := obsView(t, w, x, WithPolicy(k), WithActorEligibility(fake))
	if e := evidenceOf(t, ko, bare); !e.Counted {
		t.Fatalf("a bare statement by a trusted KEY is counted by key trust: %+v", e)
	}
	if slices.Contains(fake.calls, bare) || slices.Contains(fake.calls, w.ids["S1"]) {
		t.Fatalf("hook asked about a key-trusted statement: %v", fake.calls)
	}

	// the A5 run line asks the same question
	g := groupWorld(t, "bytes", "", map[string]string{"A": "X"})
	g.sign("BR", "BB", "reproduced", obj("of", g.ids["A1"], "result", "match", "content", contentOf("X"),
		"provenance", obj("workflow", dig("W"), "inputs", []string{dig("I")})))
	g.sign("BR2", "CC", "reproduced", obj("of", g.ids["A1"], "result", "match", "content", contentOf("X"),
		"provenance", obj("workflow", dig("W"), "inputs", []string{dig("I")})))
	ap := pol(t, nil, []*canon.Object{trustIdentity([]string{"attestation"})})
	gf := &actorFake{}
	gf.set(g.ids, "BR", policy.ActorEligible)
	gf.set(g.ids, "BR2", policy.ActorDenied)
	none := g.store(nil, WithPolicy(ap)).Artifact(dig("X"))
	has(t, none.Render(), "your trust in this key: trust for attestation of")
	has(t, none.Render(), "identity profile is not active")
	hook := g.store(nil, WithPolicy(ap), WithActorEligibility(gf)).Artifact(dig("X"))
	has(t, hook.Render(), "your trust in this key: trusted for attestation of")
	has(t, hook.Render(), "as identity "+actorI[:12])
	has(t, hook.Render(), "your trust in this key: not trusted for attestation")
	hasNot(t, hook.Render(), "profile is not active")
	if hook.Step != none.Step || hook.Outcome() != none.Outcome() {
		t.Fatalf("trust moved a grade: %s %s", none.Step, hook.Step)
	}
}

// TestActorHookAbsentIsToday: no hook, a nil hook, and a hook under a key-only policy render every view exactly
// as before, and the hook is never asked when no identity entry could decide the answer.
func TestActorHookAbsentIsToday(t *testing.T) {
	w, x := hotReading(t)
	boom := &actorFake{}
	for name, p := range map[string]*policy.Policy{
		"key only":     pol(t, nil, []*canon.Object{trustKey(w.signer("S1"), []string{"corroboration"}), trustKey(w.signer("S2"), []string{"corroboration"})}),
		"unconfigured": pol(t, nil, nil),
		"admission":    pol(t, nil, []*canon.Object{trustIdentity([]string{"admission"})}),
	} {
		want := obsView(t, w, x, WithPolicy(p)).Render()
		if got := obsView(t, w, x, WithPolicy(p), WithActorEligibility(nil)).Render(); got != want {
			t.Errorf("%s: a nil hook moved the view:\n%s\nvs\n%s", name, got, want)
		}
		if got := obsView(t, w, x, WithPolicy(p), WithActorEligibility(boom)).Render(); got != want {
			t.Errorf("%s: a hook that no identity entry reaches moved the view:\n%s\nvs\n%s", name, got, want)
		}
	}
	if len(boom.calls) != 0 {
		t.Fatalf("hook asked with no identity entry naming the purpose: %v", boom.calls)
	}
}

// TestActorIdentitySelection: a principal selection `{identity: I}` follows I's eligible claims through the
// hook, exactly as `{key: K}` follows K's; a bare statement by the same worker key is not followed; an
// undecided claim makes the selection unknown rather than met without it; an eligible claim that amends
// another is unknown (amendment authority is not evaluated here); with no hook it stays unknown (identity
// profile not active) and no key's claims are followed in its place.
func TestActorIdentitySelection(t *testing.T) {
	conformance.Partial(t, "C-id-31", "principal-following selection of an identity through a test-only actor evaluator (its eligible claims only, never a bare worker-key statement, unknown when undecided); exact pins to identity-context statements, amendment DAG and the real evaluator adapter remain")
	conformance.Partial(t, "C-id-32", "an undecided or denied claim is never substituted (unknown / not met); the production preflight (exit 2) and the real evaluator adapter remain")
	w := newWorld(t)
	w.authored("A1", "A", "X", "licence", "CC0-1.0")
	w.authored("B1", "BB", "X", "licence", "MIT")
	w.authored("A2", "A", "X", "licence", "Apache-2.0") // amends A1 by key, and is bare: no actor
	sel := pol(t, []*canon.Object{identitySel(dig("X"), policy.RoleAuthorship)}, nil)
	f := &actorFake{}
	f.set(w.ids, "B1", policy.ActorEligible)
	f.set(w.ids, "A1", policy.ActorDenied)

	off := w.store(nil, WithPolicy(sel)).Artifact(dig("X"))
	wantField(t, off, "licence", FieldSelectionUnmet, "")
	has(t, off.Render(), SelIdentity)
	has(t, off.Render(), "no key's claims are followed in its place")
	hasNot(t, off.Render(), SelIdentityUnknown)

	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		wantField(t, a, "licence", FieldDefault, `"MIT"`)
		fl := a.Field("licence")
		if len(fl.Rivals) != 1 || fl.Rivals[0].Value != `"Apache-2.0"` { // A1 is amended by A2: A's current claim is A2
			t.Fatalf("rivals: %+v", fl)
		}
		has(t, a.Render(), `"identity":"`+actorI+`"`)
		has(t, a.Render(), ": "+SelMet)
	}, WithPolicy(sel), WithActorEligibility(f))

	// no claim of I at all: not met, nothing substituted
	g := &actorFake{}
	none := w.store(nil, WithPolicy(sel), WithActorEligibility(g)).Artifact(dig("X"))
	wantField(t, none, "licence", FieldSelectionUnmet, "")
	has(t, none.Render(), SelNone)

	// one claim the evaluator cannot decide: unknown, B1 is not chosen without it
	f.set(w.ids, "A1", policy.ActorUnknown)
	unk := w.store(nil, WithPolicy(sel), WithActorEligibility(f)).Artifact(dig("X"))
	wantField(t, unk, "licence", FieldSelectionUnmet, "")
	has(t, unk.Render(), SelIdentityUnknown)
	hasNot(t, unk.Render(), "profile not active")
	hasNot(t, none.Render(), "profile not active")
	if code, why := unk.VerifyExit(); code != 3 || !slices.ContainsFunc(why, func(s string) bool { return strings.Contains(s, "reader's authorship selection") }) {
		t.Fatalf("verify %d %v", code, why)
	}

	// an eligible claim that amends another: unknown, never guessed
	w2 := newWorld(t)
	w2.authored("B1", "BB", "X", "licence", "MIT")
	am := w2.authored("B2", "BB", "X", "licence", "Apache-2.0", wire.IdentityCrit, canon.Value(obj("amends", []string{w2.ids["B1"]})))
	h := &actorFake{}
	h.set(w2.ids, "B1", policy.ActorEligible)
	h.set(w2.ids, "B2", policy.ActorEligible)
	_ = am
	am2 := w2.store(nil, WithPolicy(sel), WithActorEligibility(h)).Artifact(dig("X"))
	wantField(t, am2, "licence", FieldSelectionUnmet, "")
	has(t, am2.Render(), "amendment authority is not evaluated here")

	// the workflow role follows the same way: an identity's eligible workflow declaration supplies the mode
	gw := groupWorld(t, "bytes", "", map[string]string{"A": "X"})
	gw.workflow("QW", "W", "protocol", "K")
	wsel := pol(t, []*canon.Object{identitySel(dig("W"), policy.RoleWorkflow)}, nil)
	q := &actorFake{}
	q.set(gw.ids, "wf:W:QW", policy.ActorEligible)
	a := gw.store(nil, WithPolicy(wsel), WithActorEligibility(q), WithComparator(newFakeComparator())).Artifact(dig("X"))
	if a.Group == nil || a.Group.Mode != "protocol" {
		t.Fatalf("workflow selection through the hook: %+v\n%s", a.Group, a.Render())
	}
	has(t, a.Render(), "selected by the reader's policy")
}

// TestActorIdentityCountStaysUnknown: with a hook the identity counting unit is still unknown (the task consumer
// that deduplicates eligible submissions by identity is not built), and the answer says why, differently from
// the no-hook text.
func TestActorIdentityCountStaysUnknown(t *testing.T) {
	conformance.Partial(t, "C-id-34", "identity counting stays unknown with or without an actor evaluator; deduplicating eligible submissions by identity needs the task consumer")
	w := newWorld(t)
	g := w.task("G", "R")
	e1 := w.taskEdition("E1", "R", g, []string{g}, w.contract("R", "counting_unit", "identity", "quorum", quorum(1, IndependenceNotRequired)))
	w.submit("S", "A", g, e1, "X")
	off := readinessOf(t, taskView(t, w, g), w.ed(e1))
	on := readinessOf(t, taskView(t, w, g, WithActorEligibility(&actorFake{})), w.ed(e1))
	if off.Token != ReadyUnknown || on.Token != ReadyUnknown {
		t.Fatalf("identity counting: %s / %s", off.Token, on.Token)
	}
	if !slices.ContainsFunc(off.Why, func(s string) bool { return strings.Contains(s, "no identity profile is active") }) ||
		!slices.ContainsFunc(on.Why, func(s string) bool { return strings.Contains(s, "needs the task consumer") }) ||
		slices.ContainsFunc(on.Why, func(s string) bool { return strings.Contains(s, "profile is active") }) {
		t.Fatalf("why: off %v on %v", off.Why, on.Why)
	}
}
