package resolve

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
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
	// what is counted is the counting gate's (D-1108-2): with an evaluator, the denied and undecided identity
	// statements count toward nothing whatever the trust policy, exactly as with no policy at all
	wantStatus(t, other, obsView(t, w, x, WithActorEligibility(fake)).Corroboration.Status())
	wantStatus(t, other, "corroborated 1 within statements you hold")

	// a key entry still decides by the signer, and the hook is never asked when a key entry matches
	fake.calls = nil
	k := pol(t, nil, []*canon.Object{trustKey(w.signer("S1"), []string{"corroboration"}), trustIdentity([]string{"corroboration"}, X)})
	ko := obsView(t, w, x, WithPolicy(k), WithActorEligibility(fake))
	if e := evidenceOf(t, ko, bare); !e.Counted {
		t.Fatalf("a bare statement by a trusted KEY is counted by key trust: %+v", e)
	}
	// the trust question itself never asks the hook when a key entry matches (the counting gate asks about every
	// evidence-ready statement: D-1108-2)
	fake.calls = nil
	for _, id := range []string{bare, w.ids["S1"]} {
		pl, _ := w.store(nil).Statement(id)
		if a := k.TrustsStatement(pl.St, policy.PurposeCorroboration, X, fake); !a.Trusted() || a.Evaluator != "" {
			t.Fatalf("key-trusted %s: %+v", id[:12], a)
		}
	}
	if len(fake.calls) != 0 {
		t.Fatalf("trust question asked the hook about a key-trusted statement: %d calls", len(fake.calls))
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
	// The trust question never asks the hook without an identity entry (policy.TestTrustsStatementThroughActors).
	// The counting gate does ask (D-1108-2, profile §5.3: key counting never bypasses actor authority, whatever
	// the policy), and an answer binding no identity leaves every bare-key statement exactly where Counts put it.
	for _, id := range boom.calls {
		if p, ok := w.store(nil).Statement(id); !ok || !p.EvidenceReady() {
			t.Fatalf("hook asked about %s, which is not evidence-ready", id)
		}
	}
}

// TestActorIdentitySelection: a principal selection `{identity: I}` follows I's eligible claims through the
// hook, exactly as `{key: K}` follows K's; a bare statement by the same worker key is not followed; an
// undecided claim makes the selection unknown rather than met without it; an eligible claim that explicitly
// amends another eligible claim of I replaces it (amendments_test.go has the §5.1 cases); with no hook it stays
// unknown (identity profile not active) and no key's claims are followed in its place.
func TestActorIdentitySelection(t *testing.T) {
	conformance.Partial(t, "C-id-31", "principal-following selection of an identity through a test-only actor evaluator (its eligible claims only, never a bare worker-key statement, unknown when undecided), following explicit amendments; exact pins to identity-context statements and the real evaluator adapter remain")
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

	// an eligible claim that explicitly amends another eligible claim of I: the amendment is current
	w2 := newWorld(t)
	w2.authored("B1", "BB", "X", "licence", "MIT")
	w2.authored("B2", "BB", "X", "licence", "Apache-2.0", wire.IdentityCrit, canon.Value(obj("amends", []string{w2.ids["B1"]})))
	h := &actorFake{}
	h.set(w2.ids, "B1", policy.ActorEligible)
	h.set(w2.ids, "B2", policy.ActorEligible)
	am2 := w2.store(nil, WithPolicy(sel), WithActorEligibility(h)).Artifact(dig("X"))
	wantField(t, am2, "licence", FieldDefault, `"Apache-2.0"`)
	hasNot(t, am2.Render(), "amendment authority is not evaluated here")

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

// TestActorIdentityCount: identity profile §5.3 through the resolver with a test-only evaluator. Under counting unit
// identity, eligible submissions are deduplicated by the identity they act for (two delegates of I count once);
// bare submissions never become identity votes; denied or undecided actors are not counted and the answer names
// them. Under key counting an identity submission with denied authority is not counted for its key either. With
// no evaluator identity counting stays unknown, as before; a contract listing key issuers cannot be read for
// identities.
func TestActorIdentityCount(t *testing.T) {
	conformance.Partial(t, "C-id-34", "identity counting through the resolver with a test-only evaluator: eligible submissions deduplicated by identity, bare and unresolved ones named and not counted; the provisional contract half; the whole outcome over signed rc/2 evidence is TestRC2IdentityCounting")
	conformance.Partial(t, "C-id-35", "key counting through the resolver with a test-only evaluator: an identity submission with denied or undecided authority is not counted for its key; the provisional contract half; the whole outcome over signed rc/2 evidence is TestRC2KeyCountingNoBypass")
	w := newWorld(t)
	g := w.task("G", "R")
	e1 := w.taskEdition("E1", "R", g, []string{g}, w.contract("R", "counting_unit", "identity", "quorum", quorum(2, IndependenceNotRequired)))
	w.submit("SA", "A", g, e1, "X")  // A for I
	w.submit("SB", "BB", g, e1, "X") // BB for I: the same identity, one vote
	w.submit("SC", "C", g, e1, "X")  // C bare
	w.submit("SD", "D", g, e1, "X")  // D for I, denied
	w.submit("SQ", "Q", g, e1, "X")  // Q for I, undecided
	off := readinessOf(t, taskView(t, w, g), w.ed(e1))
	if off.Token != ReadyUnknown || !slices.ContainsFunc(off.Why, func(s string) bool { return strings.Contains(s, "no identity profile is active") }) {
		t.Fatalf("no evaluator: %s %v", off.Token, off.Why)
	}
	fake := &actorFake{}
	for n, st := range map[string]string{"SA": policy.ActorEligible, "SB": policy.ActorEligible, "SD": policy.ActorDenied, "SQ": policy.ActorUnknown} {
		fake.set(w.ids, n, st)
	}
	tk := taskView(t, w, g, WithActorEligibility(fake))
	on := readinessOf(t, tk, w.ed(e1))
	if on.Token != NotReady || on.N != 1 || on.Unit != CountedAsIdentities {
		t.Fatalf("identity counting: %s %d %q\n%s", on.Token, on.N, on.Unit, tk.Render())
	}
	has(t, tk.Render(), "(1 of 2, "+CountedAsIdentities+")")
	for name, why := range map[string]string{"SC": "not an identity vote", "SD": "not eligible for identity", "SQ": "is not established"} {
		if !slices.ContainsFunc(on.Reports, func(s string) bool { return strings.Contains(s, keylog.Short(w.ids[name])) && strings.Contains(s, why) }) {
			t.Errorf("%s: no report %q in %v", name, why, on.Reports)
		}
	}
	// a second identity reaches the quorum
	w2 := strings.Repeat("cd", 32)
	fake.rows[w.ids["SC"]] = actorRow{w2, policy.ActorEligible}
	if rd := readinessOf(t, taskView(t, w, g, WithActorEligibility(fake)), w.ed(e1)); rd.Token != Ready || rd.N != 2 {
		t.Fatalf("two identities: %s %d", rd.Token, rd.N)
	}
	delete(fake.rows, w.ids["SC"])

	// key counting: an identity submission is counted for its key only after actor authority passed
	k := w.task("K", "R")
	ek := w.taskEdition("EK", "R", k, []string{k}, w.contract("R", "counting_unit", "key", "quorum", quorum(3, IndependenceNotRequired)))
	for _, n := range []string{"A", "BB", "C", "D", "Q"} {
		w.submit("K"+n, n, k, ek, "X")
	}
	keyOff := readinessOf(t, taskView(t, w, k), w.ed(ek))
	for n, st := range map[string]string{"KA": policy.ActorEligible, "KBB": policy.ActorEligible, "KD": policy.ActorDenied, "KQ": policy.ActorUnknown} {
		fake.set(w.ids, n, st)
	}
	keyOn := readinessOf(t, taskView(t, w, k, WithActorEligibility(fake)), w.ed(ek))
	if keyOff.Token != Ready || keyOff.N != 5 || keyOn.Token != Ready || keyOn.N != 3 || keyOn.Unit != CountedAs {
		t.Fatalf("key counting: without %s %d, with %s %d %q", keyOff.Token, keyOff.N, keyOn.Token, keyOn.N, keyOn.Unit)
	}

	// a contract listing key issuers: identity issuers cannot be checked
	h := w.task("H", "R")
	eh := w.taskEdition("EH", "R", h, []string{h}, w.contract("R", "counting_unit", "identity", "eligible_issuers", []string{w.signer("A")}, "quorum", quorum(1, IndependenceNotRequired)))
	w.submit("HA", "A", h, eh, "X")
	fake.set(w.ids, "HA", policy.ActorEligible)
	if rd := readinessOf(t, taskView(t, w, h, WithActorEligibility(fake)), w.ed(eh)); rd.Token != ReadyUnknown ||
		!slices.ContainsFunc(rd.Why, func(s string) bool { return strings.Contains(s, "task-contract profile") }) {
		t.Fatalf("key-listed issuers under identity counting: %s %v", rd.Token, rd.Why)
	}
}

// TestActorCountGate: R5SEAM-F1 / D-1108-2. With an actor evaluator, a statement it binds to an identity counts by
// evidence readiness and actor eligibility, not by its key's bare-key status: an eligible identity corroboration
// by a key that has since revoked itself counts, with the bare-key status shown beside it; a denied or undecided
// identity statement counts toward nothing whatever the trust policy; bare statements (no identity) keep the
// bare-key gate exactly. With no evaluator, the view is what it was.
func TestActorCountGate(t *testing.T) {
	conformance.Partial(t, "C-id-10", "the resolver's counting gate through a test-only evaluator: an eligible identity corroboration by a self-revoked worker key counts, its bare-key status shown beside it; a bare corroboration after the same self-revoke does not count; the warning text is the real evaluator's (internal/identity)")
	w, x := hotReading(t)
	// S1 revokes itself after its corroboration (hard, last_good before it: the corroboration falls outside), then
	// signs another one
	w.sign("S1rev", "S1", "revoke_key", obj("reason", "key_compromise", "last_good", w.ids["R1"]))
	late := w.corroborates("S1late", "S1", x, w.result("R1late", "S2", "v1l", "W", "X", "d"), "supports")
	base := obsView(t, w, x)
	if e := evidenceOf(t, base, w.ids["S1"]); e.Counted {
		t.Fatalf("precondition: the hard self-revoke leaves S1 counted: %+v", e)
	}
	fake := &actorFake{}
	fake.set(w.ids, "S1", policy.ActorEligible)
	fake.set(w.ids, "S1late", policy.ActorDenied)
	o := obsView(t, w, x, WithActorEligibility(fake))
	e := evidenceOf(t, o, w.ids["S1"])
	if !e.Counted || !strings.Contains(e.Cause, "acts for identity "+actorI[:12]+"; its key's bare-key status, shown and not applied:") {
		t.Fatalf("eligible identity corroboration by a self-revoked key: %+v", e)
	}
	if e := evidenceOf(t, o, late); e.Counted || !strings.Contains(e.Cause, "not eligible for identity") {
		t.Fatalf("denied identity corroboration: %+v", e)
	}
	// S2 and C3 have no row: bare statements, exactly as without the hook
	for _, n := range []string{"S2", "C3"} {
		if a, b := evidenceOf(t, o, w.ids[n]), evidenceOf(t, base, w.ids[n]); a.Counted != b.Counted || a.Cause != b.Cause {
			t.Fatalf("%s moved: %+v vs %+v", n, a, b)
		}
	}
	if o.Corroboration.Corroborated != base.Corroboration.Corroborated+1 {
		t.Fatalf("corroborated %d, without the evaluator %d", o.Corroboration.Corroborated, base.Corroboration.Corroborated)
	}
	// undecided: counted nowhere, and never as the key either
	fake.set(w.ids, "S1", policy.ActorUnknown)
	if e := evidenceOf(t, obsView(t, w, x, WithActorEligibility(fake)), w.ids["S1"]); e.Counted || !strings.Contains(e.Cause, "is not established") {
		t.Fatalf("undecided identity corroboration: %+v", e)
	}
	// no evaluator: identical to today
	if got := obsView(t, w, x, WithActorEligibility(nil)).Render(); got != base.Render() {
		t.Fatalf("a nil evaluator moved the view")
	}
}
