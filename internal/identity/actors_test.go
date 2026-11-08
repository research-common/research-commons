package identity_test

// The actor evaluator (Actors) over signed, admitted evidence: what it answers the trust seam for each shape of
// statement. Every statement is signed with a disposable synthetic key and admitted from its exact bytes.

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/identitymodel"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

var _ policy.ActorEligibility = (*identity.Actors)(nil)
var _ policy.ActorEvaluator = (*identity.Actors)(nil)

// stOf is the statement as the DEFAULT reader holds it: an rc/2 line is another major, unverified, with no
// actor. The evaluator must answer from its own evidence by id, never from the caller's copy.
func (w *world) stOf(name string) *wire.Statement {
	w.t.Helper()
	st, err := wire.Read(w.lines[name])
	if err != nil {
		w.t.Fatalf("%s: %v", name, err)
	}
	if st.Actor != nil {
		w.t.Fatalf("%s: the default reader set an actor", name)
	}
	return st
}

func (w *world) eligible(a *identity.Actors, name, wantID, wantState, why string) []string {
	w.t.Helper()
	id, state, reasons := a.Eligible(w.stOf(name))
	if id != wantID || state != wantState {
		w.t.Fatalf("%s: (%q, %s), want (%q, %s); why %v", name, short12(id), state, short12(wantID), wantState, reasons)
	}
	if why != "" && !slices.ContainsFunc(reasons, func(s string) bool { return strings.Contains(s, why) }) {
		w.t.Fatalf("%s: why %v lacks %q", name, reasons, why)
	}
	return reasons
}

func short12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// TestActorsMapsModelResults: the evaluator maps each model result onto the hook's three states, names the
// identity only for an issuer-authenticated binding, and gives "" for a bare statement.
func TestActorsMapsModelResults(t *testing.T) {
	w := base(t)
	// a self-revoke by K1 after A2: G1 stays open (profile §4.1), the warning travels with the answer
	w.sign(stmt{name: "K1rev", by: "K1", rc: "rc/1", parent: "A2", kind: "revoke_key", body: obj("reason", "superseded", "last_good", w.ids["A2"])})
	// an outsider signs a statement naming I and K1's grant: no binding of S to I
	w.sign(stmt{name: "S.0", by: "S", rc: "rc/1", kind: "authored", body: authoredBody(6)})
	w.sign(stmt{name: "SX", by: "S", parent: "S.0", kind: "authored", body: authoredBody(7), actor: [2]string{"I", "G1"}})
	// an rc/1 line carrying x_actor_v1 is a bare-key statement (not upgraded)
	w.sign(stmt{name: "K2.1", by: "K2", rc: "rc/1", parent: "K2.0", kind: "authored", body: authoredBody(11), actor: [2]string{"I", "G2"}})
	a, err := identity.NewActors(func() (ls [][]byte) {
		for _, n := range w.order {
			ls = append(ls, w.lines[n])
		}
		return
	}())
	if err != nil {
		t.Fatal(err)
	}
	I := w.ids["I"]
	w.eligible(a, "A1", I, policy.ActorEligible, "warning delegate_self_event")
	w.eligible(a, "B1", I, policy.ActorEligible, "")
	w.eligible(a, "B2", I, policy.ActorDenied, "scope_excluded") // bound, out of scope: I's own denial
	w.eligible(a, "K1.0", "", policy.ActorDenied, "no_identity_actor")
	w.eligible(a, "K2.1", "", policy.ActorDenied, "no_identity_actor")
	w.eligible(a, "SX", "", policy.ActorDenied, "no issuer-authenticated binding")
	w.eligible(a, "I", "", policy.ActorDenied, "") // administrative: not an act for anyone
	if id, state, why := a.Eligible(&wire.Statement{ID: strings.Repeat("0", 64)}); id != "" || state != policy.ActorUnknown || len(why) == 0 {
		t.Fatalf("unheld statement: (%q, %s, %v)", id, state, why)
	}
	if id, state, _ := a.Eligible(nil); id != "" || state != policy.ActorUnknown {
		t.Fatal("nil statement")
	}

	// a cut of G1 at A1 denies A2 for I; I stays named (the denial is I's)
	w.sign(stmt{name: "C1", by: "R", parent: "G2", kind: "identity_cut", body: cutBody(w, "G1", "A1")})
	c := w.admit().Actors()
	w.eligible(c, "A1", I, policy.ActorEligible, "")
	w.eligible(c, "A2", I, policy.ActorDenied, "cut_excluded")

	// a missing grant: no binding, so the uncertainty is the candidate's alone, never I's
	m := w.admit(without(w.order, "G1", "G2", "C1")...).Actors()
	w.eligible(m, "A1", "", policy.ActorUnknown, "missing_evidence")

	// a root event the profile cannot read: bound, unknown for I
	u := base(t)
	u.sign(stmt{name: "Rrev", by: "R", parent: "G2", kind: "revoke_key", body: obj("reason", "superseded")})
	u.eligible(u.admit().Actors(), "A1", u.ids["I"], policy.ActorUnknown, "unsupported_root_event")
}

// TestActorsCapIsUnknown: a model cap makes the answer unknown naming the cap, never a pass and never a denial.
func TestActorsCapIsUnknown(t *testing.T) {
	w := base(t)
	a := w.admit().Actors()
	w.eligible(a, "A2", w.ids["I"], policy.ActorEligible, "")
	for _, c := range []struct {
		name    string
		d, e, i int
	}{{identitymodel.LimitDependencies, 1, 0, 0}, {identitymodel.LimitInspections, 0, 0, 1}} {
		w.eligible(a.WithLimits(c.d, c.e, c.i), "A2", w.ids["I"], policy.ActorUnknown, "model_limit: "+c.name+" limit")
	}
	// a denial found before the cap does not turn into a definite denial either: the walk stopped
	w.eligible(a.WithLimits(1, 0, 0), "B2", w.ids["I"], policy.ActorUnknown, "model_limit")
}

// TestActorsEvaluatorContext: the evaluator names itself (version, evidence digest, receipt), the trust answer
// that consulted it cites that beside the policy digest, and different evidence gives a different citation.
func TestActorsEvaluatorContext(t *testing.T) {
	w := base(t)
	s := w.admit()
	a := s.Actors()
	ctx := a.Context()
	if ctx.Version != identitymodel.EvaluatorVersion || ctx.EvidenceDigest != s.EvidenceDigest() || ctx.Receipt != s.Receipt() {
		t.Fatalf("context %+v", ctx)
	}
	if a.Snapshot() != s {
		t.Fatal("snapshot")
	}
	p, err := policy.Parse([]byte(`{"selections":[],"trust":[{"principal":{"identity":"` + w.ids["I"] +
		`"},"purposes":["corroboration"],"targets":{"any_content":true}}],"version":"reader-policy-v1"}`))
	if err != nil {
		t.Fatal(err)
	}
	ans := p.TrustsStatement(w.stOf("A1"), policy.PurposeCorroboration, digest(1), a)
	if !ans.Trusted() || ans.Principal.Identity != w.ids["I"] || ans.Evaluator != a.Evaluator() {
		t.Fatalf("answer %+v", ans)
	}
	for _, want := range []string{"as identity " + w.ids["I"][:12], "actor evaluator " + identitymodel.EvaluatorVersion, "evidence " + short12(ctx.EvidenceDigest)} {
		if !strings.Contains(ans.String(), want) {
			t.Fatalf("%q lacks %q", ans, want)
		}
	}
	w.sign(stmt{name: "C1", by: "R", parent: "G2", kind: "identity_cut", body: cutBody(w, "G1", "")})
	b := w.admit().Actors()
	if b.Evaluator() == a.Evaluator() {
		t.Fatal("different evidence, same evaluator citation")
	}
	nb := p.TrustsStatement(w.stOf("A1"), policy.PurposeCorroboration, digest(1), b)
	if nb.Trusted() || !strings.Contains(nb.String(), "cut_excluded") || !strings.Contains(nb.String(), b.Evaluator()) {
		t.Fatalf("cut answer %q", nb)
	}
	// a key-only answer never consults the evaluator and cites none
	if k := p.TrustsStatement(w.stOf("K1.0"), policy.PurposeAttestation, digest(9), a); k.Evaluator != "" || k.State != policy.Unconfigured {
		t.Fatalf("key-only answer %+v", k)
	}
}
