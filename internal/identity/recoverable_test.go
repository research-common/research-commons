package identity_test

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/identitymodel"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// End to end through the reader and the adapter: a recoverable-root identity whose root is stolen and recovered
// (recoverable-root note RR-02, RR-14), with the handover carrying the signed recovery line, read from received
// bytes. The full scenario table is registered as conformance cases in recoverable_cases_test.go.

func commitments(w *world, names ...string) *canon.Object {
	var cs []string
	for _, n := range names {
		cs = append(cs, wire.RecoveryCommitment(w.signer(n)))
	}
	return obj("commitments", cs, "rule", obj("any_one", true))
}

// recoverable is the stolen-root world: R (generation 0) commits to C0; K1 is the owner's delegate, T the thief's;
// the owner recovers to R1 (committing to C1) with last_good at G1; R1 grants K2; the thief grants T2.
//
//	R:  I(0) ── G1(1, K1) ── GT(2, T) ── H(3: handover carrying REC)
//	                                 └── GT2(3, T2)
//	R1: S1(0) ── G2(1, K2)
//	C0: REC(0)
func recoverable(t *testing.T) *world {
	w := newWorld(t)
	w.keys["R1"] = key("root-1", true)
	w.keys["C0"] = key("recovery-0", false)
	w.keys["C1"] = key("recovery-1", false)
	w.keys["T"] = key("thief-delegate", false)
	w.keys["T2"] = key("thief-delegate-2", false)
	w.sign(stmt{name: "I", by: "R", kind: "identity_inception", body: obj("profile", wire.RecoverableRootProfile, "recovery", commitments(w, "C0"))})
	for _, k := range []string{"K1", "K2", "T", "T2"} {
		w.sign(stmt{name: k + ".0", by: k, rc: "rc/1", kind: "authored", body: authoredBody(9)})
	}
	w.sign(stmt{name: "G1", by: "R", parent: "I", kind: "identity_grant", body: w.grantBody("K1", authoredAny())})
	w.sign(stmt{name: "GT", by: "R", parent: "G1", kind: "identity_grant", body: w.grantBody("T", authoredAny())})
	w.sign(stmt{name: "A1", by: "K1", parent: "K1.0", kind: "authored", body: authoredBody(1), actor: [2]string{"I", "G1"}})
	w.sign(stmt{name: "AT", by: "T", parent: "T.0", kind: "authored", body: authoredBody(2), actor: [2]string{"I", "GT"}})
	w.sign(stmt{name: "S1", by: "R1", kind: "identity_succession", body: obj("identity", w.ids["I"])})
	w.sign(stmt{name: "REC", by: "C0", kind: "identity_recovery", body: obj("identity", w.ids["I"], "last_good", w.ids["G1"],
		"successor", obj("key", w.signer("R1"), "inception", w.ids["S1"]), "next", commitments(w, "C1"))})
	w.sign(stmt{name: "H", by: "R", parent: "GT", kind: "identity_handover", body: obj("identity", w.ids["I"], "recovery", w.statement("REC"))})
	w.sign(stmt{name: "GT2", by: "R", parent: "GT", kind: "identity_grant", body: w.grantBody("T2", authoredAny())})
	w.sign(stmt{name: "G2", by: "R1", parent: "S1", kind: "identity_grant", body: w.grantBody("K2", authoredAny())})
	w.sign(stmt{name: "A2", by: "K2", parent: "K2.0", kind: "authored", body: authoredBody(3), actor: [2]string{"I", "G2"}})
	w.sign(stmt{name: "AT2", by: "T2", parent: "T2.0", kind: "authored", body: authoredBody(4), actor: [2]string{"I", "GT2"}})
	return w
}

// statement is a signed line as the object a handover carries.
func (w *world) statement(name string) *canon.Object {
	w.t.Helper()
	v, err := canon.Parse(w.lines[name])
	if err != nil {
		w.t.Fatal(err)
	}
	return v.(*canon.Object)
}

func TestRecoverableRootRecovery(t *testing.T) {
	w := recoverable(t)
	s := w.admit()
	if n := len(s.Refused()); n != 0 {
		t.Fatalf("refused %d: %+v", n, s.Refused())
	}
	for _, name := range []string{"I", "S1", "REC", "H", "G2"} {
		if st, _ := s.Status(w.ids[name]); st != wire.Valid {
			t.Fatalf("%s reads %s", name, st)
		}
	}
	r := w.expect(s, "A1", identitymodel.Eligible, "")
	if r.Generation != 1 || len(r.Recoveries) != 1 || string(r.Recoveries[0]) != w.ids["H"] || r.Closed {
		t.Fatalf("A1: %+v", r)
	}
	w.expect(s, "A2", identitymodel.Eligible, "")
	w.expect(s, "AT", identitymodel.Denied, "recovery_voided")
	w.expect(s, "AT2", identitymodel.Denied, "recovery_voided")
	// RR-14: a reader that holds everything but the handover reads the pre-recovery state.
	before := w.admit(without(w.order, "H")...)
	w.expect(before, "AT", identitymodel.Eligible, "")
	if r := w.expect(before, "A1", identitymodel.Eligible, ""); r.Generation != 0 {
		t.Fatalf("before the handover: generation %d", r.Generation)
	}
	// the policy view: the new root's grant binds its delegate to the identity (the succession is the evidence)
	actors, err := identity.NewActors(linesOf(w))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"A1": policy.ActorEligible, "A2": policy.ActorEligible, "AT": policy.ActorDenied} {
		st, err := wire.NewIdentityReader().Read(w.lines[name])
		if err != nil {
			t.Fatal(err)
		}
		id, state, why := actors.Eligible(st)
		if id != w.ids["I"] || state != want {
			t.Fatalf("%s: identity %q state %s why %v; want %s", name, id, state, why, want)
		}
		if name == "AT" && !strings.Contains(strings.Join(why, " "), "recovery_voided") {
			t.Fatalf("AT: %v", why)
		}
	}
}

// RR-24b and RR-27 through the reader: a handover by R alone (carrying a stranger's statement) is void and changes
// nothing; a handover carrying a second, different recovery the committed key signed retires the identity.
func TestRecoverableRootVoidAndRival(t *testing.T) {
	w := recoverable(t)
	w.sign(stmt{name: "S-S", by: "S", kind: "identity_succession", body: obj("identity", w.ids["I"])})
	w.sign(stmt{name: "FAKE", by: "S", kind: "identity_recovery", body: obj("identity", w.ids["I"], "last_good", nil,
		"successor", obj("key", w.signer("S"), "inception", w.ids["S-S"]), "next", commitments(w, "T"))})
	w.sign(stmt{name: "HF", by: "R", parent: "GT2", kind: "identity_handover", body: obj("identity", w.ids["I"], "recovery", w.statement("FAKE"))})
	s := w.admit()
	r := w.expect(s, "A1", identitymodel.Eligible, "")
	if r.Generation != 1 || !hasWarning(r, "void_handover") {
		t.Fatalf("void handover: gen %d warnings %+v", r.Generation, r.Warnings)
	}
	// the owner's abandoned second recovery, handed over by whoever holds R (RR-27)
	w.keys["R1b"] = key("root-1b", true)
	w.sign(stmt{name: "S1b", by: "R1b", kind: "identity_succession", body: obj("identity", w.ids["I"])})
	w.sign(stmt{name: "RECb", by: "C0", kind: "identity_recovery", body: obj("identity", w.ids["I"], "last_good", w.ids["G1"],
		"successor", obj("key", w.signer("R1b"), "inception", w.ids["S1b"]), "next", commitments(w, "C1"))})
	w.sign(stmt{name: "Hb", by: "R", parent: "GT2", kind: "identity_handover", body: obj("identity", w.ids["I"], "recovery", w.statement("RECb"))})
	w.expect(w.admit(), "A1", identitymodel.Denied, "retired_for_good")
	w.expect(w.admit(), "A2", identitymodel.Denied, "retired_for_good")
}

func linesOf(w *world) [][]byte {
	var out [][]byte
	for _, n := range w.order {
		out = append(out, w.lines[n])
	}
	return out
}
