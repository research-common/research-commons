package identity_test

// Signed adapter-level checks for profile scenarios that had only model-level (fact) tests. Every statement is
// signed with a disposable synthetic key and admitted from its exact bytes, like slice_test.go.

import (
	"slices"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/identitymodel"
)

// One key, grants from two identities: each statement acts for exactly the actor it names, and cutting the grant
// of one identity changes nothing for the other.
func TestCaseOneKeyTwoIdentities(t *testing.T) {
	conformance.Partial(t, "C-id-06", "signed adapter and model; the production reader asks this evaluator, but this case is not yet run through a command")
	w := base(t)
	w.keys["RJ"] = key("root-j", false)
	w.sign(stmt{name: "J", by: "RJ", kind: "identity_inception", body: obj("profile", "fixed-root-v1")})
	w.sign(stmt{name: "GJ", by: "RJ", parent: "J", kind: "identity_grant", body: obj("identity", w.ids["J"],
		"delegate", obj("key", w.signer("K1"), "inception", w.ids["K1.0"]), "permissions", canon.Array{authoredAny()})})
	w.sign(stmt{name: "AJ", by: "K1", parent: "A2", kind: "authored", body: authoredBody(6), actor: [2]string{"J", "GJ"}})
	s := w.admit()
	r := w.expect(s, "AJ", identitymodel.Eligible, "")
	if string(r.Actor.Identity) != w.ids["J"] || string(r.Grant) != w.ids["GJ"] {
		t.Fatalf("AJ acts for %+v under %s", r.Actor, r.Grant)
	}
	r = w.expect(s, "A2", identitymodel.Eligible, "")
	if string(r.Actor.Identity) != w.ids["I"] {
		t.Fatalf("A2 acts for %+v", r.Actor)
	}
	// Naming J with I's grant (or I with J's) never borrows the other identity's authority.
	w.sign(stmt{name: "AX", by: "K1", parent: "AJ", kind: "authored", body: authoredBody(7), actor: [2]string{"J", "G1"}})
	w.expect(w.admit(), "AX", identitymodel.Denied, "wrong_grant_identity")
	// A null cut of J's grant leaves I's acts by the same key untouched, and vice versa.
	w.sign(stmt{name: "CJ", by: "RJ", parent: "GJ", kind: "identity_cut", body: obj("identity", w.ids["J"], "grant", w.ids["GJ"],
		"last_good", nil, "reason", "key_compromise")})
	s = w.admit()
	w.expect(s, "AJ", identitymodel.Denied, "cut_excluded")
	for _, n := range []string{"A1", "A2", "B1"} {
		w.expect(s, n, identitymodel.Eligible, "")
	}
	w.sign(stmt{name: "C1", by: "R", parent: "G2", kind: "identity_cut", body: cutBody(w, "G1", "")})
	s = w.admit(without(w.order, "CJ")...)
	w.expect(s, "A2", identitymodel.Denied, "cut_excluded")
	w.expect(s, "AJ", identitymodel.Eligible, "")
}

// A new grant cannot relabel bytes signed under an older one: after G1 is cut to nothing, K1's acts under G1 stay
// excluded even though a second grant G3 to the same key and inception is valid, and acts under G3 are eligible.
func TestCaseNewGrantCannotRelabel(t *testing.T) {
	conformance.Partial(t, "C-id-14", "signed adapter and model; the production reader asks this evaluator, but this case is not yet run through a command")
	w := base(t)
	w.sign(stmt{name: "C1", by: "R", parent: "G2", kind: "identity_cut", body: cutBody(w, "G1", "")})
	w.sign(stmt{name: "G3", by: "R", parent: "C1", kind: "identity_grant", body: w.grantBody("K1", authoredAny())})
	w.sign(stmt{name: "A3", by: "K1", parent: "A2", kind: "authored", body: authoredBody(1), actor: [2]string{"I", "G3"}})
	s := w.admit()
	for _, n := range []string{"A1", "A2", "A1x"} {
		r := w.expect(s, n, identitymodel.Denied, "cut_excluded")
		if string(r.Grant) != w.ids["G1"] {
			t.Fatalf("%s judged under %s, not its signed grant", n, r.Grant)
		}
	}
	// Same content as A1, new statement under G3: a different id, eligible on its own; A1 is unchanged.
	if w.ids["A3"] == w.ids["A1"] {
		t.Fatal("re-signing under another grant produced the same id")
	}
	w.expect(s, "A3", identitymodel.Eligible, "")
}

// Grants issued on two forks of the root's log both stand; a root merge of the forks never reopens a cut grant.
//
//	R: I ── G1 ── G2 ── C1(cut G1, null) ── M(merges F)
//	     └── F(grant G4 to K1, fork at seq 1)
func TestCaseRootForkGrantsCoexist(t *testing.T) {
	conformance.Partial(t, "C-id-16", "signed adapter and model; the production reader asks this evaluator, but this case is not yet run through a command")
	w := base(t)
	w.sign(stmt{name: "F", by: "R", parent: "I", kind: "identity_grant", body: w.grantBody("K1",
		obj("kind", "authored", "targets", obj("contents", []string{digest(6)}), "amend", false))})
	if w.ids["F"] == w.ids["G1"] {
		t.Fatal("fork grant is not a distinct statement")
	}
	w.sign(stmt{name: "A4", by: "K1", parent: "A2", kind: "authored", body: authoredBody(6), actor: [2]string{"I", "F"}})
	s := w.admit()
	w.expect(s, "A4", identitymodel.Eligible, "")
	w.expect(s, "A2", identitymodel.Eligible, "")
	w.expect(s, "B1", identitymodel.Eligible, "")
	w.sign(stmt{name: "C1", by: "R", parent: "G2", kind: "identity_cut", body: cutBody(w, "G1", "")})
	w.sign(stmt{name: "M", by: "R", rc: "rc/1", parent: "C1", merges: []string{"F"}, kind: "describes",
		body: obj("about", obj("statement", w.ids["I"]), "note", "merge forks")})
	s = w.admit()
	if st, _ := s.Status(w.ids["M"]); st == "" {
		t.Fatal("merge line not held")
	}
	w.expect(s, "A2", identitymodel.Denied, "cut_excluded")
	w.expect(s, "A4", identitymodel.Eligible, "")
	w.expect(s, "B1", identitymodel.Eligible, "")
}

// Authority is a function of held public bytes only: with every private key discarded, admitting the same lines
// gives the same receipt, digest and answers.
func TestCaseRootKeyLossChangesNothing(t *testing.T) {
	conformance.Partial(t, "C-id-18", "Admit takes bytes only, so evaluation cannot depend on key custody; restoring the same root key file to resume administration is drilled through the commands in internal/cli TestIdentitySimplePathDrill")
	w := base(t)
	w.sign(stmt{name: "C1", by: "R", parent: "G2", kind: "identity_cut", body: cutBody(w, "G1", "A1")})
	before := w.admit()
	lines := make([][]byte, 0, len(w.order))
	for _, n := range w.order {
		lines = append(lines, slices.Clone(w.lines[n]))
	}
	ids := w.ids
	w.keys = nil // the root (and every worker) key is gone
	after, err := identity.Admit(lines)
	if err != nil {
		t.Fatal(err)
	}
	if before.Receipt() != after.Receipt() || before.EvidenceDigest() != after.EvidenceDigest() {
		t.Fatal("receipt or digest changed")
	}
	for _, n := range []string{"A1", "A2", "A1x", "B1", "B2"} {
		a, b := before.Evaluate(ids[n]), after.Evaluate(ids[n])
		if a.Status != b.Status || len(a.Reasons) != len(b.Reasons) {
			t.Fatalf("%s: %s vs %s", n, a.Status, b.Status)
		}
	}
}
