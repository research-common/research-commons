package identity_test

import (
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/identitymodel"
	"github.com/research-common/research-commons/internal/wire"
)

// TestCriticalRegistryNeverBetterThanWithholding: a signed act of the grant holder that breaks the critical-marker
// rules the production reader's registry enforces (a marker that is not an object or carries a member its closed
// shape lacks, an amendment without an actor, an actor without the marker, a critical token the reader has not
// registered) is never eligible, and no other statement is more permissive for holding it than for not holding it.
// With the production registry wired, this closes the two cases' last open part; the rest of each case's text is
// the tests listed beside it in the profile's coverage file (the unchanged reader's retention and views for
// C-id-36; byte tampering, the published negatives and canonical forms for C-id-37). Each defect has a repaired twin that IS eligible, so the mutation reached the boundary under test.
func TestCriticalRegistryNeverBetterThanWithholding(t *testing.T) {
	conformance.Covers(t, "C-id-36", "C-id-37")
	actor := [2]string{"I", "G1"}
	amends := func(w *world) canon.Value { return obj("amends", []string{w.ids["A1"]}) }
	grantAmend := func(w *world) {
		w.sign(stmt{name: "G9", by: "R", parent: "G2", kind: "identity_grant", body: w.grantBody("K1",
			obj("kind", "authored", "targets", obj("any_content", true), "amend", true))})
	}
	cases := []struct {
		name     string
		build    func(w *world) stmt // the defective act
		repaired func(w *world) stmt // the same act with the defect removed
		read     wire.Status         // what the production reader holds the defective line as
	}{
		{"marker is a string",
			func(w *world) stmt {
				return stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: withField(authoredBody(12), wire.IdentityCrit, canon.String("x")), actor: actor}
			},
			func(w *world) stmt {
				return stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: authoredBody(12), actor: actor}
			},
			wire.Invalid},
		{"marker with a member the closed shape lacks",
			func(w *world) stmt {
				return stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: withField(authoredBody(12), wire.IdentityCrit, obj("junk", 1)), actor: actor}
			},
			func(w *world) stmt {
				return stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: authoredBody(12), actor: actor}
			},
			wire.Invalid},
		{"amendment without an actor",
			func(w *world) stmt {
				return stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: withField(authoredBody(12), wire.IdentityCrit, amends(w))}
			},
			func(w *world) stmt {
				return stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: withField(authoredBody(12), wire.IdentityCrit, amends(w)), actor: [2]string{"I", "G9"}}
			},
			wire.Invalid},
		{"actor without the marker",
			func(w *world) stmt {
				return stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: authoredBody(12), actor: actor, noMarker: true}
			},
			func(w *world) stmt {
				return stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: authoredBody(12), actor: actor}
			},
			wire.Invalid},
		{"a critical token the reader has not registered",
			func(w *world) stmt {
				return stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: withField(authoredBody(12), "x_future", obj()), actor: actor,
					crit: []string{"x_future", wire.IdentityCrit}}
			},
			func(w *world) stmt {
				return stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: authoredBody(12), actor: actor}
			},
			wire.Unsupported},
		{"only an unregistered critical token",
			func(w *world) stmt {
				return stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: withField(authoredBody(12), "x_future", obj()), actor: actor,
					crit: []string{"x_future"}, noMarker: true}
			},
			func(w *world) stmt {
				return stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: authoredBody(12), actor: actor}
			},
			wire.Invalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := base(t)
			grantAmend(w)
			// the repaired twin is eligible: the defect, not the scaffolding, is what is refused
			twin := base(t)
			grantAmend(twin)
			twin.sign(c.repaired(twin))
			twin.expect(twin.admit(), "A9", identitymodel.Eligible, "")

			bad := c.build(w)
			w.sign(bad)
			withheld := w.admit(without(w.order, "A9")...)
			held := w.admit()
			if st, verified := held.Status(w.ids["A9"]); st != c.read || !verified {
				t.Fatalf("the production reader holds the defective line as %s (verified %v), want %s verified", st, verified, c.read)
			}
			// the unchanged reader's half (C-id-36): the same bytes are retained there unverified as unsupported,
			// under the same id, whatever the registry decides
			if old, err := wire.Read(w.lines["A9"]); err != nil || old.Status != wire.Unsupported || old.Verified || old.ID != w.ids["A9"] {
				t.Fatalf("the unchanged reader holds the line as %+v (%v), want unsupported, unverified, id %s", old, err, w.ids["A9"])
			}
			if r := held.Evaluate(w.ids["A9"]); r.Status == identitymodel.Eligible {
				t.Fatalf("a critical-marker defect is eligible: %+v", r.Reasons)
			}
			for _, n := range without(w.order, "A9") {
				if got := held.Evaluate(w.ids[n]).Status; got == identitymodel.Eligible && withheld.Evaluate(w.ids[n]).Status != identitymodel.Eligible {
					t.Fatalf("holding the defective line made %s eligible; withholding it does not", n)
				}
			}
			// delivery order does not change the answer
			rev := make([][]byte, 0, len(w.order))
			for i := len(w.order) - 1; i >= 0; i-- {
				rev = append(rev, w.lines[w.order[i]])
			}
			s2, err := identity.Admit(rev)
			if err != nil {
				t.Fatal(err)
			}
			if s2.Receipt() != held.Receipt() {
				t.Fatal("the receipt depends on delivery order")
			}
		})
	}
}

// TestMarkerWithoutActorIsNoIdentityAct: the other half of "actor/marker without the other": a verified rc/2 line
// with the marker and no actor reads Valid (a key(K) statement on an identity-aware body, profile §2.3) and is
// never an identity act: the evaluator finds no actor, so it is not eligible for I, and holding it changes no
// other statement's answer.
func TestMarkerWithoutActorIsNoIdentityAct(t *testing.T) {
	w := base(t)
	withheld := w.admit()
	w.sign(stmt{name: "M", by: "K1", parent: "A2", kind: "authored", body: authoredBody(12)})
	held := w.admit()
	if st, verified := held.Status(w.ids["M"]); st != wire.Valid || !verified {
		t.Fatalf("marker-only line read %s (verified %v), want valid", st, verified)
	}
	r := w.expect(held, "M", identitymodel.Denied, "no_identity_actor")
	if r.Actor.Kind == identitymodel.IdentitySubject {
		t.Fatalf("a marker-only line acts for an identity: %+v", r.Actor)
	}
	for _, n := range without(w.order, "M") {
		if held.Evaluate(w.ids[n]).Status != withheld.Evaluate(w.ids[n]).Status {
			t.Fatalf("holding the marker-only line changed %s", n)
		}
	}
}
