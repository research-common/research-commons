package wire

import (
	"bytes"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// rc2Read signs an rc/2 statement of kind with body b (the marker set to marker) and reads it with the identity
// reader. actor, when non-nil, is the envelope x_actor_v1.
func rc2Read(t *testing.T, kind string, b, marker, actor *canon.Object) *Statement {
	t.Helper()
	k := Ed25519Key{Seed: bytes.Repeat([]byte{61}, 32)}
	d := Draft{RC: "rc/2", Kind: kind, Seq: 3, Prev: tID, TS: "2026-10-15T00:00:00Z", Crit: []string{IdentityCrit},
		Body: setField(b, IdentityCrit, marker)}
	env := d.Envelope(k)
	if actor != nil {
		env = setField(env, ActorField, actor)
	}
	line := canon.Encode(setField(env, "sig", canon.String(k.Sign(PAE(PayloadType(kind, 2), canon.Encode(env))))))
	st, err := NewIdentityReader().Read(line)
	if err != nil {
		t.Fatalf("%s refused: %v", kind, err)
	}
	if !st.Verified {
		t.Fatalf("%s not verified", kind)
	}
	return st
}

// The rc/2 resource kinds are read, not retained: genesis with typed controller subjects, edition with a typed
// controller change and the task_roles marker (shape only), withdraw_approval. Every negative is a verified line
// whose one mutation the reader names (Invalid with the reason), so the boundary under test is the one reached.
func TestCandidateResourceKindsRead(t *testing.T) {
	conformance.Partial(t, "C-id-25", "wire half: typed, duplicate-free, sorted subjects on signed rc/2 genesis and edition lines; effective-subject slot counting is the resolver's (TestTypedControllerSlots)")
	conformance.Partial(t, "C-id-28", "wire half: a controller change names both complete typed controllers and rule; predecessor and merge authority are the resolver's (TestTypedControllerSlots)")
	key := "ed25519:" + strings.Repeat("2b", 32)
	idS := body("identity", tID)
	keyS := body("key", key)
	ctrl := arr(idS, keyS) // {"identity":…} sorts before {"key":…}
	gen := body("type", "collection", "name", "n", "controllers", ctrl, "rule", body("k_of_n", body("k", 2)))
	ed := func(contents *canon.Object) *canon.Object {
		return body("resource", tID, "predecessors", arr(s(tID)), "contents", contents)
	}
	roles := body("beneficiary", idS, "any_issuer", canon.Bool(true), "counting_unit", "identity")
	contract := body("profile", "task-contract-v1")
	empty := body()
	for _, c := range []struct {
		name, kind string
		b, marker  *canon.Object
		actor      *canon.Object
		want       Status
		why        string
	}{
		{"genesis typed", "genesis", gen, empty, nil, Valid, ""},
		{"edition plain", "edition", ed(body("members", arr())), empty, body("identity", tID, "grant", tID2), Valid, ""},
		{"edition controller change", "edition", ed(body("controllers", arr(keyS), "rule", body("any_one", canon.Bool(true)))), empty, nil, Valid, ""},
		{"edition task roles", "edition", ed(body("contract", contract)), body("task_roles", roles), nil, Valid, ""},
		{"withdraw_approval", "withdraw_approval", body("resource", tID, "edition", tID2), empty, body("identity", tID, "grant", tID2), Valid, ""},

		{"genesis untyped key", "genesis", setField(gen, "controllers", arr(s(key))), empty, nil, Invalid, "is not a typed subject"},
		{"genesis empty", "genesis", setField(gen, "controllers", arr()), empty, nil, Invalid, "empty set"},
		{"genesis two tags", "genesis", setField(gen, "controllers", arr(body("identity", tID, "key", key))), empty, nil, Invalid, "exactly one of key, identity"},
		{"genesis unknown tag", "genesis", setField(gen, "controllers", arr(body("role", "x"))), empty, nil, Invalid, "not a member of a typed subject"},
		{"genesis unsorted", "genesis", setField(gen, "controllers", arr(keyS, idS)), empty, nil, Invalid, "not sorted"},
		{"genesis duplicate", "genesis", setField(gen, "controllers", arr(idS, idS)), empty, nil, Invalid, "not sorted"},
		{"genesis k above n", "genesis", setField(gen, "rule", body("k_of_n", body("k", 3))), empty, nil, Invalid, "no set of controllers"},
		{"genesis marker member", "genesis", gen, body("task_roles", roles), nil, Invalid, "must be {} for genesis"},
		{"genesis with actor", "genesis", gen, empty, body("identity", tID, "grant", tID2), Invalid, "raw-key statement"},
		{"edition controllers without rule", "edition", ed(body("controllers", arr(keyS))), empty, nil, Invalid, "both complete controllers and rule"},
		{"edition rule without controllers", "edition", ed(body("rule", body("any_one", canon.Bool(true)))), empty, nil, Invalid, "both complete controllers and rule"},
		{"edition untyped controllers", "edition", ed(body("controllers", arr(s(key)), "rule", body("any_one", canon.Bool(true)))), empty, nil, Invalid, "is not a typed subject"},
		{"edition contract without roles", "edition", ed(body("contract", contract)), empty, nil, Invalid, "requires body.x_identity_v1.task_roles"},
		{"edition roles without contract", "edition", ed(body()), body("task_roles", roles), nil, Invalid, "requires body.contents.contract"},
		{"edition contract role field", "edition", ed(body("contract", setField(contract, "beneficiary", s(key)))), body("task_roles", roles), nil, Invalid, "contract.beneficiary is forbidden"},
		{"edition contract no profile", "edition", ed(body("contract", body())), body("task_roles", roles), nil, Invalid, "profile is missing"},
		{"edition roles no unit", "edition", ed(body("contract", contract)), body("task_roles", dropField(roles, "counting_unit")), nil, Invalid, "counting_unit is missing"},
		{"edition roles two issuer modes", "edition", ed(body("contract", contract)), body("task_roles", setField(roles, "eligible_issuers", arr(idS))), nil, Invalid, "exactly one of"},
		{"edition roles unknown member", "edition", ed(body("contract", contract)), body("task_roles", setField(roles, "issuer", idS)), nil, Invalid, "issuer is not a member"},
		{"edition marker unknown member", "edition", ed(body()), body("amends", arr(s(tID))), nil, Invalid, "amends is not a member"},
		{"withdraw marker member", "withdraw_approval", body("resource", tID, "edition", tID2), body("task_roles", roles), nil, Invalid, "must be {} for withdraw_approval"},
		{"withdraw missing edition", "withdraw_approval", body("resource", tID), empty, nil, Invalid, "edition is missing"},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := rc2Read(t, c.kind, c.b, c.marker, c.actor)
			if st.Status != c.want || !strings.Contains(st.Why, c.why) {
				t.Fatalf("read %s (%q), want %s containing %q", st.Status, st.Why, c.want, c.why)
			}
		})
	}
	// The unchanged rc/1 schema still reads genesis controllers as keys: rc/1 meaning is untouched.
	if _, err := readBody(t, "genesis", minimal("genesis")); err != nil {
		t.Fatalf("rc/1 key-controller genesis: %v", err)
	}
	if _, err := readBody(t, "genesis", setField(minimal("genesis"), "controllers", arr(idS))); err == nil {
		t.Fatal("rc/1 genesis read a typed subject")
	}
}
