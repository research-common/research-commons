package wire

import (
	"bytes"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

// The recoverable-root profile's kinds at the reader (recoverable-root note §4, §8): what reads Valid, what is
// Invalid, what is Unsupported, and how a handover's carried statement is read.

func rrKeys() (root, recovery, successor Key) {
	return EIP191Key{Scalar: bytes.Repeat([]byte{51}, 32)}, Ed25519Key{Seed: bytes.Repeat([]byte{52}, 32)}, EIP191Key{Scalar: bytes.Repeat([]byte{53}, 32)}
}

func commitmentsOf(keys ...Key) *canon.Object {
	var cs canon.Array
	for _, k := range keys {
		cs = append(cs, canon.String(RecoveryCommitment(k.Signer())))
	}
	return body("commitments", cs, "rule", body("any_one", canon.Bool(true)))
}

func rrRead(t *testing.T, line []byte) *Statement {
	t.Helper()
	st, err := NewIdentityReader().Read(line)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	return st
}

func TestRecoveryCommitment(t *testing.T) {
	_, c, _ := rrKeys()
	got := RecoveryCommitment(c.Signer())
	if !reCommitment.MatchString(got) || got != RecoveryCommitment(c.Signer()) || got == RecoveryCommitment("0x"+strings.Repeat("0", 40)) {
		t.Fatal(got)
	}
	// The commitment is over the canonical signer string: letter case changes it, so a tool lowercases first.
	if RecoveryCommitment("0xABCDEF") == RecoveryCommitment("0xabcdef") {
		t.Fatal("case-insensitive")
	}
}

func TestRecoverableInceptionStatuses(t *testing.T) {
	root, c, s := rrKeys()
	cases := []struct {
		name   string
		b      *canon.Object
		status Status
		why    string
	}{
		{"one commitment under any_one", body("profile", RecoverableRootProfile, "recovery", commitmentsOf(c)), Valid, ""},
		{"no recovery member", body("profile", RecoverableRootProfile), Invalid, "body.recovery is required"},
		{"two commitments", body("profile", RecoverableRootProfile, "recovery", commitmentsOf(c, s)), Unsupported, "recovery rule any_one over 2"},
		{"another rule", body("profile", RecoverableRootProfile, "recovery", body("commitments", canon.Array{canon.String(RecoveryCommitment(c.Signer()))}, "rule", body("k_of_n", 1))), Unsupported, "recovery rule k_of_n"},
		{"any_one false", body("profile", RecoverableRootProfile, "recovery", body("commitments", canon.Array{canon.String(RecoveryCommitment(c.Signer()))}, "rule", body("any_one", canon.Bool(false)))), Invalid, "any_one is not true"},
		{"not a commitment", body("profile", RecoverableRootProfile, "recovery", body("commitments", canon.Array{canon.String("sha256:00")}, "rule", body("any_one", canon.Bool(true)))), Invalid, "commitments[0] is not a commitment"},
		{"extra member in recovery", body("profile", RecoverableRootProfile, "recovery", setField(commitmentsOf(c), "note", canon.String("x"))), Invalid, "closed object"},
		{"fixed-root still valid", body("profile", FixedRootProfile), Valid, ""},
		{"unknown profile", body("profile", "future-profile-v9"), Unsupported, "identity profile future-profile-v9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := rrRead(t, frSign(frDraft(t, "identity_inception", root, tc.b), root))
			if st.Status != tc.status || !strings.Contains(st.Why, tc.why) {
				t.Fatalf("status %q why %q; want %q containing %q", st.Status, st.Why, tc.status, tc.why)
			}
			if tc.status == Valid && tc.b.Members["profile"] == canon.String(RecoverableRootProfile) && InceptionCommitment(st) != RecoveryCommitment(c.Signer()) {
				t.Fatalf("commitment %q", InceptionCommitment(st))
			}
		})
	}
}

func TestSuccessionAndRecoveryBodies(t *testing.T) {
	root, c, s := rrKeys()
	inc := rrRead(t, frSign(frDraft(t, "identity_inception", root, body("profile", RecoverableRootProfile, "recovery", commitmentsOf(c))), root))
	succ := rrRead(t, frSign(frDraft(t, "identity_succession", s, body("identity", inc.ID)), s))
	if succ.Status != Valid {
		t.Fatalf("succession: %s %s", succ.Status, succ.Why)
	}
	// a succession must be seq 0
	later := setField(frDraft(t, "identity_succession", s, body("identity", inc.ID)), "seq", canon.Int(1))
	later = setField(later, "prev", canon.String(succ.ID))
	if st := rrRead(t, frSign(later, s)); st.Status != Invalid || !strings.Contains(st.Why, "seq 0") {
		t.Fatalf("succession at seq 1: %s %s", st.Status, st.Why)
	}
	successor := body("key", s.Signer(), "inception", succ.ID)
	next := commitmentsOf(EIP191Key{Scalar: bytes.Repeat([]byte{54}, 32)})
	cases := []struct {
		name   string
		b      *canon.Object
		status Status
		why    string
	}{
		{"last_good a line, successor and next", body("identity", inc.ID, "last_good", tID, "successor", successor, "next", next), Valid, ""},
		{"last_good null", body("identity", inc.ID, "last_good", canon.Null{}, "successor", successor, "next", next), Valid, ""},
		{"closing: successor null, no next", body("identity", inc.ID, "last_good", tID, "successor", canon.Null{}), Valid, ""},
		{"with a note", body("identity", inc.ID, "last_good", tID, "successor", successor, "next", next, "note", "root device lost"), Valid, ""},
		{"closing with next", body("identity", inc.ID, "last_good", tID, "successor", canon.Null{}, "next", next), Invalid, "next is not allowed"},
		{"successor without next", body("identity", inc.ID, "last_good", tID, "successor", successor), Invalid, "next is required"},
		{"no last_good", body("identity", inc.ID, "successor", successor, "next", next), Invalid, "last_good is required"},
		{"last_good not an id", body("identity", inc.ID, "last_good", "tip", "successor", successor, "next", next), Invalid, "neither null nor a statement id"},
		{"successor missing inception", body("identity", inc.ID, "last_good", tID, "successor", body("key", s.Signer()), "next", next), Invalid, "successor.inception"},
		{"successor extra member", body("identity", inc.ID, "last_good", tID, "successor", setField(successor, "note", canon.String("x")), "next", next), Invalid, "closed object"},
		{"next with two commitments", body("identity", inc.ID, "last_good", tID, "successor", successor, "next", commitmentsOf(root, s)), Unsupported, "recovery rule"},
		{"successor in a future key form", body("identity", inc.ID, "last_good", tID, "successor", body("key", "mldsa65:"+strings.Repeat("ab", 32), "inception", succ.ID), "next", next), Unsupported, "key form"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := rrRead(t, frSign(frDraft(t, "identity_recovery", c, tc.b), c))
			if st.Status != tc.status || !strings.Contains(st.Why, tc.why) {
				t.Fatalf("status %q why %q; want %q containing %q", st.Status, st.Why, tc.status, tc.why)
			}
		})
	}
	// an actor on any of the three kinds is invalid: they are raw-key statements
	withActor := setField(frDraft(t, "identity_recovery", c, body("identity", inc.ID, "last_good", canon.Null{}, "successor", canon.Null{})), ActorField, body("identity", inc.ID, "grant", tID))
	if st := rrRead(t, frSign(withActor, c)); st.Status != Invalid || !strings.Contains(st.Why, "takes no "+ActorField) {
		t.Fatalf("recovery with an actor: %s %s", st.Status, st.Why)
	}
}

func TestHandoverCarriesTheSignedRecovery(t *testing.T) {
	root, c, s := rrKeys()
	inc := rrRead(t, frSign(frDraft(t, "identity_inception", root, body("profile", RecoverableRootProfile, "recovery", commitmentsOf(c))), root))
	succ := rrRead(t, frSign(frDraft(t, "identity_succession", s, body("identity", inc.ID)), s))
	recLine := frSign(frDraft(t, "identity_recovery", c, body("identity", inc.ID, "last_good", canon.Null{},
		"successor", body("key", s.Signer(), "inception", succ.ID), "next", commitmentsOf(s))), c)
	rec := rrRead(t, recLine)
	if rec.Status != Valid {
		t.Fatalf("recovery: %s %s", rec.Status, rec.Why)
	}
	parsed := func(line []byte) *canon.Object {
		v, err := canon.Parse(line)
		if err != nil {
			t.Fatal(err)
		}
		return v.(*canon.Object)
	}
	handover := func(carried *canon.Object) *Statement {
		d := frDraft(t, "identity_handover", root, body("identity", inc.ID, "recovery", carried))
		d = setField(setField(d, "seq", canon.Int(1)), "prev", canon.String(inc.ID))
		return rrRead(t, frSign(d, root))
	}
	// a good carry: the handover is valid and the carried statement is verified and valid
	h := handover(parsed(recLine))
	if h.Status != Valid || h.Carried == nil || !h.Carried.Verified || h.Carried.Status != Valid || h.Carried.ID != rec.ID || h.Carried.Signer != c.Signer() {
		t.Fatalf("handover %s %s carried %+v", h.Status, h.Why, h.Carried)
	}
	// a tampered carry (one body byte changed, same sig): the handover stays valid; the carried signature does not verify
	tampered := parsed(bytes.Replace(recLine, []byte(`"last_good":null`), []byte(`"last_good":"`+tID+`"`), 1))
	h = handover(tampered)
	if h.Status != Valid || h.Carried == nil || h.Carried.Verified || h.Carried.Status != Invalid || !strings.Contains(h.Carried.Why, "signature does not verify") {
		t.Fatalf("tampered carry: handover %s %s carried %+v", h.Status, h.Why, h.Carried)
	}
	// a carry under an algorithm this reader lacks: the handover stays valid; the carried statement is unsupported, unverified
	future := setField(setField(dropField(parsed(recLine), "sig"), "alg", canon.String("mldsa-65")), "signer", canon.String("mldsa65:"+strings.Repeat("ab", 32)))
	future = setField(future, "sig", canon.String("mldsa65:"+strings.Repeat("cd", 32)))
	h = handover(future)
	if h.Status != Valid || h.Carried == nil || h.Carried.Verified || h.Carried.Status != Unsupported || !strings.HasPrefix(h.Carried.Why, "alg ") {
		t.Fatalf("future-alg carry: handover %s %s carried %+v", h.Status, h.Why, h.Carried)
	}
	// a carry that is a statement of another kind: valid handover, carried valid but not a recovery (the evaluator voids it)
	h = handover(parsed(frSign(frDraft(t, "identity_succession", s, body("identity", inc.ID)), s)))
	if h.Status != Valid || h.Carried == nil || h.Carried.Kind != "identity_succession" {
		t.Fatalf("other-kind carry: %s %s %+v", h.Status, h.Why, h.Carried)
	}
	// not a statement at all: the handover is invalid
	for name, carried := range map[string]canon.Value{
		"no sig":     dropField(parsed(recLine), "sig"),
		"not object": canon.String("x"),
		"garbage":    body("kind", "identity_recovery", "sig", "0x00"),
	} {
		d := frDraft(t, "identity_handover", root, body("identity", inc.ID, "recovery", carried))
		d = setField(setField(d, "seq", canon.Int(1)), "prev", canon.String(inc.ID))
		if st := rrRead(t, frSign(d, root)); st.Status != Invalid || st.Carried != nil {
			t.Fatalf("%s: %s %s", name, st.Status, st.Why)
		}
	}
	// a handover at seq 0 is invalid: the root's first line is its inception
	if st := rrRead(t, frSign(frDraft(t, "identity_handover", root, body("identity", inc.ID, "recovery", parsed(recLine))), root)); st.Status != Invalid || !strings.Contains(st.Why, "follow the root's first line") {
		t.Fatalf("seq 0: %s %s", st.Status, st.Why)
	}
	// the marker of the three kinds must be {}
	marked := setField(frDraft(t, "identity_handover", root, body("identity", inc.ID, "recovery", parsed(recLine))), "body",
		setField(body("identity", inc.ID, "recovery", parsed(recLine)), IdentityCrit, body("intent", tID)))
	marked = setField(setField(marked, "seq", canon.Int(1)), "prev", canon.String(inc.ID))
	if st := rrRead(t, frSign(marked, root)); st.Status != Invalid || !strings.Contains(st.Why, "must be {}") {
		t.Fatalf("marker: %s %s", st.Status, st.Why)
	}
}
