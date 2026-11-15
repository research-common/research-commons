package wire

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
)

// The production identity reader reads its one critical extension through the same registry type the unchanged
// reader carries (extensions.go): rc/2 registers x_identity_v1 and nothing else, rc/1 registers nothing. These
// tests drive real signed lines through the production constructor, and through a reader built with other
// registrations where the registry's own behaviour is the point, so a mutation of the wiring (an unregistered
// validator, a no-op one) fails a named test below.

var regKey = Ed25519Key{Seed: bytes.Repeat([]byte{83}, 32)}

// regLine signs d (rc/2 unless d.RC says otherwise) with regKey.
func regLine(d Draft) []byte {
	if d.RC == "" {
		d.RC = "rc/2"
	}
	if d.TS == "" {
		d.TS = tTS
	}
	if d.Seq == 0 && d.Kind != "identity_inception" {
		d.Seq, d.Prev = 3, tID
	}
	line, _ := Sign(d, regKey)
	return line
}

func regAuthored(marker canon.Value, crit []string, actor *Actor) Draft {
	b := minimal("authored")
	if marker != nil {
		b = setField(b, IdentityCrit, marker)
	}
	for _, c := range crit {
		if _, ok := b.Get(c); !ok {
			b = setField(b, c, body())
		}
	}
	return Draft{Kind: "authored", Crit: crit, Body: b, Actor: actor}
}

// TestIdentityReaderRegistryIsTheOnlyHook: the production reader's registries hold exactly the profile's one
// extension on rc/2 and none on rc/1, and every registered name is a validator the reader runs.
func TestIdentityReaderRegistryIsTheOnlyHook(t *testing.T) {
	conformance.Partial(t, "C-id-36", "the production identity reader's critical registry is the wire reader's: rc/2 registers x_identity_v1 only, rc/1 none (TestIdentityReaderRegistryIsTheOnlyHook); the keylog, resolver and command halves are elsewhere")
	ir := NewIdentityReader()
	if len(ir.v1.extensions) != 0 {
		t.Fatalf("rc/1 registry holds %d extensions, want none", len(ir.v1.extensions))
	}
	var names []string
	for n, v := range ir.v2.extensions {
		if v == nil {
			t.Fatalf("%s registered with a nil validator", n)
		}
		names = append(names, n)
	}
	if !slices.Equal(names, []string{IdentityCrit}) {
		t.Fatalf("rc/2 registry holds %v, want [%s]", names, IdentityCrit)
	}
	// The production reader (ReadStored) is built from the same constructor.
	if got := NewDualReader().id; len(got.v2.extensions) != 1 || got.v2.extensions[IdentityCrit] == nil {
		t.Fatalf("the dual reader's identity reader has registry %v", got.v2.extensions)
	}
}

// TestIdentityReaderCriticalRegistryDecides: each case is a verified rc/2 line whose one defect the registry path
// names (the marker, its pairing with the actor, or an unregistered critical token); the production reader holds it
// verified and non-passing with the stated reason, and the same line with the defect removed reads Valid, so the
// mutation reached the boundary under test. The unknown-token cases are Unsupported (retained, never evaluated), not
// refused: they chain, and no reader reads their body.
func TestIdentityReaderCriticalRegistryDecides(t *testing.T) {
	conformance.Covers(t, "C-id-37")
	conformance.Partial(t, "C-id-41", "wire half through the registry: a marker that is not an object, an actor on a raw-key kind, a closed-marker violation and amends without an actor are verified Invalid; the other pairings are the vector cases and internal/identity; mixed controller semantics need the resource consumer")
	act := &Actor{Identity: tID, Grant: tID2}
	empty := canon.Value(body())
	id := []string{IdentityCrit}
	for _, c := range []struct {
		name   string
		d      Draft
		want   Status
		why    string
		actor  bool
		repair func(Draft) Draft // the same line with the defect removed must read Valid
	}{
		{"valid, no actor", regAuthored(empty, id, nil), Valid, "", false, nil},
		{"valid, actor", regAuthored(empty, id, act), Valid, "", true, nil},
		{"marker is a string", regAuthored(s("x"), id, nil), Invalid, "body.x_identity_v1 is not an object", false,
			func(d Draft) Draft { return regAuthored(empty, id, nil) }},
		{"marker is an array", regAuthored(arr(), id, act), Invalid, "body.x_identity_v1 is not an object", true,
			func(d Draft) Draft { return regAuthored(empty, id, act) }},
		{"marker closed object", regAuthored(body("junk", 1), id, nil), Invalid, "body.x_identity_v1.junk is not a member of this closed object", false,
			func(d Draft) Draft { return regAuthored(empty, id, nil) }},
		{"amends without actor", regAuthored(body("amends", arr(s(tID))), id, nil), Invalid, "amends requires an identity actor", false,
			func(d Draft) Draft { return regAuthored(body("amends", arr(s(tID))), id, act) }},
		{"amends with actor", regAuthored(body("amends", arr(s(tID))), id, act), Valid, "", true, nil},
		{"amends empty set", regAuthored(body("amends", arr()), id, act), Invalid, "body.x_identity_v1.amends", true,
			func(d Draft) Draft { return regAuthored(body("amends", arr(s(tID))), id, act) }},
		{"inception with a marker member", Draft{Kind: "identity_inception", Crit: id,
			Body: body("profile", FixedRootProfile, IdentityCrit, body("junk", 1))}, Invalid, "body.x_identity_v1 must be {}", false,
			func(d Draft) Draft {
				return Draft{Kind: "identity_inception", Crit: id, Body: body("profile", FixedRootProfile, IdentityCrit, body())}
			}},
		{"inception with an actor", Draft{Kind: "identity_inception", Crit: id, Actor: act,
			Body: body("profile", FixedRootProfile, IdentityCrit, body())}, Invalid, "identity_inception is a raw-key statement and takes no x_actor_v1", true,
			func(d Draft) Draft {
				return Draft{Kind: "identity_inception", Crit: id, Body: body("profile", FixedRootProfile, IdentityCrit, body())}
			}},
		{"progress without its pin", Draft{Kind: "progress", Crit: id, Actor: act, Body: setField(minimal("progress"), IdentityCrit, empty)},
			Invalid, "intent is required for progress", true,
			func(d Draft) Draft {
				return Draft{Kind: "progress", Crit: id, Actor: act, Body: setField(minimal("progress"), IdentityCrit, body("intent", tID))}
			}},
		{"submit with a pin", Draft{Kind: "submit", Crit: id, Actor: act, Body: setField(minimal("submit"), IdentityCrit, body("intent", tID))},
			Invalid, "must be {} for submit", true,
			func(d Draft) Draft {
				return Draft{Kind: "submit", Crit: id, Actor: act, Body: setField(minimal("submit"), IdentityCrit, empty)}
			}},
		{"genesis with a member", Draft{Kind: "genesis", Crit: id, Body: setField(
			body("type", "collection", "name", "n", "controllers", arr(body("identity", tID)), "rule", body("any_one", canon.Bool(true))),
			IdentityCrit, body("task_roles", body()))}, Invalid, "must be {} for genesis", false, nil},
		{"genesis with an actor", Draft{Kind: "genesis", Crit: id, Actor: act, Body: setField(
			body("type", "collection", "name", "n", "controllers", arr(body("identity", tID)), "rule", body("any_one", canon.Bool(true))),
			IdentityCrit, empty)}, Invalid, "genesis is a raw-key statement and takes no x_actor_v1", true, nil},
		{"edition task_roles malformed", Draft{Kind: "edition", Crit: id, Body: setField(
			body("resource", tID, "predecessors", arr(s(tID)), "contents", body("members", arr())),
			IdentityCrit, body("task_roles", body("junk", 1)))}, Invalid, "task_roles", false, nil},

		// an unregistered critical token: the whole line is unsupported, never partly read
		{"identity plus unknown token", regAuthored(empty, []string{IdentityCrit, "x_other"}, act), Unsupported, "crit x_identity_v1,x_other", true, nil},
		{"unknown token sorting first", regAuthored(empty, []string{"x_a", IdentityCrit}, act), Unsupported, "crit x_a,x_identity_v1", true, nil},
		{"unknown token, junk marker", regAuthored(s("x"), []string{IdentityCrit, "x_other"}, nil), Unsupported, "crit x_identity_v1,x_other", false, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			line := regLine(c.d)
			st, err := NewIdentityReader().Read(line)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !st.Verified || st.Status != c.want || !strings.Contains(st.Why, c.why) {
				t.Fatalf("read %s verified=%v %q, want %s %q", st.Status, st.Verified, st.Why, c.want, c.why)
			}
			if c.want == Unsupported && st.Why != c.why {
				t.Fatalf("why %q, want exactly %q", st.Why, c.why)
			}
			if (st.Actor != nil) != c.actor {
				t.Fatalf("actor %+v, want present=%v", st.Actor, c.actor)
			}
			if c.repair != nil {
				fixed, err := NewIdentityReader().Read(regLine(c.repair(c.d)))
				if err != nil || fixed.Status != Valid {
					t.Fatalf("with the defect removed the line reads %v %v, want valid", fixed, err)
				}
			}
			// the production dispatch (ReadStored) gives the same answer
			via, err := ReadStored(line)
			if err != nil || via.ID != st.ID || via.Status != st.Status || via.Why != st.Why {
				t.Fatalf("ReadStored differs: %+v %v", via, err)
			}
		})
	}
}

// TestIdentityReaderRegistryContract: the registry runs under the wire reader's contract for validators:
// after signature verification, never for an unsupported list, in crit order, on a private copy of the envelope
// without sig; a validator's error is a verified Invalid line (the identity reader's one difference from the
// unchanged reader, which refuses), never a refusal and never Valid. rc/1 never reaches a validator.
func TestIdentityReaderRegistryContract(t *testing.T) {
	var calls []string
	rec := func(name string, err error) ExtensionValidator {
		return func(env *canon.Object) error {
			calls = append(calls, name)
			env.Keys = nil // mutating the private copy must change nothing the reader returns
			env.Members = map[string]canon.Value{}
			return err
		}
	}
	reset := func() { calls = nil }
	line := regLine(regAuthored(body(), []string{IdentityCrit}, &Actor{Identity: tID, Grant: tID2}))
	base, err := NewIdentityReader().Read(line)
	if err != nil || base.Status != Valid {
		t.Fatalf("baseline: %v %v", base, err)
	}

	t.Run("accepting validator runs once, on a copy, and changes nothing", func(t *testing.T) {
		reset()
		st, err := newIdentityReader(map[string]ExtensionValidator{IdentityCrit: rec("id", nil)}).Read(line)
		if err != nil || !slices.Equal(calls, []string{"id"}) {
			t.Fatalf("calls %v err %v", calls, err)
		}
		if st.Status != Valid || st.ID != base.ID || !bytes.Equal(st.Line(), base.Line()) || st.Actor == nil {
			t.Fatalf("a validator that mutated its copy changed the result: %+v", st)
		}
	})
	t.Run("the envelope handed over is the verified one without sig", func(t *testing.T) {
		var got *canon.Object
		v := func(env *canon.Object) error { got = env; return nil }
		if _, err := newIdentityReader(map[string]ExtensionValidator{IdentityCrit: v}).Read(line); err != nil {
			t.Fatal(err)
		}
		if _, hasSig := got.Get("sig"); hasSig {
			t.Fatal("the validator was handed sig")
		}
		want := dropField(parseObj(t, line), "sig")
		if !bytes.Equal(canon.Encode(got), canon.Encode(want)) {
			t.Fatalf("envelope differs from the signed one:\n%s\n%s", canon.Encode(got), canon.Encode(want))
		}
	})
	t.Run("a validator error is a verified invalid line, not a refusal", func(t *testing.T) {
		reset()
		boom := errors.New("registered rule broken")
		st, err := newIdentityReader(map[string]ExtensionValidator{IdentityCrit: rec("id", boom)}).Read(line)
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		if st.Status != Invalid || !st.Verified || st.Why != boom.Error() || st.ID != base.ID || st.Actor == nil {
			t.Fatalf("got %s verified=%v %q", st.Status, st.Verified, st.Why)
		}
	})
	t.Run("no validator runs before the signature verifies", func(t *testing.T) {
		reset()
		bad := bytes.Replace(line, []byte(`"sig":"`), []byte(`"sig":"0`), 1) // one hex digit too many
		_, err := newIdentityReader(map[string]ExtensionValidator{IdentityCrit: rec("id", nil)}).Read(bad)
		var r *refusal.Refusal
		if !errors.As(err, &r) || len(calls) != 0 {
			t.Fatalf("err %v calls %v", err, calls)
		}
	})
	t.Run("an unregistered name in the list means no validator runs", func(t *testing.T) {
		reset()
		l := regLine(regAuthored(body(), []string{IdentityCrit, "x_other"}, nil))
		st, err := newIdentityReader(map[string]ExtensionValidator{IdentityCrit: rec("id", nil)}).Read(l)
		if err != nil || st.Status != Unsupported || len(calls) != 0 {
			t.Fatalf("%+v %v calls %v", st, err, calls)
		}
	})
	t.Run("registering the other name too runs both, in crit order, and an error stops the rest", func(t *testing.T) {
		reset()
		l := regLine(regAuthored(body(), []string{IdentityCrit, "x_other"}, nil))
		both := map[string]ExtensionValidator{IdentityCrit: rec("id", nil), "x_other": rec("other", nil)}
		st, err := newIdentityReader(both).Read(l)
		if err != nil || st.Status != Valid || !slices.Equal(calls, []string{"id", "other"}) {
			t.Fatalf("%+v %v calls %v", st, err, calls)
		}
		reset()
		both["x_identity_v1"] = rec("id", errors.New("no"))
		st, err = newIdentityReader(both).Read(l)
		if err != nil || st.Status != Invalid || !slices.Equal(calls, []string{"id"}) {
			t.Fatalf("%+v %v calls %v", st, err, calls)
		}
	})
	t.Run("rc/1 never reaches a validator", func(t *testing.T) {
		reset()
		l := regLine(Draft{RC: "rc/1", Kind: "authored", Crit: []string{IdentityCrit}, Body: setField(minimal("authored"), IdentityCrit, body())})
		st, err := newIdentityReader(map[string]ExtensionValidator{IdentityCrit: rec("id", nil)}).Read(l)
		if err != nil || st.Status != Unsupported || st.Why != "crit "+IdentityCrit || len(calls) != 0 {
			t.Fatalf("%+v %v calls %v", st, err, calls)
		}
	})
	t.Run("a reader without the registration cannot read rc/2 at all", func(t *testing.T) {
		st, err := newIdentityReader(nil).Read(line)
		if err != nil || st.Status != Unsupported || st.Why != "crit "+IdentityCrit || !st.Verified || st.ID != base.ID {
			t.Fatalf("%+v %v", st, err)
		}
		if st.Actor != nil && st.Status == Valid {
			t.Fatal("a statement read without its registration reads Valid")
		}
	})
	t.Run("a registration that accepts everything does not read a broken marker as valid", func(t *testing.T) {
		// The registry decides the marker; the kind's body schema still runs after it (a recognized marker never
		// replaces the base schema): a base-schema violation stays Invalid under any validator.
		bad := regLine(Draft{Kind: "authored", Crit: []string{IdentityCrit}, Body: body("content", 7, IdentityCrit, body())})
		st, err := newIdentityReader(map[string]ExtensionValidator{IdentityCrit: func(*canon.Object) error { return nil }}).Read(bad)
		if err != nil || st.Status != Invalid {
			t.Fatalf("%+v %v", st, err)
		}
	})
}

// TestCheckUnsignedRunsTheRegistry: the writer's check of an envelope prepared for an external signer goes through
// the same registry as a signed read, so the bytes handed to the signer are bytes every reader holds valid.
func TestCheckUnsignedRunsTheRegistry(t *testing.T) {
	for _, c := range []struct {
		name   string
		marker canon.Value
		want   Status
	}{{"valid", body(), Valid}, {"junk marker", body("junk", 1), Invalid}, {"marker not an object", s("x"), Invalid}} {
		t.Run(c.name, func(t *testing.T) {
			env := regAuthoredEnvelope(regAuthored(c.marker, []string{IdentityCrit}, nil))
			st, err := CheckUnsigned(env)
			if err != nil || st.Status != c.want || st.Verified {
				t.Fatalf("%+v %v", st, err)
			}
		})
	}
}

func regAuthoredEnvelope(d Draft) *canon.Object {
	d.RC, d.TS, d.Seq, d.Prev = "rc/2", tTS, 3, tID
	return d.Envelope(regKey)
}

func parseObj(t *testing.T, line []byte) *canon.Object {
	t.Helper()
	v, err := canon.Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	return v.(*canon.Object)
}
