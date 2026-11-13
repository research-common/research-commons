package identity_test

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// TestWriterOutputAdmits: lines the writer path signs (wire.WriterMajor + wire.IdentityDraft + wire.Write) for an
// inception, a grant, an act under it and a cut at last_good are admitted by identity.Admit, and the evaluator
// answers exactly what the profile says: the act eligible for I, a later act cut. The writer's output is the
// reader's input, with no test-only signer in between.
func TestWriterOutputAdmits(t *testing.T) {
	seed := func(l string) wire.Key { h := sha256.Sum256([]byte(l)); return wire.Ed25519Key{Seed: h[:]} }
	root, worker := seed("writer root"), seed("writer worker")
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	ts := "2026-11-13T00:00:00Z"
	var lines [][]byte
	heads := map[string]*wire.Statement{}
	write := func(k wire.Key, kind string, body *canon.Object, actor *wire.Actor, marker *canon.Object) *wire.Statement {
		t.Helper()
		d := wire.Draft{Kind: kind, TS: ts, Body: body}
		if h := heads[k.Signer()]; h != nil {
			d.Seq, d.Prev = h.Seq+1, h.ID
		}
		if wire.WriterMajor(kind, actor != nil) == wire.CandidateMajor {
			var err error
			if d, err = wire.IdentityDraft(d, actor, marker); err != nil {
				t.Fatal(err)
			}
		}
		st, err := wire.Write(d, k, now)
		if err != nil || st.Status != wire.Valid {
			t.Fatalf("%s: %v %v %s", kind, err, st.Status, st.Why)
		}
		heads[k.Signer()] = st
		lines = append(lines, st.Line())
		return st
	}
	o := func(kv ...any) *canon.Object {
		x := &canon.Object{Members: map[string]canon.Value{}}
		for i := 0; i < len(kv); i += 2 {
			x.Keys = append(x.Keys, kv[i].(string))
			x.Members[kv[i].(string)] = kv[i+1].(canon.Value)
		}
		return x
	}
	c := func(n byte) canon.Value {
		d := "sha256:"
		for range 64 {
			d += string("0123456789abcdef"[n%16])
		}
		return o("digest", canon.String(d), "size", canon.Int(1))
	}
	d := write(worker, "authored", o("content", c(1), "type", canon.String("dataset")), nil, nil)
	if d.RC != "rc/1" {
		t.Fatal("a bare-key line was not written rc/1")
	}
	i := write(root, "identity_inception", o("profile", canon.String(wire.FixedRootProfile)), nil, nil)
	perms := canon.Array{o("amend", canon.Bool(false), "kind", canon.String("authored"), "targets", o("any_content", canon.Bool(true)))}
	g := write(root, "identity_grant", o("delegate", o("inception", canon.String(d.ID), "key", canon.String(worker.Signer())),
		"identity", canon.String(i.ID), "permissions", perms), nil, nil)
	actor := &wire.Actor{Identity: i.ID, Grant: g.ID}
	a1 := write(worker, "authored", o("content", c(2), "type", canon.String("dataset")), actor, nil)
	a2 := write(worker, "authored", o("content", c(3), "type", canon.String("dataset")), actor, nil)
	if a1.RC != "rc/2" || a1.Actor == nil || a1.Actor.Grant != g.ID {
		t.Fatalf("act: %s %+v", a1.RC, a1.Actor)
	}
	ev := func() *identity.Actors {
		a, err := identity.NewActors(lines)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	if id, st, why := ev().Eligible(a2); id != i.ID || st != policy.ActorEligible {
		t.Fatalf("before the cut: %s %s %v", id, st, why)
	}
	write(root, "identity_cut", o("grant", canon.String(g.ID), "identity", canon.String(i.ID), "last_good", canon.String(a1.ID),
		"reason", canon.String("key_compromise")), nil, nil)
	a := ev()
	if _, st, why := a.Eligible(a1); st != policy.ActorEligible {
		t.Fatalf("last_good act: %s %v", st, why)
	}
	if _, st, why := a.Eligible(a2); st != policy.ActorDenied {
		t.Fatalf("act after last_good: %s %v", st, why)
	}
}
