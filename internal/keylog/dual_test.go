package keylog_test

import (
	"bytes"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// TestStoreWithDualReader: the store option. NewStore() and NewStore(WithReader(nil)) read with wire.Read; a store
// built WithReader(wire.NewDualReader()) places a verified rc/2 line directly (no vouching needed: it is verified),
// reads its actor, refuses a bad rc/2 signature the unchanged reader would retain, and gives an rc/1 log the same
// view as the default store.
func TestStoreWithDualReader(t *testing.T) {
	conformance.Partial(t, "C-id-36", "keylog half of the dual reader: rc/2 verified and placed, a bad rc/2 signature refused, rc/1 logs unchanged; the resolver views are in internal/resolve")
	k := wire.Ed25519Key{Seed: bytes.Repeat([]byte{53}, 32)}
	ts := "2026-10-21T00:00:00Z"
	parse := func(raw string) *canon.Object {
		v, err := canon.Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return v.(*canon.Object)
	}
	first, fid := wire.Sign(wire.Draft{Kind: "describes", TS: ts, Body: parse(`{"about":{"content":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)}, k)
	d := wire.Draft{RC: "rc/2", Kind: "authored", Seq: 1, Prev: fid, TS: ts, Crit: []string{wire.IdentityCrit},
		Body: parse(`{"content":{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":0},"type":"dataset","x_identity_v1":{}}`)}
	env := d.Envelope(k)
	env.Keys = append(env.Keys, wire.ActorField)
	env.Members[wire.ActorField] = parse(`{"identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","grant":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`)
	ss := wire.PAE(wire.PayloadType("authored", 2), canon.Encode(env))
	mid := wire.ID(ss)
	env.Keys = append(env.Keys, "sig")
	env.Members["sig"] = canon.String(k.Sign(ss))
	middle := canon.Encode(env)

	dual := keylog.NewStore(keylog.WithReader(wire.NewDualReader()))
	log := dual.Log(k.Signer())
	for _, l := range [][]byte{middle, first} { // rc/2 first: it waits on its prev like any verified line
		if _, err := log.Add(l); err != nil {
			t.Fatal(err)
		}
	}
	v := log.View()
	if len(v.Retained) != 0 || len(v.Lines) != 2 {
		t.Fatalf("dual store: a verified rc/2 line is placed, not retained: %s", v.Render())
	}
	for _, ln := range v.Lines {
		if ln.State != keylog.Chained || !ln.St.Verified || ln.St.Status != wire.Valid {
			t.Fatalf("dual store line: %+v", ln)
		}
		if ln.St.ID == mid && (ln.St.Actor == nil || ln.St.RC != "rc/2") {
			t.Fatalf("dual store did not read the actor: %+v", ln.St)
		}
	}
	// the default store, and a nil reader, retain the same rc/2 line unverified
	for _, s := range []*keylog.Store{keylog.NewStore(), keylog.NewStore(keylog.WithReader(nil))} {
		st, err := s.Log(k.Signer()).Add(middle)
		if err != nil || st.Verified || st.Status != wire.Unsupported || st.ID != mid {
			t.Fatalf("default store changed: %+v %v", st, err)
		}
	}
	// a bad rc/2 signature: retained by the unchanged reader, refused by the dual one
	env.Members["sig"] = canon.String(k.Sign([]byte("something else")))
	bad := canon.Encode(env)
	if st, err := keylog.NewStore().Log(k.Signer()).Add(bad); err != nil || st.Verified {
		t.Fatalf("unchanged reader on a bad rc/2 signature: %+v %v", st, err)
	}
	if _, err := dual.Log(k.Signer()).Add(bad); err == nil {
		t.Fatal("dual store kept a bad rc/2 signature")
	}
	// an rc/1-only log: the same view under both stores
	plain, dualOnly := keylog.NewStore(), keylog.NewStore(keylog.WithReader(wire.NewDualReader()))
	second, _ := wire.Sign(wire.Draft{Kind: "revoke_key", Seq: 1, Prev: fid, TS: ts, Body: parse(`{"reason":"superseded"}`)}, k)
	for _, s := range []*keylog.Store{plain, dualOnly} {
		for _, l := range [][]byte{second, first} {
			if _, err := s.Log(k.Signer()).Add(l); err != nil {
				t.Fatal(err)
			}
		}
	}
	if a, b := plain.Log(k.Signer()).View().Render(), dualOnly.Log(k.Signer()).View().Render(); a != b {
		t.Fatalf("rc/1 log differs under the dual store:\n%s\nvs\n%s", a, b)
	}
}
