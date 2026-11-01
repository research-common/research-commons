package keylog_test

// Wire/linkage compatibility demonstration only, not identity authorization.
import (
	"bytes"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

func TestFixedRootCandidateOldReaderMixedHistory(t *testing.T) {
	if wire.Major != 1 {
		t.Fatal("test targets the unchanged rc/1 reader")
	}
	object := func(raw string) *canon.Object {
		v, e := canon.Parse([]byte(raw))
		if e != nil {
			t.Fatal(e)
		}
		return v.(*canon.Object)
	}
	k := wire.Ed25519Key{Seed: bytes.Repeat([]byte{51}, 32)}
	other := wire.Ed25519Key{Seed: bytes.Repeat([]byte{52}, 32)}
	body := object(`{"about":{"content":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
	d := wire.Draft{Kind: "describes", TS: "2026-10-21T00:00:00Z", Body: body}
	first, fid := wire.Sign(d, k)
	unrelated, uid := wire.Sign(d, other)
	d.RC = "rc/2"
	d.Seq = 1
	d.Prev = fid
	d.Crit = []string{"x_identity_v1"}
	d.Body = object(`{"content":{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":0},"type":"dataset","x_identity_v1":{}}`)
	d.Kind = "authored"
	env := d.Envelope(k)
	env.Keys = append(env.Keys, "x_actor_v1")
	env.Members["x_actor_v1"] = object(`{"identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","grant":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`)
	ss := wire.PAE(wire.PayloadType("authored", 2), canon.Encode(env))
	mid := wire.ID(ss)
	env.Keys = append(env.Keys, "sig")
	env.Members["sig"] = canon.String(k.Sign(ss))
	middle := canon.Encode(env)
	// Raw key events remain rc/1, with no actor/crit, after rc/2 lines. Old readers
	// must see the unchanged key event; no v2-only event is relied upon for raw revocation.
	final, _ := wire.Sign(wire.Draft{Kind: "revoke_key", Seq: 2, Prev: mid, TS: d.TS, Body: object(`{"reason":"key_compromise"}`)}, k)
	store := keylog.NewStore()
	log := store.Log(k.Signer())
	if _, err := log.Add(first); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Log(other.Signer()).Add(unrelated); err != nil {
		t.Fatal(err)
	}
	st, err := log.Add(middle)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != wire.Unsupported || st.Verified || st.ID != mid || st.Body != nil {
		t.Fatalf("old-reader retention: %+v", st)
	}
	before := log.View()
	if len(before.Retained) != 1 || len(before.Lines) != 1 {
		t.Fatalf("unvouched rc/2 must be retained, not placed: %+v", before)
	}
	if _, err := log.Add(final); err != nil {
		t.Fatal(err)
	}
	after := log.View()
	if len(after.Retained) != 0 || len(after.Lines) != 3 {
		t.Fatalf("verified rc/1 descendant must vouch the v2 link: %+v", after)
	}
	for _, ln := range after.Lines {
		if ln.State != keylog.Chained {
			t.Fatal("mixed log detached")
		}
	}
	events := after.KeyState().Events
	if len(events) != 1 || !events[0].InForce || events[0].Kind != "revoke_key" {
		t.Fatalf("legacy key event lost: %+v", events)
	}
	ov := store.Log(other.Signer()).View()
	if len(ov.Lines) != 1 || ov.Lines[0].St.ID != uid {
		t.Fatal("other key history changed")
	}
	original, err := wire.Read(first)
	if err != nil || original.Status != wire.Valid || original.ID != fid {
		t.Fatal("rc/1 signed history changed")
	}
	// An old reader deliberately cannot authenticate even a bad rc/2 signature.
	// Retain-as-unsupported is not a successful candidate signature validation.
	env.Members["sig"] = canon.String("not-a-signature")
	bad, err := wire.Read(canon.Encode(env))
	if err != nil || bad.Verified || bad.Status != wire.Unsupported {
		t.Fatalf("unknown-major behavior: %+v %v", bad, err)
	}
}
