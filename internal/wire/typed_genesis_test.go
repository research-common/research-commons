package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
)

// The writer's typed-controller genesis (identity profile §2.1: a bare-key creator can sign a typed genesis whose
// controllers are {key} and/or {identity} subjects). Genesis only: a typed-controller edition is not a raw-key
// statement (§2.3) and is not written from a bare key.

const tgTS = "2026-11-17T00:00:00Z"

var tgNow = time.Date(2026, 11, 17, 0, 1, 0, 0, time.UTC)

func tgKey() Ed25519Key { return Ed25519Key{Seed: bytes.Repeat([]byte{61}, 32)} }

func tgRule(k int) *canon.Object {
	if k == 0 {
		return ivObj("any_one", true)
	}
	return ivObj("k_of_n", ivObj("k", k))
}

// tgSubjects is the typed controllers, sorted by their JCS text as the profile's sets are.
func tgSubjects(identity, key string) canon.Array {
	a := canon.Array{ivObj("identity", identity), ivObj("key", key)}
	if string(canon.Encode(a[0])) > string(canon.Encode(a[1])) {
		a[0], a[1] = a[1], a[0]
	}
	return a
}

func tgGenesis(ctrl canon.Value, rule *canon.Object) Draft {
	b := ivObj("type", "collection", "name", "c", "controllers", ctrl, "rule", rule)
	return Draft{Kind: "genesis", Seq: 0, TS: tgTS, Body: b}
}

// TestTypedGenesisSignsRC2: a bare key signs a genesis naming an identity and a key as controllers: rc/2, crit
// [x_identity_v1], body marker {}, no actor, and the identity reader reads it back Valid.
func TestTypedGenesisSignsRC2(t *testing.T) {
	k := tgKey()
	d := tgGenesis(tgSubjects(hex64('a'), k.Signer()), tgRule(2))
	if WriterMajor("genesis", false) != Major {
		t.Fatal("WriterMajor(genesis, false) must stay rc/1: the typed path is explicit")
	}
	td, err := TypedGenesisDraft(d)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Write(td, k, tgNow)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != Valid {
		t.Fatalf("typed genesis reads %s: %s", st.Status, st.Why)
	}
	line := string(st.Line())
	for _, want := range []string{`"rc":"rc/2"`, `"crit":["x_identity_v1"]`, `"x_identity_v1":{}`} {
		if !strings.Contains(line, want) {
			t.Errorf("line lacks %s: %s", want, line)
		}
	}
	if strings.Contains(line, ActorField) {
		t.Errorf("a genesis is a raw-key statement and carries no actor: %s", line)
	}
	if st.Actor != nil {
		t.Errorf("statement has an actor: %+v", st.Actor)
	}
	// the input draft is not mutated: TypedGenesisDraft works on a copy of the body
	if _, ok := d.Body.Get(IdentityCrit); ok || d.RC != "" {
		t.Error("TypedGenesisDraft changed its input draft")
	}
	// an identity-only controller list is just as valid
	only, err := TypedGenesisDraft(tgGenesis(canon.Array{ivObj("identity", hex64('a'))}, tgRule(0)))
	if err != nil {
		t.Fatal(err)
	}
	if st, err := Write(only, k, tgNow); err != nil || st.Status != Valid {
		t.Fatalf("identity-only controllers: %v %v", st, err)
	}
}

// TestKeyOnlyGenesisBytes: a genesis of plain key controllers is rc/1 byte for byte as before: no marker, no crit,
// no rc/2. The line is pinned (Ed25519 is deterministic), captured from the writer before the typed path existed
// (origin/next at f1e9637), so any change to the plain path moves these bytes.
func TestKeyOnlyGenesisBytes(t *testing.T) {
	k := tgKey()
	d := tgGenesis(canon.Array{canon.String(k.Signer())}, tgRule(0))
	line, id := Sign(d, k)
	got := string(line)
	if !strings.Contains(got, `"rc":"rc/1"`) || strings.Contains(got, "crit") || strings.Contains(got, IdentityCrit) {
		t.Fatalf("key-only genesis is not plain rc/1: %s", got)
	}
	st, err := Write(d, k, tgNow)
	if err != nil || st.Status != Valid || st.ID != id || !bytes.Equal(st.Line(), line) {
		t.Fatalf("Write of a key-only genesis: %v %v", st, err)
	}
	if got != tgKeyOnlyLine || id != tgKeyOnlyID {
		t.Fatalf("key-only genesis bytes moved\n got %s\n id %s", got, id)
	}
}

// TestTypedGenesisBytes pins the rc/2 typed-controller genesis the way TestKeyOnlyGenesisBytes pins rc/1: the same
// seed key, a genesis naming {identity, key} controllers under k_of_n 2, signed through TypedGenesisDraft. Ed25519
// is deterministic, so the line and the id are frozen; the signed string is rebuilt here by the DSSE formula (not by
// PAE or PayloadType) to show the signature covers the rc/2 payload type and that the id is sha256 of that string.
func TestTypedGenesisBytes(t *testing.T) {
	k := tgKey()
	td, err := TypedGenesisDraft(tgGenesis(tgSubjects(hex64('a'), k.Signer()), tgRule(2)))
	if err != nil {
		t.Fatal(err)
	}
	line, id := Sign(td, k)
	got := string(line)
	if !strings.Contains(got, `"rc":"rc/2"`) || !strings.Contains(got, `"crit":["x_identity_v1"]`) {
		t.Fatalf("typed genesis is not rc/2 with the identity crit: %s", got)
	}
	st, err := Write(td, k, tgNow)
	if err != nil || st.Status != Valid || st.ID != id || !bytes.Equal(st.Line(), line) {
		t.Fatalf("Write of a typed genesis: %v %v", st, err)
	}
	if got != tgTypedLine || id != tgTypedID {
		t.Fatalf("typed genesis bytes moved\n got %s\n id %s", got, id)
	}
	// The signed string, by the note's formula: the payload type names major 2, the payload is the JCS envelope
	// without sig.
	const ptype = "application/vnd.research-commons.genesis.v2+json"
	env := strings.Replace(tgTypedLine, `"sig":"`+st.Sig+`",`, "", 1)
	if env == tgTypedLine {
		t.Fatal("could not strip sig from the pinned line")
	}
	ss := "DSSEv1 " + strconv.Itoa(len(ptype)) + " " + ptype + " " + strconv.Itoa(len(env)) + " " + env
	if string(PAE(PayloadType("genesis", 2), []byte(env))) != ss {
		t.Error("PAE(PayloadType(genesis, 2), env) differs from the DSSE formula")
	}
	if ID([]byte(ss)) != tgTypedID {
		t.Errorf("id is not sha256 of the rc/2 signed string")
	}
	pub, _ := hex.DecodeString(strings.TrimPrefix(k.Signer(), "ed25519:"))
	sig, _ := hex.DecodeString(st.Sig)
	if !ed25519.Verify(pub, []byte(ss), sig) {
		t.Error("the pinned signature does not verify over the rc/2 signed string")
	}
	// the same draft signed under the rc/1 payload type would be a different statement: the type is in the PAE
	if ID(PAE(PayloadType("genesis", 1), []byte(env))) == tgTypedID {
		t.Error("the rc/1 and rc/2 payload types hash to the same id")
	}
}

// TestTypedGenesisRefusals: the identity reader's rules still refuse what no reader would read; Write returns the
// invalid statement (the CLI refuses it, nothing signed), and the draft constructor refuses every other kind.
func TestTypedGenesisRefusals(t *testing.T) {
	k := tgKey()
	// (c) satisfiable: k_of_n k=3 over two controllers
	td, err := TypedGenesisDraft(tgGenesis(tgSubjects(hex64('a'), k.Signer()), tgRule(3)))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Write(td, k, tgNow)
	if err == nil && st.Status == Valid {
		t.Fatalf("an unsatisfiable typed genesis read Valid")
	}
	if err == nil && !strings.Contains(st.Why, "no set of controllers satisfies it") {
		t.Errorf("why: %s", st.Why)
	}
	// unsorted typed subjects, a subject with two members, a malformed identity id
	for name, ctrl := range map[string]canon.Value{
		"unsorted":  canon.Array{ivObj("key", k.Signer()), ivObj("identity", hex64('a'))},
		"two":       canon.Array{ivObj("identity", hex64('a'), "key", k.Signer())},
		"bad id":    canon.Array{ivObj("identity", "nope")},
		"mixed raw": canon.Array{ivObj("identity", hex64('a')), canon.String(k.Signer())},
	} {
		td, err := TypedGenesisDraft(tgGenesis(ctrl, tgRule(0)))
		if err != nil {
			t.Fatal(name, err)
		}
		if st, err := Write(td, k, tgNow); err == nil && st.Status == Valid {
			t.Errorf("%s: read Valid", name)
		}
	}
	// (d) only a genesis; an edition (typed controllers or not) is never written in rc/2 from a bare key
	ed := Draft{Kind: "edition", TS: tgTS, Body: ivObj("resource", hex64('c'), "predecessors", canon.Array{canon.String(hex64('c'))},
		"contents", ivObj("controllers", canon.Array{ivObj("identity", hex64('a'))}, "rule", tgRule(0)))}
	for _, kind := range []string{"edition", "authored", "describes", "identity_grant", "rotate_key"} {
		d := ed
		d.Kind = kind
		if _, err := TypedGenesisDraft(d); err == nil {
			t.Errorf("TypedGenesisDraft accepted %s", kind)
		}
	}
	if _, err := IdentityDraft(ed, nil, nil); err == nil {
		t.Error("IdentityDraft(edition, nil actor) built an rc/2 draft")
	}
	if WriterMajor("edition", false) != Major || WriterMajor("genesis", false) != Major {
		t.Error("a bare-key edition or genesis is rc/1 in WriterMajor")
	}
	// even signed rc/1 by hand, a typed edition from a bare key is refused by the rc/1 reader
	if st, err := Write(ed, k, tgNow); err == nil && st.Status == Valid {
		t.Error("a typed-controller edition signed rc/1 from a bare key read Valid")
	}
	// a body that already carries the marker is refused
	withMarker := tgGenesis(canon.Array{ivObj("identity", hex64('a'))}, tgRule(0))
	withMarker.Body = withMember(withMarker.Body, IdentityCrit, ivObj())
	if _, err := TypedGenesisDraft(withMarker); err == nil {
		t.Error("TypedGenesisDraft accepted a body already carrying the marker")
	}
}

const (
	tgTypedLine   = `{"alg":"ed25519","body":{"controllers":[{"identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"key":"ed25519:70df9e2279adbec6d12bf2921184c9222eb24ed852005bf640139f52e59cd9ae"}],"name":"c","rule":{"k_of_n":{"k":2}},"type":"collection","x_identity_v1":{}},"crit":["x_identity_v1"],"kind":"genesis","prev":null,"rc":"rc/2","seq":0,"sig":"2152d604b6a239557896e66b281d0d0dde5c24f5720944fad9f0e0d0579363c37be7e8cdf4ec33956ce18a30db6df3b57b82a5063ce348bb89ab913aac93f602","signer":"ed25519:70df9e2279adbec6d12bf2921184c9222eb24ed852005bf640139f52e59cd9ae","ts":"2026-11-17T00:00:00Z"}`
	tgTypedID     = "2ab3d96e70bcb4ce82cde6a70dd902bcda760782ee3bdbee0ca53a9ad28f7664"
	tgKeyOnlyLine = `{"alg":"ed25519","body":{"controllers":["ed25519:70df9e2279adbec6d12bf2921184c9222eb24ed852005bf640139f52e59cd9ae"],"name":"c","rule":{"any_one":true},"type":"collection"},"kind":"genesis","prev":null,"rc":"rc/1","seq":0,"sig":"63d862ffacc914486d2d589e29753cf411118935ff75546705cafd5cbca047cd91aa75adeff34dcd2e0990e8ecf68cbc563d48c3bbf839e881e796a9412e730f","signer":"ed25519:70df9e2279adbec6d12bf2921184c9222eb24ed852005bf640139f52e59cd9ae","ts":"2026-11-17T00:00:00Z"}`
	tgKeyOnlyID   = "c58bfa899fcef977bd4f9258809a23b62844c7e0691277ec1f41e8a281659fe7"
)

func withMember(o *canon.Object, k string, v canon.Value) *canon.Object {
	out := &canon.Object{Members: map[string]canon.Value{}}
	for _, x := range o.Keys {
		out.Keys = append(out.Keys, x)
		out.Members[x] = o.Members[x]
	}
	out.Keys = append(out.Keys, k)
	out.Members[k] = v
	return out
}
