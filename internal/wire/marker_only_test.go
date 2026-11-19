package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

// TestMarkerOnlyDraft: a bare key's edition or withdraw_approval of a resource whose genesis is rc/2 (identity
// profile §2.3: an rc/2 line with the marker and no actor is key(K)'s). The draft is rc/2, crit [x_identity_v1], the
// body marker {}, no actor, and reads back Valid; it signs the same body bytes as an identity's approval of the same
// draft (IdentityDraft), so both approve one edition (§2.2). Only those two kinds are accepted, the input draft is
// not changed, and a body already carrying the marker is refused.
func TestMarkerOnlyDraft(t *testing.T) {
	k := tgKey()
	ed := Draft{Kind: "edition", TS: tgTS, Body: ivObj("resource", hex64('c'), "predecessors", canon.Array{canon.String(hex64('c'))},
		"contents", ivObj("members", canon.Array{}, "selection", "curated"))}
	wd := Draft{Kind: "withdraw_approval", TS: tgTS, Body: ivObj("resource", hex64('c'), "edition", hex64('d'))}
	for _, d := range []Draft{ed, wd} {
		md, err := MarkerOnlyDraft(d)
		if err != nil {
			t.Fatalf("%s: %v", d.Kind, err)
		}
		if md.RC != "rc/2" || len(md.Crit) != 1 || md.Crit[0] != IdentityCrit || md.Actor != nil {
			t.Fatalf("%s: not marker-only rc/2: %+v", d.Kind, md)
		}
		if m, ok := md.Body.Get(IdentityCrit); !ok || len(m.(*canon.Object).Keys) != 0 {
			t.Fatalf("%s: marker is not {}", d.Kind)
		}
		if _, ok := d.Body.Get(IdentityCrit); ok || d.RC != "" {
			t.Fatalf("%s: MarkerOnlyDraft changed its input draft", d.Kind)
		}
		st, err := Write(md, k, tgNow)
		if err != nil || st.Status != Valid || st.Actor != nil {
			t.Fatalf("%s: Write: %v %v", d.Kind, st, err)
		}
		// the identity's approval of the same draft signs the same body bytes
		id, err := IdentityDraft(d, &Actor{Identity: hex64('a'), Grant: hex64('b')}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(canon.Encode(id.Body), canon.Encode(md.Body)) || id.RC != md.RC {
			t.Fatalf("%s: marker-only and identity bodies differ\n %s\n %s", d.Kind, canon.Encode(md.Body), canon.Encode(id.Body))
		}
		// a body that already carries the marker is refused
		if _, err := MarkerOnlyDraft(md); err == nil {
			t.Fatalf("%s: a body carrying the marker was accepted", d.Kind)
		}
	}
	for _, kind := range []string{"genesis", "authored", "describes", "identity_grant", "rotate_key", "revoke_key"} {
		if _, err := MarkerOnlyDraft(Draft{Kind: kind, TS: tgTS, Body: ivObj("x", "y")}); err == nil {
			t.Errorf("MarkerOnlyDraft accepted %s", kind)
		}
	}
	if WriterMajor("edition", false) != Major || WriterMajor("withdraw_approval", false) != Major {
		t.Error("WriterMajor of a bare edition or withdraw_approval moved: the rc/2 path is explicit")
	}
}

// tgEditionDraft is an edition of the typed genesis pinned by TestTypedGenesisBytes: the draft both a bare key
// (MarkerOnlyDraft) and an identity (IdentityDraft) approve.
func tgEditionDraft() Draft {
	return Draft{Kind: "edition", Seq: 1, Prev: tgTypedID, TS: tgTS, Body: ivObj("resource", tgTypedID,
		"predecessors", canon.Array{canon.String(tgTypedID)},
		"contents", ivObj("members", canon.Array{}, "selection", "curated"))}
}

// TestMarkerOnlyBytes pins a bare key's approval of an edition of the typed genesis pinned by TestTypedGenesisBytes,
// written through MarkerOnlyDraft (the way TestTypedGenesisBytes pins the genesis): rc/2, crit [x_identity_v1], the
// body marker {}, no actor. Ed25519 is deterministic, so the line and the id are frozen. The signed string is
// rebuilt by the DSSE formula to show the signature covers the edition rc/2 payload type.
func TestMarkerOnlyBytes(t *testing.T) {
	k := tgKey()
	md, err := MarkerOnlyDraft(tgEditionDraft())
	if err != nil {
		t.Fatal(err)
	}
	line, id := Sign(md, k)
	got := string(line)
	if got != tgMarkerOnlyLine || id != tgMarkerOnlyID {
		t.Fatalf("marker-only edition bytes moved\n got %s\n id %s", got, id)
	}
	st, err := Write(md, k, tgNow)
	if err != nil || st.Status != Valid || st.ID != id || !bytes.Equal(st.Line(), line) || st.Actor != nil {
		t.Fatalf("Write of a marker-only edition: %v %v", st, err)
	}
	if !strings.Contains(got, `"rc":"rc/2"`) || !strings.Contains(got, `"crit":["x_identity_v1"]`) ||
		!strings.Contains(got, `"x_identity_v1":{}}`) || strings.Contains(got, "x_actor_v1") {
		t.Fatalf("not marker-only rc/2: %s", got)
	}
	const ptype = "application/vnd.research-commons.edition.v2+json"
	env := strings.Replace(tgMarkerOnlyLine, `"sig":"`+st.Sig+`",`, "", 1)
	if env == tgMarkerOnlyLine {
		t.Fatal("could not strip sig from the pinned line")
	}
	ss := "DSSEv1 " + strconv.Itoa(len(ptype)) + " " + ptype + " " + strconv.Itoa(len(env)) + " " + env
	if string(PAE(PayloadType("edition", 2), []byte(env))) != ss {
		t.Error("PAE(PayloadType(edition, 2), env) differs from the DSSE formula")
	}
	if ID([]byte(ss)) != tgMarkerOnlyID {
		t.Error("id is not sha256 of the rc/2 signed string")
	}
	pub, _ := hex.DecodeString(strings.TrimPrefix(k.Signer(), "ed25519:"))
	sig, _ := hex.DecodeString(st.Sig)
	if !ed25519.Verify(pub, []byte(ss), sig) {
		t.Error("the pinned signature does not verify over the rc/2 signed string")
	}
	if ID(PAE(PayloadType("edition", 1), []byte(env))) == tgMarkerOnlyID {
		t.Error("the rc/1 and rc/2 payload types hash to the same id")
	}
}

const (
	tgMarkerOnlyLine = `{"alg":"ed25519","body":{"contents":{"members":[],"selection":"curated"},"predecessors":["2ab3d96e70bcb4ce82cde6a70dd902bcda760782ee3bdbee0ca53a9ad28f7664"],"resource":"2ab3d96e70bcb4ce82cde6a70dd902bcda760782ee3bdbee0ca53a9ad28f7664","x_identity_v1":{}},"crit":["x_identity_v1"],"kind":"edition","prev":"2ab3d96e70bcb4ce82cde6a70dd902bcda760782ee3bdbee0ca53a9ad28f7664","rc":"rc/2","seq":1,"sig":"a9ca77e29d451587865024a5fbc16c70b3497c846ad61b45c54a9ea5156b40a6abc68f2ae278808ea5288083761e503508c3123653833d67a3af8e77cc510802","signer":"ed25519:70df9e2279adbec6d12bf2921184c9222eb24ed852005bf640139f52e59cd9ae","ts":"2026-11-17T00:00:00Z"}`
	tgMarkerOnlyID   = "b8c6f4b9bfc57436b8ad4a40bf4fd5423db3fbadf5f25eacfd340b6bb9a73dce"
)
