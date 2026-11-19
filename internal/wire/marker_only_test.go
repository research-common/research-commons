package wire

import (
	"bytes"
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
