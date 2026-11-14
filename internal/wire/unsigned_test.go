package wire

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

// TestCheckUnsigned: an unsigned rc/2 envelope reads exactly as the same envelope once signed (same signed string,
// id, status and reason), with nothing verified; a sig member, another major and a linkage error are refused.
func TestCheckUnsigned(t *testing.T) {
	for _, k := range []Key{Ed25519Key{Seed: bytes.Repeat([]byte{7}, 32)}, EIP191Key{Scalar: sha256Of("unsigned")}} {
		ok, _ := IdentityDraft(Draft{Kind: "identity_inception", TS: "2026-11-14T00:00:00Z",
			Body: &canon.Object{Keys: []string{"profile"}, Members: map[string]canon.Value{"profile": canon.String(FixedRootProfile)}}}, nil, nil)
		bad, _ := IdentityDraft(Draft{Kind: "identity_inception", TS: "2026-11-14T00:00:00Z",
			Body: &canon.Object{Keys: []string{"profile"}, Members: map[string]canon.Value{"profile": canon.String("other-profile")}}}, nil, nil)
		for _, d := range []Draft{ok, bad} {
			env := d.Envelope(k)
			u, err := CheckUnsigned(env)
			if err != nil {
				t.Fatal(err)
			}
			line, id := Sign(d, k)
			s, err := NewIdentityReader().Read(line)
			if err != nil {
				t.Fatal(err)
			}
			if u.Verified || u.Sig != "" || u.ID != id || s.ID != id || !bytes.Equal(u.SignedString, s.SignedString) || u.Status != s.Status || u.Why != s.Why {
				t.Fatalf("unsigned %v %q %s; signed %v %q %s", u.Verified, u.Status, u.ID, s.Verified, s.Status, s.ID)
			}
		}
		if u, _ := CheckUnsigned(bad.Envelope(k)); u.Status == Valid {
			t.Fatal("an unknown profile reads valid unsigned")
		}
		withSig := ok.Envelope(k)
		withSig.Keys = append(withSig.Keys, "sig")
		withSig.Members["sig"] = canon.String("00")
		v1 := Draft{Kind: "describes", TS: "2026-11-14T00:00:00Z", Body: &canon.Object{Members: map[string]canon.Value{}}}.Envelope(k)
		linkage := ok.Envelope(k)
		linkage.Members["seq"] = canon.Int(-1)
		for name, env := range map[string]*canon.Object{"sig member": withSig, "rc/1": v1, "bad seq": linkage} {
			if _, err := CheckUnsigned(env); err == nil {
				t.Fatalf("%s: not refused", name)
			}
		}
	}
}

func sha256Of(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}
