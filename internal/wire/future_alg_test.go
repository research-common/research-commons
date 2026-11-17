package wire

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
)

// futureSigner is a signer in a future algorithm's own key form: a scheme prefix this reader does not know and hex.
var futureSigner = "ml-dsa-65:" + strings.Repeat("ab", 40)

// futureAlgLine is a well-formed envelope of major rc signed under alg by signer: the sig is opaque to this reader.
func futureAlgLine(rc, alg, signer string) []byte {
	ed := testKeys("A")["A"]
	d := authoredDraft(0, "")
	d.RC = rc
	env := d.Envelope(ed)
	env.Members["alg"] = canon.String(alg)
	env.Members["signer"] = canon.String(signer)
	env.Keys = append(env.Keys, "sig")
	env.Members["sig"] = canon.String("00")
	return canon.Encode(env)
}

// TestFutureAlgorithmSigner: an alg this reader does not implement, with a signer in that algorithm's own key form
// (a scheme prefix and hex), reads unsupported with an id in both majors and under every reader (wire §4: unknown
// alg is retained, adding one is a minor change). An implemented alg with a signer outside its form stays
// malformed, and so does a signer that borrows a known scheme prefix in the wrong shape.
func TestFutureAlgorithmSigner(t *testing.T) {
	readers := map[string]func([]byte) (*Statement, error){
		"Read":           Read,
		"IdentityReader": NewIdentityReader().Read,
		"DualReader":     NewDualReader().Read,
	}
	for _, rc := range []string{"rc/1", "rc/2"} {
		for name, read := range readers {
			if name == "Read" && rc == "rc/2" {
				continue // Read reads rc/2 as another major, which already admits the other-key shape
			}
			st, err := read(futureAlgLine(rc, "ml-dsa-65", futureSigner))
			if err != nil || st.Status != Unsupported || st.Why != "alg ml-dsa-65" || st.Verified || st.ID == "" || st.Signer != futureSigner {
				t.Fatalf("%s %s future signer: %+v %v", name, rc, st, err)
			}
			for _, c := range []struct{ alg, signer, detail string }{
				{AlgEd25519, futureSigner, "neither"},
				{AlgEIP191, futureSigner, "neither"},
				{AlgEd25519, "0x" + strings.Repeat("ab", 20), "alg ed25519 with signer"},
				{"ml-dsa-65", "ed25519:" + strings.Repeat("ab", 20), "neither"},
				{"ml-dsa-65", "0x" + strings.Repeat("AB", 20), "neither"},
				{"ml-dsa-65", "ML-DSA-65:" + strings.Repeat("ab", 40), "neither"},
				{"ml-dsa-65", "ml-dsa-65:", "neither"},
			} {
				_, err := read(futureAlgLine(rc, c.alg, c.signer))
				refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, c.detail)
			}
		}
	}
}
