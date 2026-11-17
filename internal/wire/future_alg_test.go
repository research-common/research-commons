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

// TestFutureKeyInGrantAndSubjects: a grant whose delegate.key, or a typed subject {key: K}, is a key in a form this
// reader does not implement (a future algorithm's) reads unsupported, never invalid: a later reader may accept acts
// under it, so this one may not definitely deny them. A malformed key (a known scheme in the wrong shape, upper case,
// no hex) stays invalid, and the rest of the body is still checked: a future key does not excuse a broken grant.
func TestFutureKeyInGrantAndSubjects(t *testing.T) {
	fk := "ml-dsa-65:" + strings.Repeat("ab", 40)
	perm := arr(body("kind", "authored", "targets", body("any_content", canon.Bool(true)), "amend", canon.Bool(true)))
	grant := func(k string, perms canon.Array) *canon.Object {
		return body("identity", tID, "delegate", body("key", k, "inception", tID2), "permissions", perms)
	}
	for _, c := range []struct {
		name string
		b    *canon.Object
		want Status
		why  string
	}{
		{"future delegate", grant(fk, perm), Unsupported, "key form ml-dsa-65"},
		{"future delegate, broken permissions", grant(fk, arr()), Invalid, "body.permissions"},
		{"ed25519 prefix, wrong length", grant("ed25519:"+strings.Repeat("ab", 20), perm), Invalid, "not a key"},
		{"0x prefix, wrong length", grant("0x"+strings.Repeat("ab", 10), perm), Invalid, "not a key"},
		{"upper-case scheme", grant("ML-DSA-65:"+strings.Repeat("ab", 40), perm), Invalid, "not a key"},
		{"scheme without hex", grant("ml-dsa-65:", perm), Invalid, "not a key"},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := rc2Read(t, "identity_grant", c.b, body(), nil)
			if st.Status != c.want || !strings.Contains(st.Why, c.why) {
				t.Fatalf("read %s (%q), want %s containing %q", st.Status, st.Why, c.want, c.why)
			}
		})
	}
	idS := body("identity", tID)
	gen := func(ctrl canon.Array) *canon.Object {
		return body("type", "collection", "name", "n", "controllers", ctrl, "rule", body("any_one", canon.Bool(true)))
	}
	ed := func(contents *canon.Object) *canon.Object {
		return body("resource", tID, "predecessors", arr(s(tID)), "contents", contents)
	}
	roles := func(ben *canon.Object) *canon.Object {
		return body("task_roles", body("beneficiary", ben, "any_issuer", canon.Bool(true), "counting_unit", "identity"))
	}
	contract := body("profile", "task-contract-v1")
	for _, c := range []struct {
		name, kind string
		b, marker  *canon.Object
		want       Status
		why        string
	}{
		{"genesis future controller", "genesis", gen(arr(idS, body("key", fk))), body(), Unsupported, "key form ml-dsa-65"},
		{"edition future controller", "edition", ed(body("controllers", arr(body("key", fk)), "rule", body("any_one", canon.Bool(true)))), body(), Unsupported, "key form ml-dsa-65"},
		{"edition future beneficiary", "edition", ed(body("contract", contract)), roles(body("key", fk)), Unsupported, "key form ml-dsa-65"},
		{"genesis future controller, unsorted", "genesis", gen(arr(body("key", fk), idS)), body(), Invalid, "not sorted"},
		{"genesis malformed ed25519 controller", "genesis", gen(arr(body("key", "ed25519:"+strings.Repeat("ab", 8)))), body(), Invalid, "a key"},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := rc2Read(t, c.kind, c.b, c.marker, nil)
			if st.Status != c.want || !strings.Contains(st.Why, c.why) {
				t.Fatalf("read %s (%q), want %s containing %q", st.Status, st.Why, c.want, c.why)
			}
		})
	}
}
