package sig_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/sig"
)

// TestSignedIdentityVectorsTwoImplementations: C-core-144 (b) on the signed rc/2 identity vectors
// (docs/fixed-root-identity.signed-vectors.json). Every Ed25519 signature of the file, positive or negative, is
// checked by internal/sig (filippo.io/edwards25519) and by the standard-library implementation of
// ed25519_crosscheck_test.go (math/big for pre-checks 1–3, crypto/ed25519 for step 4) over the exact string the
// reader verifies: the verdicts and the refusing steps are identical and equal the file's. Every positive is also
// re-signed from the published seed with the standard library's own signer (RFC 8032 is deterministic) and must
// reproduce the file's signature byte for byte, so the file is not only self-consistent under one library.
//
// The comparison lives here because the second implementation is private to this test package; the wire package's
// test runs the same file through the production reader (TestSignedIdentityPositiveVectors and
// TestSignedIdentityNegativeVectors) and checks the same signatures with internal/sig. EIP-191 has one
// implementation in this module (secp256k1 recovery), so those vectors are checked there only.
func TestSignedIdentityVectorsTwoImplementations(t *testing.T) {
	conformance.Partial(t, "C-core-144", "(b) and (c) as signed rc/2 identity lines under two Ed25519 libraries: checked here; the rc/1 cases are in the wire-format vectors' test, (a) in keylog; EIP-191 has one implementation")
	v, err := conformance.LoadSignedIdentityVectors()
	if err != nil {
		t.Fatal(err)
	}
	seeds := map[string][]byte{}
	for _, k := range v.Keys {
		if k.Alg == "ed25519" {
			seeds[k.Signer] = unhex(t, k.Secret)
		}
	}
	if len(seeds) != 2 {
		t.Fatalf("%d Ed25519 keys in the file, want 2", len(seeds))
	}
	type c struct {
		name, signer, msg, sg string
		fileStep              string // "" = must verify
	}
	var cases []c
	for _, x := range v.Positive {
		if x.Alg == "ed25519" {
			cases = append(cases, c{x.Name, x.Signer, x.SignedString, x.Sig, ""})
		}
	}
	nPos := len(cases)
	for _, x := range v.Negative {
		if x.Alg != "ed25519" {
			continue
		}
		step := ""
		if !x.SigVerifies {
			step = x.Ed25519Step
			if step == "" {
				t.Fatalf("%s: a non-verifying Ed25519 signature without a step", x.Name)
			}
		}
		cases = append(cases, c{x.Name, x.Signer, x.VerifiedString, x.Sig, step})
	}
	if nPos != 8 || len(cases) != 8+12 {
		t.Fatalf("%d positives / %d cases of Ed25519, want 8 / 20", nPos, len(cases))
	}
	accepted, stockOnly := 0, 0
	for i, x := range cases {
		pub := unhex(t, strings.TrimPrefix(x.signer, "ed25519:"))
		msg, sg := []byte(x.msg), unhex(t, x.sg)
		got := stepNumber(sig.VerifyEd25519(pub, msg, sg))
		if ref := refVerify(pub, msg, sg, true); got != ref {
			t.Errorf("%s: internal/sig says step %q, the independent implementation says %q", x.name, got, ref)
			continue
		}
		if phased := refVerify(pub, msg, sg, false); (phased == "") != (got == "") {
			t.Errorf("%s: phased ordering changed the verdict: %q vs %q", x.name, phased, got)
		}
		if got != x.fileStep {
			t.Errorf("%s: both implementations say step %q, the file says %q", x.name, got, x.fileStep)
		}
		if got == "" {
			accepted++
		} else if ed25519.Verify(pub, msg, sg) {
			stockOnly++ // accepted by the stock verifier alone: the pinned pre-checks are what refuse it
		}
		if i < nPos {
			seed := seeds[x.signer]
			if seed == nil {
				t.Fatalf("%s: no published seed for %s", x.name, x.signer)
			}
			priv := ed25519.NewKeyFromSeed(seed)
			if hex.EncodeToString(priv.Public().(ed25519.PublicKey)) != strings.TrimPrefix(x.signer, "ed25519:") {
				t.Errorf("%s: the standard library derives another public key from the published seed", x.name)
			}
			if re := hex.EncodeToString(ed25519.Sign(priv, msg)); re != x.sg {
				t.Errorf("%s: the standard library re-signs to %s, the file says %s", x.name, re, x.sg)
			}
		}
	}
	// the positives, plus the three negatives whose signature is genuine and whose line the reader retains
	// (rc/1 with an actor, rc/1 naming the identity crit, rc/2 revoke_key)
	if accepted != nPos+3 {
		t.Fatalf("%d cases verified, want %d (the positives and 3 genuinely signed negatives); the harness may not reach the pre-checks", accepted, nPos+3)
	}
	// negatives built from valid signatures fail only at step 4 (the signed bytes changed); the three wire-set edge
	// cases fail before it; the identity point is accepted by the stock verifier over this message too
	if stockOnly < 1 {
		t.Fatal("no negative is one the standard library alone would accept; the pre-check negative does not reach step 3")
	}
	t.Logf("%d Ed25519 cases (%d positive, %d negative), identical verdicts in both implementations; %d negative(s) accepted by the stock verifier alone", len(cases), nPos, len(cases)-nPos, stockOnly)
}
