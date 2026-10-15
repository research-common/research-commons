// Package sig implements the two required signature algorithms of wire-format note §4.
//
// Ed25519 verification is pinned: three pre-checks run in front of the stock verifier, so every reader
// refuses the same crafted signatures whatever its library would do alone (C-core-144). EIP-191 verification
// recovers the signer's address and accepts every valid encoding of a signature; Canonical returns the one
// encoding a reader stores (low s, v in {27, 28}).
package sig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"

	"filippo.io/edwards25519"
)

// Ed25519 pre-check failures name the step of the pinned rule (wire-format note §4) that refused.
const (
	StepScalar    = "step 1 (S >= L)"
	StepEncoding  = "step 2 (not a valid RFC 8032 point encoding)"
	StepSubgroup  = "step 3 (not in the prime-order subgroup)"
	StepEquation  = "step 4 (equation does not hold)"
	StepKeyLength = "malformed key or signature length"
)

// l is the group order L = 2^252 + 27742317777372353535851937790883648493, little-endian.
var l = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// p is the field prime 2^255 - 19, little-endian.
var p = [32]byte{
	0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
}

// lessLE reports a < b for two 32-byte little-endian integers.
func lessLE(a, b *[32]byte) bool {
	for i := 31; i >= 0; i-- {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// lMinus1 is L-1 as a canonical scalar; [L]P is computed as [L-1]P + P because L itself is not a canonical
// scalar.
var lMinus1 = func() *edwards25519.Scalar {
	b := l
	b[0]--
	s, err := edwards25519.NewScalar().SetCanonicalBytes(b[:])
	if err != nil {
		panic(err)
	}
	return s
}()

// checkPoint runs steps 2 and 3 on one 32-byte encoding.
func checkPoint(enc []byte) string {
	var y [32]byte
	copy(y[:], enc)
	y[31] &= 0x7f
	if !lessLE(&y, &p) {
		return StepEncoding
	}
	pt, err := new(edwards25519.Point).SetBytes(enc)
	if err != nil {
		return StepEncoding
	}
	// SetBytes accepts x = 0 with the sign bit set; RFC 8032 §5.1.3 does not. A canonical point re-encodes
	// to the bytes it came from.
	if !bytes.Equal(pt.Bytes(), enc) {
		return StepEncoding
	}
	id := edwards25519.NewIdentityPoint()
	if pt.Equal(id) == 1 {
		return StepSubgroup
	}
	q := new(edwards25519.Point).ScalarMult(lMinus1, pt)
	q.Add(q, pt)
	if q.Equal(id) != 1 {
		return StepSubgroup
	}
	return ""
}

// VerifyEd25519 applies the pinned rule to a 32-byte public key, a message and a 64-byte signature. It
// returns "" when the signature is valid, else the step that refused it.
func VerifyEd25519(pub, msg, signature []byte) string {
	if len(pub) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return StepKeyLength
	}
	var s [32]byte
	copy(s[:], signature[32:])
	if !lessLE(&s, &l) {
		return StepScalar
	}
	if f := checkPoint(pub); f != "" {
		return f
	}
	if f := checkPoint(signature[:32]); f != "" {
		return f
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, signature) {
		return StepEquation
	}
	return ""
}

// SignEd25519 signs msg with the key derived from a 32-byte seed (RFC 8032 §5.1.5). The seed is what a
// writer stores (§4.1).
func SignEd25519(seed, msg []byte) (pub, signature []byte) {
	k := ed25519.NewKeyFromSeed(seed)
	return bytes.Clone(k.Public().(ed25519.PublicKey)), ed25519.Sign(k, msg)
}

// constant-time compare kept for address comparisons.
func equalCT(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
