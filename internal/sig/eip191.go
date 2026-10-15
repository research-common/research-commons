package sig

import (
	"strconv"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// EIP191Hash is keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg).
func EIP191Hash(msg []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(msg))))
	h.Write(msg)
	return h.Sum(nil)
}

// Address is the 20-byte Ethereum address of a public key.
func Address(pub *secp256k1.PublicKey) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(pub.SerializeUncompressed()[1:])
	return h.Sum(nil)[12:]
}

// Canonical returns the stored encoding of a 65-byte r‖s‖v signature: low s and v in {27, 28}. It accepts v
// as 0/1 or 27/28 and s in either form. ok is false when the bytes are not a signature encoding at all
// (wrong length, v out of range, r or s zero or not below n).
func Canonical(sig65 []byte) (canon []byte, ok bool) {
	if len(sig65) != 65 {
		return nil, false
	}
	v := sig65[64]
	switch v {
	case 0, 1:
		v += 27
	case 27, 28:
	default:
		return nil, false
	}
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(sig65[:32]) || r.IsZero() || s.SetByteSlice(sig65[32:64]) || s.IsZero() {
		return nil, false
	}
	if s.IsOverHalfOrder() {
		s.Negate()
		v = 55 - v // 27 <-> 28: negating s flips the parity of the recovered R
	}
	out := make([]byte, 65)
	r.PutBytesUnchecked(out[:32])
	s.PutBytesUnchecked(out[32:64])
	out[64] = v
	return out, true
}

// RecoverEIP191 returns the address that signed msg under EIP-191 personal_sign, after canonicalising the
// encoding. err is non-nil when no key can be recovered.
func RecoverEIP191(msg, sig65 []byte) (addr []byte, canon []byte, err error) {
	c, ok := Canonical(sig65)
	if !ok {
		return nil, nil, errBadEncoding
	}
	compact := make([]byte, 65)
	compact[0] = c[64] // decred wants [27+recid] r s for an uncompressed key
	copy(compact[1:], c[:64])
	pub, _, err := ecdsa.RecoverCompact(compact, EIP191Hash(msg))
	if err != nil {
		return nil, nil, err
	}
	return Address(pub), c, nil
}

// VerifyEIP191 reports whether sig65 is a valid EIP-191 signature of msg by the 20-byte address want, and
// returns the canonical encoding to store.
func VerifyEIP191(msg, sig65, want []byte) (canon []byte, ok bool) {
	addr, c, err := RecoverEIP191(msg, sig65)
	if err != nil || !equalCT(addr, want) {
		return nil, false
	}
	return c, true
}

// SignEIP191 signs msg with a 32-byte secp256k1 scalar and returns the canonical encoding. For tests and
// the writer; RFC 6979 nonces, so the output is deterministic.
func SignEIP191(key, msg []byte) []byte {
	priv := secp256k1.PrivKeyFromBytes(key)
	compact := ecdsa.SignCompact(priv, EIP191Hash(msg), false)
	out := make([]byte, 65)
	copy(out, compact[1:])
	out[64] = compact[0]
	return out
}

type sigError string

func (e sigError) Error() string { return string(e) }

const errBadEncoding = sigError("not a signature encoding")

// AddressOf is the address of a 32-byte secp256k1 scalar.
func AddressOf(key []byte) []byte {
	return Address(secp256k1.PrivKeyFromBytes(key).PubKey())
}

// Equivalents returns the other valid encodings of a canonical r‖s‖v signature: v as 0/1, high s, and both.
// A reader must treat every one as the same statement (§4, C-core-10, P-02).
func Equivalents(canon65 []byte) [][]byte {
	if len(canon65) != 65 {
		return nil
	}
	v01 := append([]byte{}, canon65...)
	v01[64] -= 27
	var s secp256k1.ModNScalar
	s.SetByteSlice(canon65[32:64])
	s.Negate()
	high := append([]byte{}, canon65...)
	s.PutBytesUnchecked(high[32:64])
	high[64] = 55 - high[64]
	highV01 := append([]byte{}, high...)
	highV01[64] -= 27
	return [][]byte{v01, high, highV01}
}
