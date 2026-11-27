package hdkey

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/research-common/research-commons/internal/ledger"
	"github.com/research-common/research-commons/internal/sig"
)

// ErrInvalidKey is returned when the spec's "invalid key" case happens: the left half of the HMAC output is
// not below the curve order, or the resulting private key is zero. BIP-32 says to continue with the next
// index. This package returns an error instead: the caller asked for one specific path, a silent move to a
// different index would hand back a key at a path the caller did not name (and which other software that
// errors would not reproduce), and the case has probability below 2^-127, so no real phrase reaches it.
var ErrInvalidKey = errors.New("hdkey: derivation produced an invalid key (probability below 2^-127); choose another path")

// ErrSeedLength is returned for a seed outside 16 to 64 bytes (BIP-32 allows 128 to 512 bits).
var ErrSeedLength = errors.New("hdkey: a seed is 16 to 64 bytes")

const hardenedBit = 0x80000000

// Key is a BIP-32 extended private key: a 32-byte secp256k1 scalar and a 32-byte chain code. Its String
// method never shows the bytes.
type Key struct {
	key   [32]byte
	chain [32]byte
}

// String is fixed text; it does not format the secret.
func (*Key) String() string { return "hdkey.Key(redacted)" }

// GoString is the same, so %#v does not print the fields either.
func (*Key) GoString() string { return "hdkey.Key(redacted)" }

// Zero overwrites the key and chain code.
func (k *Key) Zero() {
	Zero(k.key[:])
	Zero(k.chain[:])
}

// Private returns a copy of the 32-byte private key. The caller should Zero the copy.
func (k *Key) Private() []byte { return append([]byte(nil), k.key[:]...) }

// ChainCode returns a copy of the 32-byte chain code.
func (k *Key) ChainCode() []byte { return append([]byte(nil), k.chain[:]...) }

func fromI(i []byte, add *secp256k1.ModNScalar) (*Key, error) {
	var il secp256k1.ModNScalar
	if overflow := il.SetByteSlice(i[:32]); overflow {
		return nil, ErrInvalidKey
	}
	if add != nil {
		il.Add(add)
	}
	if il.IsZero() {
		return nil, ErrInvalidKey
	}
	k := &Key{}
	il.PutBytesUnchecked(k.key[:])
	copy(k.chain[:], i[32:])
	il.Zero()
	return k, nil
}

// Master derives the master key from a seed: HMAC-SHA512 with key "Bitcoin seed".
func Master(seed []byte) (*Key, error) {
	if len(seed) < 16 || len(seed) > 64 {
		return nil, ErrSeedLength
	}
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	h.Write(seed)
	i := h.Sum(nil)
	defer Zero(i)
	return fromI(i, nil)
}

// Child derives the private child at index (hardened when index >= 2^31).
func (k *Key) Child(index uint32) (*Key, error) {
	h := hmac.New(sha512.New, k.chain[:])
	if index >= hardenedBit {
		h.Write([]byte{0})
		h.Write(k.key[:])
	} else {
		var s secp256k1.ModNScalar
		s.SetBytes(&k.key)
		pub := secp256k1.NewPrivateKey(&s).PubKey().SerializeCompressed()
		s.Zero()
		h.Write(pub)
	}
	h.Write([]byte{byte(index >> 24), byte(index >> 16), byte(index >> 8), byte(index)})
	i := h.Sum(nil)
	defer Zero(i)
	var par secp256k1.ModNScalar
	par.SetBytes(&k.key)
	defer par.Zero()
	return fromI(i, &par)
}

// Derive walks a path from k. It reuses the Ledger path type and parser (ledger.ParsePath), so a path means
// the same thing for a device and for a phrase. Intermediate keys are zeroed.
func (k *Key) Derive(p ledger.Path) (*Key, error) {
	cur := k
	for n, idx := range p {
		next, err := cur.Child(idx)
		if cur != k {
			cur.Zero()
		}
		if err != nil {
			return nil, err
		}
		cur = next
		_ = n
	}
	if cur == k {
		c := *k
		return &c, nil
	}
	return cur, nil
}

// PublicKey returns the 33-byte compressed public key.
func (k *Key) PublicKey() []byte {
	var s secp256k1.ModNScalar
	s.SetBytes(&k.key)
	defer s.Zero()
	return secp256k1.NewPrivateKey(&s).PubKey().SerializeCompressed()
}

// Address returns the 20-byte Ethereum address of the key (the module's existing sig.Address).
func (k *Key) Address() []byte {
	var s secp256k1.ModNScalar
	s.SetBytes(&k.key)
	defer s.Zero()
	return sig.Address(secp256k1.NewPrivateKey(&s).PubKey())
}

// DeriveFromMnemonic is the whole chain: phrase and passphrase to seed, seed to master, master to the key at
// path. Seed and intermediate keys are zeroed before it returns.
func DeriveFromMnemonic(mnemonic, passphrase string, path ledger.Path) (*Key, error) {
	seed, err := Seed(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}
	defer Zero(seed)
	m, err := Master(seed)
	if err != nil {
		return nil, err
	}
	defer m.Zero()
	return m.Derive(path)
}
