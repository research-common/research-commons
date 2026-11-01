package btctime

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
)

// HeaderSize is the length of a serialized Bitcoin block header.
const HeaderSize = 80

// Hash is a double-SHA-256 in internal byte order (as serialized). Its display form is the reverse, in hex.
type Hash [32]byte

// String is the display order (big-endian hex), as block explorers and Bitcoin Core's RPC print it.
func (h Hash) String() string {
	var r [32]byte
	for i := range h {
		r[31-i] = h[i]
	}
	return hex.EncodeToString(r[:])
}

// ParseDisplayHash reads a hash written in display order. The conversion is explicit and tested (note §5).
func ParseDisplayHash(s string) (Hash, error) {
	var h Hash
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return h, fmt.Errorf("not a 64-hex display hash: %q", s)
	}
	for i := range b {
		h[31-i] = b[i]
	}
	return h, nil
}

func dsha256(b []byte) Hash {
	a := sha256.Sum256(b)
	return Hash(sha256.Sum256(a[:]))
}

// Header is a parsed 80-byte header. Every field comes from the raw bytes, never from a backend's strings (§5).
type Header struct {
	Raw        [HeaderSize]byte
	Version    int32
	Prev       Hash
	MerkleRoot Hash // internal order: what an OTS proof's calculated digest must equal
	Time       uint32
	Bits       uint32
	Nonce      uint32
	Hash       Hash
}

// ParseHeader parses exactly 80 bytes.
func ParseHeader(b []byte) (Header, error) {
	var h Header
	if len(b) != HeaderSize {
		return h, fmt.Errorf("header is %d bytes, not %d", len(b), HeaderSize)
	}
	copy(h.Raw[:], b)
	h.Version = int32(binary.LittleEndian.Uint32(b[0:4]))
	copy(h.Prev[:], b[4:36])
	copy(h.MerkleRoot[:], b[36:68])
	h.Time = binary.LittleEndian.Uint32(b[68:72])
	h.Bits = binary.LittleEndian.Uint32(b[72:76])
	h.Nonce = binary.LittleEndian.Uint32(b[76:80])
	h.Hash = dsha256(b)
	return h, nil
}

// Serialize writes the header's fields in wire order.
func (h Header) Serialize() [HeaderSize]byte {
	var b [HeaderSize]byte
	binary.LittleEndian.PutUint32(b[0:4], uint32(h.Version))
	copy(b[4:36], h.Prev[:])
	copy(b[36:68], h.MerkleRoot[:])
	binary.LittleEndian.PutUint32(b[68:72], h.Time)
	binary.LittleEndian.PutUint32(b[72:76], h.Bits)
	binary.LittleEndian.PutUint32(b[76:80], h.Nonce)
	return b
}

// CompactToTarget decodes nBits as Bitcoin Core's arith_uint256::SetCompact does, reporting the sign bit and
// overflow as Core does. A target is usable only when it is positive, non-zero and not overflowing.
func CompactToTarget(bits uint32) (target *big.Int, negative, overflow bool) {
	size := bits >> 24
	word := bits & 0x007fffff
	t := new(big.Int)
	if size <= 3 {
		t.SetUint64(uint64(word >> (8 * (3 - size))))
	} else {
		t.SetUint64(uint64(word))
		t.Lsh(t, uint(8*(size-3)))
	}
	negative = word != 0 && bits&0x00800000 != 0
	overflow = word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32))
	return t, negative, overflow
}

// TargetToCompact encodes a target as Core's arith_uint256::GetCompact (non-negative).
func TargetToCompact(t *big.Int) uint32 {
	size := uint32((t.BitLen() + 7) / 8)
	var compact uint32
	if size <= 3 {
		compact = uint32(t.Uint64() << (8 * (3 - size)))
	} else {
		compact = uint32(new(big.Int).Rsh(t, uint(8*(size-3))).Uint64())
	}
	if compact&0x00800000 != 0 {
		compact >>= 8
		size++
	}
	return compact | size<<24
}

// Work is the expected number of hashes for a target: 2^256 / (target + 1), as Core's GetBlockProof.
func Work(target *big.Int) *big.Int {
	d := new(big.Int).Add(target, big.NewInt(1))
	return d.Div(new(big.Int).Lsh(big.NewInt(1), 256), d)
}

// hashInt is the header hash as a 256-bit integer (internal order is little-endian).
func hashInt(h Hash) *big.Int {
	var r [32]byte
	for i := range h {
		r[31-i] = h[i]
	}
	return new(big.Int).SetBytes(r[:])
}

// CheckProofOfWork is Core's CheckProofOfWork: the target decodes to a positive, non-overflowing value within the
// network's PoW limit, and the hash does not exceed it.
func CheckProofOfWork(h Header, powLimit *big.Int) error {
	t, neg, over := CompactToTarget(h.Bits)
	switch {
	case neg || over || t.Sign() == 0:
		return fmt.Errorf("bad-diffbits: compact target %08x is negative, zero or overflowing", h.Bits)
	case t.Cmp(powLimit) > 0:
		return fmt.Errorf("bad-diffbits: target %08x above the proof-of-work limit", h.Bits)
	case hashInt(h.Hash).Cmp(t) > 0:
		return fmt.Errorf("high-hash: hash %s above target %08x", h.Hash, h.Bits)
	}
	return nil
}
