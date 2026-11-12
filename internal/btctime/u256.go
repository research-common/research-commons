package btctime

import (
	"encoding/binary"
	"math/big"
	"math/bits"
)

// u256 is an unsigned 256-bit integer held in place: four 64-bit limbs, least significant first. The chain keeps
// every header's cumulative work in one (Bitcoin Core's nChainWork is an arith_uint256 too), so a held header costs
// no heap allocation beyond its node. Targets and proofs of work are compared in it on the hot path; *big.Int stays
// the exported form (ChainView.TipWork, Bootstrap.WorkBelow, Work, CompactToTarget).
type u256 [4]uint64

// u256FromBig converts a non-negative integer of at most 256 bits; ok is false for anything else.
func u256FromBig(b *big.Int) (u u256, ok bool) {
	if b == nil || b.Sign() < 0 || b.BitLen() > 256 {
		return u, false
	}
	var buf [32]byte
	b.FillBytes(buf[:])
	for i := range u {
		u[i] = binary.BigEndian.Uint64(buf[32-8*(i+1) : 32-8*i])
	}
	return u, true
}

// big is the value as a new *big.Int.
func (a u256) big() *big.Int {
	var buf [32]byte
	for i := range a {
		binary.BigEndian.PutUint64(buf[32-8*(i+1):32-8*i], a[i])
	}
	return new(big.Int).SetBytes(buf[:])
}

// add is a + b; ok is false when the sum does not fit in 256 bits.
func (a u256) add(b u256) (sum u256, ok bool) {
	var c uint64
	for i := range a {
		sum[i], c = bits.Add64(a[i], b[i], c)
	}
	return sum, c == 0
}

// cmp is -1, 0 or +1 as a is below, equal to or above b.
func (a u256) cmp(b u256) int {
	for i := len(a) - 1; i >= 0; i-- {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

// hashU256 is the header hash as a 256-bit integer (internal byte order is little-endian), as hashInt.
func hashU256(h Hash) (u u256) {
	for i := range u {
		u[i] = binary.LittleEndian.Uint64(h[8*i : 8*i+8])
	}
	return u
}
