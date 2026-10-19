package btctime

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // an OpenTimestamps operation (note §5.1); collisions do not weaken a timestamp
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // an OpenTimestamps operation (note §5.1)
	"golang.org/x/crypto/sha3"
)

// The `ots-detached-v1` format (bitcoin-time note §5.1): the OpenTimestamps detached-timestamp file as the
// reference library python-opentimestamps v0.4.5 reads it. Every row of the note's table is enforced here, during
// parsing, under the resource limits of §12.

// ProofFormat is the only proof_format this package verifies.
const ProofFormat = "ots-detached-v1"

// HeaderMagic is the 31-byte file magic: "\x00OpenTimestamps\x00\x00Proof\x00" and 8 fixed bytes.
var HeaderMagic = []byte("\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

// Attestation tags (note §5.1).
var (
	TagBitcoin = [8]byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
	TagPending = [8]byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
)

// Operation tags (note §5.1).
const (
	opAppend    = 0xf0
	opPrepend   = 0xf1
	opReverse   = 0xf2
	opHexlify   = 0xf3
	opSHA1      = 0x02
	opRIPEMD160 = 0x03
	opSHA256    = 0x08
	opKeccak256 = 0x67

	tagAttestation = 0x00
	tagFork        = 0xff

	maxMsg      = 4096 // the library's Op.MAX_MSG_LENGTH and MAX_RESULT_LENGTH
	maxPayload  = 8192 // TimeAttestation.MAX_PAYLOAD_SIZE
	maxURI      = 1000 // PendingAttestation.MAX_URI_LENGTH
	uriAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:"
	// keepPending bounds how many pending URIs are retained for display; the rest are counted. They grant nothing
	// and are never dereferenced (§2), so retaining every one would only let a sender spend the reader's memory.
	keepPending = 64
)

// Limits are the reader's resource limits for one proof (note §12). They are local and never set by received data.
type Limits struct {
	ProofBytes int // the proof blob; default 8 MiB
	Depth      int // tree depth; default 256 (the library's recursion limit)
	Nodes      int // operations plus attestations; default 100 000
}

// DefaultLimits are the note's §12 defaults.
func DefaultLimits() Limits { return Limits{ProofBytes: 8 << 20, Depth: 256, Nodes: 100_000} }

// AttestationKind is what an attestation can yield.
type AttestationKind string

const (
	// KindBitcoin is a BitcoinBlockHeaderAttestation: the only kind that can yield `bitcoin` quality.
	KindBitcoin AttestationKind = "bitcoin"
	// KindPending is a calendar's promise: displayed `pending`, never dereferenced, granting nothing.
	KindPending AttestationKind = "pending"
	// KindUnsupported is any other tag (Litecoin included): retained, granting nothing (I5).
	KindUnsupported AttestationKind = "unsupported attestation"
)

// Attestation is one (calculated digest, attestation) pair of the operation tree (note §5).
type Attestation struct {
	Kind AttestationKind
	Tag  [8]byte
	// Height is the claimed block height of a Bitcoin attestation. HeightOK is false when it does not fit a
	// non-negative int64, which the verifier reports as `unknown-height`.
	Height   int64
	HeightOK bool
	// Digest is the message the operations computed at this leaf, kept for Bitcoin attestations only: the value
	// that must equal the header's hashMerkleRoot, in the library's (internal) byte order.
	Digest []byte
	// URI is a pending attestation's calendar URI (display only).
	URI string
	// PayloadLen is the payload size of an unsupported attestation.
	PayloadLen int
}

// Proof is a parsed `ots-detached-v1` file.
type Proof struct {
	// FileDigest is the digest the tree is rooted at: for this profile, the raw 32 bytes of `covered`.
	FileDigest [32]byte
	// Bitcoin lists every Bitcoin attestation in tree order.
	Bitcoin []Attestation
	// Pending lists up to keepPending pending attestations; PendingCount counts all of them.
	Pending      []Attestation
	PendingCount int
	// Unsupported counts attestations of any other tag.
	Unsupported int
	// Nodes and Depth are what the parse consumed, for diagnostics.
	Nodes, Depth int
}

// ProofError is a proof the parser rejected. State is StateInvalidProof (intrinsic: wrong for every reader) or
// StateUnsupported (a major version this reader does not read).
type ProofError struct {
	State  State
	Offset int
	Detail string
}

func (e *ProofError) Error() string {
	return fmt.Sprintf("%s at byte %d: %s", e.State, e.Offset, e.Detail)
}

// ParseProof parses b as an `ots-detached-v1` file, replaying every operation, under lim. It does not compare the
// file digest with anything; the verifier does (§4 check 7). A proof over lim.ProofBytes is the caller's
// operational refusal and is never handed here (§4 check 5); ParseProof refuses it too, as a guard.
func ParseProof(b []byte, lim Limits) (*Proof, error) {
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	p := &parser{b: b, lim: lim, out: &Proof{}}
	if len(b) > lim.ProofBytes {
		return nil, p.fail("proof is %d bytes, over the %d-byte limit", len(b), lim.ProofBytes)
	}
	if !bytes.HasPrefix(b, HeaderMagic) {
		return nil, p.fail("header magic does not match")
	}
	p.pos = len(HeaderMagic)
	// The major version: v0.4.5 reads a varuint, master a single byte; for version 1 both are the byte 01, and a
	// conforming parser accepts exactly that byte (§5.1).
	start := p.pos
	major, err := p.varuint()
	if err != nil {
		return nil, err
	}
	if major != 1 {
		return nil, &ProofError{State: StateUnsupported, Offset: start, Detail: fmt.Sprintf("major version %d", major)}
	}
	if p.pos-start != 1 {
		return nil, &ProofError{State: StateInvalidProof, Offset: start, Detail: "major version 1 not written as the single byte 01"}
	}
	op, err := p.byte1()
	if err != nil {
		return nil, err
	}
	if op != opSHA256 {
		return nil, p.failAt(p.pos-1, "file-hash operation 0x%02x; this profile stamps sha256 digests only", op)
	}
	d, err := p.take(32)
	if err != nil {
		return nil, err
	}
	copy(p.out.FileDigest[:], d)
	if err := p.timestamp(d, 1); err != nil {
		return nil, err
	}
	if p.pos != len(b) {
		return nil, p.fail("%d trailing bytes after the tree", len(b)-p.pos)
	}
	return p.out, nil
}

type parser struct {
	b   []byte
	pos int
	lim Limits
	out *Proof
}

func (p *parser) fail(f string, a ...any) *ProofError { return p.failAt(p.pos, f, a...) }

func (p *parser) failAt(off int, f string, a ...any) *ProofError {
	return &ProofError{State: StateInvalidProof, Offset: off, Detail: fmt.Sprintf(f, a...)}
}

func (p *parser) byte1() (byte, error) {
	if p.pos >= len(p.b) {
		return 0, p.fail("truncated")
	}
	c := p.b[p.pos]
	p.pos++
	return c, nil
}

func (p *parser) take(n int) ([]byte, error) {
	if n < 0 || len(p.b)-p.pos < n {
		return nil, p.fail("truncated: %d bytes needed, %d left", n, len(p.b)-p.pos)
	}
	s := p.b[p.pos : p.pos+n]
	p.pos += n
	return s, nil
}

// varuint reads the library's base-128 little-endian integer. The library sets no maximum; this reader refuses
// one that does not fit 64 bits, which no conforming writer produces.
func (p *parser) varuint() (uint64, error) {
	start := p.pos
	var v uint64
	for shift := uint(0); ; shift += 7 {
		c, err := p.byte1()
		if err != nil {
			return 0, err
		}
		if shift > 63 || (shift == 63 && c&0x7f > 1) {
			return 0, p.failAt(start, "varuint does not fit 64 bits")
		}
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, nil
		}
	}
}

func (p *parser) varbytes(min, max int) ([]byte, error) {
	start := p.pos
	n, err := p.varuint()
	if err != nil {
		return nil, err
	}
	if n > uint64(max) || n < uint64(min) {
		return nil, p.failAt(start, "length %d outside %d..%d", n, min, max)
	}
	return p.take(int(n))
}

// timestamp reads one node of the tree for message msg: (ff item)* item, where an item is an attestation or an
// operation followed by the node for its result.
func (p *parser) timestamp(msg []byte, depth int) error {
	if depth > p.lim.Depth {
		return p.fail("tree deeper than %d", p.lim.Depth)
	}
	if depth > p.out.Depth {
		p.out.Depth = depth
	}
	// The library holds a node's operations in a dict keyed by (tag, argument) and its attestations in a set, so a
	// repeated sibling silently replaces or merges with the first. Two parsers could then disagree about which
	// attestations a file holds; this profile refuses the file instead (C-btc-11, "duplicate keys").
	var seen map[string]bool
	for {
		tag, err := p.byte1()
		if err != nil {
			return err
		}
		fork := tag == tagFork
		if fork {
			if tag, err = p.byte1(); err != nil {
				return err
			}
		}
		at := p.pos - 1
		key, err := p.item(tag, msg, depth)
		if err != nil {
			return err
		}
		if seen == nil {
			seen = map[string]bool{}
		}
		if seen[key] {
			return p.failAt(at, "duplicate sibling (tag 0x%02x) at one node", tag)
		}
		seen[key] = true
		if !fork {
			return nil
		}
	}
}

// item reads one attestation or operation and returns its sibling key: the tag and the serialized argument or
// attestation bytes.
func (p *parser) item(tag byte, msg []byte, depth int) (string, error) {
	p.out.Nodes++
	if p.out.Nodes > p.lim.Nodes {
		return "", p.fail("more than %d nodes", p.lim.Nodes)
	}
	start := p.pos - 1
	if tag == tagAttestation {
		err := p.attestation(msg)
		return string(p.b[start:p.pos]), err
	}
	at := p.pos - 1
	res, err := p.op(tag, msg)
	if err != nil {
		return "", err
	}
	key := string(p.b[start:p.pos])
	if len(res) > maxMsg {
		return "", p.failAt(at, "operation 0x%02x result is %d bytes, over %d", tag, len(res), maxMsg)
	}
	return key, p.timestamp(res, depth+1)
}

func (p *parser) op(tag byte, msg []byte) ([]byte, error) {
	at := p.pos - 1
	if len(msg) > maxMsg {
		return nil, p.failAt(at, "message over %d bytes", maxMsg)
	}
	switch tag {
	case opAppend, opPrepend:
		arg, err := p.varbytes(1, maxMsg)
		if err != nil {
			return nil, err
		}
		out := make([]byte, 0, len(msg)+len(arg))
		if tag == opAppend {
			return append(append(out, msg...), arg...), nil
		}
		return append(append(out, arg...), msg...), nil
	case opReverse:
		if len(msg) == 0 {
			return nil, p.failAt(at, "reverse of an empty message")
		}
		out := make([]byte, len(msg))
		for i, c := range msg {
			out[len(msg)-1-i] = c
		}
		return out, nil
	case opHexlify:
		if len(msg) == 0 || len(msg) > maxMsg/2 {
			return nil, p.failAt(at, "hexlify of a %d-byte message", len(msg))
		}
		return []byte(hex.EncodeToString(msg)), nil
	case opSHA1:
		h := sha1.Sum(msg) //nolint:gosec
		return h[:], nil
	case opRIPEMD160:
		h := ripemd160.New()
		h.Write(msg)
		return h.Sum(nil), nil
	case opSHA256:
		h := sha256.Sum256(msg)
		return h[:], nil
	case opKeccak256:
		h := sha3.NewLegacyKeccak256()
		h.Write(msg)
		return h.Sum(nil), nil
	}
	return nil, p.failAt(at, "unknown operation tag 0x%02x", tag)
}

func (p *parser) attestation(msg []byte) error {
	t, err := p.take(8)
	if err != nil {
		return err
	}
	var tag [8]byte
	copy(tag[:], t)
	payload, err := p.varbytes(0, maxPayload)
	if err != nil {
		return err
	}
	end := p.pos
	// the payload is parsed to its exact end (§5.1)
	sub := &parser{b: payload, lim: p.lim, out: p.out}
	off := end - len(payload)
	switch tag {
	case TagBitcoin:
		h, err := sub.varuint()
		if err != nil {
			return p.failAt(off, "bitcoin attestation: %s", err.(*ProofError).Detail)
		}
		if sub.pos != len(payload) {
			return p.failAt(off+sub.pos, "bitcoin attestation: %d trailing payload bytes", len(payload)-sub.pos)
		}
		a := Attestation{Kind: KindBitcoin, Tag: tag, Digest: append([]byte(nil), msg...)}
		if h <= math.MaxInt64 {
			a.Height, a.HeightOK = int64(h), true
		}
		p.out.Bitcoin = append(p.out.Bitcoin, a)
	case TagPending:
		uri, err := sub.varbytes(0, maxURI)
		if err != nil {
			return p.failAt(off, "pending attestation: %s", err.(*ProofError).Detail)
		}
		if sub.pos != len(payload) {
			return p.failAt(off+sub.pos, "pending attestation: %d trailing payload bytes", len(payload)-sub.pos)
		}
		for _, c := range uri {
			if !bytes.ContainsRune([]byte(uriAlphabet), rune(c)) {
				return p.failAt(off, "pending attestation URI holds byte 0x%02x outside the allowed set", c)
			}
		}
		p.out.PendingCount++
		if len(p.out.Pending) < keepPending {
			p.out.Pending = append(p.out.Pending, Attestation{Kind: KindPending, Tag: tag, URI: string(uri)})
		}
	default:
		p.out.Unsupported++
	}
	return nil
}
