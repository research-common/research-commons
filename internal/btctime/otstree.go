package btctime

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/research-common/research-commons/internal/refusal"
)

// The operation tree as data (note §5, §5.1, §2 "Upgrade"): ParseTree reads an `ots-detached-v1` file into a tree
// with the same parser and the same refusals as ParseProof; Serialize writes a tree back in the reference
// library's canonical order; Merge splices a calendar's completed subtree in at a pending attestation's node, which
// is what `anchor upgrade` needs. Nothing here opens a network connection: the caller fetches the subtree.

// Tree is a parsed `ots-detached-v1` file: the file digest and the operation tree rooted at it.
type Tree struct {
	FileDigest [32]byte
	Root       *Node
}

// Node is one timestamp of the tree: the message the operations computed here, the attestations on it and the
// operations leaving it. ParseTree keeps siblings in file order; Serialize writes them in canonical order.
type Node struct {
	Msg          []byte
	Attestations []TreeAttestation
	Ops          []TreeOp
}

// TreeOp is one operation: its tag, its argument (append and prepend only) and the node for its result.
type TreeOp struct {
	Tag   byte
	Arg   []byte
	Child *Node
}

// TreeAttestation is one attestation: its 8-byte tag and its payload, exactly as the file holds them.
type TreeAttestation struct {
	Tag     [8]byte
	Payload []byte
}

// MaxUpgradeBytes bounds a calendar's completed subtree handed to Merge: the reference client reads at most this
// many bytes of a calendar's response.
const MaxUpgradeBytes = 10_000

// ParseTree parses b exactly as ParseProof does (same limits, same refusals, the same *ProofError values) and
// returns the operation tree.
func ParseTree(b []byte, lim Limits) (*Tree, error) {
	p, root, err := parseFile(b, lim, true)
	if err != nil {
		return nil, err
	}
	return &Tree{FileDigest: p.FileDigest, Root: root}, nil
}

// Serialize writes t as an `ots-detached-v1` file in canonical order. For every file the reference writer produced,
// ParseTree followed by Serialize returns the same bytes; a file whose siblings are in another order (which the
// parser accepts) comes back in canonical order.
//
// The canonical order is what python-opentimestamps v0.4.5 `Timestamp.serialize` emits. At each node the
// attestations come first, then the operations; every item but the last is preceded by `ff`. Attestations are
// sorted: two Bitcoin attestations by height (two Litecoin ones likewise), two pending ones by URI, two of one other tag by payload bytes, and
// attestations of different tags by their 8-byte tag. Operations are sorted by tag byte, then by argument bytes
// (an argument that is a prefix of another sorts first; unary operations have none). Values are written with
// minimal varuints, the only encoding the parser accepts.
//
// A node with neither attestations nor operations has no serialization (the reference writer refuses one); it is
// written as nothing, so the result fails to parse. ParseTree and Merge never produce one.
func (t *Tree) Serialize() []byte {
	out := append([]byte{}, HeaderMagic...)
	out = append(out, 0x01, opSHA256)
	out = append(out, t.FileDigest[:]...)
	return t.Root.appendTo(out, canonicalOrder)
}

// siblingOrder orders one node's attestations and operations for writing.
type siblingOrder struct {
	att func(a, b TreeAttestation) bool
	op  func(a, b TreeOp) bool
}

var canonicalOrder = siblingOrder{att: attestationLess, op: opLess}

// attestationLess is the canonical attestation order (see Serialize).
func attestationLess(a, b TreeAttestation) bool {
	if a.Tag != b.Tag {
		return bytes.Compare(a.Tag[:], b.Tag[:]) < 0
	}
	switch a.Tag {
	case TagBitcoin, tagLitecoin:
		ha, oka := payloadVaruint(a.Payload)
		hb, okb := payloadVaruint(b.Payload)
		if oka && okb {
			return ha < hb
		}
	case TagPending:
		ua, oka := payloadVarbytes(a.Payload)
		ub, okb := payloadVarbytes(b.Payload)
		if oka && okb {
			return bytes.Compare(ua, ub) < 0
		}
	}
	return bytes.Compare(a.Payload, b.Payload) < 0
}

// tagLitecoin is the reference library's Litecoin block-header attestation. This profile parses it as an unsupported
// attestation (it grants nothing); the writer still sorts two of them by height, as the library does.
var tagLitecoin = [8]byte{0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45}

// opLess is the canonical operation order (see Serialize).
func opLess(a, b TreeOp) bool {
	if a.Tag != b.Tag {
		return a.Tag < b.Tag
	}
	return bytes.Compare(a.Arg, b.Arg) < 0
}

func payloadVaruint(b []byte) (uint64, bool) {
	p := &parser{b: b, out: &Proof{}}
	v, err := p.varuint()
	return v, err == nil && p.pos == len(b)
}

func payloadVarbytes(b []byte) ([]byte, bool) {
	p := &parser{b: b, out: &Proof{}}
	v, err := p.varbytes(0, len(b))
	return v, err == nil && p.pos == len(b)
}

// appendTo writes n with its siblings in order ord, without touching n.
func (n *Node) appendTo(out []byte, ord siblingOrder) []byte {
	atts := append([]TreeAttestation(nil), n.Attestations...)
	ops := append([]TreeOp(nil), n.Ops...)
	sort.SliceStable(atts, func(i, j int) bool { return ord.att(atts[i], atts[j]) })
	sort.SliceStable(ops, func(i, j int) bool { return ord.op(ops[i], ops[j]) })
	items := len(atts) + len(ops)
	i := 0
	for _, a := range atts {
		i++
		if i < items {
			out = append(out, tagFork)
		}
		out = append(out, tagAttestation)
		out = append(out, a.Tag[:]...)
		out = appendVarbytes(out, a.Payload)
	}
	for _, o := range ops {
		i++
		if i < items {
			out = append(out, tagFork)
		}
		out = append(out, o.Tag)
		if o.Tag == opAppend || o.Tag == opPrepend {
			out = appendVarbytes(out, o.Arg)
		}
		out = o.Child.appendTo(out, ord)
	}
	return out
}

// appendVaruint writes the minimal base-128 little-endian encoding of v.
func appendVaruint(out []byte, v uint64) []byte {
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func appendVarbytes(out, b []byte) []byte {
	return append(appendVaruint(out, uint64(len(b))), b...)
}

// PendingCommitment is one pending attestation: its calendar URI and the commitment, the message at its node. The
// commitment is what a client asks that calendar for (`GET <URI>/timestamp/<hex commitment>`); the URI is only a
// display value here and nothing in this package dereferences it.
type PendingCommitment struct {
	URI        string
	Commitment []byte
}

// PendingCommitments lists every pending attestation of t with the message at its node, in tree order (depth
// first, siblings in the order the tree holds them).
func PendingCommitments(t *Tree) []PendingCommitment {
	var out []PendingCommitment
	var walk func(n *Node)
	walk = func(n *Node) {
		for _, a := range n.Attestations {
			if a.Tag != TagPending {
				continue
			}
			if uri, ok := payloadVarbytes(a.Payload); ok {
				out = append(out, PendingCommitment{URI: string(uri), Commitment: append([]byte(nil), n.Msg...)})
			}
		}
		for _, o := range n.Ops {
			walk(o.Child)
		}
	}
	if t != nil && t.Root != nil {
		walk(t.Root)
	}
	return out
}

// Merge splices upgrade, a calendar's completed subtree for commitment (the body of its
// `GET <base>/timestamp/<hex commitment>` response: a serialized timestamp with no file header, rooted at
// commitment), into pending at every node whose message is commitment and which carries a pending attestation. The
// merge is the reference library's `Timestamp.merge`: a union, so the pending attestation is kept, an attestation
// already present is not repeated and an operation already present has its subtree merged in turn.
//
// upgrade is parsed with the strict parser (duplicate siblings, non-minimal varuints, unknown operations and every
// other §5.1 refusal apply) under lim and MaxUpgradeBytes. The result is serialized and parsed again under lim, so
// the depth, node and size limits hold for the merged proof as a whole, and it must still be rooted at pending's
// file digest. pending is not modified.
func Merge(pending *Tree, commitment, upgrade []byte, lim Limits) (*Tree, error) {
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	if pending == nil || pending.Root == nil {
		return nil, &refusal.Refusal{Class: refusal.Intrinsic, Reason: refusal.UpgradeRootedElsewhere, Detail: "no pending tree to merge into"}
	}
	if len(upgrade) > MaxUpgradeBytes {
		return nil, &refusal.Refusal{Class: refusal.Operational, Reason: refusal.SizeLimit,
			Detail: fmt.Sprintf("upgrade is %d bytes, over the %d-byte limit", len(upgrade), MaxUpgradeBytes)}
	}
	sub, err := parseSubtree(upgrade, commitment, lim)
	if err != nil {
		return nil, err
	}
	// Work on a copy: the round trip through the parser is the deep copy, and it re-checks pending as well.
	work, err := ParseTree(pending.Serialize(), lim)
	if err != nil {
		return nil, fmt.Errorf("merge: pending tree: %w", err)
	}
	var targets []*Node
	var walk func(n *Node)
	walk = func(n *Node) {
		if bytes.Equal(n.Msg, commitment) {
			for _, a := range n.Attestations {
				if a.Tag == TagPending {
					targets = append(targets, n)
					break
				}
			}
		}
		for _, o := range n.Ops {
			walk(o.Child)
		}
	}
	walk(work.Root)
	if len(targets) == 0 {
		return nil, &refusal.Refusal{Class: refusal.Intrinsic, Reason: refusal.UpgradeRootedElsewhere,
			Detail: fmt.Sprintf("no pending attestation's node has message %x", commitment)}
	}
	for _, n := range targets {
		mergeNode(n, sub)
	}
	out, err := ParseTree(work.Serialize(), lim)
	if err != nil {
		return nil, fmt.Errorf("merge: merged proof: %w", err)
	}
	if out.FileDigest != pending.FileDigest {
		return nil, &refusal.Refusal{Class: refusal.Intrinsic, Reason: refusal.UpgradeRootedElsewhere, Detail: "the merged proof is rooted at another file digest"}
	}
	return out, nil
}

// parseSubtree reads b as one serialized timestamp for msg (no file header), to its exact end, under lim.
func parseSubtree(b, msg []byte, lim Limits) (*Node, error) {
	if len(msg) > maxMsg {
		return nil, &refusal.Refusal{Class: refusal.Intrinsic, Reason: refusal.UpgradeRootedElsewhere, Detail: fmt.Sprintf("commitment over %d bytes", maxMsg)}
	}
	p := &parser{b: b, lim: lim, out: &Proof{}}
	n := &Node{}
	if err := p.timestamp(msg, 1, n); err != nil {
		return nil, err
	}
	if p.pos != len(b) {
		return nil, p.fail("%d trailing bytes after the upgrade subtree", len(b)-p.pos)
	}
	return n, nil
}

// mergeNode merges src into dst (both for the same message): the reference library's Timestamp.merge.
func mergeNode(dst, src *Node) {
	for _, a := range src.Attestations {
		dup := false
		for _, b := range dst.Attestations {
			if a.Tag == b.Tag && bytes.Equal(a.Payload, b.Payload) {
				dup = true
				break
			}
		}
		if !dup {
			dst.Attestations = append(dst.Attestations, TreeAttestation{Tag: a.Tag, Payload: append([]byte(nil), a.Payload...)})
		}
	}
	for _, o := range src.Ops {
		var into *Node
		for _, d := range dst.Ops {
			if d.Tag == o.Tag && bytes.Equal(d.Arg, o.Arg) {
				into = d.Child
				break
			}
		}
		if into == nil {
			into = &Node{Msg: o.Child.Msg}
			dst.Ops = append(dst.Ops, TreeOp{Tag: o.Tag, Arg: append([]byte(nil), o.Arg...), Child: into})
		}
		mergeNode(into, o.Child)
	}
}
