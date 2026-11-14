package btctime

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/refusal"
)

var otsFixtures = []string{"hello-world.txt.ots", "bad-stamp.txt.ots", "incomplete.txt.ots", "known-and-unknown-notary.txt.ots"}

// canonicalTrees are test-built files whose siblings are in the canonical order: attestations before operations,
// Bitcoin heights numerically (129 before 256, although 256's varuint 80 02 sorts before 129's 81 01 as bytes),
// pending URIs by URI (https://aa before https://b, although the shorter payload sorts first as bytes), operations
// by tag and then argument (a prefix first).
func canonicalTrees() map[string][]byte {
	d := sha([]byte("canonical"))
	return map[string][]byte{
		"one attestation":     otsFile(d, attBitcoin(10)),
		"heights numerically": otsFile(d, []byte{tagFork}, attBitcoin(129), attBitcoin(256)),
		"uris by uri":         otsFile(d, []byte{tagFork}, attPending("https://aa"), attPending("https://b")),
		"tags before payloads": otsFile(d, []byte{tagFork}, attBitcoin(1), []byte{tagFork}, attOther([8]byte{0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45}, uvar(9)),
			attPending("https://a")),
		"unknown tag then payload": otsFile(d, []byte{tagFork}, attOther([8]byte{1}, []byte{2}), []byte{tagFork}, attOther([8]byte{1}, []byte{2, 0}),
			attOther([8]byte{1}, []byte{3})),
		"attestations before operations": otsFile(d, []byte{tagFork}, attPending("https://a"), opSHA256B(), attBitcoin(3)),
		"ops by tag then arg": otsFile(d,
			[]byte{tagFork}, opSHA256B(), attBitcoin(1),
			[]byte{tagFork}, opAppendB([]byte("a")), attBitcoin(2),
			[]byte{tagFork}, opAppendB([]byte("ab")), attBitcoin(3),
			[]byte{tagFork}, opAppendB([]byte("b")), attBitcoin(4),
			[]byte{tagFork}, opPrependB([]byte("a")), attBitcoin(5),
			[]byte{tagFork}, []byte{opReverse}, attBitcoin(6),
			[]byte{opHexlify}, attBitcoin(7)),
		"nested forks": otsFile(d, []byte{tagFork}, attBitcoin(1), opAppendB([]byte("x")), []byte{tagFork, opRIPEMD160}, []byte{tagFork},
			attBitcoin(2), []byte{opKeccak256}, attBitcoin(3), opSHA256B(), attPending("https://c")),
	}
}

// TestTreeRoundTrip: ParseTree then Serialize returns every public example and every canonical test-built file byte
// for byte, and the tree carries the same attestations ParseProof lists.
func TestTreeRoundTrip(t *testing.T) {
	files := map[string][]byte{}
	for _, n := range otsFixtures {
		files[n] = fixtureFile(t, n)
	}
	for n, b := range canonicalTrees() {
		files[n] = b
	}
	for n, b := range files {
		t.Run(n, func(t *testing.T) {
			tr, err := ParseTree(b, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if got := tr.Serialize(); !bytes.Equal(got, b) {
				t.Fatalf("round trip differs:\n got %x\nwant %x", got, b)
			}
			p, _ := ParseProof(b, Limits{})
			var bit, pend, other int
			var walk func(n *Node, msg []byte)
			walk = func(n *Node, msg []byte) {
				if !bytes.Equal(n.Msg, msg) {
					t.Fatalf("node message %x, replayed %x", n.Msg, msg)
				}
				for _, a := range n.Attestations {
					switch a.Tag {
					case TagBitcoin:
						h, _ := payloadVaruint(a.Payload)
						if !bytes.Equal(p.Bitcoin[bit].Digest, n.Msg) || p.Bitcoin[bit].Height != int64(h) {
							t.Fatalf("bitcoin attestation %d differs from ParseProof's", bit)
						}
						bit++
					case TagPending:
						pend++
					default:
						other++
					}
				}
				for _, o := range n.Ops {
					res, why := applyOp(o.Tag, o.Arg, msg)
					if why != "" {
						t.Fatal(why)
					}
					walk(o.Child, res)
				}
			}
			walk(tr.Root, tr.FileDigest[:])
			if bit != len(p.Bitcoin) || pend != p.PendingCount || other != p.Unsupported || tr.FileDigest != p.FileDigest {
				t.Fatalf("tree holds %d/%d/%d attestations, ParseProof %d/%d/%d", bit, pend, other, len(p.Bitcoin), p.PendingCount, p.Unsupported)
			}
		})
	}
}

// reversedOrder and bytesOrder are wrong writers: the round trip must catch either.
var (
	reversedOrder = siblingOrder{
		att: func(a, b TreeAttestation) bool { return attestationLess(b, a) },
		op:  func(a, b TreeOp) bool { return opLess(b, a) },
	}
	bytesOrder = siblingOrder{
		att: func(a, b TreeAttestation) bool {
			return bytes.Compare(append(a.Tag[:], a.Payload...), append(b.Tag[:], b.Payload...)) < 0
		},
		op: opLess,
	}
)

func serializeWith(t *Tree, ord siblingOrder) []byte {
	out := append([]byte{}, HeaderMagic...)
	out = append(out, 0x01, opSHA256)
	out = append(out, t.FileDigest[:]...)
	return t.Root.appendTo(out, ord)
}

// TestSerializeOrderMutations: a writer that orders siblings any other way fails the round trip, on a public example
// (two operations at one node) and on the test-built cases where the canonical order is not the byte order of the
// payloads. The canonical writer passes on the same trees (TestTreeRoundTrip), so the mutation is what fails.
func TestSerializeOrderMutations(t *testing.T) {
	ct := canonicalTrees()
	for _, c := range []struct {
		name string
		b    []byte
		ord  siblingOrder
	}{
		{"public example, siblings reversed", fixtureFile(t, "known-and-unknown-notary.txt.ots"), reversedOrder},
		{"ops reversed", ct["ops by tag then arg"], reversedOrder},
		{"attestations reversed", ct["tags before payloads"], reversedOrder},
		{"heights as payload bytes", ct["heights numerically"], bytesOrder},
		{"uris as payload bytes", ct["uris by uri"], bytesOrder},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr, err := ParseTree(c.b, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(tr.Serialize(), c.b) {
				t.Fatal("control: the canonical writer does not round-trip")
			}
			got := serializeWith(tr, c.ord)
			if bytes.Equal(got, c.b) {
				t.Fatal("a reordering writer still round-trips: the test does not reach the order")
			}
			// the reordered file is still a valid proof (order is not a parse rule) and canonicalises back
			tr2, err := ParseTree(got, Limits{})
			if err != nil {
				t.Fatalf("reordered file: %v", err)
			}
			if !bytes.Equal(tr2.Serialize(), c.b) {
				t.Fatal("a reordered file does not canonicalise back")
			}
		})
	}
	// attestations after operations is not the canonical order either: a file written that way is accepted and
	// canonicalised
	d := sha([]byte("canonical"))
	late := otsFile(d, []byte{tagFork}, opSHA256B(), attBitcoin(3), attPending("https://a"))
	tr, err := ParseTree(late, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := tr.Serialize(); bytes.Equal(got, late) || !bytes.Equal(got, canonicalTrees()["attestations before operations"]) {
		t.Fatalf("attestations after operations not canonicalised: %x", got)
	}
}

// TestParseTreeSameRefusals: ParseTree is ParseProof's parser. On the §5.1 refusals (non-minimal varuints first) and
// on every single-byte mutation of the public examples both return the same error or both accept, and an accepted
// mutation serializes to a file that parses to the same attestations.
func TestParseTreeSameRefusals(t *testing.T) {
	d := sha([]byte("covered"))
	cases := [][]byte{
		cat(HeaderMagic, []byte{0x81, 0x00, opSHA256}, d, attBitcoin(1)),
		otsFile(d, []byte{opAppend, 0x81, 0x00, 0x41}, attBitcoin(1)),
		otsFile(d, append(append([]byte{tagAttestation}, TagBitcoin[:]...), vbytes([]byte{0x87, 0x00})...)),
		otsFile(d, append(append([]byte{tagAttestation}, TagBitcoin[:]...), vbytes([]byte{0x80, 0x00})...)),
		otsFile(d, attPending("https://cal?x=1")),
		otsFile(d, []byte{tagFork}, attBitcoin(7), attBitcoin(7)),
		otsFile(d, []byte{tagFork}, opSHA256B(), attBitcoin(1), opSHA256B(), attBitcoin(2)),
		otsFile(d, attBitcoin(1), []byte{0}),
	}
	for i, b := range cases {
		_, e1 := ParseProof(b, Limits{})
		_, e2 := ParseTree(b, Limits{})
		var pe *ProofError
		if e1 == nil || !errors.As(e2, &pe) || e1.Error() != e2.Error() {
			t.Fatalf("case %d: ParseProof %v, ParseTree %v", i, e1, e2)
		}
		if i < 4 && !strings.Contains(e2.Error(), "non-minimal varuint") {
			t.Fatalf("case %d does not reach the varuint rule: %v", i, e2)
		}
	}
	accepted := 0
	for _, n := range otsFixtures {
		base := fixtureFile(t, n)
		for i := range base {
			for _, x := range []byte{0x01, 0x80, 0xff} {
				b := append([]byte(nil), base...)
				b[i] ^= x
				p, e1 := ParseProof(b, Limits{})
				tr, e2 := ParseTree(b, Limits{})
				if (e1 == nil) != (e2 == nil) || (e1 != nil && e1.Error() != e2.Error()) {
					t.Fatalf("%s byte %d ^%02x: ParseProof %v, ParseTree %v", n, i, x, e1, e2)
				}
				if e1 != nil {
					continue
				}
				accepted++
				p2, err := ParseProof(tr.Serialize(), Limits{})
				if err != nil || p2.FileDigest != p.FileDigest || len(p2.Bitcoin) != len(p.Bitcoin) || p2.PendingCount != p.PendingCount || p2.Unsupported != p.Unsupported {
					t.Fatalf("%s byte %d ^%02x: serialized tree parses to %+v %v, want %+v", n, i, x, p2, err, p)
				}
			}
		}
	}
	if accepted == 0 {
		t.Fatal("no mutation was accepted: the serialize half of the check never ran")
	}
}

// FuzzParseTree: ParseTree and ParseProof agree on every input, and an accepted tree serializes to a file that
// parses and is a fixed point of the writer.
func FuzzParseTree(f *testing.F) {
	for _, b := range canonicalTrees() {
		f.Add(b)
	}
	lim := Limits{ProofBytes: 1 << 16, Depth: 64, Nodes: 1000}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, e1 := ParseProof(b, lim)
		tr, e2 := ParseTree(b, lim)
		if (e1 == nil) != (e2 == nil) || (e1 != nil && e1.Error() != e2.Error()) {
			t.Fatalf("ParseProof %v, ParseTree %v", e1, e2)
		}
		if e1 != nil {
			return
		}
		s := tr.Serialize()
		tr2, err := ParseTree(s, lim)
		if err != nil || !bytes.Equal(tr2.Serialize(), s) {
			t.Fatalf("serialized tree: %v", err)
		}
	})
}

// subtree serializes one node: what a calendar returns for its message.
func subtree(n *Node) []byte { return n.appendTo(nil, canonicalOrder) }

// TestPendingCommitments: the message at each pending attestation's node, the thing a client asks that calendar for.
func TestPendingCommitments(t *testing.T) {
	for _, c := range []struct {
		file string
		uris []string
	}{
		{"incomplete.txt.ots", []string{"https://alice.btc.calendar.opentimestamps.org"}},
		{"known-and-unknown-notary.txt.ots", []string{"https://bob.btc.calendar.opentimestamps.org"}},
		{"hello-world.txt.ots", nil},
	} {
		tr, err := ParseTree(fixtureFile(t, c.file), Limits{})
		if err != nil {
			t.Fatal(err)
		}
		pcs := PendingCommitments(tr)
		if len(pcs) != len(c.uris) {
			t.Fatalf("%s: %d pending commitments", c.file, len(pcs))
		}
		for i, pc := range pcs {
			if pc.URI != c.uris[i] {
				t.Fatalf("%s: URI %q", c.file, pc.URI)
			}
			// the commitment is the replayed message: the pending node's, found independently by walking ops
			var found bool
			var walk func(n *Node)
			walk = func(n *Node) {
				for _, a := range n.Attestations {
					if a.Tag == TagPending && bytes.Equal(n.Msg, pc.Commitment) {
						found = true
					}
				}
				for _, o := range n.Ops {
					walk(o.Child)
				}
			}
			walk(tr.Root)
			if !found || len(pc.Commitment) == 0 {
				t.Fatalf("%s: commitment %x is no pending node's message", c.file, pc.Commitment)
			}
		}
	}
	// two pending attestations on two branches, listed in tree order
	d := sha([]byte("two"))
	tr, _ := ParseTree(otsFile(d, []byte{tagFork}, opAppendB([]byte("a")), attPending("https://a"), opAppendB([]byte("b")), attPending("https://b")), Limits{})
	pcs := PendingCommitments(tr)
	if len(pcs) != 2 || pcs[0].URI != "https://a" || !bytes.Equal(pcs[0].Commitment, append(append([]byte{}, d...), 'a')) ||
		pcs[1].URI != "https://b" || !bytes.Equal(pcs[1].Commitment, append(append([]byte{}, d...), 'b')) {
		t.Fatalf("%+v", pcs)
	}
}

// TestMergeUpgradesIncomplete: a calendar's completed subtree for incomplete.txt.ots's pending commitment, merged in,
// yields a proof that ParseProof reads with the Bitcoin attestation at the expected height, that verifies on a
// synthetic chain whose block commits to the calculated digest, and that keeps the pending attestation (the
// reference library's merge is a union).
func TestMergeUpgradesIncomplete(t *testing.T) {
	pending, err := ParseTree(fixtureFile(t, "incomplete.txt.ots"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	pcs := PendingCommitments(pending)
	commitment := pcs[0].Commitment
	// the shape of a calendar's answer: sha256 of the commitment, then a Merkle path to the block's root
	sib := sha([]byte("sibling"))
	upgrade := cat(opSHA256B(), opPrependB(sib), opSHA256B(), attBitcoin(150))
	root := sha(sib, sha(commitment))
	before := pending.Serialize()

	merged, err := Merge(pending, commitment, upgrade, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pending.Serialize(), before) {
		t.Fatal("Merge modified its input")
	}
	b := merged.Serialize()
	p, err := ParseProof(b, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Bitcoin) != 1 || p.Bitcoin[0].Height != 150 || !bytes.Equal(p.Bitcoin[0].Digest, root) {
		t.Fatalf("bitcoin attestations %+v, want height 150 at %x", p.Bitcoin, root)
	}
	if p.PendingCount != 1 || p.Pending[0].URI != pcs[0].URI || p.FileDigest != pending.FileDigest {
		t.Fatalf("pending %d %+v, digest %x", p.PendingCount, p.Pending, p.FileDigest)
	}
	// the merged file is canonical and is exactly the pending file with the subtree spliced in after the pending
	// attestation (attestations before operations at that node)
	if !bytes.Equal(b, merged.Serialize()) {
		t.Fatal("merged tree not a fixed point")
	}
	pfile := fixtureFile(t, "incomplete.txt.ots")
	pat := attPending(pcs[0].URI)
	want := cat(pfile[:len(pfile)-len(pat)], []byte{tagFork}, pat, upgrade)
	if !bytes.Equal(b, want) {
		t.Fatalf("merged bytes\n got %x\nwant %x", b, want)
	}
	// the upgraded proof verifies: a synthetic chain whose block 150 commits to the calculated digest
	s := newSynth(t, testParams("testchain", 0x207fffff))
	s.roots[150] = root
	s.extend(s.genesis(), 160, 0, "")
	e := s.fresh(nil).EvaluateProof(b, pending.FileDigest[:])
	if !e.Live() || e.BlockHeight != 150 {
		t.Fatalf("upgraded proof: %s", e)
	}
	if e := s.fresh(nil).EvaluateProof(pfile, pending.FileDigest[:]); e.State != StatePending {
		t.Fatalf("pending control: %s", e)
	}
	// merging the same answer again changes nothing (union)
	again, err := Merge(merged, commitment, upgrade, Limits{})
	if err != nil || !bytes.Equal(again.Serialize(), b) {
		t.Fatalf("second merge: %v", err)
	}
}

// TestMergeReassemblesHelloWorld cross-checks Merge on real data. The public hello-world proof is complete (it has no
// pending branch), so the test makes one: it cuts the tree at an inner node, puts a pending attestation there, and
// hands Merge the cut subtree as the calendar's answer. The merge must give back hello-world's own bytes plus the
// pending attestation, and verify on the mainnet headers at block 358 391.
func TestMergeReassemblesHelloWorld(t *testing.T) {
	file := fixtureFile(t, "hello-world.txt.ots")
	full, err := ParseTree(file, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	c, now := mainnetChain(t, fixtureTip)
	v := &Verifier{Policy: DefaultPolicy(), View: c.Snapshot(), Now: func() time.Time { return now }}
	for _, cut := range []int{1, 5, 20, 38} {
		t.Run(fmt.Sprint("depth ", cut), func(t *testing.T) {
			work, _ := ParseTree(file, Limits{})
			n := work.Root
			for i := 1; i < cut; i++ {
				n = n.Ops[0].Child
			}
			answer := subtree(n)
			commitment := append([]byte(nil), n.Msg...)
			pat := TreeAttestation{Tag: TagPending, Payload: vbytes([]byte("https://calendar.example"))}
			*n = Node{Msg: commitment, Attestations: []TreeAttestation{pat}}
			pending, err := ParseTree(work.Serialize(), Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if e := v.EvaluateProof(pending.Serialize(), full.FileDigest[:]); e.State != StatePending {
				t.Fatalf("cut proof: %s", e)
			}
			pcs := PendingCommitments(pending)
			if len(pcs) != 1 || !bytes.Equal(pcs[0].Commitment, commitment) {
				t.Fatalf("pending commitments %+v", pcs)
			}
			merged, err := Merge(pending, pcs[0].Commitment, answer, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			e := v.EvaluateProof(merged.Serialize(), full.FileDigest[:])
			if !e.Live() || e.BlockHeight != 358391 {
				t.Fatalf("merged proof: %s", e)
			}
			// drop the pending attestation again: hello-world's bytes exactly
			var walk func(n *Node)
			walk = func(n *Node) {
				var keep []TreeAttestation
				for _, a := range n.Attestations {
					if a.Tag != TagPending {
						keep = append(keep, a)
					}
				}
				n.Attestations = keep
				for _, o := range n.Ops {
					walk(o.Child)
				}
			}
			walk(merged.Root)
			if !bytes.Equal(merged.Serialize(), file) {
				t.Fatal("merged proof without the pending attestation is not hello-world's bytes")
			}
		})
	}
}

// TestMergeRefusals: an answer rooted elsewhere, oversize, malformed under §5.1, or one that would take the merged
// proof past the depth or node limit is refused, and the pending tree is untouched. Each control merges.
func TestMergeRefusals(t *testing.T) {
	pending, err := ParseTree(fixtureFile(t, "incomplete.txt.ots"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	commitment := PendingCommitments(pending)[0].Commitment
	good := cat(opSHA256B(), attBitcoin(150))
	if _, err := Merge(pending, commitment, good, Limits{}); err != nil {
		t.Fatalf("control: %v", err)
	}
	before := pending.Serialize()
	pendingDepth := 7 // the pending node of incomplete.txt.ots (six operations below the file digest)
	chain := func(n int) []byte {
		return cat(bytes.Repeat([]byte{opSHA256}, n), attBitcoin(1))
	}
	if _, err := Merge(pending, commitment, chain(256-pendingDepth), Limits{}); err != nil {
		t.Fatalf("depth control (exactly 256): %v", err)
	}
	wide := func(n int) []byte {
		var b []byte
		for i := 0; i < n; i++ {
			b = append(b, tagFork)
			b = append(b, attOther([8]byte{1, byte(i >> 8), byte(i)}, nil)...)
		}
		return append(b, attBitcoin(1)...)
	}
	if _, err := Merge(pending, commitment, wide(20), Limits{ProofBytes: 1 << 20, Depth: 256, Nodes: 30}); err != nil {
		t.Fatalf("node control: %v", err)
	}
	for _, c := range []struct {
		name       string
		commitment []byte
		upgrade    []byte
		lim        Limits
		class      refusal.Class
		reason     string // a refusal.Refusal reason, or "" for a *ProofError
		want       string
	}{
		{"rooted at the file digest (no pending attestation there)", pending.FileDigest[:], good, Limits{}, refusal.Intrinsic, "upgrade rooted elsewhere", "no pending attestation"},
		{"rooted at an unrelated message", sha([]byte("elsewhere")), good, Limits{}, refusal.Intrinsic, "upgrade rooted elsewhere", "no pending attestation"},
		{"rooted at an inner node without a pending attestation", pending.Root.Ops[0].Child.Msg, good, Limits{}, refusal.Intrinsic, "upgrade rooted elsewhere", "no pending attestation"},
		{"oversize", commitment, cat(opAppendB(make([]byte, 4000)), opAppendB(make([]byte, 4000)), opAppendB(make([]byte, 2000)), opSHA256B(), attBitcoin(1)), Limits{}, refusal.Operational, refusal.SizeLimit, "over the 10000-byte limit"},
		{"would exceed depth", commitment, chain(257 - pendingDepth), Limits{}, "", "", "deeper than 256"},
		{"would exceed a local depth limit", commitment, chain(10), Limits{ProofBytes: 1 << 20, Depth: 16, Nodes: 1000}, "", "", "deeper than 16"},
		{"would exceed the node limit (answer alone fits)", commitment, wide(25), Limits{ProofBytes: 1 << 20, Depth: 256, Nodes: 30}, "", "", "more than 30 nodes"},
		{"duplicate siblings in the answer", commitment, cat([]byte{tagFork}, attBitcoin(7), attBitcoin(7)), Limits{}, "", "", "duplicate sibling"},
		{"non-minimal varuint in the answer", commitment, append(append([]byte{tagAttestation}, TagBitcoin[:]...), vbytes([]byte{0x87, 0x00})...), Limits{}, "", "", "non-minimal varuint"},
		{"trailing bytes after the answer", commitment, append(append([]byte{}, good...), 0x00), Limits{}, "", "", "trailing bytes"},
		{"truncated answer", commitment, good[:len(good)-1], Limits{}, "", "", "truncated"},
		{"empty answer", commitment, nil, Limits{}, "", "", "truncated"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Merge(pending, c.commitment, c.upgrade, c.lim)
			if err == nil {
				t.Fatal("merged")
			}
			if c.reason != "" {
				var r *refusal.Refusal
				if !errors.As(err, &r) || r.Class != c.class || r.Reason != c.reason || !strings.Contains(r.Detail, c.want) {
					t.Fatalf("got %v, want %s/%s naming %q", err, c.class, c.reason, c.want)
				}
			} else {
				var pe *ProofError
				if !errors.As(err, &pe) || pe.State != StateInvalidProof || !strings.Contains(pe.Detail, c.want) {
					t.Fatalf("got %v, want invalid-proof naming %q", err, c.want)
				}
			}
			if !bytes.Equal(pending.Serialize(), before) {
				t.Fatal("a refused merge modified the pending tree")
			}
		})
	}
}

// TestMergeUnion: an answer that repeats part of what the node already holds merges into it (the reference
// library's Timestamp.merge), so the merged proof never carries a duplicate sibling; a seeded sweep over random
// answers keeps the merged proof canonical and every attestation of both inputs present.
func TestMergeUnion(t *testing.T) {
	d := sha([]byte("union"))
	// pending at the node after append "n"; the node also already has a sha256 branch with a pending attestation
	file := otsFile(d, opAppendB([]byte("n")), []byte{tagFork}, attPending("https://a"), opSHA256B(), attPending("https://b"))
	pending, err := ParseTree(file, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	commitment := append(append([]byte{}, d...), 'n')
	answer := cat([]byte{tagFork}, attPending("https://a"), opSHA256B(), []byte{tagFork}, attPending("https://b"), attBitcoin(9))
	merged, err := Merge(pending, commitment, answer, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	want := otsFile(d, opAppendB([]byte("n")), []byte{tagFork}, attPending("https://a"), opSHA256B(), []byte{tagFork}, attBitcoin(9), attPending("https://b"))
	if got := merged.Serialize(); !bytes.Equal(got, want) {
		t.Fatalf("union\n got %x\nwant %x", got, want)
	}

	r := rand.New(rand.NewPCG(1114, 3))
	var gen func(depth int) []byte
	gen = func(depth int) []byte {
		var items [][]byte
		seen := map[string]bool{}
		k := 1 + r.IntN(3)
		for len(items) < k {
			var it []byte
			switch x := r.IntN(5); {
			case x == 0 || depth > 4:
				it = attBitcoin(uint64(r.IntN(4)))
			case x == 1:
				it = attPending(fmt.Sprintf("https://c%d", r.IntN(3)))
			case x == 2:
				it = append(opAppendB([]byte{byte('a' + r.IntN(3))}), gen(depth+1)...)
			default:
				it = append(opSHA256B(), gen(depth+1)...)
			}
			key := string(it) // an attestation: its bytes
			switch it[0] {
			case opSHA256:
				key = string(it[:1])
			case opAppend:
				key = string(it[:3])
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			items = append(items, it)
		}
		var out []byte
		for i, it := range items {
			if i < len(items)-1 {
				out = append(out, tagFork)
			}
			out = append(out, it...)
		}
		return out
	}
	for i := 0; i < 300; i++ {
		ans := gen(1)
		m, err := Merge(pending, commitment, ans, Limits{})
		if err != nil {
			t.Fatalf("seed 1114/3 iteration %d: %v (answer %x)", i, err, ans)
		}
		b := m.Serialize()
		p, err := ParseProof(b, Limits{})
		if err != nil {
			t.Fatalf("iteration %d: merged proof %v", i, err)
		}
		sub, err := parseSubtree(ans, commitment, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		// every (message, attestation) pair of the pending tree and of the answer is in the merged proof, and
		// nothing else is
		pairs := func(roots ...*Node) map[string]bool {
			out := map[string]bool{}
			var walk func(n *Node)
			walk = func(n *Node) {
				for _, a := range n.Attestations {
					out[fmt.Sprintf("%x %x %x", n.Msg, a.Tag, a.Payload)] = true
				}
				for _, o := range n.Ops {
					walk(o.Child)
				}
			}
			for _, r := range roots {
				walk(r)
			}
			return out
		}
		want, got := pairs(pending.Root, sub), pairs(m.Root)
		if len(want) != len(got) {
			t.Fatalf("iteration %d: %d attestation pairs, want %d", i, len(got), len(want))
		}
		for k := range want {
			if !got[k] {
				t.Fatalf("iteration %d: merged proof lost %s", i, k)
			}
		}
		if p.PendingCount < 2 {
			t.Fatalf("iteration %d: pending attestations dropped", i)
		}
		if again, err := Merge(m, commitment, ans, Limits{}); err != nil || !bytes.Equal(again.Serialize(), b) {
			t.Fatalf("iteration %d: merge not idempotent: %v", i, err)
		}
	}
}
