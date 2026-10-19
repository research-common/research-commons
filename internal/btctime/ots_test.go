package btctime

import (
	"bytes"
	"crypto/sha1" //nolint:gosec
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/conformance"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck
	"golang.org/x/crypto/sha3"
)

// helloDigest is sha256("Hello World!\n"), the digest the public hello-world example stamps.
const helloDigest = "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340"

// TestParseHelloWorld parses the public OpenTimestamps example: one Bitcoin attestation at 358 391 whose calculated
// digest is that block's Merkle root in internal order (testdata/SOURCES.md).
func TestParseHelloWorld(t *testing.T) {
	p, err := ParseProof(fixtureFile(t, "hello-world.txt.ots"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.FileDigest[:]; !bytes.Equal(got, unhex(t, helloDigest)) {
		t.Fatalf("file digest %x", got)
	}
	if len(p.Bitcoin) != 1 || p.Bitcoin[0].Height != 358391 || !p.Bitcoin[0].HeightOK || p.PendingCount != 0 {
		t.Fatalf("attestations: %+v pending %d", p.Bitcoin, p.PendingCount)
	}
	// Merkle root of block 358 391: display order 8a1b66ec…7e00 (two explorers), internal order its reverse.
	if got := Hash(p.Bitcoin[0].Digest); got.String() != "8a1b66ecb7cbd07d8139a7e7d7f2c41aab1f5009b8364aaf61d03ad245e47e00" {
		t.Fatalf("calculated digest (display) %s", got)
	}
}

// TestParsePublicExamples: the pending-only and unknown-notary examples parse to the kinds §5.1 names.
func TestParsePublicExamples(t *testing.T) {
	p, err := ParseProof(fixtureFile(t, "incomplete.txt.ots"), Limits{})
	if err != nil || len(p.Bitcoin) != 0 || p.PendingCount != 1 || p.Pending[0].URI != "https://alice.btc.calendar.opentimestamps.org" {
		t.Fatalf("incomplete: %+v %v", p, err)
	}
	p, err = ParseProof(fixtureFile(t, "known-and-unknown-notary.txt.ots"), Limits{})
	if err != nil || p.PendingCount != 1 || p.Unsupported != 1 {
		t.Fatalf("known-and-unknown: %+v %v", p, err)
	}
}

// TestParseOperations replays every operation of §5.1 on a synthetic tree and checks the digests reached.
func TestParseOperations(t *testing.T) {
	d := sha([]byte("x"))
	tree := cat(
		[]byte{tagFork}, opAppendB([]byte("a")), []byte{opReverse}, attBitcoin(1),
		[]byte{tagFork}, []byte{opHexlify}, []byte{opSHA1}, attBitcoin(2),
		[]byte{tagFork}, []byte{opRIPEMD160}, attBitcoin(3),
		[]byte{tagFork}, []byte{opKeccak256}, attBitcoin(4),
		opPrependB([]byte("b")), opSHA256B(), attBitcoin(5),
	)
	p, err := ParseProof(otsFile(d, tree), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Bitcoin) != 5 {
		t.Fatalf("%d attestations", len(p.Bitcoin))
	}
	rev := append(append([]byte{}, d...), 'a')
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	rmd := ripemd160.New()
	rmd.Write(d)
	kec := sha3.NewLegacyKeccak256()
	kec.Write(d)
	s1 := sha1.Sum([]byte(hex.EncodeToString(d)))
	want := map[int64][]byte{1: rev, 2: s1[:], 3: rmd.Sum(nil), 4: kec.Sum(nil), 5: sha(append([]byte("b"), d...))}
	for _, a := range p.Bitcoin {
		if !bytes.Equal(a.Digest, want[a.Height]) {
			t.Fatalf("height %d digest %x, want %x", a.Height, a.Digest, want[a.Height])
		}
	}
	if len(p.Bitcoin[1].Digest) != 20 || len(p.Bitcoin[2].Digest) != 20 || len(p.Bitcoin[3].Digest) != 32 {
		t.Fatalf("digest lengths %d %d %d", len(p.Bitcoin[1].Digest), len(p.Bitcoin[2].Digest), len(p.Bitcoin[3].Digest))
	}
}

// TestProofRefusals: C-btc-11 (bounded invalid-proof) and the §5.1 table, each mutation shown to reach the parser
// rule it targets: the error names the rule, and the unmutated control parses.
func TestProofRefusals(t *testing.T) {
	conformance.Covers(t, "C-btc-11")
	d := sha([]byte("covered"))
	good := otsFile(d, attBitcoin(10))
	if _, err := ParseProof(good, Limits{}); err != nil {
		t.Fatalf("control: %v", err)
	}
	deep := func(n int) []byte {
		var b []byte
		for i := 0; i < n; i++ {
			b = append(b, opSHA256)
		}
		return otsFile(d, b, attBitcoin(1))
	}
	wide := func(n int) []byte {
		var b []byte
		for i := 0; i < n; i++ {
			b = append(b, tagFork)
			b = append(b, attOther([8]byte{1, 2, 3, 4, 5, 6, 7, byte(i)}, uvar(uint64(i)))...)
		}
		return otsFile(d, b, attBitcoin(1))
	}
	for _, c := range []struct {
		name  string
		b     []byte
		state State
		want  string
	}{
		{"bad magic", append([]byte{1}, good[1:]...), StateInvalidProof, "magic"},
		{"major version 2", cat(HeaderMagic, []byte{0x02, opSHA256}, d, attBitcoin(1)), StateUnsupported, "major version 2"},
		{"major version 1 as a two-byte varuint", cat(HeaderMagic, []byte{0x81, 0x00, opSHA256}, d, attBitcoin(1)), StateInvalidProof, "single byte"},
		{"file hash sha1", cat(HeaderMagic, []byte{0x01, opSHA1}, d[:20], attBitcoin(1)), StateInvalidProof, "file-hash operation 0x02"},
		{"trailing bytes", append(append([]byte{}, good...), 0x00), StateInvalidProof, "trailing"},
		{"truncated tree", good[:len(good)-1], StateInvalidProof, "truncated"},
		{"truncated digest", good[:len(HeaderMagic)+10], StateInvalidProof, "truncated"},
		{"empty tree", otsFile(d), StateInvalidProof, "truncated"},
		{"unknown op", otsFile(d, []byte{0x55}, attBitcoin(1)), StateInvalidProof, "unknown operation tag 0x55"},
		{"empty append", otsFile(d, []byte{opAppend, 0x00}, attBitcoin(1)), StateInvalidProof, "outside 1..4096"},
		{"append over 4096", otsFile(d, opAppendB(make([]byte, 4097)), attBitcoin(1)), StateInvalidProof, "outside 1..4096"},
		{"result over 4096", otsFile(d, opAppendB(make([]byte, 4096)), attBitcoin(1)), StateInvalidProof, "over 4096"},
		{"payload over 8192", otsFile(d, attOther([8]byte{9}, make([]byte, 8193))), StateInvalidProof, "outside 0..8192"},
		{"trailing payload bytes in a bitcoin attestation", otsFile(d, append(append([]byte{tagAttestation}, TagBitcoin[:]...), vbytes([]byte{0x05, 0x00})...)), StateInvalidProof, "trailing payload"},
		{"pending URI outside the alphabet", otsFile(d, attPending("https://cal?x=1")), StateInvalidProof, "outside the allowed set"},
		{"pending URI over 1000", otsFile(d, attPending(strings.Repeat("a", 1001))), StateInvalidProof, "outside 0..1000"},
		{"duplicate attestation at one node", otsFile(d, []byte{tagFork}, attBitcoin(7), attBitcoin(7)), StateInvalidProof, "duplicate sibling"},
		{"duplicate operation at one node", otsFile(d, []byte{tagFork}, opSHA256B(), attBitcoin(1), opSHA256B(), attBitcoin(2)), StateInvalidProof, "duplicate sibling"},
		{"varuint over 64 bits", otsFile(d, append(append([]byte{tagAttestation}, TagBitcoin[:]...), vbytes(bytes.Repeat([]byte{0xff}, 10))...)), StateInvalidProof, "64 bits"},
		{"depth over 256", deep(256), StateInvalidProof, "deeper than 256"},
		{"node limit", wide(100_001), StateInvalidProof, "more than 100000 nodes"},
		{"size limit", append(good, make([]byte, 9<<20)...), StateInvalidProof, "over the 8388608-byte limit"},
	} {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			_, err := ParseProof(c.b, Limits{})
			var pe *ProofError
			if !errors.As(err, &pe) || pe.State != c.state || !strings.Contains(pe.Detail, c.want) {
				t.Fatalf("got %v, want %s naming %q", err, c.state, c.want)
			}
			if el := time.Since(start); el > 5*time.Second {
				t.Fatalf("took %s: not bounded", el)
			}
		})
	}
	// depth 255 operations plus the leaf is within the limit: the boundary is exactly the library's 256
	if _, err := ParseProof(deep(255), Limits{}); err != nil {
		t.Fatalf("depth 256: %v", err)
	}
	// the node limit counts during parsing: a tighter local limit refuses early
	if _, err := ParseProof(wide(50), Limits{ProofBytes: 1 << 20, Depth: 256, Nodes: 10}); err == nil || !strings.Contains(err.Error(), "more than 10 nodes") {
		t.Fatalf("local node limit: %v", err)
	}
}

// FuzzParseProof: the parser never panics and never runs away on any input.
func FuzzParseProof(f *testing.F) {
	f.Add(otsFile(sha([]byte("x")), attBitcoin(1)))
	f.Add(otsFile(sha([]byte("x")), []byte{tagFork}, opAppendB([]byte("a")), attPending("https://a"), []byte{opHexlify}, attBitcoin(9)))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseProof(b, Limits{ProofBytes: 1 << 16, Depth: 64, Nodes: 1000})
	})
}
