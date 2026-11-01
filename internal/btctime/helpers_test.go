package btctime

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// --- proof writer (the test's own serializer for ots-detached-v1) -------------------------------------------

func uvar(n uint64) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, b|0x80)
			continue
		}
		return append(out, b)
	}
}

func vbytes(b []byte) []byte { return append(uvar(uint64(len(b))), b...) }

func otsFile(fileDigest []byte, tree ...[]byte) []byte {
	out := append([]byte{}, HeaderMagic...)
	out = append(out, 0x01, opSHA256)
	out = append(out, fileDigest...)
	for _, t := range tree {
		out = append(out, t...)
	}
	return out
}

func opAppendB(arg []byte) []byte  { return append([]byte{opAppend}, vbytes(arg)...) }
func opPrependB(arg []byte) []byte { return append([]byte{opPrepend}, vbytes(arg)...) }
func opSHA256B() []byte            { return []byte{opSHA256} }
func attBitcoin(h uint64) []byte {
	return append(append([]byte{tagAttestation}, TagBitcoin[:]...), vbytes(uvar(h))...)
}
func attPending(uri string) []byte {
	return append(append([]byte{tagAttestation}, TagPending[:]...), vbytes(vbytes([]byte(uri)))...)
}
func attOther(tag [8]byte, payload []byte) []byte {
	return append(append([]byte{tagAttestation}, tag[:]...), vbytes(payload)...)
}
func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func sha(b ...[]byte) []byte {
	h := sha256.New()
	for _, x := range b {
		h.Write(x)
	}
	return h.Sum(nil)
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- synthetic chains (test-only easy proof of work; never reachable from production configuration) --------

var baseTime = time.Unix(1_700_000_000, 0)

// testParams is a regtest-like network: the easiest target is 0x207fffff, so about one nonce in two mines.
func testParams(name string, genesisBits uint32) Params {
	lim := new(big.Int).Lsh(big.NewInt(0x7fffff), 232)
	g := mineHeader(Header{Version: 4, MerkleRoot: Hash(sha256.Sum256([]byte("genesis " + name))), Time: uint32(baseTime.Unix()), Bits: genesisBits}, lim)
	return Params{Network: name, Genesis: g.Raw, PowLimit: lim, RetargetInterval: 1 << 40, TargetTimespan: 6000, MaxFutureSeconds: 7200}
}

func mineHeader(h Header, lim *big.Int) Header {
	for n := uint32(0); ; n++ {
		h.Nonce = n
		raw := h.Serialize()
		p, _ := ParseHeader(raw[:])
		if CheckProofOfWork(p, lim) == nil {
			return p
		}
	}
}

// mineFailing finds a nonce whose hash is above the target (for high-hash).
func mineFailing(h Header, lim *big.Int) Header {
	for n := uint32(0); ; n++ {
		h.Nonce = n
		raw := h.Serialize()
		p, _ := ParseHeader(raw[:])
		if err := CheckProofOfWork(p, lim); err != nil && strings.HasPrefix(err.Error(), "high-hash") {
			return p
		}
	}
}

// synth builds blocks on a Chain. Roots fixes the Merkle root at a height; others get a filler root.
type synth struct {
	t     testing.TB
	c     *Chain
	p     Params
	now   time.Time
	roots map[int64][]byte
}

func newSynth(t testing.TB, p Params) *synth {
	t.Helper()
	c, err := NewChain(p, "test-headers")
	if err != nil {
		t.Fatal(err)
	}
	return &synth{t: t, c: c, p: p, now: baseTime.Add(1000 * 24 * time.Hour), roots: map[int64][]byte{}}
}

func (s *synth) genesis() Hash {
	g, _ := ParseHeader(s.p.Genesis[:])
	return g.Hash
}

// next mines the header after parent. dt is the time step (0 = 600 s); bits 0 = the retarget rule's value.
func (s *synth) next(parent Hash, dt int64, bits uint32, tweak string) Header {
	s.t.Helper()
	pn := s.c.nodes[parent]
	if pn == nil {
		s.t.Fatalf("no parent %s", parent)
	}
	if dt == 0 {
		dt = 600
	}
	if bits == 0 {
		var err error
		if bits, err = s.c.nextBits(pn); err != nil {
			s.t.Fatal(err)
		}
	}
	height := pn.height + 1
	root := s.roots[height]
	if root == nil {
		root = sha([]byte(fmt.Sprintf("filler %d %s", height, tweak)))
	}
	h := Header{Version: 4, Prev: parent, MerkleRoot: Hash(root), Time: uint32(int64(pn.h.Time) + dt), Bits: bits}
	return mineHeader(h, s.p.PowLimit)
}

// extend adds n blocks on parent and returns the new tip.
func (s *synth) extend(parent Hash, n int, dt int64, tweak string) Hash {
	s.t.Helper()
	for i := 0; i < n; i++ {
		h := s.next(parent, dt, 0, tweak)
		if err := s.c.Add(h.Raw[:], s.now); err != nil {
			s.t.Fatalf("extend: %v", err)
		}
		parent = h.Hash
	}
	return parent
}

// policy is the default policy pointed at the synthetic network.
func (s *synth) policy() Policy {
	p := DefaultPolicy()
	p.Network, p.Genesis = s.p.Network, s.genesis().String()
	return p
}

// fresh returns a verifier over a fresh snapshot: synced a minute ago, the clock ten minutes past the tip.
func (s *synth) fresh(blobs BlobSource) *Verifier {
	v := s.c.Snapshot()
	now := time.Unix(int64(v.TipTime), 0).Add(10 * time.Minute)
	s.c.MarkSynced(now.Add(-time.Minute))
	return &Verifier{Policy: s.policy(), View: s.c.Snapshot(), Blobs: blobs, Now: func() time.Time { return now }}
}

// --- mainnet fixture ----------------------------------------------------------------------------------------

const (
	fixtureBase = 356832
	fixtureTip  = 359000
)

// workBelowFixture is the chainwork through height 356 831 (testdata/SOURCES.md).
var workBelowFixture, _ = new(big.Int).SetString("6f293e337e48534b58620", 16)

func fixtureHeaders(t testing.TB) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "mainnet-356832-359000.headers"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != (fixtureTip-fixtureBase+1)*HeaderSize {
		t.Fatalf("fixture is %d bytes", len(raw))
	}
	var out [][]byte
	for i := 0; i < len(raw); i += HeaderSize {
		out = append(out, raw[i:i+HeaderSize])
	}
	return out
}

func fixtureFile(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// mainnetChain validates the fixture from an 11-header bootstrap at 356 832 up to height upTo.
func mainnetChain(t testing.TB, upTo int64) (*Chain, time.Time) {
	t.Helper()
	hs := fixtureHeaders(t)
	c, err := NewChainFrom(Mainnet(), "fixture", Bootstrap{Height: fixtureBase, Headers: hs[:11], WorkBelow: workBelowFixture})
	if err != nil {
		t.Fatal(err)
	}
	last, _ := ParseHeader(hs[upTo-fixtureBase])
	now := time.Unix(int64(last.Time), 0).Add(10 * time.Minute)
	for i := 11; i <= int(upTo-fixtureBase); i++ {
		if err := c.Add(hs[i], now); err != nil {
			t.Fatalf("height %d: %v", fixtureBase+i, err)
		}
	}
	c.MarkSynced(now.Add(-time.Minute))
	return c, now
}

// --- statements, logs and the resolver -----------------------------------------------------------------------

func testKey(name string) wire.Key {
	h := sha256.Sum256([]byte("research-commons go test btctime key " + name))
	if len(name)%2 == 0 {
		return wire.EIP191Key{Scalar: h[:]}
	}
	return wire.Ed25519Key{Seed: h[:]}
}

func obj(kv ...any) *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	for i := 0; i < len(kv); i += 2 {
		k := kv[i].(string)
		o.Keys = append(o.Keys, k)
		switch v := kv[i+1].(type) {
		case string:
			o.Members[k] = canon.String(v)
		case int:
			o.Members[k] = canon.Int(v)
		case bool:
			o.Members[k] = canon.Bool(v)
		case []string:
			a := canon.Array{}
			for _, s := range v {
				a = append(a, canon.String(s))
			}
			o.Members[k] = a
		case canon.Value:
			o.Members[k] = v
		default:
			panic(fmt.Sprintf("obj: %T", v))
		}
	}
	slices.SortFunc(o.Keys, canon.CompareKeys)
	return o
}

func dig(name string) string { return "sha256:" + hex.EncodeToString(sha([]byte(name))) }

type world struct {
	t     testing.TB
	keys  map[string]wire.Key
	head  map[string]string
	seq   map[string]int64
	lines [][]byte
	ids   map[string]string
	sts   map[string]*wire.Statement
	blobs MapBlobs
	// roots: the Merkle root each attested height must carry (filled by the stamp helpers)
	roots map[int64][]byte
}

func newWorld(t testing.TB) *world {
	return &world{t: t, keys: map[string]wire.Key{}, head: map[string]string{}, seq: map[string]int64{}, ids: map[string]string{},
		sts: map[string]*wire.Statement{}, blobs: MapBlobs{}, roots: map[int64][]byte{}}
}

func (w *world) key(n string) wire.Key {
	k, ok := w.keys[n]
	if !ok {
		k = testKey(n)
		w.keys[n] = k
	}
	return k
}

func (w *world) signer(n string) string { return w.key(n).Signer() }

func (w *world) sign(name, n, kind string, body *canon.Object) string {
	w.t.Helper()
	s := w.seq[n]
	line, id := wire.Sign(wire.Draft{Kind: kind, Seq: s, Prev: w.head[n], TS: fmt.Sprintf("2026-10-16T02:%02d:%02dZ", s/60%60, s%60), Body: body}, w.key(n))
	st, err := wire.Read(line)
	if err != nil {
		w.t.Fatalf("%s: %v", name, err)
	}
	w.head[n], w.seq[n] = id, s+1
	w.lines = append(w.lines, line)
	w.ids[name], w.sts[name] = id, st
	return id
}

func (w *world) authored(name, n, x string, kv ...any) string {
	b := []any{"content", canon.Value(obj("digest", dig(x), "size", len(x)))}
	if !slices.Contains(kv, any("type")) {
		b = append(b, "type", "dataset")
	}
	for i := 0; i < len(kv); i += 2 {
		if kv[i] == "prov" {
			p := kv[i+1].([]string)
			in := []string{}
			for _, y := range p[1:] {
				in = append(in, dig(y))
			}
			b = append(b, "provenance", canon.Value(obj("workflow", dig(p[0]), "inputs", in)))
			continue
		}
		b = append(b, kv[i], kv[i+1])
	}
	return w.sign(name, n, "authored", obj(b...))
}

// anchorProof signs an anchors statement by key n covering its head, with the given proof bytes stored as a blob.
func (w *world) anchorProof(name, n string, proof []byte, format string) string {
	d := w.blobs.Put(proof)
	return w.sign(name, n, "anchors", obj("covered", w.head[n], "proof", d, "proof_format", format))
}

func nonce(name string) []byte { return sha([]byte("nonce " + name))[:16] }

// anchorAt anchors key n's head with a proof that a block at height commits to it alone. The block's Merkle root
// is recorded for the chain builder.
func (w *world) anchorAt(name, n string, height int64) string {
	w.t.Helper()
	cov := unhex(w.t, w.head[n])
	leaf := sha(cov, nonce(name))
	if r, ok := w.roots[height]; ok && string(r) != string(leaf) {
		w.t.Fatalf("height %d already carries another root; use sameBlock", height)
	}
	w.roots[height] = leaf
	return w.anchorProof(name, n, otsFile(cov, opAppendB(nonce(name)), opSHA256B(), attBitcoin(uint64(height))), ProofFormat)
}

// sameBlock anchors the heads of keys n1 and n2 in one block: root = sha256(leaf1 || leaf2).
func (w *world) sameBlock(height int64, name1, n1, name2, n2 string) {
	w.t.Helper()
	c1, c2 := unhex(w.t, w.head[n1]), unhex(w.t, w.head[n2])
	l1, l2 := sha(c1, nonce(name1)), sha(c2, nonce(name2))
	w.roots[height] = sha(l1, l2)
	w.anchorProof(name1, n1, otsFile(c1, opAppendB(nonce(name1)), opSHA256B(), opAppendB(l2), opSHA256B(), attBitcoin(uint64(height))), ProofFormat)
	w.anchorProof(name2, n2, otsFile(c2, opAppendB(nonce(name2)), opSHA256B(), opPrependB(l1), opSHA256B(), attBitcoin(uint64(height))), ProofFormat)
}

// chain mines a synthetic chain to tip carrying the world's roots.
func (w *world) chain(tip int64) *synth {
	w.t.Helper()
	s := newSynth(w.t, testParams("testchain", 0x207fffff))
	s.roots = w.roots
	s.extend(s.genesis(), int(tip), 0, "")
	return s
}

func (w *world) logs(order []int) *keylog.Store {
	w.t.Helper()
	s := keylog.NewStore()
	if order == nil {
		for i := range w.lines {
			order = append(order, i)
		}
	}
	for _, i := range order {
		st, err := wire.Read(w.lines[i])
		if err != nil {
			w.t.Fatal(err)
		}
		if kept, err := s.Log(st.Signer).Add(w.lines[i]); err != nil && kept == nil {
			w.t.Fatalf("line %d refused: %v", i, err)
		}
	}
	return s
}

func (w *world) resolver(order []int, v *Verifier) *resolve.Resolver {
	return resolve.New(w.logs(order), resolve.WithTimeVerifier(TimeVerifier{V: v}))
}

// orders: file order plus a seeded sample of delivery orders (a full sweep is the resolver's property tests' job).
func orders(n int, seed uint64) [][]int {
	out := [][]int{nil}
	x := seed | 1
	for k := 0; k < 12; k++ {
		o := make([]int, n)
		for i := range o {
			o[i] = i
		}
		for i := n - 1; i > 0; i-- {
			x ^= x << 13
			x ^= x >> 7
			x ^= x << 17
			j := int(x % uint64(i+1))
			o[i], o[j] = o[j], o[i]
		}
		out = append(out, o)
	}
	return out
}

type resolveArtifact = resolve.Artifact

type wireStatement = wire.Statement

// countingBlobs records every digest asked for.
type countingBlobs struct {
	inner BlobSource
	asked []string
}

func (c *countingBlobs) OpenBlob(d string) (io.ReadCloser, bool) {
	c.asked = append(c.asked, d)
	return c.inner.OpenBlob(d)
}

// batchBlobs runs hook on every open: a stand-in for the chain changing while a batch runs.
type batchBlobs struct {
	inner BlobSource
	hook  func()
}

func (b *batchBlobs) OpenBlob(d string) (io.ReadCloser, bool) {
	b.hook()
	return b.inner.OpenBlob(d)
}

// everyOrder resolves blob x under several delivery orders and requires one rendering.
func everyOrder(t *testing.T, w *world, x string, v *Verifier, check func(*resolveArtifact)) {
	t.Helper()
	var first string
	for _, o := range orders(len(w.lines), uint64(len(w.lines))*7919) {
		a := w.resolver(o, v).Artifact(dig(x))
		check(a)
		if got := a.Render(); first == "" {
			first = got
		} else if got != first {
			t.Fatalf("order %v changed the answer:\n%s\nvs\n%s", o, got, first)
		}
	}
}

func has(t testing.TB, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("missing %q in:\n%s", sub, s)
	}
}

func hasNot(t testing.TB, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Fatalf("unexpected %q in:\n%s", sub, s)
	}
}

func exitOf(a *resolve.Artifact) int {
	c, _ := a.VerifyExit()
	return c
}

func le32(n uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return b
}
