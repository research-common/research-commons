package btctime

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
)

// reparse re-serializes a modified header so its hash matches its fields.
func reparse(h Header) Header {
	raw := h.Serialize()
	p, _ := ParseHeader(raw[:])
	return p
}

func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	var he *HeaderError
	if !errors.As(err, &he) || he.Reason != reason {
		t.Fatalf("got %v, want %s", err, reason)
	}
}

// TestDisplayOrder: display hash <-> internal bytes, both ways, on the genesis block.
func TestDisplayOrder(t *testing.T) {
	mp := Mainnet()
	g, _ := ParseHeader(mp.Genesis[:])
	if g.Hash.String() != MainnetGenesisHash {
		t.Fatalf("genesis %s", g.Hash)
	}
	h, err := ParseDisplayHash(MainnetGenesisHash)
	if err != nil || h != g.Hash {
		t.Fatalf("round trip %v %v", h, err)
	}
	if g.Hash[31] != 0 || g.Hash[0] != 0x6f {
		t.Fatalf("internal order is not little-endian: %x", g.Hash)
	}
	v := &ChainView{GenesisHash: MainnetGenesisHash}
	if v.ChainID() != "bip122:000000000019d6689c085ae165831e93" {
		t.Fatalf("CAIP-2 %s", v.ChainID())
	}
}

// TestCompactTarget: Core's SetCompact / GetCompact vectors (arith_uint256_tests.cpp), incl. sign and overflow.
func TestCompactTarget(t *testing.T) {
	for _, c := range []struct {
		bits      uint32
		hex       string
		neg, over bool
		back      uint32
	}{
		{0x00000000, "0", false, false, 0},
		{0x01003456, "0", false, false, 0},
		{0x01123456, "12", false, false, 0x01120000},
		{0x02008000, "80", false, false, 0x02008000},
		{0x05009234, "92340000", false, false, 0x05009234},
		{0x04923456, "12345600", true, false, 0},
		{0x04123456, "12345600", false, false, 0x04123456},
		{0x1d00ffff, "ffff0000000000000000000000000000000000000000000000000000", false, false, 0x1d00ffff},
		{0xff123456, "", false, true, 0},
	} {
		got, neg, over := CompactToTarget(c.bits)
		if neg != c.neg || over != c.over {
			t.Fatalf("%08x: neg %v over %v", c.bits, neg, over)
		}
		if c.over {
			continue
		}
		if got.Text(16) != c.hex {
			t.Fatalf("%08x: %s", c.bits, got.Text(16))
		}
		if c.back != 0 && !c.neg && TargetToCompact(got) != c.back {
			t.Fatalf("%08x back %08x", c.bits, TargetToCompact(got))
		}
	}
	// genesis work: 2^256 / (target+1) = 0x100010001
	if w := Work(target(0x1d00ffff)); w.Text(16) != "100010001" {
		t.Fatalf("work %s", w.Text(16))
	}
}

// TestMainnetFixtureValidates: the real headers 356 832 – 359 000 validate under mainnet rules from an explicit
// bootstrap, including the retarget at 358 848 (bits 181686f5 → 18171a8b) computed exactly; the tip chainwork
// equals the sum. C-btc-14 (retarget across a real boundary) and C-btc-13 (90 real nTime decreases).
func TestMainnetFixtureValidates(t *testing.T) {
	c, _ := mainnetChain(t, fixtureTip)
	v := c.Snapshot()
	if v.TipHeight != fixtureTip || v.TipHash.String() != "000000000000000003cd67bf7e67dee8ee0b17c957199b4f16a7e44ba738be68" {
		t.Fatalf("tip %d %s", v.TipHeight, v.TipHash)
	}
	h, _ := v.HeaderAt(358848)
	if h.Bits != 0x18171a8b {
		t.Fatalf("retarget bits %08x", h.Bits)
	}
	work := new(big.Int).Set(workBelowFixture)
	for i := int64(fixtureBase); i <= fixtureTip; i++ {
		hh, _ := v.HeaderAt(i)
		work.Add(work, Work(target(hh.Bits)))
	}
	if work.Cmp(v.TipWork) != 0 {
		t.Fatalf("chainwork %s vs %s", v.TipWork.Text(16), work.Text(16))
	}
	decreases := 0
	for i := int64(fixtureBase + 1); i <= fixtureTip; i++ {
		a, _ := v.HeaderAt(i - 1)
		b, _ := v.HeaderAt(i)
		if b.Time < a.Time {
			decreases++
		}
	}
	if decreases != 90 {
		t.Fatalf("%d nTime decreases", decreases)
	}
}

// TestHeaderRules: C-btc-14. Each invalid header is refused with Core's reason, and each mutation is shown to reach
// its rule: a control header built the same way is accepted, and the refused header passes every earlier check.
func TestHeaderRules(t *testing.T) {
	conformance.Covers(t, "C-btc-14")
	hs := fixtureHeaders(t)
	// real data: the header at the retarget boundary with the pre-retarget bits carries real proof of work for
	// its own (correct) bits; re-mining is impossible, so the contextual check is shown on a synthetic chain below.
	c, now := mainnetChain(t, 358847)
	real, _ := ParseHeader(hs[358848-fixtureBase])
	wrong := real
	wrong.Bits = 0x181686f5 // the old period's bits: PoW-valid (easier) but not the retarget's value
	raw := wrong.Serialize()
	err := c.Add(raw[:], now)
	if err == nil {
		t.Fatal("pre-retarget bits accepted at a retarget boundary")
	}
	// either the hash no longer meets the (changed-header) target or the contextual rule fires; both refuse
	if !strings.Contains(err.Error(), "high-hash") && !strings.Contains(err.Error(), "retarget rule gives 18171a8b") {
		t.Fatalf("got %v", err)
	}
	if err := c.Add(hs[358848-fixtureBase], now); err != nil {
		t.Fatalf("control: the real header: %v", err)
	}

	// synthetic: a short retarget interval, so boundaries come quickly at the easy target
	p := testParams("rules", 0x200fffff)
	p.RetargetInterval, p.TargetTimespan = 4, 4*600
	s := newSynth(t, p)
	tip := s.extend(s.genesis(), 3, 1200, "") // three slow blocks: the boundary at 4 must make the target easier
	n := s.c.nodes[tip]
	want, _ := s.c.nextBits(n)
	if want == n.h.Bits {
		t.Fatalf("the synthetic retarget did not change the target (%08x)", want)
	}
	// clamping: an extremely slow period clamps at ×4, capped at the PoW limit
	if tt := target(want); tt.Cmp(new(big.Int).Mul(target(n.h.Bits), big.NewInt(4))) > 0 {
		t.Fatalf("retarget exceeded the ×4 clamp")
	}
	ok := s.next(tip, 0, 0, "ok")
	for _, c := range []struct {
		name, reason string
		h            Header
	}{
		{"PoW-valid header with the wrong contextual target", "bad-diffbits", mineHeader(Header{Version: 4, Prev: tip, MerkleRoot: ok.MerkleRoot, Time: ok.Time, Bits: n.h.Bits}, p.PowLimit)},
		{"bad compact target (negative)", "bad-diffbits", func() Header { h := ok; h.Bits = 0x04923456; return reparse(h) }()},
		{"bad compact target (zero)", "bad-diffbits", func() Header { h := ok; h.Bits = 0x01003456; return reparse(h) }()},
		{"target above the PoW limit", "bad-diffbits", func() Header { h := ok; h.Bits = 0x2100ffff; return reparse(h) }()},
		{"hash above target", "high-hash", mineFailing(ok, target(ok.Bits))},
		{"wrong predecessor", "prev-blk-not-found", mineHeader(Header{Version: 4, Prev: Hash(sha([]byte("nowhere"))), MerkleRoot: ok.MerkleRoot, Time: ok.Time, Bits: ok.Bits}, p.PowLimit)},
		{"median-time-past violation", "time-too-old", mineHeader(Header{Version: 4, Prev: tip, MerkleRoot: ok.MerkleRoot, Time: s.c.nodes[tip].parent.h.Time, Bits: ok.Bits}, p.PowLimit)},
		{"more than two hours ahead", "time-too-new", mineHeader(Header{Version: 4, Prev: tip, MerkleRoot: ok.MerkleRoot, Time: uint32(s.now.Unix() + 7201), Bits: ok.Bits}, p.PowLimit)},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := s.c.Epoch()
			raw := c.h.Serialize()
			wantReason(t, s.c.Add(raw[:], s.now), c.reason)
			if s.c.Epoch() != before {
				t.Fatal("a refused header changed the chain")
			}
		})
	}
	// MTP boundary: a time equal to the median is refused, one second above is accepted
	mtp := medianTimePast(n)
	eq := mineHeader(Header{Version: 4, Prev: tip, MerkleRoot: ok.MerkleRoot, Time: uint32(mtp), Bits: ok.Bits}, p.PowLimit)
	raw = eq.Serialize()
	wantReason(t, s.c.Add(raw[:], s.now), "time-too-old")
	if err := s.c.Add(ok.Raw[:], s.now); err != nil {
		t.Fatalf("control header refused: %v", err)
	}
	// version rule (BIP 34/66/65 style): below the minimum version from its height on
	p2 := testParams("versions", 0x207fffff)
	p2.MinVersion = [][2]int64{{2, 3}}
	s2 := newSynth(t, p2)
	t1 := s2.extend(s2.genesis(), 1, 0, "")
	old := s2.next(t1, 0, 0, "")
	old.Version = 2
	old = mineHeader(old, p2.PowLimit)
	raw = old.Serialize()
	wantReason(t, s2.c.Add(raw[:], s2.now), "bad-version")
}

// TestForkChoice: C-btc-15. A fork longer by height but with less work is not selected; two tips of equal work
// leave the chain unresolved above their fork point, and a bound on either branch has no live eligibility.
func TestForkChoice(t *testing.T) {
	conformance.Covers(t, "C-btc-15")
	// equal targets: the longer branch has more work and is selected
	p := testParams("forks", 0x207fffff)
	s := newSynth(t, p)
	base := s.extend(s.genesis(), 2, 0, "")
	short := s.extend(base, 2, 0, "short")
	long := s.extend(base, 5, 0, "long")
	v := s.c.Snapshot()
	if v.TipHash != long || v.TipHeight != 7 || v.IsActive(short, 4) {
		t.Fatalf("tip %s at %d", v.TipHash, v.TipHeight)
	}

	// mixed-work tree: nodes inserted by hand (the retarget rule is not under test here)
	c := newChain(p, "t", "test", 0)
	g, _ := ParseHeader(p.Genesis[:])
	root := &node{h: g, height: 0, work: big.NewInt(1)}
	c.insert(root)
	add := func(parent *node, w int64, tag string) *node {
		h := Header{Prev: parent.h.Hash, MerkleRoot: Hash(sha([]byte(tag)))}
		raw := h.Serialize()
		hh, _ := ParseHeader(raw[:])
		n := &node{h: hh, height: parent.height + 1, work: new(big.Int).Add(parent.work, big.NewInt(w)), parent: parent}
		c.insert(n)
		return n
	}
	heavy := add(add(add(root, 10, "h1"), 10, "h2"), 10, "h3") // height 3, work 31
	l := root
	for i := 0; i < 6; i++ {
		l = add(l, 4, "l"+string(rune('a'+i))) // height 6, work 25
	}
	v = c.Snapshot()
	if v.TipHash != heavy.h.Hash || v.Unresolved != 0 {
		t.Fatalf("longer-by-height, lower-work fork selected: tip %d", v.TipHeight)
	}
	if v.IsActive(l.h.Hash, 6) {
		t.Fatal("light branch active")
	}
	// equal work: a second branch of total work 31
	eq := add(add(root, 15, "e1"), 15, "e2")
	v = c.Snapshot()
	if v.Unresolved != 2 || v.TipHeight != 0 {
		t.Fatalf("equal-work tips: unresolved %d, accepted tip %d", v.Unresolved, v.TipHeight)
	}
	if v.IsActive(eq.h.Hash, 2) || v.IsActive(heavy.h.Hash, 3) {
		t.Fatal("a tied branch is on the accepted chain")
	}
}

// TestNetworkPolicy: C-btc-16. A testnet/signet/regtest chain under mainnet policy is refused as production
// evidence, even when the proof verifies against it.
func TestNetworkPolicy(t *testing.T) {
	conformance.Covers(t, "C-btc-16")
	for _, net := range []string{"testnet", "signet", "regtest"} {
		w := newWorld(t)
		w.authored("A1", "A", "X")
		w.anchorAt("AA", "A", 3)
		s := w.chain(10)
		s.p.Network = net
		v := s.fresh(w.blobs)
		v.View.Network = net
		// control: the same proof is verified when the policy names that network
		ctl := *v
		ctl.Policy.Network = net
		if e := ctl.Evaluate(w.sts["AA"]); e.State != StateVerified {
			t.Fatalf("%s control: %s", net, e)
		}
		v.Policy = DefaultPolicy() // mainnet only
		e := v.Evaluate(w.sts["AA"])
		if e.Live() || e.Quality == QualityBitcoin || !strings.Contains(e.Why, "production evidence") {
			t.Fatalf("%s under mainnet policy: %s", net, e)
		}
	}
}

// TestNTimeDoesNotOrder: C-btc-13. Two anchors in blocks n and n+1 where block n+1's nTime is earlier than block
// n's: priority follows height.
func TestNTimeDoesNotOrder(t *testing.T) {
	conformance.Covers(t, "C-btc-13")
	w := newWorld(t)
	w.authored("A1", "A", "X", "licence", "CC0-1.0")
	w.anchorAt("AA", "A", 5)
	w.authored("B1", "BB", "X", "licence", "MIT")
	w.anchorAt("BA", "BB", 6)
	s := newSynth(t, testParams("testchain", 0x207fffff))
	s.roots = w.roots
	tip := s.extend(s.genesis(), 5, 0, "")
	h6 := s.next(tip, -300, 0, "") // block 6 is stamped 300 s before block 5 (still above the MTP)
	if err := s.c.Add(h6.Raw[:], s.now); err != nil {
		t.Fatal(err)
	}
	s.extend(h6.Hash, 10, 0, "")
	v := s.fresh(w.blobs)
	h5, _ := v.View.HeaderAt(5)
	if h6.Time >= h5.Time {
		t.Fatal("fixture: nTime did not decrease")
	}
	everyOrder(t, w, "X", v, func(a *resolveArtifact) {
		if a.Default == nil || a.Default.Claims[0].Signer != w.signer("A") {
			t.Fatalf("%s", a.Render())
		}
		has(t, a.Render(), "later claimant")
	})
	// and on real data: block 356 895's nTime is below 356 894's, heights order them
	c, _ := mainnetChain(t, fixtureTip)
	rv := c.Snapshot()
	a, _ := rv.HeaderAt(356894)
	b, _ := rv.HeaderAt(356895)
	if b.Time >= a.Time {
		t.Fatal("fixture: real decrease not found")
	}
	ea := Evidence{State: StateVerified, Quality: QualityBitcoin, Network: "mainnet", BlockHeight: 356894, HeaderTime: a.Time}
	eb := Evidence{State: StateVerified, Quality: QualityBitcoin, Network: "mainnet", BlockHeight: 356895, HeaderTime: b.Time}
	if Compare(ea, eb, 0) != EarlierCommitment || Compare(eb, ea, 0) != Later {
		t.Fatalf("relation %s", Compare(ea, eb, 0))
	}
}
