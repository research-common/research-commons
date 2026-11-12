package btctime

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sort"
	"sync"
	"time"
)

// A headers-only chain provider (bitcoin-time note §6.1). It validates, with the parameters it was built for:
// genesis identity or an explicit local bootstrap; 80-byte serialization, hashes and prev linkage; compact-target
// decoding; actual proof of work; the exact retarget (rounding and clamping as Bitcoin Core computes them);
// nTime above the median of the previous 11 (time-too-old); future-time admission against the local clock
// (time-too-new); the minimum block version after BIP 34, 66 and 65; cumulative chainwork with greatest-work
// selection; reorgs; lookup by height and hash. It never opens a connection: Add takes headers from whatever
// explicit sync command obtained them, and transport is never a substitute for these checks.
//
// What it does not do: testnet's minimum-difficulty exception and other non-mainnet rules (their headers are
// refused as production evidence anyway, §7), block bodies, and checkpoints shipped with the tool (there are none;
// a bootstrap is a value the reader configures, §17 decided 3).

// Params are a network's header rules.
type Params struct {
	Network string // "mainnet", or a name that is refused as production evidence under the default policy
	Genesis [HeaderSize]byte
	// PowLimit is the easiest admitted target.
	PowLimit *big.Int
	// RetargetInterval and TargetTimespan (seconds) drive the difficulty adjustment.
	RetargetInterval int64
	TargetTimespan   int64
	// MinVersion lists (height, version): from that height on, a header's version is at least that version.
	MinVersion [][2]int64
	// MaxFutureSeconds is Core's MAX_FUTURE_BLOCK_TIME (2 hours).
	MaxFutureSeconds int64
}

// Mainnet returns Bitcoin mainnet's header rules (Bitcoin Core chainparams).
func Mainnet() Params {
	lim, _ := new(big.Int).SetString("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	var g [HeaderSize]byte
	copy(g[:], mustHex(mainnetGenesisHex))
	return Params{
		Network: "mainnet", Genesis: g, PowLimit: lim,
		RetargetInterval: 2016, TargetTimespan: 14 * 24 * 60 * 60,
		MinVersion:       [][2]int64{{227931, 2}, {363725, 3}, {388381, 4}}, // BIP 34, 66, 65 heights
		MaxFutureSeconds: 2 * 60 * 60,
	}
}

// mainnetGenesisHex is block 0's header (Bitcoin Core chainparams.cpp, CreateGenesisBlock).
const mainnetGenesisHex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"

// MainnetGenesisHash is block 0's hash in display order.
const MainnetGenesisHash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Bootstrap is an explicit local trust root (§6.1): consecutive headers the reader accepts without validating
// them, starting at Height, with the chainwork before the first. The first header must start a retarget period
// and there must be at least 11 of them, so the exact retarget and median-time-past rules hold from the first
// validated header on. A height-to-time table is not a bootstrap. The tool ships none.
type Bootstrap struct {
	Height    int64
	Headers   [][]byte
	WorkBelow *big.Int
}

// ID is the bootstrap identity every ChainView names: a content hash of what the reader chose to trust.
func (b Bootstrap) ID() string {
	h := sha256.New()
	fmt.Fprintf(h, "bootstrap height %d work %s\n", b.Height, b.WorkBelow)
	for _, x := range b.Headers {
		h.Write(x)
	}
	return "bootstrap:sha256:" + hex.EncodeToString(h.Sum(nil))
}

// node is one held header, compact: its 80 raw bytes (the only copy; fields are read from them on demand), its
// hash (computed once, at admission), its height, the cumulative chainwork up to and including it as an in-place
// 256-bit value, and its parent. No per-header heap object besides the node itself: a chain synced from genesis
// holds about a million of them, and every read command loads and re-validates them all.
type node struct {
	raw    [HeaderSize]byte
	hash   Hash
	height int64
	work   u256 // cumulative
	parent *node
}

func newNode(h Header, height int64, work u256, parent *node) *node {
	return &node{raw: h.Raw, hash: h.Hash, height: height, work: work, parent: parent}
}

// header is the parsed header, from the raw bytes and the hash computed at admission (no second hash).
func (n *node) header() Header { return headerFrom(n.raw, n.hash) }

func (n *node) time() uint32       { return binary.LittleEndian.Uint32(n.raw[68:72]) }
func (n *node) bits() uint32       { return binary.LittleEndian.Uint32(n.raw[72:76]) }
func (n *node) merkleRoot() []byte { return n.raw[36:68] }

// powEntry is what one compact target decodes to, kept per chain: the target and the work of a header that
// carries it. Targets change once per retarget period, so a chain holds a few hundred of these at most.
type powEntry struct{ target, work u256 }

// maxPowCache bounds the per-chain cache of decoded targets; headers past it are checked without caching.
const maxPowCache = 4096

// Chain is a validated header tree. It is safe for concurrent use; readers take immutable snapshots.
type Chain struct {
	mu        sync.Mutex
	p         Params
	provider  string
	bootstrap string
	base      int64 // height of the lowest held header
	nodes     map[Hash]*node
	pow       map[uint32]powEntry // valid compact targets seen, decoded (checkPoW)
	lastSync  time.Time
	epoch     uint64
	// boot is the explicit bootstrap the chain started from (nil from genesis), kept so the header database can
	// persist the trust root the reader chose alongside the headers validated on top of it.
	boot *Bootstrap
	// view is the last snapshot built, reused while the epoch is unchanged: building one walks every held
	// header, which is the cost of a verify on a chain synced from genesis.
	view *ChainView
}

// HeaderError is a header the chain refused, with Core's reject reason where there is one.
type HeaderError struct {
	Reason string
	Detail string
}

func (e *HeaderError) Error() string { return e.Reason + ": " + e.Detail }

func refuse(reason, f string, a ...any) error {
	return &HeaderError{Reason: reason, Detail: fmt.Sprintf(f, a...)}
}

// NewChain starts a chain at the network's genesis block.
func NewChain(p Params, provider string) (*Chain, error) {
	g, err := ParseHeader(p.Genesis[:])
	if err != nil {
		return nil, err
	}
	if err := CheckProofOfWork(g, p.PowLimit); err != nil {
		return nil, err
	}
	c := newChain(p, provider, "genesis:"+g.Hash.String(), 0)
	pe, err := c.checkPoW(g)
	if err != nil {
		return nil, err
	}
	c.insert(newNode(g, 0, pe.work, nil))
	return c, nil
}

// NewChainFrom starts a chain at an explicit local bootstrap.
func NewChainFrom(p Params, provider string, b Bootstrap) (*Chain, error) {
	if len(b.Headers) < 11 {
		return nil, errors.New("bootstrap needs at least 11 consecutive headers (median time past)")
	}
	if b.Height%p.RetargetInterval != 0 {
		return nil, fmt.Errorf("bootstrap height %d does not start a retarget period", b.Height)
	}
	if b.WorkBelow == nil || b.WorkBelow.Sign() < 0 {
		return nil, errors.New("bootstrap names no chainwork below its first header")
	}
	c := newChain(p, provider, b.ID(), b.Height)
	c.boot = &Bootstrap{Height: b.Height, WorkBelow: new(big.Int).Set(b.WorkBelow)}
	for _, raw := range b.Headers {
		c.boot.Headers = append(c.boot.Headers, slices.Clone(raw))
	}
	var prev *node
	work, ok := u256FromBig(b.WorkBelow)
	if !ok {
		return nil, errors.New("bootstrap chainwork does not fit in 256 bits")
	}
	for i, raw := range b.Headers {
		h, err := ParseHeader(raw)
		if err != nil {
			return nil, err
		}
		if prev != nil && h.Prev != prev.hash {
			return nil, fmt.Errorf("bootstrap header %d does not link to the one before", b.Height+int64(i))
		}
		pe, err := c.checkPoW(h)
		if err != nil {
			return nil, fmt.Errorf("bootstrap header %d: %w", b.Height+int64(i), err)
		}
		if work, ok = work.add(pe.work); !ok {
			return nil, fmt.Errorf("bootstrap header %d: cumulative chainwork overflows 256 bits", b.Height+int64(i))
		}
		n := newNode(h, b.Height+int64(i), work, prev)
		c.insert(n)
		prev = n
	}
	return c, nil
}

func newChain(p Params, provider, bootstrap string, base int64) *Chain {
	return &Chain{p: p, provider: provider, bootstrap: bootstrap, base: base, nodes: map[Hash]*node{}, pow: map[uint32]powEntry{}}
}

// checkPoW is CheckProofOfWork with the decoded target and its work cached per compact value: the comparison runs
// on in-place 256-bit values, and a refusal is CheckProofOfWork's own (same reason, same text). On success it
// returns the header's target and work.
func (c *Chain) checkPoW(h Header) (powEntry, error) {
	pe, ok := c.pow[h.Bits]
	if !ok {
		if err := CheckProofOfWork(h, c.p.PowLimit); err != nil {
			return pe, err
		}
		t := target(h.Bits)
		pe.target, _ = u256FromBig(t)     // within the PoW limit: fits
		pe.work, _ = u256FromBig(Work(t)) // 2^256/(t+1) with t >= 1: fits
		if len(c.pow) < maxPowCache {
			c.pow[h.Bits] = pe
		}
		return pe, nil
	}
	if hashU256(h.Hash).cmp(pe.target) > 0 {
		return pe, CheckProofOfWork(h, c.p.PowLimit) // the refusal, worded as CheckProofOfWork words it
	}
	return pe, nil
}

func target(bits uint32) *big.Int {
	t, _, _ := CompactToTarget(bits)
	return t
}

func (c *Chain) insert(n *node) {
	c.nodes[n.hash] = n
	c.epoch++
}

// Add validates one header against the chain it extends and the local clock now, and keeps it. A header already
// held is accepted again without effect. A refused header leaves the chain unchanged; one refused as time-too-new
// may be offered again later.
func (c *Chain) Add(raw []byte, now time.Time) error {
	h, err := ParseHeader(raw)
	if err != nil {
		return refuse("bad-header", "%v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.nodes[h.Hash]; ok {
		return nil
	}
	parent, ok := c.nodes[h.Prev]
	if !ok {
		return refuse("prev-blk-not-found", "header %s names predecessor %s, which this chain does not hold", h.Hash, h.Prev)
	}
	pe, err := c.checkPoW(h)
	if err != nil {
		var r string
		if bytes.HasPrefix([]byte(err.Error()), []byte("high-hash")) {
			r = "high-hash"
		} else {
			r = "bad-diffbits"
		}
		return refuse(r, "%v", err)
	}
	height := parent.height + 1
	want, err := c.nextBits(parent)
	if err != nil {
		return err
	}
	if h.Bits != want {
		return refuse("bad-diffbits", "header %s at height %d has bits %08x; the retarget rule gives %08x", h.Hash, height, h.Bits, want)
	}
	if mtp := medianTimePast(parent); int64(h.Time) <= mtp {
		return refuse("time-too-old", "header %s time %d is not above the median time past %d", h.Hash, h.Time, mtp)
	}
	if int64(h.Time) > now.Unix()+c.p.MaxFutureSeconds {
		return refuse("time-too-new", "header %s time %d is more than %ds ahead of the local clock", h.Hash, h.Time, c.p.MaxFutureSeconds)
	}
	for _, mv := range c.p.MinVersion {
		if height >= mv[0] && int64(h.Version) < mv[1] {
			return refuse("bad-version", "header %s version %d below %d required from height %d", h.Hash, h.Version, mv[1], mv[0])
		}
	}
	work, ok := parent.work.add(pe.work)
	if !ok {
		return refuse("bad-diffbits", "header %s: cumulative chainwork overflows 256 bits", h.Hash)
	}
	c.insert(newNode(h, height, work, parent))
	return nil
}

// held is what the header database persists: the bootstrap (nil from genesis), every other held header in an
// order where each follows its parent (height, then hash), and the last successful sync. The genesis header and
// the bootstrap's own headers are not in rest: NewChain and NewChainFrom insert them.
func (c *Chain) held() (boot *Bootstrap, rest [][]byte, lastSync time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	skip := map[Hash]bool{}
	if c.boot != nil {
		for _, raw := range c.boot.Headers {
			skip[dsha256(raw)] = true
		}
	}
	var ns []*node
	for _, n := range c.nodes {
		if n.parent == nil || skip[n.hash] {
			continue
		}
		ns = append(ns, n)
	}
	sort.Slice(ns, func(i, j int) bool {
		if ns[i].height != ns[j].height {
			return ns[i].height < ns[j].height
		}
		return bytes.Compare(ns[i].hash[:], ns[j].hash[:]) < 0
	})
	for _, n := range ns {
		rest = append(rest, n.raw[:])
	}
	return c.boot, rest, c.lastSync
}

// Len is the number of headers the chain holds (every branch).
func (c *Chain) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.nodes)
}

// Params returns the network rules the chain validates with.
func (c *Chain) Params() Params { return c.p }

// Epoch counts changes to the chain; a snapshot carries the epoch it was taken at.
func (c *Chain) Epoch() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch
}

// MarkSynced records a successful sync at t: the time freshness policy measures from (§7).
func (c *Chain) MarkSynced(t time.Time) {
	c.mu.Lock()
	c.lastSync = t
	c.epoch++
	c.mu.Unlock()
}

// nextBits is Core's GetNextWorkRequired without the testnet exceptions: unchanged within a period; at a period
// start, the previous period's actual timespan (last header's time minus the period's first header's time),
// clamped to [timespan/4, timespan*4], scales the last target, capped at the PoW limit, then compact-encoded.
func (c *Chain) nextBits(last *node) (uint32, error) {
	height := last.height + 1
	if height%c.p.RetargetInterval != 0 {
		return last.bits(), nil
	}
	first := last
	for i := int64(0); i < c.p.RetargetInterval-1; i++ {
		if first.parent == nil {
			return 0, refuse("bad-diffbits", "retarget at height %d needs the header at height %d, which precedes this chain's bootstrap", height, height-c.p.RetargetInterval)
		}
		first = first.parent
	}
	span := int64(last.time()) - int64(first.time())
	span = max(span, c.p.TargetTimespan/4)
	span = min(span, c.p.TargetTimespan*4)
	t := target(last.bits())
	t.Mul(t, big.NewInt(span))
	t.Div(t, big.NewInt(c.p.TargetTimespan))
	if t.Cmp(c.p.PowLimit) > 0 {
		t.Set(c.p.PowLimit)
	}
	return TargetToCompact(t), nil
}

// medianTimePast is Core's GetMedianTimePast: the median of the last 11 header times (fewer near the root).
func medianTimePast(n *node) int64 {
	var buf [11]int64
	ts := buf[:0]
	for i := 0; i < 11 && n != nil; i++ {
		ts = append(ts, int64(n.time()))
		n = n.parent
	}
	slices.Sort(ts)
	return ts[len(ts)/2]
}

// Snapshot returns an immutable view of the chain now (§6.3). One batch of verifications uses one snapshot, so a
// header from one view is never compared with another view's tip.
//
// A view is immutable, so one built at the current epoch is shared: every snapshot taken before the chain changes
// returns the same tree (with its own copy of TipWork, the one exported pointer).
func (c *Chain) Snapshot() *ChainView {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.view == nil || c.view.Epoch != c.epoch {
		c.view = c.snapshot()
	}
	v := *c.view
	v.TipWork = new(big.Int).Set(c.view.TipWork)
	return &v
}

// snapshot builds a view of the chain now; the caller holds c.mu.
func (c *Chain) snapshot() *ChainView {
	v := &ChainView{
		Network: c.p.Network, Provider: c.provider, Mode: ModeHeadersSPV, Bootstrap: c.bootstrap,
		LastSync: c.lastSync, Epoch: c.epoch, Base: c.base,
	}
	g, _ := ParseHeader(c.p.Genesis[:])
	v.GenesisHash = g.Hash.String()
	// greatest cumulative work; tips that tie at the greatest work leave the chain above their fork point unresolved
	var best []*node
	for _, n := range c.nodes {
		switch {
		case len(best) == 0 || n.work.cmp(best[0].work) > 0:
			best = []*node{n}
		case n.work.cmp(best[0].work) == 0:
			best = append(best, n)
		}
	}
	sort.Slice(best, func(i, j int) bool { return bytes.Compare(best[i].hash[:], best[j].hash[:]) < 0 })
	tip := best[0]
	if len(best) > 1 {
		tip = forkPoint(best)
		v.Unresolved = len(best)
	}
	// the accepted chain, indexed by height above the base: one pointer per header, not a map entry
	v.active = make([]*node, tip.height-c.base+1)
	for n := tip; n != nil; n = n.parent {
		v.active[n.height-c.base] = n
	}
	for _, n := range c.nodes {
		if a := v.activeAt(n.height); a != n {
			v.others = append(v.others, n)
		}
	}
	v.tip = tip
	v.TipHeight, v.TipHash, v.TipWork, v.TipTime = tip.height, tip.hash, tip.work.big(), tip.time()
	return v
}

// forkPoint is the highest node every one of tips descends from.
func forkPoint(tips []*node) *node {
	on := map[*node]int{}
	for _, t := range tips {
		for n := t; n != nil; n = n.parent {
			on[n]++
		}
	}
	for n := tips[0]; n != nil; n = n.parent {
		if on[n] == len(tips) {
			return n
		}
	}
	return nil
}

// Validation modes disclosed on every verdict (§3).
const (
	ModeHeadersSPV   = "headers-spv"
	ModeOperatorNode = "operator-node"
)

// ChainView is one immutable snapshot (§6.3): network and genesis, provider, validation mode, bootstrap identity,
// epoch, tip, last successful sync.
type ChainView struct {
	Network, GenesisHash, Provider, Mode, Bootstrap string
	Epoch                                           uint64
	LastSync                                        time.Time
	// Base is the lowest height the view holds (0 from genesis, else the bootstrap height).
	Base      int64
	TipHeight int64
	TipHash   Hash
	TipWork   *big.Int
	TipTime   uint32
	// Unresolved counts tips tied at the greatest chainwork (0 when one tip has the most). When set, the accepted
	// chain ends at their fork point, and nothing above it is on the accepted chain (C-btc-15).
	Unresolved int

	tip *node
	// active is the accepted chain: active[h-Base] is the header at height h. others are the held headers off it.
	active []*node
	others []*node
}

func (v *ChainView) activeAt(height int64) *node {
	if i := height - v.Base; i >= 0 && i < int64(len(v.active)) {
		return v.active[i]
	}
	return nil
}

// HeaderAt returns the header at height on the accepted chain.
func (v *ChainView) HeaderAt(height int64) (Header, bool) {
	n := v.activeAt(height)
	if n == nil {
		return Header{}, false
	}
	return n.header(), true
}

// IsActive reports whether the block hash is on the accepted chain at height.
func (v *ChainView) IsActive(h Hash, height int64) bool {
	n := v.activeAt(height)
	return n != nil && n.hash == h
}

// offChain finds a held header outside the accepted chain at height whose Merkle root is root: a block a reorg
// orphaned, or one on a branch that ties for the most work.
func (v *ChainView) offChain(height int64, root []byte) (Header, bool) {
	for _, n := range v.others {
		if n.height == height && bytes.Equal(n.merkleRoot(), root) {
			return n.header(), true
		}
	}
	return Header{}, false
}

// ChainID is the CAIP-2 chain id (display only, §8.1): "bip122:" and the first 32 hex digits of the genesis hash.
func (v *ChainView) ChainID() string { return "bip122:" + v.GenesisHash[:32] }
