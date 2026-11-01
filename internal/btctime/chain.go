package btctime

import (
	"bytes"
	"crypto/sha256"
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

type node struct {
	h      Header
	height int64
	work   *big.Int // cumulative
	parent *node
}

// Chain is a validated header tree. It is safe for concurrent use; readers take immutable snapshots.
type Chain struct {
	mu        sync.Mutex
	p         Params
	provider  string
	bootstrap string
	base      int64 // height of the lowest held header
	nodes     map[Hash]*node
	byHeight  map[int64][]*node
	lastSync  time.Time
	epoch     uint64
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
	c.insert(&node{h: g, height: 0, work: Work(target(g.Bits))})
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
	var prev *node
	work := new(big.Int).Set(b.WorkBelow)
	for i, raw := range b.Headers {
		h, err := ParseHeader(raw)
		if err != nil {
			return nil, err
		}
		if prev != nil && h.Prev != prev.h.Hash {
			return nil, fmt.Errorf("bootstrap header %d does not link to the one before", b.Height+int64(i))
		}
		if err := CheckProofOfWork(h, p.PowLimit); err != nil {
			return nil, fmt.Errorf("bootstrap header %d: %w", b.Height+int64(i), err)
		}
		work = new(big.Int).Add(work, Work(target(h.Bits)))
		n := &node{h: h, height: b.Height + int64(i), work: work, parent: prev}
		c.insert(n)
		prev = n
	}
	return c, nil
}

func newChain(p Params, provider, bootstrap string, base int64) *Chain {
	return &Chain{p: p, provider: provider, bootstrap: bootstrap, base: base, nodes: map[Hash]*node{}, byHeight: map[int64][]*node{}}
}

func target(bits uint32) *big.Int {
	t, _, _ := CompactToTarget(bits)
	return t
}

func (c *Chain) insert(n *node) {
	c.nodes[n.h.Hash] = n
	c.byHeight[n.height] = append(c.byHeight[n.height], n)
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
	if err := CheckProofOfWork(h, c.p.PowLimit); err != nil {
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
	c.insert(&node{h: h, height: height, work: new(big.Int).Add(parent.work, Work(target(h.Bits))), parent: parent})
	return nil
}

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
		return last.h.Bits, nil
	}
	first := last
	for i := int64(0); i < c.p.RetargetInterval-1; i++ {
		if first.parent == nil {
			return 0, refuse("bad-diffbits", "retarget at height %d needs the header at height %d, which precedes this chain's bootstrap", height, height-c.p.RetargetInterval)
		}
		first = first.parent
	}
	span := int64(last.h.Time) - int64(first.h.Time)
	span = max(span, c.p.TargetTimespan/4)
	span = min(span, c.p.TargetTimespan*4)
	t := target(last.h.Bits)
	t.Mul(t, big.NewInt(span))
	t.Div(t, big.NewInt(c.p.TargetTimespan))
	if t.Cmp(c.p.PowLimit) > 0 {
		t.Set(c.p.PowLimit)
	}
	return TargetToCompact(t), nil
}

// medianTimePast is Core's GetMedianTimePast: the median of the last 11 header times (fewer near the root).
func medianTimePast(n *node) int64 {
	var ts []int64
	for i := 0; i < 11 && n != nil; i++ {
		ts = append(ts, int64(n.h.Time))
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
		active: map[int64]*node{}, others: map[Hash]*node{},
	}
	g, _ := ParseHeader(c.p.Genesis[:])
	v.GenesisHash = g.Hash.String()
	// greatest cumulative work; tips that tie at the greatest work leave the chain above their fork point unresolved
	var best []*node
	for _, n := range c.nodes {
		switch {
		case len(best) == 0 || n.work.Cmp(best[0].work) > 0:
			best = []*node{n}
		case n.work.Cmp(best[0].work) == 0:
			best = append(best, n)
		}
	}
	sort.Slice(best, func(i, j int) bool { return bytes.Compare(best[i].h.Hash[:], best[j].h.Hash[:]) < 0 })
	tip := best[0]
	if len(best) > 1 {
		tip = forkPoint(best)
		v.Unresolved = len(best)
	}
	for n := tip; n != nil; n = n.parent {
		v.active[n.height] = n
	}
	for _, n := range c.nodes {
		if v.active[n.height] != n {
			v.others[n.h.Hash] = n
		}
	}
	v.tip = tip
	v.TipHeight, v.TipHash, v.TipWork, v.TipTime = tip.height, tip.h.Hash, new(big.Int).Set(tip.work), tip.h.Time
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

	tip    *node
	active map[int64]*node
	others map[Hash]*node
}

// HeaderAt returns the header at height on the accepted chain.
func (v *ChainView) HeaderAt(height int64) (Header, bool) {
	n, ok := v.active[height]
	if !ok {
		return Header{}, false
	}
	return n.h, true
}

// IsActive reports whether the block hash is on the accepted chain at height.
func (v *ChainView) IsActive(h Hash, height int64) bool {
	n, ok := v.active[height]
	return ok && n.h.Hash == h
}

// offChain finds a held header outside the accepted chain at height whose Merkle root is root: a block a reorg
// orphaned, or one on a branch that ties for the most work.
func (v *ChainView) offChain(height int64, root []byte) (Header, bool) {
	for _, n := range v.others {
		if n.height == height && bytes.Equal(n.h.MerkleRoot[:], root) {
			return n.h, true
		}
	}
	return Header{}, false
}

// ChainID is the CAIP-2 chain id (display only, §8.1): "bip122:" and the first 32 hex digits of the genesis hash.
func (v *ChainView) ChainID() string { return "bip122:" + v.GenesisHash[:32] }
