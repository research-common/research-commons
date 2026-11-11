package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/store"
)

// A synthetic network for the CLI tests: easy proof of work (about one nonce in two), no retarget. It is reachable
// only by replacing chainParams/chainPolicy from a test of this package; no flag or environment variable selects it.
var testChainStart = time.Unix(1_700_000_000, 0)

func testChainParams() btctime.Params {
	lim := new(big.Int).Lsh(big.NewInt(0x7fffff), 232)
	g := mine(btctime.Header{Version: 4, MerkleRoot: btctime.Hash(sha256.Sum256([]byte("cli test genesis"))), Time: uint32(testChainStart.Unix()), Bits: 0x207fffff}, lim)
	return btctime.Params{Network: "cli-test", Genesis: g.Raw, PowLimit: lim, RetargetInterval: 1 << 40, TargetTimespan: 6000, MaxFutureSeconds: 7200}
}

func mine(h btctime.Header, lim *big.Int) btctime.Header {
	for n := uint32(0); ; n++ {
		h.Nonce = n
		raw := h.Serialize()
		p, _ := btctime.ParseHeader(raw[:])
		if btctime.CheckProofOfWork(p, lim) == nil {
			return p
		}
	}
}

// testChain mines n headers on the test genesis; roots fixes the Merkle root at a height. It returns the raw
// headers (genesis excluded, as a sync file carries them) and the tip time.
func testChain(n int, roots map[int64][]byte) ([]byte, time.Time) {
	p := testChainParams()
	prev, _ := btctime.ParseHeader(p.Genesis[:])
	var out bytes.Buffer
	for h := int64(1); h <= int64(n); h++ {
		root := roots[h]
		if root == nil {
			s := sha256.Sum256([]byte{byte(h), byte(h >> 8), 'f'})
			root = s[:]
		}
		hd := mine(btctime.Header{Version: 4, Prev: prev.Hash, MerkleRoot: btctime.Hash(root), Time: prev.Time + 600, Bits: 0x207fffff}, p.PowLimit)
		out.Write(hd.Raw[:])
		prev = hd
	}
	return out.Bytes(), time.Unix(int64(prev.Time), 0)
}

// useTestChain points the CLI at the synthetic network and fixes the clock; settled overrides the settled depth.
func useTestChain(t *testing.T, at *time.Time, settled int64) {
	t.Helper()
	p := testChainParams()
	g, _ := btctime.ParseHeader(p.Genesis[:])
	oldP, oldPol, oldNow := chainParams, chainPolicy, Now
	chainParams = func() btctime.Params { return p }
	chainPolicy = func() btctime.Policy {
		pol := btctime.DefaultPolicy()
		pol.Network, pol.Genesis = p.Network, g.Hash.String()
		if settled > 0 {
			pol.SettledDepth = settled
		}
		return pol
	}
	Now = func() time.Time { return *at }
	t.Cleanup(func() { chainParams, chainPolicy, Now = oldP, oldPol, oldNow })
}

// chainWorld: two keys claim blob X; K1's anchor commits at height 10, K2's at 12 (its proof's calculated digest is
// the covered id, so the header at that height carries it as its Merkle root). The store is not git-backed;
// COMMONS_STATE_DIR names the state.
type chainWorld struct {
	*world
	env     map[string]string
	headers string
	tip     time.Time
}

func newChainWorld(t *testing.T, n int) *chainWorld {
	w := newWorld(t)
	w.blob("X", []byte("X"))
	w.authored("A:1", "K1", "X")
	cov1, _ := hex.DecodeString(w.head["K1"])
	w.anchor("anc1", "K1", 10)
	w.authored("A:2", "K2", "X")
	cov2, _ := hex.DecodeString(w.head["K2"])
	w.anchor("anc2", "K2", 12)
	raw, tip := testChain(n, map[int64][]byte{10: cov1, 12: cov2})
	f := filepath.Join(t.TempDir(), "chain.headers")
	if err := os.WriteFile(f, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return &chainWorld{world: w, env: map[string]string{StateDirEnv: t.TempDir()}, headers: f, tip: tip}
}

func (c *chainWorld) run(args ...string) result { return runIn(c.root, c.env, args...) }

// TestAnchorHeadersSyncVerifies: L-02's first slice end to end. Before a sync every bound is backend-unconfigured
// and the rival claim contested (exit 3); `anchor headers sync --from` validates and persists the chain; afterwards
// verify reads both anchors against it: K1 verified at 10, K2 at 12, K1 the default author, exit 0; explain's time
// context names the view; `anchor status` reports it. Re-running the sync adds nothing.
//
// C-btc-01 itself is covered in internal/btctime (TestPriorityEndToEnd); this is the same ranking reached through
// the CLI over a persisted, synced view.
func TestAnchorHeadersSyncVerifies(t *testing.T) {
	c := newChainWorld(t, 30)
	now := c.tip.Add(10 * time.Minute)
	useTestChain(t, &now, 0)
	x := dig("X")
	if r := c.run("verify", x, "--json"); r.code != ExitCouldNot || strings.Count(r.stdout, `"time_state":"backend-unconfigured"`) != 2 {
		t.Fatalf("before sync: %d %s", r.code, r.stdout)
	}
	if r := c.run("anchor", "status", "--json"); r.code != ExitCouldNot || jsonOf(t, r).Members["configured"] != canon.Bool(false) {
		t.Fatalf("status before sync: %d %s", r.code, r.stdout)
	}
	r := c.run("anchor", "headers", "sync", "--from", c.headers, "--json")
	o := jsonOf(t, r)
	if r.code != ExitOK || o.Members["added"] != canon.Int(30) || o.Members["completed"] != canon.Bool(true) {
		t.Fatalf("sync: %d %s", r.code, r.stdout)
	}
	ch := o.Members["chain"].(*canon.Object)
	if ch.Members["tip_height"] != canon.Int(30) || ch.Members["freshness"] != canon.String("fresh") || !strings.HasPrefix(string(ch.Members["bootstrap"].(canon.String)), "genesis:") {
		t.Fatalf("sync chain: %s", r.stdout)
	}
	r = c.run("verify", x, "--json")
	if r.code != ExitOK || jsonOf(t, r).Members["authorship"] != canon.String("default author") {
		t.Fatalf("after sync: %d %s", r.code, r.stdout)
	}
	if r := c.run("show", x, "--json"); !strings.Contains(r.stdout, `"quality":"bitcoin"`) {
		t.Fatalf("show after sync: %s", r.stdout)
	}
	tc, _ := jsonOf(t, c.run("explain", x, "--json")).Members["time_context"].(canon.String)
	if !strings.Contains(string(tc), "chain view (cli-test, tip 30") || !strings.Contains(string(tc), "fresh") {
		t.Fatalf("explain time context: %s", tc)
	}
	r = c.run("anchor", "status", "--json")
	o = jsonOf(t, r)
	if r.code != ExitOK || o.Members["configured"] != canon.Bool(true) || o.Members["headers"] != canon.Int(31) {
		t.Fatalf("status: %d %s", r.code, r.stdout)
	}
	for _, secret := range []string{"key", "mac"} {
		if _, ok := o.Members[secret]; ok {
			t.Fatalf("status prints %s", secret)
		}
	}
	if h := c.run("anchor", "status"); h.code != ExitOK || !strings.Contains(h.stdout, "tip_height: 30") && !strings.Contains(h.stdout, "tip height: 30") {
		t.Fatalf("human status: %s", h.stdout)
	}
	// idempotent
	r = c.run("anchor", "headers", "sync", "--from", c.headers, "--json")
	if o := jsonOf(t, r); r.code != ExitOK || o.Members["added"] != canon.Int(0) || o.Members["already_held"] != canon.Int(30) {
		t.Fatalf("second sync: %d %s", r.code, r.stdout)
	}
	// nothing was written into the store (the data surface)
	if _, err := os.Stat(filepath.Join(c.root, "headers-v1")); err == nil {
		t.Fatal("header database inside the store")
	}
}

// TestAnchorFreshness: §7 and §9.4 through the CLI with an injected clock. Two hours after the sync the view is
// past the maximum view age: a block with 21 confirmations is below the settled depth (144), so both bounds are
// verified-historical and priority is not computed (contested, exit 3); with the settled depth at 20 they keep
// bitcoin quality as of the sync and rank (exit 0). A clock before the last sync is stale-chain.
// (C-btc-17a and C-btc-18 are covered in internal/btctime; this is the CLI path over a persisted view.)
func TestAnchorFreshness(t *testing.T) {
	c := newChainWorld(t, 30)
	now := c.tip.Add(10 * time.Minute)
	useTestChain(t, &now, 0)
	if r := c.run("anchor", "headers", "sync", "--from", c.headers); r.code != ExitOK {
		t.Fatalf("sync: %d %s", r.code, r.stdout+r.stderr)
	}
	x := dig("X")
	now = now.Add(2 * time.Hour)
	r := c.run("verify", x, "--json")
	if r.code != ExitCouldNot || strings.Count(r.stdout, `"state":"verified-historical"`) != 2 {
		t.Fatalf("old view: %d %s", r.code, r.stdout)
	}
	if st := jsonOf(t, c.run("anchor", "status", "--json")).Members["chain"].(*canon.Object).Members["freshness"].(canon.String); !strings.HasPrefix(string(st), "not fresh: last sync 2h0m0s ago") {
		t.Fatalf("status freshness: %s", st)
	}
	useTestChain(t, &now, 20)
	if r := c.run("verify", x, "--json"); r.code != ExitOK {
		t.Fatalf("old view past the settled depth: %d %s", r.code, r.stdout)
	}
	now = c.tip.Add(-time.Hour) // before the last sync
	if r := c.run("verify", x, "--json"); r.code != ExitCouldNot || strings.Count(r.stdout, `"state":"stale-chain"`) != 2 {
		t.Fatalf("clock rollback: %d %s", r.code, r.stdout)
	}
}

// TestAnchorDatabaseRefused: a database that is not trusted (here: loosened permissions; the btctime tests cover
// the rest) is never used: every bound reads backend-unavailable naming why, status reports it, and a sync refuses
// to extend it.
func TestAnchorDatabaseRefused(t *testing.T) {
	c := newChainWorld(t, 30)
	now := c.tip.Add(10 * time.Minute)
	useTestChain(t, &now, 0)
	if r := c.run("anchor", "headers", "sync", "--from", c.headers); r.code != ExitOK {
		t.Fatal(r.stdout + r.stderr)
	}
	p := filepath.Join(c.env[StateDirEnv], "research-commons", "headers-v1", "chain")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	r := c.run("verify", dig("X"), "--json")
	if r.code != ExitCouldNot || strings.Count(r.stdout, `"state":"backend-unavailable"`) != 2 {
		t.Fatalf("refused database: %d %s", r.code, r.stdout)
	}
	r = c.run("anchor", "status", "--json")
	if o := jsonOf(t, r); r.code != ExitCouldNot || !strings.Contains(string(canon.Encode(o)), "readable or writable by others") {
		t.Fatalf("status: %d %s", r.code, r.stdout)
	}
	r = c.run("anchor", "headers", "sync", "--from", c.headers, "--json")
	if r.code != ExitCouldNot || !strings.Contains(r.stdout, "header-database-refused") {
		t.Fatalf("sync over a refused database: %d %s", r.code, r.stdout)
	}
}

// TestAnchorSyncStops: a header failing validation stops the sync with exit 1 and its reason; what validated is
// kept (status shows the shorter tip), and the sync does not count as completed (last sync never).
func TestAnchorSyncStops(t *testing.T) {
	c := newChainWorld(t, 30)
	now := c.tip.Add(10 * time.Minute)
	useTestChain(t, &now, 0)
	raw, _ := os.ReadFile(c.headers)
	raw[20*btctime.HeaderSize+4] ^= 0xff // header 21's prev: it links to nothing held
	os.WriteFile(c.headers, raw, 0o644)
	r := c.run("anchor", "headers", "sync", "--from", c.headers, "--json")
	o := jsonOf(t, r)
	if r.code != ExitWrong || o.Members["completed"] != canon.Bool(false) {
		t.Fatalf("stopped sync: %d %s", r.code, r.stdout)
	}
	st := o.Members["stopped"].(*canon.Object)
	if st.Members["position"] != canon.Int(21) {
		t.Fatalf("stopped at %v: %s", st.Members["position"], r.stdout)
	}
	ch := o.Members["chain"].(*canon.Object)
	if ch.Members["tip_height"] != canon.Int(20) || ch.Members["last_sync"] != canon.String("never") {
		t.Fatalf("kept: %s", r.stdout)
	}
	// a never-completed view carries no live evidence: stale-chain
	if r := c.run("verify", dig("X"), "--json"); r.code != ExitCouldNot || !strings.Contains(r.stdout, `"state":"stale-chain"`) {
		t.Fatalf("verify on a never-synced view: %d %s", r.code, r.stdout)
	}
}

// TestAnchorSyncInvocation: every bad invocation exits 2 before any work, and a store with no state directory
// exits 3 naming why.
func TestAnchorSyncInvocation(t *testing.T) {
	c := newChainWorld(t, 3)
	odd := filepath.Join(t.TempDir(), "odd")
	os.WriteFile(odd, make([]byte, 81), 0o644)
	for _, args := range [][]string{
		{},
		{"--from", filepath.Join(t.TempDir(), "absent")},
		{"--from", odd},
		{"--from", c.headers, "--bootstrap-height", "10"},
		{"--from", c.headers, "--bootstrap-work", "ff"},
		{"--from", c.headers, "--bootstrap-height", "-1", "--bootstrap-work", "ff"},
		{"--from", c.headers, "--bootstrap-height", "10", "--bootstrap-work", "xyz"},
		{"--from", c.headers, "--max-headers", "0"},
	} {
		r := c.run(append([]string{"anchor", "headers", "sync", "--json"}, args...)...)
		if r.code != ExitDidNotStart {
			t.Errorf("%v: exit %d %s", args, r.code, r.stdout)
		}
	}
	if _, err := os.Stat(filepath.Join(c.env[StateDirEnv], "research-commons")); err == nil {
		t.Fatal("a refused invocation created state")
	}
	r := runIn(c.root, nil, "anchor", "headers", "sync", "--from", c.headers, "--json")
	if r.code != ExitCouldNot || !strings.Contains(r.stdout, "no-state") {
		t.Fatalf("no state directory: %d %s", r.code, r.stdout)
	}
}

// TestAnchorMainnetBootstrap: the real mainnet fixture through the command with the production parameters: an
// explicit bootstrap (--bootstrap-height/--bootstrap-work, the first 11 headers) and every later header validated.
func TestAnchorMainnetBootstrap(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "btctime", "testdata", "mainnet-356832-359000.headers"))
	if err != nil {
		t.Fatal(err)
	}
	last, _ := btctime.ParseHeader(raw[len(raw)-btctime.HeaderSize:])
	now := time.Unix(int64(last.Time), 0).Add(10 * time.Minute)
	old := Now
	Now = func() time.Time { return now }
	t.Cleanup(func() { Now = old })
	c := newChainWorld(t, 1)
	f := filepath.Join(t.TempDir(), "mainnet.headers")
	os.WriteFile(f, raw, 0o644)
	r := c.run("anchor", "headers", "sync", "--from", f, "--bootstrap-height", "356832", "--bootstrap-work", "6f293e337e48534b58620", "--json")
	o := jsonOf(t, r)
	if r.code != ExitOK || o.Members["added"] != canon.Int(2169-11) {
		t.Fatalf("mainnet sync: %d %s", r.code, r.stdout)
	}
	ch := o.Members["chain"].(*canon.Object)
	if ch.Members["tip_height"] != canon.Int(359000) || ch.Members["network"] != canon.String("mainnet") ||
		ch.Members["tip_hash"] != canon.String(last.Hash.String()) || !strings.HasPrefix(string(ch.Members["bootstrap"].(canon.String)), "bootstrap:") {
		t.Fatalf("mainnet chain: %s", r.stdout)
	}
	// a second sync naming another bootstrap is refused; without one it extends nothing
	r = c.run("anchor", "headers", "sync", "--from", f, "--bootstrap-height", "356833", "--bootstrap-work", "6f293e337e48534b58620", "--json")
	if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "bootstrap-mismatch") {
		t.Fatalf("another bootstrap: %d %s", r.code, r.stdout)
	}
	// the fixture's anchors attest heights 10 and 12, below the bootstrap: unknown-height, never verified
	if r := c.run("verify", dig("X"), "--json"); r.code != ExitCouldNot || strings.Count(r.stdout, `"state":"unknown-height"`) != 2 {
		t.Fatalf("anchors outside the view: %d %s", r.code, r.stdout)
	}
}

// TestNoDatabaseByteIdentical: with no header database (a state directory with nothing synced, or none at all) every
// read surface prints exactly what it printed before the backend existed.
func TestNoDatabaseByteIdentical(t *testing.T) {
	w := fixture(t)
	empty := map[string]string{StateDirEnv: t.TempDir()}
	for _, a := range sweepArgs(w) {
		for _, js := range []bool{false, true} {
			args := a
			if js {
				args = append(append([]string{}, a...), "--json")
			}
			want := runIn(w.root, nil, args...)
			got := runIn(w.root, empty, args...)
			if a[0] == "anchor" {
				continue // anchor status names the state directory it looked in
			}
			if want.code != got.code || want.stdout != got.stdout {
				t.Fatalf("%v differs with an empty state directory", args)
			}
		}
	}
}

// TestReadVerifierReadsTip: the read commands' time verifier answers resolve.TipReader from the persisted view (so a
// task deadline reads the validated tip, task-contracts note §4.3), and with no database it has no tip (the deadline
// stays unchecked, as before).
func TestReadVerifierReadsTip(t *testing.T) {
	c := newChainWorld(t, 30)
	now := c.tip.Add(10 * time.Minute)
	useTestChain(t, &now, 0)
	ctx := func() *Ctx {
		s, err := store.Open(c.root, store.Options{NoSync: true})
		if err != nil {
			t.Fatal(err)
		}
		return &Ctx{Root: c.root, Store: s, Env: &Env{Getenv: func(k string) string { return c.env[k] }}}
	}
	if _, ok := (btctime.TimeVerifier{V: timeVerifierFor(ctx())}).Tip(); ok {
		t.Fatal("a tip with no database")
	}
	if r := c.run("anchor", "headers", "sync", "--from", c.headers); r.code != ExitOK {
		t.Fatal(r.stdout + r.stderr)
	}
	var tr resolve.TipReader = btctime.TimeVerifier{V: timeVerifierFor(ctx())}
	if h, ok := tr.Tip(); !ok || h != 30 {
		t.Fatalf("tip %d %v", h, ok)
	}
}
