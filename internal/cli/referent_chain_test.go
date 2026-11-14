package cli

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// forkedTestChain mines n headers on the test genesis and a losing branch of m headers off height at (m < n-at, so
// the main chain keeps the greatest chainwork). It returns the sync file (main chain, then the branch), the display
// hash of every main-chain header by height, the branch's hashes, and the tip time.
func forkedTestChain(n int, at, m int) (raw []byte, main map[int64]string, side []string, tip time.Time) {
	p := testChainParams()
	g, _ := btctime.ParseHeader(p.Genesis[:])
	main = map[int64]string{}
	var out bytes.Buffer
	headers := map[int64]btctime.Header{0: g}
	prev := g
	for h := int64(1); h <= int64(n); h++ {
		s := sha256.Sum256([]byte{byte(h), byte(h >> 8), 'm'})
		hd := mine(btctime.Header{Version: 4, Prev: prev.Hash, MerkleRoot: btctime.Hash(s), Time: prev.Time + 600, Bits: 0x207fffff}, p.PowLimit)
		out.Write(hd.Raw[:])
		main[h], headers[h], prev = hd.Hash.String(), hd, hd
	}
	tip = time.Unix(int64(prev.Time), 0)
	prev = headers[int64(at)]
	for i := 1; i <= m; i++ {
		s := sha256.Sum256([]byte{byte(i), 's'})
		hd := mine(btctime.Header{Version: 4, Prev: prev.Hash, MerkleRoot: btctime.Hash(s), Time: prev.Time + 601, Bits: 0x207fffff}, p.PowLimit)
		out.Write(hd.Raw[:])
		side, prev = append(side, hd.Hash.String()), hd
	}
	return out.Bytes(), main, side, tip
}

// TestReferentPositionCommands: C-core-72 through the commands. Over a synced header chain (30 headers, a losing
// branch of 3 off height 20), show, verify and explain re-check each exact-bytes observation's pinned block in the
// reader's own chain: an observation asserting depth 7 (final under `confirmations ≥ 6`) whose block is at depth 2
// shows the asserted `final` beside the computed `provisional (2; final at 6)` with `disagrees: true` (JSON) and
// "they disagree" (text); a block at depth 21 is `final`, agreeing; a block on the losing branch is `not canonical`;
// a block the chain does not hold, and a referent on another chain, stay unchecked, naming why. The re-check is
// position only: no corroboration evidence on any of them, and `verify` exits 0 for each (its pins hold; the
// referent status is a disclosure beside the exit, claims §13). Before the sync every view is today's: nothing is
// re-checked and nothing is shown beside.
func TestReferentPositionCommands(t *testing.T) {
	conformance.Covers(t, "C-core-72")
	raw, main, side, tip := forkedTestChain(30, 20, 3)
	w := newWorld(t)
	f := filepath.Join(t.TempDir(), "chain.headers")
	if err := os.WriteFile(f, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{StateDirEnv: t.TempDir()}
	now := tip.Add(10 * time.Minute)
	useTestChain(t, &now, 0)
	p := testChainParams()
	g, _ := btctime.ParseHeader(p.Genesis[:])
	chainID := "bip122:" + g.Hash.String()[:32]
	obs := func(name, n, x, chain, hash string, asserted int) string {
		w.blob(x, []byte(x))
		return w.sign(name, n, "observed", obj("content", content(x), "class", "exact-bytes",
			"referent", obj("chain_id", chain, "block_hash", hash, "depth", asserted),
			"capture", obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted"),
			"finality", obj("rule", "confirmations ≥ 6", "state_at_capture", obj("depth", asserted))))
	}
	shallow := obs("A", "K1", "a", chainID, main[29], 7)                // depth 2 now; asserted 7
	deep := obs("B", "K2", "b", chainID, main[10], 3)                   // depth 21 now; asserted 3
	orphan := obs("C", "K3", "c", chainID, side[1], 2)                  // on the losing branch
	absent := obs("D", "K4", "d", chainID, strings.Repeat("ab", 32), 2) // not held
	other := obs("E", "K5", "e", "bip122:000000000019d6689c085ae165831e93", main[29], 7)
	run := func(args ...string) result { return runIn(w.root, env, args...) }
	referent := func(cmd, id string) (*canon.Object, result) {
		t.Helper()
		r := run(cmd, id, "--json")
		ref, _ := jsonOf(t, r).Members["referent"].(*canon.Object)
		if ref == nil {
			t.Fatalf("%s %s: no referent member: %s", cmd, id, r.stdout)
		}
		return ref, r
	}

	// before the sync: no checker, nothing beside, the status from the asserted state (today's behaviour)
	before := map[string]string{}
	for _, id := range []string{shallow, deep, orphan, absent, other} {
		ref, r := referent("show", id)
		if _, ok := ref.Members["beside"]; ok || !strings.Contains(r.stdout, "no referent checker configured") {
			t.Fatalf("before sync: %s", r.stdout)
		}
		before[id] = r.stdout
	}
	if r := run("anchor", "headers", "sync", "--from", f); r.code != ExitOK {
		t.Fatalf("sync: %d %s", r.code, r.stdout+r.stderr)
	}

	// C-core-72: asserted final beside computed provisional, the disagreement flagged on every surface
	for _, cmd := range []string{"show", "verify", "explain"} {
		ref, r := referent(cmd, shallow)
		if ref.Members["status"] != canon.String("provisional") || ref.Members["detail"] != canon.String("2; final at 6") {
			t.Fatalf("%s shallow: %s", cmd, r.stdout)
		}
		b, _ := ref.Members["beside"].(*canon.Object)
		if b == nil || b.Members["disagrees"] != canon.Bool(true) || b.Members["asserted"] != canon.String("final") ||
			b.Members["asserted_state"] != canon.String("7") || b.Members["computed"] != canon.String("provisional (2; final at 6)") ||
			b.Members["computed_state"] != canon.String("2") || b.Members["via"] != canon.String("position re-checked") {
			t.Fatalf("%s shallow: the pair: %s", cmd, r.stdout)
		}
		if strings.Contains(r.stdout, "identical bytes") {
			t.Fatalf("%s shallow: a position re-check shown as bytes: %s", cmd, r.stdout)
		}
		h := run(cmd, shallow)
		for _, want := range []string{"disagrees: yes", "the observer's asserted state and this reader's re-check disagree"} {
			if !strings.Contains(h.stdout, want) {
				t.Fatalf("%s shallow text lacks %q:\n%s", cmd, want, h.stdout)
			}
		}
	}
	if _, r := referent("explain", shallow); !strings.Contains(r.stdout, "reader re-check: depth 2 (this reader's header chain, tip 30; position only, bytes not re-read): provisional (2; final at 6) (asserted state 7 shown beside it: they disagree)") {
		t.Fatalf("explain history: %s", r.stdout)
	}
	// the control: a deeper block is final and agrees with its asserted state (time passed, nothing disagrees)
	ref, r := referent("show", deep)
	if b, _ := ref.Members["beside"].(*canon.Object); ref.Members["status"] != canon.String("final") || b == nil || b.Members["disagrees"] != canon.Bool(false) {
		t.Fatalf("deep: %s", r.stdout)
	}
	if ref, r := referent("show", orphan); ref.Members["status"] != canon.String("not canonical") || !strings.Contains(r.stdout, "held off the accepted chain") {
		t.Fatalf("orphan: %s", r.stdout)
	}
	if ref, r := referent("show", absent); ref.Members["status"] != canon.String("provisional") || !strings.Contains(r.stdout, "block not in this reader's header chain") {
		t.Fatalf("absent: %s", r.stdout)
	} else if _, ok := ref.Members["beside"]; ok {
		t.Fatalf("absent: a pair with no computed state: %s", r.stdout)
	}
	if ref, r := referent("show", other); ref.Members["status"] != canon.String("final (as captured, not re-checked)") ||
		!strings.Contains(r.stdout, `referent chain \"bip122:000000000019d6689c085ae165831e93\" is not this reader's header chain`) {
		t.Fatalf("other chain: %s", r.stdout)
	}
	for _, id := range []string{shallow, deep, orphan, absent, other} {
		r := run("verify", id, "--json")
		o := jsonOf(t, r)
		co, _ := o.Members["corroboration"].(*canon.Object)
		if r.code != ExitOK || co == nil || co.Members["state"] != canon.String("unchecked") || co.Members["corroborated"] != canon.Int(0) {
			t.Fatalf("verify %s: a position re-check moved the exit or added evidence: %d %s", id, r.code, r.stdout)
		}
	}
	// the chain is what changed the answer: with the state directory gone, every view is the one before the sync
	env[StateDirEnv] = t.TempDir()
	for id, want := range before {
		if r := run("show", id, "--json"); r.stdout != want {
			t.Fatalf("no chain: the view changed:\n%s\nvs\n%s", r.stdout, want)
		}
	}
}
