package btctime

import (
	"fmt"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// ReferentChecker re-checks an exact-bytes observation's referent against the reader's own header chain
// (resolve.ReferentChecker, claims-model note §5.3.1): where the pinned block hash is, never what bytes the
// observation captured. A header chain proves a block's position and depth; it holds no block contents, so this
// checker never reports identical or different bytes and adds no corroboration evidence. Its outcomes:
//
//   - the block on the accepted chain: resolve.RePosition at depth tip height - block height + 1, which the
//     finality rule reads as provisional or final;
//   - the block held off the accepted chain (a reorg orphaned it): not canonical;
//   - the block on one of several tips tied at the greatest chainwork, or not held at all, or a referent on another
//     chain than this view's, or a view never synced: unchecked, naming why.
//
// Only `bip122:` chain ids naming this view's genesis are re-checked; every other referent is unchecked.
type ReferentChecker struct {
	View   *ChainView
	Policy Policy
	Now    func() time.Time
}

// Check implements resolve.ReferentChecker.
func (c ReferentChecker) Check(st *wire.Statement) resolve.ReCheck {
	unchecked := func(f string, a ...any) resolve.ReCheck {
		return resolve.ReCheck{Outcome: resolve.ReUnchecked, PositionOnly: true, Why: fmt.Sprintf(f, a...)}
	}
	if st == nil || st.Body == nil || c.View == nil {
		return resolve.ReCheck{Outcome: resolve.ReUnchecked, Why: "no referent checker configured"}
	}
	if cls, _ := st.Body.Get("class"); cls != canon.String("exact-bytes") {
		return resolve.ReCheck{Outcome: resolve.ReUnchecked, Why: "no referent checker for this class (a header chain re-checks exact-bytes referents only)"}
	}
	rv, _ := st.Body.Get("referent")
	ref, _ := rv.(*canon.Object)
	chain, hash := text(ref, "chain_id"), text(ref, "block_hash")
	if chain != c.View.ChainID() {
		return unchecked("referent chain %q is not this reader's header chain (%s); no checker for it", chain, c.View.ChainID())
	}
	h, err := ParseDisplayHash(hash)
	if err != nil {
		return unchecked("block hash %q is not a display-order block hash", hash)
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	fresh, never, why := c.Policy.Freshness(c.View, now())
	if never {
		return unchecked("header chain: %s", why)
	}
	view := fmt.Sprintf("this reader's header chain, tip %d", c.View.TipHeight)
	if !fresh {
		view += ", not fresh: " + why
	}
	height, active, held := c.View.locate(h)
	switch {
	case active:
		return resolve.ReCheck{Outcome: resolve.RePosition, PositionOnly: true, Why: view,
			State: resolve.State{HasDepth: true, Depth: c.View.TipHeight - height + 1}}
	case held && c.View.Unresolved > 0 && height > c.View.TipHeight:
		return unchecked("block at height %d is on one of %d tips tied at the greatest chainwork in %s; unresolved", height, c.View.Unresolved, view)
	case held:
		return resolve.ReCheck{Outcome: resolve.ReNotCanonical, PositionOnly: true,
			Why: fmt.Sprintf("block at height %d held off the accepted chain in %s", height, view)}
	}
	return unchecked("block not in %s (heights %d to %d)", view, c.View.Base, c.View.TipHeight)
}

func text(o *canon.Object, k string) string {
	if o == nil {
		return ""
	}
	v, _ := o.Get(k)
	s, _ := v.(canon.String)
	return string(s)
}

// locate finds a block hash among the view's headers: its height, and whether it is on the accepted chain. It
// scans the view (one pass per call, no index), which is the cost of one observation's re-check.
func (v *ChainView) locate(h Hash) (height int64, active, held bool) {
	for _, n := range v.active {
		if n.hash == h {
			return n.height, true, true
		}
	}
	for _, n := range v.others {
		if n.hash == h {
			return n.height, false, true
		}
	}
	return 0, false, false
}
