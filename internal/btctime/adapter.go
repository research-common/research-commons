package btctime

import (
	"fmt"

	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// TimeVerifier adapts a Verifier to the resolver (resolve.TimeVerifier), so priority among rival claims reads
// bounds this reader verified and nothing else (claims-model note §10, I10).
//
//   - a live verdict (verified, bitcoin quality) is a Bitcoin bound at the block's height, carrying the policy's
//     priority margin (§8.3);
//   - an anchor refused under §4 (invalid-proof, invalid-anchor, a size limit) yields no bound at all: the anchor
//     is named with its refusal, and the log's other statements are untouched (C-btc-05);
//   - every other state (pending, missing-proof, insufficient-confirmations, verified-historical, unknown-height,
//     orphaned, stale-chain, backend-*, unsupported) is a local bound, shown as not verified by this reader with
//     the state token, ordering nothing (C-btc-06, P-06).
//
// Each Verify reads the snapshot the Verifier holds; build the resolver for one batch with one snapshot.
type TimeVerifier struct{ V *Verifier }

// Verify implements resolve.TimeVerifier.
func (t TimeVerifier) Verify(a *wire.Statement) resolve.Bound {
	return BoundOf(t.V.Evaluate(a), t.V.Policy.PriorityMargin)
}

// BoundOf maps evidence to the resolver's bound.
func BoundOf(e Evidence, margin int64) resolve.Bound {
	switch {
	case e.Live():
		return resolve.Bound{Quality: resolve.Bitcoin, Anchor: e.Anchor, Network: e.Network, Height: e.BlockHeight, Margin: margin,
			Detail: e.String() + ", verified by this reader"}
	case e.State == StateInvalidProof || e.State == StateInvalidAnchor || e.State == StateRefused:
		why := fmt.Sprintf("%s: %s", e.State, e.Why)
		if e.Refusal != nil {
			why = fmt.Sprintf("%s (%s, %s): %s", e.State, e.Refusal.Class, e.Refusal.Reason, e.Why)
		}
		return resolve.Bound{Quality: resolve.NoBound, Anchor: e.Anchor, Why: why}
	}
	why := e.Why
	if e.State == StateVerifiedHistorical {
		why = e.String()
	}
	return resolve.Bound{Quality: resolve.Local, Anchor: e.Anchor, Why: fmt.Sprintf("not verified by this reader: %s (%s)", e.State, why)}
}
