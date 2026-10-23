package resolve

import (
	"fmt"

	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// Time evidence (claims-model note §10; bitcoin-time note §8). A bound is what the reader verified about when
// a statement existed. Only a quality the reader verified itself orders rival claims (I10): `local` and
// anything a statement says about itself order nothing (C-core-19, C-core-107, P-06).
//
// The resolver never reads proofs. It asks a TimeVerifier, which the reader configures. The default verifies
// nothing (no proof format is implemented yet), so every bound is `local` at best and every rival construction
// claim is honestly `contested` (§5.2, the #59 limit, C-core-07). A proof-format profile plugs in here.

// Quality is a bound's quality.
type Quality string

const (
	// NoBound: no counting anchor of the signer covers the statement.
	NoBound Quality = "none"
	// Local: covered by an anchor the reader did not verify. Shown as (local, self-declared); orders nothing.
	Local Quality = "local"
	// Bitcoin: the reader verified the anchor's proof against block evidence it trusts (bitcoin-time note).
	Bitcoin Quality = "bitcoin"
)

// Bound is the evidence that a statement existed by some point.
type Bound struct {
	Quality Quality
	// Anchor is the anchors statement the bound comes from; "" for NoBound.
	Anchor string
	// Network and Height place a Bitcoin bound (the height of the block that commits to the proof).
	Network string
	Height  int64
	// Why says why a bound is not of a verified quality ("not verified by this reader: ...").
	Why string
}

func (b Bound) verified() bool { return b.Quality == Bitcoin }

func (b Bound) String() string {
	switch b.Quality {
	case NoBound:
		return "no anchor"
	case Bitcoin:
		return fmt.Sprintf("bitcoin %s height %d (anchor %s)", b.Network, b.Height, keylog.Short(b.Anchor))
	}
	s := "(local, self-declared) anchor " + keylog.Short(b.Anchor)
	if b.Why != "" {
		s += ": " + b.Why
	}
	return s
}

// TimeVerifier turns an anchors statement into a bound. It must answer from receiver-local state only and
// never from a field of the statement itself: a quality label in a file grants nothing (C-core-107).
type TimeVerifier interface {
	Verify(anchor *wire.Statement) Bound
}

// NoTimeVerifier is the default: it verifies no proof format, so every anchor yields a local bound.
type NoTimeVerifier struct{}

// Verify implements TimeVerifier.
func (NoTimeVerifier) Verify(a *wire.Statement) Bound {
	return Bound{Quality: Local, Anchor: a.ID, Why: "not verified by this reader (no proof format " + str(a.Body, "proof_format") + " verifier configured)"}
}

// Option configures a Resolver.
type Option func(*Resolver)

// WithTimeVerifier sets the reader's time verifier.
func WithTimeVerifier(v TimeVerifier) Option { return func(r *Resolver) { r.time = v } }

// bound is the best bound the reader holds for statement st: the earliest verified bound among the counting
// anchors of st's signer whose covered head has st in its history; else a local one; else none. An anchor
// bounds only its signer's own log (§10).
func (r *Resolver) bound(st *wire.Statement) Bound {
	best := Bound{Quality: NoBound}
	for _, a := range r.byKind["anchors"] {
		if a.St.Signer != st.Signer || !a.Counts() {
			continue
		}
		// covered is a line of the signer's own log that the anchor line itself reaches (wire §5), and st is in
		// its history
		cov := str(a.St.Body, "covered")
		if !r.precedes(st.Signer, cov, a.St.ID) || !closure(cov, r.chained[st.Signer])[st.ID] {
			continue
		}
		b := r.time.Verify(a.St)
		switch {
		case b.verified() && (!best.verified() || b.Height < best.Height || (b.Height == best.Height && b.Anchor < best.Anchor)):
			best = b
		case !b.verified() && best.Quality == NoBound:
			best = b
		case !b.verified() && best.Quality == Local && b.Anchor < best.Anchor:
			best = b // deterministic choice among unverified bounds; none of them orders anything
		}
	}
	return best
}

// earlier reports whether bound a ranks strictly before bound b for priority (bitcoin-time note §8.3, claims
// §5.2): a is verified, and b is either unverified (the earliest verified claim, C-btc-01 (b)) or verified on
// the same network at a strictly lower height (margin 0). Same height, different networks or an unverified a
// never rank.
func earlier(a, b Bound) (bool, string) {
	switch {
	case !a.verified():
		return false, "unverified"
	case !b.verified():
		return true, "earliest verified claim; rival unverified"
	case a.Network != b.Network:
		return false, "incomparable"
	case a.Height == b.Height:
		return false, "same-block"
	case a.Height < b.Height:
		return true, "earlier-commitment"
	}
	return false, "later"
}
