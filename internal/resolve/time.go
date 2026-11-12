package resolve

import (
	"fmt"
	"slices"
	"strings"

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
	// Time is the committing block's header time (Unix seconds; miner-reported, bitcoin-time note §8): set by a
	// verifier for a verified bound, 0 otherwise. It is for display and for the shelf-life age only, never an
	// ordering key.
	Time int64
	// Why says why a bound is not of a verified quality ("not verified by this reader: ...").
	Why string
	// Margin is the reader's priority margin (bitcoin-time note §7, §8.3) that the verifier applies: a verified
	// bound ranks before another only when it leads by more than Margin blocks. One verifier gives every bound
	// the same margin.
	Margin int64
	// Detail is the verifier's further disclosure for explain (block hash, confirmations, validation mode).
	Detail string
	// State is the verifier's state token for the anchor (bitcoin-time note §8.1: verified, pending,
	// verified-historical, ...); "" when the verifier names none. A task deadline reads it (task-contracts note
	// §4.3): a verified-historical bound carries Network and Height, still of Local quality, so it orders nothing
	// here and meets a deadline only.
	State string
}

func (b Bound) verified() bool { return b.Quality == Bitcoin }

func (b Bound) String() string {
	switch b.Quality {
	case NoBound:
		if b.Anchor == "" && b.Why != "" {
			return "no bound (" + b.Why + ")"
		}
		if b.Anchor != "" {
			// an anchor the verifier refused: no bound is derived from it (bitcoin-time note §4)
			return "no anchor (anchor " + keylog.Short(b.Anchor) + " refused: " + b.Why + ")"
		}
		return "no anchor"
	case Bitcoin:
		s := fmt.Sprintf("bitcoin %s height %d (anchor %s)", b.Network, b.Height, keylog.Short(b.Anchor))
		if b.Detail != "" {
			s += ": " + b.Detail
		}
		return s
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

// WithIncoherentAnchorProofKept lets an `anchors` statement on an incoherent line keep a bound its proof places
// (a verified bound, a verified-historical height), dropping only the one that rests on its own timestamp. The
// default drops every bound such an anchor would yield (C-core-106: any bound derived from an incoherent line is
// discarded for every use).
func WithIncoherentAnchorProofKept() Option {
	return func(r *Resolver) { r.incoherentAnchorProofKept = true }
}

// TipReader is implemented by a TimeVerifier that knows the reader's validated chain tip. A task deadline asks
// it whether the tip is at or past the deadline height (task-contracts note §4.3); ok is false when no chain
// view is configured.
type TipReader interface {
	Tip() (height int64, ok bool)
}

// tip is the reader's validated tip height; ok false when its verifier reads no chain.
func (r *Resolver) tip() (int64, bool) {
	if t, ok := r.time.(TipReader); ok {
		return t.Tip()
	}
	return 0, false
}

// anchorCounts is whether anchor a can bound its signer's log. An anchor is a statement about one key's log
// (wire §5), and every caller keeps that: it reads only anchors whose signer signed the bounded statement, never
// another key's (identity profile §4: anchors remain key-local; a root's anchor gives a delegate no earlier
// timestamp). Whether the anchor itself counts is the counting gate's: with no actor evaluator exactly Counts; with
// one, an identity-context anchor (a grant may carry `anchors` over its signer's own log, profile §3) counts while
// its actor is eligible, so a cut that excludes it loses its time bound while the claim's authority may survive
// (profile §4, C-id-23).
func (r *Resolver) anchorCounts(a *Placed) bool { return r.counts(a) }

// IncoherentWhy is the reason shown in place of the bound of a statement whose log line is flagged incoherent.
const IncoherentWhy = "incoherent line: its ts is earlier than its predecessor's, so no time bound is derived for it"

// Incoherent lines (wire §2, claims-model note §10, bitcoin-time note §1 rule 6). A line whose ts is earlier
// than the ts of the line at its prev is still a valid statement and is still displayed with its flag, but:
//   - a statement on an incoherent line has no time bound for any use (priority, "existed by T", a deadline):
//     bound answers NoBound with IncoherentWhy and bounds answers nothing;
//   - an `anchors` statement on an incoherent line yields no bound for any statement it covers. The anchor is
//     still shown, and its proof is still handed to the verifier for display (explain); only the bound is
//     withheld. WithIncoherentAnchorProofKept keeps a bound the proof places (its chain position comes from the
//     header, not from the anchor's ts) and drops only the local, self-declared one.

// incoherent reports whether the line with this id is flagged incoherent in its signer's log.
func (r *Resolver) incoherent(id string) bool {
	p, ok := r.byID[id]
	return ok && p.Incoherent
}

// fromProof reports whether b's position comes from a proof the verifier checked rather than from a statement's
// timestamp: a verified bound, or a verified-historical height (task-contracts note §4.3).
func fromProof(b Bound) bool {
	return b.verified() || (b.State == "verified-historical" && b.Network != "")
}

// anchorBound is the bound anchor a yields, and false when it yields none: an anchor on an incoherent line yields
// none (with WithIncoherentAnchorProofKept, only one its proof places).
func (r *Resolver) anchorBound(a *Placed) (Bound, bool) {
	b := r.time.Verify(a.St)
	if a.Incoherent && (!r.incoherentAnchorProofKept || !fromProof(b)) {
		return Bound{}, false
	}
	return b, true
}

// bounds is every bound the reader derives for statement st from the counting anchors of st's signer whose
// covered head has st in its history, by anchor id. bound picks the best of them. A statement on an incoherent
// line has none.
func (r *Resolver) bounds(st *wire.Statement) []Bound {
	if r.incoherent(st.ID) {
		return nil
	}
	var out []Bound
	for _, a := range r.byKind["anchors"] {
		if a.St.Signer != st.Signer || !r.anchorCounts(a) {
			continue
		}
		cov := str(a.St.Body, "covered")
		if !r.precedes(st.Signer, cov, a.St.ID) || !closure(cov, r.chained[st.Signer])[st.ID] {
			continue
		}
		if b, ok := r.anchorBound(a); ok {
			out = append(out, b)
		}
	}
	slices.SortFunc(out, func(a, b Bound) int { return strings.Compare(a.Anchor, b.Anchor) })
	return out
}

// bound is the best bound the reader holds for statement st: the earliest verified bound among the counting
// anchors of st's signer whose covered head has st in its history; else a local one; else none. An anchor
// bounds only its signer's own log (§10). A statement on an incoherent line has no bound (IncoherentWhy).
func (r *Resolver) bound(st *wire.Statement) Bound {
	if r.incoherent(st.ID) {
		return Bound{Quality: NoBound, Why: IncoherentWhy}
	}
	best := Bound{Quality: NoBound}
	for _, a := range r.byKind["anchors"] {
		if a.St.Signer != st.Signer || !r.anchorCounts(a) {
			continue
		}
		// covered is a line of the signer's own log that the anchor line itself reaches (wire §5), and st is in
		// its history
		cov := str(a.St.Body, "covered")
		if !r.precedes(st.Signer, cov, a.St.ID) || !closure(cov, r.chained[st.Signer])[st.ID] {
			continue
		}
		b, ok := r.anchorBound(a)
		if !ok {
			continue
		}
		switch {
		case b.verified() && (!best.verified() || b.Height < best.Height || (b.Height == best.Height && b.Anchor < best.Anchor)):
			best = b
		case b.Quality == NoBound && best.Quality == NoBound && (best.Anchor == "" || b.Anchor < best.Anchor):
			best = b // a refused anchor, shown as such; still no bound
		case b.Quality == Local && best.Quality == NoBound:
			best = b // a local bound beats an anchor the verifier refused
		case b.Quality == Local && best.Quality == Local && b.Anchor < best.Anchor:
			best = b // deterministic choice among unverified bounds; none of them orders anything
		}
	}
	return best
}

// earlier reports whether bound a ranks strictly before bound b for priority (bitcoin-time note §8.3, claims
// §5.2): a is verified, and b is either unverified (the earliest verified claim, C-btc-01 (b)) or verified on
// the same network at a lower height by more than the reader's margin. Same height, a gap within the margin,
// different networks or an unverified a never rank.
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
	case a.Height < b.Height && b.Height-a.Height > a.Margin:
		return true, "earlier-commitment"
	case a.Height > b.Height && a.Height-b.Height > a.Margin:
		return false, "later"
	}
	return false, fmt.Sprintf("within-margin (gap %d, margin %d)", max(a.Height-b.Height, b.Height-a.Height), a.Margin)
}
