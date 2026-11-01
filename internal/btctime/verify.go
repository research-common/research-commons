package btctime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// VerifierVersion names this verifier in every evidence record and policy fingerprint.
const VerifierVersion = "research-commons btctime/1"

// Policy is the reader's local policy (§7). Received data sets none of it.
type Policy struct {
	// Network and Genesis are the only chain whose headers count as production evidence.
	Network string
	Genesis string // display hash
	// MinConfirmations: tip − height + 1 below this is insufficient-confirmations.
	MinConfirmations int64
	// SettledDepth: confirmations, in the last validated view, past which a bound keeps bitcoin quality when that
	// view is no longer fresh (§9.4).
	SettledDepth int64
	// PriorityMargin: extra blocks the earlier bound must lead by to rank (§8.3).
	PriorityMargin int64
	// MaxViewAge: since the last successful sync. MaxTipAge: the tip header's time against the local clock.
	MaxViewAge, MaxTipAge time.Duration
	// ChainworkFloor: a view whose tip has less cumulative work is not ready (nil: no floor).
	ChainworkFloor *big.Int
	// AnchorBytes caps the anchors statement (64 KiB); Limits cap the proof.
	AnchorBytes int
	Limits      Limits
}

// DefaultPolicy returns the defaults an implementation ships (§7).
func DefaultPolicy() Policy {
	return Policy{
		Network: "mainnet", Genesis: MainnetGenesisHash,
		MinConfirmations: 6, SettledDepth: 144, PriorityMargin: 0,
		MaxViewAge: time.Hour, MaxTipAge: 6 * time.Hour,
		AnchorBytes: 64 << 10, Limits: DefaultLimits(),
	}
}

// Fingerprint is a content hash of the policy (I14): two readers that disclose the same fingerprint applied the
// same policy.
func (p Policy) Fingerprint() string {
	floor := "none"
	if p.ChainworkFloor != nil {
		floor = p.ChainworkFloor.Text(16)
	}
	s := fmt.Sprintf("%s\nnetwork %s\ngenesis %s\nconfirmations %d\nsettled %d\nmargin %d\nview-age %d\ntip-age %d\nfloor %s\nanchor-bytes %d\nproof-bytes %d\ndepth %d\nnodes %d\n",
		VerifierVersion, p.Network, p.Genesis, p.MinConfirmations, p.SettledDepth, p.PriorityMargin,
		int64(p.MaxViewAge/time.Second), int64(p.MaxTipAge/time.Second), floor, p.AnchorBytes,
		p.Limits.ProofBytes, p.Limits.Depth, p.Limits.Nodes)
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

// Evidence is the structured record of one bound (§8.1). It is what every consumer reads; an exit code alone is
// not an authority API.
type Evidence struct {
	Quality Quality
	State   State
	// Why explains any state other than verified, in words a reader can act on.
	Why string
	// Refusal is set for an anchor refused outright (intrinsic or operational), scoped to the anchors statement.
	Refusal *refusal.Refusal

	Signer, Anchor, Covered, Proof string

	Network, GenesisHash, ChainID string
	BlockHeight                   int64
	BlockHash                     string // display order
	HeaderTime                    uint32 // nTime: miner-reported, display only, never an ordering key
	Confirmations                 int64
	ChainValidation               string
	ChainEpoch                    uint64
	Bootstrap                     string
	// AsOf is the view's last successful sync, set when the bound rests on a view that is no longer fresh.
	AsOf              time.Time
	VerifiedAt        time.Time
	PolicyFingerprint string
	VerifierVersion   string
	// Notes are further disclosures: an earlier attestation not evaluable, pending calendars, the eclipse limit.
	Notes []string
}

// Live reports whether the evidence ranks for priority: verified at bitcoin quality.
func (e Evidence) Live() bool { return e.State == StateVerified && e.Quality == QualityBitcoin }

// String is a one-line display of the evidence.
func (e Evidence) String() string {
	switch e.State {
	case StateVerified:
		s := fmt.Sprintf("bitcoin %s height %d block %s, header time %s (miner-reported), %d confirmations, %s",
			e.Network, e.BlockHeight, e.BlockHash, time.Unix(int64(e.HeaderTime), 0).UTC().Format(time.RFC3339), e.Confirmations, e.ChainValidation)
		if !e.AsOf.IsZero() {
			s += ", as of " + e.AsOf.UTC().Format(time.RFC3339)
		}
		return s
	case StateVerifiedHistorical:
		return fmt.Sprintf("verified-historical: height %d, header time %s (miner-reported) as of %s; priority not computed from it",
			e.BlockHeight, time.Unix(int64(e.HeaderTime), 0).UTC().Format(time.RFC3339), e.AsOf.UTC().Format(time.RFC3339))
	}
	return string(e.State) + ": " + e.Why
}

// BlobSource opens a proof blob the reader holds, by its digest ("sha256:" + hex). It never fetches.
type BlobSource interface {
	OpenBlob(digest string) (io.ReadCloser, bool)
}

// MapBlobs is an in-memory BlobSource.
type MapBlobs map[string][]byte

// OpenBlob implements BlobSource.
func (m MapBlobs) OpenBlob(d string) (io.ReadCloser, bool) {
	b, ok := m[d]
	if !ok {
		return nil, false
	}
	return io.NopCloser(bytes.NewReader(b)), true
}

// Put stores b under its digest and returns the digest.
func (m MapBlobs) Put(b []byte) string {
	h := sha256.Sum256(b)
	d := "sha256:" + hex.EncodeToString(h[:])
	m[d] = append([]byte(nil), b...)
	return d
}

// Verifier evaluates anchors statements against one immutable chain snapshot. View nil means no backend is
// configured (C-btc-06). Unavailable, when set, says the configured backend could not be read.
type Verifier struct {
	Policy      Policy
	View        *ChainView
	Unavailable string
	Blobs       BlobSource
	// Now is the reader's clock (freshness, §7).
	Now func() time.Time
}

// Evaluate runs §4's binding checks 3–7 and §5's attestation selection on one anchors statement, then applies the
// policy in the current view. Checks 1 and 2 (the statement verifies, is chained in its signer's log, and its
// covered head is in its own prefix) are the log's and the resolver's, which call a TimeVerifier only for an
// anchors statement that passed them.
func (v *Verifier) Evaluate(a *wire.Statement) Evidence {
	e := Evidence{Quality: QualityLocal, Signer: a.Signer, Anchor: a.ID, Covered: str(a.Body, "covered"), Proof: str(a.Body, "proof"),
		PolicyFingerprint: v.Policy.Fingerprint(), VerifierVersion: VerifierVersion}
	if v.Now != nil {
		e.VerifiedAt = v.Now()
	}
	fail := func(s State, why string, a ...any) Evidence {
		e.State, e.Why = s, fmt.Sprintf(why, a...)
		return e
	}
	if a.Kind != "anchors" {
		return fail(StateInvalidAnchor, "statement kind %q is not anchors", a.Kind)
	}
	if lim := v.Policy.AnchorBytes; lim > 0 && len(a.Line()) > lim {
		e.Refusal = &refusal.Refusal{Class: refusal.Operational, Reason: refusal.SizeLimit, Detail: fmt.Sprintf("anchors statement over %d bytes; scope this anchor", lim)}
		return fail(StateRefused, "%s", e.Refusal)
	}
	if f := str(a.Body, "proof_format"); f != ProofFormat {
		return fail(StateUnsupported, "proof_format %q is not %s; this reader verifies no other format, so the anchor grants nothing", f, ProofFormat)
	}
	covered, err := hex.DecodeString(e.Covered)
	if err != nil || len(covered) != 32 {
		return fail(StateInvalidAnchor, "covered is not a statement id")
	}
	// §4 check 4: the blob is held and hashes to proof. Never fetched.
	if v.Blobs == nil {
		return fail(StateMissingProof, "proof blob %s not held (no blob store); no fetch attempted", e.Proof)
	}
	rc, ok := v.Blobs.OpenBlob(e.Proof)
	if !ok {
		return fail(StateMissingProof, "proof blob %s not held; no fetch attempted", e.Proof)
	}
	lim := v.Policy.Limits
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	// read once, at most one byte over the limit; the same bytes are hashed and parsed (§9.2)
	b, err := io.ReadAll(io.LimitReader(rc, int64(lim.ProofBytes)+1))
	rc.Close()
	if err != nil {
		return fail(StateMissingProof, "proof blob %s unreadable: %v", e.Proof, err)
	}
	if len(b) > lim.ProofBytes {
		e.Refusal = &refusal.Refusal{Class: refusal.Operational, Reason: refusal.SizeLimit, Detail: fmt.Sprintf("proof blob over %d bytes; scope this anchor", lim.ProofBytes)}
		return fail(StateRefused, "%s", e.Refusal)
	}
	if h := sha256.Sum256(b); "sha256:"+hex.EncodeToString(h[:]) != e.Proof {
		return fail(StateMissingProof, "held bytes for proof blob %s do not hash to it", e.Proof)
	}
	return v.proof(e, b, covered)
}

// EvaluateProof runs §4 checks 6 and 7, §5 and §7 on proof bytes the caller already holds against a stamped digest
// (for an anchors statement, the raw bytes of covered). Evaluate calls it; it is exported for fixtures whose
// proof stamps something other than a statement id (the historical mainnet fixture).
func (v *Verifier) EvaluateProof(proof, stamped []byte) Evidence {
	e := Evidence{Quality: QualityLocal, Covered: hex.EncodeToString(stamped), PolicyFingerprint: v.Policy.Fingerprint(), VerifierVersion: VerifierVersion}
	if v.Now != nil {
		e.VerifiedAt = v.Now()
	}
	return v.proof(e, proof, stamped)
}

func (v *Verifier) proof(e Evidence, b, covered []byte) Evidence {
	fail := func(s State, why string, a ...any) Evidence {
		e.State, e.Why = s, fmt.Sprintf(why, a...)
		return e
	}
	lim := v.Policy.Limits
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	p, err := ParseProof(b, lim)
	if err != nil {
		var pe *ProofError
		if errors.As(err, &pe) && pe.State == StateUnsupported {
			return fail(StateUnsupported, "%v", err)
		}
		e.Refusal = &refusal.Refusal{Class: refusal.Intrinsic, Reason: "invalid proof", Detail: err.Error() + "; scope this anchor"}
		return fail(StateInvalidProof, "%v", err)
	}
	if !bytes.Equal(p.FileDigest[:], covered) {
		e.Refusal = &refusal.Refusal{Class: refusal.Intrinsic, Reason: "invalid proof", Detail: "file digest is not the raw bytes of covered; scope this anchor"}
		return fail(StateInvalidProof, "invalid for %s: the proof stamps %s, not the raw bytes of covered %s", e.Signer, hex.EncodeToString(p.FileDigest[:]), e.Covered)
	}
	if p.PendingCount > 0 {
		e.Notes = append(e.Notes, fmt.Sprintf("%d pending calendar attestation(s), never dereferenced", p.PendingCount))
	}
	if p.Unsupported > 0 {
		e.Notes = append(e.Notes, fmt.Sprintf("%d unsupported attestation(s), granting nothing", p.Unsupported))
	}
	if len(p.Bitcoin) == 0 {
		if p.PendingCount > 0 {
			return fail(StatePending, "only calendar attestations (pending); a calendar's promise grants nothing")
		}
		return fail(StateUnsupported, "no Bitcoin attestation")
	}
	return v.chain(e, p)
}

// chain applies §5 (attestation selection) and §7 (policy) against the view.
func (v *Verifier) chain(e Evidence, p *Proof) Evidence {
	fail := func(s State, why string, a ...any) Evidence {
		e.State, e.Why = s, fmt.Sprintf(why, a...)
		return e
	}
	view := v.View
	if view == nil {
		if v.Unavailable != "" {
			return fail(StateUnavailable, "not verified by this reader: chain backend unavailable (%s)", v.Unavailable)
		}
		return fail(StateUnconfigured, "not verified by this reader: no chain backend configured")
	}
	e.Network, e.GenesisHash, e.ChainID, e.ChainValidation, e.ChainEpoch, e.Bootstrap = view.Network, view.GenesisHash, view.ChainID(), view.Mode, view.Epoch, view.Bootstrap
	if view.Network != v.Policy.Network || view.GenesisHash != v.Policy.Genesis {
		return fail(StateUnconfigured, "not verified by this reader: the configured chain is %s (genesis %s), and policy admits only %s as production evidence",
			view.Network, short(view.GenesisHash), v.Policy.Network)
	}
	if f := v.Policy.ChainworkFloor; f != nil && view.TipWork.Cmp(f) < 0 {
		return fail(StateUnavailable, "chain view not ready: tip chainwork below the local floor")
	}
	// §5: every candidate is kept; the lowest eligible height on the accepted chain is selected, never the lowest
	// nTime. A bad or unknown candidate does not invalidate a distinct good one.
	var best *Header
	var bestHeight int64
	var unknown, mismatch, orphan []string
	for _, at := range p.Bitcoin {
		if !at.HeightOK || at.Height < view.Base || at.Height > view.TipHeight {
			if _, ok := view.offChain(at.Height, at.Digest); at.HeightOK && ok {
				orphan = append(orphan, heightText(at)) // a held block above the accepted tip, on a losing branch
			} else {
				unknown = append(unknown, heightText(at))
			}
			continue
		}
		h, _ := view.HeaderAt(at.Height)
		if !bytes.Equal(h.MerkleRoot[:], at.Digest) {
			if _, ok := view.offChain(at.Height, at.Digest); ok {
				orphan = append(orphan, heightText(at))
			} else {
				mismatch = append(mismatch, heightText(at))
			}
			continue
		}
		if best == nil || at.Height < bestHeight {
			hh := h
			best, bestHeight = &hh, at.Height
		}
	}
	if best == nil {
		switch {
		case len(orphan) > 0 && view.Unresolved > 0:
			return fail(StateStaleChain, "attested block is on one of %d tips tied at the greatest chainwork; unresolved, no live eligibility", view.Unresolved)
		case len(orphan) > 0:
			return fail(StateOrphaned, "attested block at %s is not on the accepted (greatest-chainwork) chain", strings.Join(orphan, ", "))
		case len(mismatch) > 0:
			e.Refusal = &refusal.Refusal{Class: refusal.Intrinsic, Reason: "invalid proof", Detail: "calculated digest is not the Merkle root of the header at the attested height; scope this anchor"}
			return fail(StateInvalidProof, "the proof's calculated digest is not the Merkle root of the accepted header at %s", strings.Join(mismatch, ", "))
		}
		return fail(StateUnknownHeight, "attested height %s is not within this reader's chain (heights %d to %d)", strings.Join(unknown, ", "), view.Base, view.TipHeight)
	}
	for _, u := range unknown {
		if n, ok := heightNum(u); !ok || n < bestHeight {
			e.Notes = append(e.Notes, "earlier attestation at "+u+" not evaluable")
		}
	}
	e.BlockHeight, e.BlockHash, e.HeaderTime = bestHeight, best.Hash.String(), best.Time
	e.Confirmations = view.TipHeight - bestHeight + 1
	if e.Confirmations < v.Policy.MinConfirmations {
		return fail(StateInsufficient, "%d confirmations, policy requires %d", e.Confirmations, v.Policy.MinConfirmations)
	}
	// freshness (§7, §9.4)
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	switch {
	case view.LastSync.IsZero():
		return fail(StateStaleChain, "chain view never synced")
	case now.Before(view.LastSync):
		return fail(StateStaleChain, "local clock is before the last sync (%s); no live eligibility until a sync succeeds", view.LastSync.UTC().Format(time.RFC3339))
	}
	fresh := now.Sub(view.LastSync) <= v.Policy.MaxViewAge && now.Sub(time.Unix(int64(view.TipTime), 0)) <= v.Policy.MaxTipAge
	if fresh {
		e.State, e.Quality = StateVerified, QualityBitcoin
		return e
	}
	e.AsOf = view.LastSync
	if e.Confirmations >= v.Policy.SettledDepth {
		e.State, e.Quality = StateVerified, QualityBitcoin
		e.Notes = append(e.Notes, fmt.Sprintf("view not fresh; the block had %d confirmations (settled depth %d) as of the last sync", e.Confirmations, v.Policy.SettledDepth))
		return e
	}
	e.State = StateVerifiedHistorical
	e.Why = fmt.Sprintf("view not fresh and the block had %d confirmations as of the last sync, below the settled depth %d", e.Confirmations, v.Policy.SettledDepth)
	return e
}

func heightText(a Attestation) string {
	if !a.HeightOK {
		return "height beyond int64"
	}
	return fmt.Sprintf("height %d", a.Height)
}

func heightNum(s string) (int64, bool) {
	var n int64
	_, err := fmt.Sscanf(s, "height %d", &n)
	return n, err == nil
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func str(o *canon.Object, k string) string {
	if o == nil {
		return ""
	}
	if v, ok := o.Get(k); ok {
		if s, ok := v.(canon.String); ok {
			return string(s)
		}
	}
	return ""
}

// Relation is the comparison relation of §8.3, computed apart from any display sort.
type Relation string

const (
	EarlierCommitment Relation = "earlier-commitment"
	WithinMargin      Relation = "within-margin"
	SameBlock         Relation = "same-block"
	Unverified        Relation = "unverified"
	Incomparable      Relation = "incomparable"
	// Later is EarlierCommitment seen from the other side.
	Later Relation = "later"
)

// Compare relates bound a to bound b under the priority margin. Only EarlierCommitment ranks a before b.
func Compare(a, b Evidence, margin int64) Relation {
	for _, x := range []Evidence{a, b} {
		if x.State == StateOrphaned || x.State == StateStaleChain {
			return Incomparable
		}
	}
	switch {
	case !a.Live() || !b.Live():
		return Unverified
	case a.Network != b.Network || a.GenesisHash != b.GenesisHash || a.ChainEpoch != b.ChainEpoch:
		return Incomparable
	case a.BlockHeight == b.BlockHeight:
		return SameBlock
	case a.BlockHeight < b.BlockHeight && b.BlockHeight-a.BlockHeight > margin:
		return EarlierCommitment
	case b.BlockHeight < a.BlockHeight && a.BlockHeight-b.BlockHeight > margin:
		return Later
	}
	return WithinMargin
}

// Exit is the verify exit code for a batch of evidence (§10): 1 when any is invalid-proof or invalid-anchor, else 3
// when any could not be checked, else 0. An empty batch requested nothing and exits 0.
func Exit(es []Evidence) int {
	code := 0
	for _, e := range es {
		switch {
		case e.State == StateInvalidProof || e.State == StateInvalidAnchor:
			return 1
		case !e.Live():
			code = 3
		}
	}
	return code
}

// ErrIncomplete is returned by Batch when the chain changed during the batch twice in a row (§6.3).
var ErrIncomplete = errors.New("incomplete: the chain view changed during the batch and again on the one retry")

// Batch evaluates anchors against one snapshot of c. If the chain's epoch moved while the batch ran, it retries
// once against a new snapshot; if it moved again it reports ErrIncomplete and no evidence, never a mix of views.
func Batch(c *Chain, base Verifier, anchors []*wire.Statement) ([]Evidence, error) {
	for try := 0; try < 2; try++ {
		v := base
		v.View = c.Snapshot()
		out := make([]Evidence, len(anchors))
		for i, a := range anchors {
			out[i] = v.Evaluate(a)
		}
		if c.Epoch() == v.View.Epoch {
			return out, nil
		}
	}
	return nil, ErrIncomplete
}
