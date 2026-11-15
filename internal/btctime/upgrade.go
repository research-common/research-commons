package btctime

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/research-common/research-commons/internal/refusal"
)

// The writer's half of §2 "Upgrade" and of multi-calendar stamping, without a network: UpgradeProof asks the
// calendars the author's policy names for each pending commitment and merges every answer in; UnionProofs merges
// several calendars' pending proofs for one digest into one. The caller supplies the calendar clients (a test, a
// mock); nothing here dials.

// Upgrader asks one calendar for the completed timestamp of a pending commitment: the bare answer (a timestamp
// rooted at the commitment) or ErrStillPending when the calendar has none yet. Any other error is that calendar's
// failure.
type Upgrader interface {
	URI() string
	Upgrade(commitment []byte) ([]byte, error)
}

// ErrStillPending is an Upgrader's answer when the calendar has no completed timestamp for the commitment yet (the
// calendar protocol's 404): the proof stays pending; it is not the calendar's failure.
var ErrStillPending = errors.New("still pending (the calendar has no completed timestamp for this commitment yet)")

// AskResult is what one pending commitment's calendar answered.
type AskResult string

const (
	// AskNotInPolicy: the pending attestation names a calendar the author's policy does not; it is not contacted.
	AskNotInPolicy AskResult = "not in local calendar policy"
	// AskDryRun: the calendar would be asked (a dry run contacts nothing).
	AskDryRun AskResult = "would ask"
	// AskPending: the calendar answered that the commitment is not yet in a block.
	AskPending AskResult = "pending"
	// AskFailed: the calendar could not be asked or answered with an error.
	AskFailed AskResult = "failed"
	// AskRefused: the calendar answered, and the answer was refused (it does not parse, roots elsewhere, is too big).
	AskRefused AskResult = "refused"
	// AskAnswered: the calendar's answer was merged into the proof.
	AskAnswered AskResult = "answered"
)

// UpgradeAsk is one (calendar, commitment) question and its outcome.
type UpgradeAsk struct {
	URI        string // the pending attestation's calendar URI, as the proof holds it
	Commitment []byte
	Result     AskResult
	Err        error // AskFailed, AskRefused
}

// UpgradeResult is what UpgradeProof did. Proof is set only when the merged proof gained a Bitcoin attestation the
// stored proof did not have; it is then canonical, parsed again, and rooted at the stored proof's file digest.
type UpgradeResult struct {
	Asks       []UpgradeAsk
	Proof      []byte
	Services   []string // the calendars whose answer was merged, in the order asked
	Heights    []int64  // the merged proof's Bitcoin attestation heights (when Proof is set)
	HadBitcoin bool     // the stored proof already carries a Bitcoin attestation
	Contacted  int      // calendars asked (questions sent)
	Failed     int      // of those, failed or refused
	Pending    int      // of those, still pending
}

// TrimCalendarURI is the calendar-policy match key: the URI with one trailing "/" removed. A pending attestation's
// URI matches a configured calendar when the two keys are equal byte for byte.
func TrimCalendarURI(u string) string { return strings.TrimSuffix(u, "/") }

// UpgradeProof upgrades a stored `ots-detached-v1` proof (bitcoin-time note §2 "Upgrade"). Each pending
// attestation's calendar URI is matched against cals (keyed by TrimCalendarURI of the configured URL); a URI
// outside the policy is reported and not contacted. Each matching (calendar, commitment) pair is asked once; every
// answer is merged with Merge (a union: pending attestations are kept), and a refused answer is scoped to its
// calendar. With dry set nothing is asked. The error is for a stored proof that does not parse.
func UpgradeProof(proof []byte, cals map[string]Upgrader, dry bool, lim Limits) (*UpgradeResult, error) {
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	before, err := ParseProof(proof, lim)
	if err != nil {
		return nil, err
	}
	tree, err := ParseTree(proof, lim)
	if err != nil {
		return nil, err
	}
	res := &UpgradeResult{HadBitcoin: len(before.Bitcoin) > 0}
	asked := map[string]bool{}
	for _, pc := range PendingCommitments(tree) {
		key := TrimCalendarURI(pc.URI) + "\x00" + string(pc.Commitment)
		if asked[key] {
			continue
		}
		asked[key] = true
		ask := UpgradeAsk{URI: pc.URI, Commitment: pc.Commitment}
		cal, ok := cals[TrimCalendarURI(pc.URI)]
		switch {
		case !ok:
			ask.Result = AskNotInPolicy
		case dry:
			ask.Result = AskDryRun
		default:
			res.Contacted++
			body, err := cal.Upgrade(pc.Commitment)
			switch {
			case errors.Is(err, ErrStillPending):
				ask.Result = AskPending
				res.Pending++
			case err != nil:
				ask.Result, ask.Err = AskFailed, err
				res.Failed++
			default:
				merged, err := Merge(tree, pc.Commitment, body, lim)
				if err != nil {
					ask.Result, ask.Err = AskRefused, err
					res.Failed++
					break
				}
				tree = merged
				ask.Result = AskAnswered
				if !containsString(res.Services, cal.URI()) {
					res.Services = append(res.Services, cal.URI())
				}
			}
		}
		res.Asks = append(res.Asks, ask)
	}
	if len(res.Services) == 0 {
		return res, nil
	}
	out := tree.Serialize()
	after, err := ParseProof(out, lim)
	if err != nil {
		return nil, fmt.Errorf("upgrade: the merged proof does not parse: %w", err)
	}
	if after.FileDigest != before.FileDigest {
		return nil, &refusal.Refusal{Class: refusal.Intrinsic, Reason: refusal.UpgradeRootedElsewhere, Detail: "the merged proof is rooted at another file digest"}
	}
	if len(after.Bitcoin) <= len(before.Bitcoin) {
		return res, nil
	}
	res.Proof = out
	for _, b := range after.Bitcoin {
		res.Heights = append(res.Heights, b.Height)
	}
	return res, nil
}

// UnionProofs merges pending proofs for one file digest (one per calendar that answered a stamp) into one proof:
// the reference library's merge at the root, so every calendar's branch and pending attestation is kept. One proof
// is returned unchanged; several are merged and written in canonical order, and the result is parsed again under
// lim. Proofs rooted at different digests are refused.
func UnionProofs(proofs [][]byte, lim Limits) ([]byte, error) {
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	switch len(proofs) {
	case 0:
		return nil, errors.New("no proof to merge")
	case 1:
		return proofs[0], nil
	}
	var work *Tree
	for i, p := range proofs {
		t, err := ParseTree(p, lim)
		if err != nil {
			return nil, fmt.Errorf("proof %d: %w", i+1, err)
		}
		if work == nil {
			work = t
			continue
		}
		if t.FileDigest != work.FileDigest {
			return nil, &refusal.Refusal{Class: refusal.Intrinsic, Reason: refusal.UpgradeRootedElsewhere,
				Detail: fmt.Sprintf("proof %d is rooted at %x, not %x", i+1, t.FileDigest[:], work.FileDigest[:])}
		}
		mergeNode(work.Root, t.Root)
	}
	out := work.Serialize()
	back, err := ParseTree(out, lim)
	if err != nil {
		return nil, fmt.Errorf("merged proof: %w", err)
	}
	if !bytes.Equal(back.Serialize(), out) {
		return nil, errors.New("merged proof is not a fixed point of the writer")
	}
	return out, nil
}

func containsString(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
