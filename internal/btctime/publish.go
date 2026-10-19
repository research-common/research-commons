package btctime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// Stamp-at-publish (bitcoin-time note §2). The order is observable: the statements are signed, the covered head's
// raw 32 bytes go to the calendars, the pending proof is stored as a blob, an anchors statement naming it is
// appended, and only then does anything reach the transport. This is the writer's side; it never runs during a
// read.

// Calendar submits a stamped digest and returns the pending proof bytes (an `ots-detached-v1` file). Calendars are
// the author's local policy; a test supplies a mock.
type Calendar interface {
	URI() string
	Submit(digest [32]byte) ([]byte, error)
}

// Transport is whatever moves bytes off the machine (a hub push). The first call is the first byte out.
type Transport interface {
	Send(lines [][]byte, blobs map[string][]byte) error
}

// AnchorDefault is the decision when every calendar fails (§2 step 3).
type AnchorDefault string

const (
	// AnchorRequired refuses to publish: nothing is transported.
	AnchorRequired AnchorDefault = "anchor required"
	// AnchorNone publishes with `anchor: none` recorded and a warning.
	AnchorNone AnchorDefault = "anchor: none"
)

// PublishPolicy is the author's local policy for stamping.
type PublishPolicy struct {
	// Override, when set, replaces the default by standing for every statement.
	Override AnchorDefault
}

// DefaultFor is the default by standing (§2 step 3, §17 decided 2): anchor required for an authored without
// provenance, a statement carrying fulfills, an authored or observed whose availability.redistribution is withheld,
// and an observed whose capture.evidence is anchored-at-capture; anchor: none for everything else. why names the
// rule that decided.
func DefaultFor(st *wire.Statement) (d AnchorDefault, why string) {
	b := st.Body
	if b == nil {
		return AnchorNone, "no rule requires an anchor for this statement"
	}
	if _, ok := b.Get("fulfills"); ok {
		return AnchorRequired, "carries fulfills (a pre-registration is only worth its bound)"
	}
	if st.Kind == "authored" || st.Kind == "observed" {
		if av, ok := b.Get("availability"); ok {
			if o, ok := av.(*canon.Object); ok && str(o, "redistribution") == "withheld" {
				return AnchorRequired, "availability.redistribution is withheld (a commitment to bytes not yet released)"
			}
		}
	}
	switch st.Kind {
	case "authored":
		if _, ok := b.Get("provenance"); !ok {
			return AnchorRequired, "authored without provenance (its priority is its time bound)"
		}
		return AnchorNone, "authored with provenance (a derivation-group member; priority is not computed within a group)"
	case "observed":
		if c, ok := b.Get("capture"); ok {
			if o, ok := c.(*canon.Object); ok && str(o, "evidence") == "anchored-at-capture" {
				return AnchorRequired, "observed with capture.evidence anchored-at-capture"
			}
		}
		return AnchorNone, "observed capture without anchored-at-capture evidence (a closing capture window is not stopped by a calendar outage)"
	}
	return AnchorNone, "no rule requires an anchor for this statement"
}

// Appender signs the anchors statement as the next line of the author's log and returns it.
type Appender func(body *canon.Object) (line []byte, id string, err error)

// PublishResult reports what publish did and which policy decided it. It is never silent.
type PublishResult struct {
	Anchor     string // the anchors statement id; "" when anchor: none was recorded
	ProofBlob  string
	Services   []string
	Decision   AnchorDefault // set when every calendar failed
	DecidedBy  string        // the rule or override that decided
	Warnings   []string
	Lines      [][]byte
	Blobs      map[string][]byte
	Calendared []string // every calendar tried, in order
}

// ErrAnchorRequired is the refusal when every calendar failed and policy requires an anchor.
var ErrAnchorRequired = errors.New(string(AnchorRequired))

// Publish stamps and transports. lines are the signed statements being published, in log order; head is the last
// of them, the covered head. blobs are the content blobs going with them.
func Publish(head *wire.Statement, lines [][]byte, blobs map[string][]byte, cals []Calendar, pol PublishPolicy, appendAnchor Appender, tr Transport) (*PublishResult, error) {
	res := &PublishResult{Blobs: map[string][]byte{}}
	for k, v := range blobs {
		res.Blobs[k] = v
	}
	res.Lines = append(res.Lines, lines...)
	var digest [32]byte
	raw, err := hex.DecodeString(head.ID)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("covered head id %q is not 32 bytes of hex", head.ID)
	}
	copy(digest[:], raw) // the raw hash bytes: no hex, no newline, no framing (§2 step 2)
	var proof []byte
	var failures []string
	for _, c := range cals {
		res.Calendared = append(res.Calendared, c.URI())
		p, err := c.Submit(digest)
		if err != nil {
			failures = append(failures, c.URI()+": "+err.Error())
			continue
		}
		if proof == nil {
			proof = p
		}
		res.Services = append(res.Services, c.URI())
	}
	if proof == nil {
		def, why := DefaultFor(head)
		if pol.Override != "" {
			def, why = pol.Override, "local policy override ("+string(pol.Override)+")"
		}
		res.Decision, res.DecidedBy = def, why
		tried := strings.Join(res.Calendared, ", ")
		if tried == "" {
			tried = "none configured"
		}
		if def == AnchorRequired {
			return res, &refusal.Refusal{Class: refusal.Policy, Reason: string(AnchorRequired),
				Detail: fmt.Sprintf("every calendar failed (tried: %s; %s); decided by: %s; override with a local policy of %q; nothing transported",
					tried, strings.Join(failures, "; "), why, AnchorNone)}
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf("published with anchor: none recorded: every calendar failed (tried: %s); decided by: %s", tried, why))
		return res, tr.Send(res.Lines, res.Blobs)
	}
	h := sha256.Sum256(proof)
	res.ProofBlob = "sha256:" + hex.EncodeToString(h[:])
	res.Blobs[res.ProofBlob] = proof
	svc := canon.Array{}
	for _, s := range res.Services {
		svc = append(svc, canon.String(s))
	}
	body := &canon.Object{Keys: []string{"covered", "proof", "proof_format", "services"}, Members: map[string]canon.Value{
		"covered": canon.String(head.ID), "proof": canon.String(res.ProofBlob), "proof_format": canon.String(ProofFormat), "services": svc,
	}}
	line, id, err := appendAnchor(body)
	if err != nil {
		return res, err
	}
	res.Anchor = id
	res.Lines = append(res.Lines, line)
	if len(failures) > 0 {
		res.Warnings = append(res.Warnings, "some calendars failed: "+strings.Join(failures, "; "))
	}
	return res, tr.Send(res.Lines, res.Blobs)
}
