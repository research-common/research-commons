package resolve

import (
	"strings"

	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/policy"
)

// countGate is the counting gate of one statement for a consumer that counts it (corroboration, a task's
// submissions, an exact selection pin). A bare-key statement keeps the bare-key gate (Counts) exactly. A
// statement the actor evaluator binds to an identity is an identity-context statement: it counts by evidence
// readiness and actor eligibility, and its signer's bare-key status is shown beside it, not applied as a filter
// (identity profile §4.1: the reader must not discard identity evidence by first running a global bare-key
// revocation filter; §6 "Requirements on consumers"). An identity-context statement whose actor is denied or
// undecided is not counted, under any counting unit (§5.3: key counting never bypasses a missing grant).
//
// With no evaluator (every production reader) this is Counts, and the evaluator is never asked.
type countGate struct {
	// Identity is the identity the evaluator binds the statement to; "" for a bare-key statement.
	Identity string
	Counts   bool
	// Why is why it is not counted; for a counted identity-context statement whose key the bare-key gate would
	// have left out, the bare-key status shown beside it. "" otherwise.
	Why string
	// State and Reasons are the evaluator's answer for an identity-context statement it binds (policy.Actor*
	// and its reasons, "code: detail"); "" and nil otherwise. A consumer that must tell an undecided answer from a
	// denial (a resource slot: unknown is contested, never silently unauthorized) reads them.
	State   string
	Reasons []string
}

func (r *Resolver) gate(p *Placed) countGate {
	if r.actors == nil || !p.EvidenceReady() {
		// Not evidence-ready (detached, unverified, uninterpreted: every rc/2 line under the rc/1 reader) counts
		// toward nothing on either path, and the evaluator is not asked.
		return countGate{Counts: p.Counts(), Why: whyNot(p)}
	}
	id, state, why := r.actors.Eligible(p.St)
	if id == "" && p.IdentityContext() {
		// A signed actor the evaluator binds to no identity: not the key's evidence either (never a key fallback).
		return countGate{Why: "names identity " + keylog.Short(p.St.Actor.Identity) + ", and the actor evaluator binds it to no identity (" +
			strings.Join(why, "; ") + "); never counted as its key"}
	}
	if id == "" {
		return countGate{Counts: p.Counts(), Why: whyNot(p)}
	}
	g := countGate{Identity: id, State: state, Reasons: why}
	because := ""
	if len(why) > 0 {
		because = " (" + strings.Join(why, "; ") + ")"
	}
	switch {
	case state == policy.ActorEligible:
		g.Counts = true
		if !p.keyEventsClear() {
			g.Why = "acts for identity " + keylog.Short(id) + "; its key's bare-key status, shown and not applied: " + keyStatusWhy(p)
		}
	case state == policy.ActorDenied:
		g.Why = "not eligible for identity " + keylog.Short(id) + because
	default:
		g.Why = "names identity " + keylog.Short(id) + ", and whether it acts for it is not established" + because
	}
	return g
}

func whyNot(p *Placed) string {
	if p.Counts() {
		return ""
	}
	return notCountedWhy(p)
}
