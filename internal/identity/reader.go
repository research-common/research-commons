package identity

import (
	"bytes"
	"fmt"

	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// Evaluator is the production reader's actor evaluator over the statements it holds: what every view, gate and
// command that builds a resolver passes as its policy.ActorEligibility. Built once per invocation from the exact
// held lines (and, at a gate, the package's), it is:
//
//   - nil when no line is an rc/2 line. Nothing held carries an identity actor (the reader reads none from rc/1),
//     so there is nothing to evaluate, and every answer is exactly the hook-absent one: a corpus with no rc/2 line
//     reads byte for byte as it did before the reader was active.
//   - the Actors over Admit otherwise.
//   - when Admit fails as a whole (more than MaxAdmitLines authenticated statements: there is no partial snapshot)
//     an evaluator that answers `unknown` naming the failure for every statement with an identity actor, and the
//     certain `no_identity_actor` denial for every other one. Never a crash, never a key fallback.
func Evaluator(lines [][]byte) policy.ActorEligibility {
	any := false
	for _, l := range lines {
		if mayBeCandidate(l) && wire.CandidateMajorLine(l) {
			any = true
			break
		}
	}
	if !any {
		return nil
	}
	a, err := NewActors(lines)
	if err != nil {
		return Unavailable{Err: err}
	}
	return a
}

// mayBeCandidate is a cheap prefilter: a line whose bytes never spell the rc/2 marker is not an rc/2 line.
func mayBeCandidate(l []byte) bool { return bytes.Contains(l, []byte(`"rc/2"`)) }

// Unavailable is the evaluator of a reader whose held evidence could not be admitted (Admit failed as a whole). It
// decides nothing about any identity.
type Unavailable struct{ Err error }

// Eligible implements policy.ActorEligibility: for a statement with an identity actor, unknown for the identity
// it names, naming the failure (the identity's question is undecided, not answered for its key); the certain
// no_identity_actor denial for every other statement (it acts for no identity, whatever the evidence).
func (u Unavailable) Eligible(st *wire.Statement) (string, string, []string) {
	if st != nil && st.Actor != nil {
		return st.Actor.Identity, policy.ActorUnknown, []string{"model_limit: " + u.Err.Error()}
	}
	return "", policy.ActorDenied, []string{"no_identity_actor"}
}

// Evaluator implements policy.ActorEvaluator.
func (u Unavailable) Evaluator() string { return fmt.Sprintf("no identity evaluation (%v)", u.Err) }
