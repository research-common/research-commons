package policy

import "github.com/research-common/research-commons/internal/wire"

// NoEvaluator is the reason an identity statement's actor is `unknown` where the reader has no actor evaluator.
const NoEvaluator = "no identity evaluator"

// ActorState is the one answer every surface prints about an identity statement's actor (`show`, `explain` and
// `hub check` print it alike): the identity the evaluator binds the statement to ("" when it binds none), the
// state (ActorEligible, ActorDenied or ActorUnknown) and the reasons. With no evaluator it is unknown, naming
// NoEvaluator. An actor the evaluator binds to no identity is never eligible (it acts for no one, never its key's
// either) and says so. Nothing here reads policy or trust: eligibility is authority, not trust.
func ActorState(a ActorEligibility, st *wire.Statement) (identity, state string, why []string) {
	if a == nil {
		return "", ActorUnknown, []string{NoEvaluator}
	}
	identity, state, why = a.Eligible(st)
	if state != ActorEligible && state != ActorDenied {
		state = ActorUnknown // anything else is read as unknown (ActorEligibility)
	}
	if identity == "" && state == ActorEligible {
		state = ActorUnknown
	}
	if identity == "" {
		why = append(why, "binds to no identity")
	}
	return identity, state, why
}
