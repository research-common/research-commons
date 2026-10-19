package run

import (
	"strings"
)

// Comparing a re-run with its pin (execution note §4 "Comparison", §5.2, §5.3).

// Comparator runs a declared comparator on two outputs: the same signature as the resolver's Comparator, so
// one implementation serves both the reader's re-run and the resolver's grade path. Result is "match",
// "diverged", "not comparable" or "unchecked" (it could not run); why explains the last two.
type Comparator interface {
	Compare(comparator, a, b string) (result, why string)
}

// Pin is what a re-run is compared against: the workflow's declarations (from its `authored` statement, never
// from the spec) and the pinned result (from the `authored` or `reproduced` being verified).
type Pin struct {
	// Mode is the workflow's replication: "bytes", "protocol", "none", or "" (undeclared).
	Mode       string
	Comparator string
	// Match is the workflow's environment_match; nil means the default for the mode (§1 table).
	Match []string
	// Env is the pinned environment record, field name → canonical JSON (Fields).
	Env map[string]string
	// Output names the spec output the pinned blob is; Digest is the pinned blob. When Output is "" the spec
	// must have exactly one output.
	Output, Digest string
}

// MatchFields is the environment_match in force.
func (p Pin) MatchFields() []string {
	if p.Match != nil {
		return p.Match
	}
	return DefaultMatch(p.Mode)
}

// Decision is a re-run's comparison with its pin.
type Decision struct {
	Token   Token
	Explain []string
	// Mismatch is the environment comparison, side-by-side fields included.
	Mismatch Mismatch
}

// Decide compares a completed run with its pin. stopped is the token of a run that compared nothing (a cap, a
// failed step, an incomplete output), nil when the step completed and produced got (the digest of the pinned
// output). Order (§4, §5.2):
//
//  1. an environment mismatch on a field environment_match names is exit 5, and the byte comparison is
//     `not compared (environment mismatch)`. It comes first: a run in an environment the pin does not declare
//     says nothing about the pin, whether it completed or not;
//  2. a run that compared nothing keeps its own token (exit 3), and explain says what that means for the claim;
//  3. otherwise the outputs are compared under the workflow's mode (§5.3).
func Decide(pin Pin, rerun map[string]string, stopped *Token, got string, cmp Comparator, acceptNative bool) Decision {
	var d Decision
	d.Mismatch = Compare(pin.Env, rerun, pin.MatchFields(), acceptNative)
	if len(d.Mismatch.Side) > 0 {
		d.Explain = append(d.Explain, "environment fields not named by environment_match differ (shown side by side, never exit 5): "+strings.Join(d.Mismatch.Side, ", "))
	}
	if d.Mismatch.Profile != "" && d.Mismatch.ProfileAccepted {
		d.Explain = append(d.Explain, d.Mismatch.Profile+": named; the comparison proceeds because the reader's policy accepts native records")
	}
	if d.Mismatch.Mismatched() {
		d.Token = d.Mismatch.Token()
		d.Explain = append(d.Explain, "not compared (environment mismatch); next step: run where the pinned environment exists")
		return d
	}
	if stopped != nil {
		d.Token = *stopped
		switch {
		case stopped.Stopped() && stopped.Below:
			d.Explain = append(d.Explain, "the step ran below its declared profile at the reader's choice; this is not evidence of a workflow defect; next step: run where the declared profile is available")
		case stopped.Stopped():
			d.Explain = append(d.Explain, "a limit of this reader stopped the step, so it could not check; next step: raise the limit")
		case pin.Mode == "bytes":
			d.Explain = append(d.Explain, "the step failed or left an output missing in an environment that matches the pin: the determinism claim may be weaker than declared (a hidden dependency, nondeterminism); the pinned bytes are not shown wrong, and no statement is changed or emitted on the author's behalf")
		default:
			d.Explain = append(d.Explain, "the step compared nothing; the pinned bytes are not shown wrong")
		}
		return d
	}
	d.Token, d.Explain = compareOutputs(pin, got, cmp, d.Explain)
	return d
}

func compareOutputs(pin Pin, got string, cmp Comparator, explain []string) (Token, []string) {
	same := got == pin.Digest
	switch pin.Mode {
	case "bytes":
		if same {
			return Token{Kind: Match}, explain
		}
		return Token{Kind: Diverged}, append(explain, "an environment differs or the determinism claim is wrong; both environment records are shown side by side; the earlier statement is unchanged")
	case "protocol":
		if pin.Comparator == "" {
			return Token{Kind: Unchecked}, append(explain, "the workflow declares protocol replication and no comparator")
		}
		if same {
			return Token{Kind: Match, Identical: true}, append(explain, "identical bytes (protocol workflow): no T0")
		}
		if cmp == nil {
			return Token{Kind: Unchecked}, append(explain, "no comparator runner configured")
		}
		// the pair in digest order, as the resolver asks it, so an asymmetric comparator is asked one way round
		a, b := pin.Digest, got
		if b < a {
			a, b = b, a
		}
		switch res, why := cmp.Compare(pin.Comparator, a, b); res {
		case "match":
			return Token{Kind: Match}, explain
		case "diverged":
			return Token{Kind: Diverged}, explain
		case "not comparable":
			return Token{Kind: NotComparable}, append(explain, "not comparable: "+why)
		default:
			return Token{Kind: Unchecked}, append(explain, "comparator did not run: "+why)
		}
	}
	mode := pin.Mode
	if mode == "" {
		mode = "undeclared"
	}
	return Token{Kind: Unchecked}, append(explain, "replication "+mode+": no comparison is made")
}

// DerivationPrefix is how the resolver's VerifyExit names a derivation cause ("derivation: not re-derived").
const DerivationPrefix = "derivation: "

// VerifyWithRerun is `verify` when the reader also re-ran the derivation (claims-model §13; the resolver's
// VerifyExit says the reader's own re-run "replaces this answer when it runs"). The statement-only answer's
// derivation causes are replaced by the re-run's token; every other cause (authorship, contested fields)
// stays. Exit 1 needs a completed comparison that disagreed; 5 an environment mismatch; a re-run token of exit
// 3 or 4 is a cause like any other.
func VerifyWithRerun(stmtExit int, stmtWhy []string, rerun Token) (int, []string) {
	var why []string
	for _, w := range stmtWhy {
		if !strings.HasPrefix(w, DerivationPrefix) {
			why = append(why, w)
		}
	}
	switch e := rerun.Exit(); e {
	case 1, 4, 5:
		return e, append([]string{"re-run: " + rerun.String()}, why...)
	case 3:
		why = append(why, "re-run: "+rerun.String())
	}
	if len(why) > 0 {
		return 3, why
	}
	return 0, nil
}
