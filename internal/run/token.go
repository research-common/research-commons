// Package run is the execution profile (DESIGN-notes-execution.md): what a workflow spec pins, the two
// profiles and the reader's execution policy, staging confinement, caps, the environment record, result
// tokens and `verify` exits for a re-run, and what `run --publish` emits.
//
// The package is split so that every decision is a pure function a test can call without running anything:
//
//   - spec.go: the workflow spec (§1) and what it leaves unpinned;
//   - policy.go, admit.go: the reader's execution policy and the checks made before staging (§2, §2.3, §2.4);
//   - caps.go: cap values from the spec's resource profile and the reader's ceiling (§2.2);
//   - confine.go: the one confinement function for every host-side join of a peer-supplied name (§3);
//   - record.go: the environment record (§4), its validation and its field-by-field comparison;
//   - token.go (this file): result tokens and their `verify` exits (§5.2);
//   - verify.go: the comparison of a re-run with its pin by replication mode (§5.3);
//   - publish.go: what `run --publish` emits (§5.1, §7, §1 rule 3);
//   - runner.go, execute.go: the Runner interface, an in-process runner for tests, and the one path that
//     admits, stages, runs, reads back and records.
//
// A refusal before the step starts is a typed refusal (package refusal), never a result token, and writes no
// record (§5.2). Grades stay the resolver's (package resolve): a re-run gives the reader its own comparison,
// which is the input the resolver's grade path takes (claims-model note §5.2, I9).
package run

import (
	"fmt"
	"strconv"
	"strings"
)

// Kind is the kind of a run result token (execution note §5.2).
type Kind string

const (
	Match            Kind = "match"
	Diverged         Kind = "diverged"
	Unchecked        Kind = "unchecked"
	NotComparable    Kind = "not comparable"
	IncompleteOutput Kind = "incomplete output"
	FailedExit       Kind = "failed: <exit n>"
	FailedCap        Kind = "failed: operational: <cap>"
	Timeout          Kind = "timeout"
	EnvMismatch      Kind = "environment mismatch: <field>"
	// NothingToRerun is not a run token: it is what `verify` reports for a derivation with an unpinned input
	// (§1 rule 1, exit 4). It lives here so the exit table has one source.
	NothingToRerun Kind = "nothing to re-run"
)

// tokenTable is the one source of the token vocabulary and its exits: Token.Exit reads it, and a test checks
// it row by row against the table in the execution note §5.2 (C-core-133: the documented table and the code
// come from one source).
var tokenTable = []struct {
	Kind Kind
	Exit int
}{
	{Match, 0},
	{Diverged, 1},
	{Unchecked, 3},
	{NotComparable, 3},
	{IncompleteOutput, 3},
	{FailedExit, 3},
	{FailedCap, 3},
	{Timeout, 3},
	{EnvMismatch, 5},
	{NothingToRerun, 4},
}

// Exit is the `verify` exit of a token kind (claims-model note §13; execution note §5.2). Exit 1 is reserved
// for a comparison that ran to completion and disagreed; 5 is an environment mismatch only.
func (k Kind) Exit() int {
	for _, r := range tokenTable {
		if r.Kind == k {
			return r.Exit
		}
	}
	panic("run: unknown token kind " + string(k))
}

// Caps names (the resource profile of §1, the caps of §2.2).
const (
	CapCPUs     = "cpus"
	CapMemory   = "memory"
	CapPids     = "pids"
	CapDisk     = "disk"
	CapWallTime = "wall_time"
)

// Token is one run result: its kind and the detail the kind names (the exit status, the cap, the field).
type Token struct {
	Kind Kind
	// ExitStatus is the step's exit code for FailedExit.
	ExitStatus int
	// Cap is the cap that stopped the step for FailedCap ("memory", "pids", "disk").
	Cap string
	// Fields are the environment_match fields that differ, for EnvMismatch, in the order compared.
	Fields []string
	// Below marks a cap stop in a run the reader chose to run below the spec's declared profile (§2.2).
	Below bool
	// Identical marks a protocol-workflow match on identical bytes: shown as `identical bytes (protocol
	// workflow)`, no T0 (§5.3).
	Identical bool
}

// Exit is the token's `verify` exit.
func (t Token) Exit() int { return t.Kind.Exit() }

// String is the token as every surface prints it.
func (t Token) String() string {
	var s string
	switch t.Kind {
	case FailedExit:
		s = "failed: exit " + strconv.Itoa(t.ExitStatus)
	case FailedCap:
		s = "failed: operational: " + t.Cap
	case EnvMismatch:
		s = "environment mismatch: " + strings.Join(t.Fields, ", ")
	case Match:
		s = "match"
		if t.Identical {
			s = "match (identical bytes)"
		}
	default:
		s = string(t.Kind)
	}
	if t.Below && (t.Kind == FailedCap || t.Kind == Timeout) {
		s += " (below declared profile)"
	}
	return s
}

// Compared reports whether a comparison ran to completion: only then is there anything to sign as a
// `reproduced` result (wire §5: match, diverged, not-comparable).
func (t Token) Compared() bool {
	return t.Kind == Match || t.Kind == Diverged || t.Kind == NotComparable
}

// WireResult is the token in the `reproduced` result vocabulary of wire §5, or "" when the run compared
// nothing (and so emits no `reproduced`).
func (t Token) WireResult() string {
	switch t.Kind {
	case Match:
		return "match"
	case Diverged:
		return "diverged"
	case NotComparable:
		return "not-comparable"
	}
	return ""
}

// Stopped reports whether a cap or the wall-time limit stopped the step.
func (t Token) Stopped() bool { return t.Kind == FailedCap || t.Kind == Timeout }

// TableRows renders the token table as `token | exit` pairs, in table order (the documented table's source).
func TableRows() [][2]string {
	out := make([][2]string, 0, len(tokenTable))
	for _, r := range tokenTable {
		out = append(out, [2]string{string(r.Kind), strconv.Itoa(r.Exit)})
	}
	return out
}

func (t Token) GoString() string { return fmt.Sprintf("run.Token(%s)", t) }
