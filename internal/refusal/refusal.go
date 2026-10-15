// Package refusal holds the typed refusal every gate returns: a class, a named reason, and a detail.
//
// The classes and reasons are the vocabulary of the claims-model note §11 and the wire-format note. A test
// asserts on Class and Reason, never on the rendered string, so wording can improve without breaking the
// conformance record.
package refusal

import "fmt"

// Class is the refusal class of claims-model note §11.
type Class string

const (
	// Intrinsic: the object is wrong for every reader (bad signature, malformed statement, hash mismatch).
	Intrinsic Class = "intrinsic"
	// Operational: a documented limit of this reader was reached (size, depth). Another reader may accept it.
	Operational Class = "operational"
	// Policy: the reader's own policy refused it (trust floor, admission rule).
	Policy Class = "reader policy"
)

// Reasons used across the wire layer. Each is a stable token; Detail carries the specifics.
const (
	MalformedStatement = "malformed statement"
	BadSignature       = "bad signature"
	DepthLimit         = "depth limit"
	SizeLimit          = "size limit"
)

// Refusal is an error that names its class, its reason and what it applies to.
type Refusal struct {
	Class  Class
	Reason string
	Detail string
}

func (r *Refusal) Error() string {
	if r.Detail == "" {
		return fmt.Sprintf("%s: %s", r.Class, r.Reason)
	}
	return fmt.Sprintf("%s: %s (%s)", r.Class, r.Reason, r.Detail)
}

// Malformed is shorthand for an intrinsic malformed-statement refusal.
func Malformed(format string, args ...any) *Refusal {
	return &Refusal{Class: Intrinsic, Reason: MalformedStatement, Detail: fmt.Sprintf(format, args...)}
}

// BadSig is shorthand for an intrinsic bad-signature refusal.
func BadSig(format string, args ...any) *Refusal {
	return &Refusal{Class: Intrinsic, Reason: BadSignature, Detail: fmt.Sprintf(format, args...)}
}
