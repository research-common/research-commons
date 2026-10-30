package run

import (
	"bytes"
	"context"
	"strings"
)

// ComparatorRunner runs comparators as workflows, under the same profile and boundary as any workflow (execution
// note §5.3, §6): fetched code is fetched code. It has the resolver's Comparator method, so a reader passes it
// to resolve.WithComparator and every `protocol` comparison the resolver makes runs sandboxed; the resolver
// caches each pair (claims §5.2), and nothing here is evidence.
//
// The comparator interface is execution note §5.3: a comparator is a workflow spec with exactly two inputs, named
// "a" and "b" (the two outputs in digest order, as the resolver asks), no network, and one output named
// "verdict" whose bytes are exactly `match`, `diverged` or `not comparable` (a trailing newline allowed).
// Anything else, a failed step or a cap stop is `unchecked`, with the reason. A comparator's own `authored`
// declares `replication: bytes` (a comparison has one answer per pair, claims §5.2); a comparator that declares
// anything else, or whose declaration the reader does not hold, is not run, and the comparison is `unchecked`.
type ComparatorRunner struct {
	Policy *Policy
	Runner Runner
	// Specs maps a comparator's digest to its spec bytes; Signers to the key that signed its `authored`
	// (admission is per signer or per hash, the same grant structure as workflows, §2.3).
	Specs   map[string][]byte
	Signers map[string]string
	// Replication maps a comparator's digest to the replication mode its `authored` declares, as the reader
	// resolved it (the selected workflow declaration). Only `bytes` is run.
	Replication map[string]string
	// Blobs supplies the comparator's code and the outputs being compared, by digest.
	Blobs map[string][]byte
	// Profile is the invoking run's profile ("" = sandbox).
	Profile string
}

// Compare implements the resolver's Comparator.
func (c *ComparatorRunner) Compare(comparator, a, b string) (string, string) {
	sb, ok := c.Specs[comparator]
	if !ok {
		return "unchecked", "comparator " + comparator + " is not held"
	}
	switch mode := c.Replication[comparator]; mode {
	case "bytes":
	case "":
		return "unchecked", "comparator " + comparator + " has no replication declaration held; a comparator must declare replication: bytes, and is not run"
	default:
		return "unchecked", "comparator " + comparator + " declares replication: " + strings.ToValidUTF8(truncate(mode, 32), "?") + ", not bytes; a comparator must declare replication: bytes, and is not run"
	}
	spec, err := ParseSpec(sb)
	if err != nil {
		return "unchecked", "comparator spec: " + err.Error()
	}
	if spec.Digest != comparator {
		return "unchecked", "comparator spec bytes do not hash to " + comparator
	}
	if len(spec.Inputs) != 2 || spec.Inputs[0].Name != "a" || spec.Inputs[1].Name != "b" || len(spec.Outputs) != 1 || spec.Outputs[0].Name != "verdict" || spec.Network != nil {
		return "unchecked", "comparator spec does not follow the comparator ABI (inputs a, b; output verdict; no network)"
	}
	// the two outputs replace the spec's placeholder inputs; the spec's own pins name the comparator, not data
	spec.Inputs = []Input{{Name: "a", Ref: a}, {Name: "b", Ref: b}}
	blobs := map[string][]byte{spec.Code: c.Blobs[spec.Code], a: c.Blobs[a], b: c.Blobs[b]}
	res, err := Execute(context.Background(), c.Policy, c.Runner, Invocation{
		Request: Request{Spec: spec, Signer: c.Signers[comparator], Profile: c.Profile}, Blobs: blobs})
	if err != nil {
		return "unchecked", "comparator not run: " + err.Error()
	}
	if !res.Completed() {
		return "unchecked", "comparator run: " + res.Token.String()
	}
	v, _ := res.Output("verdict")
	switch s := string(bytes.TrimSuffix(v.Bytes, []byte("\n"))); s {
	case "match", "diverged", "not comparable":
		return s, ""
	default:
		return "unchecked", "comparator verdict is not match, diverged or not comparable: " + strings.ToValidUTF8(truncate(s, 64), "?")
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
