package resolve

import (
	"fmt"

	"github.com/research-common/research-commons/internal/refusal"
)

// The provenance traversal bound (storage note §8 "bounded scans", claims-model note §12 and §11 exit 3; C-core-131).
// The weakest-link grade follows a result's derivation inputs, and theirs in turn. A chain longer than the
// reader's bound is not followed past it: the cut is an operational refusal naming the limit, its value and the
// scope it cut, the artifact is `incomplete`, the grade at the cut is `unchecked` (so every result resting on it is
// at most that, by the weakest-link rule), and nothing below the cut reads as checked. Cycles are a separate
// matter, already not followed (group.go).

// DefaultProvenanceDepth is the number of derivation steps (blobs on one path, the viewed blob included) the
// grade follows. A research derivation chain is tens deep at the very most; the bound exists so a hostile or
// runaway chain costs a bounded amount of work, not so that a real one is cut.
const DefaultProvenanceDepth = 128

// ProvenanceDepthLimit names the limit in refusals and in `status --limits`.
const ProvenanceDepthLimit = "provenance_depth"

// WithProvenanceDepth sets the depth bound (DefaultProvenanceDepth when unset or < 1).
func WithProvenanceDepth(n int) Option { return func(r *Resolver) { r.provDepth = n } }

func (r *Resolver) provenanceDepth() int {
	if r.provDepth < 1 {
		return DefaultProvenanceDepth
	}
	return r.provDepth
}

// cutProvenance records that the traversal stopped at input in (below a) and makes a's grade `unchecked`.
func (a *Artifact) cutProvenance(in string, limit int) {
	a.Incomplete = mergeRefusals(a.Incomplete, []*refusal.Refusal{{
		Class: refusal.Operational, Reason: refusal.DepthLimit,
		Detail: fmt.Sprintf("%s=%d, scope: the derivation of %s and everything it rests on, not followed from %s; incomplete", ProvenanceDepthLimit, limit, shortDigest(in), shortDigest(a.Digest)),
	}})
	a.Grade = Grade{Why: UncheckedToken}
}

func mergeRefusals(into, from []*refusal.Refusal) []*refusal.Refusal {
	for _, f := range from {
		dup := false
		for _, x := range into {
			dup = dup || x.Detail == f.Detail
		}
		if !dup {
			into = append(into, f)
		}
	}
	return into
}

// provenanceMayCut is a cheap upper bound on whether the grade's traversal from d reaches the depth bound: a walk
// over every claim's declared provenance (no grading, no comparison) that is true when some path has as many
// blobs as the bound. Verify grades the whole chain, with its comparisons, only when this says it may be cut;
// the grade itself decides (a claim the grade does not follow can make this true when the grade is not cut).
func (r *Resolver) provenanceMayCut(d string) bool {
	limit := r.provenanceDepth()
	onPath := map[string]bool{}
	reached := map[string]int{} // the least depth each blob was walked from: a deeper arrival adds nothing
	var walk func(d string, n int) bool
	walk = func(d string, n int) bool {
		if n >= limit {
			return true
		}
		if m, seen := reached[d]; seen && m <= n {
			return false
		}
		reached[d] = n
		onPath[d] = true
		defer delete(onPath, d)
		for _, c := range r.authorship(d).Claims {
			if c.Provenance == nil {
				continue
			}
			for _, in := range c.Provenance.Inputs {
				if !onPath[in] && !r.isObservation(in) && walk(in, n+1) {
					return true
				}
			}
		}
		return false
	}
	return walk(d, 1)
}
