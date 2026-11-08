package identity

import "github.com/research-common/research-commons/internal/identitymodel"

// WithLimits returns the evaluator under lowered model caps, so a test reaches a cap cheaply. Test-only: no
// production caller can raise or lower the profile's caps through the adapter.
func (a *Actors) WithLimits(dependencies, pathEdges, inspections int) *Actors {
	return &Actors{s: a.s, lim: identitymodel.Limits{Dependencies: dependencies, PathEdges: pathEdges, Inspections: inspections}}
}
