package resolve

import (
	"slices"
	"strings"
)

// All returns every placed statement the resolver holds, by kind then id: the input set a surface lists when
// it explains an answer (claims §13 "explain", I14). The slice is fresh; the statements are the resolver's own.
func (r *Resolver) All() []*Placed {
	out := make([]*Placed, 0, len(r.byID))
	for _, p := range r.byID {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b *Placed) int { return strings.Compare(a.St.Kind+a.St.ID, b.St.Kind+b.St.ID) })
	return out
}

// Token is the resolver's display token of a grade: the tier ("T0", "T1", "T2") or the token that stands in
// for one. A T1's comparator is Under.
func (g Grade) Token() string {
	if g.Tier != "" {
		return g.Tier
	}
	return g.Why
}
