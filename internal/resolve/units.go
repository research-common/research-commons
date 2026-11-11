package resolve

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// Identity authorship units (identity profile §5.1). Only a reader with an actor evaluator reaches this file: with
// none (every production reader) the counting gate binds nothing to an identity, and authorship is the bare-key
// computation of artifact.go unchanged.

// identityNodes are I's claims of kind on content: every evidence-ready statement of the kind on the content the
// counting gate binds to I and counts (eligible for I).
func (r *Resolver) identityNodes(identity, kind, content string) []*Placed {
	var out []*Placed
	for _, p := range r.byKind[kind] {
		if contentDigest(p.St.Body) != content {
			continue
		}
		if g := r.gate(p); g.Counts && g.Identity == identity {
			out = append(out, p)
		}
	}
	return out
}

// identityAuthorship builds I's claims on blob d from its eligible `authored` nodes. Claims group only by the
// explicit I and the explicit `amends` DAG (identityClaims); the current claims are split by provenance as a
// key's are. A claim's statements, and so its bound, are its current statements and their explicit eligible
// amendment ancestry, never an unrelated claim of the same I (§5.1 "cannot borrow an unrelated early claim's
// bound"). An amendment that applies to nothing is not a claim: it is listed not counted, under I, with why.
//
// When I has an authorized unresolved amendment (I's current view unknown), I still takes part in priority with
// the bounds of all its eligible statements, since when the bytes existed does not depend on which claim is
// current; its current candidates are kept, and Unresolved names why the view is unknown (fields read unknown).
func (r *Resolver) identityAuthorship(identity, d string, nodes []*Placed) (claims []*Claim, notCounted []NotCounted, explain []string) {
	g := r.identityClaims(identity, "authored", d, nodes)
	subj := IdentitySubject(identity)
	byID := map[string]*Placed{}
	for _, p := range nodes {
		byID[p.St.ID] = p
		if why, ok := g.deniedBy[p.St.ID]; ok {
			notCounted = append(notCounted, NotCounted{p.St.ID, subj, p.St.Signer, "not a claim of identity " + keylog.Short(identity) + ": " + why})
		}
	}
	byProv := map[string]*Claim{}
	for _, st := range g.current {
		pv := provenance(st.Body)
		c, ok := byProv[pv.key()]
		if !ok {
			c = &Claim{Subject: subj, Provenance: pv, Amends: map[string][]string{}, Bound: Bound{Quality: NoBound}}
			byProv[pv.key()] = c
		}
		c.Current = append(c.Current, st.ID)
		c.current = append(c.current, st)
	}
	if len(g.unresolved) > 0 && len(byProv) == 0 {
		// every eligible claim is the target of an unresolved amendment: I still claims the blob, with no
		// current candidate, so its unit takes part in priority and reads unknown
		byProv[(*Provenance)(nil).key()] = &Claim{Subject: subj, Amends: map[string][]string{}, Bound: Bound{Quality: NoBound}}
	}
	for _, pk := range sortedKeys(byProv) {
		c := byProv[pk]
		members := g.ancestry(c.Current)
		if len(g.unresolved) > 0 {
			// the current view is unknown: every eligible statement of I bears on when I claimed the bytes
			members = nil
			for _, p := range nodes {
				if _, denied := g.deniedBy[p.St.ID]; !denied {
					members = append(members, p.St.ID)
				}
			}
			c.Unresolved = slices.Clone(g.unresolved)
		}
		var signers []string
		var sts []*wire.Statement
		for _, id := range members {
			if p, ok := byID[id]; ok {
				sts = append(sts, p.St)
			}
		}
		slices.SortFunc(sts, cmpSeq)
		for _, st := range sts {
			c.Statements = append(c.Statements, st.ID)
			c.Bound = better(c.Bound, r.bound(st))
			signers = append(signers, st.Signer)
			if t, ok := g.amends[st.ID]; ok {
				c.Amends[st.ID] = t
			}
		}
		slices.Sort(signers)
		c.Signers = slices.Compact(signers)
		slices.Sort(c.Current)
		claims = append(claims, c)
	}
	if n := len(g.current); n > 1 {
		explain = append(explain, fmt.Sprintf("identity %s holds %d current claims on this blob (%s), none preferred: no sequence, arrival or timestamp tiebreak; "+
			"a field they disagree on stays contested until an eligible amendment naming both reconciles them", keylog.Short(identity), n, shorts(ids_(g.current))))
	}
	explain = append(explain, g.unresolved...)
	return claims, notCounted, explain
}

// identityCurrent reports whether q, an `authored` the gate binds to identity, is one of I's current claims on its
// blob (no accepted explicit amendment of I names it). The derivation group runs only current claims (C-core-11).
func (r *Resolver) identityCurrent(identity string, q *Placed, cache map[string]identityGraph) bool {
	d := contentDigest(q.St.Body)
	k := identity + "|" + d
	g, ok := cache[k]
	if !ok {
		g = r.identityClaims(identity, "authored", d, r.identityNodes(identity, "authored", d))
		cache[k] = g
	}
	return slices.ContainsFunc(g.current, func(st *wire.Statement) bool { return st.ID == q.St.ID })
}

// unresolvedDefault is why the default unit's current view is unknown: the unresolved amendments of every
// identity claim in it. Nil when there is none (always, with no actor evaluator).
func unresolvedDefault(a *Artifact) []string {
	if a.Default == nil {
		return nil
	}
	var out []string
	for _, c := range a.Default.Claims {
		out = append(out, c.Unresolved...)
	}
	return out
}

func joinUnresolved(why []string) string { return strings.Join(why, "; ") }
