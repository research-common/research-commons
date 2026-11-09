package resolve

import (
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// identityGraph is one identity's claims of one kind on one blob (identity profile §5.1): the nodes the actor
// hook calls eligible for I, joined only by explicit amendments. Same-key ancestry plays no part.
type identityGraph struct {
	// current are the maximal nodes, by id: the candidate current claims.
	current []*wire.Statement
	// unresolved names each authorized amendment whose target cannot be established (not held, not
	// evidence-ready, or its eligibility for I undecided): I's current view is unknown while one is held.
	unresolved []string
	// denied names each amendment that applies to nothing because a target is not one of I's claims of this
	// kind on this blob (another principal, another blob, another kind). The amending statement is not a claim.
	denied []string
}

// amendsOf is the statement's explicit amendment targets (`body.x_identity_v1.amends`) and whether it names any.
func amendsOf(st *wire.Statement) ([]string, bool) {
	m, ok := st.Body.Get(wire.IdentityCrit)
	if !ok {
		return nil, false
	}
	mo, ok := m.(*canon.Object)
	if !ok {
		return nil, false
	}
	av, ok := mo.Get("amends")
	if !ok {
		return nil, false
	}
	var out []string
	a, _ := av.(canon.Array)
	for _, v := range a {
		s, _ := v.(canon.String)
		out = append(out, string(s))
	}
	return out, true
}

// identityClaims builds I's claim graph over nodes. Every amendment is judged on its own (never through another
// amendment's verdict), so the answer is a function of the held set alone. An amendment applies when each target
// is held, evidence-ready, of the same kind, on the same blob and eligible for I; the grant check (amend:true, or
// amend:"own" with the acting key's own records) is the actor hook's, already in the node's eligibility. One
// target outside I's claims denies the amendment (it applies to nothing and is not itself a claim); otherwise
// one target that cannot be established leaves the amendment unresolved. Accepted amendments remove their
// targets from the current set; what remains is current.
func (r *Resolver) identityClaims(identity, kind, content string, nodes []*Placed) identityGraph {
	var g identityGraph
	amended := map[string]bool{}
	var accepted []*Placed
	for _, b := range nodes {
		targets, has := amendsOf(b.St)
		if !has {
			accepted = append(accepted, b)
			continue
		}
		denied, unknown := r.amendTargets(identity, kind, content, b, targets)
		switch {
		case len(denied) > 0:
			g.denied = append(g.denied, keylog.Short(b.St.ID)+" amends nothing: "+strings.Join(denied, ", "))
		case len(unknown) > 0:
			g.unresolved = append(g.unresolved, keylog.Short(b.St.ID)+" is an authorized amendment of identity "+keylog.Short(identity)+"'s claims and "+strings.Join(unknown, ", "))
		default:
			accepted = append(accepted, b)
			for _, t := range targets {
				amended[t] = true
			}
		}
	}
	for _, p := range accepted {
		if !amended[p.St.ID] {
			g.current = append(g.current, p.St)
		}
	}
	slices.SortFunc(g.current, func(a, b *wire.Statement) int { return strings.Compare(a.ID, b.ID) })
	slices.Sort(g.unresolved)
	slices.Sort(g.denied)
	return g
}

// amendTargets checks b's targets against §5.1: why each one that is not I's claim of this kind on this blob is
// not (denied), and why each one that cannot be established is not (unknown).
func (r *Resolver) amendTargets(identity, kind, content string, b *Placed, targets []string) (denied, unknown []string) {
	for _, t := range targets {
		q, held := r.byID[t]
		switch {
		case t == b.St.ID:
			denied = append(denied, "it names itself")
		case !held:
			unknown = append(unknown, "its target "+keylog.Short(t)+" is not held")
		case q.St.Kind != kind:
			denied = append(denied, "target "+keylog.Short(t)+" is a "+q.St.Kind+", not an "+kind)
		case contentDigest(q.St.Body) != content:
			denied = append(denied, "target "+keylog.Short(t)+" is about another blob")
		case !q.EvidenceReady():
			unknown = append(unknown, "its target "+keylog.Short(t)+" is held but not evidence-ready ("+notCountedWhy(q)+")")
		default:
			id, state, _ := r.actors.Eligible(q.St)
			switch {
			case state == policy.ActorUnknown:
				unknown = append(unknown, "whether its target "+keylog.Short(t)+" acts for the identity is not established")
			case id != identity || state != policy.ActorEligible:
				denied = append(denied, "target "+keylog.Short(t)+" is not a claim of identity "+keylog.Short(identity))
			}
		}
	}
	return denied, unknown
}
