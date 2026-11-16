package cli

import (
	"strings"

	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/resolve"
)

// gateReport is a gate's report (hub check, pull) as one result tree (hub template H-50, H-51): one line per
// refused, undecided, not-applied or labelled object (path, id or digest in full, verdict, class, reason,
// labels, the narrowest next step), then the policy that applied and a count per verdict. Plainly admitted
// objects are counted, not listed. Peer-supplied text (a label's detail, a refusal's detail, a path from the
// package) goes in peerV members only, so it is inert on the human surface and a JSON string on the other.
func gateReport(rep *gate.Report) *Obj {
	o := newObj()
	objs := listV{}
	counts := map[string]int64{}
	for i := range rep.Results {
		x := &rep.Results[i]
		v := string(x.Verdict)
		if x.Labelled() {
			v = "admitted and labelled"
		}
		counts[v]++
		if x.Verdict == gate.Admitted && len(x.Labels) == 0 {
			continue
		}
		row := rowObj().set("path", peerV(x.Path))
		if x.ID != "" {
			row.set("id", refV(x.ID))
		}
		row.set("verdict", tokV(tok(v)))
		if x.Refusal != nil {
			row.set("class", tokV(tok(string(x.Refusal.Class)))).set("reason", textV(x.Refusal.Reason))
			if x.Refusal.Detail != "" {
				row.set("detail", peerV(x.Refusal.Detail))
			}
		}
		if len(x.Labels) > 0 {
			ls, ds := listV{}, listV{}
			for _, l := range x.Labels {
				ls = append(ls, tokV(tok(l.Token)))
				if l.Detail != "" {
					ds = append(ds, peerV(l.Detail))
				}
			}
			row.set("labels", ls)
			if len(ds) > 0 {
				row.set("label_details", ds)
			}
		}
		if x.IntendedFor != nil {
			// JSON carries the typed object; the one-line human row carries the same two states beside the labels
			ro := recordedObj(x.IntendedFor)
			row.setJSON("intended_for", ro)
			row.setHuman("intended_for_named", ro.get("named").(*Obj).get("state"))
			if cur, ok := ro.get("current").(*Obj); ok {
				row.setHuman("intended_for_current", cur.get("state"))
			}
		}
		if x.Completeness != nil {
			// the receiver's check of the edition's completeness claim (selection.refuse_incomplete): the same typed
			// state `show` prints on the resource view, on refused, undecided and labelled rows alike
			co := completenessObj(x.Completeness, false)
			row.setJSON("completeness", co)
			row.setHuman("completeness_state", co.get("state"))
		}
		if x.Series != nil {
			// the receiver's comparison of the edition's declared boundary with its members' computed one: the same
			// typed state `show` prints on the series resource, on refused, undecided and labelled rows alike
			so := seriesBoundaryObj(x.Series, false)
			row.setJSON("series_boundary", so)
			row.setHuman("series_boundary_state", so.get("state"))
		}
		if x.Actor != nil {
			// the same member `show` prints for an identity statement; a label only (hub check), never a verdict
			a := newObj().set("identity", refV(x.Actor.Identity)).set("grant", refV(x.Actor.Grant)).set("state", tokV(tok(x.Actor.State)))
			if len(x.Actor.Reasons) > 0 {
				a.set("reasons", texts(x.Actor.Reasons...))
			}
			row.set("actor", setFreshness(a))
		}
		if x.Scope != "" && x.Verdict != gate.Admitted {
			row.set("scope", peerV(x.Scope))
		}
		if x.Override != "" {
			row.set("override", peerV(x.Override))
		}
		if x.Next != "" {
			row.set("next", textV(x.Next))
		}
		objs = append(objs, row)
	}
	o.set("gate", textV(rep.Gate))
	o.set("objects", objs)
	c := newObj()
	for _, v := range []string{"admitted", "admitted and labelled", "refused", "could not check", "not applied"} {
		c.set(strings.ReplaceAll(v, " ", "_"), intV(counts[v]))
	}
	o.set("counts", c)
	o.set("policy", newObj().set("name", peerV(rep.PolicyName)).set("digest", refV(rep.PolicyDigest)))
	return o
}

// gateExit is a report's exit (claims §13: 0 all admitted, 1 at least one refused under any class, an
// operational refusal included, 3 nothing refused and something undecided).
func gateExit(rep *gate.Report) int { return rep.Exit() }

// recordedObj is the receiver's re-application of a statement's intended_for as typed members beside the label
// detail (claims-model note §8, §13: every rule evaluation is one of ok, fail, unchecked): the named edition's
// outcome and, when the resource has a current edition, the current edition's, each a state token; what the
// publisher recorded is its own word, a peer value, never a state of this reader's.
func recordedObj(c *resolve.Recorded) *Obj {
	o := newObj().set("resource", refV(c.Resource)).set("edition", refV(c.NamedEdition))
	named := newObj().set("edition", refV(c.NamedEdition))
	if c.Named == "" {
		// the resource or the edition is not held: nothing was evaluated, which is not a pass
		named.set("state", tokV(tok(string(resolve.RuleUnchecked))))
	} else {
		named.set("state", tokV(tok(string(c.Named))))
	}
	o.set("named", named)
	if c.CurrentEdition != "" {
		cur := newObj().set("edition", refV(c.CurrentEdition))
		if c.Current == "" {
			cur.set("state", tokV(tok(string(resolve.RuleUnchecked))))
		} else {
			cur.set("state", tokV(tok(string(c.Current))))
		}
		o.set("current", cur)
	}
	if len(c.Evals) > 0 {
		o.set("evaluations", evalsObj(c.Evals))
	}
	o.set("publisher_said", peerV(c.PublisherSaid))
	return o
}

// evalsObj is a rule's evaluations, one typed row each (claims-model note §13: every rule evaluation is one of ok,
// fail, unchecked): the outcome is a `state` token and the rest is detail beside it. A rule's dialect, expression
// and the reason a dialect gives are the edition's text or derived from the content, so they are peer text.
func evalsObj(es []resolve.Eval) listV {
	l := listV{}
	for _, e := range es {
		r := rowObj().set("rule", intV(int64(e.Rule))).set("dialect", peerV(e.Dialect)).set("expr", peerV(e.Expr)).
			set("member", refV(e.Member)).set("state", tokV(tok(string(e.Outcome))))
		if e.Why != "" {
			r.set("why", peerV(e.Why))
		}
		if len(e.Conflicts) > 0 {
			r.set("conflicts", refs(e.Conflicts...))
		}
		l = append(l, r)
	}
	return l
}
