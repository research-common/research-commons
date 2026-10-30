package cli

import (
	"strings"

	"github.com/research-common/research-commons/internal/gate"
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
