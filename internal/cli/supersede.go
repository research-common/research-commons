package cli

import (
	"github.com/research-common/research-commons/internal/resolve"
)

// anchorLines is what explain prints for a statement bounded by more than one `anchors` line of one covered head
// (bitcoin-time note §1 rule 5: a later line supersedes an earlier one for display; both stay in the log and
// explain lists both): every anchors line of the signer that bounds the statement, its quality and state, whether
// it is the one displayed and why. For an `anchors` line itself the list is the lines of its own covered head.
// With at most one line per covered head nothing is printed, so those answers are as before. The ids listed are
// inputs of the answer (I14): a line arriving or leaving changes which one is displayed.
func (v *view) anchorLines(id string) (listV, []string) {
	p, ok := v.r.Statement(id)
	if !ok {
		return nil, nil
	}
	var ls []resolve.AnchorLine
	if p.St.Kind == "anchors" {
		cov := bodyString(p.St.Body, "covered")
		for _, l := range v.r.AnchorLines(cov) {
			if l.Covered == cov {
				ls = append(ls, l)
			}
		}
	} else {
		ls = v.r.AnchorLines(id)
	}
	perHead := map[string]int{}
	several := false
	for _, l := range ls {
		perHead[l.Covered]++
		several = several || perHead[l.Covered] > 1
	}
	if !several {
		return nil, nil
	}
	out := listV{}
	var ids []string
	for _, l := range ls {
		row := rowObj().set("anchor", refV(l.Anchor)).set("covered", refV(l.Covered)).
			set("quality", tokV(tok(string(l.Bound.Quality))))
		if e, ok := v.anchorEvidence(l.Anchor); ok {
			row.set("time_state", tokV(tok(string(e.State))))
		}
		out = append(out, row.set("displayed", boolV(l.Displayed)).set("why", textV(l.Why)))
		ids = append(ids, l.Anchor)
	}
	return out, ids
}

// claimantAnchors is the anchor each claimant's displayed bound comes from, in claimant order.
func claimantAnchors(a *resolve.Artifact) []string {
	var out []string
	for _, u := range a.Units {
		if u.Bound.Anchor != "" {
			out = append(out, u.Bound.Anchor)
		}
	}
	return out
}

// setAnchorLines sets explain's `anchors` member: the anchorLines of each ref, each line once, when any covered
// head has more than one; the lines listed join the answer's inputs.
func (v *view) setAnchorLines(o *Obj, inputs *[]string, refs ...string) {
	out := listV{}
	seen := map[string]bool{}
	for _, ref := range refs {
		rows, ids := v.anchorLines(ref)
		for i, id := range ids {
			if !seen[id] {
				seen[id] = true
				out = append(out, rows[i])
				*inputs = append(*inputs, id)
			}
		}
	}
	if len(out) > 0 {
		o.set("anchors", out)
	}
}
