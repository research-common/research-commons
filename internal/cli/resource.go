package cli

import (
	"fmt"
	"slices"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/resolve"
)

// The resource view (claims-model note §8; wire-format note §3, §5 `genesis`, `edition`): what show, verify and
// explain print for a resource, an edition, or one approval of an edition.
//
// How a reference names a resource. There is no third kind of argument: a resource id IS the id of its genesis
// statement (C-core-77), so `show <id>` of a genesis prints the statement and, beside it, the resource it
// creates. An edition id is a hash under a payload type of its own and never equals a statement id (wire §3),
// so an id that names no held statement is looked up among the editions of the held resources; and the
// statement id of an approval resolves to its edition (wire §3: "a surface that takes an id from a user ...
// resolves the statement id of any approval to its edition", C-core-78). None of the three can name two
// objects, so no new ambiguity arises and no new subcommand is needed.

// resourceRef is what an id names among the resources: the resource, and the edition it pins ("" for the
// resource itself, its genesis).
type resourceRef struct {
	res     *resolve.Resource
	edition *resolve.Edition
}

// resourceOf resolves id as a resource (a genesis id), an approval's statement id, or an edition id. ok is false
// when id names none of them in this view.
func (v *view) resourceOf(id string) (resourceRef, bool) {
	if p, ok := v.r.Statement(id); ok {
		switch p.St.Kind {
		case "genesis":
			if res, ok := v.r.Resource(id); ok {
				return resourceRef{res: res}, true
			}
		case "edition":
			// an approval: its body names the resource, and its edition is found by the approval's id
			if res, ok := v.r.Resource(bodyString(p.St.Body, "resource")); ok {
				if e, ok := res.Edition(id); ok {
					return resourceRef{res: res, edition: e}, true
				}
			}
		}
		return resourceRef{}, false
	}
	// an edition id is never a statement id: look it up among the held resources
	for _, g := range v.geneses() {
		if res, ok := v.r.Resource(g); ok {
			for _, e := range res.Editions {
				if e.ID == id {
					return resourceRef{res: res, edition: e}, true
				}
			}
		}
	}
	return resourceRef{}, false
}

// geneses is every held genesis statement id, sorted.
func (v *view) geneses() []string {
	var out []string
	for _, p := range v.r.All() {
		if p.St.Kind == "genesis" {
			out = append(out, p.St.ID)
		}
	}
	slices.Sort(out)
	return out
}

func bodyString(body *canon.Object, k string) string {
	if body == nil {
		return ""
	}
	if x, ok := body.Get(k); ok {
		if s, ok := x.(canon.String); ok {
			return string(s)
		}
	}
	return ""
}

// resourceObj is the resource view: its controllers and rule, its current edition (or the FORK that leaves it
// without one), the chain of editions behind the current one by hash, every edition with its state and
// approvals, the current edition's members and the receiver's check of its completeness claim. explain adds
// each edition's reasoning (full).
func (v *view) resourceObj(res *resolve.Resource, full bool) *Obj {
	o := newObj().set("resource", refV(res.ID)).set("type", peerV(res.Type)).set("name", peerV(res.Name))
	if res.ForkedFrom != "" {
		o.set("forked_from", refV(res.ForkedFrom))
	}
	ctl, k := v.authorityOf(res)
	o.set("controllers", refs(ctl...)).set("rule", textV(ruleText(k, len(ctl))))
	switch {
	case res.Current == res.ID:
		o.set("current", refV(res.ID)).set("current_is", textV("the genesis: no edition is authorized yet"))
	case res.Current != "":
		o.set("current", refV(res.Current))
	default:
		o.set("state", tokV(tok("FORK"))).set("tips", refs(res.Tips...))
	}
	if len(res.Contested) > 0 {
		o.set("contested", refs(res.Contested...))
	}
	if res.Current != "" {
		o.set("chain", refs(chain(res)...))
	}
	if len(res.Forks) > 0 {
		fl := listV{}
		for _, f := range res.Forks {
			fo := newObj().set("at", refV(f.At)).set("branches", refs(f.Branches...))
			if f.Cleared() {
				fo.set("cleared_by", refV(f.ClearedBy))
			} else {
				fo.set("state", tokV(tok("FORK"))).set("tips", refs(f.Tips...))
			}
			fl = append(fl, fo)
		}
		o.set("forks", fl)
	}
	if res.NoController {
		o.set("no_controller", textV("no key the current edition's rule authorizes remains: no further edition can exist"))
	}
	if len(res.RevokedControllers) > 0 {
		rl := listV{}
		for _, c := range sortedMapKeys(res.RevokedControllers) {
			rl = append(rl, newObj().set("controller", refV(c)).set("retired_by", refV(res.RevokedControllers[c])))
		}
		o.set("revoked_controllers", rl)
	}
	el := listV{}
	for _, e := range res.Editions {
		el = append(el, v.editionObj(e, full))
	}
	o.set("editions", el)
	if res.Current != "" && res.Current != res.ID {
		if e, ok := res.Edition(res.Current); ok {
			o.set("membership", v.membershipObj(res, e))
		}
		if c, ok := v.r.Completeness(res.ID, ""); ok && c.Declared {
			o.set("completeness", completenessObj(c, full))
		}
	}
	return o
}

// authorityOf is the current authority: the current edition's controllers and rule, the genesis's when no
// edition is authorized; none under a FORK (each branch has its own).
func (v *view) authorityOf(res *resolve.Resource) ([]string, int) {
	if res.Current != "" && res.Current != res.ID {
		if e, ok := res.Edition(res.Current); ok {
			return controllerWords(e.Controllers), e.K
		}
	}
	if res.Current == res.ID && res.Genesis != nil {
		return controllerWords(res.GenesisControllers), res.GenesisK
	}
	return nil, 0
}

// controllerWords is a controller set as display words: a key controller is its key, as it has always been
// printed; an identity controller (candidate rc/2 only, never read by a production reader) is identity:<id>.
func controllerWords(cs []resolve.Controller) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.String())
	}
	return out
}

func ruleText(k, n int) string {
	switch {
	case n == 0:
		return "none current (each FORK branch carries its own)"
	case k <= 1:
		return "any one"
	}
	return fmt.Sprintf("%d of %d", k, n)
}

// chain is the current edition's ancestry from the genesis, every authorized edition behind it once, each
// after all of its predecessors (ties by edition id): for a linear history, G → E1 → E2 (C-core-79).
func chain(res *resolve.Resource) []string {
	byID := map[string]*resolve.Edition{}
	for _, e := range res.Editions {
		byID[e.ID] = e
	}
	depth := map[string]int{res.ID: 0}
	var walk func(id string) int
	walk = func(id string) int {
		if d, ok := depth[id]; ok {
			return d
		}
		d := 0
		if e, ok := byID[id]; ok {
			for _, p := range e.Predecessors {
				d = max(d, walk(p)+1)
			}
		}
		depth[id] = d
		return d
	}
	walk(res.Current)
	ids := make([]string, 0, len(depth))
	for id := range depth {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b string) int {
		if depth[a] != depth[b] {
			return depth[a] - depth[b]
		}
		if a < b {
			return -1
		}
		return 1
	})
	return ids
}

// editionObj is one proposal: its edition id, what became of it, its predecessors by hash, and one row per
// approval of its body (C-core-82: approvals of one body are one proposal; different bodies never combine).
func (v *view) editionObj(e *resolve.Edition, full bool) *Obj {
	o := newObj().set("edition", refV(e.ID)).set("state", tokV(tok(string(e.State))))
	if e.Predecessors != nil {
		o.set("predecessors", refs(e.Predecessors...))
	}
	al := listV{}
	for _, a := range e.Approvals {
		ao := newObj().set("statement", refV(a.Statement)).set("signer", refV(a.Signer))
		switch {
		case a.Withdrawn != "":
			ao.set("counted", tokV(tok("not counted"))).set("withdrawn_by", refV(a.Withdrawn))
		case a.Counted:
			ao.set("counted", tokV(tok("counted")))
		default:
			ao.set("counted", tokV(tok("not counted"))).set("reason", textV(a.Why))
		}
		al = append(al, ao)
	}
	o.set("approvals", al)
	if e.State == resolve.Authorized {
		o.set("controllers", refs(controllerWords(e.Controllers)...)).set("rule", textV(ruleText(e.K, len(e.Controllers))))
	}
	if full && len(e.Explain) > 0 {
		o.set("reasoning", texts(e.Explain...))
	}
	return o
}

// membershipObj is the current edition's members: what each entry names, its role, and the edition's rules
// re-applied for it (claims-model note §8: membership is endorsement; a failing rule rejects the membership,
// never the artifact). The selection is the controller's declaration (§6 (3)).
func (v *view) membershipObj(res *resolve.Resource, e *resolve.Edition) *Obj {
	o := newObj().set("edition", refV(e.ID))
	if s := resolve.Selection(e.Body); s == "undeclared" {
		o.set("selection", newObj().set("state", tokV(tok("undeclared"))))
	} else {
		o.set("selection", newObj().set("value", peerV(s)))
	}
	ml := listV{}
	endorsed := 0
	for _, x := range e.Members {
		mo, ok := x.(*canon.Object)
		if !ok {
			continue
		}
		var by, key string
		for _, f := range []string{"content", "statement", "resource"} {
			if s := bodyString(mo, f); s != "" {
				by, key = f, s
				break
			}
		}
		if key == "" {
			continue
		}
		row := newObj().set("member", refV(key)).set("by", textV(by)).set("member_role", peerV(bodyString(mo, "role")))
		if m, ok := v.r.Membership(res.ID, key); ok && m.Listed {
			row.set("state", tokV(tok(string(m.Outcome))))
			if m.Endorsed {
				endorsed++
			}
		}
		ml = append(ml, row)
	}
	o.set("members", ml).set("count", intV(int64(len(ml)))).set("endorsed", intV(int64(endorsed)))
	return o
}

// completenessObj is the receiver's check of the current edition's completeness claim beside the declaration
// (claims-model note §6 (3), §7 "declared beside computed"; C-core-60). It changes no membership, no
// authorization and no verify exit (I6).
func completenessObj(c *resolve.Completeness, full bool) *Obj {
	o := newObj().set("labels", tokens("completeness claim")).set("state", tokV(tok(string(c.Outcome))))
	if c.Scoped {
		o.set("reading_class", peerV(c.Class)).set("source", peerV(c.Source)).set("from", peerV(c.From)).set("to", peerV(c.To))
		if c.Timescale != "" {
			o.set("timescale", peerV(c.Timescale))
		}
	}
	if len(c.Missing) > 0 {
		o.set("missing", refs(c.Missing...))
	}
	o.set("listed", refs(c.Listed...))
	if len(c.Unread) > 0 {
		ul := listV{}
		for _, id := range sortedMapKeys(c.Unread) {
			ul = append(ul, newObj().set("reading", refV(id)).set("why", textV(c.Unread[id])))
		}
		o.set("unread", ul)
	}
	if full && len(c.Explain) > 0 {
		o.set("reasoning", texts(c.Explain...))
	}
	return o
}

// resourceInputs is every statement a resource answer read: the genesis, every approval, every withdrawal and
// key event its editions name, the statements its members name, and the readings its completeness check named
// (I14: a statement arriving or leaving that changes the answer is listed).
func (v *view) resourceInputs(res *resolve.Resource) []string {
	ids := []string{res.ID}
	for _, e := range res.Editions {
		for _, a := range e.Approvals {
			ids = append(ids, a.Statement)
			if a.Withdrawn != "" {
				ids = append(ids, a.Withdrawn)
			}
		}
		for _, x := range e.Members {
			if mo, ok := x.(*canon.Object); ok {
				if s := bodyString(mo, "statement"); s != "" {
					ids = append(ids, s)
				}
			}
		}
	}
	for _, ev := range res.RevokedControllers {
		ids = append(ids, ev)
	}
	if c, ok := v.r.Completeness(res.ID, ""); ok && c.Declared {
		ids = append(ids, c.Missing...)
		ids = append(ids, c.Listed...)
		ids = append(ids, sortedMapKeys(c.Unread)...)
	}
	return ids
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// corroborationObj is an observation's corroboration status (claims-model note §5.3.2; resolve.Corroboration):
// the counts under the counting unit, always with the scope, never an unscoped count and never `uncontradicted`.
// The counts are numbers beside the summary line, not new state tokens. A disclosure (I6): it moves no exit.
// full adds each piece of evidence, counted or not, with the statement it is.
func corroborationObj(c *resolve.Corroboration, full bool) *Obj {
	o := newObj().set("summary", textV(c.Status())).set("corroborated", intV(int64(c.Corroborated))).
		set("contradicted", intV(int64(c.Contradicted)))
	if c.Unchecked || (c.Corroborated == 0 && c.Contradicted == 0) {
		o.set("state", tokV(tok("unchecked")))
	}
	if c.Why != "" {
		o.set("why", textV(c.Why))
	}
	if c.Unit != "" {
		o.set("counting_unit", textV(c.Unit))
	}
	o.set("independence", textV(c.Independence+" (distinct keys prove nothing about independence)"))
	if c.Trust != "" {
		o.set("trust", textV(c.Trust))
	}
	if !full {
		return o
	}
	if bm := c.ByModel(); len(bm) > 0 {
		o.set("by_model", texts(bm...))
	}
	el := listV{}
	for _, e := range c.Evidence {
		eo := newObj().set("via", textV(e.Via))
		if e.Reader() {
			eo.set("by", textV("the reader"))
		} else {
			eo.set("statement", refV(e.Statement)).set("signer", refV(e.Key))
		}
		if e.Verdict != "" {
			eo.set("says", textV(e.Verdict))
		}
		if e.Model != "" {
			eo.set("model", peerV(e.Model))
		}
		if e.Counted {
			eo.set("counted", tokV(tok("counted")))
		} else {
			eo.set("counted", tokV(tok("not counted")))
		}
		if e.Cause != "" {
			eo.set("reason", textV(e.Cause))
		}
		// the corroboration is an ordinary derived result (claims §5.3.2): the result it names, the grade of its
		// own derivation, its comparison data, and the reader's re-application of its declared cohort rule
		if e.Result != "" {
			eo.set("result", refV(e.Result))
		}
		if e.Grade != "" {
			eo.set("result_grade", textV(e.Grade))
		}
		if len(e.Comparison) > 0 {
			eo.set("comparison_data", refs(e.Comparison...))
		}
		if len(e.CohortCheck) > 0 {
			eo.set("cohort_check", texts(e.CohortCheck...))
		}
		el = append(el, eo)
	}
	o.set("evidence", el)
	if len(c.Held) > 0 {
		o.set("held", texts(c.Held...))
	}
	return o
}

// corroborationInputs is every statement an observation's corroboration status read.
func corroborationInputs(c *resolve.Corroboration) []string {
	var ids []string
	for _, e := range c.Evidence {
		if e.Statement != "" {
			ids = append(ids, e.Statement)
		}
	}
	return ids
}

// observationsObj is the observations of one blob, each with its corroboration status (the lite form: the counts
// and the scope); `show <statement>` of one prints its evidence.
func (v *view) observationsObj(d string) listV {
	l := listV{}
	for _, ob := range v.r.Observations(d) {
		o := newObj().set("statement", refV(ob.Statement)).set("signer", refV(ob.Signer))
		if ob.Corroboration != nil {
			o.set("corroboration", corroborationObj(ob.Corroboration, false))
		}
		l = append(l, o)
	}
	return l
}
