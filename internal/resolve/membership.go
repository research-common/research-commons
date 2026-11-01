package resolve

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
)

// Membership, admission and the pre-pin check (claims-model note §8 "Membership is endorsement",
// "Intended-for runs the rules before the bytes are pinned"; I7, I9).
//
// Only a resource's editions add members. A member's own "part of" claim (a `describes` naming the resource)
// confers nothing: it is listed as that key's annotation and no rule of the resource is applied to it
// (C-core-88). A membership is computed from the resource's own editions and rules only, so a laxer
// collection's rules never satisfy a stricter one's (C-core-89).
//
// Which rules govern a membership. A listed member is checked against the rules of the edition that lists
// it, re-applied over that edition's own member set (§6: a rule-based selection publishes a rule others can
// re-apply). A candidate for a next edition is checked against a base edition's rules over the base members
// plus every candidate proposed together (the edition under formation). The two agree whenever the next
// edition keeps its base's rules. A membership is endorsed when the current edition lists it and every rule
// is `ok` for it; `fail` rejects the membership and `unchecked` never endorses (I4). Neither touches the
// artifact's own view (C-core-91).

// Membership is one key's standing in one resource.
type Membership struct {
	Resource, Member string
	// Edition is the edition the membership was computed from: the current one; "" when there is none.
	Edition string
	Listed  bool
	Role    string
	// Evals are the edition's rules re-applied for this member; nil when it is not listed.
	Evals []Eval
	// Outcome aggregates Evals (fail over unchecked over ok); "" when not listed.
	Outcome  Outcome
	Endorsed bool
	// Claims are counted `describes` statements about the member that link the resource: each is its signer's
	// annotation and confers nothing (C-core-88).
	Claims []*Placed
	// Selection is the current edition's declared selection (§6 (3)): `curated`, `rule-based`, `completeness`,
	// or `undeclared` when the edition declares none, never a value nobody signed.
	Selection string
	Explain   []string
}

// Selection is the selection disclosure of an edition body: the declared value, or `undeclared` (§6 (3); §7:
// "Missing means undeclared").
func Selection(body *canon.Object) string {
	contents, _ := body.Get("contents")
	if s := str(contents.(*canon.Object), "selection"); s != "" {
		return s
	}
	return "undeclared"
}

// Membership resolves key's membership in resource id. key is what an edition entry names: a content digest,
// a statement id, or a resource id.
func (r *Resolver) Membership(id, key string) (*Membership, bool) {
	res, ok := r.Resource(id)
	if !ok {
		return nil, false
	}
	m := &Membership{Resource: id, Member: key, Claims: r.partOfClaims(id, key)}
	for _, c := range m.Claims {
		m.Explain = append(m.Explain, fmt.Sprintf("%s says it is part of %s (describes %s): an annotation, confers nothing",
			shortKey(c.St.Signer), keylog.Short(id), keylog.Short(c.St.ID)))
	}
	switch {
	case res.Current == "":
		m.Explain = append(m.Explain, "no current edition (FORK; tips "+shorts(res.Tips)+"): membership cannot be computed")
		return m, true
	case res.Current == id:
		m.Explain = append(m.Explain, "no edition yet: nothing is a member")
		return m, true
	}
	e, _ := res.Edition(res.Current)
	m.Edition, m.Selection = e.ID, Selection(e.Body)
	form := r.editionMembers(e)
	for _, x := range form {
		if x.Key == key {
			m.Listed, m.Role = true, x.Role
		}
	}
	if !m.Listed {
		m.Explain = append(m.Explain, "not listed by the current edition "+keylog.Short(e.ID)+"; its rules are not applied")
		return m, true
	}
	for _, ev := range r.evalRules(r.loadRules(e.Body), form) {
		if ev.Member == key {
			m.Evals = append(m.Evals, ev)
		}
	}
	m.Outcome = aggregate(m.Evals)
	m.Endorsed = m.Outcome == RuleOK
	m.Explain = append(m.Explain, fmt.Sprintf("listed by %s as %q; rules: %s", keylog.Short(e.ID), m.Role, m.Outcome))
	return m, true
}

// Render is the membership display.
func (m *Membership) Render() string {
	var b strings.Builder
	state := "not a member"
	switch {
	case m.Endorsed:
		state = "member (endorsed)"
	case m.Listed:
		state = "listed, not endorsed (rules " + string(m.Outcome) + ")"
	}
	fmt.Fprintf(&b, "%s in %s: %s\n", shortMember(m.Member), keylog.Short(m.Resource), state)
	if m.Selection != "" {
		fmt.Fprintf(&b, "  selection: %s\n", m.Selection)
	}
	for _, e := range m.Evals {
		fmt.Fprintf(&b, "  %s\n", e)
	}
	for _, x := range m.Explain {
		fmt.Fprintf(&b, "  %s\n", x)
	}
	return b.String()
}

// partOfClaims lists counted `describes` statements whose `about` names key and whose `links` name resource.
func (r *Resolver) partOfClaims(resource, key string) []*Placed {
	var out []*Placed
	for _, p := range r.byKind["describes"] {
		if !p.Counts() {
			continue
		}
		about, _ := p.St.Body.Get("about")
		ao := about.(*canon.Object)
		if str(ao, "content") != key && str(ao, "statement") != key && str(ao, "resource") != key {
			continue
		}
		links, _ := p.St.Body.Get("links")
		la, _ := links.(canon.Array)
		for _, l := range la {
			if str(l.(*canon.Object), "resource") == resource {
				out = append(out, p)
				break
			}
		}
	}
	slices.SortFunc(out, func(a, b *Placed) int { return strings.Compare(a.St.ID, b.St.ID) })
	return out
}

// aggregate is the outcome of several evaluations: any fail is fail; else any unchecked is unchecked; else ok
// (no rules is ok: there is nothing to check).
func aggregate(es []Eval) Outcome {
	out := RuleOK
	for _, e := range es {
		switch {
		case e.Outcome == RuleFail:
			return RuleFail
		case e.Outcome != RuleOK:
			out = RuleUnchecked
		}
	}
	return out
}

// Admission is the evaluation of candidates for a next edition against a base edition (C-core-90, C-core-93b).
type Admission struct {
	Resource, Edition string
	Candidates        []string // sorted
	// Evals are the base edition's rules for each candidate, over the base members plus every candidate.
	Evals    []Eval
	Outcomes map[string]Outcome
	Explain  []string
}

// Entry is an edition member entry naming key by "content", "statement" or "resource".
func Entry(by, key, role string) *canon.Object {
	return &canon.Object{Keys: []string{by, "role"}, Members: map[string]canon.Value{by: canon.String(key), "role": canon.String(role)}}
}

// Admit evaluates candidates proposed together for the edition after edition (an authorized edition of
// resource id, by edition id or any approval's statement id). The formation is the base edition's members
// plus every candidate, as a set: a set-level rule names every member in conflict and admits none by order.
// The base edition is only read: no edition, artifact or membership changes (C-core-91).
func (r *Resolver) Admit(id, edition string, candidates ...*canon.Object) (*Admission, error) {
	res, ok := r.Resource(id)
	if !ok {
		return nil, &refusal.Refusal{Class: refusal.Policy, Reason: EditionNotHeld, Detail: "resource " + keylog.Short(id) + " not held"}
	}
	var cs []*Member
	for _, c := range candidates {
		cs = append(cs, r.memberRecord(c))
	}
	return r.admit(res, edition, cs)
}

// EditionNotHeld is the reason a check that names an edition this reader does not hold refuses with (§8:
// "refuses and names the fetch").
const EditionNotHeld = "edition not held"

func (r *Resolver) admit(res *Resource, edition string, cs []*Member) (*Admission, error) {
	e, ok := res.Edition(edition)
	if !ok || e.State != Authorized {
		why := "not held"
		if ok {
			why = "held but " + string(e.State)
		}
		return nil, &refusal.Refusal{Class: refusal.Policy, Reason: EditionNotHeld,
			Detail: fmt.Sprintf("edition %s of %s %s; fetch it", keylog.Short(edition), keylog.Short(res.ID), why)}
	}
	a := &Admission{Resource: res.ID, Edition: e.ID, Outcomes: map[string]Outcome{}}
	form := r.editionMembers(e)
	cand := map[string]bool{}
	for _, c := range cs {
		form = slices.DeleteFunc(form, func(m *Member) bool { return m.Key == c.Key })
		form = append(form, c)
		cand[c.Key] = true
	}
	a.Candidates = sortedKeys(cand)
	per := map[string][]Eval{}
	for _, ev := range r.evalRules(r.loadRules(e.Body), form) {
		if cand[ev.Member] {
			a.Evals = append(a.Evals, ev)
			per[ev.Member] = append(per[ev.Member], ev)
		}
	}
	for _, k := range a.Candidates {
		a.Outcomes[k] = aggregate(per[k])
	}
	return a, nil
}

// Render is the admission display.
func (a *Admission) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "candidates for the edition after %s of %s\n", keylog.Short(a.Edition), keylog.Short(a.Resource))
	for _, k := range a.Candidates {
		fmt.Fprintf(&b, "  %s: %s\n", shortMember(k), a.Outcomes[k])
	}
	for _, e := range a.Evals {
		fmt.Fprintf(&b, "  %s\n", e)
	}
	return b.String()
}

// PrePin is the result of the pre-pin check (§8 "Intended-for").
type PrePin struct {
	Resource, Edition string
	Evals             []Eval
	Outcome           Outcome // ok or unchecked; a fail refuses instead
	// Body is the draft body with `intended_for` recorded (resource, edition, edition_applied, outcome).
	Body *canon.Object
}

// RuleFailed is the reason the pre-pin check refuses with when the named edition's rules fail the draft.
const RuleFailed = "intended_for rule failed"

// CheckIntendedFor runs the named edition's rules on a draft `authored` or `observed` body before its bytes are
// pinned. The check is the publisher's own policy, chosen by naming the edition (I9):
//   - edition not held: refuses (reader policy, EditionNotHeld) and names the edition to fetch; no body
//     (C-core-95a);
//   - any rule fails: refuses (reader policy, RuleFailed), scope this statement, naming the edition and the
//     rules; no body (C-core-96);
//   - otherwise: returns the body with `intended_for` recording the edition applied and the outcome, `ok` when
//     every rule is ok and `unchecked` when one could not finish (C-core-95, C-core-97). A statement never
//     records `ok` for a rule that did not run.
//
// The field confers nothing (I7): a reader re-applies the rules itself (CheckRecorded).
func (r *Resolver) CheckIntendedFor(draft *canon.Object, resource, edition string) (*PrePin, error) {
	res, ok := r.Resource(resource)
	if !ok {
		return nil, &refusal.Refusal{Class: refusal.Policy, Reason: EditionNotHeld,
			Detail: fmt.Sprintf("resource %s not held (edition %s); fetch it", keylog.Short(resource), keylog.Short(edition))}
	}
	a, err := r.admit(res, edition, []*Member{draftMember(draft)})
	if err != nil {
		return nil, err
	}
	p := &PrePin{Resource: resource, Edition: a.Edition, Evals: a.Evals, Outcome: a.Outcomes[a.Candidates[0]]}
	if p.Outcome == RuleFail {
		var failed []string
		for _, e := range a.Evals {
			if e.Outcome == RuleFail {
				failed = append(failed, e.String())
			}
		}
		return nil, &refusal.Refusal{Class: refusal.Policy, Reason: RuleFailed,
			Detail: fmt.Sprintf("scope this statement; edition %s: %s", keylog.Short(a.Edition), strings.Join(failed, "; "))}
	}
	rec := &canon.Object{Keys: []string{"edition", "edition_applied", "outcome", "resource"}, Members: map[string]canon.Value{
		"resource": canon.String(resource), "edition": canon.String(a.Edition), "edition_applied": canon.String(a.Edition),
		"outcome": canon.String(string(p.Outcome))}}
	body := &canon.Object{Members: map[string]canon.Value{}}
	for _, k := range draft.Keys {
		if k != "intended_for" {
			body.Keys = append(body.Keys, k)
			body.Members[k] = draft.Members[k]
		}
	}
	body.Keys = append(body.Keys, "intended_for")
	body.Members["intended_for"] = rec
	slices.SortFunc(body.Keys, canon.CompareKeys)
	p.Body = body
	return p, nil
}

// Recorded is a reader's re-application of a published statement's `intended_for` (§8: "a hub re-applies the
// named edition from its base revision, and separately the current edition when it endorses; both results are
// the reader's computation, shown side by side").
type Recorded struct {
	Statement, Resource string
	// Named and Current are the reader's own outcomes for the named edition and the current one. Current is
	// "" when the resource has no current edition.
	NamedEdition, CurrentEdition string
	Named, Current               Outcome
	Evals                        []Eval
	// PublisherSaid is the recorded outcome, shown only as the signer's word.
	PublisherSaid, Signer string
	Endorsed              bool
	Explain               []string
}

// CheckRecorded re-applies the edition a statement's `intended_for` names, and the resource's current edition.
func (r *Resolver) CheckRecorded(stmt string) (*Recorded, bool) {
	p, ok := r.byID[stmt]
	if !ok || !p.Evaluable {
		return nil, false
	}
	iv, ok := p.St.Body.Get("intended_for")
	if !ok {
		return nil, false
	}
	io := iv.(*canon.Object)
	out := &Recorded{Statement: stmt, Resource: str(io, "resource"), NamedEdition: str(io, "edition"),
		PublisherSaid: str(io, "outcome"), Signer: p.St.Signer}
	res, ok := r.Resource(out.Resource)
	if !ok {
		out.Explain = append(out.Explain, "resource "+keylog.Short(out.Resource)+" not held")
		return out, true
	}
	cand := []*Member{r.memberRecord(Entry("statement", stmt, "member"))}
	if a, err := r.admit(res, out.NamedEdition, cand); err != nil {
		out.Named = RuleUnchecked
		out.Explain = append(out.Explain, "named edition: "+err.Error())
	} else {
		out.Named, out.Evals = a.Outcomes[stmt], append(out.Evals, a.Evals...)
	}
	if res.Current != "" && res.Current != res.ID {
		out.CurrentEdition = res.Current
		if a, err := r.admit(res, res.Current, cand); err == nil {
			out.Current = a.Outcomes[stmt]
			if res.Current != out.NamedEdition {
				out.Evals = append(out.Evals, a.Evals...)
			}
		}
	}
	if m, ok := r.Membership(out.Resource, stmt); ok {
		out.Endorsed = m.Endorsed
	}
	return out, true
}

// Render shows both computations side by side, and the publisher's outcome only as its word.
func (c *Recorded) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "intended_for %s of %s (statement %s)\n", keylog.Short(c.NamedEdition), keylog.Short(c.Resource), keylog.Short(c.Statement))
	fmt.Fprintf(&b, "  %s: %s (named edition; this reader's computation)\n", keylog.Short(c.NamedEdition), c.Named)
	if c.CurrentEdition != "" {
		fmt.Fprintf(&b, "  %s: %s (current edition; this reader's computation)\n", keylog.Short(c.CurrentEdition), c.Current)
	}
	fmt.Fprintf(&b, "  publisher %s says: %s (the publisher's word, not checked by it)\n", shortKey(c.Signer), c.PublisherSaid)
	if c.Endorsed {
		b.WriteString("  membership: endorsed\n")
	} else {
		b.WriteString("  membership: not endorsed\n")
	}
	for _, e := range c.Evals {
		fmt.Fprintf(&b, "  %s\n", e)
	}
	for _, x := range c.Explain {
		fmt.Fprintf(&b, "  %s\n", x)
	}
	return b.String()
}
