package resolve

import (
	"fmt"

	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// Pre-registration (claims-model note §7 disclosure table, §9.4; bitcoin-time note §8.2).
//
// A statement carrying `fulfills` (an `authored` result or an `observed` capture) names a task edition by its
// edition id. It displays `pre-registered <edition> (<bound quality>)`, where the bound is the one the reader
// holds for the edition: the best bound of its counted approvals, read through the same TimeVerifier as every
// other bound (one evidence record, I12). A local bound displays `(local, self-declared)` and never a verified
// time; a verified bound displays `(bitcoin)` with its height. A pre-registration proves the plan existed by
// that bound, not that its author had not seen the data, and the display claims nothing more.
//
// `fulfills` that names no authorized edition of a task the reader holds displays what it names and never
// `pre-registered`. With no `fulfills`, `pre_registration: exploratory` displays `exploratory`, and a missing
// field displays `undeclared`, never `exploratory` (§7: missing means undeclared).

// PreRegistration is the pre-registration disclosure of one statement.
type PreRegistration struct {
	// Display is the disclosure as every surface shows it.
	Display string
	// Edition is the task edition `fulfills` names ("" when none); Bound the reader's bound for it.
	Edition string
	Bound   Bound
	// Registered is true when the display is `pre-registered …`.
	Registered bool
	Explain    []string
}

// preRegistration computes the disclosure for st (an `authored` or `observed` body that has passed its schema).
func (r *Resolver) preRegistration(st *wire.Statement) PreRegistration {
	f := object(st.Body, "fulfills")
	exploratory := str(st.Body, "pre_registration") == "exploratory"
	if f == nil {
		if exploratory {
			return PreRegistration{Display: "exploratory"}
		}
		return PreRegistration{Display: "undeclared"}
	}
	res, ed := str(f, "resource"), str(f, "edition")
	p := PreRegistration{Edition: ed}
	task, ok := r.Resource(res)
	var e *Edition
	if ok {
		for _, x := range task.Editions {
			if x.ID == ed {
				e = x
			}
		}
	}
	switch {
	case !ok:
		p.Display = "fulfills " + keylog.Short(ed) + " of " + keylog.Short(res) + " (task not held): not shown as pre-registered"
	case task.Type != "task":
		p.Display = "fulfills " + keylog.Short(ed) + " of " + keylog.Short(res) + " (a " + task.Type + ", not a task): not shown as pre-registered"
	case e == nil:
		why := "names no edition of the task held"
		if x, held := task.Edition(ed); held {
			why = "is the statement id of an approval of " + keylog.Short(x.ID) + ", not an edition id"
		}
		p.Display = "fulfills " + keylog.Short(ed) + " (" + why + "): not shown as pre-registered"
	case e.State != Authorized:
		p.Display = "fulfills " + keylog.Short(ed) + " (" + string(e.State) + "): not shown as pre-registered"
	default:
		p.Bound = r.editionBound(e)
		p.Registered = true
		p.Display = "pre-registered " + keylog.Short(ed) + " (" + qualityLabel(p.Bound) + ")"
		if p.Bound.verified() {
			p.Display += fmt.Sprintf(" at %s height %d", p.Bound.Network, p.Bound.Height)
		}
		p.Explain = append(p.Explain, "the plan's bound: "+p.Bound.String()+"; a pre-registration proves the plan existed by its bound, not that its author had not seen the data (claims §9.4)")
		if rb := r.bound(st); rb.verified() && p.Bound.verified() {
			if ok, how := earlier(p.Bound, rb); ok {
				p.Explain = append(p.Explain, "the plan's bound ranks before this statement's ("+how+")")
			} else {
				p.Explain = append(p.Explain, "the plan's bound does not rank before this statement's ("+how+")")
			}
		}
	}
	if exploratory {
		p.Display += "; also declares exploratory (disagreement flagged; neither replaces the other)"
	}
	return p
}

// editionBound is the best bound the reader holds for an edition: the best over its counted approvals.
func (r *Resolver) editionBound(e *Edition) Bound {
	best := Bound{Quality: NoBound}
	for _, a := range e.Approvals {
		if !a.Counted {
			continue
		}
		if p, ok := r.byID[a.Statement]; ok {
			best = better(best, r.bound(p.St))
		}
	}
	return best
}

// qualityLabel is a bound's quality as the pre-registration display names it (bitcoin-time note §8.2).
func qualityLabel(b Bound) string {
	switch b.Quality {
	case Bitcoin:
		return "bitcoin"
	case Local:
		return "local, self-declared"
	}
	return "no anchor"
}

// PreRegistration is the pre-registration disclosure of statement id (an `authored` or `observed`); ok is false
// when no such statement is held or its body is not understood.
func (r *Resolver) PreRegistration(id string) (PreRegistration, bool) {
	p, ok := r.byID[id]
	if !ok || (p.St.Kind != "authored" && p.St.Kind != "observed") || !p.St.Verified || p.St.Status != wire.Valid {
		return PreRegistration{}, false
	}
	return r.preRegistration(p.St), true
}

// artifactPreReg is a blob's pre-registration disclosure: from the default unit's `fulfills` when it has one,
// else its `pre_registration`. nil when either field has no default (contested or no default author): the
// field display then shows that state.
func (r *Resolver) artifactPreReg(a *Artifact) *PreRegistration {
	f, x := a.Field("fulfills"), a.Field("pre_registration")
	if (f.State != FieldDefault && f.State != FieldAbsent) || (x.State != FieldDefault && x.State != FieldAbsent) {
		return nil
	}
	src := f
	if f.State == FieldAbsent {
		src = x
	}
	if src.State == FieldAbsent {
		return &PreRegistration{Display: "undeclared"}
	}
	p := r.preRegistration(r.byID[src.From[0].Statement].St)
	return &p
}
