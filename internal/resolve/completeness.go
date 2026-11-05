package resolve

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/rctime"
)

// Completeness claims (claims-model note §6 (3), §7 "Declared beside computed"; wire-format note §5
// `edition.contents.completeness`; C-core-60).
//
// An edition that declares selection `completeness` names its scope: an observation class, the source (that
// class's identifying referent field) and a time window. The reader checks the claim against the observations
// it holds: a counted `observed` of the class, naming the source, positioned in the window, is in scope, and
// the edition must list it, by its statement or by its content. The outcome is
//
//   - `fail`: some reading in scope is not listed; each one is named (a decided refutation of the claim);
//   - `unchecked`: no reading fails it, but some reading of the class has a source or position this reader
//     cannot read, or a position in another timescale (never converted); or the claim names no scope;
//   - `ok`: every reading in scope that the reader holds is listed. Scoped to the statements held: never a
//     claim that no other reading exists (§6 (1), C-core-01).
//
// The check is the reader's computation beside the controller's declaration. It changes no membership, no
// edition's authorization, no grade and no verify exit (I6): a hub that wants to refuse an edition whose claim
// fails does so under its own policy, as it may refuse a premature freeze (§8).

// Completeness is the reader's check of one edition's completeness claim.
type Completeness struct {
	Resource, Edition string
	// Declared is true when the edition's selection is `completeness`; nothing is checked otherwise.
	Declared bool
	// Scoped is true when the claim names its scope; the fields below are read from it.
	Scoped              bool
	Class, Source       string
	From, To, Timescale string
	Outcome             Outcome
	// Missing are the readings in scope the edition does not list (statement ids, sorted); Listed those it does;
	// Unread the readings of the class whose source or position could not be read or compared, each with why.
	Missing, Listed []string
	Unread          map[string]string
	Scope           string
	Explain         []string
}

// sourceField is the referent field that names a reading's source, per class (wire §5).
var sourceField = map[string]string{"source": "endpoint", "phenomenon": "instrument", "method": "method_edition"}

// Completeness checks the completeness claim of resource id at edition (its current edition when ""). ok is
// false when the resource or an authorized edition is not held, as for Series.
func (r *Resolver) Completeness(id, edition string) (*Completeness, bool) {
	res, ok := r.Resource(id)
	if !ok {
		return nil, false
	}
	if edition == "" {
		edition = res.Current
	}
	e, ok := res.Edition(edition)
	if !ok || e.State != Authorized {
		return nil, false
	}
	c := &Completeness{Resource: id, Edition: e.ID, Scope: r.obs.scope, Unread: map[string]string{}}
	// the selection is read here only to find the claim; it informs no agreement model (C-core-59)
	if c.Declared = Selection(e.Body) == "completeness"; !c.Declared {
		c.Explain = append(c.Explain, "the edition declares no completeness claim; nothing to check")
		return c, true
	}
	contents, _ := e.Body.Get("contents")
	sv, ok := contents.(*canon.Object).Get("completeness")
	if !ok {
		c.Outcome = RuleUnchecked
		c.Explain = append(c.Explain, "the completeness claim names no scope (class, source, window): it cannot be checked")
		return c, true
	}
	sc := sv.(*canon.Object)
	w := object(sc, "window")
	c.Scoped, c.Class, c.Source, c.From, c.To, c.Timescale = true, str(sc, "class"), str(sc, "source"), str(w, "from"), str(w, "to"), str(sc, "timescale")
	from, err1 := rctime.ParseIn(c.From, c.Timescale)
	to, err2 := rctime.ParseIn(c.To, c.Timescale)
	if err1 != nil || err2 != nil {
		c.Outcome = RuleUnchecked // the schema refuses this edition; kept for a body read some other way
		c.Explain = append(c.Explain, "the claim's window does not read in its timescale")
		return c, true
	}

	listed := map[string]bool{}
	for _, m := range r.editionMembers(e) {
		listed[m.Key] = true
		if m.Digest != "" {
			listed[m.Digest] = true
		}
	}
	for _, p := range r.byKind["observed"] {
		if !p.Counts() || str(p.St.Body, "class") != c.Class {
			continue
		}
		in, why := c.inScope(p, from, to)
		switch {
		case why != "":
			c.Unread[p.St.ID] = why
		case !in:
		case listed[p.St.ID] || listed[contentDigest(p.St.Body)]:
			c.Listed = append(c.Listed, p.St.ID)
		default:
			c.Missing = append(c.Missing, p.St.ID)
		}
	}
	slices.Sort(c.Listed)
	slices.Sort(c.Missing)
	switch {
	case len(c.Missing) > 0:
		c.Outcome = RuleFail
		for _, id := range c.Missing {
			c.Explain = append(c.Explain, fmt.Sprintf("reading %s by %s from %s in the window is not listed by %s",
				keylog.Short(id), shortKey(r.byID[id].St.Signer), c.Source, keylog.Short(e.ID)))
		}
	case len(c.Unread) > 0:
		c.Outcome = RuleUnchecked
	default:
		c.Outcome = RuleOK
	}
	for _, id := range sortedKeys(c.Unread) {
		c.Explain = append(c.Explain, fmt.Sprintf("reading %s: %s", keylog.Short(id), c.Unread[id]))
	}
	return c, true
}

// inScope reports whether a counted observed of the claim's class is in its scope. why is set when the reader
// cannot tell: the source or the position cannot be read, or the position is in another timescale.
func (c *Completeness) inScope(p *Placed, from, to rctime.Time) (bool, string) {
	ref := object(p.St.Body, "referent")
	f := sourceField[c.Class]
	src := str(ref, f)
	if src == "" && c.Class == "source" {
		// a batch names the endpoint every logged request shares, when there is one (wire §5)
		src, f = str(object(ref, "requests"), "endpoint"), "endpoint (one request) or requests.endpoint (a batch)"
	}
	if src == "" {
		return false, "referent names no " + f + ": its source cannot be read"
	}
	switch compareSource(src, c.Source) {
	case uriDiffer:
		return false, ""
	case uriLoose:
		return false, "source " + quoteInert(src) + " equals the claim's only once a trailing / or a percent-encoding is set aside: it may or may not be the same resource"
	}
	// the position, read as a series segment's (§8): the start of the window (for a source, the period the
	// response covers), else the time, else the time in the finality state at capture
	text, scale := str(object(ref, "window"), "from"), str(ref, "timescale")
	if text == "" {
		text = str(ref, "at")
	}
	if text == "" {
		text, scale = str(object(object(p.St.Body, "finality"), "state_at_capture"), "captured_at"), ""
	}
	if text == "" {
		return false, "no time position (no referent window or time, no captured_at finality state)"
	}
	if utc(scale) != utc(c.Timescale) {
		return false, fmt.Sprintf("position in timescale %s, the window in %s: not comparable, never converted", utc(scale), utc(c.Timescale))
	}
	at, err := rctime.ParseIn(text, scale)
	if err != nil {
		return false, "position does not read: " + err.Error()
	}
	return rctime.Compare(at, from) >= 0 && rctime.Compare(at, to) < 0, ""
}

// utc names the scale a time is in: UTC when none is named (wire §1.1).
func utc(scale string) string {
	if scale == "" {
		return "UTC"
	}
	return scale
}

// Line is the one-line display of the check.
func (c *Completeness) Line() string {
	switch {
	case !c.Declared:
		return "no completeness claim"
	case !c.Scoped:
		return "completeness claim (no scope declared): " + string(c.Outcome)
	}
	line := fmt.Sprintf("completeness claim: %s readings from %s in [%s, %s)", c.Class, c.Source, c.From, c.To)
	if c.Timescale != "" {
		line += " " + c.Timescale
	}
	line += " (declared) · " + string(c.Outcome)
	if len(c.Missing) > 0 {
		line += fmt.Sprintf(" (%s not listed)", plural(len(c.Missing), "reading"))
	}
	return line + " " + c.Scope
}

// Render is the completeness display: the declaration beside the reader's check, each reading named.
func (c *Completeness) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s at %s\n  %s\n", keylog.Short(c.Resource), keylog.Short(c.Edition), c.Line())
	for _, id := range c.Listed {
		fmt.Fprintf(&b, "  listed %s\n", keylog.Short(id))
	}
	for _, x := range c.Explain {
		fmt.Fprintf(&b, "  %s\n", x)
	}
	return b.String()
}
