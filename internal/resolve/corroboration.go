package resolve

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/rctime"
	"github.com/research-common/research-commons/internal/wire"
)

// Corroboration status (claims-model note §5.3.2, §6 (1), I4).
//
// An observation's corroboration status is computed per reader from the evidence it holds, always printed with
// its scope ("within statements you hold", or "within this hub" on a hub's own surface), never as a
// completeness claim. Evidence is of four kinds, each attributed:
//
//   - a `corroborates` statement about the observation: a signed verdict naming the derived result that
//     computed it (a corroboration is a derivation, so its own grade is shown beside it, never gating it);
//   - another key's re-read of an exact-bytes referent: its own `observed` of the same chain and block hash
//     with identical bytes and its own capture record (§5.3.1), at any confirmation depth (the bytes at a hash
//     never change; finality drives the referent status, not agreement); a source-class re-capture counts only
//     once the source's finality rule holds at it (class migration by rule); identical bytes in any other case
//     are a second publication or a copy, not a corroboration;
//   - the reader's comparison of two captures of one referent with different bytes: at one block hash they
//     contradict; for a source under a finality rule, `inconclusive (referent revised)` across ordered states
//     before finality, `inconclusive (not comparable under the rule)` when the rule cannot order them,
//     `contradicts` at one state or both past it;
//   - the reader's own re-check of the referent (ReferentChecker).
//
// Counting is behind Counter. Which unit corroboration counts (signing keys, identities, operators,
// environments) is not decided yet; the only implementation counts distinct signing keys, as the merged note's
// text reads today, and every status says so. Independence is never inferred: distinct keys prove nothing about
// it (§5.3.2, §9.3), so it reads `unknown` and declared shared sources are grouped beside the count.
//
// Trust: the note computes the status from the corroborations a reader "holds and trusts". Trust is configured
// per purpose: with no reader policy, or one that names no principal for corroboration, every counted statement
// is counted and the status says trust is not configured; once the policy (WithPolicy) names any principal for
// corroboration, only evidence from keys it trusts for corroboration of the observation's content is counted
// (policy.go).

// Evidence is one input to a corroboration status.
type Evidence struct {
	Verdict string // supports, contradicts, inconclusive
	Cause   string // for inconclusive, or why a statement is not counted
	Model   string
	// Key is the signer of the statement the evidence is; "" for the reader's own computation.
	Key       string
	Statement string
	// Via names the kind of evidence: "corroborates", "re-read", "re-capture", "reader re-check",
	// "reader finality-aware comparison".
	Via     string
	Cohort  string
	Shares  []string
	Counted bool
	// Result is the derived result a `corroborates` names; Grade its derivation's grade (full view only).
	Result, Grade string
	// CohortCheck is the reader's re-application of the declared cohort rule (full view only).
	CohortCheck []string
	Comparison  []string // the result's comparison data (its inputs other than the observation)
	Capture     string   // a re-read's capture record, as signed
	Origins     []string // delivery metadata: where the statement came from, when the reader configured it
}

// Reader reports whether the evidence is the reader's own computation.
func (e Evidence) Reader() bool { return e.Key == "" }

// Counter counts the evidence behind one verdict. observer is the observation's signer. It returns the count,
// the unit it counted in, and a note per item it left out.
type Counter interface {
	Count(observer string, ev []Evidence) (n int, unit string, left []string)
}

// KeyCounter counts distinct signing keys, plus one for the reader's own computation; evidence signed by the
// observer's own key is left out (a re-read by the observer is its own word again). This is the merged note's
// current text ("distinct keys", §9.3), and it is labelled wherever a count is shown: the counting unit is
// pending a decision on identity.
type KeyCounter struct{}

// UnitKeys is KeyCounter's label.
const UnitKeys = "distinct signing keys (counting unit pending identity decision)"

// Count implements Counter.
func (KeyCounter) Count(observer string, ev []Evidence) (int, string, []string) {
	seen := map[string]bool{}
	var left []string
	reader := false
	for _, e := range ev {
		switch {
		case e.Reader():
			reader = true
		case e.Key == observer:
			left = append(left, fmt.Sprintf("%s %s is signed by the observer's own key: not counted", e.Via, keylog.Short(e.Statement)))
		default:
			seen[e.Key] = true
		}
	}
	n := len(seen)
	if reader {
		n++
	}
	return n, UnitKeys, left
}

// CohortRules re-applies a declared cohort rule to the reference collection the reader chose (§5.3.2, §6 (4)).
// members are the content digests the rule selects; edition cites the collection edition it was applied to.
// The project ships no reference collection, so the default chooses none.
type CohortRules interface {
	Apply(rule string) (members []string, edition string, why string, ok bool)
}

// NoCohortRules is the default: no reference collection is chosen.
type NoCohortRules struct{}

// NoReference is the cause a re-application reports with no reference collection chosen (C-core-61).
const NoReference = "no reference collection chosen"

// Apply implements CohortRules.
func (NoCohortRules) Apply(string) ([]string, string, string, bool) {
	return nil, "", NoReference, false
}

// WithCohortRules sets the reader's cohort-rule evaluator over the reference collections it chose.
func WithCohortRules(c CohortRules) Option { return func(r *Resolver) { r.obs.cohorts = c } }

// OriginIndex names where the reader got a statement (a hub, a relayer, a file). Delivery metadata: shown in
// explain, never an input to any status (I14).
type OriginIndex interface {
	Origins(id string) []string
}

// WithOrigins sets the reader's delivery-metadata index.
func WithOrigins(o OriginIndex) Option { return func(r *Resolver) { r.origins = o } }

// Corroboration is an observation's corroboration status.
type Corroboration struct {
	Scope, Unit string
	// Corroborated and Contradicted are the counts under Unit; Inconclusive lists the inconclusive evidence.
	Corroborated, Contradicted int
	// Unchecked is set when no class-specific model applies (an unpinned referent): every count is zero.
	Unchecked bool
	Why       string
	Evidence  []Evidence
	// Independence is always "unknown": nothing the resolver holds establishes it.
	Independence string
	// Shared groups counted evidence by declared shared source (upstream feed, operator, instrument).
	Shared map[string][]string
	// Held lists the other statements about the observation: refutes, describes, retracts (display only).
	Held    []string
	Left    []string
	Explain []string
	// Trust is the reader's trust line: not configured, or the policy and what it left uncounted (policy.go).
	Trust string
}

// Status is the status token with its scope: `corroborated n · contradicted m within …`, or `unchecked within
// …` when nothing counts. Never an unscoped count, never `uncontradicted`.
func (c *Corroboration) Status() string {
	if c.Unchecked || (c.Corroborated == 0 && c.Contradicted == 0) {
		return "unchecked " + c.Scope
	}
	var parts []string
	if c.Corroborated > 0 {
		parts = append(parts, fmt.Sprintf("corroborated %d", c.Corroborated)+c.readerNote("supports"))
	}
	if c.Contradicted > 0 {
		parts = append(parts, fmt.Sprintf("contradicted %d", c.Contradicted)+c.readerNote("contradicts"))
	}
	return strings.Join(parts, " · ") + " " + c.Scope
}

func (c *Corroboration) readerNote(verdict string) string {
	others := 0
	reader := false
	for _, e := range c.Evidence {
		if e.Counted && e.Verdict == verdict {
			if e.Reader() && e.Via == "reader re-check" {
				reader = true
			} else {
				others++
			}
		}
	}
	switch {
	case reader && others == 0:
		return " (reader re-check)"
	case reader:
		return " (incl. reader re-check)"
	}
	return ""
}

// ByModel is the per-model breakdown: "contradicted by 2 under M".
func (c *Corroboration) ByModel() []string {
	type k struct{ verdict, model string }
	groups := map[k][]Evidence{}
	for _, e := range c.Evidence {
		if e.Counted && e.Verdict != "inconclusive" {
			groups[k{e.Verdict, e.Model}] = append(groups[k{e.Verdict, e.Model}], e)
		}
	}
	var out []string
	for key, ev := range groups {
		n, _, _ := KeyCounter{}.Count("", ev)
		word := "corroborated"
		if key.verdict == "contradicts" {
			word = "contradicted"
		}
		out = append(out, fmt.Sprintf("%s by %d under %s", word, n, key.model))
	}
	slices.Sort(out)
	return out
}

func (r *Resolver) corroboration(o *Observation, st *wire.Statement) *Corroboration {
	return r.corroborate(o, st, true)
}

// corroborate computes the status. full adds what only the observation's own view shows (each corroboration's
// grade, the cohort re-application); the lite form serves the summary beside a derived result's grade, and
// never resolves a result's grade, so a result resting on an observation cannot recurse into it.
func (r *Resolver) corroborate(o *Observation, st *wire.Statement, full bool) *Corroboration {
	c := &Corroboration{Scope: r.obs.scope, Independence: "unknown", Shared: map[string][]string{}}
	if len(o.Unpinned) > 0 {
		c.Unchecked = true
		c.Why = "referent unpinned (" + strings.Join(o.Unpinned, ", ") + "): no class-specific agreement model applied"
	}
	// corroborates statements about this observation
	for _, p := range r.byKind["corroborates"] {
		// A type-checked of associates retained evidence only. It grants no body semantics.
		if str(p.St.Body, "of") != st.ID {
			continue
		}
		if !p.St.Verified || p.St.Status != wire.Valid {
			c.Evidence = append(c.Evidence, Evidence{Key: p.St.Signer, Statement: p.St.ID, Via: "corroborates",
				Origins: r.originsOf(p.St.ID), Cause: "counts toward nothing: " + notCountedWhy(p) + "; " + uninterpretedBodyWhy(p.St)})
			continue
		}
		b := p.St.Body
		e := Evidence{Verdict: str(b, "verdict"), Model: str(b, "model"), Key: p.St.Signer, Statement: p.St.ID, Via: "corroborates",
			Shares: ids(b, "shares"), Cause: str(b, "cause"), Result: str(b, "result"), Origins: r.originsOf(p.St.ID)}
		if co := object(b, "cohort"); str(co, "rule") != "" {
			e.Cohort = "rule: " + str(co, "rule")
		} else {
			e.Cohort = "hand-picked"
		}
		e.Comparison = r.comparisonData(e.Result, o.Digest)
		switch {
		case !p.Counts():
			e.Cause = "counts toward nothing: " + notCountedWhy(p)
		case c.Unchecked:
			e.Cause = "not applied: " + c.Why
		case o.Class == "method" && r.incomparableInput(o, e.Result):
			e.Cause = "comparability unchecked: its comparison data includes a method-class observation that does not pin the same clause members"
		default:
			e.Counted = e.Verdict != "inconclusive"
		}
		if full && p.Counts() {
			r.corroborationDetail(&e, o)
		}
		c.Evidence = append(c.Evidence, e)
	}
	if !c.Unchecked {
		r.symmetric(c, o, st)
		r.recaptures(c, o, st)
		r.readerCheck(c, o)
	}
	slices.SortFunc(c.Evidence, func(a, b Evidence) int {
		return strings.Compare(a.Via+a.Key+a.Statement, b.Via+b.Key+b.Statement)
	})
	r.trustFilter(c, o) // the reader's corroboration trust, before Counter (policy.go)
	var sup, con []Evidence
	for _, e := range c.Evidence {
		if !e.Counted {
			continue
		}
		if e.Verdict == "supports" {
			sup = append(sup, e)
		} else if e.Verdict == "contradicts" {
			con = append(con, e)
		}
		for _, s := range e.Shares {
			c.Shared[s] = append(c.Shared[s], e.Via+" "+keylog.Short(e.Statement))
		}
	}
	var l1, l2 []string
	c.Corroborated, c.Unit, l1 = r.obs.counter.Count(o.Signer, sup)
	c.Contradicted, _, l2 = r.obs.counter.Count(o.Signer, con)
	c.Left = append(l1, l2...)
	c.Held = r.heldAbout(st)
	return c
}

// symmetric adds the contradictions this observation takes part in as comparison data (§5.3.2 "disagreement is
// symmetric"): a counted `contradicts` on another observation whose result names this observation's bytes among
// its comparison data is a disagreement between the two, and counts against both. The tool does not decide which
// side is wrong (§6). Supports is not mirrored: a check against comparison data says nothing about that data.
func (r *Resolver) symmetric(c *Corroboration, o *Observation, st *wire.Statement) {
	for _, p := range r.byKind["corroborates"] {
		b := p.St.Body
		if !p.Counts() || str(b, "of") == st.ID || str(b, "verdict") != "contradicts" {
			continue
		}
		of, ok := r.byID[str(b, "of")]
		if !ok || of.St.Kind != "observed" || !of.Counts() || contentDigest(of.St.Body) == o.Digest {
			continue
		}
		if !slices.Contains(r.comparisonData(str(b, "result"), contentDigest(of.St.Body)), o.Digest) {
			continue
		}
		c.Evidence = append(c.Evidence, Evidence{Verdict: "contradicts", Model: str(b, "model"), Key: p.St.Signer, Statement: p.St.ID,
			Via: "corroborates (symmetric)", Counted: true, Shares: ids(b, "shares"), Origins: r.originsOf(p.St.ID),
			Cause: "disagreement is symmetric: it contradicts " + keylog.Short(of.St.ID) + " by " + shortKey(of.St.Signer) + " with these bytes as comparison data; neither side is marked wrong"})
	}
}

// recaptures reads the other captures of the same referent (§5.3.1): re-reads, re-captures after finality, and
// the reader's finality-aware comparison of captures with different bytes.
func (r *Resolver) recaptures(c *Corroboration, o *Observation, st *wire.Statement) {
	myCapture := string(canon.Encode(object(st.Body, "capture")))
	for _, q := range r.byKind["observed"] {
		if !q.Counts() || q.St.ID == st.ID || !sameReferent(st, q.St) {
			continue
		}
		e := Evidence{Key: q.St.Signer, Statement: q.St.ID, Model: o.Class + " (" + o.Class + " class model)", Origins: r.originsOf(q.St.ID),
			Capture: string(canon.Encode(object(q.St.Body, "capture")))}
		same := contentDigest(q.St.Body) == o.Digest
		switch {
		case same && e.Capture == myCapture:
			e.Via, e.Verdict = "re-read", "supports"
			e.Cause = "shares its capture record byte for byte with this observation: not its own capture, not counted"
		case same && o.Class == "source" && o.Finality != nil && !r.finalAt(st, q.St):
			e.Via, e.Verdict, e.Model = "re-capture", "inconclusive", "source (class model before finality)"
			e.Cause = "re-capture before the finality rule holds: evaluated under the source-class model (near-equality around the same time, which needs a declared tolerance), not an exact-bytes corroboration"
		case same && o.Class == "exact-bytes":
			// The bytes at a block hash never change (a reorg orphans the block, it does not alter what the hash
			// holds), so a re-read counts at any confirmation depth; the finality rule drives the referent status
			// only (§5.3.1).
			e.Via, e.Verdict, e.Counted = "re-read", "supports", true
			e.Model = "exact-bytes (identical bytes at the pinned block hash)"
		case same && o.Class == "source" && r.finalAt(st, q.St):
			e.Via, e.Verdict, e.Counted = "re-capture", "supports", true
			e.Model = "exact-bytes (class migration by rule: the finality rule holds at the re-capture)"
		case same:
			continue // a second publication; listed beside the observation, never evidence
		default:
			r.finalityAware(&e, o, st, q.St)
			if e.Verdict == "" {
				continue
			}
		}
		c.Evidence = append(c.Evidence, e)
	}
}

// finalityAware compares two captures of one referent with different bytes (§5.3.1 "expected revision is not
// contradiction"). An exact-bytes pair at one block hash contradicts at any depth: those bytes cannot be revised,
// so the finality rule never applies to the comparison. A source pair is compared under its finality rule; with
// none on both it is not compared (the source-class model needs a declared tolerance).
func (r *Resolver) finalityAware(e *Evidence, o *Observation, st, q *wire.Statement) {
	e.Via = "reader finality-aware comparison"
	if o.Class == "exact-bytes" {
		e.Via = "reader comparison"
		e.Verdict, e.Counted, e.Model = "contradicts", true, "exact-bytes (different bytes at the pinned block hash)"
		return
	}
	if o.Finality == nil || (captureState(q) == State{}) {
		return
	}
	e.Model = "finality-aware (" + o.Finality.Rule + ")"
	e.Verdict, e.Counted, e.Cause = finalityVerdict(r.obs.finality, o.Finality.Rule, o.Finality.State, captureState(q))
}

// finalityVerdict is the finality-aware agreement model on two captures with different bytes.
func finalityVerdict(rules FinalityRules, rule string, a, b State) (verdict string, counted bool, cause string) {
	metA, _, knownA := rules.Evaluate(rule, a)
	metB, _, knownB := rules.Evaluate(rule, b)
	if !knownA || !knownB {
		return "inconclusive", false, "finality rule not evaluable by this reader"
	}
	c, ok := rules.Compare(rule, a, b)
	switch {
	case ok && c == 0, metA && metB:
		return "contradicts", true, ""
	case !ok:
		return "inconclusive", false, NotComparableUnderRule
	}
	return "inconclusive", false, "referent revised"
}

// NotComparableUnderRule is the cause for two captures at states the finality rule cannot order (§5.3.1: "states
// that the rule cannot order are not comparable"): no revision is asserted, because the reader has no order.
const NotComparableUnderRule = "not comparable under the rule"

// readerCheck turns the reader's own re-check into evidence.
func (r *Resolver) readerCheck(c *Corroboration, o *Observation) {
	rc := o.ReCheck
	e := Evidence{Via: "reader re-check", Model: o.Class + " (reader re-check)"}
	switch rc.Outcome {
	case ReSame:
		e.Verdict, e.Counted = "supports", true
	case ReDifferent:
		e.Verdict, e.Counted = "contradicts", true
		if o.Class != "exact-bytes" && o.Finality != nil && (rc.State != State{}) {
			e.Model = "finality-aware (" + o.Finality.Rule + ")"
			e.Verdict, e.Counted, e.Cause = finalityVerdict(r.obs.finality, o.Finality.Rule, o.Finality.State, rc.State)
		}
	case ReNotCanonical, ReUnavailable:
		e.Verdict, e.Cause = "inconclusive", rc.Outcome
	default:
		return
	}
	c.Evidence = append(c.Evidence, e)
}

// comparisonData lists a corroboration result's inputs other than the observation itself (§5.3.2: the
// original observation plus comparison data), from the result's counted `authored`.
func (r *Resolver) comparisonData(result, observed string) []string {
	p, ok := r.byID[result]
	if !ok || p.St.Kind != "authored" || !p.Counts() {
		return nil
	}
	pv := provenance(p.St.Body)
	if pv == nil {
		return nil
	}
	var out []string
	for _, in := range pv.Inputs {
		if in != observed {
			out = append(out, in)
		}
	}
	return out
}

// incomparableInput reports whether a method-class corroboration's comparison data includes a method-class
// observation of the same method edition that does not pin the same measured-system members (C-core-32).
func (r *Resolver) incomparableInput(o *Observation, result string) bool {
	for _, in := range r.comparisonData(result, o.Digest) {
		for _, q := range r.observedOf(in, true) {
			for _, c := range o.Comparability {
				if c.With == q.St.ID && !c.Comparable {
					return true
				}
			}
		}
	}
	return false
}

// corroborationDetail adds the corroboration's own grade (it is a derivation, §5.3.2) and the reader's
// re-application of its cohort rule.
func (r *Resolver) corroborationDetail(e *Evidence, o *Observation) {
	if p, ok := r.byID[e.Result]; ok && p.St.Kind == "authored" && p.Counts() {
		a := r.Artifact(contentDigest(p.St.Body))
		e.Grade = a.Grade.String()
		if a.Group != nil {
			e.Grade += " (" + a.Group.Token + ")"
		}
	} else {
		e.Grade = "result " + keylog.Short(e.Result) + " not held"
	}
	if !strings.HasPrefix(e.Cohort, "rule: ") {
		return
	}
	rule := strings.TrimPrefix(e.Cohort, "rule: ")
	members, edition, why, ok := r.obs.cohorts.Apply(rule)
	if !ok {
		e.CohortCheck = append(e.CohortCheck, "reader re-application of the cohort rule: inconclusive ("+why+")")
		return
	}
	e.CohortCheck = append(e.CohortCheck, fmt.Sprintf("reader re-applied the cohort rule to %s: %d member(s) (the reader's computation, beside the corroboration's own)", edition, len(members)))
	for _, m := range members {
		if m != o.Digest && !slices.Contains(e.Comparison, m) {
			e.CohortCheck = append(e.CohortCheck, "left out by inputs: "+shortDigest(m))
		}
	}
	for _, m := range e.Comparison {
		if !slices.Contains(members, m) {
			e.CohortCheck = append(e.CohortCheck, "in inputs, outside the rule as re-applied: "+shortDigest(m))
		}
	}
}

// heldAbout lists the statements about the observation that are not evidence: refutes, describes, and the
// observer's own retracts (displayed `retracted`, §13). Each attributed, none an input to the status.
func (r *Resolver) heldAbout(st *wire.Statement) []string {
	var out []string
	for _, kind := range []string{"describes", "refutes", "retracts"} {
		for _, p := range r.byKind[kind] {
			if !p.Evaluable {
				continue
			}
			b := p.St.Body
			about := str(b, "of")
			if kind == "describes" {
				about = str(object(b, "about"), "statement")
			}
			if about != st.ID {
				continue
			}
			line := fmt.Sprintf("held %s %s by %s", kind, keylog.Short(p.St.ID), shortKey(p.St.Signer))
			switch {
			case kind == "retracts" && p.St.Signer == st.Signer:
				line += " (retracted by the observer)"
			case kind == "retracts":
				line += " (names another key's statement: changes nothing)"
			case kind == "refutes":
				line += " evidence " + shortDigest(str(b, "evidence"))
			}
			out = append(out, line+" (not an input to the status)")
		}
	}
	slices.Sort(out)
	return out
}

func (r *Resolver) originsOf(id string) []string {
	if r.origins == nil {
		return nil
	}
	o := append([]string{}, r.origins.Origins(id)...)
	slices.Sort(o)
	return o
}

func (c *Corroboration) render(indent string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%scorroboration: %s\n", indent, c.Status())
	if c.Why != "" {
		fmt.Fprintf(&b, "%s  %s\n", indent, c.Why)
	}
	for _, m := range c.ByModel() {
		fmt.Fprintf(&b, "%s  %s\n", indent, m)
	}
	if c.Unit != "" && (c.Corroborated > 0 || c.Contradicted > 0) {
		fmt.Fprintf(&b, "%s  counted as: %s\n", indent, c.Unit)
	}
	fmt.Fprintf(&b, "%s  independence: %s (distinct keys prove nothing about independence)\n", indent, c.Independence)
	for _, s := range sortedKeys(c.Shared) {
		fmt.Fprintf(&b, "%s  declared shared source %q: %s\n", indent, s, strings.Join(c.Shared[s], ", "))
	}
	fmt.Fprintf(&b, "%s  %s\n", indent, cmp.Or(c.Trust, "your trust in these keys: not configured (every counted statement is counted)"))
	for _, e := range c.Evidence {
		who := "the reader"
		if !e.Reader() {
			who = shortKey(e.Key) + " in " + keylog.Short(e.Statement)
		}
		fmt.Fprintf(&b, "%s  %s by %s: %s under %s", indent, e.Via, who, e.Verdict, e.Model)
		if e.Cause != "" {
			fmt.Fprintf(&b, " (%s)", e.Cause)
		}
		if !e.Counted {
			b.WriteString(" [not counted]")
		}
		b.WriteString("\n")
		if e.Cohort != "" {
			fmt.Fprintf(&b, "%s    cohort: %s\n", indent, e.Cohort)
		}
		if len(e.Shares) > 0 {
			fmt.Fprintf(&b, "%s    shares with the original (declared): %s\n", indent, strings.Join(e.Shares, ", "))
		}
		if e.Result != "" {
			fmt.Fprintf(&b, "%s    result %s, grade %s\n", indent, keylog.Short(e.Result), orDash(e.Grade))
		}
		if len(e.Comparison) > 0 {
			cs := make([]string, len(e.Comparison))
			for i, x := range e.Comparison {
				cs[i] = shortDigest(x)
			}
			fmt.Fprintf(&b, "%s    comparison data: %s\n", indent, strings.Join(cs, ","))
		}
		if e.Capture != "" {
			fmt.Fprintf(&b, "%s    capture record (as signed): %s\n", indent, e.Capture)
		}
		for _, x := range e.CohortCheck {
			fmt.Fprintf(&b, "%s    %s\n", indent, x)
		}
		if len(e.Origins) > 0 {
			fmt.Fprintf(&b, "%s    held via %s (delivery metadata)\n", indent, strings.Join(e.Origins, ", "))
		}
	}
	for _, l := range c.Left {
		fmt.Fprintf(&b, "%s  %s\n", indent, l)
	}
	for _, h := range c.Held {
		fmt.Fprintf(&b, "%s  %s\n", indent, h)
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// obsNotes is the scoped summary beside a derived result's grade for one observation input d (claims §7): the
// referent statuses that bear on it and whether it is contradicted, within the reader's scope. It uses the lite
// status, which never resolves another artifact.
func (r *Resolver) obsNotes(d string) (contradicted bool, status string) {
	rank := map[string]int{RefNotCanonical: 5, RefRevised: 4, RefUnavailable: 3, RefProvisional: 2, RefFinal: 1}
	best := 0
	ps, unmet := r.observedFor(d) // every counted observation, or the reader's selected one (policy.go)
	if unmet != "" {
		return false, unmet
	}
	for _, p := range ps {
		o := r.observationLite(p)
		if o.Corroboration.Contradicted > 0 && !o.Corroboration.Unchecked {
			contradicted = true
		}
		s := o.ReferentStatus
		if strings.HasPrefix(s, RefProvisional) {
			s = RefProvisional
		}
		if rank[s] > best {
			best, status = rank[s], s
		}
	}
	return contradicted, status
}

// observationLite is the observation without the parts that resolve other artifacts.
func (r *Resolver) observationLite(p *Placed) *Observation {
	o := r.observationBase(p)
	if !o.BodyUnderstood {
		return o
	}
	st := p.St
	o.Finality = r.finality(st)
	r.referentStatus(o, st)
	if o.Class == "method" {
		r.comparability(o, st)
	}
	o.Corroboration = r.corroborate(o, st, false)
	return o
}

// --- reputation (claims §5.4) --------------------------------------------------------------------------------

// ReputationRule is a projection rule the reader chooses: a window over capture times and which evidence counts
// toward the record. The tool ships none (§5.4, C-core-56).
type ReputationRule struct {
	Name     string
	From, To string // a half-open window [From, To) over capture.at, UTC time values
	// Admit picks the evidence the reader counts toward the record (for example, corroborations that declare no
	// shared source with the observer). Describe says, in words, what it admits.
	Admit    func(Evidence) bool
	Describe string
}

// Reputation is one reputation projection: its rule, window and denominator are always part of it.
type Reputation struct {
	Observer, Rule, Admits, Window string
	// Denominator is the number of the observer's counted observations whose capture falls in the window.
	Denominator                           int
	Corroborated, Contradicted, Unchecked int
	Unit                                  string
}

// Reputation computes observer's record under rule. The observer is one signing key; whether a record should
// span the keys of one participant is the identity decision still open.
func (r *Resolver) Reputation(observer string, rule ReputationRule) (*Reputation, error) {
	from, err := rctime.ParseUTC(rule.From)
	if err != nil {
		return nil, err
	}
	to, err := rctime.ParseUTC(rule.To)
	if err != nil {
		return nil, err
	}
	rep := &Reputation{Observer: observer, Rule: rule.Name, Admits: rule.Describe, Window: "[" + rule.From + ", " + rule.To + ")",
		Unit: "one signing key per observer (counting unit pending identity decision)"}
	for _, p := range r.byKind["observed"] {
		if p.St.Signer != observer || !p.Counts() {
			continue
		}
		at, err := rctime.ParseUTC(str(object(p.St.Body, "capture"), "at"))
		if err != nil || rctime.Compare(at, from) < 0 || rctime.Compare(at, to) >= 0 {
			continue
		}
		rep.Denominator++
		o := r.observationLite(p)
		sup, con := false, false
		for _, e := range o.Corroboration.Evidence {
			if !e.Counted || e.Key == observer || (rule.Admit != nil && !rule.Admit(e)) {
				continue
			}
			sup = sup || e.Verdict == "supports"
			con = con || e.Verdict == "contradicts"
		}
		if sup {
			rep.Corroborated++
		}
		if con {
			rep.Contradicted++
		}
		if !sup && !con {
			rep.Unchecked++
		}
	}
	return rep, nil
}

// String renders the projection with its rule, window and denominator.
func (p *Reputation) String() string {
	return fmt.Sprintf("record of %s under rule %q (admits: %s), window %s: of %d observation(s), %d corroborated, %d contradicted, %d unchecked; %s",
		shortKey(p.Observer), p.Rule, p.Admits, p.Window, p.Denominator, p.Corroborated, p.Contradicted, p.Unchecked, p.Unit)
}
