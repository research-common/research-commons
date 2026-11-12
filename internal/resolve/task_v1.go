package resolve

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
)

// task-contract-v1 readiness (task-contracts note §4–§5). Under an edition whose terms are task-contract-v1:
//
//   - a submission is a `submit` naming the edition, or an `authored` / `observed` whose `fulfills` names it
//     (§5.1); the latter's result is its own content digest, and an amended `authored` is read from its current
//     claim;
//   - each submission is counted, undecided or not counted under the seven conditions of §5.1, every reason
//     named; it stays admissible whatever the outcome (TC3);
//   - a unit counts by its current submission only: the one no later submission of the same key to the same
//     edition follows in the key's log order; disagreeing branches of an uncleared fork count in none (§6 Q1);
//   - readiness is the bracket of §5.6: the lower evaluation counts counted submissions only, the upper one
//     takes every undecided condition (and every comparison that did not run) as passing.
//
// The deadline (§4.3) reads the bounds the reader's TimeVerifier derives, never `ts` or `capture.at`. Result kind,
// min_grade and pins (§6 Q2, Q3) read the held record for the result's digest, never the submission's kind.

// DeadlineNotShown is the deadline outcome for a submission no bound shows at or below the deadline height once
// the tip is past it and nothing can still resolve (§4.3). It is not "missed": a later bound does not show
// lateness.
const DeadlineNotShown Outcome = "not shown"

// Submission states under task-contract-v1 (§5.1).
const (
	SubCounted    = "counted"
	SubUndecided  = "undecided"
	SubNotCounted = "not counted"
)

// V1Conditions are one submission's task-contract-v1 conditions (§5.1 (5)–(7)) and the outcome.
type V1Conditions struct {
	// Deadline is "" with no deadline; else ok, unchecked or not shown. DeadlineWhy explains it (bounds read,
	// a commitment's bound, an amendment that broke the run).
	Deadline    Outcome
	DeadlineWhy []string
	// Results, MinGrade, Pins: "" when the contract declares no such term.
	Results, MinGrade, Pins          Outcome
	ResultsWhy, MinGradeWhy, PinsWhy string
	// Current: the unit's current submission of the edition (§6 Q1); CurrentWhy says why not.
	Current    bool
	CurrentWhy string
	// State is counted, undecided or not counted; Reasons name every condition that is not ok.
	State   string
	Reasons []string
	// Retracted lists `retracts` of the submitting statement: shown beside it, the count unchanged (§5.1).
	Retracted []string
	// IndepUndecided: counted but for independence the contract requires and the reader did not establish.
	IndepUndecided bool
}

// BoundRefutation is a `refutes` bound to an edition of the task by its own `task`/`edition` (§4.2): a
// submission on the refutation track, credited as a refutation, in no quorum group. Anyone may sign one.
type BoundRefutation struct {
	Statement, Signer, Of, Evidence, Edition string
	Counts                                   bool
	Why                                      string
}

func (b *BoundRefutation) line() string {
	s := fmt.Sprintf("bound refutation %s by %s on %s: refutes %s, evidence %s; the refutation track (credited as a refutation, in no quorum group)",
		keylog.Short(b.Statement), shortKey(b.Signer), keylog.Short(b.Edition), keylog.Short(b.Of), shortDigest(b.Evidence))
	if !b.Counts {
		s += "; counts toward nothing: " + b.Why
	} else if b.Why != "" {
		s += " (" + b.Why + ")"
	}
	return s
}

func (r *Resolver) boundRefutation(p *Placed, bind func(string) Binding) *BoundRefutation {
	b := p.St.Body
	g := r.gate(p) // bare-key: Counts; identity-context: actor eligibility (a `refutes` grant over its target)
	x := &BoundRefutation{Statement: p.St.ID, Signer: p.St.Signer, Of: str(b, "of"), Evidence: str(b, "evidence"), Edition: str(b, "edition"), Counts: g.Counts}
	if !x.Counts {
		x.Why = g.Why
		return x
	}
	if bd := bind(x.Edition); bd.State != string(Authorized) {
		x.Why = "binds to an edition that is " + bd.State
	}
	return x
}

// boundRefutation finds a counted refutation bound to edition ed by statement id.
func (t *Task) boundRefutation(id, ed string) *BoundRefutation {
	for _, b := range t.Bound {
		if b.Statement == id && b.Edition == ed && b.Counts {
			return b
		}
	}
	return nil
}

func (b Binding) v1() bool { return b.ok() && b.Terms.Profile == TaskContractV1Profile }

// fulfillsSubmissions adds every `authored` and `observed` whose `fulfills` names an edition of this task as a
// submission (§5.1), unless the edition's terms are the provisional reading's (there `fulfills` is a disclosure
// only). An `authored` an amendment of its signer replaced is no submission: its current claim is read.
func (r *Resolver) fulfillsSubmissions(t *Task, bind func(string) Binding) {
	for _, kind := range []string{"authored", "observed"} {
		for _, p := range r.byKind[kind] {
			if !p.EvidenceReady() {
				continue
			}
			f := object(p.St.Body, "fulfills")
			if f == nil || str(f, "resource") != t.ID {
				continue
			}
			ed := str(f, "edition")
			bd := bind(ed)
			if bd.State == "not held" || bd.State == "genesis" || (bd.Terms != nil && bd.Terms.Provisional) {
				continue // a submission of nothing; the disclosure says so (prereg.go)
			}
			if kind == "authored" && r.amendedBy(p) != "" {
				continue // not the current claim: the amendment withdrew or moved the submission
			}
			g := r.gate(p)
			s := &Submission{Statement: p.St.ID, Signer: p.St.Signer, Result: contentDigest(p.St.Body), Edition: ed, Counts: g.Counts,
				Identity: g.Identity, Why: g.Why, Kind: kind, Subject: actorSubject(p, g)}
			r.admitSubmission(t, s, p, bd)
			t.Submissions = append(t.Submissions, s)
		}
	}
	slices.SortFunc(t.Submissions, func(a, b *Submission) int { return strings.Compare(a.Signer+a.Statement, b.Signer+b.Statement) })
}

// amendedBy names a counted `authored` of the same key on the same blob that comes later in the key's log ("" for
// none): p is then not a current claim (claims-model note §4).
func (r *Resolver) amendedBy(p *Placed) string {
	d := contentDigest(p.St.Body)
	best := ""
	for _, q := range r.byKind["authored"] {
		if q.St.Signer == p.St.Signer && r.countsAsKey(q) && contentDigest(q.St.Body) == d && r.precedes(p.St.Signer, p.St.ID, q.St.ID) && (best == "" || q.St.ID < best) {
			best = q.St.ID
		}
	}
	return best
}

// v1Conditions evaluates §5.1 (5)–(7) for every submission bound to a task-contract-v1 edition and classifies it.
func (r *Resolver) v1Conditions(t *Task, bind func(string) Binding) {
	tip, hasTip := r.tip()
	for _, s := range t.Submissions {
		bd := bind(s.Edition)
		if !bd.v1() {
			continue
		}
		tm := bd.Terms
		c := &V1Conditions{}
		s.V1 = c
		p := r.byID[s.Statement]
		if tm.HasDeadline {
			c.Deadline, c.DeadlineWhy = r.deadline(s, p, tm.DeadlineHeight, tip, hasTip)
		}
		recs := r.resultRecords(s, p)
		if tm.Results != "" {
			c.Results, c.ResultsWhy = resultKind(tm.Results, recs)
		}
		if tm.Quorum != nil && tm.Quorum.MinGrade != "" {
			if c.Results == RuleOK {
				c.MinGrade, c.MinGradeWhy = r.minGrade(tm.Quorum.MinGrade, s.Result, recs)
			} else {
				// min_grade grades derived results only: until the result is one, there is nothing to grade
				c.MinGrade, c.MinGradeWhy = RuleUnchecked, "graded only once the result is shown to be a derived result"
			}
		}
		if tm.Pins != nil {
			c.Pins, c.PinsWhy = pinsCheck(tm.Pins, recs)
		}
		for _, q := range r.byKind["retracts"] {
			if r.gate(q).Counts && str(q.St.Body, "of") == s.Statement {
				c.Retracted = append(c.Retracted, q.St.ID)
			}
		}
		slices.Sort(c.Retracted)
	}
	// (7) the current submission per unit, in the key's own log order (§6 Q1); never ts, never delivery order
	for _, s := range t.Submissions {
		if s.V1 == nil {
			continue
		}
		var currents []*Submission
		later := ""
		for _, o := range t.Submissions {
			if !r.sameSeries(o, s, bind) || !o.Counts || o == s {
				continue
			}
			if r.precedes(s.Signer, s.Statement, o.Statement) && (later == "" || o.Statement < later) {
				later = o.Statement
			}
		}
		if later != "" {
			s.V1.CurrentWhy = "superseded by " + keylog.Short(later) + ", a later submission of the same key to this edition in its log"
			continue
		}
		for _, o := range t.Submissions {
			if r.sameSeries(o, s, bind) && o.Counts && !r.hasLater(o, t, bind) {
				currents = append(currents, o)
			}
		}
		results := map[string]bool{}
		for _, o := range currents {
			results[o.Result] = true
		}
		if len(results) > 1 {
			var rs []string
			for _, x := range sortedKeys(results) {
				rs = append(rs, shortDigest(x))
			}
			s.V1.CurrentWhy = "branches of an uncleared fork of " + shortKey(s.Signer) + "'s log disagree (results " + strings.Join(rs, ", ") + "): counts in none"
			continue
		}
		s.V1.Current = true
	}
	// Under identity counting the unit is the identity, and its keys' logs have no common order (profile §5.3: no
	// implicit cross-key ordering). Each key's current submission is read as above; when the current submissions
	// of one identity's keys disagree, the identity counts in none, as an uncleared fork's branches do (§6 Q1).
	split := map[string]string{} // edition+identity -> the disagreeing results, for identities whose keys disagree
	for _, s := range t.Submissions {
		if s.V1 == nil || !s.V1.Current || s.Identity == "" || !r.identityCounting(bind(s.Edition).Terms) {
			continue
		}
		u := s.Edition + "/" + s.Identity
		if _, done := split[u]; done {
			continue
		}
		results := map[string]bool{}
		for _, o := range t.Submissions {
			if o.V1 != nil && o.V1.Current && o.Identity == s.Identity && o.Edition == s.Edition {
				results[o.Result] = true
			}
		}
		split[u] = ""
		if len(results) > 1 {
			var rs []string
			for _, x := range sortedKeys(results) {
				rs = append(rs, shortDigest(x))
			}
			split[u] = strings.Join(rs, ", ")
		}
	}
	for _, s := range t.Submissions {
		if s.V1 != nil && s.V1.Current && s.Identity != "" && split[s.Edition+"/"+s.Identity] != "" {
			s.V1.Current = false
			s.V1.CurrentWhy = "the current submissions of identity " + keylog.Short(s.Identity) + "'s keys disagree (results " +
				split[s.Edition+"/"+s.Identity] + ") and no cross-key order picks one: counts in none"
		}
	}
	for _, s := range t.Submissions {
		if s.V1 != nil {
			tm := bind(s.Edition).Terms
			classify(s, tm, t, r.identityCounting(tm))
		}
	}
}

func (r *Resolver) hasLater(s *Submission, t *Task, bind func(string) Binding) bool {
	for _, o := range t.Submissions {
		if o != s && r.sameSeries(o, s, bind) && o.Counts && r.precedes(s.Signer, s.Statement, o.Statement) {
			return true
		}
	}
	return false
}

// sameSeries reports whether o and s are in one key's series of submissions to one edition, whose last in the
// key's log is current (§6 Q1). Under key counting the unit is the key, so a key's raw submission and one it signs
// for an identity are one series (identity profile §5.3: they count once, and a hedge across them closes as any
// other). Under identity counting through an evaluator a key's series is per subject: a later bare submission,
// which is no identity vote, does not withdraw the key's vote for the identity.
func (r *Resolver) sameSeries(o, s *Submission, bind func(string) Binding) bool {
	if o.Signer != s.Signer || o.Edition != s.Edition {
		return false
	}
	return o.Subject == s.Subject || !r.identityCounting(bind(s.Edition).Terms)
}

// classify sets the submission's state from §5.1's seven conditions: any fail or not shown → not counted; else
// any unchecked → undecided; else counted. Independence is not a condition here: the bracket reads it (§5.6).
func classify(s *Submission, tm *Terms, t *Task, byIdentity bool) {
	c := s.V1
	var fail, unchecked []string
	if !s.Counts {
		fail = append(fail, "counts toward nothing: "+s.Why)
	}
	if byIdentity && s.Counts && s.Identity == "" {
		// identity profile §5.3: bare submissions do not turn into identity votes
		fail = append(fail, "a bare-key submission is not an identity vote (counting unit identity)")
	}
	if !s.Eligible {
		fail = append(fail, "not an eligible issuer")
	}
	if tm.Coordinator != "" && s.Granted == "" {
		why := "no grant from " + shortKey(tm.Coordinator) + " for this edition"
		if !s.Subject.IsKey() && s.Subject.ID != "" {
			why += " (a coordinator grant names a key; an identity grantee waits for task-contracts note §6 Q9)"
		}
		for _, g := range t.Grants {
			if g.Grantee == s.Signer && g.Edition != s.Edition {
				why += " (grant " + keylog.Short(g.Statement) + " names edition " + keylog.Short(g.Edition) + "; a grant does not carry)"
				break
			}
		}
		fail = append(fail, why)
	}
	for _, e := range s.Rubric {
		switch e.Outcome {
		case RuleFail:
			fail = append(fail, "rubric "+e.Criterion+" fail: "+e.Why)
		case RuleUnchecked:
			unchecked = append(unchecked, "rubric "+e.Criterion+" unchecked: "+e.Why)
		}
	}
	add := func(name string, o Outcome, why string) {
		switch o {
		case RuleFail, DeadlineNotShown:
			fail = append(fail, name+" "+string(o)+": "+why)
		case RuleUnchecked:
			unchecked = append(unchecked, name+" unchecked: "+why)
		}
	}
	add("deadline", c.Deadline, strings.Join(c.DeadlineWhy, "; "))
	add("results", c.Results, c.ResultsWhy)
	add("min_grade", c.MinGrade, c.MinGradeWhy)
	add("pins", c.Pins, c.PinsWhy)
	if !c.Current && s.Counts {
		fail = append(fail, "not its unit's current submission: "+c.CurrentWhy)
	}
	switch {
	case len(fail) > 0:
		c.State, c.Reasons = SubNotCounted, append(fail, unchecked...)
	case len(unchecked) > 0:
		c.State, c.Reasons = SubUndecided, unchecked
	default:
		c.State = SubCounted
	}
}

// deadlineStatements are the statements whose bounds may meet the deadline for s (§4.3, §5.1, §6 Q4): a `submit`
// itself and the submitter's withheld-availability `authored` commitment of the same digest; an `observed` itself;
// an `authored` the unbroken run of its amendment chain that names this edition, ending at the current claim.
// broke names the amendment that broke the run and earlier the statements before it ("" / nil when unbroken).
func (r *Resolver) deadlineStatements(s *Submission, p *Placed) (sts []*Placed, commitments []string, broke string, earlier []*Placed) {
	switch s.Kind {
	case "submit":
		sts = append(sts, p)
		for _, q := range r.byKind["authored"] {
			if q.St.Signer == s.Signer && r.countsAsKey(q) && contentDigest(q.St.Body) == s.Result &&
				str(object(q.St.Body, "availability"), "redistribution") == "withheld" {
				sts = append(sts, q)
				commitments = append(commitments, q.St.ID)
			}
		}
	case "observed":
		sts = append(sts, p)
	case "authored":
		var chain []*Placed
		for _, q := range r.byKind["authored"] {
			if q.St.Signer == s.Signer && r.countsAsKey(q) && contentDigest(q.St.Body) == s.Result && (q == p || r.precedes(s.Signer, q.St.ID, p.St.ID)) {
				chain = append(chain, q)
			}
		}
		slices.SortFunc(chain, func(a, b *Placed) int { return -cmpSeq(a.St, b.St) })
		for i, q := range chain {
			f := object(q.St.Body, "fulfills")
			if f == nil || str(f, "resource") != str(object(p.St.Body, "fulfills"), "resource") || str(f, "edition") != s.Edition {
				broke, earlier = q.St.ID, chain[i:]
				break
			}
			sts = append(sts, q)
		}
	}
	return
}

// resolvable are the bitcoin-time states that can still turn into a verified bound (§4.3).
var resolvable = []string{"pending", "insufficient-confirmations", "missing-proof", "unknown-height", "backend-unconfigured", "backend-unavailable", "stale-chain"}

func meets(b Bound, h int64) bool {
	return (b.verified() || (b.State == "verified-historical" && b.Network != "")) && b.Height <= h
}

// deadline computes one submission's deadline outcome (§4.3).
func (r *Resolver) deadline(s *Submission, p *Placed, h, tip int64, hasTip bool) (Outcome, []string) {
	sts, commitments, broke, earlier := r.deadlineStatements(s, p)
	var why []string
	canResolve := false
	for _, q := range sts {
		for _, b := range r.bounds(q.St) {
			who := "its bound"
			if slices.Contains(commitments, q.St.ID) {
				who = "commitment " + keylog.Short(q.St.ID) + "'s bound"
			} else if q != p {
				who = "run statement " + keylog.Short(q.St.ID) + "'s bound"
			}
			if meets(b, h) {
				out := []string{fmt.Sprintf("%s: %s, at or below deadline height %d", who, b, h)}
				if slices.Contains(commitments, q.St.ID) {
					out = append(out, "the commitment shows possession by T only, never independence")
				}
				for _, o := range why {
					out = append(out, "also held: "+o)
				}
				return RuleOK, out
			}
			switch {
			case b.verified() || b.State == "verified-historical" && b.Network != "":
				why = append(why, fmt.Sprintf("%s: %s, above deadline height %d (a later bound does not show lateness)", who, b, h))
			case slices.Contains(resolvable, b.State):
				canResolve = true
				why = append(why, fmt.Sprintf("%s: %s, can still resolve", who, b))
			default:
				why = append(why, fmt.Sprintf("%s: %s", who, b))
			}
		}
	}
	if len(why) == 0 {
		why = append(why, "no anchor covers it")
	}
	if broke != "" {
		for _, q := range earlier {
			for _, b := range r.bounds(q.St) {
				if meets(b, h) {
					why = append(why, fmt.Sprintf("amendment %s broke the run naming this edition; %s's bound at height %d is not inherited", keylog.Short(broke), keylog.Short(q.St.ID), b.Height))
					break
				}
			}
		}
	}
	switch {
	case !hasTip:
		return RuleUnchecked, append(why, "this reader reads no validated chain tip, so the deadline cannot have passed for it")
	case tip < h:
		return RuleUnchecked, append(why, fmt.Sprintf("the validated tip %d is below deadline height %d", tip, h))
	case canResolve:
		return RuleUnchecked, why
	}
	return DeadlineNotShown, append(why, "not shown to exist by the deadline (ts and capture.at meet nothing; a later or local bound does not show lateness)")
}

// resultRecords are the held records for a submission's result: a statement carrying `fulfills` is its own
// record; for a `submit`, every held `authored` and `observed` of the digest.
func (r *Resolver) resultRecords(s *Submission, p *Placed) []*Placed {
	if s.Kind != "submit" {
		return []*Placed{p}
	}
	var out []*Placed
	for _, k := range []string{"authored", "observed"} {
		for _, q := range r.byKind[k] {
			if q.EvidenceReady() && contentDigest(q.St.Body) == s.Result {
				out = append(out, q)
			}
		}
	}
	slices.SortFunc(out, func(a, b *Placed) int { return strings.Compare(a.St.ID, b.St.ID) })
	return out
}

func isDerived(p *Placed) bool {
	if p.St.Kind != "authored" {
		return false
	}
	_, a := p.St.Body.Get("provenance")
	_, b := p.St.Body.Get("provenance_partial")
	return a || b
}

func recordNames(recs []*Placed) string {
	var ns []string
	for _, q := range recs {
		ns = append(ns, q.St.Kind+" "+keylog.Short(q.St.ID)+" by "+shortKey(q.St.Signer))
	}
	return strings.Join(ns, ", ")
}

// resultKind reads a result's kind from its held records (§6 Q2).
func resultKind(want string, recs []*Placed) (Outcome, string) {
	var derived, observed bool
	for _, q := range recs {
		derived = derived || isDerived(q)
		observed = observed || q.St.Kind == "observed"
	}
	switch {
	case len(recs) == 0:
		return RuleUnchecked, "no statement for the result is held, so its kind is unknown"
	case derived && observed:
		return RuleUnchecked, "held records give it both kinds: " + recordNames(recs)
	case want == ResultsDerived && derived, want == ResultsObserved && observed:
		return RuleOK, ""
	case want == ResultsDerived:
		return RuleFail, "not a derived result (held: " + recordNames(recs) + ")"
	}
	return RuleFail, "not an observation (held: " + recordNames(recs) + ")"
}

// minGrade compares the reader's own grade of a derived result with the contract's min_grade (§6 Q2).
func (r *Resolver) minGrade(min, d string, recs []*Placed) (Outcome, string) {
	if !slices.ContainsFunc(recs, isDerived) {
		return RuleUnchecked, "no derived record held to grade"
	}
	g := r.Artifact(d).Grade
	want := Grade{Tier: min}.rank()
	switch {
	case g.Tier != "" && g.rank() >= want:
		return RuleOK, "graded " + g.String()
	case g.Tier != "":
		return RuleFail, "graded " + g.String() + ", below min_grade " + min
	case g.Why == UncheckedToken || g.Why == NotHeld || g.Why == "":
		return RuleUnchecked, "ungraded (" + g.String() + ")"
	}
	return RuleFail, "grade " + g.String() + " carries no tier: below min_grade " + min
}

// pinsCheck checks the contract's exact pins against each held record (§6 Q3): ok when no record fails and one
// passes; fail when every record fails; unchecked otherwise, or with no record held.
func pinsCheck(pins *Pins, recs []*Placed) (Outcome, string) {
	if len(recs) == 0 {
		return RuleUnchecked, "no statement for the result is held, so its method and inputs are unknown"
	}
	var oks, fails, unc []string
	for _, q := range recs {
		o, why := pinRecord(pins, q)
		n := q.St.Kind + " " + keylog.Short(q.St.ID)
		switch o {
		case RuleOK:
			oks = append(oks, n)
		case RuleFail:
			fails = append(fails, n+": "+why)
		default:
			unc = append(unc, n+": "+why)
		}
	}
	switch {
	case len(fails) == 0 && len(unc) == 0:
		return RuleOK, ""
	case len(oks) == 0 && len(unc) == 0:
		return RuleFail, strings.Join(fails, "; ")
	}
	return RuleUnchecked, strings.Join(append(append(unc, fails...), oks...), "; ")
}

func includes(have, want []string) []string {
	var miss []string
	for _, x := range want {
		if !slices.Contains(have, x) {
			miss = append(miss, x)
		}
	}
	return miss
}

func pinRecord(pins *Pins, q *Placed) (Outcome, string) {
	b := q.St.Body
	switch {
	case isDerived(q):
		if pins.MethodEdition != "" && pins.Workflow == "" {
			return RuleFail, "a derived result: the contract pins a method edition, which no derived result shows"
		}
		pv, partial := object(b, "provenance"), false
		if pv == nil {
			pv, partial = object(b, "provenance_partial"), true
		}
		if pins.Workflow != "" && str(pv, "workflow") != pins.Workflow {
			return RuleFail, "workflow " + shortDigest(str(pv, "workflow")) + " is not the pinned " + shortDigest(pins.Workflow)
		}
		if miss := includes(ids(pv, "inputs"), pins.Inputs); len(miss) > 0 {
			if un, _ := strings_(pv, "unpinned"); partial && len(un) > 0 {
				return RuleUnchecked, "pinned input " + shortDigest(miss[0]) + " is not among its pinned inputs and may be one of its unpinned (" + strings.Join(un, ", ") + ")"
			}
			return RuleFail, "inputs lack the pinned " + shortDigest(miss[0])
		}
		return RuleOK, ""
	case q.St.Kind == "observed":
		if pins.Workflow != "" && pins.MethodEdition == "" {
			return RuleFail, "an observation: the contract pins a workflow, which no observation shows"
		}
		if str(b, "class") != "method" {
			return RuleFail, "an observation of class " + str(b, "class") + ", not method: it cannot show the pinned method or inputs"
		}
		ref := object(b, "referent")
		if pins.MethodEdition != "" {
			me, has := ref.Get("method_edition")
			switch {
			case !has:
				return RuleUnchecked, "referent.method_edition is unpinned (the observer's omission)"
			case string(me.(canon.String)) != pins.MethodEdition:
				return RuleFail, "method edition " + keylog.Short(string(me.(canon.String))) + " is not the pinned " + keylog.Short(pins.MethodEdition)
			}
		}
		if len(pins.Inputs) > 0 {
			if _, has := ref.Get("inputs"); !has {
				return RuleUnchecked, "referent.inputs is unpinned (the observer's omission)"
			}
			if miss := includes(ids(ref, "inputs"), pins.Inputs); len(miss) > 0 {
				return RuleFail, "referent inputs lack the pinned " + shortDigest(miss[0])
			}
		}
		return RuleOK, ""
	}
	return RuleFail, "an authored record with no provenance: it cannot show the pinned method or inputs"
}

// readinessV1 is §5.6's bracket over the edition's submissions.
func (r *Resolver) readinessV1(t *Task, b Binding) *Readiness {
	rd := &Readiness{Edition: b.Edition}
	tm := b.Terms
	var counted, undecided []*Submission
	for _, s := range t.Submissions {
		if s.Edition != b.Edition || s.V1 == nil {
			continue
		}
		switch s.V1.State {
		case SubCounted:
			counted = append(counted, s)
		case SubUndecided:
			undecided = append(undecided, s)
			rd.Reports = append(rd.Reports, fmt.Sprintf("submission %s undecided: %s", keylog.Short(s.Statement), strings.Join(s.V1.Reasons, "; ")))
		default:
			rd.Reports = append(rd.Reports, fmt.Sprintf("submission %s admissible, not counted: %s", keylog.Short(s.Statement), strings.Join(s.V1.Reasons, "; ")))
		}
	}
	for _, x := range t.Bound {
		if x.Edition == b.Edition {
			rd.Reports = append(rd.Reports, x.line())
		}
	}
	q := tm.Quorum
	if q == nil {
		// settled by review: per-submission outcomes inform the beneficiary and change no exit (§5.6)
		rd.Token = ByReview
		return rd
	}
	byIdentity := r.identityCounting(tm)
	if tm.CountingUnit == CountIdentity && !byIdentity {
		rd.Token = ReadyUnknown
		if r.actors != nil {
			// an evaluator is configured, but the rc/1 placement names its roles as keys: no identity can be
			// checked against them (identity profile §5.3)
			rd.Why = append(rd.Why, "counting unit identity: this edition names its roles in the contract (the rc/1 placement), as keys; typed identity roles are an rc/2 edition's task_roles, so no identity count exists (never a key count shown as one)")
			return rd
		}
		rd.Why = append(rd.Why, "counting unit identity: no identity profile is registered for task-contract-v1 in this reader, so no identity count exists (never a key count shown as one)")
		return rd
	}
	rd.K, rd.Unit = q.K, CountedAs
	if byIdentity {
		rd.Unit = CountedAsIdentities
	}
	count := func(g []*Submission, only func(*Submission) bool) int {
		keys := map[string]bool{}
		for _, s := range g {
			if only == nil || only(s) {
				// the unit: the key (after actor authority passed: the gate), or the eligible identity (§5.3)
				if byIdentity {
					keys["identity:"+s.Identity] = true
				} else {
					keys[s.Signer] = true
				}
			}
		}
		return len(keys)
	}
	established := func(s *Submission) bool {
		switch q.Independence {
		case IndependenceNotRequired:
			return true
		case IndependenceSelfDeclared:
			return s.Independent || s.SelfDeclared
		}
		return s.Independent
	}
	reach := func(groups [][]*Submission, only func(*Submission) bool) int {
		best := 0
		for _, g := range groups {
			best = max(best, count(g, only))
		}
		return best
	}
	lowG, notes, lowUnc := r.quorumGroupsAs(q, counted, r.exch.maxGroup, false)
	rd.Reports = append(rd.Reports, notes...)
	for _, g := range lowG {
		var ids []string
		for _, s := range g {
			ids = append(ids, s.Statement)
		}
		rd.Groups = append(rd.Groups, ids)
	}
	upper := append(slices.Clone(counted), undecided...)
	upG, _, upUnc := r.quorumGroupsAs(q, upper, r.exch.maxGroup, true)
	lower := reach(lowG, established)
	// upper without independence taken as passing, to tell `unknown` from `unchecked`
	upperIndep := reach(upG, func(s *Submission) bool { return s.V1.State == SubUndecided || established(s) })
	upperAll := reach(upG, nil)
	for _, s := range upper {
		if q.Independence != IndependenceNotRequired && !established(s) {
			w := s.IndepWhy
			if s.SelfDeclared && q.Independence == IndependenceRequired {
				w += "; self-declared independence is the submitter's word, which this contract does not accept"
			}
			if s.Kind != "submit" && q.Independence == IndependenceSelfDeclared {
				w += "; a statement carrying fulfills declares no independence"
			}
			rd.Why = append(rd.Why, fmt.Sprintf("independence of %s not established: %s", keylog.Short(s.Statement), w))
		}
	}
	switch {
	case lower >= q.K:
		rd.Token, rd.N = Ready, lower
		rd.SelfDeclared = q.Independence == IndependenceSelfDeclared && reach(lowG, func(s *Submission) bool { return s.Independent }) < q.K
	case upG == nil && upUnc != "":
		rd.Token = ReadyUnchecked
		rd.Why = append(rd.Why, upUnc)
	case upperAll < q.K:
		rd.Token, rd.N = NotReady, lower
	case upperIndep < q.K:
		rd.Token = ReadyUnknown
		rd.Why = append(rd.Why, "required independence not established: readiness unknown, not a smaller count")
	default:
		rd.Token = ReadyUnchecked
		if lowUnc != "" {
			rd.Why = append(rd.Why, lowUnc)
		}
		rd.Why = append(rd.Why, "the quorum is reached only if undecided submissions pass: unchecked")
	}
	if q.Grouping != GroupAny {
		reached := map[string]bool{}
		for _, g := range lowG {
			if count(g, nil) >= q.K {
				for _, s := range g {
					reached[s.Statement] = true
				}
			}
		}
		if len(reached) > 0 {
			for _, s := range counted {
				if !reached[s.Statement] {
					rd.Reports = append(rd.Reports, fmt.Sprintf("divergence report: submission %s by %s (result %s) is in no group that reached the quorum; kept beside the readiness token",
						keylog.Short(s.Statement), shortKey(s.Signer), shortDigest(s.Result)))
				}
			}
		}
	}
	return rd
}

// renderV1 is a submission's task-contract-v1 lines.
func (s *Submission) renderV1(b *strings.Builder) {
	c := s.V1
	if c.Deadline != "" {
		fmt.Fprintf(b, "    deadline %s: %s\n", c.Deadline, strings.Join(c.DeadlineWhy, "; "))
	}
	for _, x := range []struct {
		n   string
		o   Outcome
		why string
	}{{"results", c.Results, c.ResultsWhy}, {"min_grade", c.MinGrade, c.MinGradeWhy}, {"pins", c.Pins, c.PinsWhy}} {
		if x.o != "" {
			fmt.Fprintf(b, "    %s %s", x.n, x.o)
			if x.why != "" {
				fmt.Fprintf(b, " (%s)", x.why)
			}
			b.WriteString("\n")
		}
	}
	if !c.Current && c.CurrentWhy != "" {
		fmt.Fprintf(b, "    not current: %s\n", c.CurrentWhy)
	}
	for _, x := range c.Retracted {
		fmt.Fprintf(b, "    retracted by %s (shown beside it; the count is unchanged)\n", keylog.Short(x))
	}
	fmt.Fprintf(b, "    %s", c.State)
	if len(c.Reasons) > 0 {
		fmt.Fprintf(b, ": %s", strings.Join(c.Reasons, "; "))
	}
	b.WriteString("\n")
}

// FulfillsDropWarning is the `publish` guard of §5.1 (C-exch-15b): an `authored` by signer about to be signed on
// blob d replaces the signer's current claims on d (an amendment replaces, never patches). When a current claim
// carries `fulfills` and the new body drops it or names another edition, the submission is withdrawn or moved;
// the warning names the edition. "" when nothing changes. A warning, never a refusal.
func (r *Resolver) FulfillsDropWarning(signer, d string, body *canon.Object) string {
	nf := object(body, "fulfills")
	var lost []string
	for _, p := range r.byKind["authored"] {
		if p.St.Signer != signer || !r.countsAsKey(p) || contentDigest(p.St.Body) != d || r.amendedBy(p) != "" {
			continue
		}
		f := object(p.St.Body, "fulfills")
		if f == nil {
			continue
		}
		if nf == nil || str(nf, "resource") != str(f, "resource") || str(nf, "edition") != str(f, "edition") {
			lost = append(lost, keylog.Short(str(f, "edition"))+" (task "+keylog.Short(str(f, "resource"))+", carried by "+keylog.Short(p.St.ID)+")")
		}
	}
	if len(lost) == 0 {
		return ""
	}
	slices.Sort(lost)
	lost = slices.Compact(lost)
	how := "drops"
	if nf != nil {
		how = "changes"
	}
	return "this amendment " + how + " the fulfills of your current claim on these bytes, naming edition " + strings.Join(lost, ", ") +
		": your submission to it is withdrawn (an amendment replaces, never patches); re-adding fulfills later starts a new run, " +
		"and the deadline does not inherit the earlier bound. Carry fulfills forward to keep the submission. This warning is not recorded"
}
