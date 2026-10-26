package resolve

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// The research exchange: the task view (claims-model note §9; wire-format note §5 `intent`, `progress`,
// `withdraw`, `submit`, `decide`).
//
// A task is a resource of type `task` (§8); its editions carry the contract. Every lifecycle statement binds
// to one task edition by its edition id, and is read under that edition's terms and no other: a later edition
// never changes the terms of an earlier binding (§8, C-exch-07). A binding naming anything but an edition of
// the task is shown with the state of what it names and evaluated toward nothing.
//
// Lifecycle (§9.1). An intent is advisory: it is listed and excludes nobody. `progress` is evidence of activity,
// never a lease renewal: no state here expires, and no deadline is applied to an intent. A `withdraw` ends the
// signer's attempts on that edition that precede it in the signer's log; a later intent is a new attempt.
// Submissions are always admissible: every one is listed, whoever signed it and whatever else is held. Whether
// one counts toward readiness is a separate question (eligible issuer, its own key events, the coordinator's
// grants, the rubric, independence).
//
// Exclusion (§9.1). A task that names a coordinator counts only submissions whose signer holds a grant signed by
// that coordinator for that edition; a grant by anyone else is listed as its signer's statement with no effect.
// The wire format has no grant kind yet, so grants are read through the reader's GrantReader (default: none).
//
// Settlement (§9.2). A decision is the beneficiary's signed `decide` citing exact submissions and evaluations.
// One that cites no submission is shown `cites nothing` and settles nothing. Two decisions of the beneficiary
// that give one submission different verdicts are a visible conflict (`contested`, exit 3) until a later
// decision explicitly supersedes one by id; neither `ts` nor file order nor log order picks.
//
// Readiness (§9.3) is computed per task edition over the submissions bound to it: see readiness.

// GrantReader reads a coordinator grant out of a held statement. The wire format defines no grant kind, so no
// reading ships; a reader that has one plugs in here. ok is false for every statement that is not a grant.
type GrantReader interface {
	Grant(st *wire.Statement) (g Grant, ok bool)
}

// Grant is one signed grant: Signer grants Grantee exclusion on one task edition.
type Grant struct {
	Statement, Signer, Grantee, Task, Edition string
}

// NoGrantReader is the default: no statement is a grant.
type NoGrantReader struct{}

// Grant implements GrantReader.
func (NoGrantReader) Grant(*wire.Statement) (Grant, bool) { return Grant{}, false }

// RubricEvaluator evaluates one rubric criterion against one submission (§9.2 checks; §13: ok, fail, unchecked).
type RubricEvaluator interface {
	Evaluate(c Criterion, submission *wire.Statement) (Outcome, string)
}

// NoRubricEvaluator is the default: every criterion is unchecked.
type NoRubricEvaluator struct{}

// Evaluate implements RubricEvaluator.
func (NoRubricEvaluator) Evaluate(Criterion, *wire.Statement) (Outcome, string) {
	return RuleUnchecked, "no rubric evaluator configured"
}

// IndependenceVerifier establishes, from a bound proof it verifies itself, that a submission is independent
// (§9.3: "unless an implemented verifier checks a bound proof"). The default establishes nothing: first
// publication, a commit-reveal match, distinct keys and unverified labels never do.
type IndependenceVerifier interface {
	Independent(submission *wire.Statement, t *Terms) (established bool, why string)
}

// NoIndependenceVerifier is the default.
type NoIndependenceVerifier struct{}

// NoIndependenceWhy is why independence is not established with no verifier configured.
const NoIndependenceWhy = "no independence verifier configured: first publication, commit-reveal, distinct keys and labels establish nothing"

// Independent implements IndependenceVerifier.
func (NoIndependenceVerifier) Independent(*wire.Statement, *Terms) (bool, string) {
	return false, NoIndependenceWhy
}

type exchConfig struct {
	contracts ContractReader
	grants    GrantReader
	rubric    RubricEvaluator
	indep     IndependenceVerifier
	maxGroup  int
}

func defaultExchConfig() *exchConfig {
	return &exchConfig{contracts: NoContractReader{}, grants: NoGrantReader{}, rubric: NoRubricEvaluator{}, indep: NoIndependenceVerifier{}, maxGroup: DefaultGroupingLimit}
}

// DefaultGroupingLimit bounds the distinct results an all-pairs grouping searches (the search is exponential in
// them); past it readiness is `unchecked` naming the limit (I15).
const DefaultGroupingLimit = 16

// WithGrantReader sets the reader's grant reading.
func WithGrantReader(g GrantReader) Option { return func(r *Resolver) { r.exch.grants = g } }

// WithRubricEvaluator sets the reader's rubric evaluator.
func WithRubricEvaluator(e RubricEvaluator) Option { return func(r *Resolver) { r.exch.rubric = e } }

// WithIndependenceVerifier sets the reader's independence verifier.
func WithIndependenceVerifier(v IndependenceVerifier) Option {
	return func(r *Resolver) { r.exch.indep = v }
}

// Readiness tokens.
const (
	Ready          = "ready"
	NotReady       = "not ready"
	ReadyUnknown   = "unknown"
	ReadyUnchecked = "unchecked"
	// ByReview: the edition has no quorum predicate; it is settled by review, not by counting (§9.2).
	ByReview = "settled by review, not by counting"
)

// CountedAs is the counting label every count shows. Keys are not people: a count never says anything about
// independence (§9.3).
const CountedAs = "counted as: distinct signing keys"

// Binding is where a lifecycle statement binds.
type Binding struct {
	Edition string
	// State is the state of the edition named: an EditionState, "genesis", or "not held".
	State string
	// Terms are the edition's terms as the reader's contract reader read them; nil when unread (TermsWhy).
	Terms    *Terms
	TermsWhy string
}

func (b Binding) ok() bool { return b.State == string(Authorized) && b.Terms != nil }

// Attempt is one signer's intent on one edition and what followed it.
type Attempt struct {
	Signer, Intent, Edition string
	// Progress lists the signer's progress statements on the edition after the intent (activity evidence).
	Progress []string
	// Withdrawn names the withdraw that ended this attempt; "" when none.
	Withdrawn string
}

// Submission is one `submit` naming the task.
type Submission struct {
	Statement, Signer, Result, Edition string
	// Counts is the bare-key gate (key events, chained, understood); Why when not.
	Counts bool
	Why    string
	// Eligible: the edition's terms admit the signer as an issuer; Granted names the coordinator grant that
	// admits it under a coordinator ("" when the edition names none or the signer holds no counting grant).
	Eligible bool
	Granted  string
	// Rubric is one evaluation per criterion of the bound edition's rubric.
	Rubric []CriterionEval
	// Independence: established by the reader's verifier, self-declared (the submitter's word), or neither.
	Independent, SelfDeclared bool
	IndepWhy                  string
	// Salted is true when the submission carries a salt: a commit-reveal shows possession by T, not independence.
	Salted bool
	// Labels are body fields this reader does not interpret (receipt, tee, model family): the submitter's word.
	Labels []string
	// Departure is the departure check of the result's sampling against the bound edition's declared sampling.
	Departure, DepartureWhy string
	// Verdict is the beneficiary's settled verdict for this submission: accept, reject, contested, or "".
	Verdict string
	// Refuted lists `refutes` statements naming this submission: first-class refutations on their own track.
	Refuted []string
}

// CriterionEval is one rubric evaluation.
type CriterionEval struct {
	Criterion string
	Outcome   Outcome
	Why       string
}

// Decision is one `decide` naming the task.
type Decision struct {
	Statement, Signer, Verdict, Edition string
	Submissions, Evaluations            []string
	Supersedes                          string
	// Counts: the decision is the bound edition's beneficiary's, counts under its key events, and cites at least
	// one submission of this task. Why explains a decision that does not count.
	Counts bool
	Why    string
	// SupersededBy names the counted decision that superseded this one ("" when none).
	SupersededBy string
}

// Readiness is one edition's readiness.
type Readiness struct {
	Edition string
	Token   string
	// N is the count behind the token (distinct signing keys in the best group); K the quorum.
	N, K int
	// Check is the rubric check over the counted submissions: ok, fail or unchecked ("" with no rubric). An
	// unchecked criterion never lets the check pass (§13, I4).
	Check Outcome
	// SelfDeclared is true when the token rests on self-declared independence, which the contract accepted.
	SelfDeclared bool
	Groups       [][]string // each group's submissions by statement id
	Reports      []string   // divergence and every other report beside the token, kept after readiness
	Why          []string
}

// Task is the view of one task.
type Task struct {
	*Resource
	Bindings    map[string]Binding // by edition id named
	Attempts    []*Attempt
	Submissions []*Submission
	Decisions   []*Decision
	Grants      []Grant
	GrantNotes  []string
	Refutations []*Placed
	Readiness   []*Readiness
	// Contested lists the submissions whose effective decisions disagree.
	DecisionConflict []string
	Explain          []string
}

// Task resolves the task whose genesis statement is id.
func (r *Resolver) Task(id string) (*Task, bool) {
	res, ok := r.Resource(id)
	if !ok || res.Type != "task" {
		return nil, false
	}
	t := &Task{Resource: res, Bindings: map[string]Binding{}}
	bind := func(eid string) Binding {
		if b, ok := t.Bindings[eid]; ok {
			return b
		}
		b := Binding{Edition: eid, State: "not held"}
		switch {
		case eid == id:
			b.State, b.TermsWhy = "genesis", "the genesis carries no contract"
		default:
			for _, e := range res.Editions {
				if e.ID == eid {
					b.State = string(e.State)
				}
			}
			if b.State == "not held" {
				if e, ok := res.Edition(eid); ok {
					b.TermsWhy = "names the statement id of an approval of " + keylog.Short(e.ID) + ", not an edition id"
				} else {
					b.TermsWhy = "names no edition of this task held"
				}
			}
		}
		if b.State == string(Authorized) {
			e, _ := res.Edition(eid)
			c := object(object(e.Body, "contents"), "contract")
			if c == nil {
				b.TermsWhy = "the edition carries no contract"
			} else {
				b.Terms, b.TermsWhy, _ = r.exch.contracts.Read(c)
			}
		} else if b.TermsWhy == "" {
			b.TermsWhy = "the edition is " + b.State + ": a binding to it is evaluated toward nothing"
		}
		t.Bindings[eid] = b
		return b
	}
	mine := func(kind string) []*Placed {
		var out []*Placed
		for _, p := range r.byKind[kind] {
			if p.St.Verified && p.St.Status == wire.Valid && str(p.St.Body, "task") == id {
				out = append(out, p)
			}
		}
		slices.SortFunc(out, func(a, b *Placed) int { return strings.Compare(a.St.Signer+a.St.ID, b.St.Signer+b.St.ID) })
		return out
	}

	r.attempts(t, mine, bind)
	r.grants(t, bind)
	r.submissions(t, mine("submit"), bind)
	r.decisions(t, mine("decide"), bind)
	r.refutations(t)
	editions := map[string]bool{}
	for _, s := range t.Submissions {
		editions[s.Edition] = true
	}
	if res.Current != "" && res.Current != id {
		editions[res.Current] = true
	}
	for _, e := range sortedKeys(editions) {
		t.Readiness = append(t.Readiness, r.readiness(t, bind(e)))
	}
	return t, true
}

// attempts builds every signer's attempts from intent, progress and withdraw.
func (r *Resolver) attempts(t *Task, mine func(string) []*Placed, bind func(string) Binding) {
	withdraws := mine("withdraw")
	progress := mine("progress")
	for _, p := range mine("intent") {
		if !p.Counts() {
			t.Explain = append(t.Explain, fmt.Sprintf("intent %s by %s counts toward nothing: %s", keylog.Short(p.St.ID), shortKey(p.St.Signer), notCountedWhy(p)))
			continue
		}
		ed := str(p.St.Body, "edition")
		bind(ed)
		a := &Attempt{Signer: p.St.Signer, Intent: p.St.ID, Edition: ed}
		for _, w := range withdraws {
			if w.Counts() && w.St.Signer == a.Signer && str(w.St.Body, "edition") == ed && r.precedes(a.Signer, a.Intent, w.St.ID) {
				if a.Withdrawn == "" || r.precedes(a.Signer, w.St.ID, a.Withdrawn) {
					a.Withdrawn = w.St.ID
				}
			}
		}
		for _, g := range progress {
			if g.Counts() && g.St.Signer == a.Signer && str(g.St.Body, "edition") == ed && r.precedes(a.Signer, a.Intent, g.St.ID) {
				a.Progress = append(a.Progress, g.St.ID)
			}
		}
		t.Attempts = append(t.Attempts, a)
	}
}

// grants reads every held statement through the reader's GrantReader and keeps the grants naming this task.
func (r *Resolver) grants(t *Task, bind func(string) Binding) {
	for _, k := range sortedKeys(r.byKind) {
		for _, p := range r.byKind[k] {
			if !p.EvidenceReady() {
				continue
			}
			g, ok := r.exch.grants.Grant(p.St)
			if !ok || g.Task != t.ID {
				continue
			}
			g.Statement, g.Signer = p.St.ID, p.St.Signer
			b := bind(g.Edition)
			switch {
			case !p.Counts():
				t.GrantNotes = append(t.GrantNotes, fmt.Sprintf("grant %s by %s counts toward nothing: %s", keylog.Short(g.Statement), shortKey(g.Signer), notCountedWhy(p)))
			case !b.ok():
				t.GrantNotes = append(t.GrantNotes, fmt.Sprintf("grant %s by %s binds to %s (%s): no effect", keylog.Short(g.Statement), shortKey(g.Signer), keylog.Short(g.Edition), b.State))
			case b.Terms.Coordinator != g.Signer:
				t.GrantNotes = append(t.GrantNotes, fmt.Sprintf("grant %s to %s is %s's statement; %s is not the edition's coordinator: no effect",
					keylog.Short(g.Statement), shortKey(g.Grantee), shortKey(g.Signer), shortKey(g.Signer)))
			default:
				t.Grants = append(t.Grants, g)
			}
		}
	}
	slices.SortFunc(t.Grants, func(a, b Grant) int { return strings.Compare(a.Grantee+a.Statement, b.Grantee+b.Statement) })
	slices.Sort(t.GrantNotes)
}

// submissionFields are the `submit` body fields wire §5 defines; anything else is the submitter's opaque word.
var submissionFields = []string{"task", "edition", "result", "salt", "self_declared_independence"}

func (r *Resolver) submissions(t *Task, ps []*Placed, bind func(string) Binding) {
	for _, p := range ps {
		b := p.St.Body
		s := &Submission{Statement: p.St.ID, Signer: p.St.Signer, Result: str(b, "result"), Edition: str(b, "edition"), Counts: p.Counts()}
		if !s.Counts {
			s.Why = notCountedWhy(p)
		}
		_, s.Salted = b.Get("salt")
		if v, ok := b.Get("self_declared_independence"); ok {
			s.SelfDeclared = bool(v.(canon.Bool))
		}
		for _, k := range b.Keys {
			if !slices.Contains(submissionFields, k) {
				s.Labels = append(s.Labels, k+"="+string(canon.Encode(b.Members[k])))
			}
		}
		bd := bind(s.Edition)
		if bd.ok() {
			tm := bd.Terms
			s.Eligible = tm.AnyIssuer || slices.Contains(tm.EligibleIssuers, s.Signer)
			if tm.Coordinator != "" {
				for _, g := range t.Grants {
					if g.Grantee == s.Signer && g.Edition == s.Edition {
						s.Granted = g.Statement
						break
					}
				}
			}
			for _, c := range tm.Rubric {
				out, why := r.exch.rubric.Evaluate(c, p.St)
				s.Rubric = append(s.Rubric, CriterionEval{c.ID, out, why})
			}
			if tm.Quorum != nil {
				s.Independent, s.IndepWhy = r.exch.indep.Independent(p.St, tm)
			}
			if tm.Sampling != nil {
				s.Departure, s.DepartureWhy = DepartureCheck(tm.Sampling, r.deliveredSampling(s.Result))
			}
		}
		t.Submissions = append(t.Submissions, s)
	}
}

// deliveredSampling is the result's sampling disclosure as its default author declared it; nil when it has none
// (or no default exists, so no single declaration speaks for it).
func (r *Resolver) deliveredSampling(d string) *canon.Object {
	f := r.authorship(d).Field("sampling")
	if f.State != FieldDefault {
		return nil
	}
	st, ok := r.byID[f.From[0].Statement]
	if !ok {
		return nil
	}
	return object(st.St.Body, "sampling")
}

func (r *Resolver) decisions(t *Task, ps []*Placed, bind func(string) Binding) {
	subs := map[string]*Submission{}
	for _, s := range t.Submissions {
		subs[s.Statement] = s
	}
	byID := map[string]*Decision{}
	for _, p := range ps {
		b := p.St.Body
		d := &Decision{Statement: p.St.ID, Signer: p.St.Signer, Verdict: str(b, "verdict"), Edition: str(b, "edition"),
			Submissions: ids(b, "submissions"), Evaluations: ids(b, "evaluations"), Supersedes: str(b, "supersedes"), Counts: true}
		bd := bind(d.Edition)
		var cited int
		for _, s := range d.Submissions {
			if subs[s] != nil {
				cited++
			}
		}
		switch {
		case !p.Counts():
			d.Counts, d.Why = false, notCountedWhy(p)
		case !bd.ok():
			d.Counts, d.Why = false, "bound edition "+keylog.Short(d.Edition)+" has no terms this reader read: "+bd.TermsWhy
		case bd.Terms.Beneficiary != d.Signer:
			d.Counts, d.Why = false, "signed by "+shortKey(d.Signer)+", not the edition's beneficiary "+shortKey(bd.Terms.Beneficiary)+": shown, settles nothing"
		case len(d.Submissions) == 0:
			d.Counts, d.Why = false, "cites nothing"
		case cited == 0:
			d.Counts, d.Why = false, "cites no submission of this task held"
		}
		byID[d.Statement] = d
		t.Decisions = append(t.Decisions, d)
	}
	// Explicit supersession only: a counted decision supersedes the decision it names when that one is the same
	// signer's decision on this task. Anything else it names is shown and superseded by nothing.
	for _, d := range t.Decisions {
		if !d.Counts || d.Supersedes == "" {
			continue
		}
		x, ok := byID[d.Supersedes]
		switch {
		case !ok:
			t.Explain = append(t.Explain, fmt.Sprintf("decision %s supersedes %s, which is no decision on this task held", keylog.Short(d.Statement), keylog.Short(d.Supersedes)))
		case x.Signer != d.Signer:
			t.Explain = append(t.Explain, fmt.Sprintf("decision %s names %s, signed by another key: no effect", keylog.Short(d.Statement), keylog.Short(x.Statement)))
		case x.SupersededBy == "" || d.Statement < x.SupersededBy:
			x.SupersededBy = d.Statement
		}
	}
	verdicts := map[string]map[string][]string{} // submission -> verdict -> deciding statements
	for _, d := range t.Decisions {
		if !d.Counts || d.SupersededBy != "" {
			continue
		}
		for _, s := range d.Submissions {
			if subs[s] == nil {
				continue
			}
			if verdicts[s] == nil {
				verdicts[s] = map[string][]string{}
			}
			verdicts[s][d.Verdict] = append(verdicts[s][d.Verdict], d.Statement)
		}
	}
	for _, s := range sortedKeys(verdicts) {
		v := verdicts[s]
		if len(v) > 1 {
			subs[s].Verdict = "contested"
			t.DecisionConflict = append(t.DecisionConflict, s)
			t.Explain = append(t.Explain, fmt.Sprintf("decision conflict on %s: accept by %s, reject by %s; neither ts nor order picks, a later decision must supersede one",
				keylog.Short(s), shorts(v["accept"]), shorts(v["reject"])))
			continue
		}
		for verdict := range v {
			subs[s].Verdict = verdict
		}
	}
}

// refutations lists every counted `refutes` naming a submission of this task: first-class, on their own track.
func (r *Resolver) refutations(t *Task) {
	subs := map[string]*Submission{}
	for _, s := range t.Submissions {
		subs[s.Statement] = s
	}
	// a refutation names the submission, or a counted `authored` claim of a submitted result
	claimOf := map[string]*Submission{}
	for _, s := range t.Submissions {
		for _, p := range r.byKind["authored"] {
			if p.Counts() && contentDigest(p.St.Body) == s.Result {
				claimOf[p.St.ID] = s
			}
		}
	}
	for _, p := range r.byKind["refutes"] {
		if !p.EvidenceReady() {
			continue
		}
		s := subs[str(p.St.Body, "of")]
		if s == nil {
			s = claimOf[str(p.St.Body, "of")]
		}
		if s != nil {
			t.Refutations = append(t.Refutations, p)
			if p.Counts() {
				s.Refuted = append(s.Refuted, p.St.ID)
			}
		}
	}
	slices.SortFunc(t.Refutations, func(a, b *Placed) int { return strings.Compare(a.St.ID, b.St.ID) })
}

// readiness computes one edition's readiness over the submissions bound to it (§9.3).
func (r *Resolver) readiness(t *Task, b Binding) *Readiness {
	rd := &Readiness{Edition: b.Edition}
	if !b.ok() {
		rd.Token = ReadyUnchecked
		rd.Why = append(rd.Why, "terms not read: "+b.TermsWhy)
		return rd
	}
	tm := b.Terms
	if tm.CountingUnit == CountIdentity {
		rd.Token = ReadyUnknown
		rd.Why = append(rd.Why, "counting unit identity: no identity profile is active in this reader, so no identity count exists")
		return rd
	}
	var pool []*Submission
	uncheckedRubric, evaluated := false, false
	for _, s := range t.Submissions {
		if s.Edition != b.Edition {
			continue
		}
		switch {
		case !s.Counts:
			rd.Reports = append(rd.Reports, fmt.Sprintf("submission %s admissible, not counted: %s", keylog.Short(s.Statement), s.Why))
		case !s.Eligible:
			rd.Reports = append(rd.Reports, fmt.Sprintf("submission %s admissible, not counted: %s is not an eligible issuer", keylog.Short(s.Statement), shortKey(s.Signer)))
		case tm.Coordinator != "" && s.Granted == "":
			rd.Reports = append(rd.Reports, fmt.Sprintf("submission %s admissible, not counted: %s holds no grant signed by coordinator %s", keylog.Short(s.Statement), shortKey(s.Signer), shortKey(tm.Coordinator)))
		default:
			ok := true
			evaluated = true
			for _, c := range s.Rubric {
				switch c.Outcome {
				case RuleFail:
					ok = false
					rd.Reports = append(rd.Reports, fmt.Sprintf("submission %s: rubric criterion %s fail: %s", keylog.Short(s.Statement), c.Criterion, c.Why))
				case RuleUnchecked:
					ok = false
					uncheckedRubric = true
					rd.Reports = append(rd.Reports, fmt.Sprintf("submission %s: rubric criterion %s unchecked: %s", keylog.Short(s.Statement), c.Criterion, c.Why))
				}
			}
			if ok {
				pool = append(pool, s)
			}
		}
	}
	if len(tm.Rubric) > 0 {
		// ok: some counted submission passes every criterion and none is unchecked; unchecked: a criterion could
		// not be evaluated, or no counted submission was evaluated; fail otherwise.
		switch {
		case uncheckedRubric || !evaluated:
			rd.Check = RuleUnchecked
		case len(pool) == 0:
			rd.Check = RuleFail
		default:
			rd.Check = RuleOK
		}
	}
	q := tm.Quorum
	if q == nil {
		rd.Token = ByReview
		if uncheckedRubric {
			rd.Why = append(rd.Why, "a rubric criterion is unchecked: the check does not pass")
		}
		return rd
	}
	rd.K = q.K
	groups, notes, unchecked := r.quorumGroups(q, pool, r.exch.maxGroup)
	rd.Reports = append(rd.Reports, notes...)
	var counter Counter = KeyCounter{}
	count := func(g []*Submission, only func(*Submission) bool) int {
		var ev []Evidence
		for _, s := range g {
			if only == nil || only(s) {
				ev = append(ev, Evidence{Key: s.Signer, Statement: s.Statement, Via: "submit"})
			}
		}
		n, _, _ := counter.Count("", ev)
		return n
	}
	best, bestEst, needIndep := 0, 0, false
	selfUsed := false
	for _, g := range groups {
		var ids []string
		for _, s := range g {
			ids = append(ids, s.Statement)
		}
		rd.Groups = append(rd.Groups, ids)
		n := count(g, nil)
		best = max(best, n)
		if q.Independence == IndependenceNotRequired {
			continue
		}
		est := count(g, func(s *Submission) bool {
			return s.Independent || (q.Independence == IndependenceSelfDeclared && s.SelfDeclared)
		})
		if n >= q.K {
			needIndep = true
			if est > bestEst {
				bestEst = est
				selfUsed = count(g, func(s *Submission) bool { return s.Independent }) < q.K
			}
		}
	}
	rd.N = best
	for _, s := range pool {
		if q.Independence != IndependenceNotRequired && !s.Independent {
			w := s.IndepWhy
			if s.SelfDeclared {
				if q.Independence == IndependenceSelfDeclared {
					w = "self-declared (the contract accepts self-declared independence)"
				} else {
					w += "; self-declared independence is the submitter's word, which this contract does not accept"
				}
			}
			if s.Salted {
				w += "; a commit-reveal shows possession by T only"
			}
			rd.Why = append(rd.Why, fmt.Sprintf("independence of %s not established: %s", keylog.Short(s.Statement), w))
		}
	}
	switch {
	case q.Independence == IndependenceNotRequired && best >= q.K:
		rd.Token = Ready
	case needIndep && bestEst >= q.K:
		rd.Token, rd.N, rd.SelfDeclared = Ready, bestEst, selfUsed
	case needIndep:
		// required independence cannot be established: unknown, never a smaller count (§9.3)
		rd.Token, rd.N = ReadyUnknown, 0
		rd.Why = append(rd.Why, "required independence not established: readiness unknown, not a smaller count")
	case unchecked != "":
		rd.Token = ReadyUnchecked
		rd.Why = append(rd.Why, unchecked)
	case uncheckedRubric:
		rd.Token = ReadyUnchecked
		rd.Why = append(rd.Why, "a rubric criterion is unchecked: the check does not pass")
	default:
		rd.Token = NotReady
	}
	if rd.Token != Ready {
		rd.SelfDeclared = false
	}
	// Genuine divergence stays visible as its own report, also once readiness is reached (§9.3).
	reached := map[string]bool{}
	for _, g := range groups {
		if count(g, nil) >= q.K {
			for _, s := range g {
				reached[s.Statement] = true
			}
		}
	}
	if len(reached) > 0 {
		for _, s := range pool {
			if !reached[s.Statement] {
				rd.Reports = append(rd.Reports, fmt.Sprintf("divergence report: submission %s by %s (result %s) is in no group that reached the quorum; kept beside the readiness token",
					keylog.Short(s.Statement), shortKey(s.Signer), shortDigest(s.Result)))
			}
		}
	}
	return rd
}

// quorumGroups forms the result groups of a quorum (§9.3 "grouping is explicit"). Byte equality is transitive, so with
// no comparator identical results group by digest. Under a comparator (or a pinned test) the contract's rule
// decides: all-pairs keeps only sets in which every pair matches; reference-based groups each result with the
// reference submitter's. Without a rule nothing groups and the missing rule is named. Results outside every
// group that reached the quorum are reported as divergence, also after readiness.
func (r *Resolver) quorumGroups(q *Quorum, pool []*Submission, limit int) (groups [][]*Submission, notes []string, unchecked string) {
	byResult := map[string][]*Submission{}
	for _, s := range pool {
		byResult[s.Result] = append(byResult[s.Result], s)
	}
	results := sortedKeys(byResult)
	members := func(rs []string) []*Submission {
		var out []*Submission
		for _, x := range rs {
			out = append(out, byResult[x]...)
		}
		return out
	}
	cmp := q.comparator()
	if cmp == "" || len(results) <= 1 {
		// byte equality is transitive: identical results group without a rule
		for _, x := range results {
			groups = append(groups, byResult[x])
		}
		if cmp == "" && len(results) > 1 {
			for _, x := range results {
				notes = append(notes, fmt.Sprintf("result %s from %s (byte equality)", shortDigest(x), plural(len(byResult[x]), "submission")))
			}
		}
		return groups, notes, ""
	}
	match := func(a, b string) (bool, string) {
		if a == b {
			return true, ""
		}
		res, why := r.pair(cmp, a, b)
		switch res {
		case "match":
			return true, ""
		case "diverged":
			notes = append(notes, fmt.Sprintf("divergence report: results %s and %s diverged under %s", shortDigest(min(a, b)), shortDigest(max(a, b)), q.comparatorName()))
			return false, ""
		}
		return false, fmt.Sprintf("results %s and %s: %s (%s)", shortDigest(min(a, b)), shortDigest(max(a, b)), res, why)
	}
	var pending []string
	switch q.Grouping {
	case "":
		return nil, nil, "no grouping rule declared: a comparator quorum names reference-based or all-pairs (tolerance is not transitive)"
	case GroupReference:
		var ref []string
		for _, x := range results {
			for _, s := range byResult[x] {
				if s.Signer == q.Reference && !slices.Contains(ref, x) {
					ref = append(ref, x)
				}
			}
		}
		if len(ref) != 1 {
			return nil, nil, fmt.Sprintf("reference-based grouping: %d counted result(s) by the reference %s (needs exactly one)", len(ref), shortKey(q.Reference))
		}
		in := []string{ref[0]}
		for _, x := range results {
			if x == ref[0] {
				continue
			}
			ok, p := match(ref[0], x)
			if ok {
				in = append(in, x)
			} else if p != "" {
				pending = append(pending, p)
			}
		}
		slices.Sort(in)
		groups = append(groups, members(in))
	default: // all-pairs: every maximal set of results in which every pair matches
		if len(results) > limit {
			return nil, nil, fmt.Sprintf("grouping limit: %d distinct results exceed the all-pairs search limit %d", len(results), limit)
		}
		n := len(results)
		edge := make([][]bool, n)
		for i := range edge {
			edge[i] = make([]bool, n)
			edge[i][i] = true
		}
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				ok, p := match(results[i], results[j])
				edge[i][j], edge[j][i] = ok, ok
				if p != "" {
					pending = append(pending, p)
				}
			}
		}
		var cliques []uint64
		for m := uint64(1); m < 1<<n; m++ {
			ok := true
			for i := 0; i < n && ok; i++ {
				for j := i + 1; j < n && ok; j++ {
					if m&(1<<i) != 0 && m&(1<<j) != 0 && !edge[i][j] {
						ok = false
					}
				}
			}
			if ok {
				cliques = append(cliques, m)
			}
		}
		for _, m := range cliques {
			maximal := true
			for _, o := range cliques {
				if o != m && o&m == m {
					maximal = false
					break
				}
			}
			if !maximal {
				continue
			}
			var rs []string
			for i := 0; i < n; i++ {
				if m&(1<<i) != 0 {
					rs = append(rs, results[i])
				}
			}
			groups = append(groups, members(rs))
		}
	}
	if len(pending) > 0 {
		unchecked = "comparisons that did not run: " + strings.Join(pending, "; ")
	}
	slices.Sort(notes)
	notes = slices.Compact(notes)
	return groups, notes, unchecked
}

// VerifyExit is the task's `verify` exit (claims §13): 3 (could not check) when its decisions conflict
// (`contested`), the resource itself does not pass (FORK, contested edition), or the current edition's readiness
// is `unchecked` or `unknown`; 0 otherwise. `not ready` is a checked answer, not a failure: the token says it.
func (t *Task) VerifyExit() int {
	if len(t.DecisionConflict) > 0 {
		return 3
	}
	for _, rd := range t.Readiness {
		if rd.Edition == t.Current && (rd.Token == ReadyUnchecked || rd.Token == ReadyUnknown || rd.Check == RuleUnchecked) {
			return 3
		}
	}
	return t.Resource.VerifyExit()
}

// Render is the task display: a function of the view only.
func (t *Task) Render() string {
	var b strings.Builder
	b.WriteString(t.Resource.Render())
	for _, eid := range sortedKeys(t.Bindings) {
		bd := t.Bindings[eid]
		fmt.Fprintf(&b, "  terms of %s (%s):", keylog.Short(eid), bd.State)
		if bd.Terms == nil {
			fmt.Fprintf(&b, " unchecked: %s\n", bd.TermsWhy)
			continue
		}
		b.WriteString("\n")
		for _, l := range bd.Terms.describe() {
			fmt.Fprintf(&b, "    %s\n", l)
		}
	}
	for _, a := range t.Attempts {
		fmt.Fprintf(&b, "  intent %s by %s on %s (advisory: excludes nobody; no lease, no expiry)", keylog.Short(a.Intent), shortKey(a.Signer), keylog.Short(a.Edition))
		if a.Withdrawn != "" {
			fmt.Fprintf(&b, " withdrawn by %s", keylog.Short(a.Withdrawn))
		}
		b.WriteString("\n")
		for _, p := range a.Progress {
			fmt.Fprintf(&b, "    progress %s: activity evidence, not a lease renewal\n", keylog.Short(p))
		}
	}
	for _, g := range t.Grants {
		fmt.Fprintf(&b, "  grant %s: coordinator %s grants %s on %s\n", keylog.Short(g.Statement), shortKey(g.Signer), shortKey(g.Grantee), keylog.Short(g.Edition))
	}
	for _, n := range t.GrantNotes {
		fmt.Fprintf(&b, "  %s\n", n)
	}
	for _, s := range t.Submissions {
		fmt.Fprintf(&b, "  submission %s by %s: result %s, bound to %s, read under its terms only; admissible", keylog.Short(s.Statement), shortKey(s.Signer), shortDigest(s.Result),
			keylog.Short(s.Edition))
		if !s.Counts {
			fmt.Fprintf(&b, "; counts toward nothing: %s", s.Why)
		}
		b.WriteString("\n")
		if s.Granted != "" {
			fmt.Fprintf(&b, "    granted by %s\n", keylog.Short(s.Granted))
		}
		for _, c := range s.Rubric {
			fmt.Fprintf(&b, "    rubric %s: %s", c.Criterion, c.Outcome)
			if c.Why != "" {
				fmt.Fprintf(&b, " (%s)", c.Why)
			}
			b.WriteString("\n")
		}
		switch {
		case s.Independent:
			fmt.Fprintf(&b, "    independence established by the reader's verifier: %s\n", s.IndepWhy)
		case s.SelfDeclared:
			b.WriteString("    independence self-declared (the submitter's word)\n")
		}
		if s.Salted {
			b.WriteString("    salted commitment: shows possession by T only, not independence\n")
		}
		for _, l := range s.Labels {
			fmt.Fprintf(&b, "    %s (the submitter's word; no verifier checked it)\n", l)
		}
		if s.Departure != "" {
			fmt.Fprintf(&b, "    departure check: %s (%s); the grade is unchanged\n", s.Departure, s.DepartureWhy)
		}
		if s.Verdict != "" {
			fmt.Fprintf(&b, "    decision: %s\n", s.Verdict)
		}
		for _, x := range s.Refuted {
			fmt.Fprintf(&b, "    refuted by %s (a first-class refutation, credited on its own track)\n", keylog.Short(x))
		}
	}
	for _, p := range t.Refutations {
		fmt.Fprintf(&b, "  refutation %s by %s of %s, evidence %s\n", keylog.Short(p.St.ID), shortKey(p.St.Signer), keylog.Short(str(p.St.Body, "of")), shortDigest(str(p.St.Body, "evidence")))
	}
	for _, d := range t.Decisions {
		fmt.Fprintf(&b, "  decision %s by %s: %s citing %s", keylog.Short(d.Statement), shortKey(d.Signer), d.Verdict, citeList(d.Submissions))
		if len(d.Evaluations) > 0 {
			ev := make([]string, len(d.Evaluations))
			for i, e := range d.Evaluations {
				ev[i] = shortDigest(e)
			}
			fmt.Fprintf(&b, ", evaluations %s", strings.Join(ev, ","))
		}
		if d.Supersedes != "" {
			fmt.Fprintf(&b, ", supersedes %s", keylog.Short(d.Supersedes))
		}
		switch {
		case !d.Counts:
			fmt.Fprintf(&b, " (%s)", d.Why)
		case d.SupersededBy != "":
			fmt.Fprintf(&b, " (superseded by %s)", keylog.Short(d.SupersededBy))
		}
		b.WriteString("\n")
	}
	if len(t.DecisionConflict) > 0 {
		fmt.Fprintf(&b, "  decisions: contested on %s\n", shorts(t.DecisionConflict))
	}
	for _, rd := range t.Readiness {
		fmt.Fprintf(&b, "  readiness of %s: %s", keylog.Short(rd.Edition), rd.Token)
		if rd.Token == Ready || rd.Token == NotReady {
			fmt.Fprintf(&b, " (%d of %d, %s)", rd.N, rd.K, CountedAs)
		}
		if rd.SelfDeclared {
			b.WriteString(" (independence self-declared)")
		}
		if rd.Check != "" {
			fmt.Fprintf(&b, "; rubric check %s", rd.Check)
		}
		b.WriteString("\n")
		for _, g := range rd.Groups {
			fmt.Fprintf(&b, "    group %s\n", shorts(g))
		}
		for _, x := range rd.Reports {
			fmt.Fprintf(&b, "    %s\n", x)
		}
		for _, x := range rd.Why {
			fmt.Fprintf(&b, "    explain: %s\n", x)
		}
	}
	fmt.Fprintf(&b, "  verify %d\n", t.VerifyExit())
	for _, x := range t.Explain {
		fmt.Fprintf(&b, "  explain: %s\n", x)
	}
	return b.String()
}

func citeList(ids []string) string {
	if len(ids) == 0 {
		return "nothing"
	}
	return shorts(ids)
}
