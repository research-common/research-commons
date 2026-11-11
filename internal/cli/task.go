package cli

import (
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/resolve"
)

// The task section (claims-model note §9, §13; task-contracts note §5): a task is a resource, so show, verify and
// explain of a task's genesis id, one of its edition ids or an approval's statement id print the resource view
// and, beside it, this section. There is no task command of its own: one verb set reads every resource kind.
//
// The section is the resolver's task view (resolve.Task) on both surfaces: each edition's terms as this reader
// read them (or why it read none), the readiness of the current edition and of every edition a submission binds
// to (the bracket's token, the count and the reasons), every submission with its state (counted, undecided, not
// counted) and every reason, grants, bound refutations on their own track, decisions and a decision conflict.
// explain adds every check: the conditions that passed, the groups, the reports, the readiness reasoning and the
// task's own explanation lines.

// taskOf is the task view of a resource, when the resource is a task this reader resolves.
func (v *view) taskOf(res *resolve.Resource) (*resolve.Task, bool) {
	if res == nil || res.Type != "task" {
		return nil, false
	}
	return v.r.Task(res.ID)
}

// taskObj is the task section.
func (v *view) taskObj(t *resolve.Task, full bool) *Obj {
	o := newObj()
	tl := listV{}
	for _, eid := range sortedMapKeys(t.Bindings) {
		tl = append(tl, termsObj(t.Bindings[eid], full))
	}
	o.set("terms", tl)
	rl := listV{}
	for _, rd := range t.Readiness {
		rl = append(rl, readinessObj(rd, t.Bindings[rd.Edition], rd.Edition == t.Current, full))
	}
	o.set("readiness", rl)
	sl := listV{}
	for _, s := range t.Submissions {
		sl = append(sl, submissionObj(s, full))
	}
	o.set("submissions", sl)
	if len(t.Grants) > 0 || len(t.GrantNotes) > 0 {
		gl := listV{}
		for _, g := range t.Grants {
			gl = append(gl, newObj().set("statement", refV(g.Statement)).set("coordinator", refV(g.Signer)).
				set("grantee", refV(g.Grantee)).set("edition", refV(g.Edition)))
		}
		o.set("grants", gl)
		if len(t.GrantNotes) > 0 {
			o.set("grants_without_effect", texts(t.GrantNotes...))
		}
	}
	if len(t.Bound) > 0 {
		bl := listV{}
		for _, b := range t.Bound {
			bo := newObj().set("statement", refV(b.Statement)).set("signer", refV(b.Signer)).set("edition", refV(b.Edition)).
				set("refutes", refV(b.Of)).set("evidence", refV(b.Evidence)).set("track", textV("refutation: credited as a refutation, in no quorum group"))
			if b.Counts {
				bo.set("counted", tokV(tok("counted")))
				if b.Why != "" {
					bo.set("note", textV(b.Why))
				}
			} else {
				bo.set("counted", tokV(tok("not counted"))).set("reason", textV(b.Why))
			}
			bl = append(bl, bo)
		}
		o.set("bound_refutations", bl)
	}
	if len(t.Refutations) > 0 {
		rf := listV{}
		for _, p := range t.Refutations {
			rf = append(rf, newObj().set("statement", refV(p.St.ID)).set("signer", refV(p.St.Signer)).
				set("refutes", refV(bodyString(p.St.Body, "of"))).set("evidence", refV(bodyString(p.St.Body, "evidence"))))
		}
		o.set("refutations", rf)
	}
	if len(t.Decisions) > 0 {
		dl := listV{}
		for _, d := range t.Decisions {
			do := newObj().set("statement", refV(d.Statement)).set("signer", refV(d.Signer)).set("verdict", tokV(tok(d.Verdict))).
				set("edition", refV(d.Edition)).set("cites", refs(d.Submissions...))
			if len(d.Evaluations) > 0 {
				do.set("evaluations", refs(d.Evaluations...))
			}
			if d.Supersedes != "" {
				do.set("supersedes", refV(d.Supersedes))
			}
			switch {
			case !d.Counts:
				do.set("counted", tokV(tok("not counted"))).set("reason", textV(d.Why))
			case d.SupersededBy != "":
				do.set("counted", tokV(tok("not counted"))).set("superseded_by", refV(d.SupersededBy)).
					set("reason", textV("superseded: kept in the log, no longer the beneficiary's decision"))
			default:
				do.set("counted", tokV(tok("counted")))
			}
			dl = append(dl, do)
		}
		o.set("decisions", dl)
	}
	if len(t.DecisionConflict) > 0 {
		o.set("decision_conflict", newObj().set("state", tokV(tok("contested"))).set("on", refs(t.DecisionConflict...)).
			set("why", textV("the beneficiary's counted decisions disagree; neither ts nor order picks one: a later decision must supersede one")))
	}
	if full {
		if len(t.Attempts) > 0 {
			al := listV{}
			for _, a := range t.Attempts {
				ao := newObj().set("intent", refV(a.Intent)).set("signer", refV(a.Signer)).set("edition", refV(a.Edition)).
					set("note", textV("advisory: excludes nobody; no lease, no expiry"))
				if len(a.Progress) > 0 {
					ao.set("progress", refs(a.Progress...))
				}
				if a.Withdrawn != "" {
					ao.set("withdrawn_by", refV(a.Withdrawn))
				}
				al = append(al, ao)
			}
			o.set("attempts", al)
		}
		if len(t.Explain) > 0 {
			o.set("reasoning", texts(t.Explain...))
		}
	}
	return o
}

// termsObj is one bound edition's terms: the contract as read, or why none was.
func termsObj(b resolve.Binding, full bool) *Obj {
	o := newObj().set("edition", refV(b.Edition))
	if IsToken(b.State) {
		o.set("state", tokV(tok(b.State)))
	} else {
		o.set("binding", textV(b.State))
	}
	if b.Terms == nil {
		return o.set("contract", tokV(tok("unchecked"))).set("why", textV("terms not read: "+b.TermsWhy))
	}
	o.set("contract_profile", textV(contractProfile(b.Terms)))
	if full {
		o.set("terms", texts(b.Terms.Describe()...))
	}
	return o
}

func contractProfile(tm *resolve.Terms) string {
	if tm.Provisional {
		return tm.Profile + " (provisional: the contract grammar is pending)"
	}
	return tm.Profile
}

// readinessObj is one edition's readiness (task-contracts note §5.6): the bracket's token, how it is settled, the
// count behind it, the rubric check and the reasons. b is the edition's binding; a readiness without read terms
// is unchecked and names why.
func readinessObj(rd *resolve.Readiness, b resolve.Binding, current, full bool) *Obj {
	o := newObj().set("edition", refV(rd.Edition))
	if current {
		o.set("current", boolV(true))
	}
	o.set("state", tokV(tok(rd.Token)))
	switch {
	case b.Terms == nil:
		o.set("why", textV("readiness unchecked: the contract is not read by this reader: "+b.TermsWhy))
	case b.Terms.Quorum == nil:
		o.set("why", textV("no quorum predicate: "+resolve.ByReview))
	default:
		o.set("quorum", intV(int64(rd.K))).set("unit", textV(rd.Unit))
		if rd.Token == resolve.Ready || rd.Token == resolve.NotReady {
			o.set("count", intV(int64(rd.N)))
		}
		o.set("why", textV("settled by counting: "+strconv.Itoa(rd.K)+" distinct "+unitWord(rd.Unit)))
	}
	if rd.SelfDeclared {
		o.set("independence", textV("self-declared (the submitters' word, which the contract accepts)"))
	}
	if rd.Check != "" {
		o.set("rubric_check", newObj().set("state", tokV(tok(string(rd.Check)))))
	}
	if b.Terms != nil {
		o.set("contract_profile", textV(contractProfile(b.Terms)))
	}
	if len(rd.Why) > 0 {
		o.set("explain", texts(rd.Why...))
	}
	if full {
		if len(rd.Groups) > 0 {
			gl := listV{}
			for _, g := range rd.Groups {
				gl = append(gl, newObj().set("statements", refs(g...)))
			}
			o.set("groups", gl)
		}
		if len(rd.Reports) > 0 {
			o.set("reports", texts(rd.Reports...))
		}
	}
	return o
}

func unitWord(unit string) string {
	if unit == resolve.CountedAsIdentities {
		return "eligible identities"
	}
	return "signing keys"
}

// submissionObj is one submission: what it binds, its state under task-contract-v1 (counted, undecided, not
// counted) and every reason; explain adds each condition, the ones that passed included.
func submissionObj(s *resolve.Submission, full bool) *Obj {
	o := newObj().set("statement", refV(s.Statement)).set("kind", peerV(s.Kind)).set("signer", refV(s.Signer)).
		set("result", refV(s.Result)).set("edition", refV(s.Edition))
	if s.Identity != "" {
		o.set("identity", refV(s.Identity))
	}
	if c := s.V1; c != nil {
		o.set("state", tokV(tok(c.State)))
		if len(c.Reasons) > 0 {
			o.set("reasons", texts(c.Reasons...))
		}
		if c.IndepUndecided {
			o.set("independence", textV("not established: undecided for a quorum that requires it"))
		}
		if len(c.Retracted) > 0 {
			o.set("retracted_by", refs(c.Retracted...))
		}
	} else {
		// the provisional reading: whether its line counts; the readiness reports say why it is not counted
		if s.Counts {
			o.set("counted", tokV(tok("counted")))
		} else {
			o.set("counted", tokV(tok("not counted"))).set("reason", textV(s.Why))
		}
	}
	if s.Granted != "" {
		o.set("granted_by", refV(s.Granted))
	}
	if s.Verdict != "" {
		o.set("decision", newObj().set("verdict", tokV(tok(s.Verdict))))
	}
	if len(s.Refuted) > 0 {
		o.set("refuted_by", refs(s.Refuted...))
	}
	if full {
		if ch := checksOf(s); len(ch) > 0 {
			o.set("checks", ch)
		}
		if len(s.Labels) > 0 {
			o.set("labels_submitters_word", texts(s.Labels...))
		}
		switch {
		case s.Independent:
			o.set("independence_evidence", textV("established by the reader's verifier: "+s.IndepWhy))
		case s.SelfDeclared:
			o.set("independence_evidence", textV("self-declared (the submitter's word)"))
		}
		if s.Salted {
			o.set("salt", textV("retained, inert: shows possession at most, never independence"))
		}
		if s.Departure != "" {
			o.set("departure_check", textV(s.Departure+" ("+s.DepartureWhy+"); the grade is unchanged"))
		}
	}
	return o
}

// checksOf is every condition evaluated for a submission (task-contracts note §5.1), passing or not.
func checksOf(s *resolve.Submission) listV {
	l := listV{}
	add := func(about string, out resolve.Outcome, why string) {
		if out == "" {
			return
		}
		c := newObj().set("about", textV(about)).set("state", tokV(tok(string(out))))
		if why != "" {
			c.set("why", textV(why))
		}
		l = append(l, c)
	}
	for _, r := range s.Rubric {
		add("rubric "+r.Criterion, r.Outcome, r.Why)
	}
	if c := s.V1; c != nil {
		add("deadline", c.Deadline, strings.Join(c.DeadlineWhy, "; "))
		add("results", c.Results, c.ResultsWhy)
		add("min_grade", c.MinGrade, c.MinGradeWhy)
		add("pins", c.Pins, c.PinsWhy)
		cur := resolve.RuleOK
		if !c.Current {
			cur = resolve.RuleFail
		}
		add("current submission of its unit", cur, c.CurrentWhy)
	}
	return l
}

// taskCauses are the causes a task's verify exit reads (task-contracts note §5.7): for the edition (the current
// edition when "" or the resource), readiness unknown or unchecked, a by-review edition whose rubric check is
// unchecked, or a decision conflict. None: the readiness is ready, not ready or settled by review and the
// beneficiary's decisions agree (exit 0 for the task part; not ready is a completed check that says "not yet").
func taskCauses(t *resolve.Task, edition string) listV {
	causes := listV{}
	if edition == "" {
		edition = t.Current
	}
	for _, rd := range t.Readiness {
		if rd.Edition != edition {
			continue
		}
		switch {
		case rd.Token == resolve.ReadyUnchecked || rd.Token == resolve.ReadyUnknown:
			causes = append(causes, newObj().set("about", textV("readiness")).set("state", tokV(tok(rd.Token))))
		case rd.Token == resolve.ByReview && rd.Check == resolve.RuleUnchecked:
			causes = append(causes, newObj().set("about", textV("rubric check")).set("state", tokV(tok(string(rd.Check)))))
		}
	}
	if conflict := conflictsOn(t, edition); len(conflict) > 0 {
		causes = append(causes, newObj().set("about", textV("decisions")).set("state", tokV(tok("contested"))).set("on", refs(conflict...)))
	}
	return causes
}

// conflictsOn is the decision conflicts of a task on submissions bound to the edition; every conflict when the
// edition is the task's current one (a conflict is the task's, whatever edition it names).
func conflictsOn(t *resolve.Task, edition string) []string {
	if edition == t.Current {
		return t.DecisionConflict
	}
	var out []string
	for _, s := range t.Submissions {
		if s.Edition == edition && slices.Contains(t.DecisionConflict, s.Statement) {
			out = append(out, s.Statement)
		}
	}
	return out
}

// taskInputs is every statement the task section read: submissions, every grant naming the task (one without
// effect too: it is shown, and a key event of its signer could change that), refutations, decisions, intents
// with their progress and withdrawals, and retractions shown beside submissions.
func (v *view) taskInputs(t *resolve.Task) []string {
	var ids []string
	for _, p := range v.r.All() {
		if p.St.Kind == "grant" && bodyString(p.St.Body, "task") == t.ID {
			ids = append(ids, p.St.ID)
		}
	}
	for _, s := range t.Submissions {
		ids = append(ids, s.Statement)
		if s.Granted != "" {
			ids = append(ids, s.Granted)
		}
		ids = append(ids, s.Refuted...)
		if s.V1 != nil {
			ids = append(ids, s.V1.Retracted...)
		}
	}
	for _, g := range t.Grants {
		ids = append(ids, g.Statement)
	}
	for _, b := range t.Bound {
		ids = append(ids, b.Statement)
	}
	for _, p := range t.Refutations {
		ids = append(ids, p.St.ID)
	}
	for _, d := range t.Decisions {
		ids = append(ids, d.Statement)
		ids = append(ids, d.Submissions...)
		if d.Supersedes != "" {
			ids = append(ids, d.Supersedes)
		}
	}
	for _, a := range t.Attempts {
		ids = append(ids, a.Intent)
		ids = append(ids, a.Progress...)
		if a.Withdrawn != "" {
			ids = append(ids, a.Withdrawn)
		}
	}
	return ids
}
