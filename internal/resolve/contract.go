package resolve

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/rctime"
)

// Task contracts (claims-model note §9.1, §9.3; wire-format note §5 `contents.contract`).
//
// The wire format types `contents.contract` as an arbitrary object, and no merged note fixes its grammar: who
// decides, who may submit, the quorum predicate (deduplication, evidence strength, independence, grouping,
// estimand and test), the coordinator, deadlines, the rubric, the declared sampling. The resolver therefore
// never reads a contract itself. It asks the reader's ContractReader, which turns one task edition's contract
// into Terms or says why it cannot. The default reads nothing, so every task's terms are `unchecked`, its
// readiness is `unchecked` and nothing passes (I4, I11); lifecycle, bindings, decisions that need no terms and
// pre-registration displays still resolve.
//
// ProvisionalContract is a PROVISIONAL reading, for tests and for review of a contract-profile note: its field
// names are a proposal, not part of the format. Every surface that shows terms read by it says so
// (Terms.Profile, Terms.Provisional). A contract that does not name the provisional profile is an unknown
// contract profile and is never read by it (unknown profiles never produce passing readiness or settlement).

// ContractReader reads one task edition's `contents.contract`. ok is false when the reader does not understand
// the contract; why then names the reason ("unknown contract profile …", "contract field … malformed").
type ContractReader interface {
	Read(contract *canon.Object) (t *Terms, why string, ok bool)
}

// NoContractReader is the default: it reads no contract.
type NoContractReader struct{}

// NoContractProfile is why a contract is unread when the reader configured no contract reader.
const NoContractProfile = "no contract profile configured by this reader (contract grammar pending)"

// Read implements ContractReader.
func (NoContractReader) Read(*canon.Object) (*Terms, string, bool) {
	return nil, NoContractProfile, false
}

// WithContractReader sets the reader's contract reader.
func WithContractReader(c ContractReader) Option { return func(r *Resolver) { r.exch.contracts = c } }

// Grouping rules of a comparator quorum (§9.3 "grouping is explicit").
const (
	GroupAllPairs  = "all-pairs"
	GroupReference = "reference"
)

// Independence requirements of a quorum (§9.3).
const (
	IndependenceNotRequired  = "not-required"
	IndependenceRequired     = "required"
	IndependenceSelfDeclared = "self-declared-accepted"
)

// Counting units (fixed-root identity profile §5.3: a task contract declares `key` or `identity`).
const (
	CountKey      = "key"
	CountIdentity = "identity"
)

// Terms are one task edition's contract as a ContractReader read it. Every field is the contract's word; the
// resolver applies it to statements bound to that edition and to no other (claims §8, C-exch-07).
type Terms struct {
	// Profile names the contract profile that read these terms; Provisional is true for a reading whose
	// grammar is not part of the format, and every display of the terms says so.
	Profile     string
	Provisional bool
	// Beneficiary is the key whose signed decisions settle the task (§9.2).
	Beneficiary string
	// EligibleIssuers lists the keys whose submissions count toward readiness; AnyIssuer admits every key.
	// Submissions from anyone else are still admissible and listed (§9.1).
	EligibleIssuers []string
	AnyIssuer       bool
	// CountingUnit is `key` or `identity`; "" is the documented rc/1 default, `key`.
	CountingUnit string
	// Coordinator is the key whose signed grants are the only exclusion that counts (§9.1); "" for none.
	Coordinator string
	// Roles are an rc/2 edition's typed roles (task_roles.go); nil under rc/1. When set, Beneficiary and
	// EligibleIssuers are empty and AnyIssuer and CountingUnit mirror Roles.
	Roles *TaskRoles
	// Deadline is the provisional reading's deadline as written (a time value); "" for none. It is displayed and
	// never evaluated. It is a term of this edition, never a lease: no intent expires by it (C-exch-02).
	Deadline string
	// DeadlineHeight is a task-contract-v1 deadline (HasDeadline): the last block height at which a counted
	// submission must be shown to exist, evaluated against verified bounds only (task-contracts note §4.3).
	DeadlineHeight int64
	HasDeadline    bool
	// Question is the task's question as prose (task-contract-v1): displayed, never evaluated.
	Question string
	// Results restricts counting to one kind of result (task-contract-v1, "" for either); Pins are its exact
	// pins (nil for none).
	Results string
	Pins    *Pins
	// Rubric lists the acceptance criteria (§9.2 checks); each evaluation is ok, fail or unchecked.
	Rubric []Criterion
	// Quorum is the quorum predicate; nil means the task is settled by review, not by counting (§9.2).
	Quorum *Quorum
	// Sampling is the declared sampling the departure check compares deliveries with (§9.4); nil for none.
	Sampling *DeclaredSampling
}

// Criterion is one rubric criterion.
type Criterion struct {
	ID, Text string
}

// Quorum is a quorum predicate (§9.3).
type Quorum struct {
	K int
	// Independence is one of the Independence* constants.
	Independence string
	// Grouping is "", GroupAllPairs or GroupReference; Reference names the reference submitter's key.
	Grouping, Reference string
	// Comparator is the comparator digest results are compared under ("" for byte equality only). Test, when
	// pinned, is the statistical test for stochastic replication (#65), and Estimand what it tests; a pinned test
	// is the comparator (overlapping confidence intervals are not equivalence).
	Comparator     string
	Estimand, Test string
	// MinGrade is task-contract-v1's weakest grade a derived result may have and still count ("" for none).
	MinGrade string
}

// comparator is what result pairs are compared under: the pinned test when there is one.
func (q *Quorum) comparator() string {
	if q.Test != "" {
		return q.Test
	}
	return q.Comparator
}

// comparatorName is the comparator's display.
func (q *Quorum) comparatorName() string {
	if q.Test != "" {
		s := "test " + shortDigest(q.Test)
		if q.Estimand != "" {
			s += " on estimand " + fmt.Sprintf("%q", q.Estimand)
		}
		return s
	}
	return "comparator " + shortDigest(q.Comparator)
}

// DeclaredSampling is a contract's declared n, unit and per-group n (§9.4 departure check; §7 sampling).
type DeclaredSampling struct {
	N      int
	Unit   string
	Groups []SamplingGroup
}

// SamplingGroup is one arm of a design.
type SamplingGroup struct {
	Name string
	N    int
}

// Describe is the terms as the task display renders them, one line per term (a display helper for surfaces).
func (t *Terms) Describe() []string { return t.describe() }

// describe renders terms for the task display.
func (t *Terms) describe() []string {
	label := "contract profile " + t.Profile
	if t.Provisional {
		label += " (PROVISIONAL reading: contract grammar pending)"
	}
	out := []string{label}
	if t.Question != "" {
		out = append(out, fmt.Sprintf("question %q (displayed, never evaluated)", t.Question))
	}
	if t.Roles != nil {
		out = append(out, t.Roles.describe()...)
	} else {
		out = append(out, t.rc1Roles()...)
	}
	if t.Coordinator != "" {
		out = append(out, "coordinator "+shortKey(t.Coordinator))
	}
	if t.Deadline != "" {
		out = append(out, "deadline "+t.Deadline)
	}
	if t.HasDeadline {
		out = append(out, fmt.Sprintf("deadline bitcoin height %d (met only by a verified bound at or below it; ts meets nothing)", t.DeadlineHeight))
	}
	if t.Results != "" {
		out = append(out, "results: "+t.Results+" only (the kind is read from the held record for each result)")
	}
	if p := t.Pins; p != nil {
		var ps []string
		if p.Workflow != "" {
			ps = append(ps, "workflow "+shortDigest(p.Workflow))
		}
		if p.MethodEdition != "" {
			ps = append(ps, "method edition "+keylog.Short(p.MethodEdition))
		}
		if len(p.Inputs) > 0 {
			in := make([]string, len(p.Inputs))
			for i, d := range p.Inputs {
				in[i] = shortDigest(d)
			}
			ps = append(ps, "inputs "+strings.Join(in, ","))
		}
		out = append(out, "pins: "+strings.Join(ps, "; "))
	}
	for _, c := range t.Rubric {
		out = append(out, fmt.Sprintf("rubric criterion %s: %q", c.ID, c.Text))
	}
	if q := t.Quorum; q != nil {
		s := fmt.Sprintf("quorum %d, independence %s", q.K, q.Independence)
		if q.comparator() != "" {
			s += ", " + q.comparatorName()
		}
		if q.MinGrade != "" {
			s += ", min grade " + q.MinGrade
		}
		switch q.Grouping {
		case "":
			if t.Provisional || q.comparator() != "" {
				s += ", grouping undeclared"
			} else {
				s += ", grouping by byte equality"
			}
		case GroupAny:
			s += ", grouping any (collecting: every counted submission in one group)"
		case GroupReference:
			s += ", grouping reference-based (" + shortKey(q.Reference) + ")"
		default:
			s += ", grouping " + q.Grouping
		}
		out = append(out, s)
	} else {
		out = append(out, "no quorum predicate: settled by review, not by counting")
	}
	if s := t.Sampling; s != nil {
		d := fmt.Sprintf("declared sampling n=%d %s", s.N, s.Unit)
		for _, g := range s.Groups {
			d += fmt.Sprintf(", group %s n>=%d", g.Name, g.N)
		}
		out = append(out, d)
	}
	return out
}

// ProvisionalProfile is the profile name the provisional reading recognises in `contract.profile`.
const ProvisionalProfile = "provisional-task-contract-0"

// ProvisionalContract is the PROVISIONAL contract reading (contract grammar pending). It recognises only a
// contract whose `profile` is ProvisionalProfile, and reads:
//
//	beneficiary       key R
//	eligible_issuers  set of key   } exactly one (non-empty, sorted, duplicate-free)
//	any_issuer        true         }
//	counting_unit     "key" | "identity" O (absent: rc/1 default, key)
//	coordinator       key O
//	deadline          ts O (a UTC time value, wire §1.1; shape checked, kept as written, never evaluated)
//	rubric            list of {id string R, text string O} O (ids unique)
//	quorum            {k integer >=1 R, independence "not-required"|"required"|"self-declared-accepted" R,
//	                   grouping {rule "all-pairs"} | {rule "reference", reference key} O,
//	                   comparator digest O, estimand string O, test digest O} O
//	                  (at most one of comparator and test; grouping only beside one of them)
//	sampling          {n integer R, unit string R, groups list of {name string R, n integer R} O (names unique)} O
//
// Any malformed or unknown field makes the whole contract unread (never a partial reading).
type ProvisionalContract struct{}

// Read implements ContractReader.
func (ProvisionalContract) Read(c *canon.Object) (*Terms, string, bool) {
	if c == nil {
		return nil, "no contract", false
	}
	if p := str(c, "profile"); p != ProvisionalProfile {
		return nil, fmt.Sprintf("unknown contract profile %q (this reader reads %s, provisionally)", p, ProvisionalProfile), false
	}
	known := []string{"profile", "beneficiary", "eligible_issuers", "any_issuer", "counting_unit", "coordinator", "deadline", "rubric", "quorum", "sampling"}
	for _, k := range c.Keys {
		if !slices.Contains(known, k) {
			return nil, "contract field " + k + " not in the provisional reading", false
		}
	}
	bad := func(f string) (*Terms, string, bool) { return nil, "contract field " + f + " malformed", false }
	t := &Terms{Profile: ProvisionalProfile, Provisional: true}
	var ok bool
	if t.Beneficiary, ok = keyMember(c, "beneficiary", true); !ok {
		return bad("beneficiary")
	}
	if t.Coordinator, ok = keyMember(c, "coordinator", false); !ok {
		return bad("coordinator")
	}
	if t.CountingUnit, ok = optString(c, "counting_unit"); !ok {
		return bad("counting_unit")
	}
	_, hasList := c.Get("eligible_issuers")
	av, hasAny := c.Get("any_issuer")
	switch {
	case hasList == hasAny:
		return nil, "contract must declare exactly one of eligible_issuers and any_issuer", false
	case hasAny:
		if b, ok := av.(canon.Bool); !ok || !bool(b) {
			return bad("any_issuer")
		}
		t.AnyIssuer = true
	default:
		l, ok := strings_(c, "eligible_issuers")
		if !ok || len(l) == 0 || slices.ContainsFunc(l, func(k string) bool { return !reKeyForm.MatchString(k) }) {
			return bad("eligible_issuers")
		}
		// a set, as controllers are (wire §1 "arrays"): sorted by the key order, no duplicates
		for i := 1; i < len(l); i++ {
			if canon.CompareKeys(l[i-1], l[i]) >= 0 {
				return bad("eligible_issuers")
			}
		}
		t.EligibleIssuers = l
	}
	// The deadline is a time value (wire §1.1), checked for shape only: it is displayed as a term and never
	// evaluated here.
	if v, ok := c.Get("deadline"); ok {
		d, ok := v.(canon.String)
		if !ok {
			return bad("deadline")
		}
		if _, err := rctime.ParseUTC(string(d)); err != nil {
			return bad("deadline")
		}
		t.Deadline = string(d)
	}
	if t.CountingUnit != "" && t.CountingUnit != CountKey && t.CountingUnit != CountIdentity {
		return bad("counting_unit")
	}
	if v, ok := c.Get("rubric"); ok {
		a, ok := v.(canon.Array)
		if !ok {
			return bad("rubric")
		}
		for _, x := range a {
			o, ok := x.(*canon.Object)
			if !ok {
				return bad("rubric")
			}
			id, ok := stringMember(o, "id")
			if !ok || id == "" {
				return bad("rubric.id")
			}
			if slices.ContainsFunc(t.Rubric, func(c Criterion) bool { return c.ID == id }) {
				return bad("rubric.id")
			}
			text := ""
			if _, has := o.Get("text"); has {
				if text, ok = stringMember(o, "text"); !ok {
					return bad("rubric.text")
				}
			}
			t.Rubric = append(t.Rubric, Criterion{ID: id, Text: text})
		}
	}
	if v, ok := c.Get("quorum"); ok {
		o, ok := v.(*canon.Object)
		if !ok {
			return bad("quorum")
		}
		q := &Quorum{}
		k, ok := o.Get("k")
		if n, isInt := k.(canon.Int); !ok || !isInt || n < 1 {
			return bad("quorum.k")
		}
		q.K = intOf(o, "k")
		if q.Independence, ok = optString(o, "independence"); !ok ||
			!slices.Contains([]string{IndependenceNotRequired, IndependenceRequired, IndependenceSelfDeclared}, q.Independence) {
			return bad("quorum.independence")
		}
		if q.Comparator, ok = digestMember(o, "comparator"); !ok {
			return bad("quorum.comparator")
		}
		if q.Test, ok = digestMember(o, "test"); !ok {
			return bad("quorum.test")
		}
		if q.Estimand, ok = optString(o, "estimand"); !ok {
			return bad("quorum.estimand")
		}
		// A pinned test is the comparator; the reading never picks one of two silently.
		if q.Comparator != "" && q.Test != "" {
			return bad("quorum.test")
		}
		g, present, ok := memberObject(o, "grouping")
		if !ok {
			return bad("quorum.grouping")
		}
		if present {
			if q.Comparator == "" && q.Test == "" {
				return bad("quorum.grouping")
			}
			var okRule, okRef bool
			q.Grouping, okRule = optString(g, "rule")
			q.Reference, okRef = keyMember(g, "reference", false)
			if !okRule || !okRef || (q.Grouping != GroupAllPairs && q.Grouping != GroupReference) || (q.Grouping == GroupReference) != (q.Reference != "") {
				return bad("quorum.grouping")
			}
		}
		t.Quorum = q
	}
	o, present, ok := memberObject(c, "sampling")
	if !ok {
		return bad("sampling")
	}
	if present {
		s := &DeclaredSampling{N: intOf(o, "n"), Unit: str(o, "unit")}
		if nv, _ := o.Get("n"); !isInt(nv) {
			return bad("sampling.n")
		}
		if _, ok := stringMember(o, "unit"); !ok {
			return bad("sampling.unit")
		}
		if v, ok := o.Get("groups"); ok {
			a, ok := v.(canon.Array)
			if !ok {
				return bad("sampling.groups")
			}
			for _, x := range a {
				g, ok := x.(*canon.Object)
				if !ok {
					return bad("sampling.groups")
				}
				name, ok := stringMember(g, "name")
				if !ok || slices.ContainsFunc(s.Groups, func(h SamplingGroup) bool { return h.Name == name }) {
					return bad("sampling.groups.name")
				}
				nv, _ := g.Get("n")
				n, ok := nv.(canon.Int)
				if !ok {
					return bad("sampling.groups.n")
				}
				s.Groups = append(s.Groups, SamplingGroup{Name: name, N: int(n)})
			}
		}
		t.Sampling = s
	}
	return t, "", true
}

// memberObject reads member k of o strictly: present is false when the member is absent; ok is false when it
// is present and not an object (a present member of the wrong type is malformed, never absent).
func memberObject(o *canon.Object, k string) (x *canon.Object, present, ok bool) {
	v, present := o.Get(k)
	if !present {
		return nil, false, true
	}
	x, ok = v.(*canon.Object)
	return x, true, ok
}

// optString reads an optional string member: "" and ok when absent; ok is false when present and not a string.
func optString(o *canon.Object, k string) (string, bool) {
	if _, present := o.Get(k); !present {
		return "", true
	}
	return stringMember(o, k)
}

// reKeyForm is the key shape of wire §5 (`key`): ed25519: + 64 lowercase hex, or 0x + 40 lowercase hex.
var reKeyForm = regexp.MustCompile(`^(0x[0-9a-f]{40}|ed25519:[0-9a-f]{64})$`)

// reIDForm is the statement and edition id shape of wire §5 (`id`): 64 lowercase hex.
var reIDForm = regexp.MustCompile(`^[0-9a-f]{64}$`)

// keyMember reads a key member; absent is ok unless required. A present non-key is malformed.
func keyMember(o *canon.Object, k string, required bool) (string, bool) {
	if _, present := o.Get(k); !present {
		return "", !required
	}
	s, ok := stringMember(o, k)
	return s, ok && reKeyForm.MatchString(s)
}

// digestMember reads an optional digest member (wire §5 `digest`). A present non-digest is malformed.
func digestMember(o *canon.Object, k string) (string, bool) {
	if _, present := o.Get(k); !present {
		return "", true
	}
	s, ok := stringMember(o, k)
	return s, ok && reDigestForm.MatchString(s)
}

func isInt(v canon.Value) bool { _, ok := v.(canon.Int); return ok }

// stringMember reads member k of o as a string; ok is false when it is absent or not a string.
func stringMember(o *canon.Object, k string) (string, bool) {
	v, ok := o.Get(k)
	if !ok {
		return "", false
	}
	s, ok := v.(canon.String)
	return string(s), ok
}

func intOf(o *canon.Object, k string) int {
	if o == nil {
		return 0
	}
	if v, ok := o.Get(k); ok {
		if n, ok := v.(canon.Int); ok {
			return int(n)
		}
	}
	return 0
}

// strings_ reads a list of strings; ok is false when the member is absent or holds anything but strings.
func strings_(o *canon.Object, k string) ([]string, bool) {
	v, ok := o.Get(k)
	if !ok {
		return nil, false
	}
	a, ok := v.(canon.Array)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		s, ok := x.(canon.String)
		if !ok {
			return nil, false
		}
		out = append(out, string(s))
	}
	return out, true
}

// Departure check tokens (§9.4).
const (
	Conforms         = "conforms"
	Departed         = "departed"
	DepUnchecked     = "unchecked"
	DepNotComparable = "not comparable"
)

// DepartureCheck compares a delivered `sampling` disclosure (wire §5; nil when absent) with the contract's
// declared sampling (§9.4): per group where the contract declares groups. It never moves a grade (I6); the
// caller shows the token beside it.
func DepartureCheck(declared *DeclaredSampling, delivered *canon.Object) (string, string) {
	if declared == nil {
		return "", "the contract declares no sampling"
	}
	if delivered == nil {
		return DepUnchecked, "no structured sampling count delivered"
	}
	unit := str(delivered, "unit")
	if _, ok := delivered.Get("n"); !ok || unit == "" {
		return DepUnchecked, "no structured sampling count delivered"
	}
	if unit != declared.Unit {
		return DepNotComparable, fmt.Sprintf("delivered unit %q, declared %q: never converted", unit, declared.Unit)
	}
	if len(declared.Groups) == 0 {
		if n := intOf(delivered, "n"); n < declared.N {
			return Departed, fmt.Sprintf("delivered n=%d %s, declared %d", n, unit, declared.N)
		}
		return Conforms, fmt.Sprintf("delivered n=%d %s, declared %d", intOf(delivered, "n"), unit, declared.N)
	}
	got := map[string]int{}
	if v, ok := delivered.Get("groups"); ok {
		a, _ := v.(canon.Array)
		for _, x := range a {
			if g, ok := x.(*canon.Object); ok {
				got[str(g, "name")] = intOf(g, "n")
			}
		}
	}
	var missing, short []string
	for _, g := range declared.Groups {
		n, ok := got[g.Name]
		switch {
		case !ok:
			missing = append(missing, g.Name)
		case n < g.N:
			short = append(short, fmt.Sprintf("group %s n=%d, declared >=%d", g.Name, n, g.N))
		}
	}
	switch {
	case len(missing) > 0:
		return DepUnchecked, "no count delivered for declared group(s) " + strings.Join(missing, ",")
	case len(short) > 0:
		return Departed, strings.Join(short, "; ")
	}
	return Conforms, fmt.Sprintf("every declared group delivered (%d groups)", len(declared.Groups))
}

// rc1Roles is the rc/1 placement's role lines (roles in the contract).
func (t *Terms) rc1Roles() []string {
	out := []string{"beneficiary " + shortKey(t.Beneficiary)}
	switch {
	case t.AnyIssuer:
		out = append(out, "eligible issuers: any key")
	default:
		ks := make([]string, len(t.EligibleIssuers))
		for i, k := range t.EligibleIssuers {
			ks[i] = shortKey(k)
		}
		out = append(out, "eligible issuers: "+strings.Join(ks, ","))
	}
	unit := t.CountingUnit
	if unit == "" {
		unit = CountKey + " (rc/1 default)"
	}
	out = append(out, "counting unit "+unit)
	return out
}
