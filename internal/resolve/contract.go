package resolve

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
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
	// Deadline is the contract's deadline as written (a time value); "" for none. It is a term of this edition,
	// never a lease: no intent expires by it (C-exch-02).
	Deadline string
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

// describe renders terms for the task display.
func (t *Terms) describe() []string {
	label := "contract profile " + t.Profile
	if t.Provisional {
		label += " (PROVISIONAL reading: contract grammar pending)"
	}
	out := []string{label, "beneficiary " + shortKey(t.Beneficiary)}
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
	if t.Coordinator != "" {
		out = append(out, "coordinator "+shortKey(t.Coordinator))
	}
	if t.Deadline != "" {
		out = append(out, "deadline "+t.Deadline)
	}
	for _, c := range t.Rubric {
		out = append(out, fmt.Sprintf("rubric criterion %s: %q", c.ID, c.Text))
	}
	if q := t.Quorum; q != nil {
		s := fmt.Sprintf("quorum %d, independence %s", q.K, q.Independence)
		if q.comparator() != "" {
			s += ", " + q.comparatorName()
		}
		switch q.Grouping {
		case "":
			s += ", grouping undeclared"
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
//	eligible_issuers  list of key  } exactly one
//	any_issuer        true         }
//	counting_unit     "key" | "identity" O (absent: rc/1 default, key)
//	coordinator       key O
//	deadline          string O (a time value, as written)
//	rubric            list of {id string R, text string O} O
//	quorum            {k integer >=1 R, independence "not-required"|"required"|"self-declared-accepted" R,
//	                   grouping {rule "all-pairs"} | {rule "reference", reference key} O,
//	                   comparator digest O, estimand string O, test digest O} O
//	sampling          {n integer R, unit string R, groups list of {name string, n integer} O} O
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
	t := &Terms{Profile: ProvisionalProfile, Provisional: true, Beneficiary: str(c, "beneficiary"), CountingUnit: str(c, "counting_unit"),
		Coordinator: str(c, "coordinator"), Deadline: str(c, "deadline")}
	bad := func(f string) (*Terms, string, bool) { return nil, "contract field " + f + " malformed", false }
	if t.Beneficiary == "" {
		return bad("beneficiary")
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
		if !ok || len(l) == 0 {
			return bad("eligible_issuers")
		}
		t.EligibleIssuers = l
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
			if !ok || str(o, "id") == "" {
				return bad("rubric")
			}
			t.Rubric = append(t.Rubric, Criterion{ID: str(o, "id"), Text: str(o, "text")})
		}
	}
	if v, ok := c.Get("quorum"); ok {
		o, ok := v.(*canon.Object)
		if !ok {
			return bad("quorum")
		}
		q := &Quorum{K: intOf(o, "k"), Independence: str(o, "independence"), Comparator: str(o, "comparator"), Estimand: str(o, "estimand"), Test: str(o, "test")}
		if q.K < 1 || !slices.Contains([]string{IndependenceNotRequired, IndependenceRequired, IndependenceSelfDeclared}, q.Independence) {
			return bad("quorum")
		}
		if g := object(o, "grouping"); g != nil {
			q.Grouping, q.Reference = str(g, "rule"), str(g, "reference")
			if (q.Grouping != GroupAllPairs && q.Grouping != GroupReference) || (q.Grouping == GroupReference) != (q.Reference != "") {
				return bad("quorum.grouping")
			}
		}
		t.Quorum = q
	}
	if o := object(c, "sampling"); o != nil {
		s := &DeclaredSampling{N: intOf(o, "n"), Unit: str(o, "unit")}
		if v, ok := o.Get("groups"); ok {
			a, _ := v.(canon.Array)
			for _, x := range a {
				g, _ := x.(*canon.Object)
				s.Groups = append(s.Groups, SamplingGroup{Name: str(g, "name"), N: intOf(g, "n")})
			}
		}
		t.Sampling = s
	}
	return t, "", true
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
