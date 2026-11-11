package resolve

import (
	"fmt"
	"slices"

	"github.com/research-common/research-commons/internal/canon"
)

// The accepted contract profile (task-contracts note §3). TaskContractV1 reads a contract whose `profile` is
// TaskContractV1Profile and nothing else; ContractProfiles picks a reader by the contract's `profile`, so the
// provisional reading keeps its own name and no contract silently changes meaning (task-contracts note §8).

// TaskContractV1Profile is the profile name of the accepted task-contract profile.
const TaskContractV1Profile = "task-contract-v1"

// GroupAny is the collecting grouping of task-contract-v1 (task-contracts note §5.2): every counted submission
// is in one group. Allowed only with neither comparator nor test.
const GroupAny = "any"

// Result kinds a task-contract-v1 contract may restrict counting to (task-contracts note §6 Q2).
const (
	ResultsDerived  = "derived"
	ResultsObserved = "observed"
)

// Pins are a task-contract-v1 contract's exact pins (task-contracts note §6 Q3): a derived result's
// provenance.workflow must equal Workflow; an observation's referent.method_edition must equal MethodEdition;
// the result's inputs must include every member of Inputs. "" and nil are absent members.
type Pins struct {
	Workflow, MethodEdition string
	Inputs                  []string
}

// v1Fields are the task-contract-v1 field table (task-contracts note §3.1). Any other member, `x_` names
// included, leaves the contract unread (§3.3).
var v1Fields = []string{"profile", "question", "beneficiary", "eligible_issuers", "any_issuer", "counting_unit", "coordinator",
	"deadline", "rubric", "quorum", "results", "pins", "sampling"}

var v1QuorumFields = []string{"k", "independence", "grouping", "comparator", "test", "estimand", "min_grade"}

// TaskContractV1 reads task-contract-v1 contracts (task-contracts note §3). It reads the rc/1 placement of the
// role fields (§3.2): the format's only major today. A contract it does not fully read is unread, naming the
// profile or the field; there is never a partial reading.
type TaskContractV1 struct{}

// Read implements ContractReader.
func (TaskContractV1) Read(c *canon.Object) (*Terms, string, bool) { return readV1(c, nil) }

// ReadRC2 implements RC2ContractReader: the rc/2 placement (§3.2), the roles from the edition's task_roles.
func (TaskContractV1) ReadRC2(c *canon.Object, roles *TaskRoles) (*Terms, string, bool) {
	if roles == nil {
		return nil, "an rc/2 contract needs the edition's " + taskRolesPath, false
	}
	return readV1(c, roles)
}

// readV1 reads a task-contract-v1 contract. roles nil is the rc/1 placement (roles in the contract); non-nil is
// the rc/2 placement: the four role fields are forbidden in the contract (identity profile §5.3, task-contracts
// note §3.2) and the roles are the edition's task_roles. The coordinator stays a key in the contract (§6 Q9).
func readV1(c *canon.Object, roles *TaskRoles) (*Terms, string, bool) {
	if c == nil {
		return nil, "no contract", false
	}
	if v, ok := c.Get("profile"); !ok {
		return nil, "contract names no profile", false
	} else if p, ok := v.(canon.String); !ok || string(p) != TaskContractV1Profile {
		return nil, fmt.Sprintf("unknown contract profile %s (this reader reads %s)", canon.Encode(v), TaskContractV1Profile), false
	}
	for _, k := range c.Keys {
		if !slices.Contains(v1Fields, k) {
			return nil, "contract field " + k + " is not a " + TaskContractV1Profile + " field (an unknown field leaves the contract unread)", false
		}
	}
	bad := func(f string) (*Terms, string, bool) { return nil, "contract field " + f + " malformed", false }
	t := &Terms{Profile: TaskContractV1Profile}
	var ok bool
	if t.Question, ok = stringMember(c, "question"); !ok {
		return nil, "contract field question is missing or not a string", false
	}
	if roles != nil {
		for _, f := range roleFields {
			if _, has := c.Get(f); has {
				return nil, "contract field " + f + " is forbidden under rc/2: the roles are the edition's " + taskRolesPath, false
			}
		}
		if t.Coordinator, ok = keyMember(c, "coordinator", false); !ok {
			return bad("coordinator")
		}
		t.Roles, t.AnyIssuer, t.CountingUnit = roles, roles.AnyIssuer, roles.Unit
	} else if why, ok := readV1Roles(c, t); !ok {
		return nil, why, false
	}
	if d, present, ok := memberObject(c, "deadline"); !ok {
		return bad("deadline")
	} else if present {
		hv, has := d.Get("height")
		h, isInt := hv.(canon.Int)
		if len(d.Keys) != 1 || !has || !isInt || h < 0 {
			return bad("deadline")
		}
		t.DeadlineHeight, t.HasDeadline = int64(h), true
	}
	if v, ok := c.Get("rubric"); ok {
		a, ok := v.(canon.Array)
		if !ok {
			return bad("rubric")
		}
		for _, x := range a {
			o, ok := x.(*canon.Object)
			if !ok || slices.ContainsFunc(o.Keys, func(k string) bool { return k != "id" && k != "text" }) {
				return bad("rubric")
			}
			id, ok := stringMember(o, "id")
			if !ok || id == "" || slices.ContainsFunc(t.Rubric, func(c Criterion) bool { return c.ID == id }) {
				return bad("rubric.id")
			}
			text, ok := optString(o, "text")
			if !ok {
				return bad("rubric.text")
			}
			t.Rubric = append(t.Rubric, Criterion{ID: id, Text: text})
		}
	}
	if t.Results, ok = optString(c, "results"); !ok || (t.Results != "" && t.Results != ResultsDerived && t.Results != ResultsObserved) {
		return bad("results")
	}
	if v, ok := c.Get("quorum"); ok {
		q, why := readV1Quorum(v)
		if q == nil {
			return nil, why, false
		}
		t.Quorum = q
	}
	if p, present, ok := memberObject(c, "pins"); !ok {
		return bad("pins")
	} else if present {
		pins := &Pins{}
		if len(p.Keys) == 0 || slices.ContainsFunc(p.Keys, func(k string) bool { return k != "workflow" && k != "method_edition" && k != "inputs" }) {
			return bad("pins")
		}
		if pins.Workflow, ok = digestMember(p, "workflow"); !ok {
			return bad("pins.workflow")
		}
		if pins.MethodEdition, ok = idMember(p, "method_edition"); !ok {
			return bad("pins.method_edition")
		}
		if _, has := p.Get("inputs"); has {
			if pins.Inputs, ok = digestSet(p, "inputs"); !ok {
				return bad("pins.inputs")
			}
		}
		t.Pins = pins
	}
	if s, present, ok := memberObject(c, "sampling"); !ok {
		return bad("sampling")
	} else if present {
		ds, f := readV1Sampling(s)
		if ds == nil {
			return bad(f)
		}
		t.Sampling = ds
	}
	// Terms that can apply to no submission leave the contract unread, naming both fields (§3.3, §6 Q2).
	switch {
	case t.Quorum != nil && t.Quorum.MinGrade != "" && t.Results != ResultsDerived:
		return nil, "contract fields quorum.min_grade and results: min_grade grades derived results only, and the contract does not declare results \"derived\"", false
	case t.Results == ResultsObserved && t.Pins != nil && t.Pins.Workflow != "":
		return nil, "contract fields results and pins.workflow: a workflow pin applies to no observation result", false
	case t.Results == ResultsDerived && t.Pins != nil && t.Pins.MethodEdition != "":
		return nil, "contract fields results and pins.method_edition: a method-edition pin applies to no derived result", false
	}
	return t, "", true
}

// readV1Roles reads the rc/1 placement of the role fields (§3.2): a key beneficiary, the coordinator (in this
// order, so an rc/1 contract's first named defect is what it was), an optional counting unit (default key), and
// exactly one of a key set of eligible issuers and any_issuer.
func readV1Roles(c *canon.Object, t *Terms) (string, bool) {
	bad := func(f string) (string, bool) { return "contract field " + f + " malformed", false }
	var ok bool
	if _, has := c.Get("beneficiary"); !has {
		return "contract field beneficiary is missing", false
	}
	if t.Beneficiary, ok = keyMember(c, "beneficiary", true); !ok {
		return bad("beneficiary")
	}
	if t.Coordinator, ok = keyMember(c, "coordinator", false); !ok {
		return bad("coordinator")
	}
	if t.CountingUnit, ok = optString(c, "counting_unit"); !ok || (t.CountingUnit != "" && t.CountingUnit != CountKey && t.CountingUnit != CountIdentity) {
		return bad("counting_unit")
	}
	_, hasList := c.Get("eligible_issuers")
	av, hasAny := c.Get("any_issuer")
	switch {
	case hasList == hasAny:
		return "contract must declare exactly one of eligible_issuers and any_issuer", false
	case hasAny:
		if b, ok := av.(canon.Bool); !ok || !bool(b) {
			return bad("any_issuer")
		}
		t.AnyIssuer = true
	default:
		l, ok := keySet(c, "eligible_issuers")
		if !ok {
			return bad("eligible_issuers")
		}
		t.EligibleIssuers = l
	}
	return "", true
}

// readV1Quorum reads a task-contract-v1 `quorum` (§3.1); nil and the reason when it is malformed.
func readV1Quorum(v canon.Value) (*Quorum, string) {
	bad := func(f string) (*Quorum, string) { return nil, "contract field " + f + " malformed" }
	o, ok := v.(*canon.Object)
	if !ok {
		return bad("quorum")
	}
	for _, k := range o.Keys {
		if !slices.Contains(v1QuorumFields, k) {
			return nil, "contract field quorum." + k + " is not a " + TaskContractV1Profile + " field (an unknown field leaves the contract unread)"
		}
	}
	q := &Quorum{}
	if k, ok := o.Get("k"); !ok {
		return bad("quorum.k")
	} else if n, isInt := k.(canon.Int); !isInt || n < 1 {
		return bad("quorum.k")
	}
	q.K = intOf(o, "k")
	if q.Independence, ok = stringMember(o, "independence"); !ok ||
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
	switch {
	case q.Comparator != "" && q.Test != "":
		return nil, "contract fields quorum.comparator and quorum.test: a pinned test is the comparator, so comparator must be absent"
	case q.Estimand != "" && q.Test == "":
		return nil, "contract field quorum.estimand malformed: present only with quorum.test"
	}
	if q.MinGrade, ok = optString(o, "min_grade"); !ok || (q.MinGrade != "" && !slices.Contains([]string{"T0", "T1", "T2"}, q.MinGrade)) {
		return bad("quorum.min_grade")
	}
	g, present, ok := memberObject(o, "grouping")
	if !ok {
		return bad("quorum.grouping")
	}
	compared := q.Comparator != "" || q.Test != ""
	if present {
		rule, okRule := stringMember(g, "rule")
		var okRef bool
		q.Reference, okRef = keyMember(g, "reference", false)
		extra := slices.ContainsFunc(g.Keys, func(k string) bool { return k != "rule" && k != "reference" })
		switch {
		case !okRule || !okRef || extra:
			return bad("quorum.grouping")
		case rule == GroupAny && compared:
			return nil, "contract field quorum.grouping malformed: rule \"any\" is allowed only with neither comparator nor test"
		case (rule == GroupAllPairs || rule == GroupReference) && !compared:
			return nil, "contract field quorum.grouping malformed: rule " + rule + " needs a comparator or a test (byte equality needs no rule)"
		case rule != GroupAny && rule != GroupAllPairs && rule != GroupReference:
			return bad("quorum.grouping")
		case (rule == GroupReference) != (q.Reference != ""):
			return bad("quorum.grouping")
		}
		q.Grouping = rule
	} else if compared {
		return nil, "contract field quorum.grouping missing: a comparator or test quorum names all-pairs or reference (tolerance is not transitive)"
	}
	return q, ""
}

// readV1Sampling reads the declared sampling (§3.1: the wire-format sampling shape, n, unit and groups only);
// nil and the field when malformed.
func readV1Sampling(o *canon.Object) (*DeclaredSampling, string) {
	if slices.ContainsFunc(o.Keys, func(k string) bool { return k != "n" && k != "unit" && k != "groups" }) {
		return nil, "sampling"
	}
	nv, _ := o.Get("n")
	if !isInt(nv) {
		return nil, "sampling.n"
	}
	unit, ok := stringMember(o, "unit")
	if !ok {
		return nil, "sampling.unit"
	}
	s := &DeclaredSampling{N: intOf(o, "n"), Unit: unit}
	if v, ok := o.Get("groups"); ok {
		a, ok := v.(canon.Array)
		if !ok {
			return nil, "sampling.groups"
		}
		for _, x := range a {
			g, ok := x.(*canon.Object)
			if !ok || slices.ContainsFunc(g.Keys, func(k string) bool { return k != "name" && k != "n" }) {
				return nil, "sampling.groups"
			}
			name, ok := stringMember(g, "name")
			if !ok || slices.ContainsFunc(s.Groups, func(h SamplingGroup) bool { return h.Name == name }) {
				return nil, "sampling.groups.name"
			}
			n, ok := g.Members["n"].(canon.Int)
			if !ok {
				return nil, "sampling.groups.n"
			}
			s.Groups = append(s.Groups, SamplingGroup{Name: name, N: int(n)})
		}
	}
	return s, ""
}

// keySet reads a non-empty set of keys (sorted in the wire key order, duplicate-free).
func keySet(o *canon.Object, k string) ([]string, bool) {
	l, ok := strings_(o, k)
	if !ok || len(l) == 0 || slices.ContainsFunc(l, func(k string) bool { return !reKeyForm.MatchString(k) }) {
		return nil, false
	}
	return l, sortedSet(l)
}

// digestSet reads a non-empty set of digests.
func digestSet(o *canon.Object, k string) ([]string, bool) {
	l, ok := strings_(o, k)
	if !ok || len(l) == 0 || slices.ContainsFunc(l, func(d string) bool { return !reDigestForm.MatchString(d) }) {
		return nil, false
	}
	return l, sortedSet(l)
}

func sortedSet(l []string) bool {
	for i := 1; i < len(l); i++ {
		if canon.CompareKeys(l[i-1], l[i]) >= 0 {
			return false
		}
	}
	return true
}

// idMember reads an optional statement or edition id member (64 lowercase hex). A present non-id is malformed.
func idMember(o *canon.Object, k string) (string, bool) {
	if _, present := o.Get(k); !present {
		return "", true
	}
	s, ok := stringMember(o, k)
	return s, ok && reIDForm.MatchString(s)
}

// ContractProfiles is the production contract reader: it reads a contract by its `profile`, task-contract-v1
// with TaskContractV1 and the provisional name with ProvisionalContract (which keeps its name and its reading;
// it is never an alias of task-contract-v1). Any other profile is unread.
type ContractProfiles struct{}

// Read implements ContractReader.
func (ContractProfiles) Read(c *canon.Object) (*Terms, string, bool) {
	if c != nil && str(c, "profile") == ProvisionalProfile {
		return ProvisionalContract{}.Read(c)
	}
	if c != nil && str(c, "profile") == TaskContractV1Profile {
		return TaskContractV1{}.Read(c)
	}
	if c == nil {
		return nil, "no contract", false
	}
	v, ok := c.Get("profile")
	if !ok {
		return nil, "contract names no profile", false
	}
	return nil, fmt.Sprintf("unknown contract profile %s (this reader reads %s, and %s provisionally)", canon.Encode(v), TaskContractV1Profile, ProvisionalProfile), false
}
