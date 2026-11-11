package resolve

import (
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// The rc/2 placement of a task edition's roles (fixed-root identity profile §5.3, task-contracts note §3.2): the
// edition's `body.x_identity_v1.task_roles` names the beneficiary, the eligible issuers (or any issuer) and the
// counting unit as typed subjects, and the contract carries none of them. The CANDIDATE profile is not active:
// the default reader never reads an rc/2 edition, so no production view reaches this file.

// taskRolesPath is where an rc/2 edition carries its roles.
const taskRolesPath = "body." + wire.IdentityCrit + ".task_roles"

// roleFields are the contract fields the rc/2 placement forbids (they live in task_roles).
var roleFields = []string{"any_issuer", "beneficiary", "counting_unit", "eligible_issuers"}

// TaskRoles are an rc/2 edition's typed roles.
type TaskRoles struct {
	Beneficiary Subject
	// Issuers are the eligible issuers; AnyIssuer admits every subject (exactly one is declared).
	Issuers   []Subject
	AnyIssuer bool
	// Unit is the counting unit: CountKey or CountIdentity, always explicit under rc/2.
	Unit string
}

// RC2ContractReader is a ContractReader that also reads the rc/2 placement: the contract without role fields and
// the edition's task roles beside it. A reader that does not implement it reads no rc/2 contract.
type RC2ContractReader interface {
	ReadRC2(contract *canon.Object, roles *TaskRoles) (t *Terms, why string, ok bool)
}

// ReadRC2 implements RC2ContractReader: task-contract-v1 is read with the edition's roles; the provisional
// reading has no rc/2 placement; any other profile is unread.
func (ContractProfiles) ReadRC2(c *canon.Object, roles *TaskRoles) (*Terms, string, bool) {
	switch {
	case c != nil && str(c, "profile") == TaskContractV1Profile:
		return TaskContractV1{}.ReadRC2(c, roles)
	case c != nil && str(c, "profile") == ProvisionalProfile:
		return nil, "the provisional reading has no rc/2 placement (its roles are contract fields, which rc/2 forbids)", false
	}
	return ContractProfiles{}.Read(c)
}

// readTaskRoles reads an rc/2 edition body's task roles; nil and why when absent or not readable. The wire
// reader has already refused a malformed object (identity_resource.go, taskRoles); this reads what it admitted.
func readTaskRoles(body *canon.Object) (*TaskRoles, string) {
	tr := object(object(body, wire.IdentityCrit), "task_roles")
	if tr == nil {
		return nil, "the rc/2 edition carries no " + taskRolesPath
	}
	r := &TaskRoles{Unit: str(tr, "counting_unit")}
	var ok bool
	if r.Beneficiary, ok = subjectOf(tr.Members["beneficiary"]); !ok {
		return nil, taskRolesPath + ".beneficiary is not a typed subject"
	}
	if v, has := tr.Get("any_issuer"); has {
		b, isBool := v.(canon.Bool)
		r.AnyIssuer = isBool && bool(b)
	}
	if a, has := tr.Get("eligible_issuers"); has {
		l, _ := a.(canon.Array)
		for _, x := range l {
			s, ok := subjectOf(x)
			if !ok {
				return nil, taskRolesPath + ".eligible_issuers holds a value that is not a typed subject"
			}
			r.Issuers = append(r.Issuers, s)
		}
	}
	if r.AnyIssuer == (len(r.Issuers) > 0) || (r.Unit != CountKey && r.Unit != CountIdentity) {
		return nil, taskRolesPath + " is not readable"
	}
	return r, ""
}

// subjectOf reads one typed subject ({key: K} or {identity: I}).
func subjectOf(v canon.Value) (Subject, bool) {
	o, ok := v.(*canon.Object)
	if !ok || len(o.Keys) != 1 {
		return Subject{}, false
	}
	s, _ := o.Members[o.Keys[0]].(canon.String)
	switch o.Keys[0] {
	case "key":
		return KeySubject(string(s)), reKeyForm.MatchString(string(s))
	case "identity":
		return IdentitySubject(string(s)), reIDForm.MatchString(string(s))
	}
	return Subject{}, false
}

// describe is the roles' lines in a terms display.
func (r *TaskRoles) describe() []string {
	out := []string{"roles from the edition's " + taskRolesPath + " (rc/2)", "beneficiary " + r.Beneficiary.String()}
	if r.AnyIssuer {
		out = append(out, "eligible issuers: any subject")
	} else {
		ss := make([]string, len(r.Issuers))
		for i, s := range r.Issuers {
			ss[i] = s.String()
		}
		out = append(out, "eligible issuers: "+strings.Join(ss, ","))
	}
	return append(out, "counting unit "+r.Unit)
}

// actorSubject is the subject a task statement acts for: the identity the counting gate binds it to, the identity
// its signed actor names when the gate binds none (claimed, never established, and never its key: profile §2.3),
// or its signing key for a bare-key statement.
func actorSubject(p *Placed, g countGate) Subject {
	switch {
	case g.Identity != "":
		return IdentitySubject(g.Identity)
	case p.IdentityContext():
		return IdentitySubject(p.St.Actor.Identity)
	}
	return KeySubject(p.St.Signer)
}

// eligibleIssuer applies the edition's issuer roles to a statement's subject: the typed roles under rc/2, the
// key list (or any issuer) under rc/1.
func (t *Terms) eligibleIssuer(s Subject) bool {
	if t.Roles != nil {
		if t.Roles.AnyIssuer {
			return true
		}
		for _, x := range t.Roles.Issuers {
			if x == s {
				return true
			}
		}
		return false
	}
	return t.AnyIssuer || (s.IsKey() && containsString(t.EligibleIssuers, s.ID))
}

// beneficiaryName is the beneficiary as a display alias.
func (t *Terms) beneficiaryName() string {
	if t.Roles != nil {
		return t.Roles.Beneficiary.String()
	}
	return shortKey(t.Beneficiary)
}

// identityCounting reports whether this edition counts by identity through an evaluator: rc/2 typed roles with
// counting unit identity and an actor evaluator configured. Without the evaluator, or under rc/1 (whose issuers are
// keys), no identity count exists (profile §5.3) and readiness is unknown.
func (r *Resolver) identityCounting(t *Terms) bool {
	return r.actors != nil && t != nil && t.Roles != nil && t.Roles.Unit == CountIdentity
}

func containsString(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// readRC2Terms reads an rc/2 task edition's contract with its task roles (profile §5.3, task-contracts §3.2).
func (r *Resolver) readRC2Terms(c, body *canon.Object) (*Terms, string) {
	rc2, ok := r.exch.contracts.(RC2ContractReader)
	if !ok {
		_, why, _ := r.exch.contracts.Read(c)
		if why == "" {
			why = "this reader's contract reader reads no rc/2 contract"
		}
		return nil, why
	}
	roles, why := readTaskRoles(body)
	if roles == nil {
		return nil, why
	}
	t, why, _ := rc2.ReadRC2(c, roles)
	return t, why
}

// isBeneficiary reports whether subject s is the edition's beneficiary: the typed beneficiary under rc/2, the
// beneficiary key under rc/1 (an identity-context decide is never its key's: profile §2.3, C-id-42).
func (t *Terms) isBeneficiary(s Subject) bool {
	if t.Roles != nil {
		return t.Roles.Beneficiary == s
	}
	return s.IsKey() && s.ID == t.Beneficiary
}

// forSubject is " for identity I" for an identity subject, "" for a key (the display of a bare-key view is
// unchanged).
func forSubject(s Subject) string {
	if s.Kind == SubjectIdentity {
		return " for " + s.String()
	}
	return ""
}

func (d *Decision) forWhom() string { return forSubject(d.Subject) }
