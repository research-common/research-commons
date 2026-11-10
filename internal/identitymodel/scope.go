package identitymodel

// Kind is a closed operation registry, independent of production parser tokens.
// Root administration, raw key events, genesis and describes are not delegable.
type Kind string

const (
	Authored         Kind = "authored"
	Observed         Kind = "observed"
	Holds            Kind = "holds"
	Reproduced       Kind = "reproduced"
	Corroborates     Kind = "corroborates"
	Refutes          Kind = "refutes"
	Retracts         Kind = "retracts"
	Edition          Kind = "edition"
	WithdrawApproval Kind = "withdraw_approval"
	Intent           Kind = "intent"
	Withdraw         Kind = "withdraw"
	Progress         Kind = "progress"
	Submit           Kind = "submit"
	Decide           Kind = "decide"
	Anchors          Kind = "anchors"
)

type TargetType uint8

const (
	NoTarget TargetType = iota
	ContentTarget
	StatementTarget
	ResourceTarget
	TaskTarget
	LogTarget
)

type Target struct {
	Type TargetType
	ID   ID
	Key  Key // Used only by LogTarget.
}

type TargetMode uint8

const (
	UnspecifiedTargets TargetMode = iota
	ExactTargets
	AnyTarget // Only content and statement domains, never resource/task.
	OwnLog
)

type Permission struct {
	Kind    Kind
	Mode    TargetMode
	Targets []ID
	Amend   bool // Only authored/observed; identity-wide within these content targets.
	// AmendOwn is the `own` amend mode: only authored/observed, never together with Amend. An amendment under it
	// may name only records of the same identity signed by the exact acting key (a rotated successor does not
	// inherit), within these content targets.
	AmendOwn bool
}

type Operation struct {
	Kind   Kind
	Target Target
	Amend  bool // Adapter attests an explicit amendment; target resolution is downstream.
	// Amends are the exact amendment targets the act names (sorted). The model reads them only for an `own`
	// amend permission, whose scope depends on each target's signer and actor; every other §5.1 condition
	// (target eligibility, digest, kind, current state) belongs to the claim consumer.
	Amends []ID
}

func targetType(k Kind) TargetType {
	switch k {
	case Authored, Observed, Holds:
		return ContentTarget
	case Reproduced, Corroborates, Refutes, Retracts:
		return StatementTarget
	case Edition, WithdrawApproval:
		return ResourceTarget
	case Intent, Withdraw, Progress, Submit, Decide:
		return TaskTarget
	case Anchors:
		return LogTarget
	default:
		return NoTarget
	}
}

func checkPermissions(ps []Permission, grant ID) []Reason {
	var reasons []Reason
	add := func(code string, status Status, detail string) {
		reasons = append(reasons, Reason{Code: code, Status: status, Statement: grant, Detail: detail})
	}
	if len(ps) == 0 {
		add("empty_scope", Denied, "an empty grant never means unlimited")
	}
	seen := map[permissionKey]bool{}
	for _, p := range ps {
		domain := targetType(p.Kind)
		if domain == NoTarget {
			add("unsupported_permission", Unknown, string(p.Kind))
			continue
		}
		if (p.Amend || p.AmendOwn) && p.Kind != Authored && p.Kind != Observed {
			add("invalid_amend_permission", Denied, string(p.Kind))
		}
		if p.Amend && p.AmendOwn {
			add("invalid_amend_permission", Denied, string(p.Kind)+": two amend modes")
		}
		valid := false
		switch p.Mode {
		case ExactTargets:
			valid = domain != LogTarget && len(p.Targets) > 0
		case AnyTarget:
			valid = (domain == ContentTarget || domain == StatementTarget) && len(p.Targets) == 0
		case OwnLog:
			valid = domain == LogTarget && len(p.Targets) == 0
		}
		if !valid {
			add("invalid_scope_mode", Denied, string(p.Kind))
		}
		for i, id := range p.Targets {
			if id == "" || (i > 0 && p.Targets[i-1] == id) {
				add("invalid_scope_targets", Denied, string(p.Kind))
			}
		}
		// Length-prefixing avoids collisions even for abstract IDs containing separators.
		key := permissionKey{Kind: p.Kind, Mode: p.Mode, Amend: p.Amend, AmendOwn: p.AmendOwn, Targets: modelKey(p.Targets)}
		if seen[key] {
			add("duplicate_permission", Denied, string(p.Kind))
		}
		seen[key] = true
	}
	return reasons
}

type permissionKey struct {
	Kind     Kind
	Mode     TargetMode
	Amend    bool
	AmendOwn bool
	Targets  string
}

// lookupFact reads one fact for the scope check, accounting for it in the evaluation budget; ok is false when the
// fact is not held.
type lookupFact func(ID) (Fact, bool)

// judgeTarget evaluates an amendment target's own eligibility inside the same evaluation (one shared budget), so
// an `own` amendment of a record that is not eligible for the identity (for example one outside a cut's last_good
// prefix) is itself not eligible: #148, "every §5.1 condition holds: S is held and eligible for I".
type judgeTarget func(ID) Status

// scopeAllows reports whether some permission entry of the grant covers op by signer acting for identity. An
// entry with full authority for op (amend:true for an amendment) is matched first, without reading anything;
// an `own` amend entry is consulted only when none does, and only then are the amendment targets read
// (lookup), so a missing target never makes an act unknown that another entry already authorizes.
func scopeAllows(ps []Permission, op Operation, signer Key, identity ID, lookup lookupFact, judge judgeTarget) (bool, []Reason) {
	domain := targetType(op.Kind)
	if domain == NoTarget {
		return false, []Reason{{Code: "unsupported_operation", Status: Unknown, Detail: string(op.Kind)}}
	}
	if op.Target.Type != domain || (domain == LogTarget && (op.Target.Key != signer || op.Target.ID != "")) ||
		(domain != LogTarget && (op.Target.ID == "" || op.Target.Key != "")) ||
		(op.Amend && op.Kind != Authored && op.Kind != Observed) {
		return false, []Reason{{Code: "invalid_operation_target", Status: Denied}}
	}
	var own []Permission
	for _, p := range ps {
		if p.Kind != op.Kind || !covers(p, domain, op.Target) {
			continue
		}
		if !op.Amend || p.Amend {
			return true, nil
		}
		if p.AmendOwn {
			own = append(own, p)
		}
	}
	if len(own) == 0 {
		return false, []Reason{{Code: "scope_excluded", Status: Denied, Detail: string(op.Kind)}}
	}
	// Every own entry asks the same question of the same targets; the answer does not depend on which entry.
	status, detail := ownTargets(op, signer, identity, lookup, judge)
	switch status {
	case Eligible:
		return true, nil
	case Unknown:
		return false, []Reason{{Code: "amend_own_unresolved", Status: Unknown, Detail: detail}}
	}
	return false, []Reason{{Code: "scope_excluded", Status: Denied, Detail: string(op.Kind) + ": amend own: " + detail}}
}

func covers(p Permission, domain TargetType, t Target) bool {
	switch p.Mode {
	case AnyTarget:
		return domain == ContentTarget || domain == StatementTarget
	case OwnLog:
		return domain == LogTarget
	case ExactTargets:
		for _, id := range p.Targets {
			if id == t.ID {
				return true
			}
		}
	}
	return false
}

// ownTargets is the `own` amend mode's scope over the named targets: each must be an authenticated record whose
// signer is exactly the acting key, whose declared actor names this identity, and which is itself eligible for it
// (judge: a nested evaluation under the same budget). One target outside that is a definite denial, whatever the
// others are; otherwise a target this evidence cannot read (not held, not authenticated, or authenticated bytes
// this reader does not interpret) or whose own eligibility is undecided leaves the answer unknown. Statement ids
// cover the amends list, so targets cannot form a cycle; the shared budget bounds a long chain of amendments.
func ownTargets(op Operation, signer Key, identity ID, lookup lookupFact, judge judgeTarget) (Status, string) {
	if len(op.Amends) == 0 {
		return Denied, "no amendment target named"
	}
	status, detail := Eligible, ""
	for _, id := range op.Amends {
		f, held := lookup(id)
		switch {
		case !held:
			if status == Eligible {
				status, detail = Unknown, "target "+string(id)+" not held"
			}
		case f.Authentication != Authenticated:
			if status == Eligible {
				status, detail = Unknown, "target "+string(id)+" not authenticated"
			}
		case f.Signer != signer:
			return Denied, "target " + string(id) + " signed by another key"
		case f.Actor == nil && f.Validity != Understood:
			// Authenticated bytes this reader does not interpret: whose record it is cannot be read.
			if status == Eligible {
				status, detail = Unknown, "target "+string(id)+" not interpreted"
			}
		case f.Actor == nil || f.Actor.Identity != identity:
			return Denied, "target " + string(id) + " is not a record of this identity"
		default:
			switch judge(id) {
			case Denied:
				return Denied, "target " + string(id) + " is not eligible for this identity"
			case Unknown:
				if status == Eligible {
					status, detail = Unknown, "whether target "+string(id)+" is eligible for this identity is not established"
				}
			}
		}
	}
	return status, detail
}
