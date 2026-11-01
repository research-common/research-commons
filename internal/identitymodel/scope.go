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
}

type Operation struct {
	Kind   Kind
	Target Target
	Amend  bool // Adapter attests an explicit amendment; target resolution is downstream.
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
		if p.Amend && p.Kind != Authored && p.Kind != Observed {
			add("invalid_amend_permission", Denied, string(p.Kind))
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
		key := permissionKey{Kind: p.Kind, Mode: p.Mode, Amend: p.Amend, Targets: modelKey(p.Targets)}
		if seen[key] {
			add("duplicate_permission", Denied, string(p.Kind))
		}
		seen[key] = true
	}
	return reasons
}

type permissionKey struct {
	Kind    Kind
	Mode    TargetMode
	Amend   bool
	Targets string
}

func scopeAllows(ps []Permission, op Operation, signer Key) (bool, []Reason) {
	domain := targetType(op.Kind)
	if domain == NoTarget {
		return false, []Reason{{Code: "unsupported_operation", Status: Unknown, Detail: string(op.Kind)}}
	}
	if op.Target.Type != domain || (domain == LogTarget && (op.Target.Key != signer || op.Target.ID != "")) ||
		(domain != LogTarget && (op.Target.ID == "" || op.Target.Key != "")) ||
		(op.Amend && op.Kind != Authored && op.Kind != Observed) {
		return false, []Reason{{Code: "invalid_operation_target", Status: Denied}}
	}
	for _, p := range ps {
		if p.Kind != op.Kind || (op.Amend && !p.Amend) {
			continue
		}
		switch p.Mode {
		case AnyTarget:
			if domain == ContentTarget || domain == StatementTarget {
				return true, nil
			}
		case OwnLog:
			if domain == LogTarget {
				return true, nil
			}
		case ExactTargets:
			for _, id := range p.Targets {
				if id == op.Target.ID {
					return true, nil
				}
			}
		}
	}
	return false, []Reason{{Code: "scope_excluded", Status: Denied, Detail: string(op.Kind)}}
}
