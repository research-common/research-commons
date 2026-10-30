package identitymodel

import "testing"

func TestClosedScopeRegistry(t *testing.T) {
	// This expected registry is intentionally explicit, not derived from targetType.
	registry := []struct {
		kind     Kind
		domain   TargetType
		wildcard bool
	}{
		{Authored, ContentTarget, true}, {Observed, ContentTarget, true}, {Holds, ContentTarget, true},
		{Reproduced, StatementTarget, true}, {Corroborates, StatementTarget, true},
		{Refutes, StatementTarget, true}, {Retracts, StatementTarget, true},
		{Edition, ResourceTarget, false}, {WithdrawApproval, ResourceTarget, false},
		{Intent, TaskTarget, false}, {Withdraw, TaskTarget, false}, {Progress, TaskTarget, false},
		{Submit, TaskTarget, false}, {Decide, TaskTarget, false},
	}
	for _, entry := range registry {
		t.Run(string(entry.kind), func(t *testing.T) {
			build := func(mode TargetMode, target ID, domain TargetType) *Snapshot {
				fs := fixture()
				mutate(fs, "G", func(f *Fact) {
					p := Permission{Kind: entry.kind, Mode: mode}
					if mode == ExactTargets {
						p.Targets = []ID{"exact-subject"}
					}
					f.Grant.Permissions = []Permission{p}
				})
				mutate(fs, "A", func(f *Fact) {
					f.Operation = &Operation{Kind: entry.kind, Target: Target{Type: domain, ID: target}}
				})
				return snapshot(t, fs)
			}
			requireStatus(t, build(ExactTargets, "exact-subject", entry.domain), "A", Eligible, "")
			requireStatus(t, build(ExactTargets, "other-subject", entry.domain), "A", Denied, "scope_excluded")
			requireStatus(t, build(ExactTargets, "exact-subject", NoTarget), "A", Denied, "invalid_operation_target")
			if entry.wildcard {
				requireStatus(t, build(AnyTarget, "other-subject", entry.domain), "A", Eligible, "")
			} else {
				requireStatus(t, build(AnyTarget, "exact-subject", entry.domain), "A", Denied, "invalid_scope_mode")
			}
		})
	}
}

func TestAnchorsAreOnlyTheSignersOwnLog(t *testing.T) {
	fs := fixture()
	mutate(fs, "G", func(f *Fact) { f.Grant.Permissions = []Permission{{Kind: Anchors, Mode: OwnLog}} })
	mutate(fs, "A", func(f *Fact) { f.Operation = &Operation{Kind: Anchors, Target: Target{Type: LogTarget, Key: "K"}} })
	requireStatus(t, snapshot(t, fs), "A", Eligible, "")
	mutate(fs, "A", func(f *Fact) { f.Operation.Target.Key = "other-K" })
	requireStatus(t, snapshot(t, fs), "A", Denied, "invalid_operation_target")
}

func TestScopeIsExplicitAndFailClosed(t *testing.T) {
	cases := []struct {
		name        string
		permissions []Permission
		status      Status
		code        string
	}{
		{"empty", nil, Denied, "empty_scope"},
		{"absent mode", []Permission{{Kind: Authored}}, Denied, "invalid_scope_mode"},
		{"empty exact", []Permission{{Kind: Authored, Mode: ExactTargets}}, Denied, "invalid_scope_mode"},
		{"wildcard plus targets", []Permission{{Kind: Authored, Mode: AnyTarget, Targets: []ID{"content-a"}}}, Denied, "invalid_scope_mode"},
		{"duplicate targets", []Permission{{Kind: Authored, Mode: ExactTargets, Targets: []ID{"content-a", "content-a"}}}, Denied, "invalid_scope_targets"},
		{"empty target", []Permission{{Kind: Authored, Mode: ExactTargets, Targets: []ID{"content-a", ""}}}, Denied, "invalid_scope_targets"},
		{"duplicate permissions", []Permission{{Kind: Authored, Mode: AnyTarget}, {Kind: Authored, Mode: AnyTarget}}, Denied, "duplicate_permission"},
		{"unknown alongside allowed", []Permission{{Kind: Authored, Mode: AnyTarget}, {Kind: "new-kind", Mode: AnyTarget}}, Unknown, "unsupported_permission"},
		{"root administration not delegable", []Permission{{Kind: Authored, Mode: AnyTarget}, {Kind: "root-administration", Mode: AnyTarget}}, Unknown, "unsupported_permission"},
		{"wrong kind", []Permission{{Kind: Observed, Mode: AnyTarget}}, Denied, "scope_excluded"},
		{"separate same-kind exact entries", []Permission{{Kind: Authored, Mode: ExactTargets, Targets: []ID{"content-b"}}, {Kind: Authored, Mode: ExactTargets, Targets: []ID{"content-a"}}}, Eligible, ""},
		{"amend flag on unrelated permission", []Permission{{Kind: Authored, Mode: AnyTarget}, {Kind: Submit, Mode: ExactTargets, Targets: []ID{"task"}, Amend: true}}, Denied, "invalid_amend_permission"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := mutate(fixture(), "G", func(f *Fact) { f.Grant.Permissions = tc.permissions })
			requireStatus(t, snapshot(t, fs), "A", tc.status, tc.code)
		})
	}
}

func TestAmendPermissionIsExplicitAndIdentityWideWithinContentScope(t *testing.T) {
	for _, kind := range []Kind{Authored, Observed} {
		fs := fixture()
		mutate(fs, "G", func(f *Fact) { f.Grant.Permissions[0].Kind = kind })
		mutate(fs, "A", func(f *Fact) { f.Operation.Kind = kind; f.Operation.Amend = true })
		requireStatus(t, snapshot(t, fs), "A", Denied, "scope_excluded")
		mutate(fs, "G", func(f *Fact) { f.Grant.Permissions[0].Amend = true })
		requireStatus(t, snapshot(t, fs), "A", Eligible, "")
		// The permission test takes no "previous delegate" or same-grant qualifier.
		// Same-principal/content target resolution MUST occur in the state consumer.
		mutate(fs, "A", func(f *Fact) { f.Operation.Target.ID = "outside-scope" })
		requireStatus(t, snapshot(t, fs), "A", Denied, "scope_excluded")
	}
}

func TestGrantEligibilityDoesNotPretendToImplementRoles(t *testing.T) {
	// No resource controller or task beneficiary is represented in these facts.
	// Eligibility says only that the named operation/target is in the grant;
	// consuming engines must still enforce their roles and evidence rules.
	for _, op := range []Operation{
		{Kind: Edition, Target: Target{Type: ResourceTarget, ID: "resource"}},
		{Kind: Decide, Target: Target{Type: TaskTarget, ID: "task"}},
	} {
		fs := fixture()
		mutate(fs, "G", func(f *Fact) {
			f.Grant.Permissions = []Permission{{Kind: op.Kind, Mode: ExactTargets, Targets: []ID{op.Target.ID}}}
		})
		mutate(fs, "A", func(f *Fact) { f.Operation = &op })
		requireStatus(t, snapshot(t, fs), "A", Eligible, "")
	}
}
