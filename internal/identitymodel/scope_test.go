package identitymodel

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
)

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
	conformance.Partial(t, "C-id-45", "grant scope at the model; cross-key amendment of the principal's claims needs the claim consumer")
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
	conformance.Partial(t, "C-id-42", "the model shows a decide grant confers no role; beneficiary enforcement needs the task consumer and a contract profile")
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

// TestAmendOwnIsTheActingKeysOwnRecords: the `own` amend mode (profile §3). An amendment under it may name only
// records of the same identity signed by the exact acting key; another key's record, a record for another
// identity, or a bare record is a definite scope denial; an unheld or unauthenticated target leaves it unknown;
// content outside the entry's targets is denied before any target is read. amend:true on another entry of the
// grant answers first, without reading targets.
func TestAmendOwnIsTheActingKeysOwnRecords(t *testing.T) {
	conformance.Partial(t, "C-id-45", "the own amend mode at the model: only the acting key's records of the identity, within the content targets")
	own := Permission{Kind: Authored, Mode: ExactTargets, Targets: []ID{"content-a"}, AmendOwn: true}
	setup := func(amends ...ID) []Fact {
		fs := fixture()
		mutate(fs, "G", func(f *Fact) { f.Grant.Permissions = []Permission{own} })
		mutate(fs, "B", func(f *Fact) { f.Operation.Amend = true; f.Operation.Amends = amends })
		return fs
	}
	// A is K's record for I: eligible.
	requireStatus(t, snapshot(t, setup("A")), "B", Eligible, "")
	// No target named: an own permission covers nothing.
	requireStatus(t, snapshot(t, setup()), "B", Denied, "scope_excluded")
	// Another key's record of I.
	fs := setup("A", "O")
	o := line("O", "K2", 0, "", Data)
	o.Actor, o.Binding = &Actor{Identity: "I", Grant: "G2"}, BoundIdentityContext
	o.Operation = &Operation{Kind: Authored, Target: Target{Type: ContentTarget, ID: "content-a"}}
	r := requireStatus(t, snapshot(t, append(fs, o)), "B", Denied, "scope_excluded")
	if !strings.Contains(fmt.Sprint(r.Reasons), "signed by another key") {
		t.Fatalf("reason: %+v", r.Reasons)
	}
	// K's record for another identity J, and K's bare record.
	fs = setup("A")
	mutate(fs, "A", func(f *Fact) { f.Actor.Identity = "J" })
	requireStatus(t, snapshot(t, fs), "B", Denied, "scope_excluded")
	fs = setup("A")
	mutate(fs, "A", func(f *Fact) { f.Actor, f.Binding = nil, NoIdentityContext })
	requireStatus(t, snapshot(t, fs), "B", Denied, "scope_excluded")
	// A target the evidence does not hold, or holds unauthenticated: unknown, never a pass.
	r = requireStatus(t, snapshot(t, setup("A", "missing")), "B", Unknown, "amend_own_unresolved")
	if !slices.ContainsFunc(r.Dependencies, func(d Dependency) bool { return d.ID == "missing" && d.Purpose == "amendment target" }) {
		t.Fatalf("dependency: %+v", r.Dependencies)
	}
	fs = setup("A", "U")
	u := line("U", "K", 0, "", Data)
	u.Authentication = Unproven
	requireStatus(t, snapshot(t, append(fs, u)), "B", Unknown, "amend_own_unresolved")
	// A definite denial wins over an unresolved sibling target.
	fs = setup("missing", "O")
	requireStatus(t, snapshot(t, append(fs, o)), "B", Denied, "scope_excluded")
	// Content outside the entry's targets: denied, whatever the targets are.
	fs = setup("A")
	mutate(fs, "B", func(f *Fact) { f.Operation.Target.ID = "content-b" })
	requireStatus(t, snapshot(t, fs), "B", Denied, "scope_excluded")
	// amend:true on another entry authorizes the act without reading the targets.
	fs = setup("O-not-held")
	mutate(fs, "G", func(f *Fact) {
		f.Grant.Permissions = append(f.Grant.Permissions, Permission{Kind: Authored, Mode: AnyTarget, Amend: true})
	})
	requireStatus(t, snapshot(t, fs), "B", Eligible, "")
	// A non-amending act is ordinary publication under an own entry.
	fs = setup()
	mutate(fs, "B", func(f *Fact) { f.Operation.Amend = false })
	requireStatus(t, snapshot(t, fs), "B", Eligible, "")
	// The target's own eligibility is evaluated nested, under the act's caps: a chain B -> X -> A of own
	// amendments is eligible when every link is, and an ineligible link anywhere below denies the act.
	fs = setup("X")
	mutate(fs, "X", func(f *Fact) { f.Operation.Amend = true; f.Operation.Amends = []ID{"A"} })
	requireStatus(t, snapshot(t, fs), "B", Eligible, "")
	fs = setup("X")
	mutate(fs, "X", func(f *Fact) { f.Operation.Amend = true; f.Operation.Amends = []ID{"A"} })
	mutate(fs, "A", func(f *Fact) { f.Operation.Target.ID = "content-z" }) // outside the grant: A is denied
	r = requireStatus(t, snapshot(t, fs), "B", Denied, "scope_excluded")
	if !strings.Contains(fmt.Sprint(r.Reasons), "not eligible for this identity") {
		t.Fatalf("nested denial reason: %+v", r.Reasons)
	}
	// A link whose own eligibility is undecided (its target is not held) leaves the act unknown, naming it.
	fs = setup("X")
	mutate(fs, "X", func(f *Fact) { f.Operation.Amend = true; f.Operation.Amends = []ID{"missing"} })
	r = requireStatus(t, snapshot(t, fs), "B", Unknown, "amend_own_unresolved")
	if !strings.Contains(fmt.Sprint(r.Reasons), "eligible for this identity is not established") {
		t.Fatalf("nested unknown reason: %+v", r.Reasons)
	}
	// The nested walk shares the act's budget: a cap reached inside it is the act's model_limit, never a pass.
	fs = setup("X")
	mutate(fs, "X", func(f *Fact) { f.Operation.Amend = true; f.Operation.Amends = []ID{"A"} })
	// B's own evidence takes 28 inspections and the nested walk of X (with A) another 61 (89 in all): a cap of 60
	// is reached only inside the nested walk.
	if r := snapshot(t, fs).EvaluateWith("B", Limits{Inspections: 60}); r.Status != Unknown ||
		!slices.ContainsFunc(r.Reasons, func(x Reason) bool { return x.Code == "model_limit" }) {
		t.Fatalf("nested cap: %+v", r)
	}
	// Shape: own on another kind, or both modes on one entry, is an invalid permission.
	for _, p := range []Permission{
		{Kind: Holds, Mode: AnyTarget, AmendOwn: true},
		{Kind: Authored, Mode: AnyTarget, Amend: true, AmendOwn: true},
	} {
		fs := setup("A")
		mutate(fs, "G", func(f *Fact) { f.Grant.Permissions = []Permission{own, p} })
		requireStatus(t, snapshot(t, fs), "B", Denied, "invalid_amend_permission")
	}
}
