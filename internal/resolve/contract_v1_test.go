package resolve

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

// task-contract-v1 parse tests (task-contracts note §3): a well-formed contract reads; any malformed or unknown
// field leaves the whole contract unread, naming the field; no other profile is ever read as v1 (C-exch-03a).

const v1ID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// v1Contract is a well-formed task-contract-v1 contract with most optional fields; kv replaces (nil removes)
// members.
func v1Contract(kv ...any) *canon.Object {
	c := pcContract(append([]any{"profile", TaskContractV1Profile, "question", "does X hold?",
		"deadline", obj("height", 900000), "sampling", obj("n", 90, "unit", "runs"),
		"quorum", quorum(2, IndependenceRequired, "comparator", dig("tol"), "grouping", obj("rule", GroupAllPairs))}, kv...)...)
	return c
}

func runV1Unread(t *testing.T, cases []pcCase) {
	t.Helper()
	for _, x := range cases {
		t.Run(x.name, func(t *testing.T) {
			tm, why, ok := TaskContractV1{}.Read(x.c)
			if ok || tm != nil {
				t.Fatalf("read a malformed contract: %+v", tm)
			}
			if !strings.Contains(why, x.field) {
				t.Fatalf("reason %q does not name %s", why, x.field)
			}
			// the production reader gives the same answer
			if tm, why2, ok := (ContractProfiles{}).Read(x.c); ok || tm != nil || !strings.Contains(why2, x.field) {
				t.Fatalf("ContractProfiles differs: %q vs %q", why2, why)
			}
		})
	}
}

func TestTaskContractV1Control(t *testing.T) {
	for _, c := range []*canon.Object{
		v1Contract(),
		v1Contract("eligible_issuers", nil, "any_issuer", true, "quorum", nil, "sampling", nil, "rubric", nil, "deadline", nil, "coordinator", nil),
		v1Contract("quorum", quorum(1, IndependenceNotRequired)),
		v1Contract("quorum", quorum(3, IndependenceNotRequired, "grouping", obj("rule", GroupAny))),
		v1Contract("quorum", quorum(1, IndependenceNotRequired, "test", dig("welch"), "estimand", "mean", "grouping", obj("rule", GroupReference, "reference", pcKeyA))),
		v1Contract("results", ResultsDerived, "quorum", quorum(2, IndependenceNotRequired, "min_grade", "T1"), "pins", obj("workflow", dig("W"), "inputs", []string{dig("I1")})),
		v1Contract("results", ResultsObserved, "pins", obj("method_edition", v1ID)),
		v1Contract("pins", obj("workflow", dig("W"), "method_edition", v1ID)),
		v1Contract("sampling", obj("n", 4, "unit", "runs", "groups", canon.Value(canon.Array{obj("name", "a", "n", 2), obj("name", "b", "n", 2)}))),
	} {
		tm, why, ok := TaskContractV1{}.Read(c)
		if !ok || tm == nil {
			t.Fatalf("a well-formed contract is unread: %s\n%s", why, canon.Encode(c))
		}
		if tm.Profile != TaskContractV1Profile || tm.Provisional || tm.Question != "does X hold?" {
			t.Fatalf("terms: %+v", tm)
		}
		if tm2, _, ok := (ContractProfiles{}).Read(c); !ok || tm2.Profile != TaskContractV1Profile {
			t.Fatalf("ContractProfiles did not read v1")
		}
	}
	tm, _, _ := TaskContractV1{}.Read(v1Contract())
	if !tm.HasDeadline || tm.DeadlineHeight != 900000 || tm.Deadline != "" {
		t.Fatalf("deadline: %+v", tm)
	}
}

// C-exch-03a (a)–(e): profiles and fields the reader does not know.
func TestTaskContractV1UnknownProfileOrField(t *testing.T) {
	runV1Unread(t, []pcCase{
		{"v2 profile", v1Contract("profile", "task-contract-v2"), "task-contract-v2"},
		{"x_ field", v1Contract("x_note", "hi"), "x_note"},
		{"unknown quorum field", v1Contract("quorum", quorum(2, IndependenceRequired, "comparator", dig("tol"), "grouping", obj("rule", GroupAllPairs), "x_q", 1)), "quorum.x_q"},
		{"grouping without comparator", v1Contract("quorum", quorum(2, IndependenceRequired, "grouping", obj("rule", GroupAllPairs))), "quorum.grouping"},
		{"duplicate rubric ids", v1Contract("rubric", canon.Value(canon.Array{obj("id", "R1"), obj("id", "R1")})), "rubric.id"},
		{"no profile", v1Contract("profile", nil), "profile"},
	})
	// (e) the provisional name is never read as v1, and the production reader reads it with the provisional
	// reader (its own name, its own reading)
	pc := pcContract()
	if tm, why, ok := (TaskContractV1{}).Read(pc); ok || tm != nil || !strings.Contains(why, ProvisionalProfile) {
		t.Fatalf("provisional read as v1: %q", why)
	}
	if tm, _, ok := (ContractProfiles{}).Read(pc); !ok || !tm.Provisional || tm.Profile != ProvisionalProfile {
		t.Fatalf("ContractProfiles provisional: %+v", tm)
	}
	if _, why, ok := (ContractProfiles{}).Read(v1Contract("profile", "task-contract-v2")); ok || !strings.Contains(why, "task-contract-v2") {
		t.Fatalf("v2: %q", why)
	}
}

func TestTaskContractV1Malformed(t *testing.T) {
	runV1Unread(t, []pcCase{
		{"no question", v1Contract("question", nil), "question"},
		{"question int", v1Contract("question", 3), "question"},
		{"no beneficiary", v1Contract("beneficiary", nil), "beneficiary"},
		{"both issuers", v1Contract("any_issuer", true), "eligible_issuers and any_issuer"},
		{"neither issuers", v1Contract("eligible_issuers", nil), "eligible_issuers and any_issuer"},
		{"empty issuers", v1Contract("eligible_issuers", []string{}), "eligible_issuers"},
		{"unsorted issuers", v1Contract("eligible_issuers", []string{pcKeyB, pcKeyA}), "eligible_issuers"},
		{"any_issuer false", v1Contract("eligible_issuers", nil, "any_issuer", false), "any_issuer"},
		{"deadline string", v1Contract("deadline", "2026-12-01T00:00:00Z"), "deadline"},
		{"deadline extra", v1Contract("deadline", obj("height", 5, "time", "x")), "deadline"},
		{"deadline negative", v1Contract("deadline", obj("height", -1)), "deadline"},
		{"counting unit", v1Contract("counting_unit", "person"), "counting_unit"},
		{"results unknown", v1Contract("results", "both"), "results"},
		{"k zero", v1Contract("quorum", quorum(0, IndependenceNotRequired)), "quorum.k"},
		{"independence unknown", v1Contract("quorum", quorum(1, "maybe")), "quorum.independence"},
		{"any with comparator", v1Contract("quorum", quorum(2, IndependenceRequired, "comparator", dig("tol"), "grouping", obj("rule", GroupAny))), "quorum.grouping"},
		{"comparator without grouping", v1Contract("quorum", quorum(2, IndependenceRequired, "comparator", dig("tol"))), "quorum.grouping"},
		{"comparator and test", v1Contract("quorum", quorum(2, IndependenceRequired, "comparator", dig("tol"), "test", dig("t"), "grouping", obj("rule", GroupAllPairs))), "quorum.test"},
		{"estimand without test", v1Contract("quorum", quorum(1, IndependenceNotRequired, "estimand", "mean")), "quorum.estimand"},
		{"reference not a key", v1Contract("quorum", quorum(2, IndependenceRequired, "comparator", dig("tol"), "grouping", obj("rule", GroupReference, "reference", "bob"))), "quorum.grouping"},
		{"min_grade unknown", v1Contract("results", ResultsDerived, "quorum", quorum(1, IndependenceNotRequired, "min_grade", "T3")), "quorum.min_grade"},
		{"pins empty", v1Contract("pins", obj()), "pins"},
		{"pins unknown member", v1Contract("pins", obj("image", dig("x"))), "pins"},
		{"pins workflow not digest", v1Contract("pins", obj("workflow", "W")), "pins.workflow"},
		{"pins method_edition not id", v1Contract("pins", obj("method_edition", "E1")), "pins.method_edition"},
		{"pins inputs empty", v1Contract("pins", obj("inputs", []string{})), "pins.inputs"},
		{"sampling window", v1Contract("sampling", obj("n", 3, "unit", "runs", "window", obj())), "sampling"},
		{"sampling dup groups", v1Contract("sampling", obj("n", 2, "unit", "runs", "groups", canon.Value(canon.Array{obj("name", "a", "n", 1), obj("name", "a", "n", 1)}))), "sampling.groups.name"},
	})
}

// C-exch-08b (m1)–(m3), C-exch-15a (g): terms that apply to no submission leave the contract unread, naming
// both fields.
func TestTaskContractV1ResultsCoherence(t *testing.T) {
	for _, x := range []struct {
		name string
		c    *canon.Object
		a, b string
	}{
		{"m1 min_grade without results", v1Contract("quorum", quorum(1, IndependenceNotRequired, "min_grade", "T1")), "quorum.min_grade", "results"},
		{"min_grade with observed", v1Contract("results", ResultsObserved, "quorum", quorum(1, IndependenceNotRequired, "min_grade", "T1")), "quorum.min_grade", "results"},
		{"m2 observed + workflow pin", v1Contract("results", ResultsObserved, "pins", obj("workflow", dig("W"))), "results", "pins.workflow"},
		{"m3 derived + method_edition pin", v1Contract("results", ResultsDerived, "pins", obj("method_edition", v1ID)), "results", "pins.method_edition"},
	} {
		tm, why, ok := TaskContractV1{}.Read(x.c)
		if ok || tm != nil || !strings.Contains(why, x.a) || !strings.Contains(why, x.b) {
			t.Fatalf("%s: %v %q", x.name, ok, why)
		}
	}
}
