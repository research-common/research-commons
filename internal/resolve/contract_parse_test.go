package resolve

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

// The provisional contract reading promises that any malformed field makes the whole contract unread, never a
// partial reading. These tests feed ProvisionalContract.Read one malformed field at a time over a well-formed
// base and require an unread contract whose reason names the field.

const (
	pcKeyA = "aaaa000000000000000000000000000000000000000000000000000000000000"
	pcKeyB = "bbbb000000000000000000000000000000000000000000000000000000000000"
	pcKeyC = "cccc000000000000000000000000000000000000000000000000000000000000"
)

// pcContract is a well-formed provisional contract with every optional field; kv replaces (or, with a nil
// value, removes) members.
func pcContract(kv ...any) *canon.Object {
	base := obj("profile", ProvisionalProfile, "beneficiary", pcKeyA, "eligible_issuers", []string{pcKeyA, pcKeyB},
		"counting_unit", CountKey, "coordinator", pcKeyC, "deadline", "2026-12-01T00:00:00Z",
		"rubric", canon.Value(canon.Array{obj("id", "R1", "text", "labels match"), obj("id", "R2")}),
		"quorum", quorum(2, IndependenceRequired, "comparator", dig("tol"), "grouping", obj("rule", GroupAllPairs)),
		"sampling", obj("n", 90, "unit", "runs", "groups", canon.Value(canon.Array{obj("name", "A", "n", 45), obj("name", "B", "n", 45)})))
	for i := 0; i < len(kv); i += 2 {
		k := kv[i].(string)
		if kv[i+1] == nil {
			delete(base.Members, k)
			for j, x := range base.Keys {
				if x == k {
					base.Keys = append(base.Keys[:j], base.Keys[j+1:]...)
					break
				}
			}
			continue
		}
		v := obj(k, kv[i+1]).Members[k]
		if _, ok := base.Members[k]; !ok {
			base.Keys = append(base.Keys, k)
		}
		base.Members[k] = v
	}
	return base
}

type pcCase struct {
	name  string
	c     *canon.Object
	field string // the field the reason must name
}

func runPCUnread(t *testing.T, cases []pcCase) {
	t.Helper()
	for _, x := range cases {
		t.Run(x.name, func(t *testing.T) {
			tm, why, ok := ProvisionalContract{}.Read(x.c)
			if ok || tm != nil {
				t.Fatalf("read a malformed contract: %+v", tm)
			}
			if !strings.Contains(why, "contract field "+x.field+" ") {
				t.Fatalf("reason %q does not name %s", why, x.field)
			}
		})
	}
}

func TestProvisionalContractControl(t *testing.T) {
	for _, c := range []*canon.Object{
		pcContract(),
		pcContract("eligible_issuers", nil, "any_issuer", true, "quorum", nil, "sampling", nil, "rubric", nil, "deadline", nil),
		pcContract("quorum", quorum(1, IndependenceNotRequired, "test", dig("welch-t"), "estimand", "mean", "grouping", obj("rule", GroupReference, "reference", pcKeyA))),
		pcContract("quorum", quorum(1, IndependenceNotRequired)),
		pcContract("sampling", obj("n", 3, "unit", "runs")),
		pcContract("rubric", canon.Value(canon.Array{})),
		pcContract("eligible_issuers", []string{pcKeyB}),
	} {
		if tm, why, ok := (ProvisionalContract{}).Read(c); !ok || tm == nil {
			t.Fatalf("a well-formed contract is unread: %s\n%s", why, canon.Encode(c))
		}
	}
}

func TestProvisionalContractObjectFields(t *testing.T) {
	runPCUnread(t, []pcCase{
		{"grouping string", pcContract("quorum", quorum(2, IndependenceRequired, "comparator", dig("tol"), "grouping", "all-pairs")), "quorum.grouping"},
		{"grouping array", pcContract("quorum", quorum(2, IndependenceRequired, "comparator", dig("tol"), "grouping", canon.Value(canon.Array{}))), "quorum.grouping"},
		{"grouping null", pcContract("quorum", quorum(2, IndependenceRequired, "comparator", dig("tol"), "grouping", canon.Value(canon.Null{}))), "quorum.grouping"},
		{"sampling string", pcContract("sampling", "90 runs"), "sampling"},
		{"sampling int", pcContract("sampling", 90), "sampling"},
		{"sampling null", pcContract("sampling", canon.Value(canon.Null{})), "sampling"},
		{"quorum int", pcContract("quorum", 2), "quorum"},
		{"quorum bool", pcContract("quorum", true), "quorum"},
	})
}

func TestProvisionalContractComparatorChoice(t *testing.T) {
	runPCUnread(t, []pcCase{
		{"grouping without comparator or test", pcContract("quorum", quorum(2, IndependenceRequired, "grouping", obj("rule", GroupAllPairs))), "quorum.grouping"},
		{"grouping reference without comparator", pcContract("quorum", quorum(2, IndependenceRequired, "grouping", obj("rule", GroupReference, "reference", pcKeyA))), "quorum.grouping"},
		{"comparator and test", pcContract("quorum", quorum(2, IndependenceRequired, "comparator", dig("tol"), "test", dig("welch-t"), "grouping", obj("rule", GroupAllPairs))), "quorum.test"},
		{"comparator and test, no grouping", pcContract("quorum", quorum(2, IndependenceRequired, "comparator", dig("tol"), "test", dig("welch-t"))), "quorum.test"},
	})
}
