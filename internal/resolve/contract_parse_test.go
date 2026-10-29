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
	pcKeyA = "0xaaaa000000000000000000000000000000000000"
	pcKeyB = "ed25519:bbbb000000000000000000000000000000000000000000000000000000000000"
	pcKeyC = "ed25519:cccc000000000000000000000000000000000000000000000000000000000000"
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

func TestProvisionalContractRubric(t *testing.T) {
	rub := func(xs ...canon.Value) canon.Value { return canon.Array(xs) }
	runPCUnread(t, []pcCase{
		{"not an array", pcContract("rubric", obj("id", "R1")), "rubric"},
		{"element string", pcContract("rubric", rub(canon.String("R1"))), "rubric"},
		{"element null", pcContract("rubric", rub(canon.Null{})), "rubric"},
		{"id missing", pcContract("rubric", rub(obj("text", "x"))), "rubric.id"},
		{"id int", pcContract("rubric", rub(obj("id", 1))), "rubric.id"},
		{"id empty", pcContract("rubric", rub(obj("id", ""))), "rubric.id"},
		{"id duplicate", pcContract("rubric", rub(obj("id", "R1"), obj("id", "R2"), obj("id", "R1", "text", "again"))), "rubric.id"},
		{"text int", pcContract("rubric", rub(obj("id", "R1", "text", 3))), "rubric.text"},
	})
}

func TestProvisionalContractEligibleIssuers(t *testing.T) {
	runPCUnread(t, []pcCase{
		{"empty", pcContract("eligible_issuers", []string{}), "eligible_issuers"},
		{"unsorted", pcContract("eligible_issuers", []string{pcKeyB, pcKeyA}), "eligible_issuers"},
		{"duplicate", pcContract("eligible_issuers", []string{pcKeyA, pcKeyA}), "eligible_issuers"},
		{"duplicate sorted", pcContract("eligible_issuers", []string{pcKeyA, pcKeyB, pcKeyB}), "eligible_issuers"},
		{"not strings", pcContract("eligible_issuers", canon.Value(canon.Array{canon.Int(1)})), "eligible_issuers"},
	})
}

func TestProvisionalContractSamplingGroups(t *testing.T) {
	smp := func(gs ...canon.Value) canon.Value {
		return obj("n", 90, "unit", "runs", "groups", canon.Value(canon.Array(gs)))
	}
	runPCUnread(t, []pcCase{
		{"groups object", pcContract("sampling", obj("n", 90, "unit", "runs", "groups", obj("name", "A", "n", 1))), "sampling.groups"},
		{"element string", pcContract("sampling", smp(canon.String("A"))), "sampling.groups"},
		{"element null", pcContract("sampling", smp(canon.Null{})), "sampling.groups"},
		{"name missing", pcContract("sampling", smp(obj("n", 30))), "sampling.groups.name"},
		{"name int", pcContract("sampling", smp(obj("name", 1, "n", 30))), "sampling.groups.name"},
		{"name duplicate", pcContract("sampling", smp(obj("name", "A", "n", 30), obj("name", "A", "n", 60))), "sampling.groups.name"},
		{"n missing", pcContract("sampling", smp(obj("name", "A"))), "sampling.groups.n"},
		{"n string", pcContract("sampling", smp(obj("name", "A", "n", "30"))), "sampling.groups.n"},
	})
}

func TestProvisionalContractDeadline(t *testing.T) {
	runPCUnread(t, []pcCase{
		{"int", pcContract("deadline", 1764547200), "deadline"},
		{"empty", pcContract("deadline", ""), "deadline"},
		{"date only", pcContract("deadline", "2026-12-01"), "deadline"},
		{"numeric offset", pcContract("deadline", "2026-12-01T00:00:00+00:00"), "deadline"},
		{"lower-case t", pcContract("deadline", "2026-12-01t00:00:00Z"), "deadline"},
		{"no zone", pcContract("deadline", "2026-12-01T00:00:00"), "deadline"},
		{"trailing zero fraction", pcContract("deadline", "2026-12-01T00:00:00.50Z"), "deadline"},
		{"prose", pcContract("deadline", "end of November"), "deadline"},
	})
	// shape only: a deadline long past still reads, kept as written
	tm, why, ok := ProvisionalContract{}.Read(pcContract("deadline", "1999-01-01T00:00:00.5Z"))
	if !ok || tm.Deadline != "1999-01-01T00:00:00.5Z" {
		t.Fatalf("a past, well-formed deadline: %v %s", ok, why)
	}
}

// TestProvisionalContractScalarTypes: a present member of the wrong type or shape is malformed, never read as
// absent or as "" (before, `str` and `intOf` turned a non-string coordinator into "no coordinator" and a
// non-digest comparator into byte equality, both weaker terms than the contract states).
func TestProvisionalContractScalarTypes(t *testing.T) {
	q := func(kv ...any) canon.Value { return quorum(2, IndependenceRequired, kv...) }
	grp := obj("rule", GroupAllPairs)
	runPCUnread(t, []pcCase{
		{"beneficiary int", pcContract("beneficiary", 7), "beneficiary"},
		{"beneficiary not a key", pcContract("beneficiary", "alice"), "beneficiary"},
		{"beneficiary upper-case hex", pcContract("beneficiary", "0xAAAA000000000000000000000000000000000000"), "beneficiary"},
		{"coordinator int", pcContract("coordinator", 5), "coordinator"},
		{"coordinator not a key", pcContract("coordinator", "K"), "coordinator"},
		{"counting_unit int", pcContract("counting_unit", 1), "counting_unit"},
		{"counting_unit unknown", pcContract("counting_unit", "person"), "counting_unit"},
		{"eligible issuer not a key", pcContract("eligible_issuers", []string{"0xaaaa"}), "eligible_issuers"},
		{"quorum.k missing", pcContract("quorum", obj("independence", IndependenceRequired)), "quorum.k"},
		{"quorum.k string", pcContract("quorum", obj("k", "2", "independence", IndependenceRequired)), "quorum.k"},
		{"quorum.k zero", pcContract("quorum", quorum(0, IndependenceRequired)), "quorum.k"},
		{"quorum.independence missing", pcContract("quorum", obj("k", 2)), "quorum.independence"},
		{"quorum.independence unknown", pcContract("quorum", quorum(2, "assumed")), "quorum.independence"},
		{"quorum.comparator int", pcContract("quorum", q("comparator", 7, "grouping", grp)), "quorum.comparator"},
		{"quorum.comparator not a digest", pcContract("quorum", q("comparator", "tol", "grouping", grp)), "quorum.comparator"},
		{"quorum.test not a digest", pcContract("quorum", q("test", "welch", "grouping", grp)), "quorum.test"},
		{"quorum.estimand int", pcContract("quorum", q("test", dig("welch-t"), "estimand", 3, "grouping", grp)), "quorum.estimand"},
		{"grouping.rule int", pcContract("quorum", q("comparator", dig("tol"), "grouping", obj("rule", 1))), "quorum.grouping"},
		{"grouping.rule unknown", pcContract("quorum", q("comparator", dig("tol"), "grouping", obj("rule", "chain"))), "quorum.grouping"},
		{"grouping.reference not a key", pcContract("quorum", q("comparator", dig("tol"), "grouping", obj("rule", GroupReference, "reference", "A"))), "quorum.grouping"},
		{"grouping.reference with all-pairs", pcContract("quorum", q("comparator", dig("tol"), "grouping", obj("rule", GroupAllPairs, "reference", pcKeyA))), "quorum.grouping"},
		{"sampling.n missing", pcContract("sampling", obj("unit", "runs")), "sampling.n"},
		{"sampling.n string", pcContract("sampling", obj("n", "30", "unit", "runs")), "sampling.n"},
		{"sampling.unit missing", pcContract("sampling", obj("n", 30)), "sampling.unit"},
		{"sampling.unit int", pcContract("sampling", obj("n", 30, "unit", 1)), "sampling.unit"},
	})
}

// TestProvisionalContractReadsWhatItChecks: the control for the checks above. The well-formed base reads with
// every term as written, so a check that refused it, or a reading that dropped a term, fails here.
func TestProvisionalContractReadsWhatItChecks(t *testing.T) {
	tm, why, ok := ProvisionalContract{}.Read(pcContract())
	if !ok {
		t.Fatalf("base unread: %s", why)
	}
	want := Terms{Profile: ProvisionalProfile, Provisional: true, Beneficiary: pcKeyA, EligibleIssuers: []string{pcKeyA, pcKeyB},
		CountingUnit: CountKey, Coordinator: pcKeyC, Deadline: "2026-12-01T00:00:00Z"}
	if tm.Profile != want.Profile || !tm.Provisional || tm.Beneficiary != want.Beneficiary || strings.Join(tm.EligibleIssuers, ",") != strings.Join(want.EligibleIssuers, ",") ||
		tm.CountingUnit != want.CountingUnit || tm.Coordinator != want.Coordinator || tm.Deadline != want.Deadline {
		t.Fatalf("terms %+v, want %+v", tm, want)
	}
	if len(tm.Rubric) != 2 || tm.Rubric[0] != (Criterion{"R1", "labels match"}) || tm.Rubric[1] != (Criterion{"R2", ""}) {
		t.Fatalf("rubric %+v", tm.Rubric)
	}
	if q := tm.Quorum; q == nil || q.K != 2 || q.Independence != IndependenceRequired || q.Comparator != dig("tol") || q.Grouping != GroupAllPairs || q.Test != "" {
		t.Fatalf("quorum %+v", tm.Quorum)
	}
	if s := tm.Sampling; s == nil || s.N != 90 || s.Unit != "runs" || len(s.Groups) != 2 || s.Groups[1] != (SamplingGroup{"B", 45}) {
		t.Fatalf("sampling %+v", tm.Sampling)
	}
	// the provisional label survives on every display
	if !strings.Contains(strings.Join(tm.describe(), "\n"), "contract profile "+ProvisionalProfile+" (PROVISIONAL reading: contract grammar pending)") {
		t.Fatalf("label lost: %v", tm.describe())
	}
}

// TestMalformedContractInTaskView: through the task view, a contract malformed in a way the old reading took
// as absent (a string grouping beside a comparator) is unread: terms unchecked naming the field, readiness
// unchecked, exit 3, and the beneficiary's decision settles nothing. The control edition with the same terms
// well-formed is ready.
func TestMalformedContractInTaskView(t *testing.T) {
	w := newWorld(t)
	g := w.task("G", "R")
	good := w.taskEdition("E1", "R", g, []string{g}, w.contract("R", "quorum", quorum(1, IndependenceNotRequired, "comparator", dig("tol"), "grouping", obj("rule", GroupAllPairs))))
	w.submit("S1", "A", g, good, "X")
	tk := taskView(t, w, g, WithComparator(newFakeComparator()))
	if rd := readinessOf(t, tk, w.ed(good)); rd.Token != Ready || tk.VerifyExit() != 0 {
		t.Fatalf("control: %s exit %d\n%s", rd.Token, tk.VerifyExit(), tk.Render())
	}
	bad := w.taskEdition("E2", "R", g, []string{good}, w.contract("R", "quorum", quorum(1, IndependenceNotRequired, "comparator", dig("tol"), "grouping", "all-pairs")))
	s2 := w.submit("S2", "A", g, bad, "X")
	w.decide("D", "R", g, bad, "accept", []string{s2})
	tk = taskView(t, w, g, WithComparator(newFakeComparator()))
	rd := readinessOf(t, tk, w.ed(bad))
	out := tk.Render()
	if rd.Token != ReadyUnchecked || tk.VerifyExit() != 3 {
		t.Fatalf("malformed grouping read: %s exit %d\n%s", rd.Token, tk.VerifyExit(), out)
	}
	has(t, out, "unchecked: contract field quorum.grouping malformed")
	for _, s := range tk.Submissions {
		if s.Statement == s2 && s.Verdict != "" {
			t.Fatalf("a decision under unread terms settled: %s\n%s", s.Verdict, out)
		}
	}
}
