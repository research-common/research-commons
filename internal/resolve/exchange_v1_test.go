package resolve

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// The claims-model exchange cases (C-exch-07 to C-exch-20) under task-contract-v1. Each test here is the v1
// counterpart of a provisional-contract test in exchange_test.go: the provisional tests check the provisional
// reading and declare nothing; these declare the case. Every task view is resolved in several delivery orders
// and must render identically (taskV1View).

// TestV1BindingsToEditions: C-exch-07. A claim (intent) and a submission bind to T1 (deadline height 200, rubric
// R1); the controller publishes T2 with a stricter rubric (R1, R2) and an earlier deadline (height 193). The T1
// submission's bound at height 197 meets T1's deadline (it would not meet T2's), and it is checked under R1
// alone; T2 applies to the later binding only; T1 still displays its own terms; no id changes.
func TestV1BindingsToEditions(t *testing.T) {
	conformance.Covers(t, "C-exch-07")
	w := newWorld(t)
	g := w.task("G", "R")
	q := quorum(1, IndependenceNotRequired)
	t1 := w.taskEdition("T1", "R", g, []string{g}, w.v1c("R", "deadline", obj("height", 200),
		"rubric", canon.Value(canon.Array{obj("id", "R1")}), "quorum", q))
	w.life("IA", "A", "intent", g, t1)
	sA := w.submit("SA", "A", g, t1, "X")
	w.anchor("anA", "A", "btc:197")
	before := []string{g, w.ed(t1)}
	t2 := w.taskEdition("T2", "R", g, []string{t1}, w.v1c("R", "deadline", obj("height", 193),
		"rubric", canon.Value(canon.Array{obj("id", "R1"), obj("id", "R2")}), "quorum", q))
	sB := w.submit("SB", "BB", g, t2, "X")
	w.anchor("anB", "BB", "btc:190")
	ev := fakeRubric{"R1/X": RuleOK, "R2/X": RuleFail}
	tk := taskV1View(t, w, g, WithRubricEvaluator(ev), WithTimeVerifier(newTipBitcoin(250, 197, 190)))
	out := tk.Render()
	a, b := subOf(t, tk, sA), subOf(t, tk, sB)
	if len(a.Rubric) != 1 || len(b.Rubric) != 2 {
		t.Fatalf("criteria: T1 binding %d, T2 binding %d, want 1 and 2\n%s", len(a.Rubric), len(b.Rubric), out)
	}
	if a.V1.Deadline != RuleOK || !strings.Contains(strings.Join(a.V1.DeadlineWhy, " "), "deadline height 200") {
		t.Fatalf("T1 binding not checked against T1's deadline: %s %v\n%s", a.V1.Deadline, a.V1.DeadlineWhy, out)
	}
	wantSub(t, tk, sA, SubCounted, "")
	wantSub(t, tk, sB, SubNotCounted, "rubric R2 fail")
	wantToken(t, tk, w, t1, Ready, 0)
	if rd := readinessOf(t, tk, w.ed(t2)); rd.Token != NotReady {
		t.Fatalf("T2 binding not judged by T2: %s\n%s", rd.Token, out)
	}
	// each binding displays its own edition's terms
	t1Terms := strings.Join(tk.Bindings[w.ed(t1)].Terms.describe(), "\n")
	has(t, t1Terms, "deadline bitcoin height 200")
	hasNot(t, t1Terms, "R2")
	has(t, strings.Join(tk.Bindings[w.ed(t2)].Terms.describe(), "\n"), "deadline bitcoin height 193")
	if tk.ID != before[0] || tk.Bindings[w.ed(t1)].Edition != before[1] || len(tk.Attempts) != 1 || tk.Attempts[0].Edition != before[1] || a.Edition != before[1] {
		t.Fatalf("an id changed\n%s", out)
	}
}

// TestV1RubricUnchecked: C-exch-08. A criterion nobody can evaluate is unchecked, with no evaluator and with one
// that evaluates only the other criterion. With a quorum the readiness is `unchecked` and verify exits 3; no
// surface says ready. Settled by review, the submission is undecided naming the criterion and the readiness
// stays `settled by review` (task-contracts note §5.6: nothing is counted, so the per-submission outcome informs
// the beneficiary and changes no exit); no rubric pass is shown.
func TestV1RubricUnchecked(t *testing.T) {
	conformance.Covers(t, "C-exch-08")
	for _, withQuorum := range []bool{true, false} {
		w := newWorld(t)
		g := w.task("G", "R")
		kv := []any{"rubric", canon.Value(canon.Array{obj("id", "R1"), obj("id", "R2")})}
		if withQuorum {
			kv = append(kv, "quorum", quorum(1, IndependenceNotRequired))
		}
		e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", kv...))
		s := w.submit("S1", "A", g, e, "X")
		for _, ev := range []RubricEvaluator{NoRubricEvaluator{}, fakeRubric{"R1/X": RuleOK}} {
			tk := taskV1View(t, w, g, WithRubricEvaluator(ev))
			out := tk.Render()
			has(t, out, "rubric R2: unchecked")
			wantSub(t, tk, s, SubUndecided, "rubric R2 unchecked")
			hasNot(t, out, ": ready")
			hasNot(t, out, "rubric check ok")
			if withQuorum {
				wantToken(t, tk, w, e, ReadyUnchecked, 3)
			} else {
				wantToken(t, tk, w, e, ByReview, 0)
			}
		}
	}
}

// TestV1IndependenceNotInferred: C-exch-09 and C-btc-19. Quorum 2 requiring independence. (a) first
// publication; (b) commit-reveal as task-contracts §6 Q4 (a) reads it: a withheld-availability commitment
// whose bound meets the deadline, then the submission; (c) one result by two keys; (d) receipt/tee/model-family
// labels; (e) three submissions, one established by the reader's verifier; (btc-19) a withheld commitment by B
// after A's bytes were public. Readiness is `unknown` in every generator, never a count; (b) shows the
// commitment as possession by T only; (d) shows the labels as the submitter's word; the explanation names the
// missing independence.
func TestV1IndependenceNotInferred(t *testing.T) {
	conformance.Covers(t, "C-exch-09", "C-btc-19")
	const h = 100
	type gen struct {
		deadline bool
		build    func(w *world, g, e string) (reveal string)
	}
	gens := map[string]gen{
		"a first publication": {false, func(w *world, g, e string) string {
			w.authored("XA", "A", "X")
			w.anchor("AA", "A", "btc:100")
			w.submit("SA", "A", g, e, "X")
			w.submit("SB", "BB", g, e, "X")
			return ""
		}},
		"b commit-reveal": {true, func(w *world, g, e string) string {
			w.submit("SA", "A", g, e, "X")
			w.anchor("anA", "A", "btc:99")
			w.authored("CB", "BB", "X", "availability", obj("redistribution", "withheld", "obtainable", false))
			w.anchor("anC", "BB", "btc:95")
			return w.submit("SB", "BB", g, e, "X")
		}},
		"c two keys one result": {false, func(w *world, g, e string) string {
			w.submit("SA", "A", g, e, "X")
			w.submit("SB", "BB", g, e, "X")
			return ""
		}},
		"d labels": {false, func(w *world, g, e string) string {
			w.submit("SA", "A", g, e, "X", "receipt", "provider-r1", "model_family", "fam-1")
			w.submit("SB", "BB", g, e, "X", "tee", "enclave-q")
			return ""
		}},
		"e one of three established": {false, func(w *world, g, e string) string {
			w.submit("SA", "A", g, e, "X")
			w.submit("SB", "BB", g, e, "X")
			w.submit("SC", "C", g, e, "X")
			return ""
		}},
		"btc-19 withheld commitment": {true, func(w *world, g, e string) string {
			w.authored("XA", "A", "X")
			w.anchor("AXA", "A", "btc:90")
			w.authored("XB", "BB", "X", "availability", obj("redistribution", "withheld", "obtainable", false))
			w.anchor("AB", "BB", "btc:100")
			w.submit("SA", "A", g, e, "X")
			w.anchor("ASA", "A", "btc:99")
			return w.submit("SB", "BB", g, e, "X")
		}},
	}
	for _, name := range sortedKeys(gens) {
		x := gens[name]
		w := newWorld(t)
		g := w.task("G", "R")
		kv := []any{"quorum", quorum(2, IndependenceRequired)}
		if x.deadline {
			kv = append(kv, "deadline", obj("height", h))
		}
		e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", kv...))
		reveal := x.build(w, g, e)
		opts := []Option{WithTimeVerifier(newTipBitcoin(120, 90, 95, 99, 100))}
		if strings.HasPrefix(name, "e") {
			opts = append(opts, WithIndependenceVerifier(indepBy{w.signer("A")})) // A's alone is established
		}
		tk := taskV1View(t, w, g, opts...)
		rd := readinessOf(t, tk, w.ed(e))
		out := tk.Render()
		if rd.Token != ReadyUnknown || rd.N != 0 || tk.VerifyExit() != 3 {
			t.Fatalf("%s: readiness %s (%d) exit %d, want unknown with no count, exit 3\n%s", name, rd.Token, rd.N, tk.VerifyExit(), out)
		}
		hasNot(t, out, "1 of 2")
		hasNot(t, out, "2 of 2")
		has(t, out, "independence of")
		has(t, out, "not established")
		if reveal != "" {
			// the commitment's verified bound meets the deadline, and shows possession by T only
			s := subOf(t, tk, reveal)
			if s.V1.Deadline != RuleOK || s.Independent {
				t.Fatalf("%s: the reveal: deadline %s, independent %v\n%s", name, s.V1.Deadline, s.Independent, out)
			}
			has(t, strings.Join(s.V1.DeadlineWhy, " "), "commitment ")
			has(t, out, "possession by T only")
		}
		if name == "d labels" {
			has(t, out, `receipt="provider-r1" (the submitter's word; no verifier checked it)`)
			has(t, out, `tee="enclave-q" (the submitter's word`)
			has(t, out, `model_family="fam-1" (the submitter's word`)
		}
	}
}

// TestV1ReceiptMismatch: the C-exch-10 reading under task-contract-v1. A receipt the verifier finds bound to
// another run, or issued by an ineligible key, fills no slot; the verifier was invoked; the mismatch is named.
func TestV1ReceiptMismatch(t *testing.T) {
	conformance.Partial(t, "C-exch-10", "no receipt format and no receipt verifier ship: the outcome is shown through a test IndependenceVerifier only (task-contract-v1 reads quorum.independence: required)")
	for _, why := range []string{"subject mismatch: receipt bound to run sha256:aaaa, not this result", "issuer outside the task's eligible issuers"} {
		w := newWorld(t)
		g := w.task("G", "R")
		e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "quorum", quorum(1, IndependenceRequired)))
		s := w.submit("SA", "A", g, e, "X", "receipt", "r")
		calls := 0
		tk := taskV1View(t, w, g, WithIndependenceVerifier(fakeIndep{ok: map[string]string{"X": why}, calls: &calls}))
		if calls == 0 {
			t.Fatal("the verifier was not invoked")
		}
		if subOf(t, tk, s).Independent {
			t.Fatalf("a slot was filled\n%s", tk.Render())
		}
		wantToken(t, tk, w, e, ReadyUnknown, 3)
		has(t, tk.Render(), why)
	}
}

// TestV1ExplicitGrouping: C-exch-12. Comparator quorum of 3; A≈B, B≈C, A≉C. all-pairs: no group of 3, not
// ready. reference (A): {A,B} groups, C diverges. No grouping rule: v1 leaves the contract unread, naming the
// missing rule, so the readiness is `unchecked`. No variant chains A–B–C.
func TestV1ExplicitGrouping(t *testing.T) {
	conformance.Covers(t, "C-exch-12")
	cmp := newPairCmp([2]string{"rA", "rB"}, [2]string{"rB", "rC"})
	for _, variant := range []string{"all-pairs", "reference", "none"} {
		w := newWorld(t)
		g := w.task("G", "R")
		kv := []any{"comparator", dig("tol")}
		switch variant {
		case "all-pairs":
			kv = append(kv, "grouping", obj("rule", GroupAllPairs))
		case "reference":
			kv = append(kv, "grouping", obj("rule", GroupReference, "reference", w.signer("A")))
		}
		e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "quorum", quorum(3, IndependenceNotRequired, kv...)))
		sa := w.submit("SA", "A", g, e, "rA")
		sb := w.submit("SB", "BB", g, e, "rB")
		sc := w.submit("SC", "C", g, e, "rC")
		tk := taskV1View(t, w, g, WithComparator(cmp))
		rd := readinessOf(t, tk, w.ed(e))
		out := tk.Render()
		for _, gr := range rd.Groups {
			if len(gr) == 3 {
				t.Fatalf("%s: chained A–B–C into one group\n%s", variant, out)
			}
		}
		switch variant {
		case "all-pairs":
			if rd.Token != NotReady || rd.N != 2 || tk.VerifyExit() != 0 {
				t.Fatalf("all-pairs: %+v\n%s", rd, out)
			}
		case "reference":
			if rd.Token != NotReady || len(rd.Groups) != 1 || !slices.Contains(rd.Groups[0], sa) || !slices.Contains(rd.Groups[0], sb) || slices.Contains(rd.Groups[0], sc) {
				t.Fatalf("reference: %+v\n%s", rd, out)
			}
			has(t, out, "diverged under comparator")
		case "none":
			if rd.Token != ReadyUnchecked || tk.VerifyExit() != 3 {
				t.Fatalf("no rule: %s exit %d\n%s", rd.Token, tk.VerifyExit(), out)
			}
			has(t, out, "quorum.grouping missing")
		}
	}
}

// TestV1PinnedTest: C-exch-13. The contract pins an estimand and a test; two batches whose intervals overlap
// fail it: `diverged` under the named test, shown as its own report; readiness not advanced.
func TestV1PinnedTest(t *testing.T) {
	conformance.Covers(t, "C-exch-13")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "quorum", quorum(2, IndependenceNotRequired,
		"estimand", "mean latency", "test", dig("welch-t"), "grouping", obj("rule", GroupAllPairs))))
	w.submit("SA", "A", g, e, "batch1")
	w.submit("SB", "BB", g, e, "batch2")
	tk := taskV1View(t, w, g, WithComparator(newPairCmp())) // the intervals overlap, the pinned test fails
	rd := wantToken(t, tk, w, e, NotReady, 0)
	if len(rd.Groups) == 1 && len(rd.Groups[0]) == 2 {
		t.Fatalf("the overlap advanced readiness\n%s", tk.Render())
	}
	has(t, tk.Render(), `diverged under test `+shortDigest(dig("welch-t"))+` on estimand "mean latency"`)
}

// TestV1DepartureCheck: C-exch-17. The v1 contract declares n = 30 runs (then groups A, B, C of 30); the
// delivered sampling (wire §5) gives conforms / departed / unchecked / not comparable, departed naming group C;
// the result's grade and verify exit are identical across all seven.
func TestV1DepartureCheck(t *testing.T) {
	conformance.Covers(t, "C-exch-17")
	grp := func(ns ...int) canon.Value {
		a := canon.Array{}
		for i, n := range ns {
			a = append(a, obj("name", string(rune('A'+i)), "n", n))
		}
		return a
	}
	cases := []struct {
		groups     bool
		del        canon.Value
		want, name string
	}{
		{false, obj("n", 30, "unit", "runs"), Conforms, ""},
		{false, obj("n", 12, "unit", "runs"), Departed, ""},
		{false, nil, DepUnchecked, ""},
		{false, obj("n", 30, "unit", "slots"), DepNotComparable, ""},
		{true, obj("n", 90, "unit", "runs", "groups", grp(30, 30, 30)), Conforms, ""},
		{true, obj("n", 72, "unit", "runs", "groups", grp(30, 30, 12)), Departed, "group C"},
		{true, obj("n", 90, "unit", "runs"), DepUnchecked, ""},
	}
	var grades []string
	for i, x := range cases {
		w := newWorld(t)
		g := w.task("G", "R")
		s := obj("n", 30, "unit", "runs")
		if x.groups {
			s = obj("n", 90, "unit", "runs", "groups", grp(30, 30, 30))
		}
		e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "sampling", canon.Value(s)))
		var kv []any
		if x.del != nil {
			kv = []any{"sampling", x.del}
		}
		w.authored("X", "A", "RES", kv...)
		w.submit("S", "A", g, e, "RES")
		tk := taskV1View(t, w, g)
		if tk.Bindings[w.ed(e)].Terms == nil || tk.Bindings[w.ed(e)].Terms.Provisional {
			t.Fatalf("case %d: not read as task-contract-v1\n%s", i, tk.Render())
		}
		sub := tk.Submissions[0]
		if sub.Departure != x.want || !strings.Contains(sub.DepartureWhy, x.name) {
			t.Fatalf("case %d: %s (%s), want %s %s", i, sub.Departure, sub.DepartureWhy, x.want, x.name)
		}
		has(t, tk.Render(), "departure check: "+x.want)
		a := w.store(nil, WithContractReader(ContractProfiles{})).Artifact(dig("RES"))
		code, _ := a.VerifyExit()
		grades = append(grades, fmt.Sprint(a.Grade, code))
	}
	if len(slices.Compact(grades)) != 1 {
		t.Fatalf("grade or exit moved: %v", grades)
	}
}

// TestV1RefutationTrack: C-exch-18. A `refutes` bound to the edition, of a submission the beneficiary accepted, is
// admitted and listed on the refutation track (in no quorum group); its evidence is graded on its own derivation
// (exempt from the weakest-link rule); credit counts it on the refutation track with its own denominator, never
// as a contribution.
func TestV1RefutationTrack(t *testing.T) {
	conformance.Covers(t, "C-exch-18")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "quorum", quorum(1, IndependenceNotRequired)))
	w.workflow("WA", "W", "bytes", "")
	w.authored("I1", "A", "I")
	w.authored("XA", "A", "X", "prov", []string{"W", "I"})
	s1 := w.submit("S1", "A", g, e, "X")
	w.decide("D", "R", g, e, "accept", []string{s1})
	w.authored("EV", "BB", "EVID", "prov", []string{"W", "X"})
	w.authored("EV2", "C", "EVID", "prov", []string{"W", "X"})
	ref := w.sign("RF", "BB", "refutes", obj("of", s1, "evidence", dig("EVID"), "task", g, "edition", w.ed(e)))
	tk := taskV1View(t, w, g)
	out := tk.Render()
	if s := subOf(t, tk, s1); s.Verdict != "accept" {
		t.Fatalf("the refuted result is not accepted: %q\n%s", s.Verdict, out)
	}
	if len(tk.Bound) != 1 || tk.Bound[0].Statement != ref || !tk.Bound[0].Counts {
		t.Fatalf("the refutation is not admitted on its track: %+v\n%s", tk.Bound, out)
	}
	has(t, out, "bound refutation "+ref[:12])
	has(t, out, "the refutation track (credited as a refutation, in no quorum group)")
	for _, gr := range readinessOf(t, tk, w.ed(e)).Groups {
		if slices.Contains(gr, ref) {
			t.Fatalf("a refutation entered a quorum group\n%s", out)
		}
	}
	r := w.store(nil, WithContractReader(ContractProfiles{}))
	ev := r.Artifact(dig("EVID"))
	has(t, ev.Render(), "exempt from the weakest-link rule")
	if ev.Grade != ev.Step {
		t.Fatalf("the refutation's evidence took the chain's weakest link: grade %v, step %v\n%s", ev.Grade, ev.Step, ev.Render())
	}
	cr := r.Credit(w.signer("BB"), &CreditRule{Name: "test", Denominators: map[string]string{"refutation": DenomAll}})
	seen := 0
	for _, cc := range cr.Counts {
		switch cc.Name {
		case "refutation":
			seen++
			if cc.N != 1 || cc.Of != 1 || cc.Denominator != DenomAll {
				t.Fatalf("refutation track %+v", cc)
			}
		case "contribution":
			seen++
			if cc.N != 0 {
				t.Fatalf("a refutation counted as a contribution %+v", cc)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("missing tracks: %+v", cr.Counts)
	}
}

// TestV1CreditProjection: the C-exch-19 reading under task-contract-v1, for `submit` submissions: separate counts
// with their denominators, rule and window shown; no default projection; nothing written. An accepted `authored`
// carrying `fulfills` (a submission, task-contracts §5.1) counts in contribution and acceptance (§6 Q5: the key's
// submissions, whatever their kind).
func TestV1CreditProjection(t *testing.T) {
	conformance.Covers(t, "C-exch-19")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R"))
	s1 := w.submit("S1", "A", g, e, "X")
	w.anchor("AA", "A", "btc:100")
	w.submit("S2", "A", g, e, "Y")
	w.submit("S3", "BB", g, e, "Z")
	w.decide("D", "R", g, e, "accept", []string{s1})
	r := w.store(nil, WithContractReader(ContractProfiles{}), WithTimeVerifier(newFakeBitcoin(100)))
	lines := len(w.lines)
	if fresh := r.Credit(w.signer("A"), nil); len(fresh.Counts) != 0 || !strings.Contains(fresh.Render(), NoProjection) {
		t.Fatalf("a default projection shipped:\n%s", fresh.Render())
	}
	all := r.Credit(w.signer("A"), &CreditRule{Name: "all", Window: AllHeld{}, Denominators: map[string]string{"acceptance": DenomOwnSubmissions}})
	win := r.Credit(w.signer("A"), &CreditRule{Name: "early", Window: HeightWindow{From: 0, To: 100}, Denominators: map[string]string{"acceptance": DenomDecided}})
	get := func(c *Credit, n string) CreditCount {
		for _, x := range c.Counts {
			if x.Name == n {
				return x
			}
		}
		t.Fatalf("no count %s", n)
		return CreditCount{}
	}
	if c := get(all, "contribution"); c.N != 2 || c.Of != 3 {
		t.Fatalf("contribution %+v", c)
	}
	if c := get(all, "acceptance"); c.N != 1 || c.Of != 2 || c.Denominator != DenomOwnSubmissions {
		t.Fatalf("acceptance %+v", c)
	}
	if c := get(win, "contribution"); c.N != 1 || c.Of != 1 {
		t.Fatalf("windowed contribution %+v\n%s", c, win.Render())
	}
	if c := get(win, "acceptance"); c.N != 1 || c.Of != 1 || c.Denominator != DenomDecided {
		t.Fatalf("windowed acceptance %+v", c)
	}
	out := all.Render()
	for _, n := range CreditCounts {
		has(t, out, "  "+n+": ")
	}
	has(t, out, "nothing transferable")
	has(t, out, `rule "all", window: all statements held (chosen by the reader)`)
	if len(w.lines) != lines {
		t.Fatal("a projection wrote a statement")
	}
	// C's accepted fulfills-carrying submission is C's contribution and acceptance
	sC := w.authored("SC", "C", "W", "fulfills", fulfills(g, w.ed(e)))
	w.decide("DC", "R", g, e, "accept", []string{sC})
	r = w.store(nil, WithContractReader(ContractProfiles{}))
	if s := subOf(t, taskV1View(t, w, g), sC); s.Verdict != "accept" {
		t.Fatalf("the fulfills submission is not accepted: %q", s.Verdict)
	}
	cc := r.Credit(w.signer("C"), &CreditRule{Name: "all", Denominators: map[string]string{"acceptance": DenomOwnSubmissions}})
	if c := get(cc, "contribution"); c.N != 1 || c.Of != 4 || !slices.Contains(c.Statements, sC) {
		t.Fatalf("contribution misses the fulfills submission %+v\n%s", c, cc.Render())
	}
	if c := get(cc, "acceptance"); c.N != 1 || c.Of != 1 {
		t.Fatalf("acceptance misses the fulfills submission %+v\n%s", c, cc.Render())
	}
	// A's counts are unchanged by C's submission, except the shared contribution denominator
	if c := get(r.Credit(w.signer("A"), &CreditRule{Name: "all"}), "contribution"); c.N != 2 || c.Of != 4 {
		t.Fatalf("A's contribution %+v", c)
	}
}

// TestV1CreditAfterSupersession: C-exch-20 under task-contract-v1: after acceptance the beneficiary supersedes it
// with a rejection; the projection changes and cites the superseding decision; the earlier decision stays in the
// credit's explain and in the task view. (Which submissions the acceptance count reads is C-exch-19's gap.)
func TestV1CreditAfterSupersession(t *testing.T) {
	conformance.Covers(t, "C-exch-20")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R"))
	s1 := w.submit("S1", "A", g, e, "X")
	d1 := w.decide("D1", "R", g, e, "accept", []string{s1})
	rule := &CreditRule{Name: "r"}
	before := w.store(nil, WithContractReader(ContractProfiles{})).Credit(w.signer("A"), rule)
	d2 := w.decide("D2", "R", g, e, "reject", []string{s1}, "supersedes", d1)
	after := w.store(nil, WithContractReader(ContractProfiles{})).Credit(w.signer("A"), rule)
	acc := func(c *Credit) int {
		for _, x := range c.Counts {
			if x.Name == "acceptance" {
				return x.N
			}
		}
		return -1
	}
	if acc(before) != 1 || acc(after) != 0 {
		t.Fatalf("acceptance %d -> %d", acc(before), acc(after))
	}
	out := after.Render()
	has(t, out, "reject by decision "+d2[:12])
	has(t, out, "decision "+d1[:12]+" (accept "+s1[:12]+") superseded by "+d2[:12])
	has(t, taskV1View(t, w, g).Render(), "accept citing "+s1[:12]+" (superseded by "+d2[:12]+")")
}
