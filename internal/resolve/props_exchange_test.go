package resolve

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/fixture"
	"github.com/research-common/research-commons/internal/keylog"
)

// This file is the property tests' fixture language for the exchange view: tasks, their lifecycle statements
// and the credit projection. An abstract fixture (internal/conformance/fixture, drawn over the task kinds) is
// signed into a task world; taskSnapshot renders every answer the exchange view gives about it. P-01, P-02 and
// P-03 over the exchange view are written against these two functions.

// taskKinds are the abstract kinds a task fixture draws. Each is interpreted by concretizeTask; the signer, the
// blob, the time and the Of reference of the abstract statement pick the concrete variant.
var taskKinds = []string{"intent", "progress", "withdraw", "submit", "submit", "submit", "decide", "decide",
	"grant", "refutes", "retracts", "anchors", "authored"}

// taskFixtureOpts draws over four keys (two secp256k1), three result blobs, and the task kinds. Extended is
// set so refutes and retracts carry an Of reference.
var taskFixtureOpts = fixture.Options{Keys: 4, Blobs: 3, MaxStatements: 14, Extended: true, Kinds: taskKinds}

// taskWorld is a concretized task fixture.
type taskWorld struct {
	*world
	g     string   // the task genesis
	eds   []string // the edition statements (by name), authorized by the beneficiary R
	subs  []string // submission statement ids, in fixture order
	kinds map[string]string
}

// The contract variants a seed picks (seed % len): each reads a different part of the exchange view.
var taskContracts = []string{"v1 quorum 2", "v1 self-declared + rubric", "provisional quorum 2", "v1 coordinator", "v1 eligible issuers", "v1 by review"}

func (tw *taskWorld) contract(variant string) *canon.Object {
	w := tw.world
	switch variant {
	case "v1 quorum 2":
		return w.v1c("R", "quorum", quorum(2, IndependenceNotRequired))
	case "v1 self-declared + rubric":
		return w.v1c("R", "quorum", quorum(2, IndependenceSelfDeclared), "rubric", canon.Value(canon.Array{obj("id", "c1")}))
	case "provisional quorum 2":
		return w.contract("R", "quorum", quorum(2, IndependenceNotRequired))
	case "v1 coordinator":
		return w.v1c("R", "coordinator", w.signer("KK"), "quorum", quorum(1, IndependenceNotRequired))
	case "v1 eligible issuers":
		return w.v1c("R", "eligible_issuers", w.issuers("A", "BB", "C"), "quorum", quorum(2, IndependenceNotRequired))
	}
	return w.v1c("R")
}

// concretizeTask signs a task fixture. The base: task G by beneficiary R, an edition E1 under the seed's contract
// variant, and for one seed in three a successor E2 under another variant (so submissions bind to a superseded
// edition too). Every abstract statement then becomes a lifecycle statement on G (or, for authored, a claim
// that may carry fulfills).
func concretizeTask(t *testing.T, f fixture.Fixture) *taskWorld {
	t.Helper()
	w := newWorld(t)
	tw := &taskWorld{world: w, kinds: map[string]string{}}
	tw.g = w.task("G", "R")
	v := taskContracts[f.Seed%uint64(len(taskContracts))]
	tw.eds = append(tw.eds, w.taskEdition("E1", "R", tw.g, []string{tw.g}, tw.contract(v)))
	if f.Seed%3 == 0 {
		v2 := taskContracts[(f.Seed+1)%uint64(len(taskContracts))]
		tw.eds = append(tw.eds, w.taskEdition("E2", "R", tw.g, []string{tw.eds[0]}, tw.contract(v2)))
	}
	ed := func(s fixture.Statement) string { return tw.eds[s.Time%len(tw.eds)] }
	// the submission a decide, grant, refutes or retracts names: its Of when that is a held submission, else
	// the latest one held, else an id nobody holds
	subOf := func(s fixture.Statement) string {
		if id, ok := w.ids[s.Of]; ok && tw.kinds[s.Of] == "submit" {
			return id
		}
		if len(tw.subs) > 0 {
			return tw.subs[(s.Time)%len(tw.subs)]
		}
		return unheldID("sub " + s.Label)
	}
	intentEd := map[string]string{}
	for i, s := range f.Statements {
		label := s.Label
		if label == "" {
			label = fmt.Sprint("s", i)
		}
		tw.kinds[label] = s.Kind
		k := propKeys[s.Signer]
		result := "r" + s.Blob
		switch s.Kind {
		case "intent":
			intentEd[k] = ed(s)
			w.life(label, k, s.Kind, tw.g, ed(s))
		case "progress", "withdraw":
			e := ed(s)
			if _, ok := intentEd[k]; !ok && s.Time%2 == 0 {
				// half the time an attempt is opened first, so progress and withdraw continue something
				intentEd[k] = e
				w.life("intent:"+label, k, "intent", tw.g, e)
			}
			if x, ok := intentEd[k]; ok && s.Time%4 != 0 {
				e = x // mostly continuing the signer's own attempt; sometimes another edition's
			}
			w.life(label, k, s.Kind, tw.g, e)
		case "submit":
			var kv []any
			if s.Time%5 == 0 {
				kv = append(kv, "self_declared_independence", true)
			}
			if s.Time%7 == 0 {
				kv = append(kv, "salt", dig("salt "+label))
			}
			tw.subs = append(tw.subs, w.submit(label, k, tw.g, ed(s), result, kv...))
		case "decide":
			by := "R" // the beneficiary, mostly; a non-beneficiary's decide is shown and settles nothing
			if s.Time%4 == 3 {
				by = k
			}
			var kv []any
			if prev := w.ids["last-decide"]; prev != "" && s.Time%3 == 0 {
				kv = append(kv, "supersedes", prev)
			}
			id := w.decide(label, by, tw.g, ed(s), []string{"accept", "reject"}[s.Time%2], []string{subOf(s)}, kv...)
			if by == "R" {
				w.ids["last-decide"] = id
			}
		case "grant":
			by := "KK" // the coordinator of the "v1 coordinator" variant; another key's grant has no effect
			if s.Time%3 == 0 {
				by = k
			}
			w.grant(label, by, tw.g, w.ed(ed(s)), propKeys[string(rune('A'+s.Time%4))])
		case "refutes":
			kv := []any{"of", subOf(s), "evidence", dig("E")}
			if s.Time%2 == 0 {
				kv = append(kv, "task", tw.g, "edition", w.ed(ed(s)))
			}
			w.sign(label, k, "refutes", obj(kv...))
		case "retracts":
			w.sign(label, k, "retracts", obj("of", subOf(s)))
		case "anchors":
			if w.head[k] != "" {
				w.anchor(label, k, fmt.Sprint("btc:", 100+s.Time%3))
			}
		case "authored":
			var kv []any
			if s.Time%2 == 0 {
				kv = append(kv, "fulfills", fulfills(tw.g, w.ed(ed(s))))
			}
			w.authored(label, k, result, kv...)
		}
	}
	return tw
}

// taskKeyNames are every key a task world signs with.
var taskKeyNames = []string{"A", "BB", "C", "DD", "R", "KK"}

// taskOpts are the exchange view's reader options for the property tests: both contract readings, a time
// verifier for the anchors, and a rubric evaluator that passes c1 for result rX, fails it for rV (so the rubric is ok,
// fail and unchecked across a fixture).
func taskOpts() []Option {
	return []Option{WithContractReader(ContractProfiles{}), WithTimeVerifier(newFakeBitcoin(100, 101, 102)),
		WithRubricEvaluator(fakeRubric{"c1/rX": RuleOK, "c1/rV": RuleFail})}
}

// creditRules are the projections every snapshot renders for every key: every denominator, the whole held set
// and a height window.
var creditRules = []*CreditRule{
	{Name: "all", Window: AllHeld{}, Denominators: map[string]string{"acceptance": DenomOwnSubmissions}},
	{Name: "decided", Window: AllHeld{}, Denominators: map[string]string{"acceptance": DenomDecided, "contribution": DenomOwnSubmissions}},
	{Name: "early", Window: HeightWindow{From: 0, To: 101}},
}

// taskSnapshot renders every answer of the exchange view: the task (bindings, attempts, grants, every
// submission with its state, decisions, refutations, readiness with its counts and groups, verify exit,
// explanation), the counts behind it as numbers, and each key's credit under every rule.
func (tw *taskWorld) taskSnapshot(r *Resolver) string {
	var b strings.Builder
	if tk, ok := r.Task(tw.g); ok {
		taskAnswers(&b, tk)
	} else {
		b.WriteString("task not held\n") // the genesis withheld: the credit projections below are still answers
	}
	for _, k := range taskKeyNames {
		for _, rule := range creditRules {
			c := r.Credit(tw.signer(k), rule)
			b.WriteString(c.Render())
			for _, cc := range c.Counts {
				fmt.Fprintf(&b, "  %s %s n=%d of=%d\n", rule.Name, cc.Name, cc.N, cc.Of)
			}
		}
	}
	return b.String()
}

func taskAnswers(b *strings.Builder, tk *Task) {
	b.WriteString(tk.Render())
	fmt.Fprintf(b, "counts: submissions=%d decisions=%d attempts=%d grants=%d bound=%d refutations=%d exit=%d\n",
		len(tk.Submissions), len(tk.Decisions), len(tk.Attempts), len(tk.Grants), len(tk.Bound), len(tk.Refutations), tk.VerifyExit())
	for _, s := range tk.Submissions {
		fmt.Fprintf(b, "submission %s counts=%v eligible=%v verdict=%s refuted=%d", keylog.Short(s.Statement), s.Counts, s.Eligible, s.Verdict, len(s.Refuted))
		if s.V1 != nil {
			fmt.Fprintf(b, " v1=%s current=%v retracted=%d", s.V1.State, s.V1.Current, len(s.V1.Retracted))
		}
		b.WriteString("\n")
	}
	for _, rd := range tk.Readiness {
		fmt.Fprintf(b, "readiness %s %s n=%d k=%d groups=%d\n", keylog.Short(rd.Edition), rd.Token, rd.N, rd.K, len(rd.Groups))
	}
}

func (tw *taskWorld) answers(t *testing.T, lines [][]byte) string {
	t.Helper()
	return tw.taskSnapshot(New(storeOf(t, lines), taskOpts()...))
}

// asProp is the task world as a propWorld, for the shared delivery helpers (deliver, reencodings).
func (tw *taskWorld) asProp() *propWorld { return &propWorld{world: tw.world} }

// taskOrders is the delivery orders a task world is checked under: every permutation up to six lines (the
// convention of everyOrder and everyOrderArtifact), else the file order plus a seeded sample.
func taskOrders(n int, seed uint64, k int) [][]int {
	if n <= 6 {
		return permutations(n)
	}
	return append([][]int{nil}, sampleOrders(n, seed, k)...)
}

// TestTaskGeneratorReachesViews guards the exchange-view property tests against a generator that never reaches
// what they claim to check: over the seeds they use, the snapshots must contain each answer at least once.
func TestTaskGeneratorReachesViews(t *testing.T) {
	want := map[string]string{
		"a counted submission":            " v1=counted",
		"an undecided submission":         " v1=undecided",
		"a not-counted submission":        " v1=not counted",
		"a provisional submission":        "submission ",
		"a ready edition":                 ": ready (",
		"a not-ready edition":             ": not ready (",
		"an unknown readiness":            ": unknown",
		"settled by review":               ByReview,
		"an accepted submission":          "verdict=accept",
		"a rejected submission":           "verdict=reject",
		"a superseded decision":           "superseded by",
		"a non-beneficiary decision":      "not the edition's beneficiary",
		"contested decisions":             "decisions: contested",
		"a counted grant":                 "  grant ",
		"a grant of no effect":            "is not the edition's coordinator",
		"a bound refutation":              "bound=1",
		"a retracted submission":          "retracted=1",
		"an attempt withdrawn":            "withdrawn by",
		"activity evidence":               "activity evidence",
		"a fulfills submission":           "carrying fulfills",
		"a superseded edition binding":    "superseded",
		"a credit acceptance":             "acceptance n=1",
		"a credit contribution":           "contribution n=2",
		"a credit outside the window":     "outside the window",
		"a self-declared independence":    "independence self-declared",
		"a rubric failure":                "rubric c1: fail",
		"a rubric pass":                   "rubric c1: ok",
		"a salted submission":             "salt",
		"a current submission superseded": "current=false",
	}
	seen := map[string]bool{}
	for i := 0; i < taskPropSeeds; i++ {
		tw := concretizeTask(t, fixture.Gen(taskPropBase+uint64(i), taskFixtureOpts))
		snap := tw.answers(t, tw.lines)
		for name, sub := range want {
			if strings.Contains(snap, sub) {
				seen[name] = true
			}
		}
	}
	var miss []string
	for name := range want {
		if !seen[name] {
			miss = append(miss, fmt.Sprintf("%s (%q)", name, want[name]))
		}
	}
	slices.Sort(miss)
	if len(miss) > 0 {
		t.Errorf("no generated task fixture reached: %s", strings.Join(miss, "; "))
	}
}

const (
	taskPropBase  = 9100
	taskPropSeeds = 40
)

// TestPropertyExchangeDuplicatesAndEncodings: P-02 over the exchange view. Every line of a generated task world
// delivered twice, and once more in every equivalent signature encoding its writer could have produced (v as
// 0/1, high s, for the secp256k1 keys), in the file order and in sampled orders: the resolver holds one
// statement per body, and every answer of the task view (submission, decision, attempt and grant counts,
// readiness n and k, verify exit) and of every credit projection (each count's n and denominator) is the one of
// the single delivery. The control: one genuinely new submission (a new body) does change the counts, so the
// snapshot sees a count when there is one.
func TestPropertyExchangeDuplicatesAndEncodings(t *testing.T) {
	// with TestPropertyDuplicatesAndEncodings (corroborations, members and every other view over the same
	// deliveries) and the wire layer's one id per body (internal/wire), every count the case names is checked
	conformance.Covers(t, "P-02")
	reencoded := 0
	fixture.Check(t, taskPropBase+1000, taskPropSeeds, taskFixtureOpts, func(f fixture.Fixture) string {
		tw := concretizeTask(t, f)
		pw := tw.asProp()
		once := tw.answers(t, tw.lines)
		held := len(New(storeOf(t, tw.lines), taskOpts()...).byID)
		var many [][]byte
		forms := pw.reencodings(t)
		reencoded += len(forms) - len(tw.lines)
		for _, ln := range forms {
			many = append(many, ln, ln)
		}
		for _, o := range append([][]int{nil}, sampleOrders(len(many), f.Seed, 2)...) {
			lines := many
			if o != nil {
				lines = make([][]byte, len(o))
				for i, j := range o {
					lines[i] = many[j]
				}
			}
			r := New(storeOf(t, lines), taskOpts()...)
			if len(r.byID) != held {
				return fmt.Sprintf("duplicates or re-encodings changed the number of statements held: %d, want %d", len(r.byID), held)
			}
			if got := tw.taskSnapshot(r); got != once {
				return "duplicates or re-encodings changed an exchange answer: " + firstDiff(once, got)
			}
		}
		return ""
	})
	if reencoded == 0 {
		t.Fatal("no line was re-encoded: the secp256k1 keys signed nothing, so the encoding half is vacuous")
	}
	// control: a new submission body is a new statement and moves the counts
	tw := concretizeTask(t, fixture.Gen(taskPropBase+1000, taskFixtureOpts))
	before := tw.answers(t, tw.lines)
	tw.submit("ctl", "C", tw.g, tw.eds[0], "rCTL")
	if after := tw.answers(t, tw.lines); after == before || !strings.Contains(firstDiff(before, after), "submission") {
		t.Fatalf("a new submission changed no exchange answer: the snapshot does not see the counts\n%s", firstDiff(before, after))
	}
}

// TestPropertyExchangeOrderInvariance: P-01 over the exchange view. A generated task world delivered in the
// file order and in sampled delivery orders (every order up to six lines): every answer of the task view
// (bindings, attempts, grants, submissions with their state and verdict, decisions and supersession,
// refutations, readiness with n, k and groups, verify exit) and every credit projection is identical. The
// control: a decision that settles differently (a reject in place of an accept) changes the snapshot, so it
// sees the derived answers it compares.
func TestPropertyExchangeOrderInvariance(t *testing.T) {
	// with TestPropertyOrderInvariance (the six resolver views), TestPropertyOrderInvarianceMixedMajors and
	// internal/gate.TestPropertyGateOrderInvariance (every gate, object order and transport order), every
	// derived answer the case names is checked; orders are every permutation up to six lines, else seeded samples
	conformance.Covers(t, "P-01")
	fixture.Check(t, taskPropBase, taskPropSeeds, taskFixtureOpts, func(f fixture.Fixture) string {
		tw := concretizeTask(t, f)
		pw := tw.asProp()
		first := tw.answers(t, tw.lines)
		for _, o := range taskOrders(len(tw.lines), f.Seed, propOrders) {
			if got := tw.answers(t, pw.deliver(o)); got != first {
				return "order " + sprintOrder(o) + " changed an exchange answer: " + firstDiff(first, got)
			}
		}
		return ""
	})
	// control: the same world with one more submission and the beneficiary's accept, against the same with a
	// reject: the snapshots differ in the verdict and in the credit
	mk := func(verdict string) string {
		tw := concretizeTask(t, fixture.Gen(taskPropBase, taskFixtureOpts))
		s := tw.submit("ctl", "C", tw.g, tw.eds[0], "rCTL")
		tw.decide("ctlD", "R", tw.g, tw.eds[0], verdict, []string{s})
		return tw.answers(t, tw.lines)
	}
	if a, r := mk("accept"), mk("reject"); a == r || !strings.Contains(a, "verdict=accept") {
		t.Fatal("an accept and a reject give one snapshot: the harness does not reach the decisions")
	}
}

// taskDecision is every part of the task view a reader acts on, without the explanation: the resource decision,
// each submission's counting state and verdict, each decision's counting and supersession, each grant that
// counts, readiness with its counts, and the verify exit.
func taskDecision(tk *Task) string {
	var b strings.Builder
	b.WriteString(resourceDecision(tk.Resource))
	for _, s := range tk.Submissions {
		fmt.Fprintf(&b, "sub %s counts=%v eligible=%v granted=%s verdict=%s", s.Statement, s.Counts, s.Eligible, s.Granted, s.Verdict)
		if s.V1 != nil {
			fmt.Fprintf(&b, " v1=%s current=%v", s.V1.State, s.V1.Current)
		}
		b.WriteString("\n")
	}
	for _, d := range tk.Decisions {
		if d.Counts { // a decision that counts toward nothing is listed for the reader, and decides nothing
			fmt.Fprintf(&b, "dec %s by=%s\n", d.Statement, d.SupersededBy)
		}
	}
	for _, g := range tk.Grants {
		fmt.Fprintf(&b, "grant %s %s\n", g.Statement, g.Grantee)
	}
	for _, rd := range tk.Readiness {
		fmt.Fprintf(&b, "ready %s %s n=%d k=%d groups=%v check=%s\n", rd.Edition, rd.Token, rd.N, rd.K, rd.Groups, rd.Check)
	}
	fmt.Fprintf(&b, "conflict=%v exit=%d\n", tk.DecisionConflict, tk.VerifyExit())
	return b.String()
}

// creditNumerators is each fixture key's credit under every rule, without the "all" denominators: a count's
// numerator, and its denominator when that is the key's own (own submissions, decided). DenomAll is every
// counted statement of the kind by any key, so any new statement of the kind moves it by its definition (the
// reader chose a denominator over everyone); that is a bearing on the reader's predicate, not interference.
func (tw *taskWorld) creditNumerators(r *Resolver) string {
	var b strings.Builder
	for _, k := range taskKeyNames {
		for _, rule := range creditRules {
			for _, cc := range r.Credit(tw.signer(k), rule).Counts {
				fmt.Fprintf(&b, "%s %s %s n=%d", k, rule.Name, cc.Name, cc.N)
				if cc.Denominator != DenomAll {
					fmt.Fprintf(&b, " of=%d", cc.Of)
				}
				b.WriteString("\n")
			}
		}
	}
	return b.String()
}

// taskOutsider is the outsider key of the exchange P-03: it signs nothing in a task fixture.
const taskOutsider = "QQ"

// taskOutsideAdditions are statements of the outsider with no authority over task G and no bearing on any
// answer about it: the kinds P-03 names (holds, describes, a rival authored on another blob) and every
// lifecycle kind aimed at another task.
func taskOutsideAdditions() []addition {
	other := func(pw *propWorld) (string, string) {
		g := pw.task("OG", "OR")
		return g, pw.taskEdition("OE", "OR", g, []string{g}, pw.v1c("OR", "quorum", quorum(1, IndependenceNotRequired)))
	}
	return []addition{
		{"holds an unrelated blob", func(pw *propWorld) { pw.sign("L", taskOutsider, "holds", obj("content", contentOf("ZZ"))) }},
		{"describes an unrelated blob", func(pw *propWorld) {
			pw.sign("L", taskOutsider, "describes", obj("about", obj("content", dig("ZZ")), "note", "n"))
		}},
		{"authors an unrelated blob", func(pw *propWorld) { pw.authored("L", taskOutsider, "ZZ", "licence", "MIT") }},
		{"authors a derived unrelated blob (a rival citation)", func(pw *propWorld) {
			pw.authored("L", taskOutsider, "ZZ", "prov", []string{"W", "ZI"})
		}},
		{"authors a fixture result blob, carrying no fulfills", func(pw *propWorld) { pw.authored("L", taskOutsider, "rX") }},
		{"anchors its own log", func(pw *propWorld) {
			pw.authored("LA", taskOutsider, "ZZ")
			pw.anchor("L", taskOutsider, "btc:101")
		}},
		{"rotates its own key", func(pw *propWorld) { pw.sign("L", taskOutsider, "rotate_key", obj("successor", pw.signer("QZ"))) }},
		{"intends, progresses and withdraws on another task", func(pw *propWorld) {
			g, e := other(pw)
			pw.life("LI", taskOutsider, "intent", g, e)
			pw.life("LP", taskOutsider, "progress", g, e)
			pw.life("L", taskOutsider, "withdraw", g, e)
		}},
		{"submits to another task, and that task's beneficiary accepts", func(pw *propWorld) {
			g, e := other(pw)
			s := pw.submit("LS", taskOutsider, g, e, "rX")
			pw.decide("L", "OR", g, e, "accept", []string{s})
		}},
		{"is granted on another task", func(pw *propWorld) {
			g, e := other(pw)
			pw.grant("L", "OR", g, pw.ed(e), taskOutsider)
		}},
	}
}

// TestPropertyExchangeNonInterference: P-03 over the exchange view. For each generated task world S and each
// statement L of an outsider key with no authority over task G and no bearing on it (taskOutsideAdditions),
// the task view of S+L equals that of S, explanation included, and every credit numerator (and own denominator)
// of every fixture key is unchanged. A second class names G but comes from a key with no authority (a decide by
// a non-beneficiary, a grant by a non-coordinator, a withdraw and a progress with no intent, a decide that
// supersedes the beneficiary's decision): the decision (taskDecision) is unchanged, and the explanation shows
// the statement attributed to the outsider. Control: a decide by the beneficiary on a fresh submission does
// change the decision, so the harness reaches the view.
func TestPropertyExchangeNonInterference(t *testing.T) {
	// the last view P-03 names: with authorship (TestNonInterferenceProperty), resources, membership and
	// observations (props_noninterference_test.go), rc/2 additions (TestPropertyNonInterferenceMixedMajors) and
	// the gates (P-04, internal/gate.TestPropertyNoThirdPartyVeto), every view is checked. A credit count over
	// the "all" denominator is excluded by definition (PROPS-F6): it counts every key's statements of a kind.
	conformance.Covers(t, "P-03")
	for _, a := range taskOutsideAdditions() {
		t.Run(a.name, func(t *testing.T) {
			fixture.Check(t, taskPropBase+3000, 20, taskFixtureOpts, func(f fixture.Fixture) string {
				before := concretizeTask(t, f)
				r0 := New(storeOf(t, before.lines), taskOpts()...)
				tk0, _ := r0.Task(before.g)
				after := concretizeTask(t, f)
				n := len(after.lines)
				a.add(after.asProp())
				if len(after.lines) == n {
					return "the addition signed nothing"
				}
				r1 := New(storeOf(t, after.lines), taskOpts()...)
				tk1, _ := r1.Task(after.g)
				if tk0.Render() != tk1.Render() {
					return "the task view changed:\n" + firstDiff(tk0.Render(), tk1.Render())
				}
				if c0, c1 := before.creditNumerators(r0), after.creditNumerators(r1); c0 != c1 {
					return "a credit count changed:\n" + firstDiff(c0, c1)
				}
				return ""
			})
		})
	}

	t.Run("outsider statements naming the task decide nothing", func(t *testing.T) {
		fixture.Check(t, taskPropBase+3100, 20, taskFixtureOpts, func(f fixture.Fixture) string {
			tw := concretizeTask(t, f)
			read := func() *Task {
				tk, _ := New(storeOf(t, tw.lines), taskOpts()...).Task(tw.g)
				return tk
			}
			d0 := taskDecision(read())
			e := tw.eds[0]
			sub := unheldID("none")
			if len(tw.subs) > 0 {
				sub = tw.subs[0]
			}
			for i, add := range []func() string{
				func() string { return tw.decide(fmt.Sprint("Q", 0), taskOutsider, tw.g, e, "reject", []string{sub}) },
				func() string { return tw.grant("Q1", taskOutsider, tw.g, tw.ed(e), taskOutsider) },
				func() string { return tw.life("Q2", taskOutsider, "withdraw", tw.g, e) },
				func() string { return tw.life("Q3", taskOutsider, "progress", tw.g, e, "note", "heartbeat") },
				func() string {
					if d := tw.ids["last-decide"]; d != "" {
						return tw.decide("Q4", taskOutsider, tw.g, e, "reject", []string{sub}, "supersedes", d)
					}
					return tw.decide("Q4", taskOutsider, tw.g, e, "accept", []string{sub})
				},
			} {
				id := add()
				tk := read()
				if d := taskDecision(tk); d != d0 {
					return fmt.Sprintf("outsider statement %d changed the decision on the task:\n%s", i, firstDiff(d0, d))
				}
				// a decide and a grant are listed, attributed to the outsider; withdraw and progress with no intent
				// continue no attempt and are not listed (nothing they could be attributed to)
				if (i == 0 || i == 1 || i == 4) && !strings.Contains(tk.Render(), keylog.Short(id)) {
					return fmt.Sprintf("outsider statement %d is not shown in the task view:\n%s", i, tk.Render())
				}
			}
			return ""
		})
	})

	t.Run("control: the beneficiary's decision bears on the task", func(t *testing.T) {
		tw := concretizeTask(t, fixture.Gen(taskPropBase+3000, taskFixtureOpts))
		s := tw.submit("ctl", "C", tw.g, tw.eds[0], "rCTL")
		tk0, _ := New(storeOf(t, tw.lines), taskOpts()...).Task(tw.g)
		tw.decide("ctlD", "R", tw.g, tw.eds[0], "accept", []string{s})
		tk1, _ := New(storeOf(t, tw.lines), taskOpts()...).Task(tw.g)
		if taskDecision(tk0) == taskDecision(tk1) {
			t.Fatal("the beneficiary's accept changed no decision: the harness does not reach the task view")
		}
	})

	// PROPS-F6, pinned: the one credit answer an outsider's derived blob moves is a denominator over every key
	// (DenomAll), which is why creditNumerators leaves it out. If this stops holding, the exclusion can go.
	t.Run("an outsider's derived blob moves only the all-keys citation denominator", func(t *testing.T) {
		tw := concretizeTask(t, fixture.Gen(taskPropBase+3000, taskFixtureOpts))
		rule := &CreditRule{Name: "all", Window: AllHeld{}}
		count := func() CreditCount {
			for _, c := range New(storeOf(t, tw.lines), taskOpts()...).Credit(tw.signer("A"), rule).Counts {
				if c.Name == "citation" {
					return c
				}
			}
			return CreditCount{}
		}
		c0 := count()
		tw.authored("L", taskOutsider, "ZZ", "prov", []string{"W", "ZI"})
		c1 := count()
		if c1.N != c0.N || c1.Of != c0.Of+1 || c1.Denominator != DenomAll {
			t.Fatalf("citation before %+v, after %+v: want the numerator unchanged and the all-keys denominator one more", c0, c1)
		}
	})
}

// TestPropertyExchangeWithheldClaimsNoAbsence: P-12 over the exchange view. For each generated task world and
// each of its statements withheld in turn (a submission, a decision, a grant, a refutation, a retraction, an
// edition, a withdraw...), the task view and every credit projection computed from the rest claim no absence
// of what the reader never received, and a projection says it is chosen by the reader over what it holds. The
// scope itself is printed once per view by the CLI (TestStatusScopeFooter); this is the resolver's wording.
// Control: completenessClaim does match a rendering that claims absence, so the check is not vacuous.
func TestPropertyExchangeWithheldClaimsNoAbsence(t *testing.T) {
	conformance.Partial(t, "P-12", "the exchange view: the task view and every credit projection claim no absence with each statement of a generated task world withheld in turn; internal/cli.TestWithheldEditionAndContradictionAreScoped covers the case")
	if !completenessClaim.MatchString("readiness: no other statements") || !completenessClaim.MatchString("no newer edition") {
		t.Fatal("completenessClaim matches nothing it should: the check is vacuous")
	}
	withheld := 0
	fixture.Check(t, taskPropBase+5000, 24, taskFixtureOpts, func(f fixture.Fixture) string {
		tw := concretizeTask(t, f)
		for i := range tw.lines {
			lines := slices.Delete(slices.Clone(tw.lines), i, i+1)
			snap := tw.answers(t, lines)
			withheld++
			// "all statements held" is the AllHeld window's label: scoped by its own last word, not a claim
			if m := completenessClaim.FindString(strings.ReplaceAll(snap, "all statements held", "")); m != "" {
				return fmt.Sprintf("with line %d withheld the exchange view claims %q:\n%s", i, m, snap)
			}
			if !strings.Contains(snap, "(chosen by the reader)") {
				return "a credit projection does not say it is the reader's choice"
			}
		}
		return ""
	})
	if withheld == 0 {
		t.Fatal("nothing was withheld")
	}
}
