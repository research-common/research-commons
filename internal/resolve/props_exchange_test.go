package resolve

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
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
	tk, ok := r.Task(tw.g)
	if !ok {
		return "task not resolved\n"
	}
	b.WriteString(tk.Render())
	fmt.Fprintf(&b, "counts: submissions=%d decisions=%d attempts=%d grants=%d bound=%d refutations=%d exit=%d\n",
		len(tk.Submissions), len(tk.Decisions), len(tk.Attempts), len(tk.Grants), len(tk.Bound), len(tk.Refutations), tk.VerifyExit())
	for _, s := range tk.Submissions {
		fmt.Fprintf(&b, "submission %s counts=%v eligible=%v verdict=%s refuted=%d", keylog.Short(s.Statement), s.Counts, s.Eligible, s.Verdict, len(s.Refuted))
		if s.V1 != nil {
			fmt.Fprintf(&b, " v1=%s current=%v retracted=%d", s.V1.State, s.V1.Current, len(s.V1.Retracted))
		}
		b.WriteString("\n")
	}
	for _, rd := range tk.Readiness {
		fmt.Fprintf(&b, "readiness %s %s n=%d k=%d groups=%d\n", keylog.Short(rd.Edition), rd.Token, rd.N, rd.K, len(rd.Groups))
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
