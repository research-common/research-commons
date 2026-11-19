package resolve

import (
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// P-09 over the exchange's delegated checks: the rubric evaluator, the independence verifier and the grant
// reader (with the coordinator's wire `grant`), and the time verifier under a task deadline. Each row has a
// control where the check, configured and honest, makes the edition ready (verify exit 0), and variants where
// the check is missing, unsupported, failing or lying; for each variant the readiness is read from the task view
// and must not be `ready` with a passing check, and the task's verify exit must be non-zero or the token must be
// the weak one. The rows run under both contract readings where both read the term.

// constRubric answers one outcome, with a reason, for every criterion and submission.
type constRubric struct {
	o   Outcome
	why string
}

func (c constRubric) Evaluate(Criterion, *wire.Statement) (Outcome, string) { return c.o, c.why }

// constIndep answers one verdict for every submission.
type constIndep struct {
	ok  bool
	why string
}

func (c constIndep) Independent(*wire.Statement, *Terms) (bool, string) { return c.ok, c.why }

// strong is the answer a reader may rest on: the edition ready, a rubric (when any) checked ok, verify exit 0.
func strong(tk *Task, rd *Readiness) bool {
	return rd.Token == Ready && (rd.Check == "" || rd.Check == RuleOK) && tk.VerifyExit() == 0
}

type exchP09Row struct {
	name     string
	world    func(t *testing.T, w *world) (g, e string)
	reader   ContractReader
	control  []Option
	variants map[string][]Option
}

func TestPropertyExchangeVerifiersNeverPass(t *testing.T) {
	rubric := func(reader string) func(t *testing.T, w *world) (string, string) {
		return func(t *testing.T, w *world) (string, string) {
			g := w.task("G", "R")
			crit := canon.Value(canon.Array{obj("id", "c1")})
			c := w.v1c("R", "rubric", crit, "quorum", quorum(2, IndependenceNotRequired))
			if reader == "provisional" {
				c = w.contract("R", "rubric", crit, "quorum", quorum(2, IndependenceNotRequired))
			}
			e := w.taskEdition("E", "R", g, []string{g}, c)
			w.submit("SA", "A", g, e, "X")
			w.submit("SB", "BB", g, e, "X")
			return g, e
		}
	}
	indep := func(reader string) func(t *testing.T, w *world) (string, string) {
		return func(t *testing.T, w *world) (string, string) {
			g := w.task("G", "R")
			c := w.v1c("R", "quorum", quorum(2, IndependenceRequired))
			if reader == "provisional" {
				c = w.contract("R", "quorum", quorum(2, IndependenceRequired))
			}
			e := w.taskEdition("E", "R", g, []string{g}, c)
			w.submit("SA", "A", g, e, "X")
			w.submit("SB", "BB", g, e, "X")
			return g, e
		}
	}
	rows := []exchP09Row{}
	for _, rd := range []string{"v1", "provisional"} {
		reader := ContractReader(ContractProfiles{})
		rows = append(rows,
			exchP09Row{name: rd + " rubric", world: rubric(rd), reader: reader,
				control: []Option{WithRubricEvaluator(constRubric{RuleOK, "evaluated"})},
				variants: map[string][]Option{
					"missing (default evaluator)": nil,
					"unsupported (unchecked)":     {WithRubricEvaluator(constRubric{RuleUnchecked, "criterion format not supported"})},
					"failing":                     {WithRubricEvaluator(constRubric{RuleFail, "does not meet c1"})},
					"lying (ok for other bytes)":  {WithRubricEvaluator(fakeRubric{"c1/Y": RuleOK})},
				}},
			exchP09Row{name: rd + " independence", world: indep(rd), reader: reader,
				control: []Option{WithIndependenceVerifier(constIndep{true, "bound proof verified"})},
				variants: map[string][]Option{
					"missing (default verifier)":           nil,
					"failing":                              {WithIndependenceVerifier(constIndep{false, "receipt bound to another run"})},
					"lying (established for one key only)": {WithIndependenceVerifier(indepBy{"nobody"})},
				}},
		)
	}
	// the coordinator's grant (the wire kind, read by the resolver; a GrantReader reads only its own format)
	coord := func(grantBy string, extra func(w *world, g, e string)) func(t *testing.T, w *world) (string, string) {
		return func(t *testing.T, w *world) (string, string) {
			g := w.task("G", "R")
			e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "coordinator", w.signer("K"), "quorum", quorum(1, IndependenceNotRequired)))
			if grantBy != "" {
				w.grant("gA", grantBy, g, w.ed(e), "A")
			}
			if extra != nil {
				extra(w, g, e)
			}
			w.submit("SA", "A", g, e, "X")
			return g, e
		}
	}
	// a grant reader reading another format: a grant in it signed by a non-coordinator must not count, however the
	// reader reads it (the fake format: a describes about the task with tags ["grant", grantee, edition])
	rows = append(rows, exchP09Row{name: "v1 coordinator grant: another format, by a non-coordinator",
		world: coord("", func(w *world, g, e string) {
			w.sign("D", "X", "describes", obj("about", obj("resource", g), "tags", []string{"grant", w.signer("A"), w.ed(e)}))
		}), reader: ContractProfiles{}, control: nil,
		variants: map[string][]Option{"lying grant reader": {WithGrantReader(fakeGrants{})}}})
	// the grant itself substituted: missing, by a non-coordinator, naming another edition, for another key
	for name, w := range map[string]func(t *testing.T, w *world) (string, string){
		"missing (no grant)":          coord("", nil),
		"failing (a non-coordinator)": coord("X", nil),
		"naming the genesis, not E": func(t *testing.T, w *world) (string, string) {
			g, e := coord("", nil)(t, w)
			w.grant("gG", "K", g, g, "A")
			return g, e
		},
		"for another key than the submitter": func(t *testing.T, w *world) (string, string) {
			g, e := coord("", nil)(t, w)
			w.grant("gB", "K", g, w.ed(e), "BB")
			return g, e
		},
	} {
		rows = append(rows, exchP09Row{name: "v1 coordinator grant: " + name, world: w, reader: ContractProfiles{}, control: nil, variants: map[string][]Option{"": nil}})
	}
	// a deadline: the time verifier under the deadline height
	deadline := func(t *testing.T, w *world) (string, string) {
		g := w.task("G", "R")
		e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "deadline", obj("height", 100), "quorum", quorum(1, IndependenceNotRequired)))
		w.submit("SA", "A", g, e, "X")
		w.anchor("anA", "A", "btc:97")
		return g, e
	}
	pend := newTipBitcoin(120)
	pend.pending[dig("btc:97")] = true
	rows = append(rows, exchP09Row{name: "v1 deadline", world: deadline, reader: ContractProfiles{},
		control: []Option{WithTimeVerifier(newTipBitcoin(120, 97))},
		variants: map[string][]Option{
			"missing (default verifier)":          nil,
			"failing (verifies no proof)":         {WithTimeVerifier(failingBitcoin{})},
			"unsupported (pending, not verified)": {WithTimeVerifier(pend)},
			"verified after the deadline":         {WithTimeVerifier(newTipBitcoin(120, 105))},
		}})
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			read := func(opts []Option) (*Task, *Readiness) {
				w := newWorld(t)
				g, e := row.world(t, w)
				tk, ok := w.store(nil, append([]Option{WithContractReader(row.reader)}, opts...)...).Task(g)
				if !ok {
					t.Fatal("task not resolved")
				}
				return tk, readinessOf(t, tk, w.ed(e))
			}
			if row.control == nil {
				// a substituted statement, no reader option: the control is the world with the coordinator's grant
				w := newWorld(t)
				g, e := coord("K", nil)(t, w)
				tk, _ := w.store(nil, WithContractReader(ContractProfiles{})).Task(g)
				if rd := readinessOf(t, tk, w.ed(e)); !strong(tk, rd) {
					t.Fatalf("grant control did not reach ready:\n%s", tk.Render())
				}
			} else if tk, rd := read(row.control); !strong(tk, rd) {
				t.Fatalf("control did not reach ready with a passing check (%s, check %s, exit %d):\n%s", rd.Token, rd.Check, tk.VerifyExit(), tk.Render())
			}
			for name, opts := range row.variants {
				if tk, rd := read(opts); strong(tk, rd) {
					t.Errorf("%s: ready with a passing check on evidence that is not verified (%s, check %s, exit %d):\n%s", name, rd.Token, rd.Check, tk.VerifyExit(), tk.Render())
				}
			}
		})
	}
}

// TestFindingRubricOutcomeOutsideVocabulary: PROPS-F7, a P-09 counterexample against current code. A rubric
// evaluator that answers a token outside {ok, fail, unchecked} ("pass") is read as passing: under
// task-contract-v1 the submission is counted with no reason and the edition is ready (verify exit 0); under the
// provisional reading the rubric check reads `ok`. Edition rules normalise such a token to `unchecked` naming it
// (edition_rules.go, "not a rule outcome"); the rubric path (task.go readiness, task_v1.go v1State) has no such
// guard. No evaluator ships (NoRubricEvaluator is the only one), so the CLI never reaches it; a reader extension
// that plugs one in does. Minimal: one criterion c1, quorum 2, two submissions of one result, the evaluator
// answering "pass" for every criterion. Seedless (no generator involved).
func TestFindingRubricOutcomeOutsideVocabulary(t *testing.T) {
	for _, reading := range []string{"v1", "provisional"} {
		w := newWorld(t)
		g := w.task("G", "R")
		crit := canon.Value(canon.Array{obj("id", "c1")})
		c := w.v1c("R", "rubric", crit, "quorum", quorum(2, IndependenceNotRequired))
		if reading == "provisional" {
			c = w.contract("R", "rubric", crit, "quorum", quorum(2, IndependenceNotRequired))
		}
		e := w.taskEdition("E", "R", g, []string{g}, c)
		w.submit("SA", "A", g, e, "X")
		w.submit("SB", "BB", g, e, "X")
		tk, _ := w.store(nil, WithContractReader(ContractProfiles{}), WithRubricEvaluator(constRubric{"pass", "looks fine"})).Task(g)
		if rd := readinessOf(t, tk, w.ed(e)); strong(tk, rd) {
			t.Errorf("%s: a rubric outcome outside the vocabulary made the edition ready (%s, check %q, exit %d):\n%s", reading, rd.Token, rd.Check, tk.VerifyExit(), tk.Render())
		}
	}
}

// TestFindingDeadlineMetByUnplacedBound: PROPS-F8, a P-09 counterexample against current code. A time verifier
// that returns a Bitcoin-quality bound with no network and no height (optimisticBitcoin: quality claimed, no
// position) meets any task-contract-v1 deadline: meets() (task_v1.go) tests b.verified() && b.Height <= h, and
// height 0 is at or below every deadline. The priority path refuses the same bound (P-09 row "time verifier",
// variant "claims Bitcoin quality, no height": same-block, no default). The shipped btctime verifier always sets
// network and height on a verified bound, so only a reader-supplied verifier reaches it. Minimal: deadline at
// height 100, one submission anchored once, quorum 1. Seedless.
func TestFindingDeadlineMetByUnplacedBound(t *testing.T) {
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "deadline", obj("height", 100), "quorum", quorum(1, IndependenceNotRequired)))
	w.submit("SA", "A", g, e, "X")
	w.anchor("anA", "A", "btc:97")
	tk, _ := w.store(nil, WithContractReader(ContractProfiles{}), WithTimeVerifier(optimisticBitcoin{})).Task(g)
	if s := tk.Submissions[0]; s.V1.Deadline == RuleOK {
		t.Errorf("an unplaced bound met the deadline:\n%s", tk.Render())
	}
}
