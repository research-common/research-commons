package resolve

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/wire"
)

// --- fixture language for tasks -----------------------------------------------------------------------------

// task signs a task genesis by `by`, controlled by `by` alone.
func (w *world) task(name, by string) string {
	return w.sign(name, by, "genesis", obj("type", "task", "name", "t", "controllers", []string{w.signer(by)}, "rule", obj("any_one", true)))
}

// taskEdition signs an edition of task g after preds carrying contract c (nil: no contract).
func (w *world) taskEdition(name, by, g string, preds []string, c *canon.Object) string {
	var p []string
	for _, x := range preds {
		p = append(p, w.ed(x))
	}
	slices.Sort(p)
	contents := obj()
	if c != nil {
		contents = obj("contract", canon.Value(c))
	}
	return w.sign(name, by, "edition", obj("resource", g, "predecessors", p, "contents", contents))
}

// contract is a provisional contract with beneficiary `ben` and any issuer; kv adds or replaces fields.
func (w *world) contract(ben string, kv ...any) *canon.Object {
	base := []any{"profile", ProvisionalProfile, "beneficiary", w.signer(ben)}
	if !slices.Contains(kv, any("eligible_issuers")) {
		base = append(base, "any_issuer", true)
	}
	return obj(append(base, kv...)...)
}

func quorum(k int, indep string, kv ...any) canon.Value {
	return obj(append([]any{"k", k, "independence", indep}, kv...)...)
}

// life signs a lifecycle statement of kind on task g, edition e (a statement name); kv adds body fields.
func (w *world) life(name, by, kind, g, e string, kv ...any) string {
	return w.sign(name, by, kind, obj(append([]any{"task", g, "edition", w.ed(e)}, kv...)...))
}

func (w *world) submit(name, by, g, e, result string, kv ...any) string {
	return w.life(name, by, "submit", g, e, append([]any{"result", dig(result)}, kv...)...)
}

func (w *world) decide(name, by, g, e, verdict string, subs []string, kv ...any) string {
	return w.life(name, by, "decide", g, e, append([]any{"submissions", subs, "verdict", verdict}, kv...)...)
}

// signTS is sign with an explicit ts.
func (w *world) signTS(name, n, kind, ts string, body *canon.Object) string {
	k := w.key(n)
	s := w.seq[n]
	line, id := wire.Sign(wire.Draft{Kind: kind, Seq: s, Prev: w.head[n], TS: ts, Body: body}, k)
	w.head[n], w.seq[n] = id, s+1
	w.lines = append(w.lines, line)
	w.ids[name] = id
	w.by[id] = n
	return id
}

// taskView resolves task g under file order plus sampled delivery orders and requires one rendering.
func taskView(t *testing.T, w *world, g string, opts ...Option) *Task {
	t.Helper()
	opts = append([]Option{WithContractReader(ProvisionalContract{})}, opts...)
	var first *Task
	var out string
	for _, o := range append([][]int{nil}, sampleOrders(len(w.lines), uint64(len(w.lines))*31, 12)...) {
		tk, ok := w.store(o, opts...).Task(g)
		if !ok {
			t.Fatalf("task %s not resolved", g)
		}
		if first == nil {
			first, out = tk, tk.Render()
		} else if got := tk.Render(); got != out {
			t.Fatalf("order %v changed the task view:\n%s\nvs\n%s", o, got, out)
		}
	}
	return first
}

func readinessOf(t *testing.T, tk *Task, edition string) *Readiness {
	t.Helper()
	for _, rd := range tk.Readiness {
		if rd.Edition == edition {
			return rd
		}
	}
	t.Fatalf("no readiness for %s\n%s", edition, tk.Render())
	return nil
}

// fakeGrants reads a grant out of a `describes` about the task whose tags are ["grant", grantee, edition]: a
// test stand-in, because the wire format has no grant kind.
type fakeGrants struct{}

func (fakeGrants) Grant(st *wire.Statement) (Grant, bool) {
	if st.Kind != "describes" {
		return Grant{}, false
	}
	tags, _ := strings_(st.Body, "tags")
	if len(tags) != 3 || tags[0] != "grant" {
		return Grant{}, false
	}
	return Grant{Task: str(object(st.Body, "about"), "resource"), Grantee: tags[1], Edition: tags[2]}, true
}

// fakeRubric answers per criterion and result name.
type fakeRubric map[string]Outcome

func (f fakeRubric) Evaluate(c Criterion, st *wire.Statement) (Outcome, string) {
	for k, o := range f {
		parts := strings.SplitN(k, "/", 2)
		if parts[0] == c.ID && dig(parts[1]) == str(st.Body, "result") {
			return o, "fake evaluation"
		}
	}
	return RuleUnchecked, "missing evidence for " + c.ID
}

// fakeIndep establishes independence for submissions whose result is in ok, records every call, and explains
// a mismatch for the rest (a receipt bound to another run, or issued by an ineligible key).
type fakeIndep struct {
	ok    map[string]string // result name -> "" (established) or the mismatch explanation
	calls *int
}

func (f fakeIndep) Independent(st *wire.Statement, _ *Terms) (bool, string) {
	*f.calls++
	for name, why := range f.ok {
		if dig(name) == str(st.Body, "result") {
			if why == "" {
				return true, "bound proof verified"
			}
			return false, why
		}
	}
	return false, NoIndependenceWhy
}

// pairCmp matches exactly the listed unordered pairs of result names (non-transitive by construction).
type pairCmp map[[2]string]bool

func newPairCmp(pairs ...[2]string) pairCmp {
	p := pairCmp{}
	for _, x := range pairs {
		a, b := dig(x[0]), dig(x[1])
		p[[2]string{min(a, b), max(a, b)}] = true
	}
	return p
}

func (p pairCmp) Compare(_, a, b string) (string, string) {
	if p[[2]string{min(a, b), max(a, b)}] {
		return "match", ""
	}
	return "diverged", ""
}

// --- §9.1 lifecycle -----------------------------------------------------------------------------------------

// TestIntentsAreAdvisory: C-exch-01. A and B intend on one edition (as if partitioned); B and C (no intent)
// submit. Both intents are shown with no exclusion; every submission is admissible, listed and counted.
func TestIntentsAreAdvisory(t *testing.T) {
	conformance.Covers(t, "C-exch-01")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.contract("R", "quorum", quorum(2, IndependenceNotRequired)))
	w.life("IA", "A", "intent", g, e)
	w.life("IB", "BB", "intent", g, e)
	w.submit("SB", "BB", g, e, "X")
	w.submit("SC", "C", g, e, "X")
	tk := taskView(t, w, g)
	out := tk.Render()
	if len(tk.Attempts) != 2 || len(tk.Submissions) != 2 {
		t.Fatalf("intents/submissions not all listed\n%s", out)
	}
	has(t, out, "advisory: excludes nobody")
	hasNot(t, out, "not counted")
	if rd := readinessOf(t, tk, w.ed(e)); rd.Token != Ready || rd.N != 2 {
		t.Fatalf("readiness %+v\n%s", rd, out)
	}
	has(t, out, "ready (2 of 2, "+CountedAs+")")
	// with no contract reader at all, the same intents and submissions are listed and admissible
	tk2, _ := w.store(nil).Task(g)
	if len(tk2.Submissions) != 2 || !strings.Contains(tk2.Render(), "admissible") {
		t.Fatalf("no reader:\n%s", tk2.Render())
	}
}

// TestHeartbeatsAreNotLeases: C-exch-02. A intends, heartbeats past the contract's deadline; a silent intent;
// no coordinator. Progress is activity evidence; nothing expires; other submissions stay admissible.
func TestHeartbeatsAreNotLeases(t *testing.T) {
	conformance.Covers(t, "C-exch-02")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.contract("R", "deadline", "2026-01-01T00:00:00Z", "quorum", quorum(1, IndependenceNotRequired)))
	w.life("IA", "A", "intent", g, e)
	for i := range 3 {
		w.life(fmt.Sprint("P", i), "A", "progress", g, e, "note", "heartbeat")
	}
	w.life("IC", "C", "intent", g, e) // silent
	w.submit("SB", "BB", g, e, "X")
	tk := taskView(t, w, g)
	out := tk.Render()
	has(t, out, "activity evidence, not a lease renewal")
	has(t, out, "no lease, no expiry")
	for _, bad := range []string{"expired", "lease renewed", "extended", "excluded"} {
		hasNot(t, out, bad)
	}
	if rd := readinessOf(t, tk, w.ed(e)); rd.Token != Ready {
		t.Fatalf("B's submission did not count\n%s", out)
	}
	for _, a := range tk.Attempts {
		if a.Withdrawn != "" {
			t.Fatalf("an intent ended without a withdraw\n%s", out)
		}
	}
	// a withdraw ends A's attempt; later progress does not reopen it; a new intent is a new attempt
	w.life("WA", "A", "withdraw", g, e)
	w.life("P9", "A", "progress", g, e)
	w.life("IA2", "A", "intent", g, e)
	tk = taskView(t, w, g)
	var ended, open int
	for _, a := range tk.Attempts {
		if a.Signer == w.signer("A") {
			if a.Withdrawn != "" {
				ended++
			} else {
				open++
			}
		}
	}
	if ended != 1 || open != 1 {
		t.Fatalf("withdraw: %d ended, %d open\n%s", ended, open, tk.Render())
	}
}

// TestCoordinatorGrants: C-exch-03. K is the coordinator; A holds K's grant, X holds one signed by a
// non-coordinator, B holds none.
func TestCoordinatorGrants(t *testing.T) {
	conformance.Partial(t, "C-exch-03", "grant statement kind pending (wire §5 defines none; read through GrantReader, a test stand-in here); contract grammar pending (coordinator)")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.contract("R", "coordinator", w.signer("K"), "quorum", quorum(1, IndependenceNotRequired)))
	grant := func(name, by, grantee string) {
		w.sign(name, by, "describes", obj("about", obj("resource", g), "tags", []string{"grant", w.signer(grantee), w.ed(e)}))
	}
	grant("GA", "K", "A")
	grant("GX", "Q", "X")
	w.submit("SA", "A", g, e, "Y")
	w.submit("SX", "X", g, e, "Y")
	w.submit("SB", "BB", g, e, "Y")
	tk := taskView(t, w, g, WithGrantReader(fakeGrants{}))
	out := tk.Render()
	if len(tk.Grants) != 1 || tk.Grants[0].Grantee != w.signer("A") {
		t.Fatalf("grants %+v\n%s", tk.Grants, out)
	}
	has(t, out, "granted by "+w.ids["GA"][:12])
	has(t, out, "is not the edition's coordinator: no effect")
	has(t, out, "holds no grant signed by coordinator")
	if len(tk.Submissions) != 3 {
		t.Fatalf("an ungranted submission was refused\n%s", out)
	}
	// without a grant reader no grant counts: nothing is granted, everything is still admissible
	tk2 := taskView(t, w, g)
	if len(tk2.Grants) != 0 || len(tk2.Submissions) != 3 || readinessOf(t, tk2, w.ed(e)).Token != NotReady {
		t.Fatalf("no grant reader:\n%s", tk2.Render())
	}
}

// TestBindingsToEditions: C-exch-07. A claim and a submission bind to T1 (deadline D1, rubric R1); the
// controller publishes T2 (stricter rubric, earlier deadline). Both still read T1's terms; T2 applies to later
// bindings only; neither id changes.
func TestBindingsToEditions(t *testing.T) {
	conformance.Partial(t, "C-exch-07", "contract grammar pending (deadline, rubric field names); the deadline is displayed as a term, never evaluated against a self-declared ts")
	w := newWorld(t)
	g := w.task("G", "R")
	t1 := w.taskEdition("T1", "R", g, []string{g}, w.contract("R", "deadline", "2026-12-01T00:00:00Z",
		"rubric", canon.Value(canon.Array{obj("id", "R1")}), "quorum", quorum(1, IndependenceNotRequired)))
	w.life("IA", "A", "intent", g, t1)
	w.submit("SA", "A", g, t1, "X")
	before := []string{g, w.ed(t1)}
	t2 := w.taskEdition("T2", "R", g, []string{t1}, w.contract("R", "deadline", "2026-11-24T00:00:00Z",
		"rubric", canon.Value(canon.Array{obj("id", "R1"), obj("id", "R2")}), "quorum", quorum(1, IndependenceNotRequired)))
	w.submit("SB", "BB", g, t2, "X")
	ev := fakeRubric{"R1/X": RuleOK, "R2/X": RuleFail}
	tk := taskView(t, w, g, WithRubricEvaluator(ev))
	out := tk.Render()
	for _, s := range tk.Submissions {
		want := 1
		if s.Edition == w.ed(t2) {
			want = 2
		}
		if len(s.Rubric) != want {
			t.Fatalf("submission %s checked under %d criteria, want %d\n%s", s.Statement[:12], len(s.Rubric), want, out)
		}
	}
	if rd := readinessOf(t, tk, w.ed(t1)); rd.Token != Ready {
		t.Fatalf("T1 binding judged by T2's terms\n%s", out)
	}
	if rd := readinessOf(t, tk, w.ed(t2)); rd.Token != NotReady {
		t.Fatalf("T2 binding not judged by T2\n%s", out)
	}
	has(t, out, "deadline 2026-12-01T00:00:00Z")
	if tk.ID != before[0] || tk.Bindings[w.ed(t1)].Edition != before[1] || tk.Attempts[0].Edition != before[1] {
		t.Fatal("an id changed")
	}
	// a binding by an approval's statement id names no edition
	w.sign("SZ", "C", "submit", obj("task", g, "edition", w.ids["T1"], "result", dig("X")))
	tk = taskView(t, w, g, WithRubricEvaluator(ev))
	has(t, tk.Render(), "names the statement id of an approval")
}

// --- §9.2 settlement ----------------------------------------------------------------------------------------

// TestDecisionCites: C-exch-04. The beneficiary accepts citing submissions and an evaluation; a decision
// citing nothing is admitted, shown `cites nothing`, and settles nothing; a non-beneficiary's decision settles
// nothing.
func TestDecisionCites(t *testing.T) {
	conformance.Partial(t, "C-exch-04", "contract grammar pending (beneficiary: the decision authority is read from the provisional contract)")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.contract("R"))
	s1 := w.submit("S1", "A", g, e, "X")
	s2 := w.submit("S2", "BB", g, e, "Y")
	w.decide("D", "R", g, e, "accept", []string{s1, s2}, "evaluations", []string{dig("review")})
	tk := taskView(t, w, g)
	out := tk.Render()
	has(t, out, "accept citing "+s1[:12]+","+s2[:12]+", evaluations "+shortDigest(dig("review")))
	for _, s := range tk.Submissions {
		if s.Verdict != "accept" {
			t.Fatalf("not settled\n%s", out)
		}
	}
	w2 := newWorld(t)
	g = w2.task("G", "R")
	e = w2.taskEdition("E", "R", g, []string{g}, w2.contract("R"))
	w2.submit("S1", "A", g, e, "X")
	w2.decide("D0", "R", g, e, "accept", []string{})
	w2.decide("DQ", "Q", g, e, "accept", []string{w2.ids["S1"]})
	tk = taskView(t, w2, g)
	out = tk.Render()
	has(t, out, "accept citing nothing (cites nothing)")
	has(t, out, "not the edition's beneficiary")
	if tk.Submissions[0].Verdict != "" || len(tk.Decisions) != 2 {
		t.Fatalf("a decision that cites nothing, or a non-beneficiary's, settled\n%s", out)
	}
}

// TestDecisionConflict: C-exch-05. accept S1 then reject S1, with equal and with reversed ts, in both file
// orders: contested, exit 3, identical in every order. A third decision superseding one by hash settles it.
func TestDecisionConflict(t *testing.T) {
	conformance.Partial(t, "C-exch-05", "contract grammar pending (beneficiary)")
	for _, ts := range [][2]string{{"2026-10-20T00:00:00Z", "2026-10-20T00:00:00Z"}, {"2026-10-21T00:00:00Z", "2026-10-20T00:00:00Z"}} {
		w := newWorld(t)
		g := w.task("G", "R")
		e := w.taskEdition("E", "R", g, []string{g}, w.contract("R"))
		s1 := w.submit("S1", "A", g, e, "X")
		acc := w.signTS("DA", "R", "decide", ts[0], obj("task", g, "edition", w.ed(e), "submissions", []string{s1}, "verdict", "accept"))
		w.signTS("DR", "R", "decide", ts[1], obj("task", g, "edition", w.ed(e), "submissions", []string{s1}, "verdict", "reject"))
		n := len(w.lines)
		var renders []string
		for _, o := range [][]int{nil, reverse(n)} {
			tk, _ := w.store(o, WithContractReader(ProvisionalContract{})).Task(g)
			if tk.VerifyExit() != 3 || tk.Submissions[0].Verdict != "contested" {
				t.Fatalf("not contested (ts %v)\n%s", ts, tk.Render())
			}
			renders = append(renders, tk.Render())
		}
		if renders[0] != renders[1] {
			t.Fatalf("file order changed the answer:\n%s\nvs\n%s", renders[0], renders[1])
		}
		has(t, renders[0], "neither ts nor order picks")
		w.decide("D3", "R", g, e, "reject", []string{s1}, "supersedes", acc)
		tk := taskView(t, w, g)
		out := tk.Render()
		if tk.VerifyExit() != 0 || tk.Submissions[0].Verdict != "reject" {
			t.Fatalf("supersession did not settle\n%s", out)
		}
		has(t, out, "(superseded by "+w.ids["D3"][:12]+")")
	}
}

func reverse(n int) []int {
	o := make([]int, n)
	for i := range o {
		o[i] = n - 1 - i
	}
	return o
}

// TestSettledByReview: C-exch-06, the view half. No quorum predicate: the task display says so.
func TestSettledByReview(t *testing.T) {
	conformance.Covers(t, "C-exch-06") // the view half; the publish half is internal/cli.TestPublishTask
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.contract("R"))
	w.submit("S1", "A", g, e, "X")
	out := taskView(t, w, g).Render()
	has(t, out, "no quorum predicate: settled by review, not by counting")
	has(t, out, "readiness of "+w.ed(e)[:12]+": settled by review, not by counting")
}

// --- §9.3 readiness -----------------------------------------------------------------------------------------

// TestRubricUnchecked: C-exch-08. A criterion nobody can evaluate is unchecked; the check does not pass; the
// task exit is 3, never 0, with or without a quorum.
func TestRubricUnchecked(t *testing.T) {
	conformance.Partial(t, "C-exch-08", "contract grammar pending (rubric); criteria are evaluated through a RubricEvaluator seam, none ships")
	for _, q := range []bool{false, true} {
		w := newWorld(t)
		g := w.task("G", "R")
		kv := []any{"rubric", canon.Value(canon.Array{obj("id", "R1"), obj("id", "R2")})}
		if q {
			kv = append(kv, "quorum", quorum(1, IndependenceNotRequired))
		}
		e := w.taskEdition("E", "R", g, []string{g}, w.contract("R", kv...))
		w.submit("S1", "A", g, e, "X")
		for _, ev := range []RubricEvaluator{NoRubricEvaluator{}, fakeRubric{"R1/X": RuleOK}} {
			tk := taskView(t, w, g, WithRubricEvaluator(ev))
			rd := readinessOf(t, tk, w.ed(e))
			out := tk.Render()
			if rd.Check != RuleUnchecked || rd.Token == Ready || tk.VerifyExit() == 0 {
				t.Fatalf("quorum %v: an unchecked criterion passed: %+v\n%s", q, rd, out)
			}
			has(t, out, "rubric R2: unchecked")
		}
	}
}

// TestIndependenceNotInferred: C-exch-09 and C-btc-19. Quorum 2 requiring independence. Every generator reads
// `unknown`, never `1 of 2` or 2.
func TestIndependenceNotInferred(t *testing.T) {
	conformance.Partial(t, "C-exch-09", "contract grammar pending (quorum.independence); (b) the reveal is shown as possession only, its verification needs a commitment construction the wire format does not define")
	conformance.Partial(t, "C-btc-19", "readiness unknown whatever the bounds; contract grammar pending (quorum.independence)")
	gens := map[string]func(w *world, g, e string){
		"a first publication": func(w *world, g, e string) {
			w.authored("XA", "A", "X")
			w.anchor("AA", "A", "btc:100")
			w.submit("SA", "A", g, e, "X")
			w.submit("SB", "BB", g, e, "X")
		},
		"b commit-reveal": func(w *world, g, e string) {
			w.submit("SA", "A", g, e, "X")
			w.submit("SB", "BB", g, e, "X", "salt", "s3cret")
		},
		"c two keys one result": func(w *world, g, e string) {
			w.submit("SA", "A", g, e, "X")
			w.submit("SB", "BB", g, e, "X")
		},
		"d labels": func(w *world, g, e string) {
			w.submit("SA", "A", g, e, "X", "receipt", "provider-r1", "model_family", "fam-1")
			w.submit("SB", "BB", g, e, "X", "tee", "enclave-q")
		},
		"e one of three established": func(w *world, g, e string) {
			w.submit("SA", "A", g, e, "X")
			w.submit("SB", "BB", g, e, "X")
			w.submit("SC", "C", g, e, "X")
		},
		"btc-19 withheld commitment": func(w *world, g, e string) {
			w.authored("XB", "BB", "X", "availability", obj("redistribution", "withheld", "obtainable", false))
			w.anchor("AB", "BB", "btc:100")
			w.authored("XA", "A", "X")
			w.submit("SA", "A", g, e, "X")
			w.submit("SB", "BB", g, e, "X")
		},
	}
	for _, name := range sortedKeys(gens) {
		w := newWorld(t)
		g := w.task("G", "R")
		e := w.taskEdition("E", "R", g, []string{g}, w.contract("R", "quorum", quorum(2, IndependenceRequired)))
		gens[name](w, g, e)
		opts := []Option{WithTimeVerifier(newFakeBitcoin(100))}
		if strings.HasPrefix(name, "e") {
			opts = append(opts, WithIndependenceVerifier(indepBy{w.signer("A")})) // A's alone is established
		}
		tk := taskView(t, w, g, opts...)
		rd := readinessOf(t, tk, w.ed(e))
		out := tk.Render()
		if rd.Token != ReadyUnknown {
			t.Fatalf("%s: readiness %s, want unknown\n%s", name, rd.Token, out)
		}
		hasNot(t, out, "1 of 2")
		hasNot(t, out, "2 of 2")
		has(t, out, "independence of")
		has(t, out, "not established")
		switch name {
		case "b commit-reveal":
			has(t, out, "possession by T only")
		case "d labels":
			has(t, out, `receipt="provider-r1" (the submitter's word; no verifier checked it)`)
			has(t, out, `tee="enclave-q" (the submitter's word`)
		}
	}
}

// indepBy establishes independence for submissions signed by one key (a test verifier).
type indepBy struct{ key string }

func (v indepBy) Independent(st *wire.Statement, _ *Terms) (bool, string) {
	if st.Signer == v.key {
		return true, "bound proof verified (test)"
	}
	return false, NoIndependenceWhy
}

// TestReceiptMismatch: C-exch-10. A receipt valid in itself but bound to another run, or issued by an ineligible
// key: the verifier is invoked, no slot is filled, and the explanation names the mismatch.
func TestReceiptMismatch(t *testing.T) {
	conformance.Partial(t, "C-exch-10", "receipt format and verifier pending (a test verifier stands in); contract grammar pending (quorum.independence, evidence issuers)")
	for _, why := range []string{"subject mismatch: receipt bound to run sha256:aaaa, not this result", "issuer outside the task's eligible issuers"} {
		w := newWorld(t)
		g := w.task("G", "R")
		e := w.taskEdition("E", "R", g, []string{g}, w.contract("R", "quorum", quorum(1, IndependenceRequired)))
		w.submit("SA", "A", g, e, "X", "receipt", "r")
		calls := 0
		tk := taskView(t, w, g, WithIndependenceVerifier(fakeIndep{ok: map[string]string{"X": why}, calls: &calls}))
		if calls == 0 {
			t.Fatal("the verifier was not invoked")
		}
		s := tk.Submissions[0]
		if s.Independent || readinessOf(t, tk, w.ed(e)).Token != ReadyUnknown {
			t.Fatalf("a slot was filled\n%s", tk.Render())
		}
		has(t, tk.Render(), why)
	}
}

// TestSelfDeclaredIndependence: C-exch-11. The contract accepts self-declared independence; two submitters
// declare it: ready, and the token and the outcome say so. A contract that does not accept it: unknown.
func TestSelfDeclaredIndependence(t *testing.T) {
	conformance.Partial(t, "C-exch-11", "contract grammar pending (quorum.independence)")
	for _, accept := range []bool{true, false} {
		w := newWorld(t)
		g := w.task("G", "R")
		mode := IndependenceSelfDeclared
		if !accept {
			mode = IndependenceRequired
		}
		e := w.taskEdition("E", "R", g, []string{g}, w.contract("R", "quorum", quorum(2, mode)))
		s1 := w.submit("SA", "A", g, e, "X", "self_declared_independence", true)
		s2 := w.submit("SB", "BB", g, e, "X", "self_declared_independence", true)
		w.decide("D", "R", g, e, "accept", []string{s1, s2})
		tk := taskView(t, w, g)
		rd := readinessOf(t, tk, w.ed(e))
		out := tk.Render()
		if accept {
			if rd.Token != Ready || !rd.SelfDeclared {
				t.Fatalf("self-declared not ready: %+v\n%s", rd, out)
			}
			has(t, out, "ready (2 of 2, "+CountedAs+") (independence self-declared)")
			has(t, out, "independence self-declared (the submitter's word)")
		} else if rd.Token != ReadyUnknown {
			t.Fatalf("a contract not accepting self-declared independence: %s\n%s", rd.Token, out)
		}
	}
}

// TestExplicitGrouping: C-exch-12. Comparator quorum of 3; A≈B, B≈C, A≉C. All-pairs: no group of 3.
// Reference-based (A): {A,B} groups, C diverges. No rule: unchecked naming the missing rule. Never A–B–C.
func TestExplicitGrouping(t *testing.T) {
	conformance.Partial(t, "C-exch-12", "contract grammar pending (quorum.grouping, comparator)")
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
		e := w.taskEdition("E", "R", g, []string{g}, w.contract("R", "quorum", quorum(3, IndependenceNotRequired, kv...)))
		sa := w.submit("SA", "A", g, e, "rA")
		sb := w.submit("SB", "BB", g, e, "rB")
		sc := w.submit("SC", "C", g, e, "rC")
		tk := taskView(t, w, g, WithComparator(cmp))
		rd := readinessOf(t, tk, w.ed(e))
		out := tk.Render()
		for _, gr := range rd.Groups {
			if len(gr) == 3 {
				t.Fatalf("%s: chained A–B–C into one group\n%s", variant, out)
			}
		}
		switch variant {
		case "all-pairs":
			if rd.Token != NotReady || rd.N != 2 {
				t.Fatalf("all-pairs: %+v\n%s", rd, out)
			}
		case "reference":
			if rd.Token != NotReady || len(rd.Groups) != 1 || !slices.Contains(rd.Groups[0], sa) || !slices.Contains(rd.Groups[0], sb) || slices.Contains(rd.Groups[0], sc) {
				t.Fatalf("reference: %+v\n%s", rd, out)
			}
			has(t, out, "diverged under comparator")
		case "none":
			if rd.Token != ReadyUnchecked {
				t.Fatalf("no rule: %s\n%s", rd.Token, out)
			}
			has(t, out, "no grouping rule declared")
		}
	}
}

// TestPinnedTest: C-exch-13. The contract pins an estimand and a test; two batches whose intervals overlap fail
// it: `diverged` under the named test, its own report; readiness not advanced.
func TestPinnedTest(t *testing.T) {
	conformance.Partial(t, "C-exch-13", "contract grammar pending (quorum.estimand, quorum.test); the test runs through the Comparator seam, no statistical dialect ships")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.contract("R", "quorum", quorum(2, IndependenceNotRequired,
		"estimand", "mean latency", "test", dig("welch-t"), "grouping", obj("rule", GroupAllPairs))))
	w.submit("SA", "A", g, e, "batch1")
	w.submit("SB", "BB", g, e, "batch2")
	tk := taskView(t, w, g, WithComparator(newPairCmp())) // overlapping CIs, but the pinned test fails
	rd := readinessOf(t, tk, w.ed(e))
	out := tk.Render()
	if rd.Token != NotReady {
		t.Fatalf("readiness advanced: %+v\n%s", rd, out)
	}
	has(t, out, `diverged under test `+shortDigest(dig("welch-t"))+` on estimand "mean latency"`)
}

// TestDivergenceStaysVisible: C-exch-14. Quorum k; the first k match, a later one diverges: the task view shows
// the divergence as its own report after readiness is reached.
func TestDivergenceStaysVisible(t *testing.T) {
	conformance.Partial(t, "C-exch-14", "contract grammar pending (quorum)")
	for _, comparator := range []bool{false, true} {
		w := newWorld(t)
		g := w.task("G", "R")
		kv := []any{}
		if comparator {
			kv = []any{"comparator", dig("tol"), "grouping", obj("rule", GroupAllPairs)}
		}
		e := w.taskEdition("E", "R", g, []string{g}, w.contract("R", "quorum", quorum(2, IndependenceNotRequired, kv...)))
		ra, rb := "r~1", "r~2"
		if !comparator {
			rb = ra // byte equality
		}
		w.submit("SA", "A", g, e, ra)
		w.submit("SB", "BB", g, e, rb)
		late := w.submit("SC", "C", g, e, "z~1")
		tk := taskView(t, w, g, WithComparator(newFakeComparator("r~1", "r~2", "z~1")))
		rd := readinessOf(t, tk, w.ed(e))
		out := tk.Render()
		if rd.Token != Ready {
			t.Fatalf("not ready: %+v\n%s", rd, out)
		}
		has(t, out, "divergence report: submission "+late[:12])
	}
}

// --- §9.4 pre-registration and refutation -------------------------------------------------------------------

// TestPreRegisteredObservation: C-exch-15 and C-exch-16. An `observed` and an `authored` carry `fulfills` of a
// task edition whose only anchor is local: `pre-registered <edition> (local, self-declared)`, never a bare
// verified time; with no anchor, `(no anchor)`.
func TestPreRegisteredObservation(t *testing.T) {
	conformance.Covers(t, "C-exch-15", "C-exch-16")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("T1", "R", g, []string{g}, nil)
	w.anchor("AR", "R", "local:only")
	f := canon.Value(obj("resource", g, "edition", w.ed(e)))
	w.observed("O", "A", "OBS", "phenomenon", obj("quantity", "temperature"), "fulfills", f)
	w.authored("X", "BB", "RES", "fulfills", f)
	r := w.store(nil)
	o, _ := r.Observation(w.ids["O"])
	want := "pre-registration: pre-registered " + w.ed(e)[:12] + " (local, self-declared)"
	has(t, o.Render(), want)
	a := r.Artifact(dig("RES"))
	has(t, a.Render(), "pre_registration: pre-registered "+w.ed(e)[:12]+" (local, self-declared)")
	hasNot(t, a.Render(), "height")
	// no anchor at all
	w2 := newWorld(t)
	g2 := w2.task("G", "R")
	e2 := w2.taskEdition("T1", "R", g2, []string{g2}, nil)
	w2.authored("X", "BB", "RES", "fulfills", canon.Value(obj("resource", g2, "edition", w2.ed(e2))))
	has(t, w2.store(nil).Artifact(dig("RES")).Render(), "(no anchor)")
	// an approval's statement id is not an edition id: never shown pre-registered
	w3 := newWorld(t)
	g3 := w3.task("G", "R")
	w3.taskEdition("T1", "R", g3, []string{g3}, nil)
	w3.authored("X", "BB", "RES", "fulfills", canon.Value(obj("resource", g3, "edition", w3.ids["T1"])))
	out := w3.store(nil).Artifact(dig("RES")).Render()
	hasNot(t, out, "pre_registration: pre-registered")
	has(t, out, "not shown as pre-registered")
}

// TestPreRegistrationDisclosure: C-core-70. (a) `fulfills` T1 with a verified bound: `pre-registered T1
// (bitcoin)`; (b) `exploratory`; (c) no field: `undeclared`, never exploratory or pre-registered.
func TestPreRegistrationDisclosure(t *testing.T) {
	conformance.Covers(t, "C-core-70")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("T1", "R", g, []string{g}, nil)
	w.anchor("AR", "R", "btc:100")
	w.authored("XA", "A", "RA", "fulfills", canon.Value(obj("resource", g, "edition", w.ed(e))))
	w.authored("XB", "A", "RB", "pre_registration", "exploratory")
	w.authored("XC", "A", "RC")
	r := w.store(nil, WithTimeVerifier(newFakeBitcoin(100)))
	has(t, r.Artifact(dig("RA")).Render(), "pre_registration: pre-registered "+w.ed(e)[:12]+" (bitcoin) at mainnet height 100")
	has(t, r.Artifact(dig("RB")).Render(), "pre_registration: exploratory")
	c := r.Artifact(dig("RC")).Render()
	has(t, c, "pre_registration: undeclared")
	hasNot(t, c, "exploratory")
	hasNot(t, c, "pre-registered")
}

// TestDepartureCheck: C-exch-17. Declared n=30 runs; deliveries (a)–(d); declared groups A,B,C n>=30;
// deliveries (e)–(g). Grade and exit identical across all seven.
func TestDepartureCheck(t *testing.T) {
	conformance.Partial(t, "C-exch-17", "contract grammar pending (sampling); the delivered side reads wire §5 `sampling`")
	type c struct {
		groups bool
		del    canon.Value
		want   string
		name   string
	}
	grp := func(ns ...int) canon.Value {
		a := canon.Array{}
		for i, n := range ns {
			a = append(a, obj("name", string(rune('A'+i)), "n", n))
		}
		return a
	}
	cases := []c{
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
			s = obj("n", 90, "unit", "runs", "groups", canon.Value(canon.Array{obj("name", "A", "n", 30), obj("name", "B", "n", 30), obj("name", "C", "n", 30)}))
		}
		e := w.taskEdition("E", "R", g, []string{g}, w.contract("R", "sampling", canon.Value(s)))
		var kv []any
		if x.del != nil {
			kv = []any{"sampling", x.del}
		}
		w.authored("X", "A", "RES", kv...)
		w.submit("S", "A", g, e, "RES")
		r := w.store(nil, WithContractReader(ProvisionalContract{}))
		tk, _ := r.Task(g)
		sub := tk.Submissions[0]
		if sub.Departure != x.want || !strings.Contains(sub.DepartureWhy, x.name) {
			t.Fatalf("case %d: %s (%s), want %s %s", i, sub.Departure, sub.DepartureWhy, x.want, x.name)
		}
		a := r.Artifact(dig("RES"))
		code, _ := a.VerifyExit()
		grades = append(grades, fmt.Sprint(a.Grade, code))
	}
	if len(slices.Compact(grades)) != 1 {
		t.Fatalf("grade or exit moved: %v", grades)
	}
}

// TestRefutationTrack: C-exch-18. A `refutes` of an accepted result is admitted and listed as a refutation,
// graded on its own derivation (exempt from the weakest-link rule) and credited on its own track.
func TestRefutationTrack(t *testing.T) {
	conformance.Partial(t, "C-exch-18", "acceptance reads the beneficiary through the provisional contract (grammar pending); a `refutes` names a statement, not a task edition: binding a refutation to a task is by the submission it names")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.contract("R"))
	w.workflow("WA", "W", "bytes", "")
	w.authored("I1", "A", "I")
	w.authored("XA", "A", "X", "prov", []string{"W", "I"})
	s1 := w.submit("S1", "A", g, e, "X")
	w.decide("D", "R", g, e, "accept", []string{s1})
	w.authored("EV", "BB", "EVID", "prov", []string{"W", "X"})
	w.authored("EV2", "C", "EVID", "prov", []string{"W", "X"})
	ref := w.sign("RF", "BB", "refutes", obj("of", s1, "evidence", dig("EVID")))
	tk := taskView(t, w, g)
	out := tk.Render()
	has(t, out, "refutation "+ref[:12]+" by")
	has(t, out, "a first-class refutation, credited on its own track")
	r := w.store(nil, WithContractReader(ProvisionalContract{}))
	has(t, r.Artifact(dig("EVID")).Render(), "exempt from the weakest-link rule")
	cr := r.Credit(w.signer("BB"), &CreditRule{Name: "test"})
	for _, cc := range cr.Counts {
		if cc.Name == "refutation" && (cc.N != 1 || cc.Of != 1) {
			t.Fatalf("refutation track %+v", cc)
		}
		if cc.Name == "contribution" && cc.N != 0 {
			t.Fatalf("a refutation counted as a contribution %+v", cc)
		}
	}
}

// --- §9.5 credit --------------------------------------------------------------------------------------------

// TestCreditProjection: C-exch-19. Credit for A under two reader-chosen windows and denominators; a fresh
// install computes nothing; nothing transferable is written.
func TestCreditProjection(t *testing.T) {
	conformance.Partial(t, "C-exch-19", "the counts' definitions are this reading's (claims §9.5 names them, defines none); acceptance reads the beneficiary through the provisional contract (grammar pending)")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.contract("R"))
	s1 := w.submit("S1", "A", g, e, "X")
	w.anchor("AA", "A", "btc:100")
	w.submit("S2", "A", g, e, "Y")
	w.submit("S3", "BB", g, e, "Z")
	w.decide("D", "R", g, e, "accept", []string{s1})
	r := w.store(nil, WithContractReader(ProvisionalContract{}), WithTimeVerifier(newFakeBitcoin(100)))
	lines := len(w.lines)
	fresh := r.Credit(w.signer("A"), nil)
	if len(fresh.Counts) != 0 || !strings.Contains(fresh.Render(), NoProjection) {
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
	has(t, win.Render(), "verified bitcoin bounds at heights 0 to 100")
	if len(w.lines) != lines {
		t.Fatal("a projection wrote a statement")
	}
}

// TestCreditAfterSupersession: C-exch-20. After acceptance the beneficiary supersedes it with a rejection: the
// projection changes and cites the superseding decision; the earlier decision stays in explain.
func TestCreditAfterSupersession(t *testing.T) {
	conformance.Partial(t, "C-exch-20", "contract grammar pending (beneficiary)")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.contract("R"))
	s1 := w.submit("S1", "A", g, e, "X")
	d1 := w.decide("D1", "R", g, e, "accept", []string{s1})
	rule := &CreditRule{Name: "r"}
	before := w.store(nil, WithContractReader(ProvisionalContract{})).Credit(w.signer("A"), rule)
	d2 := w.decide("D2", "R", g, e, "reject", []string{s1}, "supersedes", d1)
	after := w.store(nil, WithContractReader(ProvisionalContract{})).Credit(w.signer("A"), rule)
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
	tk := taskView(t, w, g)
	has(t, tk.Render(), "accept citing "+s1[:12]+" (superseded by "+d2[:12]+")")
}

// --- unknowns -----------------------------------------------------------------------------------------------

// TestContractUnknowns: an unknown contract profile, no contract reader, and counting unit `identity` never
// pass: unchecked, unchecked, unknown; a decision under unread terms settles nothing.
func TestContractUnknowns(t *testing.T) {
	w := newWorld(t)
	g := w.task("G", "R")
	e1 := w.taskEdition("E1", "R", g, []string{g}, obj("profile", "someone-elses-v1", "quorum", obj("k", 1)))
	s := w.submit("S", "A", g, e1, "X")
	w.decide("D", "R", g, e1, "accept", []string{s})
	tk := taskView(t, w, g)
	rd := readinessOf(t, tk, w.ed(e1))
	if rd.Token != ReadyUnchecked || tk.Submissions[0].Verdict != "" || tk.VerifyExit() != 3 {
		t.Fatalf("unknown profile passed\n%s", tk.Render())
	}
	has(t, tk.Render(), "unknown contract profile")
	tk2, _ := w.store(nil).Task(g)
	has(t, tk2.Render(), NoContractProfile)
	e2 := w.taskEdition("E2", "R", g, []string{e1}, w.contract("R", "counting_unit", "identity", "quorum", quorum(1, IndependenceNotRequired)))
	w.submit("S2", "A", g, e2, "X")
	tk = taskView(t, w, g)
	if rd := readinessOf(t, tk, w.ed(e2)); rd.Token != ReadyUnknown {
		t.Fatalf("identity counting: %s\n%s", rd.Token, tk.Render())
	}
}
