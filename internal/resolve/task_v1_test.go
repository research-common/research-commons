package resolve

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/wire"
)

// task-contract-v1 task views (task-contracts note §4–§5). Every view is resolved in several delivery orders
// and must render identically (taskV1View).

// v1c is a task-contract-v1 contract with beneficiary ben and any issuer; kv adds or replaces fields.
func (w *world) v1c(ben string, kv ...any) *canon.Object {
	base := []any{"question", "q?", "beneficiary", w.signer(ben)}
	if !slices.Contains(kv, any("profile")) {
		base = append(base, "profile", TaskContractV1Profile)
	}
	if !slices.Contains(kv, any("eligible_issuers")) {
		base = append(base, "any_issuer", true)
	}
	return obj(append(base, kv...)...)
}

// issuers is a sorted key set of the named keys.
func (w *world) issuers(names ...string) []string {
	var out []string
	for _, n := range names {
		out = append(out, w.signer(n))
	}
	slices.SortFunc(out, canon.CompareKeys)
	return out
}

func (w *world) grant(name, by, g, e, grantee string) string {
	return w.life(name, by, "grant", g, e, "grantee", w.signer(grantee))
}

func fulfills(g, ed string) canon.Value { return obj("resource", g, "edition", ed) }

// tipBitcoin is fakeBitcoin with a validated tip; heights may also be marked pending.
type tipBitcoin struct {
	fakeBitcoin
	tip     int64
	hasTip  bool
	pending map[string]bool
}

func newTipBitcoin(tip int64, heights ...int64) tipBitcoin {
	return tipBitcoin{fakeBitcoin: newFakeBitcoin(heights...), tip: tip, hasTip: true, pending: map[string]bool{}}
}

func (f tipBitcoin) Tip() (int64, bool) { return f.tip, f.hasTip }

func (f tipBitcoin) Verify(a *wire.Statement) Bound {
	if f.pending[str(a.Body, "proof")] {
		return Bound{Quality: Local, Anchor: a.ID, State: "pending", Why: "not verified by this reader: pending"}
	}
	b := f.fakeBitcoin.Verify(a)
	if b.verified() {
		b.State = "verified"
	}
	return b
}

func taskV1View(t *testing.T, w *world, g string, opts ...Option) *Task {
	t.Helper()
	opts = append([]Option{WithContractReader(ContractProfiles{})}, opts...)
	var first *Task
	var out string
	for _, o := range append([][]int{nil}, sampleOrders(len(w.lines), uint64(len(w.lines))*37, 10)...) {
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

func subOf(t *testing.T, tk *Task, id string) *Submission {
	t.Helper()
	for _, s := range tk.Submissions {
		if s.Statement == id {
			return s
		}
	}
	t.Fatalf("no submission %s\n%s", id, tk.Render())
	return nil
}

func wantSub(t *testing.T, tk *Task, id, state, reason string) {
	t.Helper()
	s := subOf(t, tk, id)
	if s.V1 == nil || s.V1.State != state || !strings.Contains(strings.Join(s.V1.Reasons, "; "), reason) {
		t.Fatalf("submission %s: %+v, want %s naming %q\n%s", id[:8], s.V1, state, reason, tk.Render())
	}
}

func wantToken(t *testing.T, tk *Task, w *world, ed, token string, exit int) *Readiness {
	t.Helper()
	rd := readinessOf(t, tk, w.ed(ed))
	if rd.Token != token || tk.VerifyExit() != exit {
		t.Fatalf("readiness %s exit %d, want %s exit %d\n%s", rd.Token, tk.VerifyExit(), token, exit, tk.Render())
	}
	return rd
}

// C-exch-03a: profiles and fields the reader does not read leave the terms unread, no partial reading, and no
// submission counted, a fulfills one included; the provisional name is never read as v1.
func TestV1UnreadContracts(t *testing.T) {
	conformance.Covers(t, "C-exch-03a")
	for _, x := range []struct {
		name  string
		c     func(w *world) *canon.Object
		field string
	}{
		{"v2", func(w *world) *canon.Object { return w.v1c("R", "profile", "task-contract-v2") }, "task-contract-v2"},
		{"x_note", func(w *world) *canon.Object { return w.v1c("R", "x_note", "hi") }, "x_note"},
		{"grouping without comparator", func(w *world) *canon.Object {
			return w.v1c("R", "quorum", quorum(1, IndependenceNotRequired, "grouping", obj("rule", GroupAllPairs)))
		}, "quorum.grouping"},
		{"duplicate rubric", func(w *world) *canon.Object {
			return w.v1c("R", "rubric", canon.Value(canon.Array{obj("id", "a"), obj("id", "a")}))
		}, "rubric.id"},
	} {
		t.Run(x.name, func(t *testing.T) {
			w := newWorld(t)
			g := w.task("G", "R")
			e := w.taskEdition("E", "R", g, []string{g}, x.c(w))
			s := w.submit("S", "A", g, e, "X")
			o := w.observedRef("O", "B", "X", "none-yet", obj(), "fulfills", fulfills(g, w.ed(e)))
			tk := taskV1View(t, w, g)
			rd := wantToken(t, tk, w, e, ReadyUnchecked, 3)
			out := tk.Render()
			has(t, out, "unchecked: ")
			has(t, out, x.field)
			hasNot(t, out, "deadline bitcoin height")
			hasNot(t, out, "eligible issuers")
			if rd.N != 0 || subOf(t, tk, s).V1 != nil {
				t.Fatalf("a count under unread terms\n%s", out)
			}
			// the fulfills statement is listed (admissible), counted toward nothing: no condition was read
			if sub := subOf(t, tk, o); sub.V1 != nil {
				t.Fatalf("a fulfills statement was evaluated under unread terms\n%s", out)
			}
			t.Logf("unread, naming %s", x.field)
		})
	}
	// (e) the provisional name keeps its own reading; (f) control: v1 read, readiness computed
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "quorum", quorum(2, IndependenceNotRequired)))
	w.submit("S1", "A", g, e, "X")
	w.observedRef("O", "B", "X", "none-yet", obj(), "fulfills", fulfills(g, w.ed(e)))
	tk := taskV1View(t, w, g)
	wantToken(t, tk, w, e, Ready, 0)
	has(t, tk.Render(), "contract profile "+TaskContractV1Profile)
	w2 := newWorld(t)
	g2 := w2.task("G", "R")
	e2 := w2.taskEdition("E", "R", g2, []string{g2}, w2.contract("R", "quorum", quorum(2, IndependenceNotRequired)))
	w2.submit("S1", "A", g2, e2, "X")
	w2.observedRef("O", "B", "X", "none-yet", obj(), "fulfills", fulfills(g2, w2.ed(e2)))
	tk2 := taskV1View(t, w2, g2)
	if rd := readinessOf(t, tk2, w2.ed(e2)); rd.Token != NotReady || len(tk2.Submissions) != 1 {
		t.Fatalf("provisional read as v1 (fulfills counted): %s\n%s", rd.Token, tk2.Render())
	}
}

// C-exch-03b: grants by the coordinator only, per edition, in any order.
func TestV1Grants(t *testing.T) {
	conformance.Covers(t, "C-exch-03b")
	w := newWorld(t)
	g := w.task("G", "R")
	c := w.v1c("R", "coordinator", w.signer("K"), "quorum", quorum(9, IndependenceNotRequired))
	t1 := w.taskEdition("T1", "R", g, []string{g}, c)
	t2 := w.taskEdition("T2", "R", g, []string{t1}, c)
	w.grant("gA", "K", g, w.ed(t1), "A")
	w.grant("gB", "X", g, w.ed(t1), "B")
	w.grant("gD", "K", g, w.ed(t2), "D")
	sA := w.submit("SA", "A", g, t1, "r")
	sB := w.submit("SB", "B", g, t1, "r")
	sC := w.submit("SC", "C", g, t1, "r")
	sD := w.submit("SD", "D", g, t1, "r")
	w.grant("gC", "K", g, w.ed(t1), "C") // after C's submission is in C's log
	sA2 := w.submit("SA2", "A", g, t2, "r")
	tk := taskV1View(t, w, g)
	wantSub(t, tk, sA, SubCounted, "")
	wantSub(t, tk, sC, SubCounted, "")
	wantSub(t, tk, sB, SubNotCounted, "no grant from")
	wantSub(t, tk, sD, SubNotCounted, "does not carry")
	wantSub(t, tk, sA2, SubNotCounted, "no grant from")
	has(t, tk.Render(), "is not the edition's coordinator: no effect")
}

// C-exch-07a: the deadline clock.
func TestV1Deadline(t *testing.T) {
	conformance.Covers(t, "C-exch-07a")
	const h = 100
	build := func(tipAt int64) (*world, string, string, map[string]string) {
		w := newWorld(t)
		g := w.task("G", "R")
		e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "deadline", obj("height", h), "quorum", quorum(9, IndependenceNotRequired)))
		ids := map[string]string{}
		ids["a"] = w.submit("Sa", "A", g, e, "x")
		w.anchor("anA", "A", "btc:97")
		ids["b"] = w.submit("Sb", "B", g, e, "x")
		w.anchor("anB", "B", "pend")
		ids["c"] = w.submit("Sc", "C", g, e, "x")
		ids["d"] = w.submit("Sd", "D", g, e, "x")
		w.anchor("anD", "D", "btc:105")
		ids["e"] = w.submit("Se", "E", g, e, "x")
		w.anchor("anE", "E", "local-only")
		ids["f"] = w.submit("Sf", "F", g, e, "x")
		w.anchor("anF", "F", "btc:105")
		ids["g"] = w.observedRef("Og", "G1", "obs-g", "none-yet", obj(), "fulfills", fulfills(g, w.ed(e)), "at", "2020-01-01T00:00:00Z")
		w.anchor("anG", "G1", "btc:105")
		ids["h"] = w.observedRef("Oh", "H1", "obs-h", "none-yet", obj(), "fulfills", fulfills(g, w.ed(e)))
		w.anchor("anH", "H1", "btc:98")
		return w, g, e, ids
	}
	tb := newTipBitcoin(120, 97, 98, 105, 99)
	tb.pending[dig("pend")] = true
	w, g, _, ids := build(120)
	tk := taskV1View(t, w, g, WithTimeVerifier(tb))
	want := map[string]Outcome{"a": RuleOK, "b": RuleUnchecked, "d": DeadlineNotShown, "e": DeadlineNotShown, "f": DeadlineNotShown, "g": DeadlineNotShown, "h": RuleOK, "c": DeadlineNotShown}
	for k, o := range want {
		if s := subOf(t, tk, ids[k]); s.V1.Deadline != o {
			t.Fatalf("(%s) deadline %s, want %s\n%s", k, s.V1.Deadline, o, tk.Render())
		}
	}
	out := tk.Render()
	has(t, out, "a later bound does not show lateness")
	for _, bad := range []string{"missed", "late ", "expired"} {
		hasNot(t, out, bad)
	}
	// (c) no proof, tip below h: unchecked
	tb2 := newTipBitcoin(90, 97, 98, 105)
	tk2 := taskV1View(t, w, g, WithTimeVerifier(tb2))
	if s := subOf(t, tk2, ids["c"]); s.V1.Deadline != RuleUnchecked {
		t.Fatalf("(c) tip below h: %s\n%s", s.V1.Deadline, tk2.Render())
	}
	// (f) an upgraded proof verified at h-1 turns not shown into ok
	w.anchor("anF2", "F", "btc:99")
	tk3 := taskV1View(t, w, g, WithTimeVerifier(tb))
	if s := subOf(t, tk3, ids["f"]); s.V1.Deadline != RuleOK || !strings.Contains(strings.Join(s.V1.DeadlineWhy, " "), "105") {
		t.Fatalf("(f) upgrade: %s %v\n%s", s.V1.Deadline, s.V1.DeadlineWhy, tk3.Render())
	}
	for _, s := range tk3.Submissions {
		if !strings.Contains(tk3.Render(), "submission "+s.Statement[:8]) && !strings.Contains(tk3.Render(), s.Statement[:12]) {
			t.Fatalf("a submission was dropped from the view")
		}
	}
}

// C-exch-08a: the bracket. An undecided submission never vetoes a reached quorum.
func TestV1Bracket(t *testing.T) {
	conformance.Covers(t, "C-exch-08a")
	run := func(cOutcome Outcome, withB bool) (*Task, *world, string) {
		w := newWorld(t)
		g := w.task("G", "R")
		e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "rubric", canon.Value(canon.Array{obj("id", "c1")}), "quorum", quorum(2, IndependenceNotRequired)))
		w.submit("SA", "A", g, e, "X")
		if withB {
			w.submit("SB", "B", g, e, "X")
		}
		w.submit("SC", "C", g, e, "Xc")
		rub := fakeRubric{"c1/X": RuleOK}
		if cOutcome != RuleUnchecked {
			rub["c1/Xc"] = cOutcome
		}
		// (b)/(c): C's result identical to A's, distinguished by the rubric's per-statement view
		return taskV1View(t, w, g, WithRubricEvaluator(rub)), w, e
	}
	tk, w, e := run(RuleUnchecked, true)
	wantToken(t, tk, w, e, Ready, 0)
	has(t, tk.Render(), "undecided")
	// (b) A ok, C unchecked, identical results: unchecked, exit 3, naming C
	w2 := newWorld(t)
	g := w2.task("G", "R")
	e2 := w2.taskEdition("E", "R", g, []string{g}, w2.v1c("R", "rubric", canon.Value(canon.Array{obj("id", "c1")}), "quorum", quorum(2, IndependenceNotRequired)))
	w2.submit("SA", "A", g, e2, "X")
	sc := w2.submit("SC", "C", g, e2, "X", "x_flag", "c")
	tk2 := taskV1View(t, w2, g, WithRubricEvaluator(okRubric{sc: RuleUnchecked}))
	wantToken(t, tk2, w2, e2, ReadyUnchecked, 3)
	wantSub(t, tk2, sc, SubUndecided, "rubric c1 unchecked")
	// (c) as (b) with C fail: not ready, exit 0
	tk3 := taskV1View(t, w2, g, WithRubricEvaluator(okRubric{sc: RuleFail}))
	wantToken(t, tk3, w2, e2, NotReady, 0)
	wantSub(t, tk3, sc, SubNotCounted, "rubric c1 fail")
}

// okRubric is ok for every statement except the listed ones.
type okRubric map[string]Outcome

func (f okRubric) Evaluate(_ Criterion, st *wire.Statement) (Outcome, string) {
	if o, ok := f[st.ID]; ok {
		return o, "fake"
	}
	return RuleOK, "fake"
}

// C-exch-08b: results kind and min_grade read from the held record.
func TestV1ResultsMinGrade(t *testing.T) {
	conformance.Covers(t, "C-exch-08b")
	w := newWorld(t)
	w.workflow("WA", "W", "bytes", "")
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "results", ResultsDerived, "quorum", quorum(2, IndependenceNotRequired, "min_grade", "T1")))
	// (a) D re-derived byte-identically by A and B: T0 >= T1
	w.authored("dA", "A", "D", "prov", []string{"W", "I"})
	w.authored("dB", "B", "D", "prov", []string{"W", "I"})
	sA := w.submit("SA", "A", g, e, "D")
	sB := w.submit("SB", "B", g, e, "D")
	// (b) D2 derived once: not re-derived, below T1
	w.authored("d2", "C", "D2", "prov", []string{"W", "J"})
	sC := w.submit("SC", "C", g, e, "D2")
	// (c) D3 held only as an observation
	w.observedRef("o3", "E", "D3", "none-yet", obj())
	sE := w.submit("SE", "E", g, e, "D3")
	// (d) D4 not held
	sF := w.submit("SF", "F", g, e, "D4")
	// (e) D5 both kinds
	w.authored("d5", "G1", "D5", "prov", []string{"W", "K"})
	w.observedRef("o5", "H1", "D5", "none-yet", obj())
	sG := w.submit("SG", "G1", g, e, "D5")
	tk := taskV1View(t, w, g)
	wantSub(t, tk, sA, SubCounted, "")
	wantSub(t, tk, sB, SubCounted, "")
	wantToken(t, tk, w, e, Ready, 0)
	wantSub(t, tk, sC, SubNotCounted, "below min_grade T1")
	wantSub(t, tk, sE, SubNotCounted, "not a derived result")
	wantSub(t, tk, sF, SubUndecided, "no statement for the result is held")
	wantSub(t, tk, sG, SubUndecided, "both kinds")
	has(t, strings.Join(subOf(t, tk, sG).V1.Reasons, ";"), "observed")
}

// C-exch-08c: exact pins.
func TestV1Pins(t *testing.T) {
	conformance.Covers(t, "C-exch-08c")
	w := newWorld(t)
	g := w.task("G", "R")
	me := strings.Repeat("ab", 32)
	e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "pins", obj("workflow", dig("W"), "method_edition", me, "inputs", []string{dig("I1")}), "quorum", quorum(9, IndependenceNotRequired)))
	f := fulfills(g, w.ed(e))
	a := w.authored("a", "A", "ra", "prov", []string{"W", "I1", "I2"}, "fulfills", f)
	b := w.authored("b", "B", "rb", "prov", []string{"W2", "I1"}, "fulfills", f)
	c := w.authored("c", "C", "rc", "prov", []string{"W", "I2"}, "fulfills", f)
	d := w.authored("d", "D", "rd", "provenance_partial", canon.Value(obj("workflow", dig("W"), "inputs", []string{dig("I2")}, "unpinned", []string{"in1"})), "fulfills", f)
	ref := obj("method_edition", me, "environment", obj("image_digest", dig("img"), "platform", "linux/amd64", "harness_commit", strings.Repeat("c", 40)),
		"system", obj("m", "x"), "inputs", []string{dig("I1")}, "window", obj("from", "2026-01-01T00:00:00Z", "to", "2026-01-02T00:00:00Z"))
	ee := w.observedRef("e", "E", "re", "method", ref, "fulfills", f)
	ff := w.observedRef("f", "F", "rf", "none-yet", obj(), "fulfills", f)
	gg := w.submit("g", "G1", g, e, "unheld")
	hh := w.authored("h", "H1", "rh", "fulfills", f)
	tk := taskV1View(t, w, g)
	for id, st := range map[string]string{a: SubCounted, ee: SubCounted, b: SubNotCounted, c: SubNotCounted, ff: SubNotCounted, hh: SubNotCounted, d: SubUndecided, gg: SubUndecided} {
		if s := subOf(t, tk, id); s.V1.State != st {
			t.Fatalf("%s: %s (%v), want %s\n%s", id[:8], s.V1.State, s.V1.Reasons, st, tk.Render())
		}
	}
	has(t, strings.Join(subOf(t, tk, b).V1.Reasons, ";"), "pins fail")
}

// C-exch-09a: a withheld-availability commitment's bound meets the deadline; possession by T only; salt inert.
func TestV1CommitReveal(t *testing.T) {
	conformance.Covers(t, "C-exch-09a")
	const h = 100
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "deadline", obj("height", h), "quorum", quorum(2, IndependenceRequired)))
	cm := w.authored("C", "A", "Dres", "availability", obj("redistribution", "withheld", "obtainable", false))
	w.anchor("anC", "A", "btc:95")
	sA := w.submit("SA", "A", g, e, "Dres")
	w.anchor("anA", "A", "btc:103")
	sB := w.submit("SB", "B", g, e, "Dres", "salt", "n0nce")
	w.anchor("anB", "B", "btc:99")
	tk := taskV1View(t, w, g, WithTimeVerifier(newTipBitcoin(120, 95, 103, 99)), WithIndependenceVerifier(fakeIndep{ok: map[string]string{}, calls: new(int)}))
	s := subOf(t, tk, sA)
	if s.V1.Deadline != RuleOK || !strings.Contains(strings.Join(s.V1.DeadlineWhy, " "), "commitment "+cm[:8]) {
		t.Fatalf("commitment bound not read: %s %v\n%s", s.V1.Deadline, s.V1.DeadlineWhy, tk.Render())
	}
	has(t, strings.Join(s.V1.DeadlineWhy, " "), "possession by T only")
	rd := wantToken(t, tk, w, e, ReadyUnknown, 3)
	if rd.N != 0 {
		t.Fatalf("a count under missing independence: %d", rd.N)
	}
	sb := subOf(t, tk, sB)
	has(t, tk.Render(), "salt: retained, inert")
	if sb.V1.Deadline != RuleOK || sb.Independent {
		t.Fatalf("salt changed an outcome: %+v", sb)
	}
	// the salt changes nothing: the same view without it has the same readiness and conditions
	w2 := newWorld(t)
	g2 := w2.task("G", "R")
	e2 := w2.taskEdition("E", "R", g2, []string{g2}, w2.v1c("R", "deadline", obj("height", h), "quorum", quorum(2, IndependenceRequired)))
	w2.submit("SB", "B", g2, e2, "Dres")
	w2.anchor("anB", "B", "btc:99")
	tk2 := taskV1View(t, w2, g2, WithTimeVerifier(newTipBitcoin(120, 99)))
	if s2 := tk2.Submissions[0]; s2.V1.Deadline != sb.V1.Deadline || s2.V1.State != sb.V1.State {
		t.Fatalf("salt changed the outcome: %+v vs %+v", s2.V1, sb.V1)
	}
}

// C-exch-12a: grouping any collects; no grouping groups by bytes; any with a comparator or all-pairs without is unread.
func TestV1GroupingAny(t *testing.T) {
	conformance.Covers(t, "C-exch-12a")
	build := func(q canon.Value) (*world, string, string) {
		w := newWorld(t)
		g := w.task("G", "R")
		e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "eligible_issuers", w.issuers("A", "B", "C", "D"), "quorum", q))
		f := fulfills(g, w.ed(e))
		ref := func() *canon.Object {
			return obj("method_edition", strings.Repeat("ab", 32), "environment", obj("image_digest", dig("img"), "platform", "p", "harness_commit", strings.Repeat("c", 40)),
				"system", obj("m", "x"), "window", obj("from", "2026-01-01T00:00:00Z", "to", "2026-01-02T00:00:00Z"))
		}
		w.observedRef("oA", "A", "bA", "method", ref(), "fulfills", f)
		w.observedRef("oB", "B", "bB", "method", ref(), "fulfills", f)
		w.observedRef("oC", "C", "bC", "method", ref(), "fulfills", f)
		w.observedRef("oD", "D", "bA", "method", ref(), "fulfills", f)
		return w, g, e
	}
	w, g, e := build(quorum(3, IndependenceNotRequired, "grouping", obj("rule", GroupAny)))
	tk := taskV1View(t, w, g)
	rd := wantToken(t, tk, w, e, Ready, 0)
	if rd.N != 4 || len(rd.Groups) != 1 {
		t.Fatalf("(a) %d in %d groups\n%s", rd.N, len(rd.Groups), tk.Render())
	}
	hasNot(t, tk.Render(), "divergence report")
	w, g, e = build(quorum(3, IndependenceRequired, "grouping", obj("rule", GroupAny)))
	tk = taskV1View(t, w, g)
	wantToken(t, tk, w, e, ReadyUnknown, 3)
	has(t, tk.Render(), "independence of")
	w, g, e = build(quorum(3, IndependenceNotRequired))
	tk = taskV1View(t, w, g)
	rd = wantToken(t, tk, w, e, NotReady, 0)
	if len(rd.Groups) != 3 || rd.N != 2 {
		t.Fatalf("(c) %d groups best %d\n%s", len(rd.Groups), rd.N, tk.Render())
	}
	for _, q := range []canon.Value{
		quorum(3, IndependenceNotRequired, "comparator", dig("K"), "grouping", obj("rule", GroupAny)),
		quorum(3, IndependenceNotRequired, "grouping", obj("rule", GroupAllPairs)),
	} {
		w, g, e = build(q)
		tk = taskV1View(t, w, g)
		wantToken(t, tk, w, e, ReadyUnchecked, 3)
		has(t, tk.Render(), "quorum.grouping")
	}
}

// C-exch-12b: a unit counts by its current submission, whatever the kind; disagreeing fork branches count in none.
func TestV1CurrentSubmission(t *testing.T) {
	conformance.Covers(t, "C-exch-12b")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "quorum", quorum(2, IndependenceNotRequired)))
	a1 := w.submit("A1", "A", g, e, "D1")
	a2 := w.authored("A2", "A", "D2", "fulfills", fulfills(g, w.ed(e)))
	w.submit("B1", "B", g, e, "D2")
	c1 := w.submit("C1", "C", g, e, "D1")
	tk := taskV1View(t, w, g)
	wantSub(t, tk, a1, SubNotCounted, "superseded by")
	wantSub(t, tk, a2, SubCounted, "")
	wantSub(t, tk, c1, SubCounted, "")
	rd := wantToken(t, tk, w, e, Ready, 0)
	if rd.N != 2 {
		t.Fatalf("count %d\n%s", rd.N, tk.Render())
	}
	// C's log forks after C1: one branch submits D2, the other D3
	head, seq := w.head["C"], w.seq["C"]
	cx := w.submit("Cx", "C", g, e, "D2")
	w.forkAt("C", head, seq)
	cy := w.submit("Cy", "C", g, e, "D3")
	tk = taskV1View(t, w, g)
	wantSub(t, tk, cx, SubNotCounted, "uncleared fork")
	wantSub(t, tk, cy, SubNotCounted, "uncleared fork")
	has(t, tk.Render(), "counts in none")
}

// C-exch-15a: fulfills statements are submissions.
func TestV1FulfillsSubmissions(t *testing.T) {
	conformance.Covers(t, "C-exch-15a")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("T1", "R", g, []string{g}, w.v1c("R", "eligible_issuers", w.issuers("A", "B", "C"), "quorum", quorum(2, IndependenceNotRequired)))
	f := fulfills(g, w.ed(e))
	ex := obj("chain_id", "c", "block_hash", strings.Repeat("0", 64), "depth", 6)
	oa := w.observedRef("oA", "A", "D", "exact-bytes", ex, "fulfills", f)
	ob := w.observedRef("oB", "B", "D", "exact-bytes", ex, "fulfills", f)
	cA := w.authored("cA", "C", "D2", "fulfills", f)
	cS := w.submit("cS", "C", g, e, "D2")
	ox := w.observedRef("oX", "X", "D", "exact-bytes", ex, "fulfills", f)
	coll := w.genesis("COL", "R", 0, "R")
	w.authored("dd", "A", "Dz", "fulfills", fulfills(coll, coll))
	tk := taskV1View(t, w, g)
	wantToken(t, tk, w, e, Ready, 0)
	wantSub(t, tk, oa, SubCounted, "")
	wantSub(t, tk, ob, SubCounted, "")
	wantSub(t, tk, ox, SubNotCounted, "not an eligible issuer")
	// (b) C's authored then submit of the same digest: the submit is current, C counts once
	wantSub(t, tk, cA, SubNotCounted, "superseded by")
	wantSub(t, tk, cS, SubCounted, "")
	for _, s := range tk.Submissions {
		if s.Result == dig("Dz") {
			t.Fatal("(d) a fulfills naming a collection is a submission")
		}
	}
	// (e) statement grade / own exit identical with and without the task held
	full := w.store(nil, WithContractReader(ContractProfiles{})).Artifact(dig("D"))
	w2 := newWorld(t)
	w2.observedRef("oA", "A", "D", "exact-bytes", ex, "fulfills", obj("resource", g, "edition", w.ed(e)))
	bare := w2.store(nil).Artifact(dig("D"))
	fx, _ := full.VerifyExit()
	bx, _ := bare.VerifyExit()
	if fx != bx || full.Grade != bare.Grade {
		t.Fatalf("(e) the task changed the statement: %d/%s vs %d/%s", fx, full.Grade, bx, bare.Grade)
	}
	// (f) results observed: a submit of a held observed counts; unheld undecided; authored-with-provenance not counted
	w3 := newWorld(t)
	g3 := w3.task("G", "R")
	e3 := w3.taskEdition("T1", "R", g3, []string{g3}, w3.v1c("R", "results", ResultsObserved, "quorum", quorum(1, IndependenceNotRequired)))
	w3.observedRef("oA", "A", "Do", "none-yet", obj())
	w3.authored("dp", "B", "Dp", "prov", []string{"W", "I"})
	s1 := w3.submit("s1", "C", g3, e3, "Do")
	s2 := w3.submit("s2", "D", g3, e3, "Dnone")
	s3 := w3.submit("s3", "E", g3, e3, "Dp")
	tk3 := taskV1View(t, w3, g3)
	wantSub(t, tk3, s1, SubCounted, "")
	wantSub(t, tk3, s2, SubUndecided, "no statement for the result is held")
	wantSub(t, tk3, s3, SubNotCounted, "not an observation")
}

// C-exch-15b: amendments read from the current claim; the deadline reads the unbroken run; retracts do not remove.
func TestV1Amendments(t *testing.T) {
	conformance.Covers(t, "C-exch-15b")
	const h = 100
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "deadline", obj("height", h), "quorum", quorum(9, IndependenceNotRequired)))
	f := fulfills(g, w.ed(e))
	s1 := w.authored("S1", "A", "D", "fulfills", f)
	w.anchor("an1", "A", "btc:95")
	// the publish guard: an amendment without fulfills warns, naming the edition (a warning, never a refusal)
	r0 := w.store(nil, WithContractReader(ContractProfiles{}))
	warn := r0.FulfillsDropWarning(w.signer("A"), dig("D"), obj("content", canon.Value(contentOf("D")), "type", "dataset", "licence", "CC0-1.0"))
	if !strings.Contains(warn, w.ed(e)[:12]) || !strings.Contains(warn, "withdrawn") {
		t.Fatalf("(a) no warning naming the edition: %q", warn)
	}
	if r0.FulfillsDropWarning(w.signer("A"), dig("D"), obj("content", canon.Value(contentOf("D")), "fulfills", f)) != "" {
		t.Fatal("(a) carrying fulfills forward warned")
	}
	w.authored("S2", "A", "D", "licence", "CC0-1.0")
	tb := newTipBitcoin(120, 95, 104)
	tk := taskV1View(t, w, g, WithTimeVerifier(tb))
	for _, s := range tk.Submissions {
		if s.Signer == w.signer("A") {
			t.Fatalf("(a) A still has a submission after S2 dropped fulfills\n%s", tk.Render())
		}
	}
	s3 := w.authored("S3", "A", "D", "fulfills", f)
	w.anchor("an3", "A", "btc:104")
	tk = taskV1View(t, w, g, WithTimeVerifier(tb))
	s := subOf(t, tk, s3)
	why := strings.Join(s.V1.DeadlineWhy, " ")
	if s.V1.Deadline != DeadlineNotShown || !strings.Contains(why, "broke the run") || !strings.Contains(why, s1[:8]) {
		t.Fatalf("(b) %s %s\n%s", s.V1.Deadline, why, tk.Render())
	}
	// (c) an observed carrying fulfills, then retracted: still a submission, the retraction beside it
	ob := w.observedRef("ob", "B", "Do", "none-yet", obj(), "fulfills", f)
	w.anchor("anB", "B", "btc:95")
	w.sign("rt", "B", "retracts", obj("of", ob))
	tk = taskV1View(t, w, g, WithTimeVerifier(tb))
	if so := subOf(t, tk, ob); so.V1.State != SubCounted || len(so.V1.Retracted) != 1 {
		t.Fatalf("(c) %+v\n%s", so.V1, tk.Render())
	}
	has(t, tk.Render(), "the count is unchanged")
}

// C-exch-18a: bound refutations.
func TestV1BoundRefutations(t *testing.T) {
	conformance.Covers(t, "C-exch-18a")
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("T1", "R", g, []string{g}, w.v1c("R", "eligible_issuers", w.issuers("A"), "quorum", quorum(1, IndependenceNotRequired)))
	sA := w.submit("SA", "A", g, e, "X")
	ra := w.sign("Ra", "Rr", "refutes", obj("of", sA, "evidence", dig("ev"), "task", g, "edition", w.ed(e)))
	rb := w.sign("Rb", "Rr", "refutes", obj("of", sA, "evidence", dig("ev2")))
	other := w.authored("other", "Z", "elsewhere")
	rd := w.sign("Rd", "Rr", "refutes", obj("of", other, "evidence", dig("ev3"), "task", g, "edition", w.ed(e)))
	dec := w.decide("Dec", "R", g, e, "reject", []string{ra})
	tk := taskV1View(t, w, g)
	out := tk.Render()
	if len(tk.Bound) != 2 || tk.Bound[0].Edition != w.ed(e) {
		t.Fatalf("bound refutations: %+v\n%s", tk.Bound, out)
	}
	has(t, out, "bound refutation "+ra[:8])
	has(t, out, "bound refutation "+rd[:8])
	hasNot(t, out, "bound refutation "+rb[:8])
	s := subOf(t, tk, sA)
	if !slices.Contains(s.Refuted, rb) || !slices.Contains(s.Refuted, ra) {
		t.Fatalf("(b) unbound refutation not shown beside A's submission: %v", s.Refuted)
	}
	for _, p := range tk.Refutations {
		if p.St.ID == rb {
			t.Fatal("(b) an unbound refutation listed in the task under v1")
		}
	}
	rdq := readinessOf(t, tk, w.ed(e))
	for _, gr := range rdq.Groups {
		if slices.Contains(gr, ra) || slices.Contains(gr, rd) {
			t.Fatal("a refutation entered a quorum group")
		}
	}
	for _, d := range tk.Decisions {
		if d.Statement == dec && (!d.Counts || !strings.Contains(out, "citing "+ra[:8])) {
			t.Fatalf("(e) a decision citing a bound refutation: %+v\n%s", d, out)
		}
	}
	// (c) one of task/edition alone is malformed (intrinsic): wire schema test TestTaskKindsBindings
}

// counting_unit identity under v1: readiness unknown naming the missing profile (steward decision F2).
func TestV1IdentityUnit(t *testing.T) {
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.v1c("R", "counting_unit", CountIdentity, "quorum", quorum(1, IndependenceNotRequired)))
	w.submit("S", "A", g, e, "X")
	tk := taskV1View(t, w, g)
	wantToken(t, tk, w, e, ReadyUnknown, 3)
	has(t, tk.Render(), "no identity profile")
}
