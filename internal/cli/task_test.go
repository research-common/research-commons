package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// taskRefs are the ids of taskWorld: the task (its genesis), its two editions, an approval of the first, and
// the statements the section prints.
type taskRefs struct {
	g, e1, e2, approval1     string
	grantA, grantX, grantN   string
	sA, sB, sN, sX, sA2      string
	dAccept, dReject, dSuper string
	refute, review, reviewE  string
	unread, unreadE          string
}

// v1Contract is a task-contract-v1 contract: beneficiary ben, any issuer, kv adds fields.
func v1Contract(ben string, kv ...any) *canon.Object {
	return obj(append([]any{"profile", resolve.TaskContractV1Profile, "question", "q?", "beneficiary", ben, "any_issuer", true}, kv...)...)
}

func (w *world) taskGenesis(name, by string) string {
	return w.sign(name, by, "genesis", obj("type", "task", "name", "t-"+name, "controllers", []string{w.signer(by)}, "rule", obj("any_one", true)))
}

func (w *world) taskEd(name, by, g, pred string, c *canon.Object) (string, string) {
	return w.approve(name, by, obj("resource", g, "predecessors", []string{pred}, "contents", obj("contract", canon.Value(c))))
}

func (w *world) life(name, by, kind, g, e string, kv ...any) string {
	return w.sign(name, by, kind, obj(append([]any{"task", g, "edition", e}, kv...)...))
}

// taskWorld is the fixture world plus three tasks:
//   - T: two v1 editions with coordinator C and k = 2. E1: A and X granted by C (counted, agreeing), B with no
//     grant and N granted by M, not the coordinator (both admissible, not counted, named), a bound refutation; the beneficiary decides
//     accept then reject of A's submission (a conflict), then supersedes the reject. E2 (current) succeeds E1:
//     A's E1 grant does not carry, so A's E2 submission is not counted, and E2 is not ready.
//   - R: one v1 edition with no quorum: settled by review.
//   - U: one edition whose contract names a profile this reader does not read: readiness unchecked.
func taskWorld(t *testing.T) (*world, taskRefs) {
	w := fixture(t)
	var r taskRefs
	ben, coord := w.signer("Q"), w.signer("C")
	r.g = w.taskGenesis("T", "Q")
	q := obj("k", 2, "independence", "not-required")
	r.approval1, r.e1 = w.taskEd("T:E1", "Q", r.g, r.g, v1Contract(ben, "coordinator", coord, "quorum", q))
	r.grantA = w.life("gA", "C", "grant", r.g, r.e1, "grantee", w.signer("A"))
	r.grantX = w.life("gX", "C", "grant", r.g, r.e1, "grantee", w.signer("X"))
	r.grantN = w.life("gN", "M", "grant", r.g, r.e1, "grantee", w.signer("N")) // M is not the coordinator: no effect
	r.sA = w.life("SA", "A", "submit", r.g, r.e1, "result", dig("res"))
	r.sB = w.life("SB", "B", "submit", r.g, r.e1, "result", dig("res")) // no grant at all
	r.sN = w.life("SN", "N", "submit", r.g, r.e1, "result", dig("res"))
	r.sX = w.life("SX", "X", "submit", r.g, r.e1, "result", dig("res"))
	r.refute = w.life("RF", "Z", "refutes", r.g, r.e1, "of", r.sA, "evidence", dig("ev"))
	r.dAccept = w.life("D1", "Q", "decide", r.g, r.e1, "submissions", []string{r.sA}, "verdict", "accept")
	r.dReject = w.life("D2", "Q", "decide", r.g, r.e1, "submissions", []string{r.sA}, "verdict", "reject")
	_, r.e2 = w.taskEd("T:E2", "Q", r.g, r.e1, v1Contract(ben, "coordinator", coord, "quorum", q))
	r.sA2 = w.life("SA2", "A", "submit", r.g, r.e2, "result", dig("res"))
	r.review = w.taskGenesis("R", "Q")
	_, r.reviewE = w.taskEd("R:E1", "Q", r.review, r.review, v1Contract(ben))
	r.unread = w.taskGenesis("U", "Q")
	_, r.unreadE = w.taskEd("U:E1", "Q", r.unread, r.unread, obj("profile", "task-contract-v9"))
	return w, r
}

// supersede adds the beneficiary's decision superseding the reject: the conflict clears.
func (r *taskRefs) supersede(w *world) {
	r.dSuper = w.life("D3", "Q", "decide", r.g, r.e1, "submissions", []string{r.sA}, "verdict", "accept", "supersedes", r.dReject)
}

func (r taskRefs) all() []string {
	return []string{r.g, r.e1, r.e2, r.approval1, r.review, r.reviewE, r.unread, r.unreadE}
}

func taskSection(t *testing.T, o *canon.Object) *canon.Object {
	t.Helper()
	x, ok := o.Members["task"].(*canon.Object)
	if !ok {
		t.Fatalf("no task section: %s", canon.Encode(o))
	}
	return x
}

func subState(t *testing.T, sec *canon.Object, id string) *canon.Object {
	t.Helper()
	for _, x := range sec.Members["submissions"].(canon.Array) {
		s := x.(*canon.Object)
		if s.Members["statement"] == canon.String(id) {
			return s
		}
	}
	t.Fatalf("submission %s not in the section: %s", id, canon.Encode(sec))
	return nil
}

func readinessOf(t *testing.T, sec *canon.Object, ed string) *canon.Object {
	t.Helper()
	for _, x := range sec.Members["readiness"].(canon.Array) {
		rd := x.(*canon.Object)
		if rd.Members["edition"] == canon.String(ed) {
			return rd
		}
	}
	t.Fatalf("no readiness for %s: %s", ed, canon.Encode(sec))
	return nil
}

// TestTaskSurfaceSweep: C-core-132, C-core-136 and the P-12 footer over the task section. Every task ref (a
// genesis, an edition id, an approval) of every task state on show, verify and explain, before and after the
// conflict clears, in both forms: table tokens only, each on the human surface, one footer, one exit, and every
// id show cites listed by explain.
func TestTaskSurfaceSweep(t *testing.T) {
	conformance.Partial(t, "C-core-132", "the task section (show, verify, explain of a task, its editions and approvals) prints only table tokens")
	w, r := taskWorld(t)
	sweepRefs(t, w, r.all())
	r.supersede(w)
	sweepRefs(t, w, r.all())
}

// TestTaskShowVerifyExplain: C-exch-03 (and the C-exch-03b, C-exch-05, C-exch-06 outcomes) through the CLI's read verbs. show of
// the task prints the task section; verify exits per task-contracts note §5.7; explain prints every check.
func TestTaskShowVerifyExplain(t *testing.T) {
	conformance.Covers(t, "C-exch-03")
	w, r := taskWorld(t)
	sec := taskSection(t, jsonOf(t, w.run("show", r.g, "--json")))
	// C-exch-03 over the CLI: A and X granted by the coordinator count, citing its grant; B (no grant) and N (a
	// grant by a non-coordinator) are admissible and not counted, naming the coordinator; M's grant has no effect
	if s := subState(t, sec, r.sA); s.Members["state"] != canon.String("counted") || s.Members["granted_by"] != canon.String(r.grantA) {
		t.Fatalf("A: %s", canon.Encode(s))
	}
	if s := subState(t, sec, r.sB); s.Members["state"] != canon.String("not counted") || !strings.Contains(string(canon.Encode(s)), "no grant from "+w.signer("C")[:20]) {
		t.Fatalf("B: %s", canon.Encode(s))
	}
	if s := subState(t, sec, r.sN); s.Members["state"] != canon.String("not counted") || s.Members["granted_by"] != nil {
		t.Fatalf("N: %s", canon.Encode(s))
	}
	if ge := string(canon.Encode(sec.Members["grants_without_effect"])); !strings.Contains(ge, r.grantN[:12]) || !strings.Contains(ge, "is not the edition's coordinator: no effect") {
		t.Fatalf("the non-coordinator's grant: %s", canon.Encode(sec))
	}
	if gs := string(canon.Encode(sec.Members["grants"])); strings.Contains(gs, r.grantN) || !strings.Contains(gs, r.grantA) {
		t.Fatalf("grants: %s", gs)
	}
	// the grant does not carry to E2 (C-exch-03b over the CLI): A's E2 submission is not counted, naming it
	if s := subState(t, sec, r.sA2); s.Members["state"] != canon.String("not counted") || !strings.Contains(string(canon.Encode(s)), "a grant does not carry") {
		t.Fatalf("A on E2: %s", canon.Encode(s))
	}
	if rd := readinessOf(t, sec, r.e1); rd.Members["state"] != canon.String("ready") || rd.Members["count"] != canon.Int(2) {
		t.Fatalf("E1 readiness: %s", canon.Encode(rd))
	}
	if rd := readinessOf(t, sec, r.e2); rd.Members["state"] != canon.String("not ready") || rd.Members["current"] != canon.Bool(true) {
		t.Fatalf("E2 readiness: %s", canon.Encode(rd))
	}
	if b := sec.Members["bound_refutations"].(canon.Array)[0].(*canon.Object); b.Members["refutes"] != canon.String(r.sA) || b.Members["counted"] != canon.String("counted") {
		t.Fatalf("bound refutation: %s", canon.Encode(b))
	}
	// C-exch-05: accept then reject of A's submission by the beneficiary is a visible conflict, exit 3, in both
	// forms; neither ts nor delivery order picks one
	if c := sec.Members["decision_conflict"].(*canon.Object); c.Members["state"] != canon.String("contested") {
		t.Fatalf("conflict: %s", canon.Encode(c))
	}
	for _, ref := range []string{r.g, r.e1, r.approval1} {
		v := w.run("verify", ref, "--json")
		if v.code != ExitCouldNot || !strings.Contains(v.stdout, `"about":"decisions"`) {
			t.Fatalf("verify %s with a decision conflict: %d %s", ref, v.code, v.stdout)
		}
	}
	// the human surface says the same
	h := w.run("show", r.g)
	for _, want := range []string{"task:", "state: not counted", "decision conflict:", "state: contested", "bound refutations:", "grants without effect:"} {
		if !strings.Contains(h.stdout, want) {
			t.Fatalf("show (human) lacks %q:\n%s", want, h.stdout)
		}
	}
	// explain: every check, the passing ones too, the groups and the reports
	ex := taskSection(t, jsonOf(t, w.run("explain", r.g, "--json")))
	s := subState(t, ex, r.sA)
	if !strings.Contains(string(canon.Encode(s.Members["checks"])), `"about":"current submission of its unit","state":"ok"`) {
		t.Fatalf("explain checks: %s", canon.Encode(s))
	}
	if rd := readinessOf(t, ex, r.e1); rd.Members["groups"] == nil {
		t.Fatalf("explain groups: %s", canon.Encode(rd))
	}
	// the superseding decision clears the conflict: verify of E1 exits 0 (ready), of the task 0 (not ready: a
	// completed check whose answer is "not yet")
	r.supersede(w)
	sec = taskSection(t, jsonOf(t, w.run("show", r.g, "--json")))
	if sec.Members["decision_conflict"] != nil {
		t.Fatalf("the conflict did not clear: %s", canon.Encode(sec))
	}
	if s := subState(t, sec, r.sA); s.Members["decision"].(*canon.Object).Members["verdict"] != canon.String("accept") {
		t.Fatalf("the remaining decision: %s", canon.Encode(s))
	}
	if !strings.Contains(string(canon.Encode(sec.Members["decisions"])), `"superseded_by":"`+r.dSuper+`"`) {
		t.Fatalf("the superseded decision is not marked: %s", canon.Encode(sec))
	}
	for ref, want := range map[string]int{r.g: ExitOK, r.e1: ExitOK, r.e2: ExitOK, r.approval1: ExitOK} {
		if v := w.run("verify", ref); v.code != want {
			t.Fatalf("verify %s: %d, want %d\n%s", ref, v.code, want, v.stdout)
		}
	}
	// C-exch-06: settled by review, exit 0; an unread contract, exit 3 naming why
	rs := taskSection(t, jsonOf(t, w.run("show", r.review, "--json")))
	if rd := readinessOf(t, rs, r.reviewE); rd.Members["state"] != canon.String(resolve.ByReview) {
		t.Fatalf("by review: %s", canon.Encode(rd))
	}
	if v := w.run("verify", r.review); v.code != ExitOK {
		t.Fatalf("verify by review: %d %s", v.code, v.stdout)
	}
	us := taskSection(t, jsonOf(t, w.run("show", r.unread, "--json")))
	if rd := readinessOf(t, us, r.unreadE); rd.Members["state"] != canon.String("unchecked") || !strings.Contains(string(canon.Encode(rd)), "unknown contract profile") {
		t.Fatalf("unread: %s", canon.Encode(rd))
	}
	if v := w.run("verify", r.unreadE, "--json"); v.code != ExitCouldNot || !strings.Contains(v.stdout, `"about":"readiness","state":"unchecked"`) {
		t.Fatalf("verify unread: %d %s", v.code, v.stdout)
	}
}

// signLine signs a statement for key n with an explicit ts, without committing it (a delivery order of its own).
func (w *world) signLine(name, n, kind, ts string, body *canon.Object) []byte {
	w.t.Helper()
	s := w.seq[n]
	line, id := wire.Sign(wire.Draft{Kind: kind, Seq: s, Prev: w.head[n], TS: ts, Body: body}, w.key(n))
	w.head[n], w.seq[n] = id, s+1
	w.ids[name] = id
	return line
}

// TestTaskDecisionsOverTheCLI: C-exch-04 and C-exch-05 through show and verify. A decision citing submissions and
// evaluations displays them and settles; one citing nothing is shown `cites nothing` and settles nothing. accept
// then reject by the beneficiary, under equal and reversed ts and in both delivery orders, is the same visible
// conflict (exit 3); a third decision superseding one by id clears it.
func TestTaskDecisionsOverTheCLI(t *testing.T) {
	conformance.Covers(t, "C-exch-04", "C-exch-05")
	// C-exch-04 on the review task of taskWorld
	w, r := taskWorld(t)
	sR := w.life("SR", "A", "submit", r.review, r.reviewE, "result", dig("rv"))
	d1 := w.life("DR1", "Q", "decide", r.review, r.reviewE, "submissions", []string{sR}, "verdict", "accept", "evaluations", []string{dig("review")})
	d0 := w.life("DR0", "Q", "decide", r.review, r.reviewE, "submissions", []string{}, "verdict", "accept")
	sec := taskSection(t, jsonOf(t, w.run("show", r.review, "--json")))
	ds := string(canon.Encode(sec.Members["decisions"]))
	if !strings.Contains(ds, `"cites":["`+sR+`"]`) || !strings.Contains(ds, `"evaluations":["`+dig("review")+`"]`) ||
		!strings.Contains(ds, `"reason":"cites nothing"`) || !strings.Contains(ds, d0) || !strings.Contains(ds, d1) {
		t.Fatalf("decisions: %s", ds)
	}
	if s := subState(t, sec, sR); s.Members["decision"].(*canon.Object).Members["verdict"] != canon.String("accept") {
		t.Fatalf("the citing decision did not settle: %s", canon.Encode(s))
	}
	if v := w.run("verify", r.review); v.code != ExitOK {
		t.Fatalf("verify: %d %s", v.code, v.stdout)
	}
	// C-exch-05: equal and reversed ts, both delivery orders
	var answers []string
	for _, ts := range [][2]string{{"2026-10-20T00:00:00Z", "2026-10-20T00:00:00Z"}, {"2026-10-21T00:00:00Z", "2026-10-20T00:00:00Z"}} {
		for _, reversed := range []bool{false, true} {
			w := newWorld(t)
			ben := w.signer("Q")
			g := w.taskGenesis("T", "Q")
			_, e := w.taskEd("T:E1", "Q", g, g, v1Contract(ben, "quorum", obj("k", 1, "independence", "not-required")))
			s1 := w.life("S1", "A", "submit", g, e, "result", dig("x"))
			acc := w.signLine("DA", "Q", "decide", ts[0], obj("task", g, "edition", e, "submissions", []string{s1}, "verdict", "accept"))
			rej := w.signLine("DR", "Q", "decide", ts[1], obj("task", g, "edition", e, "submissions", []string{s1}, "verdict", "reject"))
			order := [][]byte{acc, rej}
			if reversed {
				order = [][]byte{rej, acc}
			}
			for _, l := range order {
				if _, err := w.s.Commit("publish", [][]byte{l}, nil); err != nil {
					t.Fatal(err)
				}
			}
			v := w.run("verify", g, "--json")
			if v.code != ExitCouldNot || !strings.Contains(v.stdout, `"about":"decisions","on":["`+s1+`"],"state":"contested"`) {
				t.Fatalf("ts %v reversed %v: %d %s", ts, reversed, v.code, v.stdout)
			}
			sec := taskSection(t, jsonOf(t, w.run("show", g, "--json")))
			answers = append(answers, string(canon.Encode(sec.Members["decision_conflict"])))
			w.life("D3", "Q", "decide", g, e, "submissions", []string{s1}, "verdict", "reject", "supersedes", w.ids["DA"])
			if v := w.run("verify", g); v.code != ExitOK {
				t.Fatalf("after supersession: %d %s", v.code, v.stdout)
			}
			sec = taskSection(t, jsonOf(t, w.run("show", g, "--json")))
			if s := subState(t, sec, s1); s.Members["decision"].(*canon.Object).Members["verdict"] != canon.String("reject") ||
				!strings.Contains(string(canon.Encode(sec.Members["decisions"])), `"superseded_by":"`+w.ids["D3"]+`"`) {
				t.Fatalf("supersession: %s", canon.Encode(sec))
			}
		}
	}
	for _, a := range answers[1:] {
		if a != answers[0] {
			t.Fatalf("the conflict differs by ts or order:\n%s\n%s", answers[0], a)
		}
	}
}
