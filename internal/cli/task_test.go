package cli

import (
	"path/filepath"
	"regexp"
	"slices"
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

// TestPublishGrant: publish grant signs a coordinator's grant for one edition and prints the readiness after it;
// it refuses (exit 2, nothing signed or appended) a grant this reader would show with no effect.
func TestPublishGrant(t *testing.T) {
	conformance.Partial(t, "C-exch-03b", "the writer half: publish grant refuses a grant by a non-coordinator, on an edition it does not read or that is not authorized; the reading is TestV1Grants in internal/resolve")
	p := newPubWorld(t)
	grantee := p.signer9()
	ct := p.file("c.json", `{"profile":"`+resolve.TaskContractV1Profile+`","question":"q?","beneficiary":"`+p.signer+`","any_issuer":true,"coordinator":"`+p.signer+`","quorum":{"k":1,"independence":"not-required"}}`)
	r := runIn(p.root, nil, "publish", "task", "--key", p.key, "--name", "g", "--contract", ct, "--json")
	if r.code != 0 {
		t.Fatalf("publish task: %d %s", r.code, r.stdout)
	}
	o := outObj(t, r)
	task, ed := string(o.Members["task"].(canon.String)), string(o.Members["edition"].(canon.String))
	approval := statementsOf(o)[1].Members["statement"].(canon.String)
	// the grantee submits before the grant: not counted, then counted once the grant is held (no time order)
	w := p.world
	w.sign("S9", "K9", "submit", obj("task", task, "edition", ed, "result", dig("r")))
	if s := subState(t, taskSection(t, jsonOf(t, w.run("show", task, "--json"))), w.ids["S9"]); s.Members["state"] != canon.String("not counted") {
		t.Fatalf("before the grant: %s", canon.Encode(s))
	}
	grant := func(key string, extra ...string) result {
		if !slices.Contains(extra, "--task") {
			extra = append(extra, "--task", task)
		}
		return runIn(p.root, nil, append([]string{"publish", "grant", "--key", key, "--json"}, extra...)...)
	}
	// refusals: nothing signed or appended
	other := filepath.Join(p.dir, "other.key")
	runIn(p.dir, nil, "key", "new", "--out", other)
	ct2 := p.file("u.json", `{"profile":"task-contract-v9"}`)
	for name, c := range map[string]struct {
		key  string
		args []string
		says string
		exit int
	}{
		"not the coordinator": {other, []string{"--edition", ed, "--grantee", grantee}, "not the edition's coordinator", ExitDidNotStart},
		"an approval id":      {p.key, []string{"--edition", string(approval), "--grantee", grantee}, "statement id of an approval", ExitDidNotStart},
		"no such edition":     {p.key, []string{"--edition", strings.Repeat("ab", 32), "--grantee", grantee}, "holds no edition with that id", ExitCouldNot},
		"no such task":        {p.key, []string{"--edition", ed, "--grantee", grantee, "--task", strings.Repeat("cd", 32)}, "no task genesis", ExitCouldNot},
	} {
		before := snapshot(t, p.root)
		r := grant(c.key, c.args...)
		if r.code != c.exit || !strings.Contains(r.stdout, c.says) || snapshot(t, p.root) != before {
			t.Fatalf("%s: %d %s", name, r.code, r.stdout)
		}
	}
	// a malformed grantee is refused at the argument
	if r := grant(p.key, "--edition", ed, "--grantee", "K9"); r.code != ExitDidNotStart {
		t.Fatalf("malformed grantee: %d %s", r.code, r.stdout)
	}
	// the grant: signed, committed, the readiness after it ready (1 of 1)
	r = grant(p.key, "--edition", ed, "--grantee", grantee, "--note", "welcome")
	if r.code != 0 || !strings.Contains(r.stdout, `"readiness":{`) || !strings.Contains(r.stdout, `"state":"ready"`) || !strings.Contains(r.stdout, `"kind":"grant"`) {
		t.Fatalf("grant: %d %s", r.code, r.stdout)
	}
	sec := taskSection(t, jsonOf(t, w.run("show", task, "--json")))
	if s := subState(t, sec, w.ids["S9"]); s.Members["state"] != canon.String("counted") || s.Members["granted_by"] == nil {
		t.Fatalf("after the grant: %s", canon.Encode(s))
	}
	// an edition this reader does not read: no coordinator is known, refused
	r = runIn(p.root, nil, "publish", "task", "--key", p.key, "--task", task, "--contract", ct2, "--json")
	ed2 := string(outObj(t, r).Members["edition"].(canon.String))
	before := snapshot(t, p.root)
	if r := grant(p.key, "--edition", ed2, "--grantee", grantee); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "does not read the edition's contract") || snapshot(t, p.root) != before {
		t.Fatalf("unread contract: %d %s", r.code, r.stdout)
	}
	// a contract with no coordinator: refused, no grant is required
	ct3 := p.file("n.json", `{"profile":"`+resolve.TaskContractV1Profile+`","question":"q?","beneficiary":"`+p.signer+`","any_issuer":true}`)
	r = runIn(p.root, nil, "publish", "task", "--key", p.key, "--task", task, "--contract", ct3, "--json")
	ed3 := string(outObj(t, r).Members["edition"].(canon.String))
	if r := grant(p.key, "--edition", ed3, "--grantee", grantee); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "names no coordinator") {
		t.Fatalf("no coordinator: %d %s", r.code, r.stdout)
	}
	// the human surface
	if h := runIn(p.root, nil, "publish", "grant", "--key", p.key, "--task", task, "--edition", ed, "--grantee", grantee, "--dry-run"); h.code != 0 || !strings.Contains(h.stdout, "readiness:") {
		t.Fatalf("dry run: %d %s", h.code, h.stdout)
	}
}

// TestTaskIndependenceAndDivergenceOverTheCLI: C-exch-11 and C-exch-14 under task-contract-v1, through show and
// explain. (a) self-declared-accepted, two submitters declare it: ready, and the readiness says the independence
// is self-declared; under `required` the same submissions are `unknown` (verify 3). (b) k = 2 by byte equality:
// A and B match, a later C diverges: ready, and explain still shows C's divergence as its own report.
func TestTaskIndependenceAndDivergenceOverTheCLI(t *testing.T) {
	conformance.Covers(t, "C-exch-11", "C-exch-14")
	for _, mode := range []string{"self-declared-accepted", "required"} {
		w := newWorld(t)
		g := w.taskGenesis("T", "Q")
		_, e := w.taskEd("T:E1", "Q", g, g, v1Contract(w.signer("Q"), "quorum", obj("k", 2, "independence", mode)))
		w.life("SA", "A", "submit", g, e, "result", dig("x"), "self_declared_independence", true)
		w.life("SB", "B", "submit", g, e, "result", dig("x"), "self_declared_independence", true)
		rd := readinessOf(t, taskSection(t, jsonOf(t, w.run("show", g, "--json"))), e)
		v := w.run("verify", g)
		switch mode {
		case "self-declared-accepted":
			if rd.Members["state"] != canon.String("ready") || !strings.Contains(string(canon.Encode(rd.Members["independence"])), "self-declared") || v.code != ExitOK {
				t.Fatalf("%s: %s (verify %d)", mode, canon.Encode(rd), v.code)
			}
			if h := w.run("show", g); !strings.Contains(h.stdout, "independence: self-declared") {
				t.Fatalf("human surface: %s", h.stdout)
			}
		default:
			if rd.Members["state"] != canon.String("unknown") || v.code != ExitCouldNot {
				t.Fatalf("%s: %s (verify %d)", mode, canon.Encode(rd), v.code)
			}
		}
	}
	w := newWorld(t)
	g := w.taskGenesis("T", "Q")
	_, e := w.taskEd("T:E1", "Q", g, g, v1Contract(w.signer("Q"), "quorum", obj("k", 2, "independence", "not-required")))
	w.life("SA", "A", "submit", g, e, "result", dig("x"))
	w.life("SB", "B", "submit", g, e, "result", dig("x"))
	late := w.life("SC", "C", "submit", g, e, "result", dig("z"))
	rd := readinessOf(t, taskSection(t, jsonOf(t, w.run("explain", g, "--json"))), e)
	if rd.Members["state"] != canon.String("ready") || !strings.Contains(string(canon.Encode(rd.Members["reports"])), "divergence report: submission "+late[:12]) {
		t.Fatalf("divergence: %s", canon.Encode(rd))
	}
}

// renderedID finds the abbreviated ids Task.Render prints, in line order: keys (algorithm prefix + 12 hex) and
// statement ids or digests (12 hex, a digest's "sha256:" dropped).
var renderedID = regexp.MustCompile(`\bed25519:[0-9a-f]{12}\b|\b[0-9a-f]{12}\b`)

func renderedIDs(line string) []string { return renderedID.FindAllString(line, -1) }

// sectionUnits collects the elements a fact can be carried by, at any depth (the caller drops the root): for
// every object (a submission, a grant, a decision, an edition, a readiness) the structured strings inside it, refs
// and tokens, into objs; every prose string (an explain line, a report) into strs. Prose inside an object does not make the
// object carry a fact: a readiness's report text repeats ids that only the report states. Lists are not units: a
// list of every grant holds every grant's ids, and would carry any mix of them.
func sectionUnits(v canon.Value, objs, strs *[]string) []string {
	switch x := v.(type) {
	case *canon.Object:
		var leaves []string
		for _, k := range x.Keys {
			leaves = append(leaves, sectionUnits(x.Members[k], objs, strs)...)
		}
		*objs = append(*objs, strings.Join(leaves, " "))
		return leaves
	case canon.Array:
		var leaves []string
		for _, e := range x {
			leaves = append(leaves, sectionUnits(e, objs, strs)...)
		}
		return leaves
	case canon.String:
		if strings.Contains(string(x), " ") {
			*strs = append(*strs, string(x))
			return nil
		}
		return []string{string(x)}
	}
	return nil
}

// TestTaskRenderSectionDrift: the resolver's Task.Render and the CLI's task section are two renderers of one
// Task (taskview F4). Each Render line that prints an id is a fact. A line the CLI prints verbatim (prose: an
// explain line, a reason, a report) is carried by that string. Any other line is its ids plus the first id of the
// line it is indented under (the submission a "refuted by" belongs to, the edition an approval is of), and one
// object of what explain --json prints for the task (its task section, or the resource view beside it for the
// resource half of Render) must hold them all. Checked for every task of taskWorld, before and after the
// conflict clears: an id or a relation printed by Render and by neither form of the CLI fails here. (A fact the
// CLI states twice, structured and in a report, survives losing one form: the guard is "printed", not "printed
// in this field".)
func TestTaskRenderSectionDrift(t *testing.T) {
	w, r := taskWorld(t)
	check := func() {
		t.Helper()
		v, err := loadView(w.s, nil, resolve.WithContractReader(resolve.ContractProfiles{}))
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range []string{r.g, r.review, r.unread} {
			tk, ok := v.r.Task(g)
			if !ok {
				t.Fatalf("task %s not resolved", g[:12])
			}
			ex := jsonOf(t, w.run("explain", g, "--json"))
			var objs, strs []string
			for _, root := range []canon.Value{taskSection(t, ex), ex.Members["resource_view"]} {
				sectionUnits(root, &objs, &strs)
				objs = objs[:len(objs)-1] // the root itself (appended last) holds every id and carries nothing
			}
			type frame struct {
				indent int
				first  string
			}
			var stack []frame
			facts := 0
			for _, line := range strings.Split(strings.TrimRight(tk.Render(), "\n"), "\n") {
				indent := len(line) - len(strings.TrimLeft(line, " "))
				for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
					stack = stack[:len(stack)-1]
				}
				ids := renderedIDs(line)
				// prose the CLI prints verbatim (an explain line, a reason, a report, a terms line, a grant without
				// effect: whole, or after its label) is carried by that string; any other line is a structured fact,
				// its ids with its parent's first id, carried by one object
				tl := strings.TrimSpace(line)
				_, tail, _ := strings.Cut(tl, ": ")
				prose := slices.ContainsFunc(strs, func(u string) bool { return strings.Contains(u, tl) || (tail != "" && strings.Contains(u, tail)) })
				fact := slices.Clone(ids)
				if !prose && len(stack) > 0 && stack[len(stack)-1].first != "" {
					fact = append(fact, stack[len(stack)-1].first)
				}
				first := ""
				if len(ids) > 0 {
					first = ids[0]
				}
				stack = append(stack, frame{indent, first})
				fact = slices.DeleteFunc(fact, func(id string) bool { return id == g[:12] }) // the ref printed for
				if len(fact) == 0 {
					continue
				}
				facts++
				if !prose && !slices.ContainsFunc(objs, func(u string) bool {
					return !slices.ContainsFunc(fact, func(id string) bool { return !strings.Contains(u, id) })
				}) {
					t.Errorf("task %s: Render line %q (ids %v): the CLI section prints it neither verbatim nor in one object", g[:12], tl, fact)
				}
			}
			if facts == 0 {
				t.Fatalf("task %s: Render printed no id\n%s", g[:12], tk.Render())
			}
		}
	}
	check()
	r.supersede(w)
	check()
}
