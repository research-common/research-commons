package resolve

import (
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// genForest is a generated log of one key as wire statements: forks (several lines on one prev), merges, and
// lines whose prev is not held. It is the input the ancestry index is compared with the plain walk on.
func genForest(seed uint64, n, mergeEvery int) map[string]*wire.Statement {
	x := seed*0x9e3779b97f4a7c15 + 11
	rnd := func(k int) int { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return int(x % uint64(k)) }
	chained := map[string]*wire.Statement{}
	var ids []string
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%064x", uint64(i)*2654435761+seed)
		st := &wire.Statement{ID: id}
		switch {
		case i == 0:
		case rnd(9) == 0:
			st.Prev = fmt.Sprintf("%064x", 0xdead0000+uint64(i)) // a prev that is not held: another root
		default:
			st.Prev = ids[rnd(len(ids))]
		}
		if mergeEvery > 0 && i > 2 && rnd(mergeEvery) == 0 {
			for k := 0; k <= rnd(2); k++ {
				st.Merges = append(st.Merges, ids[rnd(len(ids))])
			}
		}
		chained[id] = st
		ids = append(ids, id)
	}
	return chained
}

// TestAncestryAnswersWhatTheWalkAnswers: for every pair of lines of generated logs (forks, several roots, merges
// few and many), the index says a line is in another's history exactly when the walk through prev and merges
// reaches it. The many-merges logs run the fallback, and the test requires both paths to have been taken.
func TestAncestryAnswersWhatTheWalkAnswers(t *testing.T) {
	indexed, walked, viaMerge := 0, 0, 0
	for seed := uint64(1); seed <= 60; seed++ {
		mergeEvery := []int{0, 12, 5, 2}[seed%4]
		n := 30 + int(seed%5)*25
		chained := genForest(seed, n, mergeEvery)
		a := newAncestry(chained)
		if a.walk {
			walked++
		} else {
			indexed++
		}
		for from := range chained {
			want := closure(from, chained)
			for x := range chained {
				if got := a.reaches(from, x); got != want[x] {
					t.Fatalf("seed %d (%d lines, %d merge lines, walk=%v): reaches(%s, %s) = %v, the walk says %v", seed, n, len(a.merges), a.walk, from[:8], x[:8], got, want[x])
				}
				if want[x] && !a.walk && !a.onPrevPath(from, x) {
					viaMerge++
				}
			}
			// an id that is not a chained line is in no history, and has none
			if a.reaches(from, "absent") || a.reaches("absent", from) {
				t.Fatalf("seed %d: an unheld line is in a history", seed)
			}
		}
	}
	if indexed == 0 || walked == 0 || viaMerge == 0 {
		t.Fatalf("%d logs answered by the index, %d by the walk, %d answers reached through a merge: each must occur", indexed, walked, viaMerge)
	}
	var none *ancestry
	if none.reaches("a", "a") {
		t.Fatal("a key with no log has a history")
	}
}

// scanWorld is a store that exercises every index this file checks: observations sharing referents (and not),
// method-class observations of two method editions, corroborations whose results list inputs, a task with its
// lifecycle statements, a collection with editions and a withdrawn approval, anchors, retractions, and
// statements the reader cannot evaluate.
func scanWorld(t *testing.T) (*world, *Resolver) {
	w := newWorld(t)
	for i := 0; i < 6; i++ {
		k := []string{"Aa", "Ba", "Ca"}[i%3]
		w.observed(fmt.Sprintf("s%d", i), k, fmt.Sprintf("S%d", i), "source", apiRef(fmt.Sprintf("https://api.example/%d", i/2)))
		w.observed(fmt.Sprintf("x%d", i), k, fmt.Sprintf("X%d", i), "exact-bytes", chainRef(i%2))
		w.observedMethod(fmt.Sprintf("m%d", i), k, fmt.Sprintf("M%d", i), map[string]string{"model": fmt.Sprintf("v%d", i%2)}, strings.Repeat("ab", 20))
		w.phenomenon(fmt.Sprintf("p%d", i), k, fmt.Sprintf("P%d", i), "thermo-1", "")
	}
	other := obj("method_edition", strings.Repeat("cd", 32),
		"environment", obj("image_digest", dig("img"), "platform", "linux/amd64", "harness_commit", strings.Repeat("ab", 20)),
		"system", obj("model", "v0"), "window", obj("from", "2026-01-01T00:00:00Z", "to", "2026-01-02T00:00:00Z"))
	w.observedRef("m-other", "Aa", "MO", "method", other)
	// results with comparison data, and corroborations naming them
	w.authored("res1", "Ba", "R1", "prov", []string{"WF", "S0", "S1", "S0"})
	w.authored("res2", "Ca", "R2", "prov", []string{"WF", "X0"})
	w.authored("plain", "Ca", "R3")
	w.corroborates("c1", "Ba", w.ids["s0"], w.ids["res1"], "contradicts")
	w.corroborates("c2", "Ca", w.ids["x1"], w.ids["res2"], "supports")
	w.corroborates("c3", "Ca", w.ids["s2"], w.ids["plain"], "contradicts")
	w.corroborates("c4", "Aa", w.ids["s3"], w.ids["s0"], "contradicts") // its result is not an authored
	w.sign("t1", "Aa", "retracts", obj("of", w.ids["s0"], "reason", "wrong window"))
	w.sign("d1", "Ba", "describes", obj("about", obj("statement", w.ids["s0"]), "note", "n"))
	w.sign("f1", "Ca", "refutes", obj("of", w.ids["s0"], "evidence", dig("E")))
	// a task and its lifecycle
	g := w.task("T", "Aa")
	e := w.taskEdition("TE", "Aa", g, []string{g}, w.contract("Aa"))
	w.authored("sub-a", "Ba", "RS")
	sub := w.submit("sub", "Ba", g, e, "RS")
	w.decide("dec", "Aa", g, e, "accept", []string{sub})
	g2 := w.task("T2", "Ca")
	e2 := w.taskEdition("TE2", "Ca", g2, []string{g2}, w.contract("Ca"))
	w.submit("sub2", "Ba", g2, e2, "RS")
	// a wire grant on each task, by its coordinator: a task reads its own and never the other's
	w.sign("gr1", "Aa", "grant", obj("task", g, "edition", e, "grantee", w.signer("Ba")))
	w.sign("gr2", "Ca", "grant", obj("task", g2, "edition", e2, "grantee", w.signer("Ba")))
	// refutations reaching a submission three ways: naming the submit, naming the claim of the submitted result,
	// and bound to the task by its own `task` member; and one that reaches nothing
	w.sign("rf-sub", "Ca", "refutes", obj("of", sub, "evidence", dig("E1")))
	w.sign("rf-claim", "Ca", "refutes", obj("of", w.ids["sub-a"], "evidence", dig("E2")))
	w.sign("rf-task", "Aa", "refutes", obj("of", sub, "evidence", dig("E3"), "task", g, "edition", e))
	w.sign("rf-none", "Ca", "refutes", obj("of", w.ids["plain"], "evidence", dig("E4")))
	// several more of one submission by several keys, so their order in the store differs from their id order
	for i := 0; i < 6; i++ {
		w.sign(fmt.Sprintf("rf-more%d", i), []string{"Ca", "Aa", "Ba"}[i%3], "refutes", obj("of", sub, "evidence", dig(fmt.Sprintf("EM%d", i))))
	}
	// a collection with a chain of editions
	c := w.genesis("G", "Aa", 0, "Aa")
	prev := c
	for i := 0; i < 4; i++ {
		prev = w.edition(fmt.Sprintf("e%d", i), "Aa", c, []string{prev}, []string{fmt.Sprintf("S%d", i)})
	}
	w.sign("wd", "Aa", "withdraw_approval", obj("resource", c, "edition", w.ed(prev)))
	// anchors by two keys
	w.anchor("an1", "Aa", "p1")
	w.authored("late", "Aa", "LATE")
	w.anchor("an2", "Aa", "p2")
	w.anchor("an3", "Ba", "p3")
	// statements this reader cannot evaluate, with bodies no schema checked
	signCritical(w, "u1", "Ca", "observed", obj("content", contentOf("S0"), "class", 1, "referent", false))
	signCritical(w, "u2", "Ca", "corroborates", obj("of", w.ids["s0"], "verdict", "contradicts", "cohort", false))
	signCritical(w, "u3", "Ca", "edition", obj("resource", c, "contents", false))
	signCritical(w, "u4", "Ca", "submit", obj("task", g, "result", 1))
	signCritical(w, "u5", "Ca", "anchors", obj("covered", w.head["Ca"], "proof", 1, "proof_format", false))
	signCritical(w, "u6", "Ca", "observed", obj("content", contentOf("S0"), "class", "source", "referent", obj("requests", false)))
	return w, w.store(nil)
}

func strField(p *Placed, f string) string { return str(p.St.Body, f) }

// TestScanIndexesAnswerWhatTheScansAnswered: each index added for the read-cost audit is the per-kind list split,
// in the same order, and each rewired walk selects what the scan it replaced selected.
func TestScanIndexesAnswerWhatTheScansAnswered(t *testing.T) {
	w, r := scanWorld(t)

	// bySigner: every kind, every key
	for kind, all := range r.byKind {
		seen := 0
		for key, got := range r.bySigner[kind] {
			var want []*Placed
			for _, p := range all {
				if p.St.Signer == key {
					want = append(want, p)
				}
			}
			if placedIDs(got) != placedIDs(want) {
				t.Fatalf("by(%s, %s):\n got %s\nwant %s", kind, key, placedIDs(got), placedIDs(want))
			}
			seen += len(got)
		}
		if seen != len(all) {
			t.Fatalf("bySigner[%s] files %d of %d statements", kind, seen, len(all))
		}
	}
	// byField: the indexed member of each indexed kind, every value held. The member each kind is reached by is
	// written out here, not read from the table under test: a table naming the wrong member must fail.
	reachedBy := map[string]string{"edition": "resource", "withdraw_approval": "resource", "corroborates": "of", "retracts": "of",
		"submit": "task", "decide": "task", "intent": "task", "progress": "task", "withdraw": "task", "grant": "task"}
	if len(fieldIndex) != len(reachedBy) {
		t.Fatalf("fieldIndex names %d kinds, this test knows %d", len(fieldIndex), len(reachedBy))
	}
	for kind, f := range reachedBy {
		if fieldIndex[kind] != f {
			t.Fatalf("%s is indexed by %q; the walks reach it by %q", kind, fieldIndex[kind], f)
		}
		seen := 0
		for v, got := range r.byField[kind] {
			var want []*Placed
			for _, p := range r.byKind[kind] {
				if strField(p, f) == v {
					want = append(want, p)
				}
			}
			if placedIDs(got) != placedIDs(want) {
				t.Fatalf("named(%s, %s):\n got %s\nwant %s", kind, v, placedIDs(got), placedIDs(want))
			}
			seen += len(got)
		}
		if seen != len(r.byKind[kind]) {
			t.Fatalf("byField[%s] files %d of %d statements", kind, seen, len(r.byKind[kind]))
		}
	}
	for _, kind := range []string{"edition", "withdraw_approval", "corroborates", "submit", "decide", "retracts"} {
		if len(r.byKind[kind]) == 0 {
			t.Fatalf("the fixture holds no %s", kind)
		}
	}

	// the task walks select by task: each task shows the submit and decide statements that name it, and no other
	tasks, refuted, viaClaim, unsorted := 0, 0, 0, 0
	for _, g := range r.byKind["genesis"] {
		if str(g.St.Body, "type") != "task" {
			continue
		}
		task, ok := r.Task(g.St.ID)
		if !ok {
			t.Fatalf("task %s did not resolve", g.St.ID)
		}
		var want, got []string
		for _, p := range r.byKind["submit"] {
			if p.St.Verified && p.St.Status == wire.Valid && str(p.St.Body, "task") == g.St.ID {
				want = append(want, p.St.ID)
			}
		}
		for _, sb := range task.Submissions {
			if sb.Kind == "submit" {
				got = append(got, sb.Statement)
			}
		}
		slices.Sort(want)
		slices.Sort(got)
		if strings.Join(got, " ") != strings.Join(want, " ") || len(want) == 0 {
			t.Fatalf("task %s shows submissions %v, the store holds %v naming it", g.St.ID, got, want)
		}
		// grants and grant notes name this task's grants only
		mine := 0
		for _, p := range r.byKind["grant"] {
			if str(p.St.Body, "task") != g.St.ID {
				for _, gr := range task.Grants {
					if gr.Statement == p.St.ID {
						t.Fatalf("task %s lists grant %s, which names another task", g.St.ID, p.St.ID)
					}
				}
				for _, note := range task.GrantNotes {
					if strings.Contains(note, p.St.ID[:8]) {
						t.Fatalf("task %s has a note about grant %s, which names another task: %s", g.St.ID, p.St.ID, note)
					}
				}
				continue
			}
			mine++
		}
		if mine == 0 || len(task.Grants)+len(task.GrantNotes) != mine {
			t.Fatalf("task %s is named by %d grants and shows %d grants and %d notes", g.St.ID, mine, len(task.Grants), len(task.GrantNotes))
		}
		// refutations, as the walk over every `refutes` in the store attached them: one naming a submission or a
		// counted claim of its result, in the order the walk met them
		claimOf := map[string]string{}
		for _, sb := range task.Submissions {
			for _, p := range r.byKind["authored"] {
				if contentDigest(p.St.Body) == sb.Result && r.counts(p) {
					claimOf[p.St.ID] = sb.Statement
				}
			}
		}
		wantRefuted := map[string][]string{}
		for _, p := range r.byKind["refutes"] {
			if !p.EvidenceReady() || !r.gate(p).Counts {
				continue
			}
			of := str(p.St.Body, "of")
			target := ""
			for _, sb := range task.Submissions {
				if sb.Statement == of {
					target = of
				}
			}
			if target == "" {
				target = claimOf[of]
			}
			if target != "" {
				wantRefuted[target] = append(wantRefuted[target], p.St.ID)
				viaClaim += map[bool]int{true: 1}[claimOf[of] != "" && target != of]
			}
		}
		for _, sb := range task.Submissions {
			if strings.Join(sb.Refuted, " ") != strings.Join(wantRefuted[sb.Statement], " ") {
				t.Fatalf("task %s submission %s is refuted by %v, the scan says %v", g.St.ID, sb.Statement, sb.Refuted, wantRefuted[sb.Statement])
			}
			refuted += len(sb.Refuted)
			if !slices.IsSorted(sb.Refuted) && !slices.IsSortedFunc(sb.Refuted, func(a, b string) int { return strings.Compare(b, a) }) {
				unsorted++
			}
		}
		tasks++
	}
	if refuted < 3 || viaClaim == 0 || unsorted == 0 {
		t.Fatalf("%d refutations attached, %d through a claim of the result, %d submissions whose refutations are in neither id order: the fixture must have each", refuted, viaClaim, unsorted)
	}
	if tasks < 2 {
		t.Fatalf("%d tasks in the fixture: two are needed to tell one task's statements from another's", tasks)
	}

	// byReferent: sameReferent never holds between two statements filed under different keys, or under none
	obs := r.byKind["observed"]
	same := 0
	for _, a := range obs {
		for _, b := range obs {
			if a == b || !a.EvidenceReady() || !b.EvidenceReady() {
				continue
			}
			if sameReferent(a.St, b.St) {
				same++
				if ka, kb := referentKey(a.St), referentKey(b.St); ka == "" || ka != kb {
					t.Fatalf("%s and %s share a referent and are filed under %q and %q", a.St.ID, b.St.ID, ka, kb)
				}
			}
		}
		// the two walks over a referent select what the scans selected
		if !a.EvidenceReady() {
			continue
		}
		var scan, idx []string
		for _, q := range obs {
			if r.gate(q).Counts && q.St.ID != a.St.ID && sameReferent(a.St, q.St) {
				scan = append(scan, q.St.ID)
			}
		}
		for _, q := range r.byReferent[referentKey(a.St)] {
			if r.gate(q).Counts && q.St.ID != a.St.ID && sameReferent(a.St, q.St) {
				idx = append(idx, q.St.ID)
			}
		}
		if strings.Join(idx, " ") != strings.Join(scan, " ") {
			t.Fatalf("same-referent captures of %s:\n got %v\nwant %v", a.St.ID, idx, scan)
		}
	}
	if same == 0 {
		t.Fatal("no two observations in the fixture share a referent")
	}
	// byMethod: the method-class observations of one method edition
	methods := 0
	for ed, got := range r.byMethod {
		var want []*Placed
		for _, q := range obs {
			if str(q.St.Body, "class") == "method" && str(object(q.St.Body, "referent"), "method_edition") == ed {
				want = append(want, q)
			}
		}
		if placedIDs(got) != placedIDs(want) {
			t.Fatalf("byMethod[%s]:\n got %s\nwant %s", ed, placedIDs(got), placedIDs(want))
		}
		methods++
	}
	if methods < 2 {
		t.Fatalf("%d method editions in the fixture", methods)
	}
	// byComparison: the corroborates whose comparison data can include a blob. comparisonData is the definition.
	found := 0
	digests := map[string]bool{}
	for _, p := range r.byKind["authored"] {
		if pv, ok := provKey(p.St); ok && pv != "" {
			for _, in := range provenance(p.St.Body).Inputs {
				digests[in] = true
			}
		}
	}
	digests[dig("nothing lists this")] = true
	for d := range digests {
		var want []*Placed
		for _, p := range r.byKind["corroborates"] {
			res, ok := r.byID[str(p.St.Body, "result")]
			if !ok || res.St.Kind != "authored" {
				continue
			}
			if pv, filed := provKey(res.St); !filed || pv == "" {
				continue
			}
			if slices.Contains(provenance(res.St.Body).Inputs, d) {
				want = append(want, p)
			}
		}
		if got := r.byComparison[d]; placedIDs(got) != placedIDs(want) {
			t.Fatalf("byComparison[%s]:\n got %s\nwant %s", d, placedIDs(got), placedIDs(want))
		}
		found += len(want)
	}
	if found == 0 {
		t.Fatal("no corroboration in the fixture names a result with inputs")
	}
	// and every corroborates comparisonData would answer for is filed under each blob it answers with
	for _, p := range r.byKind["corroborates"] {
		of, ok := r.byID[str(p.St.Body, "of")]
		if !ok {
			continue
		}
		for _, in := range r.comparisonData(str(p.St.Body, "result"), contentDigest(of.St.Body)) {
			if !slices.Contains(r.byComparison[in], p) {
				t.Fatalf("corroborates %s has %s as comparison data and is not filed under it", p.St.ID, in)
			}
		}
	}

	// the anchors walks: covering anchors and bounds, as the scan over every anchors line answered them
	covered := 0
	for id, p := range r.byID {
		var want []string
		for _, a := range r.byKind["anchors"] {
			if a.St.Signer != p.St.Signer {
				continue
			}
			cov := str(a.St.Body, "covered")
			if cov == "" || !(cov != a.St.ID && closure(a.St.ID, r.chained[p.St.Signer])[cov]) || !closure(cov, r.chained[p.St.Signer])[id] {
				continue
			}
			want = append(want, a.St.ID)
		}
		slices.Sort(want)
		if got := r.CoveringAnchors(id); strings.Join(got, " ") != strings.Join(want, " ") {
			t.Fatalf("CoveringAnchors(%s):\n got %v\nwant %v", id, got, want)
		}
		covered += len(want)
	}
	if covered == 0 {
		t.Fatal("no statement in the fixture is covered by an anchor")
	}
	_ = w
}

// countingVerifier counts how often each anchors line is put to the time verifier.
type countingVerifier struct{ asked map[string]int }

func (c countingVerifier) Verify(a *wire.Statement) Bound {
	c.asked[a.ID]++
	return NoTimeVerifier{}.Verify(a)
}

// TestAnchorVerifiedOncePerSnapshot: the reader's time verifier is asked about an anchors line once per resolver,
// however many statements the line covers and however often their bounds are read. An anchors line covers every
// line before it, so asking per covered statement cost one proof verification per statement per anchor.
func TestAnchorVerifiedOncePerSnapshot(t *testing.T) {
	w := newWorld(t)
	var ids []string
	for i := 0; i < 40; i++ {
		ids = append(ids, w.authored(fmt.Sprintf("a%d", i), "Aa", fmt.Sprintf("B%d", i)))
		if i%10 == 9 {
			w.anchor(fmt.Sprintf("an%d", i), "Aa", fmt.Sprintf("p%d", i))
		}
	}
	cv := countingVerifier{asked: map[string]int{}}
	r := w.store(nil, WithTimeVerifier(cv))
	first := map[string]Bound{}
	for _, id := range ids {
		first[id], _ = r.StatementBound(id)
	}
	for _, id := range ids {
		if b, _ := r.StatementBound(id); b != first[id] {
			t.Fatalf("the bound of %s changed between two reads of one snapshot", id)
		}
		_ = r.AnchorLines(id)
	}
	if len(cv.asked) != 4 {
		t.Fatalf("the verifier was asked about %d anchors lines, the log holds 4", len(cv.asked))
	}
	for a, n := range cv.asked {
		if n != 1 {
			t.Fatalf("anchors line %s was verified %d times in one snapshot", a, n)
		}
	}
	// a fresh resolver asks again: nothing outlives the snapshot
	cv2 := countingVerifier{asked: map[string]int{}}
	r2 := w.store(nil, WithTimeVerifier(cv2))
	_, _ = r2.StatementBound(ids[0])
	if len(cv2.asked) == 0 {
		t.Fatal("a second resolver did not ask its own verifier")
	}
}

// authorizeBySweep is authorize as it was: every open proposal evaluated in every round, in id order, until a
// round in which none reaches a terminal state.
func authorizeBySweep(r *Resolver, id string, genAuth authority, props map[string]*Edition, alias map[string]string) (auth, contested map[string]authority) {
	auth = map[string]authority{id: genAuth}
	contested = map[string]authority{}
	for changed := true; changed; {
		changed = false
		for _, eid := range sortedKeys(props) {
			e := props[eid]
			if e.State == Authorized || e.State == Invalid || e.State == Contested {
				continue
			}
			if r.evaluate(e, auth, contested, props, alias) {
				changed = true
			}
		}
	}
	return auth, contested
}

func authorityText(m map[string]authority) string {
	var out []string
	for _, k := range sortedKeys(m) {
		out = append(out, k+"="+m[k].describe())
	}
	return strings.Join(out, ";")
}

func proposalsText(props map[string]*Edition) string {
	var b strings.Builder
	for _, eid := range sortedKeys(props) {
		e := props[eid]
		fmt.Fprintf(&b, "%s %s k=%d %v | %s\n", eid, e.State, e.K, e.Controllers, strings.Join(e.Explain, " / "))
	}
	return b.String()
}

// TestAuthorizeAnswersWhatTheSweepAnswered: over generated resources (chains, forks, joins, proposals whose
// predecessor is not held or never authorized, a controller change mid-chain, approvals by keys that are not
// controllers), authorize leaves every proposal in the state and with the explanation the full sweep leaves, and
// returns the same authorities.
func TestAuthorizeAnswersWhatTheSweepAnswered(t *testing.T) {
	states := map[EditionState]int{}
	for seed := uint64(1); seed <= 120; seed++ {
		x := seed*0x9e3779b97f4a7c15 + 5
		rnd := func(k int) int { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return int(x % uint64(k)) }
		w := newWorld(t)
		keys := []string{"Aa", "Ba", "Ca"}
		k := 0
		if seed%3 == 0 {
			k = 2
		}
		g := w.genesis("G", "Aa", k, "Aa", "Ba")
		nodes := []string{g}
		n := 4 + rnd(10)
		for i := 0; i < n; i++ {
			var preds []string
			for len(preds) == 0 || (len(preds) < 2 && rnd(4) == 0) {
				p := nodes[rnd(len(nodes))]
				if !slices.Contains(preds, p) {
					preds = append(preds, p)
				}
			}
			var extra []any
			if rnd(6) == 0 {
				extra = []any{"controllers", w.controllers("Ba", "Ca"), "rule", canon.Value(obj("any_one", true))}
			}
			body := w.editionBody(g, preds, []string{fmt.Sprintf("m%d-%d", seed, i)}, extra...)
			if rnd(7) == 0 {
				// name a predecessor nobody holds
				body.Members["predecessors"] = canon.Array{canon.String(strings.Repeat(fmt.Sprintf("%x", i%16), 64))}
			}
			name := fmt.Sprintf("e%d", i)
			for a := 0; a <= rnd(2); a++ {
				w.sign(fmt.Sprintf("%s-%d", name, a), keys[rnd(len(keys))], "edition", body)
			}
			nodes = append(nodes, w.ids[name+"-0"])
		}
		order := shuffleInts(len(w.lines), seed)
		r := w.store(order)
		gp, _ := r.byID[g]
		genAuth, _ := authorityOf(gp.St.Body, majorOf(gp.St))

		p1, a1 := r.proposals(g)
		wantAuth, wantCont := authorizeBySweep(r, g, genAuth, p1, a1)
		p2, a2 := r.proposals(g)
		gotAuth, gotCont := r.authorize(g, genAuth, p2, a2)
		if got, want := proposalsText(p2), proposalsText(p1); got != want {
			t.Fatalf("seed %d: proposals differ\n got:\n%s\nwant:\n%s", seed, got, want)
		}
		if authorityText(gotAuth) != authorityText(wantAuth) || authorityText(gotCont) != authorityText(wantCont) {
			t.Fatalf("seed %d: authorities differ\n got %s | %s\nwant %s | %s", seed, authorityText(gotAuth), authorityText(gotCont), authorityText(wantAuth), authorityText(wantCont))
		}
		for _, e := range p2 {
			states[e.State]++
		}
	}
	for _, s := range []EditionState{Authorized, Pending, Unauthorized, Orphan} {
		if states[s] == 0 {
			t.Fatalf("no generated proposal ended %s (reached: %v)", s, states)
		}
	}
}

func shuffleInts(n int, seed uint64) []int {
	x := seed*0x9e3779b97f4a7c15 + 3
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	for i := n - 1; i > 0; i-- {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		j := int(x % uint64(i+1))
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// TestOneComparisonIsTheListEntry: the single comparison a corroboration asks for (comparableWith) is the entry
// the whole list (Comparability) holds for that statement, for every pair of held statements; and it answers
// nothing for a statement the list leaves out. Under a method edition that declares no system_keys, one that
// declares some, and one the reader does not hold.
func TestOneComparisonIsTheListEntry(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("G", "MA", 1, "MA")
	body := w.editionBody(g, []string{g}, nil, "system_keys", []string{"model", "routing_era"})
	declaring := EditionID(body)
	w.sign("MA1", "MA", "edition", body)
	plainBody := w.editionBody(g, []string{declaring}, nil)
	plain := EditionID(plainBody)
	w.sign("MA2", "MA", "edition", plainBody)
	unheld := strings.Repeat("cd", 32)
	i := 0
	for _, ed := range []string{declaring, plain, unheld} {
		for _, sys := range []*canon.Object{obj("model", "m", "routing_era", "e"), obj("model", "m"), obj("model", "m", "routing_era", ""),
			obj("model", "m", "routing_era", "e", "region", "r"), obj("region", "r")} {
			for _, k := range []string{"Aa", "Ba"} {
				i++
				w.observed(fmt.Sprintf("o%d", i), k, fmt.Sprintf("B%d", i), "method", methodRef(ed, sys))
			}
		}
	}
	w.observed("src", "Aa", "SRC", "source", apiRef("https://api.example/src"))
	// an observation of another class whose referent happens to carry a method_edition member: not a method
	// observation, so never compared
	odd := apiRef("https://api.example/odd")
	odd.Keys, odd.Members["method_edition"] = append(odd.Keys, "method_edition"), canon.String(declaring)
	slices.SortFunc(odd.Keys, canon.CompareKeys)
	oddID := w.observed("odd", "Aa", "ODD", "source", odd)
	// a method observation that does not count: its key's revocation keeps only the line before it
	kept := w.authored("kept", "Rv", "kept")
	notCounted := w.observed("revoked", "Rv", "RVK", "method", methodRef(declaring, obj("model", "m", "routing_era", "e")))
	w.sign("revoke", "Rv", "revoke_key", obj("reason", "key_compromise", "last_good", kept))
	r := w.store(nil)

	if p := r.byID[notCounted]; r.counts(p) {
		t.Fatal("the revoked key's observation counts: the world no longer holds a statement the list leaves out")
	}
	if p, ok := r.byID[oddID]; !ok || !r.counts(p) {
		t.Fatal("the source observation carrying a method_edition member is not held and counted")
	}
	lists, pairs, differing := 0, 0, map[string]bool{}
	for _, p := range r.byKind["observed"] {
		o := r.observation(p)
		entries := map[string]Comparability{}
		for _, c := range o.Comparability() {
			entries[c.With] = c
		}
		if len(entries) != len(o.Comparability()) {
			t.Fatalf("%s: a statement is listed twice", p.St.ID)
		}
		if len(entries) > 0 {
			lists++
		}
		for _, q := range r.All() {
			got, ok := r.comparableWith(o, q)
			want, listed := entries[q.St.ID]
			if ok != listed || !reflect.DeepEqual(got, want) {
				t.Fatalf("%s against %s:\n one comparison %v %+v\n list entry     %v %+v", keylog.Short(p.St.ID), keylog.Short(q.St.ID), ok, got, listed, want)
			}
			if ok {
				pairs++
				differing[fmt.Sprint(got.Comparable, got.EditionUnread != "", len(got.Unpinned) > 0, len(got.MissingHere) > 0, len(got.MissingThere) > 0)] = true
			}
		}
		if lite := r.observationLite(p); !reflect.DeepEqual(lite.Comparability(), o.Comparability()) {
			t.Fatalf("%s: the lite view lists other comparisons", p.St.ID)
		}
	}
	// the world reaches what it is for: three editions' worth of lists, and comparisons of several outcomes
	if lists < 30 || pairs < 3*10*9 || len(differing) < 5 {
		t.Fatalf("%d lists, %d pairs, %d distinct outcomes: the world no longer covers the comparison", lists, pairs, len(differing))
	}
}

// costShape is one store shape and the questions a command asks of it, for TestReadCostIsLinear.
type costShape struct {
	name  string
	build func(t *testing.T, n int) func()
}

func costShapes() []costShape {
	// Odd-length names are Ed25519 keys (testKey): cheap to sign and verify, so a store can be large enough for
	// a quadratic walk to dominate what is measured. Many keys keep each log short.
	const keys = 64
	key := func(i int) string { return fmt.Sprintf("K%04d", i%keys) }
	return []costShape{
		{"observations, 8 captures per referent", func(t *testing.T, n int) func() {
			w := newWorld(t)
			var ds []string
			for i := 0; i < n; i++ {
				x := fmt.Sprintf("o%d", i)
				w.observed("o-"+x, key(i), x, "source", apiRef(fmt.Sprintf("https://api.example/%d", i/8)))
				ds = append(ds, dig(x))
			}
			r := w.store(nil)
			return func() {
				for _, d := range ds {
					_ = r.Observations(d)
				}
			}
		}},
		{"observations, each corroborated against a result", func(t *testing.T, n int) func() {
			w := newWorld(t)
			var ds []string
			for i := 0; i < n/3; i++ {
				x := fmt.Sprintf("o%d", i)
				id := w.observed("o-"+x, key(i), x, "source", apiRef("https://api.example/"+x))
				res := w.authored("r-"+x, key(i+1), "r-"+x, "prov", []string{"WF", x, "other-" + x})
				w.corroborates("c-"+x, key(i+1), id, res, "contradicts")
				ds = append(ds, dig(x))
			}
			r := w.store(nil)
			return func() {
				for _, d := range ds {
					_ = r.Observations(d)
				}
			}
		}},
		{"method observations of one method edition, each corroborated against another", func(t *testing.T, n int) func() {
			// Every observation pins the same method edition, so each has n-1 others to be compared with; one in
			// three leaves out a system key, so a third of the corroborations meet an incomparable input. The
			// corroboration needs one of those comparisons, not the list of them.
			// The edition is held and authorized and declares no system_keys: unread, every pair would be
			// unchecked whatever it pins.
			w := newWorld(t)
			g := w.genesis("G", "MA", 1, "MA")
			body := w.editionBody(g, []string{g}, nil)
			w.sign("MA1", "MA", "edition", body)
			var ds, ids []string
			for i := 0; i < n; i++ {
				x := fmt.Sprintf("m%d", i)
				sys := obj("model", "m", "routing_era", "e")
				if i%3 == 0 {
					sys = obj("model", "m")
				}
				ids = append(ids, w.observed("m-"+x, key(i), x, "method", methodRef(EditionID(body), sys)))
				ds = append(ds, dig(x))
			}
			for i := 0; i < n; i++ {
				x, y := fmt.Sprintf("m%d", i), fmt.Sprintf("m%d", (i+1)%n)
				res := w.authored("r-"+x, key(i+1), "r-"+x, "prov", []string{"WF", x, y})
				w.corroborates("c-"+x, key(i+1), ids[i], res, "supports")
			}
			r := w.store(nil)
			return func() {
				unchecked := 0
				for _, d := range ds {
					for _, o := range r.Observations(d) {
						for _, e := range o.Corroboration.Evidence {
							if strings.HasPrefix(e.Cause, "comparability unchecked") {
								unchecked++
							}
						}
					}
				}
				if unchecked == 0 || unchecked == len(ds) {
					t.Fatalf("%d of %d corroborations read comparability unchecked: the shape no longer reaches the comparison", unchecked, len(ds))
				}
			}
		}},
		{"provisional source captures under a finality rule, 2 per referent", func(t *testing.T, n int) func() {
			w := newWorld(t)
			var ds []string
			for i := 0; i < n; i++ {
				x := fmt.Sprintf("o%d", i)
				// the second capture of each referent is at a later state, with other bytes: the first is revised
				state, at := "SF", "2026-10-16T00:00:00Z"
				if i%2 == 1 {
					state, at = "SF+1", "2026-10-17T00:00:00Z"
				}
				w.observed("o-"+x, key(i), x, "source", apiRef(fmt.Sprintf("https://api.example/settle/%d", i/2)), "finality", runFinality(state), "at", at)
				ds = append(ds, dig(x))
			}
			r := w.store(nil, WithFinalityRules(settlementRules{}))
			return func() {
				revised := 0
				for _, d := range ds {
					for _, o := range r.Observations(d) {
						if strings.HasPrefix(o.ReferentStatus, RefRevised) {
							revised++
						}
					}
				}
				if revised == 0 {
					t.Fatal("no capture read as revised: the shape no longer reaches the revision walk")
				}
			}
		}},
		{"observations, each named by a corroborates of its own", func(t *testing.T, n int) func() {
			w := newWorld(t)
			var ds []string
			for i := 0; i < n; i++ { // n observations and 2n corroborates: the walk over them is what is measured
				x := fmt.Sprintf("o%d", i)
				id := w.observed("o-"+x, key(i), x, "source", apiRef("https://api.example/"+x))
				w.corroborates("c1-"+x, key(i+1), id, id, "supports")
				w.corroborates("c2-"+x, key(i+2), id, id, "supports")
				ds = append(ds, dig(x))
			}
			r := w.store(nil)
			return func() {
				for _, d := range ds {
					_ = r.Observations(d)
				}
			}
		}},
		{"derived blobs in a store holding as many refutations", func(t *testing.T, n int) func() {
			w := newWorld(t)
			var ds []string
			for i := 0; i < n; i++ {
				x := fmt.Sprintf("b%d", i)
				a := w.authored("a-"+x, key(i), x, "prov", []string{"WF", "in-" + x})
				w.sign("f-"+x, key(i+1), "refutes", obj("of", a, "evidence", dig("ev-"+x)))
				ds = append(ds, dig(x))
			}
			r := w.store(nil)
			return func() {
				for _, d := range ds {
					_ = r.Artifact(d)
				}
			}
		}},
		{"a collection with a chain of editions", func(t *testing.T, n int) func() {
			w := newWorld(t)
			var all []string
			for i := 0; i < keys; i++ {
				all = append(all, key(i))
			}
			g := w.genesis("G", key(0), 0, all...)
			prev := g
			for i := 0; i < n; i++ {
				prev = w.edition(fmt.Sprintf("e%d", i), key(i), g, []string{prev}, []string{fmt.Sprintf("m%d", i)})
			}
			r := w.store(nil)
			return func() {
				for rep := 0; rep < 3; rep++ {
					if res, ok := r.Resource(g); !ok || res.Current == "" {
						t.Fatal("the chain did not resolve to one current edition")
					}
				}
			}
		}},
		{"many collections, one edition each", func(t *testing.T, n int) func() {
			w := newWorld(t)
			var gs []string
			for i := 0; i < n/2; i++ {
				g := w.sign(fmt.Sprintf("g%d", i), key(i), "genesis", obj("type", "collection", "name", fmt.Sprintf("c%d", i), "controllers", []string{w.signer(key(i))}, "rule", obj("any_one", true)))
				w.edition(fmt.Sprintf("e%d", i), key(i), g, []string{g}, []string{fmt.Sprintf("m%d", i)})
				gs = append(gs, g)
			}
			r := w.store(nil)
			return func() {
				for _, g := range gs {
					_, _ = r.Resource(g)
				}
			}
		}},
		{"many tasks, each with a submission, a grant and a refutation", func(t *testing.T, n int) func() {
			w := newWorld(t)
			var gs []string
			for i := 0; i < n; i++ { // n tasks, six statements each: the per-task walks only show at this size
				g := w.task(fmt.Sprintf("T%d", i), key(i))
				e := w.taskEdition(fmt.Sprintf("TE%d", i), key(i), g, []string{g}, w.contract(key(i)))
				x := fmt.Sprintf("r%d", i)
				w.authored("a-"+x, key(i+1), x)
				w.submit("s-"+x, key(i+1), g, e, x)
				w.sign(fmt.Sprintf("gr%d", i), key(i), "grant", obj("task", g, "edition", e, "grantee", w.signer(key(i+1))))
				w.sign(fmt.Sprintf("rf%d", i), key(i+2), "refutes", obj("of", w.ids["s-"+x], "evidence", dig("ev-"+x)))
				gs = append(gs, g)
			}
			r := w.store(nil)
			return func() {
				for _, g := range gs {
					_, _ = r.Task(g)
				}
			}
		}},
		{"every claim amended once by its key", func(t *testing.T, n int) func() {
			w := newWorld(t)
			var ds []string
			for i := 0; i < n/2; i++ {
				x := fmt.Sprintf("b%d", i)
				w.authored("a1-"+x, key(i), x)
				w.authored("a2-"+x, key(i), x, "licence", "CC0-1.0")
				ds = append(ds, dig(x))
			}
			r := w.store(nil)
			return func() {
				for _, d := range ds {
					_ = r.Artifact(d)
				}
			}
		}},
		{"covering anchors, many keys with one anchor each", func(t *testing.T, n int) func() {
			w := newWorld(t)
			var ids []string
			for k := 0; k < n/8; k++ {
				name := fmt.Sprintf("N%04d", k)
				for i := 0; i < 7; i++ {
					x := fmt.Sprintf("b%d-%d", k, i)
					ids = append(ids, w.authored("a-"+x, name, x))
				}
				w.anchor(fmt.Sprintf("an%d", k), name, fmt.Sprintf("p%d", k))
			}
			r := w.store(nil)
			return func() {
				for rep := 0; rep < 4; rep++ {
					for _, id := range ids {
						_ = r.CoveringAnchors(id)
						_, _ = r.StatementBound(id)
					}
				}
			}
		}},
		{"many task-contract-v1 tasks, each fulfilled by a result's own statement", func(t *testing.T, n int) func() {
			w := newWorld(t)
			var gs []string
			for i := 0; i < n; i++ {
				g := w.task(fmt.Sprintf("T%d", i), key(i))
				e := w.taskEdition(fmt.Sprintf("TE%d", i), key(i), g, []string{g}, v1Contract())
				w.authored(fmt.Sprintf("f%d", i), key(i+1), fmt.Sprintf("r%d", i), "fulfills", fulfills(g, w.ed(e)))
				gs = append(gs, g)
			}
			r := w.store(nil, WithContractReader(ContractProfiles{}))
			return func() {
				for _, g := range gs {
					if tk, ok := r.Task(g); !ok || len(tk.Submissions) != 1 {
						t.Fatalf("task %s: %d submissions", g, len(tk.Submissions))
					}
				}
			}
		}},
		{"time bound of every statement, 8 anchors in all", func(t *testing.T, n int) func() {
			w := newWorld(t)
			var ids []string
			for i := 0; i < n; i++ {
				k := fmt.Sprintf("K%04d", i%4)
				x := fmt.Sprintf("b%d", i)
				ids = append(ids, w.authored("a-"+x, k, x))
				if i%(n/8) == n/8-1 {
					w.anchor(fmt.Sprintf("an%d", i), k, fmt.Sprintf("p%d", i))
				}
			}
			r := w.store(nil)
			return func() {
				for _, id := range ids {
					_, _ = r.StatementBound(id)
					_ = r.CoveringAnchors(id)
				}
			}
		}},
	}
}

// costRatio times small and large (each already built) and returns large over small. Each is the best of five
// runs after a collection, so a pause is not read as a slope.
func costRatio(small, large func()) (dSmall, dLarge time.Duration, ratio float64) {
	best := func(f func()) time.Duration {
		runtime.GC()
		b := time.Duration(0)
		for try := 0; try < 5; try++ {
			start := time.Now()
			f()
			if d := time.Since(start); try == 0 || d < b {
				b = d
			}
		}
		return b
	}
	dSmall, dLarge = best(small), best(large)
	return dSmall, dLarge, float64(dLarge) / float64(dSmall)
}

// wantLinear fails when a walk over a store factor times the size costs more than 2.5*factor times as much, in
// each of three measurements. A quadratic walk costs up to factor squared every time; one slow measurement on a
// busy machine is not a quadratic walk, so a single measurement within the bound passes. The sizes must be far
// enough apart, and the stores large enough, for the walk under test to dominate the fixed work around it: at
// a factor of 4 over a few hundred statements a quadratic walk measured between 9 and 11 times, on the bound.
func wantLinear(t *testing.T, factor int, small, large func()) {
	t.Helper()
	var seen []string
	for attempt := 0; attempt < 3; attempt++ {
		dSmall, dLarge, ratio := costRatio(small, large)
		seen = append(seen, fmt.Sprintf("%s against %s (%.1f times)", dLarge, dSmall, ratio))
		if ratio <= 2.5*float64(factor) {
			t.Logf("%d times the size: %s", factor, seen[len(seen)-1])
			return
		}
	}
	t.Fatalf("%d times the size cost more than %.0f times as much in three measurements, %s: not linear in the store", factor, 2.5*float64(factor), strings.Join(seen, "; "))
}

// TestReadCostIsLinear: for each store shape the read-cost audit found superlinear (#291), the questions a
// command asks of a store eight times the size cost well under the sixty-four times of a quadratic walk. Two
// sizes are compared, so the test does not depend on the machine. Building the stores is not timed.
func TestReadCostIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("signs several thousand statements")
	}
	const small, factor = 200, 8
	for _, s := range costShapes() {
		t.Run(s.name, func(t *testing.T) {
			wantLinear(t, factor, s.build(t, small), s.build(t, small*factor))
		})
	}
}
