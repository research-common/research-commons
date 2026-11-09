package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// sinceRow is one change explain --since printed.
type sinceRow struct{ change, statement, kind string }

// since runs explain ref --since (a file holding saved) with extra args and returns the since member's changes.
func (w *world) since(t *testing.T, ref string, saved result, extra ...string) (*canon.Object, []sinceRow) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "saved.json")
	if err := os.WriteFile(f, []byte(saved.stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	r := w.run(append([]string{"explain", ref, "--since", f, "--json"}, extra...)...)
	if r.code != ExitOK {
		t.Fatalf("explain --since: %d %s", r.code, r.stdout)
	}
	o := jsonOf(t, r)
	s, ok := o.Members["since"].(*canon.Object)
	if !ok {
		t.Fatalf("no since member: %s", r.stdout)
	}
	var rows []sinceRow
	for _, x := range s.Members["changes"].(canon.Array) {
		c := x.(*canon.Object)
		rows = append(rows, sinceRow{stringMember(c, "change"), stringMember(c, "statement"), stringMember(c, "kind")})
	}
	// the human surface prints the same changes
	h := w.run(append([]string{"explain", ref, "--since", f}, extra...)...)
	for _, row := range rows {
		if !strings.Contains(h.stdout, "change: "+row.change) {
			t.Fatalf("human surface lacks change %q:\n%s", row.change, h.stdout)
		}
	}
	return s, rows
}

func hasRow(rows []sinceRow, change, statement string) bool {
	return slices.ContainsFunc(rows, func(r sinceRow) bool { return r.change == change && (statement == "" || r.statement == statement) })
}

// listedIn reports whether explain's statements list id.
func listedIn(t *testing.T, r result, id string) bool {
	t.Helper()
	for _, x := range jsonOf(t, r).Members["statements"].(canon.Array) {
		if stringMember(x.(*canon.Object), "statement") == id {
			return true
		}
	}
	return false
}

func corrCounts(t *testing.T, r result) (canon.Value, canon.Value) {
	t.Helper()
	c := members(t, jsonOf(t, r), "corroboration")
	return c.Members["corroborated"], c.Members["contradicted"]
}

// contradictedWorld is state S of C-core-06: an observation by K5 that K6 supports and K7 contradicts, so its
// status shows `contradicted 1`.
func contradictedWorld(t *testing.T) (*world, string) {
	w := fixture(t)
	ob := w.sign("O:ob", "K5", "observed", obj("content", canon.Value(content("sole")), "class", "exact-bytes",
		"referent", canon.Value(obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "block_hash", strings.Repeat("a1", 32), "depth", 3)),
		"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted"))))
	w.sign("C:sup", "K6", "corroborates", obj("of", ob, "result", w.ids["A:sole"], "verdict", "supports", "model", "M",
		"cohort", canon.Value(obj("rule", "every station in R"))))
	w.sign("C:con", "K7", "corroborates", obj("of", ob, "result", w.ids["A:sole"], "verdict", "contradicts", "model", "M",
		"cohort", canon.Value(obj("rule", "every station in R"))))
	return w, ob
}

// corroborationPolicy is a reader-policy-v1 document trusting the given keys for corroboration of any content.
func corroborationPolicy(t *testing.T, keys ...string) string {
	var es []string
	for _, k := range keys {
		es = append(es, `{"principal":{"key":"`+k+`"},"purposes":["corroboration"],"targets":{"any_content":true}}`)
	}
	slices.SortFunc(es, canon.CompareKeys)
	f := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(f, []byte(`{"version":"reader-policy-v1","selections":[],"trust":[`+strings.Join(es, ",")+`]}`), 0o644)
	return f
}

// TestExplainSinceNamesTheCause: C-core-06. From state S (`contradicted 1`), each of (a) a verified corroboration,
// (b) a revocation of the contradicting key and (c) a reader policy change that stops trusting it moves the result;
// the earlier statement is still listed in explain; and explain --since the saved explain of S names the change's
// cause: the new statement's id, the key event's id and kind, or the reader policy digests with the entry dropped.
func TestExplainSinceNamesTheCause(t *testing.T) {
	conformance.Covers(t, "C-core-06")

	// (a) a corroboration moves the status
	w, ob := contradictedWorld(t)
	s := w.run("explain", ob, "--json")
	sup0, con0 := corrCounts(t, s)
	if con0 != canon.Int(1) {
		t.Fatalf("state S: contradicted %v", con0)
	}
	c2 := w.sign("C:sup2", "K8", "corroborates", obj("of", ob, "result", w.ids["A:sole"], "verdict", "supports", "model", "M",
		"cohort", canon.Value(obj("rule", "every station in R"))))
	now := w.run("explain", ob, "--json")
	if sup1, _ := corrCounts(t, now); sup1 == sup0 {
		t.Fatalf("(a) the corroboration did not move the status: %v", sup1)
	}
	if !listedIn(t, now, w.ids["C:con"]) {
		t.Fatal("(a) the contradicting statement is no longer listed")
	}
	so, rows := w.since(t, ob, s)
	if so.Members["answer"] != canon.String("answer changed") || !hasRow(rows, "statement added", c2) {
		t.Fatalf("(a) cause not named: %s %v", canon.Encode(so), rows)
	}

	// (b) a revocation of the contradicting key: key_compromise with no last_good leaves none of K7's lines counting
	w, ob = contradictedWorld(t)
	s = w.run("explain", ob, "--json")
	rv := w.sign("RV", "K7", "revoke_key", obj("reason", "key_compromise"))
	now = w.run("explain", ob, "--json")
	if _, con := corrCounts(t, now); con != canon.Int(0) {
		t.Fatalf("(b) the revocation did not move the status: contradicted %v", con)
	}
	if !listedIn(t, now, w.ids["C:con"]) {
		t.Fatal("(b) the contradicting statement is no longer listed")
	}
	so, rows = w.since(t, ob, s)
	if !hasRow(rows, "key event", rv) || !hasRow(rows, "counted changed", w.ids["C:con"]) {
		t.Fatalf("(b) cause not named: %s", canon.Encode(so))
	}
	for _, r := range rows {
		if r.change == "key event" && r.kind != "revoke_key" {
			t.Fatalf("(b) key event kind %q", r.kind)
		}
	}

	// (c) a reader policy change that stops trusting K7 for corroboration
	w, ob = contradictedWorld(t)
	all := corroborationPolicy(t, w.signer("K6"), w.signer("K7"))
	less := corroborationPolicy(t, w.signer("K6"))
	s = w.run("explain", ob, "--policy", all, "--json")
	if _, con := corrCounts(t, s); con != canon.Int(1) {
		t.Fatalf("(c) state S under the first policy: contradicted %v", con)
	}
	now = w.run("explain", ob, "--policy", less, "--json")
	if _, con := corrCounts(t, now); con != canon.Int(0) {
		t.Fatalf("(c) the policy change did not move the status: contradicted %v", con)
	}
	if !listedIn(t, now, w.ids["C:con"]) {
		t.Fatal("(c) the contradicting statement is no longer listed")
	}
	so, _ = w.since(t, ob, s, "--policy", less)
	var pc *canon.Object
	for _, x := range so.Members["changes"].(canon.Array) {
		if c := x.(*canon.Object); stringMember(c, "change") == "reader policy changed" {
			pc = c
		}
	}
	if pc == nil {
		t.Fatalf("(c) no reader policy change named: %s", canon.Encode(so))
	}
	ents := strs(pc.Members["entries"])
	if len(ents) != 1 || !strings.HasPrefix(ents[0], "- trust ") || !strings.Contains(ents[0], w.signer("K7")) {
		t.Fatalf("(c) entries %q, want the K7 trust entry removed", ents)
	}
	// no statement changed: the policy is the only cause
	for _, x := range so.Members["changes"].(canon.Array) {
		if ch := stringMember(x.(*canon.Object), "change"); strings.HasPrefix(ch, "statement") || ch == "key event" {
			t.Fatalf("(c) a statement change was named for a policy change: %s", canon.Encode(so))
		}
	}
}

// TestExplainSinceNamesEveryDifference: P-08 over the fixture. For every ref, a saved explain is compared with the
// explain after more statements arrive, after a hub policy change and under another evaluator: wherever the answer
// differs, at least one cause is named, and the named causes are the kinds that changed. With nothing changed the
// answer is unchanged and no change is named. The comparison is a pure function of the two outputs: the same file
// gives the same bytes twice.
func TestExplainSinceNamesEveryDifference(t *testing.T) {
	conformance.Partial(t, "P-08", "statement, key-event, hub/reader/time policy and evaluator changes between two explains are each named with their cause (explain --since; P-08 sweep over the fixture); a time-context change and an execution-context change are not exercised: no command configures a chain backend (the only source of a read-time-dependent answer), and execution context is verify --rerun's, not explain's")
	w := fixture(t)
	refs := w.refsOf()
	saved := map[string]result{}
	for _, r := range refs {
		saved[r] = w.run("explain", r, "--json")
		// nothing changed: answer unchanged, no change named, and the output is stable
		so, rows := w.since(t, r, saved[r])
		if so.Members["answer"] != canon.String("answer unchanged") || len(rows) != 0 {
			t.Fatalf("%s: unchanged state reads %s", r, canon.Encode(so))
		}
	}
	// more statements: an amendment, a second claimant, a retraction and a revocation
	w.authored("A:sole:2", "K2", "sole", "licence", "CC0-1.0")
	w.sign("R:solo", "K3", "retracts", obj("of", w.ids["A:solo"]))
	w.authored("A:solo:2", "K1", "solo", "prov", []string{"wfB", "in4"})
	w.sign("RV:K2", "K2", "revoke_key", obj("reason", "key_compromise", "last_good", w.ids["A:contested:2"]))
	check := func(what string, wantCause func(string) bool, extra ...string) {
		t.Helper()
		changed := 0
		for _, r := range refs {
			so, rows := w.since(t, r, saved[r], extra...)
			if so.Members["answer"] == canon.String("answer changed") {
				changed++
				if len(rows) == 0 {
					t.Fatalf("%s: %s changed with no cause named: %s", what, r, canon.Encode(so))
				}
			}
			if _, bad := so.Members["unexplained"]; bad {
				t.Fatalf("%s: %s unexplained", what, r)
			}
			for _, row := range rows {
				if !wantCause(row.change) {
					t.Fatalf("%s: %s names %q", what, r, row.change)
				}
			}
		}
		if changed == 0 {
			t.Fatalf("%s: no answer changed, the sweep checks nothing", what)
		}
	}
	isStatement := func(c string) bool {
		return slices.Contains([]string{"statement added", "statement removed", "key event", "status changed", "line changed", "counted changed"}, c)
	}
	check("statements", isStatement)
	// the pure function: the same file and state give the same bytes
	f := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(f, []byte(saved[dig("sole")].stdout), 0o644)
	if a, b := w.run("explain", dig("sole"), "--since", f, "--json").stdout, w.run("explain", dig("sole"), "--since", f, "--json").stdout; a != b {
		t.Fatal("explain --since is not a function of its inputs")
	}

	// the hub policy changes on top: its digest is named beside the statements
	os.WriteFile(filepath.Join(w.root, PolicyFile), []byte(`{"policy":"rc-hub-policy/1","blobs":"external-only"}`), 0o644)
	_, rows := w.since(t, dig("nobody"), saved[dig("nobody")])
	if !hasRow(rows, "policy changed", "") {
		t.Fatalf("hub policy change not named: %v", rows)
	}
	os.Remove(filepath.Join(w.root, PolicyFile))

	// another evaluator over the same statements: only the evaluator is named
	for _, r := range refs[:3] {
		now := w.run("explain", r, "--json")
		f := filepath.Join(t.TempDir(), "e.json")
		os.WriteFile(f, []byte(now.stdout), 0o644)
		var o, e bytes.Buffer
		code := Main([]string{"explain", r, "--since", f, "--json"}, &Env{Stdout: &o, Stderr: &e, Getenv: func(string) string { return "" },
			Getwd: func() (string, error) { return w.root, nil }, Build: Build{Version: "test-2", Commit: "1111111"}})
		if code != ExitOK {
			t.Fatalf("%d %s", code, o.String())
		}
		so := jsonOf(t, result{stdout: o.String()}).Members["since"].(*canon.Object)
		ch := so.Members["changes"].(canon.Array)
		if len(ch) != 1 || stringMember(ch[0].(*canon.Object), "change") != "evaluator changed" || so.Members["answer"] != canon.String("answer unchanged") {
			t.Fatalf("evaluator change: %s", canon.Encode(so))
		}
	}
}

// TestExplainSinceRefuses: a --since file that cannot be read, is not strict JSON, is not an explain output, or
// explains another ref is exit 2 before any work, the store unchanged; --since applies to explain only.
func TestExplainSinceRefuses(t *testing.T) {
	w := fixture(t)
	dir := t.TempDir()
	file := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o644)
		return p
	}
	other := file("other.json", w.run("explain", dig("contested"), "--json").stdout)
	show := file("show.json", w.run("show", dig("sole"), "--json").stdout)
	before := snapshot(t, w.root)
	for name, p := range map[string]string{
		"missing":   filepath.Join(dir, "absent.json"),
		"not json":  file("bad.json", "{not json"),
		"duplicate": file("dup.json", `{"a":1,"a":2}`),
		"array":     file("arr.json", "[]"),
		"show":      show,
		"other ref": other,
	} {
		r := w.run("explain", dig("sole"), "--since", p, "--json")
		if r.code != ExitDidNotStart || !strings.Contains(r.stdout, ProblemTypeBase+"since-") {
			t.Fatalf("%s: %d %s", name, r.code, r.stdout)
		}
	}
	if r := w.run("show", dig("sole"), "--since", other); r.code != ExitDidNotStart {
		t.Fatalf("show --since: %d", r.code)
	}
	if snapshot(t, w.root) != before {
		t.Fatal("a refused --since changed the store")
	}
}

// TestPullTrustFloorUnresolvedTarget: R5SEAM-F2 at the pull trust floor. A corroborates reaches its content through
// `of`; with a `contents` admission entry for its signer, it is admitted when the observation it names is in the
// package (the content is covered), and when the observation is in neither the package nor the store it reads
// unknown (target reference not resolved): refused under --below-floor refuse and labelled by default, never
// admitted as trusted and never refused as "not trusted".
func TestPullTrustFloorUnresolvedTarget(t *testing.T) {
	src := newWorld(t)
	src.blob("sole", []byte("sole"))
	src.authored("A:sole", "K5", "sole")
	ob := src.sign("O", "K5", "observed", obj("content", canon.Value(content("sole")), "class", "exact-bytes",
		"referent", canon.Value(obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "block_hash", strings.Repeat("a1", 32), "depth", 3)),
		"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted"))))
	cid := src.sign("C", "K6", "corroborates", obj("of", ob, "result", src.ids["A:sole"], "verdict", "supports", "model", "M",
		"cohort", canon.Value(obj("rule", "every station in R"))))
	es := []string{
		`{"principal":{"key":"` + src.signer("K5") + `"},"purposes":["admission"],"targets":{"any_content":true}}`,
		`{"principal":{"key":"` + src.signer("K6") + `"},"purposes":["admission"],"targets":{"contents":["` + dig("sole") + `"]}}`,
	}
	slices.SortFunc(es, canon.CompareKeys)
	pf := filepath.Join(t.TempDir(), "p.json")
	os.WriteFile(pf, []byte(`{"version":"reader-policy-v1","selections":[],"trust":[`+strings.Join(es, ",")+`]}`), 0o644)
	cPath := "statements/" + strings.ReplaceAll(src.signer("K6"), ":", "-") + "/" + cid
	oPath := "statements/" + strings.ReplaceAll(src.signer("K5"), ":", "-") + "/" + ob

	// the observation travels with it: the content is covered, admitted unlabelled
	full := t.TempDir()
	copyData(t, src.root, full)
	// (the report lists only objects with a verdict other than plain admitted)
	r := newWorld(t).run("pull", full, "--policy", pf, "--below-floor", "refuse", "--json")
	if r.code != ExitOK || objectRow(t, jsonOf(t, r), cPath) != nil {
		t.Fatalf("resolved: %d %s", r.code, r.stdout)
	}
	// the observation in neither package nor store: unknown, refused or labelled
	part := t.TempDir()
	copyData(t, src.root, part)
	os.Remove(filepath.Join(part, oPath))
	r = newWorld(t).run("pull", part, "--policy", pf, "--below-floor", "refuse", "--json")
	c := objectRow(t, jsonOf(t, r), cPath)
	if c == nil || c.Members["verdict"] != canon.String("refused") || !strings.Contains(stringMember(c, "detail"), "target is not resolved") ||
		strings.Contains(stringMember(c, "detail"), "not trusted") {
		t.Fatalf("unresolved, refuse: %s", r.stdout)
	}
	r = newWorld(t).run("pull", part, "--policy", pf, "--json")
	c = objectRow(t, jsonOf(t, r), cPath)
	if c == nil || !strings.Contains(string(canon.Encode(c)), "target is not resolved") || c.Members["verdict"] == canon.String("refused") {
		t.Fatalf("unresolved, label: %s", r.stdout)
	}
	// the observation already in the receiving store resolves the reference
	dst := newWorld(t)
	seed := t.TempDir()
	copyData(t, src.root, seed)
	os.Remove(filepath.Join(seed, cPath))
	if r := dst.run("pull", seed, "--policy", pf, "--json"); r.code != ExitOK {
		t.Fatalf("seed: %s", r.stdout)
	}
	r = dst.run("pull", part, "--policy", pf, "--below-floor", "refuse", "--json")
	if c := objectRow(t, jsonOf(t, r), cPath); r.code != ExitOK || c != nil && c.Members["verdict"] == canon.String("refused") {
		t.Fatalf("held in the store: %s", r.stdout)
	}
}
