package cli

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// withoutHistory drops the operation history files from a snapshot (fixture_test.go snapshot): local
// bookkeeping every finished operation appends to, never part of what a command commits.
func withoutHistory(snap string) string {
	var out []string
	for _, l := range strings.Split(snap, "\n") {
		f := strings.Fields(l)
		if len(f) > 0 && (f[0] == "journal/history.jsonl" || f[0] == "journal/history.1.jsonl") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// TestHistoryNeverDecides: C-core-146, with (d) here. A publish and a pull finish (each appends a history line);
// a third publish crashes right after step 4 and its blob is then removed, so it stays `committed, needs repair`
// with a history line saying it finished. history --json lists the publish and the pull with their statement ids.
// Every other command the sweep reaches (human and JSON: status, fsck, repair, show, verify, explain, list, gc, hub
// check, …) plus show/explain/repair of the new operations is snapshotted (exit, stdout, stderr); then the history
// file is deleted, and separately one line of it rewritten: every snapshot is byte-identical, status included (its
// `history` declaration is a property of the store's options, not of the file). So no answer, no explain, and not
// status's own account of unfinished work reads the history.
//
// The other parts of C-core-146: (a) a reused aged blob, a crash after step 1, gc, a retry: TestPublishReuseCrashThenGC
// (with a process crash) and TestPublishReuseRestartsWindow; (b) a pending record written while gc runs:
// internal/store TestGCRecheckAtDeletion; (c) the policy floor: internal/store TestGCGraceFloor; the one-run value
// through `gc --grace`: TestGCRelease.
func TestHistoryNeverDecides(t *testing.T) {
	conformance.Covers(t, "C-core-146")
	w := fixture(t)
	dir := t.TempDir()
	key, _ := newKeyFile(t, dir, wire.AlgEd25519)
	file := func(name, data string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(data), 0o644)
		return p
	}
	pub := w.run("publish", "--key", key, "--json", "--kind", "authored", "--content", file("p", "published, then listed"))
	if pub.code != 0 {
		t.Fatalf("publish: %d %s", pub.code, pub.stdout)
	}
	pubOp := string(jsonOf(t, pub).Members["operation"].(canon.String))
	pubIDs := idsOf(jsonOf(t, pub))

	src := newWorld(t)
	src.blob("pulled", []byte("pulled"))
	src.authored("A:pulled", "K5", "pulled")
	pl := w.run("pull", src.root, "--json")
	if pl.code != 0 || !strings.Contains(pl.stdout, "journal/history.jsonl (the source store's local operation history, never transported)") {
		t.Fatalf("pull (the source's history must be skipped, not refused): %d %s", pl.code, pl.stdout)
	}
	pullOp := string(jsonOf(t, pl).Members["operation"].(canon.String))
	pullID := src.ids["A:pulled"]

	// committed, needs repair: crash after step 4 (the history line is written), then the blob goes missing
	data := "bytes that go missing after the commit"
	code, out, reached := crashRun(t, w.root, store.AfterDone, 1, "publish", "--key", key, "--json", "--kind", "authored", "--content", file("m", data))
	if !reached || code != crashExit {
		t.Fatalf("crash after step 4 not reached: %v %d %s", reached, code, out)
	}
	raw := readRaw(t, w.root, dig(data))
	if len(raw.done) != 1 {
		t.Fatalf("after a crash at step 4: %+v", raw)
	}
	repOp := raw.done[0]
	os.Remove(filepath.Join(w.root, "blobs", "sha256", strings.TrimPrefix(dig(data), "sha256:")))
	if st := w.run("status", "--json"); !strings.Contains(st.stdout, `"store_state":"committed, needs repair"`) || !strings.Contains(st.stdout, repOp) {
		t.Fatalf("setup: the operation should be committed, needs repair: %s", st.stdout)
	}

	hist := filepath.Join(w.root, "journal", "history.jsonl")
	h := w.run("history", "--json")
	ho := jsonOf(t, h)
	if h.code != 0 || ho.Members["state"] != canon.String("history on") || ho.Members["note"] != canon.String(historyHeader) {
		t.Fatalf("history: %d %s", h.code, h.stdout)
	}
	listed := map[string]string{}
	for _, e := range ho.Members["entries"].(canon.Array) {
		eo := e.(*canon.Object)
		if eo.Members["what"] == canon.String("finished") {
			listed[string(eo.Members["operation"].(canon.String))] = string(canon.Encode(eo.Members["statements"]))
		}
	}
	if listed[pubOp] != `["`+strings.Join(pubIDs, `","`)+`"]` || listed[pullOp] != `["`+pullID+`"]` || listed[repOp] == "" {
		t.Fatalf("history does not list the publish %s %v and the pull %s %s with their statement ids:\n%s", pubOp, pubIDs, pullOp, pullID, h.stdout)
	}
	// newest first: the crashed publish, then the pull, then the publish
	ents := ho.Members["entries"].(canon.Array)
	if ents[0].(*canon.Object).Members["operation"] != canon.String(repOp) || ents[1].(*canon.Object).Members["operation"] != canon.String(pullOp) {
		t.Fatalf("not newest first: %s", h.stdout)
	}

	extra := [][]string{{"status"}, {"repair", pubOp}, {"repair", pullOp}, {"repair", repOp}, {"show", pullID}, {"explain", pullID}}
	for _, id := range pubIDs {
		extra = append(extra, []string{"show", id}, []string{"explain", id}, []string{"verify", id})
	}
	snap := func() []string {
		var out []string
		for _, a := range append(sweepArgs(w), extra...) {
			if a[0] == "history" || a[0] == "pull" {
				continue // history is the file's reader; pull writes (it is run above)
			}
			for _, js := range []bool{false, true} {
				args := slices.Clone(a)
				if js {
					args = append(args, "--json")
				}
				r := w.run(args...)
				out = append(out, fmt.Sprintf("%v\n%d\n%s\n%s", args, r.code, r.stdout, r.stderr))
			}
		}
		return out
	}
	held, err := os.ReadFile(hist)
	if err != nil {
		t.Fatal(err)
	}
	before := snap()
	sameSnapshot(t, "a second run", before, snap())
	if now, _ := os.ReadFile(hist); !bytes.Equal(now, held) {
		t.Fatal("the read sweep appended to the history: the comparison below would not be of one file")
	}
	joined := strings.Join(before, "\n")
	for _, want := range []string{"committed, needs repair", repOp, pullID, `"history":"on (8 MiB × 2, rotate)"`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("the sweep never printed %q: it would not see a change there", want)
		}
	}

	// (1) the history file deleted
	if err := os.Remove(hist); err != nil {
		t.Fatal(err)
	}
	sameSnapshot(t, "history deleted", before, snap())
	if r := w.run("history", "--json"); r.code != 0 || !strings.Contains(r.stdout, "no history file yet") || !strings.Contains(r.stdout, `"entries":[]`) {
		t.Fatalf("history with the file deleted: %d %s", r.code, r.stdout)
	}

	// (2) restored, then one line rewritten: the crashed operation's line now names another operation, other
	// statements and another time, and says it was replayed
	lines := strings.Split(strings.TrimSuffix(string(held), "\n"), "\n")
	for i, l := range lines {
		if strings.Contains(l, repOp) {
			lines[i] = `{"blobs":[],"kind":"rewritten","local_time":"1970-01-01T00:00:00Z","op":"` + strings.Repeat("cd", 32) + `","replayed":true,"statements":["` + pullID + `"],"v":1}`
		}
	}
	os.WriteFile(hist, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	sameSnapshot(t, "one history line rewritten", before, snap())
	if r := w.run("history", "--op", repOp, "--json"); r.code != 0 || !strings.Contains(r.stdout, `"matched":0`) {
		t.Fatalf("history --op after the rewrite: %d %s", r.code, r.stdout)
	}
}

// TestHistoryCommand: newest first, --limit, --op, malformed lines skipped and counted, quarantine events listed,
// exit 0 with the history off, with no file and with an unreadable one.
func TestHistoryCommand(t *testing.T) {
	p := newPubWorld(t)
	if r := p.run("history"); r.code != 0 || !strings.Contains(r.stdout, "no history file yet") || !strings.Contains(r.stdout, historyHeader) {
		t.Fatalf("no file: %d %s", r.code, r.stdout)
	}
	var ops []string
	for i := range 3 {
		r := p.publish("--kind", "authored", "--content", p.file(fmt.Sprint(i), fmt.Sprint("content ", i)))
		ops = append(ops, string(outObj(t, r).Members["operation"].(canon.String)))
	}
	hist := filepath.Join(p.root, "journal", "history.jsonl")
	f, _ := os.OpenFile(hist, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("not json\n{\"v\":2,\"op\":\"" + ops[0] + "\"}\n")
	f.Close()
	bad := strings.Repeat("ef", 32)
	os.WriteFile(filepath.Join(p.root, "journal", "pending", bad+".json"), []byte("{"), 0o444)

	r := p.run("history", "--json", "--limit", "2")
	o := outObj(t, r)
	es := o.Members["entries"].(canon.Array)
	if r.code != 0 || len(es) != 2 || o.Members["malformed_lines_skipped"] != canon.Int(2) || o.Members["matched"] != canon.Int(4) ||
		!strings.Contains(r.stdout, "2 more entr(ies) not shown; raise --limit") {
		t.Fatalf("--limit 2: %d %s", r.code, r.stdout)
	}
	// the quarantine (this command's own open moved the record aside) is the newest entry
	if e := es[0].(*canon.Object); e.Members["what"] != canon.String("quarantined") || e.Members["operation"] != canon.String(bad) {
		t.Fatalf("quarantine event: %s", r.stdout)
	}
	if e := es[1].(*canon.Object); e.Members["operation"] != canon.String(ops[2]) || e.Members["replayed"] != canon.Bool(false) {
		t.Fatalf("newest first: %s", r.stdout)
	}
	if r := p.run("history", "--op", ops[0]); r.code != 0 || !strings.Contains(r.stdout, ops[0]) || strings.Contains(r.stdout, ops[1]) {
		t.Fatalf("--op: %d %s", r.code, r.stdout)
	}
	for _, args := range [][]string{{"--limit", "0"}, {"--limit", "x"}, {"--op", "abc"}} {
		if r := p.run(append([]string{"history"}, args...)...); r.code != ExitDidNotStart {
			t.Fatalf("history %v: %d %s", args, r.code, r.stdout)
		}
	}
	// unreadable: reported, still exit 0
	os.Chmod(hist, 0o000)
	defer os.Chmod(hist, 0o644)
	if os.Geteuid() != 0 {
		if r := p.run("history", "--json"); r.code != 0 || !strings.Contains(r.stdout, `"unreadable"`) {
			t.Fatalf("unreadable: %d %s", r.code, r.stdout)
		}
	}
}

// TestHistoryOff: with the history off nothing is appended, status declares off, history exits 0 with the state
// token `history off` and an empty list.
func TestHistoryOff(t *testing.T) {
	defer func(o store.Options) { storeOptions = o }(storeOptions)
	storeOptions = store.Options{NoHistory: true}
	p := newPubWorld(t)
	if r := p.publish("--kind", "authored", "--content", p.file("c", "off")); r.code != 0 {
		t.Fatal(r.stdout)
	}
	if _, err := os.Stat(filepath.Join(p.root, "journal", "history.jsonl")); err == nil {
		t.Fatal("history off still wrote the file")
	}
	if r := p.run("status", "--json"); !strings.Contains(r.stdout, `"history":"off"`) {
		t.Fatal(r.stdout)
	}
	r := p.run("history", "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"state":"history off"`) || !strings.Contains(r.stdout, `"entries":[]`) {
		t.Fatalf("history off: %d %s", r.code, r.stdout)
	}
}

// TestNothingElseReadsHistory: the guard of storage note §3.6 "never read by an answer". No production file names
// the history files but internal/store/history.go (the writer, which owns their names); store.HistoryFiles (the
// reader's entry point) is called from internal/cli/cmd_history.go only, and store.IsHistoryPath (which reads
// nothing: pull uses it to skip a source tree's history) from internal/cli/cmd_pull.go only. The guard proves it
// read the files it protects.
func TestNothingElseReadsHistory(t *testing.T) {
	root, err := conformance.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]string{"HistoryFiles": "internal/cli/cmd_history.go", "IsHistoryPath": "internal/cli/cmd_pull.go"}
	seen := map[string]bool{}
	fset := token.NewFileSet()
	files := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		files++
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if rel != "internal/store/history.go" && (bytes.Contains(b, []byte("history.jsonl")) || bytes.Contains(b, []byte("history.1.jsonl"))) {
			t.Errorf("%s names the history file: only internal/store/history.go may", rel)
		}
		f, err := parser.ParseFile(fset, p, b, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				switch id.Name {
				case "historyName", "historyRotated":
					if rel != "internal/store/history.go" {
						t.Errorf("%s: names %s", fset.Position(id.Pos()), id.Name)
					}
					seen[id.Name] = true
				case "HistoryFiles", "IsHistoryPath":
					if rel != "internal/store/history.go" && rel != allowed[id.Name] {
						t.Errorf("%s: names store.%s: only %s may", fset.Position(id.Pos()), id.Name, allowed[id.Name])
					}
					if rel == allowed[id.Name] {
						seen[id.Name] = true
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 || len(seen) != 4 {
		t.Fatalf("the guard read %d production files and saw %v: it is not reading what it protects", files, seen)
	}
}
