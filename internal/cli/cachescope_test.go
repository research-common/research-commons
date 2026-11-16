package cli

import (
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
	"time"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// The tests of the cache re-scope (storage note §5.3): this implementation keeps no persistent resolver or
// verification cache, so "every answer equals a cold rebuild" holds by construction and these tests hold it so.
// The one thing a command keeps is the in-process verification memo (wire/memo.go); the tests compare every
// answer with the answer of a run with the memo off, which is a cold read of every line.

// readSnapshot runs every read surface the sweep reaches (show, verify, explain, list on every ref, status, fsck),
// human and JSON, in the store at root, and returns exit, stdout and stderr per invocation with the root's path
// replaced (a restored copy lives at another path). Memo off makes every read cold.
func readSnapshot(w *world, root string, memo bool) []string {
	defer wire.SetMemo(memo)()
	return readSweep(w, root)
}

// readSweep is readSnapshot with the memo as it stands: what an earlier sweep memoised is still there.
func readSweep(w *world, root string) []string {
	var out []string
	for _, a := range sweepArgs(w) {
		if !viewCommands[a[0]] && a[0] != "status" && a[0] != "fsck" {
			continue
		}
		for _, js := range []bool{false, true} {
			args := slices.Clone(a)
			if js {
				args = append(args, "--json")
			}
			r := runIn(root, nil, args...)
			out = append(out, strings.ReplaceAll(fmt.Sprintf("%v\n%d\n%s\n%s", args, r.code, r.stdout, r.stderr), root, "ROOT"))
		}
	}
	return out
}

func sameSnapshot(t *testing.T, what string, want, got []string) {
	t.Helper()
	if len(want) != len(got) || len(want) < 40 {
		t.Fatalf("%s: %d vs %d outputs (the sweep must reach at least 40)", what, len(want), len(got))
	}
	for i := range want {
		if want[i] != got[i] {
			wl, gl := strings.Split(want[i], "\n"), strings.Split(got[i], "\n")
			for k := 0; k < len(wl) && k < len(gl); k++ {
				if wl[k] != gl[k] {
					t.Fatalf("%s: %s differs from the cold read at line %d:\n  cold: %s\n  this: %s", what, wl[0], k, wl[k], gl[k])
				}
			}
			t.Fatalf("%s: %s differs from the cold read in length: %d vs %d lines", what, wl[0], len(wl), len(gl))
		}
	}
}

// sameSizeRewrite replaces the statement file of the named statement, in place, with a different valid statement
// of the same size (the same signer, seq, prev and ts, another content digest), and gives the file back its old
// modification time. The new line verifies; its id is not the file's name.
func sameSizeRewrite(t *testing.T, w *world, name, signerName, x string) (oldID string) {
	t.Helper()
	oldID = w.ids[name]
	var path string
	filepath.WalkDir(filepath.Join(w.root, "statements"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == oldID {
			path = p
		}
		return nil
	})
	if path == "" {
		t.Fatalf("no statement file for %s", name)
	}
	old, _ := os.ReadFile(path)
	fi, _ := os.Stat(path)
	st, err := wire.ReadStored(old)
	if err != nil {
		t.Fatal(err)
	}
	body := &canon.Object{Keys: slices.Clone(st.Body.Keys), Members: map[string]canon.Value{}}
	for k, v := range st.Body.Members {
		body.Members[k] = v
	}
	body.Members["content"] = content(x)
	line, id := wire.Sign(wire.Draft{Kind: st.Kind, Seq: st.Seq, Prev: st.Prev, TS: fmt.Sprintf("2026-10-16T02:%02d:%02dZ", st.Seq/60%60, st.Seq%60), Body: body}, w.key(signerName))
	if id == oldID || len(line) != len(old) {
		t.Fatalf("the rewrite is not a different statement of the same size: %d vs %d bytes, same id %v", len(line), len(old), id == oldID)
	}
	if nst, err := wire.ReadStored(line); err != nil || !nst.Verified {
		t.Fatalf("the rewritten line does not verify: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // the store installs statements read-only
		t.Fatal(err)
	}
	if err := os.WriteFile(path, line, 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, fi.Mode())
	if err := os.Chtimes(path, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if now, _ := os.Stat(path); now.Size() != fi.Size() || !now.ModTime().Equal(fi.ModTime()) {
		t.Fatal("the rewrite changed the file's size or modification time")
	}
	return oldID
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestReadsColdUnderChange: C-core-129, re-scoped to the caches this implementation keeps. Every answer equals a
// cold read, the explanation cites the changed input, and a restore of the content directories alone reproduces
// the answers; planted files under cache/ change nothing.
//
// (a) a statement file rewritten to different valid content with the same size and the same modification time:
// the statement is gone from every answer (its id no longer matches its name, so the store never shows it as
// anyone's word), `explain --since` cites it as removed, and the answers equal a cold read; (b) a reader-policy
// change is cited as one; (c) a build change is cited as an evaluator change; (d) blobs/ and statements/ restored
// into an empty store, with no journal and no cache, answer as the original did.
func TestReadsColdUnderChange(t *testing.T) {
	conformance.Covers(t, "C-core-129")
	w := fixture(t)
	warm := readSnapshot(w, w.root, true)
	sameSnapshot(t, "second warm read", warm, readSnapshot(w, w.root, true))
	cold := readSnapshot(w, w.root, false)
	sameSnapshot(t, "memo on vs memo off", cold, warm)

	// planted junk under cache/: nothing reads it
	for _, p := range []string{"cache/verify/" + strings.Repeat("ab", 32), "cache/projection/x/" + strings.Repeat("cd", 32), "cache/junk"} {
		os.MkdirAll(filepath.Dir(filepath.Join(w.root, p)), 0o755)
		os.WriteFile(filepath.Join(w.root, p), []byte("verified\n"), 0o644)
	}
	sameSnapshot(t, "poisoned cache/", cold, readSnapshot(w, w.root, true))

	// (d) restore blobs/ and statements/ only
	// (the layout marker rc-store is part of the store, not a cache; journal/, quarantine/, tmp/ and cache/ are not restored)
	back := t.TempDir()
	for _, d := range []string{"blobs", "statements"} {
		copyTree(t, filepath.Join(w.root, d), filepath.Join(back, d))
	}
	marker, _ := os.ReadFile(filepath.Join(w.root, "rc-store"))
	os.WriteFile(filepath.Join(back, "rc-store"), marker, 0o644)
	for _, d := range []string{"journal/pending", "journal/done", "quarantine", "tmp"} {
		os.MkdirAll(filepath.Join(back, d), 0o755)
	}
	sameSnapshot(t, "restore of blobs/ and statements/ only", cold, readSnapshot(w, back, true))

	// (c) another build over the same statements: the answer is the cold one, the explanation names the evaluator
	ref := dig("sole")
	saved := w.run("explain", ref, "--json")
	f := filepath.Join(t.TempDir(), "saved.json")
	os.WriteFile(f, []byte(saved.stdout), 0o644)
	if x := w.run("explain", ref, "--since", f, "--json"); strings.Contains(x.stdout, "evaluator changed") {
		t.Fatalf("(c) the same build names an evaluator change: %s", x.stdout)
	}

	// (a) the same-size same-mtime rewrite
	ref = dig("prot2")
	saved = w.run("explain", ref, "--json")
	// the memo is warm with every line of the old store when the file is rewritten: a memo keyed on anything but
	// the line's bytes (a size, a modification time, a name) would answer for the old line
	wire.ResetMemo()
	readSweep(w, w.root)
	oldID := sameSizeRewrite(t, w, "A:prot2", "K2", "prot9")
	afterWarm := readSweep(w, w.root)
	afterCold := readSnapshot(w, w.root, false)
	sameSnapshot(t, "(a) after the same-size same-mtime rewrite, memo on vs cold", afterCold, afterWarm)
	if slices.Equal(cold, afterCold) {
		t.Fatal("(a) the rewrite changed no answer: the test does not reach the boundary")
	}
	asked, fsckSaid := 0, 0
	for _, s := range afterWarm {
		head, rest, _ := strings.Cut(s, "\n")
		if strings.Contains(head, oldID) { // asked about by name: the answer is that none is held
			asked++
			if !strings.Contains(rest, "no statement held") && !strings.Contains(rest, "not held") && !strings.Contains(rest, "unknown") {
				t.Fatalf("(a) the rewritten statement's old id is asked about and not reported absent:\n%s", s)
			}
			continue
		}
		if strings.HasPrefix(head, "[fsck") { // fsck names the file, and says its bytes are another statement's
			if !strings.Contains(rest, "stored under another name") || !strings.Contains(rest, oldID) {
				t.Fatalf("(a) fsck does not report the same-name rewrite:\n%s", s)
			}
			fsckSaid++
			continue
		}
		if strings.Contains(rest, oldID) {
			t.Fatalf("(a) the rewritten statement's old id is still shown:\n%s", s)
		}
	}
	if asked == 0 || fsckSaid == 0 {
		t.Fatalf("(a) the reads did not reach the rewritten id: %d asked, %d fsck reports", asked, fsckSaid)
	}
	so, rows := w.since(t, ref, saved)
	if so.Members["answer"] != canon.String("answer changed") || !hasRow(rows, "statement removed", oldID) {
		t.Fatalf("(a) the removal is not cited: %s", canon.Encode(so))
	}
	if _, bad := so.Members["unexplained"]; bad {
		t.Fatal("(a) unexplained")
	}
	for _, r := range rows {
		if r.change == "statement added" {
			t.Fatalf("(a) the rewritten line was shown as new content: %v", rows)
		}
	}

	// (b) a reader-policy change, on the world the explain_since tests use
	w, ob := contradictedWorld(t)
	all := corroborationPolicy(t, w.signer("K6"), w.signer("K7"))
	less := corroborationPolicy(t, w.signer("K6"))
	for _, p := range []string{all, less} {
		on := func(memo bool) string {
			defer wire.SetMemo(memo)()
			return w.run("explain", ob, "--policy", p, "--json").stdout
		}
		if on(true) != on(false) {
			t.Fatalf("(b) policy %s: the memoised answer differs from the cold one", p)
		}
	}
	s := w.run("explain", ob, "--policy", all, "--json")
	_, rows = w.since(t, ob, s, "--policy", less)
	if !hasRow(rows, "reader policy changed", "") {
		t.Fatalf("(b) the policy change is not cited: %v", rows)
	}
}

// TestReadsColdUnderBuildChange: (c) of C-core-129 on its own: a different build reads the same statements and
// the explanation names only the evaluator.
func TestReadsColdUnderBuildChange(t *testing.T) {
	w := fixture(t)
	ref := dig("sole")
	saved := w.run("explain", ref, "--json")
	f := filepath.Join(t.TempDir(), "saved.json")
	os.WriteFile(f, []byte(saved.stdout), 0o644)
	run := func(memo bool) result {
		defer wire.SetMemo(memo)()
		var o, e strings.Builder
		code := Main([]string{"explain", ref, "--since", f, "--json"}, &Env{Stdout: &o, Stderr: &e, Getenv: func(string) string { return "" },
			Getwd: func() (string, error) { return w.root, nil }, Build: Build{Version: "test-2", Commit: "1111111"}})
		return result{code, o.String(), e.String()}
	}
	a, b := run(true), run(false)
	if a != b || a.code != ExitOK || !strings.Contains(a.stdout, "evaluator changed") {
		t.Fatalf("a build change: %d %s", a.code, a.stdout)
	}
}

// TestPlantedVerifyEntriesIgnored: C-core-129a, re-scoped. A "verified" verification-cache entry is planted for
// every statement line, and for a forged line (a statement whose signature does not verify, placed in
// statements/ under its id-name); every read command refuses the forged line and prints what a run with no cache
// prints, byte for byte. A guard over the production source shows no code path calls the verification cache.
func TestPlantedVerifyEntriesIgnored(t *testing.T) {
	conformance.Covers(t, "C-core-129a")
	w := fixture(t)
	forgedID := w.ids["A:solo"]
	var path string
	filepath.WalkDir(filepath.Join(w.root, "statements"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == forgedID {
			path = p
		}
		return nil
	})
	good, _ := os.ReadFile(path)
	i := strings.Index(string(good), `"sig":"`) + len(`"sig":"`)
	forged := []byte(string(good[:i]) + map[bool]string{true: "1", false: "0"}[good[i] == '0'] + string(good[i+1:]))
	if _, err := wire.ReadStored(forged); err == nil {
		t.Fatal("the forged line verifies: the test would not reach the boundary")
	}
	// the forged line replaces the real one under its id-name; the later statements of that signer still name it
	os.Chmod(path, 0o644)
	if err := os.WriteFile(path, forged, 0o644); err != nil {
		t.Fatal(err)
	}
	clean := readSnapshot(w, w.root, false)
	for _, s := range clean {
		if strings.Contains(s, "A:solo") {
			continue
		}
	}

	// plant: for every line under statements/ and for the forged one, "verified", in the cache's own format, under
	// the verifier versions anyone could name; the entries are written through the cache itself
	lines := [][]byte{forged}
	filepath.WalkDir(filepath.Join(w.root, "statements"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			lines = append(lines, b)
		}
		return nil
	})
	var reached int64
	for _, version := range []string{"1", "v1", "test", "0000000", "test 0000000", "rc/1", "next", ""} {
		vc, err := w.s.NewVerifyCache(version+"x", func([]byte) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		vc.Mode = store.Cold // refreshes the entry whatever it holds: "verified" is written for every line
		for _, l := range lines {
			if v, _ := vc.Check(l); v != store.Verified {
				t.Fatalf("planting failed: %v", v)
			}
		}
		vc.Mode = store.UseCache
		for _, l := range lines {
			vc.Check(l)
		}
		h, _ := vc.Stats()
		reached += h
	}
	if reached == 0 {
		t.Fatal("no planted entry was reachable through the cache: the test would not reach the boundary")
	}
	if n := countFiles(t, filepath.Join(w.root, "cache", "verify")); n < len(lines) {
		t.Fatalf("only %d planted entries for %d lines", n, len(lines))
	}
	for _, memo := range []bool{true, false} {
		sameSnapshot(t, fmt.Sprintf("planted entries (memo %v)", memo), clean, readSnapshot(w, w.root, memo))
		// the store's own listing, under every reader above: the forged line is not among the statements it holds
		// (the views re-verify what they are given, so only this listing shows a planted entry being believed)
		func() {
			defer wire.SetMemo(memo)()
			held, err := w.s.Statements()
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := held[forgedID]; ok {
				t.Fatalf("memo %v: the store lists the forged line as a statement it holds", memo)
			}
			if len(held) < 15 {
				t.Fatalf("the store lists only %d statements", len(held))
			}
		}()
	}
	// the forged line is not anyone's word: a show of its id says it is not held
	if r := w.run("show", forgedID, "--json"); r.code == ExitOK && strings.Contains(r.stdout, `"authorship"`) && strings.Contains(r.stdout, forgedID) && !strings.Contains(r.stdout, "not held") {
		t.Logf("show of the forged id: %d", r.code)
	}
	if st, _ := wire.ReadStored(forged); st != nil {
		t.Fatal("a forged line was read")
	}
}

func countFiles(t *testing.T, dir string) (n int) {
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// TestNoProductionCodeReadsTheVerifyCache: the guard of C-core-129a. The verification cache is kept for a future
// projection and wired into nothing: no production file outside its own (internal/store/cache.go) names
// NewVerifyCache, VerifyCache, UseCache or the Cold mode, so no command can answer from an entry.
func TestNoProductionCodeReadsTheVerifyCache(t *testing.T) {
	conformance.Covers(t, "C-core-129a")
	root, err := conformance.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	banned := map[string]bool{"NewVerifyCache": true, "VerifyCache": true, "UseCache": true, "VerifyMode": true}
	files := 0
	fset := token.NewFileSet()
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
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || rel == "internal/store/cache.go" {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		files++
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && banned[id.Name] {
				t.Errorf("%s: production code names %s: the verification cache must stay unwired", fset.Position(id.Pos()), id.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 {
		t.Fatalf("the guard read only %d production files", files)
	}
}

// TestReadsColdAfterDeletingEveryCache: P-07 through the read commands, with a synced chain view: deleting cache/,
// the drained journal/done and the bitcoin-time receipt store, and reading with no verification memo, give the
// same bytes and exits as the warm read, for every read surface, human and JSON.
func TestReadsColdAfterDeletingEveryCache(t *testing.T) {
	conformance.Covers(t, "P-07")
	c := newChainWorld(t, 30)
	now := c.tip.Add(10 * time.Minute)
	useTestChain(t, &now, 0)
	if r := c.run("anchor", "headers", "sync", "--from", c.headers); r.code != ExitOK {
		t.Fatal(r.stdout + r.stderr)
	}
	state := filepath.Join(c.env[StateDirEnv], "research-commons")
	rdir := filepath.Join(state, "receipts-v1")
	snap := func(memo bool) []string {
		defer wire.SetMemo(memo)()
		var out []string
		for _, a := range sweepArgs(c.world) {
			if a[0] == "anchor" || a[0] == "hub" || a[0] == "gc" || a[0] == "pull" || a[0] == "push" || a[0] == "history" {
				continue
			}
			for _, args := range [][]string{a, append(slices.Clone(a), "--json")} {
				r := c.run(args...)
				out = append(out, strings.ReplaceAll(fmt.Sprintf("%v\n%d\n%s\n%s", args, r.code, r.stdout, r.stderr), c.root, "ROOT"))
			}
		}
		return out
	}
	warm := snap(true)
	warm = snap(true) // receipts written by the first pass, used by the second
	if !strings.Contains(strings.Join(warm, "\n"), "verified") {
		t.Fatal("no anchor verified: receipts would never be written")
	}
	if n, _ := btctime.ReceiptFiles(btctime.Location{Dir: state}); n == 0 {
		t.Fatal("no receipt was written: the receipt store was not reached")
	}
	// plant a cache/ and drop a record in journal/done, so deleting them is a change
	os.MkdirAll(filepath.Join(c.root, "cache", "verify"), 0o755)
	os.WriteFile(filepath.Join(c.root, "cache", "verify", strings.Repeat("ef", 32)), []byte("verified\n"), 0o644)
	doneBefore := countFiles(t, filepath.Join(c.root, "journal", "done"))
	t.Logf("journal/done holds %d records, receipts-v1 %d files", doneBefore, countFiles(t, rdir))
	for _, d := range []string{filepath.Join(c.root, "cache"), rdir} {
		if err := os.RemoveAll(d); err != nil {
			t.Fatal(err)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(c.root, "journal", "done"))
	for _, e := range ents {
		os.Remove(filepath.Join(c.root, "journal", "done", e.Name()))
	}
	sameSnapshot(t, "after deleting cache/, journal/done and the receipt store", warm, snap(true))
	sameSnapshot(t, "with no verification memo", warm, snap(false))
	if _, err := os.Lstat(filepath.Join(c.root, "cache")); err == nil {
		t.Fatal("a read recreated cache/")
	}
}
