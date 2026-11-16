package cli

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/store"
)

// Crash helper protocol: a test re-executes this binary with crashHelperEnv set to
// root, point, nth, marker, then the command's arguments, one per line. TestPublishCrashHelper then runs that one
// command against root with storeOptions.Fault set: at the nth time the command reaches point, it writes the marker
// file and ends the process with exit code crashExit. No deferred function, abort path or cleanup runs, and the
// kernel releases the writer lock: the process crash model of the storage note (§3.3).
const (
	crashHelperEnv = "RC_TEST_CRASH_HELPER"
	crashExit      = 77
)

func TestPublishCrashHelper(t *testing.T) {
	spec := os.Getenv(crashHelperEnv)
	if spec == "" {
		t.Skip("helper process only")
	}
	f := strings.Split(spec, "\n")
	root, point, marker, args := f[0], f[1], f[3], f[4:]
	nth, _ := strconv.Atoi(f[2])
	hits := 0
	storeOptions.Fault = func(p string) {
		if p != point {
			return
		}
		if hits++; hits == nth {
			os.WriteFile(marker, []byte(p), 0o644)
			os.Exit(crashExit)
		}
	}
	r := runIn(root, nil, args...)
	// the point was never reached: say what the command did instead
	os.Stdout.WriteString("NOT-REACHED exit " + strconv.Itoa(r.code) + "\n" + r.stdout + r.stderr)
	os.Exit(3)
}

// crashRun runs one command in a child process that crashes at the nth time it reaches point, and returns the
// child's exit code, its output and whether the marker was written (the point was reached).
func crashRun(t *testing.T, root, point string, nth int, args ...string) (int, string, bool) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "reached")
	cmd := exec.Command(os.Args[0], "-test.run=^TestPublishCrashHelper$")
	cmd.Env = append(os.Environ(), crashHelperEnv+"="+strings.Join(append([]string{root, point, strconv.Itoa(nth), marker}, args...), "\n"))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	got, rerr := os.ReadFile(marker)
	return code, out.String(), rerr == nil && string(got) == point
}

// rawState is what a crash left on disk, read before any command opens (and so replays) the store.
type rawState struct {
	blob       bool     // the blob is in blobs/
	temps      int      // temporaries in tmp/
	pending    []string // op ids with a record in journal/pending
	done       []string // op ids with a record in journal/done
	statements []string // statement ids installed, sorted
}

func readRaw(t *testing.T, root, digest string) rawState {
	t.Helper()
	var r rawState
	_, err := os.Stat(filepath.Join(root, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:")))
	r.blob = err == nil
	tmps, _ := os.ReadDir(filepath.Join(root, "tmp"))
	r.temps = len(tmps)
	for _, sub := range []string{"pending", "done"} {
		ents, _ := os.ReadDir(filepath.Join(root, "journal", sub))
		for _, e := range ents {
			op := strings.TrimSuffix(e.Name(), ".json")
			if sub == "pending" {
				r.pending = append(r.pending, op)
			} else {
				r.done = append(r.done, op)
			}
		}
	}
	filepath.WalkDir(filepath.Join(root, "statements"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			r.statements = append(r.statements, d.Name())
		}
		return nil
	})
	sort.Strings(r.statements)
	return r
}

// crashSnapshot is what a reader sees: the listing and the views of the artifact and of both statements.
func crashSnapshot(t *testing.T, root, digest string, ids []string) string {
	t.Helper()
	var b strings.Builder
	for _, args := range [][]string{{"list", "--json"}, {"show", digest, "--json"}, {"show", ids[0], "--json"}, {"show", ids[1], "--json"}} {
		r := runIn(root, nil, args...)
		b.WriteString(strings.Join(args, " ") + " → " + strconv.Itoa(r.code) + "\n" + r.stdout + r.stderr + "\n")
	}
	return b.String()
}

func newStoreAt(t *testing.T, root string) {
	t.Helper()
	if r := runIn(filepath.Dir(root), nil, "init", root, "--json"); r.code != 0 {
		t.Fatalf("init: %d %s", r.code, r.stdout)
	}
}

// TestPublishCrashMatrix: C-core-125 and P-10 through the command, with a real process crash. One publish (blob,
// authored, holds: one journal record) is run in a child process that ends with exit 77 at each fault point of the
// publish in turn: before step 1, mid-blob (temporary written, not linked), after step 1, after the record, after
// each of the two statements, after the install, after done, after step 5, and after the commit returned but
// before the output. For each point the parent checks that the point was reached (marker, exit 77), what the crash
// left on disk before any command opens the store, that the next status reports what the replay finished and
// agrees with that durable state (a pending record is replayed, a done record projected, nothing else reported)
// and that the status after it has nothing pending, that list and show (the resolver) equal byte for byte either
// the store before the publish (every point before the record: plus the unreferenced blob once step 1 linked it,
// the storage note's "previous state plus unreferenced blobs") or after a publish that was never interrupted
// (every later point), that authored is never readable without its holds, and that a retry after a
// crash before the record commits, reusing a blob step 1 already installed.
func TestPublishCrashMatrix(t *testing.T) {
	conformance.Covers(t, "C-core-125")
	conformance.Covers(t, "P-10")
	dir := t.TempDir()
	key, _ := newKeyFile(t, dir, "ed25519")
	const data = "the bytes of one crash-tested publish"
	content := filepath.Join(dir, "content.bin")
	os.WriteFile(content, []byte(data), 0o644)
	digest := digestOf([]byte(data))
	args := []string{"publish", "--key", key, "--json", "--kind", "authored", "--content", content,
		"--licence", "CC0-1.0", "--description", "crash matrix", "--ts", "2026-01-01T00:00:00Z"}

	// the two reference states: a store before the publish, and one where the publish ran to the end
	before := filepath.Join(dir, "before")
	newStoreAt(t, before)
	complete := filepath.Join(dir, "complete")
	newStoreAt(t, complete)
	r := runIn(complete, nil, args...)
	if r.code != 0 {
		t.Fatalf("reference publish: %d %s", r.code, r.stdout)
	}
	out := outObj(t, r)
	op := string(out.Members["operation"].(canon.String))
	var ids []string
	for _, s := range out.Members["statements"].(canon.Array) {
		ids = append(ids, string(s.(*canon.Object).Members["statement"].(canon.String)))
	}
	if len(ids) != 2 {
		t.Fatalf("reference publish should commit authored and holds: %s", r.stdout)
	}
	authoredID, holdsID := ids[0], ids[1]
	sortedIDs := append([]string(nil), ids...)
	sort.Strings(sortedIDs)
	// the previous state plus the unreferenced blob: what a crash after step 1 leaves (storage note §3.3, row
	// "step 1"); readers then report the bytes held and nothing else
	beforeBlob := filepath.Join(dir, "before-blob")
	newStoreAt(t, beforeBlob)
	st, err := store.Open(beforeBlob, store.Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.InstallBlob(strings.NewReader(data), store.Digest(digest)); err != nil {
		t.Fatal(err)
	}
	snapBefore, snapBeforeBlob := crashSnapshot(t, before, digest, ids), crashSnapshot(t, beforeBlob, digest, ids)
	snapComplete := crashSnapshot(t, complete, digest, ids)
	if snapBefore == snapComplete || snapBefore == snapBeforeBlob || snapBeforeBlob == snapComplete || !strings.Contains(snapComplete, authoredID) {
		t.Fatalf("the reference snapshots do not tell the states apart:\n%s", snapComplete)
	}

	type want struct {
		committed bool // the record was written: the operation is the complete one after recovery
		raw       rawState
		recovered string // what the next status reports the open's replay did: "replayed", "projected" or nothing
	}
	none := rawState{}
	cases := []struct {
		point string
		nth   int
		want  want
	}{
		{store.BeforeBlobs, 1, want{false, none, ""}},
		{store.AfterBlobTemp, 1, want{false, rawState{temps: 1}, ""}},
		{store.AfterBlobs, 1, want{false, rawState{blob: true}, ""}},
		{store.AfterRecord, 1, want{true, rawState{blob: true, pending: []string{op}}, "replayed"}},
		{store.AfterStatement, 1, want{true, rawState{blob: true, pending: []string{op}, statements: []string{authoredID}}, "replayed"}},
		{store.AfterStatement, 2, want{true, rawState{blob: true, pending: []string{op}, statements: sortedIDs}, "replayed"}},
		{store.AfterInstall, 1, want{true, rawState{blob: true, pending: []string{op}, statements: sortedIDs}, "replayed"}},
		{store.AfterDone, 1, want{true, rawState{blob: true, done: []string{op}, statements: sortedIDs}, "projected"}},
		{store.AfterProject, 1, want{true, rawState{blob: true, done: []string{op}, statements: sortedIDs}, "projected"}},
		{store.AfterCommitBeforeOutput, 1, want{true, rawState{blob: true, statements: sortedIDs}, ""}},
	}
	for _, c := range cases {
		t.Run(c.point+"#"+strconv.Itoa(c.nth), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "store")
			newStoreAt(t, root)
			code, childOut, reached := crashRun(t, root, c.point, c.nth, args...)
			if !reached || code != crashExit {
				t.Fatalf("the crash point was not reached: marker %v, exit %d\n%s", reached, code, childOut)
			}
			if strings.Contains(childOut, "\"committed\"") {
				t.Fatalf("the crashed publish printed a result: %s", childOut)
			}

			// what the crash left, before any open replays it
			if got := readRaw(t, root, digest); !rawEqual(got, c.want.raw) {
				t.Fatalf("on disk after the crash: got %+v, want %+v", got, c.want.raw)
			}

			// the next open replays; status reports what that replay did, and agrees with the durable state
			st := outObj(t, runIn(root, nil, "status", "--json"))
			rec, _ := st.Members["recovered_on_open"].(canon.Array) // absent reads as empty: a dropped member is caught below
			if c.want.recovered == "" {
				if len(rec) != 0 {
					t.Fatalf("status reports a recovery the durable state does not hold: %s", canon.Encode(rec))
				}
			} else {
				if len(rec) != 1 {
					t.Fatalf("status should report the one recovered operation: %s", canon.Encode(st))
				}
				e := rec[0].(*canon.Object)
				if e.Members["what"] != canon.String(c.want.recovered) || e.Members["operation"] != canon.String(op) {
					t.Fatalf("status reports %s, want %s of %s", canon.Encode(e), c.want.recovered, op)
				}
			}
			if st.Members["store_state"] != canon.String("nothing pending") {
				t.Fatalf("store state after the replay: %s", canon.Encode(st))
			}
			again := outObj(t, runIn(root, nil, "status", "--json"))
			if again.Members["recovered_on_open"] == nil || len(again.Members["recovered_on_open"].(canon.Array)) != 0 || len(again.Members["operations"].(canon.Array)) != 0 ||
				again.Members["store_state"] != canon.String("nothing pending") {
				t.Fatalf("the second open still had work: %s", canon.Encode(again))
			}

			// readers see the previous state or the complete operation, never part of it
			snap := crashSnapshot(t, root, digest, ids)
			wantSnap := snapBefore
			if c.want.committed {
				wantSnap = snapComplete
			} else if c.want.raw.blob {
				wantSnap = snapBeforeBlob
			}
			if snap != wantSnap {
				t.Fatalf("after recovery the readers see neither the previous nor the complete state (committed=%v):\n%s\nwant:\n%s", c.want.committed, snap, wantSnap)
			}
			a := runIn(root, nil, "show", authoredID, "--json")
			h := runIn(root, nil, "show", holdsID, "--json")
			if strings.Contains(a.stdout, "no statement held") != strings.Contains(h.stdout, "no statement held") {
				t.Fatalf("authored and holds are not readable together:\n%s\n%s", a.stdout, h.stdout)
			}

			// a crash before the record committed nothing: the retry commits, reusing a blob step 1 installed; the
			// crashed process held the key's writer lock, and its exit released it
			if !c.want.committed {
				rr := runIn(root, nil, args...)
				if rr.code != 0 || outObj(t, rr).Members["operation"] != canon.String(op) || strings.Contains(rr.stdout, "writer_lock") {
					t.Fatalf("retry: %d %s", rr.code, rr.stdout)
				}
				if c.want.raw.blob != strings.Contains(rr.stdout, "blob "+digest+" already held") {
					t.Fatalf("retry after %s: the blob step 1 installed should be reused, and only it: %s", c.point, rr.stdout)
				}
				if s := crashSnapshot(t, root, digest, ids); s != snapComplete {
					t.Fatalf("after the retry:\n%s", s)
				}
				return
			}
			// a committed crash: the key's next line chains on the recovered holds (seq 2, prev = holds), and the
			// writer lock the crashed process held was released by its exit
			next := filepath.Join(t.TempDir(), "next.bin")
			os.WriteFile(next, []byte("the next publish after a crash"), 0o644)
			nr := runIn(root, nil, "publish", "--key", key, "--json", "--kind", "authored", "--content", next,
				"--licence", "CC0-1.0", "--description", "next", "--ts", "2026-01-01T00:00:01Z")
			if nr.code != 0 || strings.Contains(nr.stdout, "writer_lock") {
				t.Fatalf("the next publish after the crash: %d %s", nr.code, nr.stdout)
			}
			first := outObj(t, nr).Members["statements"].(canon.Array)[0].(*canon.Object)
			if first.Members["seq"] != canon.Int(2) || first.Members["prev"] != canon.String(holdsID) {
				t.Fatalf("the next line does not chain on the recovered operation: %s", canon.Encode(first))
			}
		})
	}
}

func rawEqual(a, b rawState) bool {
	eq := func(x, y []string) bool { return strings.Join(x, ",") == strings.Join(y, ",") }
	return a.blob == b.blob && a.temps == b.temps && eq(a.pending, b.pending) && eq(a.done, b.done) && eq(a.statements, b.statements)
}

// TestPublishReuseCrashThenGC: C-core-146 (a) with a real process crash. An unreferenced blob older than the grace
// window is named by a publish that brings no bytes (the draft names the digest); the publish process crashes right
// after step 1 (its record not written); gc --apply runs with the default window; the blob is kept because the
// reuse restarted its window, and the retry commits without the content file.
func TestPublishReuseCrashThenGC(t *testing.T) {
	conformance.Partial(t, "C-core-146", "(a) end to end through publish with a process crash right after step 1: the aged held blob the publish reused survives gc --apply and the retry commits without the bytes; (b) and the policy floor of (c) are the store's (TestGCRecheckAtDeletion, TestGCGraceFloor), the one-run value of (c) is TestGCRelease; (d) needs the operation history")
	p := newPubWorld(t)
	data := "bytes this store released long ago, then a crash"
	d, path := heldUnreferenced(t, p, data, 72*time.Hour)
	if r := p.run("gc", "--json"); !strings.Contains(r.stdout, d) {
		t.Fatalf("setup: the aged blob should be a gc candidate: %s", r.stdout)
	}
	draft := p.file("a.json", `{"kind":"authored","body":{"type":"dataset","content":{"digest":"`+d+`","size":`+strconv.Itoa(len(data))+`}}}`)

	code, childOut, reached := crashRun(t, p.root, store.AfterBlobs, 1, "publish", "--key", p.key, "--json", "--draft", draft)
	if !reached || code != crashExit {
		t.Fatalf("the crash point was not reached: marker %v, exit %d\n%s", reached, code, childOut)
	}
	if raw := readRaw(t, p.root, d); !raw.blob || len(raw.pending)+len(raw.done) != 0 {
		t.Fatalf("after a crash at step 1 the blob is held and no record exists: %+v", raw)
	}
	if fi, err := os.Stat(path); err != nil || time.Since(fi.ModTime()) > time.Hour {
		t.Fatalf("the reuse did not restart the blob's window before the crash: %v %v", fi, err)
	}

	// gc with the default window keeps it: its window restarted at the reuse
	if g := p.run("gc", "--apply", "--json"); g.code != 0 || strings.Contains(string(canon.Encode(jsonOf(t, g).Members["deleted"])), d) {
		t.Fatalf("gc deleted a blob a crashed publish had just reused: %d %s", g.code, g.stdout)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("blob gone after gc: %v", err)
	}

	// the retry commits against the held blob, with no content file
	r := p.publish("--draft", draft)
	if r.code != 0 || !strings.Contains(r.stdout, "blob "+d+" already held") {
		t.Fatalf("retry: %d %s", r.code, r.stdout)
	}
}

// TestFaultSeamTestOnly: the crash seam is a test seam. No production (non-_test.go) file assigns store.Options'
// Fault, the cli's storeOptions or beforeCommit, composes an Options literal naming Fault (or positionally), or
// declares storeOptions with a value. The guard proves it read the declarations it protects, so a rename cannot
// make it vacuous.
func TestFaultSeamTestOnly(t *testing.T) {
	root, err := conformance.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	guarded := map[string]bool{"Fault": true, "storeOptions": true, "beforeCommit": true}
	seen := map[string]bool{}
	files := 0
	fset := token.NewFileSet()
	report := func(n ast.Node, what string) {
		t.Errorf("%s: production code %s: the crash seam is for tests only", fset.Position(n.Pos()), what)
	}
	// target names the guarded identifier an assignment's left side writes (x, x.f, x.Fault, *x), or "".
	var target func(e ast.Expr) string
	target = func(e ast.Expr) string {
		switch x := e.(type) {
		case *ast.Ident:
			if guarded[x.Name] {
				return x.Name
			}
		case *ast.SelectorExpr:
			if x.Sel.Name == "Fault" {
				return "Fault"
			}
			return target(x.X)
		case *ast.StarExpr:
			return target(x.X)
		case *ast.ParenExpr:
			return target(x.X)
		case *ast.IndexExpr:
			return target(x.X)
		}
		return ""
	}
	isOptions := func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.Ident:
			return x.Name == "Options"
		case *ast.SelectorExpr:
			return x.Sel.Name == "Options"
		}
		return false
	}
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
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		files++
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				for _, l := range x.Lhs {
					if g := target(l); g != "" {
						report(x, "assigns "+g)
					}
				}
			case *ast.IncDecStmt:
				if g := target(x.X); g != "" {
					report(x, "changes "+g)
				}
			case *ast.UnaryExpr:
				// &storeOptions handed to anything could be written through
				if x.Op == token.AND && target(x.X) == "storeOptions" {
					report(x, "takes the address of storeOptions")
				}
			case *ast.CompositeLit:
				for _, e := range x.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Fault" {
							report(x, "composes a literal naming Fault")
						}
					} else if isOptions(x.Type) {
						report(x, "composes an Options literal positionally")
					}
				}
			case *ast.Field:
				for _, nm := range x.Names {
					if nm.Name == "Fault" {
						seen["Fault"] = true
					}
				}
			case *ast.ValueSpec:
				for i, nm := range x.Names {
					if nm.Name == "storeOptions" || nm.Name == "beforeCommit" {
						seen[nm.Name] = true
					}
					if nm.Name == "storeOptions" && len(x.Values) > i {
						report(x, "declares storeOptions with a value")
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
	if files < 100 {
		t.Fatalf("the guard read only %d production files", files)
	}
	for g := range guarded {
		if !seen[g] {
			t.Errorf("the guard never saw the declaration of %s: renamed? update the guard", g)
		}
	}
}

// TestReleaseAndGCCrash: P-10 for the store's other writers, with a real process crash. gc --release (one
// operation: the withdrawal is committed, then the blob removed) crashes at each of its points; a pull crashes
// before and after its commit point (its admitted set is held whole after the replay, or not at all, and pulling
// again finishes it); gc --apply crashes
// with the blob moved aside, before its re-check decides. After each crash the next status reports what the
// replay did, the blob is never gone while the serving holds is current, the withdrawal is installed exactly when
// its record was written, and running the command again finishes the work.
func TestReleaseAndGCCrash(t *testing.T) {
	conformance.Partial(t, "P-10", "release, pull and gc's move-aside with a process crash at each of their points, through the commands; the commit points of publish are TestPublishCrashMatrix")
	points := []string{store.AfterBlobs, store.AfterRecord, store.AfterStatement, store.AfterInstall, store.AfterDone,
		store.AfterProject, store.AfterWithdrawal, store.AfterBlobRemoved}
	for _, point := range points {
		t.Run("release "+point, func(t *testing.T) {
			w, b, keyFile := releaseWorld(t)
			held := len(readRaw(t, w.root, b).statements)
			code, childOut, reached := crashRun(t, w.root, point, 1, "gc", "--release", b, "--key", keyFile, "--json")
			if !reached || code != crashExit {
				t.Fatalf("the crash point was not reached: marker %v, exit %d\n%s", reached, code, childOut)
			}
			committed := point != store.AfterBlobs
			raw := readRaw(t, w.root, b)
			if !raw.blob && point != store.AfterBlobRemoved {
				t.Fatalf("blob deleted at %q, before the withdrawal was committed and installed: %+v", point, raw)
			}
			if (len(raw.pending)+len(raw.done) == 1) != (committed && point != store.AfterWithdrawal && point != store.AfterBlobRemoved) {
				t.Fatalf("journal after a crash at %q: %+v", point, raw)
			}
			st := outObj(t, w.run("status", "--json"))
			if st.Members["store_state"] != canon.String("nothing pending") {
				t.Fatalf("status after the replay: %s", canon.Encode(st))
			}
			show := w.run("show", b, "--json").stdout
			serving := strings.Contains(show, `"holders":["`+w.signer("OPR")+`"]`)
			if serving == committed {
				t.Fatalf("after a crash at %q (committed=%v) the serving holds is current=%v: %s", point, committed, serving, show)
			}
			// the release run again finishes it: the withdrawal (signed again only if none was committed), the blob gone
			r := runIn(w.root, map[string]string{KeyEnv: keyFile}, "gc", "--release", b, "--json")
			if point == store.AfterBlobRemoved {
				if _, err := os.Stat(filepath.Join(w.root, "blobs", "sha256", strings.TrimPrefix(b, "sha256:"))); err == nil {
					t.Fatal("the blob came back after its removal")
				}
				return
			}
			if r.code != 0 {
				t.Fatalf("release again after a crash at %q: %d %s", point, r.code, r.stdout)
			}
			// one withdrawal in all: a committed one is reused, not signed again
			if n := len(readRaw(t, w.root, b).statements); n != held+1 {
				t.Fatalf("after a crash at %q and a second release the store holds %d statements, want %d", point, n, held+1)
			}
			if after := w.run("show", b, "--json").stdout; !strings.Contains(after, `"bytes":"not held here"`) || !strings.Contains(after, `"holders":[]`) {
				t.Fatalf("after the second release: %s", after)
			}
		})
	}
	// pull is the other writer through the same commit: blobs, then one record with every admitted statement
	src := newWorld(t)
	src.blob("P", []byte("bytes a pull brings"))
	src.authored("A:P", "K1", "P")
	pkg := t.TempDir()
	copyData(t, src.root, pkg)
	for _, point := range []string{store.AfterBlobTemp, store.AfterBlobs, store.AfterRecord, store.AfterStatement, store.AfterDone} {
		t.Run("pull "+point, func(t *testing.T) {
			dst := newWorld(t)
			code, childOut, reached := crashRun(t, dst.root, point, 1, "pull", pkg, "--json")
			if !reached || code != crashExit {
				t.Fatalf("the crash point was not reached: marker %v, exit %d\n%s", reached, code, childOut)
			}
			committed := point != store.AfterBlobTemp && point != store.AfterBlobs
			st := outObj(t, dst.run("status", "--json"))
			if st.Members["store_state"] != canon.String("nothing pending") {
				t.Fatalf("status after the replay: %s", canon.Encode(st))
			}
			if held := !strings.Contains(dst.run("show", src.ids["A:P"], "--json").stdout, "no statement held"); held != committed {
				t.Fatalf("after a crash at %q the pulled statement is held=%v, committed=%v", point, held, committed)
			}
			r := dst.run("pull", pkg, "--json")
			if r.code != 0 || strings.Contains(dst.run("show", src.ids["A:P"], "--json").stdout, "no statement held") {
				t.Fatalf("pull again after a crash at %q: %d %s", point, r.code, r.stdout)
			}
		})
	}
	t.Run("gc apply, moved aside", func(t *testing.T) {
		p := newPubWorld(t)
		d, path := heldUnreferenced(t, p, "an unreferenced blob gc is deleting", 72*time.Hour)
		code, childOut, reached := crashRun(t, p.root, store.GCMoved, 1, "gc", "--apply", "--json")
		if !reached || code != crashExit {
			t.Fatalf("the crash point was not reached: marker %v, exit %d\n%s", reached, code, childOut)
		}
		if raw := readRaw(t, p.root, d); raw.blob || raw.temps != 1 {
			t.Fatalf("a crash with the blob moved aside leaves it in tmp/: %+v", raw)
		}
		st := outObj(t, p.run("status", "--json"))
		rec, _ := st.Members["recovered_on_open"].(canon.Array)
		if len(rec) != 1 || rec[0].(*canon.Object).Members["what"] != canon.String("restored blob") {
			t.Fatalf("status should report the blob restored: %s", canon.Encode(st))
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("the blob is not back: %v", err)
		}
		if g := p.run("gc", "--apply", "--json"); g.code != 0 || !strings.Contains(string(canon.Encode(jsonOf(t, g).Members["deleted"])), d) {
			t.Fatalf("gc again: %d %s", g.code, g.stdout)
		}
	})
}
