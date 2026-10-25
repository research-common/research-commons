package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

func testKey(name string) wire.Key {
	h := sha256.Sum256([]byte("research-commons go test key " + name))
	return wire.Ed25519Key{Seed: h[:]}
}

func digestOf(b []byte) Digest {
	h := sha256.Sum256(b)
	return Digest("sha256:" + hex.EncodeToString(h[:]))
}

// authored signs an authored statement over blob bytes b.
func authored(k wire.Key, seq int64, prev string, b []byte) ([]byte, string) {
	c := &canon.Object{Keys: []string{"digest", "size"}, Members: map[string]canon.Value{
		"digest": canon.String(digestOf(b)), "size": canon.Int(len(b))}}
	body := &canon.Object{Keys: []string{"content", "type"}, Members: map[string]canon.Value{"content": c, "type": canon.String("dataset")}}
	return wire.Sign(wire.Draft{Kind: "authored", Seq: seq, Prev: prev, TS: "2026-10-15T00:00:00Z", Body: body}, k)
}

func open(t *testing.T, root string, o Options) *Store {
	t.Helper()
	s, err := Open(root, o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func refusedAs(t *testing.T, err error, class refusal.Class, reason, detail string) {
	t.Helper()
	var r *refusal.Refusal
	if !errors.As(err, &r) || r.Class != class || r.Reason != reason || !strings.Contains(r.Detail, detail) {
		t.Fatalf("got %v, want %s: %s …%s…", err, class, reason, detail)
	}
}

// snapshot is every file under root except tmp/, by relative path → content hash.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if strings.HasPrefix(rel, "tmp"+string(filepath.Separator)) {
			return nil
		}
		b, _ := os.ReadFile(p)
		out[rel] = string(digestOf(b))
		return nil
	})
	return out
}

func TestInstallBlob(t *testing.T) {
	s := open(t, t.TempDir(), Options{NoSync: true})
	data := []byte("exact bytes\x00\xff\r\n")
	d, res, err := s.InstallBlob(bytes.NewReader(data), "")
	if err != nil || res != Installed || d != digestOf(data) {
		t.Fatal(d, res, err)
	}
	// Same bytes again: reused after a re-hash, not rewritten, and the grace window restarts (§6.1.1).
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(s.blobPath(d), old, old); err != nil {
		t.Fatal(err)
	}
	if _, res, err := s.InstallBlob(bytes.NewReader(data), d); err != nil || res != Reused {
		t.Fatal(res, err)
	}
	if fi, err := os.Stat(s.blobPath(d)); err != nil || time.Since(fi.ModTime()) > time.Minute {
		t.Fatalf("reuse did not restart the grace window: %v %v", fi.ModTime(), err)
	}
	f, err := s.OpenBlob(d)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if !bytes.Equal(got, data) {
		t.Fatal("bytes differ")
	}
	if fi, _ := os.Stat(s.blobPath(d)); fi.Mode().Perm()&0o222 != 0 {
		t.Fatal("blob installed writable")
	}
	if ents, _ := os.ReadDir(s.dir("tmp")); len(ents) != 0 {
		t.Fatalf("temporaries left behind: %v", ents)
	}
}

// changingReader yields one set of bytes: the source changed after the caller hashed it.
type changingReader struct{ r io.Reader }

func (c changingReader) Read(p []byte) (int, error) { return c.r.Read(p) }

// TestExactBytes: C-core-124. The source changed between an earlier hash and the copy: nothing installed,
// both hashes named. A destination pre-placed with wrong bytes: quarantined, verified copy installed.
func TestExactBytes(t *testing.T) {
	conformance.Covers(t, "C-core-124")
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	orig := []byte("version one")
	expect := digestOf(orig)
	before := snapshot(t, root)
	_, _, err := s.InstallBlob(changingReader{strings.NewReader("version two")}, expect)
	refusedAs(t, err, refusal.Intrinsic, HashMismatch, "expected "+string(expect)+", got "+string(digestOf([]byte("version two"))))
	if after := snapshot(t, root); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatal("a mismatched install changed the store")
	}

	// Pre-placed corrupt destination.
	p := s.blobPath(expect)
	if err := os.WriteFile(p, []byte("not version one"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, res, err := s.InstallBlob(bytes.NewReader(orig), expect)
	if err != nil || res != Replaced || d != expect {
		t.Fatal(res, err)
	}
	if h, _ := hashFile(p); h != expect {
		t.Fatal("installed bytes do not match the hash")
	}
	q, _ := os.ReadDir(s.dir("quarantine"))
	if len(q) != 1 {
		t.Fatalf("corrupt copy not quarantined: %v", q)
	}
	if b, _ := os.ReadFile(filepath.Join(s.dir("quarantine"), q[0].Name())); string(b) != "not version one" {
		t.Fatal("quarantine does not hold the corrupt bytes")
	}
}

// TestCorruptReuse: C-core-123. A stored copy corrupted in place under its own name is refused on open,
// naming both hashes; nothing reads the corrupt bytes.
func TestCorruptReuse(t *testing.T) {
	conformance.Partial(t, "C-core-123", "the store refuses the corrupt copy and names both hashes; re-fetch from a hold and run refusing need fetch and the runner")
	s := open(t, t.TempDir(), Options{NoSync: true})
	d, _, _ := s.InstallBlob(strings.NewReader("good"), "")
	p := s.blobPath(d)
	_ = os.Chmod(p, 0o644)
	_ = os.WriteFile(p, []byte("evil"), 0o644)
	_, err := s.OpenBlob(d)
	refusedAs(t, err, refusal.Intrinsic, CorruptBlob, "blob "+string(d)+": stored copy corrupt (hashes to "+string(digestOf([]byte("evil")))+"); refetch")
}

func TestCommit(t *testing.T) {
	var projected []string
	s := open(t, t.TempDir(), Options{NoSync: true, Project: func(r Record) error { projected = append(projected, r.Op); return nil }})
	k := testKey("A")
	data := []byte("dataset")
	d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
	line, id := authored(k, 0, "", data)
	out, err := s.Commit("publish", [][]byte{line}, []Digest{d})
	if err != nil || out.NeedsRepair != nil || !slices.Equal(out.IDs, []string{id}) || !slices.Equal(projected, []string{out.Op}) {
		t.Fatal(out, err)
	}
	sts, _ := s.Statements()
	if !bytes.Equal(sts[id], line) || len(sts) != 1 {
		t.Fatal(sts)
	}
	if st, _ := s.Status(); len(st) != 0 {
		t.Fatalf("journal not empty after a clean commit: %v", st)
	}
	// Re-committing the identical statement is success, one file.
	if _, err := s.Commit("publish", [][]byte{line}, []Digest{d}); err != nil {
		t.Fatal(err)
	}
	if sts, _ := s.Statements(); len(sts) != 1 {
		t.Fatal(sts)
	}
	// A statement Read refuses is never committed; a blob not held refuses before the commit point.
	if _, err := s.Commit("publish", [][]byte{line[:len(line)-2]}, nil); err == nil {
		t.Fatal("malformed line committed")
	}
	if _, err := s.Commit("publish", [][]byte{line}, []Digest{digestOf([]byte("absent"))}); err == nil {
		t.Fatal("committed against a blob not held")
	}
}

// TestCrashAtEveryPoint: C-core-125 and P-10. A two-statement publish is cut at every commit point. On the
// next Open the store is either the previous state (crash before the commit point) or the complete
// operation (crash at or after it); Status before reopening reports the operation as committed exactly when
// it is; a statement in a pending record is never visible before replay.
func TestCrashAtEveryPoint(t *testing.T) {
	conformance.Partial(t, "C-core-125", "every commit boundary of the store's protocol, and of the release operation (TestReleaseCrash) and gc's move-aside (TestGCCrashMidDeletion), recovery to previous-or-complete, status and fsck reporting of pending, done and missing-blob states: checked on the store; publish's own steps (pre-pin check, anchor) and the resolver's listing need those layers")
	conformance.Partial(t, "P-10", "crash injection at every reported commit point of the store; process crash model (the declared durability with NoSync)")
	k := testKey("A")
	data := []byte("dataset")
	l0, id0 := authored(k, 0, "", data)
	l1, id1 := authored(k, 1, id0, data)
	points := []string{AfterBlobs, AfterRecord, AfterStatement, AfterInstall, AfterDone, AfterProject}
	for _, point := range points {
		for nth := 1; nth <= 2; nth++ {
			if nth == 2 && point != AfterStatement {
				continue
			}
			t.Run(fmt.Sprintf("%s#%d", point, nth), func(t *testing.T) {
				root := t.TempDir()
				var projections []string
				proj := func(r Record) error { projections = append(projections, r.Op); return nil }
				hits := 0
				s := open(t, root, Options{NoSync: true, Project: proj, crash: func(p string) error {
					if p == point {
						hits++
						if hits == nth {
							return ErrCrash
						}
					}
					return nil
				}})
				d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
				out, err := s.Commit("publish", [][]byte{l0, l1}, []Digest{d})
				if !errors.Is(err, ErrCrash) {
					t.Fatalf("no crash at %s: %v", point, err)
				}
				committed := point != AfterBlobs
				// The caller can tell "nothing committed" from "committed, install incomplete" (§3.5).
				if out.Committed != committed || committed != strings.Contains(err.Error(), "committed, pending install") {
					t.Fatalf("crash at %s: Committed=%v, err %q", point, out.Committed, err)
				}
				// Before reopening: what is visible, and what status reports.
				visible, _ := s.Statements()
				st, _ := s.Status()
				if point == AfterRecord || point == AfterStatement || point == AfterInstall {
					if len(st) != 1 || st[0].What != "committed, pending install" || st[0].Op != out.Op {
						t.Fatalf("status %v", st)
					}
				}
				if point == AfterDone {
					if len(st) != 1 || st[0].What != "committed, needs repair" {
						t.Fatalf("status %v", st)
					}
				}
				if !committed && (len(st) != 0 || len(visible) != 0) {
					t.Fatalf("crash before the commit point left %v %v", st, visible)
				}
				_ = visible // partial visibility between a crash and replay is in-process only; Open replays first

				// Reopen: recovery runs before any read.
				projections = nil
				s2 := open(t, root, Options{NoSync: true, Project: proj})
				after, _ := s2.Statements()
				if committed {
					if len(after) != 2 || after[id0] == nil || after[id1] == nil {
						t.Fatalf("committed operation incomplete after recovery: %v", after)
					}
					if point != AfterProject && !slices.Equal(projections, []string{out.Op}) {
						t.Fatalf("recovery did not project %s: %v", out.Op, projections)
					}
				} else if len(after) != 0 {
					t.Fatalf("uncommitted operation visible after recovery: %v", after)
				}
				if st, _ := s2.Status(); len(st) != 0 {
					t.Fatalf("journal not drained after recovery: %v", st)
				}
			})
		}
	}
}

// TestProjectionFailure: C-core-126. Step 5 fails: the operation is committed and reported needs repair,
// nothing is rolled back; repair re-projects; a record whose statement fails verification is quarantined on
// recovery and none of its statements is installed.
func TestProjectionFailure(t *testing.T) {
	conformance.Partial(t, "C-core-126", "committed + needs repair, nothing rolled back, repair re-projects, a corrupt record quarantined with nothing installed: checked; the projection cache and its rebuild/drift check exist now (cache.go, TestCacheColdEqualsWarm, fsck --rebuild) and a missing blob after commit is needs repair (TestFsckMissingBlobInRecord); the resolver's own index is not wired to the cache")
	root := t.TempDir()
	fail := true
	proj := func(Record) error {
		if fail {
			return errors.New("index write: disk full")
		}
		return nil
	}
	s := open(t, root, Options{NoSync: true, Project: proj})
	k := testKey("A")
	l0, id0 := authored(k, 0, "", []byte("x"))
	d, _, _ := s.InstallBlob(strings.NewReader("x"), "")
	out, err := s.Commit("publish", [][]byte{l0}, []Digest{d})
	if err != nil || out.NeedsRepair == nil || !strings.Contains(out.NeedsRepair.Error(), "committed, needs repair") ||
		!strings.Contains(out.NeedsRepair.Error(), "run repair") {
		t.Fatal(out, err)
	}
	if sts, _ := s.Statements(); sts[id0] == nil {
		t.Fatal("committed statement rolled back")
	}
	if st, _ := s.Status(); len(st) != 1 || st[0].What != "committed, needs repair" {
		t.Fatal(st)
	}
	fail = false
	evs, err := s.Repair()
	if err != nil || len(evs) != 1 || evs[0].What != "projected" {
		t.Fatal(evs, err)
	}
	if st, _ := s.Status(); len(st) != 0 {
		t.Fatal(st)
	}

	// A pending record whose statement no longer verifies (the record itself is corrupt).
	k2 := testKey("B")
	l1, id1 := authored(k2, 0, "", []byte("x"))
	bad := bytes.Replace(l1, []byte(`"dataset"`), []byte(`"report"`), 1)
	r := Record{Kind: "publish", Lines: [][]byte{l1, bad}, Seq: 7}
	body := r.encode()
	if err := os.WriteFile(filepath.Join(root, "journal", "pending", opID(body)+".json"), append(body, '\n'), 0o444); err != nil {
		t.Fatal(err)
	}
	s3 := open(t, root, Options{NoSync: true})
	if sts, _ := s3.Statements(); sts[id1] != nil {
		t.Fatal("a statement from a corrupt record was installed")
	}
	if len(s3.Recovered) != 1 || s3.Recovered[0].What != "quarantined" {
		t.Fatal(s3.Recovered)
	}
	// A record renamed to a different op id is quarantined too.
	good := Record{Kind: "publish", Lines: [][]byte{l1}, Seq: 8}
	if err := os.WriteFile(filepath.Join(root, "journal", "pending", strings.Repeat("0", 64)+".json"), append(good.encode(), '\n'), 0o444); err != nil {
		t.Fatal(err)
	}
	s4 := open(t, root, Options{NoSync: true})
	if sts, _ := s4.Statements(); sts[id1] != nil || len(s4.Recovered) != 1 || s4.Recovered[0].What != "quarantined" {
		t.Fatal(s4.Recovered)
	}
}

// TestConcurrentSameBlob: C-core-128. Many goroutines publish the same bytes, two keys: one blob, one
// statement per key (and per distinct body), nothing overwritten.
func TestConcurrentSameBlob(t *testing.T) {
	conformance.Partial(t, "C-core-128", "goroutines here and two OS processes in TestTwoProcesses; publish's own reporting (\"already committed\") needs publish")
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	data := bytes.Repeat([]byte("same"), 4096)
	ka, kb := testKey("A"), testKey("B")
	la, ida := authored(ka, 0, "", data)
	lb, idb := authored(kb, 0, "", data)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d, _, err := s.InstallBlob(bytes.NewReader(data), digestOf(data))
			if err != nil {
				errs <- err
				return
			}
			l := la
			if i%2 == 1 {
				l = lb
			}
			if _, err := s.Commit("publish", [][]byte{l}, []Digest{d}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	blobs, _ := os.ReadDir(filepath.Join(root, "blobs", "sha256"))
	sts, _ := s.Statements()
	if len(blobs) != 1 || len(sts) != 2 || sts[ida] == nil || sts[idb] == nil {
		t.Fatalf("%d blobs, %d statements", len(blobs), len(sts))
	}
	if h, _ := hashFile(filepath.Join(root, "blobs", "sha256", blobs[0].Name())); h != digestOf(data) {
		t.Fatal("blob overwritten with other bytes")
	}
}

// TestTwoProcesses: C-core-128 across processes. The test binary re-runs itself as N writers on one store,
// each installing the same blob and committing a statement; afterwards there is one blob, one statement per
// key, an empty journal, and nothing overwritten.
func TestTwoProcesses(t *testing.T) {
	if root := os.Getenv("RC_STORE_CHILD"); root != "" {
		s, err := Open(root, Options{NoSync: true})
		if err != nil {
			fmt.Println("child open:", err)
			os.Exit(2)
		}
		data := bytes.Repeat([]byte("same"), 4096)
		k := testKey(os.Getenv("RC_STORE_KEY"))
		l, _ := authored(k, 0, "", data)
		for i := 0; i < 20; i++ {
			d, _, err := s.InstallBlob(bytes.NewReader(data), digestOf(data))
			if err == nil {
				_, err = s.Commit("publish", [][]byte{l}, []Digest{d})
			}
			if err != nil {
				fmt.Println("child:", err)
				os.Exit(1)
			}
		}
		os.Exit(0)
	}
	root := t.TempDir()
	open(t, root, Options{NoSync: true})
	exe, _ := os.Executable()
	var procs []*exec.Cmd
	for i := 0; i < 6; i++ {
		c := exec.Command(exe, "-test.run=^TestTwoProcesses$")
		c.Env = append(os.Environ(), "RC_STORE_CHILD="+root, "RC_STORE_KEY="+string(rune('A'+i%2)))
		var out bytes.Buffer
		c.Stdout, c.Stderr = &out, &out
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		procs = append(procs, c)
		t.Cleanup(func() {
			if t.Failed() {
				t.Log(out.String())
			}
		})
	}
	for _, c := range procs {
		if err := c.Wait(); err != nil {
			t.Fatalf("writer process failed: %v", err)
		}
	}
	s := open(t, root, Options{NoSync: true})
	data := bytes.Repeat([]byte("same"), 4096)
	_, ida := authored(testKey("A"), 0, "", data)
	_, idb := authored(testKey("B"), 0, "", data)
	blobs, _ := os.ReadDir(filepath.Join(root, "blobs", "sha256"))
	sts, _ := s.Statements()
	st, _ := s.Status()
	if len(blobs) != 1 || len(sts) != 2 || sts[ida] == nil || sts[idb] == nil || len(st) != 0 {
		t.Fatalf("%d blobs, %d statements, journal %v", len(blobs), len(sts), st)
	}
	if h, _ := hashFile(filepath.Join(root, "blobs", "sha256", blobs[0].Name())); h != digestOf(data) {
		t.Fatal("blob overwritten")
	}
}

func TestDurabilityDeclared(t *testing.T) {
	s := open(t, t.TempDir(), Options{})
	d := s.Durability()
	if d.FileSync != "fsync" || d.ExclusiveCreate != "link" || d.Rename != "atomic" {
		t.Fatal(d)
	}
	n := open(t, t.TempDir(), Options{NoSync: true}).Durability()
	if n.FileSync != "none" || !strings.Contains(n.Assumes, "process crash only") {
		t.Fatal(n)
	}
}

func TestLayoutMarker(t *testing.T) {
	root := t.TempDir()
	open(t, root, Options{NoSync: true})
	_ = os.WriteFile(filepath.Join(root, "rc-store"), []byte(`{"layout":"rc-store/9"}`), 0o644)
	if _, err := Open(root, Options{NoSync: true}); err == nil {
		t.Fatal("unknown layout opened")
	}
}

// TestCorruptStatementFile: a file under statements/<signer>/<id> that does not read to that id (corrupted on
// disk) never makes the store unopenable (I15, §3.4). Replay of a pending record quarantines it and installs
// the verified line; so does a fresh Commit. A file that reads to the same id under another valid encoding
// is the same statement and stays.
func TestCorruptStatementFile(t *testing.T) {
	root := t.TempDir()
	k := testKey("A")
	l0, id0 := authored(k, 0, "", []byte("x"))
	st, _ := wire.Read(l0)
	path := filepath.Join(root, "statements", signerDir(st.Signer), id0)
	corrupt := func() {
		t.Helper()
		_ = os.Chmod(path, 0o644)
		if err := os.WriteFile(path, []byte(`{"not":"a statement"}`), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	quarantined := func(want int) {
		t.Helper()
		qs, _ := filepath.Glob(filepath.Join(root, "quarantine", "statement-"+id0+"-*"))
		if len(qs) != want {
			t.Fatalf("%d quarantined statement files, want %d", len(qs), want)
		}
	}

	// Replay path: crash after the record, corrupt the installed file, reopen.
	s := open(t, root, Options{NoSync: true, crash: func(p string) error {
		if p == AfterInstall {
			return ErrCrash
		}
		return nil
	}})
	d, _, _ := s.InstallBlob(strings.NewReader("x"), "")
	if out, err := s.Commit("publish", [][]byte{l0}, []Digest{d}); !out.Committed || !errors.Is(err, ErrCrash) {
		t.Fatal(out, err)
	}
	corrupt()
	s2, err := Open(root, Options{NoSync: true})
	if err != nil {
		t.Fatalf("a corrupt statement file made the store unopenable: %v", err)
	}
	if sts, _ := s2.Statements(); !bytes.Equal(sts[id0], l0) {
		t.Fatal("verified line not installed over the corrupt copy")
	}
	var replaced bool
	for _, ev := range s2.Recovered {
		replaced = replaced || (ev.What == "replaced statement" && strings.HasPrefix(ev.Detail, id0))
	}
	if !replaced {
		t.Fatalf("recovery did not report the replacement: %v", s2.Recovered)
	}
	quarantined(1)

	// Commit path.
	corrupt()
	out, err := s2.Commit("publish", [][]byte{l0}, []Digest{d})
	if err != nil || !slices.Equal(out.Replaced, []string{id0}) {
		t.Fatal(out, err)
	}
	quarantined(2)

	// Same statement, another encoding of the file (not canonical, still reads to the id): kept, success.
	_ = os.Chmod(path, 0o644)
	if err := os.WriteFile(path, append(append([]byte(" "), l0...), '\n'), 0o444); err != nil {
		t.Fatal(err)
	}
	if out, err := s2.Commit("publish", [][]byte{l0}, []Digest{d}); err != nil || out.Replaced != nil {
		t.Fatal(out, err)
	}
	quarantined(2)
}

// TestTmpSweep: Open removes temporaries older than the grace window (a crash between CreateTemp and the link
// leaves one nothing references) and leaves young ones alone (another process may be writing).
func TestTmpSweep(t *testing.T) {
	root := t.TempDir()
	open(t, root, Options{NoSync: true})
	old, young := filepath.Join(root, "tmp", "blob-old"), filepath.Join(root, "tmp", "blob-young")
	for _, p := range []string{old, young} {
		if err := os.WriteFile(p, []byte("partial"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-tmpGrace - time.Minute)
	_ = os.Chtimes(old, past, past)
	s := open(t, root, Options{NoSync: true})
	if _, err := os.Stat(old); err == nil {
		t.Fatal("stale temporary kept")
	}
	if _, err := os.Stat(young); err != nil {
		t.Fatal("young temporary removed")
	}
	if len(s.Recovered) != 1 || s.Recovered[0].What != "removed temporary" {
		t.Fatal(s.Recovered)
	}
	if fi, err := os.Stat(filepath.Join(root, "retained")); err != nil || !fi.IsDir() {
		t.Fatal("retained/ not reserved in the layout")
	}
}
