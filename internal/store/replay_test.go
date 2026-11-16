package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/refusal"
)

// leaveDone commits l (with blob data) and stops at AfterDone, leaving a done/ record whose statements are
// installed: the state a crash after step 4 leaves.
func leaveDone(t *testing.T, root string, l []byte, data []byte) string {
	t.Helper()
	s := open(t, root, Options{NoSync: true, crash: func(p string) error {
		if p == AfterDone {
			return ErrCrash
		}
		return nil
	}})
	d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
	out, err := s.Commit("publish", [][]byte{l}, []Digest{d})
	if !errors.Is(err, ErrCrash) || !out.Installed {
		t.Fatal(out, err)
	}
	return out.Op
}

// TestDoneRecordReinstalls: a done record (installed, step 5 not reached) whose statement file was removed since
// gets the statement back on the next open: step 3 is idempotent and runs for done records too, so fsck's
// "the next open replays it" holds. Repair does the same. Nothing else is installed.
func TestDoneRecordReinstalls(t *testing.T) {
	root := t.TempDir()
	k := testKey("A")
	data := []byte("done, then removed")
	l, id := authored(k, 0, "", data)
	op := leaveDone(t, root, l, data)
	p := filepath.Join(root, "statements", signerDir(k.Signer()), id)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	// fsck promises the next open replays it
	s0 := &Store{root: root, opt: Options{NoSync: true}}
	r, _ := s0.Fsck(FsckOptions{})
	if j := r.Of(FsckJournal); len(j) != 1 || !strings.Contains(j[0].Detail, "orphan done record") || !strings.Contains(j[0].Detail, "the next open replays it") {
		t.Fatal(r.Render())
	}
	s := open(t, root, Options{NoSync: true})
	if sts, _ := s.Statements(); sts[id] == nil {
		t.Fatal("the next open did not reinstall the done record's statement")
	}
	if len(s.Recovered) != 1 || s.Recovered[0].What != "projected" || s.Recovered[0].Op != op {
		t.Fatal(s.Recovered)
	}
	if st, _ := s.Status(); len(st) != 0 {
		t.Fatal(st)
	}

	// Repair, on an open store, does it too
	root2 := t.TempDir()
	op2 := leaveDone(t, root2, l, data)
	// the first projection (on open) fails, and the statement file goes missing meanwhile
	once := true
	s2 := open(t, root2, Options{NoSync: true, Project: func(Record) error {
		if once {
			once = false
			_ = os.Remove(filepath.Join(root2, "statements", signerDir(k.Signer()), id))
			return errors.New("projection failed after the statement went missing")
		}
		return nil
	}})
	if sts, _ := s2.Statements(); sts[id] != nil {
		t.Fatal("setup: the statement should be gone")
	}
	evs, err := s2.Repair(op2)
	if err != nil || len(evs) != 1 || evs[0].What != "projected" {
		t.Fatal(evs, err)
	}
	if sts, _ := s2.Statements(); sts[id] == nil {
		t.Fatal("Repair did not reinstall the done record's statement")
	}
}

// TestDegradedOpen: a record whose replay fails (statements/ not writable) does not fail Open. The event
// "replay failed" names it with the error; readers do not see its statements (the operation is never shown half
// installed); a writer for its signer is refused naming the operation; a writer for another key, Status and Fsck
// work. Once the cause is fixed the next open finishes it.
func TestDegradedOpen(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions; the fault cannot be injected")
	}
	root := t.TempDir()
	k, other := testKey("A"), testKey("B")
	data := []byte("pending, then blocked")
	l0, id0 := authored(k, 0, "", data)
	l1, id1 := authored(k, 1, id0, data)
	// commit, crash after the first statement: a pending record, one of two statements installed
	hits := 0
	s := open(t, root, Options{NoSync: true, crash: func(p string) error {
		if p == AfterStatement {
			hits++
			return ErrCrash
		}
		return nil
	}})
	d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
	out, err := s.Commit("publish", [][]byte{l0, l1}, []Digest{d})
	if !errors.Is(err, ErrCrash) || out.Installed {
		t.Fatal(out, err)
	}
	dir := filepath.Join(root, "statements", signerDir(k.Signer()))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })

	s2, err := Open(root, Options{NoSync: true})
	if err != nil {
		t.Fatalf("a replay failure failed the open: %v", err)
	}
	if len(s2.Recovered) != 1 || s2.Recovered[0].What != "replay failed" || s2.Recovered[0].Op != out.Op || s2.Recovered[0].Detail == "" {
		t.Fatal(s2.Recovered)
	}
	if b := s2.Blocked(); len(b) != 1 || b[0].Op != out.Op {
		t.Fatal(b)
	}
	sts, err := s2.Statements()
	if err != nil || sts[id0] != nil || sts[id1] != nil {
		t.Fatalf("a half-installed operation is visible: %v %v", len(sts), err)
	}
	if st, _ := s2.Status(); len(st) != 1 || st[0].What != "committed, pending install" {
		t.Fatal(st)
	}
	if r, err := s2.Fsck(FsckOptions{}); err != nil || len(r.Of(FsckJournal)) != 1 || r.Clean() ||
		!strings.Contains(r.Of(FsckJournal)[0].Detail, "replay failed when this store was opened") {
		t.Fatal(r.Render(), err)
	}
	// a writer for the blocked key is refused, naming the operation; nothing is written
	l2, _ := authored(k, 2, id1, data)
	before := snapshot(t, root)
	_, err = s2.Commit("publish", [][]byte{l2}, nil)
	refusedAs(t, err, refusal.Operational, ErrReplayFailed, out.Op)
	if refusedAs(t, s2.BlockedFor(k.Signer()), refusal.Operational, ErrReplayFailed, out.Op); s2.BlockedFor(other.Signer()) != nil {
		t.Fatal("another key is blocked")
	}
	if !equalMaps(before, snapshot(t, root)) {
		t.Fatal("a refused writer changed the store")
	}
	// another key writes normally
	lo, ido := authored(other, 0, "", []byte("other"))
	if _, err := s2.Commit("publish", [][]byte{lo}, nil); err != nil {
		t.Fatal(err)
	}
	if sts, _ := s2.Statements(); sts[ido] == nil {
		t.Fatal("another key's statement not visible")
	}
	// Repair with the cause still there: reported, not fatal, the record kept
	if evs, err := s2.Repair(); err != nil || len(evs) != 1 || evs[0].What != "replay failed" {
		t.Fatal(evs, err)
	}
	// fixed: Repair finishes it, the statements appear, the key writes again
	os.Chmod(dir, 0o755)
	if evs, err := s2.Repair(); err != nil || len(evs) != 1 || evs[0].What != "replayed" {
		t.Fatal(evs, err)
	}
	if sts, _ := s2.Statements(); sts[id0] == nil || sts[id1] == nil {
		t.Fatal("statements not visible after the replay")
	}
	if len(s2.Blocked()) != 0 || s2.BlockedFor(k.Signer()) != nil {
		t.Fatal("still blocked")
	}
	if _, err := s2.Commit("publish", [][]byte{l2}, nil); err != nil {
		t.Fatal(err)
	}
}

// TestRepairContinues: Repair runs every named record, continues past one that fails, and reports each; a
// well-formed id no record has is "nothing to repair"; a malformed id is refused before anything runs; nothing in
// quarantine/ is touched.
func TestRepairContinues(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions; the fault cannot be injected")
	}
	root := t.TempDir()
	ka, kb := testKey("A"), testKey("B")
	la, ida := authored(ka, 0, "", []byte("a"))
	lb, idb := authored(kb, 0, "", []byte("b"))
	// both keys get a statement directory, then two pending records are left behind
	s := open(t, root, Options{NoSync: true, crash: func(p string) error {
		if p == AfterRecord {
			return ErrCrash
		}
		return nil
	}})
	for _, x := range []struct {
		l    []byte
		data string
	}{{la, "a"}, {lb, "b"}} {
		d, _, _ := s.InstallBlob(strings.NewReader(x.data), "")
		if _, err := s.Commit("publish", [][]byte{x.l}, []Digest{d}); !errors.Is(err, ErrCrash) {
			t.Fatal(err)
		}
	}
	os.MkdirAll(filepath.Join(root, "statements", signerDir(ka.Signer())), 0o755)
	os.MkdirAll(filepath.Join(root, "statements", signerDir(kb.Signer())), 0o755)
	dirA := filepath.Join(root, "statements", signerDir(ka.Signer()))
	os.Chmod(dirA, 0o500)
	t.Cleanup(func() { os.Chmod(dirA, 0o755) })
	os.WriteFile(filepath.Join(root, "quarantine", "record-x.json-0"), []byte("kept as evidence"), 0o444)
	q0 := snapshot(t, filepath.Join(root, "quarantine"))

	s2, err := Open(root, Options{NoSync: true}) // A's record fails, B's is replayed
	if err != nil {
		t.Fatal(err)
	}
	if sts, _ := s2.Statements(); sts[idb] == nil || sts[ida] != nil {
		t.Fatal("B should be installed and A hidden")
	}
	var opA string
	for _, e := range s2.Recovered {
		if e.What == "replay failed" {
			opA = e.Op
		}
	}
	unknown := strings.Repeat("ab", 32)
	evs, err := s2.Repair(opA, unknown)
	if err != nil || len(evs) != 2 || evs[0].Op != opA || evs[0].What != "replay failed" || evs[1].Op != unknown || evs[1].What != "nothing to repair" {
		t.Fatal(evs, err)
	}
	if _, err := s2.Repair("not-an-op"); err == nil {
		t.Fatal("a malformed id was accepted")
	}
	os.Chmod(dirA, 0o755)
	if evs, err := s2.Repair(); err != nil || len(evs) != 1 || evs[0].What != "replayed" {
		t.Fatal(evs, err)
	}
	if !equalMaps(q0, snapshot(t, filepath.Join(root, "quarantine"))) {
		t.Fatal("Repair touched quarantine/")
	}
}

// TestDegradedOpenInstalled: a replay that installs every statement and then fails (journal/done not writable, so
// step 4 cannot run) is reported "replay failed", but nothing is half shown: the statements stay visible and the
// key keeps writing.
func TestDegradedOpenInstalled(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions; the fault cannot be injected")
	}
	root := t.TempDir()
	k := testKey("A")
	l0, id0 := authored(k, 0, "", []byte("x"))
	s := open(t, root, Options{NoSync: true, crash: func(p string) error {
		if p == AfterRecord {
			return ErrCrash
		}
		return nil
	}})
	d, _, _ := s.InstallBlob(strings.NewReader("x"), "")
	if _, err := s.Commit("publish", [][]byte{l0}, []Digest{d}); !errors.Is(err, ErrCrash) {
		t.Fatal(err)
	}
	done := filepath.Join(root, "journal", "done")
	os.Chmod(done, 0o500)
	t.Cleanup(func() { os.Chmod(done, 0o755) })
	s2, err := Open(root, Options{NoSync: true})
	if err != nil || len(s2.Blocked()) != 1 {
		t.Fatal(s2, err)
	}
	if sts, _ := s2.Statements(); sts[id0] == nil {
		t.Fatal("an installed statement was hidden")
	}
	if s2.BlockedFor(k.Signer()) != nil {
		t.Fatal("a key whose statements are all installed was refused")
	}
}

// TestReaderSkipsPendingRecord: a reader that takes no lock, running while another writer is between step 2 and
// step 4 (some statements installed, its record still in pending/), sees none of that operation: never the
// authored statement without its holds. The writer here stops after its first statement; the reader is a second
// handle on the same store that did not replay (it opened before the record existed).
func TestReaderSkipsPendingRecord(t *testing.T) {
	root := t.TempDir()
	k := testKey("A")
	data := []byte("mid-install")
	l0, id0 := authored(k, 0, "", data)
	l1, id1 := authored(k, 1, id0, data)
	reader := open(t, root, Options{NoSync: true})
	writer := open(t, root, Options{NoSync: true, crash: func(p string) error {
		if p == AfterStatement {
			return ErrCrash
		}
		return nil
	}})
	d, _, _ := writer.InstallBlob(bytes.NewReader(data), "")
	if _, err := writer.Commit("publish", [][]byte{l0, l1}, []Digest{d}); !errors.Is(err, ErrCrash) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "statements", signerDir(k.Signer()), id0)); err != nil {
		t.Fatal("setup: the first statement should be installed")
	}
	sts, err := reader.Statements()
	if err != nil || sts[id0] != nil || sts[id1] != nil {
		t.Fatalf("a reader sees a half-installed operation: %d %v", len(sts), err)
	}
	// a done record seen in part (one statement file missing, as when the walk passed before it landed): the
	// reader shows neither, never one line of the operation without the other
	root2 := t.TempDir()
	reader2 := open(t, root2, Options{NoSync: true})
	w2 := open(t, root2, Options{NoSync: true, crash: func(p string) error {
		if p == AfterDone {
			return ErrCrash
		}
		return nil
	}})
	d2, _, _ := w2.InstallBlob(bytes.NewReader(data), "")
	if _, err := w2.Commit("publish", [][]byte{l0, l1}, []Digest{d2}); !errors.Is(err, ErrCrash) {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(root2, "statements", signerDir(k.Signer()), id1))
	if sts, _ := reader2.Statements(); sts[id0] != nil || sts[id1] != nil {
		t.Fatal("a reader sees part of a done record's operation")
	}
	// once the writer finishes (here: the next open replays it), both appear together
	if sts, _ := open(t, root, Options{NoSync: true}).Statements(); sts[id0] == nil || sts[id1] == nil {
		t.Fatal("not visible after the install finished")
	}
	if sts, _ := reader.Statements(); sts[id0] == nil || sts[id1] == nil {
		t.Fatal("the reader does not see the finished operation")
	}
}
