package store

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/conformance"
)

// TestFsckClasses: §6.3. Each class is reported separately, an intact store reports none of the fatal ones and
// says what it scanned, and fsck changes nothing authoritative.
func TestFsckClasses(t *testing.T) {
	conformance.Partial(t, "C-core-123", "fsck names a corrupt copy (hashes to …) and --quarantine moves it; fetch re-fetches (TestFetchCorruptLocalCopy); run refusing needs the runner")
	conformance.Partial(t, "C-core-125", "status/fsck list pending and done records and the missing-blob state (committed, needs repair: blob … missing); the publish-level steps remain a later layer")
	conformance.Partial(t, "C-core-126", "a committed operation whose blob went missing is reported committed, needs repair and repair does not invent it; the index projection remains a later layer")
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	k := testKey("A")
	d, id0 := publishBlob(t, s, k, 0, "", []byte("dataset bytes"))
	orphan, _, _ := s.InstallBlob(strings.NewReader("nobody names me"), "")

	r, err := s.Fsck(FsckOptions{})
	if err != nil || !r.Clean() || r.Blobs != 2 || r.Statements != 1 || r.Records != 0 {
		t.Fatal(r.Render(), err)
	}
	if got := r.Of(FsckUnreferenced); len(got) != 1 || got[0].Object != string(orphan) || got[0].Fatal {
		t.Fatalf("unreferenced storage: %v", got)
	}
	if !strings.Contains(r.Render(), "scanned 2 blob(s), 1 statement(s), 0 journal record(s): no errors found") {
		t.Fatal(r.Render())
	}
	snap := snapshot(t, root)

	// Corrupt a blob keeping its name (C-core-123).
	p := s.blobPath(d)
	_ = os.Chmod(p, 0o644)
	_ = os.WriteFile(p, []byte("evil"), 0o644)
	r, _ = s.Fsck(FsckOptions{})
	got := r.Of(FsckCorruptBlob)
	if r.Clean() || len(got) != 1 || got[0].Object != string(d) || !strings.Contains(got[0].Detail, "hashes to "+string(digestOf([]byte("evil")))) {
		t.Fatal(r.Render())
	}
	// Read-only without --quarantine: nothing moved.
	if _, err := os.Stat(p); err != nil {
		t.Fatal("fsck without --quarantine moved a blob")
	}
	r, _ = s.Fsck(FsckOptions{Quarantine: true})
	if len(r.Quarantined) != 1 || s.HasBlob(d) {
		t.Fatal(r.Render())
	}
	if qs, _ := filepath.Glob(filepath.Join(root, "quarantine", "blob-*")); len(qs) != 1 {
		t.Fatal("not quarantined, or deleted")
	}
	// Now the statement's blob is missing: committed, needs repair (§6.1.1 residual case, as availability).
	r, _ = s.Fsck(FsckOptions{})
	if m := r.Of(FsckMissingBlob); len(m) != 1 || m[0].Object != string(d) || m[0].Fatal || !strings.Contains(m[0].Detail, "unavailable (not held locally)") {
		t.Fatalf("a referenced-but-absent blob must read unavailable, not corrupt: %s", r.Render())
	}
	_ = snap
	_ = id0
}

// TestFsckInvalidStatementAndJournal: invalid authentication, a statement under the wrong name or signer,
// unresolved predecessor, an orphan done record, a pending record, a record that does not decode, stale
// temporaries, strays; each its own class.
func TestFsckInvalidStatementAndJournal(t *testing.T) {
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	k := testKey("A")
	d, id0 := publishBlob(t, s, k, 0, "", []byte("x"))
	l2, id2 := authored(k, 2, strings.Repeat("e", 64), []byte("x")) // predecessor never held
	if _, err := s.Commit("publish", [][]byte{l2}, []Digest{d}); err != nil {
		t.Fatal(err)
	}
	// tampered statement file
	good, _ := authored(testKey("B"), 0, "", []byte("y"))
	bad := bytes.Replace(good, []byte("2026-10-15T00:00:00Z"), []byte("2026-10-16T00:00:00Z"), 1)
	badID := strings.Repeat("c", 64)
	dir := filepath.Join(root, "statements", "ed25519-b")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, badID), bad, 0o444)
	// a verified statement stored under the wrong name
	_ = os.WriteFile(filepath.Join(dir, strings.Repeat("d", 64)), good, 0o444)
	// stray in blobs, stale temp, odd retained
	_ = os.WriteFile(filepath.Join(root, "blobs", "sha256", "README"), []byte("hi"), 0o644)
	old := filepath.Join(root, "tmp", "w-old")
	_ = os.WriteFile(old, []byte("partial"), 0o644)
	past := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(old, past, past)
	_ = os.WriteFile(filepath.Join(root, "retained", "notahash"), []byte("x"), 0o644)
	// pending record, done orphan, undecodable record
	w := &Store{root: root, opt: Options{NoSync: true, crash: func(p string) error {
		if p == AfterRecord {
			return ErrCrash
		}
		return nil
	}}}
	lp, _ := authored(k, 3, id2, []byte("x"))
	if out, _ := w.Commit("publish", [][]byte{lp}, []Digest{d}); !out.Committed {
		t.Fatal(out)
	}
	_ = os.WriteFile(filepath.Join(root, "journal", "pending", "junk.json"), []byte("{"), 0o644)
	// orphan done record: move the pending record to done and delete its statement (not installed yet anyway)
	pend, _ := filepath.Glob(filepath.Join(root, "journal", "pending", "*.json"))
	for _, f := range pend {
		if filepath.Base(f) != "junk.json" {
			_ = os.Rename(f, filepath.Join(root, "journal", "done", filepath.Base(f)))
		}
	}

	r, err := s.Fsck(FsckOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Clean() {
		t.Fatal(r.Render())
	}
	for class, n := range map[string]int{FsckBadStatement: 2, FsckStray: 2, FsckStaleTmp: 1, FsckMissingStmt: 1, FsckJournal: 2} {
		if got := r.Of(class); len(got) != n {
			t.Errorf("%s: %d findings, want %d:\n%s", class, len(got), n, r.Render())
		}
	}
	text := r.Render()
	for _, want := range []string{"bad signature", "stored under another name", "names predecessor " + strings.Repeat("e", 64), "orphan done record", "does not decode", "tmp/w-old"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	// Reading never repaired anything: the bad file and the junk record are still there.
	if _, err := os.Stat(filepath.Join(dir, badID)); err != nil {
		t.Fatal("fsck removed a statement file")
	}
	if _, err := os.Stat(filepath.Join(root, "journal", "pending", "junk.json")); err != nil {
		t.Fatal("fsck touched the journal")
	}
	_ = id0
}

// TestFsckMissingBlobInRecord: the residual case of §6.1.1. gc removes a blob between the check before step 2
// and step 5: the commit reports `committed, needs repair: blob <hash> missing`, nothing is rolled back,
// fsck lists the unresolved reference, and re-installing the bytes plus repair finishes it.
func TestFsckMissingBlobInRecord(t *testing.T) {
	conformance.Covers(t, "C-core-138") // the store half; the publish command is internal/cli.TestPublishCommittedPendingInstall
	root := t.TempDir()
	k := testKey("A")
	data := []byte("removed mid-publish")
	l, id := authored(k, 0, "", data)
	var s *Store
	s = open(t, root, Options{NoSync: true, crash: func(p string) error {
		if p == AfterInstall { // after step 2, before step 4: gc strikes
			_ = os.Remove(s.blobPath(digestOf(data)))
		}
		return nil
	}})
	d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
	out, err := s.Commit("publish", [][]byte{l}, []Digest{d})
	if err != nil || out.NeedsRepair == nil || !strings.Contains(out.NeedsRepair.Error(), "committed, needs repair: blob "+string(d)+" missing") {
		t.Fatalf("%v %v", out.NeedsRepair, err)
	}
	if sts, _ := s.Statements(); sts[id] == nil {
		t.Fatal("the committed statement was rolled back")
	}
	r, _ := s.Fsck(FsckOptions{})
	m := r.Of(FsckMissingBlob)
	if len(m) == 0 || !strings.Contains(m[0].Detail, "committed, needs repair: blob "+string(d)+" missing") || !m[0].Fatal || r.Clean() {
		t.Fatalf("%s", r.Render())
	}
	// Status says the operation is committed, needs repair; Repair without the bytes keeps saying so.
	if st, _ := s.Status(); len(st) != 1 || st[0].What != "committed, needs repair" {
		t.Fatal(st)
	}
	ev, _ := s.Repair()
	if len(ev) != 1 || ev[0].What != "needs repair" || !strings.Contains(ev[0].Detail, "missing") {
		t.Fatal(ev)
	}
	// Re-install the bytes: repair finishes, fsck is clean.
	if _, _, err := s.InstallBlob(bytes.NewReader(data), d); err != nil {
		t.Fatal(err)
	}
	ev, _ = s.Repair()
	if len(ev) != 1 || ev[0].What != "projected" {
		t.Fatal(ev)
	}
	if st, _ := s.Status(); len(st) != 0 {
		t.Fatal(st)
	}
	if r, _ := s.Fsck(FsckOptions{}); !r.Clean() || len(r.Of(FsckMissingBlob)) != 0 {
		t.Fatal(r.Render())
	}
}

// TestFsckRebuildUnknown: --rebuild with no cache or an unknown name is an error, not a silent pass.
func TestFsckRebuildUnknown(t *testing.T) {
	s := open(t, t.TempDir(), Options{NoSync: true})
	if _, err := s.Fsck(FsckOptions{Rebuild: []string{"x"}}); err == nil {
		t.Fatal("rebuild without a cache")
	}
	if _, err := s.Fsck(FsckOptions{Cache: NewCache(s), Rebuild: []string{"nope"}}); err == nil {
		t.Fatal("unknown projection")
	}
}
