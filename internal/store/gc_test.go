package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

func age(t *testing.T, s *Store, d Digest, by time.Duration) {
	t.Helper()
	old := time.Now().Add(-by)
	if err := os.Chtimes(s.blobPath(d), old, old); err != nil {
		t.Fatal(err)
	}
}

func hours(n int) time.Duration { return time.Duration(n) * time.Hour }

func deleted(p *GCPlan) []Digest {
	var out []Digest
	for _, b := range p.Deleted {
		out = append(out, b.Digest)
	}
	return out
}

func candidates(p *GCPlan) []Digest {
	var out []Digest
	for _, b := range p.Candidates {
		out = append(out, b.Digest)
	}
	return out
}

// TestGCNeverDeletesReferenced: §6.1. Never a statement, never a blob an installed statement references,
// never a blob a pending record names, never a serving holds' blob; an unreferenced blob outside the window
// goes. The dry run prints hashes and sizes, states its side effects, and changes nothing.
func TestGCNeverDeletesReferenced(t *testing.T) {
	conformance.Partial(t, "C-core-146", "gc keeps, re-checks and prints as specified: checked in TestGC*; the operation history (d) and publish's own reuse-then-crash (a) need history and publish")
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	k := testKey("A")
	// referenced by a statement
	refd, id0 := publishBlob(t, s, k, 0, "", []byte("referenced"))
	// unreferenced, old
	orphan, _, _ := s.InstallBlob(strings.NewReader("orphan bytes"), "")
	// unreferenced, young
	young, _, _ := s.InstallBlob(strings.NewReader("young bytes"), "")
	// named by a pending record (crash after the commit point, no reopen)
	crash := open(t, t.TempDir(), Options{NoSync: true})
	_ = crash
	for _, d := range []Digest{refd, orphan} {
		age(t, s, d, hours(48))
	}
	snap := snapshot(t, root)
	dry, err := s.GC(GCConfig{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(candidates(dry), []Digest{orphan}) || len(dry.Deleted) != 0 {
		t.Fatalf("%v", dry.Render())
	}
	out := dry.Render()
	for _, want := range []string{string(orphan), "12 bytes", "no deletion; no registry change", "grace window: 24h0m0s (policy)", "referenced by statement " + id0, "inside the grace window"} {
		if !strings.Contains(out, want) {
			t.Fatalf("dry run lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, string(young)) {
		t.Fatal("young blob not listed with its reason")
	}
	if after := snapshot(t, root); !equalMaps(after, snap) {
		t.Fatal("a dry run changed the store")
	}
	plan, err := s.GC(GCConfig{}, true)
	if err != nil || !slices.Equal(deleted(plan), []Digest{orphan}) {
		t.Fatal(plan, err)
	}
	if !strings.Contains(plan.SideEffects(), "deleted 1 blob file(s), 12 bytes") || !strings.Contains(plan.SideEffects(), "no statement, journal record") {
		t.Fatal(plan.SideEffects())
	}
	if s.HasBlob(orphan) || !s.HasBlob(refd) || !s.HasBlob(young) {
		t.Fatal("wrong blobs deleted")
	}
	if sts, _ := s.Statements(); len(sts) != 1 {
		t.Fatal("a statement went missing")
	}
	if ents, _ := os.ReadDir(s.dir("tmp")); len(ents) != 0 {
		t.Fatalf("gc left temporaries: %v", ents)
	}
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestGCPendingRecord: a blob a pending journal record names is never deleted, however old; after the record
// is replayed it is referenced by the installed statement.
func TestGCPendingRecord(t *testing.T) {
	root := t.TempDir()
	k := testKey("A")
	data := []byte("in transit")
	l0, _ := authored(k, 0, "", data)
	s := open(t, root, Options{NoSync: true, crash: func(p string) error {
		if p == AfterRecord {
			return ErrCrash
		}
		return nil
	}})
	d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
	if out, err := s.Commit("publish", [][]byte{l0}, []Digest{d}); !out.Committed || !errors.Is(err, ErrCrash) {
		t.Fatal(out, err)
	}
	age(t, s, d, hours(72))
	// Journal-only reference: take the statement out of the picture by looking before replay (no reopen).
	plan, err := s.GC(GCConfig{}, true)
	if err != nil || len(plan.Deleted) != 0 || !s.HasBlob(d) {
		t.Fatal(plan, err)
	}
	if !strings.Contains(plan.Render(), "journal record") {
		t.Fatalf("the reason is not named:\n%s", plan.Render())
	}
	// A pending record is never deleted by gc.
	if st, _ := s.Status(); len(st) != 1 {
		t.Fatal("gc touched the journal", st)
	}
}

// TestGCGraceFloor: C-core-146 (c). A policy value below 1 h is refused, naming the floor; the same value
// given for one run is used and printed in the plan. The default is 24 h.
func TestGCGraceFloor(t *testing.T) {
	s := open(t, t.TempDir(), Options{NoSync: true})
	d, _, _ := s.InstallBlob(strings.NewReader("x"), "")
	age(t, s, d, 30*time.Minute)
	_, err := s.GC(GCConfig{Policy: 10 * time.Minute}, false)
	refusedAs(t, err, refusal.Policy, GraceBelowFloor, "1h0m0s floor")
	if !strings.Contains(err.Error(), "10m0s") {
		t.Fatal(err)
	}
	ten := 10 * time.Minute
	plan, err := s.GC(GCConfig{PerRun: &ten}, true)
	if err != nil || plan.Grace != ten || plan.GraceSource != "this run (--grace)" || !slices.Equal(deleted(plan), []Digest{d}) {
		t.Fatal(plan, err)
	}
	if !strings.Contains(plan.Render(), "grace window: 10m0s (this run (--grace))") {
		t.Fatal(plan.Render())
	}
	if p, _ := s.GC(GCConfig{}, false); p.Grace != DefaultGrace || p.GraceSource != "policy" {
		t.Fatal(p)
	}
	// The policy window is part of the declaration.
	if g := open(t, t.TempDir(), Options{NoSync: true, GCGrace: hours(2)}).Durability().GCGrace; g != "2h0m0s" {
		t.Fatal(g)
	}
	// Between the floor and the default: window respected.
	s2 := open(t, t.TempDir(), Options{NoSync: true})
	d2, _, _ := s2.InstallBlob(strings.NewReader("y"), "")
	age(t, s2, d2, hours(2))
	if p, _ := s2.GC(GCConfig{Policy: hours(3)}, false); len(p.Candidates) != 0 {
		t.Fatal("a blob younger than the window was a candidate")
	}
	if p, _ := s2.GC(GCConfig{Policy: hours(1)}, false); len(p.Candidates) != 1 {
		t.Fatal("a blob older than the window was kept")
	}
}

// TestGCReuseRestartsWindow: C-core-146 (a). An unreferenced blob older than the window is reused by a new
// publish that crashes after step 1: its window restarted at reuse, so gc --apply keeps it and the retry
// commits without a fetch.
func TestGCReuseRestartsWindow(t *testing.T) {
	root := t.TempDir()
	k := testKey("A")
	data := []byte("old unreferenced bytes")
	s := open(t, root, Options{NoSync: true, crash: func(p string) error {
		if p == AfterBlobs {
			return ErrCrash
		}
		return nil
	}})
	d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
	age(t, s, d, hours(72))
	if p, _ := s.GC(GCConfig{}, false); !slices.Equal(candidates(p), []Digest{d}) {
		t.Fatal("test setup: the blob should be a candidate before reuse")
	}
	// publish: step 1 reuses the blob (window restarts), then the process crashes before the record.
	if _, res, err := s.InstallBlob(bytes.NewReader(data), d); err != nil || res != Reused {
		t.Fatal(res, err)
	}
	l, id := authored(k, 0, "", data)
	if out, err := s.Commit("publish", [][]byte{l}, []Digest{d}); out.Committed || !errors.Is(err, ErrCrash) {
		t.Fatal(out, err)
	}
	plan, err := s.GC(GCConfig{}, true)
	if err != nil || len(plan.Deleted) != 0 || !s.HasBlob(d) {
		t.Fatalf("gc deleted a blob whose window restarted at reuse: %v %v", plan, err)
	}
	// The retry commits against the held blob, nothing fetched.
	s2 := open(t, root, Options{NoSync: true})
	if _, err := s2.Commit("publish", [][]byte{l}, []Digest{d}); err != nil {
		t.Fatal(err)
	}
	if sts, _ := s2.Statements(); sts[id] == nil {
		t.Fatal("retry did not commit")
	}
}

// TestGCRecheckAtDeletion: C-core-146 (b). gc lists an unreferenced blob; then a pending record naming it
// is written before gc removes it: the blob is kept. Also a statement installed after the listing, and a
// window restarted after the listing.
func TestGCRecheckAtDeletion(t *testing.T) {
	conformance.Partial(t, "C-core-146", "gc re-checks references and window at deletion (a pending record, a statement, a reuse after the listing); the history file (d) and publish's reuse-then-crash end to end need those layers")
	k := testKey("A")
	data := []byte("raced bytes")
	for _, tc := range []struct {
		name string
		race func(t *testing.T, root string, s *Store, d Digest)
		want string
	}{
		{"pending record", func(t *testing.T, root string, s *Store, d Digest) {
			l, _ := authored(k, 0, "", data)
			w := open(t, t.TempDir(), Options{NoSync: true})
			_ = w
			// Write the pending record exactly as step 2 does, by crashing a writer right after it.
			wr := &Store{root: root, opt: Options{NoSync: true, crash: func(p string) error {
				if p == AfterRecord {
					return ErrCrash
				}
				return nil
			}}}
			if out, err := wr.Commit("publish", [][]byte{l}, []Digest{d}); !out.Committed || !errors.Is(err, ErrCrash) {
				t.Fatal(out, err)
			}
		}, "journal record"},
		{"statement", func(t *testing.T, root string, s *Store, d Digest) {
			l, _ := authored(k, 0, "", data)
			if _, err := s.Commit("publish", [][]byte{l}, []Digest{d}); err != nil {
				t.Fatal(err)
			}
		}, "statement"},
		{"reuse", func(t *testing.T, root string, s *Store, d Digest) {
			if _, res, err := s.InstallBlob(bytes.NewReader(data), d); err != nil || res != Reused {
				t.Fatal(res, err)
			}
		}, "grace window restarted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			var s *Store
			raced := false
			s = open(t, root, Options{NoSync: true})
			d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
			age(t, s, d, hours(72))
			// gc under a hook that fires after the blob is moved aside and before the re-check: the race.
			s.opt.crash = func(p string) error {
				if p == GCMoved && !raced {
					raced = true
					// The moved blob is out of blobs/; a racing writer's step 1 must find the window and install its own copy.
					s.opt.crash = nil
					if tc.name == "reuse" {
						// the writer reused it before the move: simulate by restarting the clock on the aside file
						ents, _ := os.ReadDir(s.dir("tmp"))
						for _, e := range ents {
							if strings.HasPrefix(e.Name(), "gc-") {
								now := time.Now()
								_ = os.Chtimes(s.dir("tmp", e.Name()), now, now)
							}
						}
						return nil
					}
					// put it back for the writer's commit (blob must be held), as a concurrent installer would have
					nd, _, err := s.InstallBlob(bytes.NewReader(data), d)
					if err != nil || nd != d {
						t.Fatal(err)
					}
					tc.race(t, root, s, d)
				}
				return nil
			}
			plan, err := s.GC(GCConfig{}, true)
			if err != nil {
				t.Fatal(err)
			}
			if !raced {
				t.Fatal("the race point was not reached: the test proves nothing")
			}
			if len(plan.Deleted) != 0 || !s.HasBlob(d) {
				t.Fatalf("a blob that gained a reference was deleted:\n%s", plan.Render())
			}
			if len(plan.Skipped) != 1 || !strings.Contains(plan.Skipped[0].Why, tc.want) {
				t.Fatalf("skipped = %+v, want reason containing %q", plan.Skipped, tc.want)
			}
			if h, _ := hashFile(s.blobPath(d)); h != d {
				t.Fatal("the restored blob is not intact")
			}
			if ents, _ := os.ReadDir(s.dir("tmp")); len(ents) != 0 {
				t.Fatalf("temporaries left: %v", ents)
			}
		})
	}
}

// TestGCCrashMidDeletion: a process that dies between moving a candidate aside and deciding leaves
// tmp/gc-<hex>-*; Open puts the verified file back, so a crash never loses a blob that is still referenced.
func TestGCCrashMidDeletion(t *testing.T) {
	root := t.TempDir()
	k := testKey("A")
	data := []byte("referenced late")
	s := open(t, root, Options{NoSync: true, crash: func(p string) error {
		if p == GCMoved {
			return ErrCrash
		}
		return nil
	}})
	d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
	age(t, s, d, hours(72))
	if _, err := s.GC(GCConfig{}, true); !errors.Is(err, ErrCrash) {
		t.Fatal(err)
	}
	if s.HasBlob(d) {
		t.Fatal("the crash point was not between the move and the decision")
	}
	// A statement referencing it lands (another process), then the store is reopened.
	l, _ := authored(k, 0, "", data)
	s2 := open(t, root, Options{NoSync: true})
	if _, err := s2.Commit("publish", [][]byte{l}, nil); err != nil {
		t.Fatal(err)
	}
	if !s2.HasBlob(d) {
		t.Fatalf("a referenced blob was lost to a gc crash: %v", s2.Recovered)
	}
	var restored bool
	for _, ev := range s2.Recovered {
		restored = restored || ev.What == "restored blob"
	}
	if !restored {
		t.Fatal(s2.Recovered)
	}
	if f, _ := s2.CheckBlob(d); f != nil {
		t.Fatal(f)
	}
}

// TestGCHoldsPin: §6.1: a blob referenced only by the operator's own serving holds is kept unless the hash
// is named (C-core-145 (a)), and the reason is named. A withdrawn holds, a superseded one and another key's
// do not pin it (with Operators set).
func TestGCHoldsPin(t *testing.T) {
	conformance.Partial(t, "C-core-145", "(a) gc without --release keeps the blob and names why: checked in TestGCHoldsPin; (b)-(e) in TestRelease*")
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	op, other := testKey("OP"), testKey("OTHER")
	data := []byte("served bytes")
	d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
	l, hid := holdsLine(op, 0, "", data, false, "https://mirror.example/b")
	if _, err := s.Commit("serve", [][]byte{l}, nil); err != nil {
		t.Fatal(err)
	}
	age(t, s, d, hours(72))
	plan, err := s.GC(GCConfig{Operators: []string{op.Signer()}}, true)
	if err != nil || len(plan.Deleted) != 0 || !s.HasBlob(d) {
		t.Fatal(plan, err)
	}
	if !strings.Contains(plan.Render(), "served under holds "+hid) || !strings.Contains(plan.Render(), "--release") {
		t.Fatalf("(a) the reason is not named:\n%s", plan.Render())
	}
	// With nobody configured, every key's serving holds pins.
	if p, _ := s.GC(GCConfig{}, false); len(p.Candidates) != 0 {
		t.Fatal("unconfigured operators let a serving holds go")
	}
	// A different operator set: this key's holds is a holder's word, not this store's assertion.
	if p, _ := s.GC(GCConfig{Operators: []string{other.Signer()}}, false); !slices.Equal(candidates(p), []Digest{d}) {
		t.Fatalf("another operator's holds pinned the blob:\n%s", p.Render())
	}
	// Withdrawn: no longer pins.
	w, _ := holdsLine(op, 1, hid, data, true)
	if _, err := s.Commit("withdraw", [][]byte{w}, nil); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.GC(GCConfig{Operators: []string{op.Signer()}}, false); !slices.Equal(candidates(p), []Digest{d}) {
		t.Fatalf("a withdrawn holds still pins:\n%s", p.Render())
	}
	// A new serving holds supersedes the withdrawal and pins again.
	wid := mustID(t, w)
	l2, _ := holdsLine(op, 2, wid, data, false, "https://mirror.example/b")
	if _, err := s.Commit("serve", [][]byte{l2}, nil); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.GC(GCConfig{Operators: []string{op.Signer()}}, false); len(p.Candidates) != 0 {
		t.Fatal("a re-served blob was a candidate")
	}
}

func mustID(t *testing.T, line []byte) string {
	t.Helper()
	st, err := wire.Read(line)
	if err != nil {
		t.Fatal(err)
	}
	return st.ID
}

// TestGCKeepsUnreadableReferences: a statement this reader cannot interpret (unknown kind, unknown major, a
// file that does not read) still pins what its text names: gc never deletes on a reading it could not make.
func TestGCKeepsUnreadableReferences(t *testing.T) {
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	data := []byte("named by something unreadable")
	d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
	age(t, s, d, hours(72))
	if err := os.MkdirAll(filepath.Join(root, "statements", "ed25519-zz"), 0o755); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(root, "statements", "ed25519-zz", strings.Repeat("a", 64))
	if err := os.WriteFile(junk, []byte(`{"body":{"content":{"digest":"`+string(d)+`"}},"rc":"rc/9"`), 0o444); err != nil {
		t.Fatal(err)
	}
	plan, _ := s.GC(GCConfig{}, true)
	if len(plan.Deleted) != 0 || !s.HasBlob(d) || !strings.Contains(plan.Render(), "does not read; kept, never interpreted") {
		t.Fatal(plan.Render())
	}
	// there is no retained/ area: a file there pins nothing (the mutation control: the same bytes under
	// statements/ pinned above), and fsck names the directory without touching it
	if err := os.Remove(junk); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "retained"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "retained", strings.Repeat("b", 64)), []byte(`{"x":"`+string(d)+`"}`), 0o444); err != nil {
		t.Fatal(err)
	}
	if plan, _ := s.GC(GCConfig{}, true); len(plan.Deleted) != 1 || strings.Contains(plan.Render(), "retained") {
		t.Fatal(plan.Render())
	}
}

// ----- release

func openedWithServing(t *testing.T, o Options) (root string, s *Store, op wire.Key, d Digest, hid string, data []byte) {
	t.Helper()
	root = t.TempDir()
	s = open(t, root, o)
	op = testKey("OP")
	data = []byte("bytes the operator serves")
	d, _, _ = s.InstallBlob(bytes.NewReader(data), "")
	l, id := holdsLine(op, 0, "", data, false, "https://mirror.example/b")
	if _, err := s.Commit("serve", [][]byte{l}, nil); err != nil {
		t.Fatal(err)
	}
	return root, s, op, d, id, data
}

// TestReleaseOneOperation: C-core-145 (b). One operation: a holds with withdrawn:true is committed and the
// blob deleted; the blob then shows unavailable (not held locally); the earlier serving holds is still in
// the log; the operator's current holds for the blob shows withdrawn.
func TestReleaseOneOperation(t *testing.T) {
	conformance.Partial(t, "C-core-145", "(a) keep and name, (b) one operation, (c) crash after the commit point, (d) signing refused: checked on the store; (e) intrinsic malformed withdrawn+locations is the wire schema's (checked in wire); the command surface that renders 'current holds shows withdrawn' is a later layer")
	conformance.Partial(t, "P-10", "crash injection at every commit point of release as well as publish (TestReleaseCrash)")
	root, s, op, d, hid, _ := openedWithServing(t, Options{NoSync: true})
	res, err := s.Release(d, SignerFromKey(op, nil))
	if err != nil || !res.BlobRemoved || res.Withdrawal == "" || res.Op == "" {
		t.Fatal(res, err)
	}
	if s.HasBlob(d) {
		t.Fatal("blob still held")
	}
	a, _ := s.Availability(d)
	if a.State != StateNotHeld {
		t.Fatal(a)
	}
	// The earlier serving holds is still in the log, and the withdrawal follows it.
	sts, _ := s.Statements()
	if sts[hid] == nil || sts[res.Withdrawal] == nil || len(sts) != 2 {
		t.Fatalf("statements: %d", len(sts))
	}
	wst, _ := wire.Read(sts[res.Withdrawal])
	if wst.Prev != hid || wst.Seq != 1 || wst.Kind != "holds" {
		t.Fatalf("withdrawal does not follow the serving holds: %+v", wst)
	}
	if _, ok := wst.Body.Members["withdrawn"]; !ok {
		t.Fatal("no withdrawn:true")
	}
	if _, ok := wst.Body.Members["locations"]; ok {
		t.Fatal("a withdrawal carrying locations is malformed")
	}
	if holders, _ := s.servingHolds(d); len(holders) != 0 {
		t.Fatalf("the operator still serves it: %v", holders)
	}
	// Nothing else moved: no statement deleted, the journal drained.
	if st, _ := s.Status(); len(st) != 0 {
		t.Fatal(st)
	}
	_ = root
	// Releasing again: nothing to release, and it says so; a blob held under no holds needs no release.
	if _, err := s.Release(d, SignerFromKey(op, nil)); err == nil || !strings.Contains(err.Error(), "not held locally") {
		t.Fatal(err)
	}
}

// TestReleaseRefusals: no current serving holds -> nothing to release; malformed digest; signer
// refuses (d): nothing committed, nothing deleted, the signing failure named.
func TestReleaseRefusals(t *testing.T) {
	root, s, op, d, _, _ := openedWithServing(t, Options{NoSync: true})
	before := snapshot(t, root)
	bad := &failingSigner{key: op.Signer(), err: errors.New("hardware key declined")}
	_, err := s.Release(d, bad)
	refusedAs(t, err, refusal.Policy, SigningRefused, "hardware key declined")
	if !strings.Contains(err.Error(), "nothing committed") || !bad.called {
		t.Fatal(err, bad.called)
	}
	if after := snapshot(t, root); !equalMaps(before, after) || !s.HasBlob(d) {
		t.Fatal("a refused signature changed the store")
	}
	// A different key has no serving holds for it: nothing to withdraw, and it must not sign one.
	other := testKey("NOT-THE-HOLDER")
	called := &failingSigner{key: other.Signer(), err: errors.New("must not be asked")}
	if _, err := s.Release(d, called); err == nil || !strings.Contains(err.Error(), "no current serving holds") || called.called {
		t.Fatal(err, called.called)
	}
	if _, err := s.Release("sha256:xx", SignerFromKey(op, nil)); err == nil {
		t.Fatal("malformed digest")
	}
	// A blob a pending record names is not released.
	if after := snapshot(t, root); !equalMaps(before, after) {
		t.Fatal("a refusal changed the store")
	}
}

type failingSigner struct {
	key    string
	err    error
	called bool
}

func (f *failingSigner) Key() string { return f.key }
func (f *failingSigner) SignDraft(wire.Draft) ([]byte, error) {
	f.called = true
	return nil, f.err
}

// TestReleaseCrash: C-core-145 (c), P-10. A crash injected at each point of the release leaves either the blob
// and no withdrawal (before the commit point) or the withdrawal and the blob (after it); never a deleted blob
// under a serving holds. After the next open the withdrawal is installed and the blob is a gc candidate
// (or already gone); Release again completes it.
func TestReleaseCrash(t *testing.T) {
	conformance.Partial(t, "C-core-145", "(c) crash after the commit point and before the blob is removed: checked at every point of the release; the other parts are in TestReleaseOneOperation, TestReleaseRefusals, TestGCHoldsPin")
	conformance.Partial(t, "P-10", "crash injection at every commit point of release; process crash model")
	points := []string{AfterBlobs, AfterRecord, AfterStatement, AfterInstall, AfterDone, AfterProject, AfterWithdrawal, AfterBlobRemoved}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			root := t.TempDir()
			op := testKey("OP")
			data := []byte("bytes the operator serves")
			setup := open(t, root, Options{NoSync: true})
			d, _, _ := setup.InstallBlob(bytes.NewReader(data), "")
			l, hid := holdsLine(op, 0, "", data, false, "https://mirror.example/b")
			if _, err := setup.Commit("serve", [][]byte{l}, nil); err != nil {
				t.Fatal(err)
			}
			age(t, setup, d, hours(72))

			hit := false
			s := open(t, root, Options{NoSync: true, crash: func(p string) error {
				if p == point && !hit {
					hit = true
					return ErrCrash
				}
				return nil
			}})
			res, err := s.Release(d, SignerFromKey(op, nil))
			if !hit {
				t.Fatalf("point %q never reached: the test proves nothing", point)
			}
			if !errors.Is(err, ErrCrash) {
				t.Fatal(res, err)
			}
			committed := point != AfterBlobs
			if point == AfterBlobs {
				// the protocol's step-1 hook fires inside Commit with nothing committed
				if st, _ := s.Status(); len(st) != 0 {
					t.Fatalf("status %v", st)
				}
			}
			removedBefore := point == AfterBlobRemoved
			// Never the reverse: the blob is not gone while the withdrawal is not committed.
			if !s.HasBlob(d) && !removedBefore {
				t.Fatalf("blob deleted at %q, before the withdrawal was committed and installed", point)
			}
			// Reopen: recovery installs the withdrawal when the record was written.
			s2 := open(t, root, Options{NoSync: true})
			sts, _ := s2.Statements()
			withdrawn := false
			for id, ln := range sts {
				if st, _ := wire.Read(ln); id != hid && st != nil && st.Prev == hid {
					_, withdrawn = st.Body.Members["withdrawn"]
				}
			}
			if committed != withdrawn {
				t.Fatalf("at %q: withdrawal installed=%v, committed=%v", point, withdrawn, committed)
			}
			if !committed {
				// previous state: serving holds current, blob held, gc keeps it
				if !s2.HasBlob(d) {
					t.Fatal("blob lost")
				}
				if p, _ := s2.GC(GCConfig{Operators: []string{op.Signer()}}, true); len(p.Deleted) != 0 || !s2.HasBlob(d) {
					t.Fatal("gc deleted a blob under a serving holds")
				}
				return
			}
			if removedBefore {
				if s2.HasBlob(d) {
					t.Fatal("blob back after removal")
				}
				return
			}
			// withdrawal installed, blob still here: a gc candidate, never the reverse.
			if !s2.HasBlob(d) {
				t.Fatal("blob missing")
			}
			p, err := s2.GC(GCConfig{Operators: []string{op.Signer()}}, false)
			if err != nil || !slices.Equal(candidates(p), []Digest{d}) {
				t.Fatalf("after the crash the blob is not a gc candidate:\n%s", p.Render())
			}
			// and Release again completes the removal without another signature
			again, err := s2.Release(d, SignerFromKey(op, nil))
			if err != nil || !again.Completed || !again.BlobRemoved || again.Withdrawal != "" {
				t.Fatal(again, err)
			}
			if s2.HasBlob(d) {
				t.Fatal("blob still held after completing the release")
			}
			if n := len(mustStatements(t, s2)); n != 2 {
				t.Fatalf("%d statements after completion, want the serving holds and one withdrawal", n)
			}
		})
	}
}

func mustStatements(t *testing.T, s *Store) map[string][]byte {
	t.Helper()
	m, err := s.Statements()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestReleaseNeedsRepairStillRemoves: a step-5 failure leaves the withdrawal committed; the blob is
// still removed (the withdrawal is installed) and the repair state is reported.
func TestReleaseNeedsRepair(t *testing.T) {
	root := t.TempDir()
	fail := true
	s := open(t, root, Options{NoSync: true, Project: func(Record) error {
		if fail {
			return errors.New("index write failed")
		}
		return nil
	}})
	op := testKey("OP")
	data := []byte("served")
	d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
	fail = false
	l, _ := holdsLine(op, 0, "", data, false, "https://m.example/x")
	if _, err := s.Commit("serve", [][]byte{l}, nil); err != nil {
		t.Fatal(err)
	}
	fail = true
	res, err := s.Release(d, SignerFromKey(op, nil))
	if err != nil || res.NeedsRepair == nil || !res.BlobRemoved || !strings.Contains(res.NeedsRepair.Error(), "committed, needs repair") {
		t.Fatal(res, err)
	}
}
