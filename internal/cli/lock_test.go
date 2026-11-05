package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/store"
)

// Helper protocol: a test run re-executes this binary with lockHelperEnv set; TestWriterLockHelper then acts
// as one writer process (publish n times on the shared store and key) and exits.
const lockHelperEnv = "RC_TEST_LOCK_HELPER"

func TestWriterLockHelper(t *testing.T) {
	spec := os.Getenv(lockHelperEnv)
	if spec == "" {
		t.Skip("helper process only")
	}
	f := strings.Split(spec, "|") // root|keyfile|tag|count|nolock|hold-ms
	n, _ := strconv.Atoi(f[3])
	hold, _ := strconv.Atoi(f[5])
	store.DisableWriterLock = f[4] == "1"
	afterHead = func() { time.Sleep(time.Duration(hold) * time.Millisecond) } // widen the head→commit window
	for i := 0; i < n; i++ {
		c := filepath.Join(filepath.Dir(f[1]), fmt.Sprintf("%s-%d.bin", f[2], i))
		os.WriteFile(c, []byte(fmt.Sprintf("writer %s line %d", f[2], i)), 0o644)
		r := runIn(f[0], nil, "publish", "--key", f[1], "--json", "--kind", "authored", "--content", c, "--licence", "CC0-1.0", "--description", "x")
		if r.code != 0 {
			fmt.Printf("PUBLISH-EXIT %d %s\n", r.code, r.stdout)
			os.Exit(3)
		}
	}
	os.Exit(0)
}

// twoWriters runs two processes publishing on one key into one store, concurrently, and returns the key's log.
func twoWriters(t *testing.T, p *pubWorld, n int, nolock bool) (tips, lines int, exits [2]error) {
	t.Helper()
	var wg sync.WaitGroup
	for i, tag := range []string{"a", "b"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			spec := strings.Join([]string{p.root, p.key, tag, strconv.Itoa(n), map[bool]string{true: "1", false: "0"}[nolock], "150"}, "|")
			cmd := exec.Command(os.Args[0], "-test.run=^TestWriterLockHelper$")
			cmd.Env = append(os.Environ(), lockHelperEnv+"="+spec)
			out, err := cmd.CombinedOutput()
			if err != nil {
				err = fmt.Errorf("%v: %s", err, out)
			}
			exits[i] = err
		}()
	}
	wg.Wait()
	st, err := store.Open(p.root, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := loadView(st, nil)
	if err != nil {
		t.Fatal(err)
	}
	lv := v.logs.Log(p.signer).View()
	for _, l := range lv.Lines {
		if l.State == keylog.Chained {
			lines++
		}
	}
	return len(lv.Tips), lines, exits
}

// TestWriterLockTwoProcesses: storage note §4.3 / issue #127. Two processes publish on one key concurrently
// (each publish = authored + holds). With the lock the log is linear and every publish landed; with the lock
// disabled by the test hook the same run forks, which proves the concurrent mutation reaches the boundary the
// lock guards (a green positive alone would also pass if the writers never overlapped).
func TestWriterLockTwoProcesses(t *testing.T) {
	t.Run("with lock: linear", func(t *testing.T) {
		p := newPubWorld(t)
		tips, lines, exits := twoWriters(t, p, 3, false)
		for _, e := range exits {
			if e != nil {
				t.Fatalf("writer failed: %v", e)
			}
		}
		if tips != 1 || lines != 12 {
			t.Fatalf("with the lock the log is linear and complete: tips=%d lines=%d (want 1, 12)", tips, lines)
		}
	})
	t.Run("lock disabled: forks", func(t *testing.T) {
		p := newPubWorld(t)
		tips, lines, exits := twoWriters(t, p, 1, true)
		for _, e := range exits {
			if e != nil {
				t.Fatalf("writer failed: %v", e)
			}
		}
		if tips < 2 {
			t.Fatalf("without the lock the overlapping writers must fork (tips=%d): the test did not reach the boundary", tips)
		}
		if lines != 4 {
			t.Fatalf("a fork keeps both writers' lines (2 publishes × authored+holds): %d chained lines", lines)
		}
		conformance.Partial(t, "C-core-127", "two OS processes appending one key from one sequence point fork and keep both lines (proved here with the writer lock disabled); the FORK token on the read commands is not asserted here, and the default path now prevents the fork locally")
	})
}

// TestWriterLockBoundedWait: a lock held elsewhere delays a writer for at most the bounded wait, then the
// writer proceeds without it (§4.3: "waits a bounded time, then proceeds without it and may fork"): nothing
// is refused.
func TestWriterLockBoundedWait(t *testing.T) {
	root := t.TempDir()
	s, err := store.Open(root, store.Options{NoSync: true, LockWait: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	signer := testKey("K1").Signer()
	first := s.LockKey(signer)
	if !first.Held {
		t.Fatalf("first lock not held: %s", first.Why)
	}
	other := s.LockKey(signer) // a second open file description on the same path conflicts even in-process
	if other.Held || other.Why == "" {
		t.Fatalf("a second writer must time out unheld with a reason: %+v", other)
	}
	if !s.LockKey(testKey("K2").Signer()).Held {
		t.Fatal("the lock is per key: another key's writer must not wait")
	}
	first.Unlock()
	first.Unlock() // idempotent
	again := s.LockKey(signer)
	if !again.Held {
		t.Fatalf("lock not reusable after Unlock: %s", again.Why)
	}
	again.Unlock()
}

// TestWriterLockFileIsNotData: the lock file lives under locks/, which no scan, fsck, pull archive or
// replication reads: the store stays clean and the data surface lists nothing from it.
func TestWriterLockFileIsNotData(t *testing.T) {
	p := newPubWorld(t)
	if r := p.publish("--kind", "authored", "--content", p.file("d.bin", "one"), "--licence", "CC0-1.0", "--description", "x"); r.code != 0 {
		t.Fatalf("publish: %d %s", r.code, r.stdout)
	}
	lock := filepath.Join(p.root, "locks", strings.ReplaceAll(p.signer, ":", "-")+".lock")
	if _, err := os.Stat(lock); err != nil {
		t.Fatalf("a writer leaves its lock file at locks/<signer>.lock: %v", err)
	}
	if fi, _ := os.Stat(lock); fi.Size() != 0 {
		t.Fatalf("the lock file carries no content, size %d", fi.Size())
	}
	blobs, stmts := dataObjects(t, p.root)
	for _, o := range append(blobs, stmts...) {
		if strings.Contains(o, "lock") {
			t.Fatalf("data surface lists %s", o)
		}
	}
	if r := p.run("fsck", "--json"); r.code != 0 || strings.Contains(r.stdout, "locks") {
		t.Fatalf("fsck must be clean and silent about locks/: %d %s", r.code, r.stdout)
	}
	// a pull reads the data surface only; copying it (as the sweep fixtures do) never carries locks/
	d := t.TempDir()
	copyData(t, p.root, d)
	if _, err := os.Stat(filepath.Join(d, "locks")); err == nil {
		t.Fatal("locks/ is part of the replicated surface")
	}
}

// TestEveryWriterWaitsOnTheLock: publish, publish task and revoke each go through the writer lock. Another
// holder is placed on the key; each writer must wait the bounded time (shortened here), then proceed without
// the lock, succeed, and say so in its output. A writer that never reached LockKey would return at once with
// no note.
func TestEveryWriterWaitsOnTheLock(t *testing.T) {
	old := store.DefaultLockWait
	store.DefaultLockWait = 300 * time.Millisecond
	t.Cleanup(func() { store.DefaultLockWait = old })
	p := newPubWorld(t)
	holder := p.s.LockKey(p.signer)
	if !holder.Held {
		t.Fatalf("holder: %s", holder.Why)
	}
	defer holder.Unlock()
	ct := p.file("c.json", `{"profile":"`+resolve.ProvisionalProfile+`","beneficiary":"`+p.signer+`","any_issuer":true}`)
	for _, c := range []struct {
		name string
		args []string
	}{
		{"publish", []string{"publish", "--key", p.key, "--json", "--kind", "authored", "--content", p.file("d.bin", "x"), "--licence", "CC0-1.0", "--description", "x"}},
		{"publish task", []string{"publish", "task", "--key", p.key, "--name", "t", "--contract", ct, "--json"}},
		{"revoke", []string{"revoke", "--key", p.key, "--reason", "superseded", "--json"}},
	} {
		start := time.Now()
		r := runIn(p.root, nil, c.args...)
		el := time.Since(start)
		if r.code != 0 {
			t.Fatalf("%s: a held lock must never refuse a write: %d %s", c.name, r.code, r.stdout)
		}
		if el < 250*time.Millisecond {
			t.Fatalf("%s returned in %v: it did not wait on the writer lock", c.name, el)
		}
		if !strings.Contains(r.stdout, `"writer_lock":"not held:`) {
			t.Fatalf("%s: no writer_lock note: %s", c.name, r.stdout)
		}
	}
}

// TestDryRunTakesNoLock: a dry run writes nothing, so it leaves no lock file either (the snapshot of the
// whole root, locks/ included, is unchanged).
func TestDryRunTakesNoLock(t *testing.T) {
	p := newPubWorld(t)
	before := snapshot(t, p.root)
	if r := p.publish("--kind", "authored", "--content", p.file("c", "dry"), "--dry-run"); r.code != 0 {
		t.Fatalf("dry run: %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("a dry run changed the store")
	}
	if _, err := os.Stat(filepath.Join(p.root, "locks")); err == nil {
		t.Fatal("a dry run created locks/")
	}
}
