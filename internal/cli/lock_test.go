package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	// Both processes are started before either is waited on, so they run concurrently. No goroutine is needed,
	// which keeps this package out of the CI race job's goroutine scan (the whole cli package under -race is slow).
	var cmds [2]*exec.Cmd
	var outs [2]bytes.Buffer
	for i, tag := range []string{"a", "b"} {
		spec := strings.Join([]string{p.root, p.key, tag, strconv.Itoa(n), map[bool]string{true: "1", false: "0"}[nolock], "150"}, "|")
		cmd := exec.Command(os.Args[0], "-test.run=^TestWriterLockHelper$")
		cmd.Env = append(os.Environ(), lockHelperEnv+"="+spec)
		cmd.Stdout, cmd.Stderr = &outs[i], &outs[i]
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds[i] = cmd
	}
	for i, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			exits[i] = fmt.Errorf("%v: %s", err, outs[i].String())
		}
	}
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
	// keys with statements: each has its statements/<signer>/ directory (a key's first write is below)
	for _, k := range []string{signer, testKey("K2").Signer()} {
		os.MkdirAll(filepath.Join(root, "statements", strings.ReplaceAll(k, ":", "-")), 0o755)
	}
	first := s.LockKey(signer)
	if !first.Held {
		t.Fatalf("first lock not held: %s", first.Why)
	}
	other := s.LockKey(signer) // a second open file description on the same path conflicts even in-process
	if other.Held || other.Why == "" {
		t.Fatalf("a second writer must time out unheld with a reason: %+v", other)
	}
	k2 := s.LockKey(testKey("K2").Signer())
	if !k2.Held {
		t.Fatal("the lock is per key: another key's writer must not wait")
	}
	k2.Unlock()
	// a key's first write (no directory yet) locks the whole statements/ directory, so it waits for writers
	// of other keys too, and they wait for it: two first writers of one key can't both start a log.
	if fresh := s.LockKey(testKey("K3").Signer()); fresh.Held {
		t.Fatal("a first write must wait while another key's writer holds its lock")
	}
	first.Unlock()
	fresh := s.LockKey(testKey("K3").Signer())
	if !fresh.Held {
		t.Fatalf("a first write with no other writer: %s", fresh.Why)
	}
	if again := s.LockKey(testKey("K3").Signer()); again.Held {
		t.Fatal("a second first-writer of one key must wait")
	}
	if k1 := s.LockKey(signer); k1.Held {
		t.Fatal("a first write excludes writers of other keys while it commits")
	}
	fresh.Unlock()
	first.Unlock() // idempotent
	again := s.LockKey(signer)
	if !again.Held {
		t.Fatalf("lock not reusable after Unlock: %s", again.Why)
	}
	again.Unlock()
}

// TestWriterLockAddsNoPath: the lock is flocks on existing directories, so a writer leaves no file outside the store
// layout: fsck stays clean, and the whole store tree (not only its data directories) pulls
// into a fresh store with nothing refused. A lock file anywhere else would be refused by the next pull as
// outside the data surface.
func TestWriterLockAddsNoPath(t *testing.T) {
	p := newPubWorld(t)
	if r := p.publish("--kind", "authored", "--content", p.file("d.bin", "one"), "--licence", "CC0-1.0", "--description", "x"); r.code != 0 {
		t.Fatalf("publish: %d %s", r.code, r.stdout)
	}
	if _, err := os.Stat(filepath.Join(p.root, "locks")); err == nil {
		t.Fatal("a writer created locks/")
	}
	if r := p.run("fsck", "--json"); r.code != 0 {
		t.Fatalf("fsck: %d %s", r.code, r.stdout)
	}
	// a lock on a key with no statement yet creates nothing
	before := snapshot(t, p.root)
	l := p.s.LockKey("ed25519:" + strings.Repeat("ab", 32))
	if !l.Held {
		t.Fatalf("lock on a new key: %s", l.Why)
	}
	l.Unlock()
	if snapshot(t, p.root) != before {
		t.Fatal("taking the lock changed the store")
	}
	d := filepath.Join(t.TempDir(), "b")
	if r := runIn(filepath.Dir(d), nil, "init", d, "--json"); r.code != 0 {
		t.Fatalf("init: %d %s", r.code, r.stdout)
	}
	r := runIn(d, nil, "pull", p.root, "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"refused":0`) {
		t.Fatalf("pull of a store a writer locked must refuse nothing: %d %s", r.code, r.stdout)
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
// whole root is unchanged).
func TestDryRunTakesNoLock(t *testing.T) {
	p := newPubWorld(t)
	before := snapshot(t, p.root)
	if r := p.publish("--kind", "authored", "--content", p.file("c", "dry"), "--dry-run"); r.code != 0 {
		t.Fatalf("dry run: %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("a dry run changed the store")
	}

}
