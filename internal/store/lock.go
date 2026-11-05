package store

import (
	"os"
	"time"
)

// DefaultLockWait is how long a writer waits for the per-key writer lock before it proceeds without it
// (storage note §4.3). A variable only so tests can shorten it.
var DefaultLockWait = 10 * time.Second

// DisableWriterLock is a test hook: set, LockKey takes nothing, so a test can show what the lock prevents.
// Production code never sets it.
var DisableWriterLock bool

// lockPoll is the interval between non-blocking attempts while waiting.
const lockPoll = 10 * time.Millisecond

// WriterLock is a held (or, after a bounded wait, not held) advisory lock on one signing key's log. It is
// an optimization (storage note §4.3): not holding it never refuses a write, it only lets two of this
// machine's own processes fork the key's log casually. Release it with Unlock; Unlock is idempotent.
type WriterLock struct {
	// Held is false when the wait ran out (or the platform or filesystem has no advisory locks) and the
	// caller proceeds without the lock; Why then says so for a warning.
	Held bool
	Why  string
	f    []*os.File
}

// LockKey takes the advisory writer lock for signer's log, waiting at most Options.LockWait (default
// DefaultLockWait). Call it before resolving the log's head and hold it until the statements are committed.
// It never returns an error for lock trouble: it degrades to a WriterLock with Held false.
//
// The lock creates nothing (no lock file, no directory), so a refused write leaves the store byte-identical and
// the layout gains no path a pull, a hub check or a replica would have to know about. It is two flocks on
// directories every write already has:
//   - signer has a statement directory: a shared flock on statements/, then an exclusive one on
//     statements/<signer>/. Writers of different keys don't wait on each other.
//   - signer has none yet (its first write creates it): an exclusive flock on statements/. That excludes every
//     writer holding the shared one, so a second first-writer of the key, and a writer that sees the directory
//     appear mid-commit, both wait until this write is committed.
func (s *Store) LockKey(signer string) *WriterLock {
	if DisableWriterLock {
		return &WriterLock{Why: "writer lock disabled (test hook)"}
	}
	wait := s.opt.LockWait
	if wait <= 0 {
		wait = DefaultLockWait
	}
	deadline := time.Now().Add(wait)
	root, err := os.Open(s.dir("statements"))
	if err != nil {
		return &WriterLock{Why: "statements/ not openable for locking: " + err.Error()}
	}
	kd, err := os.Open(s.dir("statements", signerDir(signer)))
	if err != nil {
		// first write of this key
		if held, why := flockWait(root, true, time.Until(deadline), wait); !held {
			root.Close()
			return &WriterLock{Why: why}
		}
		return &WriterLock{Held: true, f: []*os.File{root}}
	}
	if held, why := flockWait(root, false, time.Until(deadline), wait); !held {
		root.Close()
		kd.Close()
		return &WriterLock{Why: why}
	}
	if held, why := flockWait(kd, true, time.Until(deadline), wait); !held {
		funlock(root)
		root.Close()
		kd.Close()
		return &WriterLock{Why: why}
	}
	return &WriterLock{Held: true, f: []*os.File{root, kd}}
}

// Unlock releases the lock; safe on a nil receiver and to call twice.
func (l *WriterLock) Unlock() {
	if l == nil {
		return
	}
	for i := len(l.f) - 1; i >= 0; i-- {
		funlock(l.f[i])
		l.f[i].Close()
	}
	l.f = nil
}
