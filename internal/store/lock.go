package store

import (
	"os"
	"path/filepath"
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
	f    *os.File
}

// LockKey takes the advisory writer lock for signer's log, waiting at most Options.LockWait (default
// DefaultLockWait). Call it before resolving the log's head and hold it until the statements are committed.
// It never returns an error for lock trouble: it degrades to a WriterLock with Held false. The lock file
// lives at locks/<signer>.lock under the store root: outside blobs/ and statements/, so nothing scans it,
// replicates it or reads it back as data; it carries no content and is never consulted at read time.
func (s *Store) LockKey(signer string) *WriterLock {
	if DisableWriterLock {
		return &WriterLock{Why: "writer lock disabled (test hook)"}
	}
	wait := s.opt.LockWait
	if wait <= 0 {
		wait = DefaultLockWait
	}
	dir := s.dir("locks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return &WriterLock{Why: "no lock directory: " + err.Error()}
	}
	f, err := os.OpenFile(filepath.Join(dir, signerDir(signer)+".lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return &WriterLock{Why: "no lock file: " + err.Error()}
	}
	held, why := flockWait(f, wait)
	if !held {
		f.Close()
		return &WriterLock{Why: why}
	}
	return &WriterLock{Held: true, f: f}
}

// Unlock releases the lock; safe on a nil receiver and to call twice.
func (l *WriterLock) Unlock() {
	if l == nil || l.f == nil {
		return
	}
	funlock(l.f)
	l.f.Close()
	l.f = nil
}
