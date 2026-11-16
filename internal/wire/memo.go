package wire

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"sync"
	"sync/atomic"
)

// The in-process verification memo (storage note §5.3: this implementation keeps no persistent verification
// cache; the memo is what it keeps instead).
//
// One command reads the same stored line more than once: the store lists its statements (verifying each), the
// view delivers each into its signer's log (verifying twice more), fsck and status read them again. ReadStored
// answers every one of those reads from the first, keyed on the sha256 of the line's bytes and on nothing else:
// not the file's name, size or modification time, so a line rewritten under the same name with the same size and
// the same mtime is a different key and is verified on its own. The answer of ReadStored is a function of the
// line's bytes (a fixed registry, no clock, no state), so a memoised answer is the answer a cold read gives: the
// memo is invisible to every output.
//
// It is not persisted: it lives in this process's memory, bounded, and holds nothing the process did not compute
// itself from exactly the bytes being asked about, so a planted file or a stale directory entry can never reach
// it. A command is a process, so it is also scoped to one command; a longer-lived process (a test run, an
// embedding) reuses an answer only for identical bytes.

// memoMaxBytes bounds the line bytes the memo retains. Past it ReadStored stops adding entries and reads cold: the
// answer is the same, only the saving is lost.
var memoMaxBytes = 32 << 20 // per memo

type memoEntry struct {
	st  *Statement
	err error
}

// lineMemo is one memo: the answers of one reader to lines, keyed on the line's sha256.
type lineMemo struct {
	mu    sync.Mutex
	m     map[[sha256.Size]byte]memoEntry
	bytes int
}

var (
	memoOff     atomic.Bool
	storedMemo  lineMemo // ReadStored (the dual reader)
	identityMem lineMemo // the production IdentityReader (identity.Admit reads every held line with it)
)

func (l *lineMemo) reset() {
	l.mu.Lock()
	l.m, l.bytes = nil, 0
	l.mu.Unlock()
}

// ResetMemo drops every memoised read. For tests that count the verifications one command makes.
func ResetMemo() {
	storedMemo.reset()
	identityMem.reset()
	resetSigMemo()
}

// SetMemo turns the memo on or off (it starts on) and returns the function that restores the previous setting;
// off, every read is cold. For tests that compare the memoised answers with the cold ones.
func SetMemo(on bool) (restore func()) {
	prev := memoOff.Swap(!on)
	ResetMemo()
	return func() {
		memoOff.Store(prev)
		ResetMemo()
	}
}

// read answers line from the memo, or computes it with cold and remembers the answer. Every return is its own copy
// of the statement, with its own slices, so no caller's fields are another's; the parsed body and the signed
// string are shared and read-only, as every reader treats them.
func (l *lineMemo) read(line []byte, cold func([]byte) (*Statement, error)) (*Statement, error) {
	if len(line) > MaxLine || memoOff.Load() { // refused before parsing, and too large to be worth hashing; or off
		return cold(line)
	}
	key := sha256.Sum256(line)
	l.mu.Lock()
	e, ok := l.m[key]
	l.mu.Unlock()
	if !ok {
		e.st, e.err = cold(line)
		l.mu.Lock()
		if _, dup := l.m[key]; !dup && l.bytes+len(line) <= memoMaxBytes {
			if l.m == nil {
				l.m = map[[sha256.Size]byte]memoEntry{}
			}
			l.m[key] = e
			l.bytes += len(line)
		}
		l.mu.Unlock()
	}
	if e.st == nil {
		return nil, e.err
	}
	cp := *e.st
	cp.Merges, cp.Crit, cp.Unpinned, cp.refs = slices.Clone(e.st.Merges), slices.Clone(e.st.Crit), slices.Clone(e.st.Unpinned), slices.Clone(e.st.refs)
	if e.st.Actor != nil {
		a := *e.st.Actor
		cp.Actor = &a
	}
	return &cp, e.err
}

// memoRead is ReadStored through the memo.
func memoRead(line []byte) (*Statement, error) { return storedMemo.read(line, stored.Read) }

// The signature memo sits under the line memos. The identity evaluator reads every held line again with the
// identity reader (an rc/1 line too, which the dual reader read as Read), so the same line is read by two readers
// whose answers differ for a verified line with a bad body; what they share is the signature check, whose answer is
// a function of exactly (alg, signer, signed string, sig). Memoising that once gives one cryptographic verification
// per distinct signed line per process, whichever reader asks.

// memoMaxSigs bounds the signature memo's entries.
var memoMaxSigs = 1 << 18

type sigAnswer struct {
	sig string // the canonical signature the check settled on (s.Sig)
	err error
}

var sigMemo = struct {
	mu sync.Mutex
	m  map[[sha256.Size]byte]sigAnswer
}{}

func resetSigMemo() {
	sigMemo.mu.Lock()
	sigMemo.m = nil
	sigMemo.mu.Unlock()
}

// verifyMemo is s.verify through the memo. compute is the cryptographic check.
func (s *Statement) verifyMemo(sigS string, compute func() (string, error)) error {
	if memoOff.Load() {
		observeVerify(s.ID)
		sig, err := compute()
		if err == nil {
			s.Sig = sig
		}
		return err
	}
	h := sha256.New()
	for _, part := range [][]byte{[]byte(s.Alg), []byte(s.Signer), []byte(sigS), s.SignedString} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		h.Write(n[:])
		h.Write(part)
	}
	var key [sha256.Size]byte
	h.Sum(key[:0])
	sigMemo.mu.Lock()
	a, ok := sigMemo.m[key]
	sigMemo.mu.Unlock()
	if !ok {
		observeVerify(s.ID)
		a.sig, a.err = compute()
		sigMemo.mu.Lock()
		if sigMemo.m == nil {
			sigMemo.m = map[[sha256.Size]byte]sigAnswer{}
		}
		if len(sigMemo.m) < memoMaxSigs {
			sigMemo.m[key] = a
		}
		sigMemo.mu.Unlock()
	}
	if a.err == nil {
		s.Sig = a.sig
	}
	return a.err
}

// verifyObserver, when set, is called with the id of every statement whose signature is cryptographically
// verified (a memo hit is not a verification): the count a test reads to show one verification per line.
var verifyObserver atomic.Pointer[func(id string)]

// ObserveVerify calls f with the id of every statement this process verifies, until the returned function is
// called. For tests; there is no production caller.
func ObserveVerify(f func(id string)) (stop func()) {
	verifyObserver.Store(&f)
	return func() { verifyObserver.Store(nil) }
}

func observeVerify(id string) {
	if p := verifyObserver.Load(); p != nil {
		(*p)(id)
	}
}
