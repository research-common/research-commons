//go:build unix

package store

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// lockDeclaration is the storage note §7 `locks` value on this platform.
const lockDeclaration = "advisory"

// flockWait polls a non-blocking flock (exclusive or shared) until left runs out; total is the whole wait,
// for the message.
func flockWait(f *os.File, exclusive bool, left, total time.Duration) (bool, string) {
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	deadline := time.Now().Add(left)
	for {
		err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if err == nil {
			return true, ""
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return false, "advisory locks unavailable here: " + err.Error()
		}
		if !time.Now().Before(deadline) {
			return false, "another process held this key's writer lock for " + total.String()
		}
		time.Sleep(lockPoll)
	}
}

func funlock(f *os.File) { syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
