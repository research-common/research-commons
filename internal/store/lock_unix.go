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

// flockWait polls a non-blocking exclusive flock until wait runs out.
func flockWait(f *os.File, wait time.Duration) (bool, string) {
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return true, ""
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return false, "advisory locks unavailable here: " + err.Error()
		}
		if !time.Now().Before(deadline) {
			return false, "another process held this key's writer lock for " + wait.String()
		}
		time.Sleep(lockPoll)
	}
}

func funlock(f *os.File) { syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
