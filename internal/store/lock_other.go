//go:build !unix

package store

import (
	"os"
	"time"
)

// lockDeclaration is the storage note §7 `locks` value on this platform.
const lockDeclaration = "none"

// flockWait: no advisory locks on this platform; the writer proceeds without one (storage note §4.3).
func flockWait(f *os.File, exclusive bool, left, total time.Duration) (bool, string) {
	return false, "no advisory locks on this platform"
}

func funlock(f *os.File) {}
