//go:build unix

package store

import (
	"os"
	"syscall"
)

const sameFSKnown = true

// sameDevice reports whether a and b are on one filesystem (same st_dev), so rename between them is atomic.
func sameDevice(a, b string) bool {
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	if err1 != nil || err2 != nil {
		return false
	}
	sa, ok1 := fa.Sys().(*syscall.Stat_t)
	sb, ok2 := fb.Sys().(*syscall.Stat_t)
	return ok1 && ok2 && uint64(sa.Dev) == uint64(sb.Dev)
}
