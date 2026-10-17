//go:build !unix

package store

// On platforms without st_dev the check is not made; the durability declaration says "assumed".
const sameFSKnown = false

func sameDevice(a, b string) bool { return true }
