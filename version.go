// Package research holds the repository's single version source: the VERSION file at the module root,
// embedded into every binary built from this module. It sits at the root because go:embed cannot reach a
// parent directory.
package research

import (
	_ "embed"
	"runtime/debug"
	"strings"
)

//go:embed VERSION
var embedded string

// Embedded returns the VERSION file's content with surrounding whitespace removed.
func Embedded() string { return strings.TrimSpace(embedded) }

// Version reports the tool version. A non-empty stamped value (from -ldflags -X main.version=…) wins; then the
// embedded VERSION file; then, only if that is empty, the module version the Go toolchain recorded
// (ignoring the "(devel)" placeholder); otherwise "devel".
func Version(stamped string) string {
	if s := strings.TrimSpace(stamped); s != "" {
		return s
	}
	if v := Embedded(); v != "" {
		return v
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := strings.TrimPrefix(bi.Main.Version, "v"); v != "" && v != "(devel)" {
			return v
		}
	}
	return "devel"
}
