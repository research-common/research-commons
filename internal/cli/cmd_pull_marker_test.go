package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPullStoreMarkerQuiet: pulling a store tree whose rc-store marker is byte-identical to the receiver's
// reports nothing about the marker (nothing for a maintainer to review); a marker that differs is still
// reported as not applied.
func TestPullStoreMarkerQuiet(t *testing.T) {
	src := newWorld(t)
	src.blob("a", []byte("a"))
	src.authored("A:a", "K1", "a", "licence", "CC0-1.0")
	pkg := t.TempDir()
	copyData(t, src.root, pkg)
	if _, err := os.Stat(filepath.Join(pkg, "rc-store")); err != nil {
		t.Fatal("the package has no rc-store marker: ", err)
	}

	dst := newWorld(t)
	r := dst.run("pull", pkg, "--dry-run")
	if r.code != 0 || strings.Contains(r.stdout, "rc-store") || strings.Contains(r.stdout, "needs maintainer review") {
		t.Fatalf("identical marker: exit %d\n%s", r.code, r.stdout)
	}

	// a different marker: the same layout without the trailing newline is accepted but is not the same bytes
	old, _ := os.ReadFile(filepath.Join(pkg, "rc-store"))
	if err := os.WriteFile(filepath.Join(pkg, "rc-store"), []byte(strings.TrimSuffix(string(old), "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	r = newWorld(t).run("pull", pkg, "--dry-run", "--json")
	if !strings.Contains(r.stdout, `"path":"rc-store"`) || !strings.Contains(r.stdout, `"verdict":"not applied"`) {
		t.Fatalf("differing marker must still be reported: exit %d\n%s", r.code, r.stdout)
	}
}
