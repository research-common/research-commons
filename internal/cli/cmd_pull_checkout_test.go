package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPullFromCheckout: a hub checkout carries a top-level .git. Without --from-checkout it is refused (exit 1,
// as before); with it the entry is transport metadata, skipped and reported once, and a pull whose data is all
// admitted exits 0. A .git anywhere deeper is still refused with the flag.
func TestPullFromCheckout(t *testing.T) {
	mk := func() (*world, string) {
		src := newWorld(t)
		src.blob("a", []byte("a"))
		src.authored("A:a", "K1", "a", "licence", "CC0-1.0")
		pkg := t.TempDir()
		copyData(t, src.root, pkg)
		os.MkdirAll(filepath.Join(pkg, ".git", "hooks"), 0o755)
		os.WriteFile(filepath.Join(pkg, ".git", "hooks", "post-checkout"), []byte("#!/bin/sh\n"), 0o755)
		return newWorld(t), pkg
	}
	const skipped = ".git (transport metadata, --from-checkout)"

	dst, pkg := mk()
	r := dst.run("pull", pkg, "--dry-run", "--json")
	if r.code != 1 || strings.Contains(r.stdout, "skipped") {
		t.Fatalf("without the flag: exit %d\n%s", r.code, r.stdout)
	}

	dst, pkg = mk()
	r = dst.run("pull", pkg, "--from-checkout")
	if r.code != 0 || strings.Count(r.stdout, skipped) != 1 {
		t.Fatalf("with the flag: exit %d\n%s", r.code, r.stdout)
	}
	if r := dst.run("pull", pkg, "--from-checkout", "--json"); r.code != 0 || !strings.Contains(r.stdout, `"skipped":["`+skipped+`"]`) {
		t.Fatalf("json: exit %d\n%s", r.code, r.stdout)
	}
	if strings.Contains(dst.run("list", "--json").stdout, ".git") {
		t.Fatal(".git reached the store")
	}

	// a nested .git is still refused, with the flag
	dst, pkg = mk()
	os.MkdirAll(filepath.Join(pkg, "statements", ".git"), 0o755)
	os.WriteFile(filepath.Join(pkg, "statements", ".git", "config"), []byte("x"), 0o644)
	r = dst.run("pull", pkg, "--from-checkout", "--json")
	if r.code != 1 || !strings.Contains(r.stdout, "statements/.git/config") {
		t.Fatalf("nested .git: exit %d\n%s", r.code, r.stdout)
	}
	if strings.Count(r.stdout, skipped) != 1 {
		t.Fatalf("the top-level .git should still be the one skipped:\n%s", r.stdout)
	}
}
