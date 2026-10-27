package cli

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Sweep fixtures for the commands that need more than a store and a ref: hub check runs in the fixture store
// made a git hub (one commit of its data surface), pull reads a package directory holding a copy of the
// fixture's data (every object already held: exit 0, nothing installed).

var pkgDirs = map[*world]string{}

// gitHub makes the fixture root a git repository with one commit of its data and control plane, as a hub
// clone is. The store's local directories are ignored, as the hub template's .gitignore does.
func (w *world) gitHub() {
	t := w.t
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		return // hub check then exits 2 in the sweep (no commit at HEAD); the dedicated test skips
	}
	os.WriteFile(filepath.Join(w.root, ".gitignore"), []byte("/journal/\n/quarantine/\n/retained/\n/tmp/\n"), 0o644)
	gitIn(t, w.root, "init", "-q", "-b", "main")
	gitIn(t, w.root, "add", "-A")
	gitIn(t, w.root, "commit", "-q", "-m", "fixture")
}

func gitIn(t testing.TB, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// pkgDir is a package directory holding a copy of the fixture's data surface (rc-store, blobs, statements).
func (w *world) pkgDir() string {
	if d, ok := pkgDirs[w]; ok {
		return d
	}
	d := w.t.TempDir()
	copyData(w.t, w.root, d)
	pkgDirs[w] = d
	return d
}

func copyData(t testing.TB, from, to string) {
	t.Helper()
	os.WriteFile(filepath.Join(to, "rc-store"), mustRead(t, filepath.Join(from, "rc-store")), 0o644)
	for _, top := range []string{"blobs", "statements"} {
		filepath.WalkDir(filepath.Join(from, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				t.Fatal(err)
			}
			rel, _ := filepath.Rel(from, p)
			if d.IsDir() {
				return os.MkdirAll(filepath.Join(to, rel), 0o755)
			}
			return os.WriteFile(filepath.Join(to, rel), mustRead(t, p), 0o644)
		})
	}
}

func mustRead(t testing.TB, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sweepNonStore is the sweep invocation of a command that reads no store.
func (w *world) sweepNonStore(c *Command) []string {
	if c.Name == "hub check" {
		return []string{"hub", "check"}
	}
	return nil
}

// badInvocations are per-command invocations that must exit 2 before any work.
func (w *world) badInvocations(c *Command) [][]string {
	switch c.Name {
	case "hub check":
		return [][]string{{"--base", "no-such-rev"}, {"--base", "--output=/tmp/x"}, {"--store", w.root}}
	case "pull":
		d := w.pkgDir()
		return [][]string{{filepath.Join(d, "absent")}, {filepath.Join(d, "rc-store")}, {w.root}, {d, "--override", "Bad Name=x"},
			{d, "--override", "ok="}, {d, "--override", "ok=a,,b"}, {d, "--below-floor", "maybe"}}
	case "gc":
		return [][]string{{"--grace", "soon"}, {"--grace", "-1h"}, {"--release", "not-a-digest"}, {"--release", dig("sole"), "--apply"},
			{"--release", dig("sole"), "--grace", "1h"}, {"--key", "/nonexistent"}, {"--release", dig("sole"), "--key", "/nonexistent"}}
	case "fsck":
		return [][]string{{"--rebuild", "no-such-projection"}, {"--rebuild", ""}}
	case "status":
		return [][]string{{"--limits", "x"}}
	}
	return nil
}

// mayRefuse: a sweep invocation whose exit 1 is a legitimate verdict over the fixture (none today).
func (w *world) mayRefuse(a []string) bool { return false }
