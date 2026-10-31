package btctime

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Where receiver-local state lives (bitcoin-time note §9.1): outside the replicated data surface. For a
// git-backed hub that is the repository's git directory, resolved the way Git resolves it, so a linked worktree
// and a submodule find the one common directory; for any other root it is a directory the reader configures
// explicitly. With neither there is no state: no receipts, no header database, and every bound stays local
// (backend-unconfigured, C-btc-06).
//
// Git is read, never run: the `.git` entry at the hub root is either the git directory itself, or a file
// `gitdir: <path>` naming it (linked worktrees, submodules), and a git directory holding a `commondir` file
// names the shared directory relative to itself. This is what `git rev-parse --git-common-dir` reports. No
// caller environment (GIT_DIR and the rest) redirects it, and parents of the hub root are never searched: an
// enclosing repository that is not the hub's is not the hub's state.

// Location is a resolved state directory and the hub instance identity bound into every receipt kept there.
type Location struct {
	// Dir is the directory receiver-local state lives under.
	Dir string
	// Hub identifies the hub instance: "git:" and the resolved common git directory, or "dir:" and the hub root.
	// A receipt names it; one read under another hub is foreign and never trusted.
	Hub string
	// Via says how Dir was found: "git" or "configured".
	Via string
}

// ErrNoState is Locate's answer for a root that is not git-backed when no state directory is configured.
var ErrNoState = errors.New("no receiver-local state: the hub is not git-backed and no state directory is configured; every bound stays local (backend-unconfigured)")

// stateSubdir is the directory under a git directory (or a configured directory) that this tool owns.
const stateSubdir = "research-commons"

// Locate resolves the state directory for the hub rooted at hubRoot. A configured directory, when given, is the
// reader's explicit choice and wins; it must exist, and must not lie inside the hub root, which is the data surface. Otherwise a
// git-backed hub resolves to <common git dir>/research-commons; anything else is ErrNoState.
func Locate(hubRoot, configured string) (Location, error) {
	root, err := realDir(hubRoot)
	if err != nil {
		return Location{}, fmt.Errorf("hub root: %w", err)
	}
	if configured != "" {
		dir, err := realDir(configured)
		if err != nil {
			return Location{}, fmt.Errorf("state directory: %w", err)
		}
		if within(dir, root) {
			return Location{}, fmt.Errorf("state directory %s is inside the hub root %s, which is the replicated data surface; receipts never live there", dir, root)
		}
		return Location{Dir: filepath.Join(dir, stateSubdir), Hub: "dir:" + root, Via: "configured"}, nil
	}
	common, err := gitCommonDir(root)
	if err != nil {
		return Location{}, err
	}
	return Location{Dir: filepath.Join(common, stateSubdir), Hub: "git:" + common, Via: "git"}, nil
}

// gitCommonDir reads the hub root's `.git` entry as Git does. ErrNoState when there is none.
func gitCommonDir(root string) (string, error) {
	dotgit := filepath.Join(root, ".git")
	fi, err := os.Lstat(dotgit)
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNoState
	}
	if err != nil {
		return "", err
	}
	var gitdir string
	switch {
	case fi.IsDir():
		gitdir = dotgit
	case fi.Mode().IsRegular():
		b, err := readSmall(dotgit)
		if err != nil {
			return "", err
		}
		p, ok := strings.CutPrefix(strings.TrimRight(string(b), "\r\n"), "gitdir: ")
		if !ok || p == "" || strings.ContainsAny(p, "\n\x00") {
			return "", fmt.Errorf("%s is not a gitdir file", dotgit)
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(root, p)
		}
		gitdir = p
	default:
		return "", fmt.Errorf("%s is neither a directory nor a gitdir file", dotgit)
	}
	gitdir, err = realDir(gitdir)
	if err != nil {
		return "", fmt.Errorf("git directory: %w", err)
	}
	common := gitdir
	if b, err := readSmall(filepath.Join(gitdir, "commondir")); err == nil {
		p := strings.TrimRight(string(b), "\r\n")
		if p == "" || strings.ContainsAny(p, "\n\x00") {
			return "", fmt.Errorf("%s/commondir is malformed", gitdir)
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(gitdir, p)
		}
		if common, err = realDir(p); err != nil {
			return "", fmt.Errorf("git common directory: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(common, "HEAD")); err != nil {
		if _, err2 := os.Stat(filepath.Join(gitdir, "HEAD")); err2 != nil {
			return "", fmt.Errorf("%s is not a git directory (no HEAD)", common)
		}
	}
	return common, nil
}

// readSmall reads a file of at most 4 KiB (a gitdir or commondir file).
func readSmall(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, 4097)
	n, err := f.Read(b)
	if err != nil && n == 0 {
		return nil, err
	}
	if n > 4096 || bytes.IndexByte(b[:n], 0) >= 0 {
		return nil, fmt.Errorf("%s is not a small text file", p)
	}
	return b[:n], nil
}

// realDir is the absolute, symlink-resolved path of an existing directory.
func realDir(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	r, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(r)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%s is not a directory", r)
	}
	return r, nil
}

// within reports whether p is root or lies under it (both cleaned, absolute).
func within(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
