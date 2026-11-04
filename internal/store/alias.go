package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// AliasLen is the length of a display alias (wire-format note §3, "Display aliases"): the first 12 hex
// characters of a statement id, or of a content digest after its "sha256:" prefix.
const AliasLen = 12

var reAlias = regexp.MustCompile(`^(sha256:)?[0-9a-f]{12}$`)

// IsAlias reports whether s has the shape of a display alias: 12 lowercase hex characters (a statement id or a
// digest), or "sha256:" + 12 lowercase hex (a digest only).
func IsAlias(s string) bool { return reAlias.MatchString(s) }

// AliasCandidates is every held object whose full hash starts with alias: blobs held under blobs/sha256 (as
// "sha256:<64 hex>") and statements installed under statements/ (as "<64 hex>"), sorted. An alias written with
// the "sha256:" prefix matches blobs only. The store under root is read, never opened: nothing is replayed,
// created or written, so a caller can resolve an argument before any work starts. Only file names are read;
// whether a matching file is intact is the caller's next question (OpenBlob, Statements, fsck). A name that is
// not 64 lowercase hex is not a held object and never matches.
//
// The note's rule is the caller's: an alias is accepted only when exactly one held object matches; zero is
// "not found" and two or more is an error listing every candidate, selecting nothing (C-core-03).
func AliasCandidates(root, alias string) ([]string, error) {
	if !IsAlias(alias) {
		return nil, errors.New("not an alias: " + alias)
	}
	hex, blobOnly := strings.CutPrefix(alias, "sha256:")
	var out []string
	ents, err := os.ReadDir(filepath.Join(root, "blobs", "sha256"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	for _, e := range ents {
		if !e.IsDir() && reHex.MatchString(e.Name()) && strings.HasPrefix(e.Name(), hex) {
			out = append(out, "sha256:"+e.Name())
		}
	}
	if !blobOnly {
		dirs, err := os.ReadDir(filepath.Join(root, "statements"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		for _, d := range dirs {
			if !d.IsDir() {
				continue
			}
			files, err := os.ReadDir(filepath.Join(root, "statements", d.Name()))
			if err != nil {
				return nil, err
			}
			for _, f := range files {
				if !f.IsDir() && reHex.MatchString(f.Name()) && strings.HasPrefix(f.Name(), hex) {
					out = append(out, f.Name())
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}
