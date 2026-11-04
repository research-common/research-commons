package gate

import (
	"strings"

	"github.com/research-common/research-commons/internal/store"
)

// ReadArchive reads a tar archive (plain or gzip-compressed) as a whole-tree package: the same Package ReadTree
// makes of a directory holding the same files, so the gate judges both deliveries with the same code and the
// same answer (C-core-04). Nothing is extracted; a member name is only ever a path the gate classifies.
//
//   - A regular-file member is an object with its bytes, read to maxBytes plus one, as ReadTree reads a file;
//     a larger member is then refused by the gate's size limit.
//   - A symbolic link is a Symlink object, and every other member type (hard link, device, fifo, sparse file,
//     unknown) an Other object: never followed, never read, refused by the gate as an unsafe path. So is a
//     member whose name is absolute or carries `..`, `.` or empty segments, or a backslash: the gate's path
//     rules are the only ones, and an archive cannot reach outside the package because nothing is ever written
//     at a member's name.
//   - A member outside the store layout is refused as outside the data surface, exactly as in a tree.
//   - A top-level `.git` directory (members named `.git/…`) is listed as one Other object `.git` with nothing
//     read, as ReadTree lists a `.git` directory: refused by default, skippable by a caller that knows the
//     package is a checkout. A `.git` anywhere deeper keeps its path and is refused as outside the data
//     surface; a top-level regular file named `.git` is an object like any other, as in a tree.
//   - Directory members and the archive-wide header `git archive` writes are not objects.
//
// The archive's own bounds are the scan limits lim (members, total_bytes, path_bytes, expansion_ratio); lim's
// MemberBytes is replaced by maxBytes, so the per-object bound is the tree's. A limit that stops the read, or an
// archive that does not read to its end, returns the error (an operational refusal) and no package: a package
// read in part is never judged. An archive that reads but is ambiguous (one name twice, bytes after its end)
// returns an intrinsic refusal and no package.
func ReadArchive(data []byte, maxBytes int64, lim store.Limits) (Package, *store.Archive, error) {
	lim.MemberBytes = maxBytes
	a, err := store.ReadArchive(data, lim, isGitPath)
	if err != nil {
		return Package{}, a, err
	}
	pkg := Package{Tree: true}
	git := false
	for _, m := range a.Members {
		if isGitPath(m.Name) {
			if !git {
				pkg.Objects = append(pkg.Objects, Object{Path: ".git", Mode: Other})
				git = true
			}
			continue
		}
		o := Object{Path: m.Name}
		switch m.Type {
		case store.TypeFile:
			o.Data = m.Data
		case store.TypeSymlink:
			o.Mode = Symlink
		default:
			o.Mode = Other
		}
		pkg.Objects = append(pkg.Objects, o)
	}
	return pkg, a, nil
}

// isGitPath: a member inside the top-level `.git` directory, or that directory itself (a directory member
// carries its trailing slash).
func isGitPath(name string) bool { return strings.HasPrefix(name, ".git/") }
