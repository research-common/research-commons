package run

import (
	"archive/tar"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/research-common/research-commons/internal/refusal"
)

// Staging confinement (execution note §3). Every host-side join of a peer-supplied name (attachment, input,
// output, comparator file and archive member names) goes through Join, the one confinement function. It
// refuses, class intrinsic, reason `unsafe path`, with the name printed verbatim and control characters escaped:
//
//	empty, or containing NUL                            unsafe path: malformed name
//	absolute (/…, a drive prefix, \\…) or starting ~    unsafe path: absolute
//	any .. component, after normalising \ to /          unsafe path: traversal
//	any existing component that is a symlink            unsafe path: symlink component
//	resolving outside the directory for another reason  unsafe path: resolves outside directory
//	a device, socket, fifo or other non-regular target  unsafe path: not a regular file
//
// Join examines the real filesystem at the time it is called, so a symlink the step created inside the output
// directory is caught when outputs are read back, whatever the spec's text said.

// Path refusal details (the part after "unsafe path: ").
const (
	PathMalformed  = "malformed name"
	PathAbsolute   = "absolute"
	PathTraversal  = "traversal"
	PathSymlink    = "symlink component"
	PathOutside    = "resolves outside directory"
	PathNotRegular = "not a regular file"
)

var reDrive = regexp.MustCompile(`^[A-Za-z]:`)

// PathRefusal is an unsafe-path refusal: the kind of fault, the name as given and the scope it applies to.
type PathRefusal struct {
	*refusal.Refusal
	What, Name string
}

func (e *PathRefusal) Unwrap() error { return e.Refusal }

func unsafePath(what, name, scope string) *PathRefusal {
	d := "unsafe path: " + what + ": " + strconv.Quote(name)
	if scope != "" {
		d += " in " + scope
	}
	return &PathRefusal{Refusal: &refusal.Refusal{Class: refusal.Intrinsic, Reason: ReasonUnsafePath, Detail: d}, What: what, Name: name}
}

// cleanName applies the textual rules and returns the name as a relative slash path.
func cleanName(name, scope string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", unsafePath(PathMalformed, name, scope)
	}
	n := strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(n, "/") || strings.HasPrefix(name, "~") || reDrive.MatchString(n) {
		return "", unsafePath(PathAbsolute, name, scope)
	}
	for _, c := range strings.Split(n, "/") {
		if c == ".." {
			return "", unsafePath(PathTraversal, name, scope)
		}
	}
	c := filepath.Clean(n)
	if c == "." {
		return "", unsafePath(PathMalformed, name, scope) // the directory itself is not a file name
	}
	return c, nil
}

// Join confines name to root and returns the host path. Every component that exists must be a real directory
// (or, for the last, any non-symlink); a missing tail is allowed, so Join serves writes into staging as well as
// reads. A target that exists must resolve inside root.
func Join(root, name, scope string) (string, error) {
	rel, err := cleanName(name, scope)
	if err != nil {
		return "", err
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	p := realRoot
	parts := strings.Split(rel, "/")
	for i, c := range parts {
		p = filepath.Join(p, c)
		fi, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			return filepath.Join(realRoot, filepath.FromSlash(rel)), nil
		}
		if err != nil {
			return "", unsafePath(PathOutside, name, scope)
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return "", unsafePath(PathSymlink, name, scope)
		}
		if i < len(parts)-1 && !fi.IsDir() {
			return "", unsafePath(PathOutside, name, scope)
		}
	}
	// The whole path exists with no symlink component; a final realpath check catches anything else (an alias,
	// a bind mount, a case-folding filesystem mapping the name elsewhere).
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", unsafePath(PathOutside, name, scope)
	}
	if r, err := filepath.Rel(realRoot, real); err != nil || r == ".." || strings.HasPrefix(r, "../") {
		return "", unsafePath(PathOutside, name, scope)
	}
	return p, nil
}

// ReadRegular confines name to root and reads it as a regular file. The last component is opened without
// following a symlink and checked on the open descriptor, so nothing outside root is read even if the name
// changed between the check and the open. A missing file returns fs.ErrNotExist (an incomplete output, not an
// unsafe path).
func ReadRegular(root, name, scope string, limit int64) ([]byte, error) {
	p, err := Join(root, name, scope)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, unsafePath(PathSymlink, name, scope)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, unsafePath(PathNotRegular, name, scope)
	}
	if limit > 0 && fi.Size() > limit {
		return nil, &refusal.Refusal{Class: refusal.Operational, Reason: refusal.SizeLimit,
			Detail: "output " + strconv.Quote(name) + " is " + strconv.FormatInt(fi.Size(), 10) + " bytes, over the read-back limit " + strconv.FormatInt(limit, 10)}
	}
	return io.ReadAll(f)
}

// WriteNew confines name to root and creates it with data, making parent directories inside root. It never
// follows or replaces an existing entry: staging writes into a fresh directory, so an existing name is a fault
// of the caller.
func WriteNew(root, name, scope string, data []byte, perm fs.FileMode) error {
	p, err := Join(root, name, scope)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	// re-check after MkdirAll: a parent created here is a real directory; anything else was already refused
	if _, err := Join(root, name, scope); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// CheckNames applies the textual rules to every name and returns the first refusal: used before anything is
// written, so one bad name refuses the whole staging with nothing staged.
func CheckNames(names []string, scope string) error {
	for _, n := range names {
		if _, err := cleanName(n, scope); err != nil {
			return err
		}
	}
	return nil
}

// ExtractTar extracts a tar archive into root (§3, archive members). Every member name is checked before
// anything is written, so an archive with one bad member is refused as a whole, scope the member, with nothing
// extracted. Only regular files and directories are extracted; any other member type (symlink, hard link,
// device, fifo) is refused as not a regular file.
func ExtractTar(root string, archive []byte, scope string) error {
	type member struct {
		name string
		dir  bool
		data []byte
	}
	var ms []member
	tr := tar.NewReader(strings.NewReader(string(archive)))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return refusal.Malformed("archive in %s: %v", scope, err)
		}
		mscope := scope + ", member " + strconv.Quote(h.Name)
		name := strings.TrimSuffix(h.Name, "/")
		if _, err := cleanName(name, mscope); err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			ms = append(ms, member{name: name, dir: true})
		case tar.TypeReg:
			b, err := io.ReadAll(tr)
			if err != nil {
				return refusal.Malformed("archive in %s: %v", scope, err)
			}
			ms = append(ms, member{name: name, data: b})
		default:
			return unsafePath(PathNotRegular, h.Name, mscope)
		}
	}
	for _, m := range ms {
		if m.dir {
			p, err := Join(root, m.name, scope)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(p, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := WriteNew(root, m.name, scope, m.data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
