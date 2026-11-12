package btctime

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Receiver-local state is never read or written through a symbolic link. The state directory is the reader's own
// (0700), so a link there is not an attack the permissions admit; but nothing the tool writes there is a link, and
// following one would read or chmod whatever it points at. Every path the header database and the receipt store
// open is checked with Lstat first (a link is refused, naming the path); a file is then opened and the opened file
// must be the one Lstat saw (os.SameFile), so a link swapped in between the check and the open is refused too. This
// is O_NOFOLLOW's effect without the syscall package, which this package does not import (no network, C-btc-25).

// ErrSymlink is a state path that is a symbolic link.
var ErrSymlink = errors.New("is a symbolic link; receiver-local state is never followed through one")

// symlinkError names the path.
func symlinkError(p string) error { return fmt.Errorf("%s %w", p, ErrSymlink) }

// noSymlinkDirs refuses any of dirs that is a symbolic link or exists and is not a directory.
func noSymlinkDirs(dirs ...string) error {
	for _, d := range dirs {
		fi, err := os.Lstat(d)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return symlinkError(d)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", d)
		}
	}
	return nil
}

// mkdirsNoFollow creates each of dirs (in order, parents first) with mode 0700 and tightens an existing one to
// 0700, refusing a symbolic link at any of them before it is created into or chmodded.
func mkdirsNoFollow(dirs ...string) error {
	for _, d := range dirs {
		if err := noSymlinkDirs(d); err != nil {
			return err
		}
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		if err := noSymlinkDirs(d); err != nil { // a link swapped in after the check
			return err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// openNoFollow opens p read-only without following a symbolic link at it: Lstat refuses a link, and the file
// opened must be the very file Lstat saw, else a link (or another file) was swapped in between and it is refused.
func openNoFollow(p string) (*os.File, error) {
	li, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		return nil, symlinkError(p)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !os.SameFile(li, fi) {
		f.Close()
		return nil, fmt.Errorf("%s changed while it was opened (%w)", p, ErrSymlink)
	}
	return f, nil
}
