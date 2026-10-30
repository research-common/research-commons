package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrNoMarker is returned by CheckMarker for a directory that holds no rc-store marker.
var ErrNoMarker = errors.New("no rc-store marker")

// CheckMarker reports whether root is a store of the layout this package implements, without creating or
// changing anything (Open creates a missing store; a reader that must not do so checks first). The marker is
// read as a regular file, never followed through a symbolic link. An absent marker is ErrNoMarker; a marker
// naming another layout is an error naming it.
func CheckMarker(root string) error {
	p := filepath.Join(root, "rc-store")
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNoMarker
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("rc-store marker is not a regular file")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(b)) != layoutMarker {
		return fmt.Errorf("unknown layout marker")
	}
	return nil
}

// Layout is the layout marker this package implements.
func Layout() string { return layoutMarker }
