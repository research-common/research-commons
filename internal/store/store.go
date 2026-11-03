package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const layoutMarker = `{"layout":"rc-store/1"}`

// Durability is the storage note §7 declaration: what this store actually does, printed with every
// conformance result. Values are the note's vocabulary.
type Durability struct {
	FileSync, DirSync, Rename, ExclusiveCreate, SameFilesystem, Locks, GCGrace, Assumes string
}

func (d Durability) String() string {
	return fmt.Sprintf("file_sync=%s dir_sync=%s rename=%s exclusive_create=%s same_filesystem=%s locks=%s gc_grace=%s assumes=%q",
		d.FileSync, d.DirSync, d.Rename, d.ExclusiveCreate, d.SameFilesystem, d.Locks, d.GCGrace, d.Assumes)
}

// Projector is step 5 of the commit protocol: it updates whatever projections the caller keeps from one
// committed operation. It is not authoritative; a failure leaves the operation committed, needs repair. It
// must be idempotent: replay, repair and two committers of one identical operation may each call it.
type Projector func(Record) error

// Options configure a store. The zero value is a store with no projections and full syncs.
type Options struct {
	Project Projector
	// NoSync skips fsync (tests that do not exercise durability). The declaration says so.
	NoSync bool
	// GCGrace is the local policy grace window (§6.1.1) the declaration prints; zero means DefaultGrace. gc
	// takes its own GCConfig: a command passes this value as GCConfig.Policy.
	GCGrace time.Duration
	// crash, when set, is called at each commit point and may abort the operation there (tests only).
	crash func(point string) error
}

// Store is an open store. Open runs recovery before returning, so every read sees only installed objects.
type Store struct {
	root string
	opt  Options
	// Recovered lists what Open's journal replay did.
	Recovered []RecoveryEvent
	sameFS    bool
}

// Open opens (creating if needed) the store at root and replays the journal (§3.4).
func Open(root string, opt Options) (*Store, error) {
	s := &Store{root: root, opt: opt}
	for _, d := range []string{"blobs/sha256", "statements", "journal/pending", "journal/done", "quarantine", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return nil, err
		}
	}
	marker := filepath.Join(root, "rc-store")
	if b, err := os.ReadFile(marker); err == nil {
		if strings.TrimSpace(string(b)) != layoutMarker {
			return nil, fmt.Errorf("store %s: unknown layout marker %q", root, b)
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(marker, []byte(layoutMarker+"\n"), 0o644); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	s.sameFS = sameDevice(filepath.Join(root, "tmp"), filepath.Join(root, "blobs", "sha256"))
	if !s.sameFS && sameFSKnown {
		return nil, fmt.Errorf("store %s: tmp/ is not on the blob store's filesystem; rename into place would not be atomic", root)
	}
	if err := s.restoreGCAsides(); err != nil {
		return nil, err
	}
	if err := s.sweepTmp(time.Now()); err != nil {
		return nil, err
	}
	if err := s.recover(); err != nil {
		return nil, err
	}
	return s, nil
}

// tmpGrace is how old a temporary must be before Open removes it. Nothing references a temporary (a crash
// between creating it and linking it into place leaves it behind), but the store takes no locks, so another
// process may be writing one right now; the age gate leaves in-flight writes alone. A write stalled longer
// than this loses its temporary and fails at the link (nothing is installed, nothing corrupted).
const tmpGrace = 24 * time.Hour

// sweepTmp removes temporaries last modified before now - tmpGrace. It runs before journal replay; no
// committed state lives in tmp/.
func (s *Store) sweepTmp(now time.Time) error {
	ents, err := os.ReadDir(s.dir("tmp"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		fi, err := e.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if now.Sub(fi.ModTime()) > tmpGrace {
			if err := os.Remove(s.dir("tmp", e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			s.Recovered = append(s.Recovered, RecoveryEvent{What: "removed temporary", Detail: e.Name()})
		}
	}
	return nil
}

// Root is the store's directory.
func (s *Store) Root() string { return s.root }

// Durability returns this store's declaration (§7).
func (s *Store) Durability() Durability {
	d := Durability{FileSync: "fsync", DirSync: "fsync", Rename: "atomic", ExclusiveCreate: "link",
		SameFilesystem: "checked", Locks: "none", GCGrace: DefaultGrace.String(),
		Assumes: "POSIX rename and link semantics; a local filesystem (not NFS)"}
	if s.opt.GCGrace != 0 {
		d.GCGrace = s.opt.GCGrace.String()
	}
	if s.opt.NoSync {
		d.FileSync, d.DirSync = "none", "none"
		d.Assumes += "; process crash only, not power loss"
	}
	if !sameFSKnown {
		d.SameFilesystem = "assumed"
	}
	return d
}

func (s *Store) dir(parts ...string) string {
	return filepath.Join(append([]string{s.root}, parts...)...)
}

func (s *Store) hook(point string) error {
	if s.opt.crash != nil {
		return s.opt.crash(point)
	}
	return nil
}

func (s *Store) syncFile(f *os.File) error {
	if s.opt.NoSync {
		return nil
	}
	return f.Sync()
}

func (s *Store) syncDir(dir string) error {
	if s.opt.NoSync {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// linkExclusive publishes tmp at dst only if dst does not exist (POSIX link(): EEXIST), then removes tmp and
// syncs dst's directory. An existing dst is fs.ErrExist and tmp is left for the caller.
func (s *Store) linkExclusive(tmp, dst string) error {
	if err := os.Link(tmp, dst); err != nil {
		return err
	}
	_ = os.Remove(tmp)
	return s.syncDir(filepath.Dir(dst))
}

// writeExclusive writes b to a temporary file, syncs it, and links it into place at dst create-exclusive.
func (s *Store) writeExclusive(dst string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(s.dir("tmp"), "w-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := s.syncFile(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return s.linkExclusive(tmp.Name(), dst)
}

// quarantine moves p aside under quarantine/<what>-<base>-<n>, never deleting it.
func (s *Store) quarantine(p, what string) error {
	base := filepath.Base(p)
	for n := 0; ; n++ {
		q := s.dir("quarantine", fmt.Sprintf("%s-%s-%d", what, base, n))
		if _, err := os.Lstat(q); errors.Is(err, fs.ErrNotExist) {
			if err := os.Rename(p, q); err != nil {
				return err
			}
			return s.syncDir(filepath.Dir(p))
		}
	}
}
