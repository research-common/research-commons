package cli

import (
	"os"
	"path/filepath"

	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/store"
)

// init: create a store. It is the one command that makes a store; every other command refuses a directory
// without the marker (the read commands never create one). It creates the directory when it is missing,
// refuses a non-empty directory that is not already a store of this layout, and is idempotent on one that is.
// The store package makes the layout (directories and the rc-store marker); this command never builds paths of
// its own.

func init() {
	Register(&Command{Name: "init", Summary: "create a store in a directory (default: the working directory)",
		Args:   []Arg{{Name: "dir", Shape: ShapeText, Optional: true}},
		Before: initBefore,
		Help:   "Creates the directory if needed and the store layout inside it (marker " + "rc-store" + ", layout " + "rc-store/1" + "). A directory that already holds a store of this layout is left as it is and the command exits 0 saying so; a non-empty directory that is not a store is refused and nothing is written. Creates no key: the next step is commons key new --out <file>.",
		Run:    initCmd})
}

func initDir(c *Ctx) (string, error) {
	d, ok := c.Args["dir"]
	if !ok {
		wd, err := c.Env.Getwd()
		if err != nil {
			return "", err
		}
		return wd, nil
	}
	return filepath.Abs(d)
}

func initBefore(c *Ctx) *Problem {
	dir, err := initDir(c)
	if err != nil {
		return usage("malformed-argument", "the directory could not be resolved", "nothing was done", "argument dir", "give a directory path", c.Args["dir"])
	}
	fi, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil // created by Run
	}
	if err != nil {
		return usage("not-a-directory", "the directory could not be read", "nothing was done", "argument dir", "give a directory you can read and write", dir)
	}
	if !fi.IsDir() {
		return usage("not-a-directory", "the path is not a directory", "nothing was done", "argument dir", "give a directory path", dir)
	}
	switch cerr := store.CheckMarker(dir); {
	case cerr == nil:
		return nil
	case cerr != store.ErrNoMarker:
		p := usage("not-a-store", "the directory has an rc-store marker this tool cannot use",
			"the marker is not a regular file or names a layout other than "+store.Layout()+"; nothing was done", "argument dir",
			"choose another directory", dir)
		p.Class = refusal.Operational
		return p
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return usage("not-a-directory", "the directory could not be read", "nothing was done", "argument dir", "give a directory you can read and write", dir)
	}
	if len(ents) > 0 {
		p := usage("directory-not-empty", "the directory is not empty and is not a store",
			"a store is created only in a new or empty directory; nothing was written", "argument dir",
			"choose a new or empty directory", dir)
		p.Class = refusal.Operational
		return p
	}
	return nil
}

func initCmd(c *Ctx) (*Obj, int, error) {
	dir, _ := initDir(c)
	existing := store.CheckMarker(dir) == nil
	if !existing {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, 0, failed(err, "argument dir", false, "check the path and its permissions")
		}
		s, err := store.Open(dir, store.Options{})
		if err != nil {
			return nil, 0, failed(err, "argument dir", false, "check the path and its permissions")
		}
		_ = s
	}
	state := "created"
	said := "created a store"
	if existing {
		state, said = "existing", "already a store of this layout; nothing changed"
	}
	return newObj().set("store", peerV(dir)).set("layout", refV(store.Layout())).set("result", textV(state)).set("detail", textV(said)).
		set("next", textV("generate a signing key with commons key new --out <file>, then give --key <file> or "+KeyEnv+" to every signing command")), ExitOK, nil
}
