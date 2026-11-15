package hubcheck

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/resolve"
)

// The sender's side of `push` (storage note §4.5: a hub kept in a version-control repository receives a package
// as the change between a base revision and the change's head). The store is the hub checkout, and the change is
// read exactly as `hub check` reads it, through Prepare, then judged by gate.Push: the receiving hub's history at
// the base and its policy as it is there. Nothing here writes, fetches or transports.

// PushConfig is one push's own choices.
type PushConfig struct {
	// Remote names the git remote the hub is ("origin" by default in the CLI).
	Remote string
	// Base is the revision the change is judged against; "" means the remote's default branch as this checkout
	// last saw it (refs/remotes/<remote>/HEAD).
	Base string
	// Resolver adds the reader's verifiers, as Config.Resolver.
	Resolver []resolve.Option
}

// PushPlan is what a push would carry and the hub's verdict on it.
type PushPlan struct {
	*Result
	Remote string
	// BaseFrom says where the base came from: "--base" or the remote's default branch ref.
	BaseFrom string
	// Uncommitted lists data-surface paths (blobs/, statements/) present or changed in the working tree but not in
	// HEAD: they are not part of the change, so a push would not carry them.
	Uncommitted []string
	// Held is the hub's history at the base (the receiver's held set).
	Held gate.MemHeld
}

// PlanPush reads the change a push from the hub checkout containing dir would carry and runs gate.Push over it.
// The store must be the checkout itself (its rc-store marker at the repository's top level), and the remote must
// exist. Its errors are Check's: *gate.DidNotStart when the push cannot start (exit 2), another error when git
// failed.
func PlanPush(dir string, cfg PushConfig) (*PushPlan, error) {
	root, err := FindRoot(dir)
	if err != nil {
		var d *gate.DidNotStart
		if errors.As(err, &d) {
			d.Title, d.Next = "not inside a hub checkout", "run push from inside a git checkout of the hub; to send a store kept elsewhere, pull it into a hub checkout first (commons pull <store>)"
		}
		return nil, err
	}
	r := newRepo(root)
	top, err := r.git(nil, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, &gate.DidNotStart{Title: "the store is not a git checkout", Detail: err.Error(), Scope: "store " + root,
			Next: "push sends a change of a hub's git checkout: clone the hub, pull this store into the clone (commons pull <store>) and push from there"}
	}
	if !sameDir(strings.TrimSpace(string(top)), root) {
		return nil, &gate.DidNotStart{Title: "the store is not the checkout's top level",
			Detail: "the rc-store marker is in " + root + ", the git checkout's top level is " + strings.TrimSpace(string(top)), Scope: "store " + root,
			Next: "push from a hub checkout whose top level holds rc-store; pull this store into one (commons pull <store>)"}
	}
	remote := cfg.Remote
	if remote == "" || strings.HasPrefix(remote, "-") || strings.ContainsAny(remote, " \t\n/:\\") {
		return nil, &gate.DidNotStart{Title: "not a remote name", Detail: "a remote name is non-empty, does not start with -, and holds no space, slash or colon", Scope: "option --remote",
			Next: "name a remote of this checkout (git remote)"}
	}
	if out, err := r.git(nil, "config", "--get", "remote."+remote+".url"); err != nil || len(bytes.TrimSpace(out)) == 0 {
		return nil, &gate.DidNotStart{Title: "no such remote", Detail: "this checkout has no remote named " + remote, Scope: "option --remote",
			Next: "name a remote of this checkout (git remote), or add the hub as one"}
	}
	plan := &PushPlan{Remote: remote, BaseFrom: "--base"}
	base := cfg.Base
	if base == "" {
		ref := "refs/remotes/" + remote + "/HEAD"
		if _, err := r.commit(ref); err != nil {
			return nil, &gate.DidNotStart{Title: "the hub's default branch is not known here",
				Detail: ref + " is not set in this checkout", Scope: "option --base",
				Next: "name the hub branch the change is for with --base " + remote + "/<branch>, or record the default with git remote set-head " + remote + " --auto"}
		}
		base, plan.BaseFrom = ref, ref
	}
	p, err := prepareAt(r, root, Config{Base: base, Resolver: cfg.Resolver})
	if err != nil {
		return nil, err
	}
	rep, err := gate.Push(p.Package, p.Held, p.Policy, gate.Options{})
	if err != nil {
		return nil, err
	}
	plan.Result, plan.Held = p.result(rep), p.Held
	if plan.Uncommitted, err = uncommitted(r); err != nil {
		return nil, err
	}
	return plan, nil
}

// uncommitted lists the data-surface paths (under blobs/ and statements/) where the working tree and HEAD differ:
// a file HEAD lacks, a file whose bytes are not HEAD's object, a HEAD file the working tree lacks. Sorted. It reads
// the files and compares git object ids computed here (no `git status`: nothing runs a filter, a hook or an
// fsmonitor, and nothing touches the index).
func uncommitted(r *repo) ([]string, error) {
	f, err := r.git(nil, "rev-parse", "--show-object-format")
	if err != nil {
		return nil, err
	}
	format := strings.TrimSpace(string(f))
	es, err := r.tree("HEAD")
	if err != nil {
		return nil, err
	}
	inHead := map[string]entry{}
	for _, e := range es {
		if strings.HasPrefix(e.path, "blobs/") || strings.HasPrefix(e.path, "statements/") {
			inHead[e.path] = e
		}
	}
	var ps []string
	seen := map[string]bool{}
	for _, top := range []string{"blobs", "statements"} {
		err := filepath.WalkDir(filepath.Join(r.dir, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(r.dir, p)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			seen[rel] = true
			e, ok := inHead[rel]
			if !ok || !d.Type().IsRegular() || modeOf(e.mode) != gate.Regular {
				ps = append(ps, rel)
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if gitBlobID(format, b) != e.oid {
				ps = append(ps, rel)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for p := range inHead {
		if !seen[p] {
			ps = append(ps, p)
		}
	}
	slices.Sort(ps)
	return ps, nil
}

// gitBlobID is git's object id of a blob with these bytes, in the repository's object format.
func gitBlobID(format string, b []byte) string {
	hdr := "blob " + strconv.Itoa(len(b)) + "\x00"
	if format == "sha256" {
		h := sha256.New()
		h.Write([]byte(hdr))
		h.Write(b)
		return hex.EncodeToString(h.Sum(nil))
	}
	h := sha1.New()
	h.Write([]byte(hdr))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func sameDir(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	if err1 != nil || err2 != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return ra == rb
}
