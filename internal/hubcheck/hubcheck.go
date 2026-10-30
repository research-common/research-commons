// Package hubcheck is `hub check` as a library: a hub's CI over one change in a git repository (the hub
// template's CLI contract, H-03 and H-10 to H-36). It reads the repository through git plumbing only and
// passes the change to gate.HubCheck, the same validation core `pull`, `push` and the pre-pin check call:
// what differs is that the held history is the tree at the base revision and the policy is the hub policy
// file as it is at the base revision, read from the object database, never from the change (claims-model
// note §11, C-core-115).
//
// Nothing here writes, caches, fetches or runs anything from the repository.
package hubcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// PolicyFile is the hub policy file's path at the repository root.
const PolicyFile = "hub-policy.json"

// Config is the reader's own configuration for a check: never read from the hub.
type Config struct {
	// Base is the revision the change is checked against ("" = a full check of the tree at HEAD).
	Base string
	// Resolver adds the reader's verifiers (rule dialects, segment re-check) used to re-apply edition rules
	// and series boundaries. Edition rules read blob bytes from the evaluated tree unless one of these
	// options sets a content reader of its own.
	Resolver []resolve.Option
	// Overrides are typed per-object overrides (gate.Override); CI normally passes none.
	Overrides []gate.Override
}

// Result is a check's report plus what it ran against.
type Result struct {
	*gate.Report
	Root string
	// Head, Base and MergeBase are full commit ids (Base and MergeBase "" for a full check).
	Head, Base, MergeBase string
	// PolicyRev is the commit the policy was read from; PolicyAbsent says the file was absent there.
	PolicyRev    string
	PolicyAbsent bool
}

// SideEffects is the dry-run declaration every check prints (claims-model note §13; H-14).
const SideEffects = "no registry change; no fetch; no cache"

// FindRoot returns the nearest ancestor of dir (dir included) holding the `rc-store` marker, or a
// *gate.DidNotStart (H-10).
func FindRoot(dir string) (string, error) {
	d, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if fi, err := os.Lstat(filepath.Join(d, "rc-store")); err == nil && fi.Mode().IsRegular() {
			return d, nil
		}
		up := filepath.Dir(d)
		if up == d {
			return "", &gate.DidNotStart{Title: "not inside a hub", Detail: "no rc-store marker in " + dir + " or any directory above it",
				Scope: "working directory", Next: "run the check from inside a hub checkout"}
		}
		d = up
	}
}

// Check runs `hub check` in the hub containing dir. Every condition about the change is a verdict in the
// report; the error is non-nil only when the check did not start (*gate.DidNotStart: no hub root, unknown
// layout, base not a commit, unusable policy file at the policy revision; the CLI maps it to exit 2), or when
// git itself failed.
func Check(dir string, cfg Config) (*Result, error) {
	root, err := FindRoot(dir)
	if err != nil {
		return nil, err
	}
	r := newRepo(root)
	head, err := r.commit("HEAD")
	if err != nil {
		return nil, &gate.DidNotStart{Title: "no commit at HEAD", Detail: err.Error(), Scope: "repository " + root, Next: "commit the change to check"}
	}
	res := &Result{Root: root, Head: head, PolicyRev: head}
	if cfg.Base != "" {
		base, err := r.commit(cfg.Base)
		if err != nil {
			return nil, &gate.DidNotStart{Title: "--base is not a commit here", Detail: err.Error(), Scope: "argument --base", Next: "fetch the base branch, or name a commit of this repository"}
		}
		mb, err := r.mergeBase(base, head)
		if err != nil {
			return nil, &gate.DidNotStart{Title: "no merge base", Detail: err.Error(), Scope: "argument --base", Next: "name a base that shares history with HEAD"}
		}
		res.Base, res.MergeBase, res.PolicyRev = base, mb, base
	}
	if err := checkMarker(r, res.PolicyRev); err != nil {
		return nil, err
	}
	raw, err := r.fileAt(res.PolicyRev, PolicyFile)
	if err != nil {
		return nil, &gate.DidNotStart{Title: "hub policy file unreadable", Detail: err.Error(), Scope: "policy file " + PolicyFile + " at " + res.PolicyRev, Next: "fix hub-policy.json through the repository's own review"}
	}
	res.PolicyAbsent = raw == nil
	pol, err := gate.ParseHubPolicy(raw, res.PolicyRev)
	if err != nil {
		return nil, err
	}

	var pkg gate.Package
	var held gate.MemHeld
	var content treeContent
	if cfg.Base == "" {
		pkg, content, err = treePackage(r, head)
		held = gate.MemHeld{Lines: map[string][]byte{}, Blobs: map[string]bool{}}
	} else {
		var baseContent treeContent
		held, baseContent, err = heldAt(r, res.Base)
		if err == nil {
			pkg, content, err = changePackage(r, res.MergeBase, head)
			for d, b := range baseContent {
				content[d] = b
			}
		}
	}
	if err != nil {
		return nil, err
	}
	pol.Resolver = append([]resolve.Option{resolve.WithContent(content)}, cfg.Resolver...)
	rep, err := gate.HubCheck(pkg, held, pol, gate.Options{Overrides: cfg.Overrides, Audit: cfg.Base == ""})
	if err != nil {
		return nil, err
	}
	res.Report = rep
	return res, nil
}

// checkMarker requires the marker at rev to name the layout this tool implements (H-10).
func checkMarker(r *repo, rev string) error {
	m, err := r.fileAt(rev, "rc-store")
	switch {
	case err != nil:
		return &gate.DidNotStart{Title: "rc-store marker unreadable", Detail: err.Error(), Scope: "rc-store at " + rev}
	case m == nil:
		return &gate.DidNotStart{Title: "not a hub at " + rev, Detail: "no rc-store marker in the tree", Scope: "rc-store at " + rev,
			Next: "an alpha-format hub needs the alpha tool; a next-format hub carries rc-store"}
	case strings.TrimSuffix(string(m), "\n") != gate.LayoutMarker:
		return &gate.DidNotStart{Title: "unknown layout", Detail: fmt.Sprintf("rc-store names a layout this tool does not implement (%d bytes)", len(m)),
			Scope: "rc-store at " + rev, Next: "use a tool that implements this hub's layout"}
	}
	return nil
}

func modeOf(m string) gate.Mode {
	switch m {
	case "100644", "100755":
		return gate.Regular
	case "120000":
		return gate.Symlink
	}
	return gate.Other
}

// treeContent is the blob bytes of an evaluated tree, by digest, for edition rules that read content. Only
// blobs whose bytes hash to their name are entered.
type treeContent map[string][]byte

func (c treeContent) Units(d string) ([]resolve.ContentUnit, bool) {
	b, ok := c[d]
	if !ok {
		return nil, false
	}
	return []resolve.ContentUnit{{Name: d, Data: b}}, true
}

func (c treeContent) add(path string, b []byte) {
	if !strings.HasPrefix(path, "blobs/sha256/") {
		return
	}
	h := sha256.Sum256(b)
	if d := "sha256:" + hex.EncodeToString(h[:]); gate.BlobPath(d) == path {
		c[d] = b
	}
}

// readEntries reads the regular files among es.
func readEntries(r *repo, es []entry) (map[string][]byte, error) {
	var oids []string
	for _, e := range es {
		if e.typ == "blob" && modeOf(e.mode) == gate.Regular {
			oids = append(oids, e.oid)
		}
	}
	return r.blobs(oids)
}

// treePackage is the whole tree at rev as a package.
func treePackage(r *repo, rev string) (gate.Package, treeContent, error) {
	es, err := r.tree(rev)
	if err != nil {
		return gate.Package{}, nil, err
	}
	data, err := readEntries(r, es)
	if err != nil {
		return gate.Package{}, nil, err
	}
	pkg := gate.Package{Tree: true}
	content := treeContent{}
	for _, e := range es {
		o := gate.Object{Path: e.path, Mode: modeOf(e.mode)}
		if e.typ != "blob" {
			o.Mode = gate.Other
		}
		if o.Mode == gate.Regular {
			o.Data = data[e.oid]
			content.add(e.path, o.Data)
		}
		pkg.Objects = append(pkg.Objects, o)
	}
	return pkg, content, nil
}

// heldAt is the data surface of the tree at rev: its statements (those wire.Read accepts under their id, at
// their signer's path) and its blobs (regular files whose bytes hash to their name). Nothing else in the tree is
// history, so a corrupt blob or an unreadable statement file at the base held nothing and may be removed or
// replaced (gate: not held).
func heldAt(r *repo, rev string) (gate.MemHeld, treeContent, error) {
	h := gate.MemHeld{Lines: map[string][]byte{}, Blobs: map[string]bool{}}
	es, err := r.tree(rev)
	if err != nil {
		return h, nil, err
	}
	var keep []entry
	for _, e := range es {
		if strings.HasPrefix(e.path, "statements/") || strings.HasPrefix(e.path, "blobs/sha256/") {
			keep = append(keep, e)
		}
	}
	data, err := readEntries(r, keep)
	if err != nil {
		return h, nil, err
	}
	content := treeContent{}
	for _, e := range keep {
		b, ok := data[e.oid]
		if !ok {
			continue
		}
		if strings.HasPrefix(e.path, "blobs/sha256/") {
			// held only when the bytes are the blob the name says: a corrupt file holds nothing
			if sum := sha256.Sum256(b); gate.BlobPath("sha256:"+hex.EncodeToString(sum[:])) == e.path {
				h.Blobs["sha256:"+e.path[len("blobs/sha256/"):]] = true
				content.add(e.path, b)
			}
			continue
		}
		if st, err := wire.Read(b); err == nil && gate.StatementPath(st.Signer, st.ID) == e.path {
			h.Lines[st.ID] = b
		}
	}
	return h, content, nil
}

// changePackage is the change from mergeBase to head as a package (H-11): every path that differs, added,
// modified or deleted, with the new bytes for added and modified paths.
func changePackage(r *repo, mergeBase, head string) (gate.Package, treeContent, error) {
	cs, err := r.diff(mergeBase, head)
	if err != nil {
		return gate.Package{}, nil, err
	}
	var oids []string
	for _, c := range cs {
		if c.status != "D" && modeOf(c.newMode) == gate.Regular {
			oids = append(oids, c.newOID)
		}
	}
	data, err := r.blobs(oids)
	if err != nil {
		return gate.Package{}, nil, err
	}
	var pkg gate.Package
	content := treeContent{}
	for _, c := range cs {
		if modeOnly(c) {
			continue
		}
		o := gate.Object{Path: c.path}
		switch c.status {
		case "A":
			o.Change, o.Mode = gate.Add, modeOf(c.newMode)
		case "D":
			o.Change, o.Mode = gate.Delete, modeOf(c.oldMode)
		case "M", "T":
			o.Change, o.Mode = gate.Modify, modeOf(c.newMode)
		default:
			return gate.Package{}, nil, errors.New("diff: unexpected status " + c.status + " for " + c.path)
		}
		if c.status != "D" && o.Mode == gate.Regular {
			o.Data = data[c.newOID]
			content.add(c.path, o.Data)
		}
		pkg.Objects = append(pkg.Objects, o)
	}
	return pkg, content, nil
}

// modeOnly reports a change that only flips git's executable bit on a data-surface file: the same object id,
// both modes regular (100644, 100755). A store file is its bytes; the contract asks data files to be regular
// files and says nothing of the executable bit (an added 100755 blob is admitted alike), so such a change
// changes nothing held and is not part of the package. A change to or from any other mode (a symlink, a
// submodule) stays in, and the gate refuses it as an unsafe path. Control-plane paths always stay in: a
// maintainer reviews every change to them.
func modeOnly(c change) bool {
	if c.status != "M" && c.status != "T" {
		return false
	}
	if !strings.HasPrefix(c.path, "blobs/") && !strings.HasPrefix(c.path, "statements/") {
		return false
	}
	return c.oldOID == c.newOID && modeOf(c.oldMode) == gate.Regular && modeOf(c.newMode) == gate.Regular
}

// Render is the human output (H-50): the report, then the revisions and the side-effects line.
func (r *Result) Render() string {
	var b strings.Builder
	b.WriteString(r.Report.Render())
	if r.Base != "" {
		fmt.Fprintf(&b, "change %s..%s (base %s)\n", r.MergeBase, r.Head, r.Base)
	} else {
		fmt.Fprintf(&b, "full check of %s\n", r.Head)
	}
	return b.String()
}
