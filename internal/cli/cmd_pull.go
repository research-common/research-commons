package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// pull <package>: the receiver's ingest of a package (a store tree, in a directory or in a tar archive) into this
// store, under this reader's policy (claims-model note §11): gate.ReadTree reads a directory confined to it, or
// gate.ReadArchive lists a tar archive's members (plain or gzip-compressed; nothing is extracted) under the scan
// limits, into the same package; gate.Pull judges every object, and gate.Commit installs the admitted set as one
// operation (storage note §3.2). Refused objects are reported and never written; what the store already held is
// never touched (C-core-121). A directory and an archive holding the same files give the same report and the
// same store (C-core-04).
//
// An archive that cannot be read to its end within the scan limits (members, total_bytes, expansion_ratio; a
// truncated or corrupt stream) is judged not at all: a package read in part is never judged, so the result is
// exit 3 with the limit named and nothing committed. An archive that reads but is ambiguous (one member name
// twice; bytes after its end) is refused whole: exit 1, nothing committed. A file in any other format (zip, a
// gzip stream that is not a tar, xz, …) does not start (exit 2).
//
// The receiver's policy is the hub policy at this store's root (its limits, not_served and blobs mode; a hub
// clone's own files are its control plane, so they are not applied rather than refused) plus the reader's
// trust floor: the `admission` trust entries of the reader policy (policy.Admit). With no reader policy every
// signer is admitted unlabelled (policy D-1 is undecided; this keeps the round-1 behaviour). --below-floor
// picks refuse or label for a signer the floor does not cover; the default is label, since reader-policy-v1
// has no member for the choice.
//
// Overrides are typed and per object: --override <name>=<path>[,<path>…] admits exactly those objects, and
// only where the refusal is the reader's own policy; there is no blanket force (C-core-121a). The journal
// record names every override that admitted something.

func init() {
	Register(&Command{Name: "pull", Summary: "admit a package (a store tree in a directory or a tar archive) into this store under this reader's policy",
		Args: []Arg{{Name: "package", Shape: ShapeText}},
		Flags: []Flag{
			{Name: "below-floor", Value: "refuse|label", Help: "a statement whose signer the reader policy's admission trust does not cover: refuse it (class reader policy, reason trust floor) or admit it labelled `below trust floor` (default label)",
				Check: func(v string) error {
					if v != "refuse" && v != "label" {
						return errors.New("refuse or label")
					}
					return nil
				}},
			{Name: "override", Value: "name=path[,path…]", Help: "a typed override: admits exactly the named objects (paths in the package) where the refusal is this reader's own policy; never an intrinsic or operational refusal",
				Check: func(v string) error { _, err := parseOverride(v); return err }},
			{Name: "from-checkout", Help: "the package is a git checkout (or an archive of one): a top-level .git entry is transport metadata, not listed to the gate and reported as skipped (never the default; a .git anywhere deeper is still refused)"},
			{Name: "dry-run", Help: "judge the package and print the report; install nothing (no registry change; no fetch; no cache)"},
		},
		Store: true, ReaderPolicy: true, Before: pullBefore,
		Help: "<package> is a directory holding a store tree, or a tar archive of one (.tar, or gzip-compressed .tar.gz; the format is read from the file's first bytes, not its name). An archive is never extracted: its members are judged by name and bytes exactly as a directory's files are, under the scan limits of status --limits; a symlink, hard link, device or other non-regular member, and any name that is absolute or carries `..`, is refused like the same entry in a directory. With --from-checkout (a hub checkout), the top-level .git is skipped as transport metadata and reported once; without it .git is refused. Exit 0 every object admitted (possibly labelled; nothing new is not an error), 1 at least one object refused (the admitted rest is still committed, and the output says so), 2 did not start (no such directory or file, a file that is not a tar archive, a malformed option, an unusable policy), 3 nothing refused and something undecided, an archive not read to its end within the scan limits (nothing judged), or the commit failed after work started. An ambiguous archive (one member name twice, bytes after its end) is refused whole: exit 1, nothing committed.",
		Run:  pullCmd})
}

var reOverrideName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// parseOverride reads one --override value: a name, "=", and a comma-separated list of package paths.
func parseOverride(v string) (gate.Override, error) {
	name, paths, ok := strings.Cut(v, "=")
	if !ok || !reOverrideName.MatchString(name) {
		return gate.Override{}, errors.New("an override is name=path[,path…], the name lowercase letters, digits, - and _")
	}
	o := gate.Override{Name: name}
	for _, p := range strings.Split(paths, ",") {
		if p == "" {
			return gate.Override{}, errors.New("an override names every object it covers; an empty path is not one (there is no blanket override)")
		}
		o.Objects = append(o.Objects, p)
	}
	return o, nil
}

// pullState is what pullBefore found: the package's ingest format ("" for a directory).
type pullState struct{ format string }

func pullBefore(c *Ctx) *Problem {
	dir := c.Args["package"]
	fi, err := os.Stat(dir)
	if err != nil || !(fi.IsDir() || fi.Mode().IsRegular()) {
		peer := dir
		if err != nil {
			peer = err.Error()
		}
		return usage("malformed-argument", "the package cannot be read", "<package> must be an existing directory or a tar archive; nothing was done",
			"argument package", "name the directory holding the package (a store tree), or a tar archive of one", peer)
	}
	if fi.IsDir() {
		if a, _ := filepath.Abs(dir); a == c.Root {
			return usage("malformed-argument", "the package is this store", "pulling a store into itself does nothing; nothing was done",
				"argument package", "name another directory", dir)
		}
		c.state = pullState{}
		return nil
	}
	// a file: its format is read from its first bytes (never from its name), before any work
	head, err := readHead(dir, 64<<10)
	if err != nil {
		return usage("malformed-argument", "the package cannot be read", "<package> must be a readable directory or tar archive; nothing was done",
			"argument package", "check the file is readable", err.Error())
	}
	switch f := store.IngestFormat(head); f {
	case store.FormatTar, store.FormatTarGzip:
		c.state = pullState{format: f}
		return nil
	case "":
		return usage("malformed-argument", "the package is not an archive this tool reads", "a file package must be a tar archive (plain or gzip-compressed); this file is neither; nothing was done",
			"argument package", "give a directory holding a store tree, or a tar archive of one", dir)
	default:
		return usage("malformed-argument", "the package is not an archive this tool reads", "a file package must be a tar archive, plain or gzip-compressed; this file is "+f+"; nothing was done",
			"argument package", "repack the store tree as a tar (tar -cf, or git archive --format=tar), or unpack it and pull the directory", dir)
	}
}

func readHead(p string, n int) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(n)))
	return b, err
}

// trustFloor is the reader policy's admission trust as a gate hook (gate.StatementHook): policy.Admit over the
// statement's signer and the content it names.
type trustFloor struct {
	p     *policy.Policy
	floor policy.Floor
}

func (f trustFloor) Label() bool { return f.floor == policy.FloorLabel }

func (f trustFloor) CheckStatement(st *wire.Statement) *refusal.Refusal {
	a := f.p.Admit(st.Signer, contentOf(st), policy.FloorRefuse)
	if a.Admitted {
		return nil
	}
	return a.Refusal
}

// pullContent gives edition rules the bytes at pull, so a content rule reads what `hub check` reads instead of
// `unchecked (content not held)`: the package's own blobs (the gate has not installed them yet; only a blob whose
// bytes hash to its name is entered, as at hub check) and the blobs this store already holds. An archive is
// walked member by member by the store's scanner under the default scan limits (gate.ScanUnits); any other
// blob is one unit. Nothing is copied: the units share the package's bytes, so memory stays what the package
// read already held plus the members the scanner keeps (bounded by the scan's total_bytes).
type pullContent struct {
	pkg  map[string][]byte
	held prepinContent
}

func newPullContent(pkg gate.Package, st *store.Store) pullContent {
	c := pullContent{pkg: map[string][]byte{}, held: prepinContent{st: st}}
	for _, o := range pkg.Objects {
		if o.Mode != gate.Regular || !strings.HasPrefix(o.Path, "blobs/sha256/") {
			continue
		}
		h := sha256.Sum256(o.Data)
		if d := "sha256:" + hex.EncodeToString(h[:]); gate.BlobPath(d) == o.Path {
			c.pkg[d] = o.Data
		}
	}
	return c
}

func (c pullContent) Units(d string) ([]resolve.ContentUnit, bool) {
	if b, ok := c.pkg[d]; ok {
		return gate.ScanUnits(d, b, store.DefaultLimits()), true
	}
	return c.held.Units(d)
}

// pullSideEffects is the dry run's declaration (claims-model note §13, C-core-137).
const pullSideEffects = "no registry change; no fetch; no cache"

func pullCmd(c *Ctx) (*Obj, int, error) {
	dir := c.Args["package"]
	format := c.state.(pullState).format
	pol := *c.Policy.Hub
	pol.Name = "pull into this store: " + c.Policy.Source
	if c.Policy.Reader != nil {
		floor := policy.FloorLabel
		if v, _ := c.Flag("below-floor"); v == "refuse" {
			floor = policy.FloorRefuse
		}
		pol.Hooks = append(append([]gate.StatementHook{}, pol.Hooks...), trustFloor{c.Policy.Reader, floor})
		pol.Name += " + reader policy " + c.Policy.ReaderSource
		pol.Digest = digestPair(pol.Digest, c.Policy.Reader.Digest)
	}
	var opt gate.Options
	if v, ok := c.Flag("override"); ok {
		o, _ := parseOverride(v)
		opt.Overrides = append(opt.Overrides, o)
	}
	var pkg gate.Package
	var err error
	if format == "" {
		pkg, err = gate.ReadTree(dir, pol.Limits[gate.LimitBlobBytes])
	} else {
		pkg, err = readArchive(dir, pol.Limits[gate.LimitBlobBytes])
	}
	if err != nil {
		var p *Problem
		if errors.As(err, &p) {
			return nil, 0, p
		}
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			return nil, 0, failed(err, "package "+dir, false, "check the package is readable, then pull again")
		}
		return nil, 0, failed(err, "package "+dir, false, "pull again; nothing was committed")
	}
	var skipped listV
	if _, ok := c.Flag("from-checkout"); ok {
		// only the top-level entry named .git (a directory, or the file a linked worktree has); a .git deeper in
		// the tree keeps its path and the gate refuses it as before
		kept := pkg.Objects[:0:0]
		for _, ob := range pkg.Objects {
			if ob.Path == ".git" {
				skipped = append(skipped, textV(".git (transport metadata, --from-checkout)"))
				continue
			}
			kept = append(kept, ob)
		}
		pkg.Objects = kept
	}
	// Edition rules read content as `hub check` does: the package's blobs (by digest, only those whose bytes hash to
	// their name) and, for a blob the package does not carry, the ones this store already holds.
	ropts := []resolve.Option{resolve.WithContent(gate.NewMemoContent(newPullContent(pkg, c.Store), 0))}
	for _, d := range ruleDialects {
		ropts = append(ropts, resolve.WithDialect(d))
	}
	pol.Resolver = append(ropts, pol.Resolver...)
	rep, err := gate.Pull(pkg, gate.StoreHeld{S: c.Store}, &pol, opt)
	if err != nil {
		var d *gate.DidNotStart
		if errors.As(err, &d) {
			return nil, 0, didNotStart(d)
		}
		return nil, 0, failed(err, "package "+dir, false, "pull again; nothing was committed")
	}
	dropUnchangedControlPlane(rep, pkg, c.Root)
	o := gateReport(rep)
	o.set("package", peerV(dir))
	if format != "" {
		o.set("package_format", textV(format))
	}
	if len(skipped) > 0 {
		o.set("skipped", skipped)
	}
	if c.Policy.Reader != nil {
		o.get("policy").(*Obj).set("reader_policy", c.Policy.readerObj())
	}
	o.set("evaluator", evaluatorObj(c.Env.Build))
	if _, dry := c.Flag("dry-run"); dry {
		o.set("side_effects", textV(pullSideEffects))
		return o, gateExit(rep), nil
	}
	out, err := gate.Commit(c.Store, rep)
	if err != nil {
		return nil, 0, failed(err, "store", out.Committed, "run status; if the store is damaged, fsck")
	}
	lines, _ := rep.Admitted()
	if out.Op == "" {
		o.set("side_effects", textV("nothing new to install: no registry change; no fetch; no cache"))
		return o, gateExit(rep), nil
	}
	o.set("operation", refV(out.Op)).set("journal_kind", textV(gate.CommitKind(rep)))
	o.set("side_effects", textV(fmt.Sprintf("committed one operation: %d statement(s) and the admitted blob(s) installed in this store; no fetch; no cache; refused objects were not written", len(lines))))
	if out.NeedsRepair != nil {
		o.set("store_state", tokV(tok("committed, needs repair")))
	}
	return o, gateExit(rep), nil
}

// digestPair is the digest of the pair of policies a pull applied (hub policy, reader policy), so the report
// names one digest that changes when either does.
func digestPair(hub, reader string) string {
	return digestOf([]byte(hub + "\n" + reader + "\n"))
}

// readArchive reads a tar archive package under the scan limits (store.DefaultLimits; status --limits prints
// them), each member bounded as a tree's file is (blob_bytes). A refusal of the archive itself is a Problem: an
// archive not read to its end is exit 3 (the reader's own limit, or a stream that stops; nothing was judged),
// an ambiguous one exit 1 (a decided verdict on the package as a whole). Either way nothing is committed.
func readArchive(path string, maxBytes int64) (gate.Package, error) {
	lim := store.DefaultLimits()
	f, err := os.Open(path)
	if err != nil {
		return gate.Package{}, err
	}
	defer f.Close()
	bound := store.MaxArchiveFileBytes(lim)
	data, err := io.ReadAll(io.LimitReader(f, bound+1))
	if err != nil {
		return gate.Package{}, err
	}
	scope := "package " + path
	if int64(len(data)) > bound {
		return gate.Package{}, &Problem{Slug: "refused", Title: "refused: " + refusal.SizeLimit, Class: refusal.Operational, Scope: scope,
			Detail: fmt.Sprintf("the archive is larger than the scan limits allow (archive_bytes=%d: scan.total_bytes plus per-member overhead for scan.members); nothing in it was judged and nothing was committed", bound),
			Next:   "split the package into smaller archives, or pull it as a directory", Exit: ExitCouldNot}
	}
	pkg, _, err := gate.ReadArchive(data, maxBytes, lim)
	if err == nil {
		return pkg, nil
	}
	var r *refusal.Refusal
	if !errors.As(err, &r) {
		return gate.Package{}, err
	}
	p := &Problem{Slug: "refused", Title: "refused: " + r.Reason, Class: r.Class, Scope: scope, Peer: r.Detail}
	if r.Class == refusal.Intrinsic {
		p.Detail = "the archive is refused whole: it does not read as one package every reader agrees on; nothing in it was judged and nothing was committed"
		p.Next = "repack the store tree as a fresh tar archive (one member per path, nothing after its end)"
		p.Exit = ExitWrong
	} else {
		p.Detail = "the archive was not read to its end (a scan limit, or a truncated or corrupt stream); a package read in part is never judged, so nothing in it was judged and nothing was committed"
		p.Next = "if a limit is named, split the package; if the archive is truncated, fetch it again"
		p.Exit = ExitCouldNot
	}
	return gate.Package{}, p
}

// dropUnchangedControlPlane removes from a pull's report the control-plane objects that are byte-identical to the
// receiver's own file at the same path (the store marker of a fresh store, a hub's README the receiver already
// holds): there is nothing for a maintainer to review, so the report does not ask. A control-plane object that
// differs, or that the receiver does not have, is kept as "not applied".
func dropUnchangedControlPlane(rep *gate.Report, pkg gate.Package, root string) {
	data := map[string][]byte{}
	for _, ob := range pkg.Objects {
		if ob.Mode == gate.Regular && ob.Change != gate.Delete {
			data[ob.Path] = ob.Data
		}
	}
	kept := rep.Results[:0:0]
	for _, r := range rep.Results {
		if r.Kind == gate.KindControlPlane || r.Kind == gate.KindMarker {
			if in, ok := data[r.Path]; ok && r.Verdict == gate.NotApplied {
				fp := filepath.Join(root, filepath.FromSlash(r.Path))
				if fi, err := os.Lstat(fp); err == nil && fi.Mode().IsRegular() {
					if mine, err := os.ReadFile(fp); err == nil && bytes.Equal(mine, in) {
						continue
					}
				}
			}
		}
		kept = append(kept, r)
	}
	rep.Results = kept
}
