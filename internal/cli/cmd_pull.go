package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// pull <dir>: the receiver's ingest of a package (a store tree in a directory) into this store, under this
// reader's policy (claims-model note §11): gate.ReadTree reads the tree confined to <dir>, gate.Pull judges
// every object, and gate.Commit installs the admitted set as one operation (storage note §3.2). Refused
// objects are reported and never written; what the store already held is never touched (C-core-121).
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
	Register(&Command{Name: "pull", Summary: "admit a package (a store tree in a directory) into this store under this reader's policy",
		Args: []Arg{{Name: "dir", Shape: ShapeText}},
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
			{Name: "from-checkout", Help: "the package is a git checkout: a top-level .git entry is transport metadata, not listed to the gate and reported as skipped (never the default; a .git anywhere deeper is still refused)"},
			{Name: "dry-run", Help: "judge the package and print the report; install nothing (no registry change; no fetch; no cache)"},
		},
		Store: true, ReaderPolicy: true, Before: pullBefore,
		Help: "With --from-checkout (a hub checkout), the top-level .git is skipped as transport metadata and reported once; without it .git is refused. Exit 0 every object admitted (possibly labelled; nothing new is not an error), 1 at least one object refused (the admitted rest is still committed, and the output says so), 2 did not start (no such directory, a malformed option, an unusable policy), 3 nothing refused and something undecided, or the commit failed after work started.",
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

func pullBefore(c *Ctx) *Problem {
	dir := c.Args["dir"]
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		peer := dir
		if err != nil {
			peer = err.Error()
		}
		return usage("malformed-argument", "the package directory cannot be read", "<dir> must be an existing directory; nothing was done",
			"argument dir", "name the directory holding the package (a store tree)", peer)
	}
	if a, _ := filepath.Abs(dir); a == c.Root {
		return usage("malformed-argument", "the package is this store", "pulling a store into itself does nothing; nothing was done",
			"argument dir", "name another directory", dir)
	}
	return nil
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

// pullSideEffects is the dry run's declaration (claims-model note §13, C-core-137).
const pullSideEffects = "no registry change; no fetch; no cache"

func pullCmd(c *Ctx) (*Obj, int, error) {
	dir := c.Args["dir"]
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
	pkg, err := gate.ReadTree(dir, pol.Limits[gate.LimitBlobBytes])
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			return nil, 0, failed(err, "package "+dir, false, "check the directory is readable, then pull again")
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
	rep, err := gate.Pull(pkg, gate.StoreHeld{S: c.Store}, &pol, opt)
	if err != nil {
		var d *gate.DidNotStart
		if errors.As(err, &d) {
			return nil, 0, didNotStart(d)
		}
		return nil, 0, failed(err, "package "+dir, false, "pull again; nothing was committed")
	}
	o := gateReport(rep)
	o.set("package", peerV(dir))
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
