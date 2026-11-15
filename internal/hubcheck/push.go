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

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// The sender's side of `push` (storage note §4.5: a hub kept in a version-control repository receives a package
// as the change between a base revision and the change's head). The store is the hub checkout, and the change is
// read exactly as `hub check` reads it, through Prepare, then judged by gate.Push: the receiving hub's history at
// the base and its policy as it is there. Nothing here writes, fetches or transports; Send (transport.go) is the
// one step that does, and only on the caller's word.

// PushConfig is one push's own choices.
type PushConfig struct {
	// Remote names the git remote the hub is ("origin" by default in the CLI).
	Remote string
	// Base is the revision the change is judged against; "" means the remote's default branch as this checkout
	// last saw it (refs/remotes/<remote>/HEAD).
	Base string
	// Branch names the remote branch the change goes to (refs/heads/<Branch>); "" means the base's branch, when the
	// base is a branch of Remote.
	Branch string
	// Transport says the caller will Send the plan: a branch that cannot be determined is then a did-not-start.
	Transport bool
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
	// Branch is the remote branch Send would update (refs/heads/<Branch>), "" when it is not determined (a dry run
	// only); BranchFrom says where it came from: "--branch" or the base's remote-tracking ref.
	Branch, BranchFrom string

	pkg  gate.Package
	repo *repo
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
	if err := plan.chooseBranch(r, cfg, base); err != nil {
		return nil, err
	}
	p, err := prepareAt(r, root, Config{Base: base, Resolver: cfg.Resolver})
	if err != nil {
		return nil, err
	}
	// the options hub check passes for a change: push previews that answer, labels included
	rep, err := gate.Push(p.Package, p.Held, p.Policy, gate.Options{ActorLabels: true})
	if err != nil {
		return nil, err
	}
	plan.Result, plan.Held, plan.pkg, plan.repo = p.result(rep), p.Held, p.Package, r
	if plan.Uncommitted, err = uncommitted(r); err != nil {
		return nil, err
	}
	return plan, nil
}

// chooseBranch sets the branch a push updates: --branch, else the base's own branch when the base is a branch of the
// remote pushed to (refs/remotes/<remote>/<branch>, or refs/remotes/<remote>/HEAD's target). Anything else (a base
// that is a commit id, a tag, a local branch, another remote's branch) determines nothing: guessing would update
// a branch the user never named. Without a branch a transport does not start; a dry run says so.
func (pl *PushPlan) chooseBranch(r *repo, cfg PushConfig, base string) error {
	if cfg.Branch != "" {
		pl.Branch, pl.BranchFrom = cfg.Branch, "--branch"
	} else if out, err := r.git(nil, "rev-parse", "--symbolic-full-name", base); err == nil {
		full := strings.TrimSpace(string(out))
		prefix := "refs/remotes/" + pl.Remote + "/"
		if b, ok := strings.CutPrefix(full, prefix); ok && b != "HEAD" && b != "" {
			pl.Branch, pl.BranchFrom = b, full
		}
	}
	if pl.Branch == "" {
		if cfg.Transport {
			return &gate.DidNotStart{Title: "the branch to push to is not known", Scope: "option --branch",
				Detail: "the base " + base + " is not a branch of the remote " + pl.Remote + ", so it names no branch to update there",
				Next:   "name the branch with --branch <name> (a branch of the hub or of your fork, then open a pull request), or base the change on a branch of " + pl.Remote + " (--base " + pl.Remote + "/<branch>)"}
		}
		return nil
	}
	if !BranchName(pl.Branch) {
		return &gate.DidNotStart{Title: "not a branch name", Detail: pl.Branch + " is not a valid branch name", Scope: "option --branch", Next: "name a branch: --branch <name>"}
	}
	if _, err := r.git(nil, "check-ref-format", "refs/heads/"+pl.Branch); err != nil {
		return &gate.DidNotStart{Title: "not a branch name", Detail: "git does not accept refs/heads/" + pl.Branch + " as a ref name", Scope: "option --branch", Next: "name a branch: --branch <name>"}
	}
	return nil
}

// BranchName is the static half of a branch name's check (git check-ref-format is the other): a short name, so the
// refspec is <sha>:refs/heads/<name>, never a pattern, a deletion or anything git would read as an option.
func BranchName(b string) bool {
	return b != "" && b != "HEAD" && !strings.HasPrefix(b, "-") && !strings.HasPrefix(b, "+") && !strings.HasPrefix(b, "refs/") &&
		!strings.ContainsAny(b, " \t\n:*?[\\^~") && !strings.Contains(b, "@{")
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

// The writer's transport preconditions (bitcoin-time note §2, §10; storage note §3.2; claims-model note §7, §11).
// They are not admission verdicts and no other gate applies them: they protect the author's own priority and the
// author's own commitment to withhold, and a transport outside the tool bypasses them at the author's cost.

// AnchorRow is the anchor precondition's answer for one statement the push would carry.
type AnchorRow struct {
	Path, ID, Kind string
	// Standing is btctime.AnchorRequired or btctime.AnchorNone; DecidedBy names the rule or the override.
	Standing  btctime.AnchorDefault
	DecidedBy string
	// CoveredBy lists the anchors lines (carried or held by the hub) that cover the statement.
	CoveredBy []string
	// Refused: required and not covered. The push carries nothing while any row is refused.
	Refused bool
}

// WithheldRow is a blob the push would carry whose availability a statement declares withheld, with no serving
// `holds` (no reveal) in the hub's history or the change.
type WithheldRow struct {
	Path, Digest string
	// By lists the statements declaring it withheld.
	By []string
}

// Preconditions is the precondition half of a push plan.
type Preconditions struct {
	Anchors  []AnchorRow
	Withheld []WithheldRow
	Warnings []string
}

// Refused reports whether any precondition refuses the push.
func (p *Preconditions) Refused() bool {
	for _, a := range p.Anchors {
		if a.Refused {
			return true
		}
	}
	return len(p.Withheld) > 0
}

// carried lists the statements and blobs the push would carry: admitted additions the hub does not already hold.
func (pl *PushPlan) carried(objs map[string][]byte) (sts []carriedStatement, blobs []gate.Result) {
	for _, x := range pl.Report.Results {
		if x.Verdict != gate.Admitted || x.Change != gate.Add {
			continue
		}
		switch x.Kind {
		case gate.KindStatement:
			if x.HasLabel(gate.LabelAlreadyHeld) {
				continue
			}
			if st, err := wire.ReadStored(objs[x.Path]); err == nil {
				sts = append(sts, carriedStatement{x.Path, st})
			}
		case gate.KindBlob:
			if !pl.Held.HasBlob(x.ID) {
				blobs = append(blobs, x)
			}
		}
	}
	return sts, blobs
}

type carriedStatement struct {
	path string
	st   *wire.Statement
}

// CheckPreconditions applies the writer's preconditions to what the push would carry, over the evaluated set (the
// hub's history at the base plus the carried statements). override, when set, replaces the default by standing
// for every statement (the author's local policy, bitcoin-time note §2 step 3).
//
// The anchor precondition: a statement whose standing requires an anchor is refused unless an `anchors` line by
// its signer in the evaluated set covers it (resolve.CoveringAnchors: structural, a pending proof covers; an
// anchor operation that never reached a commit is not in the evaluated set, so it is absent). A statement whose
// standing is `anchor: none` and that nothing covers is carried with a warning naming the rule. An `anchors` line
// is the time evidence itself and gets a row, never a warning.
//
// The withheld precondition: a carried blob that a statement of the evaluated set declares withheld
// (availability.redistribution) while no serving `holds` for it is in the evaluated set is refused: carrying it
// would release the bytes the author committed to withhold, and that cannot be walked back.
//
// A carried anchors line whose proof blob neither travels nor is held by the hub is a warning: the line still
// fixes the order in the log, and readers see `missing-proof` until the proof is held.
func (pl *PushPlan) CheckPreconditions(override btctime.AnchorDefault) *Preconditions {
	objs := map[string][]byte{}
	for _, o := range pl.pkg.Objects {
		objs[o.Path] = o.Data
	}
	sts, blobs := pl.carried(objs)
	ks := keylog.NewStoredStore()
	for _, id := range sortedKeys(pl.Held.Lines) {
		_, _ = ks.Log(signerOf(pl.Held.Lines[id])).Add(pl.Held.Lines[id])
	}
	for _, c := range sts {
		_, _ = ks.Log(c.st.Signer).Add(c.st.Line())
	}
	res := resolve.New(ks)
	out := &Preconditions{}
	carriedBlobs := map[string]bool{}
	for _, b := range blobs {
		carriedBlobs[b.ID] = true
	}
	for _, c := range sts {
		std, why := btctime.DefaultFor(c.st)
		if override != "" {
			std, why = override, "--anchor-policy "+anchorPolicyWord(override)+" (your local policy, replacing the default by standing)"
		}
		row := AnchorRow{Path: c.path, ID: c.st.ID, Kind: c.st.Kind, Standing: std, DecidedBy: why, CoveredBy: res.CoveringAnchors(c.st.ID)}
		row.Refused = std == btctime.AnchorRequired && len(row.CoveredBy) == 0
		out.Anchors = append(out.Anchors, row)
		if std == btctime.AnchorNone && len(row.CoveredBy) == 0 && c.st.Kind != "anchors" {
			out.Warnings = append(out.Warnings, "carried with anchor: none, no anchors line covers "+c.st.ID+" ("+why+")")
		}
		if c.st.Kind == "anchors" {
			if d := str(c.st, "proof"); d != "" && !carriedBlobs[d] && !pl.Held.HasBlob(d) {
				out.Warnings = append(out.Warnings, "proof not carried: anchors "+c.st.ID+" names proof "+d+", which neither travels nor is held by the hub; readers see missing-proof until it is held")
			}
		}
	}
	for _, b := range blobs {
		if by := res.WithheldBy(b.ID); len(by) > 0 && len(res.Holders(b.ID)) == 0 {
			out.Withheld = append(out.Withheld, WithheldRow{Path: b.Path, Digest: b.ID, By: by})
		}
	}
	return out
}

func anchorPolicyWord(d btctime.AnchorDefault) string {
	if d == btctime.AnchorRequired {
		return "required"
	}
	return "none"
}

func str(st *wire.Statement, k string) string {
	if st.Body == nil {
		return ""
	}
	v, ok := st.Body.Get(k)
	if !ok {
		return ""
	}
	s, _ := v.(canon.String)
	return string(s)
}

func signerOf(line []byte) string {
	if st, err := wire.ReadStored(line); err == nil {
		return st.Signer
	}
	return ""
}

func sortedKeys(m map[string][]byte) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}
