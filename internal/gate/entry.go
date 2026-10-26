package gate

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/store"
)

// The four gates of claims-model note §11. Each is a thin wrapper over Admit: what differs is the history the
// caller passes as Held and the policy it passes (C-core-109). None of them adds a check of its own.

// Pull is the receiver's ingest of a package into its own store, under its own reader policy.
func Pull(pkg Package, held Held, pol *Policy, opt Options) (*Report, error) {
	return Admit("pull", pkg, held, pol, opt)
}

// Push is the sender's check, before sending, of what the receiving hub would admit: held is the hub's
// history as the sender knows it, pol the hub's policy. An unsigned draft never leaves (C-core-108).
func Push(pkg Package, held Held, pol *Policy, opt Options) (*Report, error) {
	return Admit("push", pkg, held, pol, opt)
}

// HubCheck is a hub's CI over one change: held is the base revision's statements and blobs, pol the policy
// read from the base revision (package hubcheck reads both from git).
func HubCheck(pkg Package, held Held, pol *Policy, opt Options) (*Report, error) {
	return Admit("hub check", pkg, held, pol, opt)
}

// PrePin is the publisher's check at `publish`, after signing and before the statements are committed: the
// same admission, with the publisher's own policy, which refuses a statement whose intended_for edition's
// rules fail (claims-model note §8). The draft body's intended_for record itself is computed earlier by
// resolve.CheckIntendedFor; this is the validity half every gate shares.
func PrePin(pkg Package, held Held, pol *Policy, opt Options) (*Report, error) {
	if pol == nil {
		pol = DefaultPolicy()
	}
	p := *pol
	p.IntendedFor = RefuseOnFail
	return Admit("pre-pin", pkg, held, &p, opt)
}

// Admitted returns the statement lines and blob objects a report admitted, in path order: the unit a pull
// commits (storage note §3.2: the package's admitted set as one operation).
func (r *Report) Admitted() (lines [][]byte, blobs []Result) {
	for _, x := range r.Results {
		if x.Verdict != Admitted || x.Change != Add {
			continue
		}
		switch x.Kind {
		case KindStatement:
			if !x.HasLabel(LabelAlreadyHeld) {
				lines = append(lines, x.st.Line())
			}
		case KindBlob:
			blobs = append(blobs, x)
		}
	}
	return lines, blobs
}

// Commit installs a pull's admitted set into the store as one operation (storage note §3.1, §3.2): each
// admitted blob through the store's exact-bytes install (verified against its name again), then one journal
// record holding every admitted statement. Refused objects are never written, and what the store already
// held is never touched (C-core-121).
func Commit(s *store.Store, r *Report) (store.Outcome, error) {
	lines, blobs := r.Admitted()
	var digests []store.Digest
	for _, b := range blobs {
		d, _, err := s.InstallBlob(bytes.NewReader(b.data), store.Digest(b.ID))
		if err != nil {
			return store.Outcome{}, err
		}
		digests = append(digests, d)
	}
	if len(lines) == 0 && len(digests) == 0 {
		return store.Outcome{}, nil
	}
	return s.Commit(CommitKind(r), lines, digests)
}

// CommitKind is the journal record kind of a report's commit: the gate, and every override that admitted
// something, by name, so the admission is recorded with the override named (C-core-121a).
func CommitKind(r *Report) string {
	k := r.Gate
	names := make([]string, 0, len(r.Overrides))
	for n := range r.Overrides {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		k += " override " + n
	}
	return k
}

// StoreHeld adapts a local store to Held.
type StoreHeld struct{ S *store.Store }

func (h StoreHeld) Statements() map[string][]byte {
	m, err := h.S.Statements()
	if err != nil {
		return map[string][]byte{}
	}
	return m
}

func (h StoreHeld) HasBlob(d string) bool { return h.S.HasBlob(store.Digest(d)) }

// ReadTree reads a directory as a whole-tree package, confined to root: every entry is listed with its path
// relative to root, symlinks and other non-regular files are listed as such (never followed), and regular
// files are read through an os.Root, so nothing outside root is read. maxBytes bounds one file's read; a
// larger file is listed with no data and refused by the gate's size limit (its size is reported as the read
// bound plus one).
func ReadTree(root string, maxBytes int64) (Package, error) {
	rt, err := os.OpenRoot(root)
	if err != nil {
		return Package{}, err
	}
	defer rt.Close()
	pkg := Package{Tree: true}
	err = fs.WalkDir(rt.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == "." {
			return nil
		}
		if d.IsDir() {
			if p == ".git" {
				return fs.SkipDir // the transport's own metadata, never part of a package
			}
			return nil
		}
		o := Object{Path: filepath.ToSlash(p)}
		switch t := d.Type(); {
		case t&fs.ModeSymlink != 0:
			o.Mode = Symlink
		case !t.IsRegular():
			o.Mode = Other
		default:
			f, err := rt.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			buf := bytes.Buffer{}
			if _, err := buf.ReadFrom(io.LimitReader(f, maxBytes+1)); err != nil {
				return err
			}
			o.Data = buf.Bytes()
		}
		pkg.Objects = append(pkg.Objects, o)
		return nil
	})
	return pkg, err
}

// Render is the human report (hub template contract H-50): one line per refused, undecided, not-applied or
// labelled object, then the policy and a count per verdict. Peer-supplied text is inert.
func (r *Report) Render() string {
	var b strings.Builder
	counts := map[string]int{}
	for _, x := range r.Results {
		v := string(x.Verdict)
		if x.Labelled() {
			v = "admitted and labelled"
		}
		counts[v]++
		id := x.ID
		if id == "" {
			id = "-"
		}
		switch {
		case x.Verdict == Refused:
			fmt.Fprintf(&b, "%s  %s  refused  %s: %s (%s)\n    next: %s\n", inert(x.Path), id, x.Refusal.Class, x.Refusal.Reason, inert(x.Refusal.Detail), x.Next)
		case x.Verdict == Admitted && len(x.Labels) == 0:
			continue
		default:
			var ls []string
			for _, l := range x.Labels {
				ls = append(ls, inert(l.String()))
			}
			fmt.Fprintf(&b, "%s  %s  %s  %s\n", inert(x.Path), id, x.Verdict, strings.Join(ls, "; "))
		}
	}
	fmt.Fprintf(&b, "gate %s; policy %s %s\n", r.Gate, inert(r.PolicyName), r.PolicyDigest)
	ks := make([]string, 0, len(counts))
	for k := range counts {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	for _, k := range ks {
		fmt.Fprintf(&b, "  %s: %d\n", k, counts[k])
	}
	b.WriteString("no registry change; no fetch; no cache\n")
	return b.String()
}

// Exit maps a report to the gate exit code the hub template proposes (0 every object admitted, possibly
// labelled, or only control-plane paths reported; 1 at least one refused; 3 nothing refused and at least one
// undecided). Refusals of every class map to 1 by default; with operationalUndecided an operational refusal
// maps to 3 instead (the open question of whether "stopped by the reader's own limit" is a completed check).
func (r *Report) Exit(operationalUndecided bool) int {
	refused, undecided := false, false
	for _, x := range r.Results {
		switch x.Verdict {
		case Refused:
			if operationalUndecided && x.Refusal.Class == refusal.Operational {
				undecided = true
			} else {
				refused = true
			}
		case Undecided:
			undecided = true
		}
	}
	switch {
	case refused:
		return 1
	case undecided:
		return 3
	}
	return 0
}
