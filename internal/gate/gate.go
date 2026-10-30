// Package gate is the one validation core of claims-model note §11: `pull`, hub CI (`hub check`), `push` and
// the pre-pin check at `publish` all call Admit, and differ only in the history they hold (Held) and whose
// policy applies (Policy). Two gates disagreeing on one object under the same history and policy is a bug by
// definition (I12, C-core-109).
//
// A package is a set of paths with bytes (a directory tree, or the paths a change adds, modifies or deletes).
// Its data surface is the store layout of the storage note: `blobs/sha256/<64 hex>`, `statements/<signer-dir>/
// <statement id>` and the `rc-store` marker. Everything else is control plane or outside the surface: data
// never carries control (I9). Every object gets its own verdict: admitted (possibly labelled), refused with a
// class, a reason and a scope (I8), could not be decided, or not applied (a control-plane path a maintainer
// reviews). Refusing one object never changes another object's verdict, and never touches what the receiver
// already holds (C-core-121).
//
// Statements are read only through wire.Read and placed only through keylog: the gate adds no rule of its
// own about what a statement is. The rules it adds are about paths (the data surface), bytes (canonical
// form, hash = name), the receiver's policy (limits, hub rules, hooks, the freeze policy, intended_for) and
// overrides. Nothing here reads the network, runs code, or writes anywhere; Commit is the only write, and it
// goes through the store's one commit protocol.
package gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// Reasons the gate adds to the refusal vocabulary. Each is a stable token; Detail carries the specifics.
const (
	// OutsideSurface: a path that is neither data surface nor a control-plane path this gate reviews.
	OutsideSurface = "outside the data surface"
	// UnsafePath: an absolute path, a `..` or `.` segment, an empty segment, a backslash, a symlink or any other
	// non-regular file.
	UnsafePath = "unsafe path"
	// HashMismatch: a blob whose bytes do not hash to its name, or a statement whose id is not its file name.
	HashMismatch = "hash mismatch"
	// NotCanonical: a statement file whose bytes are not the canonical stored form (wire §1, §2).
	NotCanonical = "not canonical"
	// UnsignedDraft: a statement without a signature. Only signed statements enter a hub (§11, C-core-108).
	UnsignedDraft = "unsigned draft"
	// HeldObjectChanged: a change that modifies, deletes or renames something the receiver holds (wire §7:
	// nothing held is ever replaced or removed by a delivery).
	HeldObjectChanged = "held object changed"
	// NotAStore: a tree without the `rc-store` marker, or with a layout this tool does not implement (an
	// alpha-format hub, for one). Package scope: nothing in it is read as a statement (C-core-141).
	NotAStore = "not a store tree"
	// HubRules prefixes the reason of a refusal under a hub's own policy file: "hub rules: <field>".
	HubRules = "hub rules"
	// TrustFloor is the reason of a KeyFloor refusal.
	TrustFloor = "trust floor"
)

// Verdict is what the gate decided for one object.
type Verdict string

const (
	Admitted Verdict = "admitted"
	Refused  Verdict = "refused"
	// Undecided: admission could not be decided (a series boundary that is unchecked or not comparable under a
	// freeze policy). Never a pass (I4).
	Undecided Verdict = "could not check"
	// NotApplied: a control-plane path in a change this gate only reports (hub CI, H-33), or the layout marker of
	// a tree. Nothing is admitted and nothing is refused.
	NotApplied Verdict = "not applied"
)

// Kind is what a path is on the data surface.
type Kind string

const (
	KindStatement    Kind = "statement"
	KindBlob         Kind = "blob"
	KindMarker       Kind = "marker"
	KindControlPlane Kind = "control plane"
	KindOutside      Kind = "outside"
)

// Change says what a package does to a path. A delivery adds; a change set (a hub pull request) may also
// modify or delete, and the gate refuses that for data (HeldObjectChanged) except a not-served takedown.
type Change string

const (
	Add    Change = ""
	Modify Change = "modified"
	Delete Change = "deleted"
)

// Mode is the file type of a path as the transport reported it. Only regular files can be data.
type Mode string

const (
	Regular Mode = ""
	Symlink Mode = "symlink"
	Other   Mode = "other" // a directory entry that is neither (a git submodule, a device, a fifo)
)

// Object is one path in a package.
type Object struct {
	// Path is slash-separated and relative to the package root.
	Path   string
	Data   []byte
	Mode   Mode
	Change Change
}

// Package is what a gate evaluates as one unit (claims-model note §11, storage §4.5).
type Package struct {
	Objects []Object
	// Tree is true when the package is a whole store tree (a directory pulled, a hub checked at one revision):
	// its root must carry the `rc-store` marker of a layout this tool implements. A change set (the paths a
	// pull request touches, a push) carries no marker.
	Tree bool
}

// Held is the receiver's history: the statements and blobs it already holds.
type Held interface {
	// Statements returns every held statement line keyed by id.
	Statements() map[string][]byte
	// HasBlob reports whether the blob with this digest ("sha256:<hex>") is held.
	HasBlob(digest string) bool
}

// MemHeld is a Held in memory.
type MemHeld struct {
	Lines map[string][]byte
	Blobs map[string]bool
}

func (m MemHeld) Statements() map[string][]byte { return m.Lines }
func (m MemHeld) HasBlob(d string) bool         { return m.Blobs[d] }

// Label tokens (closed vocabulary, claims-model note §13). Detail carries the specifics.
const (
	LabelAlreadyHeld   = "already held"
	LabelDetached      = "detached"
	LabelFork          = "FORK"
	LabelIncoherent    = "incoherent"
	LabelUnsupported   = "unsupported"
	LabelUnknownKind   = "unknown kind"
	LabelUnpinned      = "unpinned"
	LabelUnreferenced  = "unreferenced"
	LabelUnavailable   = "unavailable"
	LabelNotHeldHere   = "not held here (policy)"
	LabelMarker        = "layout marker"
	LabelControlPlane  = "control-plane change: needs maintainer review"
	LabelTakedown      = "removed (not_served)"
	LabelStillServed   = "not served: still present"
	LabelIntendedFor   = "intended_for"
	LabelOverridden    = "admitted by override"
	LabelSeriesUnknown = "series boundary"
	LabelTrustFloor    = "below trust floor"
)

// Label is one admitted-and-labelled annotation.
type Label struct {
	Token  string
	Detail string
}

func (l Label) String() string {
	if l.Detail == "" {
		return l.Token
	}
	return l.Token + " (" + l.Detail + ")"
}

// Result is the verdict on one object.
type Result struct {
	Path string
	Kind Kind
	// ID is the statement id or the blob digest, when the path names one.
	ID      string
	Change  Change
	Verdict Verdict
	Labels  []Label
	// Refusal is set when Verdict is Refused: class, reason, detail.
	Refusal *refusal.Refusal
	// Scope is what the verdict covers: "object <path>" or "package".
	Scope string
	// Next is the narrowest next step for a refusal or an undecided object; never a blanket force.
	Next string
	// Override names the override that admitted the object, when one did (C-core-121a).
	Override string
	// IntendedFor is the hub's re-application of a statement's intended_for (C-core-98), when it carries one.
	IntendedFor *resolve.Recorded
	// Series is the series view behind a freeze-policy verdict (C-core-104), when there is one.
	Series *resolve.Series

	data []byte
	st   *wire.Statement
}

// Labelled reports whether an admitted object carries labels.
func (r *Result) Labelled() bool { return r.Verdict == Admitted && len(r.Labels) > 0 }

// HasLabel reports whether the result carries a label with this token.
func (r *Result) HasLabel(token string) bool {
	return slices.ContainsFunc(r.Labels, func(l Label) bool { return l.Token == token })
}

func (r *Result) label(token, detail string) { r.Labels = append(r.Labels, Label{token, detail}) }

func (r *Result) refuse(rf *refusal.Refusal, scope string) {
	r.Verdict, r.Refusal, r.Scope = Refused, rf, scope
	r.Next = nextStep(r)
}

// Report is a gate's answer for one package.
type Report struct {
	// Gate names the entry point that ran ("pull", "hub check", "push", "pre-pin").
	Gate string
	// Policy names whose policy applied and its digest.
	PolicyName, PolicyDigest string
	// Results are every object's verdict, sorted by path (delivery order never changes a report).
	Results []Result
	// Overrides lists the overrides applied, by name, with the objects each admitted.
	Overrides map[string][]string
}

// Result returns the verdict for a path.
func (r *Report) Result(path string) (*Result, bool) {
	for i := range r.Results {
		if r.Results[i].Path == path {
			return &r.Results[i], true
		}
	}
	return nil, false
}

// Override is a typed, per-object override of reader-policy refusals (claims-model note §13: "never a blanket
// --force"; C-core-121a). It names every object it covers; it admits exactly those objects, and only where
// the refusal is the reader's own policy: an intrinsic refusal stays refused under any override, and an
// operational one is lifted by raising the named limit, not by an override.
type Override struct {
	Name    string
	Objects []string // paths
}

// Options are per-run inputs that are not policy.
type Options struct {
	Overrides []Override
	// Audit marks a package that is what the receiver already holds (a hub checked at one revision), not a
	// delivery: a blob whose digest is not served is reported (`not served: still present`), not refused.
	Audit bool
}

var (
	reHex        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reSignerAddr = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	reSignerDir  = regexp.MustCompile(`^[a-z][a-z0-9-]*-[0-9a-f]+$`)
)

// LayoutMarker is the only `rc-store` marker content this tool implements (one trailing newline allowed).
const LayoutMarker = `{"layout":"rc-store/1"}`

// Admit is the one validation core. It never returns an error for anything about the package: every
// condition is a verdict. It returns an error only for an unusable invocation (an override naming no
// objects), as *DidNotStart.
func Admit(gate string, pkg Package, held Held, pol *Policy, opt Options) (*Report, error) {
	if pol == nil {
		pol = DefaultPolicy()
	}
	for _, o := range opt.Overrides {
		if o.Name == "" || len(o.Objects) == 0 {
			return nil, &DidNotStart{Title: "override names no objects",
				Detail: "an override is typed and names the objects it covers; there is no blanket override",
				Next:   "name the override and list each object path it covers"}
		}
	}
	rep := &Report{Gate: gate, PolicyName: pol.Name, PolicyDigest: pol.Digest, Overrides: map[string][]string{}}
	objs := slices.Clone(pkg.Objects)
	slices.SortStableFunc(objs, func(a, b Object) int { return strings.Compare(a.Path, b.Path) })

	// 1. Paths: classify every object; package-scope refusal of a tree that is not a store.
	results := make([]Result, len(objs))
	hasData := false
	markerOK := !pkg.Tree
	var markerWhy string
	for i, o := range objs {
		r := &results[i]
		r.Path, r.Change, r.data = o.Path, o.Change, o.Data
		r.Kind = classify(o, pol)
		if r.Kind == KindStatement || r.Kind == KindBlob {
			hasData = true
		}
		if o.Path == "rc-store" && o.Change == Add && o.Mode == Regular {
			if m := strings.TrimSuffix(string(o.Data), "\n"); m == LayoutMarker {
				markerOK = true
			} else {
				markerOK, markerWhy = false, fmt.Sprintf("rc-store marker %q names a layout this tool does not implement", inert(string(o.Data)))
			}
		}
	}
	if pkg.Tree && !markerOK {
		if markerWhy == "" {
			markerWhy = "no rc-store marker at the root"
			if slices.ContainsFunc(objs, func(o Object) bool {
				return strings.HasPrefix(o.Path, "registry/") || strings.HasPrefix(o.Path, "manifests/")
			}) {
				markerWhy += "; an alpha-format registry (manifests, ledgers) is not read: no statement is synthesized from it"
			}
		}
		for i := range results {
			r := &results[i]
			r.refuse(&refusal.Refusal{Class: refusal.Intrinsic, Reason: NotAStore, Detail: markerWhy + "; scope package"}, "package")
		}
		rep.Results = results
		return rep, nil
	}

	heldLines := held.Statements()
	refBlobs := map[string]bool{} // blobs some statement of the evaluated set names
	pkgBlobs := map[string]bool{} // blobs this package adds and the gate admits
	for _, line := range heldLines {
		if st, err := wire.Read(line); err == nil {
			addRefs(st, refBlobs)
		}
	}

	// 2. Per-object checks that need nothing but the object and the policy.
	var cands []int // statement results that passed the object checks
	for i := range results {
		r := &results[i]
		o := objs[i]
		scope := "object " + r.Path
		switch {
		case r.Kind == KindOutside:
			reason, detail := OutsideSurface, "not a blob or statement path of the store layout"
			if why := unsafePath(o); why != "" {
				reason, detail = UnsafePath, why
			}
			r.refuse(&refusal.Refusal{Class: refusal.Intrinsic, Reason: reason, Detail: detail + "; scope " + scope}, scope)
			continue
		case r.Kind == KindControlPlane:
			if pkg.Tree {
				r.Verdict = NotApplied
				r.label(LabelControlPlane, "present in the tree, not checked")
			} else if hasData {
				r.refuse(&refusal.Refusal{Class: refusal.Intrinsic, Reason: OutsideSurface,
					Detail: "control-plane path changed together with data; the data is checked under the base policy and this path is not applied; scope " + scope}, scope)
			} else {
				r.Verdict = NotApplied
				r.label(LabelControlPlane, "not applied by the check")
			}
			continue
		case r.Kind == KindMarker:
			r.Verdict = NotApplied
			r.label(LabelMarker, "not installed")
			continue
		}
		// Data surface. A delivery never changes what is held.
		if o.Change == Modify || o.Change == Delete {
			if r.Kind == KindBlob && o.Change == Delete {
				d := "sha256:" + lastSeg(r.Path)
				r.ID = d
				if _, ok := pol.NotServed[d]; ok {
					r.Verdict = Admitted
					r.label(LabelTakedown, "listed in "+pol.Name+" not_served")
					continue
				}
			}
			r.refuse(&refusal.Refusal{Class: refusal.Intrinsic, Reason: HeldObjectChanged,
				Detail: fmt.Sprintf("%s %s; a delivery never replaces or removes what is held (a correction is a new statement); scope %s", r.Kind, o.Change, scope)}, scope)
			continue
		}
		if r.Kind == KindBlob {
			checkBlob(r, pol, scope, opt.Audit)
			if r.Verdict != Refused {
				pkgBlobs[r.ID] = true
			}
			continue
		}
		if checkStatement(r, pol, scope) {
			cands = append(cands, i)
		}
	}

	// 3. Placement: every held line and every candidate in one set of per-key logs. keylog decides ownership
	// and every log-relative rule over the whole set, so delivery order changes nothing (I14).
	logs := keylog.NewStore()
	for _, id := range sortedIDs(heldLines) {
		if st, err := wire.Read(heldLines[id]); err == nil {
			_, _ = logs.Log(st.Signer).Add(heldLines[id])
		}
	}
	for _, i := range cands {
		r := &results[i]
		owner := dirSigner(dirSeg(r.Path))
		if _, err := logs.Log(owner).Add(r.data); err != nil {
			if rf, ok := err.(*refusal.Refusal); ok && rf.Reason == refusal.WrongLog {
				r.refuse(rf, "object "+r.Path)
			}
			// A log-relative refusal is decided below from the view, which every order reaches alike.
		}
	}
	views := map[string]keylog.View{}
	for _, k := range logs.Keys() {
		views[k] = logs.Log(k).View()
	}
	for _, i := range cands {
		r := &results[i]
		if r.Verdict == Refused {
			continue
		}
		v := views[r.st.Signer]
		if rf := refusedIn(v, r.ID); rf != nil {
			r.refuse(rf, "object "+r.Path)
			continue
		}
		if _, ok := heldLines[r.ID]; ok {
			r.label(LabelAlreadyHeld, "")
		}
		placeLabels(r, v)
		for _, h := range pol.Hooks {
			if rf := h.CheckStatement(r.st); rf != nil {
				if h.Label() {
					r.label(LabelTrustFloor, rf.Detail)
					continue
				}
				r.refuse(rf, "object "+r.Path)
				break
			}
		}
		if r.Verdict != Refused {
			r.Verdict = Admitted
		}
	}

	// 4. The evaluated set: what the receiver would hold if it admits the package.
	evaluated := map[string][]byte{}
	for id, l := range heldLines {
		evaluated[id] = l
	}
	for _, i := range cands {
		if r := &results[i]; r.Verdict == Admitted {
			evaluated[r.ID] = r.st.Line()
			addRefs(r.st, refBlobs)
		}
	}

	// 5. Resolver-level policy: intended_for re-application (C-core-98) and the freeze policy (C-core-104).
	if pol.Freeze != nil || anyIntendedFor(results, cands) {
		res := resolver(evaluated, pol)
		for _, i := range cands {
			r := &results[i]
			if r.Verdict == Admitted {
				resolverChecks(r, res, pol)
			}
		}
	}

	// 6. Blob and statement availability labels, now that the evaluated set is known.
	for i := range results {
		r := &results[i]
		if r.Verdict != Admitted {
			continue
		}
		switch r.Kind {
		case KindBlob:
			if r.Change == Add && !refBlobs[r.ID] {
				r.label(LabelUnreferenced, "no statement in the evaluated set names it")
			}
		case KindStatement:
			for _, d := range refsOf(r.st) {
				if reason, ok := pol.NotServed[d]; ok {
					r.label(LabelNotHeldHere, notServedDetail(d, reason))
				} else if !pkgBlobs[d] && !held.HasBlob(d) {
					r.label(LabelUnavailable, "not held locally: "+d)
				}
			}
		}
	}

	// 7. Overrides: typed, per object, reader policy only.
	for _, o := range opt.Overrides {
		for _, p := range o.Objects {
			for i := range results {
				r := &results[i]
				if r.Path != p || r.Verdict != Refused || r.Refusal.Class != refusal.Policy {
					continue
				}
				r.label(LabelOverridden, o.Name+": "+r.Refusal.Error())
				r.Verdict, r.Override, r.Refusal, r.Next = Admitted, o.Name, nil, ""
				rep.Overrides[o.Name] = append(rep.Overrides[o.Name], p)
			}
		}
	}
	rep.Results = results
	return rep, nil
}

// classify places a path on the data surface. The control plane is the policy's list (a hub reviews changes
// to it); with no list, every non-data path is outside the surface.
func classify(o Object, pol *Policy) Kind {
	if unsafePath(o) != "" {
		return KindOutside
	}
	if pol.isControlPlane(o.Path) {
		return KindControlPlane
	}
	seg := strings.Split(o.Path, "/")
	switch {
	case len(seg) == 1 && seg[0] == "rc-store":
		return KindMarker
	case len(seg) == 3 && seg[0] == "blobs" && seg[1] == "sha256" && reHex.MatchString(seg[2]):
		return KindBlob
	case len(seg) == 3 && seg[0] == "statements" && validSignerDir(seg[1]) && reHex.MatchString(seg[2]):
		return KindStatement
	}
	return KindOutside
}

// unsafePath names why a path cannot be confined to the package root (claims-model note §12: absolute paths,
// `..` and symlinks are refused), or "".
func unsafePath(o Object) string {
	p := o.Path
	switch {
	case p == "":
		return "empty path"
	case strings.HasPrefix(p, "/"):
		return "absolute path"
	case strings.ContainsRune(p, '\\'):
		return "backslash in path"
	case strings.ContainsRune(p, 0):
		return "NUL in path"
	}
	for _, s := range strings.Split(p, "/") {
		switch s {
		case "..":
			return "`..` segment"
		case ".", "":
			return "empty or `.` segment"
		}
	}
	switch o.Mode {
	case Symlink:
		return "symlink"
	case Other:
		return "not a regular file"
	}
	return ""
}

func validSignerDir(d string) bool { return reSignerAddr.MatchString(d) || reSignerDir.MatchString(d) }

// dirSigner maps a statement directory back to the signer it is named for: the signer with ':' written as
// '-' (`ed25519-<hex>`), or a 0x address as is. Hex has no '-', so the last '-' is the separator.
func dirSigner(d string) string {
	if reSignerAddr.MatchString(d) {
		return d
	}
	if i := strings.LastIndexByte(d, '-'); i > 0 {
		return d[:i] + ":" + d[i+1:]
	}
	return d
}

func dirSeg(p string) string  { return strings.Split(p, "/")[1] }
func lastSeg(p string) string { return p[strings.LastIndexByte(p, '/')+1:] }

func checkBlob(r *Result, pol *Policy, scope string, audit bool) {
	r.ID = "sha256:" + lastSeg(r.Path)
	if lim := pol.Limits[LimitBlobBytes]; int64(len(r.data)) > lim {
		r.refuse(sizeLimit(LimitBlobBytes, lim, len(r.data), scope), scope)
		return
	}
	h := sha256.Sum256(r.data)
	if got := "sha256:" + hex.EncodeToString(h[:]); got != r.ID {
		r.refuse(&refusal.Refusal{Class: refusal.Intrinsic, Reason: HashMismatch,
			Detail: fmt.Sprintf("expected %s, got %s; scope %s", r.ID, got, scope)}, scope)
		return
	}
	if pol.ExternalOnly {
		r.refuse(&refusal.Refusal{Class: refusal.Policy, Reason: HubRules + ": blobs",
			Detail: pol.Name + " is external-only: it carries statements and no blob bytes; scope " + scope}, scope)
		return
	}
	if reason, ok := pol.NotServed[r.ID]; ok && audit {
		r.label(LabelStillServed, notServedDetail(r.ID, reason))
	} else if ok {
		r.refuse(&refusal.Refusal{Class: refusal.Policy, Reason: HubRules + ": not_served",
			Detail: notServedDetail(r.ID, reason) + "; scope " + scope}, scope)
		return
	}
	r.Verdict = Admitted
}

// checkStatement runs the object-level checks: the size limit, wire.Read (the one statement validator), the
// canonical stored form and id = file name. It reports whether the statement goes on to placement.
func checkStatement(r *Result, pol *Policy, scope string) bool {
	r.ID = lastSeg(r.Path)
	if lim := pol.Limits[LimitStatementBytes]; int64(len(r.data)) > lim {
		r.refuse(sizeLimit(LimitStatementBytes, lim, len(r.data), scope), scope)
		return false
	}
	st, err := wire.Read(r.data)
	if err != nil {
		rf, ok := err.(*refusal.Refusal)
		if !ok {
			rf = refusal.Malformed("%v", err)
		}
		if isDraft(r.data) {
			rf = &refusal.Refusal{Class: refusal.Intrinsic, Reason: UnsignedDraft,
				Detail: "no sig: an unsigned statement is a local draft and never enters a hub; sign it with your key"}
		} else if rf.Class == refusal.Operational && rf.Reason == refusal.SizeLimit {
			rf = &refusal.Refusal{Class: refusal.Operational, Reason: refusal.SizeLimit,
				Detail: fmt.Sprintf("%s=%d (the format's single-statement bound; %s)", "signed_string_bytes", wire.MaxSignedString, rf.Detail)}
		}
		rf = &refusal.Refusal{Class: rf.Class, Reason: rf.Reason, Detail: rf.Detail + "; scope " + scope}
		r.refuse(rf, scope)
		return false
	}
	r.st = st
	if !bytes.Equal(st.Line(), r.data) {
		r.refuse(&refusal.Refusal{Class: refusal.Intrinsic, Reason: NotCanonical,
			Detail: "the file is not the statement's canonical stored form (canonical JSON, canonical sig, no trailing newline); scope " + scope}, scope)
		return false
	}
	if st.ID != r.ID {
		r.refuse(&refusal.Refusal{Class: refusal.Intrinsic, Reason: HashMismatch,
			Detail: fmt.Sprintf("file name %s, statement id %s; scope %s", r.ID, st.ID, scope)}, scope)
		return false
	}
	return true
}

// isDraft reports whether bytes that wire.Read refused are a JSON object carrying no signature: an unsigned
// draft. This only names the refusal wire.Read already made; it validates nothing.
func isDraft(b []byte) bool {
	v, err := canon.Parse(b)
	if err != nil {
		return false
	}
	o, ok := v.(*canon.Object)
	if !ok {
		return false
	}
	_, hasSig := o.Get("sig")
	_, hasKind := o.Get("kind")
	return !hasSig && hasKind
}

func sizeLimit(name string, lim int64, n int, scope string) *refusal.Refusal {
	return &refusal.Refusal{Class: refusal.Operational, Reason: refusal.SizeLimit,
		Detail: fmt.Sprintf("%s=%d (object of %d bytes); scope %s", name, lim, n, scope)}
}

func notServedDetail(d, reason string) string {
	s := d + " is not served here"
	if reason != "" {
		s += " (maintainers' note: " + inert(reason) + ")"
	}
	return s
}

func refusedIn(v keylog.View, id string) *refusal.Refusal {
	for _, x := range v.Refused {
		if x.St.ID == id {
			return x.Reason
		}
	}
	return nil
}

// placeLabels adds the labels a placed line carries: detached with its gap, FORK, incoherent, and what the
// reader could not interpret. None of them refuses (claims-model note §12; wire §6, §7).
func placeLabels(r *Result, v keylog.View) {
	st := r.st
	for _, ln := range v.Lines {
		if ln.St.ID != st.ID {
			continue
		}
		if ln.State == keylog.Detached {
			r.label(LabelDetached, "waiting for "+gapText(ln.Waiting))
		}
		if ln.Incoherent {
			r.label(LabelIncoherent, "ts earlier than its predecessor's")
		}
	}
	for _, f := range v.Forks {
		if f.ClearedBy == "" && (slices.Contains(f.Branches, st.ID) || slices.Contains(f.Tips, st.ID)) {
			r.label(LabelFork, "at "+keylog.Short(f.At))
			break
		}
	}
	switch st.Status {
	case wire.Unsupported:
		r.label(LabelUnsupported, st.Why)
	case wire.UnknownKind:
		r.label(LabelUnknownKind, st.Why)
	}
	if len(st.Unpinned) > 0 {
		r.label(LabelUnpinned, strings.Join(st.Unpinned, ","))
	}
}

func gapText(g keylog.Gap) string {
	var parts []string
	if g.HasSeq {
		parts = append(parts, fmt.Sprintf("seq %d..%d", g.FromSeq, g.ToSeq))
	}
	for _, id := range g.IDs {
		parts = append(parts, keylog.Short(id))
	}
	if len(parts) == 0 {
		return "a predecessor"
	}
	return strings.Join(parts, ", ")
}

// refsOf lists the blobs a statement names as its content.
func refsOf(st *wire.Statement) []string {
	if st == nil || !st.Verified || st.Status != wire.Valid || st.Body == nil {
		return nil
	}
	c, ok := st.Body.Get("content")
	if !ok {
		return nil
	}
	co, ok := c.(*canon.Object)
	if !ok {
		return nil
	}
	if d, ok := co.Get("digest"); ok {
		if s, ok := d.(canon.String); ok {
			return []string{string(s)}
		}
	}
	return nil
}

func addRefs(st *wire.Statement, into map[string]bool) {
	for _, d := range refsOf(st) {
		into[d] = true
	}
}

func sortedIDs(m map[string][]byte) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

func resolver(lines map[string][]byte, pol *Policy) *resolve.Resolver {
	s := keylog.NewStore()
	for _, id := range sortedIDs(lines) {
		if st, err := wire.Read(lines[id]); err == nil {
			_, _ = s.Log(st.Signer).Add(lines[id])
		}
	}
	return resolve.New(s, pol.Resolver...)
}

// resolverChecks applies the receiver's resolver-level policy to one admitted statement.
func resolverChecks(r *Result, res *resolve.Resolver, pol *Policy) {
	st := r.st
	if st.Status != wire.Valid || !st.Verified {
		return
	}
	if _, ok := st.Body.Get("intended_for"); ok {
		if rec, ok := res.CheckRecorded(st.ID); ok {
			r.IntendedFor = rec
			r.label(LabelIntendedFor, fmt.Sprintf("named %s: %s; current %s: %s (this receiver's computation); publisher says %s",
				keylog.Short(rec.NamedEdition), outcomeOr(rec.Named), keylog.Short(rec.CurrentEdition), outcomeOr(rec.Current), inert(rec.PublisherSaid)))
			if pol.IntendedFor == RefuseOnFail && (rec.Named == resolve.RuleFail || (rec.CurrentEdition != "" && rec.Current == resolve.RuleFail)) {
				r.refuse(&refusal.Refusal{Class: refusal.Policy, Reason: resolve.RuleFailed,
					Detail: "intended_for re-applied by " + pol.Name + "; scope object " + r.Path}, "object "+r.Path)
				return
			}
		}
	}
	if pol.Freeze != nil && st.Kind == "edition" {
		rid, _ := st.Body.Get("resource")
		resID, _ := rid.(canon.String)
		rs, ok := res.Resource(string(resID))
		if !ok || rs.Type != "series" {
			return
		}
		s, rf := res.EndorseSeries(string(resID), resolve.EditionID(st.Body), pol.Freeze)
		if s == nil {
			r.label(LabelSeriesUnknown, "edition not authorized in the evaluated set; freeze policy not applicable")
			return
		}
		r.Series = s
		if rf == nil {
			return
		}
		switch s.Comparison {
		case "flagged":
			r.refuse(&refusal.Refusal{Class: refusal.Policy, Reason: HubRules + ": series.refuse_premature_freeze",
				Detail: rf.Detail + "; the edition stays a valid statement elsewhere; " + ReaderRecheck}, "object "+r.Path)
		default:
			r.Verdict, r.Scope = Undecided, "object "+r.Path
			if s.NoRecheck() {
				r.label(LabelSeriesUnknown, s.Comparison+": "+s.Line()+"; "+NoSegmentRecheck)
				r.Next = SeriesNoRecheckNext
			} else {
				r.label(LabelSeriesUnknown, s.Comparison+": "+s.Line())
				r.Next = "make the series boundary computable (finality rules on every segment, one unit) or accept that this edition is not endorsed here"
			}
		}
	}
}

// NoSegmentRecheck is what every series.refuse_premature_freeze verdict says about this tool version: it ships
// no finality re-check for series segments (the default segment reader records positions only), so a members'
// boundary is never computed by the shipped tool and, with the knob on, every series edition is could not
// check. A reader that configures its own re-check (resolve.WithSegments) gets real comparisons; no command
// can supply one, and a hub check takes no input but the base (H-13).
const NoSegmentRecheck = "this tool version ships no finality re-check for series segments, so with series.refuse_premature_freeze on every series edition is could not check until a re-check ships"

// ReaderRecheck is added to a series.refuse_premature_freeze refusal: a flagged boundary needs a members'
// boundary, which only a segment re-check the reader configured itself can compute in this tool version.
const ReaderRecheck = "the members' boundary came from a segment finality re-check this reader configured; this tool version ships none"

// SeriesNoRecheckNext is the next step of a series edition left could-not-check because no re-check ships.
const SeriesNoRecheckNext = "nothing in this change can make the boundary computable with this tool version (no finality re-check ships); turn series.refuse_premature_freeze off through the maintainers' own review, or accept that series editions are not endorsed here until a re-check ships"

func outcomeOr(o resolve.Outcome) string {
	if o == "" {
		return "none"
	}
	return string(o)
}

// nextStep is the narrowest next step for a refusal (claims-model note §13). It never proposes a blanket
// force: an intrinsic refusal is the object's own fault, an operational one names the limit, a policy one
// names the typed per-object override.
func nextStep(r *Result) string {
	rf := r.Refusal
	switch {
	case rf.Reason == NotAStore:
		return "point the gate at a store tree (one with an rc-store marker); an alpha-format registry needs the alpha tool"
	case rf.Reason == UnsignedDraft:
		return "sign the draft with your own key, then retry this object"
	case rf.Class == refusal.Intrinsic && r.Kind == KindControlPlane:
		return "split the change: send the data alone; the control-plane change goes through the maintainers' own review"
	case rf.Class == refusal.Intrinsic:
		return "nothing makes this object admissible; drop it, and the other objects can be retried on their own"
	case rf.Class == refusal.Operational:
		return "raise the named limit in your own policy if you accept objects this large; the other objects are unaffected"
	default:
		return "an override naming this object (" + r.Path + "), or a change to your own policy; the other objects are unaffected"
	}
}

// inert renders peer-supplied text with every control character escaped, so nothing in it reaches a
// terminal as a control sequence (C-core-122). It is idempotent (a backslash is left as is), so text built
// from inert parts can pass through it again at render time.
func inert(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0) || c == 0x2028 || c == 0x2029 || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069):
			fmt.Fprintf(&b, `\u%04x`, c)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

func anyIntendedFor(rs []Result, cands []int) bool {
	for _, i := range cands {
		if r := &rs[i]; r.Verdict == Admitted && r.st.Status == wire.Valid && r.st.Verified {
			if _, ok := r.st.Body.Get("intended_for"); ok {
				return true
			}
		}
	}
	return false
}

// StatementPath is the data-surface path of a statement: statements/<signer with ':' as '-'>/<id>.
func StatementPath(signer, id string) string {
	return "statements/" + strings.ReplaceAll(signer, ":", "-") + "/" + id
}

// BlobPath is the data-surface path of a blob digest "sha256:<hex>".
func BlobPath(digest string) string {
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
}
