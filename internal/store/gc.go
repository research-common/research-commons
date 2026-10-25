package store

// Garbage collection and local deletion (storage note §6.1, §6.2).
//
// What pins a blob (gc never deletes it):
//
//   - an installed statement, of any kind or format major, other than a `holds`, whose stored line mentions
//     its digest (found by scanning for `sha256:<64 hex>`, so a statement this reader cannot interpret pins
//     too), and any file under statements/ or retained/ that does not read: kept, never interpreted;
//   - any journal record, pending or done, that names it (a record is in transit; gc never touches one);
//   - a serving `holds`: the current `holds` of an operator key for that digest that is not withdrawn
//     (GCConfig.Operators; with none configured every key's serving holds pins, which can only keep more).
//     Only Release moves such a blob.
//
// A `holds` that is withdrawn, superseded by a later one of its key, or by a key that is not an operator does
// not pin: it is a holder's word, and local deletion is availability, not erasure (§6.2). This reading makes
// C-core-145 (c) true (after a withdrawal and a crash the blob is a gc candidate); see the report.
//
// The grace window is the blob file's modification time (set by install, refreshed by reuse, blob.go). That
// is the window's clock only; no cache key reads it (§5.1).

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/rctime"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// Grace window policy (§6.1.1).
const (
	DefaultGrace = 24 * time.Hour
	// MinGrace is the floor for the policy value: below it the window must be given for one run.
	MinGrace = time.Hour
)

// Crash points of gc and Release (C-core-145 (c), P-10), beside the commit protocol's own.
const (
	GCMoved          = "gc: blob moved aside, before the re-check"
	AfterWithdrawal  = "release: after the withdrawal is committed and installed"
	AfterBlobRemoved = "release: after the blob is removed"
)

// Reasons of gc.
const (
	GraceBelowFloor = "grace window below floor"
	SigningRefused  = "signing refused"
)

var reDigestAny = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

// GCConfig configures one gc run.
type GCConfig struct {
	// Policy is the local policy window; zero means DefaultGrace. Below MinGrace it is refused unless PerRun
	// is set.
	Policy time.Duration
	// PerRun, when non-nil, is `gc --grace <d>`: used for this run only and printed in the plan.
	PerRun *time.Duration
	// Operators are the signers whose serving `holds` pin a blob. Nil means every key's.
	Operators []string
	// Now is the clock; zero means time.Now().
	Now time.Time
}

func (c GCConfig) now() time.Time {
	if c.Now.IsZero() {
		return time.Now()
	}
	return c.Now
}

// Grace resolves the window in force and says where it came from. A policy value below MinGrace is a refusal
// (reader policy, naming the floor); a per-run value is used as given.
func (c GCConfig) Grace() (time.Duration, string, error) {
	if c.PerRun != nil {
		if *c.PerRun < 0 {
			return 0, "", &refusal.Refusal{Class: refusal.Policy, Reason: GraceBelowFloor,
				Detail: fmt.Sprintf("grace %s is negative", *c.PerRun)}
		}
		return *c.PerRun, "this run (--grace)", nil
	}
	p := c.Policy
	if p == 0 {
		p = DefaultGrace
	}
	if p < MinGrace {
		return 0, "", &refusal.Refusal{Class: refusal.Policy, Reason: GraceBelowFloor,
			Detail: fmt.Sprintf("policy grace window %s is below the %s floor; give it for one run with --grace if nothing else is writing to this store", p, MinGrace)}
	}
	return p, "policy", nil
}

// GCBlob is one blob in a plan.
type GCBlob struct {
	Digest Digest
	Size   int64
	// Why is what makes it a candidate, or the reason it is kept.
	Why string
}

// GCPlan is what gc decided (dry run) and did (apply).
type GCPlan struct {
	Grace       time.Duration
	GraceSource string
	Applied     bool
	// Candidates are unreferenced blobs outside the grace window, in digest order. After an apply, Deleted is
	// the subset removed and Skipped the rest, each with the reason the re-check at deletion kept it.
	Candidates []GCBlob
	Deleted    []GCBlob
	Skipped    []GCBlob
	// Kept lists every other blob with the reason it stays.
	Kept []GCBlob
	// Strays are files in blobs/sha256 that are not blob names; gc never touches them (fsck reports them).
	Strays []string
}

// SideEffects states exactly what this run did or would do (§6.1.1).
func (p *GCPlan) SideEffects() string {
	if !p.Applied {
		return "no deletion; no registry change"
	}
	var n int64
	for _, b := range p.Deleted {
		n += b.Size
	}
	return fmt.Sprintf("deleted %d blob file(s), %d bytes, under blobs/; no statement, journal record or registry entry changed", len(p.Deleted), n)
}

// Render is the text a command prints: the grace window and its source, every candidate with hash and size,
// what is kept and why, and the side effects.
func (p *GCPlan) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "grace window: %s (%s)\n", p.Grace, p.GraceSource)
	list, verb := p.Candidates, "would delete"
	if p.Applied {
		list, verb = p.Deleted, "deleted"
	}
	fmt.Fprintf(&b, "%s %d blob(s):\n", verb, len(list))
	for _, c := range list {
		fmt.Fprintf(&b, "  %s %d bytes\n", c.Digest, c.Size)
	}
	if len(p.Skipped) > 0 {
		fmt.Fprintf(&b, "kept at the re-check before deletion (%d):\n", len(p.Skipped))
		for _, c := range p.Skipped {
			fmt.Fprintf(&b, "  %s: %s\n", c.Digest, c.Why)
		}
	}
	if len(p.Kept) > 0 {
		fmt.Fprintf(&b, "kept (%d):\n", len(p.Kept))
		for _, c := range p.Kept {
			fmt.Fprintf(&b, "  %s %d bytes: %s\n", c.Digest, c.Size, c.Why)
		}
	}
	fmt.Fprintf(&b, "side effects: %s\n", p.SideEffects())
	if !p.Applied {
		b.WriteString("re-run with --apply to delete\n")
	}
	return b.String()
}

// holdsEntry is one installed, verified `holds` statement.
type holdsEntry struct {
	signer    string
	digest    Digest
	seq       int64
	id        string
	withdrawn bool
	size      int64 // declared content.size, -1 when absent
	locations []string
}

// refIndex is what pins blobs. refresh is cheap to repeat: the journal is re-listed in full and only
// statement files not read before are read.
type refIndex struct {
	s     *Store
	ops   map[string]bool // nil = every signer
	seen  map[string]bool
	pins  map[Digest][]string // non-journal pins
	jpins map[Digest][]string // journal pins, rebuilt on every refresh
	holds []holdsEntry
}

func (s *Store) newRefIndex(operators []string) *refIndex {
	ri := &refIndex{s: s, seen: map[string]bool{}, pins: map[Digest][]string{}}
	if operators != nil {
		ri.ops = map[string]bool{}
		for _, o := range operators {
			ri.ops[o] = true
		}
	}
	return ri
}

func (ri *refIndex) refresh() error {
	ri.jpins = map[Digest][]string{}
	for _, sub := range []string{"pending", "done"} {
		dir := ri.s.dir("journal", sub)
		ents, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			op := strings.TrimSuffix(e.Name(), ".json")
			for _, m := range slices.Compact(slices.Sorted(slices.Values(reDigestAny.FindAllString(string(b), -1)))) {
				ri.jpins[Digest(m)] = append(ri.jpins[Digest(m)], fmt.Sprintf("journal record %s (%s)", op, sub))
			}
		}
	}
	for _, top := range []string{"statements", "retained"} {
		err := filepath.WalkDir(ri.s.dir(top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if d.IsDir() || ri.seen[p] {
				return nil
			}
			b, err := os.ReadFile(p)
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			ri.seen[p] = true
			ri.readFile(top, d.Name(), b)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// contentDigest is body.content.digest of a statement, when present and typed.
func contentDigest(st *wire.Statement) (Digest, bool) {
	if st.Body == nil {
		return "", false
	}
	c, ok := st.Body.Members["content"].(*canon.Object)
	if !ok {
		return "", false
	}
	d, ok := c.Members["digest"].(canon.String)
	if !ok {
		return "", false
	}
	if _, ok := Digest(d).hex(); !ok {
		return "", false
	}
	return Digest(d), true
}

func (ri *refIndex) readFile(top, name string, b []byte) {
	why := "retained line " + name
	if top == "statements" {
		st, err := wire.Read(b)
		switch {
		case err != nil || st.ID != name:
			why = "statement file " + name + " (does not read; kept, never interpreted)"
		case st.Verified && st.Kind == "holds":
			if d, ok := contentDigest(st); ok {
				_, w := st.Body.Members["withdrawn"]
				h := holdsEntry{signer: st.Signer, digest: d, seq: st.Seq, id: st.ID, withdrawn: w, size: -1}
				if c, ok := st.Body.Members["content"].(*canon.Object); ok {
					if n, ok := c.Members["size"].(canon.Int); ok {
						h.size = int64(n)
					}
				}
				if ls, ok := st.Body.Members["locations"].(canon.Array); ok {
					for _, l := range ls {
						if t, ok := l.(canon.String); ok {
							h.locations = append(h.locations, string(t))
						}
					}
				}
				ri.holds = append(ri.holds, h)
			}
			return
		default:
			why = "statement " + name
		}
	}
	for _, m := range slices.Compact(slices.Sorted(slices.Values(reDigestAny.FindAllString(string(b), -1)))) {
		ri.pins[Digest(m)] = append(ri.pins[Digest(m)], why)
	}
}

// serving returns, per digest, the operator `holds` that are the current serving `holds` of their key: the
// key's highest-seq holds for the digest, not withdrawn. On a tie (an uncleared fork) every serving one
// counts, so the answer only ever keeps more.
func (ri *refIndex) serving() map[Digest][]holdsEntry {
	type k struct {
		signer string
		d      Digest
	}
	top := map[k]int64{}
	for _, h := range ri.holds {
		if ri.ops != nil && !ri.ops[h.signer] {
			continue
		}
		if cur, ok := top[k{h.signer, h.digest}]; !ok || h.seq > cur {
			top[k{h.signer, h.digest}] = h.seq
		}
	}
	out := map[Digest][]holdsEntry{}
	for _, h := range ri.holds {
		if ri.ops != nil && !ri.ops[h.signer] {
			continue
		}
		if h.seq == top[k{h.signer, h.digest}] && !h.withdrawn {
			out[h.digest] = append(out[h.digest], h)
		}
	}
	return out
}

func (ri *refIndex) refs(d Digest) []string {
	return append(slices.Clone(ri.pins[d]), ri.jpins[d]...)
}

// why returns what pins d, or "" when nothing does.
func (ri *refIndex) why(d Digest) string {
	var parts []string
	if ws := ri.refs(d); len(ws) > 0 {
		first := slices.Min(ws)
		if len(ws) > 1 {
			first += fmt.Sprintf(" and %d more", len(ws)-1)
		}
		parts = append(parts, "referenced by "+first)
	}
	if hs := ri.serving()[d]; len(hs) > 0 {
		slices.SortFunc(hs, func(a, b holdsEntry) int { return strings.Compare(a.id, b.id) })
		parts = append(parts, fmt.Sprintf("served under holds %s by %s; name the hash with --release to withdraw and delete", hs[0].id, hs[0].signer))
	}
	return strings.Join(parts, "; ")
}

// GC lists, and with apply deletes, the unreferenced blobs outside the grace window (§6.1, §6.1.1). Without
// apply nothing changes. It never deletes a statement or a journal record, and re-checks each blob
// immediately before removing it: the file is moved out of the blob namespace, references and window are
// checked again, and it is either removed or moved back.
func (s *Store) GC(cfg GCConfig, apply bool) (*GCPlan, error) {
	grace, src, err := cfg.Grace()
	if err != nil {
		return nil, err
	}
	now := cfg.now()
	plan := &GCPlan{Grace: grace, GraceSource: src}
	ri := s.newRefIndex(cfg.Operators)
	if err := ri.refresh(); err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(s.dir("blobs", "sha256"))
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if !reHex.MatchString(e.Name()) || e.IsDir() {
			plan.Strays = append(plan.Strays, e.Name())
			continue
		}
		fi, err := e.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		d := Digest("sha256:" + e.Name())
		b := GCBlob{Digest: d, Size: fi.Size()}
		if w := ri.why(d); w != "" {
			b.Why = w
			plan.Kept = append(plan.Kept, b)
			continue
		}
		if age := now.Sub(fi.ModTime()); age < grace {
			b.Why = fmt.Sprintf("inside the grace window (installed or reused %s ago, window %s)", age.Round(time.Second), grace)
			plan.Kept = append(plan.Kept, b)
			continue
		}
		b.Why = "unreferenced, outside the grace window"
		plan.Candidates = append(plan.Candidates, b)
	}
	if !apply {
		return plan, nil
	}
	plan.Applied = true
	for _, c := range plan.Candidates {
		kept, err := s.removeIfStillUnreferenced(c, ri, grace, now)
		if err != nil {
			return plan, err
		}
		if kept != "" {
			c.Why = kept
			plan.Skipped = append(plan.Skipped, c)
			continue
		}
		plan.Deleted = append(plan.Deleted, c)
	}
	return plan, nil
}

// removeIfStillUnreferenced is the re-check at deletion (§6.1.1). Moving the file aside first closes the
// window in which an installer could reuse it while it is being deleted: a concurrent install now finds no
// destination and installs its own verified copy. It returns the reason the blob was kept, or "" when it was
// removed.
func (s *Store) removeIfStillUnreferenced(c GCBlob, ri *refIndex, grace time.Duration, now time.Time) (string, error) {
	src := s.blobPath(c.Digest)
	f, err := os.CreateTemp(s.dir("tmp"), "gc-"+strings.TrimPrefix(string(c.Digest), "sha256:")+"-*")
	if err != nil {
		return "", err
	}
	aside := f.Name()
	f.Close()
	if err := os.Remove(aside); err != nil {
		return "", err
	}
	if err := os.Rename(src, aside); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "already gone", nil
		}
		return "", err
	}
	if err := s.hook(GCMoved); err != nil {
		if !errors.Is(err, ErrCrash) { // a crash leaves the file where a dead process would: Open puts it back
			_ = s.restoreAside(aside, src)
		}
		return "", err
	}
	if err := ri.refresh(); err != nil {
		_ = s.restoreAside(aside, src)
		return "", err
	}
	keep := ""
	if w := ri.why(c.Digest); w != "" {
		keep = "gained a reference since the listing: " + w
	} else if fi, err := os.Stat(aside); err != nil {
		keep = "unreadable at the re-check: " + err.Error()
	} else if now.Sub(fi.ModTime()) < grace {
		keep = "its grace window restarted since the listing"
	}
	if keep != "" {
		return keep, s.restoreAside(aside, src)
	}
	if err := os.Remove(aside); err != nil {
		return "", err
	}
	return "", s.syncDir(filepath.Dir(src))
}

// restoreAside puts a moved blob back create-exclusive. If an installer put a copy there meanwhile, the
// moved file is a duplicate and is dropped.
func (s *Store) restoreAside(aside, dst string) error {
	if err := os.Link(aside, dst); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := os.Remove(aside); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return s.syncDir(filepath.Dir(dst))
}

// ---------------------------------------------------------------------------------------------------------
// gc --release

// Signer signs one draft for Release. Signing may be refused (no key, a prompt declined); Release then
// deletes nothing and commits nothing (C-core-145 (d)).
type Signer interface {
	// Key is the signer string of the key ("ed25519:<hex>" or "0x<address>").
	Key() string
	SignDraft(d wire.Draft) ([]byte, error)
}

type keySigner struct {
	k   wire.Key
	now func() time.Time
}

func (k keySigner) Key() string { return k.k.Signer() }
func (k keySigner) SignDraft(d wire.Draft) ([]byte, error) {
	st, err := wire.Write(d, k.k, k.now())
	if err != nil {
		return nil, err
	}
	return st.Line(), nil
}

// SignerFromKey adapts a wire.Key (a nil clock means time.Now).
func SignerFromKey(k wire.Key, now func() time.Time) Signer {
	if now == nil {
		now = time.Now
	}
	return keySigner{k, now}
}

func holdsBody(blob Digest, withdrawn bool) *canon.Object {
	c := &canon.Object{Keys: []string{"digest", "size"}, Members: map[string]canon.Value{}}
	c.Members["digest"] = canon.String(blob)
	return &canon.Object{Keys: []string{"content", "withdrawn"}, Members: map[string]canon.Value{
		"content": c, "withdrawn": canon.Bool(withdrawn)}}
}

// ReleaseResult says what Release did.
type ReleaseResult struct {
	Blob Digest
	// Withdrawal is the id of the committed `holds` statement; empty when this call committed none.
	Withdrawal string
	Op         string
	// BlobRemoved is true when the file was deleted.
	BlobRemoved bool
	// Completed is true when an earlier release had already committed its withdrawal and this call only
	// removed the blob.
	Completed bool
	// NeedsRepair is set when the withdrawal committed and its projection step failed (§3.5).
	NeedsRepair error
}

// Release is `gc --release <hash>` (§6.2): one operation that signs a `holds` with withdrawn:true for the
// blob, commits it through the commit protocol, and removes the blob only after the commit point and after
// the withdrawal is installed. A crash leaves the blob and no withdrawal (before the commit point) or the
// withdrawal and the blob (after it; the blob is then a gc candidate unless something else pins it, and
// Release again completes the removal). Never the reverse. It needs the signer's current serving `holds` for
// the hash; with none there is nothing to withdraw and the error says so. It refuses while a journal record
// names the blob. Statements are never deleted.
//
// The size recorded in the withdrawal is the blob's present size.
func (s *Store) Release(blob Digest, sg Signer) (*ReleaseResult, error) {
	if _, ok := blob.hex(); !ok {
		return nil, refusal.Malformed("digest %q is not sha256: + 64 lowercase hex", blob)
	}
	res := &ReleaseResult{Blob: blob}
	fi, err := os.Stat(s.blobPath(blob))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return res, fmt.Errorf("blob %s: unavailable (not held locally); nothing to release", blob)
		}
		return res, err
	}
	ri := s.newRefIndex([]string{sg.Key()})
	if err := ri.refresh(); err != nil {
		return res, err
	}
	if js := ri.jpins[blob]; len(js) > 0 {
		return res, fmt.Errorf("blob %s: named by %s; not releasing until that operation is finished", blob, js[0])
	}
	if len(ri.serving()[blob]) == 0 {
		if ri.latestWithdrawn(sg.Key(), blob) {
			// An earlier release committed its withdrawal and stopped before the removal.
			res.Completed = true
			return res, s.removeReleased(blob, ri, res)
		}
		return res, fmt.Errorf("blob %s: %s has no current serving holds for it, so there is nothing to release (gc removes it once unreferenced and outside the grace window)", blob, sg.Key())
	}
	prev, err := s.logHead(sg.Key())
	if err != nil {
		return res, err
	}
	d := wire.Draft{Kind: "holds", TS: time.Now().UTC().Format("2006-01-02T15:04:05Z"), Body: holdsBody(blob, true)}
	d.Body.Members["content"].(*canon.Object).Members["size"] = canon.Int(fi.Size())
	if prev != nil {
		d.Seq, d.Prev = prev.Seq+1, prev.ID
		if now, err := rctime.ParseUTC(d.TS); err == nil && rctime.Compare(prev.TS, now) > 0 {
			d.TS = prev.TS.Text // never earlier than the line it follows (C-core-106)
		}
	}
	line, err := sg.SignDraft(d)
	if err != nil {
		return res, &refusal.Refusal{Class: refusal.Policy, Reason: SigningRefused,
			Detail: fmt.Sprintf("%v; nothing committed, blob %s kept", err, blob)}
	}
	out, err := s.Commit("release", [][]byte{line}, nil)
	res.Op = out.Op
	if len(out.IDs) == 1 {
		res.Withdrawal = out.IDs[0]
	}
	if err != nil {
		return res, err // the blob is untouched whether or not the commit point was reached
	}
	res.NeedsRepair = out.NeedsRepair
	if err := s.hook(AfterWithdrawal); err != nil {
		return res, err
	}
	if err := ri.refresh(); err != nil {
		return res, err
	}
	return res, s.removeReleased(blob, ri, res)
}

// removeReleased deletes the blob once the signer's current holds for it is a withdrawal.
func (s *Store) removeReleased(blob Digest, ri *refIndex, res *ReleaseResult) error {
	if hs := ri.serving()[blob]; len(hs) > 0 {
		return fmt.Errorf("blob %s: serving holds %s is still current; not deleting", blob, hs[0].id)
	}
	if err := os.Remove(s.blobPath(blob)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := s.syncDir(s.dir("blobs", "sha256")); err != nil {
		return err
	}
	res.BlobRemoved = true
	return s.hook(AfterBlobRemoved)
}

// latestWithdrawn: the signer's highest-seq holds for the digest is a withdrawal.
func (ri *refIndex) latestWithdrawn(signer string, d Digest) bool {
	var best *holdsEntry
	for i := range ri.holds {
		h := &ri.holds[i]
		if h.signer == signer && h.digest == d && (best == nil || h.seq > best.seq) {
			best = h
		}
	}
	return best != nil && best.withdrawn
}

// logHead returns the tip of the signer's installed log: the statement no installed statement names as prev
// or in merges. On a fork, the highest seq (then the lowest id); the new line then follows that tip only and
// leaves FORK shown (§4.2). Nil when the signer has no statement.
func (s *Store) logHead(signer string) (*wire.Statement, error) {
	dir := s.dir("statements", signerDir(signer))
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sts []*wire.Statement
	hasSucc := map[string]bool{}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		st, err := wire.Read(b)
		if err != nil || st.ID != e.Name() || st.Signer != signer || !st.Verified {
			continue
		}
		sts = append(sts, st)
		if st.Prev != "" {
			hasSucc[st.Prev] = true
		}
		for _, m := range st.Merges {
			hasSucc[m] = true
		}
	}
	var tips []*wire.Statement
	for _, st := range sts {
		if !hasSucc[st.ID] {
			tips = append(tips, st)
		}
	}
	if len(tips) == 0 {
		return nil, nil
	}
	sort.Slice(tips, func(i, j int) bool {
		if tips[i].Seq != tips[j].Seq {
			return tips[i].Seq > tips[j].Seq
		}
		return tips[i].ID < tips[j].ID
	})
	return tips[0], nil
}

// restoreGCAsides runs on Open, before the temporary sweep. A process that died between moving a gc
// candidate out of blobs/ and deciding leaves tmp/gc-<hex>-*; the file is hashed and, if it is the blob its
// name says and blobs/ has no copy, linked back create-exclusive. A file that does not hash to its name is
// left for the sweep. Nothing here deletes a verified blob.
func (s *Store) restoreGCAsides() error {
	ents, err := os.ReadDir(s.dir("tmp"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, "gc-") || len(name) < 3+64+1 || !reHex.MatchString(name[3:67]) {
			continue
		}
		d := Digest("sha256:" + name[3:67])
		p := s.dir("tmp", name)
		have, err := hashFile(p)
		if err != nil || have != d {
			continue
		}
		if err := s.restoreAside(p, s.blobPath(d)); err != nil {
			return err
		}
		s.Recovered = append(s.Recovered, RecoveryEvent{What: "restored blob", Detail: string(d) + ": a gc run stopped before deciding; the verified file is back in blobs/"})
	}
	return nil
}
