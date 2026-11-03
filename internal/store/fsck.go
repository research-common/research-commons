package store

// fsck (storage note §6.3).
//
// Fsck scans blobs plus statements and journal and reports, as distinct classes: byte corruption, invalid
// authentication, unresolved references, projection drift, unreferenced storage, and the housekeeping
// classes (stale temporaries, orphan or unreadable journal records, stray files). It never changes
// authoritative state. Options can quarantine corrupt blobs (§2 step 5) and rebuild named projections;
// nothing else is ever written, signed or deleted.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/research-common/research-commons/internal/wire"
)

// Classes of finding, in report order.
const (
	FsckCorruptBlob     = "corrupt blob"
	FsckBadStatement    = "invalid statement"
	FsckMissingBlob     = "unresolved reference: blob"
	FsckMissingStmt     = "unresolved reference: statement"
	FsckDrift           = "projection drift"
	FsckUnreferenced    = "unreferenced blob"
	FsckStaleTmp        = "stale temporary"
	FsckJournal         = "journal record"
	FsckStray           = "stray file"
	FsckQuarantined     = "quarantined"
	FsckMarker          = "layout marker"
	FsckUnreadableEntry = "unreadable"
)

// Finding is one thing fsck found.
type Finding struct {
	Class  string
	Object string // a digest, statement id, path relative to the store, or operation id
	Detail string
	// Fatal marks findings that mean "a reader gets a wrong or missing answer" (corruption, invalid
	// authentication, unresolved references, drift); the others are housekeeping and storage notes.
	Fatal bool
}

func (f Finding) String() string { return fmt.Sprintf("%s: %s: %s", f.Class, f.Object, f.Detail) }

// FsckOptions select the optional actions.
type FsckOptions struct {
	// Quarantine moves corrupt blobs aside (§2 step 5). Nothing else is moved.
	Quarantine bool
	// Rebuild recomputes the named registered projections of Cache (§5.3 item 6); an unknown name is an error.
	Rebuild []string
	Cache   *Cache
	// DriftOf names the projections to compare with a cold rebuild; nil means every registered one of Cache.
	DriftOf []string
	// StaleTmp is how old a temporary must be to be reported stale; zero means the store's tmpGrace.
	StaleTmp time.Duration
	Now      time.Time
	// OnlyBlob restricts the byte check to one digest (a fetch's pre-reuse check); "" means all.
	OnlyBlob Digest
}

// FsckReport is the result. It is never "ok" by omission: Clean is true only when there is no finding of any
// class that matters (housekeeping and unreferenced storage do not make a store unclean).
type FsckReport struct {
	Findings []Finding
	// Scanned counts what was examined, so an empty report says what it covered.
	Blobs, Statements, Records int
	// Rebuilt lists projections `Rebuild` recomputed.
	Rebuilt []Rebuilt
	// Quarantined lists blobs moved aside.
	Quarantined []Digest
}

// Clean is true when no fatal finding was made.
func (r *FsckReport) Clean() bool {
	for _, f := range r.Findings {
		if f.Fatal {
			return false
		}
	}
	return true
}

// Of returns the findings of one class.
func (r *FsckReport) Of(class string) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Class == class {
			out = append(out, f)
		}
	}
	return out
}

// Render is the text a command prints: one line per finding, a summary that says what was scanned, and no
// "ok" unless there is no fatal finding.
func (r *FsckReport) Render() string {
	var b strings.Builder
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "%s\n", f)
	}
	for _, d := range r.Quarantined {
		fmt.Fprintf(&b, "moved to quarantine: %s\n", d)
	}
	for _, x := range r.Rebuilt {
		fmt.Fprintf(&b, "rebuilt projection %s (%d bytes)\n", x.Name, x.Bytes)
	}
	state := "no errors found"
	if !r.Clean() {
		state = "errors found"
	}
	fmt.Fprintf(&b, "scanned %d blob(s), %d statement(s), %d journal record(s): %s\n", r.Blobs, r.Statements, r.Records, state)
	return b.String()
}

// stmtInfo is what fsck keeps of one installed, verified statement.
type stmtInfo struct {
	id, signer, kind string
	content          Digest
	prev             string
	merges           []string
}

func infoOf(st *wire.Statement) stmtInfo {
	i := stmtInfo{id: st.ID, signer: st.Signer, kind: st.Kind, prev: st.Prev, merges: st.Merges}
	if d, ok := contentDigest(st); ok {
		i.content = d
	}
	return i
}

// Fsck scans the store (see the file comment). It reads every blob in full; the cost is the point.
func (s *Store) Fsck(opt FsckOptions) (*FsckReport, error) {
	r := &FsckReport{}
	add := func(class, obj, detail string, fatal bool) {
		r.Findings = append(r.Findings, Finding{Class: class, Object: obj, Detail: detail, Fatal: fatal})
	}
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}

	// Layout marker.
	if b, err := os.ReadFile(s.dir("rc-store")); err != nil {
		add(FsckMarker, "rc-store", "missing or unreadable: "+err.Error(), true)
	} else if strings.TrimSpace(string(b)) != layoutMarker {
		add(FsckMarker, "rc-store", fmt.Sprintf("unknown layout %q", strings.TrimSpace(string(b))), true)
	}

	// Blobs: byte corruption (C-core-123). Each file is hashed; the name is the claim.
	ents, err := os.ReadDir(s.dir("blobs", "sha256"))
	if err != nil {
		return nil, err
	}
	held := map[Digest]bool{} // present and intact
	present := map[Digest]bool{}
	for _, e := range ents {
		if !reHex.MatchString(e.Name()) || e.IsDir() {
			add(FsckStray, "blobs/sha256/"+e.Name(), "not a blob name; left alone", false)
			continue
		}
		d := Digest("sha256:" + e.Name())
		if opt.OnlyBlob != "" && d != opt.OnlyBlob {
			present[d], held[d] = true, true // not examined; assumed for reference purposes only in OnlyBlob mode
			continue
		}
		r.Blobs++
		present[d] = true
		have, err := hashFile(s.blobPath(d))
		if err != nil {
			add(FsckUnreadableEntry, string(d), err.Error(), true)
			continue
		}
		if have != d {
			add(FsckCorruptBlob, string(d), fmt.Sprintf("stored copy corrupt (hashes to %s); refetch or republish the bytes", have), true)
			if opt.Quarantine {
				if err := s.quarantine(s.blobPath(d), "blob"); err != nil {
					return r, err
				}
				r.Quarantined = append(r.Quarantined, d)
				delete(present, d)
			}
			continue
		}
		held[d] = true
	}

	// Statements: authentication and unresolved references.
	infos := map[string]stmtInfo{}
	var order []string
	err = filepath.WalkDir(s.dir("statements"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(s.root, p)
		b, err := os.ReadFile(p)
		if err != nil {
			add(FsckUnreadableEntry, rel, err.Error(), true)
			return nil
		}
		r.Statements++
		st, rerr := wire.Read(b)
		switch {
		case rerr != nil:
			add(FsckBadStatement, d.Name(), "does not read: "+rerr.Error()+" (never shown as anyone's word)", true)
		case st.ID != d.Name():
			add(FsckBadStatement, d.Name(), "file reads to id "+st.ID+" (stored under another name)", true)
		case filepath.Base(filepath.Dir(p)) != signerDir(st.Signer):
			add(FsckBadStatement, d.Name(), "stored in the directory of another signer than "+st.Signer, true)
		default:
			infos[st.ID] = infoOf(st)
			order = append(order, st.ID)
		}
		return nil
	})
	if err != nil {
		return r, err
	}
	sort.Strings(order)
	reported := map[Digest]bool{}
	referenced := map[Digest]bool{}
	for _, id := range order {
		in := infos[id]
		for _, p := range append(slices.Clone(in.merges), in.prev) {
			if p == "" {
				continue
			}
			if _, ok := infos[p]; !ok {
				add(FsckMissingStmt, id, "names predecessor "+p+", which is not held (detached until it arrives)", false)
			}
		}
		// A statement may name bytes this store never held or has released (external holds, a hub that
		// carries statements only, a withheld artifact): that is availability, never invalidity (§6.2, §9).
		if in.content != "" && in.kind != "describes" && !present[in.content] && !reported[in.content] {
			reported[in.content] = true
			add(FsckMissingBlob, string(in.content), fmt.Sprintf("unavailable (not held locally); named by %s statement %s", in.kind, id), false)
		}
	}
	// Referenced = any pin (the gc index): statements of any kind, journal.
	ri := s.newRefIndex(nil)
	if err := ri.refresh(); err != nil {
		return r, err
	}
	for d := range ri.pins {
		referenced[d] = true
	}

	// Journal: pending and done records, read without side effects.
	for _, sub := range []string{"pending", "done"} {
		dir := s.dir("journal", sub)
		jents, err := os.ReadDir(dir)
		if err != nil {
			return r, err
		}
		for _, e := range jents {
			r.Records++
			op := strings.TrimSuffix(e.Name(), ".json")
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				add(FsckJournal, op, "unreadable: "+err.Error(), true)
				continue
			}
			rec, derr := decodeRecord(b, e.Name())
			if derr != nil {
				add(FsckJournal, op, sub+" record does not decode ("+derr.Error()+"); the next open quarantines it, installing nothing from it", true)
				continue
			}
			for _, bl := range rec.Blobs {
				referenced[bl] = true
				if !present[bl] {
					// The record says the store promised these bytes: that replaces the plain "unavailable" note.
					r.Findings = slices.DeleteFunc(r.Findings, func(f Finding) bool {
						return f.Class == FsckMissingBlob && f.Object == string(bl) && !f.Fatal
					})
					add(FsckMissingBlob, string(bl), fmt.Sprintf("committed, needs repair: blob %s missing; named by %s journal record %s (%s); re-install the bytes", bl, sub, op, rec.Kind), true)
				}
			}
			if sub == "pending" {
				add(FsckJournal, op, fmt.Sprintf("%s record pending (committed, pending install); the next open replays it", rec.Kind), false)
				continue
			}
			// A done record whose statements are not all installed is an orphan: replay would fix it, so say so.
			var missing []string
			for _, l := range rec.Lines {
				if st, err := wire.Read(l); err == nil {
					if _, ok := infos[st.ID]; !ok {
						missing = append(missing, st.ID)
					}
				}
			}
			if len(missing) > 0 {
				add(FsckJournal, op, fmt.Sprintf("orphan done record: statement(s) %s are not installed; the next open replays it", strings.Join(missing, ", ")), true)
			} else {
				add(FsckJournal, op, fmt.Sprintf("%s record done, projections not yet rebuilt (committed, needs repair)", rec.Kind), false)
			}
		}
	}

	// Unreferenced storage: GC candidates, not errors.
	var unref []Digest
	for d := range held {
		if !referenced[d] && ri.serving()[d] == nil {
			unref = append(unref, d)
		}
	}
	slices.Sort(unref)
	for _, d := range unref {
		add(FsckUnreferenced, string(d), "no statement or journal record names it; a gc candidate once outside the grace window", false)
	}

	// Temporaries and quarantine.
	stale := opt.StaleTmp
	if stale == 0 {
		stale = tmpGrace
	}
	if tents, err := os.ReadDir(s.dir("tmp")); err == nil {
		for _, e := range tents {
			fi, err := e.Info()
			if err != nil {
				continue
			}
			if age := now.Sub(fi.ModTime()); age > stale {
				add(FsckStaleTmp, "tmp/"+e.Name(), fmt.Sprintf("last written %s ago; no committed state lives in tmp/; the next open removes it", age.Round(time.Minute)), false)
			}
		}
	}
	if qents, err := os.ReadDir(s.dir("quarantine")); err == nil && len(qents) > 0 {
		var names []string
		for _, e := range qents {
			names = append(names, e.Name())
		}
		add(FsckQuarantined, "quarantine/", fmt.Sprintf("%d item(s) moved aside, never deleted: %s", len(names), strings.Join(names, ", ")), false)
	}
	// The layout has no retained/ area (§1: a statement this reader cannot evaluate is stored under its id with
	// its signer's statements). One left by an earlier version is named, never read or deleted.
	if rents, err := os.ReadDir(s.dir("retained")); err == nil {
		add(FsckStray, "retained/", fmt.Sprintf("not part of the rc-store/1 layout (%d entr(ies)); statements this reader cannot evaluate are stored under statements/; left alone", len(rents)), false)
	}

	// Projections: drift against a cold rebuild, then optional rebuild.
	if opt.Cache != nil {
		drifts, err := opt.Cache.Drift(opt.DriftOf...)
		if err != nil {
			return r, err
		}
		for _, d := range drifts {
			add(FsckDrift, d.Name, fmt.Sprintf("entry %s differs from a cold rebuild (warm %s, cold %s); run --rebuild %s", d.Key, d.Warm, d.Cold, d.Name), true)
		}
		if len(opt.Rebuild) > 0 {
			rb, err := opt.Cache.Rebuild(opt.Rebuild...)
			r.Rebuilt = rb
			if err != nil {
				return r, err
			}
		}
	} else if len(opt.Rebuild) > 0 {
		return r, errors.New("fsck --rebuild: no projection cache was given")
	}
	return r, nil
}

// CheckBlob re-hashes one held blob and returns the finding, or nil when it is intact or not held. It is the
// pre-reuse check a fetch or run makes (C-core-123); OpenBlob does the same on the read path.
func (s *Store) CheckBlob(d Digest) (*Finding, error) {
	if _, ok := d.hex(); !ok {
		return nil, fmt.Errorf("digest %q is not sha256: + 64 lowercase hex", d)
	}
	have, err := hashFile(s.blobPath(d))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if have != d {
		return &Finding{Class: FsckCorruptBlob, Object: string(d), Fatal: true,
			Detail: fmt.Sprintf("stored copy corrupt (hashes to %s)", have)}, nil
	}
	return nil, nil
}
