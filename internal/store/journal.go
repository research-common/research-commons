package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// Record is one journal record (§3.1 step 2): everything needed to finish the operation without the
// process that started it. Its id is the hash of its canonical encoding, so a record cannot be edited
// without changing its name.
type Record struct {
	Op    string   // operation id: hex sha256 of the canonical record without "op"
	Kind  string   // operation kind (publish, pull, genesis, …), for status and explain
	Lines [][]byte // the signed statements, canonical lines
	Blobs []Digest // blobs the operation installed in step 1 (and that its statements need)
	// Seq orders records for replay: a strictly increasing counter assigned at commit.
	Seq int64
}

func (r Record) encode() []byte {
	lines := canon.Array{}
	for _, l := range r.Lines {
		lines = append(lines, canon.String(l))
	}
	blobs := canon.Array{}
	for _, b := range r.Blobs {
		blobs = append(blobs, canon.String(b))
	}
	o := &canon.Object{Keys: []string{"blobs", "kind", "lines", "seq"}, Members: map[string]canon.Value{
		"blobs": blobs, "kind": canon.String(r.Kind), "lines": lines, "seq": canon.Int(r.Seq)}}
	return canon.Encode(o)
}

func opID(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

func decodeRecord(b []byte, name string) (Record, error) {
	v, err := canon.Parse(bytes.TrimSuffix(b, []byte("\n")))
	if err != nil {
		return Record{}, err
	}
	o, ok := v.(*canon.Object)
	if !ok {
		return Record{}, errors.New("record is not an object")
	}
	var r Record
	k, ok1 := o.Members["kind"].(canon.String)
	seq, ok2 := o.Members["seq"].(canon.Int)
	ls, ok3 := o.Members["lines"].(canon.Array)
	bs, ok4 := o.Members["blobs"].(canon.Array)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return Record{}, errors.New("record fields missing or mistyped")
	}
	r.Kind, r.Seq = string(k), int64(seq)
	for _, x := range ls {
		s, ok := x.(canon.String)
		if !ok {
			return Record{}, errors.New("record line is not a string")
		}
		r.Lines = append(r.Lines, []byte(s))
	}
	for _, x := range bs {
		s, ok := x.(canon.String)
		if !ok {
			return Record{}, errors.New("record blob is not a string")
		}
		r.Blobs = append(r.Blobs, Digest(s))
	}
	r.Op = opID(r.encode())
	if name != "" && name != r.Op+".json" {
		return Record{}, fmt.Errorf("record %s hashes to %s", name, r.Op)
	}
	return r, nil
}

// Commit points, named for crash injection (C-core-125, P-10).
const (
	AfterBlobs     = "after step 1 (blobs installed)"
	AfterRecord    = "after step 2 (record pending)"
	AfterStatement = "after step 3, one statement installed"
	AfterInstall   = "after step 3 (all statements installed)"
	AfterDone      = "after step 4 (record done)"
	AfterProject   = "after step 5 (projections)"
)

// ErrCrash is what a crash hook returns to abort an operation at a commit point.
var ErrCrash = errors.New("injected crash")

// Outcome reports an operation. Committed says whether it reached its commit point (its record is in
// pending/ or later): the line between "nothing happened" and "it happened, maybe not all installed yet".
type Outcome struct {
	Op string
	// Committed is true once the record exists. An error with Committed set means the operation is committed
	// and its install is incomplete; the next Open (or Repair) replays it (§3.4). Status reports it as
	// "committed, pending install" meanwhile.
	Committed bool
	// IDs of the statements, in the order given.
	IDs []string
	// Replaced lists statement ids whose stored file was corrupt: quarantined and replaced by the verified line.
	Replaced []string
	// NeedsRepair is set when step 5 failed: the operation is committed and its projections are untrusted.
	NeedsRepair error
}

// Commit runs the protocol of §3.1 for one operation: blobs (already installed by the caller through
// InstallBlob, and listed here so the record names them), then the record (the commit point), then the
// statements, then done, then projections. Every line is read through wire.Read first: nothing that a reader
// would refuse is committed. A blob a statement depends on must already be held.
//
// An error with Outcome.Committed false means nothing was committed. An error with Committed true means the
// record exists (the commit point was reached) and steps 3–4 did not finish; the error says so, names the
// op id, and the next Open replays the operation. A step-5 failure is not an error: Outcome.NeedsRepair.
func (s *Store) Commit(kind string, lines [][]byte, blobs []Digest) (Outcome, error) {
	var out Outcome
	canonical := make([][]byte, len(lines))
	for i, l := range lines {
		st, err := wire.Read(l)
		if err != nil {
			return out, err
		}
		if st.ID == "" {
			return out, &refusal.Refusal{Class: refusal.Policy, Reason: "unsupported",
				Detail: "this writer does not commit a statement whose id it cannot compute (" + st.Why + ")"}
		}
		canonical[i] = st.Line()
		out.IDs = append(out.IDs, st.ID)
	}
	for _, b := range blobs {
		if !s.HasBlob(b) {
			return out, fmt.Errorf("blob %s is not held: install it before committing", b)
		}
	}
	if err := s.hook(AfterBlobs); err != nil {
		return out, err
	}
	seq, err := s.nextSeq()
	if err != nil {
		return out, err
	}
	r := Record{Kind: kind, Lines: canonical, Blobs: blobs, Seq: seq}
	body := r.encode()
	r.Op = opID(body)
	out.Op = r.Op
	if err := s.writeExclusive(s.dir("journal", "pending", r.Op+".json"), append(body, '\n'), 0o444); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return out, err
		}
		// The identical operation is already committed; finish it like any recovered record.
	}
	out.Committed = true
	err = s.hook(AfterRecord)
	if err == nil {
		err = s.finish(r, &out)
	}
	if err != nil {
		return out, fmt.Errorf("operation %s committed, pending install: %w; the next open of the store replays it", r.Op, err)
	}
	return out, nil
}

// finish runs steps 3–5 for a committed record. It is the replay path too, so every step is idempotent.
func (s *Store) finish(r Record, out *Outcome) error {
	pending := s.dir("journal", "pending", r.Op+".json")
	done := s.dir("journal", "done", r.Op+".json")
	if _, err := os.Stat(pending); err == nil {
		for _, l := range r.Lines {
			id, res, err := s.installStatement(l)
			if err != nil {
				return err
			}
			if res == Replaced {
				out.Replaced = append(out.Replaced, id)
			}
			if err := s.hook(AfterStatement); err != nil {
				return err
			}
		}
		if err := s.hook(AfterInstall); err != nil {
			return err
		}
		// Another committer of the identical operation (same record, same op id) may have renamed it first;
		// steps 3–5 are idempotent, so that is success.
		if err := os.Rename(pending, done); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := s.syncDir(filepath.Dir(done)); err != nil {
			return err
		}
		if err := s.syncDir(filepath.Dir(pending)); err != nil {
			return err
		}
		if err := s.hook(AfterDone); err != nil {
			return err
		}
	}
	if s.opt.Project != nil {
		if err := s.opt.Project(r); err != nil {
			out.NeedsRepair = fmt.Errorf("operation %s committed, needs repair: projection failed: %w; run repair", r.Op, err)
			return nil
		}
	}
	if err := s.hook(AfterProject); err != nil {
		return err
	}
	if err := os.Remove(done); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// installStatement places one verified line under statements/<signer>/<id>, create-exclusive (§3.1 step 3).
// A file already under the id that reads (wire.Read, signature verified) to that same id is the same
// statement (wire §2: the id is the statement; any valid signature over one signed string is one statement),
// so it stays and this is success. A file that does not read to the id is a corrupt stored copy: it is moved
// to quarantine and the verified line installed in its place, as §2 does for blobs. Either way a corrupt file
// never makes the store unopenable (I15).
func (s *Store) installStatement(line []byte) (string, BlobResult, error) {
	st, err := wire.Read(line)
	if err != nil {
		return "", "", err
	}
	dir := s.dir("statements", signerDir(st.Signer))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	dst := filepath.Join(dir, st.ID)
	for attempt := 0; ; attempt++ {
		err = s.writeExclusive(dst, st.Line(), 0o444)
		if err == nil {
			if attempt > 0 {
				return st.ID, Replaced, nil
			}
			return st.ID, Installed, nil
		}
		if !errors.Is(err, fs.ErrExist) || attempt > 0 {
			return "", "", err
		}
		have, rerr := os.ReadFile(dst)
		if errors.Is(rerr, fs.ErrNotExist) {
			continue // removed since the link failed; try once more
		}
		if rerr != nil {
			return "", "", rerr
		}
		if bytes.Equal(have, st.Line()) {
			return st.ID, Reused, nil
		}
		if hs, herr := wire.Read(have); herr == nil && hs.ID == st.ID && (hs.Verified || !st.Verified) {
			return st.ID, Reused, nil
		}
		if err := s.quarantine(dst, "statement"); err != nil {
			return "", "", err
		}
	}
}

// signerDir is the directory name for a signer: the signer string with ':' replaced (ed25519:<hex> is not a
// portable file name).
func signerDir(signer string) string { return strings.ReplaceAll(signer, ":", "-") }

// nextSeq is one more than the highest record seq in the journal, or 0. Records are deleted once projected,
// so the counter is per journal lifetime; it only orders records that coexist, which is all replay needs.
func (s *Store) nextSeq() (int64, error) {
	rs, err := s.records()
	if err != nil {
		return 0, err
	}
	var max int64 = -1
	for _, r := range rs {
		if r.rec.Seq > max {
			max = r.rec.Seq
		}
	}
	return max + 1, nil
}

type held struct {
	rec     Record
	pending bool
}

// records lists every journal record, pending and done, in replay order. A record that does not decode or
// whose name does not match its hash is quarantined and reported (§3.4).
func (s *Store) records() ([]held, error) {
	var out []held
	for _, sub := range []string{"pending", "done"} {
		dir := s.dir("journal", sub)
		ents, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if errors.Is(err, fs.ErrNotExist) {
				continue // moved to done/ or finished by another committer since the listing
			}
			if err != nil {
				return nil, err
			}
			r, err := decodeRecord(b, e.Name())
			if err != nil {
				continue // recover() quarantines it
			}
			out = append(out, held{r, sub == "pending"})
		}
	}
	slices.SortFunc(out, func(a, b held) int {
		switch {
		case a.rec.Seq < b.rec.Seq:
			return -1
		case a.rec.Seq > b.rec.Seq:
			return 1
		}
		return strings.Compare(a.rec.Op, b.rec.Op)
	})
	return out, nil
}

// RecoveryEvent is one thing journal replay did.
type RecoveryEvent struct {
	Op, Kind string
	// What: "replayed" (pending → installed), "projected" (done → projections rebuilt), "needs repair",
	// or "quarantined" (the record failed to decode or to verify).
	What   string
	Detail string
}

// recover replays the journal (§3.4): every pending record is finished, every done record is re-projected.
// A record that fails to decode, or any of whose statements fails wire.Read, is quarantined and none of its
// statements is installed (C-core-126).
func (s *Store) recover() error {
	for _, sub := range []string{"pending", "done"} {
		dir := s.dir("journal", sub)
		ents, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range ents {
			p := filepath.Join(dir, e.Name())
			b, err := os.ReadFile(p)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			r, derr := decodeRecord(b, e.Name())
			if derr == nil {
				for _, l := range r.Lines {
					if _, err := wire.Read(l); err != nil {
						derr = err
						break
					}
				}
			}
			if derr != nil {
				if err := s.quarantine(p, "record"); err != nil {
					return err
				}
				s.Recovered = append(s.Recovered, RecoveryEvent{Op: strings.TrimSuffix(e.Name(), ".json"),
					What: "quarantined", Detail: derr.Error()})
			}
		}
	}
	rs, err := s.records()
	if err != nil {
		return err
	}
	for _, h := range rs {
		var out Outcome
		if err := s.finish(h.rec, &out); err != nil {
			return fmt.Errorf("replaying %s: %w", h.rec.Op, err)
		}
		ev := RecoveryEvent{Op: h.rec.Op, Kind: h.rec.Kind, What: "projected"}
		if h.pending {
			ev.What = "replayed"
		}
		if out.NeedsRepair != nil {
			ev.What, ev.Detail = "needs repair", out.NeedsRepair.Error()
		}
		for _, id := range out.Replaced {
			s.Recovered = append(s.Recovered, RecoveryEvent{Op: h.rec.Op, Kind: h.rec.Kind, What: "replaced statement",
				Detail: id + ": stored copy corrupt, quarantined; verified line installed"})
		}
		s.Recovered = append(s.Recovered, ev)
	}
	return nil
}

// Status lists journal records still present: pending (committed, not installed: only visible between a
// crash and the next Open, which replays them) and done (installed, projections not yet rebuilt: needs
// repair).
func (s *Store) Status() ([]RecoveryEvent, error) {
	rs, err := s.records()
	if err != nil {
		return nil, err
	}
	var out []RecoveryEvent
	for _, h := range rs {
		w := "committed, needs repair"
		if h.pending {
			w = "committed, pending install"
		}
		out = append(out, RecoveryEvent{Op: h.rec.Op, Kind: h.rec.Kind, What: w})
	}
	return out, nil
}

// Repair re-runs step 5 for every done record (§3.5). It never signs, rewrites or deletes a statement.
func (s *Store) Repair() ([]RecoveryEvent, error) {
	rs, err := s.records()
	if err != nil {
		return nil, err
	}
	var out []RecoveryEvent
	for _, h := range rs {
		var o Outcome
		if err := s.finish(h.rec, &o); err != nil {
			return out, err
		}
		ev := RecoveryEvent{Op: h.rec.Op, Kind: h.rec.Kind, What: "projected"}
		if o.NeedsRepair != nil {
			ev.What, ev.Detail = "needs repair", o.NeedsRepair.Error()
		}
		out = append(out, ev)
	}
	return out, nil
}

// Statements returns every installed statement line, verified through wire.Read, keyed by id. Readers
// resolve from installed statements only: a statement in a pending record is not here (§3.3).
func (s *Store) Statements() (map[string][]byte, error) {
	out := map[string][]byte{}
	root := s.dir("statements")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		st, rerr := wire.Read(b)
		if rerr != nil || st.ID != d.Name() {
			return nil // fsck reports it; never shown as anyone's word
		}
		out[st.ID] = b
		return nil
	})
	return out, err
}
