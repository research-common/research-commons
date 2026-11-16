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

// Commit points, named for crash injection (C-core-125, P-10). BeforeBlobs and AfterCommitBeforeOutput are a
// command's own (it calls Store.FaultPoint there); AfterBlobTemp is inside InstallBlob; the rest are Commit's.
const (
	BeforeBlobs             = "before step 1 (lines signed, no blob installed)"
	AfterBlobTemp           = "step 1, mid-blob (temporary written, not linked into place)"
	AfterCommitBeforeOutput = "after the commit returned, before the command's output"
	AfterBlobs              = "after step 1 (blobs installed)"
	AfterRecord             = "after step 2 (record pending)"
	AfterStatement          = "after step 3, one statement installed"
	AfterInstall            = "after step 3 (all statements installed)"
	AfterDone               = "after step 4 (record done)"
	AfterProject            = "after step 5 (projections)"
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
	// Installed is true once every statement of the operation is installed under its id (step 3 done). An error
	// with Installed set happened later (step 4 or 5): the statements are visible and only the journal's own
	// bookkeeping is unfinished, so the operation is not "pending install".
	Installed bool
	// IDs of the statements, in the order given.
	IDs []string
	// Replaced lists statement ids whose stored file was corrupt: quarantined and replaced by the verified line.
	Replaced []string
	// NeedsRepair is set when step 5 failed: the operation is committed and its projections are untrusted.
	NeedsRepair error
}

// Commit runs the protocol of §3.1 for one operation: blobs (already installed by the caller through
// InstallBlob, and listed here so the record names them), then the record (the commit point), then the
// statements, then done, then projections. Every line is read through wire.ReadStored first (rc/1 and rc/2 verified): nothing that a reader
// would refuse is committed. A blob a statement depends on must already be held.
//
// An error with Outcome.Committed false means nothing was committed. An error with Committed true means the
// record exists (the commit point was reached) and steps 3–4 did not finish; the error says so, names the
// op id, and the next Open replays the operation. A step-5 failure is not an error: Outcome.NeedsRepair.
func (s *Store) Commit(kind string, lines [][]byte, blobs []Digest) (Outcome, error) {
	var out Outcome
	canonical := make([][]byte, len(lines))
	for i, l := range lines {
		st, err := wire.ReadStored(l)
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
	if err := s.refuseBlockedSigners(canonical); err != nil {
		return out, err
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
		err = s.finish(r, &out, false)
	}
	if err != nil {
		if out.Installed {
			return out, fmt.Errorf("operation %s committed and installed; finishing its journal record failed: %w; commons repair %s (or the next open of the store) finishes it", r.Op, err, r.Op)
		}
		return out, fmt.Errorf("operation %s committed, pending install: %w; commons repair %s (or the next open of the store) replays it", r.Op, err, r.Op)
	}
	return out, nil
}

// finish runs steps 3–5 for a committed record. It is the replay path too, so every step is idempotent.
//
// replay says the call is a replay or a repair (not the commit that wrote the record): the history line says so.
func (s *Store) finish(r Record, out *Outcome, replay bool) error {
	pending := s.dir("journal", "pending", r.Op+".json")
	done := s.dir("journal", "done", r.Op+".json")
	if _, err := os.Stat(pending); err != nil {
		// A done record: step 3 already ran once, but a statement file may have been removed since (by hand, or a
		// restore of part of the store). Step 3 is idempotent (an identical file already in place is success), so
		// it runs again here: replay and repair reinstall what the record holds, never anything else.
		for _, l := range r.Lines {
			id, res, err := s.installStatement(l)
			if err != nil {
				return err
			}
			if res == Replaced {
				out.Replaced = append(out.Replaced, id)
			}
		}
		out.Installed = true
	} else {
		var ids []string
		for _, l := range r.Lines {
			id, res, err := s.installStatement(l)
			if err != nil {
				return err
			}
			ids = append(ids, id)
			if res == Replaced {
				out.Replaced = append(out.Replaced, id)
			}
			if err := s.hook(AfterStatement); err != nil {
				return err
			}
		}
		out.Installed = true
		if err := s.hook(AfterInstall); err != nil {
			return err
		}
		// Another committer of the identical operation (same record, same op id) may have renamed it first;
		// steps 3–5 are idempotent, so that is success. Only the call whose rename moved the record writes its
		// history line, so an operation gets one line at most.
		moved := true
		if err := os.Rename(pending, done); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			moved = false
		}
		if err := s.syncDir(filepath.Dir(done)); err != nil {
			return err
		}
		if err := s.syncDir(filepath.Dir(pending)); err != nil {
			return err
		}
		if moved {
			// the operation history (§3.6): after step 4, before step 5; best-effort, never fails the operation
			s.historyFinished(r, ids, replay)
		}
		if err := s.hook(AfterDone); err != nil {
			return err
		}
	}
	// Step 5 begins by checking the blobs the record names are still held (§6.1.1, the residual case: gc removed
	// one between the check before step 2 and now). Nothing is rolled back; the done record stays until the
	// bytes are installed again and Repair finishes it.
	for _, b := range r.Blobs {
		if !s.HasBlob(b) {
			out.NeedsRepair = fmt.Errorf("operation %s committed, needs repair: blob %s missing; install the bytes again (commons repair %s --blob <file>, or commons fetch %s from a hold and then commons repair %s); commons status shows it until then", r.Op, b, r.Op, b, r.Op)
			return nil
		}
	}
	if s.opt.Project != nil {
		if err := s.opt.Project(r); err != nil {
			out.NeedsRepair = fmt.Errorf("operation %s committed, needs repair: projection failed: %w; once the cause is fixed, commons repair %s re-projects it (so does the next open of the store); commons status shows it until then", r.Op, err, r.Op)
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
// A file already under the id that reads (wire.ReadStored, signature verified) to that same id is the same
// statement (wire §2: the id is the statement; any valid signature over one signed string is one statement),
// so it stays and this is success. A file that does not read to the id is a corrupt stored copy: it is moved
// to quarantine and the verified line installed in its place, as §2 does for blobs. Either way a corrupt file
// never makes the store unopenable (I15).
func (s *Store) installStatement(line []byte) (string, BlobResult, error) {
	st, err := wire.ReadStored(line)
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
		if hs, herr := wire.ReadStored(have); herr == nil && hs.ID == st.ID && (hs.Verified || !st.Verified) {
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
	// "replay failed" (the record could not be finished: Detail is the error; see replay), "quarantined" (the
	// record failed to decode or to verify), or, from Repair only, "nothing to repair" (no record has that id).
	What   string
	Detail string
}

// recover replays the journal (§3.4): every pending record is finished, every done record is re-projected.
// A record that fails to decode, or any of whose statements fails wire.ReadStored, is quarantined and none of its
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
					if _, err := wire.ReadStored(l); err != nil {
						derr = err
						break
					}
				}
			}
			if derr != nil {
				if err := s.quarantine(p, "record"); err != nil {
					return err
				}
				op := strings.TrimSuffix(e.Name(), ".json")
				s.Recovered = append(s.Recovered, RecoveryEvent{Op: op, What: "quarantined", Detail: derr.Error()})
				s.historyQuarantined(op)
			}
		}
	}
	rs, err := s.records()
	if err != nil {
		return err
	}
	for _, h := range rs {
		s.Recovered = append(s.Recovered, s.replay(h)...)
	}
	return nil
}

// replay finishes one record and reports what it did. A failure (an unwritable statements/ directory, a full
// disk) does not stop the open (degraded open): the record stays in the journal and the event "replay failed"
// names it with the error (Blocked lists it). If the failure came before every statement was installed, the
// statements it names are hidden from every reader (so the operation is not shown half installed) and a writer
// refuses a line by any of its signers, naming it (BlockedFor), until a later open or Repair finishes it. Every
// other command (status, fsck, reads of other statements) keeps working.
func (s *Store) replay(h held) []RecoveryEvent {
	var out Outcome
	var evs []RecoveryEvent
	err := s.finish(h.rec, &out, true)
	for _, id := range out.Replaced {
		evs = append(evs, RecoveryEvent{Op: h.rec.Op, Kind: h.rec.Kind, What: "replaced statement",
			Detail: id + ": stored copy corrupt, quarantined; verified line installed"})
	}
	if err != nil {
		s.block(h.rec, err, out.Installed)
		return append(evs, RecoveryEvent{Op: h.rec.Op, Kind: h.rec.Kind, What: "replay failed", Detail: err.Error()})
	}
	s.unblock(h.rec.Op)
	ev := RecoveryEvent{Op: h.rec.Op, Kind: h.rec.Kind, What: "projected"}
	if h.pending {
		ev.What = "replayed"
	}
	if out.NeedsRepair != nil {
		ev.What, ev.Detail = "needs repair", out.NeedsRepair.Error()
	}
	return append(evs, ev)
}

// blockedOp is a committed record whose replay failed on this open. When every statement it holds was installed
// (installed: the failure was later, at step 4 or 5) nothing is half shown, so nothing is hidden or refused; the
// failure is still reported.
type blockedOp struct {
	op, kind, err string
	installed     bool
	ids, signers  map[string]bool
}

func (s *Store) block(r Record, err error, installed bool) {
	s.unblock(r.Op)
	b := blockedOp{op: r.Op, kind: r.Kind, err: err.Error(), installed: installed, ids: map[string]bool{}, signers: map[string]bool{}}
	for _, l := range r.Lines {
		if st, rerr := wire.ReadStored(l); rerr == nil {
			b.ids[st.ID] = true
			b.signers[st.Signer] = true
		}
	}
	s.blocked = append(s.blocked, b)
}

func (s *Store) blockedOp(op string) *blockedOp {
	for i := range s.blocked {
		if s.blocked[i].op == op {
			return &s.blocked[i]
		}
	}
	return nil
}

func (s *Store) unblock(op string) {
	s.blocked = slices.DeleteFunc(s.blocked, func(b blockedOp) bool { return b.op == op })
}

// Blocked lists the operations whose replay failed on this open and are still unfinished: each with its kind and
// the error, as "replay failed" events. Their statements are hidden from readers and their signers' writes refused.
func (s *Store) Blocked() []RecoveryEvent {
	var out []RecoveryEvent
	for _, b := range s.blocked {
		out = append(out, RecoveryEvent{Op: b.op, Kind: b.kind, What: "replay failed", Detail: b.err})
	}
	return out
}

// ErrReplayFailed is the reason a writer gives when one of its signers is named by a record whose replay failed.
const ErrReplayFailed = "replay failed"

// BlockedFor is the refusal a writer for signer gets while a record naming that key failed its replay (nil when
// none does). Commit applies it too; a command calls it first so it refuses before it signs or installs anything.
func (s *Store) BlockedFor(signer string) error {
	for _, b := range s.blocked {
		if !b.installed && b.signers[signer] {
			return &refusal.Refusal{Class: refusal.Operational, Reason: ErrReplayFailed,
				Detail: fmt.Sprintf("operation %s (%s) of key %s is committed and could not be installed when this store was opened (%s); nothing was written", b.op, b.kind, signer, b.err)}
		}
	}
	return nil
}

// refuseBlockedSigners refuses an operation any of whose lines is signed by a key named by a record whose replay
// failed: the log's head is not known while that record's statements are hidden, so a new line could fork it.
func (s *Store) refuseBlockedSigners(lines [][]byte) error {
	for _, l := range lines {
		st, err := wire.ReadStored(l)
		if err != nil {
			continue // Commit refuses it already
		}
		if err := s.BlockedFor(st.Signer); err != nil {
			return err
		}
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

// Repair finishes the named journal records, or every record when none is named (§3.5): steps 3–5 again, each
// idempotent (a done record's statements are reinstalled if a file went missing). It continues past a record
// that fails and returns one event per record, in replay order: "replayed", "projected", "needs repair" or
// "replay failed" (with the error), and "nothing to repair" for a well-formed id no record has. A malformed id
// is refused before anything runs. It never signs, rewrites or deletes a statement, never rolls back, and never
// touches quarantine/. The error is for the journal listing only.
func (s *Store) Repair(ops ...string) ([]RecoveryEvent, error) {
	for _, op := range ops {
		if !reHex.MatchString(op) {
			return nil, refusal.Malformed("operation id %q is not 64 lowercase hex", op)
		}
	}
	rs, err := s.records()
	if err != nil {
		return nil, err
	}
	var out []RecoveryEvent
	found := map[string]bool{}
	for _, h := range rs {
		if len(ops) > 0 && !slices.Contains(ops, h.rec.Op) {
			continue
		}
		found[h.rec.Op] = true
		out = append(out, s.replay(h)...)
	}
	for _, op := range ops {
		if !found[op] {
			out = append(out, RecoveryEvent{Op: op, What: "nothing to repair"})
		}
	}
	return out, nil
}

func (s *Store) hidden(id string) bool {
	for _, b := range s.blocked {
		if !b.installed && b.ids[id] {
			return true
		}
	}
	return false
}

// Statements returns every installed statement line, verified through wire.ReadStored, keyed by id. Readers
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
		st, rerr := wire.ReadStored(b)
		if rerr != nil || st.ID != d.Name() {
			return nil // fsck reports it; never shown as anyone's word
		}
		if s.hidden(st.ID) {
			return nil // named by a record whose replay failed: the operation is not shown half installed
		}
		out[st.ID] = b
		return nil
	})
	if err != nil {
		return out, err
	}
	// A concurrent writer between step 2 and step 4 has some of its statements installed and its record still in
	// pending/: those are skipped, so a reader that takes no lock does not see the operation half installed (§3.3).
	// The journal is listed after the walk. A record still pending hides every statement it names. A done record
	// (step 4 reached: every statement installed) whose statements the walk saw only in part, because the walk
	// passed before the writer's later statements landed, hides the part it saw: an operation is shown whole or
	// not at all. The residue is a writer that also finished step 5 (record deleted) between the walk and the
	// listing; the storage note states it.
	ops, err := s.journalIDs()
	for _, o := range ops {
		whole := !o.pending
		for _, id := range o.ids {
			if _, ok := out[id]; !ok {
				whole = false
			}
		}
		if !whole {
			for _, id := range o.ids {
				delete(out, id)
			}
		}
	}
	return out, err
}

type journalOp struct {
	pending bool
	ids     []string
}

// journalIDs lists the statement ids of each record in journal/pending and journal/done, as readers need them:
// a record this open replayed in part and could not finish past step 3 counts as pending; one that installed
// every statement and failed later (step 4) counts as done.
func (s *Store) journalIDs() ([]journalOp, error) {
	var out []journalOp
	for _, sub := range []string{"pending", "done"} {
		dir := s.dir("journal", sub)
		ents, err := os.ReadDir(dir)
		if err != nil {
			return out, err
		}
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if errors.Is(err, fs.ErrNotExist) {
				continue // finished since the listing
			}
			if err != nil {
				return out, err
			}
			r, err := decodeRecord(b, e.Name())
			if err != nil {
				continue // the next open quarantines it; nothing from it is installed
			}
			o := journalOp{pending: sub == "pending"}
			if b := s.blockedOp(r.Op); b != nil && b.installed {
				o.pending = false // this open installed every statement and only step 4 failed
			}
			for _, l := range r.Lines {
				if st, err := wire.ReadStored(l); err == nil {
					o.ids = append(o.ids, st.ID)
				}
			}
			out = append(out, o)
		}
	}
	return out, nil
}
