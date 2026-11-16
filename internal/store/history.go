package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/research-common/research-commons/internal/canon"
)

// The operation history (storage note §3.6): one appended line per operation this store finished, written by the
// call that moved its journal record from pending/ to done/ (a live commit or a replay of a pending record), after
// that rename and before step 5. It is a convenience log, not part of the store:
//
//   - nothing reads it but the history command: no answer, status, explain, fsck, gc, repair, projection or gate
//     consults it (a test guards that no other production file names it), so deleting or editing it changes
//     nothing any other command prints;
//   - it lives under journal/, which no package, pull, push or hub check carries;
//   - it is best-effort: appended with O_APPEND and never synced, and a write error never fails the operation. A
//     crash right after step 4 may lose the line; the operation is committed regardless;
//   - it is bounded: at HistoryBound bytes the file is renamed to history.1.jsonl (replacing the previous one),
//     so at most two files of about HistoryBound bytes each are kept;
//   - its time is this machine's clock, evidence of nothing beyond this machine.
//
// A line is one canonical JSON object: {"v":1,"op","kind","statements","blobs","local_time","replayed"} for a
// finished operation, {"v":1,"event":"quarantined","op"} for a journal record moved to quarantine/ on open.

const (
	historyName    = "history.jsonl"
	historyRotated = "history.1.jsonl"
	// HistoryBound is the size at which the history file is rotated (one rotated file is kept).
	HistoryBound = 8 << 20
)

// historyBound is HistoryBound, lowered by this package's tests to exercise the rotation.
var historyBound int64 = HistoryBound

// HistoryFiles are the history files under a store root, oldest first: the rotated file, then the current one.
// Either may be missing. Only the history command reads them.
func HistoryFiles(root string) []string {
	return []string{filepath.Join(root, "journal", historyRotated), filepath.Join(root, "journal", historyName)}
}

// IsHistoryPath says whether a slash-separated path relative to a store root is one of its history files. A pull
// of a whole store tree (a directory, or an archive of one) skips them: the history is never transported.
func IsHistoryPath(rel string) bool {
	return rel == "journal/"+historyName || rel == "journal/"+historyRotated
}

// historyDeclaration is the storage note §7 `history` value for a store opened with these options.
func (o Options) historyDeclaration() string {
	if o.NoHistory {
		return "off"
	}
	return "on (8 MiB × 2, rotate)"
}

// HistoryOn says whether this store appends to the operation history.
func (s *Store) HistoryOn() bool { return !s.opt.NoHistory }

// historyFinished appends the line of an operation this call moved to done/.
func (s *Store) historyFinished(r Record, ids []string, replayed bool) {
	st := canon.Array{}
	for _, id := range ids {
		st = append(st, canon.String(id))
	}
	bl := canon.Array{}
	for _, b := range r.Blobs {
		bl = append(bl, canon.String(b))
	}
	s.historyAppend(&canon.Object{Members: map[string]canon.Value{
		"v": canon.Int(1), "op": canon.String(r.Op), "kind": canon.String(r.Kind), "statements": st, "blobs": bl,
		"local_time": canon.String(time.Now().UTC().Format(time.RFC3339)), "replayed": canon.Bool(replayed)}})
}

// historyQuarantined appends the event of a journal record moved to quarantine/ on open.
func (s *Store) historyQuarantined(op string) {
	if !utf8.ValidString(op) {
		return // a file name that is not text: the quarantine directory itself is the evidence
	}
	s.historyAppend(&canon.Object{Members: map[string]canon.Value{
		"v": canon.Int(1), "event": canon.String("quarantined"), "op": canon.String(op)}})
}

// historyAppend writes one line, best-effort: every error is dropped (the operation it records is committed
// whatever happens here).
func (s *Store) historyAppend(o *canon.Object) {
	if s.opt.NoHistory {
		return
	}
	for k := range o.Members {
		o.Keys = append(o.Keys, k)
	}
	line := append(canon.Encode(o), '\n')
	cur := s.dir("journal", historyName)
	if fi, err := os.Stat(cur); err == nil && fi.Size()+int64(len(line)) > historyBound && fi.Size() > 0 {
		// two writers may both rotate: the second renames a short file over the first's; best-effort
		_ = os.Rename(cur, s.dir("journal", historyRotated))
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return
	}
	f, err := os.OpenFile(cur, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	_, _ = f.Write(line)
	_ = f.Close()
}
