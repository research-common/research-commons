package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/store"
)

// history [--limit N] [--op <id>]: the store's local operation history (storage note §3.6), newest first. It is a
// convenience log the store appends to when an operation finishes: not authoritative, never transported, and read
// by nothing but this command (a test guards that no other production file names it), so no answer, status,
// explain, fsck or repair depends on it. This command reads only the two history files: it never decides
// anything about the store, and it exits 0 whatever it finds (history off, no file yet, malformed lines: each is
// reported, and an empty list is a complete answer).

const historyHeader = "local, not authoritative; times are this machine's clock"

func init() {
	Register(&Command{Name: "history", Summary: "list operations this store finished, newest first (local, not authoritative)",
		Flags: []Flag{
			{Name: "limit", Value: "n", Help: "list at most n entries (default 50)",
				Check: func(v string) error {
					if n, err := strconv.Atoi(v); err != nil || n <= 0 {
						return errors.New("a positive whole number")
					}
					return nil
				}},
			{Name: "op", Value: "operation", Help: "only the entries of this operation id (64 lowercase hex)",
				Check: func(v string) error {
					if !reOpID.MatchString(v) {
						return errors.New("an operation id (64 lowercase hex)")
					}
					return nil
				}},
		},
		Store: true, Run: historyCmd,
		Help: "The store appends one line per operation it finishes (after the operation's statements are installed) and one per journal record it moves to quarantine/, under journal/: best-effort (a crash right after an operation may lose its line), bounded (8 MiB, then rotated to one older file), never transported, and read by nothing but this command, so deleting or editing it changes no other output. local_time is this machine's clock, evidence of nothing beyond it; replayed says the operation was finished by a later open or by repair rather than by the command that committed it. A line that does not parse is skipped and counted. Exit 0 always: with the history off (history off), with no history file yet, or with nothing matching, the list is empty and the output says why.",
	})
}

func historyCmd(c *Ctx) (*Obj, int, error) {
	limit := 50
	if v, ok := c.Flag("limit"); ok {
		limit, _ = strconv.Atoi(v)
	}
	op, byOp := c.Flag("op")
	o := newObj().set("store", refV(c.Root)).set("note", textV(historyHeader))
	if !c.Store.HistoryOn() {
		o.set("state", tokV(tok("history off")))
	} else {
		o.set("state", tokV(tok("history on")))
	}
	var entries []*canon.Object
	malformed, files := 0, 0
	for _, f := range store.HistoryFiles(c.Root) { // oldest first
		b, err := os.ReadFile(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			// unreadable: reported, never a failure (the history decides nothing)
			o.set("unreadable", peerV(err.Error()))
			continue
		}
		files++
		for _, l := range bytes.Split(b, []byte("\n")) {
			if len(l) == 0 {
				continue
			}
			if e := historyEntry(l); e != nil {
				entries = append(entries, e)
			} else {
				malformed++
			}
		}
	}
	slices.Reverse(entries) // newest first: lines are appended in finishing order
	rows := listV{}
	matched := 0
	for _, e := range entries {
		if byOp && string(e.Members["op"].(canon.String)) != op {
			continue
		}
		matched++
		if len(rows) < limit {
			rows = append(rows, historyRow(e))
		}
	}
	o.set("entries", rows)
	o.set("shown", intV(int64(len(rows)))).set("matched", intV(int64(matched)))
	if malformed > 0 {
		o.set("malformed_lines_skipped", intV(int64(malformed)))
	}
	switch {
	case !c.Store.HistoryOn():
		o.set("detail", textV("this store keeps no operation history; nothing is appended"))
	case files == 0:
		o.set("detail", textV("no history file yet: no operation has finished since the history was started, or the file was deleted"))
	case matched == 0 && byOp:
		o.set("detail", textV("no entry names that operation: it finished before the history was kept or rotated out, its line was lost, or it was never committed here"))
	case matched > len(rows):
		o.set("detail", textV(fmt.Sprintf("%d more entr(ies) not shown; raise --limit", matched-len(rows))))
	}
	return o, ExitOK, nil
}

// historyEntry parses one history line, or nil when it is not a well-formed entry of a version this reader knows.
func historyEntry(l []byte) *canon.Object {
	v, err := canon.Parse(l)
	if err != nil {
		return nil
	}
	e, ok := v.(*canon.Object)
	if !ok || e.Members["v"] != canon.Int(1) {
		return nil
	}
	op, ok := e.Members["op"].(canon.String)
	if !ok || !reOpID.MatchString(string(op)) {
		return nil
	}
	if ev, ok := e.Members["event"]; ok {
		if ev != canon.String("quarantined") {
			return nil
		}
		return e
	}
	if _, ok := e.Members["kind"].(canon.String); !ok {
		return nil
	}
	if _, ok := e.Members["local_time"].(canon.String); !ok {
		return nil
	}
	if _, ok := e.Members["replayed"].(canon.Bool); !ok {
		return nil
	}
	for _, k := range []string{"statements", "blobs"} {
		a, ok := e.Members[k].(canon.Array)
		if !ok {
			return nil
		}
		for _, x := range a {
			s, ok := x.(canon.String)
			if !ok || (k == "statements" && !isID(string(s))) || (k == "blobs" && !isDigest(string(s))) {
				return nil
			}
		}
	}
	return e
}

func historyRow(e *canon.Object) *Obj {
	x := newObj().set("operation", refV(string(e.Members["op"].(canon.String))))
	if _, ok := e.Members["event"]; ok {
		return x.set("what", tokV(tok("quarantined")))
	}
	x.set("what", tokV(tok("finished"))).set("kind", peerV(string(e.Members["kind"].(canon.String))))
	x.set("local_time", peerV(string(e.Members["local_time"].(canon.String))))
	x.set("replayed", boolV(bool(e.Members["replayed"].(canon.Bool))))
	var ids, bl []string
	for _, s := range e.Members["statements"].(canon.Array) {
		ids = append(ids, string(s.(canon.String)))
	}
	for _, s := range e.Members["blobs"].(canon.Array) {
		bl = append(bl, string(s.(canon.String)))
	}
	x.set("statements", refs(ids...)).set("blobs", refs(bl...))
	return x
}
