package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

func historyLines(t *testing.T, root string) []*canon.Object {
	t.Helper()
	var out []*canon.Object
	for _, f := range HistoryFiles(root) {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n")) {
			v, err := canon.Parse(l)
			if err != nil {
				t.Fatalf("history line is not strict JSON: %v: %q", err, l)
			}
			if !bytes.Equal(canon.Encode(v), l) {
				t.Fatalf("history line is not canonical: %q", l)
			}
			out = append(out, v.(*canon.Object))
		}
	}
	return out
}

// TestHistoryWritten: one line per finished operation, written by the call that moved the record to done/ (a
// live commit, or a replay of a pending record: then "replayed":true); a done-only replay and an identical
// re-commit add none; a quarantined record adds an event; NoHistory writes nothing and declares off.
func TestHistoryWritten(t *testing.T) {
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	if d := s.Durability().History; d != "on (8 MiB × 2, rotate)" {
		t.Fatalf("declaration %q", d)
	}
	k := testKey("A")
	data := []byte("dataset")
	d, _, _ := s.InstallBlob(bytes.NewReader(data), "")
	line, id := authored(k, 0, "", data)
	out, err := s.Commit("publish", [][]byte{line}, []Digest{d})
	if err != nil {
		t.Fatal(err)
	}
	h := historyLines(t, root)
	if len(h) != 1 {
		t.Fatalf("%d lines after one commit", len(h))
	}
	want := `{"blobs":["` + string(d) + `"],"kind":"publish","local_time":"`
	if got := string(canon.Encode(h[0])); !strings.HasPrefix(got, want) || !strings.HasSuffix(got, `","op":"`+out.Op+`","replayed":false,"statements":["`+id+`"],"v":1}`) {
		t.Fatalf("line %s", got)
	}
	// the identical operation again: its record already went through done/ and was removed, so this commit moves
	// a fresh pending record and writes a line (it is a second operation as far as this store saw it)
	if _, err := s.Commit("publish", [][]byte{line}, []Digest{d}); err != nil {
		t.Fatal(err)
	}
	if n := len(historyLines(t, root)); n != 2 {
		t.Fatalf("%d lines after a re-commit", n)
	}

	// a crash after the record: the replay on the next open finishes it and writes "replayed":true; the open after
	// that has nothing to do and writes nothing
	line2, id2 := authored(k, 1, id, data)
	s2 := open(t, root, Options{NoSync: true, crash: func(p string) error {
		if p == AfterRecord {
			return ErrCrash
		}
		return nil
	}})
	if _, err := s2.Commit("publish", [][]byte{line2}, nil); !errors.Is(err, ErrCrash) {
		t.Fatal(err)
	}
	if n := len(historyLines(t, root)); n != 2 {
		t.Fatalf("a crash before step 4 wrote a line: %d", n)
	}
	open(t, root, Options{NoSync: true})
	h = historyLines(t, root)
	if len(h) != 3 || h[2].Members["replayed"] != canon.Bool(true) || string(canon.Encode(h[2].Members["statements"])) != `["`+id2+`"]` {
		t.Fatalf("replay line: %d %s", len(h), canon.Encode(h[len(h)-1]))
	}

	// a crash after done (before step 5): the line is already written; the replay of the done record adds none
	line3, _ := authored(k, 2, id2, data)
	s3 := open(t, root, Options{NoSync: true, crash: func(p string) error {
		if p == AfterDone {
			return ErrCrash
		}
		return nil
	}})
	if _, err := s3.Commit("publish", [][]byte{line3}, nil); !errors.Is(err, ErrCrash) {
		t.Fatal(err)
	}
	if n := len(historyLines(t, root)); n != 4 {
		t.Fatalf("after a crash at step 4: %d lines", n)
	}
	open(t, root, Options{NoSync: true})
	if n := len(historyLines(t, root)); n != 4 {
		t.Fatalf("a done-only replay wrote a line: %d", n)
	}

	// a record that does not decode is quarantined on open: an event line names it
	bad := strings.Repeat("ab", 32)
	os.WriteFile(filepath.Join(root, "journal", "pending", bad+".json"), []byte("{not json"), 0o444)
	open(t, root, Options{NoSync: true})
	h = historyLines(t, root)
	if got := string(canon.Encode(h[len(h)-1])); got != `{"event":"quarantined","op":"`+bad+`","v":1}` {
		t.Fatalf("quarantine event %s", got)
	}

	// off: nothing appended, declared off
	n := len(historyLines(t, root))
	off := open(t, root, Options{NoSync: true, NoHistory: true})
	if off.Durability().History != "off" {
		t.Fatal(off.Durability().History)
	}
	line4, _ := authored(testKey("B"), 0, "", data)
	if _, err := off.Commit("publish", [][]byte{line4}, nil); err != nil {
		t.Fatal(err)
	}
	if len(historyLines(t, root)) != n {
		t.Fatal("history off still appended")
	}
}

// TestHistoryWriteErrorNeverFails: an unwritable history file (here: a directory in its place) fails nothing.
func TestHistoryWriteErrorNeverFails(t *testing.T) {
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	os.Mkdir(filepath.Join(root, "journal", "history.jsonl"), 0o755)
	line, id := authored(testKey("A"), 0, "", []byte("x"))
	out, err := s.Commit("publish", [][]byte{line}, nil)
	if err != nil || out.NeedsRepair != nil {
		t.Fatal(out, err)
	}
	if sts, _ := s.Statements(); sts[id] == nil {
		t.Fatal("not installed")
	}
	if st, _ := s.Status(); len(st) != 0 {
		t.Fatal(st)
	}
}

// TestHistoryRotation: past the bound the file is renamed to history.1.jsonl (replacing the older one), so at
// most two files are kept, and no line is split across them.
func TestHistoryRotation(t *testing.T) {
	defer func(b int64) { historyBound = b }(historyBound)
	historyBound = 600
	root := t.TempDir()
	s := open(t, root, Options{NoSync: true})
	k := testKey("A")
	prev := ""
	for i := int64(0); i < 12; i++ {
		line, id := authored(k, i, prev, []byte("x"))
		if _, err := s.Commit("publish", [][]byte{line}, nil); err != nil {
			t.Fatal(err)
		}
		prev = id
	}
	ents, _ := os.ReadDir(filepath.Join(root, "journal"))
	var names []string
	for _, e := range ents {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if strings.Join(names, ",") != "history.1.jsonl,history.jsonl" {
		t.Fatalf("journal files %v", names)
	}
	for _, f := range HistoryFiles(root) {
		fi, _ := os.Stat(f)
		if fi.Size() > historyBound {
			t.Fatalf("%s is %d bytes, bound %d", f, fi.Size(), historyBound)
		}
	}
	h := historyLines(t, root) // every line parses: none split
	if len(h) == 0 || len(h) >= 12 {
		t.Fatalf("%d lines kept of 12: rotation dropped none or all", len(h))
	}
	if string(h[len(h)-1].Members["statements"].(canon.Array)[0].(canon.String)) != prev {
		t.Fatal("the newest line is not the last operation")
	}
}
