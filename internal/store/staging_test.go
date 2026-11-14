package store

import (
	"bytes"
	"os"
	"testing"
	"time"
)

// TestStagingUndo: Undo removes only the blobs this operation installed; a blob that was already held, or that
// another operation touched since (its time changed), is kept.
func TestStagingUndo(t *testing.T) {
	s, err := Open(t.TempDir(), Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	held, _, err := s.InstallBlob(bytes.NewReader([]byte("held before")), "")
	if err != nil {
		t.Fatal(err)
	}
	g := s.Stage()
	for _, b := range []string{"held before", "mine", "touched"} {
		if err := g.Install(bytes.NewReader([]byte(b)), ""); err != nil {
			t.Fatal(err)
		}
	}
	mine, touched := digestOf([]byte("mine")), digestOf([]byte("touched"))
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(s.blobPath(touched), later, later); err != nil {
		t.Fatal(err)
	}
	kept, err := g.Undo()
	if err != nil {
		t.Fatal(err)
	}
	if !s.HasBlob(held) || s.HasBlob(mine) || !s.HasBlob(touched) || len(kept) != 1 || kept[touched] == "" {
		t.Fatalf("held %v mine %v touched %v kept %v", s.HasBlob(held), s.HasBlob(mine), s.HasBlob(touched), kept)
	}
}
