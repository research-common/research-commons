package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
)

// TestRecoverQuarantinesRecordWithBadRC2Line: a journal record is installed whole or not at all. One holding a good
// rc/1 line beside an rc/2 line whose signature fails (a record an older release could have written) is
// quarantined whole when the store opens: neither line is installed, and the record is moved aside, not deleted.
// The release notes say so as an upgrade note.
func TestRecoverQuarantinesRecordWithBadRC2Line(t *testing.T) {
	conformance.Partial(t, "C-core-126", "a pending record holding a good rc/1 line and an rc/2 line with a bad signature is quarantined whole on open: nothing from it is installed")
	v, err := conformance.LoadSignedIdentityVectors()
	if err != nil {
		t.Fatal(err)
	}
	var rc2 []byte
	for _, p := range v.Positive {
		if p.Chain == "ed" && p.Name == "ed-inception" {
			rc2 = []byte(p.Line)
		}
	}
	if rc2 == nil {
		t.Fatal("no ed-inception vector")
	}
	bad := bytes.Replace(rc2, []byte(`"fixed-root-v1"`), []byte(`"fixed-root-v2"`), 1)
	if bytes.Equal(bad, rc2) {
		t.Fatal("the mutation did not reach the line")
	}

	root := t.TempDir()
	open(t, root, Options{NoSync: true})
	l0, id0 := authored(testKey("A"), 0, "", []byte("x"))
	r := Record{Kind: "publish", Lines: [][]byte{l0, bad}, Seq: 3}
	body := r.encode()
	pending := filepath.Join(root, "journal", "pending", opID(body)+".json")
	if err := os.WriteFile(pending, append(body, '\n'), 0o444); err != nil {
		t.Fatal(err)
	}
	s2 := open(t, root, Options{NoSync: true})
	if sts, _ := s2.Statements(); sts[id0] != nil {
		t.Fatal("the good rc/1 line of a quarantined record was installed")
	}
	if len(s2.Recovered) != 1 || s2.Recovered[0].What != "quarantined" {
		t.Fatalf("recovered %v", s2.Recovered)
	}
	if _, err := os.Stat(pending); err == nil {
		t.Fatal("the record is still pending")
	}
	if es, _ := os.ReadDir(filepath.Join(root, "quarantine")); len(es) == 0 {
		t.Fatal("nothing in quarantine: the record was deleted, not moved aside")
	}
	// the control: the same record with the good rc/2 line installs both
	root2 := t.TempDir()
	open(t, root2, Options{NoSync: true})
	ok := Record{Kind: "publish", Lines: [][]byte{l0, rc2}, Seq: 3}
	b2 := ok.encode()
	if err := os.WriteFile(filepath.Join(root2, "journal", "pending", opID(b2)+".json"), append(b2, '\n'), 0o444); err != nil {
		t.Fatal(err)
	}
	s3 := open(t, root2, Options{NoSync: true})
	if sts, _ := s3.Statements(); sts[id0] == nil || len(s3.Recovered) != 1 || s3.Recovered[0].What != "replayed" {
		t.Fatalf("the control record did not replay: %v", s3.Recovered)
	}
}
