package btctime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Reference-client fixtures (testdata/SOURCES.md): a calendar's real upgrade answer, the file the reference client
// wrote after merging that same answer, and a real multi-calendar pending proof. They pin the writer to the
// reference tools on real data, not only on test-built trees.

func fixtureSHA(t *testing.T, name, want string) []byte {
	t.Helper()
	b := fixtureFile(t, name)
	if got := sha256.Sum256(b); hex.EncodeToString(got[:]) != want {
		t.Fatalf("%s: sha256 %x, want %s (fixture changed)", name, got, want)
	}
	return b
}

const (
	shaIncomplete = "95673f2878cbcfdddded530bd2ad5f3fb04e13d2e659760d7c1386346fdd036c"
	shaUpgrade    = "4acea6404115ad0fe73589dc1e2ebdd39752decac1120b7a35873ec518619e24"
	shaUpgraded   = "965b5f4090439cc3f4a79576d48c93cb0b372176c76fccbb8e910afac5ac3413"
	shaMulti      = "de3927daebed0e07ce67e71c2c3576f75124f7ef17222ee7793dceda829ce332"
)

// TestMergeMatchesReferenceClient: merging the calendar's real answer into incomplete.txt.ots gives, byte for byte,
// the file the reference client wrote from the same answer; the result lists Bitcoin block 428 648 and keeps the
// pending attestation.
func TestMergeMatchesReferenceClient(t *testing.T) {
	pfile := fixtureSHA(t, "incomplete.txt.ots", shaIncomplete)
	answer := fixtureSHA(t, "incomplete-upgrade-428648.bin", shaUpgrade)
	want := fixtureSHA(t, "incomplete-upgraded.txt.ots", shaUpgraded)

	pending, err := ParseTree(pfile, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	pcs := PendingCommitments(pending)
	if len(pcs) != 1 {
		t.Fatalf("pending commitments %+v", pcs)
	}
	if got := hex.EncodeToString(pcs[0].Commitment); got != "57cfa5c46716df9bd9e83595bce439c58108d8fcc1678f30d4c6731c3f1fa6c79ed712c66fb1ac8d4e4eb0e7" {
		t.Fatalf("commitment %s is not the one the calendar was asked for", got)
	}
	merged, err := Merge(pending, pcs[0].Commitment, answer, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	got := merged.Serialize()
	if !bytes.Equal(got, want) {
		i := 0
		for i < len(got) && i < len(want) && got[i] == want[i] {
			i++
		}
		t.Fatalf("merged proof differs from the reference client's at byte %d (got %d bytes, want %d)", i, len(got), len(want))
	}
	p, err := ParseProof(got, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Bitcoin) != 1 || p.Bitcoin[0].Height != 428648 {
		t.Fatalf("bitcoin attestations %+v, want one at 428648", p.Bitcoin)
	}
	if p.PendingCount != 1 || p.Pending[0].URI != pcs[0].URI {
		t.Fatalf("pending %d %+v, want the original pending kept", p.PendingCount, p.Pending)
	}
	// the reference client's file round-trips too
	rt, err := ParseTree(want, Limits{})
	if err != nil || !bytes.Equal(rt.Serialize(), want) {
		t.Fatalf("reference upgraded file round trip: %v", err)
	}
}

// TestMultiCalendarReferenceRoundTrip: a real three-calendar pending proof written by the reference client
// round-trips byte for byte and lists its three pending calendars.
func TestMultiCalendarReferenceRoundTrip(t *testing.T) {
	b := fixtureSHA(t, "multi.txt.ots", shaMulti)
	tr, err := ParseTree(b, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tr.Serialize(), b) {
		t.Fatal("multi.txt.ots does not round-trip")
	}
	pcs := PendingCommitments(tr)
	if len(pcs) != 3 {
		t.Fatalf("pending commitments %d, want 3", len(pcs))
	}
	p, err := ParseProof(b, Limits{})
	if err != nil || p.PendingCount != 3 || len(p.Bitcoin) != 0 {
		t.Fatalf("ParseProof: %v %+v", err, p)
	}
	want := sha256.Sum256([]byte("research-commons anchor upgrade fixture 2026-11-15\n"))
	if p.FileDigest != want {
		t.Fatalf("file digest %x, want sha256 of the stamped string", p.FileDigest)
	}
}
