package store

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

// What the repair command needs besides Repair itself: which blobs each unfinished record names (bytes given by
// hand are installed only against a digest a record names, hash-checked), and how much is under quarantine/
// (repair never reads, moves or deletes anything there; it says how much is there).

// JournalBlobs maps the op id of every journal record under root (pending or done) to the blobs it names, in
// the record's order. It reads the journal only: no replay, no quarantine, no write, so a command can check its
// invocation against the journal before it opens the store. A record that does not decode is not listed (the
// next open quarantines it); a store with no journal directory has no record.
func JournalBlobs(root string) (map[string][]Digest, error) {
	s := &Store{root: root}
	rs, err := s.records()
	if errors.Is(err, fs.ErrNotExist) {
		return map[string][]Digest{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make(map[string][]Digest, len(rs))
	for _, h := range rs {
		out[h.rec.Op] = append([]Digest(nil), h.rec.Blobs...)
	}
	return out, nil
}

// QuarantineCount is the number of items under quarantine/ (records, blobs and statement copies moved aside,
// never deleted). It only lists the directory.
func (s *Store) QuarantineCount() (int, error) {
	ents, err := os.ReadDir(s.dir("quarantine"))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return len(ents), nil
}

// HashReader is the content digest of everything r yields, in wire form: how a command checks bytes it was given
// against a digest before it opens the store. InstallBlob hashes what it writes again; that hash is the one that
// counts.
func HashReader(r io.Reader) (Digest, error) { return hashReader(r) }
