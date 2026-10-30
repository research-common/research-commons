// Package store is the local store of the storage note: content-addressed blobs (§1.1, §2), statements one
// per file under their id (§1), and the one commit protocol with its journal (§3). Projections live outside
// it; the store holds only authoritative objects and the journal.
//
// Layout (a recommendation of §1.1 for blobs; the rest is this implementation's choice, which the note
// leaves open):
//
//	<root>/rc-store                     version marker {"layout":"rc-store/1"}
//	<root>/blobs/sha256/<64 hex>        blob bytes, read-only
//	<root>/statements/<signer>/<id>     one canonical statement line, read-only
//	<root>/journal/pending/<op>.json    committed, not yet installed (§3.1 step 2)
//	<root>/journal/done/<op>.json       installed, projections pending (§3.1 step 4)
//	<root>/cache/<projection>/<digest>   projections (disposable; created on first use)
//	<root>/retained/<hex>               reserved: lines under an rc major this reader cannot compute ids for,
//	                                    keyed by the sha256 of their canonical form (wire §6, §8); written by pull
//	<root>/quarantine/                  corrupt blobs, statements and records, moved aside, never deleted
//	<root>/tmp/                         temporaries on the same filesystem (§2 step 1); Open removes those
//	                                    older than tmpGrace
//
// Every write that publishes an object is temporary file → fsync → create-exclusive link into place →
// fsync of the directory (the durability declaration, §7).
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/research-common/research-commons/internal/refusal"
)

// Reasons of the storage layer.
const (
	HashMismatch = "hash mismatch"
	CorruptBlob  = "stored copy corrupt"
)

var reHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Digest is a content digest in wire form: "sha256:" + 64 lowercase hex.
type Digest string

func (d Digest) hex() (string, bool) {
	s := string(d)
	if len(s) != 71 || s[:7] != "sha256:" || !reHex.MatchString(s[7:]) {
		return "", false
	}
	return s[7:], true
}

// BlobResult says what Install did with the destination.
type BlobResult string

const (
	Installed BlobResult = "installed" // renamed into place
	Reused    BlobResult = "reused"    // destination existed and re-hashed correctly
	Replaced  BlobResult = "replaced"  // destination was corrupt: quarantined, verified copy installed
)

// InstallBlob streams src into the blob store (§2). expect is the digest the caller expects, or "" when the
// bytes have no expectation yet (a first publish). The hash of what was written is the only hash that
// counts: a mismatch with expect installs nothing. An existing destination is re-hashed before reuse; a
// corrupt one is moved to quarantine and replaced by the verified copy (C-core-124).
func (s *Store) InstallBlob(src io.Reader, expect Digest) (Digest, BlobResult, error) {
	if expect != "" {
		if _, ok := expect.hex(); !ok {
			return "", "", refusal.Malformed("expected digest %q is not sha256: + 64 lowercase hex", expect)
		}
	}
	tmp, err := os.CreateTemp(s.dir("tmp"), "blob-*")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(tmp.Name()) // a no-op once linked into place and unlinked below
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), src); err != nil {
		tmp.Close()
		return "", "", err
	}
	if err := s.syncFile(tmp); err != nil {
		tmp.Close()
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		return "", "", err
	}
	got := Digest("sha256:" + hex.EncodeToString(h.Sum(nil)))
	if expect != "" && got != expect {
		return "", "", &refusal.Refusal{Class: refusal.Intrinsic, Reason: HashMismatch,
			Detail: fmt.Sprintf("expected %s, got %s; nothing installed", expect, got)}
	}
	if err := os.Chmod(tmp.Name(), 0o444); err != nil {
		return "", "", err
	}
	dst := s.blobPath(got)
	res, err := s.placeVerified(tmp.Name(), dst, got)
	return got, res, err
}

// placeVerified links a verified temporary into place create-exclusive; on an existing destination it
// re-hashes, reuses or replaces.
func (s *Store) placeVerified(tmp, dst string, want Digest) (BlobResult, error) {
	err := s.linkExclusive(tmp, dst)
	if err == nil {
		return Installed, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	have, herr := hashFile(dst)
	if herr == nil && have == want {
		// Reuse refreshes the grace window (§6.1.1): the window is measured from the last install or reuse, so
		// an old unreferenced blob a new operation is about to name is not a gc candidate between step 1 and
		// step 2. The blob's mtime is the window's clock; content is never touched.
		now := time.Now()
		if err := os.Chtimes(dst, now, now); err != nil {
			return "", err
		}
		return Reused, nil
	}
	if err := s.quarantine(dst, "blob"); err != nil {
		return "", err
	}
	if err := s.linkExclusive(tmp, dst); err != nil {
		return "", err
	}
	return Replaced, nil
}

// OpenBlob opens a held blob after re-hashing it (§2 step 5, C-core-123): a corrupt copy is refused, never
// read. The returned refusal names both hashes. A blob not held is fs.ErrNotExist. The path is opened once and
// hashed through that descriptor, which is then rewound and returned, so the bytes checked are the bytes the
// caller reads even if the path is replaced in between.
func (s *Store) OpenBlob(d Digest) (*os.File, error) {
	if _, ok := d.hex(); !ok {
		return nil, refusal.Malformed("digest %q is not sha256: + 64 lowercase hex", d)
	}
	f, err := os.Open(s.blobPath(d))
	if err != nil {
		return nil, err
	}
	have, err := hashReader(f)
	if err == nil && have != d {
		err = &refusal.Refusal{Class: refusal.Intrinsic, Reason: CorruptBlob,
			Detail: fmt.Sprintf("blob %s: stored copy corrupt (hashes to %s); refetch", d, have)}
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// HasBlob reports whether a file is present under d (not whether it is intact; OpenBlob checks that).
func (s *Store) HasBlob(d Digest) bool {
	if _, ok := d.hex(); !ok {
		return false
	}
	_, err := os.Stat(s.blobPath(d))
	return err == nil
}

func (s *Store) blobPath(d Digest) string {
	h, _ := d.hex()
	return filepath.Join(s.root, "blobs", "sha256", h)
}

func hashFile(p string) (Digest, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return hashReader(f)
}

func hashReader(r io.Reader) (Digest, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return Digest("sha256:" + hex.EncodeToString(h.Sum(nil))), nil
}
