package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// Key files (wire-format note §4.1, guidance). A key file holds one signing key as a small canonical JSON
// object:
//
//	{"alg":"ed25519","format":"rc-key/0","seed":"<64 hex>"}            the RFC 8032 seed, never the expanded scalar
//	{"alg":"eip191-secp256k1","format":"rc-key/0","scalar":"<64 hex>"} the secp256k1 scalar
//
// Both secrets are 32 bytes, so the file names its algorithm; the signer is recomputed from the secret on
// load, never trusted from the file. The format tag is this tool's own (no key-file format is published by
// the notes). Mnemonic derivation (§4.1, optional) is not built.
//
// Custody rules the tool enforces: the file is created mode 0600 with O_EXCL (never overwritten), in a
// directory that must already exist; on use, a file readable or writable by group or others, or one that is
// not a regular file (a symlink, a device), is refused before any work. There is no default key location:
// the key is named by --key or $COMMONS_KEY, every time. No surface ever prints key material: errors about a
// key file name the file and what is wrong with its shape, never its content.

// KeyEnv is the environment variable naming the key file when --key is not given.
const KeyEnv = "COMMONS_KEY"

// KeyFormat is the format tag of a key file.
const KeyFormat = "rc-key/0"

// maxKeyFile bounds a key file read: a real one is under 120 bytes.
const maxKeyFile = 4096

// secretField is the member holding the secret for each algorithm.
var secretField = map[string]string{wire.AlgEd25519: "seed", wire.AlgEIP191: "scalar"}

// newKey generates a key of alg from the OS's random source.
func newKey(alg string) (wire.Key, []byte, error) {
	switch alg {
	case wire.AlgEd25519:
		seed := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			return nil, nil, err
		}
		return wire.Ed25519Key{Seed: seed}, seed, nil
	case wire.AlgEIP191:
		pk, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return nil, nil, err
		}
		b := pk.Serialize()
		return wire.EIP191Key{Scalar: b}, b, nil
	}
	return nil, nil, errors.New("unknown algorithm")
}

func keyFileBytes(alg string, secret []byte) []byte {
	o := &canon.Object{Keys: []string{"alg", "format", secretField[alg]}, Members: map[string]canon.Value{
		"alg": canon.String(alg), "format": canon.String(KeyFormat), secretField[alg]: canon.String(hex.EncodeToString(secret))}}
	return append(canon.Encode(o), '\n')
}

// writeKeyFile creates path exclusively, mode 0600, and syncs it and its directory. It never overwrites.
func writeKeyFile(path string, b []byte) *Problem {
	bad := func(detail, next string) *Problem {
		return usage("key-file-unwritable", "the key file was not written", detail+"; nothing was written",
			"option --out", next, path)
	}
	dir := filepath.Dir(path)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return bad("the directory for the key file does not exist (the tool creates no directories for keys)",
			"create the directory yourself, with permissions you chose, then run the command again")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return bad("a file already exists at that path; a key file is never overwritten",
			"choose another path; to retire the old key, rotate or revoke it first")
	}
	if err != nil {
		return bad("the file could not be created", "check the path and the directory's permissions")
	}
	// the umask may have narrowed the mode; it cannot have widened it, but say exactly what is on disk
	if err := f.Chmod(0o600); err == nil {
		_, err = f.Write(b)
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		os.Remove(path)
		p := failed(errors.New("writing the key file failed"), "option --out", false, "check free space and permissions, then run the command again")
		p.Peer = path
		return p
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// loadedKey is a key read from a file: the key and the file it came from.
type loadedKey struct {
	Key  wire.Key
	Path string
}

// keyPath is the key file the invocation names: --key, else $COMMONS_KEY. There is no default.
func keyPath(c *Ctx) (string, string, *Problem) {
	if p, ok := c.Flag("key"); ok {
		return p, "option --key", nil
	}
	if p := c.Env.Getenv(KeyEnv); p != "" {
		return p, "environment " + KeyEnv, nil
	}
	return "", "", usage("no-key", "no signing key named",
		"this command signs and no key file was named; there is no default key location; nothing was done", "invocation",
		"create one with commons key new --out <file> (first-run setup), then give --key <file> or set "+KeyEnv, "")
}

// loadKey reads and checks a key file. Every failure is exit 2 and names the file, never its content.
func loadKey(path, scope string) (*loadedKey, *Problem) {
	bad := func(detail, next string) *Problem {
		p := usage("key-file-unusable", "the key file could not be used", detail+"; nothing was done", scope, next, path)
		return p
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, bad("the file does not exist or cannot be read", "check the path; create a key with commons key new --out <file>")
	}
	if !fi.Mode().IsRegular() {
		return nil, bad("the path is not a regular file (a symlink, directory or device is refused)", "name the key file itself")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		p := bad("the file is readable or writable by group or others", "restrict it with chmod 600, then run the command again")
		p.Class = refusal.Policy
		return nil, p
	}
	if fi.Size() > maxKeyFile {
		return nil, bad("the file is too large to be a key file", "name the key file itself")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, bad("the file cannot be read", "check its permissions")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	f.Close()
	if err != nil || len(b) > maxKeyFile {
		return nil, bad("the file cannot be read", "check its permissions")
	}
	malformed := func() (*loadedKey, *Problem) {
		return nil, bad("the file is not a key file of format "+KeyFormat+" (its content is not shown)", "name a key file written by commons key new")
	}
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	v, err := canon.Parse(b)
	if err != nil {
		return malformed()
	}
	o, ok := v.(*canon.Object)
	if !ok || o.Members["format"] != canon.String(KeyFormat) {
		return malformed()
	}
	alg, _ := o.Members["alg"].(canon.String)
	field, known := secretField[string(alg)]
	if !known || len(o.Keys) != 3 {
		return malformed()
	}
	keys := slices.Clone(o.Keys)
	slices.Sort(keys)
	want := []string{"alg", "format", field}
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		return malformed()
	}
	hx, ok := o.Members[field].(canon.String)
	if !ok || len(hx) != 64 {
		return malformed()
	}
	for _, ch := range string(hx) {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return malformed()
		}
	}
	secret, _ := hex.DecodeString(string(hx))
	switch string(alg) {
	case wire.AlgEd25519:
		return &loadedKey{Key: wire.Ed25519Key{Seed: secret}, Path: path}, nil
	default:
		var s secp256k1.ModNScalar
		if overflow := s.SetByteSlice(secret); overflow || s.IsZero() {
			return malformed()
		}
		return &loadedKey{Key: wire.EIP191Key{Scalar: secret}, Path: path}, nil
	}
}

// signingKey resolves and loads the invocation's key.
func signingKey(c *Ctx) (*loadedKey, *Problem) {
	p, scope, prob := keyPath(c)
	if prob != nil {
		return nil, prob
	}
	return loadKey(p, scope)
}
