package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// A signing key file, for the commands that sign (gc --release today). PROVISIONAL: the key-file format and
// key generation belong to the publish track; this loader exists so gc --release can sign, and is the merge
// point with it. The format is one canonical-JSON object:
//
//	{"alg":"ed25519","seed":"<64 hex>"}            an RFC 8032 seed
//	{"alg":"eip191-secp256k1","scalar":"<64 hex>"} a secp256k1 scalar
//
// The file is named by --key <file>, else $COMMONS_KEY_FILE; nothing is read implicitly. It must be a regular
// file readable by its owner only (no group or other permission bits). The key's bytes are never printed: an
// error names the file and what is wrong with it, never its contents.

// KeyEnv names the signing key file when --key is not given. A different name from the alpha tool's variable,
// so an alpha-format key is never misread as this one.
const KeyEnv = "COMMONS_KEY_FILE"

const maxKeyFile = 4096

func loadKeyFile(path string) (wire.Key, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("the key file cannot be read")
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("the key file is not a regular file")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("the key file is readable by group or others (mode %04o); chmod 600 it", fi.Mode().Perm())
	}
	b, err := readCapped(path, maxKeyFile)
	if err != nil {
		return nil, errors.New("the key file cannot be read, or is larger than a key file")
	}
	v, err := canon.Parse(b)
	if err != nil {
		v, err = canon.Parse(trimNL(b))
	}
	o, ok := v.(*canon.Object)
	if err != nil || !ok {
		return nil, errors.New("the key file is not a JSON object")
	}
	field := func(k string) ([]byte, error) {
		s, ok := o.Members[k].(canon.String)
		if !ok || len(s) != 64 {
			return nil, fmt.Errorf("the key file's %s is not 64 lowercase hex", k)
		}
		raw, err := hex.DecodeString(string(s))
		if err != nil || hex.EncodeToString(raw) != string(s) {
			return nil, fmt.Errorf("the key file's %s is not 64 lowercase hex", k)
		}
		return raw, nil
	}
	if len(o.Keys) != 2 {
		return nil, errors.New("the key file carries members other than alg and its key")
	}
	switch o.Members["alg"] {
	case canon.String(wire.AlgEd25519):
		seed, err := field("seed")
		if err != nil {
			return nil, err
		}
		return wire.Ed25519Key{Seed: seed}, nil
	case canon.String(wire.AlgEIP191):
		sc, err := field("scalar")
		if err != nil {
			return nil, err
		}
		return wire.EIP191Key{Scalar: sc}, nil
	}
	return nil, errors.New("the key file's alg is not one this tool signs with (ed25519, eip191-secp256k1)")
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
