package cli

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/research-common/research-commons/internal/wire"
)

// key new, key show: first-run setup (claims-model note §11: "Generating a key is part of first-run setup")
// and the one way to see which signer a key file is. Neither reads a store; neither prints key material.

func init() {
	Register(&Command{Name: "key new", Summary: "generate a signing key into a new file (mode 0600, never overwritten)",
		Flags: []Flag{
			{Name: "out", Value: "file", Help: "the key file to create; its directory must exist; an existing file is never overwritten"},
			{Name: "alg", Value: "alg", Help: "ed25519 (default) or eip191-secp256k1", Check: checkAlg},
		},
		Help: "Writes the key as a small JSON file (format " + KeyFormat + ") holding the 32-byte Ed25519 seed or the secp256k1 scalar, mode 0600. The tool keeps no copy and uses no default location: name the file with --key or " + KeyEnv + " on every signing command. Back it up once, somewhere only you can read; never reuse a payment key as a Commons key (wire-format note §4.1). Seed-phrase derivation is not built.",
		Run:  keyNewCmd})
	Register(&Command{Name: "key show", Summary: "print the signer and algorithm of a key file (never the key)",
		Args: []Arg{{Name: "file", Shape: ShapeText}},
		Run:  keyShowCmd})
}

func checkAlg(v string) error {
	if _, ok := secretField[v]; !ok {
		return errors.New("the algorithm must be " + wire.AlgEd25519 + " or " + wire.AlgEIP191)
	}
	return nil
}

func keyNewCmd(c *Ctx) (*Obj, int, error) {
	out, ok := c.Flag("out")
	if !ok || out == "" {
		return nil, 0, usage("missing-argument", "the key file path is missing", "give --out <file>; nothing was done",
			"option --out", "commons key new --out <file>", "")
	}
	alg, ok := c.Flag("alg")
	if !ok {
		alg = wire.AlgEd25519
	}
	if abs, err := filepath.Abs(out); err == nil {
		out = abs
	}
	if _, err := os.Lstat(out); err == nil {
		return nil, 0, usage("key-file-unwritable", "the key file was not written",
			"a file already exists at that path; a key file is never overwritten; nothing was written", "option --out",
			"choose another path; to retire the old key, rotate or revoke it first", out)
	}
	k, secret, err := newKey(alg)
	if err != nil {
		return nil, 0, failed(errors.New("the random source failed"), "invocation", false, "run the command again")
	}
	signer := k.Signer() // before the secret is cleared: k shares its bytes
	b := keyFileBytes(alg, secret)
	clear(secret)
	if p := writeKeyFile(out, b); p != nil {
		clear(b)
		return nil, 0, p
	}
	clear(b)
	return newObj().set("signer", refV(signer)).set("alg", textV(alg)).set("file", peerV(out)).
		set("mode", textV("0600")).set("format", textV(KeyFormat)).
		set("next", textV("back the file up once, somewhere only you can read; sign with --key <file> or "+KeyEnv+"=<file>")), ExitOK, nil
}

func keyShowCmd(c *Ctx) (*Obj, int, error) {
	lk, p := loadKey(c.Args["file"], "argument file")
	if p != nil {
		return nil, 0, p
	}
	return newObj().set("signer", refV(lk.Key.Signer())).set("alg", textV(lk.Key.Alg())).set("file", peerV(lk.Path)).
		set("format", textV(KeyFormat)), ExitOK, nil
}
