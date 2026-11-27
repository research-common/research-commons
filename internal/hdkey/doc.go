// Package hdkey derives keys from a BIP-39 mnemonic phrase along a BIP-32 path. It is a library only: no
// command uses it yet, and it reads and writes no key file.
//
// It is written on the module's existing dependencies (PBKDF2 from golang.org/x/crypto, secp256k1 arithmetic
// from dcrd, HMAC and SHA-2 from the standard library). Both algorithms are small and are pinned by published
// test vectors, which the tests run from testdata.
//
// Secrets are byte slices the caller owns and can zero (Zero). No error text and no String method ever
// contains secret bytes.
//
// Not implemented, on purpose: Base58 extended keys (xprv, xpub), public-key-only derivation, wordlists other
// than English, and Unicode normalisation (see Seed and ParseMnemonic).
package hdkey
