# Key files (`rc-key/0`)

A key file holds one signing key. `commons key new --out <file>` writes it; every command that signs
(`publish`, `publish task`, `gc --release`) reads one. `commons key show <file>` prints the signer a file
stands for, and nothing else.

**Status: provisional.** The format tag is this tool's own and is versioned (`rc-key/0`). The wire-format
note specifies what a signature is and how a signer is derived, not a file encoding. Expect the format to be
revised before a stable release; a revision gets a new tag, and a file with a tag this tool does not know is
refused, never guessed at.

## Format

One strict JSON object (UTF-8, no duplicate members), written in canonical form with a trailing newline. Exactly
three members:

| member | value |
|---|---|
| `format` | the string `rc-key/0` |
| `alg` | `ed25519` or `eip191-secp256k1` |
| `seed` (for `ed25519`) or `scalar` (for `eip191-secp256k1`) | the secret as 64 lowercase hex characters (32 bytes) |

For `ed25519` the secret is the RFC 8032 seed, never the expanded scalar. For `eip191-secp256k1` it is the
secp256k1 scalar and must be non-zero and below the curve order. A file with any other member, a missing
member, the wrong secret member for its algorithm, uppercase hex, or a secret of another length is refused.

The **signer is never stored in the file.** It is recomputed from the secret every time the file is loaded
(`ed25519:<public key hex>`, or the `0x` address for secp256k1). A file cannot claim to be a different signer
than its secret makes it.

## Permissions and custody

- `key new` creates the file with mode `0600`, exclusively: it never overwrites an existing file, and it does
  not create directories (the directory must exist).
- When a command loads a key, it refuses, before doing any work, a path that is not a regular file (a symlink,
  directory or device), a file readable or writable by group or others, and a file larger than 4 KiB. The fix
  for the permission case is `chmod 600`.
- **Key material is never printed.** No output, error, log line or JSON member carries the secret; an error
  about a key file names the file and what is wrong with its shape, not its content. `key show` prints the
  signer, the algorithm, the path and the format tag.
- **There is no default key path.** The tool does not look in your home directory and keeps no copy. Name the
  file with `--key <file>` or the `COMMONS_KEY` environment variable on every signing command; `--key` wins
  when both are given. With neither, the command exits 2 and tells you to run `commons key new --out <file>`.
- The tool never generates a key implicitly. First-run setup is `commons init`, then `commons key new`.

## Backup and reuse

- Back the file up once, somewhere only you can read. If it is lost, nothing can recover it: the key is the
  identity, and the signer that published with it cannot be resumed by a new key.
- If it leaks, anyone holding it can sign as you; there is no way to un-leak it. Stop using it and publish
  from a new key.
- Never use a wallet or payment key as a Commons key, and never reuse a Commons key elsewhere.
- Seed-phrase (mnemonic) derivation is not built.
