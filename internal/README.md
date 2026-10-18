# Next-format implementation (Go)

This tree is the new implementation of the format specified in `docs/DESIGN-notes-claims-model.md`,
`docs/DESIGN-notes-wire-format.md` and the other design notes, built test-first against
`docs/CONFORMANCE.md`. It lives on the `next` branch and will ship as `0.5.0-alpha.1`. Nothing here is wired
to a command yet; the alpha CLI under `bin/` and `lib/` is unchanged.

## Build and test

Go is pinned by `go.mod` (`toolchain`); with `GOTOOLCHAIN=auto` (the default) the right toolchain downloads
on first use. Three runtime dependencies, pinned by `go.sum`: `filippo.io/edwards25519` (Ed25519 point
checks), `github.com/decred/dcrd/dcrec/secp256k1/v4` (EIP-191 recovery), `golang.org/x/crypto` (keccak256).

```sh
go test ./...                                                     # everything
go test -run TestConformanceCases -v ./internal/conformance       # progress against CONFORMANCE.md
go test -run '^$' -fuzz FuzzRead -fuzztime 60s ./internal/wire    # one fuzz target (also FuzzParse, FuzzTime)
CGO_ENABLED=0 go build ./...                                      # static build
```

## Packages

| package | covers |
|---|---|
| `canon` | strict JSON reader and RFC 8785 writer (wire §1). The only JSON parser in the module: `encoding/json` is banned by a test, because its defaults (case-insensitive fields, last duplicate wins, invalid UTF-8 repaired) break the format |
| `rctime` | time values (wire §1.1): one spelling per instant, parsed comparison, FITS timescales, leap seconds as written |
| `sig` | Ed25519 with the pinned pre-checks, EIP-191 recovery and canonical encoding (wire §4) |
| `wire` | the envelope (incl. `merges`), the DSSE PAE signed string, statement ids, `crit`, unknown `rc`/`alg` (wire §2, §3, §6); the per-kind body schema (wire §5), the one validation core every gate will call; `Read` for received bytes, `Write` for the writer |
| `dag` | forks and their clearing over signed predecessor links: the one definition of "fork" and "cleared" shared by key logs and resource editions (claims-model I12, §8; wire §7) |
| `keylog` | per-key logs (wire §7, storage §4): ownership, duplicates, chained vs detached with the gap named, forks and `merges`, incoherent `ts`, log-relative refusals; key events (`rotate_key`/`revoke_key` in force once chained, the lines after each, successions); every answer a function of the held set, so delivery order changes nothing |
| `resolve` | the one resolver (claims-model I12): reads chained lines only and applies key events in log order. Slice 1 = resources (claims §8): genesis id, edition id = body digest, k-of-n approvals per body by distinct controllers, controller changes under the previous edition's rule, merges under every predecessor's rule, `FORK` via `dag`, `orphan`/`pending`/`unauthorized`/`detached`/`invalid`, no authorized controller after revocation. Slice 2 = authorship (claims §5.1, §5.2): claims and amendments, derivation groups, priority on reader-verified bounds only (`TimeVerifier`), single-party defaults with rivals, holders; grades (§7) through the workflow's declared replication and the reader's `Comparator`, weakest-link chain grade, leaf summary |
| `store` | the local store (storage §1–§3, §7): exact-bytes blob install with re-hash on reuse and quarantine of corrupt copies, statements one file per id, the one commit protocol (record = commit point, idempotent steps 3–5), journal replay on every open (stale temporaries swept first), `Outcome.Committed` on errors, `committed, needs repair`, the durability declaration |
| `refusal` | typed refusals (class, reason, detail) of claims-model §11 |
| `conformance` | the harness: case ids from CONFORMANCE.md and the profile notes (bitcoin-time §14), vectors from the vectors file |
| `conformance/fixture` | seeded generator of abstract statement sets for property tests, with shrinking |

## How tests map to CONFORMANCE.md

Every case id in `docs/CONFORMANCE.md`, and in the profile notes listed in `conformance.ProfileNotes` (today the
bitcoin-time note's §14), is a subtest of `TestConformanceCases`. Each id is defined in exactly one table; a note
restating a case defined elsewhere writes its id in backticks. A test declares what it checks:

- `conformance.Covers(t, "C-core-105")`: this test checks the case's whole required outcome. The case passes.
- `conformance.Partial(t, "C-core-12", "what is still unchecked")`: this test checks part of it, usually the
  layers built so far. The case stays skipped, and the report names both the test and what remains.

Cases nobody declares are skipped as pending. A declaration naming an id no case document defines fails
the build. The scan is static, so arguments must be string literals.

Negative tests show that their mutation reached the boundary under test (CONFORMANCE.md, "How a result is
recorded"): a time-rule vector is first checked to carry a valid signature, so only the time rule can refuse
it. Property tests print the seed and a shrunk fixture on failure.
