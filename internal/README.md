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
| `resolve` | the one resolver (claims-model I12): reads chained lines only and applies key events in log order. Slice 1 = resources (claims §8): genesis id, edition id = body digest, k-of-n approvals per body by distinct controllers, controller changes under the previous edition's rule, merges under every predecessor's rule, `FORK` via `dag`, `orphan`/`pending`/`unauthorized`/`detached`/`invalid`, no authorized controller after revocation. Slice 2 = authorship (claims §5.1, §5.2): claims and amendments, derivation groups, priority on reader-verified bounds only (`TimeVerifier`), single-party defaults with rivals, holders; grades (§7) through the workflow's declared replication and the reader's `Comparator`, weakest-link chain grade, leaf summary. Slice 3 = edition rules, membership, series (claims §8): the rule domain (candidate record, its content, the edition under formation) and `ok`/`fail`/`unchecked` with dialects plugged in by the reader (none shipped), set-level rules over the whole formation, a step budget and scan honesty; membership as endorsement, `intended_for` pre-pin check and re-application; `frozen_before` declared beside the computed boundary, `REVISED-FROZEN`, a freeze-policy hook. Slice 4 = observations (claims §5.3, §5.4): one view per `observed` statement (class as the observer's assertion, pinned referent fields, `unpinned`), referent status by finality rule and the reader's own re-check (`provisional`/`final`/`revised`/`not canonical`/`source unavailable`), rule provenance, capture evidence shown only as verified (`TimeVerifier`, `AttestationVerifier`), corroboration status always scoped, symmetric, with declared shared sources and independence `unknown`, counted by `Counter` (distinct signing keys today, labelled: the counting unit is pending the identity decision), cohort rules re-applied through `CohortRules`, reputation only as a reader-chosen projection |
| `btctime` | the bitcoin-time profile (bitcoin-time note): `ots-detached-v1` parser under the §12 limits; 80-byte headers, compact targets, proof of work; a headers-only chain from genesis or an explicit local bootstrap (exact retarget, median time past, future time, version rules, greatest chainwork, reorgs, immutable snapshots); the §4 binding checks, §5 attestation selection, §7 policy (confirmations, settled depth, priority margin, freshness), §8 evidence record and relation, §10 tokens and exits; stamp-at-publish (§2); `TimeVerifier` for the resolver. No network anywhere in the package. Fixtures: real mainnet headers 356 832–359 000 and the public OpenTimestamps hello-world proof (`testdata/SOURCES.md`). Not built: the receipt store (§9) and the commands (§10) |
| `store` | the local store (storage §1–§3, §7): exact-bytes blob install with re-hash on reuse and quarantine of corrupt copies, statements one file per id, the one commit protocol (record = commit point, idempotent steps 3–5), journal replay on every open (stale temporaries swept first), `Outcome.Committed` on errors, `committed, needs repair`, the durability declaration |
| `refusal` | typed refusals (class, reason, detail) of claims-model §11 |
| `conformance` | the harness: case ids from CONFORMANCE.md and the profile notes (bitcoin-time §14), vectors from the vectors file |
| `conformance/fixture` | seeded generator of abstract statement sets for property tests, with shrinking |

### Unsupported evidence in resolver views

Retaining a signed statement is not permission to interpret its body. Unknown kinds and unsupported
critical extensions grant no resource authority, authorship defaults, derivation credit or time bounds.
Edition bodies are grouped as raw evidence: a string `resource` field may associate an uncounted approval
with a resource display, but members and predecessor links are read only when a verified, valid approval
has schema-checked that exact body. A well-formed detached approval still shows its proposal and counts
toward nothing. Unknown-format-major bodies remain opaque, including when a later verified line vouches
for their placement in a key log. Retained signed bytes and each approval's non-counting reason remain
available; unsupported data is not silently converted into a bare-key authorization.

### Evidence and bare-key eligibility

`Placed.EvidenceReady()` exposes the existing `Evaluable` snapshot fact: a statement is verified,
chained and understood. It does not apply its signer's key events. `Placed.BareKeyEligible()` adds
the existing intersection of those key-event exclusions; `Placed.Counts()` remains its compatibility
alias, with unchanged results and reason strings. For example, a hard revocation can be ready evidence
and in force even when its own line is outside `last_good` and is not bare-key eligible.

Neither accessor establishes a controller role, threshold, identity authority or trust. Known-valid
detached proposals retain their typed display without becoming ready evidence. Unsupported or unknown
evidence never becomes eligible just because its signature verifies or a valid co-approval interprets
the same body. This separation adds no identity profile, actor inference, key fallback or reader
registration; existing views and legacy snapshots keep their current behavior.

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
