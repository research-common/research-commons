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
CGO_ENABLED=0 go build -ldflags "-X main.version=0.5.0-alpha.1 -X main.commit=$(git rev-parse HEAD)" ./cmd/commons
RC_TEST_IMAGE=alpine:latest go test -tags sandbox_oci -run OCI ./internal/run   # the OCI sandbox against a real runtime
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
| `resolve` | the one resolver (claims-model I12): reads chained lines only and applies key events in log order. Slice 1 = resources (claims §8): genesis id, edition id = body digest, k-of-n approvals per body by distinct controllers, controller changes under the previous edition's rule, merges under every predecessor's rule, `FORK` via `dag`, `orphan`/`pending`/`unauthorized`/`detached`/`invalid`, no authorized controller after revocation. Slice 2 = authorship (claims §5.1, §5.2): claims and amendments, derivation groups, priority on reader-verified bounds only (`TimeVerifier`), single-party defaults with rivals, holders; grades (§7) through the workflow's declared replication and the reader's `Comparator`, weakest-link chain grade, leaf summary. Slice 3 = edition rules, membership, series (claims §8): the rule domain (candidate record, its content, the edition under formation) and `ok`/`fail`/`unchecked` with dialects plugged in by the reader (none shipped), set-level rules over the whole formation, a step budget and scan honesty; membership as endorsement, `intended_for` pre-pin check and re-application; `frozen_before` declared beside the computed boundary, `REVISED-FROZEN`, a freeze-policy hook. Slice 4 = observations (claims §5.3, §5.4): one view per `observed` statement (class as the observer's assertion, pinned referent fields, `unpinned`), referent status by finality rule and the reader's own re-check (`provisional`/`final`/`revised`/`not canonical`/`source unavailable`), rule provenance, capture evidence shown only as verified (`TimeVerifier`, `AttestationVerifier`), corroboration status always scoped, symmetric, with declared shared sources and independence `unknown`, counted by `Counter` (distinct signing keys today, labelled: the counting unit is pending the identity decision), cohort rules re-applied through `CohortRules`, reputation only as a reader-chosen projection. Slice 5 = the research exchange (claims §9): the task view (`Task`): intents advisory, progress as activity evidence (no lease, no expiry), every submission admissible, bindings to task editions read under that edition's terms only, coordinator grants through `GrantReader` (no grant kind exists), the beneficiary's decisions citing exact submissions, contradictory decisions `contested` until explicit `supersedes`; readiness per edition (`ready`/`not ready`/`unknown`/`unchecked`/`settled by review, not by counting`) counted as distinct signing keys, rubric via `RubricEvaluator`, independence only via `IndependenceVerifier` (never inferred), explicit grouping (all-pairs/reference) with divergence reports kept after readiness; the departure check; pre-registration (`pre-registered <edition> (<bound quality>)`) on artifacts and observations; credit as a reader-chosen projection (`Credit`). Contracts are read through `ContractReader`: none by default, and `ProvisionalContract` is a PROVISIONAL reading pending a contract-profile note |
| `btctime` | the bitcoin-time profile (bitcoin-time note): `ots-detached-v1` parser under the §12 limits; 80-byte headers, compact targets, proof of work; a headers-only chain from genesis or an explicit local bootstrap (exact retarget, median time past, future time, version rules, greatest chainwork, reorgs, immutable snapshots); the §4 binding checks, §5 attestation selection, §7 policy (confirmations, settled depth, priority margin, freshness), §8 evidence record and relation, §10 tokens and exits; stamp-at-publish (§2); `TimeVerifier` for the resolver. No network anywhere in the package. Fixtures: real mainnet headers 356 832–359 000 and the public OpenTimestamps hello-world proof (`testdata/SOURCES.md`). Not built: the receipt store (§9) and the commands (§10) |
| `store` | the local store (storage §1–§3, §5–§9, §7): exact-bytes blob install with re-hash on reuse and quarantine of corrupt copies, statements one file per id, the one commit protocol (record = commit point, idempotent steps 3–5), journal replay on every open, `Outcome.Committed` on errors, `committed, needs repair` (also for a blob that went missing after commit), the durability declaration. Projection cache keyed on input digests, policy, evaluator and time (never size or mtime), `Why` a miss, rebuild and drift per named projection, a verification cache with a cold mode for conformance runs (`cache.go`); gc with the grace window re-checked at deletion, dry run by default, and `Release` = signed `holds` with `withdrawn:true` then removal through the commit protocol (`gc.go`); `Fsck` by class with optional quarantine and rebuild (`fsck.go`); `Scanner`, bounded archive scans over tar/gzip/zip with `unscanned (<limit>=<value>)`, operational refusals for run-level limits, and an optional `KeyScan` inspector whose patterns are configuration (`scan.go`); `Fetch` behind a `Transport` interface, wrong bytes refused and the next location tried, `Availability` as the holder's word; no transport is installed by default (`fetch.go`) |
| `run` | the execution profile (execution note): the workflow spec and its unpinned inputs (§1), the reader's execution policy and every check before staging (§2), caps against the reader's ceiling with the explicit below-profile opt-in (§2.2), the one confinement function for every host-side join (§3), the environment record and `environment_match` (§4, §8), result tokens and `verify` exits from one table (§5.2), comparison by replication mode (§5.3), what `run --publish` emits (§5.1, §7, §1 rule 3); a `Runner` interface with an in-process fake, comparators run as workflows (the resolver's `Comparator`), and an OCI backend through the container CLI whose tests need `-tags sandbox_oci` and a runtime |
| `gate` | the one validation core of claims-model §11 (I8, I9, I12): `Admit` evaluates a package (paths with bytes) against the receiver's held history and policy and returns a verdict per object (admitted, admitted and labelled, refused with class, reason and scope, could not check, not applied). The data surface is the store layout; every other path is control plane or outside the surface, and unsafe paths are refused. Statements go through `wire.Read` and `keylog` only. Four thin entry points (`Pull`, `HubCheck`, `Push`, `PrePin`) that differ only in history and policy; typed per-object overrides of reader-policy refusals (never a blanket force); `Commit` installs the admitted set through the store's one commit protocol; the `rc-hub-policy/1` parser (strict, `DidNotStart` on any problem; its `control_plane` member adds a hub's own paths to the template's control plane, never the data surface or the marker); the exit mapping 0 / 1 / 3 |
| `hubcheck` | `hub check` as a library: the change from `merge-base(<base>, HEAD)` to `HEAD`, the base tree as held history and `hub-policy.json` from the base revision, read through git plumbing only (`ls-tree`, `diff-tree --raw -z`, `cat-file --batch`; no filters, attributes, external diff or caller `GIT_*` environment), checked by `gate.HubCheck`. Not wired to a command |
| `cli` | the command-line surface (`cmd/commons` is a thin main): a registry where each command is one file calling `Register` from `init`; global flags, argument shapes, store discovery (`--store`, `$COMMONS_STORE`, nearest `rc-store`) and the policy file checked before any work (exit 2); one exit table and one closed vocabulary that both surfaces print from and `docs/CLI-OUTPUTS.md` is generated from; RFC 9457 problem details; peer text inert on both surfaces. Read commands: `show`, `verify` (statement-only; never runs anything), `explain`, `list`, `status` |
| `policy` | the reader's local policy `reader-policy-v1` (fixed-root identity note §6 and its schema): a strict, closed parser (sorted entries, one selection per content and role, identical trust entries refused, 65,536 canonical bytes) whose every failure is an `*Error` with exit 2; the policy digest and `Diff`; purpose- and target-scoped trust answers; the admission predicate a gate calls for a trust floor (`Admit`: refused, or admitted and labelled). The resolver reads it through `resolve.WithPolicy`: exact pins and key-following selections for authorship, workflow and observation declarations, and the trust filter on corroboration and run attestation (`resolve/policy.go`) |
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

Observation views apply the same boundary before class, referent, finality, capture or corroboration
interpretation, including lite views used by derivation summaries. `Observation.BodyUnderstood` means
the statement is verified and `Valid`; it is independent of `Counts`. Unsupported observations retain
their statement/signer metadata, a type-checked content-digest association where available, and an
explicit unchecked diagnostic. They do not call referent, finality, attestation, time or cohort verifiers.
Unsupported corroborations may be associated by a string `of`, retaining their statement/signer,
delivery origins and non-counting reason, but supplying no verdict, model, shared sources, comparison
data or result grade. Another valid statement over the same body does not promote an unsupported one.
Absent/malformed associations do not invent a lookup target; unknown-major bodies expose no association.
The original signed bytes remain available through statement/log evidence. Verified, understood
detached and key-revoked statements keep their typed displays without becoming eligible: key-event
exclusion must not be mislabeled as an unverified signature.

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

### Candidate identity admission (opt-in, not wired)

`wire.NewIdentityReader()` reads rc/1 exactly as `wire.Read` accepts it, plus the candidate rc/2 of
`docs/DESIGN-notes-fixed-root-identity.md`. It verifies the signature before interpreting signer-chosen
fields, so an authentic but malformed line is kept as `Invalid` (attributable, never authority) instead of
being refused. `wire.Read`, the zero `wire.Reader`, `Major`, keylog and resolve are unchanged: for them rc/2
is still an unverified other-major line.

`identity.Admit` is the only production constructor of `identitymodel` facts (a test enforces it). A fact is
authenticated only when this reader verified its signature, or when a verified line of the same key commits to
its exact id through prev/merges (then it is authenticated but unsupported). Bad-signature copies are refused,
never facts. Authenticated non-administrative lines that are not understood become unsupported, so a malformed
root key event reads unknown rather than ineffective. rc/2 resource and task kinds are verified but unsupported.
`Snapshot.Receipt()` digests the admitted canonical lines; `EvidenceDigest()` is the model's fact digest. No
consumer (authorship, resources, tasks, policy, time) reads the result yet.

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
