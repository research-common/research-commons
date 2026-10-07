# Design note: Receiver-local Bitcoin / OpenTimestamps verification

**Date:** 2026-10-05, revised 2026-10-06 · **Status:** proposal for design review, not implemented
**Builds on:** #57 (anchor trust containment, merged) and `docs/DESIGN-notes-anchor-trust.md`
**Tracking issue:** #59
**Related:** #47 (authority among several publishers), #43 (signed manifest views)
**Implementation:** separate PRs, sequenced in [§16](#16-delivery-plan-and-release-gates)

**Purpose:** restore usable Bitcoin-backed checkpoint evidence without trusting replicated metadata,
requiring a full Bitcoin node, or treating a miner's timestamp as an exact wall-clock bound.

## How to comment or implement

This note is a proposal. Nothing in it is an accepted policy or an available command.

- **Comment** on the tracking issue (#59) or on the PR that adds this note. Line-level comments on
  the PR are welcome. Point out wrong claims about the code, attacks the threat model misses, and
  requirements you think are unnecessary.
- **Implement** by opening an issue first to say which phase you are taking. Phase 1 in §16
  (dependency selection and an offline header-conformance spike) does not depend on any open
  decision and is the natural place to start. Phases 2–3 change ordering and settlement semantics
  and should wait until the §16 decisions are settled.
- **Open decisions** are listed at the end of §16. Where this note says "proposed" or "subject to
  maintainer approval", treat the value as a starting point for discussion.

The words MUST, MUST NOT, SHOULD and MAY below are normative requirements of this proposed design.
Example commands, schemas and module names are proposed interfaces, not currently available
commands.

## 1. Proposed design summary

The proposal is an explicit receiver-side verifier with two separable components:

1. An **OTS verifier** binds a detached proof to the exact checkpoint commitment and verifies its
   operation tree against a Bitcoin block's Merkle root.
2. A **Bitcoin chain provider** supplies authenticated headers and an accepted chain view. A
   validated headers-only light client is the preferred supported path; an operator-controlled
   Bitcoin Core node is an optional alternative, not a prerequisite.

Successful verification writes a **receiver-local receipt**. Ordinary reads use receipts plus the
current local chain view; they never run a network request or infer verification from `anchored`,
`bitcoin_blocks`, `confirmed_at`, `created`, or `verified_locally` in received JSON.

Use **block height and block hash on the accepted chain** for Bitcoin checkpoint ordering. Display
the header's `nTime` as authenticated miner-reported time, not a precise UTC creation bound. A lower
checkpoint height establishes an earlier chain commitment, not necessarily an earlier publication or
independent derivation.

Do not restore the `bitcoin` label until the receipt validation and all security-sensitive ordering
consumers ship together.

**Relation to the anchor trust note.** That note says a future verifier should use a trusted block
*time*. This proposal refines it: verified Bitcoin evidence is ordered by chain *position* (height
and hash on the accepted chain), and the header time is displayed but is not an ordering key (§9).

**Relation to #47 and #43.** Since #57, anchored first-publisher order cannot decide metadata
authority among several publishers, and #43 withdrew its anchored tie-break. This verifier does not
restore that authority by itself. It produces stronger *evidence of commitment order*; any rule that
turns that order into edit rights is a separate decision (§9, §12).

## 2. Problem and current boundary

Before #57, `anchor_bounds()` accepted a peer-supplied JSON claim of Bitcoin confirmation and used
the JSON's `created` as its bound. A root-consistent, proofless checkpoint could consequently win
first-publisher credit and report a discrepancy against the honest publisher.

PR #57 contains that failure by checking root/signature/log scope and assigning every checkpoint
`local` quality. Its local bound time comes from the signed anchor event. It also ignores a signed
anchor event dated before any line it covers, and an unsigned checkpoint never bounds an unsigned
line that claims an `addr`. It does not yet parse and authenticate OTS proofs against a Bitcoin
chain, and deliberately does not produce Bitcoin-quality evidence.

The relevant existing functions are `cmd_anchor`, `ots_blocks`, `cmd_anchor_upgrade`,
`cmd_anchor_verify`, `anchor_bounds`, `first_publisher_index`, `publish_ordering_evidence`,
`derivation_commits`, and `derivation_evidence` in `bin/commons`.

Important implementation facts:

- `cmd_anchor` stamps a file containing **the lowercase hexadecimal root plus one LF**, not the raw
  32-byte Merkle root.
- `ots_blocks` parses human-readable `ots info` output for attestation heights. This is inspection,
  not verification.
- The OTS library's `BitcoinBlockHeaderAttestation.verify_against_blockheader()` checks that a
  calculated digest equals a header's Merkle root and returns `nTime`. It does **not** authenticate
  chain membership, proof of work or difficulty history.
- Current ordering consumers use `(timestamp, quality)`-shaped evidence, and commit-reveal also
  consults self-declared ledger timestamps. That shape is insufficient for height-based verified
  evidence.

## 3. Goals and non-goals

### Goals

- Independently verify an existing Bitcoin OTS proof without a full block/transaction download.
- Make remote confirmation claims inert until the receiver performs verification.
- Support offline re-verification against an already validated local header view.
- Make reorgs, insufficient confirmations, stale chain views, policy changes and modified inputs
  remove live Bitcoin eligibility.
- Give callers structured evidence and explicit failure reasons, rather than a boolean or parsed
  console text.
- Preserve local checkpoint creation, unsigned operational drift checks and use without optional
  verifier dependencies.
- Provide hermetic security tests and bounded processing of hostile files.

### Non-goals

- Proving original authorship, independent intellectual work, or absence of earlier public
  disclosure.
- Granting manifest edit rights based on the earliest checkpoint.
- Rewriting signed ledger history or changing the replicated anchor schema merely to add a
  receiver's verdict.
- Installing a node, wallet, system service or scheduler automatically.
- Implementing a novel Bitcoin consensus/light-client stack inside the Commons CLI.
- Silently trusting a public block explorer or an arbitrary height-to-time table.
- Making `pull` or `hub check` depend on network availability. Stronger structural ingest rejection
  is separate work.

## 4. Threat and trust model

### Untrusted inputs

Treat anchor JSON, root/proof files, ledger files received from another hub, OTS calendar URIs,
remote headers, remote block-height labels and backend error text as attacker-controlled.

An attacker may have a valid Commons signing identity. They may backdate their own signed events,
replace JSON fields, replay someone else's proof, supply an orphan header, feed an easy-difficulty
chain, withhold newer headers, send oversized proof trees or embed paths/URLs intended to trigger
unwanted reads or network calls.

### Trusted receiver state

The receiver controls its verifier executable/dependencies, selected Bitcoin network and chain
provider, local policy, receipt store and local filesystem permissions. Arbitrary same-user code
execution or the ability to alter those trusted components is outside this boundary; a local receipt
is not protection against a compromised host.

### Headers-only assumptions

A headers-only provider validates header-level rules and follows the greatest-chainwork chain it
knows. It does not fully validate block bodies or transaction consensus. Its security relies on the
stated SPV/PoW assumptions, adequate access to the actual network, and absence of a successful
eclipse or adversarial-work attack.

The display and machine-readable verdict MUST disclose `chain_validation: headers-spv` versus
`operator-node`. They MUST NOT call a headers-only result full-node consensus validation.

Independent network sources and an operator-reviewed minimum-chainwork floor are mitigations, not
substitutes for header validation and not proof that no better chain is being withheld.

## 5. Checkpoint authorization and byte binding

Perform these checks before attempting Bitcoin quality:

1. Parse a bounded anchor JSON object; reject duplicate JSON keys and ill-shaped heads. Recompute
   the checkpoint root with the existing sorted-heads Merkle algorithm.
2. Require `record.root == recomputed_root`. Ignore cached `leaves` as an authority source.
3. Require a verified signed `anchor` event binding the record's anchor id and root. The event MUST
   reside in the log named after its recovered signer. If `sig2` is present, it MUST also verify.
4. Preserve #57's scope rule: use only that signer's own log prefix ending at the committed head.
   The head MUST precede the anchor event in that physical log. Keep #57's other two rules: an
   anchor event whose `ts` is earlier than any covered line's `ts` is ignored, and unsigned
   checkpoints never bound an unsigned line that claims an `addr`.
5. For Bitcoin coverage, verify the hash-chain links of the covered prefix over the exact stored
   line bytes (a line's hash is the SHA-256 of the line without its trailing LF, as `ledger_head`
   computes it). A head hash covers earlier lines only when the `prev` chain actually connects them.
   Position in a file alone is not cryptographic coverage. Treat an unverifiable legacy prefix as
   ineligible for Bitcoin quality rather than inventing a chain.
6. Security-sensitive consumers still verify the particular publish/commit event's signature and
   physical log binding; anchoring a prefix does not make every event inside it a valid signed
   claim.
7. Construct the expected stamped bytes independently:

   ```python
   root_bytes = (recomputed_root + "\n").encode("ascii")
   expected_file_digest = sha256(root_bytes).digest()
   ```

8. If a `.root` file is supplied, its bytes MUST exactly equal `root_bytes`. Do not trust its
   contents to define the expected digest. A missing `.root` may be reconstructed in memory from the
   authenticated checkpoint; verification need not mutate replicated files.
9. Deserialize the detached `.ots` proof using the pinned OTS library. Initial version supports
   SHA-256 as the file hash operation only. Require its declared digest to equal
   `expected_file_digest`. Raw-root bytes, missing LF, a different root, an unsupported file hash
   operation, trailing garbage or malformed serialization do not pass.

A peer's JSON date is not used anywhere in this Bitcoin proof chain. The signed anchor event's `ts`
authenticates an assertion but is also not the Bitcoin ordering value.

### File resolution

`ots_proof` is an untrusted locator, never authority. Initially accept only a regular proof file
within the anchor directory, with a basename-only locator and the expected `.ots` suffix. Reject
absolute paths, traversal, separators, symlinks and non-regular files; use safe open/fstat checks
rather than a check-then-open race. Apply equivalent protections to optional `.root` files.

Normalize proof/record paths only for diagnostics and receipt binding; never execute them. A proof
bytes hash, not its filename, identifies the proof.

## 6. OTS operation and attestation verification

Use the OTS library's structured parser/API, not regexes over `ots info` or success-looking messages
from `ots verify`.

Parsing a detached timestamp computes its operation tree from the declared file digest. After
checking that digest against the independently constructed expected digest, enumerate
`(calculated_digest, attestation)` pairs through `all_attestations()`.

For every `BitcoinBlockHeaderAttestation` candidate:

- Check the height is a supported nonnegative integer, not a boolean or a value outside the
  provider's known chain.
- Resolve the header **at that height in the locally accepted Bitcoin mainnet chain**, not a header
  embedded by the sender or selected by a remote height label.
- Verify `calculated_digest == header.hashMerkleRoot` using the library's byte representation.
  Human-readable block hashes and Merkle roots usually reverse the serialized/internal byte order;
  conversions MUST be explicit and tested.
- Derive the header hash and `nTime` from the actual 80-byte header. Do not accept backend-reported
  strings without matching them to those bytes.
- Require the block to meet the receiver's confirmation policy in the selected chain view.

No transaction/block-body download is necessary for this OTS check: the operation path terminates at
the header's Merkle root. Chain authentication remains the provider's separate job.

Pending calendar attestations and unknown/non-Bitcoin attestations do not provide Bitcoin quality.
Their URIs MUST NOT be dereferenced during local verification. Calendar upgrades stay an explicit
`anchor-upgrade` action with separate network controls.

When several valid attestations exist, retain their structured candidates and select the **lowest
eligible height on the accepted chain**. Do not choose the lowest `nTime`. A bad/unavailable
additional candidate cannot invalidate a distinct good candidate, but a proof that fails
serialization or input binding is invalid as a whole. A later eligible candidate may be selected
while an earlier one lacks sufficient chain evidence; show this limitation.

## 7. Bitcoin chain-provider contract

### 7.1 Preferred backend: locally validated headers

Use a maintained header-chain implementation behind an adapter. Commons MUST NOT accept a database
merely because its filename says `headers` or a daemon says `verified: true`; the configured adapter
is trusted code, and its validation behavior must be reviewed and tested.

The provider MUST validate, with Bitcoin mainnet parameters:

- The genesis/network identity or an explicit locally trusted checkpoint bootstrap.
- 80-byte serialization, header hashes and previous-header linkage.
- Valid compact-target decoding: positive, nonzero, nonoverflowing, within the network PoW limit.
- Actual header proof of work against that target.
- The **exact expected difficulty/retarget history**, including boundary rounding and clamping.
  Accepting any PoW-valid target or only a permitted retarget range is insufficient.
- Relevant contextual header rules, including `nTime` strictly greater than the median of the
  preceding 11 header times, and version/activation rules enforced by the chosen header validator.
  This is not a requirement that each header time exceed its predecessor's time.
- Future-time admission checks against its local clock. The historical arrival clock cannot be
  reconstructed from stored headers; do not pretend to validate a historical receive time.
- Cumulative chainwork and greatest-work selection, not longest-by-height selection.
- Fork/reorg detection and lookup by both accepted height and block hash.

The simplest baseline is full mainnet **header** history from genesis, with enough retained context
for every retarget and MTP check. An 80-byte header per block means approximately 80 MB per million
headers before indices/metadata, not full-block storage. Checkpoint/pruned bootstraps MAY be
supported later, but their trust root and retained difficulty/MTP context must be explicit; a pinned
height/time table is not such a bootstrap.

Header transport is untrusted. The adapter MAY acquire headers over Bitcoin P2P or another
transport; transport authentication alone never replaces chain validation. The operator selects the
implementation/source policy explicitly. The verifier performs no automatic provider discovery.

### 7.2 Optional backend: operator-controlled node

A configured local Bitcoin Core node may supply its active-chain header at a height, tip and
confirmation state. The adapter verifies the returned raw header's hash and Merkle root binding,
uses the node's mainnet chain selection, and checks it is not in initial block download or otherwise
outside readiness policy.

RPC credentials come from receiver-local configuration/cookie handling, never received metadata. An
unavailable node does not trigger a public explorer fallback. A remote RPC is a separately disclosed
trusted-node mode, not local independent header validation.

### 7.3 Provider API

One verification batch uses an immutable provider snapshot or holds a read transaction:

```text
snapshot() -> ChainView
header_at(height, view) -> raw_header + block_hash
is_active(block_hash, height, view) -> bool
sync_explicitly(policy) -> ChainView   # network only through an explicit command
```

`ChainView` contains at least:

```text
network/genesis_hash, provider_id, validation_mode, policy_fingerprint,
chain_epoch, tip_height, tip_hash, tip_chainwork,
last_successful_sync, readiness/freshness status, bootstrap identity
```

A snapshot that changes during verification MUST cause retry against one stable new view or a
non-authoritative failure; never combine one chain's header with another chain's tip/confirmation
count.

Provider implementations have their own local trust/dependency versions. The selected provider
identity and policy participate in receipt eligibility.

## 8. Proposed local policy

Recommended initial values, **subject to maintainer approval**, not existing defaults:

| Setting | Proposal | Meaning |
|---|---|---|
| Network | Bitcoin mainnet only | Reject testnet/regtest/signet as production authority |
| Preferred mode | `headers-spv` | Full node optional |
| Minimum confirmations | 6 | `tip_height - attestation_height + 1 >= 6` |
| Maximum chain-view age | 1 hour | Elapsed since a successful validated synchronization/readiness check |
| Maximum tip timestamp age | 6 hours | Operational stale-tip warning/refusal, not a consensus rule |
| Automatic network during reads | Never | Reads inspect receiver-local state only |
| Public explorer fallback | Disabled/unsupported | No silent third-party time trust |
| Header sources | Operator-configured | Recommend independent sources; disclose eclipse limitations |
| Minimum chainwork/bootstrap | Explicit local policy | No sender-selected trust root |

Freshness checks use the receiver's clock and local synchronization state, not JSON dates. A recent
successful request to a stale/eclipsed source is not proof that the view is current. Combine source
readiness, a work floor and stale-tip checks, and state the remaining availability/security
assumptions.

A backward local-clock jump or an untrustworthy age calculation marks the view unavailable for live
Bitcoin eligibility. A monotonic clock can support checks within a process; across restarts use
persisted local times with conservative clock validation. Clock drift is an operational condition,
not proof failure.

## 9. Structured evidence, not a timestamp tuple

Introduce an `AnchorEvidence` record, conceptually:

```json
{
  "quality": "bitcoin",
  "verification_state": "verified",
  "anchor_id": "anchor-<id>",
  "signer": "<recovered address>",
  "log_name": "<signer>.jsonl",
  "covered_head": "<line hash>",
  "checkpoint_root": "<recomputed root>",
  "root_file_sha256": "<digest of root plus LF>",
  "proof_sha256": "<digest of proof bytes>",
  "network": "bitcoin-mainnet",
  "genesis_hash": "<mainnet genesis hash>",
  "block_height": 0,
  "block_hash": "<display-order hash>",
  "header_time": 0,
  "confirmations": 0,
  "chain_validation": "headers-spv",
  "chain_epoch": "<local generation>",
  "verified_at": "<receiver-local time>",
  "policy_fingerprint": "<local policy digest>"
}
```

Zeroes are schema placeholders, not a valid verification example. Local evidence carries the
authenticated signed event's asserted time and explicitly lacks independently verified chain
position. Uncheckpointed evidence has quality `none`.

Use named fields/types throughout. A compatibility timestamp formatter MAY display `header_time`,
but a `(header_time, "bitcoin")` tuple MUST NOT remain the ordering/independence API.

### Comparisons

- For Bitcoin evidence on the **same currently accepted network/chain view**, lower height means an
  earlier blockchain commitment.
- The same accepted height/hash is a tie in chain ordering. Do not break an authority or
  independence tie with a signed or JSON timestamp. A deterministic display sort by signer/id is
  allowed only when visibly labelled non-evidentiary.
- Different networks, unverifiable views or non-active blocks cannot be compared as live Bitcoin
  evidence.
- Local assertions never outrank verified Bitcoin commitments for evidentiary ranking. They still
  cannot prove they were created later; this is a ranking rule, not a temporal inference.
- If an unverified rival exists, an earlier verified commitment is the earliest **verified
  commitment**, not a proof that the rival never published earlier. Any future
  canonical-view/authority rule must keep unresolved rivals visible and may require a contested
  state rather than silently assigning rights.

Return a comparison relation (`earlier-commitment`, `later-commitment`, `same-block`,
`unverified/incomparable`) separately from presentation ordering.

## 10. Receiver-local receipt store

### Location and identity

For a git-backed hub, store policy, receipts and optional header database under the resolved hub git
directory:

```text
<git-dir>/commons-anchor-verification/policy.json
<git-dir>/commons-anchor-verification/receipts.sqlite
<git-dir>/commons-anchor-verification/headers.sqlite
```

Resolve the git directory with Git rather than assuming `.git` is a directory; linked worktrees must
work. Scope receipts to the actual hub instance/worktree. Git metadata is not a tracked data path
and cannot be smuggled through ordinary `pull`/`hub check` federation.

For a non-git root, require an explicitly configured receiver-local state directory **outside the
replicated root**; otherwise return `backend-unconfigured` and preserve local quality. Never fall
back to a cache under `registry/anchors/` or use a state path from anchor JSON. Tests supply an
isolated local state directory.

Restrict directory/file permissions; use transactional SQLite or atomic replacement, locking and
crash-safe writes. Do not create a signing-key requirement: receivers without a Commons ledger key
must be able to verify proofs.

### Receipt binding

A receipt binds at least:

- Hub instance, anchor id, signer, authenticated anchor-event identity and physical event-line hash.
- Recomputed root/heads, covered head and relevant verified ledger-prefix fingerprint.
- Expected root-file digest and exact proof-bytes digest.
- Network/genesis, accepted block height/hash and raw-header digest.
- Chain provider/bootstrap identity, validation mode, verifier implementation/version and policy
  fingerprint.
- Verification-time chain snapshot and diagnostics.

Input fingerprints are **content hashes**, not mtimes or lengths. The CLI reads the proof/record
snapshots once, uses those bytes for verification and hashing, and checks any separately opened
ledger snapshot consistently. Modification during verification cannot produce a receipt for
different bytes.

The JSON may change harmlessly (for example, `confirmed_at`) without changing its authenticated
commitment. It may be simplest to bind the full record bytes initially: this safely forces
re-verification on harmless edits. Do not mistake that conservative invalidation for authentication
of every JSON field.

### Eligibility on every read

A stored `verified` row is not itself current authority. Before emitting live `bitcoin` quality,
validate:

1. Current record/proof/event/prefix fingerprints still match.
2. Verifier/provider/policy versions remain compatible.
3. The local chain view is ready and fresh under policy.
4. The recorded block hash remains active at its height and has sufficient current confirmations.
5. No relevant chain epoch/reorg invalidation is outstanding.

Tip extension does not require re-running a valid OTS operation tree: recheck membership and
confirmation count against the new view. A tip/reorg epoch change forces this recheck; it does not
automatically delete all historical cryptographic results. An orphaned block loses live quality
immediately. If a proof has another valid active attestation, select that candidate only after local
evaluation.

Cache immutable proof-to-header binding separately from mutable active-chain eligibility. This
avoids unnecessary full proof work while preventing a cached branch from surviving a reorg.

A corrupted, copied, wrong-hub, unknown-version or malformed cache is rejected/downgraded, never
trusted optimistically. Unknown JSON `verified_locally` flags remain inert even if their shape
resembles a receipt.

### Offline behavior

Verification against a local header snapshot can be cryptographically successful offline. Report the
verified snapshot tip and whether live freshness policy is satisfied.

- A fresh, locally validated snapshot may produce eligible Bitcoin evidence without a network
  request.
- An old snapshot may produce `verified-historical` diagnostics but not live Bitcoin priority by
  default.
- No receipt/fresh provider means fallback to `local` or `none`, with `pending`, `stale-chain`,
  `orphaned`, `backend-unconfigured` or another explicit reason.

An offline user can inspect proof correctness without the tool pretending to know the present active
chain.

## 11. Proposed CLI contract

Preserve existing default commands as inspection/stamping surfaces. Add explicit verification and
header-sync actions:

```text
commons anchor-verify [anchor-id ...] --check-time [--offline] [--json]
commons anchor-headers sync [--json]
commons anchor-verifier status [--json]
```

- `anchor-verify` without `--check-time` retains its structural inspection contract and makes no
  authority claim.
- `--check-time` verifies bounded local proof files using the configured provider and writes
  receiver-local receipts. It never silently upgrades a pending proof through its calendar URI.
- `--offline` refuses all network activity and uses only stored header state. Without `--offline`,
  the initial implementation still uses existing local state; synchronization is a separate explicit
  `anchor-headers sync` action. For the optional node backend, local RPC access is allowed only in
  the non-offline path unless the adapter has a cached local header view.
- `anchor-headers sync` is the only new command that acquires header data. It is bounded/cancellable
  and uses receiver-local source policy. It does not install a daemon or scheduler.
- `anchor-verifier status` reports configuration, dependency version, validation mode,
  tip/work/freshness, policy, and receipt counts. It prints no credentials.
- Configuration is a local operator-managed file under the state directory. A configuration writer
  can be added later; no guessed executable or received metadata chooses the backend.
- Ordinary `status`, `queue`, `settle` and first-publisher reads perform **no network I/O**, do not
  fetch `.ots` files, and do not mutate shared anchor records.

Example JSON result states:

```text
verified                    binding + active chain + confirmations + freshness pass
verified-historical         binding passes for an old local snapshot, not live eligible
pending                     no completed Bitcoin attestation
insufficient-confirmations  valid active attestation, depth below policy
missing-proof               expected proof unavailable
invalid-proof               parse, digest or Merkle-root binding fails
invalid-checkpoint          authorization/root/prefix fails
unknown-height              local provider lacks required chain evidence
orphaned                    valid historical binding, block not active
stale-chain                 present active-chain knowledge not fresh enough
backend-unconfigured        no explicitly selected provider
backend-unavailable         configured provider/dependency not operational
unsupported                 unsupported file-hash/network/verifier version
```

Proposed exit codes for the **new** `--check-time` mode: `0` only when every selected checkpoint is
live verified; `1` for any invalid checkpoint/proof; `4` when none is invalid but at least one is
pending/unavailable/stale/ineligible. For mixed batches, report every per-anchor state and use
invalid > incomplete > verified precedence. These meanings do not change the old default command's
exit contract.

Neither an exit code alone nor a backend's `verified: true` is an authority API. Only validated
structured evidence reaches readers.

## 12. Integration and inference limits

### Required integrations

1. Replace/augment `anchor_bounds()` with a structured `anchor_evidence()` map. Keep local drift
   coverage separate from live Bitcoin eligibility.
2. Teach `first_publisher_index` and `publish_ordering_evidence` to use verified chain-position
   comparisons rather than `nTime` sorting. Preserve `publish`-only authorship candidates and
   log/signature binding.
3. Make `fmt_bound`, status and discrepancy output distinguish local asserted times, verified chain
   commitments and unavailable/stale proof state.
4. Extend in-process cache keys to include receipt input fingerprints, policy/verifier versions and
   provider chain epoch. `id(lines)` and anchor-file mtimes alone are insufficient.
5. Audit `derivation_commits`, `derivation_evidence`, settlement and any future authority consumer
   before enabling Bitcoin quality. No caller may treat `header_time` as a signed event's true
   publication time.

### Commit-reveal is not fixed by comparing two upper bounds

**This section proposes a change to current behavior.** Today `derivation_evidence` grants
`commit-reveal` when the commit's asserted `ts` precedes the first publisher's, provided the commit
is checkpointed whenever the publish is. The requirement below would stop a Bitcoin receipt from
strengthening that grant and would make the commit-reveal policy itself an open decision (§16).

Let C be the commit checkpoint and P a publication checkpoint. `height(C) < height(P)` establishes
that the commit checkpoint is earlier on chain. It does **not** establish that C predates
publication: the result may have been public before C and anchored only at P.

Likewise, `commit.ts < publish.ts` only compares assertions. Combining that comparison with the
existence of an anchor does not turn it into independent evidence.

The current commitment is `sha256(content_sha256 + salt)`: its binding is to the content **digest**
and salt, not a proof that the committer possessed or independently computed the underlying bytes.
If the digest was already public, the commitment could be made without obtaining the blob. Local
Bitcoin verification does not strengthen that knowledge/derivation claim.

Therefore, the new verifier MUST NOT grant commit-reveal independence solely from either comparison.
A separate disclosure/commit protocol or explicit receiver-scoped publication-observation model must
define what lower bound on disclosure is being used. A receiver observation proves what that
receiver saw and when, not absence of worldwide earlier disclosure.

Until that policy exists, preserve the distinction between `verified-commitment` and
`independent-derivation`; contested independence remains a reference/non-quorum result. This is a
release prerequisite for restoring strong Bitcoin-backed claims in settlement, not an assertion that
the verifier proves original derivation. Existing local-only behavior must be clearly labelled
provisional and must not become stronger merely because a new Bitcoin receipt appears.

A future earliest-verified-claim display rule may use chain commitment order under its stated
policy. This spec does not turn that ordering into rights ownership or destructive edit permission.

## 13. Transport and CI

This work's authority boundary is receiver-local; transport cannot import verification receipts.

- `pull` must neither export nor import the git-dir state. An incoming tracked
  `registry/.../verified` field never becomes local policy.
- Optional verifier packages must not be required merely to publish an unsigned artifact or run
  baseline `hub check`.
- A deterministic structural anchor check can require root consistency, safe file locators and proof
  input-digest binding without needing a live chain. Such checks MUST distinguish incomplete
  calendar proofs from malformed proofs.
- Do not require an incoming JSON `confirmed` label for verification, and do not accept it as
  evidence. A valid locally verified proof may be labelled `pending` by its publisher; the
  receiver's result wins for its own view.
- Adding new structural refusals to existing `pull`/`hub check` requires a separate documented
  compatibility decision. Do not smuggle that gate change into a read-side cache feature.
- CI acceptance tests use fixed proof/header fixtures, not public networks or calendars.

## 14. Dependency and implementation boundaries

Proposed layout:

```text
bin/commons                         CLI/read-side integration, no embedded consensus stack
lib/anchor_evidence.py               input checks, structured evidence and receipt validity
lib/verify_ots.py                    bounded structured OTS parser/helper
lib/bitcoin-chain-provider.*         reviewed backend adapters
optional verifier requirements      exact versions/hashes and licence review
tests/test-anchor-verification.sh    deterministic unit/integration/security gate
```

Prefer the existing OTS parsing/attestation library as an optional dependency, pinned reproducibly;
do not copy its source into the Apache-licensed tree. The reference library
(`python-opentimestamps`) is LGPL-3.0-or-later; keep it an optional, separately installed dependency
and record that in the licence review. Inspect its actual API version rather than inferring behavior
from CLI text.

Dependency selection for the headers backend is an implementation spike: choose a maintained
validator that satisfies section 7, document its supported consensus/header rules and bootstrap
model, and run conformance fixtures. A bare `python-bitcoinlib` header parser/individual PoW check
is not a complete header-chain validator. Selection must be reviewed before advertising a working
headers backend; no full-node fallback is allowed to paper over its absence.

The helper executable/interpreter is a receiver-local configuration choice, never a received path.
Invoke with an argument array, no shell interpolation, and a bounded versioned JSON protocol.
Unknown versions, unexpected fields required for authority, malformed output or mismatched echoed
input hashes fail closed.

Initial proposed resource limits: anchor JSON 1 MiB; proof 8 MiB; tree depth 256; 100,000
operation/attestation nodes; 30 seconds CPU/wall per proof helper; 256 MiB helper memory; 60 seconds
per backend request; explicit total sync budget/cancellation. Use a bounded parser/context and
subprocess limits so the tree cannot consume resources before node limits are noticed. Limit head
count as well as input bytes. These are configurable **local** limits subject to fixture validation,
not sender choices.

Do not follow pending calendar URLs in the verifier, evaluate code from an artifact, allow
proof-path reads outside the anchor directory or leak credentials through diagnostics.

## 15. Acceptance tests

Every row below is a deterministic regression requirement; fixtures use synthetic identities, never
operational keys.

### Checkpoint / input binding

| Case | Required result |
|---|---|
| Correct root + signed event + matching completed proof | Eligible only after valid chain checks |
| Old `created`/`confirmed_at`, arbitrary block list, `verified_locally: true`, no proof | Never Bitcoin quality |
| Change a head without changing signed root | Invalid checkpoint |
| Valid signed anchor moved to another identity's log | Invalid authorization |
| One signer's multi-log anchor lists a rival log | No rival coverage |
| Covered head after anchor event / broken `prev` link / altered covered line | No Bitcoin coverage |
| Invalid present `sig2` | Invalid authorization |
| Unsigned checkpoint or signed event relayed into unsigned log | No signed Bitcoin authority |
| Proof for other root, raw root bytes, missing LF, wrong hash operation | Invalid input binding |
| Missing `.root`, valid canonical digest constructed from commitment | May verify without writing a shared file |
| Absolute/traversal/symlink/FIFO proof locator | Refused without external read |
| Duplicate JSON keys, malformed/truncated/trailing proof data | Bounded invalid result |

### OTS / header binding

| Case | Required result |
|---|---|
| Correct operation tree and accepted mainnet header Merkle root | Cryptographic binding passes |
| Broken operation edge / wrong Merkle root / wrong byte-order conversion | Invalid proof |
| Pending calendar URI with no Bitcoin attestation | Pending, zero calendar requests |
| Claimed height paired with an otherwise valid header from another height | Refused |
| Header supplied by sender with no validated chain membership | No Bitcoin quality |
| Multiple attestations including one valid eligible candidate | Use lowest eligible chain height |
| Earlier candidate unknown, later candidate valid | Use later eligible height and disclose coverage limitation |
| Unknown/non-Bitcoin additional attestation | Does not grant Bitcoin quality or invalidate a distinct good candidate |

### Chain validation / policy

| Case | Required result |
|---|---|
| Mainnet header fixtures crossing difficulty boundaries | Exact expected target validated |
| Individually PoW-valid header with wrong contextual target | Refused |
| Negative/zero/overflow/out-of-limit compact target | Refused |
| Wrong predecessor / invalid PoW / MTP violation | Refused |
| Longer-by-height but lower-chainwork fork | Not selected |
| Equal-work competing tips | No arbitrary priority resolution; policy reports unresolved view |
| Testnet/regtest/signet provider against mainnet policy | Refused as production authority |
| Five versus six confirmations under proposed default | Ineligible versus eligible |
| Header `nTime` decreases while chain height increases | Order by height, not timestamp |
| Stale-tip/snapshot/clock rollback/backend unavailable | Historical/local fallback, not live Bitcoin |
| Snapshot changes mid-batch | Retry once against stable view or report incomplete |

### Receipts / reorgs / consumers

| Case | Required result |
|---|---|
| Received JSON/SQLite tries to supply receiver verification | No imported authority |
| Proof/record/covered prefix changes with same mtime and size | Content binding invalidates receipt |
| Policy/provider/network/verifier/hub identity changes | Receipt ineligible until rechecked |
| Crash/partial SQLite write/corrupt cache | Safe downgrade, no optimistic authority |
| Ordinary tip extension | Membership/depth rechecked, immutable binding reusable |
| Reorg removes attested block, including cached result | Immediate loss of live quality |
| Deep rollback below attestation or confirmation threshold | Ineligible |
| Fresh offline validated snapshot versus old snapshot | Eligible versus historical-only under policy |
| `status`/`queue`/settlement reads | Zero network requests |
| Same-block rivals with different signed timestamps | Evidentiary tie/contested, no authority tiebreak |
| Earlier verified commitment versus earlier backdated local assertion | Bitcoin evidence ranks first, no false creation-time inference |
| Commit height before publication anchor but bytes published before commit | No automatic independence/quorum credit |
| Earlier verified claim with an unverified rival | Show unresolved rival; no claim that earlier disclosure was impossible |
| End-to-end forged anchor through `hub check` and `pull` | Cannot seize Bitcoin-backed origin/authority or create a false verified backdating accusation |
| Existing optional-dependency-free and unsigned workflows | Continue to run without verifier |

Maintain #57's anchor-trust suite and run the full suite after implementation. Add a checked-in
historical mainnet proof/header fixture with documented provenance and independently cross-checked
expected digest/hash/height/time. Synthetic header fixtures are useful for negative cases, but
test-only easier-PoW/regtest behavior MUST NOT be reachable by an environment variable in production
mainnet verification.

## 16. Delivery plan and release gates

1. **Evidence/model spike:** choose and pin the optional OTS and headers dependencies; prove mainnet
   header/PoW/difficulty conformance offline; finalize policy values and the structured evidence
   interface. No restoration of `bitcoin` quality yet.
2. **Verifier and local state:** implement checkpoint/prefix binding, OTS parsing, provider
   snapshots, receipts, reorg/freshness eligibility and explicit CLI actions. Expose diagnostic
   results behind the new commands; ordinary priority remains contained until consumer review
   passes.
3. **Consumer integration:** migrate Bitcoin ordering to height/hash, make same-block ties explicit,
   audit commit-reveal and settlement inference, and test all cache invalidations. Only now allow
   `anchor_evidence()` to emit live Bitcoin quality.
4. **Operational migration:** verify existing proof files explicitly against the chosen local
   provider. Never grandfather `confirmed` metadata or pre-existing caches. A missing/stale backend
   leaves local quality, not an implicit explorer call.
5. **Optional ingest hardening:** a separate PR/version decision for new anchor-file refusal
   semantics.

The new flags/subcommands and evidence/settlement semantics call for a MINOR release under the
project's release rules (proposed 0.4.x work, not a tag decision made by this spec). The replicated
`SCHEMA` need not change solely for receiver-local receipts.

### Decisions still needing approval

- Header-validator implementation and packaging/licence pin; headers transport/source policy.
- Proposed six-confirmation and one-hour/six-hour freshness thresholds; bootstrap/work-floor policy.
- Exact publication-disclosure/independence policy for commit-reveal, separately from verifying a
  checkpoint.
- Whether structural ingest refusals ship separately and at what compatibility boundary.

The technical requirements above do **not** depend on choosing a full node. A correctly validated
headers-only path is explicitly sufficient under the disclosed SPV assumptions.

## 17. Source-backed rationale

Reviewed 2026-10-05; Research Commons references rechecked against `main` after #57 and #43 on
2026-10-06. Upstream `master` references explain behavior; implementation dependencies must be
pinned to reviewed versions/commits rather than following those moving branches.

- Research Commons #57 and `docs/DESIGN-notes-anchor-trust.md`:
  https://github.com/research-common/research-commons/pull/57
- #47 (authority among several publishers) and `docs/DESIGN-notes-signed-manifests.md` (#43).
- OpenTimestamps overview: https://opentimestamps.org/
- OTS detached-proof parsing and operation evaluation:
  https://raw.githubusercontent.com/opentimestamps/python-opentimestamps/master/opentimestamps/core/timestamp.py
  (`DetachedTimestampFile.deserialize`, `Timestamp.deserialize`, `all_attestations`).
- OTS Bitcoin attestation/header binding:
  https://raw.githubusercontent.com/opentimestamps/python-opentimestamps/master/opentimestamps/core/notary.py
  (`BitcoinBlockHeaderAttestation`, `verify_against_blockheader`). Its height is a lookup aid; the
  header Merkle root and header time must be verified independently.
- Bitcoin Core serialized header fields:
  https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/primitives/block.h (`CBlockHeader`).
- Bitcoin Core target/PoW and retarget rules:
  https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/pow.cpp (`GetNextWorkRequired`,
  `CalculateNextWorkRequired`, `DeriveTarget`, `CheckProofOfWorkImpl`). A permitted retarget range
  is not the same as exact expected difficulty.

This note changes no code and no existing behavior.
