# Design note: receiver-local Bitcoin time verification

**Status:** proposed · **Companion to:** the claims-model note (§15, "receiver-local Bitcoin verification")
**Covers:** the §15 item for #59; conformance cases C-btc-01 – C-btc-06, and the parts of C-core-19,
C-core-20, C-core-53, C-core-70, C-core-107, C-exch-16 and P-06 that depend on what `bitcoin` quality means
**Tracks:** #59 · **Re-bases:** the proposal in #60 onto the statement model. The verifier core of #60
(detached OpenTimestamps proof → operation tree → block Merkle root → authenticated header chain → receiver-
local receipt → ordering by chain position) is kept intact; what changes is what gets stamped, where the proof
lives and what the result unlocks.

**Scope: one proof format.** The `anchors` statement is format-neutral (wire-format note §5: `covered`,
`proof`, `proof_format`, `services`). This note is the profile for `proof_format: ots-detached-v1`, an
OpenTimestamps detached proof checked against Bitcoin headers, and it defines the quality `bitcoin`. Another
timestamping service is another `proof_format` with its own note and its own quality (§16).

Standards used here, per the wire-format note's standards-first rule (its §0): the OpenTimestamps detached
format as implemented by its reference library (§5.1; there is no standards-body specification), Bitcoin
Core's consensus header rules and BIP 34, 113, 130 and 157 (§6), and CAIP-2 for the display-only chain id
(§8.1). RFC 3161 time-stamp tokens and Roughtime (RFC 10049) were considered and are out of scope (§16).

Every requirement below is stated as something an implementation does, refuses or displays. "The reader" is
the implementation evaluating statements on the user's machine; "the author" is the key that signs them.

## 0. Summary

- The thing stamped is a **statement id**. Because `prev` is inside the signature, one id commits to the
  signer's whole log prefix ending there; an `anchors` statement bounds only that signer's own prefix.
- `publish` stamps first: the id is submitted to one or more calendars, the pending proof is stored as a
  content-addressed blob and referenced from an `anchors` statement, and only then do bytes leave the machine.
  A later `anchors` statement carries the upgraded proof.
- A proof is a blob, named by its full hash from the `anchors` statement. There is no sibling file, no
  locator, no path.
- Quality is the reader's verdict. `bitcoin` means *this reader* walked the proof to a header on a chain it
  validated itself. A `quality` field in received data grants nothing (C-core-107).
- Ordering is by chain position (height, then block hash on the reader's accepted chain). The header's
  `nTime` is displayed as miner-reported time and is never an ordering key.
- Verification writes a receiver-local receipt; every later read re-checks membership, confirmations and
  freshness against the current chain view. A reorg removes live quality at once; nothing is grandfathered.
- `bitcoin` unlocks exactly two things: priority among rival authorship claims for a construction (strictly
  earliest only) and a displayable "existed by T". Never ownership, edit rights or independence (I10).
  Derivation groups are exempt from priority altogether.
- Ordinary reads (`status`, `verify`, `explain`, settlement) make no network request. Header acquisition is
  one explicit command.

## 1. What is anchored

| Term | Meaning |
|---|---|
| **statement id** | hash of a statement's canonical signed body (claims-model note §4; encoding per the wire-format note) |
| **covered head** | the statement id an anchor stamps; the last statement of the bounded prefix |
| **bounded prefix** | the covered head plus every statement reachable from it through signed `prev` and `merges` links in the same key's log |
| **`anchors` statement** | a statement in the signer's own log carrying `covered`, `proof` (blob hash), `proof_format` (`ots-detached-v1` here), and `services` (the calendars submitted to; informational) |
| **stamped digest** | the raw 32 bytes of `covered`: what is submitted to calendars and what the proof's tree is rooted at. Derived, never carried in the statement, so it cannot disagree with `covered` |
| **bound** | the reader's conclusion "statement S existed by chain position P", at a quality the reader assigns |

Rules:

1. **Per signer, by construction.** An `anchors` statement bounds statements in the signer's own log only.
   Any other key's ids listed in its body receive no bound and are shown as `no anchor`; a proof whose
   stamped digest is another key's statement id is reported `invalid for <signer>` and ignored (C-btc-04).
2. **Coverage is the signed `prev` chain.** Statement S is covered by anchor A iff S is the covered head or
   is reached from it by following `prev`, and `merges` where a line carries it (wire-format note §7),
   through verified signatures. A line's id commits to every id it names, so an anchor taken after a fork
   is cleared covers both branches; one taken on a single branch before clearing covers that branch only.
   File position, line count and timestamps play no part. A break in the chain (missing statement, failed
   signature) ends coverage at the break; the reader shows `coverage ends at <id>`.
3. **The anchor chains after its head.** A valid `anchors` statement has the covered head in its own prefix
   (the head is reachable from the anchor's `prev`). An anchor whose head is not in its prefix is malformed
   and refused (intrinsic); the signer cannot bound a statement it has not yet appended.
4. **Anchoring a prefix does not validate its members.** A consumer that relies on a particular `authored`
   or `observed` statement still verifies that statement's own signature and log membership.
5. **Supersession.** A later `anchors` statement by the same key for the same `covered` head replaces the
   earlier one for display (typically pending → upgraded). Both stay in the log; `explain` lists both.
6. **Timestamps stay subordinate.** The `anchors` statement's own timestamp is the `local` bound and nothing
   more. An `anchors` statement timestamped earlier than its head is `incoherent` under the claims-model
   note §10 (C-core-106): its local bound is discarded, its signature is still reported valid, and its proof
   is still evaluated, because the chain position comes from the header, not from the timestamp.

Dropped from the alpha with no replacement: multi-log checkpoint roots, `ledger_head` line hashing, legacy
unsigned prefixes, `sig2`, anchor JSON records and `.root` files. The next format has none of them.

## 2. Stamp-at-publish flow

`publish` performs these steps in this order, and the order is observable (C-btc-03):

1. Sign the statement(s) being published; compute the covered head id `H`.
2. Compute the stamped digest = the raw hash bytes of `H` (no hex, no trailing newline, no framing).
3. Submit the stamped digest to each configured calendar. Calendar URLs are the author's local policy. A
   calendar that fails to answer within the local timeout is skipped; if every calendar fails, `publish`
   either refuses (`anchor required`) or continues with `anchor: none` recorded and a warning. It never
   proceeds silently. The default depends on what the statement's standing rests on (§17, decided 2):
   `anchor required` for an `authored` without `provenance` (its priority is the time bound, claims-model
   note §5.2), a statement carrying `fulfills` (a pre-registration is only worth its bound), an `authored` or
   `observed` whose `availability.redistribution` is `withheld` (a commitment to bytes not yet released), and
   an `observed` whose `capture.evidence` is `anchored-at-capture`; `anchor: none` with a warning for every
   other statement (other `observed` captures, members of a derivation group), so a calendar outage does not
   stop a capture whose window is closing. Local policy may override either default; neither is silent.
4. Store the returned pending proof as a blob; its id is the hash of the exact proof bytes.
5. Append an `anchors` statement: `covered = H`, `proof = <blob hash>`, `proof_format = ots-detached-v1`,
   `services = [<calendar URIs>]`.
6. Only now transport anything: blobs, statements, the proof blob.

A copier who observes the push (C-btc-03) can at best stamp its own `authored` statement afterwards; any
verified bound it obtains is at the same or a later chain position, and "same block" is `contested`, never a
win for the copier (C-btc-02).

**Pending proofs go in the log** (§17, decided 1). The step-5 `anchors` statement carries the pending proof,
so the stamp-before-transport order is observable to everyone (C-btc-03) and the proof survives the loss of
the author's machine as soon as anything has been pushed.

**Upgrade.** `anchor upgrade` (explicit, networked) fetches the completed attestation from the calendar,
stores the upgraded proof as a new blob and appends a second `anchors` statement for the same head. Readers
never dereference calendar URIs themselves; a pending proof held by a reader stays `pending`.

**Pending proofs grant nothing.** A pending calendar attestation is the calendar's promise. Its display
token is `pending`; its quality is `local` at best.

## 3. Threat and trust model

**Untrusted:** every statement, proof blob, header, block-height label, calendar response and backend error
string received from anyone, including a valid signing identity. An attacker may backdate its own statements,
replay another key's proof under its own `anchors` statement, submit an orphaned or easy-difficulty header
chain, withhold newer headers, send a 100 MB proof or a tree a million nodes deep, or embed URLs hoping the
reader fetches them.

**Trusted:** the reader's verifier code and pinned dependencies, its selected network and chain provider, its
local policy, its receipt store and its filesystem permissions. Same-user code execution is out of scope; a
receipt does not protect a compromised host.

**Headers-only assumptions.** A headers-only provider validates header rules and follows the
greatest-chainwork chain it has seen. It does not validate block bodies. Its security rests on SPV and
proof-of-work assumptions, adequate network access, and the absence of a successful eclipse or
adversarial-work attack. Every verdict discloses `chain_validation: headers-spv` or `operator-node`; a
headers-only result is never described as full-node validation. Independent header sources and an
operator-set minimum-chainwork floor mitigate eclipse risk; they do not remove it, and the display says so.

## 4. Binding the proof to the statement

Before any chain work, the reader checks, in order; the first failure names its class and stops:

| # | Check | On failure |
|---|---|---|
| 1 | The `anchors` statement verifies: signature, log membership, closed vocabulary, size limit | refuse the statement (intrinsic or operational) |
| 2 | `covered` is a statement id in the signer's own prefix (§1 rule 3) | `invalid-anchor`, refused |
| 3 | `proof_format` is `ots-detached-v1` (any other value is another profile's, not this note's) | `unsupported`, granting nothing |
| 4 | The proof blob named by `proof` is held and its bytes hash to `proof` | `missing-proof` (not a refusal; bound absent) |
| 5 | Proof bytes within size limit | operational refusal |
| 6 | Proof deserializes per §5.1 under depth/node limits; no trailing bytes | `invalid-proof` |
| 7 | The proof's declared file digest equals the stamped digest (the raw bytes of `covered`); file-hash op is SHA-256 | `invalid-proof` |

A refusal under 1, 2 or 5–7, and the `unsupported` of 3, are scoped to the `anchors` statement (C-btc-05):
the log's other statements are untouched, remain displayed, and simply have no bound from this anchor.
Nothing in received data can widen that scope.

A hex-encoded digest, a digest with a newline, a proof for a different statement, or a raw digest of the
statement bytes rather than of the canonical body all fail check 7.

## 5. Operation tree and attestations

The reader uses the OTS library's structured parser, never regular expressions over `ots info` output or a
CLI's "success" text.

Deserializing yields an operation tree rooted at the stamped digest. The reader enumerates
`(calculated_digest, attestation)` pairs and, for every `BitcoinBlockHeaderAttestation`:

- requires `height` to be within the provider's known chain: the format's varuint cannot carry a negative
  value or a non-integer, so `unknown-height` here means a height too large for the reader's integer type,
  below the lowest height the view holds (a checkpointed bootstrap, §6.1), or above the tip;
- resolves the header **at that height on the reader's accepted chain**, never a header carried in the proof,
  the statement, or a remote label;
- requires `calculated_digest == header.hashMerkleRoot` in the library's byte order, with explicit, tested
  conversions between internal and display order;
- derives `block_hash` and `nTime` from the 80 raw header bytes, not from backend strings;
- applies the confirmation policy (§7) in the current chain view.

No transaction or block body is downloaded: the path ends at the header's Merkle root. Pending and non-Bitcoin
attestations never grant `bitcoin`; their URIs are never dereferenced during verification.

**Several attestations.** Keep every candidate; select the **lowest eligible height on the accepted chain**,
never the lowest `nTime`. A bad or unknown additional candidate does not invalidate a distinct good one. A
proof that fails checks 5–7 in §4 is invalid as a whole. If an earlier candidate is `unknown-height` and a
later one is eligible, use the later one and display `earlier attestation at <h> not evaluable`.

### 5.1 The `ots-detached-v1` format

`ots-detached-v1` names the OpenTimestamps detached-timestamp file as implemented by the reference library
`python-opentimestamps` (`opentimestamps/core/timestamp.py`, `op.py`, `notary.py`, `serialize.py`; values
below checked against tag `python-opentimestamps-v0.4.5`). OpenTimestamps has no standards-body
specification; this table is therefore part of the profile, and a parser that differs from it on any row does
not conform, whichever library it uses.

| Element | Bytes | Rule here |
|---|---|---|
| header magic | `00 4f70656e54696d657374616d7073 0000 50726f6f66 00 bf89e2e884e89294` (31 bytes: `\0OpenTimestamps\0\0Proof\0` + 8 bytes) | exact match, else `invalid-proof` |
| major version | varuint `1` | any other value is `unsupported`, not `invalid-proof` |
| file-hash op | `08` (sha256), then 32 digest bytes | any other hash op is `invalid-proof` (§4 check 7) |
| operations | `f0` append, `f1` prepend (each with a varbytes argument, 1–4096 bytes); `f2` reverse; `f3` hexlify; `02` sha1, `03` ripemd160, `08` sha256, `67` keccak256 | any other tag is `invalid-proof`; an op whose result exceeds 4096 bytes is `invalid-proof` |
| branching | `ff` before every branch except the last | depth ≤ 256 (the library's recursion limit, and §12's) |
| duplicate siblings | two siblings at one node with the same operation and argument, or the same attestation bytes | `invalid-proof`. The library keeps a node's operations in a map keyed by operation and argument and its attestations in a set, so it merges duplicates silently; this profile refuses them, so that two parsers never disagree about what a file holds (C-btc-11) |
| attestation | `00`, an 8-byte tag, varbytes payload ≤ 8192 bytes, parsed to its exact end | trailing bytes inside a payload are `invalid-proof` |
| Bitcoin attestation | tag `0588960d73d71901`; payload = varuint height | the only tag that can yield `bitcoin` quality |
| pending attestation | tag `83dfe30d2ef90c8e`; payload = URI ≤ 1000 bytes from `A–Z a–z 0–9 - . _ / :` | displayed `pending`; never dereferenced (§2) |
| other attestations | any other tag, including Litecoin `06869a0d73d71b45` | retained as `unsupported attestation`, granting nothing (I5) |
| varuint encoding | every varuint (version, argument and payload lengths, Bitcoin height) | minimal only: a final byte `00` after a continuation byte (`81 00` for 1, `80 00` for 0) is `invalid-proof`, as is a value over 64 bits. The library reads a non-minimal varuint but its writer never emits one; refusing it gives each value one byte string, so "same operation and argument" in the duplicate-sibling row is byte-canonical, and no conforming file is refused |
| end of file | no bytes after the tree | `invalid-proof` |

`varuint` is the library's base-128 little-endian encoding (seven bits per byte, high bit = continuation). The
library's `master` writes the major version as a single byte while v0.4.5 writes a varuint; for version 1 the
two are the same byte `01`, and a conforming parser accepts exactly that byte.

## 6. Chain-provider contract

### 6.1 Preferred: locally validated headers

A maintained header-chain validator behind an adapter. The adapter is trusted code and is reviewed as such;
a database is not trusted because its name says `headers`, nor a daemon because it says `verified: true`.

The provider validates, with mainnet parameters: genesis identity or an explicit local checkpoint bootstrap;
80-byte serialization, hashes and `prev` linkage; compact-target decoding (positive, non-zero,
non-overflowing, within the PoW limit); actual proof of work; the **exact** retarget history including
rounding and clamping (a permitted range is not enough); contextual rules (`nTime` above the median of the
previous 11, as Bitcoin Core's `ContextualCheckBlockHeader` enforces it, `time-too-old`; the same
median-time-past BIP 113 uses; version/activation rules of the chosen validator, e.g. BIP 34 block versions);
future-time admission against the local clock (Core's `MAX_FUTURE_BLOCK_TIME`, 2 hours, `time-too-new`);
cumulative chainwork with greatest-work selection, never longest-by-height; reorg detection; lookup by height
and by hash.

**Equal-work tips are unresolved.** Bitcoin Core keeps the tip it saw first when two tips carry equal
chainwork. This profile deliberately does not: first-seen depends on delivery order, which two readers do not
share. The accepted chain ends at the tied tips' fork point, so a block above it on either branch is not on
the accepted chain, and an attestation there has no live eligibility (`stale-chain` when the block is held on a
tied branch, `unknown-height` when it is not) until more work breaks the tie (C-btc-15).

Baseline: full header history from genesis (~80 MB per million headers on disk; held in memory with
per-header chainwork and links it costs several times that, about 0.5 KB per header in this repository's
implementation, so a reader sizes memory separately), obtained headers-first (BIP 130
`sendheaders` announcements; a BIP 157 compact-filter client is an acceptable header source). Pruned or
checkpointed bootstraps may be offered with an explicit trust root and retained retarget/MTP context; a
height-to-time table is not a bootstrap. **The tool ships no checkpoint** (§17, decided 3): a checkpoint or
chainwork floor is a value the reader configures and the bootstrap identity names, so no trust root is
chosen by the project, and a reader that sets none syncs from genesis. Transport (P2P or other) is untrusted and never substitutes for
validation. The operator chooses sources explicitly; there is no automatic discovery.

### 6.2 Optional: operator-controlled node

A configured Bitcoin Core node supplies active-chain headers, tip and confirmation state. The adapter
re-hashes the raw header and checks the Merkle-root binding itself, uses the node's chain selection, and
refuses a node in initial block download. Credentials come from local configuration or cookie, never from
received data. An unavailable node never triggers an explorer fallback. A remote RPC is disclosed as
`operator-node (remote)`, not as local validation.

### 6.3 Provider API

```text
snapshot() -> ChainView
header_at(height, view) -> raw_header, block_hash
is_active(block_hash, height, view) -> bool
sync(policy) -> ChainView            # the only networked call; invoked by one explicit command
```

`ChainView` carries: network and genesis hash, provider id, validation mode, policy fingerprint, chain
epoch, tip height/hash/chainwork, last successful sync, readiness and freshness, bootstrap identity. One
batch uses one immutable snapshot. If the view changes mid-batch the reader retries once against a new
stable view or reports `incomplete`; it never mixes one view's header with another's tip.

## 7. Local policy

Defaults an implementation ships; every one is the reader's to change (I9), none can be set by received data.

| Setting | Default | Meaning |
|---|---|---|
| network | mainnet only | testnet/signet/regtest headers are refused as production evidence |
| validation mode | `headers-spv` | node optional |
| minimum confirmations | 6 | `tip_height − height + 1 ≥ 6`: below it a bound is `insufficient-confirmations` |
| settled depth | 144 (about a day) | confirmations, counted in the last validated view, past which a bound keeps `bitcoin` quality when that view is no longer fresh (§9.4) |
| priority margin | 0 | extra blocks the earlier bound must lead by to rank (§8.3); same block is always a tie |
| maximum view age | 1 h | since last successful validated sync or readiness check |
| maximum tip age | 6 h | operational stale-tip refusal, not a consensus rule: the tip header's `nTime` against the local clock, as Bitcoin Core's stale-tip check reads it. The only use of `nTime` beyond display and the §6.1 header rules |
| network during reads | never | reads touch receiver-local state only |
| explorer fallback | none | unsupported, not merely disabled |
| header sources | operator-configured | independent sources recommended; eclipse limit disclosed |
| chainwork floor / bootstrap | explicit local value | no sender-selected trust root. The analogue of Bitcoin Core's `nMinimumChainWork`, which Core ships per release; here the reader sets it, and it is never taken from received data |

**Finality is the reader's policy.** Bitcoin finality is economic and probabilistic: no depth makes a block
irreversible, each further block makes reversal more expensive. The three depth settings above are the
reader's view of that, never a property of the evidence, and received data cannot change them. Two readers
with different depths can therefore disagree about priority between close claims; each discloses the policy
it used (`policy_fingerprint`, §8.1). A depth protects against reorganisation only: a reader whose header
sources are all eclipsed is not protected by any depth (§3).

Freshness uses the reader's clock and local sync state. A backward clock jump marks the view unavailable for
live eligibility until a sync succeeds; this is reported as `stale-chain`, an operational state, never a proof
failure. Test-only easier-PoW parameters are not reachable from production configuration by any environment
variable.

## 8. Evidence, quality and what it unlocks

### 8.1 Structured evidence

Every bound is a record, not a `(timestamp, quality)` pair:

```text
quality            none | local | bitcoin
state              verified | verified-historical | pending | insufficient-confirmations | missing-proof
                   | invalid-proof | invalid-anchor | unknown-height | orphaned | stale-chain
                   | backend-unconfigured | backend-unavailable | unsupported | refused
signer             key
anchor             statement id of the `anchors` statement
covered            statement id of the head
proof              blob hash
network, genesis_hash, chain_id (CAIP-2, display only: `bip122:` + the first 32 hex of genesis_hash)
block_height, block_hash (display order), header_time (nTime, display only), confirmations
chain_validation   headers-spv | operator-node | operator-node (remote)
chain_epoch, verified_at (reader-local), policy_fingerprint, verifier_version
```

`local` evidence carries the signer's own timestamp and no chain fields. `none` is the absence of any anchor.
`refused` is an operational refusal under §4 (the `anchors` statement or the proof exceeds one of the reader's
size limits, checks 1 and 5); the record names the class and the limit, and the bound is absent.

### 8.2 Quality table

From the claims-model note §10, made concrete:

| Use | `local` | `bitcoin` |
|---|---|---|
| priority among rival `authored` claims for a construction without provenance (§5.2) | never ranks (C-core-19, P-06) | ranks iff strictly earlier chain position than every rival (C-btc-01); equal position → `contested` (C-btc-02) |
| "existed by T" for `anchored at capture` (C-core-53) | `anchored at capture (local, self-declared)` | the header's `nTime` displayed as a time, labelled miner-reported, plus height |
| "existed by T" for pre-registration (C-core-70, C-exch-16) | `pre-registered <edition> (local, self-declared)` | `pre-registered <edition> (bitcoin)` with the time |
| ownership, edit rights, independence, quorum credit | never | never (I10, §11 below) |

**Derivation groups are exempt.** `authored` statements sharing a workflow hash and input hashes form one
group (claims-model note §5.2); priority is never computed within it, whatever bounds the members carry.
Display is `derived by k under wf-…`; `explain` states that priority is not computed within a derivation
group (C-core-20). Bitcoin evidence on a group member still serves the "existed by T" rows.

**Same receipts everywhere.** Capture evidence, pre-registration and priority all read one bound record per
anchor (I12). There is no separate "capture anchor" mechanism.

### 8.3 Comparison relation

Computed separately from any display sort, and returned by `explain`:

| Relation | When |
|---|---|
| `earlier-commitment` | both `bitcoin` on the same network and accepted chain view, and the earlier bound's height is lower by more than the priority margin (§7; default 0, so any lower height). Same height is a tie: no rule on block hash is applied |
| `within-margin` | both `bitcoin`, different heights, but the gap is within a non-zero priority margin |
| `same-block` | same accepted height and hash |
| `unverified` | either side is `local`, `none`, or any non-`verified` state |
| `incomparable` | different networks, or either side `orphaned`/`stale-chain` |

The priority margin is the reader's policy, so both bounds in one comparison are read under the same margin; a
reader that one day combines bounds from more than one verifier (a second proof format, §16) applies one margin
to the pair, never a different one per side.

Only `earlier-commitment` ranks. `same-block`, `within-margin` and `unverified` resolve to `contested` for
priority; `explain` names which, and for `within-margin` the gap and the margin. A
`bitcoin` bound always outranks a `local` assertion in evidentiary order, and the display never infers that
the `local` party actually came later. Where one claimant is verified and another is unverified, the display
is "earliest **verified** claim", with the rival shown as `later claimant` (C-btc-01 (b)) but never as
"proven later". A deterministic display order by signer or id is permitted only under a visible
`non-evidentiary order` label.

Header `nTime` may decrease while height increases; the reader orders by height (acceptance test C-btc-13).

## 9. Receipt store

### 9.1 Location

Receipts, policy and the optional header database live in receiver-local state **outside the replicated data
surface**: for a git-backed hub, under the git directory resolved through Git (linked worktrees work); for any
other root, under an explicitly configured state directory. Without one, the state is `backend-unconfigured`
and every bound stays `local` (C-btc-06). Receipts are never written into blobs or statements, never pulled
or pushed, and a received file shaped like a receipt is inert.

Files are permission-restricted; writes are transactional or atomic-replace with locking. Verifying requires
no signing key: a reader with no key of its own verifies proofs.

### 9.2 What a receipt binds

Hub instance · `anchors` statement id and signer · covered head · proof blob hash · stamped digest · network
and genesis · block height, display hash and raw-header digest · provider and bootstrap identity · validation
mode · verifier version · policy fingerprint · chain snapshot at verification · diagnostics.

All fingerprints are content hashes (I14, C-core-129). Proof bytes are read once and the same bytes are used
for parsing and hashing, so modification during verification cannot yield a receipt for other bytes.

### 9.3 Eligibility on every read

A stored `verified` row is not authority. Before a read emits `bitcoin`, the reader confirms:

1. the `anchors` statement and proof blob still hash as recorded;
2. verifier, provider and policy fingerprints are compatible;
3. the chain view is ready and fresh under policy;
4. the recorded block hash is still active at its height with sufficient confirmations;
5. no outstanding chain-epoch invalidation.

The immutable proof-to-header binding is cached separately from mutable active-chain eligibility, so a tip
extension re-checks only 3–5, while a reorg can never let a cached branch survive. An orphaned block loses
live quality immediately; if the proof holds another active attestation, it is selected only after local
re-evaluation. A corrupt, copied, foreign-hub or unknown-version cache is downgraded, never trusted.

### 9.4 Offline behaviour

Verification against a stored header snapshot can succeed offline. The reader reports the snapshot tip and
whether freshness policy holds:

- fresh validated snapshot → `verified`, live `bitcoin` quality, no network request;
- old snapshot in which the block already had at least the settled depth (§7) → `verified`, `bitcoin`
  quality, displayed `as of <last sync>`; it ranks for priority. A reorganisation that deep would have to
  have happened since the sync, and the display says when that was;
- old snapshot in which the block was shallower → `verified-historical`: the header time is shown as a time,
  labelled `as of <last sync>`, and priority is not computed from it;
- no snapshot or no backend → `backend-unconfigured` / `backend-unavailable`, quality `local` or `none`.

`--offline` refuses every network call. Without it, reads still make none; only `anchor headers sync` and
`anchor upgrade` do.

## 10. Outputs

**Commands** (names illustrative; semantics normative):

```text
verify <statement> [--time] [--offline]   evaluate bounds; writes receipts when --time
anchor headers sync                        the only header-acquiring command; bounded, cancellable
anchor upgrade <anchors-statement>         fetch completed proof, store blob, append a new anchors statement
anchor status                              provider, mode, tip, freshness, policy, receipt counts; no secrets
explain <statement>                        the bound record, the relation, and every check performed
```

**Exit codes** follow the claims-model note §13 for `verify`:

| Condition | Exit |
|---|---|
| every requested bound is `verified` | 0 |
| any `invalid-proof` or `invalid-anchor` | 1 |
| none invalid, but any `pending`, `missing-proof`, `insufficient-confirmations`, `unknown-height`, `orphaned`, `stale-chain`, `backend-*`, `unsupported`, `verified-historical`, `refused` | 3 |

Mixed batches report every per-anchor state; precedence invalid > could-not-check > verified. A `bitcoin`
label in received data with no local verification yields state `backend-unconfigured` or `pending`, displays
`not verified by this reader`, and never exits 0 (C-core-107, C-btc-06). Neither an exit code alone nor a
backend's `verified: true` is an authority API; consumers read the evidence record.

## 11. Inference limits

**Priority is not independence.** An earlier verified bound says the statement existed by that block. It does
not say its author worked independently, nor that a later claimant copied (claims-model note §5.2, §9.3).

**Commit-reveal is not fixed by comparing two bounds.** A withheld-availability `authored` statement
(claims-model note §7) anchored at block `C`, revealed after a rival's publication anchored at `P`, with
`C < P`, establishes that the commitment existed before the rival's anchor. It does not establish that the
committed bytes were unknown to the committer's environment before `C`: a hash that was already public can be
committed to by anyone. The reader therefore never grants independence or quorum credit from `C < P`, nor
from comparing two signers' self-declared timestamps, nor from either combined with the existence of a proof.
Readiness stays `unknown` where independence is required and not otherwise established (acceptance test
C-btc-19). A receiver's own observation of a publication proves what that receiver saw and when, not the
absence of earlier disclosure anywhere.

**Unverified rivals stay visible.** An earliest verified claim beside an unverified rival is displayed as
such; the tool never states the rival could not have published earlier.

## 12. Dependency and implementation boundaries

- OTS parsing uses the reference library (`python-opentimestamps`, LGPL-3.0-or-later) or any parser that meets
  §5.1, as a pinned **optional** dependency, never vendored into the Apache-licensed tree. Absence of the
  dependency leaves every bound `local` and every other command working.
- The header validator is selected by an implementation spike against §6; a bare header parser with a
  per-header PoW check does not qualify. Its supported rules and bootstrap model are documented before a
  headers backend is advertised.
- An implementation may instead carry its own proof parser and header validator in its tree, in its own
  language, provided they pass C-btc-11, C-btc-14 and C-btc-15 and the parser meets the §5.1 table row for
  row. Such code is trusted code and reviewed as such (§6.1); the optional-dependency rule above still
  applies to any external helper it calls.
- Helpers are invoked with argument arrays (no shell), over a versioned, bounded JSON protocol; unknown
  versions, missing required fields, malformed output or mismatched echoed input hashes fail closed.
- Resource limits (local, operator-adjustable, never sender-set): `anchors` statement 64 KiB; proof blob
  8 MiB; tree depth 256; 100 000 nodes; 30 s and 256 MiB per proof helper; 60 s per provider request; total
  sync budget with cancellation. Limits apply during parsing, not after.
- The verifier never follows calendar URLs during `verify`, never reads outside the blob store and state
  directory, and never prints credentials or key material in diagnostics.

## 13. What an implementation provides to claim the bitcoin-time profile

An implementation declaring the `bitcoin-time` profile (CONFORMANCE.md "Core and profiles") provides all of:

1. the stamp-at-publish ordering of §2, observable against a mock transport;
2. the `anchors` statement fields of §1 and the binding checks of §4;
3. a chain provider satisfying §6.1 or §6.2, with its validation mode disclosed on every verdict;
4. the policy surface of §7, local and documented, with the stated defaults;
5. the evidence record and comparison relation of §8, consumed by priority, capture-evidence display and
   pre-registration display through one code path (I12);
6. the receipt store and re-check rules of §9, including offline behaviour;
7. the tokens and exit codes of §10;
8. the acceptance tests of §14 with fixtures checked in, including one historical mainnet proof/header fixture
   with documented provenance and independently cross-checked height, hash and digest;
9. a conformance statement listing by id every C-btc case it does not pass.

Without all nine, the implementation declares no profile; its C-btc cases report `unsupported` and every bound
it displays is `local` or `none`.

## 14. Acceptance tests

Fixtures use synthetic keys and either a checked-in historical mainnet fixture or synthetic header chains for
negative cases. CI contacts no public network or calendar. C-btc-01 – C-btc-06 are the conformance cases from
CONFORMANCE.md, restated here in brief (their ids in backticks, because CONFORMANCE.md is where they are defined);
the rest are this note's supplementary regressions, defined here. Every id has exactly one defining table, and
the conformance harness reads both documents.

### 14.1 Conformance cases

| Id | Scenario | Required outcome |
|---|---|---|
| `C-btc-01` | rival `authored`, A verified at block n, B at n+1; or A verified, B unanchored; permute | A default author, B `later claimant`, not `contested`, exit 0; `explain` cites the reader-verified bound |
| `C-btc-02` | both verified in the same block | `contested`, both listed, exit 3, no default single-party field |
| `C-btc-03` | observe `publish` against a mock transport; copier C publishes after seeing the push | `anchors` statement precedes the first byte out; C's bound later; original default, C later claimant |
| `C-btc-04` | A's anchor lists a B line id; variant: proof stamping B's prefix under A's anchor | B's line `no anchor`; the misattached proof invalid for A; B's log untouched |
| `C-btc-05` | malformed and oversized proofs on a valid log | anchor refused with class named; statements valid and displayed; no bound |
| `C-btc-06` | well-formed proof, no backend configured | bound shown unverified (`local, self-declared` or `unknown`); no priority; exit 3 |

### 14.2 Binding

| Id | Scenario | Required outcome |
|---|---|---|
| C-btc-07 | a proof whose file digest is not the raw bytes of `covered`; an `anchors` with `proof_format` other than `ots-detached-v1` | `invalid-proof`; `unsupported`, no bound, nothing refused |
| C-btc-08 | proof declares hex digest, digest + newline, or a different statement's id | `invalid-proof` |
| C-btc-09 | `anchors` statement whose `covered` is not in the signer's prefix | refused (intrinsic), scoped to the statement |
| C-btc-10 | proof blob not held | `missing-proof`, exit 3, no fetch attempted |
| C-btc-11 | duplicate keys, trailing bytes, truncated tree, depth or node limit exceeded | bounded `invalid-proof`, within time and memory limits |
| C-btc-12 | pending-only attestation | `pending`, zero calendar requests |

### 14.3 Chain and policy

| Id | Scenario | Required outcome |
|---|---|---|
| C-btc-13 | `nTime` decreases while height increases | ordering by height |
| C-btc-14 | header fixtures across retarget boundaries; PoW-valid header with wrong contextual target; bad compact target; wrong predecessor; MTP violation | exact target validated; each invalid case refused |
| C-btc-15 | longer-by-height, lower-chainwork fork; equal-work tips | fork not selected; equal work reported unresolved, no live eligibility |
| C-btc-16 | testnet/signet/regtest provider under mainnet policy | refused as production evidence |
| C-btc-17 | 5 vs 6 confirmations | `insufficient-confirmations` vs `verified` |
| C-btc-17a | old snapshot (past maximum view age); the block had 143 vs 144 confirmations in it; then minimum confirmations set to 200 | 143: `verified-historical`, time shown `as of <sync>`, no priority, exit 3; 144: `verified`, `bitcoin` `as of <sync>`, ranks, exit 0; at 200 both `insufficient-confirmations` |
| C-btc-17b | rival `authored`, verified at heights n and n+3; priority margin 0, then 3 | margin 0: `earlier-commitment`, default author; margin 3: `within-margin`, `contested`, exit 3, `explain` names gap 3 and margin 3 |
| C-btc-18 | stale tip, old snapshot below settled depth, clock rollback, backend down; snapshot changes mid-batch | historical or `local`, never live; one retry or `incomplete` |
| C-btc-19 | withheld-availability commitment at C < rival's P, bytes public before C | no independence or quorum credit; readiness `unknown` |

### 14.4 Receipts, reorgs, consumers

| Id | Scenario | Required outcome |
|---|---|---|
| C-btc-20 | received statement or file shaped like a receipt | no imported authority |
| C-btc-21 | proof or anchor bytes change with identical size and mtime | content binding invalidates the receipt |
| C-btc-22 | policy, provider, network, verifier or hub identity changes | ineligible until re-checked |
| C-btc-23 | crash mid-write, corrupt cache, foreign-hub cache | downgrade, no optimistic authority |
| C-btc-24 | tip extension; reorg orphaning the attested block (including cached); deep rollback | re-check only; immediate loss; ineligible |
| C-btc-25 | `status`, `verify`, settlement reads | zero network requests (asserted via network audit) |
| C-btc-26 | derivation group with members verified at different heights | `derived by k`, no priority, `explain` says so (with C-core-20) |
| C-btc-27 | `observed` with `anchored at capture`, local vs verified | `(local, self-declared)` vs time with height (with C-core-53) |
| C-btc-28 | result `fulfills` edition, local vs verified bound | `(local, self-declared)` vs `(bitcoin)` (with C-core-70, C-exch-16) |
| C-btc-29 | earlier verified claim beside unverified rival | rival displayed; no "could not have published earlier" text |
| C-btc-30 | verifier dependency absent | every other command runs; bounds `local`; profile reports `unsupported` |

## 15. Relationship to the alpha

**Kept:** the whole verifier core from #60 (detached OTS proof, structured parsing, Merkle-root binding at the
accepted header, chain-position ordering, header-chain provider contract, receipt store, reorg and offline
rules, inference limits), and the containment stance of #57 (a label in a file grants nothing).

**Dropped:** multi-log checkpoint roots and the sorted-heads Merkle algorithm; `.root` files and the
hex-plus-newline stamping convention; `ots_proof` locators and anchor-directory path rules (a proof is a blob,
fetched by hash like any other); `sig2`; `ledger_head` line hashing and legacy unsigned prefixes (coverage is
the signed `prev` chain); the `(timestamp, quality)` tuple; the alpha's `--check-time` exit codes (now the
`verify` vocabulary of the claims-model note §13); the phased delivery plan and the "do not restore `bitcoin`
until consumers ship" gate, replaced by the profile declaration of §13.

**Why:** the clean break (claims-model note §14) makes every alpha structure the verifier bound to disappear.
Signing `prev` removes the need to hash physical lines; single-key logs remove multi-log checkpoints; blob
identity removes locators. Priority established under the alpha does not carry over; alpha proofs stamp alpha
roots and bind nothing in the new format.

## 16. Out of scope

- The wire format of statements and the exact byte encoding of a statement id (wire-format note).
- Non-OTS timestamping schemes and non-Bitcoin chains; a second `proof_format` value is a separate note.
  RFC 3161 time-stamp tokens are the likeliest candidate (a trusted-third-party time, so a quality of its own,
  never `bitcoin`); Roughtime (RFC 10049, Experimental) attests a server's clock, not a digest's existence,
  and could at most inform the reader's clock checks.
- Choosing the header-validator dependency (implementation spike, §12).
- Hub-side structural checks of `anchors` statements beyond the one validation core (claims-model note §11).
- Any rule that turns commitment order into edit rights; none exists and none is planned (I10).
- Receipt sharing between readers (would reintroduce transported verdicts).

## 17. Decisions and open questions

**Decided (2026-10-16).** All five.

1. **Pending anchors in the log.** Kept: the pending proof is appended before transport and the upgraded
   proof in a second `anchors` statement (§2). Holding the pending proof locally would leave nothing
   observable until upgrade and lose the proof with the author's machine.
2. **Calendar failure at publish.** The default depends on the statement's standing (§2 step 3): `anchor
   required` where the claim is the time bound, `anchor: none` with a warning elsewhere; both overridable.
3. **Chainwork floor and bootstrap.** No checkpoint ships with the tool; the floor and any checkpoint are
   explicit local values (§6.1, §7). Genesis sync is the default.

4. **Historical verdicts as display.** Folded into one local finality policy (§7): a bound whose block had at
   least the settled depth (default 144) in the last validated view keeps `bitcoin` quality when that view
   is old, displayed `as of <last sync>`; a shallower one is `verified-historical`, shown as a time with that
   label and never used for priority (§9.4). "Verified" is never permanent: every read re-checks (§9.3).
5. **Confirmation depth versus priority ties.** A local priority margin (default 0): the earlier bound ranks
   only if it leads by more than the margin, otherwise `within-margin` → `contested` (§8.3). The default
   keeps honest near-simultaneous publishers ordered; a cautious reader raises it.

The questions as first asked:

1. **Pending anchors in the log.** §2 appends an `anchors` statement with a pending proof before transport so
   that C-btc-03 is observable, then a second one on upgrade. Alternative: stamp before transport but append
   only the upgraded statement, with the pending proof held locally. The alternative leaves nothing observable
   in the log until upgrade and loses the proof if the author's machine dies first. Decide which.
2. **Calendar failure at publish.** Default `anchor required` (refuse to publish when no calendar answers) or
   default `anchor: none` with a warning? The first protects priority; the second protects availability. A
   third option, raised in review: make the default depend on what the statement's standing rests on.
   `anchor required` for the kinds whose claim *is* the time bound: an `authored` without provenance
   (priority, claims-model note §5.2), a statement that `fulfills` a pre-registration task, a `withheld`
   commitment, and an `observed` declaring `anchored at capture` evidence. `anchor: none` recorded, with a
   warning, for everything else (other `observed` captures, derivation-group members), so a calendar outage
   does not stop a capture whose window is closing. Both overridable by local policy; neither silent.
3. **Chainwork floor and bootstrap.** Ship a pinned mainnet checkpoint in the tool (fast first sync, a trust
   root the project chose) or require genesis sync (slow, no project-chosen trust root)?
4. **Historical verdicts as display.** Should `verified-historical` show the header time as a time (with a
   staleness label) or only as `unverified` until a fresh sync? The first is more useful offline; the second
   is stricter under I4.
5. **Confirmation depth versus priority ties.** With 6 confirmations required, two anchors one block apart
   are both eligible and ordered. Should priority additionally require the earlier bound to be *d* blocks
   deeper than the later one, to make reorg-induced flips rarer, or is "same accepted chain view" enough?
