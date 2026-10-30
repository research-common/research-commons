# Candidate profile: fixed-root identity

**Status: review candidate; not enabled in the production reader or writer.**
This document selects one wire proposal, `fixed-root-v1` on **`rc/2`**, rather than
changing `rc/1` fields through a critical-extension handler. It does not change
`wire.Major`, the current release version, old design notes, or any conformance claim.
The validation harness is test-only. It checks syntax and selected cryptographic and
compatibility properties, **not end-to-end identity authority**.

## 1. Purpose and non-goals

One principal has one fixed, dedicated administrative root R. Its inception's ordinary
statement id is I. R grants explicitly scoped authority to operational signing keys;
workers consent separately in each signed statement. R can cut a grant while preserving
an exact accepted prefix. A root's historical acceptance is not proof that a worker was
honest when it signed.

There is no root rotation under the same I, guardian/recovery quorum, recursive
delegation, root-algorithm migration, implicit succession, mandatory certificate expiry,
separate bare-key recovery, or Commons-operated identity service. Root loss freezes new
administration without invalidating already provable grants; a restored copy of the
**same** root key can resume. Root compromise requires a new I and independently
accepted resource/policy changes. Independently generated spare keys are not recovery.

This is not proof of a person, institutional membership, unique operator, independent
experiment, truth, or freshness. Public key/identity associations are correlatable.
An offline bundle can omit a cut; all positive results are relative to held evidence.

## 2. Exact representation and version boundary

### 2.1 Selected proposal

A future dual-major reader would implement both:

* **`rc/1`:** existing bare-key statements retain their signed bytes, ids and semantics.
  All raw `rotate_key` and `revoke_key` events **remain `rc/1`, without identity actor or
  marker**, including after `rc/2` lines. Thus old readers still recognize their effect
  on bare-key history. This candidate does not accept these events as `rc/2`.
* **`rc/2`:** all statements of this candidate require
  `crit:["x_identity_v1"]` and an object `body.x_identity_v1`. The currently recognized
  critical registry contains only that token. This includes administrative statements,
  typed resource bodies and identity-aware task lifecycle statements. `x_actor_v1` is
  optional, but when present is a **signed envelope** object, not part of the body.

`rc/2` retains the ordinary envelope fields `rc`, `kind`, `signer`, `alg`, `seq`,
`prev`, `ts`, `body`, optional `merges`, and `sig`. `signer` remains the actual key.
`x_actor_v1` is exactly `{"identity": I, "grant": G}`; I and G are full lowercase
64-hex statement ids, without new prefixes. All fields except `sig` are signed.
There is no carrier-key or `controller_identities` map.

In `rc/2`, `genesis.body.controllers` and
`edition.body.contents.controllers` are sets of **tagged subjects**:
`{"key": K}` or `{"identity": I}`. Exactly one tag is allowed. The optional
`identity AND key` restriction is not writable in this profile. Genesis requires a
nonempty controller set and satisfiable rule. A controller change requires **both**
complete `controllers` and `rule`, never a partial patch. Without a change, predecessor
authorities must agree or the edition remains unresolved/contested until an explicit
complete merge authority is supplied. Authorization still comes from predecessor
controllers, not the proposed new controllers.

This is an explicit major-version proposal because replacing a key string by a tagged
object changes a required field's type and meaning. A recognized `crit` handler must
not suppress the selected major's base schema. No conversion is performed on existing
signed statements. Old key-only resources adopt typed controllers only through an
edition authorized under their existing controller authority (or a new resource).

A future dual-major reader must reject identity actor/marker use in `rc/1` as outside
this profile, not silently upgrade it. Unextended `rc/1` remains unchanged. There is
**no alpha-ledger importer** here: dual reading concerns only these `rc/1` and `rc/2`
statement envelopes, not older ledger formats.

### 2.2 Canonicalization, signatures and ids

Reuse the existing wire rules, not a new JSON or cryptographic profile:

* Strict UTF-8/I-JSON; no BOM, duplicate decoded member names, lone surrogates,
  fractions, exponents, negative zero, or integer magnitude above `2^53-1`.
* RFC 8785 JCS, sorting object keys by UTF-16 code units; no Unicode normalization.
  Noncanonical whitespace/member order may be received; canonicalize before checking
  the original signature, never re-sign a received statement.
* Maximum nesting depth 16; exact PAE signed string at most 65,536 bytes. Preserve
  the existing preparse received-line bound. Canonical UTC times use the existing
  time parser, not a generic JSON Schema `date-time` validator.
* `PAE(type,payload) = "DSSEv1 " + len(type) + " " + type + " " + len(payload) + " " + payload`,
  with decimal byte lengths and JCS(envelope excluding `sig`) as payload.
* Statement type: `application/vnd.research-commons.<kind>.v2+json` for `rc/2`;
  retain `.v1+json` for `rc/1`. Statement id is lowercase SHA-256 of that PAE.
* **Edition id for `rc/2`** is SHA-256 of
  `PAE("application/vnd.research-commons.edition-body.v2+json", JCS(body))`.
  `rc/1` edition ids retain the `.v1+json` domain. A resolver must retain the major
  alongside a body; it must not use the existing single v1 edition-domain constant
  for both. Approvals of one edition share exactly the same major and body bytes.
* Ed25519: existing public-key encoding and pinned verifier, pure Ed25519 over exact
  PAE, without prehash/context. EIP-191: existing `personal_sign` over those exact PAE
  bytes (including its EIP-191 length prefix); existing address/recovery and canonical
  signature rules. Unknown algorithms grant nothing. No EIP-712, WebAuthn, OpenPGP,
  or smart-contract-wallet proof is accepted as a substitute.

Existing unknown noncritical fields remain signed, retained and semantically inert.
New actor, subject, permission, target and critical-marker objects are closed in the
candidate schema: an unrecognized member does not create new authority. New profiles,
permissions or critical features require explicit reader support. A schema failure
is never an instruction to discard authenticated relevant control evidence and then
claim that the remaining positive grant is complete (§5).

### 2.3 Actor / body validity matrix

| Signed body and envelope | Upgraded interpretation |
|---|---|
| `rc/1`, no identity marker or actor | Existing `key(K)` semantics. |
| `rc/2`, understood marker, no actor | `key(K)` on an identity-aware body; may fill only a key slot. |
| `rc/2`, understood marker and one actor I/G | Exactly I/G, subject to authority checks; never a key fallback. |
| Actor without body marker or without critical declaration | Invalid candidate even if correctly signed. |
| Marker present but unknown critical feature/profile | Unsupported/non-passing, not bare-key interpretation. |
| Marker object has a field inappropriate to this kind | Invalid candidate; do not ignore it. |

Marker fields are kind-specific: `authored`/`observed` may contain `amends`;
`edition` may contain `task_roles`; `progress`/`withdraw` must contain `intent`;
other candidate kinds use `{}`. `amends` requires an identity actor. Genesis,
`describes`, and the three administrative kinds do not accept identity actors in
this profile. A root signature alone does not fill its identity slot.

A bare-key creator can sign a typed genesis containing identity controllers. This
creates a proposal, not the named identities' endorsement, and avoids the circularity
of needing a resource-scoped grant before the resource id exists. Different approval
signatures may choose different I/G or no actor while signing the same body. Even the
same actual key may emit distinct raw and identity-context approvals: each signature
acts for exactly one subject; one signature never fills both slots.

### 2.4 Old readers and historical mixed logs

The unchanged `rc/1` wire reader takes its unknown-major path for `rc/2`: it preserves
canonical envelope bytes/id and key-local linkage, marks `unsupported`, and **does not
verify the signature or decode the body**. This is weaker than verified retention.
The key log retains an unvouched `rc/2` line without placing it. A later verified
`rc/1` statement from that same key can vouch for it through `prev`/`merges`, permitting
linkage, but never semantic evaluation. A later raw `rc/1` key event remains visible.
Other keys' historical lines are unchanged. No claim is made that an old reader
understands root cuts or identity authorizations.

Tests demonstrate `rc/1 → rc/2 → rc/1 revoke_key` linkage, retention before the last
line, unchanged original ids, a second independent key's log, and both candidate
signature algorithms. An old reader even retains a bad-signature unknown-major line;
therefore its retention is not proof of `rc/2` authenticity.

**Integration blocker:** wire/keylog compatibility is not whole-reader safety. The
baseline resource resolver contains unsupported-body inspection before its evaluation
guard; `rc/2` bodies may be absent in the old parsed representation. Unsupported-input
hardening is required before any full mixed-reader/resource safety claim. Do not run
this candidate's resource vectors through an unhardened production resolver and infer
that retain-as-unsupported implies panic freedom. Also, a malicious signer can create
nonconforming `rc/1` bytes with an unmarked envelope actor that an old reader ignores;
this proposal does not retroactively repair old readers. No conforming candidate
writer emits that combination.

## 3. Administrative vocabulary and permissions

Exactly three new administrative kinds exist. They are root-signed raw-key statements,
not worker actions. There is no second identity log; all reside in R's ordinary log.

| Kind | Required body besides the marker | Additional rules |
|---|---|---|
| `identity_inception` | `profile:"fixed-root-v1"` | `seq:0`, `prev:null`, no merges. Its ordinary statement id is I. |
| `identity_grant` | `identity:I`, `delegate:{key:K,inception:D}`, nonempty `permissions` | Same root and complete root lineage descending from I; K must differ from R. D is K's exact seq-0 statement. |
| `identity_cut` | `identity:I`, `grant:G`, mandatory `last_good:L-or-null`, `reason` token | Same root lineage, exact G binding, and complete relevant dependencies. |

A different inception, even for the same public key, is a different lineage and is
not interchangeable with I or D. `seq`, `prev`, and `merges` must satisfy the existing
complete key-local linkage rules; an arbitrary valid signature or nonzero head is not
an inception. Root freshness/dedication is a writer requirement, not proof that no
other log exists. Validators enforce K != R within this identity.

Permissions form a nonempty, sorted, duplicate-free set (at most 64 entries). Sorting
for structured sets is by UTF-16 ordering of each entry's JCS text; string sets use
the ordinary UTF-16 string order. Target arrays are nonempty sorted sets of at most
256 entries. Each entry has exactly the fields in the table; no missing/empty target
means unlimited. Multiple entries may cover different targets for the same kind;
matching one complete entry is sufficient. No permission merges fields from separate
entries to manufacture broader authority.

| `kind` | Exact target dispatch | Allowed `targets` | Extra required fields |
|---|---|---|---|
| `authored`, `observed` | `body.content.digest` | `{any_content:true}` or `{contents:[digest,…]}` | `amend:true` or `amend:false` |
| `holds` | `body.content.digest` | Same content choices | None |
| `reproduced`, `corroborates`, `refutes`, `retracts` | `body.of` | `{any_statement:true}` or `{statements:[id,…]}` | None |
| `edition`, `withdraw_approval` | `body.resource` | `{resources:[id,…]}` only | None |
| `intent`, `withdraw`, `progress`, `submit`, `decide` | `body.task` | `{tasks:[id,…]}` only | None |
| `anchors` | Signer's own key log | No `targets` field | None |

No resource/task wildcard, administrative grant, root control, or key-event delegation
is admitted. `describes` and genesis remain raw-key statements. A permission for one
kind does not authorize another. A target mentioned incidentally elsewhere in a body
does not satisfy scope. Unknown permission kinds/target modes make the grant unsupported
and non-passing, not broader. That uncertainty is confined to the one grant: grants only
accumulate and never restrict each other, and every permission kind in `fixed-root-v1`
is a leaf operation, so no grant can carry a power over another grant, a cut, or the
root. Acts under the unsupported grant read unknown; sibling grants are evaluated
normally, with a warning naming the grant that could not be read. **Invariant for every
later version of this profile:** a permission kind may never confer administrative power
(issuing, cutting or re-delegating grants, or any root control), and may never narrow or
otherwise affect any grant but its own (no negative or cross-grant permissions). Such powers need a new
inception profile, which older readers already report as unknown for the whole identity.

`amend:true` permits **identity-wide**, cross-key, cross-grant replacement within the
specified content targets. It is not “amend only your own publication stream.” Issuer
UI must disclose and require acknowledgment of this breadth, especially with
`any_content:true`. `amend:false` prevents explicit supersession, but another new claim
may still conflict with the principal's other claims. No implicit expiry, renewal,
sequence budget, same-grant-only amendment right, or timestamp-based scope is provided.

Root vocabulary on the pinned I lineage is closed for authority evaluation:

* Inception, grants and cuts are administrative. Recognized grants accumulate across
  root forks; grants do not form a mutable last-writer-wins controller state.
* Valid raw **`rc/1`** `revoke_key` or `rotate_key` in I's lineage is terminal for the
  entire identity, irrespective of reason, `last_good`, successor, or branch, and
  irrespective of defects in its own ancestry or merges: placement on I's lineage is
  decided by its `prev` chain alone. (Otherwise one malformed line planted by whoever
  holds the root key could void the owner's fork-clearing revoke.) All
  passing identity authority stops, including historical uses. No successor inherits I.
  To close workers while keeping accepted history, cut grants instead of revoking R.
* Fully understood raw `describes` and `anchors` are inert for administration. They
  do not modify grants; anchors remain subject to their ordinary time/coverage rules.
* Any other root operation on I's lineage is unsupported authority-bearing state,
  not silently inert. Relevant unresolved/unsupported root state yields unknown.
  Root events on a proved rival inception do not retire I. Unknown lineage relationship
  is reported as unknown, not mistaken for a rival that can safely be ignored.

A cut on I's lineage is addressed by its `grant`. A cut that names a grant of I under
another `identity` is an invalid cut addressed to that grant: it denies the grant and is
reported, never treated as a cut for some other identity.

Malformed or mismatched purported administrative statements grant no authority. An
issuer-authenticated potentially relevant control event that cannot be evaluated
must remain a named uncertainty; exact invalid targets/reasons must be reported.
No rule proves that entirely unseen root events do not exist.

## 4. Explicit consent, lineage and grant-history cuts

A statement with actor I/G must be cryptographically verified, fully understood and
chained to the exact delegate inception D in G, signed by its K. G must be issued by
I's fixed R in I's root lineage and cover the registered kind/target. Issuing G alone
does not attribute past bare-key statements to I. A key with grants from I and J must
choose one for each signature; membership caches never choose an actor.

For each valid cut of G, define its allowed set:

* `last_good:null`: the empty set;
* `last_good:L`: L and all its ancestors through **both** `prev` and `merges`, after
  establishing that L is a real line in the pinned K/D lineage. L need not itself
  carry G; it selects a key-log prefix, whose individual counted statements must
  independently carry and qualify under G.

A missing L is unknown. A known wrong-key/wrong-lineage L is an invalid cut, not an
empty or unlimited cutoff substituted by a guess. A relevant authenticated but
unevaluable/invalid control must not disappear from a supposedly clean pass for G.
A purported outsider cut is not authority merely because it spells I/G; the trusted
issuer/lineage relevance boundary still applies.

For all held valid cuts, use **intersection**, not the newest cut, largest sequence,
latest timestamp, arrival order, or union. L is inclusive. Siblings outside its ancestry
and descendants after it are excluded. A later wider cut or root merge never reopens G.
A new grant G2 cannot relabel bytes signed under G1. All conflicts and uncertainties
remain in the explanation. Cut monotonicity holds only while grants/root state and
other evidence are fixed; it is not a global theorem about adding arbitrary evidence.

### 4.1 Deliberate worker self-revocation exception

For opted-in I/G statements, R controls grant-history authority. K's raw rotate/revoke
signals **do not erase or close G**. The signals remain visible as warnings, and retain
their unchanged effects on bare-key uses. Before a root cut is known, an otherwise
valid G may still authorize K after a visible self-revoke. Operators must publish a
root cut to shut it off; an emergency self-revoke UI must not claim otherwise.

The reader must separate cryptographic verification, complete linkage, understanding,
bare-key eligibility and actor eligibility. It must not discard identity evidence by
first running a global bare-key revocation filter. A stricter local admission refusal
can be disclosed but cannot rewrite protocol history. This exception affects neither
other identities that use K nor K's raw historical uses.

A root cut cannot repair a bad signature, detached lineage, unknown semantics, wrong
scope or invalid time proof. Original time evidence is still required. Anchors remain
key-local; R's cut/anchor does not create an earlier timestamp for K. If a required
anchor is cut or ineligible, authority may survive while time quality does not.

## 5. Claims, authorized uncertainty and operation-specific authority

### 5.1 Amendments

Identity `authored`/`observed` claims group only by the explicit I, not possible grant
membership. Amendments name a nonempty, sorted, duplicate-free
`body.x_identity_v1.amends:[S,…]`. Each exact target must be held, eligible for the same
I, have the same content digest and appropriate claim kind. The new grant must permit
amendment of that content. Replacement is of the complete claim fields, not a patch.
Same-key ancestry alone does not amend an identity-context claim. Bare-key amendment
rules do not change.

Maximal eligible nodes in this explicit DAG are candidate current claims. Concurrent
cross-key amendments remain concurrent/contested; no cross-key sequence, arrival-time,
or timestamp tiebreak is permitted. An eligible amendment naming both can reconcile
branches. Priority can follow eligible explicit amendment ancestry and original
verified bounds; it cannot borrow an unrelated early claim's bound merely because I
is the same. Content changes use existing artifact-lineage relations, not amendments.

A resolved current view also requires absence of **known authorized unresolved
mutations of that subject**. If B has issuer-authenticated authority to amend A's
content and names eligible A plus missing X, do not discard B and advertise A as
cleanly current. Current/principal-following selection becomes unknown; an exact pin
to individually eligible A may still select A.

Conversely, an outsider's self-signed I header with an invented/missing G must not stall
I globally. First establish issuer-authenticated binding of this signer, kind and
subject scope before propagating its uncertainty. Unsupported/unproven affiliation
remains unresolved for that candidate only. Later real grant delivery can change the
answer; this is not a completeness assertion. The same relevance boundary applies to
unresolved resource predecessors/approvals and task decisions. A cut authenticated by
the pinned root qualifies even when its prefix dependency is missing. Definite denials
are reported alongside unknowns and never hidden by them.

### 5.2 Resources

Count distinct **effective subjects** (`key(K)` or `identity(I)`), not raw key strings
or cached memberships. Two delegates for I fill one I slot. An identity approval with
missing authority fills no key slot, even if K is also a listed key controller. A
separate valid raw-key signature may fill that key slot. An I signature requires a
grant for the exact resource and operation; a root's raw signature is not sufficient.

Shared body bytes, predecessor authority and the resource merge DAG remain required.
Identity cuts that remove necessary approvals propagate contested/unresolved status
to affected editions and dependants; no silent fallback to a previously convenient tip.

Approval withdrawal/reapproval is **key-and-grant-local** (raw-key context has no grant).
Use existing same-key ordering; one delegate cannot withdraw another delegate's
approval merely because they both act for I. A new grant also does not let the same
key cancel an approval made under a different G. Principal-wide withdrawal and
cross-key withdrawal ordering are not implemented by this profile.

### 5.3 Task roles and lifecycle

Each `rc/2` task-contract edition carries a complete `task_roles` object inside the
shared `body.x_identity_v1`:

* `beneficiary`: one typed key/identity subject;
* exactly one of nonempty `eligible_issuers:[subject,…]` and `any_issuer:true`;
* `counting_unit`: explicitly `key` or `identity`.

These roles differ from resource controllers and grant permissions. The role object
is in the edition id. Any edition carrying `contents.contract` requires this object;
the reverse requires a contract. Non-task resources cannot use it semantically.
`contents.contract.profile` identifies an independently recognized contract profile.
Its top-level `beneficiary`, `eligible_issuers`, `any_issuer` and `counting_unit` fields
are **forbidden**, not silently overridden by the extension. A recognized contract
profile must not provide hidden alternate role/counting declarations elsewhere either.
Unknown contract profiles never produce passing readiness/settlement.

**Explicit remaining contract gap:** the baseline types `contents.contract` as an
arbitrary object; it does not freeze a complete task-contract grammar. This candidate
pins the role representation and forbids direct duplicate declarations, but does not
invent a universal mapping for third-party/nested legacy contracts. Task integration
must register a concrete contract profile, its requirements/evidence grammar and
legacy alias rejection. The schema's `example-unimplemented-contract-v1` example is
structurally illustrative and cannot settle a task. No legacy task contract is
implicitly upgraded or assigned new roles by this candidate.

| Operation | Additional role/continuity rule |
|---|---|
| `intent` | Participant is exactly its actor. Statement id identifies an advisory attempt, not a lock/quorum reservation. |
| `progress`, `withdraw` | Mandatory `body.x_identity_v1.intent` exact statement pin; same pinned task edition and same actor as that intent. K2 for I can continue K1-for-I, not a bare K1 attempt. Each operation needs its own task-scoped grant if acting for I. |
| `submit` | Retain signed evidence independently of readiness. Count only after actor eligibility, eligible issuer restriction, evidence/method and independence checks. Intent is not a prerequisite. |
| `decide` | Actor must equal the pinned task edition's beneficiary and, if identity-context, hold a `decide` grant for that task. Grant or resource controller status alone is insufficient. |

A withdrawn attempt cannot be reopened by reordered or later progress. New intent
means a new attempt. Cross-key decisions by the same I use the existing explicit
`body.supersedes` statement id; targets must have the same task edition and beneficiary.
Conflicting unsuperseded decisions remain contested; authorized unknown decisions
prevent clean settlement. No implicit cross-key ordering.

Identity counting deduplicates eligible explicit I values. Bare submissions do not turn
into identity votes. Key counting deduplicates actual K values **after** actor authority
passes; it never bypasses a missing G. Counting principals does not establish human or
experimental independence. Existing `rc/1` tasks retain their legacy defaults; received
evidence never changes their counting unit.

## 6. Local reader policy and exact pins

`fixed-root-identity-policy.schema.json` is a linked **candidate local policy**, not a
received statement. It requires `version:"reader-policy-v1"`, `selections` and `trust`
(arrays may be empty, each at most 256 entries). Canonical bytes are at most 65,536.
Its digest is `sha256:` plus SHA-256(JCS(entire policy)); the version participates.
Received objects do not install or modify it, even when signed by an identity root.

Each selection has `subject:{content:digest,role:token}` and exactly one of
`statement:S` or `principal:{key:K}` / `principal:{identity:I}`. Allowed role tokens:

| Role | Declaration eligible to supply it |
|---|---|
| `authorship-declaration` | `authored` of that exact content digest |
| `workflow-declaration` | `authored` of that digest with `type:"workflow"` |
| `observation-declaration` | `observed` of that exact digest |

An exact pin selects **that exact eligible statement**, not an edition alias, content
alias, successor, amendment or latest-by-key. Missing or ineligible S remains exact
and non-passing; never substitute another statement. Principal selection follows only
the named principal's eligible resolved current claims and cannot choose among
conflicts by arrival order. A selected workflow can change a recomputed derived
result/grade because the declaration changed; it cannot fabricate execution/evidence.

Each trust entry has one typed `principal`, a sorted nonempty set of `purposes` from
`attestation`, `corroboration`, `admission`, and explicit content `targets` (the same
content target union as grants). A purpose matches only itself. Targets apply to the
content being judged, not an incidental digest; unresolved target references remain
unknown. Trust admits otherwise eligible evidence for the named purpose, not signature
validity, authorship, independent-person status, successful reproduction or time quality.
No configured trust means unconfigured/not trusted where trust is required, not universal
trust. No local arbitrary speaks-for grammar or automatic old-to-new-I trust transfer.

Selections/trust entries sort by JCS text as above; `purposes` and explicit contents
sort as string sets. Duplicate/conflicting selections for the **same content/role**
are errors even if their statements/principals differ. Unknown tokens, duplicate
selectors or malformed policy fail before evaluation (production exit 2). Identical
trust entries are refused; overlapping positive entries are additive only within the
explicit purpose/target intersection. Separate explicit pins and trust never authorize
a missing/denied actor or silently turn one authority into another.

The policy syntax is concrete. A production selector/trust evaluator, admission UI,
policy diff review and task contract integration are still required. Stricter admission
may withhold a local passing view, but cannot rewrite transported signed evidence.

## 7. Evaluation contract, limits and transport

A future pure resolver consumes an immutable evidence snapshot and explicit policy;
no implicit network fetches. For S: verify/understand/chain; resolve actor once; validate
I/G/R/K/D and scope; collect **all held relevant** cuts/root controls and dependencies;
apply cut intersections; then operation-specific authority, policy, evidence and time
checks. A signature is necessary but not sufficient.

Return structured evidence: `status` (`eligible`, `denied`, `unknown`, or consuming
surface `contested`), signer, actor, grant, basis/missing ids, reasons, root lineage,
relevant cuts, raw-key status, policy digest, evaluator/profile version and evidence
snapshot digest. Report definite failures as well as simultaneous uncertainty.
Core freshness is always `not_established`; a named external freshness policy must be
separately implemented before any stronger claim. Offline inclusion is not non-omission.

Transport uses the existing statements/blobs store. Include I, G, root/delegate
ancestry, held relevant cuts, amendment/predecessor targets and time proofs; request
missing ids only via configured transport outside resolution. Rebuildable indexes
must not define authority or erase retained cuts. Duplication/reordering must preserve
results for the **same** evidence and policy.

Candidate syntax caps: permissions 64; explicit targets, subjects, amendment targets,
predecessors and merges 256 each; the inherited JSON depth/PAE limits above. A future
reader additionally uses evaluation caps of 100,000 distinct statement dependencies,
100,000 ancestry edges on one path, and 1,000,000 dependency/edge inspections per
query. Account work deterministically; on a cap, return unknown/non-passing and the cap,
not a partial grant/prefix. These evaluation caps are a proposal, **not enforced by the
syntax-only harness**; model/production integration must agree on accounting.

**Evidence digest integration gap:** the production evidence snapshot serialization
must be pinned before claiming cache/replay equivalence across implementations. It
must cover the canonical retained statement bytes (not merely unverified claimed ids),
relevant blob availability/verified bytes, and retained unresolved authenticated control
inputs; policy/evaluator digests are separately named. This artifact intentionally does
not pretend an id-only list proves equal evidence. No such production digest is enabled.

Production verify exits retain their existing meanings: 0 for the requested operation
checked/passed; 1 only for a completed disagreeing comparison; 2 for invalid invocation/
local policy before work; 3 for missing/unknown/unsupported/contested/limit outcomes;
5 for environment mismatch. The Go test utility below is **not** that production verify
command and uses ordinary test success/failure exits.

## 8. Root-signing ceremony and compatibility targets

Custody is not a protocol validity rule. The root is administratively distinct from
workers, but need not be physically offline. Local/offline signing, external wallets/
hardware and optional user-operated services may emit the same supported signatures.
No Commons-operated service, online root, seed import, or arbitrary-data signing oracle
is required or justified.

Prepare a canonical **unsigned administrative envelope** only after resolving its exact
I/G/D/L references and ordinary root `prev`/`merges`. An external-signing package must
carry that envelope and the **exact PAE bytes** (binary or losslessly encoded), with
algorithm, displayed signer and proposed statement id. Recompute PAE/id locally;
never accept a display summary as the signed payload. Review human-readable identity,
worker key/inception, permission breadth or cut prefix and irreversibility. Sign using
only the designated Ed25519/EIP-191 profile; locally verify the returned signature
against the unchanged prepared bytes/key; append durably only after verification and
root-log concurrency checks. Rejection, disconnect, cancellation and stale preparation
must leave no falsely appended operation. This specifies invariants, not a shipped
connector or a finalized external-package interchange schema.

Ledger Nano X, Flex and Stax are **untested targets** for Ethereum-account EIP-191 via
an explicitly tested connector. Test firmware/app/connector, exact payload fidelity,
size limits, display readability and rejection/disconnect separately per model.
YubiKey 5 is an **untested family**: exact variant/firmware and interface matter;
Ed25519 PIV support must be established, not inferred from the family name (5.7+
capability is not every YubiKey 5). WebAuthn assertions or OpenPGP packets do not replace
the required raw proof. MetaMask EOA testing must use synthetic/test accounts. Unsupported
signing must fail, not silently change algorithm/preimage. A valid signature does not
prove safe informed approval or custody quality. GitHub can transport unsigned packages
and logs without holding a root; a secret-bearing workflow is optional, user-owned,
lower-assurance deployment work, not the default or a tested service.

## 9. Schemas, vectors and reproducible checks

Files in this candidate:

* `fixed-root-identity.schema.json`: JSON Schema 2020-12 for the candidate's 20 kinds,
  typed subjects, permissions and role/actor extensions. Root schema requires `sig`;
  `#/$defs/draft` is explicitly unsigned. The schema is standalone, with only local
  references. Sorting, cross-field thresholds, canonical time and crypto are additional
  specified checks, not capabilities attributed to ordinary JSON Schema validators.
* `fixed-root-identity-policy.schema.json`: standalone local policy syntax; same-subject
  selection conflicts and set sorting require the additional checks.
* `fixed-root-identity.vectors.json`: **82 unsigned schema vectors**, including all
  candidate kinds, forbidden `rc/2` key events, actor/marker combinations, typed mixed
  controllers, scope modes, tasks, policy and negatives. Example ids are SHA-256 of
  labels, not actual referents; example signer strings are not proven public keys.
  `accept:true` means syntax/local constraints only, **never valid signed wire or
  eligible authority**. The task contract example is explicitly unimplemented.
* `fixed-root-identity.coverage.json`: all 45 provisional scenario handles, vector/test
  links and exact remaining model/integration obligations. A linked shape check does
  not mean the scenario is covered. These are not C-core claims or registered ids.
* `internal/wire/fixed_root_identity_profile_test.go`: isolated candidate validation,
  restricted local JSON Schema interpreter and real synthetic Ed25519/EIP-191 tests.
  It reuses the existing JCS, PAE, signature verifier, time and base-schema functions.
  New typed controller shapes are checked explicitly; unchanged base fields are checked
  independently, so critical-marker recognition cannot bypass them. No production
  registry, reader, writer or global major is changed.
* `internal/keylog/fixed_root_identity_profile_test.go`: actual old-reader mixed-log
  behavior, without claiming whole-resolver mixed-resource safety.
* `internal/identity` (with `internal/identitymodel`): the candidate admission adapter
  from signed bytes to model facts, its contract in the package README, and the signed
  slice and review-regression tests that the coverage file links as partial evidence.

Run from the repository:

```sh
scripts/validate-fixed-root-identity.sh
# A real signed rc/2 envelope: syntax + cryptography, NOT grant/history eligibility.
scripts/validate-fixed-root-identity.sh --statement /path/to/candidate.json
# Local policy syntax/conflicts only, NOT trust installation or evaluation.
scripts/validate-fixed-root-identity.sh --policy /path/to/policy.json
```

The test-only schema interpreter parses schemas and vectors through the same strict
`canon` parser, handles only the keywords used here, rejects unknown executable
keywords, and never fetches external schema references. It is not a general
JSON Schema implementation. No new third-party dependency is introduced. Runtime
synthetic keys use public test constants; they must never be used operationally. Tests
bind actor tampering and v1/v2 domain changes to signature failure, assert one shared
edition id across raw/different-actor approvals, exercise both signature profiles, and
reject canonicalization/criticality violations. Canonical whitespace/member-order permutations are accepted and
normalize to the same bytes. UTF-16 sorting is explicitly tested. Required-field
removal is tested across every reused base kind admitted by the candidate; each
correctly re-signed malformed body is rejected despite the recognized marker.

### Completion boundary

This candidate is useful input to an authority model and wire integration, not a
claim that all 45 semantic scenarios pass. Still required: independent review of this
major transition/domain choice; unsupported-input hardening; dual-major authenticated
reader and critical registry; typed snapshot binding to the pure model; all claim,
resource, time and task consumers; concrete task-contract profile; policy evaluation;
transport/explanations and snapshot digest; deterministic evaluation caps; differential
and full end-to-end signed authority tests; detached signing packages/connectors and
custody/hardware usability drills. No writer enablement, release, deployment, live keys
or devices are implied by these artifacts.
