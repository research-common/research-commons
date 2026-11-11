# Candidate profile: fixed-root identity

**Status: review candidate; not enabled in the production reader or writer.**
This document selects one wire proposal, `fixed-root-v1` on **`rc/2`**, rather than
changing `rc/1` fields through a critical-extension handler. It does not change
`wire.Major`, the current release version, old design notes, or any existing conformance
case; its own cases (§10) form a separate profile table.
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

**Root compromise is total and retroactive.** A raw `revoke_key` or `rotate_key` on I's
lineage (§3) ends every passing use of I, including every identity act signed before it;
`last_good` is not read. This is deliberate. A worker's hard revocation can keep a
prefix (claims-model note §4.1) because the root that issued the grant stays trusted
and can say which lines were the worker's. Nothing stands above R to say when R was
taken: the time of a root compromise cannot be established from the log, and a thief
holding R can sign grants, cuts and forks that look exactly like the owner's, on any
branch and with any timestamp. A prefix-preserving root revoke would trust R's own
statement about where the compromise began, which is the statement a compromise makes
worthless. The delegates' bytes survive as bare-key statements; nothing "as I" passes.
Recovery is a new identity plus resources that list a second controller subject
(§8). Issuer tools must say this before an inception is signed.

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

A dual-major reader never upgrades identity actor/marker use in `rc/1`: an `rc/1`
`x_actor_v1` is not read (the line is evaluated as a bare-key line and grants nothing
as an identity), and an `rc/1` `crit` naming `x_identity_v1` makes the line
unsupported, since this reader registers no `rc/1` extension. Unextended `rc/1` remains unchanged. There is
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
  Because the major is inside both the type and the payload, a line whose `rc` was
  relabelled after signing (either direction) fails signature verification before
  any body rule is read; no reader rule on `crit` or the actor is needed to refuse it.
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
| `rc/2`, understood marker, no actor | `key(K)` on an identity-aware body; may fill only a key slot. It carries no `amends` (that requires an actor). An `authored`/`observed` of this shape is a `key(K)` claim and follows bare-key amendment rules unchanged: it amends the same key's earlier claim of the same digest (either major) through same-key ancestry, exactly as `rc/1` does, because the subject is `key(K)` under both majors and one key never contests itself. |
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

**Mixed-reader safety (formerly the integration blocker):** wire/keylog compatibility
is not by itself whole-reader safety: `rc/2` bodies are absent in the old parsed
representation, and a view that inspected an unsupported body before its evaluation
guard could fail. Every resolver view is now exercised on the signed candidate lines
(both chains, `rc/2` resource and task kinds with identity controllers,
authenticated-invalid and tampered lines) through the unchanged reader and through the
candidate dual-major reader, in sampled delivery orders, with and without an actor
evaluator: no view panics, and every `rc/2` line stays unverified and undecoded under the
unchanged reader. This is a test result over those corpora, not a proof for every
possible input. Also, a malicious signer can create nonconforming `rc/1` bytes with an
unmarked envelope actor that an old reader ignores; this proposal does not
retroactively repair old readers. No conforming candidate writer emits that combination.

**Dual-major reader (candidate, opt-in).** A reader that understands this profile
dispatches each line by its `rc` major and nothing else. `rc/1` goes through the
unchanged `rc/1` reader: the same refusals, statuses and ids; an `rc/1` envelope actor
is not read, and an `rc/1` `crit` naming the identity marker is unsupported. `rc/2` goes
through the candidate reader (verify first; marker and actor read; a verified line that
breaks a candidate rule is held as invalid). Any other major stays an unknown major.
Under it, a corpus of `rc/1` statements only gives the same ids, statuses and every
resolver answer as the unchanged reader (C-id-01). An `rc/2` line carrying an actor is
never its signing key's evidence: with no actor evaluator it counts toward nothing and
reads `unknown (identity profile not active)`; an evaluator that binds it to no identity
leaves it uncounted as well (§2.3, "never a key fallback"). An `rc/2` line with the
marker and no actor is a `key(K)` statement and keeps the bare-key gate. The `rc/2`
resource kinds (genesis, edition, withdraw_approval) and task kinds (intent, progress,
withdraw, submit, decide) are read: a task edition's roles come from its `task_roles`,
and task statements count through the actor evaluator as every other identity-context
statement does (§5.3). An `rc/2` kind the reader does not implement stays verified and
unsupported and counts toward nothing. Nothing in a production reader uses this dispatch
yet.

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
| `authored`, `observed` | `body.content.digest` | `{any_content:true}` or `{contents:[digest,…]}` | `amend:true`, `amend:false` or `amend:"own"` |
| `holds` | `body.content.digest` | Same content choices | None |
| `reproduced`, `corroborates`, `refutes`, `retracts` | `body.of` | `{any_statement:true}` or `{statements:[id,…]}` | None |
| `edition`, `withdraw_approval` | `body.resource` | `{resources:[id,…]}` only | None |
| `intent`, `withdraw`, `progress`, `submit`, `decide` | `body.task` | `{tasks:[id,…]}` only | None |
| `anchors` | Signer's own key log | No `targets` field | None |

No resource/task wildcard, administrative grant, root control, or key-event delegation
is admitted. `describes` and genesis remain raw-key statements. A permission for one
kind does not authorize another. A target mentioned incidentally elsewhere in a body
does not satisfy scope. A permission has three extension points a later version of this
profile may use: a new `kind`, a new target mode (a token key of `targets`), and a new
`amend` mode (a token in place of the boolean; `fixed-root-v1` defines one, `own`, below). Each
unknown one makes the grant unsupported and non-passing, not broader. Shapes that are malformed rather than new stay invalid: a
missing `amend` (absence is not a mode), a value that is neither a boolean nor a token,
two target modes, a known mode on the wrong kind, and `any_resource` / `any_task`, which
this profile excludes for good. The schema describes `fixed-root-v1` itself (including
`amend:"own"`) and rejects all three extensions; the reader's unsupported reading is what lets a later version add
one without older readers denying acts they cannot judge. That uncertainty is confined to the one grant: grants only
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
`amend:"own"` is the narrower mode, so a capture agent can correct its own records without
being able to rewrite everything the identity signed. **An act by K for I under a grant
carrying `amend:"own"` may name a target S only if: S's actor identity is I, and S was
signed by K (the exact key; a rotated successor needs its own grant and doesn't inherit);
every §5.1 condition holds: S is held and eligible for I, has the same content digest and
claim kind, and the amending grant's content targets cover S. Which of I's grants carried S
doesn't matter.** A target signed by another key, naming another identity (or none), or
itself not eligible for I (for example outside a cut's `last_good` prefix) is a scope denial
of the act; the target's eligibility is evaluated inside the act's evaluation, under the same
caps (§7). A target the reader does not hold, or whose eligibility is undecided, leaves the
act unknown (§5.1, missing target). A grant entry without `amends` under `amend:"own"` publishes exactly as under
`amend:false`. Where another entry of the same grant carries `amend:true` for the content,
that entry authorizes the act and the targets' signers do not matter. `amend:"own"` is a
leaf under the invariant above. Any other `amend` token is a later version's: this reader
reads a grant with one as unsupported, acts under it read unknown, and the identity's other
grants are unaffected. Issuers who want a later mode to degrade that way should put it on
its own grant, beside an ordinary `amend:false` grant for everyday acts.

Root vocabulary on the pinned I lineage is closed for authority evaluation:

* Inception, grants and cuts are administrative. Recognized grants accumulate across
  root forks; grants do not form a mutable last-writer-wins controller state.
* Valid raw **`rc/1`** `revoke_key` or `rotate_key` in I's lineage is terminal for the
  entire identity, irrespective of reason, `last_good`, successor, or branch, and
  irrespective of defects in its own ancestry or merges: placement on I's lineage is
  decided by its `prev` chain alone. (Otherwise one malformed line planted by whoever
  holds the root key could void the owner's fork-clearing revoke.) All
  passing identity authority stops, including historical uses (why: §1). No successor
  inherits I.
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
A cut applies wherever it sits on I's root lineage; it need not descend from the grant
it names (this is what lets a cut clear a root fork).

### 4.1 Deliberate worker self-revocation exception

For opted-in I/G statements, R controls grant-history authority. K's raw rotate/revoke
signals **do not erase or close G**. The signals remain visible as warnings, and retain
their unchanged effects on bare-key uses. Before a root cut is known, an otherwise
valid G may still authorize K after a visible self-revoke. Operators must publish a
root cut to shut it off; an emergency self-revoke UI must not claim otherwise.
Requirements on consumers: every view of a delegate K shows two axes side by side,
bare-key status ("self-revoked; bare-key lines after X do not count") and per-grant
status ("G from I: open / cut at L / cut null / unknown"); an identity act under an open
G after a visible self-revoke is never shown as a clean `eligible` (the
`delegate_self_event` warning travels with it); and a self-revoke command prints, by id,
every grant it does not close.

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
rules do not change (§2.3: an `rc/2` marker-only claim is a bare-key claim). An amendment
naming a target that is not one of I's claims of the same kind on the same blob (another
principal, another blob, another kind, or a claim not eligible for I) applies to nothing,
and the amending statement is not itself a claim of I. Under `amend:"own"` (§3) a target
must also be signed by the acting key.

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
remains unresolved for that candidate only. Binding means an authenticated grant,
signed by I's pinned root key, that names I and this signer as delegate. A bound actor's
denial or uncertainty is I's to report; an unbound actor's is the candidate's alone. Scope
is evaluated after binding and does not unbind. Later real grant delivery can change the
answer; this is not a completeness assertion. The same relevance boundary applies to
unresolved resource predecessors/approvals and task decisions. A cut authenticated by
the pinned root is relevant even when its prefix dependency is missing, and reads unknown
(§4: a missing L is unknown); its uncertainty propagates to the grant it names. Definite denials
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
cross-key withdrawal ordering are not implemented by this profile. Because withdrawal is
key-and-grant-local, a `withdraw_approval` permission is usable only by a delegate whose
same grant also carries `edition` for that resource (the approval it withdraws).

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
implicitly upgraded or assigned new roles by this candidate. In particular, a contract
whose `eligible_issuers` lists keys does not make identity counting read "any identity a
listed key acts for": until a contract profile types its subjects, identity counting under
it is `unknown`, naming the missing profile.

| Operation | Additional role/continuity rule |
|---|---|
| `intent` | Participant is exactly its actor. Statement id identifies an advisory attempt, not a lock/quorum reservation. |
| `progress`, `withdraw` | Mandatory `body.x_identity_v1.intent` exact statement pin; same pinned task edition and same actor as that intent. K2 for I can continue K1-for-I, not a bare K1 attempt. Each operation needs its own task-scoped grant if acting for I. |
| `submit` | Retain signed evidence independently of readiness. Count only after actor eligibility, eligible issuer restriction, evidence/method and independence checks. Intent is not a prerequisite. |
| `decide` | Actor must equal the pinned task edition's beneficiary and, if identity-context, hold a `decide` grant for that task. Grant or resource controller status alone is insufficient. |

A withdrawn attempt cannot be reopened by reordered or later progress. New intent
means a new attempt. Cross-key decisions by the same I use the existing explicit
`body.supersedes` statement id; targets must have the same task edition and beneficiary.
This needs only the `decide` grant for the task, not `amend:true`: `decide` is already
restricted to the beneficiary, so a delegate's decision superseding another delegate's is
within the authority the `decide` grant discloses.
Conflicting unsuperseded decisions remain contested; authorized unknown decisions
prevent clean settlement. No implicit cross-key ordering.

Identity counting deduplicates eligible explicit I values. Bare submissions do not turn
into identity votes. Key counting deduplicates actual K values **after** actor authority
passes; it never bypasses a missing G. Under key counting, a raw submission by K and an
identity submission by K for I count once: the unit is the key, whatever subject it acted
for (§2.3 treats them as two subjects for authority, not for counting). Counting principals does not establish human or
experimental independence. Existing `rc/1` tasks retain their legacy defaults; received
evidence never changes their counting unit.

## 6. Local reader policy and exact pins

The production reader already loads `reader-policy-v1` with key principals only; its user-facing
specification is `docs/READER-POLICY.md` (provisional). This section stays the candidate profile's text,
including what an `{identity: I}` principal would mean once the profile is active.
`{identity: I}` principals need **no new `reader-policy` version** (decided 2026-11-08).
`reader-policy-v1` already parses them and fixes their meaning: "statements eligible to act
for I". What changes when the profile is activated is the reader's actor evaluator, not the
policy. So an answer that consulted the evaluator cites it (evaluator version, and the
evidence digest and receipt it answered from) beside the policy digest, and two readers with
the same policy and different evaluators or evidence can be told apart. §2.1 is different:
there a received statement's type changes, so the same received bytes would change meaning
and a major is bumped. A local policy's text means the same in both readers.

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
unknown. (Production reader: a statement whose content is reached through `of`, or a
`describes` of a statement, is judged by the referenced statement's content, one hop; an
unheld reference reads `unknown (target reference not resolved)` whenever a `contents`
entry for the purpose could match, never trusted and never not trusted.) Trust admits otherwise eligible evidence for the named purpose, not signature
validity, authorship, independent-person status, successful reproduction or time quality.
Trust is configured per purpose. A purpose that no trust entry names is unconfigured:
the reader keeps its documented default for it (for corroboration, every counted
statement is counted) and labels the answer "not configured", never as trust. Once any
entry names a principal for a purpose, only the listed principals are trusted for it;
no configured trust is then not trusted, never universal trust. The admission floor
follows the same rule. No local arbitrary speaks-for grammar or automatic old-to-new-I trust transfer.

Selections/trust entries sort by JCS text as above; `purposes` and explicit contents
sort as string sets. Duplicate/conflicting selections for the **same content/role**
are errors even if their statements/principals differ. Unknown tokens, duplicate
selectors or malformed policy fail before evaluation (production exit 2). Identical
trust entries are refused; overlapping positive entries are additive only within the
explicit purpose/target intersection. Separate explicit pins and trust never authorize
a missing/denied actor or silently turn one authority into another.

Requirements on consumers: every consumer of trust asks one question of a **statement**, not of
its signing key: "is this statement trusted for this purpose over this content". A `{key: K}` entry
answers for the statement's signer. An `{identity: I}` entry answers only when actor evaluation
finds the statement eligible for I (not denied, not unknown), so a bare statement by a worker key
of I is never I's and a key entry never trusts an identity. An answer actor evaluation cannot
decide reads unknown and is not counted, never trusted by default. A reader without actor
evaluation answers unknown for every identity entry, as today. Counting follows the same
split (decided 2026-11-08). A statement the evaluator binds to an identity counts by evidence
readiness and actor eligibility. Its signer's bare-key status is shown beside it and is not
applied as a filter (§4.1), so a denied or undecided actor is not counted under any unit (§5.3).
A bare-key statement keeps the bare-key gate unchanged. This applies to corroboration, task
submissions and exact pins alike. Selections follow the same rule: an
`{identity: I}` selection follows only I's eligible claims, reads unknown while a claim that may be
I's is undecided, and substitutes no key's claims. The trust question itself does no authority
evaluation and no policy reading of its own: eligibility comes from the evaluator, trust from the
policy, and neither stands in for the other.

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
not a partial grant/prefix. A cap hit is `unknown` even when a denial was found before it
(a stopped walk has not shown its answer complete); the denial found is still listed
beside it, never hidden. The identity model enforces these three caps (injectable for
tests, defaulting to the numbers above); the syntax-only harness does not. Accounting,
identical for the same evidence and limits whatever the delivery order:

- **Dependency:** one distinct statement id the query reads, held or missing: the statement,
  its inception and grant, every node of every ancestry closure walked, each prev/merge link
  read for a sequence check, and each authenticated root-signer event examined. Counted once
  per query however often it is read.
- **Path edge:** the longest prev/merge path from a walked head to the end of its closure (a
  missing link is one edge), and the prev-only path a placement walk follows to an inception.
- **Inspection:** every fact read, link followed or memoized result reused; the total-work bound.
  Ancestry proofs are memoized per query, so a long linear history costs work linear in its length.

A cap yields `unknown` with a `model_limit` reason naming the cap (`dependencies`,
`path_edges`, `inspections`) and its value; definite denials established first stay denied.
Facts by other keys and unproven facts are never read (scans use per-signer indexes of
authenticated facts), so they cannot spend this identity's budget. The root's and the
delegate's own authenticated facts are read whether or not they turn out relevant: the
root scan reads every authenticated R fact as a dependency before deciding it is outside
I's lineage (a rival inception's events included), and the delegate scan inspects every
fact of K's log. Only R or K can author that load, so it is not third-party noise; it
fails closed (`model_limit`). On linear histories the dependency cap binds before the
inspection cap (measured: about 7.7 inspections per dependency at 6,000 root events plus a
5,000-edge delegate path); on merge-dense logs the
inspection cap can bind first.

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

**The simple path, which most volunteer hubs will take:** R is an ordinary `rc-key/0`
key file (`docs/KEY-FILES.md`) kept on a machine that does not run the hub's daily work,
and the CLI signs with it. No package, connector or hardware is involved. The custody
questions are a backup of that file and how quickly its holder can sign.

**Reachability, not only safety.** Closing a stolen delegate key needs a root cut, and a
prefix-preserving cut needs L known at cut time, so it cannot be pre-signed. The root
must therefore be reachable within the exposure window the hub tolerates. That, rather
than fear of compromise, is what pulls a root toward being kept warm.

**Hub resources should list a second controller subject.** If a resource's controllers
are `{identity: I}` alone, re-accepting it after a compromise of R is authorized by
"predecessor controllers" (§2.1), which then includes the thief. A second subject (a
second identity, or a key held apart) under a controller `rule` gives the resource layer
the threshold this profile does not have.

**Co-maintenance.** There are two honest patterns: shared custody of one root file (§1
treats a restored copy as the same root), or one identity per maintainer with every hub
resource listing both under a `rule`. The second gives co-maintenance at the resource
layer but not for grants: a delegate acts for exactly one I.

No custody drill has been run or recorded; C-id-40 stays pending until one is.

## 9. Schemas, vectors and reproducible checks

Files in this candidate:

* `fixed-root-identity.schema.json`: JSON Schema 2020-12 for the candidate's 20 kinds,
  typed subjects, permissions and role/actor extensions. Root schema requires `sig`;
  `#/$defs/draft` is explicitly unsigned. The schema is standalone, with only local
  references. Sorting, cross-field thresholds, canonical time and crypto are additional
  specified checks, not capabilities attributed to ordinary JSON Schema validators.
* `fixed-root-identity-policy.schema.json`: standalone local policy syntax; same-subject
  selection conflicts and set sorting require the additional checks.
* `fixed-root-identity.vectors.json`: **82 unsigned schema vectors** (the signed counterpart is below), including all
  candidate kinds, forbidden `rc/2` key events, actor/marker combinations, typed mixed
  controllers, scope modes, tasks, policy and negatives. Example ids are SHA-256 of
  labels, not actual referents; example signer strings are not proven public keys.
  `accept:true` means syntax/local constraints only, **never valid signed wire or
  eligible authority**. The task contract example is explicitly unimplemented.
* `fixed-root-identity.signed-vectors.json`: **signed rc/2 vectors for both required algorithms**
  (`ed25519`, `eip191-secp256k1`), in the style of the wire-format vectors. Four published test-only keys
  (root and worker per algorithm; the secret is `sha256` of a published label, so anyone can reproduce and
  nobody may use them operationally). Per algorithm, one log of each signer: the worker's `rc/1` genesis (the
  delegate inception D); the root's `identity_inception`, an `identity_grant` for the worker, two
  `identity_cut`s (`last_good` set and `null`), and the root's raw **`rc/1` `revoke_key`** after them (§2.1: raw key
  events stay `rc/1`; a root revoke is therefore not an `rc/2` positive); the worker's two `authored` acts
  under `x_actor_v1`, the second carrying `amends`. Each positive entry gives the payload type
  (`…<kind>.v2+json`), the JCS payload, the exact PAE signed string, its byte count, the statement id, the
  signature and the delivered line, plus the outcome the candidate reader must give (and the actor it must
  read). Negative entries are delivered lines derived from a positive by exactly the members named in
  `changed_members`: the actor changed or stripped after signing; a signature over the `.v1+json` preimage of an
  `rc/2` envelope; `rc/2`→`rc/1` and `rc/1`→`rc/2` relabels; (valid signatures, retained as given) an `rc/1`
  line carrying `x_actor_v1` (valid, actor not read), an `rc/1` line naming `x_identity_v1` in `crit`
  (unsupported), and an `rc/2` `revoke_key` (invalid, never an identity act); and, for Ed25519, three wire-format
  edge cases (`NE1`, `NE7`, `NE11`) and the identity-point forgery delivered as `rc/2` identity lines, each a bad
  signature at the pinned step. The vectors check **representation** (bytes, domain separation, ids,
  signatures, reader outcome), never authority. `internal/wire` regenerates the file from the labels and compares
  it byte for byte, runs every entry through the production `rc/2` reader and the unchanged `rc/1` reader, and
  `internal/sig` verifies every Ed25519 signature under two independent implementations (the pinned verifier and
  a standard-library reimplementation of the pinned rule) and re-signs each positive with the standard
  library's signer. `RC_REGENERATE_SIGNED_IDENTITY_VECTORS=1 go test -run TestSignedIdentityVectorsReproduce
  ./internal/wire` rewrites the file after a deliberate change.
* `fixed-root-identity.coverage.json`: the 45 scenario handles (ID-01 … ID-45), each with
  its registered case id (§10), vector/test links and the exact remaining model/integration
  obligations. A linked shape check does not mean the scenario is covered. The handles are
  registered conformance cases `C-id-01` … `C-id-45` (§10); the file's per-case status is
  checked against the harness by a test, so it cannot drift.
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
major transition/domain choice; wiring the candidate dual-major reader into a production
reader (pull, gates, views) and the critical registry (the reader itself, its `rc/1`
differential and resolver-wide mixed-input tests exist, §2.4); typed snapshot binding to the pure model; all claim,
resource, time and task consumers; concrete task-contract profile; policy evaluation;
transport/explanations and snapshot digest; deterministic evaluation caps; differential
and full end-to-end signed authority tests; detached signing packages/connectors and
custody/hardware usability drills. No writer enablement, release, deployment, live keys
or devices are implied by these artifacts.

## 10. Conformance cases

The 45 scenario handles of §9 are registered conformance cases, one to one: handle `ID-NN` is case `C-id-NN`.
The conformance harness reads them from this table, like the bitcoin-time profile's supplementary cases. They are
cases **of this candidate profile**: while the profile is not active (no writer, no resolver consumer, `wire.Major`
1) a case can be checked only at the layers that exist (the rc/2 reader, the admission adapter and the reference
model), so most are partial. A case is covered only when its whole required outcome is checked by a signed,
end-to-end test that does not depend on a consumer that does not exist yet. A schema vector is a shape check, not
a scenario.

| Id | Profile | Scenario | Required outcome |
|---|---|---|---|
| C-id-01 | §2.1, §2.4 (handle ID-01) | Ordinary bare-key corpus | A corpus of rc/1 bare-key statements only reads identically with and without the dual-major reader: same ids, statuses and every resolver answer. |
| C-id-02 | §3, §4 (handle ID-02) | I / D / G / opted-in statement | An rc/2 statement with actor I/G, signed by K, chained to D, in G's scope, with no cut: `eligible`, basis naming I, G, D and the root lineage. |
| C-id-03 | §3, §4 (handle ID-03) | Rival root/delegate inception | A rival seq-0 inception by R (or by K) is a different lineage: a grant on it, or a G pinning the wrong D, never authorizes; `denied` naming the lineage. |
| C-id-04 | §4 (handle ID-04) | Grant alone cannot attribute raw statements | Issuing G does not attribute K's earlier or later bare-key statements to I: those read `no_identity_actor` for identity, unchanged for bare-key use. |
| C-id-05 | §2.3, §3, §4 (handle ID-05) | Wrong signer / I / G / self-grant | Actor statement signed by a key other than G's delegate, a grant not signed by I's root, or a grant whose delegate is R: `denied` with the named reason. |
| C-id-06 | §4 (handle ID-06) | One key with grants for multiple identities | K holds grants from I and J: each statement acts for exactly the actor it names; a J statement never affects I's answers and vice versa. |
| C-id-07 | §3, §7 (handle ID-07) | Missing dependencies or unsupported root operation | Missing I, G, D or an ancestor, or an authenticated in-lineage root event outside the closed vocabulary: `unknown`, naming each missing or unsupported id; never `eligible`. |
| C-id-08 | §4, §5.1 (handle ID-08) | Known cut with missing ancestry or prefix | A held root cut for G whose last-good L or ancestry is missing: G's acts read `unknown` naming L; the cut is listed as relevant. |
| C-id-09 | §1, §4 (handle ID-09) | Stale bundle omits entire cut | A bundle that omits a cut entirely: acts read `eligible` relative to held evidence; freshness is `not_established`; no claim that no cut exists. |
| C-id-10 | §4.1 (handle ID-10) | Worker self-revoke / rotate | K's own rc/1 revoke/rotate does not close G: identity acts under G stay `eligible` with a `delegate_self_event` warning; K's bare-key status follows the legacy rules. |
| C-id-11 | §4 (handle ID-11) | Cut prefix excludes descendants/siblings | A cut at L keeps exactly L's inclusive prev+merges closure; descendants and siblings of L read `denied` (`cut_excluded`); other grants are unaffected. |
| C-id-12 | §4 (handle ID-12) | Multiple cuts / wider cuts / null cut | Several valid cuts of G intersect (never newest/widest/union); `last_good:null` excludes everything; a later wider cut never reopens G; result is permutation-invariant. |
| C-id-13 | §3, §4 (handle ID-13) | Malformed/unsupported relevant root cut | An authenticated root cut that is malformed, has a bad last-good, or names G under the wrong identity: denies G (never ignored); an unreadable grant on a cut makes every grant of I `unknown`. |
| C-id-14 | §4 (handle ID-14) | New grant cannot relabel old bytes | A new grant G2 cannot relabel bytes signed under G1: an act signed with actor G1 is judged under G1 only, and re-signing would be a new statement. |
| C-id-15 | §4, §7 (handle ID-15) | No cross-identity or raw-history interference | Adding evidence about another identity, or bare-key history of any key, never changes any answer for I. |
| C-id-16 | §3 (handle ID-16) | Independent root-fork grants coexist | Grants issued on two root forks of I both stand; a later root merge never un-cuts a cut grant. |
| C-id-17 | §3 (handle ID-17) | Root events in correct versus rival lineage | A valid rc/1 revoke/rotate placed on I's lineage by its prev chain retires I (`root_retired`) whatever its merges; the same event on a proved rival inception has no effect; unplaceable reads `unknown`. |
| C-id-18 | §1, §3 (handle ID-18) | Root lost but public evidence held | With the root's private key lost, held public evidence evaluates exactly as before; nothing depends on key availability. |
| C-id-19 | §3 (handle ID-19) | Closed permissions and exact targets | Permissions are closed: kind and target must match one complete entry; an incidental target, a merged pair of entries or an unknown kind never widens scope; an unknown kind affects its own grant only. |
| C-id-20 | §3, §5.1 (handle ID-20) | Publish without amend permission | A grant with `amend:false` lets K publish `authored` in scope but an act carrying `amends` reads `denied` (scope). |
| C-id-21 | §5.1 (handle ID-21) | Explicit cross-key concurrent amendments | Two eligible cross-key amendments of one claim with no amendment between them: the claim view is `contested`, both listed; no sequence, arrival or timestamp tiebreak. |
| C-id-22 | §5.1 (handle ID-22) | Wrong principal/content or missing amendment target | An amendment naming a target of another principal, another content digest, or a missing target: no amendment applies; missing target makes the current view `unknown`; wrong principal/content: the amending act is not a claim of I (under `amend:"own"`, a target not signed by the acting key or not I's is a scope denial of the act). |
| C-id-23 | §4, §4.1 (handle ID-23) | Cut preserves claim but loses anchor | A cut that excludes K's anchor but preserves the claim: claim authority survives; the time bound from that anchor is lost and reported separately. |
| C-id-24 | §2.2, §5.2 (handle ID-24) | Per-signature actors, one edition body | Approvals of one rc/2 edition by different signers with different actors share one edition id; each counts once for the subject its signature names. |
| C-id-25 | §5.2 (handle ID-25) | Two delegates of one I count once | Two delegates of I approving one edition fill one identity slot, not two. |
| C-id-26 | §5.2 (handle ID-26) | Missing identity authority is never root-key fallback | An identity approval with missing or invalid authority fills no slot (no key fallback); a root's raw signature does not fill an I slot. |
| C-id-27 | §2.3, §5.2 (handle ID-27) | Mixed raw/identity slots with same signer | One key's raw approval and its identity approval of the same body are two signatures for two subjects; neither fills both slots. |
| C-id-28 | §2.1, §5.2 (handle ID-28) | Complete typed controller changes and merges | A controller change must carry complete typed controllers and rule; partial, untyped or duplicate shapes are refused; merges need predecessor authority. |
| C-id-29 | §5.2 (handle ID-29) | Key-and-grant-local withdrawal / reapproval | Withdrawal/reapproval is key-and-grant-local: one delegate cannot withdraw another's approval; a new grant cannot cancel an approval made under another. |
| C-id-30 | §5.2 (handle ID-30) | Cut removes required resource approval | A cut that removes a required approval makes the edition and its dependants `contested`/unresolved; no fallback to an older tip without that token: the resource may name its last authorized edition only beside the contested list, and `verify` exits 3 (as C-core-143e for a key revocation). |
| C-id-31 | §6 (handle ID-31) | Exact pin versus principal-following selection | An exact pin selects that statement only (no alias/successor); a principal selection follows that principal's eligible current claims. |
| C-id-32 | §6 (handle ID-32) | Invalid/missing exact pin and policy conflicts | A missing or ineligible pinned statement is non-passing (never substituted); conflicting selections for the same content/role fail before evaluation (exit 2). |
| C-id-33 | §6 (handle ID-33) | Trust purpose boundaries / received policy injection | Trust applies only to the named purpose and targets; a received statement (even root-signed) never installs or changes local policy. |
| C-id-34 | §5.3 (handle ID-34) | Identity-counting quorum | Under `counting_unit: identity`, eligible submissions are deduplicated by I; unresolved actors are not counted and the answer names them. |
| C-id-35 | §5.3 (handle ID-35) | Key counting cannot bypass actor authority | Under `counting_unit: key`, an identity submission with missing or denied actor authority is not counted for its key. |
| C-id-36 | §2.4 (handle ID-36) | Old-reader compatibility | An unchanged rc/1 reader retains rc/2 lines unverified as unsupported, keeps key-local linkage and ids, and never panics or evaluates them in any view. |
| C-id-37 | §2.2, §2.3 (handle ID-37) | Tamper / marker / criticality / canonicalization | Any byte tamper, actor/marker without the other, unknown critical token, or non-canonical signed form: never `eligible`; never better than withholding the line. |
| C-id-38 | §7 (handle ID-38) | Cache / replay / permutation invariance | Duplicate, reordered or re-serialised delivery of the same evidence gives identical results, evidence digest and receipt; a cache/replay gives the same answer as a cold read. |
| C-id-39 | §7 (handle ID-39) | Deterministic resource caps | Every evaluation cap reached returns `unknown`/non-passing naming the cap (exit 3), never a partial grant or prefix. |
| C-id-40 | §8 (handle ID-40) | Root backup / compromised operational host | Root backup restore and a compromised operational host: a recorded drill (custody, not protocol). None is recorded yet (§8). |
| C-id-41 | §2.3 (handle ID-41) | Marker without actor / actor without marker | An actor without the body marker, or a marker without the critical declaration, is invalid even when correctly signed; never read as bare-key. |
| C-id-42 | §5.3 (handle ID-42) | Decide grant is not beneficiary role | A `decide` grant does not make K the beneficiary: `decide` by an actor that is not the pinned edition's beneficiary is `denied`. |
| C-id-43 | §5.3 (handle ID-43) | Cross-key exact-intent continuity | `progress`/`withdraw` by K2 for I continues K1-for-I's exact intent; a bare-key K1 intent is not continued; a withdrawn attempt cannot be reopened. |
| C-id-44 | §5.1 (handle ID-44) | Authorized unknown amendment versus outsider DoS | An issuer-authenticated amendment naming a missing target makes I's current view `unknown`; an outsider's unauthenticated I header with an invented G changes nothing. |
| C-id-45 | §3, §5.1 (handle ID-45) | Identity-wide amendment breadth | `amend:true` lets any delegate of I amend any of I's claims within the content targets, across keys and grants; outside the targets `denied`. |
