# internal/identity: the admission contract (candidate)

**Status: candidate, not activated.** This package binds the candidate fixed-root identity profile
(`docs/DESIGN-notes-fixed-root-identity.md`, "the profile") to the isolated reference model in
`internal/identitymodel` through one adapter, `Admit`. No writer, resolver consumer, CLI command or global
major uses it; `wire.Major` stays 1. Nothing here is frozen wire. The profile's §7 states the evaluation
contract a future resolver must meet; this file states what the adapter does today, section by section, so
a reviewer can check the code against it.

## 0. Shape

```
raw lines ──► wire.NewIdentityReader().Read   verify-first; rc/1 and candidate rc/2; keeps authenticated-invalid lines
          ──► identity.Admit                  dedupe, caps, receipt, Fact translation (the only Fact constructor)
          ──► identitymodel.Snapshot.Evaluate the reference semantics, unchanged
```

`wire.Read`, the zero `wire.Reader`, `keylog` and `resolve` are untouched: for every existing consumer an
rc/2 line stays an unknown major, retained unverified.

## 1. Two majors

- The identity reader verifies rc/1 exactly as the default reader does, and rc/2 under the candidate profile
  (payload type `.v2+json`). Any other major takes the existing linkage path: unverified, an `Unproven` fact.
- rc/1 bytes, ids and meaning are unchanged. An rc/1 envelope carrying `x_actor_v1` is **not** upgraded: it is
  a bare-key statement for identity purposes, so identity evaluation answers `no_identity_actor`.
- An unverified line (another major, an unknown `alg`) that no verified line vouches for is `Unproven`: it
  cannot be told from a forgery naming that signer, and affects nothing. A **vouched** one (§4) is
  `Authenticated` and `Unsupported`.

## 2. Edition ids

Not covered. rc/2 `genesis`, `edition`, `withdraw_approval` and the five task kinds read as verified but
`Unsupported` ("not implemented by this reader"), which is non-passing. Major-aware edition grouping is a
precondition for resource and task integration.

## 3. Authenticated invalid controls

- The identity reader checks the signature **before** the body schema. A signature failure is refused and
  never becomes a fact. A body, time, marker or actor failure under a good signature is `Status=Invalid`,
  `Verified=true`, retained. The default readers keep their old order and refuse.
- A bad-signature copy is refused at admission. The id excludes `sig`, so admitting a rejected-signature fact
  under a real line's id would let anyone shadow or poison a snapshot; the adapter therefore never produces
  `identitymodel.RejectedSignature`.
- Translation of authenticated-invalid lines:
  - `identity_inception`, `identity_grant`, `identity_cut` → `Validity=Invalid`, with the typed fields read
    best-effort (well-formed identity and grant ids are kept). In the model, an invalid cut addressed to grant
    G **denies** G; a cut with no readable grant is `unknown` for every grant of the identity; an actor naming
    an invalid grant is denied.
  - every other kind, including a malformed key event → `Validity=Unsupported`. In the root lineage that is
    `unknown`, never a silently ineffective warning: a root's malformed revocation must not leave the identity
    passing. Elsewhere it is linkage only. A line that carries an actor keeps it (`Data` event, operation
    `unevaluated`, `InvalidIdentityContext` or `UnsupportedIdentityContext`).
- rc/2 `rotate_key` / `revoke_key` are outside the profile: wire reads them `Invalid`, the adapter maps them
  to `Unsupported`, and the same `unknown` rule applies.
- Accepted consequence (fail-closed): a root's own invalid line that is an ancestor of a grant or cut makes that
  grant non-passing (`invalid_ancestry`). Only the root can do this to its own identity.
- **Terminal root events.** A valid, understood rc/1 `revoke_key` or `rotate_key` whose `prev` lineage reaches
  the identity's inception retires it (`root_retired`) whatever its merges or any invalid ancestor carry.
  Vocabulary is checked before ancestry: a root event outside the closed vocabulary is `unknown` whatever its
  ancestry, and an ancestry defect adds its own denial. A terminal event whose `prev` chain cannot be placed on
  the identity (a sequence gap) is non-passing, not `root_retired`.
- **Cuts are addressed by their grant.** A cut naming G under another identity is `wrong_cut_identity`: it
  denies G and is listed among the relevant cuts. A readable grant with a missing or malformed identity denies
  that grant; an unreadable grant stays `unknown` for every grant.
- Body and actor are read before `ts` or `crit` can fail, so an authenticated-invalid cut keeps its address and
  an invalid line keeps its identity context.

## 4. Linkage versus authentication

`Authentication=Authenticated` holds exactly when this reader verified the line's signature over its exact PAE
string, **or** a verified line of the **same key** committed to its exact id through `prev`/`merges`, directly or
through other such lines. The id is SHA-256 over every signed byte, `signer` included, so the commitment
authenticates content and signer. It says nothing about meaning, so such a line is `Validity=Unsupported`.
Authentication never comes from key-log placement as such, nor from a test flag.

Why vouched lines are authenticated rather than unproven: a root that writes a future-major line and then vouches
for it from rc/1 might have written a terminal control. Keeping it unproven would ignore it; authenticated and
unsupported makes it `unknown` for every grant of the identity. Vouched future-major lines in a *delegate's*
ancestry are walked as linkage, with no consequence.

Otherwise: wire `Valid` → `Understood`; `Invalid` → per §3; `Unsupported` or an unknown kind → `Unsupported`.

## 5. Admission boundary

- `internal/identity` is the only non-test importer of `internal/identitymodel` (`TestOnlyAdapterImportsModel`).
  `Fact` stays exported for the model's own tests; production callers get `identity.Admit` and `Evaluate`.
- Actor binding: `BoundIdentityContext` only for a verified, valid rc/2 line whose `crit` is exactly
  `["x_identity_v1"]` and whose `x_actor_v1` parsed. Verified-unsupported rc/2 with an actor →
  `UnsupportedIdentityContext`; verified-invalid → `InvalidIdentityContext`.
- A signed actor header grants nothing by itself. Root-relevant uncertainty comes only from facts the adapter
  authenticated under the pinned root key.

## 6. Limits and digests

- `MaxAdmitLines = 100000` distinct **authenticated** lines (verified or vouched) per snapshot. Over it, admission
  fails as a whole: no partial snapshot, so no partial pass (`TestAdmitCapRefusesWholeSnapshot`).
- `MaxUnprovenLines = 100000` unverified, unvouched lines. Over it, the largest ids are dropped deterministically
  (a dropped link reads missing, which is no more permissive than unproven); the snapshot does not fail.
- rc/2 sets (merges, targets, subjects, predecessors) are capped at 256 and permissions at 64; over a cap the line
  is authenticated-invalid. Per-line bounds are wire's (`MaxLine`, `MaxSignedString`).
- Evaluation: the model's `MaxTraversalFacts = 2048` per walk is the effective cap; reaching it is `unknown`
  (`model_limit`). `MaxDelegateSelfEvents = 64` bounds the warnings for a delegate's own raw key events.
  **Open liveness item:** a long-lived worker log exceeds 2048 lines. Reconcile with the profile's proposed
  100,000 / 1,000,000 accounting (§7) before any real use.
- Two digests, never conflated. `EvidenceDigest` (model) is over normalized facts. `Receipt` (adapter) is
  SHA-256 over the sorted `id`, length and canonical stored line of each admitted line, keeping the smallest
  canonical line per id so duplicate deliveries with different valid signatures give the same receipt. For an
  unverified line the receipt covers its signed content with `sig` emptied: anyone could resend it with other
  `sig` bytes. Blob availability is **not** covered (nothing here depends on a blob); it is required before
  resource or observation use.
- Facts are a function of canonical bytes: every retained statement is re-read from its canonical line, and a
  permission with other than exactly one target mode is `UnspecifiedTargets`.

## 7. Scope and invalidity

- The permission registry is the profile's §3 table, which is the model's `scope.go` (15 kinds, the same target
  domains). Wire validates the closed per-kind target shapes. An **unknown permission kind** makes its grant
  verified-`Unsupported`: acts under that grant read `unknown` (no scope reason is computed from a partial
  parse), and sibling grants evaluate normally with an `unsupported_sibling_grant` warning. This relies on the
  profile §3 invariant that `fixed-root-v1` permissions are leaf operations. A malformed known permission makes
  the grant `Invalid`.
- Inception profile: any token reads; only `fixed-root-v1` maps to `FixedRoot`; anything else is `unknown`.
- Root vocabulary on the pinned lineage: rc/2 inception, grant, cut; rc/1 `rotate_key` / `revoke_key`
  (terminal); bare `describes` / `anchors` → `Inert`; everything else → `unknown`.
- Permission eligibility confers no resource or task role, amendment ownership or trust. Those belong to
  consumers.

## 8. Task contracts

Every rc/2 task kind is verified-`Unsupported`. No settlement or readiness can pass.

## 9. Not covered

Consumer wiring (authorship, amendments, resources, tasks, policy, time); major-aware edition ids; blob
availability in the receipt; timestamp coherence as an identity input; a detached signing ceremony; devices.
Scenario-level status: `docs/fixed-root-identity.coverage.json` (every row `not_claimed`).
