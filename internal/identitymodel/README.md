# Fixed-root authority reference model

**Status: isolated semantic model, not enabled identity support.** This package is
not imported by the wire reader, writer, key log, resolver, CLI, or storage path.
It uses only the Go standard library. Its enums are model tags, not a wire-format
proposal. There is no production format-version change or reinterpretation of
existing signed bytes.

## Trust boundary: facts, not untrusted submissions

`NewSnapshot([]Fact)` consumes **trusted adapter attestations** about held evidence.
It does not parse canonical bytes, compute statement IDs, check signatures, verify
critical markers, or prove that supplied facts match the bytes. In particular,
setting `Authentication: Authenticated` does **not** authenticate anything. Tests
use synthetic attestations, not cryptographic test vectors.

An eventual adapter must establish these facts independently:

- The exact statement ID binds all extracted fields, including signer, local
  links, scope, and per-signature identity/grant context.
- `Authenticated` means the claimed signer authenticated those exact fields under
  a supported cryptographic profile. `Unproven` is merely a claim; a rejected
  signature is distinct from an unsupported/unavailable verification result.
- `Understood` means the supported format/profile and intrinsic semantics passed.
  `Unsupported` can still carry authenticated linkage, but cannot itself earn
  authority. `Invalid` includes established intrinsic/relative invalidity, such
  as time incoherence not represented by this model.
- `BoundIdentityContext` means that the actor is covered by the actual signature
  and its required critical body context is understood. It is not a local
  affiliation label or a body field copied into an envelope after verification.
- `Inert` must be an explicitly recognized root vocabulary member. Unknown root
  events must not be relabeled inert just to get a positive answer.

The package independently checks the represented key-local link facts: exact
`seq:0` pins, same-key links, `prev` sequence adjacency, lower-sequence merges,
missing links, and inception consistency across both `prev` and `merges`. It does
not call production indexes or trust a test `chained: true` flag. An adapter may mark
retained evidence `Authenticated` without verifying its own signature only under one
reviewed rule: a verified line **of the same key** committed to its exact id through
`prev`/`merges` (transitively through other such lines). The id covers every signed
byte, so this authenticates content and signer but not meaning: such a fact must be
`Unsupported`, never `Understood`.

Never feed user-decoded JSON directly to this API. Never discard opted-in facts
through a preliminary bare-key revocation/rotation eligibility filter. A valid raw
self-revocation event and an intrinsically invalid statement are different things.

## API and immutable evidence

```go
snapshot, err := identitymodel.NewSnapshot(adapterFacts)
if err != nil {
    // Empty IDs or conflicting facts at the same exact ID are adapter errors.
    return err
}
answer := snapshot.Evaluate(statementID)
independentCopy := snapshot.Clone()
_ = independentCopy
```

`NewSnapshot` deep-copies all nested data. Duplicate identical facts collapse;
conflicting facts at one ID are rejected rather than arrival-order selected.
Set-valued merges, permission entries, and target sets are normalized for the
model digest; their original wire ordering/canonicalization remains an adapter
responsibility. Duplicates *inside* an invalid permission/link set are not erased.
There are no public setters or exposed fact pointers. `Clone` owns independent
maps/slices/nested values. Evaluation uses request-local state and is concurrency
safe; returned explanation slices do not alias snapshot internals.

`EvidenceDigest` is SHA-256 of deterministic normalized **model facts**, preceded
by the evaluator-version field in a private length-framed model encoding. It is
not JSON, a wire/signature preimage, the transport bundle digest, or a cryptographic
verification receipt. The encoding follows the fixed model struct schema; schema
changes require an evaluator-version change. Arrival order and repeated
identical delivery do not change it. Adding unrelated facts changes the digest,
but not the relevant authority decision. Removal of retained evidence must be an
explicit new snapshot; production storage must ensure known cuts cannot disappear
through cache rebuilding.

The model limits each ancestry traversal and relevant authenticated root-event
scan to 2,048 facts. Exceeding a limit adds an `unknown` reason; a partial walk must
never produce a pass. Independent/unproven noise does not consume another
identity's semantic limit. This is **not** a transport/memory DoS admission layer:
constructing/hashing a snapshot and locating its relevant facts still examine held
input. An eventual reader must separately bound admission, bytes, links and work.

## Implemented authority rules

- An identity pins a supported fixed-root inception `I`. The administrative root
  cannot be its own worker. A grant `G` must be authenticated by that root and
  completely chained to `I`; it pins one exact worker key and inception `D`.
- Each opted-in signature declares exactly one `I/G`. A grant does not reattribute
  existing bare statements. Missing, unsupported or invalid identity authority
  never becomes bare-key authority or a different grant.
- Independent grants on root forks coexist. There is no latest-grant/controller
  winner and no cross-key timestamp or sequence ordering.
- Each relevant cut preserves either nothing (explicit null) or the exact
  inclusive ancestor set of `L`, following both `prev` and `merges`. All cuts are
  intersected. A sibling outside that closure is excluded. A later broader cut,
  a root merge, or a new grant cannot reopen an old grant or relabel signed acts.
- Missing `L` or required ancestry is unknown. Wrong-key/lineage last-good evidence
  and malformed attributable cuts are denied, not silently dropped. Omitted
  last-good is neither null nor unlimited.
- Held root-signed evidence whose root relationship is unresolved blocks a clean
  answer. Unknown/unsupported authority-bearing in-lineage root events are
  unknown. Relevant authenticated cuts with missing dependencies block their
  grant. A conclusively invalid non-cut root sibling cannot retire the identity;
  it is reported as an ineffective root-event warning. An unaddressable
  authenticated cut is unknown because its affected grant is not established.
- Valid in-lineage root rotation/revocation is terminal for the identity,
  including historical acts. There is no successor following or same-ID rescue.
  Events conclusively rooted at a rival inception do not administer this identity,
  even if they claim its name. Merges cannot import a rival inception.
- Worker rotation/revocation does not close explicitly opted-in grants or erase
  their preserved history; complete in-lineage self-events are visible warnings.
  A successor key does not inherit the old worker grant. Bare-key effects remain
  the legacy evaluator's job.
- Only authenticated evidence from the pinned issuer can create root-state
  uncertainty. Arbitrary affiliation assertions, forged signer claims and a
  stranger's real signature cannot stall another identity. A statement with an
  invented/missing grant has its **own** unknown authority; there is no global
  membership or arbitrary caller-asserted affiliation index.

## Closed grant scope

| Operations | Registered target | Allowed scope modes |
|---|---|---|
| authored, observed, holds | Exact content digest | Explicit set or any content |
| reproduced, corroborates, refutes, retracts | Exact referenced statement | Explicit set or any statement |
| edition, withdraw_approval | Exact resource ID | Explicit set only |
| intent, withdraw, progress, submit, decide | Exact task ID | Explicit set only |
| anchors | Actual signer's own log | Own log only |

Empty scope is not unlimited. Unknown permission kinds make the grant unsupported,
including when another entry would otherwise permit the operation. Duplicate
permissions/targets and contradictory target modes are invalid. Multiple distinct
entries for a kind are allowed; their explicit matching scopes form a union.

Only authored/observed accept the amendment permission. `Amend: true` is
identity-wide within the content scope, **not** restricted to one delegate or
previous grant. This model checks permission to attempt amendment, not the
amendment DAG, target eligibility, same-principal rule or current-state selection.
Root administration and raw key events are never delegated operations.

## Structured answers, not application authorization

`Result` includes `eligible`, `denied` or `unknown`; declared actor, actual signer,
grant, root/delegate pins, held basis IDs, relevant cut IDs, dependencies, reason
codes, warnings, evidence digest, evaluator version and freshness. A known denial
takes precedence over unknown, but unresolved reasons/dependencies remain visible.
`Freshness` is always `not_established`. A held offline set never establishes that
no omitted cut or terminal event exists.

`Evaluate` evaluates **identity grant eligibility only**. For a bare statement it
returns `denied / no_identity_actor` with `key(K)` as the declared subject. This is
not a bare-key revocation verdict: the legacy evaluator must handle that statement.
For an opted-in statement the declared subject remains `identity(I)` even when the
result is denied/unknown. There is no fallback.

**Consumers must apply operation-specific roles and state rules after grant
eligibility.** In particular this package does not implement resource controller
slots/quorums, approval withdrawal, task beneficiary/issuer roles or continuity,
amendment/retraction target checks, current-state uncertainty propagation, trust,
selection/admission policy, priority/time proofs, custody, root signing, network
fetches, persistence or CLI exit codes. An eligible `decide` grant is not proof that
the actor is the task's beneficiary. An eligible `edition` grant is not a
controller vote until the resource engine establishes the role.

## Verification scope

The deterministic fixture has sibling worker branches, a merge, exact/null cuts,
and root forks. Table tests cover supported scopes, malformed/unsupported facts,
authentication boundaries, missing dependencies, lineage pins, terminal versus
rival root events, worker self-events, explicit actors and isolation of cloned
snapshots/results. Seeded tests cover:

- 60 generated DAGs checked against independent precomputed ancestry sets and
  literal cut-set intersections, including no widening under added cuts;
- 20 DAGs × 8 evidence permutations, including duplicate delivery and identical
  full structured results/digests;
- 30 scope-narrowing DAGs with an independently specified target predicate;
- 20 foreign/unproven-noise cases with unchanged relevant decisions;
- concurrent requests and mutation of inputs, clones and returned explanations.

Run `go test ./internal/identitymodel -count=1 -cover` and
`go test -race ./internal/identitymodel -count=1`. These are **model-level** tests,
not wire conformance, cryptographic admission, reader integration, or end-to-end
identity support. A future adapter/profile integration needs independent signed
vectors, signature-tampering/criticality tests, real retained-evidence rules,
consumer role/state tests and baseline compatibility review before activation.
