# Reader policy file (`reader-policy-v1`)

`show`, `verify`, `explain`, `list`, `status` and `pull` can answer under a reader policy: a local file the reader
writes that says which declarations it reads where several keys disagree (**selections**) and which keys it
trusts for what (**trust**). The file is named by `--policy <file>`, else by `$COMMONS_POLICY`. Nothing is read
implicitly: no file in the home directory and none in the store. Without one, every answer is the no-policy
answer described below.

**Status: provisional.** The claims-model note says what a reader policy decides (trust, admission and reference
choices are local, I9); it does not fix a file encoding. This format is the tool's own and versioned
(`reader-policy-v1`). It will change, with a new version. A document with another `version` is refused. The
JSON Schema for the shapes is `docs/fixed-root-identity-policy.schema.json`; the rules below that a schema cannot
express are checked too.

A policy is local. Received objects never install, extend or modify it, whoever signed them (data never carries
control, claims §11).

## Format

One strict JSON object (UTF-8, no duplicate members, integers only): the file at most 394,240 bytes, and at most
65,536 bytes in canonical (RFC 8785, JCS) form. Exactly three members, all required:

| member | value |
|---|---|
| `version` | `"reader-policy-v1"` |
| `selections` | array of selection entries (may be empty; at most 256) |
| `trust` | array of trust entries (may be empty; at most 256) |

Parsing is strict and closed. A member this version does not define, an unknown role or purpose, a malformed
value, an entry array that is not sorted, two identical entries, or two selections for the same subject is an
invocation error: the command exits 2 before any work and nothing is evaluated (claims §13).

- **Sorting.** Entries of `selections` and of `trust` are sorted by their canonical (JCS) text, compared by UTF-16
  code units. `purposes` and `contents` are sorted string sets (UTF-16 order, no repeats).
- **Digest.** The policy digest is `sha256:` + SHA-256 of the canonical bytes of the whole document, `version`
  included. Every answer a policy changes cites it, and `explain` and `status` print it, so two readers that
  differ only by policy see which policy made the difference.

### Principals

A principal is `{"key": K}`: one signing key, `ed25519:` + 64 lowercase hex, or `0x` + 40 lowercase hex.

The schema also admits `{"identity": I}`: the principal is the identity, never one of its keys. Trust is asked of a
statement: only a statement the reader's identity evaluator finds eligible for I is I's, and a bare statement by one
of I's worker keys never is. The reader builds that evaluator from the `rc/2` statements it holds (a corpus with none
has no evaluator). An entry naming an identity is never treated as a key. Where there is no evaluator, a selection
that names an identity is unmet, labelled `unknown (identity profile not active)` (the text of the evaluator-absent
answer: no `rc/2` evidence is held), and no key's claims are followed in its place; a trust entry that names one
trusts no key, and an answer it would have decided reads the same and counts as not trusted. With an evaluator, a
statement it finds eligible for I is trusted as I's, one it finds denied is not trusted, and one it cannot decide
reads `unknown (actor eligibility not established)` with the evaluator's reasons.

Identity evaluation did not change this policy's version: `reader-policy-v1` already fixes what an `{identity: I}`
entry means, and what changed is the reader's evaluator. An answer that consults one cites it beside the policy
digest, so two readers with the same policy and different evaluators can be told apart.

## Selections

A selection chooses which declaration supplies an answer the resolver otherwise derives from every claimant.

```json
{"subject": {"content": "sha256:…", "role": "authorship-declaration"}, "statement": "<statement id>"}
{"subject": {"content": "sha256:…", "role": "workflow-declaration"}, "principal": {"key": "ed25519:…"}}
```

`subject` names a content digest and a role. Exactly one of `statement` (an exact pin) or `principal` (a key to
follow) is given. One selection per (content, role): a second one is an error even when it differs.

| role | the declaration eligible to supply it | what it changes |
|---|---|---|
| `authorship-declaration` | an `authored` of that exact content digest | the blob's single-party defaults (licence, availability, …); every other current claim's value is listed beside it as a rival |
| `workflow-declaration` | an `authored` of that digest with `type: "workflow"` | the replication mode and comparator every derivation group under that workflow is read with |
| `observation-declaration` | an `observed` of that exact digest | the observation a derived result's leaf summary reads |

- **An exact pin** selects that eligible statement and nothing else: never an alias, an edition, a successor, an
  amendment or the key's latest statement. A pinned statement that is not held, or is held and ineligible (another
  kind, another blob, not a workflow, or a line that counts toward nothing), leaves the selection **not met**, and
  nothing is substituted.
- **A principal selection** follows that key's eligible current claims on the content (its counted statements
  that no later counted statement of the same key amends). When they disagree, the disagreement is shown (a
  contested field, a workflow selection marked not met); arrival order never settles it.
- **A key rotation is not followed.** A successor named by `rotate_key` inherits no claims (claims §4.1). A
  reader that wants to read the successor's declaration selects the successor's key, or pins its statement.
- An unmet selection leaves the answer without a default: no field defaults, no replication mode is read, no
  observation is summarised. It never falls back to the no-policy answer.
- A selection may change a recomputed grade because the declaration read changed (a different workflow mode, for
  example). It never adds a run, a comparison, an anchor or a statement.

## Trust

A trust entry trusts one principal for a set of purposes over a content target.

```json
{"principal": {"key": "ed25519:…"}, "purposes": ["admission", "corroboration"], "targets": {"any_content": true}}
{"principal": {"key": "0x…"}, "purposes": ["attestation"], "targets": {"contents": ["sha256:…", "sha256:…"]}}
```

`purposes` is a nonempty sorted set drawn from the three purposes below; `targets` is exactly one of
`{"any_content": true}` or `{"contents": [...]}` (a nonempty sorted set of at most 256 content digests). A target
applies to the content being judged (the observation's blob for corroboration, the run's output for attestation,
the content a statement names for admission), never to an incidental digest. A statement that names no content
is covered only by `any_content`. A statement that reaches its content through a reference (a `corroborates`,
`refutes` or `retracts` names the statement it is about in `of`; a `describes` may be about a statement) is judged by
the referenced statement's content, one hop, when that statement is held (at `pull`: in the package or this store).
When it is not held, the content is unknown, not absent: an answer that depends on it (a `contents` entry for the
purpose could match the signer) reads `unknown (target reference not resolved)`, which is neither trusted nor a
refusal of the signer. At the trust floor it is refused under `--below-floor refuse` and labelled by default, like any
answer that is not `trusted`. An `any_content` entry, and a signer no entry names, answer the same whatever the
content.

| purpose | where it is read | effect |
|---|---|---|
| `corroboration` | an observation's corroboration status (claims §5.3.2) | evidence signed by a key not trusted for corroboration over the observation's content is shown, with the reason, and not counted. The reader's own computations are never filtered |
| `attestation` | a run's signed result and environment | the reader's trust in the runner is shown beside the run. Display only: no grade or exit reads it |
| `admission` | `pull` (the trust floor) | a statement whose signer is not trusted for admission over its content is refused (class `reader policy`, reason `trust floor`, scoped to that signer's objects), or admitted and labelled `below trust floor`; `pull --below-floor refuse\|label` chooses, and the default is `label` |

**Trust is configured per purpose.** A purpose that no trust entry names is **not configured**: the reader keeps
its no-policy behaviour for it and says `not configured`, never `trusted`. With no policy, or with a policy that
names nobody for corroboration, every counted statement is counted; with no admission entry, every signer is
admitted unlabelled. Once any entry names a principal for a purpose, only the listed principals are trusted for
it, and a key no entry lists is `not trusted`: configured trust is never universal. A purpose matches only
itself, and overlapping entries are additive (one matching entry is enough).

Trust admits otherwise eligible evidence for the named purpose. It never makes a signature valid, an authorship
claim true, two keys independent people, a reproduction successful or a time bound better. Trust in a key is not
permission to execute: execution has its own policy file (`docs/EXEC-POLICY.md`).

## Not expressible yet

- The trust floor's refuse-or-label choice: there is no member for it, so `pull --below-floor` carries it.
- A counting unit other than the signing key, and identity principals (see above).
- Reference collections, hub selection and subscriptions: they are chosen by other commands or not yet by any.

These are absent rather than defaulted: a member that is not listed above is refused, so a file written for a
later version fails here instead of being silently under-applied.

## Example

```json
{
  "version": "reader-policy-v1",
  "selections": [
    {"principal": {"key": "ed25519:0000000000000000000000000000000000000000000000000000000000000000"},
     "subject": {"content": "sha256:1111111111111111111111111111111111111111111111111111111111111111", "role": "workflow-declaration"}}
  ],
  "trust": [
    {"principal": {"key": "ed25519:0000000000000000000000000000000000000000000000000000000000000000"},
     "purposes": ["corroboration"], "targets": {"any_content": true}}
  ]
}
```
