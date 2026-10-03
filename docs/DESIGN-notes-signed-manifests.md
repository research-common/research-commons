# Design note: Signed manifest views

**Date:** 2026-10-02 · **Status:** proposal for design review
**Covers:** #41 part 2 and #10 · **Builds on:** #42 (`ManifestEditGate`, open), #39, #18
**Implementation:** separate PRs, sequenced in [§12](#12-migration-plan)

## Summary

A manifest is a JSON file that several parties write. The publisher writes most of it, a
submitter adds `fulfills`, a beneficiary adds `accepted`, an attester adds `attested_by`, and
`pull` adds a local `ingest` stamp. Today no signature covers any of those bytes. A ledger
signature covers `action, agent, id, sha256, ts`, and `sha256` is the content hash. So whoever
holds a manifest can rewrite its tier, licence, criteria, parameters, links or verdicts.
Nothing in the file shows that it changed. #42 closes the transport path, so `pull` and
`hub check --base` now refuse unbacked edits. It cannot make a manifest checkable on its own,
and it has a known ride-along gap.

This note proposes:

1. **A publisher view.** This is a normalised projection of the manifest that keeps exactly
   the fields the publisher vouches for. Each field of a manifest has one source of authority,
   and the view drops every field whose authority lies elsewhere ([§3](#3-field-classification),
   [§4](#4-normalisation-the-publisher-view)).
2. **A publisher statement in the manifest.** It is an EIP-191 signature over
   `{rc: "manifest/1", id, sha256, view, ts}`, stored next to the fields it covers, as
   attestations are. Anyone holding the file can check it without a ledger, a blob or a spec
   ([§5.1](#51-publisher-statement-in-the-manifest)).
3. **A second signature on ledger entries.** New entries carry `sig2` over **every** field,
   and keep today's `sig` over `SIGNED_FIELDS` unchanged. Old tools therefore keep verifying
   new entries. `publish`/`republish` entries carry the view digest, which binds the event to
   exact manifest bytes and closes #42's ride-along gap. `sig2` also signs the lifecycle fields
   (`task`, `result`, `exec_mode`, …) that the derived class depends on. Today nothing signs
   them ([§2.2](#22-two-gaps-found-while-preparing-this-note), [§5.2](#52-ledger-entries-a-second-signature)).
4. **Attestation statement v2** (#10). It adds `params` to the signed statement, with the same
   `stale` handling as `criteria` ([§8](#8-attestations-10)).
5. **Authority from the held view, not from ledger history.** The key that signed the view you
   already hold, plus keys that view names, may sign the next one
   ([§6](#6-authority-who-may-sign-the-next-view)). This replaces #42's "any verified publisher
   at the base". That rule can be laundered (see [§2.2](#22-two-gaps-found-while-preparing-this-note)).
6. **A three-phase migration** with no `SCHEMA` bump: first readers, then writers, then
   enforcement each hub opts into. #42's rules stay as the legacy path for manifests that have
   never carried a view ([§12](#12-migration-plan), [§13](#13-where-42s-rules-end-up)).

## 1. Problem

#41 shows that a manifest-only edit (tier T3 → T0, a new licence, obtainability, title and
`derives` link) passed `pull`, `fsck`, `hub check` and `hub check --base`. #10 shows the same
for `verification.params` under a T3 attestation. `verify` still reported the attester as valid.

#42 makes both gates compare a modified manifest with its merge base. It accepts the edit only
if (a) the range carries a verified signed `publish`/`republish` by a key with authority, or
(b) every change is an annotation that a signed ledger event backs. That gate is necessary and
stays. Its limits are structural:

- **Ride-along.** A republish signs the content hash, not the manifest. Any edit committed
  after a genuine republish in the same range passes with it. `tests/test-manifest-edit.sh` §6
  pins this.
- **Path-dependent.** The verdict depends on the git range a manifest arrived in. A file
  copied in any other way (a tarball, a hand-merge, a hub whose CI was skipped) carries no
  evidence either way, and `fsck` and `status` cannot tell it apart from the original.

The goal stated in #41 is that anyone holding a manifest can tell which key stated each field
and whether that statement still covers what is displayed.

## 2. What is signed today

| Signed object | Bytes signed | Where it lives | Not covered |
|---|---|---|---|
| Ledger entry (`sign_entry`) | `canonical({k: e[k] for k in SIGNED_FIELDS})`, `SIGNED_FIELDS = (action, agent, id, sha256, ts)` | `sig`, `addr` on the line | Every other field: `task`, `result`, `tier`, `reason`, `salt`, `settlement`, `verdict_vector`, `exec_mode`, `image_digest`, `superseded_by`, `ingest_unchecked`, `backfill`, `schema` |
| T3 attestation (`cmd_attest`) | `canonical({attests, sha256, criteria, observed})` | `verification.attested_by.{addr,sig,statement}` | `params` (#10), everything else |
| Manifest | nothing | — | all of it |

Both signed objects use the same primitive: EIP-191 `personal_sign` over a canonical JSON
string, from `lib/sign-message.mjs`. Neither carries a domain tag. The two key sets are
disjoint today, so neither can be passed off as the other. Any new statement must keep it that
way on purpose, not by accident ([§5.4](#54-domain-separation)).

### 2.1 Background read for this note

- `signing_payload()` / `verify_entry()`
- `cmd_attest()` / `check_attestation()`
- `build_verification()`, `cmd_publish()` and the `--force` carry-forward from #18
- `ANNOTATION_FIELDS` / `merge_manifest_annotations()`
- `ManifestEditGate` in #42
- `first_publisher_index()`, which orders publishes by anchored time and then by asserted time
- `cmd_run` / `cmd_run_task` `--publish`, `cmd_rebaseline`, `cmd_submit`, `_settle`,
  `cmd_settle`, which are all the code paths that write a manifest

### 2.2 Two gaps found while preparing this note

Both were reproduced on #42's head (`fix/41-manifest-edit-gate`) with that PR's own test
fixtures: a lead L, a contributor C, both registered with `trust=full`, and a throwaway hub.
They shape the proposal, so they are recorded here. Each also deserves a fix independent of
this design ([§12](#12-migration-plan), phase 0).

**G1. Lifecycle fields are unsigned, so a signed event can be replayed with different
meaning.** `accept` signs `{action, agent, id=task, sha256=task content hash, ts}`. The
accepted `result` is not signed. C copied L's genuine `accept` line, changed `result` to a
dataset C had just published, fixed up `prev` (which is unsigned by design) and appended the
line to **L's own log file**. C also added `{"rel":"accepted","id":<C's dataset>}` to the task
manifest. Results:

- `hub check --base`: OK.
- `pull`: accepted. #42's gate found a "signed ledger event" behind the annotation.
- `log --verify`: OK.
- The task's settled event is now the forged line.

The same holds for `submit` (`task` and `result` unsigned; `task_events()` selects by the
unsigned `task`), for `rebaseline` (`result=match`, `exec_mode`, `image_digest` unsigned) and
for `settle`'s `verdict_vector`. Two consequences follow:

- Replayed v1 authenticated identities need to be detected now.
- The derived class in [§7](#7-the-derived-class) cannot rest on v1 entries.

**G2. #42's authority rule can be laundered in two pushes.** Authority is "a verified
publisher **or republisher** of the id at the base".

1. C ran `publish --force` on L's dataset and reverted the manifest file. C pushed only the
   resulting signed `republish` line. No manifest was modified, so both gates passed and L
   pulled it.
2. C's key was now a "republisher at the base". C ran `publish --force --tier T0 --license
   proprietary-internal` with a new title. `hub check --base` passed, and L's `pull` accepted
   it as "backed by a signed republish". L's manifest now shows T0 with C's licence and title.

Excluding `republish` from authority is not enough on its own. C can sign a `publish` line with
any `ts`, and among unanchored events `first_publisher_index()` falls back to the asserted
time. [§6](#6-authority-who-may-sign-the-next-view) takes authority from the view already
held, so it does not depend on timestamps.

## 3. Field classification

Every field a current manifest can carry, from every writer listed in §2.1. The rule for a
field this table doesn't list (for example one added by a future PR) is **default-include**:
it is part of the publisher view, and so signed by the publisher, until a new view version
moves it out ([§4.3](#43-versioning)). Defaulting the other way would let any new field arrive
unsigned without anyone deciding that it should.

| Field | Class | Vouched for by | Reason |
|---|---|---|---|
| `schema`, `id`, `type`, `content.sha256` | Identity | the id derivation (`<type prefix>-<sha256[:8]>`), checked by `hub check`; also in the view | Already self-checking. Including them binds the view to one artifact. |
| `content.bytes` | Publisher claim | view signature; checkable against the blob when held | The publisher states it. A lazy peer cannot recompute it. |
| `content.filename` | Publisher claim | view signature | Used as an on-disk name by `run-skill` and `_export_executable`. The publisher chose it. |
| `title`, `description`, `tags` | Publisher claim | view signature | Editorial. These were the #41 repro's display forgery. |
| `agent`, `created` | Publisher claim | view signature | Self-declared name and first-publish time. Ordering never trusts `created` (anchors do that). Signing it makes it attributable, not true. |
| `license`, `availability.{obtainability,source}` | Publisher claim | view signature | Disclosure. The push gate reads these. |
| `verification.tier`, `verification.criteria` | Publisher claim | view signature (+ attestation for T3 `criteria`) | The tier is the central claim. A T3 attester also signs `criteria` (§8). |
| `verification.params` | Publisher claim | view signature (+ attestation v2 for T3) | #10. For T1 these are the comparator parameters `verify` passes to the comparator, so they are load-bearing at T1 as well as T3. |
| `judgement` | Publisher claim | view signature | The verdict vector T2 quorum settlement groups by (`judgement_vector_key`). As load-bearing as the tier. |
| `generation` (`model_family`, `attestation`, …) | Publisher claim | view signature | Input to diversity quorums (`result_family`). `publish` never writes it; it is set by hand, so the view must cover whatever bytes are present (default-include does). **Signing makes the level attributable, not true.** `attestation: tee` is still the publisher's own word ([§15](#15-residual-risks-and-open-questions)). |
| `provenance.inputs`, `provenance.workflow` | Publisher claim | view signature | The derivation the T0/T1 re-run follows. |
| `authority`, `reproducers` | Publisher claim | view signature | Delegations for a future view (§6) or a derived reproduction stamp (§7.2). |
| `provenance.run.{finished,env,exec}` written at publish, `provenance.run.rebaseline_of` | Publisher claim | view signature | The environment `verify` compares a re-run against (`recorded_exec`). |
| `provenance.run.exec` + `.rebaselined` written by a `rebaseline` match | **Derived** (from v2 on) | the signed `rebaseline` event | A third party's reproduction statement, not the publisher's. Phase 2 stops writing it into the manifest ([§7](#7-the-derived-class)). Legacy values already present are covered by whoever signs the view. |
| `rubric` | Pinned by content (hint) | the `sk-` id; re-derived from `rubric.json` in the bundle when held; also in the view | Derived from the blob at publish. Signing the hint helps peers that hold the manifest only. |
| `ingest_policy` (flag) | Pinned by content (hint) | the `cl-` spec; `hub check` compares; also in the view | Same as #39: the spec decides. The hint tells a lazy peer to fetch the spec. |
| links `supersedes` on a **collection** | Pinned by content (hint) | the spec's `supersedes` (#39); also in the view | As above. The spec wins where it is held. |
| links `cites`, `derives`, `supports`, `refutes`, `based-on` | Publisher claim | view signature | Evidence links feed the chain grade. |
| links `part-of`, `applies`, `supersedes` (non-collection) | Publisher claim | view signature | Membership and method claims. Ingest policy reads `part-of`. |
| links `fulfills` | **Derived** | v2-signed `submit` (`task`, `result` signed) | A fact about the ledger. `run-task --publish` also writes it at publish; v2 stops that. |
| links `accepted` | **Derived** | v2-signed `accept`/`settle` by the beneficiary | As above. G1 shows why v1 events cannot back it. |
| `verification.attested_by` | Separately signed | the attester's statement (§8) | Another party's signature over its own statement. It is excluded from the view so attesting doesn't invalidate it. |
| `publisher_sig` (new) | Separately signed | itself | The publisher statement ([§5.1](#51-publisher-statement-in-the-manifest)). Excluded from the view it signs. |
| task and collection spec fields | Pinned by content | the id | They live in the blob, so the manifest holds no copy to forge. |
| `ingest.{received_at,from}` | Local only | nothing | An arrival stamp. Excluded from every digest and never read from a peer. Phase 2 moves it to a local-only sidecar ([§7.3](#73-ingest-leaves-the-manifest)). |

Pinned-by-content hints are included in the view **and** re-derived from the blob wherever it
is held. The two checks answer different questions. The signature says the publisher stated
the hint; the re-derivation says the content agrees. If they disagree the content wins, as
`hub check` already enforces for `ingest_policy` and (#39) `supersedes`.

## 4. Normalisation: the publisher view

### 4.1 Construction

The view is a pure function of the manifest:

```python
VIEW_VERSION = "manifest-view/1"
VIEW_DROP_TOP = ("ingest", "publisher_sig")        # local-only; the statement itself
VIEW_DROP_VERIFICATION = ("attested_by",)          # separately signed
DERIVED_RELS = ("fulfills", "accepted")            # derived from the ledger
SET_VALUED = (("links",), ("tags",))

def publisher_view(m):
    v = copy.deepcopy(m)
    for k in VIEW_DROP_TOP: v.pop(k, None)
    if isinstance(v.get("verification"), dict):
        for k in VIEW_DROP_VERIFICATION: v["verification"].pop(k, None)
    if isinstance(v.get("links"), list):
        v["links"] = [l for l in v["links"]
                      if not (isinstance(l, dict) and l.get("rel") in DERIVED_RELS)]
    v = prune_empty(v, preserve_members_of=(("verification", "params"),))
    for path in SET_VALUED:
        sort_and_dedupe(v, path, key=canonical)    # in place, if present and a list
    return {"rc": VIEW_VERSION, "manifest": v}

def view_digest(m):
    return hashlib.sha256(canonical(publisher_view(m)).encode("ascii")).hexdigest()
```

- **Bytes hashed.** `canonical()` exactly as it exists today:
  `json.dumps(obj, sort_keys=True, separators=(",", ":"))`.
  - `ensure_ascii` stays at its default `True`, so the output is ASCII and non-ASCII
    characters are written as `\uXXXX` escapes.
  - Keys sort by code point.
  - The wrapper object adds the `rc` domain tag ([§5.4](#54-domain-separation)).
  - Reusing the existing function means one canonical form in the codebase. A second one
    would be a divergence waiting to happen.
- **NaN/Infinity.** Signing refuses them; verification reports the manifest as
  `unnormalisable`. (`json.dumps(..., allow_nan=False)` in the view path.)
- **Floats** are allowed. `generation` can carry sampling parameters set by hand. They
  serialise as Python's shortest round-trip `repr`, and parsing and re-serialising is stable.
  Other implementations must match the test vectors ([§16](#16-implementation-checklist)), not
  RFC 8785, whose number and key-ordering rules differ.
- **No Unicode normalisation.** Strings are hashed as parsed. A publisher who writes NFD gets
  NFD.

### 4.2 Absent, empty and ordered

- **Absent ≡ empty only where empty has no effect.** `prune_empty` removes, recursively and
  bottom-up, object members whose value is `null`, `""`, `[]` or `{}`, except that it does
  **not** remove members of `verification.params`; `preserve_members_of` makes that object
  opaque to pruning. It may remove the `params` object itself when it has no members; absent
  params and `{}` both mean no parameters. A present parameter with value `""` must remain:
  `verify` passes it to the comparator, and it can change the result. List elements are never
  removed. Elsewhere, `description: ""` and `tags: []` are what `publish` writes for "none";
  a missing and an empty `criteria` are read alike. The test vectors must cover the
  exception as well as those safe equivalences.
- **Set-valued lists** are sorted by the canonical JSON of each element and deduplicated:
  - `links`: the relation graph has no order, and `merge_manifest_annotations` already treats
    links as a set.
  - `tags`
- **All other lists keep their order.** This includes `provenance.inputs`: the verifier builds
  an id-to-hash map by walking that list, so if an id appears twice with different hashes,
  the last occurrence wins. Sorting or deduplicating could hide a change in the input the
  verifier uses. Other examples are `rubric` (criterion order is how
  `judgement_vector_key` orders a vector) and anything inside `generation`. If you're not
  sure a list is a set, keep its order: treating a list as ordered can only cause a spurious
  mismatch, while treating it as a set can let a real change through unnoticed.

### 4.3 Versioning

The view version is inside the hashed bytes (`"rc": "manifest-view/1"`) and is named again in
the statement. A future change bumps it to `manifest-view/2`. Examples: moving a field out of
the publisher class, adding a set-valued path, or changing what counts as empty.

Verifiers keep the v1 construction forever and pick the construction a statement names. Old
digests therefore stay valid after the rules grow. A tool that meets a view version it doesn't
know reports `unknown-view-version`. It never reports `altered`, so a newer manifest is never
mislabelled as forged.

## 5. Signing formats

### 5.1 Publisher statement in the manifest

```json
"publisher_sig": {
  "addr": "0x…",
  "sig": "0x…",
  "statement": {
    "rc": "manifest/1",
    "id": "ds-8f7c4e17",
    "sha256": "<content.sha256>",
    "view_version": "manifest-view/1",
    "view": "<view_digest(manifest)>",
    "ts": "2026-10-02T09:00:00Z"
  }
}
```

The signature is EIP-191 over `canonical(statement)`, from the existing signer. A manifest's
`publisher_sig` is **valid** when all of the following hold:

- `statement.id == m.id`
- `statement.sha256 == m.content.sha256`
- `view_digest(m)` under `view_version` equals `statement.view`
- the signature recovers `addr`

This check needs nothing except the file, which satisfies the lazy-replication constraint
(brief Q9). Whether `addr` had **authority** to sign is a separate question
([§6](#6-authority-who-may-sign-the-next-view)), because it needs context.

Why the statement lives in the manifest (brief Option B) rather than only in the ledger
(Option A):

- The manifest can be checked without a ledger.
- Old tools ignore the unknown field.
- It follows the attestation pattern the codebase already has.

Option B alone has a hole: strip the block and the manifest looks legacy. Binding the view
into the ledger as well (§5.2) closes it, so the proposal uses both.

### 5.2 Ledger entries: a second signature

Every new ledger entry, of every action, is signed twice:

- `sig`: **unchanged.** It is the v1 signature over `signing_payload(e)` (`SIGNED_FIELDS`). Its
  meaning does not change, as the comment on `SIGNED_FIELDS` requires. A tool that predates
  this change verifies it as before and never reports BAD SIGNATURE on a new entry.
- `sig2`: new. It is EIP-191 over `canonical({"rc": "ledger/2", "entry": E})`, where `E` is the
  entry minus `addr`, `sig`, `sig2` and `prev`:
  - `addr` is checked by recovery, so it doesn't need to be signed.
  - `prev` is a chaining field, already unsigned, and set at commit time.
  - **Every other field is signed**, including `schema`, `tier`, `task`, `result`, `reason`,
    `verdict_vector`, `exec_mode`, `image_digest` and `ingest_unchecked`.

`publish` and `republish` entries gain one field: `view`, the digest of the view written in
the same commit. The view is then bound in two places: the manifest's own statement, and an
event in the signer's hash-chained log.

Readers apply these rules:

- **Ledger-only checks.** An entry with valid `sig` and `sig2` recovering the same signer is
  a **v2 entry**. All of its fields are the signer's word.
- **Entries with only `sig`.** These are **v1 entries**, and only their `SIGNED_FIELDS` are the
  signer's word. Every other field is an unsigned hint, which is how the code should already
  have treated it (G1). Legacy rules may still use v1 hints (§13); v2 rules never do.
- **Failure.** A `sig2` that is present and fails is a forgery, whatever `sig` says, and is
  reported BAD SIGNATURE. Stripping `sig2` from an existing line is a rewrite. `hub check`
  catches that through its append-only rule, and `pull` must apply the same rule (phase 0).
- **Replay identity.** Verify each signature and recover its signer before comparing entries;
  `sig` text is not an identity. Equivalent recovery-byte encodings can verify as the same
  signer while having different strings. For a v1-only entry, the identity is
  `(recovered signer, canonical(signing_payload(e)))`. Reject a later v1-only line with an
  identity already seen in any log, including on a v2 entry; changing unsigned fields or
  `prev` cannot make it new. For a v2 entry, the identity is
  `(recovered sig2 signer, canonical({"rc": "ledger/2", "entry": E}))`, the **complete signed
  payload** defined above. Reject a repeated v2 identity. A distinct v2 payload remains a
  distinct event even if its v1 `SIGNED_FIELDS` and `sig` match (for example, two `accept`
  events with different signed `result` values in the same second). Readers ignore rejected
  replays; `hub check` and `pull` report them as problems. The first authenticated identity
  in ledger order is the one readers may use.

Cost: one extra signature per event. `sign-message.mjs` gains a mode that signs both messages
in one Node process, so a publish still spawns one signer.

### 5.3 Attestation statement v2

See [§8](#8-attestations-10).

### 5.4 Domain separation

Every new signed object starts with an `rc` member that names what it is: `manifest/1`,
`ledger/2`, `attestation/2`, and inside the view, `manifest-view/1`. No v1 signed object has
an `rc` key, and neither `SIGNED_FIELDS` nor the v1 attestation keys include one. So no new
object canonicalises to the same string as an old one, and no two new objects canonicalise to
the same string as each other. The signer key stays the dedicated commons identity, as
`sign-message.mjs` already requires.

### 5.5 Schema and tool versions

- **No `SCHEMA` bump.** Every addition (`publisher_sig`, `sig2`, `view`, the `rc` keys) is an
  optional field that rc.v1 readers ignore. Old signatures keep their meaning. Nothing here
  needs `rc.v2`. That bump is reserved for a manifest-shape change old readers would
  misread, and they can't misread one they ignore.
- **No negotiated signature version.** Each signature names its own format in its `rc` tag. A
  verifier either knows it or says `unknown`.
- **Tool MINOR bumps** for phases 1 and 2, because `hub check` pass/fail semantics change
  (`docs/RELEASING.md`). A hub that opts in to enforcement pins a phase-2 tool in
  `hub-check.yml` ([§12](#12-migration-plan)).

## 6. Authority: who may sign the next view

Content addressing lets several keys publish the same bytes. #42 gives authority to any
verified publisher at the base, which G2 launders. This proposal anchors authority in the
**view already held** and never in ledger history or timestamps.

**Authority set `A(id)`**, computed against the held manifest (the merge-base copy in a gate,
the local copy otherwise):

1. If the held manifest has a valid `publisher_sig`: its `addr`, plus every address in the
   held view's optional `authority` list, plus (for collections) the maintainers named in the
   spec.
2. If the held manifest is legacy (no `publisher_sig`, and no v2 `publish`/`republish` with a
   `view` for this id anywhere in the ledger): the first verified signer of a `publish` (not
   `republish`) event by `first_publisher_index()`, plus collection maintainers. This is the
   **adoption** case, covered by its own rules in §6.2.
3. Otherwise (the ledger has a v2 view event for this id, but the manifest carries no valid
   statement): the manifest is `stripped`. Nobody has authority until a valid view is restored,
   and the gates refuse it.

**One canonical view per id.** A second key that publishes the same bytes is recorded in the
ledger as a publisher, so first-publisher ordering and derivation credit are unchanged. It
does not get the view. If its metadata disagrees, it publishes an artifact that cites this one,
such as a `report` or `wiki`. Allowing a view per publisher was considered and rejected: every
reader would need a rule for which tier to show, and a squatter could always add a second view
to any popular id.

**Accepting a new view.** In a range, an incoming manifest whose view differs from the held
one is accepted if and only if all of the following hold:

- its `publisher_sig` is valid
- its `addr ∈ A(id)`
- the range carries a **new** v2 `publish`/`republish` of the id by that `addr` whose `view`
  equals the incoming digest
- under `pull` only, the local trust policy accepts `addr` for the type and its key window
  covers the event

The event requirement blocks rollback: an older view, validly signed, cannot be replayed,
because its event is already at the base and isn't new. The view binding closes the
ride-along: an edit after the republish changes the digest.

**Repeated pull of the locally held view.** A second branch may carry the same authorised
republish that was already pulled through a first branch. After checking blob integrity,
ledger append-only history, signatures, view state and local trust, `pull` compares the
incoming publisher view and statement with the **local held manifest**, not only the merge
base. If they are the same authenticated view already accepted locally, it does not require
another new view event. Other incoming changes, including separately signed fields and
derived caches, still go through their own checks. A different view must satisfy every
new-view condition above. `hub check --base` applies the same principle when the checked
tree already holds that authenticated view.

**Rotation and transfer.** A view may carry `"authority": ["0x…", …]`. That list is a publisher
claim, so the view signs it. To hand over, the current key signs a view that names the new key.
The new key then signs the next view, and it may drop the old key. A separate optional
`"reproducers": ["0x…", …]` delegates only the ability to back a rebaseline stamp (§7.2);
it never grants permission to sign a new publisher view. A lost key has no in-band recovery,
by design: if a peer could re-key someone else's artifact, it could take any artifact over.
The recovery path is adoption under local trust (§6.2). Collections keep their existing
recovery path, the spec's maintainers list.

**#42's rule.** It is kept only for legacy manifests and tightened in phase 0 (§13). It is
replaced for every manifest that has carried a view.

### 6.1 What hub CI can check

`peers.json` is local, so `hub check --base` checks everything in "Accepting a new view" except
the trust clause. Signatures and authority come from the files alone, which meets the
constraint that CI must work from signatures alone.

### 6.2 Adoption of legacy and unsigned-only artifacts

The first view on a legacy manifest is an adoption. Under rule 2 it must be signed by the
legacy first publisher.

- **`hub check --base`** accepts it with a `note: adopts legacy view of <id>` line for
  maintainer review. It is the publisher's own key, so the same signature-only standard holds.
- **`pull`** additionally applies trust policy.

The gap is that legacy authority is only as strong as `first_publisher_index()`. Among
unanchored events it falls back to asserted time. That is why phase 2 asks every publisher to
backfill their own artifacts promptly (`commons manifest sign`, §12), and why an anchor makes
the claim robust.

An artifact whose only publish events are **unsigned** has no first publisher, so nobody can
adopt it in-band:

- It stays legacy and readable, labelled `UNSIGNED METADATA`.
- It is frozen except for annotations that the legacy rules allow.
- `publish --force --adopt` lets a key claim it, but only `pull --allow-adopt` accepts that,
  under local trust. `hub check` refuses it. A hub lead who wants it adopts locally and pushes
  to the hub.

## 7. The derived class

### 7.1 `fulfills` and `accepted`

**Phase 2 stops writing them into manifests and computes them from v2 events:**

- `fulfills`: a `submit` whose signed `task` and `result` name the pair.
- `accepted`: an `accept`/`settle` by the beneficiary that the task spec names.

`index_manifest()` and the graph readers (`status`, `collection show`, `list`) synthesise the
links from the ledger. They already need the ledger to fold task state.

Manifests that already carry these links keep them as a **cache**. The cache is outside the
view, so it never invalidates a signature. Readers show a cached link only when an event backs
it:

- a v2 event, or
- under the legacy rules, a v1 event after duplicate rejection.

An unbacked cached link is ignored and listed by `fsck`.

**Peers that hold manifests but not ledgers.** In this system the ledger replicates with
`registry/`, so a lazily replicated peer still has it. A party that reads a manifest file in
isolation (for example from a web view) can still check `publisher_sig` and `attested_by`. It
loses only the derived links, which mean nothing without the task state that also lives in the
ledger.

### 7.2 Rebaseline stamps

A `rebaseline` with `result=match` stops writing `provenance.run.exec` and `.rebaselined` into
the manifest. Today it rewrites the publisher's exec record. The v2 `rebaseline` event signs
`result`, `exec_mode` and `image_digest`. A `match` event may back the derived reproduction
stamp only when its recovered signer has standing: the signer is in the held view's `A(id)` or
is a reproducer explicitly delegated by that signed view. `hub check` can verify that
standing from the held view. `pull` additionally requires the signer to be registered,
inside its valid key window and trusted for this artifact type; `trust=none` fails. For a
sandbox claim, the authenticated event must contain the exact image digest displayed. A
v1-only event's unsigned `result`, `exec_mode` and `image_digest` cannot establish the stamp.
`recorded_exec(m)` may then report "recorded: X; reproduced under Y by K (rebaseline)".
The publisher's own record stays as published. A publisher who wants the new record as
*their* claim republishes.

### 7.3 `ingest` leaves the manifest

Today the stamp travels with the file, and `fsck` reads it to tell `NOT REPLICATED` from
`MISSING BLOB`. That means a peer's stamp can change how a missing blob is reported here.
Phase 2 moves it to `registry/ingest.json` and adds that file to `LOCAL_ONLY`. Until then it
is excluded from every digest (as #42 already excludes it) and ignored on incoming manifests.

## 8. Attestations (#10)

**Statement v2:**

```json
{"rc": "attestation/2", "attests": "<id>", "sha256": "<content.sha256>",
 "criteria": "<string>", "params": {<normalised verification.params>}, "observed": "<RFC 3339>"}
```

- `params` is the parsed `verification.params` map without pruning its members, or `{}` when
  absent. Thus absent params and `{}` both appear as `{}`, while `{"CHECK_COLUMNS": ""}`
  remains distinct. The key is always present, so an attestation over "no params" is a
  positive statement.
- `check_attestation` returns `stale` when either `criteria` or `params` differs from the
  manifest, as it already does for `criteria`.
- `publish --force` already refuses to change `--criteria` under an attestation. It refuses a
  changed `--param` the same way.
- An attestation authenticates the attester's observation, not a change to publisher-owned
  `verification.criteria` or `params`. Those changes still need an authorised new publisher
  view (§6). `pull` also requires the attester's peer registration, valid key window and trust
  for the artifact type before using the attestation as backing; `trust=none` cannot back an
  annotation. `hub check` checks the signature and publisher authority without local trust
  settings.

**Why not bind the publisher view digest instead?** An attestation is about an observation,
not about the title or licence. If its statement named the view digest, any editorial
republish (fixing a typo in the description) would leave every attestation stale. Binding the
fields the observation depends on (content, criteria, params) is the precise statement. The
publisher view already covers `params` against third-party edits, so #10's tamper is caught
twice: once by the view and once by the attestation.

**Republish after attestation.**

- If the content, criteria and params are unchanged, the attestation stays valid, and the
  publisher's new view simply omits it (views always do).
- If criteria or params change, the publisher must re-attest or get an attester to, and until
  then the attestation is `stale`.

**v1 statements** (no `rc`) remain verifiable:

- If the manifest has no `params`, a v1 attestation reports `valid` as today.
- If the manifest has `params`, it reports the new state **`partial`**: the signature is good
  but does not cover `params`. `verify` prints it and still exits `3`, not FAIL, because an
  honest pre-#10 attestation is not a forgery.
- The gates **fail closed on new attestations**: a v1 statement arriving in a range on a
  manifest with `params` is refused ("re-attest with a current tool").

**`attest --force`.** Any key can replace an attestation today. In future:

- A key may replace only its own attestation.
- Displacing another attester's statement needs an authorised republish, because the
  publisher decides whose attestation the artifact displays.
- Multiple concurrent attestations (`attestations: [...]`) are a natural follow-up. They are
  not needed to close #10.

## 9. Merging

`ANNOTATION_FIELDS = ("links", "tags")` union-merges conflicted manifests. That can't coexist
with signed views: the union of two signed views is a view nobody signed. For manifests that
carry a view:

- **The publisher view does not merge.** If both sides changed it since the merge base, the
  conflict is real, and `pull` aborts as it does today for other claims. If one side changed
  it, git applies that side without a conflict, and the gate (§6) has already ruled on it.
- **Separately signed fields** merge if only one side has them. If both sides carry different
  ones, that is a conflict (for `attested_by`, until a list exists).
- **Derived caches** (`fulfills`/`accepted` links) union. Readers recompute them anyway.
- **`ingest`**: ours (local).

`ANNOTATION_FIELDS` remains as-is for legacy manifests, so tags and publisher links still
union there, which keeps current federation working until those manifests are adopted.

## 10. Verification surfaces

A manifest is in exactly one **view state**:

| State | Meaning | `status`/`list`/`show` | `fsck` | `verify` | gates |
|---|---|---|---|---|---|
| `signed` | valid `publisher_sig`, signer in `A(id)` | `signed by 0x… (agent)` | OK | proceeds | accept, per §6 |
| `signed-unauthorised` | valid signature, signer not in `A(id)` | `METADATA SIGNED BY 0x…, NOT THE PUBLISHER` | problem | FAIL (1) | refuse |
| `altered` | digest mismatch or bad signature | `METADATA ALTERED — does not match 0x…'s signature`; the tier is shown struck through or marked `?` | problem | FAIL (1) | refuse |
| `stripped` | no statement, but the ledger has a v2 view event for the id | `METADATA SIGNATURE REMOVED` | problem | FAIL (1) | refuse |
| `superseded` | valid and authorised, but a later view event by `A(id)` exists in the ledger | `older view (newer: <ts>)` | warning | proceeds, with a note | refuse in a range (rollback) |
| `legacy` | no statement and no v2 history | `UNSIGNED METADATA (legacy)` | counted, not a problem | proceeds, with a note | #42 rules (§13) |
| `unknown-view-version` / `unnormalisable` | from a newer tool, or NaN | `cannot check metadata (…)` | warning | proceeds, with a note | refuse |

**Checks that run everywhere.** The view state, attestation state (`none`, `valid`, `partial`,
`unknown-signer`, `stale`, `invalid`), and derived links resolved from events.

**Why `verify` FAILs on `altered`.** The tier, criteria, params and recorded environment that
`verify` reads come from the view. Re-running a workflow and comparing against a forged
`provenance` would give a PASS that means nothing.

**`hub check` (full tree).** Every manifest with a `publisher_sig` must be `signed`, and v2
entries must verify `sig2`. With `--base`, modified and added manifests go through §6.

**Lazy replication.** No check needs the blob or the spec. The pinned-by-content
cross-checks run only where the blob is held, as they do today.

## 11. Version skew

| Who | Meets | Outcome |
|---|---|---|
| Old tool | new ledger entries | `sig` verifies as before, and `sig2`/`view` are ignored. No BAD SIGNATURE. |
| Old tool | new manifest | `publisher_sig` is ignored (readers ignore unknown fields). Displays as today. |
| Old tool **writes** to a viewed manifest: `submit`/`accept` (link), `attest` (v1) | — | The link is a derived cache, outside the view, so the view stays valid. A v1 attestation on a params manifest is refused by new gates ("re-attest"). |
| Old tool **republishes** a viewed manifest (`publish --force`) | — | Writes no statement and a v1-only republish. New tools see `stripped` and refuse it ("republish with commons ≥ phase 2"). Fails closed. |
| Old tool runs `rebaseline` on a viewed manifest | — | Rewrites `exec` inside the view, so the result is `altered`, refused. Re-run with a new tool. |
| New tool | legacy manifest, v1-only entries | `legacy` view state. #42 rules apply. v1 extra fields are hints. |
| Hub CI on an old tool | new contributions | Passes what it passes today. No regression, but none of the new checks run either. Enforcement needs the pin bump (§12 phase 3). |

## 12. Migration plan

**Phase 0: fixes that need no format change.** Land with #42 or right after it.

1. **Authenticated replay rejection (G1).** `pull`, `hub check` and the ledger readers
   (`task_events`, `ManifestEditGate._events`) use the recovered signer and v1 signed payload
   as the identity of a v1-only entry (§5.2), including when an equivalent signature encoding
   is supplied. A later v1-only replay is rejected across logs. Phase 1 adds the complete
   signed-payload identity for v2 entries; matching v1 fields alone do not collapse distinct
   v2 events.
2. **Authority (G2).** `republish` never grants authority. Authority is the first verified
   `publish` signer (`first_publisher_index`, restricted to `publish`) plus collection
   maintainers. `hub check --base` reports a `publish` event in the range for an id that the
   base already holds from a different key.
3. **`pull` enforces append-only ledgers.** Today only `hub check --base` checks that the base
   version of each log is a prefix. The replay defence assumes it.
4. **Legacy rebaseline gate.** A v1 `rebaseline` match cannot make an unregistered key an
   authorised metadata editor. For legacy manifests, require signer standing from the held
   publisher/maintainer authority before accepting an execution-record edit; `pull` also
   checks peer registration, key validity and trust scope. The claimed exec mode and image
   digest must match authenticated evidence. Since v1 does not sign those fields, a v1
   rebaseline alone cannot authenticate a changed execution record; use a fresh authorised
   republish or defer the stamp to v2.
5. **Repeated pull.** If incoming publisher fields already equal the locally accepted
   manifest, allow the second branch through after the usual blob, ledger, signature,
   authority and trust checks. For viewed manifests, apply the authenticated-view rule in
   §6. Equality with an altered or unauthorised local copy is insufficient.

**Phase 1: reader (tool 0.3.0).**

- Implement `publisher_view`/`view_digest`, `publisher_sig` verification, `sig2`
  verification, attestation v2 verification and the view states.
- Show them in `status`/`list`/`show`/`verify`; add `fsck --views`.
- The gates refuse `altered`, `signed-unauthorised` and `stripped`, and present-but-failing
  `sig2`.
- **This phase writes nothing new.** Hubs and peers upgrade their readers before anyone
  produces the data.

**Phase 2: writer (tool 0.4.0).**

- With a signing key set, `publish`/`republish`, `run --publish`, `run-task --publish` and
  `rebaseline --publish-superseding` write `publisher_sig` and dual-signed entries with `view`.
  Every other event is dual-signed.
- `submit`, `accept`/`settle` and `rebaseline` (match) stop writing manifests (§7).
- `attest` writes v2.
- `ingest` moves to `registry/ingest.json`.
- New command: `commons manifest sign [ID…|--mine]` backfills. For each held legacy artifact
  where your key is the legacy first publisher (§6.2), it signs the current view and emits a
  dual-signed `republish` with `view` and `backfill: true`. It prints the view it is about to
  sign, because you are vouching for whatever the file says now. If the current bytes are not
  what you published, fix them with `publish --force` first.

**Phase 3: enforcement, opted into per hub.**

- `.commons-hub` gains `"require_signed_views": true`. That file is hub metadata, so the
  change itself goes through maintainer review.
- With the flag set, `hub check --base` refuses any modified or added manifest that would not
  be `signed` after the change. The legacy edit path is closed there, and a legacy manifest
  must be adopted (backfilled) before anyone edits it.
- `COMMONS_REQUIRE_VIEWS=1` does the same for `pull`, mirroring `COMMONS_REQUIRE_SIG`.
- The hub pins a phase-2 tool in `hub-check.yml` before setting the flag.

**Old manifests are grandfathered indefinitely for reading**, as `legacy`. Nothing forces a
republish. Where a hub enforces views, editing a manifest requires adopting it first.

**Unsigned-only artifacts** stay legacy and frozen unless adopted under local trust (§6.2).

## 13. Where #42's rules end up

| #42 rule | Result |
|---|---|
| Authorised republish in range | **Replaced** for viewed manifests by §6 (view bound to event, authority from the held view). **Kept** for legacy manifests, with phase 0's tightened authority. |
| `fulfills` ← `submit`, `accepted` ← beneficiary `accept` | **Replaced** by derived links computed from v2 events (§7.1). **Kept** for legacy caches, after authenticated replay rejection. |
| `attested_by` ← valid attestation + `attest` event | **Kept**, applied to the separately signed class regardless of view state. Statements gain v2 and pull checks attester trust (§8). An attestation does not authorise changed publisher fields. |
| `exec`/`rebaselined` ← `rebaseline` match | **Replaced** by event-only rebaseline stamps (§7.2). Legacy manifest edits require the phase-0 standing and trust checks; unsigned v1 lifecycle fields alone never back a changed exec record. |
| Links may only be added; removal needs a republish | **Subsumed** for viewed manifests: any change to publisher links changes the digest. **Kept** for legacy. |
| `ingest` ignored | **Kept**, and in phase 2 the field leaves the manifest. |
| Ride-along gap (test §6) | **Closed** for viewed manifests. The pinned test flips to "refused" in phase 2. It stays open for legacy manifests until they are adopted, or permanently on hubs that never enforce. |

## 14. Worked examples

All four start from the #42 test fixtures: a lead L, a contributor C, a hub and phase 2
tools. L's dataset `ds-…` was published as T3, with criteria "hand-transcribed", CC0-1.0,
`restricted`. Its manifest carries `publisher_sig` by L over view digest `D0`, and L's log
carries a v2 `publish` with `view: D0`.

**(a) The #41 repro.** C's branch changes only `registry/artifacts/ds-….json`: tier T0, licence
`proprietary-internal`, obtainability `open`, the "official, verified" title, and a `derives`
link.

- `view_digest` of C's file is `D1 ≠ D0`, so the state is `altered`.
- `hub check --base` reports `PROBLEM: ds-…: metadata altered (view D1 does not match L's
  signature over D0)`. `pull` and `pull --dry-run` reject and quarantine it.
- Suppose plain `git merge` lands the file anyway. Then `fsck --views` reports a problem,
  `status` shows `METADATA ALTERED`, and `verify` exits 1.
- C's alternatives fail too:
  - C re-signs with C's own key: `signed-unauthorised`, because C ∉ A(id) = {L}.
  - C strips `publisher_sig`: `stripped`, because L's v2 event with a view exists.
  - C replays an older L view: no new event in the range, so refused.

**Ride-along variant.** L genuinely republishes, producing view `D2` with event `view: D2`. C
then commits an edit on top. The edit's digest `D3 ≠ D2` has no event, so it is refused. This
is §6 of `tests/test-manifest-edit.sh`, now refused.

**(b) The #10 repro.** This is a T3 capture with `--param status=200 --param url=https://api.example.org/x`.
It is attested under v2 (`params` is in the statement). The tamper sets `params` to
`{status: 500, url: https://evil.example.com/x}`.

- The view: params are a publisher claim, so the digest changes and the state is `altered`.
- The attestation: the statement's `params` no longer equal the manifest's, so
  `check_attestation` returns `stale`.
- `verify` prints `attester : STALE — attestation covers different params than the manifest`
  and exits FAIL (1). Before this change it reported a valid signature and exited 3.
- `fsck --views` and both gates report it as a problem.
- On a legacy (pre-view) manifest with a v1 attestation, the same tamper still yields
  `partial` plus the #42 edit gate. The gap closes completely once the publisher adopts the
  view.

**(c) G1, the accept replay.**

- In phase 0, C's copy of L's `accept` line has the same recovered signer and v1 signed
  payload as the original, even if C changes the signature's recovery-byte encoding. It is a
  replay, so the gates refuse it and readers ignore it. The `accepted` link loses its backing
  and is refused.
- From phase 2, if C instead edits `result` on a v2 line, `sig2` fails: BAD SIGNATURE. If C
  strips `sig2`, the line is a v1-only replay of a v2 original, refused as above. Two
  legitimately signed v2 `accept` events with different `result` values are distinct because
  their complete v2 payloads differ, even if their v1 signatures match.

**(d) G2, authority laundering.** Step 1 (a `republish` line with the manifest reverted) gives
C nothing: authority comes from the held view's signer (L), and in phase 0 from `publish`
events only. Step 2's view is signed by C, so the state is `signed-unauthorised` and the gates
refuse it. If C crafts a `publish` line in step 1 instead, with a backdated `ts`, the phase 0
legacy rule makes `hub check --base` flag it ("publish of already-held ds-… by a different
key"). Under views it would grant nothing anyway.

## 15. Residual risks and open questions

- **Attribution is not truth.** A signed `generation.attestation: tee` is the publisher's
  signed claim that a TEE was involved, not proof of it. Diversity quorums still count it.
  Receipt- or TEE-backed family claims need their own separately signed statement, analogous
  to §8. This is a follow-up and out of scope here.
- **Legacy authority leans on `first_publisher_index()`**, which falls back to asserted time
  among unanchored events. Prompt backfill and anchoring are the mitigation. Neither is a cure.
- **Lost keys** have no in-band recovery (§6). This is deliberate. Is adoption under local
  trust enough for hubs, or does a hub need a maintainer set that can re-key artifacts? That
  would be a new authority and needs its own design.
- **Concurrent legitimate views.** With an `authority` list of more than one key, two keys can
  republish concurrently. §9 makes that a merge conflict, and resolving it is manual. Is that
  acceptable, or should views carry a `prev_view` digest so that a fork can be detected
  explicitly?
- **Multiple attesters.** `attested_by` stays a single slot. Is an `attestations` list needed
  before the pilot hubs publish T3 captures with capture metadata?
- **Float canonicalisation** is defined by Python's `repr`. A second implementation must match
  the test vectors.

## 16. Implementation checklist

These are separate PRs, in this order:

1. **Phase 0** on top of #42:
   - authenticated v1 replay rejection, tightened authority, `pull` append-only
   - tests for G1 and G2 (the two repros in §2.2), alternate recovery-byte encodings, an
     unregistered rebaseline with a missing signed image digest, and a second locally equal
     pull; update `tests/test-manifest-edit.sh`
2. **Phase 1:**
   - `publisher_view`, `view_digest`, view states, `sig2` and attestation v2 verification
   - `tests/test-manifest-view.sh` with **fixed test vectors**: a manifest, its view, its
     digest, and the statement and signature from a fixed test key. Cover empty vs absent, set
     ordering, duplicate-id `provenance.inputs` order, an empty comparator parameter,
     non-ASCII, floats, an unknown field (default-include) and an unknown view version.
3. **Phase 2:**
   - the writers, `manifest sign`, derived links, `ingest.json`
   - flip the ride-along test in `tests/test-manifest-edit.sh` §6 to "refused"
   - the #10 repro as a test
4. **Phase 3:** `require_signed_views` and `COMMONS_REQUIRE_VIEWS`, plus hub docs.

### Acceptance criteria from #41, mapped

| Criterion | Where |
|---|---|
| Every field classified, with a reason | §3 (and the default-include rule for unlisted fields) |
| One normalisation and one signing format, precise enough to test | §4, §5, and the test vectors in §16 |
| Migration path for old manifests and old tools | §11, §12 |
| #42 rules placed explicitly | §13 |
| Worked examples: #41 and #10 repros refused | §14 (a), (b) |

### Brief questions, mapped

Q1 normalisation: §4. Q2 signing contract and skew: §5, §11. Q3 multiple publishers and
authority: §6. Q4 the derived class: §7. Q5 the attestation statement: §8. Q6 merging: §9.
Q7 verification surfaces: §10. Q8 migration: §12. Q9 lazy replication: §5.1, §7.1, §10.

**Out of scope**, as in the brief: transport, anchors, trust policy and #14, except that
duplicate rejection and `pull`'s append-only check (phase 0) sit next to #14 and should land
compatibly with it.
