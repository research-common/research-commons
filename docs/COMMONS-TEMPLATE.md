# COMMONS.md: template and review rubric (1.0)

A project's `COMMONS.md` is its **integration contract** with Research Commons: which of its datasets and analyses
are candidates to publish, as which kind of statement, with which disclosures, into which hub, and what still blocks
them. It is the project-side counterpart of a collection's editions.

**Who writes what.** The project's domain owner (human or agent) **writes** `COMMONS.md`, because only they know how
the data was produced and where it is wrong. A Commons maintainer **reviews** it against the format and appends a
dated verdict. The review checks that each statement will claim only what the format can show; it never
re-litigates the domain facts.

Keep it short and stable, like an index. Long rationale belongs in the project's own notes, linked from here. The
fields below are the 1.0 format's own (claims-model note §4, §5.3, §7, §8; wire-format note §5); the rubric says
which design-note rule each one answers to.

---

## Template

```markdown
# COMMONS.md: <project>

- **Owner:** <person/agent>  ·  **Last reviewed:** <YYYY-MM-DD | never>
- **Target hub:** <repository | none yet>  ·  **Audience:** <public | named collaborators | private>
- **Signs as:** <identity id + grant id | bare key> (one key per audience: a key that signs private work never
  signs public work, so a hub can take a key's whole log)
- **Collection(s):** <resource id | proposed name>  ·  **Controllers:** <keys/identities and rule>
- **Plan / rationale:** <link>

## Datasets

### <short-name>
| Field | Value |
|---|---|
| Path(s) · writer | where the bytes come from, who writes them, and the invariant (e.g. "append-only, one row per block") |
| Statement kind | `observed` (captured from a source) · `authored` (made here, incl. derived) |
| Class (observed) | `exact-bytes` · `source` · `phenomenon` · `method` · `none-yet`: what a second, independent observation could share with this one. One class per blob: a capture mixing classes is published as separate blobs |
| Referent (observed) | what it pins. exact-bytes: CAIP-2 chain id, block **hash**, depth. source: endpoint + parameters + response digest, or a request log (`rc-request-log/1`) for a batch; window. phenomenon: instrument, `geo:` location, time. method: method edition, environment, measured system, inputs, window |
| Capture evidence (observed) | `self-asserted` · `anchored-at-capture` (an `anchor stamp` at capture time) · `witnessed` · `device-attested` |
| Finality (observed, exact-bytes/source) | rule (`confirmations >= N` or `run >= L`), its source (a held policy document, a location, or the observer's convention), the state at capture; or "none: the source never revises" |
| Provenance (authored) | workflow spec + every input pinned by digest, or why not (an unpinned input makes it `provenance_partial`: no derivation group) |
| Replication | `bytes` (a public deterministic source, named) · `protocol` (re-measurable, never the same bytes) · `none` |
| Sampling | n with its unit, per-group n, window, dispersion; or n/a |
| Shelf life | days the data stays valid for its purpose; or n/a |
| Licence | SPDX expression, or a `LicenseRef-` id with its text cited; third-party data keeps its owner's terms |
| Availability | redistribution `permitted` / `restricted` / `withheld` (+ until when), and whether a peer can obtain the bytes |
| Forbidden keys / PII | the fields the exporter strips (identifiers, account ids, balances tied to people, CSV headers included) |
| Growth · size | immutable snapshot · growing series (a `series` resource whose editions list segments as members with role `segment`, plus `frozen_before`) · overwrite-in-place (must become editions); largest blob and total size |
| Known DQ issues / errata | duplicates, gaps, migrations, re-bases, with dates and the fix |
| Status | candidate · blocked (<reason>) · published (<statement ids>) |

## Analyses (workflows, syntheses, reports)
One line each: `authored` type, what it derives from which datasets (by digest once published), determinism notes,
the grade a re-derivation could reach (T0 byte-identical · T1 under a comparator · T2 rubric review), status.

## Collections
For each: name, controllers and rule (and who holds each subject: see R13), selection (`curated` · `rule-based` ·
`completeness` with class, source and window), member roles, and how members are added.

## Holdbacks
What is deliberately NOT published, and why (strategy, privacy, third-party terms, known-wrong methodology).

## Decisions pending (human)
Mirror each into wherever the project tracks decisions that need a human.

## Review (YYYY-MM-DD)
<appended by the Commons maintainer; see the rubric>
```

---

## Review rubric (for the maintainer)

For each dataset and analysis, mark each criterion **ok / fix / n.a.** and give a one-line reason for anything other
than ok.

| id | Criterion |
|---|---|
| R1 kind & class | Captured bytes are `observed`, made bytes `authored`. The class matches what a second observation could actually share (§5.3.1): byte equality is claimed only for an exact-bytes referent, and an API read is `source`, not exact-bytes. An exact-bytes blob is *the* bytes at its block (a block, a receipt set, a state proof), so any second honest capture of that referent is byte-identical. A filtered extraction (the logs of one contract over a block range, a parsed or re-serialized table) is not: two honest extractions at one block hash differ, and the reader reads them as contradicting each other. Publish an extraction as `source` (with its request log) or `method`, or publish one exact-bytes blob per referent with its query and canonical form stated beside it, so a second observer can reproduce the bytes. One class per blob. |
| R2 referent | Every field the class requires is pinned, so the referent does not show `unpinned`. Chain data pins the block hash, not the height. A batch API capture carries its request log inside the content, with responses held. |
| R3 capture evidence | The declared level is what was done: `anchored-at-capture` only with an anchor stamped at capture; `witnessed` only with the witnesses' own `observed` statements. The reader shows what it verified, not what was declared. |
| R4 finality | A source that revises (a chain below depth, a settlement run) declares its rule and where the rule comes from. A growing series declares `frozen_before` no later than its members' finality; a hub may refuse a premature freeze. |
| R5 provenance & grade | A derived artifact carries provenance with every input pinned, or says why it is partial. No analysis implies a stronger grade than its derivation supports, and a result resting on observations shows them as observation leaves, not a tier. |
| R6 licence | Stated for material the project owns; third-party data isn't relicensed. The tool never assumes a licence: an undeclared licence displays as undeclared, and the doc treats that as a blocker. |
| R7 availability | Redistribution and obtainability are stated separately. `withheld` names its reveal condition; a low-entropy withheld commitment includes a nonce. |
| R8 forbidden keys / PII | Identifiers and PII are listed, including CSV headers, and the exporter strips them before publishing. The tool's content scan looks for secret shapes; it is not a PII check, and edition rules are not yet evaluated (no rule dialect ships), so nothing downstream catches an identifier. |
| R9 growth & size | A growing series is a `series` resource whose editions add segments (members with role `segment`), never a blob rewritten in place. Blobs fit the hub's limits (`commons status --limits`; one blob 1 GiB by default, archive scans 512 MiB). |
| R10 disclosures | Sampling is declared where a result is statistical; replication says `bytes` only when the deterministic public source is named; shelf life is set where the data ages. Declared values are shown beside what a reader computes, never in place of it. |
| R11 DQ disclosure | Known duplicates, gaps and migrations are disclosed with the fix or erratum. Publishing known-bad bytes needs a stated reason. |
| R12 determinism | Workflows pin their inputs and environment, sort outputs, keep wall-clock time out of outputs, and use no network in steps (a workflow that needs the network publishes `observed`). |
| R13 signing & control | The doc names who signs: a bare key, or an identity and the grant it acts under. A key signs for one audience only. Collections say what a lost or stolen root does to them: controlled by one identity alone, a root compromise ends the collection (recovery is a successor collection, stated in the doc); with an independent second subject (a different custodian, or a different device and seed) under `any_one`, the other subject recovers it after the root is revoked; under `k_of_n` 2 (best: 2 of 3 with one subject cold) no single theft captures it. A second subject on the same seed is not independent. |
| R14 gaps upstream | Anything the format can't express yet is recorded as a tool issue, not worked around silently. |

**Verdict:** `ready` (publishable once the human decisions land) · `ready-with-fixes` (list them) · `not-yet`
(blocking criteria). The review is advisory: what a hub admits is its own CI and policy, and what a reader trusts
is that reader's policy.

---

## Coming from an alpha COMMONS.md

The 0.4 alpha template asked different questions. Rewrite rather than translate, but these map:

| Alpha field | 1.0 |
|---|---|
| Tier T3 (attested capture) | `observed` + class + referent + capture evidence. Observations are not a tier. |
| Tier T0/T1/T2 | A derivation grade, computed by each reader from re-runs and reviews; never declared by the publisher. |
| Obtainability | `availability`: redistribution and obtainable, separately. |
| Growth model + partitioning | A `series` resource (segments are members with role `segment`, plus `frozen_before`), or immutable snapshots. |
| Collection id (`cl-…`) | A resource id (the genesis statement's id) with editions. |
| "`push` requires licence + obtainability" | No such gate in 1.0. A hub may set its own policy; the review treats a missing licence as a blocker. |
