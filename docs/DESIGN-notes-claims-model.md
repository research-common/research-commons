# Design note: invariants and the claims model

**Date:** 2026-10-11 · **Status:** request for comments. Nothing here is decided or implemented.
**Tracking issue:** #69
**Builds on:** #43 (field classes and statement identity), #57 (anchor trust), #59 / #60 (receiver-local
Bitcoin verification, which priority between rival authors depends on)
**Scope:** the next format of Research Commons. This is a clean break from the alpha (§14): no compatibility
layer, no importer, no migration phases.

## 0. Summary

> **The tool verifies signatures and bytes. Everything else is a signed claim with evidence attached, weighed
> by rules the reader chooses.**

- **Content is a fact; statements about it accumulate.** A blob is identified by its full hash and has no owner.
  Every statement about it (authorship, licence, observation, reproduction, criticism) is signed by one key, in
  that key's own log. No key can overwrite or freeze another key's statements. There is no shared mutable
  manifest. Each reader computes its own view.
- **Observations and constructions answer different questions.** For a constructed artifact (a workflow, a
  synthesis, a derived table), the author is claiming to have made it first, and verified publication time
  settles rival claims. For an observation, the question is whether it reflects the world. That is answered by
  corroboration and capture evidence, which accumulate and can change in either direction.
- **Grades and disclosures are separate.** T0–T2 rank how a result was derived. Licence, availability,
  sampling, shelf life, capture evidence, corroboration status and curation are disclosed *beside* the grade.
  None of them moves it.
- **Policy is local.** Trust, admission, execution and reference data are chosen by each reader. The project
  ships no reference sets and no reputation scores. Nothing a peer sends can change a reader's policy.
- **Uncertainty is a state.** Contested, unknown, unchecked and unsupported are visible, non-passing states,
  never silent passes and never hard refusals.

## 1. What the system is for

Research Commons exists to make **agreement mean something** between parties who share no administrator. A
published result should be re-derivable by a stranger. A label (grade, licence, "accepted", "corroborated")
should be backed by evidence the reader can check. Independent confirmation should be distinguishable from
copying. Hubs, collections, the task exchange and anchoring all exist to serve these three properties.

There is no trust root. Each reader decides whom it trusts and which rules turn shared data into an
understanding of the world. The design's job is to make that choice informed, by showing what was checked,
what was taken on someone's word, and what is missing.

### 1.1 Non-goals

Triage can decline these with a citation to this section.

- **Not a consensus system.** There is no global order of events and no global truth about who was first or
  who is right.
- **Not a rights registry.** A signed licence is the signer's assertion; the tool cannot know who holds the
  rights.
- **Not a truth arbiter.** The tool never treats majority agreement as correctness (§6.4).
- **Not an erasure system.** Retraction is a signed request; copies elsewhere persist.
- **Not an identity system.** A key is an identity. Names, reputation and credit are projections a reader
  computes over the ledger.
- **Not a discovery network.** Hubs are found by convention, not protocol.

## 2. Actors and threats

| Actor | Can | Cannot |
|---|---|---|
| **Issuer** (any key holder) | sign statements in its own log about any artifact; publish any bytes | write into another key's log; make its statement read as another key's |
| **Relayer** (hub, mirror, peer) | omit statements, reorder delivery, present a partial history, refuse to carry anything | alter signed bytes undetected; forge a signature |
| **Curator** (hub maintainer) | choose what its hub admits; publish its own statements | change what other hubs or readers hold; speak for an author |
| **Reader** | set its own trust, admission, execution and reference policy; compute its own view | change another reader's policy |

**Threat model.** Assume peers, hubs, archives, workflow specs, timestamps, names and model outputs may be
hostile. Attackers can create many keys, copy public bytes, sign their own assertions, replay or withhold
statements, fork histories, send oversized or deeply nested data, and run a compromised hub. Honest parties go
offline, skew clocks, crash mid-write and lose caches. Cryptographic primitives and the reader's own machine are
assumed sound. A signature remains a valid signature after its key is judged compromised; whether to rely on it
is a policy question.

**What omission means.** With every statement signed, a relayer's only remaining lever is withholding: a
retraction, a contradiction, a newer edition. A reader cannot prove something it never received does not
exist. Readers with different histories legitimately know different things. Given the same statements, policy
and evaluator, they MUST compute the same answer. No reader may claim completeness it cannot demonstrate
("no contradictions *that you hold*", never "no contradictions").

## 3. Invariants

Grouped in priority order. When two conflict, the higher group wins **visibly**: the resolution is a third
state (§3.1), never a silent violation of the lower one. The ordering is a tie-breaker for design arguments, not
a licence to drop a guarantee.

### Integrity

- **I1 Content is self-certifying.** Identity is the full hash of the exact bytes. Short ids are display
  aliases; an ambiguous alias is an error that lists candidates, never a guess.
- **I2 Attribution.** Every displayed value is either a specific key's signed statement, with a pointer to it,
  or the reader's own computation. No unsigned field is ever shown as anyone's word.
- **I3 Per-key append-only history.** A key's log is a hash chain only that key extends. Nobody rewrites,
  reorders or relocates another key's lines. Corrections are new statements.

### Honesty

- **I4 No false assurance.** No surface shows a state stronger than the reader's evidence supports. Missing,
  unsupported, unverified, contested and unchecked never read as pass, for humans or for exit codes.
- **I5 Evidence is retained; irrelevant additions don't interfere.** Adding a statement that has no bearing on
  a claim's signature, authority or the reader's policy predicate cannot change that claim's result. Relevant
  new evidence (a verified proof, a revocation, a contradiction) may change a result in either direction. The
  earlier evidence stays visible, and the change cites its cause.
- **I6 Disclosure never grades.** Licence, availability, replication mode, sampling, shelf life, capture
  evidence, corroboration status and curation are shown wherever a grade is shown. They never move the grade or
  a verification exit code.

### Fairness

- **I7 No third-party veto.** A key with no authority over a statement or resource cannot invalidate it, freeze
  its author, or wedge federation by publishing something. A reader may still choose to rely on a critic it
  trusts, and may refuse a package for its own reasons. That is policy (I9), not a veto.
- **I8 Refusals have standing and scope.** A hard refusal comes only from intrinsic invalidity, the reader's
  own policy, or an operational limit, and it names which one and what it covers. Refusing a package is not a
  verdict on the valid statements inside it.

### Sovereignty and time

- **I9 Reader sovereignty.** Trust, admission, execution, subscription and reference choices are local. Incoming
  data cannot change them or authorize its own elevation. A policy change is authorized by the policy it
  replaces, never by keys the new policy introduces.
- **I10 Time grants priority, never authority.** Time evidence can order rival claims to have made something
  first (§5.2), but only at a quality the reader verified itself. Time never confers ownership, edit rights or
  independence. Self-declared timestamps order nothing that matters.

### Legibility and robustness

- **I11 Honest limits.** Every known gap is documented where users read, and pinned by a test that fails when
  the gap closes.
- **I12 One definition per concept.** Each concept (authorship, priority, edition lineage, task state, grade,
  corroboration status, admission) has one implementation that every surface calls. Two surfaces disagreeing
  is a bug by definition.
- **I13 Outputs are a contract.** Exit codes and status tokens form a closed, documented vocabulary. A script
  gets the same answer the prose gives.
- **I14 Explainable, order-independent answers.** Every derived answer can be explained from identified
  statements, policy, evaluator version and time context. Transport order, file order, duplicates and cache
  state never change it.
- **I15 Hostile input and partial failure stay contained.** Malformed data, crashes, races and resource
  exhaustion never produce valid-looking state, and never read or write outside the reader's approved
  boundary. This includes everything the host does before and after a sandboxed step (#67).

### 3.1 The third state

When honesty and fairness pull apart (an artifact two keys both claim to have authored first, an observation
with corroborations on both sides), the answer is neither silent acceptance nor refusal. It is a **visible,
non-blocking, non-passing state**: admit and label on write surfaces; show `contested` or `unknown` with a
non-pass exit code on read surfaces.

## 4. Data model

| Layer | What it is | Identity | Who can change it |
|---|---|---|---|
| **Content** | immutable blobs | full hash | nobody |
| **Statements** | signed lines, one claim each, in the signer's own log | hash of the canonical signed body | nobody; the signer may supersede its own |
| **Views** | each reader's resolution of the statements it trusts | computed | the reader recomputes them |

Hubs carry content and statements. They do not carry views. A per-artifact manifest, if a tool keeps one, is a
local cache rebuilt from statements, never transported and never authoritative. The question "who may edit the
manifest" disappears because no one does.

**One signature over everything.** A statement is signed over its entire canonical body plus a domain tag. No
field rides outside the signature, so relayers have nothing to rewrite. Equivalent signature encodings of one
body are one statement. Canonical encoding, field names and test vectors belong to a wire-format note (§15).

**Statement kinds.** The vocabulary is closed. An unknown kind may be stored but grants nothing.

| Kind | Signed by | Says |
|---|---|---|
| `authored` | the author | "I made these bytes." Carries the author's single-party fields: licence, availability, verification spec, description, and provenance (workflow + inputs) when derived. For a construction, it is a first-to-publish claim (§5.2). The same key's later `authored` statement on the same blob amends its earlier one. |
| `observed` | the observer | "I captured these bytes." Carries the referent, capture record, capture evidence and the observation class the observer asserts (§5.3), plus the same single-party fields. |
| `holds` | anyone | "I have these bytes and serve them." Mirroring, with no authorship and no agreement. |
| `describes` | anyone | Open annotations: tags, notes, non-evidential links. Shown as the signer's, ranked by the reader's trust. |
| `reproduced` | anyone | "I re-ran this": match / diverged / not comparable, with environment record, including a successor workflow that reproduces the same outputs (#22). |
| `corroborates` | anyone | Points at a corroboration result (§5.3.2): supports / contradicts / inconclusive under a named agreement model. |
| `refutes` | anyone | "This premise or result is wrong", with the evidence artifact. |
| `retracts` | the author | A recall request for the author's own artifact. |
| `anchors` | any key, own log | Time evidence for that key's own log prefix (§10). |
| resource editions | resource controllers | Collection and task editions (§8). |
| lifecycle | task participants | Intent, progress, withdrawal, submission, decision (§9). |
| key events | the key | Rotation and revocation. |

Lineage links that carry meaning (`supersedes`, `extends`, `fulfills`, evidence links) are fields of signed
statements, never free-standing metadata.

## 5. Authorship, priority and observation

Artifacts fall into two categories that answer different questions.

| | **Constructions** | **Observations** |
|---|---|---|
| Examples | workflows, skills, syntheses, reports, derived datasets | sensor readings, chain state, API captures, benchmark runs, field measurements |
| The author claims | "I made this, first" | "I saw this, and it reflects the world" |
| Settled by | verified publication time | corroboration and capture evidence, accumulating over time |
| Identical bytes from a second key | a later claimant (or a copy) | usually a copy; in the exact-bytes class, a possible corroboration (§5.3.1) |

### 5.1 Single-party fields

Licence, availability, verification spec and description are **single-party**: the default display comes from
one key's `authored` or `observed` statement, chosen by the rules below. Rival values from other keys are always
listed with their signers and never silently dropped. A consumer that needs certainty pins a specific
statement rather than relying on the default.

### 5.2 Constructions: first to publish

1. **Sole author.** Exactly one key has a verified `authored` statement for the blob, so its single-party
   fields are the default.
2. **Priority.** Several keys claim authorship. The one whose `authored` statement has the earliest
   time bound *at a quality the reader verified itself* (§10), strictly earlier than every rival, is the
   default. The others are listed as later claimants.
3. **Contested.** Otherwise: every claimant is listed and the state is `contested`.

To make priority hold up against copying, `publish` anchors the statement before the bytes leave the author's
machine. A copier who sees the push cannot get an earlier verified bound. Until readers can verify Bitcoin time
evidence locally (#59), every multi-author construction is honestly `contested`.

Priority is credit for publishing first. It is not evidence that the earlier author worked independently, or
that a later one copied. Independence is a separate question with its own evidence (§9.3).

### 5.3 Observations

An observation is the observer's signed assertion that these bytes record something that happened. Two separate
questions apply, on two separate axes:

- **Capture provenance:** were these bytes captured as claimed, by this observer, from this source, at this time?
- **Corroboration:** does what they say match the world?

These fail independently. An honest observer with a broken sensor has good provenance and poor corroboration.
A fabricator who copies a neighbour's feed has poor provenance and excellent corroboration.

#### 5.3.1 What a second observation can share

Every observation sits on a spectrum of third-party checkability. Classify it by what a second, independent
observation could have in common with it:

| A second observation shares… | Example | Agreement looks like | How checkability decays |
|---|---|---|---|
| **the exact bytes** | chain state at a pinned block hash (#7) | byte equality; any reader can re-read it from its own node | a fork orphans the block, temporarily or permanently |
| **the source** | a third-party API read | equal or near-equal responses around the same time | the source changes or disappears |
| **the phenomenon** | a weather station; a field measurement | agreement under a declared physical model (distance, elevation, tolerance) | the moment passes, but other observers' records of it remain |
| **the method** | a benchmark batch; a network economics measurement (#1, #65) | statistical comparability under a pinned protocol | the measured system drifts (#4) |
| **nothing yet** | a one-off log | none so far | n/a; this is a status, not a class |

Rules:

- **The observer asserts the class; evidence decides its status.** "This is consensus data" is the observer's
  belief. Whether it holds is computed from other observations and from the reader's own re-checks.
- **The observation pins its referent.** For chain data that means chain id, block hash (not height) and
  confirmation depth at capture. For APIs: endpoint, parameters and response hash. For instruments: instrument
  identity, location and time. A fork or a vanished API does not make an observation false. It is still true of
  what it pinned. What changes is whether the referent is still canonical or still available, and that is
  shown separately. It never counts against the observer.
- **Identical bytes mean different things per class.** For most classes, a second key publishing the same bytes
  is a copy. Only in the exact-bytes class is re-reading the same source a corroboration, and it still needs
  its own `observed` statement with its own capture record.

#### 5.3.2 Corroboration is a derivation

A corroboration is an ordinary derived result: a workflow whose inputs are the original observation plus
comparison data, run under a declared agreement model. Its output is `supports`, `contradicts` or
`inconclusive`, per record where that makes sense. Because it is a derivation, anyone can re-run it, and its
grade reflects how it was computed. No new trust mechanism is needed.

- **Comparison data can be other observations or reference data.** A reading of 120 °F in Denver fails a
  climate-record or physical-bounds check before any neighbouring station is consulted.
- **Cohorts are chosen by rule.** A corroboration states "every station in collection R within 50 km and 200 m
  elevation", not "these three stations". Anyone can re-apply the rule to R and see what was left out.
  Hand-picked cohorts are allowed and labelled `cohort: hand-picked`.
- **Agreement isn't independence.** Each corroboration declares what it shares with the original: upstream feed,
  operator, instrument model. Two "stations" scraping one upstream feed are one source. Distinct keys prove
  nothing about independence.
- **Timing is open.** Corroboration can be concurrent (others observing in parallel) or retrospective
  (re-reading a chain, re-running a protocol, gathering other records of the same moment).

An observation's **corroboration status** is computed per reader from the corroborations it holds and trusts:
`corroborated n · contradicted m · unchecked`, always scoped ("within statements you hold"). Disagreement is
symmetric. If Denver says 120 and two neighbours say 85, the status is "contradicted by 2 under model M", and
the tool does not decide which side is wrong.

#### 5.3.3 Capture evidence

No mechanism proves that an observer saw what they claim. Each level of capture evidence changes *whose word*
the reader relies on, and makes fabrication more expensive:

| Level | Adds | Does not prove |
|---|---|---|
| **self-asserted** | the observer's signed word | anything beyond the observer's honesty |
| **anchored at capture** | the bytes existed by time T, which rules out later fabrication with hindsight | that they were captured rather than invented before T |
| **witnessed** | simultaneous observers co-sign, each with its own `observed` statement | that the witnesses don't collude or share a feed |
| **device-attested** | a specific sealed device (secure hardware, TEE) produced the bytes | that the sensor saw reality; trust moves to the manufacturer's attestation root and the sensor's physical integrity |

The observer declares a level. The tool displays only what it verified: an attestation the reader cannot verify
shows as `device-attested (unverified)`. Agent-operated captures (#17) record roles explicitly: the signer who
vouches, the operator (human or agent) who ran the capture, and the instrument or source. One key need not
stand for one person.

### 5.4 Reputation

Reputation is a projection a reader chooses: for example, an observer's corroboration record against sources
unrelated to it, over a window, under rules the reader picks. The tool computes projections on demand and ships
none as defaults. A well-corroborated track record legitimately earns weight for the reading nobody else could
have taken. That is the honest place for "trust this observer" to come from.

## 6. Curation and hubs

A hub is controlled by one person or organization, who chooses what it admits. A hub can be curated toward any
conclusion, including far outside mainstream evidence. Curation doesn't forge anything; it **selects**. It admits
supporting corroborations, omits contradictions, and picks comparison cohorts that agree. Every signature checks
out, and the picture can still be false. The design makes selection visible and checkable. It does not try to
decide who is right.

1. **Status is always scoped.** "Corroborated by 3 *within this hub*" is the display. A hub cannot show a
   stronger state than its own holdings support (I4).
2. **Statements travel independently of hubs.** A contradiction is a signed statement about a specific
   observation id. A reader who follows several hubs sees contradictions held elsewhere next to the curated
   hub's corroborations. A curator controls admission to its hub, not the existence of evidence.
3. **Selection is disclosed beside the grade.** A hub or collection declares how it selects: `curated` (the
   curator's judgment, the default), `rule-based` (a published inclusion rule others can re-apply), or a
   `completeness claim` ("every reading from source X in this window", which can be checked and refuted).
4. **The reader brings the references.** A reader can re-run any corroboration against reference data *it*
   trusts. The project ships **no default reference collections**: they are ordinary collections that anyone
   may curate and readers choose among, consistent with categories being convention rather than protocol (#16).

The tool encodes no "consensus is correct" rule. A genuine anomaly looks exactly like an outlier until more
evidence arrives, and a tool that suppressed outliers would be worse than one that labels them. The success
criterion: a fringe hub cannot *look* stronger than its evidence. A reader who follows only that hub and trusts
only its keys will still be persuaded by it. No design that leaves trust to the reader can prevent that, and
this note says so plainly.

## 7. Grades and disclosures

**Grades rank derivation.** T0 (byte-identical re-derivation), T1 (agreement under a declared comparator), T2
(independent review against a rubric declared before work began). A result's chain grade is its weakest
derivation step. Methods (workflows, skills) are not graded. A refutation is graded on its own derivation and
is exempt from the weakest-link rule.

**Observations are not a tier.** An observation leaf shows its class and its current evidence (§5.3) instead of
a single "T3". A result derived entirely from exact-bytes observations can be re-derived all the way down from
the source.

**Disclosures sit beside the grade, never inside it (I6):**

| Disclosure | Values |
|---|---|
| licence | SPDX expression, `LicenseRef-*`, or explicit non-open terms; attribution notice (#6, #19). Missing means unknown, not open. |
| availability | redistribution permission and byte obtainability, separately |
| replication | `bytes` (public deterministic source named) · `protocol` (re-measurable, never the same bytes; method named) · `none` · undeclared (#1, #7) |
| sampling | n, dispersion, window (#2) |
| shelf life | publisher-declared validity; age shown at read time (#4) |
| capture evidence | §5.3.3 level, verified or not |
| corroboration | §5.3.2 status, scoped |
| selection | curated · rule-based · completeness claim (§6) |
| referent status | still canonical / source still available / unknown |

`run --publish` accepts every disclosure that `publish` does (#21). Defaults for licences are documentation only;
the tool never assumes one silently.

## 8. Resources: collections, tasks, series

Collections, tasks and growing series change over time. They are **resources** with a permanent id and
immutable editions.

- **Genesis.** A resource is created by a genesis statement naming its controllers and their rule (any one, or
  k of n). Its id is the hash of the genesis statement.
- **Editions.** Each edition is a signed statement by a controller that references its predecessor by hash. It
  carries the full contents: members with roles, member schema (#5), ingest rules, task contract.
- **Controller changes** are editions authorized under the *previous* edition's rule. Nobody elevates
  themselves.
- **Forks are visible.** Two editions with the same predecessor are a fork, shown as one. No timestamp or file
  order picks a winner; controllers resolve it with a merge edition.
- **Outsiders fork.** A non-controller who wants a different collection creates a new resource, which may
  declare `forked-from`.
- **Membership is endorsement.** Only the collection's editions add members. A member's own "part of" claim
  confers nothing, and a laxer collection's rules never apply to members of a stricter one.
- **Bindings are to editions.** Claims and submissions bind to the task edition they accepted. A later edition
  never changes the terms retroactively. Endorsing a task in a collection doesn't change either one's id
  (#54).
- **Growing series** (#8) are resources whose editions append segments, with an explicit `frozen_before`
  boundary when recent data is still being revised.

## 9. Research exchange

### 9.1 Tasks and coordination

A task contract pins the question, required inputs and methods, acceptance rubric or comparator, eligible
evidence, decision authority, quorum requirements and deadlines. **Claims are advisory intents, not locks.**
They make work visible without excluding independent attempts. A partition-tolerant global lock is impossible,
and the design doesn't pretend otherwise. Liveness reports (heartbeats) are evidence of activity, not lease
renewals. A task that truly needs exclusion names a coordinator, whose signed grants are the only thing that
counts. Submissions are always admissible.

### 9.2 Settlement

A **check** computes readiness; a **decision** is the beneficiary's signed acceptance or rejection, citing the
exact submissions and evaluations. A decision is that beneficiary's judgment, not a global scientific verdict.
Contradictory decisions remain a visible conflict until a later decision explicitly supersedes one. Timestamps
and file order never pick between them. A task with no quorum is settled "by review, not by counting", and
`publish task` says so up front.

### 9.3 Independence and quorums

A quorum predicate states eligible issuers, deduplication, required evidence strength, any independence
constraints, and how results are grouped. The design does not infer independence from:

- first publication of a hash (§5.2 grants priority, not independence);
- a commit-reveal match: committing to a salted hash shows possession by time T, but anyone can commit to a hash
  that is already public;
- distinct keys, which are not distinct people, organizations or models;
- model-family or `receipt`/`tee` labels, unless an implemented verifier checks a bound proof.

Where required independence can't be established, readiness is `unknown`, not a smaller count. A task may
accept self-declared independence, and its outcome then says so.

**Grouping is explicit.** Byte equality is transitive; tolerance is not, so a comparator quorum names its
grouping rule (reference-based or all-pairs) rather than chaining "close enough". Stochastic replication (#65)
pins an estimand and a test in the contract. Overlapping confidence intervals are not equivalence. Genuine
divergence stays visible as its own report.

### 9.4 Refutation and pre-registration

Refutations and failed reproductions are first-class submissions, credited on their own track. A
**pre-registration** (#3) is a task authored by its own beneficiary, published with its design and validity
rule before the data. Results that fulfil it display "pre-registered" with the bound at verified quality. A
pre-registration proves the plan existed by time T, not that the author hadn't seen the data.

### 9.5 Credit

Credit is a projection: contribution, citation, reproduction, review, corroboration and acceptance are counted
separately, under rules the reader chooses, with denominators shown. No transferable entitlement is created.

## 10. Time

- **Bounds are per signer.** An anchor bounds only the signer's own log prefix. Every key anchors its own
  statements.
- **Quality.** `local` = signed and self-consistent, but self-declared. `bitcoin` = the *reader* verified the
  proof against block evidence it trusts (#59). A label in a file grants nothing.
- **Publish anchors first.** Anchoring happens at `publish`, before the bytes leave the author's machine.

| Use | Local quality | Bitcoin quality |
|---|---|---|
| priority among rival authorship claims for a construction (§5.2) | no | yes, if strictly earliest |
| "existed by T" for capture evidence and pre-registration | shown as `(local, self-declared)` | shown as a time |
| ownership, edit rights, independence | never | never |

Timestamps more than a few minutes in the future of the writer's clock are refused at write time. A line whose
timestamp precedes the line it chains after is flagged incoherent, and its bound is discarded.

## 11. Federation and gates

- **Only signed statements enter a hub.** Unsigned work is a local draft that cannot be pushed, whatever its
  type (#14, #24). Generating a key is part of first-run setup.
- **One validation core.** `pull`, hub CI and `push` call one validation function. They differ only in what
  history they hold and whose policy applies (I12).
- **Refusal classes (I8).** *Intrinsic:* hash mismatch, bad signature, malformed statement, a line in another
  key's log, rewritten history, unsafe paths, anything outside the data surface. *Reader policy:* trust floors,
  executable admission, hub rules. *Operational:* size and resource limits. Everything else is admitted and
  labelled.
- **Data never carries control.** Incoming trees cannot carry code, hooks, configuration, trust lists or policy.
  Hub CI reads the hub's policy from the base revision, so a pull request cannot grant itself anything.
- **Admission is not execution.** Holding executable bytes never implies permission to run them. Foreign code
  runs sandboxed.
- **Byte-exact transport.** Fetch is binary-safe and verifies the full hash before installing anything (#64).
  A download location is a hint, not authenticated content.
- **Package scope.** Refusing a package states its scope and leaves already-held statements valid; retrying
  individual objects remains possible.

## 12. Execution and storage safety

- **The sandbox includes staging (#67).** Every host-side step before and after a sandboxed run (writing
  attachments and inputs, reading outputs) confines peer-supplied names to their directory and refuses absolute
  paths, `..` and symlinks. Resource caps apply *during* execution, not only after. Timeouts kill and clean up
  the container.
- **Exact bytes.** Install the bytes that were hashed, via a confined temporary copy, and verify an existing
  blob before reusing it.
- **Atomic commits.** A crash leaves either the previous state or a complete, recoverable operation, never a
  half-published artifact. A projection that fails after a commit is reported as needing repair, not rolled back
  fictionally.
- **Concurrent writers** never overwrite each other's committed objects. Same-key concurrent appends become a
  visible fork, not a lost line.
- **Caches** are keyed on content digests, policy and evaluator versions, never on file size or modification
  time. Deleting every cache yields the same answers (I14).
- **Scans are bounded and honest.** Archives are scanned member by member or reported as unscanned (#20). Size
  limits are visible, and an incomplete scan says so.

## 13. Outputs

- **Closed vocabulary.** One documented table of state tokens (`contested`, `unknown`, `unchecked`,
  `corroborated n`, `contradicted m`, `SUPERSEDED`, `FORK`, `retracted`, …), each with one meaning on every
  surface.
- **Exit codes.** `verify`: 0 checked and passed · 1 checked and wrong · 3 could not check (including contested
  and unknown) · 4 nothing to re-run · 5 environment mismatch. Exit 0 means the requested operation succeeded,
  not that everything it referenced is valid.
- **Explain.** Every status can be expanded to the statements, policy and checks behind it (I14).
- **Dry runs** state their side effects: "no registry change" differs from "no fetch, no cache, no quarantine".
- **Errors** say what failed, what is still known, whether anything was committed, and the narrowest next
  step, never a blanket `--force`.

## 14. Relationship to the alpha

This format is a clean break. The alpha tool and its hubs stay as they are for reference. Participants rebuild
their hubs and republish their data under the new format. There is no importer, no dual-format reading and no
compatibility window.

Content carries over unchanged: the same bytes have the same hash, so data does not need to be regenerated, only republished. Statements are new: authorship, licences and
time evidence are re-signed and re-anchored. Priority established under the alpha does not carry over.

What the clean break removes, and the alpha issues it closes by construction:

| Alpha mechanism | Replaced by | Issues |
|---|---|---|
| shared mutable manifests, the manifest edit gate, the "first publisher owns it" rule | accumulating statements; local views | #41, #47 |
| signatures over a subset of fields, plus a second full-body signature | one signature over the whole statement | #10, #45 |
| unsigned logs accepted on `pull` | only signed statements enter a hub | #14, #24 |
| `pull` and hub CI checking different things | one validation core | #48 |
| adoption of orphaned artifacts by a hub key | no unsigned orphans exist; a lost key means republishing under a new key, citing the old | #58 |
| short ids with a collision guard | full-hash identity, aliases for display only | |
| collection ids that change on every edit | resources with permanent ids and editions | #54, #8 |
| a single T3 tier for observations | observation class + capture evidence + corroboration | #1, #17, #65 |

## 15. Out of scope for this note

Each of these needs its own note: wire format (canonical encoding, field names, signature scheme, test vectors);
storage engine and transaction design; execution profiles (runtimes, confinement mechanism, limits); statistical
comparison dialects; attestation verifiers (receipts, TEEs); receiver-local Bitcoin verification (#59); size
policy (#9); hub discovery conventions (#66).

## 16. Open questions

1. **Resource authority depth.** Is "controllers + k-of-n + editions" enough for the core, or do delegation
   (scoped, revocable) and recovery from lost controller keys belong in it too?
2. **Pinning.** Should programmatic consumers be *required* to pin a specific `authored` statement when a
   construction is contested, or is a non-passing `contested` result enough?
3. **Observation classes.** Are the five rows in §5.3.1 the right granularity? Is "the source" (weak consensus)
   usefully distinct from "the phenomenon" in practice?
4. **Corroboration status in derived results.** A result built on contradicted observations shows that status
   beside its grade. Should the status propagate along the chain the way availability does, and at what level
   of detail?
5. **Retraction.** Should readers honour an author's retraction by default (stop serving the bytes), or only
   display it?
6. **Invariant ordering.** Is integrity > honesty > fairness > sovereignty/time > legibility the right priority
   when guarantees collide, given §3.1's rule that the loser is always visible?

## Appendix: worked examples

**Two authors, one synthesis.** A and B both publish identical bytes and sign `authored`. A anchored at publish,
B did not. With Bitcoin verification available, A is the default author and B is listed as a later claimant.
Without it, both are listed and the state is `contested`. Either way, neither can change the other's licence
statement, and a reproduction by B counts as a reproduction, not as authorship.

**A chain observation across a fork.** An observer publishes balances at block hash H, depth 3. A reorg orphans
H. The observation remains true of H and its referent status becomes `not canonical`. Results derived from it
show that status beside their grade. Other observers re-reading H from archival nodes can still corroborate the
bytes.

**An API that disappears.** Two observers captured the same endpoint within minutes and their responses
corroborate each other. The API shuts down. Future corroboration becomes impossible (`source unavailable`), but
the existing corroborations stand.

**A hot reading in Denver.** A station reports 120 °F. A climate-bounds corroboration returns `contradicts`.
A rule-based cohort of stations within 50 km returns `contradicted by 4`. A curated hub that admits only the
original shows `unchecked within this hub`. A reader who follows a regional reference collection sees the
contradictions, and either reader can re-run the cohort rule.

**A hostile package.** A pull brings one valid observation and an edit to the hub's policy file. The policy
edit is refused (data never carries control). The observation is admitted, and the refusal message names the
scope.
