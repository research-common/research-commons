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
  synthesis, a report), the author is claiming to have made it first, and verified publication time settles
  rival claims. For a derived artifact with pinned provenance, the derivation is the claim: everyone who ran
  the same workflow on the same inputs is a deriver, and nobody is first. For an observation, the question is
  whether it reflects the world. That is answered by corroboration and capture evidence, which accumulate and
  can change in either direction.
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
| `authored` | the author | "I made these bytes." Carries the author's single-party fields: licence, availability, verification spec, description, and provenance (workflow + inputs) when derived. For a construction, it is a first-to-publish claim (§5.2). The same key's later `authored` statement on the same blob amends its earlier one: the amended claim keeps the best time bound of its amendment chain, and its fields come from the latest statement alone, so a field the amendment omits is undeclared (an amendment replaces, it does not patch). |
| `observed` | the observer | "I captured these bytes." Carries the referent, capture record, capture evidence and the observation class the observer asserts (§5.3), plus the same single-party fields. |
| `holds` | anyone | "I have these bytes and serve them." Mirroring, with no authorship and no agreement. A later `holds` by the same key with `withdrawn: true` says "I no longer serve them"; the earlier one stays in the log. |
| `describes` | anyone | Open annotations: tags, notes, non-evidential links. Shown as the signer's, ranked by the reader's trust. |
| `reproduced` | anyone | "I re-ran this": match / diverged / not comparable, with environment record, including a successor workflow that reproduces the same outputs (#22). Emitted by `run --publish` in place of `authored` when the runner already holds a same-provenance `authored` for the bytes (§5.2). |
| `corroborates` | anyone | Points at a corroboration result (§5.3.2): supports / contradicts / inconclusive under a named agreement model. |
| `refutes` | anyone | "This premise or result is wrong", with the evidence artifact. |
| `retracts` | the author | A recall request for the author's own artifact. |
| `anchors` | any key, own log | Time evidence for that key's own log prefix (§10). |
| resource editions | resource controllers | Collection and task editions (§8), and a controller's withdrawal of its own approval. |
| lifecycle | task participants | Intent, progress, withdrawal, submission, decision (§9). |
| key events | the key | Rotation and revocation (§4.1). |

Lineage links that carry meaning (`supersedes`, `extends`, `fulfills`, evidence links) are fields of signed
statements, never free-standing metadata.

### 4.1 Key events

A key event is a statement by a key about itself: `rotate_key` names a successor, `revoke_key` ends the key.
Neither carries a time, because a time a key signs about itself is not evidence; what a key event does is
read from the key's own log (wire-format note §7). It is in force once it chains (a detached key event is not,
§12).

- **A revocation's history** is the revocation and every line of the same key it reaches through `prev` and
  `merges`. A line of that key outside it counts toward nothing: a line after the revocation (C-core-143), and
  a line on a branch the revocation does not include, whether that branch was signed later by whoever else
  holds the key or earlier from a second machine (the **sibling rule**, C-core-143a, C-core-143b). Such lines
  are still kept, shown and attributed to the key (I3); they grant no priority, approval, quorum or settlement.
  A revocation forked low therefore cuts every line of the key above its fork point. That is deliberate: the holder of a
  stolen key and its owner sign alike, so the rule lets either one shrink what counts and neither one widen it.
- **Hard and soft.** `superseded` and `cessation_of_operation` are soft: the key retired, and its history
  counts. Every other reason is hard, including `key_compromise`, an undocumented token and a value a later
  revision adds (C-core-143c). Under a hard reason only the lines in the history of `last_good` (that line
  and its ancestors) count; the rest of the revocation's history counts toward nothing, and a hard revocation
  with no `last_good`, or with a `last_good` outside its own history, leaves nothing of the key counting
  (C-core-143d). A revocation fails closed: a reason the reader does not know never makes it malformed.
- **Several revocations.** A line counts only if every in-force revocation of its key lets it count (the
  intersection of what each allows), so revocations on different branches, or a revocation and a later one,
  can only shrink the set. A key event signed after a revocation is outside that revocation's history and
  counts only where it makes things stricter: a hard reason after a soft one, or an earlier `last_good`.
- **Rotation retires the old key** the way a `superseded` revocation does: the old key's lines in the
  rotation's history count, and its lines outside it count toward nothing (C-core-127b). The successor starts
  its own log. Controller roles name keys and do not follow a rotation (§8): a controller that rotates first
  gets an edition naming the successor, under the resource's rule.
- **Editions that lose their approvals.** An edition whose counted approvals fall below its rule because a key
  event stopped counting an approver's line is shown `contested`, naming the key event, and so is every
  edition built on it (C-core-143e). This is visible, never a silent fallback to an older tip, and building on
  an edition does not protect it from a revocation (it does protect it from a withdrawal, §8).

Restoring what a revocation cut is not possible in-band, because the two holders of a key are
indistinguishable. A key's owner can make it possible ahead of time with a recovery key committed when the
key is created; that mechanism is specified separately.

## 5. Authorship, priority and observation

Artifacts fall into two categories that answer different questions.

| | **Constructions** | **Observations** |
|---|---|---|
| Examples | workflows, skills, syntheses, reports, derived datasets | sensor readings, chain state, API captures, benchmark runs, field measurements |
| The author claims | "I made this, first" | "I saw this, and it reflects the world" |
| Settled by | verified publication time | corroboration and capture evidence, accumulating over time |
| Identical bytes from a second key | a later claimant (or a copy); with the same provenance, a member of the same derivation group (§5.2) | usually a copy; in the exact-bytes class, a possible corroboration (§5.3.1) |

### 5.1 Single-party fields

Licence, availability, verification spec and description are **single-party**: the default display comes from
one key's `authored` or `observed` statement, chosen by the rules below. Rival values from other keys are always
listed with their signers and never silently dropped. A consumer that needs certainty pins a specific
statement rather than relying on the default.

**A forked log.** On an uncleared fork of a key's log (wire-format note §7), every `authored` statement of
that key on a blob that no later statement of the key amends is current, whichever branch it is on. Current
statements with the same provenance are one claim, and a field on which they disagree is `contested` on that
field; statements with different provenance are separate claims. This is read per statement, not by freezing
the key at the fork's base: a blob that only one branch speaks about resolves normally, and lines after the
fork count on both branches. Most forks are one key signing from two machines, and freezing would hide that
work until a merge for no conflict in what the key said. A fork by someone else holding the key is answered by
the key's revocation (§4.1), which cuts the branch it leaves out; until then the other branch can make the
key's fields `contested`, never win them. Clearing the fork with `merges` does not choose between values: an
`authored` whose history includes both branches amends both (C-core-16a).

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

**Derivation groups.** The rules above apply to constructions *without* provenance, where "I made this" is
the claim. A derived artifact with pinned provenance claims something else: "this workflow on these inputs
produced this", which anyone can check by re-running, so time evidence is the wrong adjudicator. `authored`
statements that carry the same provenance (workflow hash and input hashes) form one **derivation group**,
whatever their output bytes. Priority is never computed within a group. The display is "derived by *k* under
wf-…", each deriver listed, with independent re-runs distinguished from `holds`. Against a claimant outside
it, a group is one claimant whose bound is the best any member holds: the rules above rank the group as a
whole, and a member who joins late, with a weaker bound or none, never lowers it. This keeps the answer one
function of the statements held, whichever member a reader happened to see first (I12, I14); it is not a
defence against a hostile member, whom the reader keeps out by its own admission policy (C-core-20a). An
outside claim never erases a group's evidence: when authorship is contested or goes to the outsider, each
group's grade is still shown beside its claimants. Bytes are evidence *within*
the group, read against the `replication` mode the workflow's own `authored` statement declares (§7), which
derivers inherit. The mode and comparator are the workflow's resolved defaults under §5.1 and §5.2, never a
value a deriver or its statement supplies. When the workflow's own authorship is `contested`, a group uses
a mode and comparator only if every claimant of the workflow declares the same ones (`explain`: "all *n*
claimants of the workflow agree"); otherwise every derivation under it is `unchecked`. The workflow's own
display of those fields still shows no default. When the workflow's author amends its mode or comparator,
every group under the workflow is read under the amendment, and `explain` cites it (C-core-22a):

| the workflow declares | identical bytes | different bytes |
|---|---|---|
| `bytes` (deterministic) | a byte-identical re-derivation (T0); "derived by *k*" | `diverged`: an environment differs or the determinism claim is wrong; shown, not adjudicated |
| `protocol` | consistent with a re-run and with a copy, and not evidence of either: shown as `identical bytes (protocol workflow)`; independence is §9.3's question | compared under the workflow's declared comparator: `match` or `diverged` (T1); "derived by 3: 2 match, 1 diverged". No declared comparator: `unchecked`, never a default comparison |
| undeclared | `unchecked` | `unchecked` |

**Grades are the reader's own comparison.** A grade comes from the reader comparing output bytes itself, under
the workflow's mode and comparator; the `result` a `reproduced` statement signs is never graded. Each run in a
group is shown with what its runner signed (its token and environment record, the comparator's record nested,
attributed to the runner, I2), the reader's trust in that runner, and the reader's own result; where the
runner's token and the reader's result differ, `explain` says so, declared beside computed (§7). Trust in a
runner never moves a grade or an exit code (C-core-25a).

**Each run is graded on its own output.** Under `bytes`, an output that another run of the group also
produced is a byte-identical re-derivation (T0) whatever else the group holds, and an output no other run
produced is `diverged`; the group shows `diverged (n different outputs)` as a disclosure, so one stray run
under the same provenance never takes T0 from the runs that agree (I7, C-core-22b). Under `protocol`, the
comparator judges each pair of runs, and a run that matched at least one other run is T1, listed with the runs
it matched. Tolerance is not transitive (§9.3), so matches are never chained: the group shows `all k match under
K` only when every pair matched, and otherwise its counts and `not all runs agree`, with the number of clusters
(runs linked by matches) and the pairs that diverged, which `explain` lists (C-core-24a, C-core-24b). Checking
one output needs only its own row, so `verify` may stop at that output's first match. A comparator's result for
a pair may be cached on the comparator's hash and parameters, the unordered pair of outputs and the evaluator
version; the cache is a projection, rebuilt at will, never evidence (§12).

A comparator judges re-runs of one derivation: the same workflow on the same inputs. Agreement between
results on different data (a replication with a fresh sample) is a corroboration (§5.3.2) or a task's test
(§9.3), not a T1. A comparator must be deterministic and symmetric, so that a pair has one answer whichever
output comes first and however often it is asked; that is the comparator author's duty, and no reader can
test it.

A non-deterministic process can honestly return identical bytes (a tight response contract leaves few degrees
of freedom), so identical output under `protocol` is neither a reproduction nor a red flag. Single-party fields
default by agreement within the group; a field whose values differ is `contested` on that field only. The same
bytes under *different* provenance are two claims and stay under the rules above; byte equality across
workflows is a `reproduced: match` (#22). `run --publish` emits `reproduced` instead of a second `authored`
when the runner already holds a same-provenance `authored` for the bytes.

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
  confirmation depth at capture. For APIs: endpoint, parameters and response hash; for a batch capture, the hash, format and count of a
  request log carried inside the captured content, listing each request's endpoint, parameters, status, time
  and response hash. For instruments: instrument
  identity, location and time. For methods: the method edition followed, the execution environment record
  (image digest, platform, harness commit), the measured system's identity and state (model and provider pin,
  and whatever changes the apparatus under the observer, such as a routing era), the protocol's pinned inputs
  by hash (scenario edition, seed set, configuration), and the window (#65). A fork
  or a vanished API does not make an observation false. It is still true of what it pinned. What changes is
  whether the referent is still canonical or still available, and that is shown separately. It never counts
  against the observer. A statement whose referent lacks a field its class requires is still a valid signed
  statement: it is admitted, its referent shows `unpinned`, no class-specific agreement model is applied, and
  its corroboration status is `unchecked`.
- **One class per statement, one class per blob.** An `observed` statement asserts one class; a statement
  asserting more than one is malformed (§11). A blob carries one class as far as the observer can tell, so a
  capture that mixes classes (chain state beside an API read) is published as separate blobs. Class is a
  single-party field: two observers may assert different classes for the same bytes, both are listed with
  their signers, and each statement is corroborated under the model its own class names.
- **A source may have a declared finality rule.** Chain state at depth *d* is one instance; a settlement API
  that revises each period on a published timetable until a final run is another, on a slower clock. An
  `observed` statement in the exact-bytes or source class may carry `finality: {rule, rule_source,
  state_at_capture}`: the rule (`confirmations ≥ 6`, `epoch finalized`, `settlement run ≥ RF`), where the rule
  comes from, and the state the capture saw (the depth, or the run label from the response, or the capture
  time against the timetable when the response lacks a label). The rule is a claim about the *source's
  policy*, so `rule_source` is a citation, at best a hash-pinned capture of the policy document, which is
  itself an ordinary source-class observation that others can corroborate. Rule provenance is shown as one
  of `cited (document held)` · `cited (location only, unverified)` · `observer's convention` (a norm no
  source publishes). A reader resolves rule sources against a source-profile collection it chooses (§6).
  What the rule buys:
  - *Referent status by rule.* `provisional (SF; final at RF)` while unmet, `final` once met, `revised` when
    the bytes changed before finality, `not canonical` when they changed after it (a deep reorg, a dispute
    run). The earlier observation stays true of what it pinned in every case. "Changed" compares captures by
    their state in the rule's order, never by `capture.at`, which is the observer's word: a capture at a
    later state with different bytes is a revision, and two captures at the same state with different bytes
    contradict each other (C-core-40). States that the rule cannot order are not comparable.
  - *Expected revision is not contradiction.* A finality-aware agreement model (§5.3.2) returns
    `inconclusive (referent revised)` for two captures at different states before finality, and `contradicts`
    only when both are at the same state or past it.
  - *Class migration by rule.* While the rule is unmet, agreement is source-class (near-equality around the
    same time). Near-equality needs a declared tolerance, from the agreement model or the source profile;
    without one no default tolerance is applied and the source-class result is `inconclusive`, never counted,
    as for a `protocol` workflow with no comparator (§5.2). Once it holds, a re-capture of the same referent
    with identical bytes is an exact-bytes corroboration. The observer still asserts the class; the rule is what
    lets a reader apply the stronger agreement model.
  - *Derived results inherit the horizon*, shown beside the grade: "rests on 3 captures: 2 final, 1
    provisional until RF" (§7).
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
the tool does not decide which side is wrong. A counted `contradicts` counts against the original and against
each observation in its comparison data (the result's inputs other than the original); a `supports` counts for
the original only, because a check against data says nothing about the data (C-core-51).

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
   curator's judgment), `rule-based` (a published inclusion rule others can re-apply), or a
   `completeness claim` ("every reading from source X in this window", which can be checked and refuted).
   A hub that declares nothing displays `undeclared`, never a value it did not sign; agreement models treat
   an undeclared selection as curated, the weakest claim.
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
| licence | an SPDX license expression (SPDX 3.0.1 Annex B); terms with no SPDX identifier, open or not, are named by a `LicenseRef-` id and cited the way a finality `rule_source` is (§5.3.1): by hash when the text is held, else by location, shown `cited (text held)` or `cited (location only, unverified)`. Terms whose owner does not allow republishing the text are cited by location. Attribution notice (#6, #19). Missing or unparsable means unknown, not open. |
| availability | redistribution permission and byte obtainability, separately |
| replication | `bytes` (public deterministic source named) · `protocol` (re-measurable, never the same bytes; method named) · `none` · undeclared (#1, #7) |
| sampling | n with its unit, per-group n where the design has arms, dispersion, window (#2) |
| shelf life | publisher-declared validity; age shown at read time (#4) |
| capture evidence | §5.3.3 level, verified or not |
| corroboration | §5.3.2 status, scoped |
| selection | curated · rule-based · completeness claim · undeclared (§6). Missing means undeclared. |
| referent status | still canonical · `provisional` · `final` · `revised` · `not canonical` · source still available / unknown · `unpinned` (a field its class requires is missing) · `finality unchecked` (a declared rule the reader has no source profile to evaluate) · `pinned` (phenomenon and method classes, whose referent has no re-check) (§5.3.1) |

| pre-registration | `pre-registered <task edition> (<bound quality>)` · `exploratory` · undeclared (#3). Missing means undeclared, not exploratory. |
| finality | §5.3.1 rule and rule provenance; state at capture |

`run --publish` accepts every disclosure that `publish` does (#21). Defaults for licences are documentation only;
the tool never assumes one silently.

**Declared beside computed.** Where a declaration can be checked against the statements a reader holds, the
tool shows both and flags disagreement; it never substitutes one for the other. A synthesis author's declared
sampling n beside the n computed from its inputs (with denominators); a contract's declared n beside the
delivered sampling disclosure (§9.4); a series' declared `frozen_before` beside its members' finality (§8); an
asserted finality state beside a re-check. A derived result carries each disclosure as a scoped summary
("rests on 3 observations: 2 final, 1 provisional; 1 contradicted within statements you hold"), computed as
the weakest replication, the shortest shelf life, the per-input n, and the count of final captures, with
`explain` (§13) for the detail.

**Availability can be withheld.** An `authored` or `observed` statement may be published and anchored with
no `holds`: `availability: withheld until <condition>`, where the condition is prose or a task or edition
reference. The reveal is a later `holds`; the bytes match by construction (I1) or the reveal fails. This is
how a held-out test pool or a season seed is committed now and revealed later. Two cautions belong beside it:
a commitment proves possession by T, not independence (§9.3), and a commitment to low-entropy content (a
seed, a one-line rule) is enumerable against its hash, so the author should include a nonce. The tool cannot
tell low-entropy content from high, so this is guidance, not a check: `publish` with `withheld` warns when
the content is shorter than a documented threshold and proceeds (a heuristic, documented as one, I11).

## 8. Resources: collections, tasks, series

Collections, tasks and growing series change over time. They are **resources** with a permanent id and
immutable editions.

- **Genesis.** A resource is created by a genesis statement naming its controllers and their rule (any one, or
  k of n). Its id is the hash of the genesis statement.
- **Editions.** Each edition is a signed statement by a controller that references its predecessor by hash. It
  carries the full contents: members with roles, member schema (#5), ingest rules, task contract.
- **Rules read statements.** An edition's ingest rules are predicates over a candidate member's signed
  statement (its disclosures: sampling, replication, method edition, pre-registration, finality; its
  provenance; and its referent record, §5.3.1) and its content (forbidden keys, member schema). A rule may
  also read the edition under formation, meaning the members' statements as that edition would list them, so
  uniqueness and quota rules can be stated. A set-level rule is evaluated over the whole proposed edition:
  it never picks a winner by order, and a failure names every member in conflict. Nothing else is in a
  rule's domain. Every evaluation is `ok`, `fail` or `unchecked`, and `unchecked`
  never passes (I4). A failing rule rejects the membership, never the artifact: the artifact's own statements
  are untouched. The rule language is a profile (§15); the core fixes only what a rule may read and the
  three outcomes. *Which record and which rules* (proposed): a rule reads the statement a `statement` member
  names; for a `content` member it reads the blob's single-party defaults (§5.1), where a contested or
  undeclared field answers nothing (`unchecked`), and observation fields (referent, class, finality) need a
  `statement` member naming the `observed`; a `resource` member offers only its role. A membership is endorsed
  when the edition that lists it, re-applied over its own members, yields `ok` for it; a candidate for the next
  edition is evaluated under the base edition's rules over the base members and every candidate proposed with
  it (C-core-93b). Examples: "at least 24 h of coverage inside the window, the whole window in one routing
  era, at most one endorsed member per instrument per era"; "same scenario edition, harness commit in range,
  n ≥ 30 per arm, replication = protocol".
- **Approvals.** Under k of n each controller signs the same edition body. Approvals of byte-identical bodies
  are one proposal with one edition id (wire-format note §3), whoever signed them; bodies that differ in any
  byte are different proposals and never combine (C-core-82, C-core-83). An edition names its predecessors by
  edition id. An approval does not expire.
- **Withdrawing an approval.** A controller may withdraw its own approval (`withdraw_approval`). A withdrawal
  counts only while the edition has no authorized successor: once an edition is built on, it is locked in, as
  inclusion in a block locks in a multisig transaction. A reader resolves the editions ignoring withdrawals,
  then applies them once, to the tips: a tip whose counted approvals fall below its rule is `pending` again,
  and its predecessor is not re-examined. A withdrawal and a re-approval of one body by one key are ordered by
  that key's log, the later one standing. Binding a task submission to an edition does not lock it in, and a
  withdrawal outside its signer's counted lines (§4.1) counts toward nothing (C-core-85b).
- **Controller changes** are editions authorized under the *previous* edition's rule. Nobody elevates
  themselves. A change that leaves a rule no controller set can satisfy (k greater than the number of
  controllers) is `invalid`.
- **Forks are visible.** Two editions with the same predecessor are a fork, shown as one. No timestamp or file
  order picks a winner; controllers resolve it with a merge edition, which names every branch tip as a
  predecessor and is authorized under each predecessor's rule. The fork clears when every tip is an ancestor
  of one edition. Where the predecessors disagree on controllers or rule (`any_one` and k of n with k = 1
  count as equal), the merge declares both `controllers` and `rule`, even when only one differs; without
  them it is `invalid`, because inheriting either side's would pick a winner by branch. Where they agree, the
  merge inherits them (C-core-85a). The side that narrowed its controllers therefore holds a veto over the
  merge; forking a new resource stays the last way out.
- **Outsiders fork.** A non-controller who wants a different collection creates a new resource, which may
  declare `forked-from`.
- **Membership is endorsement.** Only the collection's editions add members. A member's own "part of" claim
  confers nothing, and a laxer collection's rules never apply to members of a stricter one.
- **Intended-for runs the rules before the bytes are pinned.** Some rules (forbidden keys in content) only
  prevent harm if they run before publication. An `authored` or `observed` statement may carry
  `intended_for: {resource, edition}`. The publisher's tool applies that edition's rules before pinning and
  refuses to publish on `fail`; the statement records the edition applied and the outcome, `ok` or
  `unchecked`. A check that ran but could not finish (an archive member it cannot scan) is `unchecked`: the
  statement is published with that outcome recorded, and no edition rule admits it on that basis (I4). A
  check that cannot run at all, because the publisher does not hold the named edition, refuses and names the
  fetch; a statement never records `ok` for a rule that did not run. The field confers nothing (I7): it is the publisher's own policy, chosen by naming it (I9), plus a signed trace. A hub re-applies
  the named edition from its base revision, and separately the current edition when it endorses; both results
  are the reader's computation, shown side by side.
- **A lost controller key ends the resource.** With no key that the current edition's rule authorizes, no
  further edition exists. A successor resource declares `forked-from`. Delegation (scoped, revocable) and
  "key B succeeds key A" mappings are reader projections, not core.
- **Bindings are to editions.** Claims and submissions bind to the task edition they accepted. A later edition
  never changes the terms retroactively. Endorsing a task in a collection doesn't change either one's id
  (#54).
- **Growing series** (#8) are resources whose editions append segments, with an explicit `frozen_before`
  boundary when recent data is still being revised. The boundary is the controller's declaration, stated in
  the unit the members' finality rules use (a date, a block height, a settlement run). Where
  segments carry finality rules (§5.3.1), a reader computes the members' finality boundary and shows both:
  "frozen_before 2025-06-01 (declared) · members final to 2025-04-01 (2 segments provisional)". A declared
  boundary later than the computed one is flagged; `unchecked` when members carry no rule; `not comparable`
  when the declared unit differs from the computed one (never converted). The computed boundary is the
  position of the earliest segment that is not final, every segment before it being final; when every
  segment is final, it is the end of the last segment. It is `unchecked` when any segment carries no finality
  rule or its state cannot be re-checked, since one segment without a rule leaves the boundary unknown. A
  series edition rule may require agreement, so a hub can refuse a premature freeze under its own policy. A
  controller can still freeze a tail the source intends to revise; it cannot do so invisibly. A segment's
  position is read from its referent: the start of its window, else its time, else its finality state, in the
  unit of `frozen_before`; a position in another unit is `not comparable` with the boundary and is explained,
  not flagged. An edition replaces a segment when a segment of its predecessor is missing from it, or it adds a
  segment, positioned before the predecessor's `frozen_before`. Such an edition is shown as `REVISED-FROZEN`;
  the earlier edition and its segment remain resolvable (I3).

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
pre-registration proves the plan existed by time T, not that the author hadn't seen the data. An `observed`
statement can carry `fulfills` to a task edition, so a pre-registered observation campaign is in scope, not
only derived results. The opposite case is declared, not inferred: `exploratory` is a disclosure value (§7). A
**departure check** compares the delivered `sampling` disclosure with the contract's declared n, per group
where the contract declares groups, and reports `conforms`, `departed`, `unchecked` (no structured count, or
no count for a declared group) or `not comparable` (unit mismatch). It never moves the grade (I6).

### 9.5 Credit

Credit is a projection: contribution, citation, reproduction, review, corroboration and acceptance are counted
separately, under rules the reader chooses, with denominators shown. No transferable entitlement is created.

## 10. Time

- **Bounds are per signer.** An anchor bounds only the signer's own log prefix. Every key anchors its own
  statements.
- **Quality.** `local` = signed and self-consistent, but self-declared. Every other quality names a proof
  format the *reader* verified: an `anchors` statement says which format its proof is in (`proof_format`),
  and each format's note defines the quality it can yield and how it orders against the others. `bitcoin` =
  the reader verified an OpenTimestamps proof against block evidence it trusts (#59), the first such
  format. A format the reader does not implement yields nothing; bounds of two different formats are
  incomparable for priority until a note says otherwise. A label in a file grants nothing.
- **Publish anchors first.** Anchoring happens at `publish`, before the bytes leave the author's machine.

| Use | Local quality | Bitcoin quality |
|---|---|---|
| priority among rival authorship claims for a construction (§5.2) | no | yes, if strictly earliest |
| "existed by T" for capture evidence and pre-registration | shown as `(local, self-declared)` | shown as a time |
| ownership, edit rights, independence | never | never |

Timestamps more than 300 seconds in the future of the writer's clock are refused at write time; the bound is
a documented default in the writer's policy, printed with the refusal. A line whose
timestamp precedes the line it chains after is flagged incoherent, and its bound is discarded.

## 11. Federation and gates

- **Only signed statements enter a hub.** Unsigned work is a local draft that cannot be pushed, whatever its
  type (#14, #24). Generating a key is part of first-run setup.
- **One validation core.** `pull`, hub CI, `push` and the pre-pin check at `publish` (§8) call one validation
  function. They differ only in what history they hold and whose policy applies (I12).
- **Refusal classes (I8).** *Intrinsic:* hash mismatch, bad signature, malformed statement (including one
  asserting more than one observation class), a line in another key's log, unsafe paths,
  anything outside the data surface. *Reader policy:* trust floors,
  executable admission, hub rules. *Operational:* size and resource limits. Everything else is admitted and
  labelled.
- **Data never carries control.** Incoming trees cannot carry code, hooks, configuration, trust lists or policy.
  Hub CI reads the hub's policy from the base revision, so a pull request cannot grant itself anything.
- **Admission is not execution.** Holding executable bytes never implies permission to run them. Foreign code
  runs sandboxed.
- **Byte-exact transport.** Fetch is binary-safe and verifies the full hash before installing anything (#64).
  A download location is a hint, not authenticated content.
- **Bytes may live elsewhere.** A `holds` statement may name an external location (an object store, a
  content-addressed network, a plain URL). Because fetch verifies the full hash whatever the source, an
  external hold is as good as a local one once fetched, and the holder's word about availability before
  that. A hub that carries statements and external holds, and no blobs, is a first-class configuration.
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
  visible fork, not a lost line. The key's owner clears it with a line that names every other tip beside its
  predecessor; as for editions (§8), a fork clears when every tip is an ancestor of one line, and following
  one branch alone does not clear it.
- **Gaps in a log.** A statement whose predecessor the reader does not hold is kept and shown as `detached`,
  with the missing range named. An `authored` or `observed` is attributed to its signer while detached, but
  counts toward nothing; every other kind is not evaluated until it chains, because the missing stretch may
  hold a revocation, a rotation or an earlier edition that changes what it means. Nothing is refused for
  being detached, and nothing decided while it waited is rewritten when the gap fills.
- **Caches** are keyed on content digests, policy and evaluator versions, never on file size or modification
  time. Deleting every cache yields the same answers (I14).
- **Scans are bounded and honest.** Archives are scanned member by member or reported as unscanned (#20). Size
  limits are visible, and an incomplete scan says so.

## 13. Outputs

- **Closed vocabulary.** One documented table of state tokens (`contested`, `unknown`, `unchecked`,
  `corroborated n`, `contradicted m`, `SUPERSEDED`, `FORK`, `retracted`, …), each with one meaning on every
  surface, including `unpinned`, `REVISED-FROZEN`, `timeout` and the referent statuses of §7. Every rule
  evaluation (edition rules, departure checks, pre-pin checks) is one of `ok`, `fail`, `unchecked`.
- **Retraction is display.** A `retracts` statement is shown wherever the artifact is; it does not stop
  anyone serving the bytes. Superseded snapshots are often the evidence for their own erratum. A hub that
  must stop serving something does so under its own admission policy (I9).
- **Exit codes.** `verify`: 0 checked and passed · 1 checked and wrong · 3 could not check (contested, unknown,
  unchecked, unpinned, unsupported; a derived artifact nobody re-derived, `not re-derived`; a re-run stopped by
  one of the reader's own limits, `timeout` or another operational cap, reported with the resources used; and a
  re-run whose step failed or left a declared output missing) · 4 nothing to re-run · 5 environment mismatch:
  the declared environment differs from, or is not available in, the one that ran. Exit 1 is reserved for a
  comparison that ran to completion and disagreed; a step that failed compared nothing, and the token says which
  kind of "could not check" it was. Limits and environments call for different next steps (raise the limit or
  accept `unchecked`, versus run where the pinned environment exists). Exit 0 means the requested operation
  succeeded, not that everything it referenced is valid.
- **`verify` of a derived artifact needs a comparison.** A derived artifact claims that its workflow on its
  inputs produced its bytes, so exit 0 needs a T0 or T1 comparison: a second run in its group, or the
  reader's own re-run inside `verify`. With neither, it is `not re-derived` and exits 3 under every
  replication mode (C-core-25b). The author's own `reproduced` is a second run, and `explain` says
  "re-derived by its author only". A construction without provenance makes no such claim, so a sole author
  with nothing contested still exits 0 (C-core-17). So under a mode that permits no comparison (undeclared,
  or `protocol` with no comparator), `verify` exits 3 whether the group holds one run or several: holding
  less evidence never passes where holding more would not.
- **Exit 2: the command did not start.** On every command, 2 means the invocation or the reader's own
  configuration could not be acted on: an unknown option, a malformed argument (an id that is not an id), a
  policy or configuration file that is present but unreadable or unparseable. Arguments and configuration are
  validated before any work starts, so exit 2 never accompanies partial results and nothing is committed; the
  error is still the problem-details object below, with `committed` false. Conditions about a particular
  artifact or check are never 2, even when they stem from configuration: an optional capability that is
  simply not configured (no Bitcoin backend, say) is a state token and exits 3. No other condition exits 2,
  so exit 1 stays reserved for a completed comparison that disagreed. An explicit request for help exits 0.
- **Explain.** Every status can be expanded to the statements, policy and checks behind it (I14).
- **Dry runs** state their side effects: "no registry change" differs from "no fetch, no cache, no quarantine".
- **Errors** say what failed, what is still known, whether anything was committed, and the narrowest next
  step, never a blanket `--force`. Error output and logs never include key material or secrets, and render
  peer-supplied text inert. In machine-readable form an error is an RFC 9457 problem-details object (`type`,
  `title`, `detail`) with four extension members: `class` (intrinsic, reader policy, operational), `scope`
  (the statement, package or blob it applies to), `committed` (whether anything landed) and `next` (the
  narrowest next step). The same object serves a CLI's JSON output and a hub's HTTP error body. Peer-supplied
  text goes in an extension member as a JSON string, never interpolated into `title` or `detail`.
- **Exit-code range.** Codes are small integers below 64, so they never collide with the shell's reserved
  values (126, 127, and 128 plus a signal number; POSIX.1-2024 §2.8.2) or with `sysexits.h`, which is
  deprecated upstream and not used. No command emits 126 or above. The split of 0, 1 and 2 follows `grep`,
  `diff` and `cmp` (0 same, 1 different, 2 trouble), so a script that already knows those reads ours.

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
comparison dialects; rule and schema dialects (what edition rules and member schemas may express, §8);
attestation verifiers (receipts, TEEs); receiver-local Bitcoin verification (#59); size policy (#9); hub
conventions (discovery #66; the hub-template and `COMMONS.md` rubric, which still use alpha vocabulary).

## 16. Decisions on the questions this note first left open

The first revision of this note asked six questions. Review against three hubs in production or standing up
answered each the way the note leaned, and they are now decided:

1. **Resource authority depth.** Controllers, k-of-n and editions are the core. A lost controller key ends the
   resource and a successor declares `forked-from` (§8). Delegation and key succession are reader projections.
2. **Pinning.** Not required. A non-passing `contested` with exit 3 is enough; a consumer that needs stability
   pins a statement hash. Derivation groups (§5.2) keep the common case, re-derived data, out of `contested`.
3. **Observation classes.** The five rows stand. Source and phenomenon are distinct in practice: a settlement
   API is a source; a wind farm's output is a phenomenon seen by that API and by the operator's own
   instruments. One class per statement and per blob (§5.3.1).
4. **Propagation.** Status propagates as a scoped summary beside the grade, with `explain` for detail, and
   declared values are shown beside computed ones (§7).
5. **Retraction.** Display only (§13).
6. **Invariant ordering.** Stands. Integrity over honesty keeps a valid signature valid on bytes nobody
   should have shared; honesty over sovereignty means a reader cannot configure disclosures away (I6).

## Appendix: worked examples

**Two authors, one synthesis.** A and B both publish identical bytes and sign `authored`. A anchored at publish,
B did not. With Bitcoin verification available, A is the default author and B is listed as a later claimant.
Without it, both are listed and the state is `contested`. Either way, neither can change the other's licence
statement, and a reproduction by B counts as a reproduction, not as authorship.

**A chain observation across a fork.** An observer publishes balances at block hash H, depth 3. A reorg orphans
H. The observation remains true of H and its referent status becomes `not canonical`. Results derived from it
show that status beside their grade. Other observers re-reading H from archival nodes can still corroborate the
bytes.

**An API with a revision schedule.** An observer captures a settlement period while the source still marks
it provisional, and declares the source's finality rule with a pinned copy of the published timetable. The
source revises the period twice on schedule; each later capture is a new `observed` statement, and a
finality-aware agreement model reads the differences as `inconclusive (referent revised)`, not as
contradiction. After the final run, a second observer re-captures the closed period and gets identical bytes.
The first observation's referent status reads `revised`; the re-capture is an observation made outside any
sandbox; the byte comparison between them is a sandboxed `corroborates` derivation. Network access lives in
`observed`, determinism in `corroborates`. A series of monthly segments built from these captures declares
`frozen_before`, and readers see it beside the boundary the members' rules compute.

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
