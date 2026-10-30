# Design note: task contracts (`task-contract-v1`)

**Date:** 2026-10-27, revised 2026-10-28 (revision 2) · **Status:** request for comments. Nothing here is
decided or implemented.
**Tracking issue:** #109
**Builds on:** the claims-model note §8 (resources, editions) and §9 (research exchange), #69; the wire-format
note §1.1, §5, §6; the bitcoin-time note §7, §8, §11; #3 (pre-registration), #65 (stochastic replication)
**Scope:** the grammar of a task edition's `contents.contract`, one new statement kind (`grant`), two optional
fields on `refutes`, a reading of the existing `fulfills` field as a submission, and the rules a reader
applies to decide readiness under a contract. It does not change the claims model's invariants, the wire
envelope, or any existing kind's meaning.
**References:** invariants (I1–I15) and bare §9.x, §10 and §13 are the claims-model note's; other bare section
numbers are this note's; any other note is named.

**Revision 2 (changes since the first draft).** From the observation-task review on #109:

- **`fulfills` is a submission** (§5.1). An `authored` or `observed` carrying `fulfills: E` is a submission
  of `E` whose result is its own content digest, read under the same five conditions; `submit` stays for
  results that are not the submitter's own statement. Q1's current-submission rule reads every kind (§6 Q1);
  a `fulfills` that fails `E`'s terms is not counted, never malformed. Touches §3.3, §4.3, §5.2, §5.3, §5.8,
  §6 Q4–Q5, §7 (C-exch-03a, C-exch-07a; new C-exch-15a), §8, and one sentence in the claims-model note §9.4.
- **Q2 `min_grade`** is for derived results only: it needs a `results: "derived"` declaration, and without
  one it leaves the contract unread. `min_capture_evidence` waits for an ordered vocabulary of verified
  capture-evidence levels; corroboration never gates a count (§6 Q2).
- **Q3 pins** read `provenance` for derived results and `referent.method_edition` / `referent.inputs` for
  observations, with the same `ok` / `fail` / `unchecked` outcomes (§6 Q3).
- **New Q12**, counting by a referent member (one per instrument), with the format gap it depends on (§6 Q12).
- **Q8 display:** an approximate date may be shown beside a height, labelled as an estimate, never used for
  ordering (§4.3).
- Leans the review agreed with are marked *Review: agreed* (§3.3, §6 Q1, Q4, Q8, Q10). Nothing is decided.

## 0. Summary

- The claims-model note says what a task contract **pins** (§9.1) and what a quorum predicate **states** (§9.3),
  but no note gives it a grammar. The wire format types `edition.contents.contract` as an object and stops
  there, so every exchange conformance case that reads a term has no normative field to read.
- This note proposes a named **contract profile**, `task-contract-v1`: a closed field table (§3), a rule for
  where the role fields live in `rc/1` and in a future `rc/2` (§3.2), and a strict recognition rule: an
  unknown profile, or an unknown field inside a known one, leaves the contract **unread**, and nothing under
  an unread contract passes (§3.3).
- Three wire additions, all minor changes under the wire-format note §6: a **`grant`** kind for coordinator
  grants (§4.1); optional **`task`/`edition`** on `refutes`, so a refutation can be a first-class submission of
  a task (§4.2); and a **deadline clock**: a deadline is a Bitcoin block height compared only with verified
  bounds, never with `ts` (§4.3).
- **Observation tasks need no second statement.** An `authored` or `observed` statement carrying
  `fulfills: E` is itself a submission of `E` whose result is its own content digest (§5.1), so in a
  pre-registered observation campaign each participant signs its observation once. `submit` stays for a
  result that is not the submitter's own statement.
- Readiness is computed as a **bracket** (§5.6): once with every undecided submission left out, once with every
  one put in. Ready if the first reaches the quorum, not ready if the second does not, `unknown` or `unchecked`
  otherwise. This replaces "any unchecked criterion anywhere makes the task unchecked", which lets any
  eligible issuer hold a ready task at exit 3.
- Twelve questions stay open (§6), each with options and a lean: deduplication, evidence strength, inputs and
  methods, commit-reveal, credit definitions, grant withdrawal, counting units for corroboration, calendar
  deadlines, the coordinator under identities, refutation eligibility, rubric dialects, and counting by a
  referent member.
- §7 lists the conformance impact: which exchange cases this grammar unblocks, and six new cases.

**Standards first.** As in the wire-format note §0: where a standard defines something this profile needs, it
is adopted and profiled; where none fits, the note says so.

| Need | Standard adopted | Profile or departure |
|---|---|---|
| encoding of the contract object | RFC 8785 (JCS) over the I-JSON subset, as the wire-format note §1 profiles it | inherited; the contract is a body field, so it is inside the signature and the edition id |
| keys, ids, digests | the wire-format note §5 types `key`, `id`, `digest` | inherited, no new syntax |
| deadline clock | Bitcoin block height as the bitcoin-time note §8.3 orders it | height only; `nTime` is not used (§4.3). A calendar form is open (§6, Q8) |
| optional machine-readable schema | JSON Schema draft 2020-12 | a companion schema may be published for tooling; it is **not** normative. The table in §3.1 and the rules in §3.3 are, because "unknown field leaves the contract unread" and "exactly one of" are reading rules, not validation results |
| statistical test for stochastic replication | none adopted | `quorum.test` pins a comparator workflow by digest (claims-model note §15 leaves comparison dialects to their own note) |
| rubric language | none adopted | criteria are identified prose; how a criterion is evaluated is a reader-side evaluator (§5.5, §6 Q11) |
| commitments | none adopted | §6 Q4 |

Considered and not adopted: **W3C Verifiable Credentials Data Model 2.0** for grants. A grant here is one
signed statement in the coordinator's own log; a credential would add a second signature format and a second
identifier scheme to carry four fields (§4.1). **ICH E9(R1)** (estimands in clinical trials) is the vocabulary
`quorum.estimand` borrows its word from, but the field stays a string: the profile names what is estimated,
it does not adopt a trial-design framework.

## 1. Problem

Claims-model note §9.1: "A task contract pins the question, required inputs and methods, acceptance rubric or
comparator, eligible evidence, decision authority, quorum requirements and deadlines." §9.3: "A quorum
predicate states eligible issuers, deduplication, required evidence strength, any independence constraints,
and how results are grouped." The wire-format note §5 gives `edition.contents.contract` the type `object` and
no fields, and says field semantics belong to the claims-model note and the profile notes. There is no profile
note. Five consequences:

1. **Every term is unreadable.** Eligible issuers, the beneficiary, the quorum, the rubric, the deadline: a
   reader has no normative field for any of them. A conforming reader today must read every contract
   `unchecked`, and every exchange case that depends on a term (C-exch-03, C-exch-07 – C-exch-14, C-exch-17)
   can only be partly met.
2. **Grants have no statement.** §9.1: a task "names a coordinator, whose signed grants are the only thing
   that counts". No kind carries a grant.
3. **Refutations cannot join a task.** §9.4: "Refutations and failed reproductions are first-class
   submissions". `refutes` has `of`, `evidence` and `note`; it cannot say which task edition it answers.
4. **Deadlines have no clock.** C-exch-07 checks submissions "under `T1`", deadline included. The only time a
   reader may rely on is a verified bound (claims-model note §10, I10, I14); `ts` orders nothing. No note says
   how a deadline meets a bound.
5. **Several required properties are undefined.** Deduplication, evidence strength, inputs and methods,
   commit-reveal and the credit counts are named by the claims-model note and defined nowhere.

An unreleased provisional reading in the reference implementation reads a contract under the profile name
`provisional-task-contract-0` behind a replaceable seam, and every result it gives is labelled provisional.
This note is the proposal that would replace it (§8).

## 2. Rules this profile adds

These sit under the claims-model note's invariants and never override them. §7 lists the cases that pin them.

- **TC1 Unread is not a pass.** A contract the reader does not fully read gives no readiness and no
  settlement: terms `unchecked`, readiness `unchecked`, `verify` exit 3 (I4, I13).
- **TC2 Terms belong to the edition.** Every evaluation uses the terms of the edition the statement binds to,
  never a later one (claims-model note §8, "bindings are to editions").
- **TC3 Nothing locks.** Intents, progress and grants never make a submission inadmissible. A coordinator's
  grant decides only whether a submission **counts** (§9.1: "submissions are always admissible").
- **TC4 Counting is not independence.** A count of keys or identities says nothing about independence;
  independence comes only from the evidence §9.3 accepts.
- **TC5 Time comes from verified bounds.** A deadline is evaluated against verified bounds only. Neither `ts`
  nor file order nor arrival order decides whether a submission met a deadline (I10, I14).
- **TC6 Order independence.** Readiness, grant effect and refutation binding are functions of the statements
  held and the reader's policy; delivery order and file order never change them (I14).
- **TC7 One declaration per role.** Each role (beneficiary, eligible issuers, counting unit, coordinator) has
  exactly one place in a contract for a given format major. A second declaration, anywhere, leaves the
  contract unread rather than picking one (I12).

## 3. The profile: `task-contract-v1`

### 3.1 Field table

`R` = required, `O` = optional. Types are the wire-format note §5 types. A list described as a set is sorted
and duplicate-free in the key order of the wire-format note §1, as `controllers` is.

| Field | Type | Meaning | Absent |
|---|---|---|---|
| `profile` | string R, `"task-contract-v1"` | names this profile (§3.3) | the contract is unread |
| `question` | string R | the question the task asks, as prose. Displayed, never evaluated | the contract is unread |
| `beneficiary` | key R (`rc/1`) | the decision authority: the only key whose `decide` settles (§9.2) | the contract is unread |
| `eligible_issuers` | list of key, a set, non-empty | keys whose submissions may count | exactly one of `eligible_issuers` and `any_issuer` (both or neither: unread) |
| `any_issuer` | `true` | any key's submission may count | as above |
| `counting_unit` | `"key"` · `"identity"` O | what a quorum counts (§5.3) | `key` in `rc/1` |
| `coordinator` | key O | the key whose `grant` statements decide which submissions count (§4.1) | no grant is required |
| `deadline` | object O, `{height: integer}` | the last block height at which a counted submission must be shown to exist (§4.3) | no deadline |
| `rubric` | list O of {`id` string R, `text` string O}; `id`s unique | acceptance criteria, each evaluated per submission (§5.5) | no rubric check |
| `quorum` | object O (below) | the counting predicate | settled by review, not by counting (§9.2, C-exch-06) |
| `sampling` | object O, the wire-format note §5 `sampling` shape: `n` integer R, `unit` string R, `groups` list of {`name` R, `n` R} O, names unique | the declared design the departure check compares delivered `sampling` with (§9.4) | no departure check |

`quorum` fields:

| Field | Type | Meaning |
|---|---|---|
| `k` | integer R, ≥ 1 | how many counting units a group needs |
| `independence` | `"not-required"` · `"required"` · `"self-declared-accepted"` R | §5.4 |
| `grouping` | object O: `{rule: "all-pairs"}` or `{rule: "reference", reference: key}` | how results group under a comparator (§5.2). Required when `comparator` or `test` is present; refused with neither (byte equality needs no rule) |
| `comparator` | digest O | a comparator skill, as the execution note §1 `comparator` field names one |
| `test` | digest O | a pinned statistical test for stochastic replication (#65); when present it is the comparator, and `comparator` must be absent |
| `estimand` | string O | what `test` estimates, as prose. Present only with `test` |

`sampling` is deliberately the same shape as the wire-format note §5 disclosure, so the departure check compares like
with like. The contract reads `n`, `unit` and `groups`; `window` and `dispersion` are disclosure fields with no
contract meaning, and a contract carrying them is unread (§3.3), not silently trimmed.

Not in the table, on purpose: required inputs and methods, deduplication, evidence strength and the
`results` declaration it needs (§6, Q1–Q3). A
field added before this note is accepted joins `task-contract-v1`; one added after is `task-contract-v2`. A
profile never changes meaning under a fixed name.

### 3.2 Role fields in `rc/1` and `rc/2`

The fixed-root identity candidate profile, proposed in a separate change and not accepted, would move the
task roles into a typed extension object in a new major, `rc/2`:
`body.x_identity_v1.task_roles` carries `beneficiary`, exactly one of `eligible_issuers` and `any_issuer`, and
an explicit `counting_unit`, each a typed key-or-identity subject. That candidate forbids the four fields at
the top level of a recognized contract profile and asks the task integration to register "a concrete contract
profile". This note is that profile. Its placement rule:

| Role | `rc/1` | `rc/2` (if the identity candidate is accepted) |
|---|---|---|
| `beneficiary` | in the contract, a key | in `task_roles` only; in the contract it leaves the contract unread |
| `eligible_issuers` / `any_issuer` | in the contract | in `task_roles` only; same |
| `counting_unit` | in the contract, optional, default `key` | in `task_roles`, required there; same |
| `coordinator` | in the contract, a key | in the contract, a key (§6, Q9) |

Every other field stays in the contract in both majors. Under `rc/2` the profile name does not change: the
placement follows from the major, which is in every payload type, so no reader can apply the wrong rule. TC7
holds in both: one place per role per major.

### 3.3 Recognition and unknown fields

- A contract whose `profile` the reader does not implement is **unread**: terms `unchecked`, naming the
  profile; readiness `unchecked`; no decision settles it, because its beneficiary is unread; `verify` exits 3.
  The provisional name `provisional-task-contract-0` is not an alias of `task-contract-v1` and is never
  upgraded to it.
- **A field not in §3.1, including an `x_` name, leaves the whole contract unread.** This departs on purpose
  from the wire-format note §6, where unknown body fields are retained and ignored. A contract's fields are
  restrictions: eligible issuers, a deadline, a test. A reader that ignored one it did not understand would
  report readiness under weaker terms than the beneficiary set, which is the false assurance I4 forbids. An
  extension to a contract is a new profile name. The departure is local to `contents.contract`; the edition
  statement around it follows the wire rules as usual. *Review: agreed (#109): a restriction a reader ignores
  is a weaker contract than the one signed.*
- A malformed field (wrong type, an empty `eligible_issuers`, a `grouping` without a comparator, duplicate
  rubric ids, a `reference` that is not a key) leaves the contract unread, naming the field. There is never a
  partial reading.
- A reader that implements `task-contract-v1` implements `grant` (§4.1), the `refutes` binding (§4.2) and
  `fulfills` submissions (§5.1) as well. A reader that read the terms but not the grants, or counted only
  `submit`s, would report a task `not ready` where the honest answer is that it cannot tell.

## 4. New wire elements

All three are minor changes under the wire-format note §6 (new kind, new optional fields): no major bump,
no existing signed bytes reinterpreted. Each needs a row in the wire-format note §5 when accepted.

### 4.1 `grant`

| `kind` | Body fields |
|---|---|
| `grant` | `task` id R · `edition` edition id R · `grantee` key R · `note` string O |

- **Effect.** A grant counts when its signer is the `coordinator` of the edition it names, that edition's
  contract is read, and the grant's line counts under the signer's key events (claims-model note §4.1). Then
  `grantee`'s submissions bound to that edition may count. Any other grant is shown as its signer's statement
  with no effect, naming why (C-exch-03).
- **Scope is one edition.** A grant does not carry to a later edition, even one with the same coordinator.
  A later edition's terms may be stricter (C-exch-07); a grant made against the earlier terms is not a grant
  under the later ones.
- **No time order.** A grant counts whether its signer published it before or after the grantee's submission
  (TC5, TC6). Grants decide what counts, not what was allowed when.
- **Not a lock.** A submission without a grant is still admissible and listed, as `admissible, not counted:
  no grant from <coordinator>` (TC3).
- **Grantee is a key.** Under an identity profile a grantee could be a typed subject; that waits for the
  identity profile (§6, Q9).
- **Name.** The identity candidate's `identity_grant` is a key-delegation statement, a different concept. The
  shared word is kept because §9.1 says "grants"; `task_grant` is the fallback if reviewers find the overlap
  confusing.

### 4.2 `refutes` bound to a task edition

| `kind` | Body fields (additions in bold) |
|---|---|
| `refutes` | `of` id R · `evidence` digest R · `note` string O · **`task` id O · `edition` edition id O** (both or neither; one alone is malformed) |

- **A bound refutation is a submission of that edition on the refutation track.** It is listed in the task
  view under its edition, may be cited by a `decide`, and is credited as a refutation (§9.4, C-exch-18). It is
  never counted toward a quorum group: it carries `evidence`, not a `result`.
- **`of` stays free.** A bound refutation may refute any statement: a submission of the same task, a result
  that submission rests on, or something outside the task. The binding says which task the refutation
  answers; `of` says what it refutes.
- **Unbound refutations** keep their present meaning: shown beside the statement they refute, credited as a
  refutation, not listed as a submission of any task. A reader does not infer a binding from `of`.
- **Grading** is unchanged: a refutation is graded on its own derivation and is exempt from the weakest-link
  rule (claims-model note §7).
- **Eligibility.** A bound refutation is admissible and credited whoever signs it; `eligible_issuers` limits
  quorum counting, which a refutation never enters (§6, Q10).

Alternatives considered: a `refutes` field on `submit` (it would make one kind mean two things, against the
closed vocabulary); inferring the task from `of` (the provisional reading does; it cannot tell a refutation
that answers a task from one that happens to touch it).

### 4.3 The deadline clock

A deadline is `{height: h}`: a height of the Bitcoin chain the reader validates (mainnet, bitcoin-time note
§7). For each submission (§5.1) bound to an edition with a deadline, the reader computes one outcome from the
submission's bound records (bitcoin-time note §8.1):

| Outcome | When |
|---|---|
| `ok` | a bound of quality `bitcoin`, state `verified` or `verified-historical`, covers the submission at height ≤ `h` |
| `unchecked` | no such bound, and either the reader's validated tip is below `h`, or a bound covering the submission is in a state that can still resolve (`pending`, `insufficient-confirmations`, `missing-proof`, `unknown-height`, `backend-unconfigured`, `backend-unavailable`, `stale-chain`) |
| `not shown` | no such bound, the validated tip is at or past `h`, and no covering bound can still resolve: every bound is verified above `h`, `local`, absent, `invalid-proof`, `invalid-anchor`, `orphaned`, or `unsupported` |

`not shown` is a statement about the evidence held, not a final verdict: a later `anchors` statement carrying
an upgraded proof that commits at or below `h` turns it into `ok`, as I5 allows relevant new evidence to.

- **Never "missed".** A verified bound is an upper bound on when a statement existed. A bound above `h` shows
  the submission existed by that later block, not that it did not exist by `h`: it may have been signed early
  and anchored late. The wire format has no lower bound on a statement's age. So the outcome is `not shown`,
  and `explain` says that a later bound does not show lateness. A submission that is `not shown` does not
  count; the honest answer to "is it on time?" for it is "not shown to be", and readiness reports exactly that.
- **`ts` meets nothing.** A submission whose `ts` is before the deadline and which has no qualifying bound is
  `unchecked` or `not shown`, never `ok` (TC5, C-exch-07a). The same holds for an observation's `capture.at`,
  which is the observer's word: the bound that meets the deadline is the observation statement's own.
- **Height, not `nTime`.** The bitcoin-time note orders by height and displays `nTime` as miner-reported, never
  an ordering key. Header `nTime` may decrease while height increases, and a node accepts it up to two hours
  ahead of its own clock; nothing a reader verifies bounds it tightly enough for a deadline to use. A calendar
  deadline is therefore not in v1 (§6, Q8). A contract that wants "about a week from now" writes the
  current height plus 1008.
- **An approximate date may be shown, never used.** Contract authors write heights from dates, so a reader may
  display an approximate date beside a deadline height, and beside a bound's height in an outcome. It is
  labelled as an estimate: for a height the reader has validated, the bound block's header `nTime`,
  miner-reported (as the bitcoin-time note §8.2 displays it); for a height above the validated tip, a
  projection from the tip, labelled as one. It is never an ordering key and never decides an outcome; it is
  display only, so it is not part of the contract and two readers may show different estimates for the
  same deadline.
- **What a deadline governs.** Only whether a submission counts. It never expires an intent, never turns
  progress into a lease and never makes a submission inadmissible (C-exch-02, TC3). It does not apply to
  bound refutations or to decisions.
- **Pending proofs settle.** Because the stamp-at-publish flow (bitcoin-time note §2) anchors before bytes
  leave the author, an honest on-time submission is normally `unchecked` for a few hours and then `ok`.

## 5. Readiness and settlement

### 5.1 Submissions, and when one counts

A **submission** of edition `E` is either of:

- a `submit` whose `task` and `edition` name `E`; its result is its `result` digest;
- an `authored` or `observed` statement whose `fulfills` names `E` (`resource` the task, `edition` the edition
  id); its result is its own `content.digest`.

`submit` is for a result that is not the submitter's own statement: a digest another key authored, or bytes
the submitter publishes no statement for. A statement carrying `fulfills` needs no `submit` beside it; a key
that sends both for the same digest has made two submissions of one result, which count once (§5.3; which of
them is read is §6 Q1).

- **The disclosure stays.** `fulfills` keeps its meaning as a disclosure (`pre-registered <edition>`,
  claims-model note §9.4, C-exch-15). Reading it as a submission adds a binding the task reads, exactly as it
  reads a `submit`'s `task`/`edition`, and changes nothing about the statement itself: its grade (for a
  derived result), its disclosures and its own `verify` exit are the same whether or not the reader holds the
  task (I6).
- **What it names.** A `fulfills` that names something other than an edition of that task (an approval's
  statement id, a collection's edition, a `resource` that is not the edition's task) is a submission of
  nothing, shown as the disclosure rules already show it.
- **Amendments.** An `authored` amended by its signer is read from its current claim (claims-model note §4):
  an amendment that drops `fulfills`, or names another edition, withdraws or moves the submission, in the
  key's log order (§6 Q1). The deadline (§4.3) reads the bounds of the statements naming `E` in the unbroken
  run that ends at the current claim, never the best bound of the whole chain: an amendment that adds
  `fulfills` late does not inherit the bound of an earlier statement that made no submission. The chain's
  bound shows the bytes existed; the deadline asks that the submission did.
- **`submit`-only fields.** A statement carrying `fulfills` has no `self_declared_independence`, so under
  `self-declared-accepted` it counts toward `k` only where its independence is established (§5.4).
- Bound refutations (§4.2) are submissions on the refutation track and never enter what follows.

A submission of `E`, with `E`'s terms read, counts toward `E`'s quorum when all of these hold:

1. its line counts under its signer's key events (claims-model note §4.1);
2. its signer is an eligible issuer (`eligible_issuers` contains it, or `any_issuer`);
3. if `E` names a coordinator, a counting grant (§4.1) names the signer for `E`;
4. every rubric criterion is `ok` for it (§5.5);
5. if `E` has a deadline, its deadline outcome is `ok` (§4.3).

A condition that is `unchecked` makes the submission **undecided**; a condition that is `fail` or `not shown`
makes it **not counted**. Both are listed with the reason. Every submission stays admissible (TC3): one
that does not meet `E`'s terms is a submission not counted, never a malformed statement. An observation
that carries `fulfills: E` from a key outside `eligible_issuers` is a valid `observed`, listed under `E` as
`not counted: not an eligible issuer`.

### 5.2 Grouping

- **No comparator, no test:** results group by byte equality of `result`. Equality is transitive, so no rule
  is needed and none may be given.
- **Comparator or test:** the contract's `grouping` decides. `all-pairs` forms the maximal sets in which every
  pair matches under the comparator; `reference` groups each result with the reference key's counted result
  and requires exactly one such result (none, or several, is `unchecked`, naming the count). A pair the
  comparator cannot decide is undecided, and enters readiness through the bracket (§5.6). No rule ever chains `A≈B`, `B≈C` into `{A,B,C}`
  (C-exch-12).
- **Observation results.** An observation's result is its content digest, so with no comparator two
  observation submissions group only when their bytes are identical. In every class but exact-bytes,
  identical bytes under a second key are a copy, not a second observation (claims-model note §5.3.1); such a
  group counts keys holding one capture (TC4), and `independence: required` is the term that keeps copies
  out. A contract that wants observations to agree under an agreement model (claims-model note §5.3.2) names
  that comparison as its `comparator`.
- **Bound on work.** All-pairs grouping is exponential in the number of distinct results. A reader declares a
  limit (the provisional reading uses 16 distinct results); above it, grouping is `unchecked` with the limit
  named, an operational limit under I8.
- Results in no group that reached the quorum stay visible as divergence reports, also after readiness
  (C-exch-14).

### 5.3 Counting

A group's count is the number of distinct counting units among its counted submissions. With `counting_unit:
key` the unit is the signing key: a key that submits the same result twice counts once, whatever the kinds
of the two submissions (a `submit` of `D` and an `authored` of `D` carrying `fulfills` are one result). With
`identity` the count needs an identity profile; with none active, readiness is `unknown`, naming the missing
profile, never a key count presented as an identity count. Every count is displayed with its unit (`2 keys`),
because keys are not people (TC4). How a unit that submits **different** results counts is open (§6, Q1);
counting by a member of an observation's referent, such as an instrument, is open too (§6, Q12).

### 5.4 Independence

| `independence` | What counts toward `k` |
|---|---|
| `not-required` | the group's count |
| `required` | only units whose independence the reader established with evidence §9.3 accepts (an implemented verifier checking a bound proof). Where the group would reach `k` but established independence does not, readiness is `unknown`, never a smaller count |
| `self-declared-accepted` | established units, plus units whose submission sets `self_declared_independence`. Readiness reached this way says so in the token and in the outcome (C-exch-11) |

Never evidence of independence: first publication, a commit-reveal match, distinct keys, labels with no
implemented verifier (§9.3, C-exch-09, C-btc-19).

### 5.5 Rubric granularity

- A criterion is evaluated **per submission**, by the reader's evaluator, to `ok`, `fail` or `unchecked` (§13).
  No evaluator for a criterion means `unchecked`.
- A submission passes the rubric when every criterion is `ok`. Any `fail`: not counted. Otherwise, with any
  `unchecked`: undecided.
- There is no separate task-level rubric verdict. What the rubric does to readiness is what it does to the
  submissions, through the bracket below.

### 5.6 Readiness: the bracket

For edition `E` the reader evaluates the quorum twice:

- **lower**: counted submissions only; undecided ones left out;
- **upper**: counted and undecided submissions, each undecided condition taken as passing.

| Lower reaches `k` | Upper reaches `k` | Token |
|---|---|---|
| yes | (yes) | `ready` (with `self-declared` where §5.4 says so) |
| no | no | `not ready` |
| no | yes | `unknown` if missing independence is among the reasons, else `unchecked` |

Independence enters the same way: under `required`, a unit without established independence is undecided
for independence. So does grouping: a comparison the comparator could not decide is non-matching in the lower
evaluation and matching in the upper one. `explain` names every undecided submission and its reason, for
every token.

The bracket is the claims-model note's rules taken literally: `unknown, not a smaller count` (§9.3) is the
upper bound refusing to be reported as the lower one, and I4 is the lower bound refusing to be reported as the
upper one. It also closes a gap in the provisional reading, which marks the whole edition `unchecked` whenever
any counted submission has an unchecked criterion, even when `k` other submissions have already passed every
criterion and agree. Under that rule any eligible issuer can hold a ready task at exit 3 by submitting a result
the evaluator cannot assess, which is the third-party veto I7 forbids.

A contract with no `quorum` is settled by review: the token is `settled by review, not by counting` and no
bracket is computed (C-exch-06). Per-submission rubric and deadline outcomes are still shown, to inform the
beneficiary's review; with nothing being counted, they do not change the exit.

### 5.7 `verify` of a task

The claims-model note §13 defines `verify` exits; for a task it reads:

| Exit | When |
|---|---|
| 0 | the current edition's readiness is `ready`, `not ready` or `settled by review`, and no decision conflict |
| 3 | the terms are unread; readiness is `unknown` or `unchecked`; or the beneficiary's decisions conflict (C-exch-05) |

`not ready` exits 0: it is a completed check whose answer is "not yet", not "checked and wrong". Exit 1 stays
reserved for a comparison that ran and disagreed (§13); a divergent submission is reported, and the task
check is not itself a comparison. A §13 line saying so is proposed with this note's acceptance.

### 5.8 Settlement

A `decide` settles when its signer is the bound edition's beneficiary (or, under `rc/2`, holds what the
identity profile requires) and it cites at least one submission (§5.1, by statement id, whatever its kind) or
bound refutation of that edition. It is the beneficiary's judgment and may differ from readiness; both are
shown. Contradictory decisions stay a visible conflict until one explicitly supersedes another (§9.2).
Nothing in this profile makes a decision from readiness automatically.

## 6. Open questions

Each question lists options and a lean. A lean is a proposal for review, not a decision. *Review: agreed*
marks a lean an outside review on #109 agreed with; it records the review, and decides nothing.

1. **Deduplication.** §9.3 asks the predicate to state it. What happens when one counting unit submits several
   results to one edition?
   (a) the unit counts once in each group it appears in (the provisional reading; a unit that hedges across
   divergent results counts toward every one of them);
   (b) a unit with divergent results counts in none;
   (c) a unit's **current** submission counts: the one with no later submission to the same edition in its log
   order (wire-format note §7), whatever the kinds (a `submit`, or an `authored` or `observed` carrying
   `fulfills`, §5.1), as a key's current `holds` is read; branches of an uncleared fork that disagree count in
   none and are shown.
   **Lean: (c).** It uses the one order a key's own statements have, never `ts`, closes the hedge, and gives an
   honest correction a way to replace an error: a corrected export carrying `fulfills` supersedes the
   erroneous one by being later in the same log. A `dedup` field is not needed while there is one rule.
   *Review: agreed (#109).*
2. **Required evidence strength.** Does a re-derived result count for more than a bare submission?
   (a) no requirement: any counted submission counts;
   (b) `quorum.min_grade`, `"T0"`/`"T1"`/`"T2"`: a submission counts only if the reader's own grade of its
   result (claims-model note §7) is at least that, `unchecked` while ungraded;
   (c) weights per evidence class.
   **Lean: (b), as an optional field, for derived results only.** It reuses the grades the reader already
   computes. (c) is rejected: a weighted sum hides why a quorum was reached.
   Grades rank derivation, and observations are not a tier (claims-model note §7), so `min_grade` cannot
   apply to an observation submission (§5.1): read literally, it would fail every one. Under (b), therefore:
   - `min_grade` is read only on a contract that accepts derived results alone. Since every contract accepts
     `fulfills` observations as submissions (§5.1), that needs a declaration: (b) brings an optional
     `results`, `"derived"` · `"observed"` (absent: either), and `min_grade` without `results: "derived"`
     leaves the contract unread, naming the field (§3.3), so a quorum is never computed under a term that
     cannot apply to its submissions. Under `results: "derived"`, an `observed` carrying `fulfills` is a
     submission not counted, `not a derived result`; under `"observed"`, a `submit` or an `authored` is not
     counted, `not an observation`. Neither is malformed (§5.1).
   - The observation analogue of a grade is capture evidence (claims-model note §5.3.3). A
     `min_capture_evidence` beside `min_grade` reads well but waits: the declared levels are a closed set
     (wire-format note §5, `capture.evidence`), but the claims-model note gives them no order and the tool
     displays only the levels it verified (`device-attested (unverified)`), so there is no closed vocabulary
     of verified, ordered levels for a contract to name yet. Until there is, a contract cannot require one.
   - Corroboration never gates a count. It is a disclosure, scoped to the statements a reader holds and the
     agreement models it trusts (claims-model note §5.3.2), and a disclosure never moves a verification
     result (I6). A contract that wants agreement among observations says so through `comparator` (§5.2).
3. **Required inputs and methods.** §9.1 says the contract pins them.
   (a) prose in `question` only;
   (b) exact pins, read from where each kind of result records its method and inputs:
   - for a **derived result**, `provenance` (wire-format note §5): `workflow`, a digest `provenance.workflow`
     must equal, and `inputs`, a set of digests `provenance.inputs` must include (under
     `provenance_partial`, a pinned input missing from its pinned `inputs` may be one of its `unpinned`
     names, so it is `unchecked`, not `fail`);
   - for an **observation**, its method referent (claims-model note §5.3.1; wire-format note §5, method
     class): `method_edition`, an edition id `referent.method_edition` must equal, and the same `inputs` set,
     which `referent.inputs` must include;
   with the same outcomes for both: `ok`; `fail` when the record is held and does not match (including an
   observation of another class, or a derived result with no `provenance`, under a contract that pins a
   method: neither can show it followed one); `unchecked` when the record is not held (a `submit` whose
   result's `authored` or `observed` the reader does not hold) or a pinned member is `unpinned` in the
   referent (it is then the observer's omission, not a mismatch). A pin is never skipped: a contract that
   pins only `workflow` fails every observation submission, one that pins only `method_edition` fails every
   derived result, and one that pins both checks each result against the pin for its kind;
   (c) an expression in a rule dialect (claims-model note §8).
   **Lean: (b).** Exact pins check without a dialect, and "under method edition M, on scenario edition S" is
   then an exact pin for a benchmark batch. Ranges (a harness commit in a range, an environment within a
   family) are (c), when the rule-dialect note exists. The environment record is not pinned under (b):
   which environment fields must match is the workflow author's `environment_match` (execution note §1), not
   a task term.
4. **Commit-reveal.** `submit` has an optional `salt`, and no note says what is hashed or how the commitment
   is published.
   (a) reuse the claims-model note §7 mechanism: the commitment is an `authored` statement with availability
   withheld until the task edition, the reveal a later `holds`, and the `submit` names the result by the
   committed digest; `salt` is retired;
   (b) define `submit.salt`: a prior `submit` carries `result = sha256(result bytes ‖ salt)`, the reveal carries
   the plain digest and the salt;
   (c) drop commit-reveal from tasks.
   **Lean: (a).** It needs no new construction, and its cautions (possession by T, never independence;
   a nonce for low-entropy content) are already written. Under (a), a commitment that itself carries
   `fulfills` is the submission (§5.1) and needs no `submit`; its own bound is the one the deadline reads.
   Sub-question, for a `submit` that names an earlier commitment: may the commitment's bound, rather than the
   submission's, meet the deadline? Leaning yes, when the submission names that commitment: the plan of
   "commit before the deadline, reveal after" is the use the mechanism exists for. Under every option the
   match shows possession by T only (C-exch-09 (b), C-btc-19). *Review: agreed (#109), the sub-question
   included: the withheld-availability commitment is the held-out-pool pattern, and its bound meeting the
   deadline is the use it exists for.*
5. **Credit definitions.** §9.5 names six counts and defines none; §9.4 says refutations are credited "on
   their own track", which is a seventh. Proposed definitions, each over counted statements in the reader's
   window: **contribution**, the key's submissions (§5.1, whatever their kind); **citation**, other keys'
   `authored` whose provenance names a blob the key authored; **reproduction**, the key's `reproduced`;
   **refutation**, the key's `refutes`; **review**, the key's counted `decide`s; **corroboration**, the key's
   `corroborates`; **acceptance**, the key's submissions whose beneficiary decision, after supersession, is
   `accept`.
   (a) these, with §9.5 amended to name refutation;
   (b) leave definitions to readers.
   **Lean: (a)**, with denominators still the reader's choice and no default projection.
6. **Grant withdrawal.**
   (a) none: a grant lasts for its edition; to exclude a grantee the controllers publish a new edition and the
   coordinator re-grants;
   (b) `grant` with `withdrawn: true`, the coordinator's current grant read by its own log order. Sound, because
   one key orders it, but **retroactive**: a withdrawn grant counts toward nothing, including for submissions
   made while it stood, since no cross-key time order exists to say "made while it stood".
   **Lean: (a)** for v1. (b) is coherent, and the retroactivity would have to be stated where users read.
7. **Counting unit for corroboration.** Should a reader's corroboration counts (claims-model note §5.3.2) follow the task's
   `counting_unit`? **Lean: no.** Corroboration is a reader-side projection with no contract behind it; its unit
   is reader policy. Tasks count by their contract.
8. **Calendar deadlines.**
   (a) none in v1: heights only;
   (b) `{at: ts}` compared with the bound block's `nTime` plus a reader-declared margin, labelled
   miner-reported;
   (c) `{at: ts}` evaluated by a later time-conversion profile, `unchecked` until one exists.
   **Lean: (a).** (b) makes `nTime` an ordering key, which the bitcoin-time note rules out. (c) would let a
   contract be written that no reader can ever check, which is worse than not offering it. Display is
   separate: an approximate date may be shown beside a height, labelled as an estimate from the bound block's
   `nTime` (miner-reported), never used for ordering (§4.3). *Review: agreed (#109), with the display ask
   that §4.3 now answers.*
9. **The coordinator under identities.** Under `rc/2`, is the coordinator a typed subject, and does it move
   into `task_roles`? **Lean:** a key in the contract for v1; an identity coordinator, and identity grantees,
   wait for the identity profile to be accepted and are a v2 question.
10. **Who may refute a task.** Should `eligible_issuers` limit bound refutations? **Lean: no.** A refutation
    never counts toward a quorum, and the contract's author should not be able to choose who may criticise the
    results it accepts. *Review: agreed (#109).*
11. **Rubric dialects.** Criteria are prose with ids, and the evaluator is the reader's.
    (a) keep it so;
    (b) let a criterion carry `dialect` and `expr`, as edition rules do (claims-model note §8).
    **Lean: (a) now, (b) when the rule-dialect note exists.** An evaluator that understands nothing yields
    `unchecked`, so prose criteria are honest, if unhelpful to automation.
12. **Counting by a referent member.** An observation quorum may count instruments, not signers: "at most one
    per `system.machine_ref` per routing era". One key can run several machines and one machine can be
    published under several keys, so neither `key` nor `identity` (§5.3) expresses it.
    (a) a third `counting_unit` form, `{referent: "<member path>"}`, e.g. `{referent: "system.machine_ref"}`:
    the unit is that member's value in each counted submission's method referent. A submission whose referent
    lacks the member is undecided (it enters the bracket, §5.6); one with no method referent (a `submit` of a
    derived result) is not counted, naming why. The count is displayed in its unit (`3 machine_ref values`)
    and is the observers' word, not a verified count of machines: like a key count it says nothing about
    independence (TC4). "Per routing era" is a second member read the same way, so (a) would also need a
    grouping by member, which this option leaves to a later field;
    (b) counting by a referent member is a rule-dialect matter, as set-level edition rules are ("at most one
    endorsed member per instrument per era", claims-model note §8), and v1 says so explicitly: a contract
    that needs it either counts by `key` and says in its `question` what it cannot enforce, or has no
    `quorum` and is settled by review (§5.6), where the beneficiary applies the rule.
    **Lean: (b) for v1.** (a) depends on a gap in the format: claims-model note §5.3.1 says a method edition
    declares the members of the measured system an observation under it must pin, but no wire field carries
    that declaration (the `edition` contents in wire-format note §5 have no member for it), and the reference
    implementation meets C-core-32 only in part for that reason. A unit read from members the method has not
    declared would key on something one observer pins and another omits, or spells differently. Once a method
    edition can declare its system members, (a) reads well, with "missing member → undecided" and a contract
    allowed to name only a declared member (any other leaves it unread, §3.3). The field is proposed in #112
    (`edition.contents.system_keys`, C-core-32a – 32d); the lean is revisited when it is accepted and built.

## 7. Conformance impact

What this profile changes for the exchange cases. "Unblocked" means the case's outcome becomes fully
specified; the implementation still has to meet it.

| Case | Before this note | With `task-contract-v1` |
|---|---|---|
| C-exch-01 | no term needed | unchanged; TC3 restates it |
| C-exch-02 | the deadline it mentions had no meaning | unblocked: a deadline never expires an intent or extends anything (§4.3) |
| C-exch-03 | no grant kind; no coordinator field | unblocked by `coordinator` and `grant` (§3.1, §4.1) |
| C-exch-04, C-exch-05 | beneficiary unreadable | unblocked by `beneficiary` (§3.1) and §5.8 |
| C-exch-06 | "no quorum" undefined | unblocked: absent `quorum` (§3.1) |
| C-exch-07 | deadline has no clock | unblocked by §4.3, TC2 |
| C-exch-08 | per-criterion only; task granularity undefined | unblocked by §5.5, §5.6 |
| C-exch-09 | independence term unreadable; commit-reveal construction undefined | terms unblocked (§5.4); generator (b) waits on §6 Q4 |
| C-exch-10 | eligible issuers unreadable | eligibility unblocked; the verifier is an attestation-note matter |
| C-exch-11 | independence term unreadable | unblocked by `self-declared-accepted` (§5.4) |
| C-exch-12, C-exch-14 | grouping rule unreadable | unblocked by `quorum.grouping` (§5.2) |
| C-exch-13 | estimand and test unreadable | fields unblocked; the test itself is a comparison-dialect matter |
| C-exch-15, C-exch-16 | a `fulfills` statement is displayed, never counted | display unchanged; the statement is also a submission of the edition it names (§5.1), pinned by C-exch-15a |
| C-exch-17 | declared sampling unreadable | unblocked by `sampling` (§3.1) |
| C-exch-18 | a refutation cannot name a task | unblocked by §4.2 |
| C-exch-19, C-exch-20 | counts named, not defined | waits on §6 Q5 |
| C-btc-19 | no term needed | unchanged; §5.4 and §6 Q4 restate it |

New cases, proposed with this note in `CONFORMANCE.md` (exchange profile, by section):

| id | pins |
|---|---|
| C-exch-03a | §3.3 recognition: unknown profile, unknown field (including `x_`), malformed field, the provisional profile name, a role field in the wrong place for the major; all unread, exit 3, and no submission counted, a `fulfills` one included |
| C-exch-03b | §4.1 grant scope: coordinator vs other signer, grant naming another edition, grant not carried to a later edition, grant published after the submission still counts, in every delivery order |
| C-exch-07a | §4.3 deadline outcomes: `ok`, `unchecked` (tip below `h`; pending proof), `not shown` (bound above `h`; `local` only); `ts` before `h` never `ok`; no output says "missed" or "late"; a `fulfills` submission read from its own bound |
| C-exch-08a | §5.6 bracket and §5.7 exit: `k` passing submissions plus one undecided elsewhere is `ready`, exit 0; `k−1` plus one undecided is `unchecked`, exit 3; `k−1` plus one failing is `not ready`, exit 0 |
| C-exch-15a | §5.1 submissions: an `authored` or `observed` carrying `fulfills` is a submission whose result is its content digest; with a `submit` of the same digest it counts once; outside `eligible_issuers` it is not counted, never malformed; a `fulfills` naming no task edition is no submission; the statement's grade is the same with or without the task held |
| C-exch-18a | §4.2 binding: bound refutation listed and credited on its own track and never grouped; `task` without `edition` malformed; an unbound refutation of a submission is shown beside it but not listed in the task |

Deduplication, evidence strength, inputs and methods, commit-reveal and counting by a referent member get
cases when their questions are answered.

## 8. Relationship to the provisional reading

The provisional reading (`provisional-task-contract-0`) was written to make the exchange layer testable before
this note existed, and most of this profile is its field table. Where they differ, this note proposes the
change, and the provisional reading keeps its own name, so no contract silently changes meaning:

| Point | Provisional reading | This note |
|---|---|---|
| `question` | not read | required (§3.1) |
| `deadline` | a string, displayed, never evaluated | `{height}`, evaluated against verified bounds (§4.3) |
| rubric over many submissions | edition `unchecked` if any counted submission has an unchecked criterion | the bracket (§5.6) |
| malformed nested objects | a non-object `grouping` or `sampling` is read as absent | every malformed field leaves the contract unread (§3.3) |
| duplicate rubric ids | accepted | malformed |
| `grouping` without a comparator | accepted and unused | malformed |
| `comparator` and `test` together; `estimand` without `test` | accepted (`test` wins) | malformed |
| `eligible_issuers` order | any order, duplicates accepted | a set: sorted, duplicate-free |
| what is a submission | `submit` only; a `fulfills` statement is a disclosure | `submit`, and an `authored` or `observed` carrying `fulfills` (§5.1) |
| refutation binding | inferred from `of` | explicit `task`/`edition` (§4.2) |
| grants | read through a stand-in, not a wire kind | `grant` (§4.1) |
| credit | seven counts, as in §6 Q5 | the same, pending Q5 |

## 9. Out of scope

Comparison dialects and the statistical tests `quorum.test` pins; rubric and rule dialects; attestation
verifiers that establish independence; the identity profile and anything an identity grantee or coordinator
needs; reputation, payment or any transferable entitlement (§9.5: none is created); scheduling, reminders or
any liveness mechanism beyond the existing `intent`/`progress`/`withdraw` kinds.
