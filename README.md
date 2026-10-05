# Research Commons

A toolkit for **reproducible, attributable research** with human and AI collaborators.
You get a content-addressed store of datasets, methods, and results, with signed
provenance, verification tiers, and git-based federation.

**Thesis:** understanding the world with AI collaborators takes shared datasets,
reproducible analysis, and common methods of interpretation. If the evidence base is
pinned, then agreement between different model families working from the same data and
methods tells you something: it approximates independent replication.

**New here? Read [`docs/WHY.md`](docs/WHY.md)**: the motivation and the epistemics, in
five minutes, with no CLI.

> **Status: alpha preview.** The core is complete and drilled end to end: verification
> tiers and chain grading, a signed per-peer ledger, git federation with an ingest gate,
> sandboxed execution, a task/claim/settle exchange with replication quorums, collections,
> and time anchoring (regression suite: `tests/run-all.sh`). There's no hosted service and
> no network yet: just git, python3, and the people you choose to trust.
>
> Run `commons --version` to see the currently checked-out tool version and data-format
> schema (independent of each other — see [`docs/RELEASING.md`](docs/RELEASING.md)).
> Release history: [`CHANGELOG.md`](CHANGELOG.md).

## This repository is the tool, not the data

**This repo contains code only. Artifacts live in hubs.** A **hub** is a separate,
data-only git repo (`registry/` + `store/`) for one topic or community. You clone this tool
once and clone any number of hubs. When you run `commons` from inside a hub clone, it
finds the hub on its own.

```
research-commons/      ← this repo: bin/commons, lib/, tests, docs      (code — reviewed, pulled deliberately)
my-topic-hub/          ← a hub: .commons-hub, registry/, store/         (data — ingested through a gate)
```

The separation is a security boundary, not just tidiness. `commons pull` refuses any
incoming change outside `registry/` and `store/`, and hub CI rejects such pull requests.
So pulling a collaborator's data can never change the code you run.

| I want to… | Do this |
|---|---|
| **Read and verify** someone's research | Clone this repo, clone their hub, `cd` into it, `commons list --type collection`. |
| **Start a topic** and invite collaborators | `commons hub init <dir>`, publish a collection, push the hub, share the **hub** URL. |
| **Contribute** to an existing topic | Clone (or fork) **that hub**, publish on a branch, open a PR, send the lead your address. |
| Change the **tool** itself | Fork *this* repo and open a PR here. Never put collections in a tool fork. |

**Full walkthrough, roles, and FAQ: [`docs/COLLABORATING.md`](docs/COLLABORATING.md).**

## Quick start

```bash
git clone https://github.com/research-common/research-commons.git ~/research-commons
cd ~/research-commons && npm ci          # viem, only needed for signing
export PATH="$HOME/research-commons/bin:$PATH"
tests/run-all.sh cold-path               # smoke test (full suite: tests/run-all.sh)

# start a hub
commons hub init ~/hubs/my-topic --name "My topic"
cd ~/hubs/my-topic
commons hub where                        # confirms the data root in use

# identity (a PATH to a key file outside every repo, never the key itself)
export COMMONS_SIGNING_KEY=~/.commons/signing.key COMMONS_AGENT=<handle>
commons peer whoami                      # see docs/COLLABORATING.md §1 to mint the key

# discover (in any hub)
commons list --type collection           # topics in this hub
commons collection show <cl-id>          # endorsed vs. claimed members + open work
commons search "some phrase"             # full-text search across artifacts
commons get <id> / cat <id> / links <id> # manifest, content, citation edges
commons graph <id> --depth 10            # transitive evidence tree

# contribute
commons publish dataset data.csv "Title" -d "desc" -t tag --license CC0-1.0 --obtainability open
commons publish report report.md "Title" --input ds-XXXX --link cites:sy-YYYY --link part-of:cl-ZZZZ

# reproduce
commons run wf-XXXX --publish --publish-type synthesis   # execute + auto-provenance
commons verify <id>                      # re-derive per tier → PASS/FAIL
commons status <id> --depth 10           # evidence chain + chain grade (weakest link)
commons tiers                            # what the tiers mean
```

Requirements: `git`, `python3` ≥3.10 (stdlib only). Signing needs `node` ≥18 plus
`npm ci`. Docker (or Podman) is needed only for sandboxed execution.

The rest of this file is the reference manual. Example ids (`cl-304d7331`,
`sy-c775b533`, …) come from a synthetic demo hub, built by `scripts/demo-hub.sh` into
a throwaway `COMMONS_ROOT`. Run it yourself and every id below resolves; in your own
hub, substitute ids from `commons list`.

## Verification tiers

Every tiered evidence artifact declares what its correctness claim rests on. `commons verify`
dispatches on the tier; the exit code tells scripts which kind of answer they got.

| Tier | Name | Guarantee | `verify` | exit |
|---|---|---|---|---|
| `T0` | bitwise | re-run of the recorded workflow reproduces identical bytes | re-runs + hash compare | 0 / 1 / 5 |
| `T1` | tolerance | re-run reproduces an equivalent result under the declared comparator | re-runs + comparator skill | 0 / 1 / 5 |
| `T2` | judged | independent review against a rubric declared before the work was claimed | prints guarantee + rubric | 3 |
| `T3` | attested | signer attests a one-time observation; raw capture is published as-is | checks the signature only — attestation binding, criteria drift, key validity at `observed`; **no capture-format check exists** | 3 (1 if invalid/stale) |
| `unverified` | — | no verification guarantee is declared by the publisher | prints guarantee when no workflow is recorded | 4 without workflow; 0 / 1 / 5 with workflow |

```bash
# defaults: T0 with --workflow · T3 for datasets · none for workflow/skill · else unverified
$COMMONS publish dataset snap.json "API snapshot" --tier T3 --criteria "GET /v1/x at 2026-07-25T00:00Z"
$COMMONS publish report note.md "Analysis" --tier T2 --criteria "Rubric: every number traces to a cited artifact"
$COMMONS publish synthesis out.json "Floats" --tier T1 --criteria sk-e0f1d443 --param EPSILON=1e-6
```

A T3 publisher may initially record only self-reported criteria; `commons attest` names
the signer and binds `{id, sha256, criteria, observed}` to that address. On ingest an
attester, if present, must be a registered peer with non-`none` trust (`datasets-only` or `full` for
non-method artifacts). The signature proves who signed that statement, not that the
observation is true or that its self-declared time is independently trustworthy.

**Chain grade.** `commons status <id>` walks provenance + `based-on`/`cites`/`derives`/
`refutes`/`supports` links (cycle-safe, depth cap 10) and reports the **weakest tier in the evidence chain**.
A perfect T0 re-derivation over an attested dataset grades T3 — re-deriving flawlessly
from an unverifiable input doesn't make the input verifiable. Exit: 0 for T0/T1 chains,
3 if any T2/T3, 4 if anything is unverified or missing. `workflow` and `skill` methods
are pinned by content hash and deliberately excluded from the ladder: a method-only
`status` reports `chain grade: n/a` / `no tiered evidence nodes` and exits 0, while
running `verify` directly on that untiered method reports UNVERIFIED and exits 4.
The `status` exclusion still applies if a method manifest carries an explicitly
declared tier. More generally, T0/T1 without `provenance.workflow` report UNVERIFIED
from `verify` and exit 4.
Surprisingly, an explicitly `unverified` artifact with `provenance.workflow` currently
takes the bitwise re-run path and returns 0, 1, or 5 rather than 4.

## Identity & signed ledger

Ledger entries are signed with EIP-191 (`personal_sign`), using viem (installed by
`npm ci`) — no new crypto, no keys in config. Each entry carries two signatures from the same
key. `sig` covers canonical JSON of `{action, agent, id, sha256, ts}`, which every version of
the tool verifies. `sig2` covers `{"rc": "ledger/2", "entry": …}`, the whole entry except
`addr`, `sig`, `sig2` and `prev`, so it also binds fields like an accept's `result` or a
rebaseline's exec record. An entry whose `sig2` fails is a forgery. Entries from before
`sig2` existed carry `sig` only, and readers bind their open fields by other means (below). The key is read from the file named by `COMMONS_SIGNING_KEY` and from
nowhere else: no other signing tool's environment variable is consulted, so a wallet key
exported for some other program can never silently become your commons identity.

```bash
export COMMONS_SIGNING_KEY=~/.commons/signing.key   # a path, never a literal key
$COMMONS peer whoami                                 # this host's signing address
$COMMONS peer add 0xABC… --agent-id bob --trust datasets-only --note "second machine"
$COMMONS log --verify                                # signatures + chain + registry + windows
$COMMONS fsck --ledger                               # blobs and ledger in one pass
```

Unset `COMMONS_SIGNING_KEY` and entries are written `"sig": null` — legal locally, and
`log --verify` reports them as *unsigned* rather than pretending they're trusted
(`--strict` makes them failures).

**Trust levels:** `full` · `datasets-only` · `none`.

**Key lifecycle.** Entries are judged against a key's validity *window*, so rotation
doesn't invalidate history: revoking affects what a key signed *after* `revoked_at` only.

```bash
$COMMONS peer revoke 0xOLD… --at 2026-08-01T00:00:00Z   # preferred over `peer rm`
$COMMONS peer add 0xNEW… --agent-id bob --rotated-from 0xOLD…
```

See [Discovery (Stage 2)](#discovery-stage-2) for the read-only
`commons peer suggest [--json] [--all]` workflow.


`peer rm` exists but makes that peer's past entries *unverifiable* rather than
historically valid — prefer `revoke`.

**Hash chain.** Every line carries `prev` = sha256 of the previous line, so deleting or
reordering entries is detectable, not just editing fields.

`commons peer stats` reputation is based on signed ledger events and is all-time by
default. `peer stats --window 30d` gives rolling-epoch reputation; events with a missing
or unparseable `ts` are excluded from windowed counts because they cannot prove recency.
`peer stats --shaped` composes with `--window`/`--json` and re-renders the SAME folded
counts through a diminishing-returns curve (`ceil(10/√rank)` per category, capped at 50)
so a flooding peer cannot outscore a modest contributor by raw volume alone. This is an
example shaping policy, not a core protocol formula — the raw counts are always still
available with no flag, and shaping never changes the ledger, the fold, or any exit code.

## Capacity exchange

Publish work others can pick up; pick up work others published.

```bash
$COMMONS queue                       # open tasks by priority
$COMMONS queue --collection cl-abc   # scoped to a topic
$COMMONS claim tk-abc --ttl 24h      # signed, TTL-bounded
$COMMONS heartbeat tk-abc            # liveness evidence only — does NOT extend the claim TTL
$COMMONS release tk-abc              # give up early, freeing the slot now
$COMMONS run-task tk-abc             # foreign tasks ALWAYS run sandboxed
$COMMONS commit-derivation tk-abc …  # commit-reveal: independent work, before you see others'
$COMMONS submit tk-abc sy-def        # result must already be published
$COMMONS accept tk-abc               # beneficiary only
$COMMONS reject tk-abc --reason "…"  # reason is mandatory
$COMMONS settle tk-abc               # auto-accept once k distinct signers agree
```

**Tasks are contracts.** Publishing lints them hard, because they cannot be edited
afterwards: criteria required *before* anyone can claim (rubric-before-claim), expiry
required, T0/T1 must name a runnable workflow, and **a T2 rubric may not reference the
generating model** — rubrics judge output, never pedigree.

**Lifecycle is folded from the ledger**, never stored: claim expiry needs no daemon, and
the queue is a view that cannot disagree with the log. Unsigned or invalidly-signed
events are dropped when computing state, not merely flagged.

**`claim` warns about federation lag, advisory only.** Within one registry the ledger
fold can't disagree with itself, but replication across peers is asynchronous, so a
claim can race a remote change that hasn't landed here yet. Before signing, `claim`
warns on stderr when (a) a declared task input has since been superseded by a newer
artifact, or (b) a result already exists locally that links `fulfills` this task with no
recorded `submit` event yet (its manifest replicated ahead of the ledger line naming
it). Same posture as anchor-drift: printed to stderr, never blocks the claim, never
moves an exit code — only the claimant has enough context to decide whether to proceed.

**Foreign tasks are sandboxed in code.** `COMMONS_EXEC=native` is explicitly ignored when
the beneficiary is not you. An env var is not a security boundary.

**Settlement is replication, not counting.** `settle` accepts when *k distinct signers*
produce byte-identical results. Divergence refuses to auto-settle and reports every
distinct result — on a machine tier, two answers is a finding about the pipeline, not a
tie to break. Because that finding lives only in stdout, `settle` also points at
`docs/DESIGN-notes-divergence-reports.md`, the convention for turning a located
disagreement into a durable `type=report` artifact and a follow-up task.

That advisory is **tier-guarded** (2026-09-10): the same detector fires at every tier but
does not mean the same thing at each. A machine tier asserted byte-identical re-derivation,
so divergence falsifies a property the task claimed; a judged rubric never promised
identical bytes, so two reviewers disagreeing is the expected — often most valuable —
outcome of review, and telling that operator to go debug determinism sends them after a
property their task never asserted. `settle` and `status` now branch the wording on tier.
Only the prose branches: both exit codes are unchanged at every tier and regression-tested
as such.

**Diversity quorums need attested families.** `generation.model_family` is advisory when
self-reported and only counts toward a quorum at `attestation: receipt|tee` — otherwise
the quorum re-monetizes the model claim it exists to test.

**Structured T2 judgements (2026-09-15).** On a judged tier the claim is a *judgement*,
not bytes, so a T2 quorum settles on **per-criterion verdict vectors**:

```bash
# task spec: enumerate the rubric alongside the prose criteria
"verification": {"tier": "T2", "criteria": "cites; traces; scope",
                 "criteria_list": [{"id": "cites",  "text": "every claim cites an artifact id"},
                                   {"id": "traces", "text": "every number traces to a cited artifact"},
                                   {"id": "scope",  "text": "no claim exceeds the cited evidence"}]},
"diversity_quorum": {"k": 2, "distinct_families": 2}

# reviewer: publish the review with a verdict per criterion, then submit
$COMMONS publish report review.md "Review" --tier T2 --criteria "rubric of tk-…" \
    --judgement cites=pass --judgement traces=pass --judgement scope=fail
$COMMONS submit tk-… rp-…
```

- Two reviews in **different prose with the same verdicts agree**; identical prose with
  different verdicts diverges. `settle` groups T2 submissions by the vector (ordered by the
  task's `criteria_list`), `status` prints a per-criterion table and marks `← SPLIT` where
  reviewers disagree, and a T2 divergence names the split criteria instead of talking about
  determinism. The ledger records `settlement: verdict-quorum` with the agreed vector.
- **Independence still rides on the prose.** A copied review with a retyped vector is still
  a copy (content-address dedup → concurring reference, zero quorum weight).
- Verdict vocabulary is closed: `pass|fail|NA`. `submit` refuses a judgement that names
  criteria the task did not declare or omits ones it did; a prose-only result on a
  structured task is refused unless `--force`d (then it is unassessed, not a rival verdict).
- **Lint:** a T2 task with `diversity_quorum.k > 1` must declare `criteria_list` — without it
  the quorum had no reachable success state (measured 2026-08-26: same verdict in different
  prose read `DIVERGENT`; identical prose deduped and stalled at 1/2). `criteria_list` on a
  machine tier is refused; the prose `criteria` stays required; nothing existing is
  invalidated (prose-only T2 tasks without a quorum behave exactly as before).
- **The honest caveat, stated as part of the tier guarantee:** a verdict vector is coarser
  than a review. Two judges agreeing on `pass/pass/fail` may disagree about *why*. The vector
  locates agreement; the prose remains the evidence — read it before citing a T2 quorum as
  congruence. (Adopted 2026-09-15.)

**Observation captures (T3 results on a judged task).** A task can't be T3, but a T2 task
with a prose protocol-conformance rubric can collect attested T3 captures from several
contributors (an interim pattern until a dedicated observation-task kind exists).
Captures of a live system are expected to differ, so when every submission is T3, `status`
prints `observations: N T3 capture(s) from K distinct signer(s)` instead of a congruence
verdict, and `submit` notes that review judges protocol conformance, not truth, instead of
asking for a `generation` block. Display only: exit codes and `settle` are unchanged, and
mixed submissions keep the congruence profile.

**A copy is not a derivation.** Submitting an artifact someone else published first is
honest and useful — it *fulfills* the task — but it counts as a **concurring reference**
with zero quorum weight, and `submit` tells you so at the time. To count as independent,
post `commit-derivation` before the result is public: revealing the salt at submit time
proves you knew the bytes while they were still unguessable. For a replication quorum
that means **commit before you derive**, not just before the original was published — in
the 2026-08-07 cross-machine drill an honest byte-identical re-derivation with no prior
commitment correctly earned zero quorum weight. Asserting an earlier timestamp instead
does not work — see Time anchoring. Ordering needs **signed** publish events: if any
publish event for the artifact is unsigned, its publication time is nobody's signed word,
so no commit can be ordered before it and every commit-reveal against it counts as a
reference. The same goes for an artifact with no publish event at all. Publish with a key.

## Collections (topics / communities)

A `collection` (`cl-`) is a signed, curated manifest naming a topic: scope, maintainers,
member artifacts with roles, wanted-work criteria, open questions. It's just an artifact, so
it inherits versioning, signing, federation, and citability for free.

```bash
$COMMONS list --type collection            # what topics exist here
$COMMONS collection show cl-304d7331       # both membership views + open tasks
$COMMONS queue --collection cl-304d7331    # work wanted on this topic
$COMMONS claim tk-95ebf3b0                 # pick something up
```

That four-step sequence is the **newcomer front door**. Note `collection` requires the
`show` subcommand. `list`/`search --tips-only` hides rows a locally-held artifact
supersedes (opt-in; plain `list`/`search` are unchanged).

**Two membership views, allowed to disagree.** *Curated-in* is the signed editorial list;
*self-declared* is artifacts pointing `--link part-of:cl-…` at the collection. Anyone may
claim membership in anything — the claim is free, the endorsement carries the weight, and
`collection show` renders both separately. It also warns when the signed publisher of the
list is not among its own listed maintainers.

**Membership is deliberately not evidence.** `part-of` is not an evidence relation, so
listing an artifact in a collection can never move its chain grade. Curation is an editorial
claim about relevance, not a claim about correctness.

**Endorsing is `collection add-member`.** Collections are content-addressed, so every
update is a new artifact superseding the old; the command republishes the spec with the
member added and the old id in the spec's `supersedes` list, through the same lint as
`publish collection`. It changes nothing but `members` and `supersedes`, warns on a role that appears nowhere else in the spec, and
refuses to build on a version that a maintainer-signed supersede has already retired —
which would silently drop every endorsement made since. Each refusal has its own opt-in
(`--force` for publishing as a non-maintainer, `--allow-retired-base` for the retired
base), on the `--allow-secrets` precedent, so overriding one never overrides the other.
See `docs/COLLABORATING.md`.

No exclusive ownership of a topic (competing collections are legal), no membership
permissions, no project-level state machine — state stays at task granularity.

**Admission is per-host trust, not a global gate.** There is no administrator who approves
collection creation, and there deliberately never will be: a collection id is `cl-` plus the
first 8 hex of its content digest, so a *name* cannot be squatted, and who may publish one
into your registry at all is already decided by your own `peers.json` — which a peer is
structurally forbidden from supplying.

> **Browse-surface disambiguation.**
> `list`/`search --json` carry `superseded_by` (locally-held supersede targets) and
> `verified_agent`/`agent_mismatch` (the signed `first_publisher`'s registered agent name
> vs. the manifest's self-asserted `agent` field); `list`/`search --tips-only` is an opt-in
> flag that hides superseded rows entirely. Default stdout with no flag is byte-identical to
> before. `collection show` additionally prints a `SUPERSEDED by …` line on a retired
> collection and a `duplicate-scope: …` advisory when two unlinked collections carry
> near-identical `scope` text — both display-only, neither moves an exit code. For example,
> in the demo hub, `commons collection show cl-0813ab12` names `cl-ccd9941d` as its
> successor directly, and `commons list --type collection --tips-only` shows only the live
> one. A duplicate open task on a superseded collection is left as-is by this display-only
> feature; withdrawing it is a separate, human-gated registry mutation.

### Analysis templates: methods and the instances that applied them

A **method** is a category-level procedure ("how is a crypto protocol / a bank / a bond
analyzed here?") published as a `skill` — a **SKILL.md bundle** (tar with `SKILL.md` at the
root) tagged `methodology` + `category:<kebab-slug>`, titled `Method: …`. The bundle may ship
`rubric.json` (`{"criteria_list":[{id,text}…]}`): the criteria an *instance* is judged by.
Because the rubric is inside the content-addressed bytes, the `sk-` id pins it; a revised
rubric is a new bundle with `--link supersedes:sk-old`.

```bash
$COMMONS list --category weather-station     # methods for a category (bare --category = all)
$COMMONS rubric sk-f43ad701                  # task-ready criteria_list JSON
$COMMONS collection show cl-69119f88         # method (ENDORSED) / instances / review queue
$COMMONS publish report r.md "Report: …" --link applies:sk-… --link part-of:cl-…   # an instance
$COMMONS publish task spec.json "…" --method sk-…   # copy the rubric into a T2 task
```

- `applies:sk-…` means "I followed this method". It is **not** an evidence relation: a
  flawless application of a bad method is still a bad analysis, so the grade comes from the
  data, never the procedure. Publish refuses `applies` at a non-skill.
- `category:<slug>` is **free text**: publish checks only that it is kebab-case, and warns if
  a `methodology` skill has none. There is no shared list, and `list --category` and
  `collection show` match the literal string within the local hub, so two hubs that name the
  same subject differently (`crypto-protocol`, `protocol-analysis`) will not find each
  other's methods this way. Whether to add a suggested list is open (#16).
- A category collection curates the method with `role: "method"` (lint: must be a skill) and
  analyses with `role: "instance"`. `collection show` then groups **method → instances →
  other**, shows `applied by N`, marks `(different method)` / `(superseded)` targets, and lists
  instances that applied the method but are not yet endorsed — the maintainer's review queue.
  Collections without a method member render exactly as before.
- `publish task … --method sk-…` copies the rubric into `verification.criteria_list`, records
  `method` on the spec, and writes `<spec>.with-method.json` beside the input. The task still
  owns its rubric (before-claim, immutable): it may **extend** the method's criteria but not
  omit any — that is what lets two beneficiaries' instance-tasks replicate on the same verdict
  vector. `method` is T2-only. `status <tk>` shows `rubric from: sk-…`.
- Bundles are inspected read-only at publish (stdlib `tarfile`): `SKILL.md` required at the
  root or one top-level dir; links, `..`/absolute members, >64 MiB members, >4096 members and
  malformed rubrics (pedigree, duplicate ids, non-JSON) are refused. `run-skill` refuses a
  bundle with extraction guidance — a method is followed, not executed.
- Worked example: `sk-f43ad701` (`weather-station`, 3-criterion rubric) in `cl-69119f88`,
  with a report as instance and `tk-fccf8b9b` as the first `--method` task.

### Local subscriptions and selective blob sync (Stage 1)

The local subscription policy commands are **implemented**:

```bash
$COMMONS subscribe cl-304d7331 origin                 # defaults: manifests only, no executables
$COMMONS subscribe cl-304d7331 origin --blobs members --executables --follow-supersedes maintainer-signed
$COMMONS subscriptions                                # policy + ready/pending status
$COMMONS unsubscribe cl-304d7331
```

A collection not replicated locally is accepted and shown as
`pending: collection not replicated`; a later sync can resolve it. The state lives in
local-only `registry/subscriptions.json` and never federates. `commons sync` always runs the
ordinary unfiltered pull gate, then applies the recorded blob policy; executable bytes still
require both explicit opt-in and a verified signed publisher with local `trust: full`.

## Federation (git transport + ingest gate)

> **Data-only pulls.** `pull` refuses to merge incoming changes to any path outside
> `registry/` and `store/` (plus inert hub metadata: `README.md`, `LICENSE`,
> `CONTRIBUTING.md`, `.gitignore`, `.commons-hub`) and quarantines the attempt. Code
> and CI workflows never arrive through a data pull. `--allow-code` overrides this after
> review and names every file it merged. `pull --branch B` ingests a contributor's
> branch. `commons hub check [--base REF]` is the matching PR/CI gate: data-only paths,
> no deletions, append-only ledgers, per-signer log ownership, valid signatures, blob
> hashes. Collaboration workflow: [`docs/COLLABORATING.md`](docs/COLLABORATING.md).

Two registries, a bare repo between them, and a validation gate on the way in.

```bash
git remote add origin <url>          # SSH/HTTPS bare repo either side, or a shared host
$COMMONS push origin                 # gated: fsck, licensing, signatures, local-only state
$COMMONS pull origin                 # gated ingest — NOT a bare git pull
$COMMONS pull origin --dry-run       # validate everything, merge nothing
$COMMONS fetch ds-abc                # route across configured remotes
$COMMONS fetch ds-abc origin         # force one remote (no fallback)
```

**Commit before you push.** `push` exports the *committed* tree — claim/submit/settle
events land in `registry/ledger/` as working-tree files, every gate passes against the
last commit, and uncommitted events silently stay local. `git add registry && git commit`
after exchange actions, then push.

### Discovery (Stage 2)

Announces are hints; nothing acts on them without a human. The practical test is:
*can a stranger's announcement change my registry without a human?* — **no**.
A `peer-announce` artifact can affect suggestions and fetch order, but it never changes
`peers.json`, adds a git remote, creates a subscription, or alters trust.

`commons announce` publishes or refreshes this signer's signed `pa-` reachability and
collection-hosting hint:

```bash
$COMMONS announce --remote-url U [--remote-url U ...] \
  [--hosts cl-ID[:manifests-only|members|all]]... [--hosts-from-local] \
  [--expires-in DUR] [--note NOTE]
```

At least one repeatable `--remote-url` is required. `--expires-in` defaults to 90 days
and may not put expiry more than six calendar months after refresh. Re-announcing
automatically supersedes the signer's previous announce. Collection claims are explicit
unless `--hosts-from-local` is opted into; that flag also declares collections the signer
published locally.

`commons peer suggest [--json] [--all]` resolves each signer's latest valid,
single-author announce and shows registration/trust/revocation state, expiry, claimed
remotes and collections, configured/subscribed matches, and copy-pasteable `peer add`,
`git remote add`, and `subscribe` commands. It is read-only and never executes those
commands; revoked signers are hidden unless `--all` is supplied.

`commons subscribe cl-X` may omit `remote`. An explicit remote always wins. Otherwise,
resolution succeeds only when exactly one registered, non-revoked `full` or
`datasets-only` signer has a latest, live announce claiming `cl-X` and one of that
announce's URLs already matches a configured git remote. If there are zero or multiple
candidates, or the candidate URL is not configured, `subscribe` prints relevant
`peer suggest` lines and refuses. If one URL has multiple local aliases, it chooses the
lexicographically first; no remote is ever added automatically.

`commons fetch <id>` without a remote—and `sync` member materialization—tries configured
remotes announced by registered peers in trust bands: `full`, then `datasets-only`,
then all remaining configured remotes in stable name order. A live announce claiming the
artifact's curated collection may reorder remotes only within its existing trust band.
Each response is re-hashed, and absence or hash mismatch falls through to the next remote.
`commons fetch <id> <remote>` remains a single-remote operation with no fallback.

| Adversarial announce | Bounded outcome |
|---|---|
| Lies that it hosts a collection | Fetch fails or falls through; wasted round-trips and incomplete status only. |
| Points at a hostile remote | A human must already have configured it or accept a suggestion; the ingest gate and blob hash checks still apply. |
| Claims another signer's identity | Refused because `announcer` must equal the ledger signer. |
| Spams many announce artifacts | Announces do not count toward reputation; suggestions collapse to the latest announce per signer. |
| Supersedes another signer's announce | Never followed; announce supersedes chains are single-author. |
| Leaves a stale locator | Required expiry bounds its routing lifetime, and `peer suggest` flags it as expired. |

**`push` refuses to export a broken or unshareable registry:** failing blob hashes,
datasets without `--license` (`--allow-unlicensed` overrides), unsigned ledger entries
under `COMMONS_REQUIRE_SIG=1`, or local-only state tracked in git.

**`pull` validates every incoming artifact before merging:** schema, type, hash
well-formedness, that the **id actually derives from the content hash**, blob integrity
(including for artifacts you already hold — otherwise a merge could overwrite good bytes
with bad), id collisions against different local content, attester registration and
trust, and **executable artifacts gated on the publisher's trust** from their signed
ledger entry. Rejects go to `registry/quarantine.log` and the fetch is left unmerged.

**An edit to a manifest you already hold is checked too (#41).** Manifests are not covered
by any signature (a publish signs the content hash), so a peer can change an artifact's
tier, criteria, licence, obtainability, title or links without changing its id. `pull` and
`hub check --base` compare every modified manifest with the merge base and accept the edit
only if the incoming range carries a new verified signed `publish`/`republish` of that id
(what `publish --force` emits) by a key with authority over it: the artifact's verified
signed publisher at the base or, for a collection, a maintainer its spec names. A
`republish` never grants authority by itself. If the base holds no verified signed publish
(a legacy unsigned artifact) or several from different keys, no key has authority and only
annotation edits can land. `pull` also requires that key to be a registered peer whose
trust covers the type and whose validity window covers the event. Without a republish, the
only edits allowed are annotations a signed ledger event backs, matched on the event's
signed fields: a `fulfills` link (a `submit` signing this result's hash), an `accepted`
link (the beneficiary's `accept` of this task, naming this result in a `sig2`-signed field
or, for an entry without `sig2`, naming a result a submit to the task binds by hash), an attestation (a valid `attested_by` plus
its `attest` event; replacing another attester, or restating the criteria, needs
authority) and a rebaseline exec
record (an owner-signed `rebaseline` whose `sig2` covers the mode and image digest).
These may only add, never remove. Anything else is rejected and quarantined.

Both gates also refuse a **replayed** ledger event: a copy of a signed event with an
unsigned field changed (`prev`, `result`, the signature encoding). Events are identified
by the recovered signer plus the signed payload. `pull` runs this check on unrelated
histories too, against what it already holds. It also refuses an incoming tree that
rewrites or truncates a ledger, as `hub check --base` already did. A second key's
`publish` of an id the base already holds is refused if the id has no verified signed
publisher (the event would make its signer the owner). Otherwise it is reported: it grants
no edit authority, but it competes for first publisher, which anchors decide. `pull` also
applies `hub check`'s per-line rules to every incoming ledger line it doesn't already hold:
signed, verifying, and in the log named after its signer. New lines in the unsigned logs
are accepted with a warning and a quarantine record, because a first pull from a hub with
legacy unsigned history needs them (#14). Tags only the incoming copy carries on a manifest
added on both sides are refused. `pull --force` overrides the manifest-edit rejections, as it
does every per-artifact ingest check, but not these ledger checks.

Lifecycle readers select a task's events by the signed `id` and ignore an event whose
`task` disagrees with it. A submit without `sig2` counts only if its `result` is a manifest
you hold whose content hash is the submit's signed hash, and an accept without `sig2` only if
its `result` names such a submission (#45).

**Known gaps** (pinned by the test suite): a republish signs the content hash, not the
manifest bytes, so an edit committed after a genuine republish in the same range is
accepted with it (#43, together with #10). A receiver that never held a `sig2`-signed
original cannot tell a copy with `sig2` stripped from an older entry, so the rules above
are what bind it: a relayed, stripped accept can still name another genuine submission to the
same task, including the relayer's own. A second key's `publish` of an artifact leaves no key able to rewrite its
manifest until the dispute is settled (#47).

**A peer can never hand you local policy.** `registry/peers.json`,
`registry/exec-policy.json`, `registry/subscriptions.json`, and `quarantine.log` are
local-only and never replicated; an incoming tree carrying one is refused outright.
Otherwise the sender could decide whom you trust, what may run, or what you intend to fetch.

**Per-peer ledgers.** Each writer owns `registry/ledger/<addr>.jsonl`, so concurrent
appends never conflict and every chain verifies independently. Unsigned writes go to
`local-unsigned.jsonl` — segregated by construction.

These logs are append-only and have no rotation or pruning. Per-peer files keep
contention and individual growth manageable, but verification cost is linear in a
file's length: `log --verify` re-verifies every signature. Revisit this limitation when
any peer log approaches roughly 50 MB.

**Lazy replication.** Manifests always travel; blobs on demand. `fsck` says
`NOT REPLICATED` (not `MISSING BLOB`) for a manifest ingested without its bytes, because
incomplete is not corrupt.

## Time anchoring

```bash
$COMMONS anchor                      # Merkle root over log heads -> OpenTimestamps
$COMMONS anchor-upgrade              # promote pending OTS proofs once confirmed
$COMMONS anchor-verify               # re-derive roots, check proofs
```

Anchoring gives an **upper** bound only ("this existed by then"); it cannot show
something didn't exist earlier. With no OTS client installed, `anchor` records a local
tamper checkpoint and says explicitly that it is not third-party-verifiable time.

**Anchors decide priority disputes, so anchoring protects your derivation credit.**
Asserted `ts` fields are self-declared — a signature proves who wrote a statement, never
that its timestamp is true. Since first-publisher decides whether a submission counts as an
independent derivation or a copy, ordering keys on the **anchored upper bound first** and
asserted time only as a tiebreak between equally-anchored claims. Only `publish` events are
candidates: a `republish` restates metadata and never claims authorship (#46).

```bash
$COMMONS status tk-…        # shows TIME DISCREPANCY when an assertion outruns its anchors
```

- Unanchored sorts last. "I had it first but never anchored it" stays claimable and never
  provable — so **if you publish work you want credit for, anchor.**
- A Bitcoin-confirmed proof outranks a local checkpoint even if the checkpoint claims an
  earlier time: you can backdate your own checkpoint, not a block.
- A peer asserting priority its anchors cannot cover downgrades to a *concurring
  reference* (zero quorum weight) and the gap is reported as a reputational tell.
  Backdating isn't prevented, it's made visible.

**Staleness warning.** Because priority now rests on anchoring, letting the cadence lapse
quietly leaves your recent work unprotected. When this host's own ledger has unanchored
lines older than 24h, `commons status` and `commons log --verify` print one line to
**stderr**:

```
warning: local chain drifted 72h past last anchor; derivation priority unprotected — run `commons anchor`
```

It is advisory: stderr only and never changes an exit code, so it cannot break a caller
parsing stdout. Drift is measured from the **oldest** unanchored line (the exposure window
is how long your earliest unprotected claim has sat there, not how recently you appended),
and registered peers' logs are ignored — their anchoring is their business.

## Attested-by-whom (T3)

"A signer attests this" means nothing until the signer is named:

```bash
$COMMONS attest ds-abc --criteria "GET /v1/rewards at 2026-07-25T00:00Z" --observed 2026-07-25T00:00:00Z
$COMMONS verify ds-abc      # attester : VALID — attested by 0x… (agent=alice, observed …)
```

A tampered attestation, or one covering different content or criteria, exits **1 (FAIL)**
— it's the one machine-checkable part of T3. Unattested T3 reports `NONE`.

`--observed` takes RFC 3339 with an explicit zone. Offset forms are accepted and
**normalised to UTC before signing** (`2026-08-09T23:00:00-08:00` is stored as
`2026-08-10T07:00:00Z`); prose, zone-less datetimes, and future dates are refused at
`attest` time. This matters because `observed` is the instant `verify` judges the
attesting key's validity window against — see the fixed defect below.

> ✅ **Fixed 2026-08-25 — `--observed` validation** (8-arm matrix in
> `tests/test-signing.sh`). The field was stored unparsed and compared to
> key-validity windows with *string* ordering, so an offset form slipped past a
> `revoked_at` that the identical instant in `Z` form correctly failed — a revoked key
> could attest by choosing a timezone, turning exit 1 into exit 3. Validation happens at
> `attest`, never at `verify`: no published artifact changed grade.

> ⚠️ **Known defect, filed 2026-08-23:**
> **`verification.params` is outside the signed statement**, so `--param` values can be edited
> after attestation without the attester going `STALE`. Only `sha256` and `criteria` are covered.
> Put anything load-bearing in `--criteria`, which *is* signed.

## Publish-time secret lint

Immutable replicated bytes can't be recalled, so prevention beats retraction. `publish`
scans content first: credential shapes **block**, PII and high-entropy tokens **warn**,
hash-shaped tokens are ignored by the entropy check (the registry is full of them), and
excerpts are always redacted so the lint never leaks what it caught.

```bash
$COMMONS publish dataset d.csv "Title" --license CC0-1.0 --obtainability open
$COMMONS publish dataset d.csv "Title" --allow-secrets     # deliberate false positive
```

**Tx/block hashes vs. eth private keys (fixed 2026-09-29, issue #9).** A bare 32-byte hex
value (`0x` + 64 hex digits) is the same *shape* whether it's a private key or a tx hash,
block hash, log topic, storage slot, or merkle root — and on-chain datasets are full of the
latter (every row of a payment ledger has a `txHash`). Before this fix the "eth private key"
block pattern couldn't tell them apart: one real 83 MB on-chain NDJSON produced 443,939
blocking findings, forcing `--allow-secrets` for the whole file — the blanket bypass this
lint exists to avoid. The fix is **context, not a weaker shape**: a bare-64-hex value is
exempted from the eth-key block only when it is the value of a JSON key or CSV column
header from a conservative built-in allowlist (`hash`, `txHash`, `blockHash`, `topics`,
`root`, `stateRoot`, `txid`, `commitment`, `nullifier`, `digest`, `sha256`/`sha1`/`keccak`,
and a few close relatives) — and the exemption is withdrawn the moment the field name also
contains a key-danger token (`private`, `secret`, `mnemonic`, `seed`, `key`, ...), so
`{"privateKeyHash": "0x…"}` and a `{"txHash": …, "privateKey": …}` line still block. An
unrecognised or ambiguous field name is **not** exempted — ties go to blocking. Every
suppressed match is counted and surfaced in one summary `WARN` line
(`N 32-byte hex value(s) under hash-named fields not treated as keys`), so the exemption is
never silent. **Residual risk, stated plainly:** a genuine private key stored under a
hash-named field — `{"txHash": "<an actual private key>"}` — is structurally
indistinguishable from a real hash and will be waved through; no purely structural check can
close that gap, only a human or a schema. Prose, `.env` files, and any field name outside the
allowlist are unaffected: `PRIVATE_KEY=0x…` and a bare value in free text still block exactly
as before.

**Binary content is scanned for block-pattern credentials (fixed 2026-09-12), still not for
archive structure.** A file with a NUL byte in its first 8 KiB (any `.zip`, `.tar`,
`.tar.gz`, Parquet, or SQLite dataset) now runs the same high-confidence credential
patterns as text, with only the leading `\b` word-boundary anchor dropped — a credential
glued directly to the preceding column's bytes with no delimiter in between
(`…api_keysk-proj-…`, the shape a packed SQLite row actually produces) is caught rather
than silently waved through. WARN_PATTERNS and entropy scanning are still skipped for
binary content (still noise there: delimiters and base64-shaped protobuf fields false-
positive constantly). **What's still missing:** archive-aware scanning — the lint reads raw
bytes only, so a secret sitting *inside a compressed member* of a zip/tar is invisible
until that member is decompressed. The planned fix (assessed 2026-08-23, not yet built)
enumerates zip/tar/gzip members and runs the full text scan on each. Until that lands, **check
compressed archive members yourself before publishing them** — and the lint now says so at
runtime (fixed 2026-10-01, issue #20): a recognised gzip/zip/bzip2/xz/tar container prints
`WARN archive members not scanned` and the verdict is folded into the same PARTIAL marker
used for an over-cap file (`secret-lint: clean (PARTIAL: ...)`), so a publisher who never read
this section still gets a signal rather than a bare `clean`.

**The scan streams, up to 100 MiB per file, and says so when it stops short.** 100 MiB is
GitHub's hard per-file limit ("GitHub blocks files larger than 100 MiB"), and hubs federate
over git, so anything that can travel through a GitHub-hosted hub is scanned in full. The
scan reads 1 MiB chunks through an incremental UTF-8 decoder, so memory stays flat (~18 MiB
RSS measured at 100 MiB, down from ~3.4x the file size). It is not faster: about 0.4 s per
MiB of all-printable text, so roughly 40 s for a 100 MiB file at publish. A file over the cap
gets a `WARN … scan incomplete` finding naming the unscanned remainder. The standalone
verdict then reads `clean (PARTIAL: …)`, and `publish` prints that the tail is unchecked.
This is advisory only: exit codes are unchanged. Split such files by their natural range
(block range, observation date) before publishing. Lines longer than 1 MiB (minified JSON)
are scanned in overlapping 1 MiB windows. On those lines, `lint: allow` markers and the
hash-field exemption are not applied (the conservative direction), and a `very long line`
warn says so. `COMMONS_LINT_MAX_BYTES` can **lower** the cap (the test suite uses it) but
never raise it.

**The lint runs on `publish` only, by design.** `pull`/`sync`/`fetch` validate provenance —
hashes, ids, signatures, peer trust — and never look at what the bytes say, so a peer's
leaked credential replicates into your store silently. Gating ingest on a content scan is
deliberately *not* planned: it would hand any peer a denial-of-merge vector (publish one
block-pattern artifact, stall every puller) whose only escape is `--force`-ing past the
provenance gate that actually matters. Rule of thumb: **`commons` scans content you publish
and never scans content you ingest** — treat pulled blobs as untrusted bytes from a peer
whose hygiene you cannot audit, which is what the trust registry is for.

### Topic-scoped forbidden field names

The lint above looks for credential *shapes*, which are recognisable anywhere and so can be
a tool default. Some leaks are not shaped like anything. `account_id: 81234` deanonymises a
provider's earnings history in a hub about provider economics, and is a harmless join key in
a hub about anything else — so the danger is a property of the **topic**, and the list has
to come from the topic rather than from here.

A collection declares one in its spec, and it applies to anything claiming membership:

```json
{"scope": "…", "maintainers": [...], "members": [...],
 "ingest": {"forbidden_keys": ["account_id", "provider_id", "provider_key", "job_id"]}}
```

```bash
$COMMONS publish dataset export.csv "Yield" --license CC0-1.0 --obtainability open \
    --link part-of:cl-…        # the collection's policy is applied here
```

Covers JSON object keys through depth 64, JSONL, and CSV header cells — measurement datasets
are routinely CSV, so a JSON-only check would miss the leak in the format most likely to
carry it. Names match whole and case-insensitively; substrings deliberately do not, or `id`
would flag `machine_id` and every other legitimate column. Content it cannot parse (an
archive interior, binary including UTF-16, prose) is reported as **not covered** rather
than passed. UTF-8 BOMs are accepted. The entire file is scanned, without a size cutoff;
valid JSONL lines are still checked when another line is malformed, and the number of
unparsed lines is reported. Malformed JSON-shaped content never falls back to CSV.
Nesting beyond 64 levels is reported as not covered; keys found in the covered portion
still block publication.

**This one fails closed**, unlike every other gate here. A missed check elsewhere is caught
downstream by whoever the bad data breaks; a leak cannot be undone, because once a signed
publish replicates, `retract` is best-effort recall and not erasure. So:

| Situation | Behaviour |
|---|---|
| policy held locally | applied; a hit **refuses**, with no override — publish different bytes |
| collection held manifest-only, and its manifest carries `ingest_policy` | **refuses**: `commons fetch cl-…` to get the policy, or `--allow-unchecked-ingest` to publish without it |
| collection superseded by maintainer-signed version(s) | **warns**, naming the current version(s); the policy applied is the union across that lineage (below) |
| no policy flagged | unchanged from today |
| no `part-of` link | unchanged from today |

`ingest_policy` on the collection's *manifest* is what lets a peer holding only the manifest
know a fetch is needed; without it, "a policy might exist" would have to refuse for every
manifest-only collection, making a blob fetch a prerequisite of publishing anywhere.
`publish collection` sets it from the spec and it is not a CLI argument. **It is a hint, and
the blob always wins**: a policy in the spec is enforced whether or not the flag is set, and
a flag over a spec with no policy enforces nothing. Since manifest fields sit outside
`SIGNED_FIELDS` a peer could strip the flag, so `hub check` compares the two where both are
held, and also applies policies **read from `--base`** to artifacts added in a PR — the
backstop for a contributor whose tool never ran the gate.

**A superseded collection keeps its successors' policies.** Collections are content-addressed,
so the usual way to *add* a policy is to supersede, and the old id keeps circulating. A
`part-of` claim therefore gets the **union** of the named collection's policy and the policy of
every version reachable from it by *maintainer-signed* supersedes, forks included (each branch
counts). Following the lineage only ever tightens: a later version that drops a key does not
relax a claim against an earlier one, and a "successor" not signed by a maintainer of the
collection it supersedes is ignored, so it can neither relax nor add keys. A part-of at a
superseded collection always warns, policy or not, naming the current version(s), because
the claim is listed under the retired id where maintainers are unlikely to look; when the
lineage contributed keys, the output says which version each came from. The lazy-replication
cases fail closed the same way: a successor whose manifest carries `ingest_policy` but whose
spec is not held refuses, and so does a flagged later version past an intermediate whose spec
is not held (without that spec there is no saying whether the next hop was maintainer-signed;
`commons fetch` the intermediate). A successor with **no verified signature** here (published
without a signing key, or whose ledger entry is not held) may still be a maintainer's, so if it
or anything after it carries a policy that is unchecked too (`commons pull` its publisher's
ledger); without a policy it is noted and not followed. A successor verified as signed by a
non-maintainer is ignored, with a note when it carries a policy. The walk has **no length
limit**: every `add-member` publishes a version, so a limit would be reached in ordinary use and
would silently drop what lies past it. A version whose manifest is not held at all carries no flag
to see, the same known hole as a collection held not at all. `hub check --base` resolves the
lineage the same way, with the successors, their specs and their ledger signatures all read
**at base**.

**A collection's lineage is declared in its spec** (#39). A successor lists what it replaces in
its content, `"supersedes": ["cl-…"]`, so the declaration is pinned by the id and covered by the
maintainer's signed publish: removing it makes a different collection. `collection add-member`
writes it for you. The manifest's `supersedes` links are derived from the spec at publish and
are only a **hint**, there so a peer holding manifests but not specs knows which specs to fetch.
Where the spec is held it always wins: a manifest link the spec does not declare retires
nothing, is never followed by a subscription and contributes no keys, and a declaration the
manifest omits still counts. `publish collection --link supersedes:X` is refused unless the spec
declares X, and `hub check` fails a collection whose manifest links disagree with its spec in
either direction. (Before #39 the manifest link *was* the declaration. Manifests are outside
`SIGNED_FIELDS`, so anyone holding one could strip a maintainer's supersede, and with it the
successor's policy over claims against the old id.) Other artifact types still supersede with a
manifest `--link supersedes:…`.

`--allow-unchecked-ingest` is recorded in the publish ledger event and shown by `verify` and
`status`, so a deliberate skip is visible rather than silent. **A denylist is only a floor:**
a contributor who exports `acct` instead of `account_id` passes cleanly. The allowlist form
is a member schema with closed properties.

### Licence and obtainability (datasets)

This section covers the tool's validated `--license`/`--obtainability` fields. For
guidance on *which* licence to pick for a dataset, report, skill, or collection you
publish into a hub, see `docs/LICENSING-artifacts.md` (distinct from this
repository's own code/docs licensing, described below).

Proprietary data is **welcome here**; the price of admission is accurate labelling.
Refusing it would not produce open data — it would produce no artifact at all, and push
the same work somewhere with no provenance. So two separate questions get two separate
fields, because one free-text string could not tell them apart:

- `--license` — **may I redistribute these bytes?** A validated identifier: an SPDX id,
  one of `proprietary` / `proprietary-internal` / `terms-unclear`, or `LicenseRef-<name>`
  for anything off-list. Free text was accepted until 2026-08-09, so a misspelt licence
  read as a real one.
- `--obtainability` — **could an independent peer acquire them at all?** This is the one
  that bears on replication:

| value | meaning |
|---|---|
| `open` | freely retrievable by anyone; the blob may federate |
| `licensed-obtainable` | a peer can acquire the same bytes under their own licence — **requires `--source`** |
| `restricted` | cannot be independently acquired; replication by anyone else is impossible in principle |

```bash
# paywalled but genuinely replicable: restrictive licence, real obtainability
$COMMONS publish dataset feed.csv "Vendor feed extract" --license proprietary \
    --obtainability licensed-obtainable --source "VendorX Terminal, product ABC"

# internal telemetry: nobody else can ever re-run this, and the artifact says so
$COMMONS publish dataset tel.csv "Internal telemetry" \
    --license proprietary-internal --obtainability restricted
```

Availability shows up wherever artifacts are read — `list`/`search` markers
(`[open]` `[licensed]` `[restricted]` `[?]`), an `availability` line in `verify`, and a
line beside the chain grade in `status`. A T0 PASS over a `restricted` input prints an
explicit caution: the result reproduced, **and** no independent party can re-run it.

**Undeclared is not "open".** It renders as `?`/UNDECLARED, and `push` refuses it (as it
refuses a `licensed-obtainable` entry with no `--source`); `--allow-undisclosed` is the
deliberate escape hatch. **None of this ever moves a tier, a chain grade, or an exit
code** — availability changes who can check a result, not what was checked.

**Non-dataset artifacts get an advisory, not a gate.** `--license` is not gated to
datasets — any artifact type can carry one — but only datasets are refused at `push`
without one. Publishing a `report`, `synthesis`, `wiki`, `workflow`, or `skill` with no
`--license` prints a one-line stderr warning: with no licence, the default under
copyright almost everywhere is "all rights reserved," which is rarely what a
contributor who simply forgot the flag intended. The warning never refuses the publish,
never touches an exit code, and stays silent on a no-op re-publish of identical bytes
(or a `--force` republish that carries an earlier licence forward). `collection` and
`task` are deliberately excluded — they are editorial metadata (a pointer structure
plus curation prose over other artifacts' hashes), not the kind of original work a
licence default is meant for; see `docs/LICENSING-artifacts.md` for the reasoning and
suggested defaults per type.

### Freshness

Beside the availability marker, `list`/`search` and `collection show` carry an age, and
it names which clock it came from:

| Marker | Source | Means |
|---|---|---|
| `[obs 5mo]` | `verification.attested_by.statement.observed` | the observation time **declared in the attestation statement**, so the claimed age of the measurement |
| `[pub 3d]` | `created` | the publisher's **self-declared** publish time — all that exists until someone runs `attest --observed` |

The two are never conflated. A measurement published months after it was captured has a
`pub` age of minutes and an `obs` age of months, and rendering the first as if it were the
second would be a silent wrong answer. Ages coarsen to one component (`<1h`, `3h`, `2d`,
`5mo`, `1y`); there is deliberately no minute unit, because `5m` and `5mo` differ by one
character in the column whose job is telling fresh from stale. `list --json` emits the
absolute `observed` and `created` values instead, with `observed: null` when absent, so its
output does not change as time passes. Legacy RFC 3339 offsets and fractional seconds are
accepted for age rendering; the stored/signed timestamp is never rewritten.

The marker identifies the timestamp's **source**, not its validity: browsing does not
reverify the attestation signature. Use `commons verify <id>` to check that binding and the
signer's key-validity window. Even a valid signature does not prove when an observation
actually occurred; an anchor supplies a provable publication bound, not an observation clock.

Like availability, freshness is **disclosure, never grading** — it moves no tier, no chain
grade and no exit code.

## Sandboxed execution

Foreign workflows and fetched skills are untrusted code. `COMMONS_EXEC=sandbox` (or
`--exec sandbox`) runs them with no network, a read-only rootfs, and capped
memory/cpu/pids, from an image allowlist in `registry/exec-policy.json`.

⚠️ **`registry/exec-policy.json` is local-only and never replicates** — it decides what
may execute on *your* machine and under what caps, so it is trust policy in exactly the
sense `peers.json` is, and an incoming tree carrying one is refused. A fresh clone seeds
it from the tracked `registry/exec-policy.example.json` on first use; edit your local
copy, not the example. (Before 2026-08-02 this file replicated, letting a peer add its
own image to your allowlist, make it your default, and lift your resource caps.)

Rungs 0–2 — reading, in-process verification, publishing, and federation — need no
container runtime. The rung-3 sandbox invokes a container CLI directly and defaults to
Docker. The default image, `research-commons-sandbox:base`, is not pulled from any
registry: build it once from the in-repo recipe before your first sandboxed run.

```bash
docker build -t research-commons-sandbox:base environments/base/
```

This snapshot also supports Podman via `COMMONS_CONTAINER_CMD=podman`; an unset
or empty value keeps the Docker default. Rootless Podman needs neither a daemon nor
membership in a privileged daemon group. Other nonempty values are rejected.

```bash
COMMONS_CONTAINER_CMD=podman $COMMONS run wf-abc --exec sandbox
```

Allowlist entries may be legacy plain tags or digest pins. Keep the candidate tag in
`default_image` (or the workflow's `image`) and pin the corresponding allowlist entry:

```json
{
  "default_image": "registry.example/research:2026-08",
  "images": [
    "registry.example/research:2026-08@sha256:ELIDED64HEX"
  ]
}
```

A plain tag still matches exactly as before. A `tag@sha256:<64-hex>` entry additionally
requires Docker's repository digest for that tag to equal the pin. If Docker is
unavailable, the image is not pulled, or the image has no repository digest, the pin
**fails closed**; it never falls back to tag matching or a local image ID. Malformed
pins are rejected when the policy is loaded. Prefer digest pins for blessed/shared
images because tags can be repushed to different bytes.

**You do not have to use the default image.** `environments/CONTRACT.md` specifies exactly what
an image must provide (interpreter, non-root, writable `/work`, no network, read-only
rootfs, no host env); `environments/base/Dockerfile` is the reference build of
`research-commons-sandbox:base`. Any image meeting the contract is first-class — which
is why per-workflow images do not collapse into one blessed monolith.

```bash
$COMMONS run wf-abc --publish --exec sandbox   # execute under a pinned userland
$COMMONS run-skill sk-abc --  arg1 arg2        # fetched skills: ALWAYS sandboxed
```

**T0 always had a hidden parameter: the execution environment.** "Bytes reproduce"
only ever meant "under the userland that produced them" — v0.1 just never wrote it
down. Runs now record it, digest and all:

```json
"run": {"exec": {"mode": "sandbox", "image": "research-commons-sandbox:base",
                 "image_digest": "sha256:…"}}
```

So `verify` can tell three different things apart:

| Situation | Result | exit |
|---|---|---|
| same environment, bytes match | `PASS` | 0 |
| same environment, bytes differ | `FAIL` — genuine defect or dishonesty | 1 |
| different environment, bytes differ | `ENV-MISMATCH` — unanswerable, not "no" | 5 |
| different environment, bytes match | `PASS` + note — environment-independent | 0 |

ENV-MISMATCH never lowers a chain grade and never counts as a verification failure;
`status` shows it as a `(pre-sandbox baseline)` annotation.

**Converging old artifacts.** The flip to a pinned userland is a migration you converge
through, not a toggle you flip back:

```bash
$COMMONS rebaseline sy-abc                        # MATCH -> stamp exec record, id unchanged
$COMMONS rebaseline sy-abc --publish-superseding  # DIVERGED -> publish sandbox result, supersede
```

Three honest outcomes: **MATCH** (metadata repair), **DIVERGED** (superseding artifact,
native one kept as legacy baseline), or **NONDETERMINISTIC** (a real workflow defect,
surfaced rather than hidden). All are ledger events.

**Methods aren't evidence.** `workflow` and `skill` artifacts carry no tier (shown as `—`):
they're pinned verbatim by content hash and re-executed as-is, so they never set a chain grade.

**Comparators** are ordinary published skills with a two-argument ABI
(`cmp <expected> <actual>` → exit 0 = equivalent), so a T1 claim is auditable:

| id | comparator | knobs |
|---|---|---|
| `sk-e0f1d443` | `json-numeric-epsilon` — recursive JSON compare, float tolerance | `EPSILON` (1e-9), `NAN_EQUAL` |
| `sk-85bdc629` | `sorted-set-equality` — order-insensitive line compare | `AS_SET`, `IGNORE_BLANK`, `STRIP`, `IGNORE_PREFIX` |

A workflow spec can declare its own tier so `run --publish` stamps outputs automatically:
`{"tier": "T1", "comparator": "sk-e0f1d443", "comparator_params": {"EPSILON": "1e-6"}}`.

## Artifact types

`dataset` (ds-) · `skill` (sk-) · `workflow` (wf-) · `wiki` (wk-) ·
`bibliography` (bb-) · `report` (rp-) · `synthesis` (sy-) · `task` (tk-) ·
`collection` (cl-)

IDs are content-derived (`<prefix>-<sha256[:8]>`): same bytes ⇒ same id ⇒
automatic cross-agent dedup. Blobs are immutable (mode 444); new versions are
new artifacts with a `supersedes` link.

## Provenance rules (important)

- **Machine-derived artifacts** (workflow outputs): publish via
  `commons run <wf> --publish` — provenance is recorded automatically and
  `commons verify` must PASS (byte-identical re-derivation).
- **Narrative artifacts** (reports, wiki pages): pin `--input` hashes and
  `--link cites:` the derived artifacts that carry the numbers. `verify`
  reports UNVERIFIED for these — by design; their verifiability flows
  through the cited machine-derived artifacts.
- Do **not** claim `--workflow` on an artifact the workflow didn't literally
  emit — verify will FAIL it (tested; that's a feature).
- Link rels: evidence (`cites supports refutes derives based-on`) are walked by
  `status` and move the chain grade; non-evidence (`supersedes`, `part-of:cl-…`
  membership, `applies:sk-…` "I followed this method", `fulfills` on submit) never do.

### Manifests are metadata

Artifact ids are content-addressed, but manifests are not. Two peers re-deriving
identical output at different times construct the same id from `content.sha256` while
recording different `provenance.run.finished` and `created` timestamps, and may add
different annotations; identical bytes still collapse to one artifact. A manifest diff
therefore does not by itself show a content disagreement. The ingest gate checks
`content.sha256` and that the id derives from that hash; on merge, `links` and `tags`
union, while conflicts in other shared fields abort (`ingest` is a local stamp).

`publish --force` over an id you already hold edits its manifest in place, starting from
the existing one: a field changes only when its flag is passed (`-d`, `-t`, `--link`,
`--input`, `--workflow`, `--license`, `--obtainability`; the title is positional and always
replaced). `provenance.run` and `created` are always kept, and the verification block is
kept unless `--tier`, `--workflow`, `--criteria` or `--param` is given. A `--force` that
would lower the tier without an explicit `--tier` is refused. There is no syntax yet to
clear a tag or link list; an omitted flag means "unchanged".

## Determinism checklist for workflow authors

Pin `TZ=UTC LC_ALL=C PYTHONHASHSEED=0` in spec `env`; sort all output
collections; no wall-clock timestamps inside outputs; no network in steps
(acquire → publish dataset first, derive second).

## Maintenance

- **Project integration contracts:** a project that wants to share data writes a
  `COMMONS.md` (datasets, tier today → ceiling, licence, obtainability, forbidden keys,
  growth model, known data-quality issues). A maintainer reviews it against a 10-point rubric.
  Template + rubric: [`docs/COMMONS-TEMPLATE.md`](docs/COMMONS-TEMPLATE.md).

- `commons reindex` — rebuild FTS index from manifests (index is disposable).
- `commons fsck` — hash-check every blob against its manifest (tamper/corruption);
  `--orphans` also reports unreferenced blobs, `--strict-orphans` exits 1 on them;
  `--attribution` reports artifacts with no `publish`/`republish` ledger event
  (`UNATTRIBUTED:`, counted as problems — blob integrity says nothing about who published),
  plus artifacts whose only publish events are unsigned (`UNSIGNED-ONLY:`, advisory:
  nothing verifiably names their publisher. There is no repair yet: a signed `publish --force`
  writes a `republish`, which never claims authorship (#46), and an adoption path is #47);
  `--availability` prints a read-only obtainability census for datasets
  (`open`/`licensed-obtainable`/`restricted`/`undeclared`, with ids) and previews what
  `push`'s disclosure gate would refuse — same shared predicate as the gate itself, so
  the preview and the real refusal can never disagree. Purely advisory: never touches
  the exit code.
- `commons migrate-store [--dry-run]` — move legacy flat blobs into the sharded layout
  (atomic and idempotent; readers accept both layouts, so this is never urgent).
- `commons anchor` — run it on a schedule if you publish: `status` and `log --verify`
  warn once your own chain has unanchored entries older than 24h.
- `commons log -n 20` — recent ledger (append-only contribution audit trail).
- `tests/run-all.sh` — full regression suite, one `tests/test-<phase>.sh` per phase
  (throwaway `COMMONS_ROOT`s, never the live registry). `tests/run-all.sh tiers` /
  `sandbox` / `two-root-drill` runs only the suites whose name matches; the sandbox,
  exchange and drill suites need docker + the default image (`docker build -t research-commons-sandbox:base environments/base/`).
  The harness clears inherited `COMMONS_*` env for hermeticity — a suite that passes only
  in a particular shell is measuring the shell.
- `scripts/migrate-v02.py [--dry-run]` — one-shot, idempotent: stamps `schema` + tiers on v0.1 manifests.
- `commons rebaseline <id>` — converge a pre-sandbox artifact onto the pinned userland.
- `registry/exec-policy.json` — image allowlist + resource caps for sandboxed runs.
  **Local-only**, seeded from `registry/exec-policy.example.json`.
- `registry/subscriptions.json` — collection sync intent and policy.
  **Local-only**; manage it with `subscribe`, `unsubscribe`, and `subscriptions`.
- `environments/CONTRACT.md` — what an execution image must guarantee (roll your own).
- `environments/base/Dockerfile` — reference build of the default image, snapshot-pinned.
- `registry/peers.json` — signer identities, trust levels, key validity windows.

`commons fsck` also reports subscription completeness directly from each subscription's
policy and local blob presence. `pinned` means present, `queued` means the policy wants an
absent blob, and `skipped` names an executable withheld by policy; incomplete subscriptions
remain a green integrity check.

```text
--- subscription completeness ---
subscription cl-304d7331 (blobs=members)
  pinned ds-efae742c
  skipped wf-1e4e0c5e — executable withheld by policy: executables not enabled; publisher trust is not full
  queued sy-c775b533
  queued wk-3180f619
  queued bb-0239689a
  queued rp-aa78911e
  skipped sk-14ad1ae2 — executable withheld by policy: executables not enabled; publisher trust is not full
  counts: pinned=1 queued=4 skipped=2 pending-review=0
fsck: OK; 15 not replicated (manifest-only)
```

## Layout

**Tool repo (this one):**

```
bin/commons              CLI (python3 stdlib only)
lib/                     signing primitives (viem wrappers) + publish-time secret lint
comparators/             reference T1 comparators
environments/            execution-image contract + reference Dockerfile
registry/exec-policy.example.json   seed sandbox policy (copied per host, local-only)
scripts/                 anchor-cron.sh, pre-commit-keyguard.sh, migrate-v02.py,
                         demo-hub.sh (builds a synthetic demo hub — README examples)
tests/                   phase-gated regression suites (run-all.sh)
docs/                    WHY, COLLABORATING, licensing + release guides, COMMONS.md
                         template, divergence-report convention (CC-BY-4.0)
```

**A hub (created by `commons hub init`):**

```
.commons-hub             marker: makes `commons` use this directory as its data root
registry/artifacts/      manifests (source of truth)
registry/ledger/<addr>.jsonl   per-signer, append-only, signed logs
registry/anchors/        Merkle roots + OpenTimestamps proofs
store/sha256/<2hex>/<hash>     content-addressed immutable blobs
.github/workflows/hub-check.yml   CI gate for pull requests
# local-only, git-ignored, never replicated:
registry/peers.json  registry/exec-policy.json  registry/subscriptions.json
registry/quarantine.log  registry/index.sqlite (derived)
```

⚠️ `.gitignore` patterns must be on their **own line**: an inline `# comment` after a
pattern is matched literally, so `dist/ # exports` ignores nothing. Verify with
`git check-ignore -v <path>`.

Readers fall back to the legacy flat `store/sha256/<fullhash>` path;
`commons migrate-store` converts it.

## Scope & limitations (alpha)

The exchange is complete and drilled across two independent roots; what remains is scale,
subscription, and discovery. Specifically:

- **Transport is git:** `push`/`pull` with a validating ingest gate. Syncthing remains
  viable as a dumb mirror, but is not the ingest path.
- **Signing is opt-in for local publishing, required for lifecycle events:** set
  `COMMONS_SIGNING_KEY` and entries are signed and attributable; leave it unset and
  publishes are written unsigned (marked as such, segregated into `local-unsigned.jsonl`).
  Claims, submissions and settlements always require a key — an unattributable claim is
  indistinguishable from squatting.
- **One key per identity, never shared:** two agents sharing a key collapse into a single
  "distinct signer", which would let one party satisfy a k=2 replication quorum alone.
- **Execution defaults to native for your own code only:** foreign task specs are **always**
  sandboxed in code (`COMMONS_EXEC` is read, reported as ignored, and overridden), as is
  `run-skill` for fetched code. `run`/`verify` on your own workflows still default to
  `COMMONS_EXEC=native`; flipping that default globally is a `rebaseline` migration, not a
  config change. A native `run --publish` on a host where the container runtime is
  unreachable says so once on stderr, so a native-only result is flagged at publish time.
- **Userland drift:** the sandbox image ships Python 3.11 vs the host's 3.12. Pure-stdlib
  workflows are unaffected (verified), but flipping the default is a migration requiring
  a `rebaseline` pass, not a config change.
- **Subscription sync is a local pinning policy:** subscriptions may remain pending until a
  collection arrives. `sync` runs the unchanged full ingest gate, then fetches according to
  `manifests-only`, curated `members`, or `all`; subscription never scopes transport.
  Executable bytes remain default-deny and require opt-in plus a verified full-trust publisher.
- **No peer discovery:** peer identities and git remotes are exchanged manually, human-gated.
  Deliberate for trust (a peer must never hand you a trust policy); the real unaddressed gap
  is content routing — "who has blob X" at N>2 peers.
- **Tiers are self-declared:** nothing stops a publisher labelling judged work T0;
  signatures make mislabelling attributable, not impossible. `status` surfaces the weakest
  link in the evidence chain so a T0 badge over attested inputs cannot oversell itself.
- **The quorum works; independence is the hard part.** `commons settle` accepts at k
  *distinct signers* producing byte-identical results. A copy of someone else's artifact is a
  legitimate concurring reference but carries **zero** quorum weight — proving independence
  for a second derivation means posting `commit-derivation` before the result is public.
  Self-reported model families never count toward a diversity quorum.
- **Scale:** flat dirs, whole-file blobs, O(n) list — comfortable to ~10⁴ artifacts,
  <100MB blobs (v0.4).
- **License is advisory locally, enforced at the boundary:** `--license` is recorded and its
  absence warned about locally; `push` hard-refuses unlicensed datasets
  (`--allow-unlicensed` to override), because publishing data onward without stated terms is
  the one mistake that cannot be walked back. Same posture for `--obtainability`
  (`--allow-undisclosed`): a *disclosure* gate, not a content ban — restricted and
  proprietary data are accepted, silence about which one it is is not.
- **Availability is disclosure, never grading:** neither `license` nor `obtainability`
  can move a tier, a chain grade, or an exit code. A PASS over data only you hold is a
  true statement about the computation that would otherwise read as a stronger claim
  about the evidence, so `verify`/`status` say the quiet part out loud instead.

## Demo hub artifacts (referenced above)

Run `scripts/demo-hub.sh` to get a hub where every id below resolves — a small,
neutral "city weather station readings" dataset, chosen so the examples read
concretely without needing any domain expertise. It's deterministic: two runs, even
under two different signing keys, produce byte-identical ids (verified by
`tests/test-demo-hub.sh`). In your own hub, `commons list` shows yours.

| id | type | tier | what |
|---|---|---|---|
| ds-efae742c | dataset | T3 | city weather station readings, June 2026 |
| wf-1e4e0c5e | workflow | — | station summary analysis (deterministic) |
| sy-c775b533 | synthesis | T0 | derived aggregate — **verify: PASS**, chain grade T3 |
| wk-3180f619 | wiki | unverified | semantic wiki page w/ evidence-backed claims |
| bb-0239689a | bibliography | unverified | curated sources (artifacts + external) |
| rp-aa78911e | report | unverified | station comparison report, inputs pinned |
| sk-14ad1ae2 | skill | — | csv-quick-profile (fetch + run anywhere) |
| sk-e0f1d443 | skill | — | comparator: json-numeric-epsilon |
| sk-85bdc629 | skill | — | comparator: sorted-set-equality |
| sk-f43ad701 | skill | — | method: weather-station comparison v1 (SKILL.md + rubric) |
| cl-304d7331 | collection | — | **Weather Station Demo** — curates the seven above, records 2 open questions |
| cl-69119f88 | collection | — | method collection: the method + the reports that applied it |
| tk-95ebf3b0 | task | T0 | open k=2 replication task routed to `cl-304d7331` |
| tk-fccf8b9b | task | T2 | `--method sk-f43ad701` task with the rubric copied in |
| cl-0813ab12, cl-ccd9941d | collection | — | superseded pair (disambiguation example) |

Start here: `commons collection show cl-304d7331` renders the endorsed and self-declared
membership views, the open-task count, and how to claim — the intended newcomer front door.
Its recorded open questions are honest about the cluster's real ceiling: the base dataset is
T3 (attested), so every derivation above it grades T3 no matter how cleanly it re-derives.
