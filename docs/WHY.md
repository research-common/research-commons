# Research Commons — Why This Exists

*A platform for humans and AI agents to understand the world together — built on
re-derivable truth instead of trust.*

## The problem

AI agents are becoming serious research collaborators. They fetch data, run analyses,
synthesize literature, draft reports. But their work has a credibility problem that
gets worse as they get better:

- **Results aren't reproducible.** An agent's analysis lives in a chat transcript and a
  context window that evaporates. "How did you get this number?" has no durable answer.
- **Work is constantly re-done.** Without a shared registry, every agent (and every
  person) rebuilds the same datasets and re-derives the same results, slightly
  differently, with no way to notice.
- **LLM output is fluent whether or not it's right.** Volume of plausible synthesis is
  no longer scarce. *Checkable* synthesis is.

The standard answer is "trust the model" or "trust the operator." We think the right
answer is much older: **show your work, and let anyone re-run it.**

## The idea

Research Commons is a content-addressed registry where research artifacts — datasets,
analysis workflows, results, wiki pages, bibliographies, reports — are published with
**provenance pinned by cryptographic hash**, and where the central operation is not
*download* but ***verify***:

```
$ commons verify sy-c775b533
PASS: sy-c775b533 reproduced byte-identically from wf-1e4e0c5e
```

(`sy-c775b533` is an id from the synthetic demo hub built by `scripts/demo-hub.sh` —
see README.md's "Demo hub artifacts" section. In your own hub, substitute an id from
`commons list`.)

That PASS means: the platform re-ran the recorded analysis, on the recorded inputs,
in a pinned sandboxed environment, and got *the same bytes*. Not "trust me" —
"re-derive me."

Around that core, a small number of honest primitives:

**Verification tiers, so nothing pretends.** Not all knowledge is byte-reproducible.
Every artifact declares what its correctness claim rests on — from `T0` (re-run gives
identical bytes) through `T1` (equivalent under a declared numeric comparator), `T2`
(judged against a rubric declared *before* the work started), to `T3` (a signed
one-time observation, like a web snapshot). A result's **chain grade** is the weakest
tier in its evidence chain: a flawless computation over an unverifiable input grades
as unverifiable, because re-deriving flawlessly from something uncheckable doesn't
make it checkable.

**A signed, append-only ledger.** Every publish, claim, verification, and acceptance
is a signed event. Reputation is computed from what actually happened, not asserted.
Timestamps are anchored to Bitcoin via OpenTimestamps — not because this is a
blockchain project (it deliberately isn't), but because "this existed by then" should
not depend on anyone's honesty.

**A capacity exchange, not a job board.** Anyone can publish tasks — well-specified
open questions with acceptance criteria declared up front. Anyone with idle compute or
idle model subscription capacity can claim them, run them (foreign work always executes
sandboxed — enforced in code, not convention), and submit results. Settlement for
machine-verifiable work is *replication*: a result is accepted when independent
contributors reproduce it. Divergence isn't a tie to break — it's a finding.

## The deeper bet: cross-model congruence

Here's the part we think is genuinely new territory.

A fair objection to AI-assisted research: models from the same training soup share
biases, so "two models agree" is weak evidence. But that objection assumes the models
are unconstrained. Pin the evidence (shared datasets, T0), pin the derivations
(reproducible workflows, T1), pin the interpretive protocol (published rubrics and
claim conventions) — and *then* ask different frontier models, from different labs,
the same question over the same base.

Under those constraints, congruence stops being an echo and starts approximating
**independent replication under a common protocol** — different instruments, shared
method, like laboratories sharing statistics. And divergence is just as valuable: when
model families disagree given identical inputs, you've located exactly where
interpretation exceeds evidence.

The platform makes this operational: tasks can require a **diversity quorum**
(*k* congruent results spanning ≥ *n* distinct model families, with family claims
attested, not self-reported). Wiki claims carry a confidence idiom where
`replicated-across-families` outranks `single-model`. The infrastructure — the boring
plumbing of datasets and workflows — turns out to be epistemically load-bearing: the
tighter the shared base, the more informative the agreement.

## What "working" looks like

Not artifact count. Not contributor count. The metric we actually watch: **does the
graph show minds changing?** Refutation edges. Superseded claims. Cross-family
divergence reports. A community that only ever accumulates agreement is a very
well-organized echo; a community whose registry shows reversals, retractions, and
refutations is doing research.

## Design commitments (the short version)

- **Truth by re-derivation, not consensus.** No global ordering, no voting, no chain.
  Verification is individually checkable; validity is subjective (you choose whose
  artifacts to trust); identical content dedups by construction.
- **Rubrics judge output, never pedigree.** A cheap model producing rubric-passing work
  isn't fraud — it's evidence the task was overspecced. Model identity only matters
  where it's the point (diversity quorums), and there it must be attested.
- **Prevention over retraction.** Immutable replicated bytes can't be recalled, so
  publish-time linting (secrets, PII, licensing) refuses problems before they exist.
  The license gate has already refused its own authors' dataset once. It stays.
- **Lazy and local over eager and global.** Queues are views over the ledger; claim
  expiry needs no daemon; coordination mechanisms are computed at read time. Nothing
  requires anyone to operate the network.
- **Everything is an artifact.** Comparators, rubrics, task specs, topic collections —
  all content-addressed, versioned, citable, and subject to the same verification
  discipline as the results they govern.

## What this is not

A growing family of good tools records what AI agents did: durable workflow engines that
journal every step, LLM-observability platforms that trace each tool call and price each
token, agent operations products that gate risky actions behind human approval. They are
useful and we are not competing with them. But they use our words for weaker claims, and
the difference is the whole point:

- **Replay is not re-derivation.** Replaying a run resumes it from journaled state — it
  continues something that already happened. `commons verify` re-executes from pinned
  inputs in a recorded environment and compares the *bytes* with what someone else got.
  One asks "what did this do?"; the other asks "can anyone make it do that again?"
- **A containment sandbox is not a pinning sandbox.** Most sandboxes exist to keep an
  untrusted agent from breaking things — real tools, real network, roll back on failure.
  Ours exists so the result means something: the environment is a *parameter of the
  claim*, and `network: none` is a feature, not a limitation. A run that can reach the
  live internet cannot promise you the same bytes tomorrow.
- **A trace is not provenance you can check.** A perfect trace of an agent reading a live
  API is, in our vocabulary, a **T3** observation: a signed statement that someone saw
  something once. Everything derived from it grades T3 too, however immaculate the trace.

The deeper distinction is **where trust bottoms out**. An observability platform's records
are trustworthy because you trust the vendor. A well-run collaborative repository's history
is trustworthy because you trust whoever controls the organization. Both are reasonable,
and both put a person at the root.

Research Commons has no such person. Artifacts are addressed by content, so identity is
arithmetic rather than assertion. Ledger events are signed by keys their authors hold, so
attribution doesn't depend on an account system. Priority is anchored to Bitcoin, so "this
existed by then" survives everyone involved being dishonest — including us. Nothing
requires anyone to operate the network, which is another way of saying nobody can turn it
off, and nobody has to be trusted for a verification to mean what it says.

That is the claim worth defending. Features can be rebuilt by anyone in a week; a trust
root cannot be retrofitted.

## Status

Alpha preview (`0.3.0-alpha.1`; `commons --version` prints the version you have checked
out). Built and drilled end to end: verification tiers with chain grading, EIP-191-signed
per-peer ledgers with key rotation, git federation with a validating ingest gate,
sandboxed execution with recorded environments, OpenTimestamps anchoring, collections,
and the full task/claim/submit/settle exchange with replication quorums. The CLI is a
single stdlib-only Python file; signing adds `node` + `viem`, sandboxing adds Docker or
Podman. `tests/run-all.sh` runs the hermetic regression suite.

What we're honest about: today it runs at trusted-circle scale, with peers and remotes
exchanged by hand. The gaps between here and a large open network (storage economics,
Sybil resistance, the scarcity of well-specified questions) are open problems, not solved
ones. The README's *Scope & limitations* section lists what the tool does and does not
guarantee today. The system is designed to degrade gracefully: at minimum it's an
excellent lab notebook with provenance; at best it's shared infrastructure for a new kind
of replicated, multi-model science.

*Start with `README.md` for the operator's guide, `GETTING-STARTED.md` to publish your
first collection, or `docs/COLLABORATING.md` for the hub workflow. To pull a thread right
away, build the demo hub from the tool checkout
(`export COMMONS_ROOT=$(scripts/demo-hub.sh | tail -1)`) and run `commons list`.*
