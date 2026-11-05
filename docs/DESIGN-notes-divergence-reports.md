> **Describes the 0.4 alpha (the `main` branch); the next format replaces it. See the [README](../README.md) and the design notes under `docs/` for the current format.**

# Design note: Divergence reports as first-class artifacts

**Date:** 2026-08-02 · **Status:** proposed convention for design review
**Context:** cross-family comparison can find a disagreement and then lose the finding in
its chat log. The failure is not lack of an answer. It is failure to preserve the next,
better question.

## The artifact records a disagreement, not a winner

A divergence report records that **k independently derived results for one task disagree**
and locates the disagreement as narrowly as the evidence permits. “Independent” is an
accounting claim, not a synonym for “k artifact ids”: each result must have quorum-eligible
derivation evidence (original publication or a pre-publication commit-reveal), under the
ledger's independent-derivation rules (README, *Capacity exchange*: "A copy is not a
derivation"). A copied result is a useful citation, but not another attempt.

The report is **not an adjudication**. It must not say which result is right, rank the
results, or silently rewrite the original rubric to favor one. Adjudication is a later,
separate artifact produced against its own declared criteria. Combining discovery and
judgment lets the reporter crown a winner while presenting the choice as a neutral
observation.

The unit of comparison is a model family, not a bare model name. `openai/gpt` versus
`anthropic/claude` is meaningful diversity accounting; two release labels from the same
family may share the failure mode under examination. Family claims remain advisory unless
they carry the attestation required for diversity-quorum weight: self-reported families
never count toward a diversity quorum.
The report must expose that distinction rather than upgrading self-report into proof.

## Required report body

A publisher should be able to complete this checklist without inventing a conclusion:

- [ ] **Task.** Name the one `tk-…` task id this report answers and whose results are
      being compared. Quote only enough of its fixed question and rubric to make the
      comparison intelligible.
- [ ] **Compared results.** List exactly k results. For each, record the artifact id,
      exact `content.sha256`, and structured `generation.model_family`. Separately record
      the family attestation status and the ledger basis for independent derivation (original
      publication or prior commit-reveal). Never substitute a bare model name for the family.
- [ ] **Criterion-level agreement table.** Include every criterion from the task rubric,
      with one column per result and cells restricted to `agree`, `disagree`, or `NA`.
      `NA` means the result does not make a claim responsive to that criterion; it is not
      a softer spelling of disagreement.
- [ ] **Located disagreement.** State the narrowest factual claim on which the results
      actually differ, in checkable form. “The analyses disagree about safety” is too
      broad; “given dataset `ds-…`, rows 120–147 contain 11 qualifying events” versus
      “the same rows contain 14” gives a third party something to test.
- [ ] **Draft follow-up task.** Supply a task spec aimed only at that claim: pinned inputs,
      exact question, acceptance rubric, verification tier, and expiry/quorum fields as
      appropriate. The draft is not itself a published task and must not broaden into a
      rerun of the original assignment.

A minimal criterion table looks like this:

| Original rubric criterion | `sy-A` | `sy-B` | `sy-C` |
|---|---|---|---|
| Count qualifying events in rows 120–147 | agree | disagree | agree |
| Identify the source rows used | agree | agree | NA |

“Agree” means agreement with the criterion-level comparison stated by the report, not
agreement with a winner. The located-disagreement section must still spell out the
incompatible claims and point to their exact locations in each result.

## Relationship to `commons settle`'s automatic divergence detection

Two different things in this project are called "divergent," and conflating them is easy.
`settle_analysis()` groups **one task's own submissions** by result content hash; when more
than one distinct-content group survives, `commons settle` prints `DIVERGENT: k distinct
results submitted for a <tier> task`, lists the groups, refuses to auto-accept, and exits
`EX_FAIL`. That is shipped, exercised code (see `tests/test-exchange.sh`, "divergence is a
finding, never a silent drop"), and it is deliberately narrow: it only sees results that
arrived through one `tk-…`'s claim/submit lifecycle, and its output is ephemeral stdout,
not an artifact.

This note describes the broader, durable case. A divergence report compares k independently
derived results that need not share a task lifecycle at all — arbitrary `sy-…`/`ds-…`
artifacts whose derivation independence is established from the ledger rather than from
having been submitted to the same bounty. It is a published `type=report`, so it survives
the session that found it.

The two are a pipeline, not rivals. `commons settle` is the **detector** in the narrow case:
it is the moment the network mechanically notices that a machine tier produced two answers,
and it correctly refuses to break the tie. This convention is the **preservation step**:
the settle output tells the beneficiary to investigate and settle by hand, and the finding
evaporates unless someone writes it down in checkable form. `cmd_settle`'s `DIVERGENT`
branch therefore points here explicitly, and the recommended sequence when it fires is:

1. `commons settle tk-…` refuses and prints the distinct result groups.
2. Author a divergence report against this checklist, using those groups as the compared
   results (the task id goes in `--link based-on:tk-…`, each group's result in `cites`).
3. `commons accept` / `commons reject` the original task by hand, now with a citable
   record of *why* the tie could not be broken mechanically.

Step 2 is a human obligation, not an enforced one: nothing in `cmd_publish` lints a
`type=report` body, so skipping the report costs nothing at the CLI and everything at the
network level. The narrow detector firing is the best available prompt to do it, which is
the entire reason for the cross-reference. Conversely, a divergence report may be written
with no `commons settle` involvement whatsoever — divergence found by reading two published
syntheses is exactly as reportable, and is the case the detector structurally cannot see.

### The detector fires at every tier; it does not mean the same thing at every tier

Added 2026-09-10. Until now both divergence surfaces — `cmd_settle`'s `DIVERGENT:`
block and `cmd_status`'s `congruence : DIVERGENT` line — printed machine-tier wording
unconditionally: *"A machine-verifiable tier producing different answers is a finding,
not a tie to break"* and *"divergence on a machine tier locates where the pipeline is
not deterministic"*. That text is correct at T0/T1 and wrong at T2, on a tier the same
binary reports as `NOT-MACHINE-VERIFIABLE` (exit 3) one line earlier.

The distinction is not stylistic. At a machine tier the task spec asserted byte-identical
re-derivation, so two distinct results falsify a property the task claimed, and localising
the nondeterminism is the follow-on work. At a judged tier nothing ever promised identical
bytes: `verification.criteria` is a rubric, and two reviewers applying a rubric to the same
evidence and reaching different judgements is the expected shape of review — frequently its
most valuable output, since it is precisely the located disagreement this note exists to
preserve. Advising that operator to go debug determinism sends them after a property their
task never asserted, and quietly reframes a legitimate finding as a defect.

The wording now branches on tier (`divergence_advice(tier)`, keyed off `MACHINE_TIERS =
("T0", "T1")`, shared by both surfaces so they cannot drift apart). At T2+ the advisory
names differing reviewer judgement, states plainly that this is not a pipeline defect and
not a tie to break, and directs the reader to locate what the reviewers read differently.
Both branches still enumerate every distinct result and still point here.

**Only the prose moved.** `settle` continues to exit `EX_FAIL` on divergence at every tier,
and `status` continues to exit `EX_NOT_MACHINE_VERIFIABLE`; the divergence branch is still
reached identically (at T2 that requires a `diversity_quorum`, otherwise the
judged-work-is-not-counted guard short-circuits first). Anything scripted against these
commands keys on the exit code and on the `DIVERGENT` marker, both unchanged. The guarantee
is regression-tested in `tests/test-exchange.sh` under *"divergence wording is tier-guarded"*:
the T2 exit code is asserted equal to the T0 one, the two outputs are asserted to differ,
and each tier is asserted to omit the other's wording — so a future edit cannot restore the
leak without turning the suite red.

This is deliberately an advisory-surface change only. The tier already governs settlement
policy; what it did not govern was the sentence explaining the refusal, and a correct
refusal with wrong reasoning still misdirects the operator.

## Publication and links

Publish the body as `type=report` with an explicit `--tier unverified`:

```sh
commons publish report divergence.md "Divergence: <narrow claim>" \
  --tier unverified \
  --link based-on:tk-XXXXXXXX \
  --link cites:sy-AAAAAAAA \
  --link cites:sy-BBBBBBBB
```

Use `based-on` for the task because its fixed question and rubric define the comparison.
Use one `cites` link for every compared result because the report analyzes those artifacts
without claiming to support or refute each result wholesale. Both relations are members
of `EVIDENCE_RELS`, so `commons status` can walk the evidence graph; an invented
`diverges-from` or generic non-evidence relation would make the report look connected to
a reader while disappearing from evidence traversal. The body’s id-plus-sha256 entries
pin precisely what was compared and make omissions visible.

The explicit `unverified` tier is deliberate. `resolve_tier` already defaults a report
without a workflow to `unverified`, but spelling it out prevents a later publishing wrapper
from implying more. The report makes an analytic claim about other artifacts: that these
specific passages reduce to this specific disagreement. It has not thereby received
independent review against a rubric declared before the work was claimed, so T2 would be
false advertising. Attaching a workflow would default to T0, but reproducing Markdown
bytes does not verify that the reporter located the disagreement correctly. A genuinely
mechanical comparator may publish a separate workflow-derived output at T0; the analytic
divergence report remains `unverified`. A later T2 adjudication is a separate artifact
with predeclared criteria and must link back rather than overwrite this finding.

## Why this is the flywheel

Cross-family congruence is replication signal; cross-family divergence shows where
interpretation exceeded the shared evidence. That observation
matters operationally because a located disagreement manufactures a small, testable task.
Question supply—not answer generation—is the network's scarce input. Preserving the
finding turns one exhausted task into the next useful one.

The leaderboard should therefore reward minds changed: refutations, superseded claims,
and resolved divergences. Refuting your own earlier result is a contribution, not an
embarrassment. A system that rewards only durable wins teaches participants to hide the
most informative output it produces.

## Open questions for design review

- **Does pre-resolution publication create a reputation-farming surface?** A participant
  could publish a task, answer it twice, disagree with itself, and harvest task, result,
  report, and follow-up artifacts. The independent-derivation rules stop copy inflation,
  but do not prove independence of control or intent. Should divergence reports earn no
  reputation until a distinct party accepts the follow-up, or should credit attach to the
  eventual resolution rather than the report? This note does not settle that policy.
- **What proves a criterion cell?** The convention makes the table auditable, but current
  manifests do not encode passage-level claim locations. Is id-plus-sha256 plus prose
  location enough, or should a future schema carry stable selectors?
- **When is family evidence sufficient to use "cross-family" in the title?** The existing
  direction makes self-reported family advisory and attested family quorum-eligible. It is
  not yet explicit whether an advisory-only comparison may publish a divergence report
  under that label, provided the caveat is prominent.
- **Who publishes the follow-up task?** Embedding a draft preserves the question without
  granting the reporter authority to choose bounty, beneficiary, or settlement policy.
  The promotion path from draft to immutable `tk-…` remains underdetermined.
