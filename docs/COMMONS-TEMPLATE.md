> **Describes the 0.4 alpha (the `main` branch); the next format replaces it. See the [README](../README.md) and the design notes under `docs/` for the current format.**

# COMMONS.md: template and review rubric

A project's `COMMONS.md` is its **integration contract** with a Research Commons registry:
which of its datasets and analyses are candidates to share, on what terms, and what still
blocks them. It is the project-side counterpart of a collection spec.

**Who writes what.** The project's domain owner (human or agent) **writes** `COMMONS.md`,
because only they know how the data was produced and where it is wrong. A Commons maintainer
**reviews** it for tool semantics (tiers, obtainability, licence, forbidden keys, growth
model) and appends a dated verdict. The review never re-litigates the domain facts; it checks
that the tool is being asked to promise only what it can keep.

Keep it short and stable, like an index. Long rationale belongs in the project's own
plans/research, linked from here.

---

## Template

```markdown
# COMMONS.md: <project>

- **Owner:** <agent/person>  ·  **Last reviewed by steward:** <YYYY-MM-DD | never>
- **Target registry/hub:** <hub repo | shared registry | none yet>
- **Collection(s):** <cl-… | proposed name>
- **Plan / rationale:** <path>

## Datasets

### <short-name>
| Field | Value |
|---|---|
| Path(s) | … |
| Writer(s) + invariant | who writes it, and what must always hold (e.g. "append-only, one row per block, height strictly increasing") |
| Re-derivable from a public source? | yes / partly (which fields) / no (live capture) |
| Tier today → ceiling | e.g. T3 (attested capture) → T0 (if re-derived from headers by a pinned workflow) |
| Licence (SPDX) | e.g. CC0-1.0 · CC-BY-4.0 · none-yet (blocks publish) |
| Obtainability | open · licensed-obtainable (+ how a peer acquires it) · restricted |
| Forbidden keys / PII | columns/keys that must never appear (addresses tied to identities, account ids, balances, …) |
| Growth model | immutable snapshot · append-only series · overwrite-in-place |
| Partitioning | how a growing series is cut into immutable artifacts (e.g. by year/epoch) |
| Known DQ issues / errata | duplicates, gaps, migrations, re-bases, with dates |
| Status | candidate · blocked (<reason>) · admitted · published (ds-…, wf-…) |

## Analyses (workflows / syntheses / reports)
One line each: what it derives, from which datasets, determinism notes, status.

## Holdbacks
What is deliberately NOT shared, and why (strategy, privacy, third-party terms).

## Decisions pending (human)
Mirror each into wherever the project tracks decisions that need a human.

## Steward review (YYYY-MM-DD)
<appended by the Commons maintainer; see rubric>
```

---

## Review rubric (for the maintainer)

For each dataset, mark each criterion **ok / fix / n.a.** and give a one-line reason for anything
other than ok:

| id | Criterion |
|---|---|
| R1 tier | The claimed tier matches how correctness actually rests: T0/T1 only if a pinned workflow re-derives it; live captures are T3; nothing is inflated. |
| R2 chain | A derived artifact's chain grade is understood (weakest input wins). No report implies T0 confidence over a T3 base. |
| R3 licence | An SPDX licence is stated for material the project owns. Third-party data isn't relicensed. `none-yet` is treated as a blocker, not a default. |
| R4 obtainability | Stated explicitly. `licensed-obtainable` says how a peer gets it. `open` means redistributable, not "re-measurable". |
| R5 forbidden keys | Identifiers and PII are enumerated, including CSV headers. The secret/PII lint catches credentials, **not identifiers**, so the doc names what the exporter must strip. |
| R6 growth | A growing series is modelled as immutable partitions + `supersedes`, not as a mutating artifact. The partition key is stated. |
| R7 re-derivation | Where a public source exists, a re-derivation path (or check over a recent window) is named, so the tier can rise. |
| R8 DQ disclosure | Known duplicates, gaps and migrations are disclosed, with the fix or erratum. Publishing known-bad bytes needs a stated reason. |
| R9 determinism | Workflows pin TZ/LC_ALL/PYTHONHASHSEED, sort outputs, have no wall-clock in outputs, and use no network in steps. |
| R10 gaps upstream | Anything the tool can't express yet is recorded as a tool gap (issue/TODO link), not worked around silently. |

**Verdict:** `ready` (publishable once human decisions land) · `ready-with-fixes` (list) ·
`not-yet` (blocking criteria). The review is advisory. Publishing is still gated by the tool
(`push` requires licence + obtainability) and by the human decisions listed in the doc.
