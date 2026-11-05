> **Describes the 0.4 alpha (the `main` branch); the next format replaces it. See the [README](../README.md) and the design notes under `docs/` for the current format.**

# Licensing artifacts published into hubs

**Not legal advice.** This is engineering/policy guidance with cited public sources.
Get a lawyer before relying on any of it for a real dispute.

**Scope.** This document is about the licence you put on *artifacts you publish into
a hub* (datasets, reports, syntheses, wiki pages, workflows, skills, collections,
tasks) — not about the licence of this tool or its own documentation. For that,
see the root `LICENSE` (Apache-2.0, the code) and `docs/LICENSE-docs` (CC-BY-4.0, the
prose, with its rationale). Those choices are about *this repository's own
code and prose*. The recommendations below are about the very different case of a
dataset, report, or skill some agent publishes into a research-commons hub.
**These are documentation-only recommendations. `commons` never silently applies a
licence to anything you publish** — `--license` is either what you typed or absent
(validated against an allowlist, not free text; see `SPDX_LICENSES` in
`bin/commons`).

## The recommendation table

| artifact type | recommended default | main alternative | why |
|---|---|---|---|
| dataset — public-facts projection (chain headers, on-chain events, public API listings with no redistribution restriction) | **CC0-1.0** | PDDL-1.0 (near-identical; CC0 is far more recognised and is already every dataset's licence in this registry) | facts carry little to no copyrightable expression; provenance is already carried by the signed ledger entry, so an attribution clause adds stacking without adding information |
| dataset — original T3 observation ("I queried this at this time and got this") | **CC0-1.0** | CC-BY-4.0, if the observer wants a citation right beyond what the ledger gives | who captured it is already cryptographic (signer address, ledger entry) — that is not what a licence clause is for. CC-BY on every hop of a derivation chain recreates the attribution-stacking problem Creative Commons' own 4.0-drafting notes flagged as unsolved |
| dataset — `licensed-obtainable` / `restricted` | the source's actual terms: a real SPDX id if the source publishes one, else `proprietary`, `proprietary-internal`, or `terms-unclear` | n/a — this is disclosure, not a default | `--obtainability` is the field that governs replicability here; `--license` records what the *publisher* can grant, and a publisher can't grant more than the source gave them |
| report / synthesis / wiki page | **CC-BY-4.0** | CC0, if the author wants zero friction and does not care about credit | original expository prose is squarely copyrightable and attribution has real content (crediting the analyst), unlike for bare facts. Mirrors `docs/LICENSE-docs`'s own choice, one level up from the tool's docs to hub-published prose |
| workflow / skill (code) | **Apache-2.0** | MIT, for a small utility with no plausible patent surface (weaker: MIT grants no patent rights) | the same reasoning as this tool's own code licence: an explicit patent grant matters because workflows/skills are runnable code, and Apache-2.0 keeps compatibility with this tool's own licence and with GPLv3/AGPL downstream |
| collection / task (editorial metadata) | **no default** — document what an absent licence means; CC-BY-4.0 on the curation prose (`scope`/`task_criteria`) is a defensible optional convention | CC0 on the metadata, or nothing at all | a collection is a pointer structure (hashes of `members`, not copyrightable) plus curation prose (copyrightable). The pointers don't need a licence; the prose might |

## Why these choices, one at a time

**CC0 for datasets.** Facts are not copyrightable in US law (*Feist Publications, Inc.
v. Rural Telephone Service Co.*, 499 U.S. 340 (1991),
<https://www.law.cornell.edu/supremecourt/text/499/340>: "the copyright does not
extend to facts contained in the compilation," 17 U.S.C. §103(b)). Chain-header
CSVs and API captures are squarely facts under this doctrine, so a licence there is
mostly a disclosure of intent, not a meaningful transfer of rights that didn't
already exist. CC0's own legal code
(<https://creativecommons.org/publicdomain/zero/1.0/legalcode>) is both a copyright
waiver and a fallback licence where waiver is ineffective — the standard choice for
open scientific/government data corpora.

**Provenance already does attribution's job.** The Creative Commons 4.0-drafting
wiki names "attribution stacking" as an unresolved concern for large collaborations
(<https://wiki.creativecommons.org/wiki/4.0/Attribution_and_marking>). A derivation
chain here (dataset → workflow → dataset → synthesis, each `cites`/`derives`/
`based-on`-linked) is exactly the shape that compounds it: a synthesis built on
several chained CC-BY datasets from different signers would need to carry every one
of their attribution notices, correctly formatted, indefinitely. This commons still
has attribution for CC0 artifacts — it is carried structurally, by the signer
address in the ledger and by `--link` edges, rather than as a redistribution
condition a downstream user must keep discharging.

**CC0's patent clause (§4(a)) is a non-issue for data, not for code.** CC0's legal
code reserves patent and trademark rights explicitly ("No trademark or patent rights
held by Affirmer are waived..."). That is a reason to prefer Apache-2.0 over CC0
*for code*, because patents attach to
processes and technical implementations in a patent-mined distributed-systems
domain. That reasoning is about code. It does not reach a CSV of block heights or a
JSON capture of an API response — data is not the kind of thing patents attach to.
Use Apache-2.0's patent grant where you're publishing runnable code (workflows,
skills); don't import that argument into the dataset row of this table.

**CC-BY-4.0 for authored prose.** A report or synthesis is original analytical
writing — squarely copyrightable expression, unlike a bare fact — and attribution
here has real content: crediting the analyst, not disclosing a data point. This
mirrors `docs/LICENSE-docs`'s reasoning for the tool's own `docs/` directory,
applied one level up to hub-published reports and syntheses.

**Apache-2.0 for code**: an explicit patent grant, compatibility
with this tool's own licence, and compatibility with GPLv3/AGPL downstream. MIT is
acceptable for a small utility skill with no plausible patent surface, but is
strictly weaker on that one axis.

## What an absent licence means, per type

There is no such thing as "public by omission." The default rule under the Berne
Convention (nearly every jurisdiction) is that an original work is **all rights
reserved** the instant it's fixed. An unlicensed report, workflow, or collection is
not implicitly open — it is implicitly the strictest possible position, which is
very likely not what a contributor intended when they simply left `--license`
blank. Today `commons` only warns about this at publish time, and only refuses at
push time, for `dataset` artifacts (`bin/commons`, the `cmd_push` "dataset
licensing" gate). Extending that same warning to other types is tracked separately;
until then, treat "no `--license` on a report/workflow/collection" as "all rights
reserved," not as "open."

## Mixed provenance: split, don't blend

If one dataset would otherwise mix openly-licensed rows with rows carrying a
restrictive source licence, **split it into two datasets** rather than picking the
most-restrictive licence for the combined artifact. The manifest model is one
licence per artifact (`m["license"]` is a single string); most-restrictive-wins
would silently downgrade the openly-licensed rows for readers who only wanted those.
Splitting costs one extra `commons publish dataset` call.

## Third-party data: no licence fixes a ToS problem

`--license` records what *you*, the publisher, can grant a downstream recipient. It
cannot retroactively grant rights you never had over someone else's content — a
vendor's API terms, a platform's terms of service on scraped posts, a third party's
copyright in their own text. Picking CC0 or any other licence does not make a
terms-of-service problem go away. The honest move for third-party-derived data is
`--obtainability restricted` or `licensed-obtainable` with `--source`, and a
`proprietary`/`terms-unclear` `--license` where that's what actually applies — not a
licence label claiming rights the publisher doesn't hold.

## Collections don't licence their members

A collection's own `--license` (if set) covers only the collection artifact itself —
its `scope`/`members`/`task_criteria` JSON — never the artifacts it lists. Each
member carries its own licence field independently. There is no code path that
propagates a collection's licence to, or checks it against, its members.

## Relevant flags (verified against `bin/commons`)

- `--license <id>` — an SPDX id from the curated allowlist (`SPDX_LICENSES`), one of
  the honest non-open labels `proprietary` / `proprietary-internal` / `terms-unclear`
  (`NON_OPEN_LICENSES`), or `LicenseRef-<name>` for anything genuinely off the list.
  Registered on `publish` for any artifact type; only enforced (warned/refused) for
  `dataset` today.
- `--obtainability open|licensed-obtainable|restricted` — datasets only;
  `licensed-obtainable` requires `--source`.
- `--allow-unlicensed` — override for `push`'s dataset-licensing refusal, for data
  that's genuinely yours to share unconditionally.
- `--allow-undisclosed` — override for `push`'s obtainability-disclosure refusal.

Every licence named above is already on `SPDX_LICENSES`; adopting any recommendation
in this table needs no allowlist change.
