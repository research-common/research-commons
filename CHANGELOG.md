# Changelog

All notable changes to the `research-commons` tool are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/) with the 0.y.z ("anything may change") clause in
effect until 1.0.0. See `docs/RELEASING.md` for the bump rules and release steps, and the
`VERSION` file for the currently checked-out tool version (independent of `SCHEMA`, the on-disk
manifest/ledger format version — `commons --version` prints both).

## [Unreleased]

### Fixed
- `publish --force` on an existing id now starts from the existing manifest: description,
  tags, links, `provenance` (inputs, workflow, run env/exec/finished), `created` and the
  verification block are kept unless their flag is passed. A `--force` that would lower the
  tier without an explicit `--tier` is refused. Previously the `fsck`/`push` remediation
  ("re-publish with --license/--obtainability") turned a verified T0 derivation into an
  unattested T3 with no provenance (#18).
- The dataset `--license`/`--obtainability` publish warnings check the final manifest, so a
  `--force` that keeps a recorded licence no longer claims it has none (#18).
- `commons status` no longer labels an unattested T3 artifact as bare `T3 attested`
  (header, per-node row, and chain-grade line). It now says `T3 attested by 0x…`
  when an attester is on file, or `T3 self-reported (no attester)` when it is not —
  matching what `commons verify` already reported (`attester : NONE`). Display only:
  no tier, chain grade, or exit code changed (#23).
- `commons collection show` and the generated collection HTML page no longer print
  `curated-in (ENDORSED — signed editorial list)` for a collection with no verified
  signed publish event. They now print `curated-in (UNSIGNED — editorial list, not
  attributable)` in that case, matching the `curated by: (no verified signed publish
  event ...)` line already printed above it. Display only (#23).
- `publish` no longer prints `warning: T3 artifact published with default attestation
  criteria` before the credential scan, the ingest-policy gate and the spec lint run. A
  refused publish used to open its stderr with "published". The warning now prints only
  for a publish that actually lands, checked against the final manifest. A no-op
  re-publish of bytes already held doesn't print it, and neither does a `--force` that
  inherits a recorded verification block (#26).

## [0.2.0-alpha.1] - 2026-10-01

First tagged release. Predates this tag, the project shipped ~21 commits of untagged history
(developed privately, 2026-07-23 through 2026-09-28) implementing verification tiers (T0/T1/T2/T3),
signed per-peer federation and an ingest gate, sandboxed execution, a task/claim/settle capacity
exchange with replication quorums, time anchoring, collections, forbidden-key ingest scanning,
and freshness markers — the v0.1→v0.3 development phases.
This tag captures the state after a further round of reviewed changes, several of them external
contributions, landed on top of that baseline.

### Added
- `VERSION` file and `commons --version` / `commons version`, printing
  `commons <version> (schema <SCHEMA>)`. Tool version and data-format schema are tracked
  independently on purpose (see `docs/RELEASING.md`).
- `package-lock.json` for the `viem` signing dependency, so `npm ci` is reproducible instead of
  floating on `viem ^2`.
- `docs/LICENSING-artifacts.md`: recommended licence per artifact type. CC0-1.0 is the default
  for datasets, including T3 observations. The recommendation is documentation only: the tool never
  applies a licence silently. The `push` refusal for unlicensed datasets now points to it (refs #6).
- `publish`: advisory stderr warning when a report, synthesis, wiki page, workflow or skill is
  published without `--license`. It never changes an exit code. Collections, tasks and
  bibliographies are exempt (refs #6).
- `docs/COMMONS-TEMPLATE.md`: COMMONS.md template + review rubric for domain hubs.
- `collection add-member`: endorse a collection member without hand-editing a signed spec.
- `list`/`search`/`collection show`: label artifact age by which clock it came from —
  self-declared vs. received-at freshness markers.
- `publish`/`hub check`: topic-scoped forbidden field names for collection ingest.

### Changed
- **Signer key source narrowed (safety fix):** `lib/sign-message.mjs` reads the key from
  `COMMONS_SIGNING_KEY`, else `~/.commons/signing.key`, and nothing else. The
  `ETH_SIGNER_KEY_PATH` fallback is gone: a variable exported for another signing tool (often a
  payment wallet) could silently become the commons identity. If you relied on it, set
  `COMMONS_SIGNING_KEY` to the same path.
- **Default sandbox image is now `research-commons-sandbox:base`**, built locally from the in-repo
  `environments/base/Dockerfile` (`docker build -t research-commons-sandbox:base environments/base/`).
  It replaces the previous defaults in both `registry/exec-policy.example.json` and the built-in
  fallback policy; those images existed only on the maintainers' hosts, so a fresh clone could not
  run the sandbox. An existing local `registry/exec-policy.json` is untouched (it is local-only):
  if yours predates this change, add `research-commons-sandbox:base` to `images` and make it the
  `default_image`. Artifacts recorded under an older image still verify, and under a different
  image they report PASS with an environment-independent note or `ENV-MISMATCH`, never FAIL.
- `scripts/anchor-cron.sh` now requires `COMMONS_AGENT` instead of defaulting it.
- The CI workflow `commons hub init` generates no longer references a
  `COMMONS_TOOL_DEPLOY_KEY` secret: the tool repo is public, so the checkout needs no key.
  `docs/COLLABORATING.md` drops the deploy-key setup and recommends pinning `--tool-ref` to a
  release's commit SHA.
- Install with `npm ci` (lockfile-exact) instead of `npm install`: README, GETTING-STARTED,
  COLLABORATING, and the CI workflow `commons hub init` generates.
- Secret lint **streams** and its cap rises from 8 MiB to **100 MiB**, GitHub's per-file push
  limit. Peak memory is flat (~18 MiB) regardless of file size; the cost is ~0.4 s per MiB of text.
  Lines longer than 1 MiB are scanned in overlapping windows, with no allow marker or hash-field
  exemption and a `very long line` warn. `COMMONS_LINT_MAX_BYTES` can only lower the cap (refs #9).

### Fixed
- **Security: commit-reveal independence check failed open on unsigned publishes.** The
  "commit posted after the result was already public" check ran only when the artifact
  had a verified *signed* first publisher. For an artifact whose only publish event was
  unsigned (written without a key, or legacy), a `commit-derivation` posted after the
  bytes were public still graded as an independent derivation and counted toward a
  replication quorum. It now fails closed: a commit against an artifact with any unsigned
  publish event, or with none, counts as a concurring reference (an unsigned timestamp
  can't prove ordering either way).
  `fsck --attribution` also reports unsigned-only artifacts (`UNSIGNED-ONLY:`, advisory).
- Secret lint: 32-byte hex values under hash-named JSON keys or CSV headers (`txHash`, `blockHash`,
  `topics`, `tx_hash`, …) no longer trip the `eth private key` block. The same value under a
  key-like field (`privateKey`, `secret`, `key`, …), in prose or in an unknown field still blocks,
  and a summary warn counts every suppression. On-chain datasets no longer need `--allow-secrets`
  (refs #9).
- Forbidden-key scanning now warns instead of silently passing when it hits the JSON nesting
  limit.
- Secret-lint no longer silently truncates scans with no warning — a truncated scan
  now reports a `warn` finding instead of a false "clean".

### Known issues (open at this tag)

- **#1** — obtainability cannot express "re-measurable, but never the same bytes."
- **#2** — no vocabulary for sampled observations: n and dispersion are invisible to the grader.
- **#3** — pre-registration outside the task/claim/settle flow — supported pattern?
- **#4** — staleness is not first-class: no shelf life, and age isn't surfaced at read time.
- **#5** — collections can't declare a member schema, so cross-peer joins rely on convention.
- **#6** — licence guidance: push requires `--license`, but the design note, the worked example,
  and registry precedent disagree.
- **#7** — network steps are invisible to lint and the manifest: chain-derived workflows need a
  declared public-source input.
- **#8** — append-only growing series: `supersedes` checks no lineage, and citing a superseded
  tip gives no advisory.
- **#9** — large datasets: no size policy for files over GitHub's 100 MiB limit (slicing by
  block range / date is under discussion). The lint cap and hash-field parts are fixed in this release.
- **#10** — `verification.params` is outside the T3 signed statement (tamper verifies unchanged).
- **#11** — ingest policy is bypassed by a `part-of` claim against a superseded collection.
- **#12** — COMMONS.md review request from an external hub: the first outside use of the
  template and rubric.

[Unreleased]: https://github.com/research-common/research-commons/compare/v0.2.0-alpha.1...HEAD
[0.2.0-alpha.1]: https://github.com/research-common/research-commons/releases/tag/v0.2.0-alpha.1
