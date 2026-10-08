# Changelog

All notable changes to the `research-commons` tool are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/) with the 0.y.z ("anything may change") clause in
effect until 1.0.0. See `docs/RELEASING.md` for the bump rules and release steps, and the
`VERSION` file for the currently checked-out tool version (independent of `SCHEMA`, the on-disk
manifest/ledger format version — `commons --version` prints both).

## [Unreleased]

### Changed
- **Anchor coverage is per signer, so every key must anchor its own log.** A checkpoint
  now bounds only the log of the key that signed its `anchor` event. A hub operator's
  `anchor` run no longer protects contributors' lines: a key that never runs `anchor`
  has uncheckpointed publishes, which sort last in every priority comparison.
- **A later publisher who anchored now outranks an earlier one who didn't.** With every
  bound local (self-declared), ordering is checkpoint first, asserted time only as a
  tiebreak. Derivation credit follows that ordering, so the uncheckpointed earlier
  publisher's submission can drop from *independent derivation* to *concurring
  reference*, and `status` reports a TIME DISCREPANCY against it.
- **Existing `confirmed` checkpoints lose Bitcoin quality, with no grandfathering.**
  They still count as local checkpoints when a matching signed `anchor` event exists
  in the signer's own log; otherwise they contribute nothing to priority. Bitcoin
  quality returns only with receiver-local proof and block-time verification.

### Fixed
- **Phase 2 preserves publisher records (#43).** `submit`, `accept`, `settle` and
  matching `rebaseline` append lifecycle events without rewriting manifests.
  Readers derive `fulfills`/`accepted` from authenticated events, honour later
  rejection, and ignore unbacked legacy link caches (`fsck` reports them).
  Trusted rebaseline reproductions with held authority or a signed reproducer
  delegation are displayed separately; the original execution record remains.
  Arrival stamps move to local-only `registry/ingest.json`; embedded `ingest`
  cannot make a missing local blob count as lazily replicated.
- **Attestation v2 writers (#10).** `attest` signs `attestation/2` with exact
  parameters, including empty values. `--force` replaces only the signer's own
  attestation. A criteria change requires publisher authority and emits a matching
  signed republish view. Displacing another attester still requires an authorised
  republish; there is no dedicated replacement flag.
- **Unchecked metadata stops verification (#43 phase 1).** `verify` exits 3
  (`NOT-MACHINE-VERIFIABLE`) for unknown view versions or unnormalisable metadata,
  before resolving or executing the artifact's workflow/comparator. This also applies
  to workflow metadata and, when needed, T1 comparator metadata, so changing the
  version or injecting NaN cannot bypass the signed-view tamper guard. Comparator
  filename/hash edits are rejected before execution; byte-identical output still
  needs no comparator lookup. Unsupported future formats are labelled unchecked,
  without a forgery accusation.
- **Signed-view readers and gates (#43 phase 1).** A present publisher statement is
  verified against the exact normalized metadata view. `pull` and `hub check` refuse
  altered or stripped views, unauthorized replacements, rollback, and changes without
  a matching new dual-signed view event. Distinct v2 ledger payloads remain distinct
  even when their v1 signatures match; known stripped copies and v1-only lines after
  a verified v2 line in the signer's own log are rejected. The floor does not prove
  original log order or detect stripping an unseen first v2 event.
- **Attestation v2 readers (#10).** `attestation/2` binds comparator parameters,
  including empty values. Parameter changes are stale; legacy attestations with
  parameters are `partial`, and new partial attestations fail the gates.
- **Untrusted anchor JSON no longer grants Bitcoin-quality priority.** A fabricated
  `confirmed` checkpoint could seize first-publisher credit and report a discrepancy
  against the honest publisher, without a proof. Read-side bounds now require a
  recomputed root and a matching signed `anchor` event in the signer's own log, cover
  only that log's preceding prefix, and use the signed event's timestamp. All current
  checkpoints stay local (self-declared), regardless of confirmation metadata;
  Bitcoin quality awaits receiver-local proof/block-time verification. Evidence quality
  sorts before time across publishers as well as within a line's bounds. Unsigned
  operational checkpoints remain usable for unsigned-log drift coverage, but cannot
  authenticate signed events or unsigned lines that claim an `addr`. A signed anchor
  event dated before a line it covers is ignored. `status` and derivation-evidence
  text now describe a TIME DISCREPANCY as a disagreement between assertions, not
  grounds to discount a peer. `pull`/`hub check` acceptance rules are unchanged.

### Added
- **Signed-view writers and backfill (#43 phase 2).** Keyed `publish`/`republish`,
  `run --publish`, `run-task` (also accepting explicit `--publish`) and new
  `rebaseline --publish-superseding` outputs write `publisher_sig` and a matching
  dual-signed ledger `view` event. Existing outputs retain their held manifests;
  replacements require held authority, and keyless writes cannot downgrade views.
  `commons manifest sign ID...` or `--mine` prints and signs eligible legacy claims
  with a `republish` carrying `backfill: true`. Authority is the sole verified
  legacy publisher or a collection maintainer in the hash-checked held spec;
  orphan, unsigned-only and ambiguous non-collection adoption is unavailable.
  Already signed current views are left unchanged. No `SCHEMA` bump.
- **Metadata inspection.** `show`, `status`, `list`, `search`, collection display and
  `list --json` expose metadata view state; `fsck --views` audits it. `verify` refuses
  altered/stripped metadata before running code. Fixed normalization and EIP-191
  vectors cover empty comparator values, ordered inputs, Unicode and floats.
  Phase 1 introduced readers; phase 2 adds the writers above. These gate/CLI changes
  require a MINOR tool release.
- **`announce` warns when a remote would leak local or internal details (#53).** A local
  filesystem path, a private/loopback/CGNAT or single-label host, an internal name
  (`.local`, `.lan`, `.internal`, `.localdomain`, `.home.arpa`) or a non-`git` username in a
  `--remote-url` (or a `publish peer-announce` spec) now prints a stderr warning that
  announces are public and permanent. Exit code and accepted URLs are unchanged.
  `announce --help` says the same.
- **`publish workflow` warns on network-shaped steps (#7, warn half).** A step that runs a
  fetch or RPC client in command position (`curl`, `wget`, `nc`, `ssh`, `bitcoin-cli`,
  `dcrctl`, `cast`, …), `git clone/fetch/pull`, a package install, names a URL, or calls a
  Python/JS HTTP client prints a stderr warning pointing at the determinism checklist
  (acquire, publish the capture, derive). Advisory: exit code unchanged, step text only.
  The declared public-source input stays open in #7.

### Documentation
- **Phase boundaries and remaining gaps.** Phase 3 enforcement is a separate
  downstream branch; `require_signed_views` and `COMMONS_REQUIRE_VIEWS` are not
  implemented here. Deployment requires a later tool pin containing both writer
  and enforcement commits; a writer-only SHA ignores the flag.
  Hub adopting authority for frozen/orphan legacy artifacts is
  deferred to #58. #45 remains open for whole-log `sig2` stripping from an unknown
  key; the received-order v2 floor cannot detect it. `verify` stops on
  unknown/unnormalisable views with exit 3 before execution; readers continue to
  display those states.
  `publish --force` preserves omitted attested parameters and refuses an explicit
  change using exact JSON comparison, including empty member values and number types.
- **How to migrate a collection superseded before #39.** The 0.3.0-alpha.1 migration note said to
  republish the successor with `supersedes` in its spec. That alone isn't enough. If the chain has
  more than one hop and the policy was added after the first version, a claim against the original
  id still escapes the policy. The new tip has to list every earlier version, and each
  intermediate version needs a `--force` republish to drop its stale manifest link, or `hub check`
  keeps failing. README §"Migrating a collection superseded before #39" gives the steps, and
  `tests/test-spec-supersedes.sh` covers them.

## [0.3.0-alpha.1] - 2026-10-04

Second tagged release. **MINOR bump:** `hub check` and `pull` now refuse things they accepted
before (hand-edited manifests, replayed or misplaced ledger lines, unbacked links and tags), so
a hub PR that passed under 0.2.0-alpha.1 can fail here. **Upgrade note for hub maintainers:**
bump `hub-check.yml`'s pinned tool SHA. New events carry a second signature (`sig2`) that older
tools ignore, so mixed fleets keep verifying each other; only this release and later check it.

### Changed
- **Breaking: a collection's lineage is declared in its spec (safety fix, #39).** A successor
  lists what it replaces in its content (`"supersedes": ["cl-…"]`), which the id pins and the
  maintainer's signed publish covers. The manifest's `supersedes` links are derived from the
  spec at publish and are only a hint for peers that hold manifests but not specs. Where the spec
  is held it wins everywhere a collection lineage is read: ingest-policy inheritance (#11),
  subscription supersede-following, the retired-base guard in `collection add-member`, the
  `SUPERSEDED` marker in `collection show`, and `list --tips-only`. `collection add-member` writes
  the field. `publish collection --link supersedes:X` is refused unless the spec declares X, and a
  `--force` republish re-derives the hints from the spec, so it can change a collection's other
  links but not its lineage. `hub check` fails a collection whose manifest hints disagree with its
  spec. The spec's list is linted (a list of `cl-` ids, no duplicates). **Migration:** a collection
  supersede declared only by a manifest link no longer counts. Republish the successor with the
  field in its spec. Other artifact types are unchanged.
- The `maintainers[i] needs an addr` collection lint now explains the expected path for a
  collection assembled before its owner's key signs it: list the intended owner's address and
  `collection show` marks the list unattributable until that address signs (#24).

### Fixed
- **`pull` merged an edit to the manifest of an already-held artifact without validation
  (safety fix, #41).** If the content hash was unchanged, the manifest was counted as "already
  present", no check ran, and `git merge` applied the edit, so a peer could rewrite tier,
  criteria, licence, obtainability, title or links. `hub check --base` did not look at modified
  manifests at all. Both gates now compare a modified manifest with the merge base. They accept
  it if the range carries a new verified signed `publish`/`republish` of the id by a key with
  authority over it: the artifact's single verified signed publisher at the base, or a
  collection maintainer. A `republish` never grants authority, and an artifact with no
  verified signed publish (legacy unsigned) or several from different keys has no owner who
  can rewrite it. `pull` also requires a registered peer with sufficient trust and a valid key
  window. Otherwise they accept only additive annotations backed by a signed ledger event,
  matched on its signed fields (`submit` → `fulfills`, the beneficiary's `accept` →
  `accepted`, `attest` → `attested_by`, an owner-signed v2 `rebaseline` → exec record).
  Everything else is rejected and quarantined. Known gap, pinned by the test suite: the
  republish signature does not cover manifest bytes, so an edit committed after a genuine
  republish in the same range rides on it (closed by signed manifest views, #43).
  **Behaviour change:** a hub PR or peer branch that hand-edits manifests now fails. Use
  `publish --force` instead.
- **Replayed and rewritten ledger events (#42 review).** Both gates refuse a copy of a
  signed event with an unsigned field changed (`prev`, `result`, the signature's
  recovery-byte encoding), whichever copy arrives first. Events are identified by recovered
  signer plus signed payload. Ledger readers keep one row per event, preferring the copy in
  the signer's own log. Byte-identical duplicates are tolerated. `pull` runs these checks on
  unrelated histories too, against the ledger it holds. Since `ts` has one-second
  resolution, signing an event identical in every signed field to one already in the
  signer's log waits for the next second, so two genuine events (`accept R1`, then
  `accept R2 --force`) never share an identity. `pull` now enforces append-only ledgers
  (including the legacy flat `registry/ledger.jsonl`), as `hub check --base` already did.
  Both gates refuse a second key's `publish` of an already-held id when the base holds no
  verified signed publish of it (the event would make its signer the owner). When the id
  already has a signed publisher, the event is reported and grants no authority, but it is
  not refused: the sender's log is append-only, so refusing would wedge federation with
  that peer, and priority between the two publishes is settled by anchors.
- **`attest --criteria` by the artifact's own publisher** restates its criteria and passes
  both gates. A different attester may add or replace `attested_by` but cannot change the
  criteria.
- `pull` from a ref already contained in `HEAD` returns before any signature pass.
  `hub check` reports a modified manifest without `content`, or a deleted ledger file,
  instead of raising.
- **Every ledger event is dual-signed (#49, format from the #43 design note §5.2).** `sig`
  still covers the v1 fields (`action, agent, id, sha256, ts`), so every older tool, including
  hub CI pinned to v0.2.0-alpha.1, verifies new events unchanged. `sig2` is EIP-191 over
  `{"rc": "ledger/2", "entry": …}`, the whole entry minus `addr`, `sig`, `sig2` and `prev`, so
  it also authenticates the fields `sig` leaves open: a submit's or accept's `task` and
  `result`, a rebaseline's exec record. A present `sig2` that fails makes the event a forgery.
  One signer process writes both. Only an owner-signed `rebaseline` carrying `sig2` can back
  a changed exec record on an already-held manifest. (Unreleased `main` briefly signed
  rebaselines with a `sig_v: 2` payload instead; old tools reported those as BAD SIGNATURE.
  That form is gone and no released tool wrote it.)
- **Lifecycle events bind the task and result they name (#45).** Lifecycle readers select a
  task's events by the signed `id`, and drop an event whose unsigned `task` disagrees, so a
  relayed accept with `task` changed no longer settles another task. A v1 submit (no `sig2`)
  counts only if its `result` is a manifest we hold whose full content hash is the submit's
  signed `sha256` (`submit` already refuses an unpublished result). A v1 accept's `result`
  counts only if it names such a submission to the task, judged against every submission
  regardless of timestamp order, and a v1 accept with its `result` removed no longer settles a
  task that has submissions. The manifest-edit gate applies the same rules to `accepted`
  links, which closes the gap #41's fix pinned. **Known gap:** a receiver that never saw a
  dual-signed original cannot tell a copy with `sig2` stripped from a v1 event, so a relayed,
  stripped accept can still name any *other* genuine submission to the same task, including
  the relayer's own. Closing that needs a per-signer v2 floor (#43 phase 3).
- **A `republish` no longer claims first-publisher credit (#46).** `first_publisher` counted
  `republish` events, so any key could sign a backdated republish of an artifact whose
  publish was unanchored, and its later `submit` of that artifact graded as an independent
  derivation. Only `publish` claims authorship now. The gates' note on a second key's
  `publish` now says it competes for first publisher, which anchors decide. **Behaviour
  change:** a signed `publish --force` (a `republish`) no longer clears `fsck --attribution`'s
  advisory `UNSIGNED-ONLY` for a legacy artifact. A backfilled signed `publish` would, but both
  gates refuse it from any peer (it would mint an owner), so there is no federating repair
  until adoption lands (#47).
- **`pull` applies `hub check`'s per-line ledger rules (#48).** Every incoming signed line
  that we don't already hold in that same file must verify and sit in the log named after its
  signer. Before, a peer's line written into your own log (even a byte-identical copy of a
  line we hold elsewhere) merged, and then failed hub CI on every later push. New lines in the
  unsigned logs (`ledger.jsonl`, `local-unsigned.jsonl`) are **not** refused: a subscriber
  bootstrapping from a hub with legacy unsigned history receives them legitimately. `pull`
  warns and records them in `quarantine.log` (#14 stays open).
- **`pull` refuses tags only the incoming copy carries on a manifest added on both sides
  (#48)**, whether from an unrelated history or two peers publishing the same bytes since the
  merge base. The add/add exemption kept both sides' tags, including tags a peer added to a
  manifest it never published. Local tags still survive the merge; `pull --force` overrides.
- **Ingest policy bypass reopened by stripping a manifest `supersedes` link (#39).** Before the
  spec-declared lineage above, the #11 walk followed the successor's manifest link, which no
  signature covers. Anyone holding the manifest could delete it (a manifest-only edit, or
  `publish --force --link …` under any key), every gate passed, and afterwards a `part-of` claim
  against the old id escaped the successor's policy at the publish gate and at `hub check --base`.
- **Ingest policy bypassed by a `part-of` claim against a superseded collection (safety fix,
  #11).** The gate read only the collection named, so a policy added by superseding never
  applied to claims against the old id, and `hub check --base` passed them too. A claim now gets
  the union of the named collection's policy and that of every version reachable by
  maintainer-signed supersedes, forks included; following the lineage only ever tightens, and
  successors not signed by a maintainer of the collection they supersede are ignored. Output names
  which version contributed each key. Every `part-of` at a superseded collection warns, naming
  the current version(s). A flagged successor, or a flagged version past an intermediate, whose
  spec is not held refuses as unchecked, with the existing `commons fetch` /
  `--allow-unchecked-ingest` ways out. So does a policy-bearing successor with no verified
  signature (unsigned, or its ledger entry not held). The lineage walk has no length limit. The
  publish gate and `hub check --base` share one resolver
  (`resolve_ingest_policy`) over a reader of the local store or of git at base, and `hub check`
  reads the whole lineage at base. Not changed here: `collection show <tip>` still does not list
  claims made against its predecessors (#8).
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
- `collection show` labelled an instance applying a method revision two or more `supersedes`
  hops behind the collection's method member as `(different method)`. It now walks the chain and
  prints `(superseded)` or `(superseded ×N)`. Display only (#8).
- `publish_lint.scan_file` now recognises gzip/zip/bzip2/xz/tar magic bytes and emits a
  `WARN archive members not scanned` finding, folded into the existing PARTIAL verdict
  (`secret-lint: clean (PARTIAL: ...)`), instead of printing nothing for an archive whose
  interior was never examined for secrets (#20). Member-aware scanning (enumerating and
  scanning archive contents) is still not built; this only makes the existing gap visible
  at runtime instead of README-only.
- `commons run --publish` on a native run now warns once on stderr when the container
  runtime (`docker`, or `COMMONS_CONTAINER_CMD`) is not reachable, saying the result is
  native-only and may not reproduce under the sandbox. Previously this surfaced only later,
  as `status`'s `(pre-sandbox baseline)` annotation. Advisory only: no exit-code or manifest
  change (#25).

### Known issues (open at this tag)

- **#14**: `pull` accepts new lines in a peer's unsigned logs (warns and records them in
  `quarantine.log`; a bootstrap from a hub with legacy unsigned history needs them).
- **#41 part 2 / #43**: a republish signs the content hash, not the manifest, so an edit
  committed after a genuine republish in the same range rides on it. Signed manifest views
  (#43) close it.
- **#45 residual**: a relayed accept with `sig2` stripped can name another genuine submission to
  the same task (needs a per-signer v2 floor, #43).
- **#46 residual (by design)**: a second key's backdated `publish` competes for first publisher
  until anchors settle it; anchor promptly if derivation credit matters.
- **#47**: a second key's `publish` leaves no key able to rewrite the artifact's manifest, and
  legacy unsigned-only artifacts have no attribution repair (adoption, #43 §6.2).
- **#48 item 3**: `pull` and `hub check --base` verify the whole held ledger on every
  non-trivial pull (~5 ms per line).
- **#10**: `verification.params` is outside the T3 signed statement.
- **#9**: no size policy for files over GitHub's 100 MiB limit.
- **#20**: archive members are flagged but not scanned.
- Design questions open for input: #1, #2, #3, #4, #5, #6, #7, #8 (predecessor claims on a tip),
  #16, #17, #19, #21, #22, #24, #25.

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

[Unreleased]: https://github.com/research-common/research-commons/compare/v0.3.0-alpha.1...HEAD
[0.3.0-alpha.1]: https://github.com/research-common/research-commons/compare/v0.2.0-alpha.1...v0.3.0-alpha.1
[0.2.0-alpha.1]: https://github.com/research-common/research-commons/releases/tag/v0.2.0-alpha.1
