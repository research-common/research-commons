# Changelog

All notable changes to the `research-commons` tool are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/) with the 0.y.z ("anything may change") clause in
effect until 1.0.0. See `docs/RELEASING.md` for the bump rules and release steps, and the
`VERSION` file for the currently checked-out tool version (independent of the wire format major,
`rc/1`). Entries up to 0.4.0-alpha.1 describe the Python alpha, which lives on `main`.

## [Unreleased]

### Added

- A collection genesis may name an identity as a controller. `publish --draft` of a `genesis` whose `controllers` hold
  typed subjects (`{"identity": "<id>"}` and/or `{"key": "<key>"}`, sorted and duplicate-free) is signed from a bare key
  as `rc/2` with the body marker `{}` and no actor, exactly as the fixed-root identity design note (section 2.1)
  describes. It is read back through the identity reader before anything is appended, so a typed genesis that reads
  invalid (a `k_of_n` its controllers cannot satisfy, an unsorted list, a malformed id) is refused with nothing signed.
  A genesis whose controllers are all plain keys is unchanged, byte for byte `rc/1`, and so is the genesis `publish task`
  writes. An edition naming an identity controller is still refused (an edition is not a raw-key statement of the
  profile): KNOWN-LIMITS L-21 now covers that case and the `publish --as` grant requirement. No change to the reader, the
  wire format or its documents, or the `rc/1` schema.

### Fixed

- A collection whose genesis names an identity and a plain key (`{identity: I}`, `{key: K}`) can now advance under
  `k_of_n`: a bare key's `publish --draft` of an `edition` or `withdraw_approval` of a resource whose genesis is `rc/2` is
  written `rc/2` with the body marker `{}` and no actor (identity design note sections 2.2 and 2.3), so it approves the
  same edition as an identity's approval of the same draft. Before, it was written `rc/1`, a different edition id, and a
  `k_of_n` collection with an identity controller could never get past its genesis. The major follows the genesis this
  store holds; an edition of a resource whose genesis is not held is refused (exit 3, nothing signed). Editions of
  resources whose genesis is `rc/1`, and a controller change to plain key strings, are unchanged, byte for byte `rc/1`.
  No change to the reader, an existing signed byte or vector, an exit code or a command.
- Task readiness no longer passes on a reader-supplied check that answers outside its contract: a rubric evaluator that
  returns anything but `ok`, `fail` or `unchecked` now reads `unchecked` (as edition rules already did), and a time bound
  that claims Bitcoin quality without a network and height no longer meets a deadline. Neither is reachable with the
  checks the reference CLI ships; found by the new property tests. No byte, identifier, exit code or `--json` member name
  changes.
- An `observed` statement's disclosures are now shown. `licence`, `replication`, `availability`, `sampling`,
  `shelf_life_days`, `pre_registration` and the other single-party fields an `observed` signs were never displayed: `show`
  of a blob with only observations read `licence: unknown` and `replication: undeclared`. Such a blob now shows the value
  its counted observations agree on, `contested` (each value with its signer) when they differ, undeclared when none
  sets it, and `unknown` with the reason when the reader's observation selection is unmet. One helper serves both this
  display and the input summary of a derived result, so the two cannot disagree; a blob that also has a counted `authored`
  statement is unchanged. Read-side only: no signed byte, exit code, command, flag or `--json` member name changes, and a
  disclosure still never moves a grade or an exit.
- A statement covered by its signer's `anchors` line now shows its time bound. `show`, `verify` and `explain` of a statement
  id of any kind except `anchors` (an edition, an authored line, an observation, …) carry a `time` member, the bound the
  reader already derives for it, in the shape an authored artifact's claim shows it: `quality` (`local` or `bitcoin`), the
  covering `anchor` and its `time_state`; a statement no counting anchor covers shows `quality: none`. Before, only the
  `anchors` line itself and a blob's claims showed a time, so a covered `edition` read as if nothing bounded it. `--json`
  gains that one member on statement views; an `anchors` line keeps its own `time` evidence member, resource views
  (an edition's approvals list) are unchanged, and no signed byte, exit code, command or flag changes: the bound is a
  disclosure and `verify` exits as it did.
- A verified time bound now shows where it sits on the chain. Beside `quality: bitcoin` and `time_state: verified`, the bound
  (on a statement, on an artifact's claim, and on an `anchors` line's own evidence) carries `network`, `block_height`,
  `block_hash`, `header_time_miner_reported` (display only, never an ordering key), `confirmations`, `chain_validation` and,
  on a view that is no longer fresh, `as_of`: the record the bitcoin-time design note (section 9) lists. Before, a reader saw
  `verified` with no height. Shown only for `verified` and `verified-historical`; no other state, exit code or signed byte
  changes.

- Output and help wording from the first end-to-end run, text only (no exit code, flag, `--json` member or signed byte
  changes): a clean `pull`, `hub check` or `push` now prints `objects: none refused, labelled or undecided` instead of
  `objects: (none)` beside `admitted: 1` (the list carries refused, labelled and undecided rows only; the JSON `objects: []`
  is unchanged); the `publish`, `identity new` and `identity grant` help say a dry run's id is the id the real run signs
  only with the same `--ts` and while the signer's log has not moved (the id commits to `prev` and `seq`); and
  `push --store` still exits 2 with the same problem type but its `next` names the reason (push runs from inside a git
  checkout of the hub; a store kept elsewhere is pulled into one first). GETTING-STARTED section 4 now says a script
  reads exit 3 as "could not check", the expected answer for an output nobody re-derived, and that it moves to 0 when an
  independent key re-derives it.

### Tests

- Pins the statement view's time bound (an uncovered statement shows `none`, a covered one `local` with its anchor and
  `time_state`, an `edition` statement and an anchors line included) and that covering a statement changes no exit and no
  other member of `show`, `verify` or `explain`.
- Pins the bytes of a typed-controller genesis (the `rc/2` line and id a bare key signs for `{identity, key}` controllers,
  next to the key-only `rc/1` pin) and adds a positive signed vector per algorithm: an `rc/2` genesis naming the identity
  as its controller, whose id is usable as a resource id. The existing vectors are byte-identical.
- Pins the bytes of a bare key's marker-only approval of an edition of that genesis (`rc/2`, marker `{}`, no actor, written
  through `MarkerOnlyDraft`), and adds per algorithm to the signed vectors that approval, the identity's approval of the
  same edition body under a grant for the resource, and the grant. A consumer test shows both approvals name one edition
  id. The existing vectors are byte-identical.
- Property cases P-01, P-02, P-03 and P-12 are covered over the exchange view and the gates (a seeded task-world
  generator; duplicate and re-encoded delivery, every delivery order, outsider statements, withheld statements); P-08's
  time-context half and P-09 over the exchange's delegated checks are checked. Conformance properties 10/12.
- P-09 is covered: a per-check substitution sweep over the gates' delegated checks. At pull, hub check, push and the
  pre-pin check, the rule dialect, content reader and step budget behind `intended_for`, the series segment re-check
  behind `series.refuse_premature_freeze`, the completeness evaluator behind `selection.refuse_incomplete` and the
  time verifier behind contested authorship are each given missing, unsupported, failing or lying evidence; none is
  shown as passing (`unchecked`, could not check, or refused), with a control row for each. The same for push's
  withheld-bytes and anchor-required preconditions, hub check's content and actor evidence, and the shipped
  `pull --dry-run` and `publish --intended-for`. Conformance properties 11/12 (P-08's execution-context half remains).

### Changed

- The advice to list a second controller subject on a resource now says what it buys. A resource controlled by one
  identity alone does not survive a compromise of its root: the root's revocation voids every edition approved only as
  that identity, and recovery is a successor resource. An independent second subject under `any_one` recovers the
  resource after the root is revoked (and could capture it alone); under `k_of_n` 2 no single stolen subject can, at
  the price of freezing on any one loss. A second subject on the same seed is not independent. Fixed-root identity
  note §8 (and §1), the claims-model note §4.1 pointer, and COMMONS-TEMPLATE R13 and its Collections line.
- Help text layout: `commons help`, `help <command>`, `help exits` and `help outputs` print a dedicated page instead of
  the generic key/value listing: the commands grouped by purpose, a short usage line (`commons publish [options]`) for a
  command with many options, options in aligned columns with their value placeholders (`--key <file>`), the options of
  `publish`, `run` and the identity commands under group headings, descriptions split into paragraphs at sentence ends,
  an `Examples` section on `init`, `key new`, `publish`, `show`, `verify`, `explain`, `pull` and `push`, and everything
  wrapped to `$COLUMNS` (80 when unset, between 60 and 120). An unknown option now names its command in the `next`
  hint (`run commons help publish to list its options`) and an unknown command suggests the nearest one. `--json`
  help output is byte-identical; no byte, identifier or exit-code change.
- Wording: the `contract_profile` text of a provisional contract now says what is true ("provisional: read under this
  profile, not task-contract-v1") instead of "the contract grammar is pending", `show` and `publish task` render it through
  one helper, and a stale "nothing is frozen" comment on the `rc/2` reader is corrected. New documented limit L-21
  (narrowed by the typed-genesis entry under Added). No byte, identifier, exit code or `--json` member name changes.
- Documentation: the README, security policy, contributing guide and design-note status lines now describe the release
  candidate (frozen format, install from PyPI or a release archive and how to verify it, a "Testing the release candidate"
  section) instead of the alpha; `--json` stability wording and limits L-08 and L-12 say what holds at 1.0. No byte,
  identifier or behaviour change.
- `docs/COMMONS-TEMPLATE.md` is rewritten for 1.0: a project's `COMMONS.md` now records each dataset's statement kind,
  observation class, referent, capture evidence, finality, provenance, replication, sampling, shelf life, licence,
  availability, growth and size, and who signs (a key or an identity and grant); the review rubric checks those against
  the claims model, with a table mapping the alpha template's fields. Docs only.
- Documentation: installing from source is `go install ./cmd/commons` from a clone (no branch switch, since `next` is the
  default branch); `go build` stays as the in-place alternative. No byte, identifier or behaviour change.
- Documentation: KNOWN-LIMITS L-21 is narrowed to what it is since #257: only a collection created key-controlled
  (genesis `rc/1`) cannot be moved to identity control. An identity-controlled collection's editions may name identity
  controllers (a collaborator's identity, or a successor identity after a root compromise), as `publish --help`,
  `docs/COLLABORATING.md` and the identity note §8 now say (#258). No byte, identifier or behaviour change.
- Documentation: the fixed-root identity note's device paragraph records a YubiKey 5 test (#250): on firmware 5.4.3 the
  OpenPGP applet, not PIV, signs both algorithms by hand through the external-signing package, with the custody caveats
  (blind signing; no backup under `fixed-root-v1`). KNOWN-LIMITS L-07 mentions it and stays open. No byte, identifier or
  behaviour change.
- Documentation: the README's "Hubs" section says how to find hubs: the GitHub topic `research-commons-hub`, which the hub
  template asks each hub to set. Being listed is not an endorsement. No byte, identifier or behaviour change.

## [1.0.0-rc.1] - 2026-11-17

**The first release candidate of 1.0: the format is frozen.** The wire majors `rc/1` and `rc/2` (the fixed-root identity
profile), key files (`rc-key/0`) and external-signing packages (`rc-signing-package/1`) are frozen, after an independent
freeze read of `rc/2` and its interchange files (#233) whose findings are all folded here: a future algorithm's lines and
keys read `unsupported` instead of malformed, an unreadable actor never falls back to the key, sets are pinned sorted,
and the signing package's summary carries no prose, so a package prepared by one 1.x release reads under every other.
`1.0.0` follows from a candidate that goes through a quiet window with no finding that would change these bytes; such a
finding means a new candidate (`docs/RELEASING.md`). Still provisional: `--json` output (L-12) and execution policy
files (`rc-exec-policy/0`, L-09). The writer's majors are unchanged since alpha.5.

### Changed

- **The external-signing package is `rc-signing-package/1`, frozen; the key file `rc-key/0` is frozen as is.** A
  package's `summary` is now tokens and values copied from its envelope only (`action` is `inception`, `grant`, `cut` or
  `act`, beside the identity, root or delegate, permissions, grant, `last_good`, reason, kind and amends); the words a
  human reads (the custody warning, "a cut cannot be undone") are printed as `review` by `--prepare`, `package show` and
  `key sign`, never stored, so a package reads the same under every release that reads its format. The identity note §8
  gives every member's type and encoding. A `rc-signing-package/0` package is refused (`retired-package-format`, exit 2):
  prepare it again. The package check (`--complete`, `package show`, `key sign`) also refuses an envelope carrying a
  member `--prepare` never writes, so `key sign` signs only an envelope the tool would prepare. `docs/KEY-FILES.md` now
  states that the secp256k1 scalar is big-endian and that the reader accepts any strict JSON. The execution-policy file
  (`rc-exec-policy/0`) stays provisional (L-09).

- **`rc/2` forward room, from the freeze review (#233).** A line under an `alg` the reader does not implement, signed by
  that algorithm's own key form (`ml-dsa-65:<hex>`), reads `unsupported` and is retained and placed in both majors,
  instead of being refused as malformed, so adding an algorithm stays a minor change; a known `alg` with a signer
  outside its form is still malformed. An identity grant or typed subject naming such a key reads `unsupported`, not
  invalid. An `rc/2` actor this reader cannot read (any `x_actor_*` member but `x_actor_v1`, or one inside the body)
  reads `unsupported`, never a bare-key claim. The schema states that every set is sorted by canonical encoding and
  that `crit` may carry an extra token a reader reads as unsupported. The identity note adds that administrative bodies
  stay open with restrictions behind `crit`, why an unreadable cut makes an identity's acts unknown, that the classical
  root's way out is a new inception profile, and that a statement can carry two valid signatures. New signed vectors
  pin each case, a tampered actor `identity` and an `rc/2` edition id; new unsigned reject vectors pin set order.

### Known issues (open at this tag)
- Every gap in `docs/KNOWN-LIMITS.md` (L-01…L-17, L-20). The ones a first user meets:
  - Block headers come only from a file the operator obtains (`anchor headers sync --from`, L-02); with no header
    database every rival construction is `contested` and a task contract with a `deadline` never reaches `ready`. (#59)
  - `publish` does not stamp (L-16): run `anchor stamp` after `publish` and before `push`, and `anchor upgrade` once
    the calendar has committed to a block (typically hours).
  - `push` sends only from a git checkout of the hub (L-17).
  - A response layout reads JSON only, through one pointer to the record array and one to the state (L-14).
  - The only hardware connector is a Ledger device running the Ethereum app (L-07), over USB on Linux only (L-20).
    The execution-policy file format is still version 0 (L-09).
  - There is no Windows build, and none is planned for 1.0 (L-11); `--json` output may change before it carries a
    `schema` member (L-12).
- The `next-format` issues are requirements for later stages, not defects in this release.

## [0.5.0-alpha.8] - 2026-11-16

**A Ledger device can sign an identity, and the 1.0 criteria are in place.** `key sign --ledger` signs an
external-signing package with a Ledger device running the Ethereum app (drilled on a physical Nano X), and an
interrupted device review is reported. The two-hub drill is scripted and runs in CI; every design note's open questions
are closed or deferred past 1.0; Windows is unsupported for 1.0; and a compromised operational host is drilled through
the commands. The writer's majors are unchanged since alpha.5 (`rc/1`, and `rc/2` from the identity commands and
`publish --as`). The Python wheels are published to PyPI from CI from this release on (`pip install research-commons`).
All 190 core conformance cases are covered.

### Added

- **A compromised operational host is drilled (identity note §8, C-id-40 covered).** With the root key kept off the
  host and every root act signed through the package, a test plays an attacker holding a full copy of the host (store
  and worker key): its forked acts under the grant are cut at the last act the holder can attest, its grant package to
  its own key presented as a routine one is refused by `key sign --expect-pae-sha256` with the digest the holder
  computed on a clean store, and it cannot sign as the root. The holder recovers on a clean machine from a fresh store
  pulled from the hub, grants a new worker key and acts under it; a reader holding everything, the attacker's store
  included, counts the legitimate acts and the new one and counts the attacker's acts toward nothing.
- **The two-hub drill is scripted (`scripts/two-hub-drill.sh`).** Two bare git repos as hubs and two stores with distinct
  keys: A publishes a construction, an observation and a resource edition and pushes; B pulls, publishes a corroborating
  observation and pushes; A pulls from B; both answer `show`, `explain` and `verify` for the same ids and the script
  compares the `--json` answers byte for byte; a tampered blob in one hub is refused on pull. Exit 0 only if every
  comparison agrees (`TWOHUB_MUTATE=1` alters one state in B and must exit non-zero). A Go test behind the `twohub` build
  tag runs it, in a non-required CI job `two-hub drill`. The anchor stamp is optional (`TWOHUB_CALENDAR`).

- **A Ledger device can sign an external-signing package (`key sign --ledger`).** `key sign --package <file> --ledger
  --ledger-path m/44'/60'/<account>'/0/<index>` asks a Ledger device running the official Ethereum app to sign the
  package's recomputed PAE bytes with EIP-191 `personal_sign` (`eip191-secp256k1`: no new algorithm or preimage). The tool
  first checks the package, that the open app is the Ethereum app, that the device's address at the path is the package's
  signer and that the PAE fits; it prints what the device will show (the PAE's length, its text start and the EIP-191
  message hash); you approve on the device; the signature is normalised (low `s`, `v` 27/28), verified as every reader
  verifies it, and written exactly as a key-file signature. A refusal on the device is exit 1; locked, closed or other app,
  too long for the device, disconnect or timeout is exit 3; each writes nothing. `key show --ledger --ledger-path <path>`
  prints the device's address (`--ledger-confirm` shows it on the device too). There is no default path: use an account
  that never holds funds. USB works on Linux (hidraw, no cgo); `--ledger-device tcp:<host>:<port>` reaches a Speculos
  emulator (labelled as such). `--complete`, `identity` and `publish` never open a device. Tested through the commands
  against an in-process fake of the app, and (opt-in, `-tags ledger_speculos`, not in CI) against the Speculos emulator for
  the Nano S Plus and Nano X, and drilled by hand on a physical Nano X (Ethereum app 1.19.3: an inception approved on the
  device completes and verifies, one rejected writes nothing; identity note §8). A review left pending by an interrupted
  `key sign` can leave a physical device unresponsive until it is restarted: check its screen before the next command
  (KNOWN-LIMITS L-07, L-20).
- **An interrupted device review is reported, not left silent.** Ctrl-C (SIGINT) or SIGTERM while a Ledger device waits for
  you (`key sign --ledger`, `key show --ledger --ledger-confirm`) prints "a review may still be open on the device: reject it
  there before signing again", closes the device and exits 3 (`ledger-interrupted`), writing nothing. `key sign --ledger`
  prints, as its last line before asking the device, that the review is now on it. An earlier review's answer reaching the
  command connected when an orphaned review is decided (a refusal or a signature) is named as such (exit 3),
  not read as a refusal of that command. No read-only request to the Ethereum app reveals a pending review (identity note §8).

### Changed

- **Design notes: open questions swept for 1.0.** Every design note's open-questions section now has a "Status for
  1.0" line: each question is closed (with the code or conformance case that shows it) or deferred past 1.0 with why
  it cannot change the bytes of an existing `rc/1` object. The quantum horizon (wire-format note) stays open for
  discussion and deferred; the 0.4-alpha notes are marked superseded by the next format. The bitcoin-time note no
  longer says the `push` anchor gate is unbuilt, and the claims-model note's header no longer says nothing in it is
  decided. RELEASING criterion 1 names the status lines.
- **Windows is unsupported for 1.0.** RELEASING criterion 4 records the decision, and the README's platform line
  cites KNOWN-LIMITS L-11.
- **The `sandbox_oci` tests run in parallel, and the gate reports are swept for prose outcomes.** Each OCI test starts
  its containers with a label of its own and checks for leftovers by that label only, so the two tagged packages no
  longer need `-p 1` (CI and the README drop it). A new OCI test shows a sandboxed comparison cannot connect to a
  listener it could reach with a network grant. The "no outcome as prose" sweep now also reads every row of the
  `pull` and `hub check` reports (intended_for, completeness, series boundary, trust floor, actor), and the two
  conformance partials that remained for execution (C-exec-14) and exchange (C-exch-10) each name the one thing left.

- **Python wheels publish to PyPI from CI.** A `publish-python` workflow runs when a release is published (or by
  hand for any existing tag): it builds the four platform wheels from that release's checksum-verified archives,
  smoke-tests one wheel in a clean virtualenv, and uploads them by OIDC trusted publishing (environment `pypi`;
  no API token exists anywhere; published wheels carry PEP 740 attestations by default). The build verifies
  every archive against the release workflow's build attestations before opening it, and a manual dispatch
  checks out and builds the tag's own commit, so an existing release can be (re)published exactly as it was
  cut. The maintainer actions are the one-time PyPI trusted-publisher entry and, before the first run, a
  protected `pypi` environment (deployment refs `next` and `v*`, a required reviewer); `docs/RELEASING.md`
  step 8 describes the new path.

### Known issues (open at this tag)
- Every gap in `docs/KNOWN-LIMITS.md` (L-01…L-17, L-20). The ones a first user meets:
  - Block headers come only from a file the operator obtains (`anchor headers sync --from`, L-02); with no header
    database every rival construction is `contested` and a task contract with a `deadline` never reaches `ready`. (#59)
  - `publish` does not stamp (L-16): run `anchor stamp` after `publish` and before `push`, and `anchor upgrade` once
    the calendar has committed to a block (typically hours).
  - `push` sends only from a git checkout of the hub (L-17).
  - A response layout reads JSON only, through one pointer to the record array and one to the state (L-14).
  - The only hardware connector is a Ledger device running the Ethereum app (L-07), over USB on Linux only (L-20).
    Key, execution-policy and signing-package file formats are still version 0 (L-09).
  - There is no Windows build, and none is planned for 1.0 (L-11); `--json` output may change between alphas (L-12).
- `rc/2` and its interchange files are frozen at 1.0 only after the review requested in #233.
- The `next-format` issues are requirements for later stages, not defects in this release.

## [0.5.0-alpha.7] - 2026-11-16

**`push` sends, and the store finishes what it starts.** `push` now transports the judged commit with `git push`
(never forced) once the hub's verdicts and the anchor and withheld-bytes checks are clean. The store re-hashes a held
blob before reusing it, keeps opening when a journal replay fails, and gains `commons repair` and a local operation
history (`commons history`) that nothing decides from. Every publish, pull and `gc` commit point is tested with a real
process crash. The writer's majors are unchanged since alpha.5 (`rc/1`, and `rc/2` from the identity commands and
`publish --as`). All 190 core conformance cases are covered.

### Added

- **An operation history, and `commons history`.** A store now appends one line to `journal/history.jsonl` when an
  operation finishes (its statements installed): the operation id, kind, statement ids, blob digests, this machine's
  time, and whether a later open or `repair` finished it; and one line when an open moves a journal record to
  `quarantine/`. It is on by default, best-effort (appended without a sync; a write error never fails the operation;
  a crash right after an operation may lose its line), bounded (8 MiB, then rotated to one `history.1.jsonl`) and
  never transported: `pull` of a store directory or archive skips it and says so under `skipped`. `commons history
  [--limit N] [--op <id>]` lists it newest first under the header "local, not authoritative; times are this
  machine's clock", skips and counts malformed lines, and exits 0 always (`history off`, no file yet, nothing
  matching). Nothing else reads the file (a test guards it): `status`, `explain`, `fsck`, `repair` and every answer
  are byte-identical with the file deleted or edited. `status` declares `history: on (8 MiB × 2, rotate)` instead
  of `off`. Closes KNOWN-LIMITS L-19.

- **CI runs the OCI sandbox tests, and the conformance scan counts them.** A new `test-sandbox-oci` job runs
  `go test -tags sandbox_oci` on `internal/run` and `internal/clirun` against the runner's docker with an image pinned by
  digest (a skipped OCI test fails the job); it is not a required check. `internal/conformance/ci-tags.txt` lists the
  build tags CI runs, the scan treats a test file whose build expression those tags satisfy as run, and a test keeps the
  list and `go.yml` in agreement in both directions. C-exec-10, C-exec-11 and C-exec-12 read covered instead of
  partial.
- **A series boundary comparison is a typed state of its own.** `show` and `explain` of a series print a
  `series_boundary` member: `state` (`agrees`, `flagged`, `not comparable` or `unchecked`, a closed set of its own:
  the comparison of a declared `frozen_before` with the boundary the members' finality rules compute, which is not a
  rule evaluation) beside a `why`, the declared and computed boundaries, and `basis` where the computed boundary rests
  on states the members asserted at capture. A `pull` or `hub check` row for a series edition carries the same member
  beside its labels. `agrees` and `flagged` join the table of state tokens; `flagged` changes no authorization (a
  freeze policy of the reader's decides what it costs). The read commands now judge a series' segments under the
  source profiles the store-root policy pins, as `pull` does, so a series boundary no longer reads `unchecked` there
  when a pinned profile can place its segments. `--json` shape change, within the alpha's stated stability.
- **A departure check is a typed state, and every rule evaluation prints as one.** `explain` of a task prints a
  submission's `departure_check` as an object, `state` (`conforms`, `departed`, `unchecked` or `not comparable`, the
  closed set of the departure check, which is a comparison of a disclosure with a declaration and not a rule) beside
  `why` and a note that the grade is unchanged; `conforms` and `departed` join the table of state tokens. The
  `evaluations` of the pre-pin check (`publish --intended-for`) and of a `pull` or `hub check` row's `intended_for` are
  rows with the rule, dialect, expression, member, `state` (`ok`, `fail` or `unchecked`) and `why`, no longer one
  sentence each. The human output says the same things.
- **One verification per stored line per command.** Reading the same statement through the store, the log view and
  the identity evaluator checked its signature three times; a line is now verified once per process and the answer
  reused. The memo lives in memory only, is keyed on the SHA-256 of the line's bytes (never on a name, size or
  modification time, so a same-name rewrite with the same size and mtime is read afresh), is bounded, and changes
  no output. `status` now declares the caches the tool keeps: no persistent cache, and this one in-process memo.
- **`pull` and `hub check` report a rule evaluation as a typed state, not only prose.** A report row for a statement
  that records `intended_for` now carries `intended_for` (JSON) with the receiver's own `named` and `current`
  outcomes, each `ok`, `fail` or `unchecked` (`unchecked` when the resource or the content could not be read, never
  `ok`), and the publisher's recorded outcome apart as `publisher_said`; a row for an edition judged under
  `selection.refuse_incomplete` carries the check as `completeness` with the same `state` `show` prints on the
  resource view. The one-line human row prints the same words (`intended for named`, `intended for current`,
  `completeness state`). The label detail keeps its prose.
- **`push --dry-run`: what a push would carry, judged as the hub's CI would.** Run in a git checkout of the hub
  (the store is the checkout): the change is `merge-base(<base>, HEAD)..HEAD`, with `--base` defaulting to
  `refs/remotes/<remote>/HEAD` (`--remote`, default `origin`; exit 2 when it is not set). Every object gets the
  verdict `hub check` would give, through the same gate, against the hub's history and `hub-policy.json` at the base.
  Beside the verdicts, two writer preconditions that are not admission verdicts (no other gate applies them): the
  anchor before transport (C-btc-03c: a statement whose standing requires an anchor is refused, reader policy
  `anchor required`, until an `anchors` line by its signer, carried or held by the hub, covers it; a pending proof
  covers; coverage is per statement; a statement with standing `anchor: none` and no anchor is carried with a warning
  naming the rule; `--anchor-policy required|none` replaces the standing for every statement), and withheld bytes (a
  blob whose availability a statement declares withheld, with no serving `holds`, is refused: carrying it would
  release it). An `anchors` line whose proof blob neither travels nor is held is a warning (`missing-proof` until it
  is). Data files the working tree has and HEAD does not are listed as uncommitted. Exit 0/1/3 as `hub check`, 1 also
  on a precondition refusal. Writes nothing (`no registry change; no fetch; no cache; no transport`). `publish` still
  does not stamp (KNOWN-LIMITS L-16): run `anchor stamp`, commit, then `push`.
- **`push` sends.** Without `--dry-run`, and only when the judgement is clean (every object admitted, no precondition
  refused), `push` runs `git push <remote> <judged commit>:refs/heads/<branch>` in your own git environment (your
  credentials, configuration and hooks): never forced, no tags, and the commit sent is the one judged, not whatever
  `HEAD` is by then. A judgement that exits 1 or 3 sends nothing. The branch is `--branch <name>`, else the base's
  branch on the remote (`origin/HEAD` → `main`); a base that is not a branch of the remote is exit 2 asking for
  `--branch`. To contribute through a pull request, push to a branch of your own (`--branch <name>`, or `--remote
  <your fork> --base origin/main --branch <name>`) and open the pull request. A refusal by git (the branch moved on,
  authentication, a hook, a protected branch) is exit 3 with `transported: false`, git's message with any URL
  credentials removed, and the next step (for a moved branch: fetch, rebase your data commits onto the hub, push
  again). Output gains `transported`, `branch`, `pushed`, `update` and, on a refusal, `git` and `next`. The git reader
  `hub check` and `push` share now ignores replacement refs (`git replace`), so the bytes judged are the bytes `git
  push` sends. Conformance cases C-core-108, C-core-135, C-core-148 and C-btc-03c are covered. `push` still needs the
  store to be a git checkout of the hub (KNOWN-LIMITS L-17).
- **`commons repair [<operation>|--all] [--blob <file>]`.** Finishes committed operations the store could not finish on
  its own (storage note §3.5): a blob a committed operation names is missing, a projection failed, or a replay
  failed on open (a permission, a full disk). It runs the journal's install steps again for the named operation (all
  of them with `--all` or no argument), continuing past one that fails, then rebuilds the registered projections and
  compares each with a cold build. `--blob <file>` installs exact bytes first: they are hashed before the store is
  opened, must be a blob an unfinished operation names, and are hashed again on install, so a missing blob is
  repaired without a hold serving it. Exit 0 finished (an operation id no record has prints `nothing to repair`,
  also 0), 1 drift after the rebuild, 2 malformed id or bytes no operation names (nothing done), 3 an operation could
  not be finished (the output names the missing blob and the next step). It never signs, rewrites or deletes a
  statement or blob, never rolls back, and never touches `quarantine/` (it prints the count). The messages of
  `status`, `fsck`, `publish` and the store that named "the next open" as the only way to finish an operation now
  name `commons repair <operation>`; `nothing to repair` joins the table of state tokens. KNOWN-LIMITS L-18 is
  closed. Conformance case C-core-126 is covered.

### Fixed
- **`status` after a `gc` that stopped mid-deletion.** A `gc --apply` killed after moving a blob aside and before
  deciding left the file for the next open to put back, and that open reported it as `restored blob`, a word missing
  from the closed vocabulary: `status` (and every command printing the recovery events) then failed with an internal
  error. `restored blob` is now a recovery token. Publish, pull, `gc --release` and `gc --apply` are tested with a
  real process crash at every point of their commit (the store is opened with a fault hook only tests can set).
- **Reusing a held blob re-hashes it and restarts its grace window.** `publish` (and `run`, `anchor stamp`,
  `anchor upgrade`) naming bytes this store already holds, and `pull` of a blob already held, used the held copy
  as it was: a copy damaged on disk was reused, and an old unreferenced blob kept its old window, so `gc` could
  remove it between the reuse and the operation's journal record. Now the held copy is re-hashed first (a copy
  that no longer matches its name is refused, naming both hashes, unless the operation brings the bytes, which
  then replace it) and its window restarts at the reuse, as the storage note says.
- **A journal replay that fails no longer makes the store unopenable.** When the open of a store could not finish
  a committed operation (an unwritable `statements/`, a full disk), every command failed, including `status` and
  `fsck`, which the error told you to run. Now the open continues: `status` lists the operation with
  `what: replay failed`, the error and the next step; `fsck` names it; reads work and show none of that
  operation's statements until it is finished; a write by one of its keys is refused naming the operation. Every
  later open replays it again. Also: a finished-but-not-cleaned-up journal record now reinstalls a statement file
  removed since (as `fsck` already promised), and a reader running alongside a writer no longer sees part of an
  operation that is still being installed.
- **`publish` failure advice.** A failure after the statements were installed is no longer reported as
  `committed, pending install` (new problem type `committed-finish-failed`); the advice says publishing again is
  safe (idempotent) instead of "do not publish again", and names `commons repair <operation>` (see Added).

### Known issues (open at this tag)
- Every gap in `docs/KNOWN-LIMITS.md` (L-01…L-17). The ones a first user meets:
  - Block headers come only from a file the operator obtains (`anchor headers sync --from`, L-02); with no header
    database every rival construction is `contested` and a task contract with a `deadline` never reaches `ready`. (#59)
  - `publish` does not stamp (L-16): run `anchor stamp` after `publish` and before `push`, and `anchor upgrade` once
    the calendar has committed to a block (typically hours).
  - `push` sends only from a git checkout of the hub (L-17).
  - A response layout reads JSON only, through one pointer to the record array and one to the state (L-14).
  - No hardware or wallet connector is built (L-07): an identity root on a device signs through the external-signing
    package, whose format `rc-signing-package/0` is provisional (L-09).
  - There is no Windows build (L-11), and `--json` output may change between alphas (L-12).
- The `next-format` issues are requirements for later stages, not defects in this release.

## [0.5.0-alpha.6] - 2026-11-15

### Added
- **Identity answers state their freshness, and a delegate key shows both of its axes.** Every identity actor block
  (`show`, `explain`, `--json`) prints `freshness: not_established` ("relative to held evidence; no claim that no cut
  exists"): no input the tool reads can establish that a root has not cut a grant elsewhere. `show <key>` and
  `explain <key>` print the key's own revoke/rotate status beside every grant naming it, each with its grant-level
  state (open, cut at its last good line, cut null, unknown, denied). `revoke` (including `--dry-run`) and `rotate`
  by a delegate key list, by id, every grant they do not close. Conformance cases C-id-09, C-id-10 and C-id-23 are covered.
- **The gate labels a contested authorship.** An admitted `authored` whose blob has several claimants and no default
  over the evaluated set (what the receiver holds plus the package's admitted statements) now carries the label
  `contested`, the word `list`, `show` and `verify` print for that blob. It appears on `pull` and `hub check` alike
  (the hub-check contract already listed it), and will on `push`. A label only: the line is still admitted and the
  exit is still 0, and a package with no `authored` builds no resolver.
- **`package show` and `key sign` warn about a future `ts`.** When an external-signing package's envelope `ts` is
  more than 300 s ahead of the local clock, both print an advisory (and `--json` carries `advisories`) that the
  store refuses it at `--complete` and the package should be prepared again with a current `--ts`. Exit codes
  are unchanged and `key sign` still signs.
- **`package show` and `key sign` take `--expect-pae-sha256 <hex>`**, the `pae_sha256` that `--prepare` printed, carried by
  a separate channel. A match prints `pae sha256: matches expected`; a different digest is exit 1 naming both digests,
  and `--pae-out` writes nothing and `key sign` signs nothing; anything but 64 lowercase hex is exit 2.
- **`package show --pae-out <file>`** writes the exact PAE bytes a signature covers (no newline) to a new file,
  for a signer that is not this tool. An existing file is never overwritten, and nothing is written unless every
  package check passes.
- **`anchor stamp` writes anchors.** `commons anchor stamp [<statement-id>]` timestamps a line of your own log (by
  default your log's tip): it submits the raw 32 bytes of the line's id to the OpenTimestamps calendars you name
  (`--calendar <https url>`, repeatable, or `COMMONS_CALENDARS`; there is no default list), merges the pending proofs
  of every calendar that answered into one proof (as the reference OpenTimestamps client does), and commits the
  proof blob and an `anchors` statement (`covered`, `proof`, `proof_format:
  ots-detached-v1`, `services`: the calendars that answered) as one journal record. A calendar's answer is checked
  before it is kept (it must parse, root at the digest submitted and carry a pending attestation; at most 10000
  bytes). Calendars are dialled over https only, with no proxy, never on a loopback, private or other non-global
  address unless `--allow-private`, and may redirect only to https on their own host. Every calendar failing
  appends nothing (exit 3) and prints the line's standing: `anchor required` (an `authored` without provenance, a
  `fulfills`, a withheld availability, an anchored-at-capture observation) or `anchor: none`, with the rule that
  decided. `--dry-run` contacts nothing. Readers show the anchor `pending`, quality `local`, until it is upgraded.
- **`anchor upgrade` completes pending anchors.** `commons anchor upgrade [<anchors-statement>]` asks the calendars
  of your policy (the same `--calendar` / `COMMONS_CALENDARS`) for each pending attestation of an anchors line of your
  own log (by default every one that is the newest for its head and has no Bitcoin attestation yet):
  `GET <calendar>/timestamp/<hex commitment>`, where 404 means still pending. Each answer (at most 10000 bytes) is
  parsed strictly and merged into the proof, keeping the pending attestations, byte for byte as the reference client
  writes it. An answer that does not root at the pending node is refused for that calendar only. A pending
  attestation naming a calendar outside your policy is reported and not contacted. Only when the merged proof gains a
  Bitcoin attestation does it commit the new proof blob and a new anchors statement (the same `covered`, `services`:
  the calendars that answered) after the old one, signed by the same key, as one journal record. After
  `anchor headers sync`, readers show the head's bound `verified` at that block. Still pending: exit 0, nothing
  appended. Every calendar failing: exit 3. `--dry-run` contacts nothing. `publish` still does not stamp and no `push`
  gate is built (KNOWN-LIMITS L-16).
### Changed
- **Design notes: the anchor before transport, per statement.** The storage note now says `push` refuses a statement whose
  standing requires an anchor while no installed `anchors` line by its signer covers it, and that a pending proof counts
  (the bitcoin-time and claims-model notes agree); new conformance case C-btc-03c. `push` itself is not built yet.
- **`provenance_partial` is stricter (pre-1.0 tightening).** `unpinned` must name at least one input and name each
  once, and every key of `supplied` must be one of the `unpinned` names (order is not constrained). A line that
  breaks either rule is refused at every gate, as intrinsic `malformed statement` naming the member; before, an
  empty `unpinned` and a `supplied` key for an unlisted input were accepted. `run --publish` now records the
  unpinned input's **name** in `unpinned` (it wrote `name ("reference")`), which is what the wire format says and
  what the new `supplied` check compares against; the reference stays in the workflow spec the line names. Lines
  already written with the old form fail the `supplied` check only if they carry `supplied`.
- **Identity profile note and coverage file state the writer.** They no longer say no command signs `rc/2`:
  the writer is `identity new|grant|cut` and `publish --as --grant`; hardware and connector signing is not built.
  Ten identity conformance cases (03, 05, 06, 11, 12, 13, 14, 16, 18, 33) now pass through the commands, and the
  coverage file states what the remaining ones still lack.
- **The production identity reader reads `x_identity_v1` through the critical-extension registry.** The `rc/2` marker
  and actor-pairing rules moved out of the reader's body code into the one validator the reader registers, so an
  unregistered critical token is now refused by the registry's preflight and a marker that breaks its shape by
  its validator, on the same path `wire.Read` offers any extension. No line reads differently: the same statuses,
  reasons, ids and actors on every `rc/1` and `rc/2` line tried (24 kinds, 9 markers, 5 `crit` lists, 4 actor shapes
  against the previous reader). Conformance cases C-id-36 and C-id-37 are covered; known limit L-08 now says that
  `x_identity_v1` is the one registered extension (`rc/2` only).
- **A later anchors line for the same head supersedes the earlier one for display.** When a key holds several
  `anchors` lines for one covered head (the head stamped twice, or a pending stamp beside its upgrade), the time
  shown is the earliest verified bound if any line yields one, otherwise the line latest in the signer's log order
  (on forked branches, where neither descends from the other, the lower id). A refused line never displaces a
  usable one. Before, the line with the lower id was shown. `explain` now lists every anchors line of such a head
  with its quality, state, whether it is displayed and why (`superseded by <id>`, `verified preferred`, ...); with
  one line per head its output is unchanged. Priority and every other answer read verified bounds only and are
  unchanged.

### Fixed
- **An unmet reader-policy selection is an answer, not an internal error.** With `--policy` holding an
  `authorship-declaration` selection that is not met (a pinned statement not held or ineligible, or a followed key
  or identity with no eligible claim), `verify` and `explain` ended in `internal error`. They now answer: `verify`
  exits 3 naming the selection's state, and the field reads `no default (reader's selection not met)`. The
  selection states are now in the closed vocabulary (`docs/CLI-OUTPUTS.md`).

### Known issues (open at this tag)
- Every gap in `docs/KNOWN-LIMITS.md` (L-01…L-16). The ones a first user meets:
  - Block headers come only from a file the operator obtains (`anchor headers sync --from`, L-02); with no header
    database every rival construction is `contested` and a task contract with a `deadline` never reaches `ready`. (#59)
  - `publish` does not stamp and there is no `push` yet (L-16): run `anchor stamp` after `publish`, and
    `anchor upgrade` once the calendar has committed to a block (typically hours).
  - A response layout reads JSON only, through one pointer to the record array and one to the state (L-14).
  - No hardware or wallet connector is built (L-07): an identity root on a device signs through the external-signing
    package, whose format `rc-signing-package/0` is provisional (L-09).
  - There is no Windows build (L-11), and `--json` output may change between alphas (L-12).
- The `next-format` issues are requirements for later stages, not defects in this release.

## [0.5.0-alpha.5] - 2026-11-14

**This release writes `rc/2`.** `identity new`, `identity grant`, `identity cut` and `publish --as` (directly or
through an external-signing package) write their statements in wire major `rc/2`; a reader from a release before
0.5.0-alpha.4 cannot read them (it keeps them as unverified lines of another major). 0.5.0-alpha.4, tagged and
published 2026-11-13, is the earliest reader of `rc/2`. Every other statement is written `rc/1`, unchanged.

### Added
- **Response layouts read batch captures.** When a batch observation's finality rule resolves through a pinned
  source profile that cites a response layout, `show`, `explain` and `verify` read the state out of every response
  its request log lists and read the batch at the least of them (the batch meets `run >= L` only when every
  response does), disclosing the spread (`records at R2..DF across 3 responses, read as R2`). If the request-log
  check is not `ok`, or any logged response is not held or not readable under the layout, the read is `unchecked`,
  naming the first such entry by index and endpoint, and the observer's asserted state is used exactly as without
  a layout. Single-response observations print exactly what they printed before.
- **Series segments read batch captures.** Under a pinned source profile that cites a response layout, `hub check`
  and `pull` now read a series segment that is a batch capture the way `show` reads the same observation: through
  its request log, at the least state over every logged response. The members' boundary is `as held` when every
  segment's state came from held bytes; one segment whose log check is not `ok`, or whose responses are not all held
  and readable, is read at its asserted state with the same reason `show` gives, and the boundary is the weaker
  `as captured, not re-checked`. Before, every batch segment was read at its asserted state.
- **A synced header chain re-checks where an observed block is.** After `anchor headers sync`, `show`, `verify`
  and `explain` look up an exact-bytes observation's pinned block hash in this reader's header chain (only a
  `bip122:` referent naming the chain's genesis): on the accepted chain its depth now is what the finality rule
  reads (`provisional (2; final at 6)` or `final`), held off it is `not canonical`, and not held stays unchecked,
  saying so. This re-checks position, never bytes, so it adds no corroboration and never moves `verify`'s exit.
  Where the observer's asserted state at capture and the re-checked state disagree (asserted `final` at depth 7,
  re-checked depth 2), the referent carries both under `beside` with `disagrees: true` and the text says they
  disagree. Other chains and source referents are not re-checked. With no header chain nothing changes.
- **`commons run`** runs a workflow spec the store holds (its digest, or the id of an `authored` statement on it)
  under your execution policy (`--exec-policy`, required) and prints the result token, the environment record and
  each output; nothing is written. With `--publish` (and `--key`) it signs what the run emits, per output:
  `authored` on a first derivation, `reproduced` (`match`, or `diverged` / the comparator's word) over your own
  current `authored` of the same workflow and inputs instead of a second `authored`, and `observed` for a workflow
  that requires the network (`--request-log <output>` pins an `rc-request-log/1` capture's format, count and
  endpoint from the log). Disclosures are given per output with the same options `publish` takes
  (`--licence out=CC-BY-4.0`, `--availability out=…`, any number of times); nothing is inherited from the workflow,
  its inputs or a sibling output. The statements, the runner's `holds` and the output blobs commit as one unit: a
  failure before the commit point removes the blobs it installed, so the store is left as it was. A run that did
  not complete, or a re-run whose comparison could not finish, publishes nothing and says why.
- **`run --input <name>=<file>` supplies an unpinned input.** A workflow spec that names an input by a tag, a URL
  or a path (not a content hash) used to be refused by `run` before staging, because nothing fetches such a
  reference. `--input` (repeatable) now supplies its bytes from a local file. It is accepted for unpinned inputs
  only: an `--input` for a pinned input, or for a name the spec does not declare, is refused (exit 2) before
  anything runs, and an unpinned input not given is still refused, now naming the option. The run has partial
  provenance as before: `run --publish` emits `authored` with `provenance_partial`, which now also records the
  supplied bytes by digest (`supplied`, never the file's path); the output joins no derivation group and `verify`
  exits 4 naming the unpinned input.
- **`observed` gets the signer's `holds`, in `publish` and `run --publish` alike.** One rule now decides which
  statements a writer signs its own `holds` beside: `authored` and `observed`, for bytes the unit installs or the
  store already keeps. Before, only `authored` got one, so a capture's bytes were installed but served by no
  statement of the observer. `publish --no-holds` now applies to `observed` too, and an external-signing package
  of an `observed` with its bytes needs it (one statement per package). A `reproduced` still gets none: its bytes
  are the held `authored`'s, or a divergence the statement names.
- **The fixed-root identity writer.** `commons identity new` signs an identity's inception with a fresh root key
  (a key that already has a log is refused), `commons identity grant` grants a delegate key (pinned at its first
  line) a permission set, and `commons identity cut` cuts a grant: `--last-good <id|none>` is required, it says it
  cannot be undone, and it lists which of the delegate's acts keep counting. `publish --as <identity> --grant <id>`
  (with `--amends` for authored and observed) signs a statement acting for the identity, and refuses it, with
  nothing written, unless the statements you hold read the act eligible. These statements are written `rc/2`;
  every other statement is still `rc/1`. Readers from 0.5.0-alpha.4 on verify identity statements; **an
  older reader cannot** (it keeps them as unverified lines of another major). `key new` and `init` now say that a bare key cannot be
  recovered and point at identities.
- **External signing for identity statements.** `identity new`, `identity grant`, `identity cut` and
  `publish --as` take `--prepare <file> --signer <key>`: with no key file, they write a signing package (the
  unsigned statement, the exact bytes to sign, the proposed id, your log's position and a readable summary) and
  append nothing. Sign the bytes on another machine or device, then run the same command with
  `--complete <file> --signature <file|->`: the tool recomputes the bytes, verifies the signature, runs every
  check again and commits, or refuses with nothing written (a changed package, a wrong signature, or
  `stale-prepare` when your log moved). The package format, `rc-signing-package/0`, is provisional. No hardware
  or wallet connector is included.
- **`commons package show` and `commons key sign`: the signing side of a package, with no store.** On the
  machine that holds the key file, `package show <file>` runs the same checks `--complete` runs (every member
  derived from the unsigned statement recomputed) and prints the summary, signer, algorithm, proposed id and
  `pae_sha256` to compare with the one `--prepare` printed: exit 0, or 1 naming the member that differs.
  `key sign --package <file> --key <file> [--out <file>|-]` runs those checks, refuses a key that is not the
  package's signer, and writes the signature `--complete --signature` reads (never overwriting a file;
  `--dry-run` writes nothing). Neither reads a store; the log position is still checked by `--complete`.

### Changed
- **`identity new` and `identity cut` say what they check.** The fresh-root check sees this store only, so the help says to use a key generated for this purpose that has signed nothing anywhere; `--last-good` says it takes any held line of the delegate's key (a bare-key line included, not only an act under the grant) and that a thief's act inside the kept prefix keeps counting, so you name the last act you can attest was the delegate's own.

### Fixed
- **`provenance_partial` is now checked like every other field of `authored`.** The wire format lists it (`workflow`
  digest, `inputs` list of digests, `unpinned` list of strings, optional `supplied` object of name → digest, optional
  `environment`) and says every required field of a listed kind is checked at every gate, but the schema never read
  it: a draft with `"provenance_partial":5` was signed, committed and accepted by `pull` and `hub check`. `publish`
  now refuses such a draft before signing, and `pull`, `hub check` and `push` refuse the line, as intrinsic
  `malformed statement` naming the member. An `authored` carrying both `provenance` and `provenance_partial` is
  refused the same way (the partial form stands in place of `provenance`, so the output joins no derivation group).
  `run --publish` writes a well-formed one, so its output is unchanged.

### Known issues (open at this tag)
- Every gap in `docs/KNOWN-LIMITS.md` (L-01…L-15). The ones a first user meets:
  - Block headers come only from a file the operator obtains (`anchor headers sync --from`, L-02); with no header
    database every rival construction is `contested` and a task contract with a `deadline` never reaches `ready`. (#59)
  - A response layout reads JSON only, through one pointer to the record array and one to the state (L-14).
  - No hardware or wallet connector is built (L-07): an identity root on a device signs through the external-signing
    package, whose format `rc-signing-package/0` is provisional (L-09).
  - There is no Windows build (L-11), and `--json` output may change between alphas (L-12).
- The `next-format` issues are requirements for later stages, not defects in this release.

## [0.5.0-alpha.4] - 2026-11-13

### Added
- **Batch captures are checked against their request log.** The format now defines one request-log layout,
  `rc-request-log/1` (JSON Lines: `endpoint`, `parameters`, `status`, `time`, `response_digest` per request).
  `show`, `explain` and `verify` of a batch observation find the log by its digest inside the captured
  content (the blob or an archive member) and print where it was found, its entries and endpoints, and how many
  responses the content holds; a wrong count, an endpoint other than the pinned one, or a response whose bytes
  were changed is named by entry and `verify` exits 1, and a log digest that matches nothing in the content
  reads `unpinned`. Another layout is `unchecked`, naming it. The run library's publish plan pins a request log only in
  this layout, with its count and shared endpoint read from the log (no command wires it yet).
- The fixed-root identity profile's **reader is active**: every command reads `rc/2` statements (verified under
  the profile; a bad `rc/2` signature is refused like an `rc/1` one) and evaluates identity actors from the
  statements you hold. `show` and `explain` print an identity statement's actor (identity, grant, `eligible` /
  `denied` / `unknown` with reasons), `counted` follows the actor's eligibility, and every answer that held
  `rc/2` evidence names the evaluator (version, evidence digest, receipt). A `pull` admission entry naming an
  identity now admits that identity's eligible acts. Past the evaluator's admission cap identity answers read
  `unknown` (exit 3). A verified `rc/2` line that breaks the profile is kept and labelled `invalid`. With no
  `rc/2` statement held every output is unchanged.
- **An official Python package, `research-commons`** (`python/`). It runs the `commons` binary with `--json` and
  returns what it printed; it reimplements nothing. A problem object the tool prints becomes an exception chosen by
  the exit code (`DidNotStart`, `CouldNotCheck`, `CheckedAndWrong`, `NothingToRerun`, `EnvironmentMismatch`), with
  the problem's fields on it. Standard library only, Python 3.9+. Platform wheels carry the binary and install a
  `commons` command; `python/scripts/build_wheels.py` builds them from a release's archives after checking every
  archive against `SHA256SUMS`, byte-for-byte reproducibly. Publishing to PyPI is a manual maintainer step
  (`docs/RELEASING.md`, step 8).
- **Response layouts: the finality state read from the held response.** A source profile can now cite, in its
  `documents`, a response layout (`rc-response-layout/1`): an RFC 6901 JSON pointer to the records of a captured
  JSON response (`""` for a bare array at the root) and one to the state within each record. When every record of
  the held response carries a label in the profile, the response reads at its least record (the earliest label in
  the profile's order, the one state the whole response meets the rule at), and that state governs: the referent
  reads `final (as held)` (or provisional at the read state); records that differ are disclosed as a spread
  (`records at R1..RF, read as R1`), and an asserted `state_at_capture` that differs is shown beside it as a
  disclosed disagreement. The same read drives revisions, the finality-aware comparison and the series boundary,
  which is `as held` when every segment's state was read from its bytes (`hub check` and `pull` decide a premature
  freeze on it). A record whose label is outside the profile, a missing field, bytes that are not JSON, a response
  that is not held, or a held layout copy that is corrupt read `unchecked`, naming why, and the asserted state is
  used exactly as before, never upgraded. A layout read never moves an exit. A profile
  citing a layout stays a valid `rc-source-profile/1`: an older reader reads the layout as one more document.
  Other formats (CSV, XML, a compressed or archived response) are not read yet.

- **`hub check` labels the actor state of an added identity statement.** An added `rc/2` statement that names an
  actor now prints `actor: eligible`, `actor: denied (<reasons>)` or `actor: unknown (<reasons>)` beside its other
  labels, with the same `identity`, `grant`, `state` and `reasons` members `show` prints (a new `actor` member on the
  object's row in `--json`). It is a label only: admission and the exit code do not change. The check judges a change
  by the evidence of the change and the base together, so a change that carries an identity's inception, a grant and
  an act under it is `eligible` by that evidence (the root key's signature is the authority, not what the hub already
  held); the identity design note says why.

- **Licences are read as SPDX license expressions.** A declared licence is parsed under the SPDX expression grammar
  (identifiers, `AND` / `OR` / `WITH`, parentheses, `+`, `LicenseRef-` / `DocumentRef-…:LicenseRef-`), syntax only: no
  licence list ships and identifiers are not checked. A value that does not parse reads `unknown` with the reason, and
  every `LicenseRef` is listed with whether its text is cited. `show`, `verify`, `explain` and `list` carry a `licence`
  member.
- **A provenance depth bound.** The weakest-link grade follows a result's derivation inputs at most 128 steps
  (`status --limits` row `provenance_depth`). A longer chain is not followed past the bound: the result is
  `incomplete`, its grade `unchecked`, and `verify` exits 3 naming the limit.
- `explain` of a derived result lists the input observations and statements its scoped summary read, and the summary
  (`rests_on`) is a JSON member on every surface; a provisional input shows its horizon (`1 provisional until 6`). A
  corroboration's evidence rows on `show` / `explain` carry its result, the grade of its own derivation, comparison data
  and the cohort check.

### Changed
- **The `invalid` token is split.** `invalid` keeps meaning an edition whose body cannot be an edition. A statement
  that is signed correctly but breaks a rule of the identity profile (an `rc/2` line) is now `invalid statement`, in
  `show`, `verify`, `explain` and the gate's labels (`docs/CLI-OUTPUTS.md` lists both). Scripts that matched
  `invalid` on a statement's `status` should match `invalid statement`.
- **Upgrade note (journals written by 0.5.0-alpha.3).** A journal record that holds an `rc/2` line with a bad
  signature is quarantined whole when the store is opened (`recover`), its good `rc/1` lines included, because a
  record is installed all or nothing. No released command writes `rc/2`, so a record like that is near-impossible in
  practice. The record is moved to `quarantine/`, never deleted; the good `rc/1` lines in it can be pulled again from
  the peer they came from.
- The identity design note and the reader-policy text no longer call the identity reader a candidate opt-in: the
  reader is active (the wire format stays a candidate, and no command writes `rc/2`).

### Fixed
- `gc` keeps a document a pinned source profile cites when the held copy is corrupt, instead of reading it as
  "no layout" and collecting it (`fsck` still reports the corruption; refetch the copy).
- **An empty `referent.system` value no longer counts as a pinned key.** A method observation whose
  `referent.system` has a member with the value `""` (an empty string identifies nothing) is now read as if the
  member were missing: under a method edition that declares `system_keys` the referent is `unpinned` naming
  `referent.system.<key>` and `verify` exits 3, and without a declaration the member is not a key two observations
  "pin" for comparability. The statement is still admitted and shown as written; nothing is refused.

### Known issues (open at this tag)
- Every gap in `docs/KNOWN-LIMITS.md` (L-01…L-14). The ones a first user meets:
  - Block headers come only from a file the operator obtains (`anchor headers sync --from`, L-02); with no header
    database every rival construction is `contested` and a task contract with a `deadline` never reaches `ready`. (#59)
  - A response layout reads JSON only, through one pointer to the record array and one to the state (L-14); a batch
    capture's responses are checked against its request log but not yet read under a layout.
  - There is no Windows build (L-11), and `--json` output may change between alphas (L-12).
- The identity profile's **reader** is active; no command writes an `rc/2` statement yet (L-07). The writer
  (inception, grant, cut, publishing as an identity) is planned for the next alpha, one release after the reader.
- The `next-format` issues are requirements for later stages, not defects in this release.

## [0.5.0-alpha.3] - 2026-11-12

### Added
- **A forked key log is shown on the read commands.** When two lines of one key name the same predecessor (two
  machines, or two processes without the writer lock, signing at once), `show`, `verify` and `explain` of a line on
  the fork print `log: FORK at seq N (tips …)`, and `merged at seq N by <id>` once a later line of the key merges
  every tip (`--json`: a `log_forks` member). `list` and `status` add a `log_forks` row per open fork, and `fsck`
  lists every fork, open or merged. Both branches still count and no exit code changes: a fork is disclosed, not
  failed. A detached line's reason now names what it waits for (the missing seq range, or the unheld line by id).
- **Observation views read the pinned source profiles.** `show`, `verify`, `explain` and `pull` read the source
  profiles the store-root `hub-policy.json` pins (`series.source_profiles`) for an observation's own finality rule,
  not only for a series boundary: a rule `run >= L` whose `rule_source` names a pinned profile (its digest, or a
  document it lists) is evaluated through it, so the referent reads `provisional (<state>; final at L)` or
  `final (as captured, not re-checked)` instead of `finality unchecked`, and corroboration orders two captures by
  the profile's labels. A profile judges the observer's asserted state, so it never makes a referent plain `final`
  (only a re-check of the source does). `show`, `verify` and `explain` of an observation now print its referent
  status (`show` and `explain` with the history behind it). A pin this store does not hold, or that is not a
  valid profile, stops these commands (exit 2) naming the entry, as it stops `pull`. Without the member every
  answer is unchanged.
- **Source profiles for growing series (#111).** A source profile is a content-addressed blob
  (`rc-source-profile/1`) stating one source's finality order: `ordered-label` (a closed list of run labels,
  earliest first, for rules written `run >= L`) or `integer-depth` (`confirmations >= N`). A hub pins the profiles
  it trusts in `hub-policy.json` as `series.source_profiles: [{"digest": "sha256:…"}]` (at most 64); the blobs are
  read from the base revision (`hub check`) or from what the store holds (`pull`), so a change cannot bring the
  profile that judges it, and a pin that is not held, corrupt or not a valid profile stops the check (exit 2)
  naming the entry. With `series.refuse_premature_freeze` on and profiles pinned, a series edition's segments
  are read at their **asserted** state at capture: the members' boundary is shown `as captured, not re-checked`;
  a declared `frozen_before` later than it is refused (exit 1: the members themselves do not claim it), and one at
  or before it is `could not check (as captured)` (exit 3), never a pass. A segment whose state or rule the
  profile cannot place (a label not in the list, no `rule_source`, a `rule_source` naming no pinned profile or
  two) leaves the boundary unchecked. Without the member, every verdict is unchanged. The profile judges the
  observer's asserted state: the state is never re-derived from the captured bytes.
- **Task view on `show`, `verify` and `explain`.** A task is a resource: `show` of a task (its genesis id), one of its
  edition ids or an approval prints, beside the resource view, a task section: each edition's terms as this reader
  read them (or why it read none), the readiness of the current edition and of every edition a submission binds to
  (the token, the count against the quorum and the reasons), every submission as `counted`, `undecided` or
  `not counted` with every reason, the coordinator's grants and grants without effect, bound refutations on their own
  track, decisions and a decision conflict. `verify` of a task exits 0 when the edition's readiness is `ready`,
  `not ready` (a completed check whose answer is "not yet") or settled by review and the beneficiary's decisions agree,
  and 3 when readiness is `unknown` or `unchecked` or the decisions conflict. `explain` adds every condition checked
  for each submission (the passing ones too), the quorum groups and reports, and lists every task statement among its
  inputs. New state tokens: `undecided`, `not shown`, `accept`, `reject`.
- **`publish grant --task T --edition E --grantee K [--note TEXT]`**: a task coordinator's grant for one edition,
  printing the edition's readiness with the grant added. Refused with nothing signed when the grant would have no
  effect: exit 2 when your key is not the edition's coordinator, the contract names none, this reader does not read the
  contract, or the id is an approval's; exit 3 when the task or edition is not held as an authorized edition.
  `publish --draft` stays the raw path.
- **A chain backend from a headers file** (bitcoin-time note §6.1, §9.1, §10; L-02 narrowed). `commons anchor headers
  sync --from <file>` reads concatenated raw 80-byte block headers, validates every one (linkage, proof of work, the
  exact retarget, median time past, future time, version rules, greatest chainwork) and persists them in the
  reader's own state: the store's git directory, or `COMMONS_STATE_DIR` for a store that is not git-backed; never
  inside the store. A header that fails validation stops the sync (exit 1) and keeps what validated; a re-run adds
  nothing; `--max-headers` bounds a sync. `--bootstrap-height`/`--bootstrap-work` start from an explicit local trust
  root instead of genesis; the tool ships no checkpoint. The database is re-validated on every load and refused
  whole when foreign, of another network, corrupt, tampered or loosely permissioned (`backend-unavailable`).
  `commons anchor status` prints provider, mode, network, bootstrap, tip, last sync, freshness and the receipt count.
  `show`, `verify`, `explain`, `list` and `publish task` readiness now evaluate anchors against the persisted view
  (fresh, as of the last sync past the settled depth, or `verified-historical`), and a task deadline reads its tip.
  With no database every answer is unchanged. No network header source and no operator node yet.
- **Reads use the receipt store, and the header database is lighter.** When a reader has a header database, `show`,
  `verify`, `explain`, `list` and `publish task` readiness read anchors through the receipt store in the same
  receiver-local state: read-write when the state directory is writable, read-only otherwise (receipts are used,
  none is written, nothing is created). Every answer is the one a cold read gives. A held header now costs about
  half the memory and time to load (about 230–260 B and 1 µs per header). Every read still re-validates the whole
  chain, so `anchor headers sync --help` now recommends a bootstrap near the tip over a sync from genesis. The header
  database and the receipt store refuse a symbolic link at any of their paths, naming it, instead of following it.

### Fixed
- Credit: `contribution` and `acceptance` now count a key's submissions whatever their kind, as the task-contracts note
  defines them: an `authored` or `observed` carrying `fulfills` for a task edition counts beside `submit` statements.
- `gc` no longer deletes a source profile that `hub-policy.json` pins in `series.source_profiles`. A profile blob held
  only for that pin used to be collected after the grace window, after which every `pull` stopped (exit 2, "not held
  at this store") until it was held again. `gc` now keeps each pinned digest and names the pin in its plan; a policy
  file it cannot use stops it before any work (exit 2), never a run as if nothing were pinned, and `gc --release` of a pinned profile does not start (exit 2) until the pin is removed.
- A series edition whose segments include one the pinned source profile cannot place (a label not in its list, a
  `rule_source` naming no pinned profile or two) is no longer always `could not check`. When a later placeable
  segment is provisional, the members' boundary is at most that segment's date whatever the unplaced state is: the
  view shows it (`members' finality unchecked: final to at most 2025-04-01 (segment … not comparable) as captured,
  not re-checked`), and with `series.refuse_premature_freeze` on a `frozen_before` later than that bound is refused
  (exit 1) on the same evidence as a premature freeze; one at or before it stays `could not check` (exit 3). With no
  placeable provisional segment there is no bound, and the verdict is unchanged.
- When a finality rule's `rule_source` names no pinned source profile, the reason now says the match is exact:
  `rule_source compared as written to each profile's digest and documents`. A location spelled differently from the
  profile's `documents` entry (case, a trailing slash, percent-encoding) does not match, as before.
- A key-log line flagged `incoherent` (its `ts` earlier than its predecessor's) no longer lends a time bound to
  anything. Its statement has no bound for any use: it does not rank in priority among rival authorship claims, an
  observation on it shows `anchored at capture (no anchor held)`, and it meets no task deadline; the bound reads
  `no bound (incoherent line: …)`. An `anchors` statement on an incoherent line keeps only the bound its proof places (its chain position comes from the block header); its own local bound is discarded. The
  signature is still reported valid and the line is still shown with its flag. Previously the flag was displayed
  but every bound was derived as if the line were coherent.

### Known issues (open at this tag)
- Every gap in `docs/KNOWN-LIMITS.md` (L-01…L-14). The ones a first user meets:
  - Block headers come only from a file the operator obtains (`anchor headers sync --from`, L-02); with no header
    database every rival construction is `contested` and a task contract with a `deadline` never reaches `ready`. (#59)
  - A source profile orders the states an observer asserted at capture; no profile reads the state out of the
    captured bytes yet (L-14), so a ledger-label boundary is shown `as captured, not re-checked`.
  - There is no Windows build (L-11), and `--json` output may change between alphas (L-12).
- The identity profile is a candidate and inactive (L-07): an `rc/2` line reads as `unsupported`. Activation is
  planned for the next alpha after a review round.
- The `next-format` issues are requirements for later stages, not defects in this release.

## [0.5.0-alpha.2] - 2026-11-11

The second prerelease of the next format. Highlights: task contracts are read under the accepted
`task-contract-v1` profile (new wire kind `grant`, refutations bound to a task edition, deadlines on verified
Bitcoin bounds), the resource view on `show`/`verify`/`explain`, `commons rotate`, `explain --since`, an idle
timeout for `fetch`, and content rules that see inside archives. The candidate fixed-root identity profile
(`rc/2`) moved a long way behind an opt-in hook, but **no command activates it**: the format major is still
`rc/1`, and every output without the hook is unchanged. `--json` output changed shape in places (claim
`subjects`, `list` `resources`); it stays unstable during the alpha (L-12).

### Changed
- Identity profile (candidate, not active): every view now asks the same counting question of a statement. Behind the
  opt-in reader and an actor evaluator, an identity statement counts by its actor's eligibility in membership and
  edition-rule member records, an observation's own status and its "also observed by" lines, holders, completeness,
  `describes` claims, corroboration lookups, derivation-group runs, credit, observer records and time anchors. A
  denied or undecided one says why (no view prints "identity profile not active" when an evaluator is set).
  A view that counts per key still counts per key: an anchor bounds only its signer's own log, credit and records
  stay per signing key, and a key's selection or amendments never take in an identity's claim. With no evaluator
  (every command today), every answer is unchanged.
- Conformance: the claims-model exchange cases C-exch-07, -08, -09, -12, -13, -17, -18, -19, -20 and C-btc-19
  are declared by task-contract-v1 tests (the provisional-contract tests no longer declare anything); C-exch-10 (no
  receipt verifier ships) stays partial. A new test fails when the resolver's task text and the CLI task section stop printing the same ids. The
  task-contracts note (§5.7) now says which edition `verify` reads for an edition id or an approval id.
- Identity profile (candidate, not active): the candidate `rc/2` reader now reads resources (`genesis`, `edition`, `withdraw_approval`) with typed controllers (`{key: K}` or `{identity: I}`); task roles on an edition are shape-checked only. Behind the opt-in reader and an actor evaluator, a resource rule counts each controller once whoever signs for it (two delegates of one identity fill one slot, a delegate never fills its own key's slot), withdrawal is local to the key and grant that approved, and an approval a grant-history cut removes, or whose eligibility is undecided, leaves the edition `contested`. An `rc/2` edition's id is computed in its own major, so `rc/1` and `rc/2` approvals of the same bytes are different editions. `rc/1` histories read exactly as before.
- **Task contracts: the `task-contract-v1` profile is read** (task-contracts note). A task edition whose contract names
  `profile: "task-contract-v1"` gets its terms read in full, or not at all: an unknown field (`x_` names included), a
  malformed field, or terms that apply to no submission (`min_grade` without `results: "derived"`, a workflow pin
  under `results: "observed"`) leave readiness `unchecked` naming the field. The provisional profile keeps its own
  name and reading; any other profile stays `unchecked`. Under v1: an `authored` or `observed` carrying `fulfills` is
  a submission; each submission is `counted`, `undecided` or `not counted` with every reason named (eligibility,
  the coordinator's `grant` for that edition, rubric, deadline, results kind, `min_grade`, pins), and stays
  admissible whatever the outcome; a key counts by its current submission only (its log order, never `ts`), and
  disagreeing branches of a fork count in none; readiness is a bracket, so an undecided submission never takes away
  a quorum the counted ones reach. A `deadline: {height: h}` is met only by a verified Bitcoin bound at or below
  `h` (or a withheld-availability commitment's bound, which shows possession only); otherwise it is `unchecked` while
  anything can still resolve and `not shown` after, never "missed". `grouping: {rule: "any"}` collects every counted
  submission in one group. `counting_unit: identity` is read and readiness is `unknown` (no identity profile is
  registered). `publish task` prints the contract profile and, when readiness is not settled, why.
- New wire kind `grant` (a task coordinator seats a key for one edition) and optional `refutes` members `task` +
  `edition` (both or neither): a bound refutation is listed under that edition on its own track, in no quorum group.
  `publish --draft` can sign a `grant`. A `submit`'s `salt` is still read and shown as an inert field.
- `publish` of an `authored` that replaces your current claim on the same bytes and drops (or changes) its
  `fulfills` now warns, naming the edition: the submission is withdrawn. It still signs.
- `show --json` (and `verify --json` on contested authorship): each claimant now names its claim **subjects** as typed values (`"subjects": [{"key": "<key>"}]`, the shape a future identity claimant `{"identity": "<id>"}` will share) beside `signers`, the keys that signed the unit's statements; a `not_counted` entry carries `subject` (`{"key": …}`) and `signers` in place of `signer`. The human output is unchanged. `--json` is not yet stable in the alpha.
- Identity profile (candidate, not active): a dual-major reader that reads `rc/1` lines exactly as today and candidate `rc/2` identity lines with their signed actor, available only as an opt-in store option (no command uses it). Under it, an `rc/2` statement that acts for an identity never counts as its signing key's evidence: without an actor evaluator it reads `unknown (identity profile not active)`. Tests show an `rc/1`-only history gives the same ids, statuses and every resolver answer with and without it, that every resolver view handles `rc/2` bytes from either reader without failing, and that order-independence and non-interference hold on mixed `rc/1` + `rc/2` histories.
- `commons pull` now gives edition rules the package's blob bytes (and the blobs this store already holds), as `hub check` does, so a content rule re-applied at pull (a forbidden key inside a pulled `.tar` or `.tar.gz` member) reads the content instead of `unchecked (content not held)`. Archives are walked by the same scanner under the same limits. Rule dialects still ship none, so a rule with no dialect stays `unchecked`.
- `publish --draft` of a `rotate_key` now prints a warning naming the checks `commons rotate` would have made and this path skips (successor, key events already held, merged tips). It still signs, so the way out after a compromise stays open; the gap is listed in `docs/KNOWN-LIMITS.md` (L-13).
- `commons fetch` now gives up on a location by **idle time**, not total time: `--idle-timeout` (default 60s) counts
  from the last body byte received, so a large transfer that keeps flowing is no longer cut off after five minutes.
  `--timeout` is now an optional cap on the whole location and has no default; the output limits show both
  (`timeout_per_location` reads `none` when unset, `idle_timeout` is new). (#129)
- `commons help "hub check"` (a multi-word command name quoted as one word) now works like `commons help hub check`.
- `commons pull` no longer reports the store marker (or any control-plane file) as "not applied" when it is byte-identical to the receiver's own; a differing one is still reported.
- Hub policy knob `selection.refuse_incomplete` (default off): `hub check` refuses an edition whose completeness claim fails against the readings the hub holds, and reports a claim it cannot check as could-not-check (exit 3).
- **Identity evaluation caps follow the profile (#126).** The model's 2,048-fact walk limit is replaced by three
  deterministic per-query caps (100,000 dependencies, 100,000 path edges, 1,000,000 inspections); hitting one is
  `unknown` naming the cap, and ancestry is memoized so long histories stay linear.
- **`publish` and `publish task` refuse to sign with a retired key** (exit 1, `key-already-retired`): once this
  store holds a `rotate_key` or `revoke_key` of the signing key (in force, or detached until its gap fills), a new
  ordinary line would count toward nothing on any branch, so nothing is signed. A key-event draft is still signed.
- The `publish` pre-pin check reads a plain (non-archive) blob up to the archive bound at the default scan limits
  (about 551 MiB, was 64 MiB), so a publisher sees the same rule outcome for a large plain capture as a hub does,
  instead of `unchecked`. If the archive scanner ever reported a member as read without its bytes, that member is
  now an unscanned unit naming it (`unchecked`, never `ok`) rather than being skipped.
- The reader-policy consumers (corroboration trust, the run attestation line, the `pull` trust floor, principal
  selections) now ask one trust question of a *statement* instead of its signing key, behind an optional
  `ActorEligibility` hook that no command wires: an `{identity: I}` entry can only trust a statement an identity
  evaluator finds eligible for I, never a bare statement by one of I's worker keys. With no hook (every command
  today) every answer, count and rendering is unchanged, and an identity entry still reads `unknown (identity
  profile not active)`.
- Candidate fixed-root identity profile, after its first outside review: the profile states that a root compromise
  is total and retroactive and why, corrects what the evaluation caps read (the root's and the delegate's own facts
  count; other keys' never), and adds custody guidance (the plain key-file path, root reachability, a second
  controller subject on hub resources, co-maintenance). New: `identity.Snapshot.Authenticated`,
  `wire.EditionBodyType(major)`, and a seeded monotonicity property over fourteen evidence shapes. Nothing is
  activated.
- Candidate identity reader: a grant permission using a later version's `amend` mode or target mode now reads as
  unsupported (acts under that grant read `unknown`, sibling grants are unaffected), as an unknown permission kind
  already did, instead of invalid (acts `denied`). Malformed shapes and `any_resource` / `any_task` stay invalid.

### Added

- `commons explain <ref> --since <file>`: given an earlier `explain --json` of the same ref, prints what changed
  since then, each change with its cause: a statement added or removed (a `rotate_key` / `revoke_key` named as a key
  event), an input's status, log line or counted state, the hub policy, the reader policy (each entry that differs),
  the time policy, the evaluator, or the time context, plus whether the rest of the answer changed. Nothing is
  cached between runs; the file is the only memory. A file that is not an explain output of that ref is exit 2.
  To make this possible `explain` now also prints `explained` (the ref), each input's `counted` state, the in-force
  key events of every input's signer among its statements, and the reader policy document beside its digest.
- Reader policy trust targets now follow references: a `corroborates`, `refutes` or `retracts` (its `of`) and a
  `describes` of a statement are judged by the referenced statement's content when it is held. When it is not, an
  answer that depends on that content reads `unknown (target reference not resolved)` instead of `not trusted`. At
  `pull` the trust floor looks for the reference in the package and in this store; the unknown answer is refused
  under `--below-floor refuse` and labelled by default. New: `policy.Target`, `policy.ResolveTarget`,
  `policy.TrustsTarget`, `policy.AdmitTarget`.
- `commons list` now prints the resources this store holds beside the blobs: one line per resource with its id,
  its current edition (or `FORK` and its tips) and how many controllers the current authority has. In `--json` this
  is a new `resources` array; the `blobs` array is unchanged.
- `show`, `verify` and `explain` print **the resource view**. A resource's id is its genesis statement's id, so
  `show <genesis id>` prints the genesis and, beside it, the resource: controllers and rule, the current edition and the
  chain behind it by hash (`G → E1 → E2`), every edition with its state (`edition`, `pending`, `orphan`,
  `unauthorized`, `invalid`, `contested`, `detached`) and one row per approval, any `FORK` and the merge that cleared
  it, the current edition's members with their rule outcome, and the receiver's check of a completeness claim
  (`ok`/`fail` naming each unlisted reading/`unchecked`, beside the declaration, never moving the exit). An edition id,
  or the statement id of one of its approvals, shows the resource pinned at that edition. `verify` of a resource
  exits 3 under an uncleared `FORK` or a contested edition; of a pinned edition, 3 unless it is an authorized edition.
  `explain` adds each edition's reasoning and lists every statement the view read. New edition-state tokens in
  `docs/CLI-OUTPUTS.md`: `edition`, `unauthorized`, `orphan`, `invalid`.
- Every surface that prints a blob (`show`, `list`, `verify`, `explain`) now prints each observation of it with its
  **corroboration status** (counts under the counting unit, always scoped); `show`/`explain` of the observation's
  statement print the evidence behind it, and `verify` prints it beside the exit, which it never moves.
- Candidate identity profile: grants may carry `amend:"own"`, an amendment right limited to the acting key's own
  records of the identity, within the grant's content targets (a record by another delegate, for another identity, or
  not itself eligible for the identity, such as one a cut excludes, is a scope denial; a rotated successor key does not inherit it). Any other `amend` token still reads unsupported.
  The schema, a vector and the evaluator (version `fixed-root-model-3`) follow. Not wired into any command.
- Candidate identity profile: with an actor evaluator configured (no command configures one), a reader policy that
  follows an identity reads that identity's claims through explicit amendments only: same-key history amends
  nothing, two concurrent amendments are both current and the fields they disagree on are contested (no sequence,
  arrival or timestamp tiebreak), an amendment naming both reconciles them, an amendment naming another principal's
  claim or another blob applies to nothing, and an authorized amendment naming a target not held makes the
  selection `unknown (identity eligibility not established)` (an exact pin to an eligible claim still selects it).
- Candidate identity profile: an actor evaluator over admitted identity evidence (not wired into any command; the
  profile stays inactive). With one configured, identity-context statements count for corroboration, task submissions
  and exact pins by actor eligibility, with the signer's bare-key status shown beside them; identity counting
  deduplicates eligible identities and never turns a bare submission into an identity vote; trust answers cite the
  evaluator beside the policy digest. Without one, every output is unchanged. The signed `rc/2` vectors now run end to
  end through it in both algorithms.
- Candidate identity profile: signed `rc/2` test vectors for both algorithms (`docs/fixed-root-identity.signed-vectors.json`):
  inception, grant, cuts (`last_good` set and null), actor-bearing acts, an `rc/1` root `revoke_key`, and delivered
  negatives (tampered or stripped actor, `v1` preimage, `rc/1`↔`rc/2` relabels, an Ed25519 edge case as an identity
  line). Tests regenerate the file from published labels, read every entry with the candidate reader and check every
  Ed25519 signature under two independent implementations. Nothing is activated.
- **`commons rotate`** signs a `rotate_key` naming the successor (`--successor <key>`, or `--successor-key <file>`
  whose signer is used and never its key). It merges every held tip as a soft revocation does and refuses (exit 1)
  a tip whose branch carries a key event outside the line extended; it also refuses (exit 1) when the history it
  extends already holds an in-force key event, or the successor's log here carries one; a successor equal to the
  signing key is exit 2 (#128).
- **Edition rules that read content now see inside archives** (C-core-95). The `publish` pre-pin check
  (`--intended-for`) and `hub check` hand a rule the members of a tar, gzip or zip blob, each read by the bounded
  archive scanner, instead of the archive's raw bytes. A member the scanner cannot examine (a compression it has
  no reader for, such as xz; a scan limit) is passed as an unscanned unit naming the member and the limit, so the
  rule's outcome is `unchecked`, never `ok`. A blob that is itself in such a compression is one unscanned unit.
  Other blobs are read as before. Previously a forbidden key inside a compressed archive was missed and the rule
  could record `ok`.

### Known issues (open at this tag)
- Every gap in `docs/KNOWN-LIMITS.md` (L-01…L-13). The ones a first user meets:
  - No command verifies Bitcoin time yet (no header sync, L-02), so every rival construction is `contested`, and a
    task contract with a `deadline` never reaches `ready`. (#59)
  - Task readiness is printed by `publish task` only; `show`/`verify` of a task do not yet print submissions.
  - There is no Windows build (L-11), and `--json` output may change between alphas (L-12).
- The identity profile is a candidate and inactive (L-07): an `rc/2` line reads as `unsupported`.
- The `next-format` issues are requirements for later stages, not defects in this release.

## [0.5.0-alpha.1] - 2026-11-05

The first release of the **next format**, a clean break from the 0.4 alpha: one signed, append-only statement log
per key, a content-addressed store directory (`rc-store/1`), and a new command-line tool written in Go
(`cmd/commons`). There is no importer from the 0.4 format. The 0.4 alpha (Python CLI, hubs, ledgers) stays on
`main` and at `v0.4.0-alpha.1`, and gets security fixes only.

**This is an alpha.** The format may still change between alpha releases, and so may `--json` output (it carries
no `schema` member yet), key files (`rc-key/0`) and execution policies (`rc-exec-policy/0`). What the tool does not
do yet is listed in `docs/KNOWN-LIMITS.md`, each line backed by a test that fails when the gap closes.

**Conformance at this tag** (`go test -run TestConformanceCases -v ./internal/conformance`; covered = the case's
whole required outcome is tested, partial = a test names what remains; no case is untested):

| profile | covered | partial | cases |
|---|---|---|---|
| core (`docs/CONFORMANCE.md`) | 133 | 46 | 179 |
| Bitcoin time | 29 | 4 | 33 |
| exchange | 5 | 15 | 20 |
| execution | 16 | 2 | 18 |
| properties | 4 | 8 | 12 |

The fixed-root identity profile (`rc/2`) is a **candidate, not active**: 0 covered, 39 partial and 6 pending of 45
scenario cases, counted on its own line and never in a total.

**Install:** `go install github.com/research-common/research-commons/cmd/commons@v0.5.0-alpha.1` (Go 1.26+), or
the attested linux/darwin × amd64/arm64 binaries attached to the GitHub release (`SHA256SUMS`,
`gh attestation verify`). Windows does not build (L-11).

### Added
- **The command line**: `init`, `key new` / `key show`, `publish` (authored, holds, describes, retracts, or a
  draft file), `publish task`, `revoke`, `pull`, `fetch`, `show`, `verify` (`--rerun` with an execution policy),
  `explain`, `list`, `status` (`--limits`), `fsck`, `gc`, `hub check`. One closed vocabulary of state tokens and one
  exit table (`docs/CLI-OUTPUTS.md`, generated from code): 0 ok, 1 checked and wrong, 2 did not start, 3 could not
  check, 4 nothing to re-run, 5 environment mismatch. Errors are RFC 9457 problem details; peer text never reaches
  the terminal unescaped. `--json` on every command. Keys come only from `--key` or `COMMONS_KEY`: no default path,
  no implicit generation.
- **Bitcoin-time profile** (`docs/DESIGN-notes-bitcoin-time.md`): receiver-local verification of OpenTimestamps
  proofs against a headers-only chain validated in-process, with a receipt store. No command syncs headers yet, so
  no anchor is verified in practice (L-01, L-02).
- **Resource editions, series, observations and corroboration** (claims-model §5.3, §8): edition rules read the
  referent record and the edition under formation, order-free; same-predecessor editions show as a fork; exact-bytes
  finality drives status only; corroboration counts by signing key in `rc/1` and names the unit.
- **Execution profile** (`docs/DESIGN-notes-execution.md`): re-runs in an OCI sandbox only when the reader passes
  `--rerun` and an execution policy that admits the workflow; the environment is measured, never copied.
- **One validation core** for `pull`, `hub check` and the publisher's pre-pin check: per-object verdicts with a
  refusal class, scope and typed overrides; data never carries control. Reader policy (`docs/READER-POLICY.md`,
  provisional) with a trust floor.
- **Exchange** (claims-model §9): tasks with provisional contracts, submissions, decisions that cite exact
  submissions, and `counting_unit`.
- **Disclosures and determinism:** availability as two values, shelf-life age against an injected read time,
  retractions display-only, declared vs computed sampling n; delivery order, duplication and relayers never change
  a view; `explain` lists every statement behind an answer.
- **Completeness claims carry a scope** (`completeness: {class, source, window}`) and are checked against the
  observations held: `ok`, `fail` naming each unlisted reading, or `unchecked`. Display only.
- **`pull` reads a tar or tar.gz archive** of a store tree as the same package as the unpacked tree, never
  extracting it; ambiguous archives are refused whole (exit 1), truncated ones judged not at all (exit 3).
- **`commons revoke`** with three documented reasons and no default; soft reasons merge every held tip, and refuse
  (exit 1) a tip whose branch carries a key event outside the line extended; `key_compromise` needs `--last-good`.
- **`commons fetch`** from the locations held `holds` statements name: https by default (`--allow-http`),
  non-global addresses refused at connect time unless `--allow-private`, size checked before the hash, a location
  serving other bytes refused and the next tried. It never publishes a `holds`. Invoking it is the opt-in to the
  network; no other command dials.
- **Per-key advisory writer lock** around resolve-head → sign → commit for every writer (#127): `flock` on
  directories every store already has (it creates nothing); waits 10 s, then proceeds and says so
  (`writer_lock`). `status --limits` declares `locks: advisory`.
- **Fixed-root identity profile, candidate** (`docs/DESIGN-notes-fixed-root-identity.md`): schemas, vectors, a
  reference model and an opt-in reader, with its 45 scenarios registered as conformance cases. Not activated:
  `wire.Major` stays 1 and an `rc/2` line reads as unsupported (L-07).
- **Release tooling:** `commons --version` reports the embedded `VERSION` on an unstamped build (a hub's CI no
  longer prints `devel`); `.github/workflows/release.yml` builds reproducible, attested binaries and `SHA256SUMS`
  on publish.
- **A scripted two-store drill** (`internal/cli/drill_test.go`): publish, pull, verify, fsck, a checkout pull, and
  a fork across two sources.
- `SECURITY.md`: report through private vulnerability reporting; supported versions.

### Changed
- **Writer refusals decided over held statements exit 1** (a check that completed and disagreed); 3 stays for
  refusals that depend on statements not held or on a choice the tool won't make for the owner.
- README, GETTING-STARTED and RELEASING rewritten for the Go tool. Documents that describe only the 0.4 alpha carry
  a banner pointing at `main`.

### Removed
- **The Python alpha CLI is no longer on this line** (`bin/`, `lib/`, `comparators/`, `tests/`, `registry/`,
  `environments/`, `package.json`). It remains on `main` and at `v0.4.0-alpha.1`.

### Fixed
- **Wire-format vector V5** listed its `controllers` set unsorted, which the note's own set rule refuses. Sorted
  and re-chained (V5–V12 and N8–N13 change; #88).

### Known issues (open at this tag)
- Every gap in `docs/KNOWN-LIMITS.md` (L-01…L-12). The ones a first user meets:
  - No command verifies Bitcoin time yet, so every rival construction is `contested`. (#59)
  - There is no Windows build (L-11), and `--json` output may change between alphas (L-12).
- The identity profile's traversal cap (2,048 relevant root events) is below its own stated limits; fixed before
  any consumer is built (#126).
- No `commons rotate` (#128); `fetch --timeout` is whole-request, not idle (#129).
- The `next-format` issues are requirements for later stages, not defects in this release.

## [0.4.0-alpha.1] - 2026-10-12

### Deprecated
- **The 0.3 alpha line is in maintenance: security fixes only.** The next format, proposed in
  #69 (design note in #70), is a clean break with no importer or compatibility layer. Feature
  PRs against this line won't be merged, and non-security bugs stay open with the
  `next-format` label, as requirements for the new format. Hubs built on this version should
  expect to be rebuilt and their data republished.

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
- **Security: workflow staging could write and read host files outside the sandbox.** A
  workflow spec's attachment names, output paths and input/comparator/skill file names
  were joined on the host with no confinement, before and after the container ran. An
  absolute or `../` attachment name wrote anywhere the user could write; an absolute or
  symlinked output path made `run --publish` read a host file and publish its bytes. Foreign
  tasks are always sandboxed, so this reached anyone who ran a peer's task. Every such name
  now goes through one check that refuses absolute paths, `..` components and symlinks.
  `export` without `-o` likewise keeps the manifest's filename in the current directory.
- **Security: an unsigned lifecycle line could settle a task.** The lifecycle fold verified
  a signature only if one was present, so an unsigned `accept`/`reject` naming the
  beneficiary's address moved the task. Combined with `pull` accepting new lines in the
  unsigned logs (#14), a peer could settle or reject another key's task. Unsigned lifecycle
  events are now dropped. Every lifecycle writer already required a key, so no line this
  tool wrote is affected.
- **Security: incoming attribution now requires a signature that verifies (#72).**
  `pull` treated a populated `verification.attested_by.addr` as an attester without
  checking its signature, so a forged attestation naming a trusted peer was ingested
  (`verify` later caught it, `status` displayed it as attested). Attestations are now
  verified at ingest. `COMMONS_REQUIRE_SIG=1` checked only for that field, so it refused
  properly signed T0 datasets and admitted forged ones; it now accepts a verified signed
  publish of the exact bytes or a valid attestation. A peer registered with `trust=none`
  is refused for every artifact type, not only as an attester. Publisher attribution for
  executables is matched on the full content hash, not the 8-character id.
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
- **How to migrate a collection superseded before #39.** The 0.3.0-alpha.1 migration note said to
  republish the successor with `supersedes` in its spec. That alone isn't enough. If the chain has
  more than one hop and the policy was added after the first version, a claim against the original
  id still escapes the policy. The new tip has to list every earlier version, and each
  intermediate version needs a `--force` republish to drop its stale manifest link, or `hub check`
  keeps failing. README §"Migrating a collection superseded before #39" gives the steps, and
  `tests/test-spec-supersedes.sh` covers them.

### Known issues (open at this tag)

This line is in maintenance (security fixes only; see Deprecated). Non-security findings are
tracked as requirements for the next format under the `next-format` label and in #74.

- **#14**: `pull` accepts new lines in a peer's unsigned logs (warns and records them in
  `quarantine.log`).
- **#41 / #45 residual / #48**: manifest edits on held artifacts, relayed lifecycle lines keyed on
  unsigned fields, and `pull` lacking three of `hub check --base`'s ledger checks. All three are
  closed by construction in the next format (#69 §4, §9.2, §11).
- **#10**: `verification.params` is outside the T3 signed statement.
- **#59**: Bitcoin-quality anchor evidence is disabled until receiver-local verification exists;
  all bounds are local.

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

[Unreleased]: https://github.com/research-common/research-commons/compare/v1.0.0-rc.1...next
[1.0.0-rc.1]: https://github.com/research-common/research-commons/compare/v0.5.0-alpha.8...v1.0.0-rc.1
[0.5.0-alpha.8]: https://github.com/research-common/research-commons/compare/v0.5.0-alpha.7...v0.5.0-alpha.8
[0.5.0-alpha.7]: https://github.com/research-common/research-commons/compare/v0.5.0-alpha.6...v0.5.0-alpha.7
[0.5.0-alpha.6]: https://github.com/research-common/research-commons/compare/v0.5.0-alpha.5...v0.5.0-alpha.6
[0.5.0-alpha.5]: https://github.com/research-common/research-commons/compare/v0.5.0-alpha.4...v0.5.0-alpha.5
[0.5.0-alpha.4]: https://github.com/research-common/research-commons/compare/v0.5.0-alpha.3...v0.5.0-alpha.4
[0.5.0-alpha.3]: https://github.com/research-common/research-commons/compare/v0.5.0-alpha.2...v0.5.0-alpha.3
[0.5.0-alpha.2]: https://github.com/research-common/research-commons/compare/v0.5.0-alpha.1...v0.5.0-alpha.2
[0.5.0-alpha.1]: https://github.com/research-common/research-commons/releases/tag/v0.5.0-alpha.1
[0.4.0-alpha.1]: https://github.com/research-common/research-commons/compare/v0.3.0-alpha.1...v0.4.0-alpha.1
[0.3.0-alpha.1]: https://github.com/research-common/research-commons/compare/v0.2.0-alpha.1...v0.3.0-alpha.1
[0.2.0-alpha.1]: https://github.com/research-common/research-commons/releases/tag/v0.2.0-alpha.1
