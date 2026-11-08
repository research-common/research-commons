# Command-line outputs

Generated from `internal/cli` (`exit.go`, `vocab.go`) by `RC_UPDATE_DOCS=1 go test -run TestOutputsDoc ./internal/cli`.
Do not edit by hand: a test fails when this file and the code differ. `commons help exits` and
`commons help outputs` print the same tables.

Errors are RFC 9457 problem-details objects (`type`, `title`, `detail`, `class`, `scope`, `committed`,
`next`, `exit`; peer-supplied text only in `peer_text`). Types are `urn:research-commons:problem:<slug>`.

Platforms: Linux and macOS. Windows is not supported: the tool does not build for it.

Stability: the `--json` output may change between alpha releases. It carries no `schema` member yet.

## Exit codes

| exit | name | meaning |
|---|---|---|
| 0 | ok | the requested operation succeeded; for verify, checked and passed. Not a claim that everything referenced is valid |
| 1 | checked and wrong | a check ran to completion and found something wrong: verify's comparison disagreed, a gate (hub check, pull) refused at least one object, fsck made a fatal finding, or a writer refused a request its check over the statements held decided (a rule the publisher named failing its bytes; a revocation that would undo itself), so holding more statements would not change the answer. What a gate admitted beside a refusal is still committed (pull) and said so |
| 2 | did not start | the invocation or the reader's own configuration could not be acted on: unknown option, malformed argument, unreadable or unparseable policy, no store. Nothing ran and nothing was committed |
| 3 | could not check | contested, unknown, unchecked, unpinned, unsupported, an optional capability not configured, a reader limit, or a failure after work started |
| 4 | nothing to re-run | the derivation names an input it did not pin |
| 5 | environment mismatch | the declared environment differs from, or is not available in, the one that ran |

## State tokens

JSON members carrying tokens: `authorship`, `role`, `state`, `grade`, `step`, `quality`, `time_state`, `status`, `line`, `counted`, `labels`, `bytes`, `causes`, `store_state`, `what`, `verdict`, `class`, `status_scope`.

| token | kind | meaning |
|---|---|---|
| `no authorship claim` | authorship | no counted authored statement for the blob is held |
| `sole author` | authorship | one claimant unit of one key |
| `derived` | authorship | one derivation group of two or more keys; priority is not computed within it |
| `default author` | authorship | several claimant units; one is strictly earliest at a quality this reader verified |
| `contested` | authorship | several claimants (or several values of one field) and none is the default; every claimant is listed. For an edition: authorized only if approvals a key event doubts are counted, or built on an edition that is; never current, authorizes nothing |
| `within statements you hold` | scope | every status of the view is computed from the statements this reader holds; nothing is claimed about statements it never received |
| `within this hub` | scope | every status of the view is computed from one hub's own holdings only |
| `author` | role | the only claimant unit |
| `derivers` | role | the keys of the one derivation group |
| `later claimant` | role | a claimant after the default author; never shown as proven later |
| `claimant` | role | a claimant of a contested blob |
| `default` | field | the field's value from the default unit, agreed by its signers |
| `undeclared` | field | no claimant declared the field; for pre-registration, not the same as exploratory |
| `unknown` | field | for a licence: none declared, which is never read as open (C-core-67); elsewhere: nothing held establishes it |
| `no default (authorship contested)` | field | authorship is contested, so no claimant's value is the default |
| `T0` | grade | byte-identical re-derivation |
| `T1` | grade | re-derivation matched under the named comparator, run by this reader |
| `T2` | grade | task-level replication |
| `no derivation (no provenance)` | grade | the blob declares no provenance, so it is a leaf, not a derivation step |
| `not re-derived` | grade | a derivation nobody else re-ran; unchecked until a second run or the reader's re-run |
| `identical bytes (protocol workflow)` | grade | identical bytes under a protocol workflow: consistent with a re-run and with a copy, evidence of neither |
| `diverged` | grade | a comparison ran to completion and the outputs disagree |
| `unchecked` | grade | the check could not run (no comparator, no backend, a limit); never a pass. Also a rule evaluation that could not decide |
| `not comparable` | grade | the comparator could not compare the outputs |
| `observation (not a tier)` | grade | the blob is an observation; observations carry no tier |
| `no statement held` | grade | this reader holds no statement about the blob or id |
| `ok` | rule | a rule evaluation that passed |
| `fail` | rule | a rule evaluation that failed |
| `none` | time | no counting anchor covers the statement |
| `local` | time | an anchor this reader did not verify; self-declared, orders nothing |
| `bitcoin` | time | an anchor whose proof this reader verified against block evidence it trusts |
| `verified` | time | the proof verified against the reader's chain view |
| `verified-historical` | time | verified against an old view at less than the settled depth; priority not computed from it |
| `pending` | time | only calendar attestations; a calendar's promise grants nothing. For an edition: approved by controllers of every predecessor, not yet enough for one predecessor's rule |
| `insufficient-confirmations` | time | below the reader's confirmation policy |
| `missing-proof` | time | the proof blob is not held here (never fetched) |
| `invalid-proof` | time | the proof does not commit to the covered statement |
| `invalid-anchor` | time | the anchors statement itself is unusable |
| `unknown-height` | time | the attested height is not in the reader's chain view |
| `orphaned` | time | the attested block is not on the accepted chain |
| `stale-chain` | time | the reader's chain view is not fresh under its policy |
| `backend-unconfigured` | time | no chain backend is configured, so no bound is verified; a state, not a failed invocation (exit 3) |
| `backend-unavailable` | time | the configured chain backend could not be read |
| `unsupported` | time | a proof format, attestation, rc major, alg or critical extension this reader does not implement |
| `refused` | time | an anchor refused under a limit of this reader; as a gate verdict, an object not admitted, with its class, reason and narrowest next step named |
| `valid` | statement | signature verified and every rule this reader implements passed |
| `unknown kind` | statement | a validly signed statement of a kind the format does not list; granted nothing |
| `chained` | line | the line reaches its log's first line through prev and merges |
| `detached` | line | a predecessor is not held; shown, attributed, counted toward nothing. For an edition: every approval is on a detached line; shown, not evaluated |
| `counted` | statement | chained, verified, understood and not excluded by a key event |
| `not counted` | statement | held and shown, counted toward nothing (the reason is named) |
| `retained` | line | an unverified line kept and not placed |
| `FORK` | line | two lines of one key's log from one sequence point, not yet merged; for a resource, two authorized editions with one predecessor and no merge: no edition is current |
| `retracted` | label | the author signed a retraction; display only, the bytes may still be served |
| `held here` | bytes | this store holds the blob's bytes and they hash correctly when read |
| `not held here` | bytes | this store does not hold the blob's bytes |
| `fetched-and-verified` | fetch | the bytes were fetched from a location and installed after the size and full-hash check; equivalent to a blob from a package |
| `unavailable (not held locally)` | fetch | not held here and no held holds names a location for it |
| `unavailable (holder's word)` | fetch | a holder said the bytes are at the location; it could not be reached (or the transfer died midway, or made no progress for --idle-timeout, default 60s), so nothing was installed |
| `unavailable (hash mismatch)` | fetch | the location served bytes whose full hash differs; refused (intrinsic), both hashes and the location named, nothing installed |
| `unavailable (size mismatch)` | fetch | the location served a different number of bytes than the holds declares; refused (intrinsic) before the hash was relied on, nothing installed |
| `unavailable (size limit)` | fetch | the declared size, or the stream when none is declared, exceeds the reader's fetch limit (max_fetch_bytes); refused (operational), a declared size before dialling |
| `unavailable (scheme not fetched)` | fetch | the location's URI scheme is not one this reader fetches (https by default, http with --allow-http); refused before dialling |
| `unavailable (no transport in this build)` | fetch | this build has no network transport, so nothing was dialled |
| `would fetch (dry run)` | fetch | a dry run: the location would be dialled; nothing was |
| `stored copy corrupt` | fetch | the blob file held here does not hash to its name; never used, replaced (and quarantined) only by verified bytes |
| `unpinned` | verify | a pin the statement needs is missing: a derivation input it did not pin (nothing to re-run), or a referent field an observation's class requires (no class agreement model applied) |
| `final` | referent | the reader's own re-check found the referent at a state that meets the declared finality rule |
| `final (as captured, not re-checked)` | referent | the observer's asserted state at capture meets the rule and no re-check of this reader confirmed it; never shown as final (I4) |
| `provisional` | referent | the finality rule is not met at the state shown (the state at capture, or this reader's re-check), with the state at which it would be |
| `revised` | referent | a later capture of the same referent holds different bytes before finality; the observation stays true of what it pinned |
| `not canonical` | referent | this reader's re-check found the referent replaced (a deep reorg, a dispute run); nothing counts against the observer |
| `still canonical` | referent | this reader's re-check found the pinned referent unchanged (no finality rule declared) |
| `source still available` | referent | this reader's re-check of a source referent returned it (no finality rule declared) |
| `source unavailable` | referent | this reader's re-check could not reach the source; existing corroborations stand |
| `unknown (not re-checked by this reader)` | referent | no finality rule declared and no re-check of this reader decided anything |
| `pinned` | referent | a phenomenon or method referent: its fields are pinned and it has no re-check |
| `no referent (class none-yet)` | referent | the observation's class names no referent yet |
| `finality unchecked` | verify | the observation's declared finality rule cannot be evaluated by this reader |
| `body not interpreted` | verify | the observation's body was kept opaque (an unsupported or critical member); nothing read from it |
| `counts toward nothing` | verify | the statement is not placed in its signer's log (a fork branch left out, a revoked key); it is shown, never counted |
| `admitted` | gate | the object passed every check of the gate and the receiver's policy |
| `admitted and labelled` | gate | admitted, with a label the reader should see (already held, detached, below trust floor, …) |
| `could not check` | gate | the gate could not decide about the object (a check that could not run); never a pass |
| `not applied` | gate | a control-plane path: reviewed by the maintainers, never admitted as data |
| `intrinsic` | class | no reader could admit it (bad signature, hash mismatch, unsafe path); no override applies |
| `reader policy` | class | this reader's own policy refused it (trust floor, hub rules); a typed override naming the object may admit it |
| `operational` | class | a limit or resource of this reader stopped it; raising the named limit is the next step |
| `already held` | label | the receiver already holds this statement; nothing new is installed |
| `incoherent` | label | the key's log is inconsistent at this line; shown, counted toward nothing |
| `unreferenced` | label | a blob no statement of the evaluated set names |
| `unavailable` | label | a statement names a blob neither the package nor the receiver holds |
| `not held here (policy)` | label | the receiver's policy does not serve the blob a statement names (not_served) |
| `layout marker` | label | the rc-store layout marker |
| `control-plane change: needs maintainer review` | label | a change to a hub's own files; not data, reviewed by the maintainers |
| `removed (not_served)` | label | a blob the hub policy no longer serves was removed |
| `not served: still present` | label | a blob the hub policy lists in not_served is still in the tree |
| `intended_for` | label | the receiver's re-application of the statement's intended_for, beside the signer's record |
| `admitted by override` | label | a reader-policy refusal lifted by a typed override that names this object |
| `series boundary` | label | a series boundary the freeze policy could not decide |
| `completeness claim` | label | the receiver's check of an edition's completeness claim (selection.refuse_incomplete): holds, or could not be checked |
| `below trust floor` | label | the signer is not trusted for admission by this reader's policy; admitted and labelled (--below-floor label) |
| `match` | rerun | the re-run's output equals the pinned output (bytes), or the comparator said match (protocol) |
| `match (identical bytes)` | rerun | a protocol workflow re-ran to identical bytes: consistent with a re-run and with a copy; no T0 |
| `incomplete output` | rerun | the step exited 0 and a declared output is missing |
| `failed` | rerun | the step exited non-zero in an environment matching the pin (detail: the exit status) |
| `failed: operational` | rerun | a cap of this reader stopped the step (detail: the cap); could not check |
| `timeout` | rerun | the wall-time cap stopped the step; could not check |
| `environment mismatch` | rerun | the re-run's environment differs from the pin on a field environment_match names, or the pinned environment is not available here (detail: the fields); nothing compared |
| `edition` | edition | an authorized edition of the resource: every predecessor's controllers approved this body under its rule |
| `unauthorized` | edition | some predecessor's controllers did not approve this body (nobody elevates themselves) |
| `orphan` | edition | a predecessor names nothing this reader holds as the genesis or an edition of the resource; never current |
| `invalid` | edition | authorized approvals, but the body cannot be an edition (a rule no controller set meets, or a merge that does not declare differing controllers and rule) |
| `settled by review, not by counting` | readiness | the task edition has no quorum predicate: its beneficiary's decisions settle it; nothing is counted |
| `ready` | readiness | the quorum is met by distinct signing keys under the edition's terms |
| `not ready` | readiness | the quorum is not met yet |
| `nothing pending` | store | no journal record is waiting: every committed operation is installed and projected |
| `committed, pending install` | store | the operation reached its commit point and its statements are not all installed yet |
| `committed, needs repair` | store | the operation is installed and its projections are untrusted; run repair |
| `replayed` | recovery | a pending operation was finished on open |
| `projected` | recovery | a done operation's projections were rebuilt on open |
| `needs repair` | recovery | a projection failed on open |
| `quarantined` | recovery | a journal record failed to decode or verify and was moved aside; nothing from it installed |
| `replaced statement` | recovery | a corrupt stored copy was quarantined and the verified line installed |
| `removed temporary` | recovery | a stale temporary file was removed |
