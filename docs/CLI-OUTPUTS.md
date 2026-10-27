# Command-line outputs

Generated from `internal/cli` (`exit.go`, `vocab.go`) by `RC_UPDATE_DOCS=1 go test -run TestOutputsDoc ./internal/cli`.
Do not edit by hand: a test fails when this file and the code differ. `commons help exits` and
`commons help outputs` print the same tables.

Errors are RFC 9457 problem-details objects (`type`, `title`, `detail`, `class`, `scope`, `committed`,
`next`, `exit`; peer-supplied text only in `peer_text`). Types are `urn:research-commons:problem:<slug>`.

## Exit codes

| exit | name | meaning |
|---|---|---|
| 0 | ok | the requested operation succeeded; for verify, checked and passed. Not a claim that everything referenced is valid |
| 1 | checked and wrong | a check ran to completion and found something wrong: verify's comparison disagreed, a gate (hub check, pull) refused at least one object, or fsck made a fatal finding. What a gate admitted beside a refusal is still committed (pull) and said so |
| 2 | did not start | the invocation or the reader's own configuration could not be acted on: unknown option, malformed argument, unreadable or unparseable policy, no store. Nothing ran and nothing was committed |
| 3 | could not check | contested, unknown, unchecked, unpinned, unsupported, an optional capability not configured, a reader limit, or a failure after work started |
| 4 | nothing to re-run | the derivation names an input it did not pin |
| 5 | environment mismatch | the declared environment differs from, or is not available in, the one that ran |

## State tokens

JSON members carrying tokens: `authorship`, `role`, `state`, `grade`, `step`, `quality`, `time_state`, `status`, `line`, `counted`, `labels`, `bytes`, `causes`, `store_state`, `what`, `verdict`, `class`.

| token | kind | meaning |
|---|---|---|
| `no authorship claim` | authorship | no counted authored statement for the blob is held |
| `sole author` | authorship | one claimant unit of one key |
| `derived` | authorship | one derivation group of two or more keys; priority is not computed within it |
| `default author` | authorship | several claimant units; one is strictly earliest at a quality this reader verified |
| `contested` | authorship | several claimants (or several values of one field) and none is the default; every claimant is listed |
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
| `pending` | time | only calendar attestations; a calendar's promise grants nothing |
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
| `detached` | line | a predecessor is not held; shown, attributed, counted toward nothing |
| `counted` | statement | chained, verified, understood and not excluded by a key event |
| `not counted` | statement | held and shown, counted toward nothing (the reason is named) |
| `retained` | line | an unverified line kept and not placed |
| `FORK` | line | two lines of one key's log from one sequence point, not yet merged |
| `retracted` | label | the author signed a retraction; display only, the bytes may still be served |
| `held here` | bytes | this store holds the blob's bytes and they hash correctly when read |
| `not held here` | bytes | this store does not hold the blob's bytes |
| `unpinned` | verify | a derivation names an input it did not pin; nothing to re-run |
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
| `below trust floor` | label | the signer is not trusted for admission by this reader's policy; admitted and labelled (--below-floor label) |
| `nothing pending` | store | no journal record is waiting: every committed operation is installed and projected |
| `committed, pending install` | store | the operation reached its commit point and its statements are not all installed yet |
| `committed, needs repair` | store | the operation is installed and its projections are untrusted; run repair |
| `replayed` | recovery | a pending operation was finished on open |
| `projected` | recovery | a done operation's projections were rebuilt on open |
| `needs repair` | recovery | a projection failed on open |
| `quarantined` | recovery | a journal record failed to decode or verify and was moved aside; nothing from it installed |
| `replaced statement` | recovery | a corrupt stored copy was quarantined and the verified line installed |
| `removed temporary` | recovery | a stale temporary file was removed |
