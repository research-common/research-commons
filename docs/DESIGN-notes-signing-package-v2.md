# External-signing package, revision 2 (`rc-signing-package/2`): proposal

**Status: proposal, not implemented.** No reader or writer knows `rc-signing-package/2`. Every tag, member,
action token, option and refusal slug below is a working name until the revision is reviewed and frozen. Today's
tool writes and reads `rc-signing-package/1` only, as the fixed-root identity note (§8) specifies it, and nothing
here changes that until it is implemented. Where this note says "the tool does", read "the tool would do, once
this proposal is implemented"; where it reports what a released build does today, it says so and names the build.

## 1. Why, and why a note of its own

The external-signing package lets a key the store never sees sign a statement: `--prepare` writes the unsigned
statement and its exact signed bytes to a file, a signing machine or device signs those bytes, and `--complete`
verifies the signature and commits the line. `rc-signing-package/1` (frozen at `1.0.0-rc.1`) carries four
actions only: an identity's inception, grant and cut, and an act for an identity (`publish --as`). Three things a
key on a device or an air-gapped machine needs to sign have no package route (KNOWN-LIMITS L-22, issue #266):

1. **A bare-key statement**, above all a controller key's `edition` approval (and its `withdraw_approval`). A
   resource whose controllers include `{key: K}` needs K itself to sign; with K on a device, nothing can.
2. **A key event**, `revoke_key` or `rotate_key`, signed by the key it retires. `revoke --ledger` and
   `rotate --ledger` (#268) sign one on a Ledger attached to the store's machine. A key on another device, or in
   a key file on an air-gapped machine, has no route, and neither has an escrowed revocation made by such a key.
3. **The three statements of a recovery** under the proposed recoverable-root profile (`recoverable-root-v1`,
   its own proposal): the successor root's first line, the recovery key's statement and the old root's
   handover. That proposal (its §8) defers their signing route to a revision of the package, made once, together
   with 1 and 2. This is that revision.

**Where this text lives: a new note, not a new section of the identity note.** Recommended because:

- The identity note's §8 is the specification of `rc-signing-package/1`, which is frozen. Adding a proposal to it
  would mix frozen text with text that may still change, in the one place a reader goes to learn what `/1` is.
- The revision spans more than the fixed-root profile: bare-key `rc/1` statements and key events belong to the
  wire format and the claims model, and the recovery statements to another profile. No single profile note owns it.
- The recoverable-root proposal already says the revision "gets its own note".

Rejected: a new section in the identity note (keeps one file for the package, but at the cost above). Once the
revision is implemented and frozen, the identity note's §8 keeps the `/1` text unchanged and gains a one-line
pointer here, as it points to the wire note for byte rules.

## 2. A new tag, `rc-signing-package/2`; `/1` is still read

**Recommendation: a new tag, `rc-signing-package/2`. Every release that reads `/2` also reads and completes
`/1`, for as long as `/1` is part of the frozen set (the whole `1.x` line).** The tag a package carries is a
function of its envelope (§2.2), so a statement has exactly one package form.

**Why not extend `/1`.** `/1` is frozen: its rule is that a change to a package's bytes takes a new tag, and the
promise made with the freeze is that a package reads the same under every release that reads its format. A
`/1` package carrying a statement `/1` does not define would read differently under different releases, and,
worse, a frozen `/1` reader is not built to refuse it cleanly. Checked on builds of `1.0.0-rc.1` and of `next`
(today's reader), with a throwaway store and keys, by placing a signed vector's envelope, its signature
removed and every derived member correct, in a `/1` package:

| Envelope in a `/1` package | `package show`, `key sign`, `<command> --complete` today |
|---|---|
| an `rc/1` `revoke_key` | refused, `malformed-package`, exit 2 ("only an `rc/2` envelope is checked unsigned"); nothing signed or written |
| an `rc/2` bare-key (marker-only) `edition` | **internal error, exit 3**: the summary is computed for an actor the envelope does not have. Nothing is signed or written, but the refusal is a crash, not a check |

So `/1` cannot safely grow: the second row shows a frozen reader reaching code paths that assume the four `/1`
actions. Extending `/1` is rejected for that reason, and for the freeze itself. (The second row is a defect in
today's `/1` reader, worth a fix before the next candidate: refuse any envelope that is not one of the four
actions, exit 2, before the summary is computed. The fix changes no signed byte and no package `/1` writes.)

### 2.1 What a `/1`-only reader does with a `/2` package

A `/1`-only reader is any release before this revision: `1.0.0-rc.1` and the builds of `next` up to it. Checked
on both, with a `/2`-tagged copy of a valid `/1` inception package and with one that also carries an extra member:

- `package show <file>`: `malformed-package`, "not an external-signing package", exit 2.
- `key sign --package <file> --key <keyfile>`: the same refusal, exit 2; no signature file is written.
- `key sign --package <file> --ledger …`: the package check runs before the device is opened, so the same
  refusal, exit 2; the device is never asked anything.
- `<command> --complete <file> --signature …`: the same refusal, exit 2, scoped to `--complete`; nothing appended.

It refuses at the `format` member, before it reads the envelope, so it never computes a summary, never shows a
PAE as if it were checked, and never signs. That is the required behaviour, and no change to a `/1`-only reader
is needed to get it. Its wording is imperfect ("not an external-signing package" where "a newer package format"
is meant). A `/2` reader does better for the next revision: a `format` of the shape `rc-signing-package/<n>`
with `n` above the highest it reads is refused as `unsupported-package-format`, exit 2, naming the tag and saying
that this machine needs a release that reads it. `rc-signing-package/0` stays refused as retired.

### 2.2 The tag follows from the envelope

A `/2` writer writes:

- **`rc-signing-package/1`**, byte for byte as today, for the four `/1` actions (inception, grant, cut, act);
- **`rc-signing-package/2`** for every action this note adds (bare-key statements, key events, recovery statements).

A reader refuses a package whose tag is not the one its envelope determines (`package-format-mismatch`, exit 2):
a `/2` package of an inception, or a `/1` package of a key event. Reasons:

- A signing machine is the machine upgraded least often (it may be air-gapped). Keeping the four existing actions
  on `/1` means a signing machine on `1.0.0-rc.1` goes on signing everything it signs today for a store on any
  later release; it needs an upgrade only to sign what it never could.
- One package form per statement, as there is one stored signature encoding per signature: no reader has to decide
  whether two packages that differ only in their tag are the same request.
- The same rule carries forward: a later `/3` would leave `/1` and `/2` actions on their tags.

Rejected: writing `/2` for every action (one writer path, but every signing machine would have to be upgraded at
once, for no gain in what it can check).

### 2.3 The `/2` vocabulary is closed

`/2` carries exactly the actions in this note. A `/2` reader refuses a `/2` package whose envelope is any other
statement (`package-kind-unsupported`, exit 2) before computing a summary. A statement kind added later takes a
new tag. Rejected: an open `/2`, where a later release adds kinds under the same tag and older `/2` readers refuse
them. It is also safe (they refuse), but it breaks the frozen promise in a quieter way: "reads `/2`" would no longer
say which packages a release can sign, and a holder would learn it only from a refusal at the signing machine.

## 3. What a `/2` package carries

### 3.1 Members

A `/2` package is one JSON object, written canonical (JCS) and newline-terminated, with exactly the `/1` members
plus one:

| member | type | value |
|---|---|---|
| `format` | string | `rc-signing-package/2` |
| `envelope` | object | the unsigned statement, every member but `sig`: an `rc/1` envelope (a bare-key `rc/1` statement or a key event) or an `rc/2` envelope with the identity marker and **no actor**. The only source of every derived member below |
| `pae` | string | the exact signed string (wire §2 PAE of the envelope, under the envelope's own major), standard base64 with padding |
| `alg`, `signer`, `statement` | string | as `/1`: the envelope's `alg` and `signer`, and the proposed statement id (sha256 of the PAE) |
| `log_head` | string or object | as `/1`: `"genesis"` when `prev` is null, else `{"seq": seq - 1, "statement": prev}` |
| `log_tips` | array | **new.** The tips of the signer's log this store held when the package was prepared: a sorted, duplicate-free set of statement ids, `[]` when it held no line of the key |
| `summary` | object | tokens and envelope values only (§6) |

Every member but `log_tips` is derived from the envelope, and `package show`, `key sign` and `--complete`
recompute and compare each, as for `/1`. `log_tips` is not derived from the envelope: it records what the store
held when the holder reviewed the plan. A signing machine with no store checks its shape only (a sorted,
duplicate-free set of statement ids; it cannot check that the envelope's `prev` and `merges` lie under them) and
displays it as "prepared against these tips; the store checks them". `--complete` compares it with the store (§3.3).
For a statement whose effect does not depend on other branches (§3.3, first row) it is written all the same, so
every `/2` package has one shape, and `--complete` does not compare it.

`log_tips` is **not a security boundary.** It is not signed, and whoever can edit the package on the store's
machine can make it match. The boundary is the signed bytes, which already fix `seq`, `prev` and `merges`, and the
rebuild check of §3.3. `log_tips` exists so that an honest store refuses to append a key event whose effect on
the log changed after the holder reviewed it (§4.2); editing it cannot make a changed statement pass, because the
statement is rebuilt from the store's current state and compared byte for byte.

The "prepared form" rule of `/1` carries over: the envelope must be exactly what `--prepare` writes for the
statement it reads as, so a package cannot smuggle an inert member a reader would ignore. Two differences: a
key event's envelope may carry `merges` (they are part of the plan, §4), and an `rc/1` envelope is checked
unsigned under the `rc/1` rules (today's unsigned check reads `rc/2` only, and is extended, not loosened).

### 3.2 The bare-key binding

A bare-key statement is signed by the key itself, with no actor, so the package binds it to nothing but the
key's own log: `seq` and `prev` in the envelope, which the signature covers. The binding is the same as `/1`'s
for an identity act: the envelope extends the one tip the store holds (a fork is refused at `--prepare` unless
`--prev` names the line, as for direct signing), and `log_head` says which line. Nothing about an identity is
bound, because there is none; the statement's other references (a `resource`, an edition's `predecessors`) are
in the body and covered by the signature.

**Which bare-key statements `/2` carries: `edition` and `withdraw_approval`**, in either major: `rc/2` marker-only
for a resource whose genesis is `rc/2` (so the approval shares its edition id with an identity's approval of the
same body), `rc/1` for a resource whose genesis is `rc/1`, exactly as `publish` chooses today. These are what a
controller key exists to sign (#266, reason 2). Every other bare-key kind (`authored`, `observed`, `holds`,
`describes`, `anchors`, task acts, a `genesis`) stays without a package route in `/2`: a device-held key that
publishes claims does so as a delegate of an identity, through `publish --as`, which `/1` already carries. This is
a decision for review (§9): adding the other kinds is mechanical, but each is one more summary to define and freeze.

### 3.3 The staleness rule, by action

`--complete` always rebuilds the statement from the package's inputs over the statements the store holds now
and refuses unless it is the prepared envelope byte for byte (`stale-prepare`, exit 1, appending nothing), as
`/1` does. What else counts as "the log moved" depends on what the statement's effect depends on:

| action | `--complete` refuses (`stale-prepare`, exit 1) when | why |
|---|---|---|
| bare-key `edition`, `withdraw_approval` | the signer's log is not at `log_head` (as `/1`) | the line is ordinary; its effect does not depend on other branches |
| key event (`revoke_key`, `rotate_key`) | the tips the store holds now are not `log_tips`, **or** the log is not at `log_head` | a key event cuts every line outside its history (claims-model §4.1): a line or tip that arrived after the review would be cut, or kept, without the holder having seen it (§4.2) |
| recovery: `identity_succession` | the new root's log is not empty | it must be that key's `seq` 0 |
| recovery: `identity_recovery` | the recovery key's log is not empty | a recovery key signs one statement; a held line of it is a rival recovery, and an alarm (§5) |
| recovery: `identity_handover` | never refused for a moved root log; it warns that the handover forks the root's log | a handover is judged by signature, not by its place in the root's log, so a thief extending the root's log must not be able to block a recovery (§5) |

A signature made over a stale package is not destroyed by the refusal: it is a valid signature over valid bytes,
sitting in a file. For an ordinary line that matters little (it is one more line of the key's log if it is ever
published). For a key event it matters: a key event signed on an old head, published later by anyone who holds
the signature file, cuts the lines signed since. So the refusal names this, and the guidance is to delete the
signature file of a refused key event unless it is kept on purpose as an escrowed revocation (§4.3).

## 4. Key events: `revoke --prepare`, `rotate --prepare`, and `--complete`

### 4.1 Prepare: the plan is made where the log is

`revoke` and `rotate` gain `--prepare <file> --signer <key>` and `--complete <file> --signature <file|->`, with the
`/1` option rules (`--prepare` takes no `--key`, no `--ledger`, no `--dry-run`; `--complete` takes its inputs from
the package). `--prepare` runs the command's whole planning step exactly as direct signing does, over the store
the command runs on, and stops where it would sign:

- **Placement:** `prev` is the one tip, or the line `--prev` names; on a forked log a hard revocation asks for
  `--prev`, a soft revocation or rotation picks a tip as it does today or asks. A key with no line held here gets
  `seq` 0 and the same `warning_key_not_held` as `--ledger` (a first-line key event is valid, so a warning, not a
  refusal). `--expect-signer` is not needed: `--signer` names the key, and the signing side refuses any other
  (`key sign` checks the key file's signer, `key sign --ledger` the device's address at the path, before anything
  is signed). So the mistake #268's hand run found, a wrong path or passphrase giving another key, is caught on
  this route by the signing side; what is left is a wrong `--signer`, which the warning names.
- **Merges:** by reason, as today: a soft revocation and a rotation merge every held tip (C-core-127c's refusal
  of a tip whose branch carries another key event included); a hard revocation merges only what `--merge` names.
- **`last_good`:** required for a hard reason, checked to lie in the revocation's own history.
- **What the holder reviews:** every tip with what happens to it, the lines that stop counting, and
  `grants_not_closed`, as the direct command prints them. Unlike the `--ledger` dry run, `--prepare` can list the
  lines that stop counting, because it reads the unsigned statement's effect (the effect of a key event does not
  depend on its signature; computing it from the unsigned envelope is an implementation change, not a format one).
- **Rotation:** the successor checks run (not the signing key itself; the successor's log holds no key event).

It then writes the package (`log_head` and `log_tips` from the same view the plan was made from) and appends
nothing. The plan the holder reviews is printed by `--prepare` on the store's machine, and the package's summary
carries its result, `merges` and `last_good` included (§6), so the signing machine shows what the plan decided
even though it cannot recompute it.

### 4.2 Complete: the plan is checked again before appending

`--complete` checks the package (§3.1) and the signature over the recomputed PAE, takes the writer lock for the
signer, and then, before anything is appended:

1. **The tips are the reviewed ones.** The tips of the signer's log held now must equal `log_tips`. A new line,
   a new branch, or a line that filled a gap (a detached line that now chains) changes the tips; each refuses
   `stale-prepare`, exit 1, naming what changed. This is the check `/1` does not need: for an ordinary line,
   a new branch beside it changes nothing about it; for a key event it changes what is cut.
2. **The plan is rebuilt.** The command's planning step runs again with the package's inputs (reason,
   `last_good`, merges as prepared, successor, note), and the statement it would sign must be the prepared
   envelope byte for byte. Every refusal of direct signing applies: a key event that is now outside the history
   (a key event held now in the history being extended, so a rotation counts toward nothing), a successor whose
   log now carries a key event.
3. **The line is verified and committed** through the same commit unit as direct signing. It is byte for byte
   the line the key's file or the Ledger signs for the same plan and `--ts`.

Every refusal appends nothing. The writer lock is held from step 1 to the commit, as for every writer. It is not
held across the signing itself: the signing happens elsewhere, minutes or days later, so the package (its
`log_head`, `log_tips` and the rebuild) does the job the lock does for `revoke --ledger`, where #268 keeps the
lock held through the device's approval for exactly this reason (a key event signed on a stale head).

Why refuse on any change of tips, and not only on a change that alters the plan: a change that leaves the
statement byte-identical can still change what it does. A hard revocation keeps only `last_good`'s history; a
branch that arrived after the review is cut, which may be the point (a thief's branch) or a loss (the owner's
own second machine). The holder approved a list of tips and what happens to each; only that list is consented to.
Rejected: refusing only when the rebuilt statement differs (it would append a revocation whose consequences the
holder never saw).

### 4.3 Escrowed revocations and the refusal

An escrowed revocation (a `revoke_key` signed early and kept offline, to be published if the key is lost) is
prepared like any other, and its signature is kept instead of completed. When it is completed later, the log has
usually moved, so `--complete` refuses it. That is the right default for a fresh revocation and the wrong one for
an escrowed one, which is meant to be published over whatever the log has become: it was signed on an old head on
purpose, and every line after it stops counting, as its signer intended.

Proposed: `--complete --escrowed` skips checks 1 and 2 (it still verifies the signature, checks the package, and
reads the line as every reader reads it), and its output lists every line that stops counting before appending.
It is refused for anything but a `revoke_key`. Rejected: no escrow route (the holder would then publish the signed
line by hand, which bypasses every check and every listing; publishing it through the command is safer than not
offering it). Rejected: making escrow the default (a fresh revocation completed over a moved log would then cut
silently). An escrowed revocation needs the whole line, so the package and the signature file are kept together;
`--complete` takes both, as for any package. Whether a separate "assemble the signed line from a package and a
signature" command is worth having for escrow kept outside any store is left to review (§9).
