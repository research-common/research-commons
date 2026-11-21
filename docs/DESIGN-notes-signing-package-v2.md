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

## 5. The recovery statements

This section depends on the recoverable-root proposal (`recoverable-root-v1`), which is itself a proposal: its
kinds and members are working names, and so are the package actions below. If that profile changes, this section
changes with it. If it is not adopted, this section is dropped and the rest of the note stands.

### 5.1 Three statements, three packages, one envelope form

A recovery takes three signatures by three keys, in order (that proposal's §4): the successor root R′ signs its
`identity_succession` D′ (`seq` 0); the recovery key C signs the `identity_recovery` naming D′; the current root R
signs the `identity_handover` carrying the signed recovery. Each is one statement by one key over one PAE, so each
fits the `/2` envelope as it stands: an `rc/2` envelope with the identity marker and no actor. **No new package
member and no package-level kind marker is needed:** the envelope's `kind` already names the statement, and the
summary's `action` token (§6) is what a reviewer reads. Rejected: a separate package format, or a `recovery`
member, for recovery. Either would be a second shape for what is, byte for byte, a single-signer statement.

**The handover carries two signatures, and only one is made from its package.** The handover's body holds the
whole signed recovery statement, C's signature included; R's signature covers that body. So the handover's
package is prepared only once C's signature exists: its envelope contains the signed recovery, and its PAE covers
it. The signing device for R signs R's PAE only. The two signatures never meet in one signing step, which is what
the profile wants (no machine needs both keys).

The commands are the recovery proposal's to name; the package needs only this order:

1. `--prepare` the succession with `--signer R′`; sign it; `--complete` it. (R′'s log must be empty: §3.3.)
2. `--prepare` the recovery with `--signer C`, naming the identity, `last_good`, the successor (R′ and D′, which
   must be held) and the next commitment; sign it with C (on its device, or from the typed phrase on an offline
   machine, recovery proposal §7.3); `--complete` it, which commits the recovery statement to the store. Alone it
   does nothing (rule 2 of that proposal); held, it is the input to step 3.
3. `--prepare` the handover with `--signer R`, naming the recovery statement held in step 2; sign it with R;
   `--complete` it.

Rejected: one package carrying all three statements. A package carries one statement and one PAE, which is what
makes the signing side simple and auditable, and the three are signed in a fixed order by three different keys
on what should be three different machines or devices.

### 5.2 What the signing side can check with no store

For the recovery and the succession, the same as for any package: the PAE, the id and the summary are recomputed
from the envelope. For the handover, more: the carried recovery is a complete signed statement inside the
envelope, so `package show` and `key sign` verify its signature, check that it names the same identity as the
handover, and compute **the recovery key's commitment** (the profile's commitment digest of the carried
statement's signer). The summary carries that commitment, and the review asks the holder to compare it with the
commitment they recorded at setup (the inception holds it; the signing side cannot read the inception). A carried
statement whose signature does not verify, or that names another identity, makes the package malformed (exit 2)
on every command, before any signing.

### 5.3 Staleness for recovery statements

As §3.3 says: the succession and the recovery are `seq` 0 statements of fresh keys, so `--complete` refuses if
either key's log is not empty here (for C, a line held means a second recovery by the same key exists somewhere,
which is a rival in the making and reported as such). The handover is **not** refused for a moved root log. The
profile judges a handover by its signature and the statement it carries, not by its place in R's log, because a
thief holding R can keep extending R's log; refusing on a moved head would let that thief block the recovery. So:

- the handover is prepared at R's current tip (or `--prev`);
- at `--complete`, if that line is no longer a tip, the handover is appended where it was prepared, as a fork of
  R's log, and the output says so (a fork is disclosed by every read command, as today);
- the rebuild check still runs: the identity, the carried recovery and every reference must still read as they
  did at `--prepare`.

**A rival recovery held at `--complete`.** If the store holds another complete handover for the same root with a
different effect, appending this one retires the identity for good (profile rule 5). That may be the right move
(a thief who holds both keys has already published a recovery that hands them the identity, and a rival is the
only answer left), but it must never happen by accident. Proposed: `--complete` refuses (exit 1, naming the rival)
unless `--retire-on-rival` is given. The same check runs at `--prepare`.

## 6. Summary and review for each new action

As in `/1`: `summary.action` is a token, every other member is a value copied or computed from the envelope (a
member the envelope lacks is `null`), and the summary holds no prose. The words a human reads beside it are
rendered at display time by `--prepare`, `package show` and `key sign` (with or without `--ledger`), so a package
reads the same under every release that reads `/2`. Every `/2` summary carries `major` (`"rc/1"` or `"rc/2"`,
the envelope's `rc`), because the same kind is a different statement in each major (an edition's id domain, wire
§3), and a reviewer approving a controller's edition should see which.

| `action` | other members | review rendered at display time (working wording) |
|---|---|---|
| `approve` | `kind` (`edition` or `withdraw_approval`), `major`, `resource`, `edition` (the edition id the signature approves or withdraws: for an `edition`, computed from its body under the envelope's major; for a `withdraw_approval`, its `body.edition`), `predecessors` (an `edition`'s, else `null`), `controllers` and `rule` (an `edition`'s `contents`, when it changes them; else `null`) | "approve edition E of resource R as the bare key S" / "withdraw S's approval of edition E"; when `controllers` is not null: "this edition changes who controls the resource" and the new set |
| `revoke` | `major`, `reason`, `reason_class` (`hard` or `soft`, by the wire note's rule: an unknown token is `hard`), `last_good` (`null` when absent), `merges` (the envelope's, `[]` when none), `tips` (= the package's `log_tips`) | "revoke the key S: every line of S outside this revocation's history stops counting, for every reader that holds it; this cannot be undone"; hard: "only last_good and its history keep counting" (`last_good` null: "no line of S counts any more"); soft: "S's history keeps counting" |
| `rotate` | `major`, `successor`, `merges`, `tips` | "retire the key S and name SUCCESSOR as its successor: S signs nothing more that counts; the successor inherits no claims; this cannot be undone" |
| `succession` | `identity`, `root` (the signer: the new root R′) | "make S the next root of identity I; this is S's first line, and a key is an identity's root at most once" |
| `recovery` | `identity`, `last_good`, `successor` (key), `successor_inception` (D′), `next_commitment` (or `null` when the identity is closed) | "as the recovery key of I: replace its root with SUCCESSOR, keep the current root's lines up to LAST_GOOD and void every other one, whenever signed; a recovery key signs once"; `successor` null: "close the identity: its kept history counts; nothing new can be administered" |
| `handover` | `identity`, `recovery` (the carried statement's id), `recovery_signer`, `recovery_commitment` (computed, §5.2), and the carried statement's `last_good`, `successor`, `successor_inception`, `next_commitment` | "as the current root of I: hand I over under the recovery above"; "compare recovery_commitment with the commitment recorded at setup"; "a second, different recovery of this root retires I for good" |

**Why the tips are in a key event's summary.** On the signing machine, the summary is all the holder sees of the
plan. A revocation's bytes name `prev` and `merges` but not what they leave out; the tips the store held are what
make "these branches are cut" visible. They are copied from `log_tips`, which the signing side cannot check
against a store, so the review says "the store this was prepared on held these tips; `--complete` refuses if
that changed". The lines that stop counting are not in the summary: their number is unbounded, and `--prepare`
prints them on the store's machine, where they can be checked.

**On the device.** The Ledger Ethereum app shows the PAE, not the summary (§7). The summary and review are for
`package show` and `key sign` on the machine the device is attached to; a holder who trusts no machine reads
the PAE on the device and compares `pae_sha256` (or the EIP-191 hash) received by a separate channel, as today.

Rejected: a single `key_event` action with `kind` as a member (it would put "revoke" and "rotate" one member
apart in a summary whose purpose is to make them unmistakable). Rejected: prose in the summary (`/0`'s mistake:
the words of a package would differ between releases).

## 7. The new kinds on the Ledger Ethereum app

The connector stays as it is: EIP-191 `personal_sign` over the PAE bytes, the app showing the message as text
when every byte is printable ASCII, and as hex otherwise. Nothing in this note needs a new algorithm, preimage or
device app.

- **Key events read acceptably: checked on hardware.** #268's hand run, on a Ledger Nano X with the Ethereum app
  1.19.3, signed a `revoke_key` and a `rotate_key` through `revoke --ledger` and `rotate --ledger`, each approved
  on the device after review, each committed with `fsck` clean, and each checked outside the tool (the EIP-191
  signature recovers the device's address; the statement id is the SHA-256 of the PAE). A `revoke_key` PAE is
  short: the signed `revoke_key` vectors are 323 bytes (`key_compromise`, no `last_good`), about two screens'
  worth of chunks, as #266 estimated. A package changes nothing the device sees: `key sign --ledger` of a `/2`
  key-event package sends the same PAE bytes `revoke --ledger` sends today, so that result carries over.
- **Bare-key approvals read like the identity acts already drilled.** A marker-only `rc/2` edition is about 480 to
  550 bytes in the signed vectors, inside the range of the inception (321), cut (603) and grant (681) drilled
  through the package on the emulator and the device. An `rc/1` edition is a little shorter. Printable unless a
  body string carries non-ASCII text (a resource name in another script), which turns the display to hex, as for
  every kind today.
- **Recovery statements are the longest.** Estimated from the recovery proposal's working shapes with
  `eip191-secp256k1` keys: a succession about 380 bytes, a recovery about 710, a handover about 1,220 (it carries
  the whole signed recovery). All far below the app's measured limit (about 7.6 KB of printable text), but the
  handover is long to read on a device: the identity, the successor and the commitment are 64-hex values deep in
  the message. The review that matters is on the machine (§5.2: the commitment comparison) and the hash
  comparison on the device; a holder is not expected to read a handover screen by screen. Not checked on
  hardware: none of the recovery statements exists yet.
- **What a device does not protect.** The device's screen shows what is signed; it cannot show what a key event
  cuts. The tips and the lines that stop counting are visible only on the store's machine (`--prepare`) and in the
  summary on the signing machine. For a key event, the hash comparison proves the bytes are the prepared ones, not
  that the plan is the one the holder wanted.

## 8. Conformance cases to add, and KNOWN-LIMITS L-22

### 8.1 Cases

Proposed cases, with working handles `PKG-nn`. When the revision is implemented they are registered as rows of
the identity note's §10 table (as `C-id-` cases, so the harness counts them) or of a table of their own, a choice
for the implementation; until then they are not registered, and no test claims them. Each is checked through the
commands, with the signing side run on a machine that holds no store (as `TestPackageShowKeySignEndToEnd` does for
`/1`) and every refusal shown to append nothing (store bytes unchanged).

**Format and compatibility**

| Handle | Scenario | Outcome |
|---|---|---|
| PKG-01 | A `/2` package given to a `/1`-only release (`package show`, `key sign` with a key file and with `--ledger`, `--complete`) | `malformed-package`, exit 2, before the envelope is read; nothing signed, no device asked, nothing appended. (Recorded today against `1.0.0-rc.1`, §2.1; kept as a fixture so the claim stays checked.) |
| PKG-02 | A `/1` package of each of the four `/1` actions, prepared by `1.0.0-rc.1`, completed by a `/2` release (and signed by a `/2` `key sign`) | accepted; the committed line is byte-identical to the one `rc.1` commits from the same package and signature |
| PKG-03 | Tag/envelope mismatch: a `/2`-tagged inception package; a `/1`-tagged key-event or bare-key package | `package-format-mismatch`, exit 2, on every command; nothing signed |
| PKG-04 | A `/1` package carrying an actor-less `rc/2` envelope (a marker-only edition) | `malformed-package`, exit 2 (today: internal error, exit 3; §2) |
| PKG-05 | A `/2` package whose envelope is a kind `/2` does not carry (`authored` bare, `anchors`, `genesis`) | `package-kind-unsupported`, exit 2, before a summary is computed |
| PKG-06 | `format` `rc-signing-package/3` | `unsupported-package-format`, exit 2, naming the tag |
| PKG-07 | A `/2` package with an inert extra envelope member, an extra package member, `log_tips` unsorted or duplicated, or any derived member changed | each refused, naming the member (exit 2 at `--complete`, exit 1 on `package show` and `key sign`, as `/1`) |

**Bare-key statements**

| Handle | Scenario | Outcome |
|---|---|---|
| PKG-10 | A controller key held apart signs, through the package, an `rc/2` marker-only edition of a two-subject resource | committed line byte-identical to direct signing at the same `--ts`; the edition id equals the identity approval's; the approval fills the `{key: K}` slot |
| PKG-11 | As PKG-10 for an `rc/1` resource, and for a `withdraw_approval` | as PKG-10; the withdrawal applies |
| PKG-12 | The signer's log moves (one more line) between `--prepare` and `--complete` of a bare-key edition | `stale-prepare`, exit 1, nothing appended; `--prev` naming the prepared line forks deliberately and is disclosed |
| PKG-13 | An edition package whose resource's current edition moved between prepare and complete (another controller approved) | the rebuild runs every check of direct signing; refused exactly when direct signing would be refused |

**Key events**

| Handle | Scenario | Outcome |
|---|---|---|
| PKG-20 | `revoke --prepare --reason key_compromise --last-good L` by a key held apart; `key sign`; `--complete` | committed line byte-identical to `revoke --key` (and to `revoke --ledger`) for the same plan and `--ts`; `fsck` clean; lines outside L's history stop counting |
| PKG-21 | `rotate --prepare`, as PKG-20 | as PKG-20; the successor checks ran at prepare and again at complete |
| PKG-22 | A new line of the key arrives between prepare and complete, extending the prepared head | `stale-prepare`, exit 1 (the log moved) |
| PKG-23 | A new branch arrives (a line forking below the prepared head), the head unchanged | `stale-prepare`, exit 1, naming the new tip: the tips are not the reviewed ones, although the statement rebuilds identically |
| PKG-24 | A detached line of the key fills its gap between prepare and complete, changing the tips | `stale-prepare`, exit 1 |
| PKG-25 | A soft revocation whose merged tip, between prepare and complete, gains a branch carrying another key event (C-core-127c) | refused at `--complete` with direct signing's refusal; nothing appended |
| PKG-26 | A rotation whose successor's log gains a key event between prepare and complete | refused, exit 1, as direct signing |
| PKG-27 | `--complete --escrowed` of a hard `revoke_key` prepared at seq n, completed after the log reached n+5 | appended; the output lists the five lines that stop counting; the same package without `--escrowed` is `stale-prepare` |
| PKG-28 | `--escrowed` on a `rotate_key` or a bare-key package | refused, exit 2 |
| PKG-29 | `revoke --prepare` for a key the store holds no line of | package written, `warning_key_not_held`; `key sign --ledger` at a path whose address is another key refuses before signing |
| PKG-30 | The summary of a revoke package: `reason_class` for `key_compromise`, `superseded` and an undocumented token; `tips` equal to `log_tips` | `hard`, `soft`, `hard`; the summary is recomputed from the envelope plus `log_tips` and any edit is refused |

**Recovery statements** (only if the recoverable-root profile is adopted)

| Handle | Scenario | Outcome |
|---|---|---|
| PKG-40 | The three-package recovery: succession, recovery, handover, each signed by a different key held apart | the identity reads recovered at the next generation; each line byte-identical to direct signing |
| PKG-41 | A handover package whose carried recovery's signature is altered, or which names another identity | malformed, exit 2, on `package show`, `key sign` and `--complete`; nothing signed |
| PKG-42 | The root's log gains lines (a thief extending it) between preparing and completing the handover | appended as a fork of the root's log, disclosed; not refused |
| PKG-43 | A rival complete handover with a different effect is held at `--complete` | refused, exit 1, naming the rival; with `--retire-on-rival` appended, and the identity reads retired |
| PKG-44 | A recovery package whose recovery key already has a line held | `stale-prepare`, exit 1, naming the held line as a possible rival recovery |
| PKG-45 | `package show` of a handover | prints `recovery_commitment` computed from the carried statement's signer, equal to the inception's commitment |

### 8.2 KNOWN-LIMITS L-22: end state

Today L-22 reads: a bare-key statement cannot be signed by a device, and a key event can be signed by a device
only on a Ledger attached to the store's machine. With this revision implemented:

- **The package half closes.** A bare-key `edition` and `withdraw_approval`, and a key's `revoke_key` and
  `rotate_key`, can be signed by any key held apart: on another machine (a key file, `key sign`), on a Ledger
  (`key sign --ledger`), or by any signer that signs the PAE bytes (`package show --pae-out`, as a YubiKey does
  through its OpenPGP applet, #250). L-22's probe (`revoke --prepare` and `rotate --prepare` exit 2
  `unknown-option`; `publish --prepare` of a `revoke_key` exits 2) then finds the gap closed, and the row is
  removed in the same change, as the limits test requires.
- **What stays open moves, not into L-22:** bare-key kinds other than approvals have no package route (§3.2): a
  new, narrower row if that decision stands (probe: `publish --prepare --signer` of a bare `authored` exits 2).
  A device other than a Ledger still has no connector (L-07): it signs through `--pae-out`, which is a route, not
  a connector.
- **Recovery:** the recovery statements are new kinds of a new profile; their package route lands with the
  profile, and no limit row is needed for something that does not exist yet.
