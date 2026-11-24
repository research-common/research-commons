# Recoverable-root identity profile (`recoverable-root-v1` on `rc/2`): proposal

**Status: the reader is implemented; no writer is.** The reader (`1.0.0-rc.2`, pull request for issue #274)
evaluates this profile as §5 states it, with the scenarios of §6 as its conformance cases (§10, C-id-46 to
C-id-76). No command writes a `recoverable-root-v1` inception or any of the three kinds: readers ship one
release before writers, as they did for the fixed-root profile, so an identity made under this profile today
would be read everywhere before anything could make one. The names in §4 are the ones the reader uses. The note
is written compromise matrix first and scenarios second, and only then the vocabulary, so the rules can be
judged before their encoding. It builds on the fixed-root profile (`DESIGN-notes-fixed-root-identity.md`, "the
fixed-root note") and changes nothing in it.

## 1. Why

The fixed-root profile gives one principal one root key R and nothing above it. Its §1 states the price:
"Root compromise is total and retroactive", because "nothing stands above R to say when R was taken".
Resilience was therefore moved to the resource layer: "Hub resources should list an independent second
controller subject." (fixed-root note §8). In use, that advice has three costs.

1. One operator ends up running two or three identities, or an identity and spare keys, only to survive the
   loss of one of them.
2. The controller set is chosen in each resource's genesis and is hard to change later. An edition that adds
   controllers is approved by the identity alone, so a later root revoke voids that edition too, and the
   resource falls back to its original controllers. The choice is a one-way door at creation.
3. A reader sees several subjects approving an edition and cannot tell an operator's backup scheme from
   independent parties agreeing.

This profile puts recovery inside the identity: **one identity, one root, and one cold key that signs nothing
until the day it is needed.** A resource names one identity again, and keeps naming it across a recovery.

It does not replace several controllers where those are different parties, or where an operator wants an
edition to need two approvals of different kinds (an agents' identity and a human-held one). Controllers
count subjects, so two delegates of one identity are one approval; that already works and is unchanged.

### Why the two earlier objections do not apply

- **A thief can sign a rival first line** (issue #100). That is true of a bare key, which is named by its
  public key. An identity is named by the statement id of its inception, and "a different inception, even
  for the same public key, is a different lineage" (fixed-root note §3). A recovery commitment written
  inside the inception is part of the identity's name. A thief's inception with another commitment is
  another identity, which nobody named.
- **Nothing stands above R.** With a committed cold key, something does: a key the thief of R does not hold
  can say which of R's lines were the owner's, exactly as R says it of a worker's lines when it cuts a grant.

## 2. Rules in one page

1. The inception commits to a **recovery key** by digest. The key itself stays unpublished and signs nothing.
2. A **recovery** takes both keys: a statement by the recovery key, carried inside a statement by the
   current root. Neither key can do anything to the identity's history by itself, with one exception (rule 6).
3. A recovery names a **last good line** of the root's log. The root's lines at or before it keep counting.
   Every other line of that root counts for nothing, whenever it was or will be signed.
4. A recovery names a **successor root** and the **next recovery commitment**. The identity id is unchanged.
   A recovery key is used once, a key is an identity's root at most once, and a recovery key is never one
   of the identity's roots.
5. Two complete recoveries of the same root that differ in any effect **retire the identity for good**. No
   clock, arrival order or first-seen rule decides between them.
6. The root alone can still **retire** the identity with a raw `revoke_key`, as today. Unlike today, a later
   recovery whose kept prefix excludes that revoke undoes it. A recovery whose kept prefix includes it is void. (Otherwise a thief of the root could always
   destroy the identity.)
7. Everything else is the fixed-root profile: grants, cuts, permissions, delegate consent, evaluation and
   uncertainty rules. "The root lineage" becomes "the kept prefix of each earlier root, then the current
   root's lineage".

## 3. Compromise matrix

R is the current root, C the committed recovery key. "Copy" means the owner still holds the key.

| Event | Thief can | Owner can | Outcome |
|---|---|---|---|
| A delegate key is stolen | act under its grant | cut the grant at a last good line | As fixed-root. |
| R stolen, owner keeps a copy of R and holds C | grant, cut, revoke R, fork R's log, until recovery | recover: name the last good line and a new root | **Recovered.** History up to the last good line is kept; the thief's lines are void, a revoke included. A thief line the owner places inside the kept prefix keeps counting, as with a cut. |
| R lost, no copy | nothing | nothing | **Not recoverable.** Administration is frozen; existing grants keep working; nothing can be cut or retired. Same as fixed-root. This follows from rule 2 and is why R needs a backup. |
| C stolen, R safe | nothing | plan a recovery at leisure | **Nothing happens.** C alone is inert. |
| C lost, R safe | nothing | nothing about C | The identity behaves as a fixed-root identity from then on. The loss is silent unless checked (§7.3). |
| R and C both stolen, owner keeps copies | recover to their own root | recover to the owner's root | Two rival recoveries: **retired for good** (rule 5). Never a takeover the owner cannot answer. |
| R and C both stolen, owner keeps no copy of one | recover to their own root | nothing in-band | **Takeover.** Resources must drop the identity by other means. |
| R and C both lost | nothing | nothing | Frozen, as fixed-root. |
| After a recovery, the old R and old C are both obtained by someone | sign a rival recovery of the old root | nothing in-band | **Retired for good**, even years later (rule 5). After a recovery the used recovery key and its backup must be destroyed; the old root is assumed stolen already. See §9 on why time does not decide. |
| A reader holds only part of the evidence | n/a | n/a | A reader that lacks the recovery reads the pre-recovery state, as it reads an identity today without a cut it has not received. A reader that holds a valid recovery but lacks a line it names reads unknown. |

Compared with the fixed-root profile, the common disaster (the root's device or backup is compromised) goes
from "new identity, successor resources" to one ceremony. The new ways to lose need **both** keys, with one
exception that needs the root and a file: a recovery statement the recovery key signed and the owner never
published (RR-27, §7.3). Whoever holds it and the stolen root can retire the identity for good.

The standing cost of rule 5, stated once more because it is the design's weakest point: for as long as a
used recovery key or any copy of it exists, the identity is one theft of that old pair away from retirement.

## 4. Vocabulary

All are `rc/2` statements with the `x_identity_v1` marker, raw-key signed, and take no actor.

| Kind | Signed by | Body besides the marker | Notes |
|---|---|---|---|
| `identity_inception` | R, `seq` 0 | `profile:"recoverable-root-v1"`, `recovery:{commitments:[c], rule:{any_one:true}}` | The id is I. The commitment is required: an identity that wants none uses `fixed-root-v1`. |
| `identity_succession` | the new root R′, `seq` 0 | `identity:I` | R′ consents and pins its own lineage, as a delegate's first line does for a grant. R′ must be a fresh key. |
| `identity_recovery` | C, `seq` 0, `prev` null | `identity:I`, `last_good:L-or-null`, `successor:{key:R′, inception:D′}` or null, `next:{commitments:[c], rule:{any_one:true}}`, optional `note` | C's only statement. It carries no reason token: a recovery has one meaning, and a free-text `note` is enough for the record. `successor:null` closes the identity with its history kept (§5, RR-11); `next` is then absent. |
| `identity_handover` | R | `identity:I`, `recovery:<the whole signed identity_recovery>` | R's half of rule 2. It carries the recovery statement, not its id (below). |

**The commitment** is a digest of the recovery key's public form under its own domain string, so it can be
confused with no statement id or content digest: lowercase hex SHA-256 of
`PAE("application/vnd.research-commons.recovery-commitment.v1", <signer string>)`. Publishing a digest and not
the key keeps the key's public form unknown until use (decided, §9). The signer string is the canonical one
of the wire format (its §4): `ed25519:` plus 64 lowercase hex, or `0x` plus 40 lowercase hex. A checksummed
or upper-case address is not a signer string, so a tool that reads an address from a device lowercases it
before computing the commitment, and `recovery check` recomputes from the key, never from a displayed form.

**The recovery key is no root of the identity.** A carried recovery signed by a key that is, or was, a root
of this identity, or by the successor it names, is void (RR-30). Without this rule a commitment to the
root's own key would let the root alone sign both halves of a recovery: the statement need only be a second
`seq`-0 line of that key.

The rule also runs forward: **a key this identity has committed to as a recovery key never becomes its
root.** A handover whose successor is such a key is void, whether the commitment is an earlier one (a spent
recovery key, every copy of which §7.3 says to destroy) or the `next` of the same recovery (RR-31). The
reader already keeps the set of commitments the identity has used, for RR-15; it compares the successor's
commitment against that set and against `next`.

**One recovery key (decided).** This version reads exactly one commitment under `any_one`. The member is
written as a set with a rule so that a later version can add a threshold without another profile; a reader
of this version reads any other count or rule as unsupported for the whole identity, never as "any one of
them". A holder who wants redundancy keeps backup copies of the one key.

**Why the handover carries the statement.** If it named the recovery by id, a thief holding only R could sign
a handover naming an id that does not exist. A reader cannot tell "not received" from "never existed", so the
identity would read unknown, and a real recovery could never clear it, because the unreadable handover might
be a rival. Carrying the signed statement makes a handover either void (the carried bytes do not verify
against the commitment) or complete, from its own bytes. This came out of the model, not out of prior art.

That argument depends on the **order of the checks**, which §5 fixes: the commitment is compared first. It
is a digest of the carried statement's signer string, so a reader can compute it whether or not it supports
the statement's algorithm. A holder of R alone cannot match it (the recovery key's public form is hidden
until its first use), so whatever they carry is void. Only a statement by the committed key can read
unknown, and that needs both keys, or the root and a statement the recovery key signed and set aside
(RR-27).

**A handover is judged by signature, not by its place in R's log.** It is bound to the identity three ways:
it names I, R signed it, and the carried statement's signer matches the commitment in force. So it applies
wherever it sits, including on a branch the recovery itself voids (decided, §9): a thief of the root can
fill the root's log with lines, and a recovery has to work all the same.

**Root generations.** The inception's root is generation 0. Each recovery with a successor starts the next
generation, whose root is R′, whose lineage starts at D′, and whose recovery commitment is `next`. A reader
evaluates generation by generation. The evaluation ends without help: a key is a root at most once and a
commitment is used at most once, so a chain of generations cannot loop, and it is no longer than the
statements held. Every reader follows at least 64 recoveries of one identity (decided, §9). A reader may stop at a limit
of its own above that; past its limit it reads unknown, never partial (RR-23).

**Signing order for a recovery:** R′ signs D′; C signs the recovery naming D′; R signs the handover carrying
it. Three signatures, each of which may come from a device through a signing package.

## 5. Evaluation

For identity I at generation g, with root R, lineage start D and commitment K:

1. Collect every `identity_handover` signed by R that names I, and judge each carried statement in this
   order:
   - a. Compute the commitment of its signer string. If it is not K, the handover is **void**, whatever the
     statement's algorithm and whether or not its signature can be checked. Void means reported, and
     changing nothing.
   - b. If the reader does not support the statement's algorithm, the identity is **unknown**. (Both
     required algorithms are supported by every reader, so this is a case for a later algorithm only.)
   - c. If it is not a valid `identity_recovery` for I at `seq` 0, with a signature that verifies, it is void.
   - d. If its signer is or was a root of I, or is the successor it names, it is void (RR-30).

   Also void: a handover whose `last_good` is a line of another key or another lineage, whose kept prefix
   (`last_good` and its ancestors) holds a raw root key event or a root line outside the closed vocabulary
   (RR-19, RR-25), whose
   successor statement is not that key's `seq`-0 `identity_succession` for I, whose `next` repeats a
   commitment already used by this identity, whose successor is a key that was already a root of this
   identity, or whose successor is a key the identity has committed to as a recovery key (a commitment
   already used, or this recovery's own `next`: RR-31). (A key is an identity's root at most once. Otherwise a recovery naming a former root would make
   that root's whole log current again, including lines an earlier recovery voided: RR-26.)
2. A valid handover that names a line the reader does not hold (the last good line, an ancestor of it, the
   successor's first line) makes the identity **unknown**. Unlike step 1 this needs both keys, so only the
   owner or a holder of both can cause it.
3. Take the distinct effects `(successor, last_good, next)` of the complete handovers.
   - **More than one:** the identity is retired for good. Nothing "as I" passes, at any generation.
   - **None:** generation g is current. R's lineage is read as the fixed-root profile reads it: a raw
     `revoke_key` or `rotate_key` on it retires the identity (a later recovery can undo this, rule 6); an
     in-lineage line whose ancestry is unresolved makes the identity unknown.
   - **One:** the kept prefix is `last_good` and its ancestors through `prev` and `merges`, plus D. R's
     administrative lines inside it count (grants accumulate, cuts apply). Every other line of R is void.
     If there is a successor, continue at generation
     g+1; if not, the identity is **closed**: its kept history counts and nothing new can be administered.
4. Grants of every generation are grants of I. The current root can cut a grant an earlier root issued. A
   recovery closes no grant by itself: the new root cuts the ones it no longer wants.
5. The answer is a function of the set of statements held. Delivery order cannot change it.

Everything a reader reports today (status, reasons, basis and missing ids, warnings, freshness
`not_established`) carries over, with the generation and the recovery statements added to the basis.

## 6. Scenarios

These were run through a small reference model of §5 before this note was written, and through a second model
written from the note alone during its review (issue #274). They are registered as conformance cases in §10 and
built from signed lines there.

| Handle | Scenario | Required outcome |
|---|---|---|
| RR-01 | Ordinary use | Current, generation 0; the root's grants count. |
| RR-02 | R stolen: the thief grants. The owner recovers with `last_good` before the theft, then grants with R′; the thief grants again with R | Before the recovery is read, the thief's grant counts. After: generation 1, the owner's old and new grants count, both thief grants are void. |
| RR-03 | The thief revokes R. The owner recovers | Retired, then current at generation 1. |
| RR-04 | A holder of R alone signs a handover carrying a "recovery" by a key of their own | Void; the identity is unchanged. |
| RR-05 | A holder of C alone signs a recovery | Nothing: no handover, no effect. |
| RR-06 | Both keys held by two parties; each completes a different recovery | Retired for good. |
| RR-07 | The same recovery is signed and handed over twice | One recovery. |
| RR-08 | A holder of R alone signs a root line with a missing ancestor; the owner then recovers | Unknown, then current: the line is outside the kept prefix. |
| RR-09 | A valid recovery whose `last_good` the reader does not hold | Unknown. |
| RR-10 | A root revoke signed at the first line and kept offline; the root goes on signing on another branch; the revoke is published; the owner later recovers with `last_good` on the working branch | Retired when the revoke is read; current again after the recovery. A reader that never receives the revoke sees ordinary use. |
| RR-11 | A recovery with no successor | Closed: kept history counts; later root lines are void. |
| RR-12 | A second recovery, by R′ and the second recovery key | Generation 2; kept grants of all three roots count. |
| RR-13 | After a recovery, the old R and old C sign another recovery of generation 0 | Retired for good. |
| RR-14 | A reader that holds everything but the handover | The pre-recovery state. |
| RR-15 | A recovery whose `next` repeats a commitment already used | Void. |
| RR-16 | R′ is revoked by its own key event | Retired at generation 1, recoverable by R′ and the second recovery key. |
| RR-17 | A delegate's acts across a recovery: (a) under a grant inside the kept prefix; (b) under a grant the recovery voids; (c) the new root cuts a grant the old root issued; (d) the old root signs a cut after the recovery | (a) Counts before and after. (b) Counted before the recovery is read, counts for nothing after, whenever the act was signed. (c) The grant is cut. (d) Void: the grant still counts. |
| RR-18 | `last_good: null` | Only the inception is kept: no earlier grant counts. |
| RR-19 | The owner names a `last_good` that has a root key event among its ancestors, then signs a second recovery with a `last_good` before it | The first recovery is void, so the raw event stands: retired, and a recovery can undo it (rule 6). The second is then the only complete one: current at generation 1. A void recovery is no rival. (The first version of this note read the first as retired for good. That made the owner's likeliest mistake permanent and gave a thief nothing they lacked.) |
| RR-20 | After a recovery, the old R is revoked | No effect on the identity. |
| RR-21 | Every subset of RR-02's statements | No subset reads generation 1 with a thief grant counting. |
| RR-22 | A complete recovery, plus a second valid one whose `last_good` is not held | Unknown: a possible rival is never passed over. |
| RR-23 | More recoveries than the reader's own limit (which is at least 64) | Unknown, with the limit as the reason. Never a guess at the current root. A chain of 64 recoveries is followed by every reader. |
| RR-24 | A handover whose carried recovery statement (a) is by the committed key and does not verify; (b) is by another key, under an algorithm the reader does not support; (c) is by the committed key, under such an algorithm | (a) Void. (b) Void: the commitment is compared first, so a holder of R alone cannot cause unknown. (c) Unknown; it needs both keys. |
| RR-26 | R is replaced by R′, a thief of R′ grants, R′ is replaced by R″ with `last_good` before that grant. A third recovery then names R′ as the successor | Void: R″ stays the root, and the thief's grant stays void. Found by the reference model after this note was first posted; the first version of §5 let the grant count again. |
| RR-25 | The root signs a statement outside its vocabulary (an ordinary `authored`, say: issue #271). Then (b) the owner recovers with `last_good` before that line, or (c) with `last_good` at or after it | Unknown, as in the fixed-root profile. (b) Current at generation 1: the line is outside the kept prefix. (c) That recovery is void, as in RR-19: still unknown, and a second recovery as in (b) clears it. |
| RR-27 | The recovery key signs recovery A; the owner abandons it and publishes a different recovery B with a handover. Later a holder of R obtains A's bytes and hands A over | With A's successor line held: **retired for good**, by R and a file, with no second key stolen. Without that line: unknown. A second signing with the same effect would have been harmless (RR-07). §7.3 says what the tool does about it. |
| RR-28 | An edition approved by a delegate under a grant that a recovery voids; another under a grant the recovery keeps | The first counted before the recovery is read and does not count after. The second counts both times. |
| RR-29 | A thief's grant extends the owner's tip; the owner, unaware, issues two grants after it. Route (a): `last_good` before the thief's grant. Route (b): `last_good` at the owner's tip, then the new root cuts the thief's grant | (a) The thief's grant is void, and so are the owner's two later grants and every act under them. (b) The owner's grants all count; the thief's counts until the cut is read, and not after. No set of statements that holds the recovery and the cut lets it count. |
| RR-30 | The commitment in force names (a) the root's own key, or (b) the successor root itself; that key signs a recovery and its handover | Void in both: the recovery key is no root of the identity. Without the rule, one key would recover alone. (Case (b) cannot arise from a recovery a reader accepts: RR-31 voids the recovery that would set it up.) |
| RR-31 | A handover names as successor (a) a recovery key the identity has already used (generations 0 and 1 recovered with C0 and C1; the third recovery names C1 as the new root), or (b) the key its own `next` commits to | Void in both: a key the identity has committed to as a recovery key never becomes its root. Without the rule, (a) makes the root a key whose copies were to be destroyed, with two `seq`-0 lines, and (b) leaves a root with no usable recovery key. An owner's mistake, not an attack: whoever does it holds both keys. |

The whole table is in the reference model. RR-25 matters beyond theft: today one mistaken command with the root key ends a
fixed-root identity (issue #271), and under this profile the owner can recover from it.

Still to write: what a collection's reader shows after RR-28 and RR-29 (an edition that stops counting, and
the editions built on it).

## 7. Setting up and holding the recovery key

Command names here are working names. The rules in this section are tool behaviour and guidance, not format:
the commitment covers a key, and a reader never learns how the key was made or kept.

### 7.1 One kind of recovery key, two ways to hold it

The tool makes one kind of recovery key: an `eip191-secp256k1` key at one fixed path under a 24-word BIP-39
phrase, with no BIP-39 passphrase. The path is `m/44'/60'/1581'/0/0` (decided): the shape the tool already
asks for with a device (`m/44'/60'/<account>'/0/<index>`), at an account number chosen to collide with
nothing in use. The number has no other meaning. Hardening the last two levels was considered and dropped:
it protects against a leaked extended public key, and none is published here. The path is printed with the
phrase, because a holder needs it to restore the key anywhere else.

**No passphrase on the printed phrase (decided).** A passphrase is a second secret, and losing it loses the
recovery key. What it would guard against, someone reading the paper, is already blunted: the recovery key
alone does nothing (rule 2). A holder who keeps the key on a device may still use the device's own
passphrase feature; the tool neither knows nor cares.

Because the key is derived the standard way, the two ways of holding it are interchangeable:

- **A printed recovery phrase** (the default). Nothing to buy; the key exists on a computer for a moment at
  setup and again at recovery.
- **A Ledger device** (the hardware option). The key never leaves the device. The device's own backup sheet
  is then the backup of the recovery key.

A phrase can be restored onto a device later, and a device's key at that path is the key its sheet derives.
Checked on a device emulator running the Ethereum app: the address the app reports at three paths under
`m/44'/60'`, one of them of this shape, equals the address standard BIP-39 and BIP-32 software derives from
the same phrase. The app refused a path under `m/43'`, so the path has to sit under `m/44'/60'`. Checked on
a physical device: it reports an address at `m/44'/60'/1581'/0/0`. Not checked: that the physical device's
address at this path matches software derivation from its phrase, a 24-word phrase (the emulator's test
phrase has 12), and whether the device warns when signing at this path.

The commitment accepts any supported key, so a holder can commit to a key made another way (an Ed25519 key
file kept offline, a key on a smart card). The tool does not build flows for those. A key generated on a
card that cannot export it has no backup, which §7.4 rules out.

### 7.2 Setup

Making the recovery key and creating the identity are separate steps, so that whoever runs the second never
sees the secret of the first.

1. **Make the recovery key and get its commitment.**
   - Phrase: `commons recovery new` generates the phrase, shows it once with the path, asks for a few of its
     words back, and prints the commitment. It writes nothing to disk and keeps nothing.
   - Device: `commons recovery commitment --ledger` reads the device's address at the path, has the holder
     confirm it on the device, and prints the commitment.
2. **Create the identity:** `commons identity new --recovery <commitment>`, signed by the root as today (a
   key file, or a device through a signing package). The tool refuses a commitment to the root's own key.

**A recovery key must be a key with no log, used for one identity.** It signs its one statement at `seq` 0,
so a key that has signed anything can never recover. The tool refuses what it can see: `recovery new` makes
a fresh key and never takes an existing one; `identity new --recovery`, and the `next` of a recovery, refuse
a commitment that matches any key the store holds a line of (the root, an earlier root, the successor, a
delegate, a key of another identity). `recovery check` and `show <identity>` warn when the key behind the
commitment in force has a log. One recovery key committed by two identities can recover only the first of
them it is used for; nothing in a reader refuses the second, but the second statement cannot be at `seq` 0
of a log that already has a line.

**The phrase is the one secret the tool ever prints.** Every other command keeps the rule "key material is
never printed" (`KEY-FILES.md`). `recovery new` therefore runs only on an interactive terminal: it refuses
when its output is redirected or `--json` is asked for, and it has no option to write the phrase to a file.

**Where step 1 must not run.** Anything shown in a session that is recorded or relayed is disclosed: a
remote shell with logging, a screen share, a terminal driven by an AI agent or an automation service. The
holder runs step 1 personally, on a machine they trust, and hands only the commitment to whatever runs step 2.

### 7.3 Checking and recovering

- **Possession check.** A key that never signs can be lost unnoticed. `commons recovery check --identity <I>`
  takes the phrase (typed at a terminal, never as an argument) or a device, derives the key, computes the
  commitment and compares it with the one in force. It signs nothing and writes nothing. Suggested: once
  after setup, from the backup and not from memory of the setup session, and then yearly.
- **Recovery** needs three signatures (§4): the new root's first line, the recovery statement, the old
  root's handover. Before starting, the holder makes the next recovery key as in §7.2, since the recovery
  statement commits to it. How the recovery key signs its one statement depends on how it is held:
  - **On its own device:** it signs there. Nothing else to do.
  - **As a printed phrase, with a hardware wallet available (taught first):** restore the phrase onto the
    device and sign there, so the phrase never touches a computer. Restoring wipes the seed the device
    holds. If the root lives on that same device, the order is: restore the recovery phrase, sign the
    recovery statement, wipe, restore the root's phrase, sign the handover. That needs the root's backup
    sheet to hand; a second device avoids it.
  - **As a printed phrase, with no hardware wallet (the fallback):** on a machine that is offline for the
    purpose, the phrase is typed at a terminal, the key exists in memory for one signature, and only the
    signed statement leaves. The tool warns when it can see a live network connection. It does not refuse:
    it cannot tell reliably, and a refusal that may be wrong is worse than a warning at this moment.

  No route needs hardware. A hardware wallet is the safer way to do this step, never a requirement for
  using the tool.
  **This is the most dangerous moment in the identity's life.** A recovery happens because the root is
  believed stolen, so whoever learns the phrase now holds both keys and can sign a rival recovery, which
  retires the identity for good (rule 5). The machine must be one the thief of the root cannot have touched:
  not the machine the root was used on, and not one that goes back online before the recovery is published.
- **The recovery key signs once, and the signed statement is as sensitive as the key until it is
  published.** A recovery statement that was signed and then set aside, because a file was lost or the owner
  changed their mind about the last good line, is all a holder of the stolen root needs to retire the
  identity: they hand it over beside the one the owner published (RR-27). So:
  - Before the recovery key signs, the tool has the holder confirm that the new root and the next recovery
    key are backed up. After that signature, losing the new root leaves two bad choices: publish anyway and
    freeze the identity under a root nobody holds, or sign a second, different recovery.
  - The prepared recovery is written to one file, and the command is resumable from it. Run again for the
    same identity and generation, it offers the same successor, last good line and next commitment, or
    refuses. It never offers a second recovery with a different effect. A second signature over the same
    effect is harmless (RR-07).
  - A device shows the holder what matters, not the whole statement: the command prints the successor, the
    next commitment and the SHA-256 of the signed string, for comparison on the device's screen.
  - An abandoned signed statement is destroyed like a key: every copy, on the offline machine too.
- **Which last good line to name.** A thief who forks the root's log is caught by the writer, which refuses
  to extend a forked log silently. A thief who extends the owner's tip is not: the owner's next line builds
  on the thief's, and from then on every line the owner signs has the thief's among its ancestors. Naming a
  last good line before the theft then voids the owner's own later grants, and every act under them
  (RR-29). So:
  - When the unwanted root lines are grants, **keep them and cut them**: name the owner's tip as the last
    good line, and have the new root cut each unwanted grant with that delegate's own last good line. The
    owner's history stays whole.
  - Name a line before the theft only when the prefix would otherwise hold something a cut cannot undo: a
    raw key event, a cut of one of the owner's own delegates, or an ordinary statement by the root (#271).
    A recovery that keeps a key event or an ordinary root statement is void in any case (RR-19, RR-25), and
    the tool refuses to prepare one.
  - The tool also refuses to prepare a recovery whose new root is a key the identity has committed to as a
    recovery key, the next one included (RR-31), or whose next commitment repeats a used one (RR-15).
  - Before anything is signed, the command lists every root line that would stop counting and, beside each
    grant, how many acts held in the store depend on it.
- **After a recovery,** destroy the used recovery key and every backup of it (rule 5 and §3: the old pair
  can still sign a rival recovery). For a device, that means wiping it and destroying its sheet, or never
  again unlocking that seed.

### 7.4 Custody rules

- **The root needs a backup** (rule 2 makes a root lost without a copy unrecoverable), and so does the
  recovery key. The two backups must not sit together: one theft must not yield both keys.
- **The recovery key's seed is not the root's seed.** A recovery key derived from the phrase that also
  derives the root is one secret, not two. The tool cannot see this; it is the holder's rule. With two
  devices, that means two different phrases.
- **A phrase is not a password.** Nothing rate-limits a guess or lets it be changed: whoever reads it holds
  the key, and replacing it takes a recovery.
- **A recovery key on a device can be destroyed in one step; a printed phrase cannot.** Rule 5 asks for the
  used recovery key and every copy of it to be destroyed after a recovery. Wiping a device is one act that
  can be checked. A phrase on paper may have copies its holder has forgotten. Where the choice exists, that
  is a reason to hold the recovery key on a device. It is not a requirement (§9).
- **Recovery is not prevention.** Until a recovery is published and has reached a reader, a stolen root
  acts as the identity for that reader. A resource that must not accept a single stolen key at all still
  needs more than one controller subject.

## 8. Compatibility

- **`rc/2` bytes are unchanged.** The profile adds one inception profile token and three kinds.
- **Readers that predate the profile fail safe.** Checked on `1.0.0-rc.1`, and kept as permanent tests
  (`internal/resolve/identity_profile_probe_test.go`, now with a token and a kind that stay unknown): an inception
  with an unknown profile token reads `unsupported`, and an act under it reads `unknown` with
  `unsupported_identity_profile`; an unknown `rc/2` kind on a `fixed-root-v1` root's log makes that identity's
  acts `unknown` (`unsupported_root_event`). A `1.0.0-rc.1` reader therefore reads a `recoverable-root-v1`
  identity as unsupported and an `identity_handover` on a fixed-root root's log as an unknown kind.
- **The commitment cannot be an optional member of a `fixed-root-v1` inception.** The same tests show such a
  member is read as valid and ignored, so an older reader would treat the identity as fixed-root and a
  recovery as nothing. A new profile token is the only safe carrier. For the same reason an existing
  fixed-root identity cannot be upgraded: it is re-created, and resources move to the new identity.
- **Signing packages.** A recovery needs three statements signed off-host, none of which is one of the four
  actions a signing package can carry today. The package format is revised once, together with packages for
  bare-key statements and key events (issue #266), and that revision gets its own note.

## 9. Decided, and open for review

**Decided by the maintainer.** Review is welcome, but these are the frame the rest is built in:

- A recovery commitment sits in the inception, under a new profile token. An existing fixed-root identity
  cannot be converted (§8).
- One recovery key, with an offline backup. The commitment is written as a set with a rule so that more can
  be read later; a reader treats anything but one key under `any_one` as unsupported.
- A recovery needs the recovery key **and** the current root. The recovery key alone does nothing.
- `identity new` creates a recoverable identity by default. `fixed-root-v1` stays readable for good and
  stays writable behind an explicit option, because the reader's conformance cases are built from it and it
  is the reviewed fallback if this profile is found wanting.
- No signing policy inside an identity (several keys that must agree). Separate roles are separate
  identities.

- **The root alone can retire the identity, and a recovery can undo that** (rule 6). A root revoke that
  stayed terminal would let a thief of the root destroy the identity, which is today's behaviour. The cost:
  a reader cannot tell a retirement that will stand from one that will be undone.
- **An identity can be closed with its history kept** (RR-11, a recovery naming no successor). It is the one
  final way to end an identity whose earlier statements should go on counting.
- **The recovery key's path is `m/44'/60'/1581'/0/0`, with no BIP-39 passphrase** (§7.1).

- **Rival recoveries retire the identity for good** (rule 5). After a recovery, the used recovery key and
  its backups must be destroyed, which nobody can prove was done. That makes this the design's weakest
  point: the old root and the old recovery key together stay a way to retire the identity for as long as
  both exist.
  Precedence by proven time was considered and rejected. Two forms were run through the reference model:
  the recovery with the earlier Bitcoin-quality bound wins, and a rival proven long after the first is void.
  Both remove the standing risk above when the owner's recovery carries a proof. Both make another case
  worse: a thief who holds both keys before any recovery signs one, timestamps it, and shows it to nobody. A
  timestamp proves a statement existed by a time, not that anyone could see it. When the owner later
  recovers, the thief reveals the earlier one and wins: the owner has lost the identity to the thief and can
  no longer even retire it. Under rule 5 the same theft ends in retirement. So time precedence trades "a
  thief with both keys can destroy the identity" for "a thief with both keys can take it". It would also
  make ownership depend on time evidence, which the claims model rules out (its §10: time evidence is never
  used for ownership or edit rights). A rule that keeps the first property without the second would reopen
  this, and is the most valuable thing a reviewer could bring.
- **Generations: a required minimum for readers, no maximum.** Every reader follows at least 64 recoveries
  of one identity, that is, through generation 64. The profile sets no upper limit; a reader that stops
  before the end of the chain it holds reports unknown with its own limit as the reason (RR-23). The writer
  warns as an identity nears 64 recoveries. The evaluation needs no cap
  to end (§4), so this is a resource floor and nothing else. A low fixed cap was rejected because it would
  end, for every reader and for good, an identity whose owner replaces the root on a schedule.

- **Encoding.** The commitment is a digest that hides the recovery key until use (§4). A handover is judged
  by signature, not by its place in the root's log (§4). A recovery carries no reason token, only an
  optional note. When the named last good line is not the tip of the branch the store has been extending,
  the tool lists every line that would stop counting and asks for confirmation; it does not refuse, because
  dropping a branch can be exactly what the owner means.

- **Signing at recovery with a printed phrase** (§7.3). The documents teach restoring the phrase onto a
  hardware wallet first, and typing it into an offline machine as the fallback. The tool warns about a live
  network connection on the typed route and does not refuse. Hardware is never required: an identity can be
  created, used and recovered with key files and a sheet of paper.

**Changed after the first outside review (issue #274).** Each of these came from the review and was checked
on the reference model before it was written in:

- A recovery whose kept prefix holds a raw root key event, or a root line outside the vocabulary, is void
  and no longer terminal (RR-19, RR-25). A holder of both keys loses nothing by this, since rivals still
  retire; an owner who names the wrong line can sign again.
- The order of the checks on a carried recovery is fixed, commitment first, so that a holder of the root
  alone cannot make the identity unknown (§5 step 1, RR-24).
- The recovery key is no root of the identity (§4, RR-30), before or after its use (RR-31, from the second
  look of the same review).
- A signed and unpublished recovery is named as a risk of its own, with what the tool does about it (§3,
  §7.3, RR-27).
- Keeping an unwanted grant and cutting it is taught ahead of naming an earlier last good line (§7.3, RR-29).

**Open: nothing the maintainer has left undecided.** Every point above has a decision and a reason, and
each can be reopened by a counterexample. The review asked for is of the whole: the matrix (§3), the rules
(§2) and the scenarios (§6).

## 10. Conformance cases

The scenarios of §6 as registered conformance cases: handle RR-NN is case C-id-(45+NN), continuing the fixed-root
profile's numbering (that note's §10 ends at C-id-45), so the harness counts both profiles under `id`. Each case is
built from signed lines through the production reader and the admission adapter (`internal/identity`,
`recoverable_cases_test.go`); the model-level copies (`internal/identitymodel/recovery_test.go`) are the oracle the
signed cases are checked against, and claim no case. The scenario and required outcome columns are the §6 rows,
word for word. `docs/recoverable-root-identity.coverage.json` lists each handle's case, tests and harness status, kept
equal to what the tests declare by a test in `internal/conformance`.

| Id | Profile | Scenario | Required outcome |
|---|---|---|---|
| C-id-46 | §5, §6 (handle RR-01) | Ordinary use | Current, generation 0; the root's grants count. |
| C-id-47 | §5, §6 (handle RR-02) | R stolen: the thief grants. The owner recovers with `last_good` before the theft, then grants with R′; the thief grants again with R | Before the recovery is read, the thief's grant counts. After: generation 1, the owner's old and new grants count, both thief grants are void. |
| C-id-48 | §5, §6 (handle RR-03) | The thief revokes R. The owner recovers | Retired, then current at generation 1. |
| C-id-49 | §5, §6 (handle RR-04) | A holder of R alone signs a handover carrying a "recovery" by a key of their own | Void; the identity is unchanged. |
| C-id-50 | §5, §6 (handle RR-05) | A holder of C alone signs a recovery | Nothing: no handover, no effect. |
| C-id-51 | §5, §6 (handle RR-06) | Both keys held by two parties; each completes a different recovery | Retired for good. |
| C-id-52 | §5, §6 (handle RR-07) | The same recovery is signed and handed over twice | One recovery. |
| C-id-53 | §5, §6 (handle RR-08) | A holder of R alone signs a root line with a missing ancestor; the owner then recovers | Unknown, then current: the line is outside the kept prefix. |
| C-id-54 | §5, §6 (handle RR-09) | A valid recovery whose `last_good` the reader does not hold | Unknown. |
| C-id-55 | §5, §6 (handle RR-10) | A root revoke signed at the first line and kept offline; the root goes on signing on another branch; the revoke is published; the owner later recovers with `last_good` on the working branch | Retired when the revoke is read; current again after the recovery. A reader that never receives the revoke sees ordinary use. |
| C-id-56 | §5, §6 (handle RR-11) | A recovery with no successor | Closed: kept history counts; later root lines are void. |
| C-id-57 | §5, §6 (handle RR-12) | A second recovery, by R′ and the second recovery key | Generation 2; kept grants of all three roots count. |
| C-id-58 | §5, §6 (handle RR-13) | After a recovery, the old R and old C sign another recovery of generation 0 | Retired for good. |
| C-id-59 | §5, §6 (handle RR-14) | A reader that holds everything but the handover | The pre-recovery state. |
| C-id-60 | §5, §6 (handle RR-15) | A recovery whose `next` repeats a commitment already used | Void. |
| C-id-61 | §5, §6 (handle RR-16) | R′ is revoked by its own key event | Retired at generation 1, recoverable by R′ and the second recovery key. |
| C-id-62 | §5, §6 (handle RR-17) | A delegate's acts across a recovery: (a) under a grant inside the kept prefix; (b) under a grant the recovery voids; (c) the new root cuts a grant the old root issued; (d) the old root signs a cut after the recovery | (a) Counts before and after. (b) Counted before the recovery is read, counts for nothing after, whenever the act was signed. (c) The grant is cut. (d) Void: the grant still counts. |
| C-id-63 | §5, §6 (handle RR-18) | `last_good: null` | Only the inception is kept: no earlier grant counts. |
| C-id-64 | §5, §6 (handle RR-19) | The owner names a `last_good` that has a root key event among its ancestors, then signs a second recovery with a `last_good` before it | The first recovery is void, so the raw event stands: retired, and a recovery can undo it (rule 6). The second is then the only complete one: current at generation 1. A void recovery is no rival. (The first version of this note read the first as retired for good. That made the owner's likeliest mistake permanent and gave a thief nothing they lacked.) |
| C-id-65 | §5, §6 (handle RR-20) | After a recovery, the old R is revoked | No effect on the identity. |
| C-id-66 | §5, §6 (handle RR-21) | Every subset of RR-02's statements | No subset reads generation 1 with a thief grant counting. |
| C-id-67 | §5, §6 (handle RR-22) | A complete recovery, plus a second valid one whose `last_good` is not held | Unknown: a possible rival is never passed over. |
| C-id-68 | §5, §6 (handle RR-23) | More recoveries than the reader's own limit (which is at least 64) | Unknown, with the limit as the reason. Never a guess at the current root. A chain of 64 recoveries is followed by every reader. |
| C-id-69 | §5, §6 (handle RR-24) | A handover whose carried recovery statement (a) is by the committed key and does not verify; (b) is by another key, under an algorithm the reader does not support; (c) is by the committed key, under such an algorithm | (a) Void. (b) Void: the commitment is compared first, so a holder of R alone cannot cause unknown. (c) Unknown; it needs both keys. |
| C-id-70 | §5, §6 (handle RR-25) | The root signs a statement outside its vocabulary (an ordinary `authored`, say: issue #271). Then (b) the owner recovers with `last_good` before that line, or (c) with `last_good` at or after it | Unknown, as in the fixed-root profile. (b) Current at generation 1: the line is outside the kept prefix. (c) That recovery is void, as in RR-19: still unknown, and a second recovery as in (b) clears it. |
| C-id-71 | §5, §6 (handle RR-26) | R is replaced by R′, a thief of R′ grants, R′ is replaced by R″ with `last_good` before that grant. A third recovery then names R′ as the successor | Void: R″ stays the root, and the thief's grant stays void. Found by the reference model after this note was first posted; the first version of §5 let the grant count again. |
| C-id-72 | §5, §6 (handle RR-27) | The recovery key signs recovery A; the owner abandons it and publishes a different recovery B with a handover. Later a holder of R obtains A's bytes and hands A over | With A's successor line held: **retired for good**, by R and a file, with no second key stolen. Without that line: unknown. A second signing with the same effect would have been harmless (RR-07). §7.3 says what the tool does about it. |
| C-id-73 | §5, §6 (handle RR-28) | An edition approved by a delegate under a grant that a recovery voids; another under a grant the recovery keeps | The first counted before the recovery is read and does not count after. The second counts both times. |
| C-id-74 | §5, §6 (handle RR-29) | A thief's grant extends the owner's tip; the owner, unaware, issues two grants after it. Route (a): `last_good` before the thief's grant. Route (b): `last_good` at the owner's tip, then the new root cuts the thief's grant | (a) The thief's grant is void, and so are the owner's two later grants and every act under them. (b) The owner's grants all count; the thief's counts until the cut is read, and not after. No set of statements that holds the recovery and the cut lets it count. |
| C-id-75 | §5, §6 (handle RR-30) | The commitment in force names (a) the root's own key, or (b) the successor root itself; that key signs a recovery and its handover | Void in both: the recovery key is no root of the identity. Without the rule, one key would recover alone. (Case (b) cannot arise from a recovery a reader accepts: RR-31 voids the recovery that would set it up.) |
| C-id-76 | §5, §6 (handle RR-31) | A handover names as successor (a) a recovery key the identity has already used (generations 0 and 1 recovered with C0 and C1; the third recovery names C1 as the new root), or (b) the key its own `next` commits to | Void in both: a key the identity has committed to as a recovery key never becomes its root. Without the rule, (a) makes the root a key whose copies were to be destroyed, with two `seq`-0 lines, and (b) leaves a root with no usable recovery key. An owner's mistake, not an attack: whoever does it holds both keys. |
