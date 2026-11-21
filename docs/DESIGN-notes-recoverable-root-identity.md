# Recoverable-root identity profile (`recoverable-root-v1` on `rc/2`): proposal

**Status: proposal for review. Nothing here is implemented.** No reader or writer knows this profile, no
bytes are fixed, and every name below (profile token, kinds, members) is a working name. The note is written
compromise matrix first and scenarios second, and only then the vocabulary, so the rules can be judged
before their encoding. It builds on the fixed-root profile (`DESIGN-notes-fixed-root-identity.md`, "the
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
   A recovery key is used once.
5. Two complete recoveries of the same root that differ in any effect **retire the identity for good**. No
   clock, arrival order or first-seen rule decides between them.
6. The root alone can still **retire** the identity with a raw `revoke_key`, as today. Unlike today, a later
   recovery whose kept prefix excludes that revoke undoes it. (Otherwise a thief of the root could always
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
| After a recovery, the old R and old C are both obtained by someone | sign a rival recovery of the old root | nothing in-band | **Retired for good**, even years later (rule 5). After a recovery the used recovery key and its backup must be destroyed; the old root is assumed stolen already. See §9, open question 2. |
| A reader holds only part of the evidence | n/a | n/a | A reader that lacks the recovery reads the pre-recovery state, as it reads an identity today without a cut it has not received. A reader that holds a valid recovery but lacks a line it names reads unknown. |

Compared with the fixed-root profile, the common disaster (the root's device or backup is compromised) goes
from "new identity, successor resources" to one ceremony. The new ways to lose all need **both** keys.

## 4. Vocabulary (working names)

All are `rc/2` statements with the `x_identity_v1` marker, raw-key signed, and take no actor.

| Kind | Signed by | Body besides the marker | Notes |
|---|---|---|---|
| `identity_inception` | R, `seq` 0 | `profile:"recoverable-root-v1"`, `recovery:{commitments:[c], rule:{any_one:true}}` | The id is I. The commitment is required: an identity that wants none uses `fixed-root-v1`. |
| `identity_succession` | the new root R′, `seq` 0 | `identity:I` | R′ consents and pins its own lineage, as a delegate's first line does for a grant. R′ must be a fresh key. |
| `identity_recovery` | C, `seq` 0, `prev` null | `identity:I`, `last_good:L-or-null`, `successor:{key:R′, inception:D′}` or null, `next:{commitments:[c], rule:{any_one:true}}` | C's only statement. `successor:null` closes the identity with its history kept (§5, RR-11); `next` is then absent. |
| `identity_handover` | R | `identity:I`, `recovery:<the whole signed identity_recovery>` | R's half of rule 2. It carries the recovery statement, not its id (below). |

**The commitment** is a digest of the recovery key's public form under its own domain string, so it can be
confused with no statement id or content digest. Proposed: lowercase hex SHA-256 of
`PAE("application/vnd.research-commons.recovery-commitment.v1", <signer string>)`. Publishing a digest and not
the key keeps the key's public form unknown until use.

**One recovery key (decided).** This version reads exactly one commitment under `any_one`. The member is
written as a set with a rule so that a later version can add a threshold without another profile; a reader
of this version reads any other count or rule as unsupported for the whole identity, never as "any one of
them". A holder who wants redundancy keeps backup copies of the one key.

**Why the handover carries the statement.** If it named the recovery by id, a thief holding only R could sign
a handover naming an id that does not exist. A reader cannot tell "not received" from "never existed", so the
identity would read unknown, and a real recovery could never clear it, because the unreadable handover might
be a rival. Carrying the signed statement makes a handover either void (the carried bytes do not verify
against the commitment) or complete, from its own bytes. This came out of the model, not out of prior art.

**A handover is judged by signature, not by its place in R's log.** It is bound to the identity three ways:
it names I, R signed it, and the carried statement's signer matches the commitment in force. So it applies
wherever it sits, including on a branch the recovery itself voids. Open to challenge (§9, open question 6).

**Root generations.** The inception's root is generation 0. Each recovery with a successor starts the next
generation, whose root is R′, whose lineage starts at D′, and whose recovery commitment is `next`. A reader
evaluates generation by generation, with a cap (proposed: 16; over the cap reads unknown, never partial).

**Signing order for a recovery:** R′ signs D′; C signs the recovery naming D′; R signs the handover carrying
it. Three signatures, each of which may come from a device through a signing package.

## 5. Evaluation

For identity I at generation g, with root R, lineage start D and commitment K:

1. Collect every `identity_handover` signed by R that names I. One whose carried statement is not a valid
   `identity_recovery` for I, at `seq` 0, signed by a key whose commitment is K, is **void**: it is reported
   and changes nothing. So is one whose `last_good` is a line of another key or another lineage, whose
   successor statement is not that key's `seq`-0 `identity_succession` for I, or whose `next` repeats a
   commitment already used by this identity.
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
     A raw key event inside the kept prefix stays terminal. If there is a successor, continue at generation
     g+1; if not, the identity is **closed**: its kept history counts and nothing new can be administered.
4. Grants of every generation are grants of I. The current root can cut a grant an earlier root issued. A
   recovery closes no grant by itself: the new root cuts the ones it no longer wants.
5. The answer is a function of the set of statements held. Delivery order cannot change it.

Everything a reader reports today (status, reasons, basis and missing ids, warnings, freshness
`not_established`) carries over, with the generation and the recovery statements added to the basis.

## 6. Scenarios

These were run through a small reference model of §5 before this note was written. They become signed,
end-to-end conformance cases when the profile is built; until then they are scenario handles, not cases.

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
| RR-19 | The owner names a `last_good` that has a root key event among its ancestors | Retired for good: a key event inside the kept prefix is terminal. |
| RR-20 | After a recovery, the old R is revoked | No effect on the identity. |
| RR-21 | Every subset of RR-02's statements | No subset reads generation 1 with a thief grant counting. |
| RR-22 | A complete recovery, plus a second valid one whose `last_good` is not held | Unknown: a possible rival is never passed over. |
| RR-23 | More generations than the reader's cap | Unknown, with the cap as the reason. Never a guess at the current root. |
| RR-24 | A handover whose carried recovery statement does not verify, or uses an algorithm the reader does not support | Void for a bad signature; unknown for an unsupported algorithm. The identity is otherwise unchanged. |
| RR-25 | The root signs a statement outside its vocabulary (an ordinary `authored`, say: issue #271). Then (b) the owner recovers with `last_good` before that line, or (c) with `last_good` at or after it | Unknown, as in the fixed-root profile. (b) Current at generation 1: the line is outside the kept prefix. (c) Still unknown. |

RR-24's unsupported-algorithm half is not in the reference model, which has no notion of an algorithm; the
rest of the table is. RR-25 matters beyond theft: today one mistaken command with the root key ends a
fixed-root identity (issue #271), and under this profile the owner can recover from it.

Still to write as a scenario: an edition approved under a grant that a recovery voids, and the resource
views that follow (RR-17b says the approval stops counting; what a collection's reader then shows needs its
own cases).

## 7. Setting up and holding the recovery key

Command names here are working names. The rules in this section are tool behaviour and guidance, not format:
the commitment covers a key, and a reader never learns how the key was made or kept.

### 7.1 One kind of recovery key, two ways to hold it

The tool makes one kind of recovery key: an `eip191-secp256k1` key at one fixed, fully hardened path under a
24-word BIP-39 phrase. Proposed path: `m/44'/60'/1581'/0'/0'`. It is printed with the phrase, because a
holder needs it to restore the key anywhere else.

Because the key is derived the standard way, the two ways of holding it are interchangeable:

- **A printed recovery phrase** (the default). Nothing to buy; the key exists on a computer for a moment at
  setup and again at recovery.
- **A Ledger device** (the hardware option). The key never leaves the device. The device's own backup sheet
  is then the backup of the recovery key.

A phrase can be restored onto a device later, and a device's key at that path is the key its sheet derives.
Checked on a device emulator running the Ethereum app: the address the app reports at three paths under
`m/44'/60'` equals the address standard BIP-39 and BIP-32 software derives from the same phrase. The app
refused a path under `m/43'`, so the path has to sit under `m/44'/60'`. Not checked: a physical device, a
24-word phrase (the emulator's test phrase has 12), a BIP-39 passphrase, and whether the device warns when
signing at this path.

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
  statement commits to it. The recovery key signs its one statement either on the device or, for a phrase,
  on a machine that is offline for the purpose: the phrase is typed at a terminal, the key exists in memory
  for one signature, and only the signed statement leaves.
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
- **Recovery is not prevention.** Until a recovery is published and has reached a reader, a stolen root
  acts as the identity for that reader. A resource that must not accept a single stolen key at all still
  needs more than one controller subject.

## 8. Compatibility

- **`rc/2` bytes are unchanged.** The profile adds one inception profile token and three kinds.
- **Readers that predate the profile fail safe.** Checked on the current reader (`1.0.0-rc.1` plus later
  documentation commits) with throwaway tests, to be added as permanent cases: an inception with an unknown profile token reads `unsupported`, and an act
  under it reads `unknown` with `unsupported_identity_profile`; an unknown `rc/2` kind on a `fixed-root-v1`
  root's log makes that identity's acts `unknown` (`unsupported_root_event`).
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

**Open: the author's proposals, not decisions.** Each is written into the text above as if settled, so that
the note reads as one design. None is.

1. **Rule 6: can the root alone retire the identity, and can the pair undo it?** The alternative, a root
   revoke that stays terminal, lets a thief of the root destroy the identity, which is today's behaviour.
2. **Rule 5: rival recoveries retire for good.** It needs the used recovery key and its backups destroyed
   after a recovery. An alternative is precedence by proven time (the recovery with the earlier
   Bitcoin-quality bound wins), which removes the standing risk but makes an identity's state depend on time
   evidence. Not proposed here.
3. **Closing with history kept** (RR-11, a recovery naming no successor). Wanted, or out of scope for a
   first version?
4. **The recovery key's path** (§7.1): is `m/44'/60'/1581'/0'/0'` acceptable?
5. **A BIP-39 passphrase on the recovery phrase:** offered or not? And is typing a phrase into an offline
   machine at recovery an acceptable default?
6. **Encoding details:**
   - the commitment digest (§4), and whether it should hide the key at all;
   - handover placement: §4 judges a handover by signature alone. Is there a case where requiring it on the
     root's lineage, with complete ancestry, is safer?
   - the generation cap of 16 (RR-23);
   - whether a recovery needs a reason token, as a cut has, and whether the tool should refuse a `last_good`
     that is not on the branch the owner has been using.
