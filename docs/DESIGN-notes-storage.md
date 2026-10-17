# Design note: storage and transactions

**Status:** proposed
**Companion to:** the claims-model note (§15, "storage engine and transaction design")
**Covers:** the storage bullets of claims-model note §12 (exact bytes, atomic commits, concurrent writers,
caches, bounded scans) and §11 (external holds, package scope). Serves conformance cases C-core-123 through
C-core-131 (with C-core-127a, C-core-127b and C-core-129a), C-core-138, C-core-145, C-core-146, and properties P-07 and P-10; touches P-01 (permutation) where storage order could
otherwise leak into answers. Carries #74 rows 1, 2, 3 and 8 as obligations.

This note binds every implementation of the core, not a profile (conformance open item 11). It fixes
*behaviour at the boundary*: what an implementation installs, refuses, displays and recovers. It does not fix
file layouts, database engines or directory names; two implementations with different layouts conform if
every case in this note gives the same answer on both.

Following the wire-format note's standards-first rule (its §0), where this note names a primitive or a
layout it uses an existing one: POSIX.1-2024 for the filesystem primitives (§2, §7), and the OCI Image
Layout's blob tree as the recommended (not required) on-disk form (§1.1).

## 0. Summary

- Three object classes: **blobs** (content-addressed, immutable), **statements** (signed, one file each,
  in the signer's own log), **projections** (indexes, caches, views; disposable). Only blobs and statements
  are authoritative. Deleting every projection changes no answer (P-07).
- **Exact bytes:** hash while streaming into a confined temporary file on the destination filesystem, fsync,
  rename into place. An existing destination is re-hashed before reuse. A mismatch refuses and names both
  hashes.
- **One commit protocol** for every authoritative write: install blobs, write a journal record holding the
  signed statements (the commit point), install the statements, mark done, then project. A crash leaves the
  previous state or a replayable record. Recovery is a journal replay on every store open.
- **Projection failure after commit** is the state `committed, needs repair`; `repair` recomputes it.
  Nothing is rolled back.
- **Concurrent writers** never overwrite committed objects: blobs and statements are create-exclusive. Two
  same-key appends from one sequence point both survive and display `FORK`. A local lock makes self-forks
  rare; correctness never depends on it.
- **Caches** are keyed on content digests, policy digest, evaluator version and time context, never on
  size or mtime. The invalidation list is explicit (§6.3).
- **Garbage collection** deletes unreferenced blobs and any projection; never a statement, never a blob a
  held statement references. Local deletion is availability, not erasure.
- Every implementation **declares its durability** (fsync and rename guarantees, filesystem assumptions),
  and every bounded scan reports what it did not scan as `unscanned` with the limit named.

## 1. Object model

| Class | Identity | Mutable? | Authoritative? | Who writes it |
|---|---|---|---|---|
| **Blob** | full content hash | never | yes | any operation that installs bytes |
| **Statement** | hash of the canonical signed body | never; the signer supersedes with a new one | yes | the operation that holds the signed bytes |
| **Journal record** | operation id (hash of its content) | state only (`pending` → `done`) | yes while `pending`: it holds statements in transit | the commit protocol (§3) |
| **Projection** | derived | rebuilt at will | no | any reader |

**Blobs** are the bytes a statement talks about. A blob has no owner, no metadata and no name beyond its
hash. Two publishers of the same bytes share one blob (C-core-128).

**Statements** live one per file (or one per row in a store with equivalent create-exclusive semantics),
addressed by their statement hash, grouped by signing key. The per-key *log* is the set of that key's
statements ordered by the predecessor each names in its signed body (§4). There is no log file to append
to and therefore no line to lose: a statement either exists under its hash or it does not.

**Projections** are everything else an implementation keeps: full-text and field indexes, the resolution of
single-party defaults, grades, corroboration status, derivation groups, per-key head pointers, signature
verification caches, the manifest-like per-artifact summaries the claims-model note (§4) allows as local
caches. Projections are never transported, never authoritative, and are recomputed from blobs plus
statements by `repair` or by a cold start.

### 1.1 Recommended blob layout

An implementation that stores blobs as files should use the blob tree of the OCI Image Layout
(image-spec `image-layout.md`): `blobs/<alg>/<encoded>`, today always `blobs/sha256/<64 lowercase hex>`, with
the rule that the content of `blobs/<alg>/<encoded>` hashes to `<alg>:<encoded>`. Two of that layout's rules
are this note's rules already: the blob directory may hold blobs nothing references (the garbage-collection
candidates of §6) and may lack blobs that are referenced (external holds, §9). A small version marker at the
root (OCI uses `oci-layout`, `{"imageLayoutVersion": "1.0.0"}`) lets `fsck` recognise a store and its layout
version. The OCI `index.json` entry point is not adopted: it would be a shared mutable file with authority,
which this note rules out. Statements and projections keep their own layout. Paths below are written in this
form.

**What this rules out.** No shared mutable file is authoritative: no manifest that two keys edit, no
per-artifact JSON that `publish` rewrites, no index whose absence changes what `verify` prints. A reader that
finds a projection disagreeing with blobs plus statements treats the projection as stale (§6).

## 2. Exact-bytes install

The install path is the same for a local file, a package member and an external fetch (§9).

1. Open a temporary file **on the destination filesystem**, inside the blob store's own temporary directory,
   with a name the implementation chose (never a peer-supplied name; claims-model note §12, #67).
2. Stream the source into it, hashing the bytes as they are written. The hash of what was *written* is the
   only hash that matters; a hash computed earlier from the source (a manifest field, a `holds` claim, a
   command-line argument) is an **expectation**, not a result.
3. `fsync` the temporary file. Compare the computed hash with the expectation, if there was one.
4. If the destination `blobs/sha256/<hash>` does not exist: rename the temporary file into place
   (create-exclusive, so a concurrent installer of the same bytes cannot overwrite; §4.3). `fsync` the
   containing directory where the platform supports it (§7).
5. If the destination exists: **re-hash the existing file** before using it. If it matches, discard the
   temporary file and reuse, refreshing the blob's grace window (§6.1.1). If it does not match, the existing
   file is corrupt.

| Situation | Behaviour | Display |
|---|---|---|
| source changed between an earlier hash and the copy (C-core-124) | the computed hash differs from the expectation; nothing is installed | `hash mismatch: expected <h1>, got <h2>` (intrinsic refusal) |
| destination pre-placed with wrong bytes (C-core-124) | step 5 detects it; the corrupt file is moved to quarantine, not deleted; the verified temporary copy is installed in its place | `blob <hash>: stored copy corrupt (hashes to <h2>); replaced from verified source` |
| reuse of a corrupt blob with no fresh source (C-core-123) | the operation refuses to proceed on those bytes; `fetch` re-fetches from any hold, `run` refuses | `blob <hash>: stored copy corrupt (hashes to <h2>); refetch` |
| no expectation (first publish of local bytes) | the computed hash becomes the blob's identity | — |

Both hashes are always printed in full. "Corrupt" is a statement about *this store's copy*; it says nothing
about the blob's validity elsewhere, and the hash stays a valid reference (§6.2).

Blob files are installed read-only. Read-only is a courtesy to the operator, not a guarantee (I15 is met by
step 5, not by permission bits).

## 3. One commit protocol

Every authoritative write, whatever the command, is one **operation** with one **journal record** and the
same five steps. The protocol is a redo log: the record contains everything needed to finish the operation
without the process that started it.

### 3.1 Steps

| Step | Action | Durable before the next step? |
|---|---|---|
| 1 | Install every blob the operation needs (§2). Blobs are content-addressed and idempotent; an unreferenced blob is a GC candidate, never an error. | yes (fsync + rename) |
| 2 | **Commit point.** Write the journal record: operation id, kind, the full signed bytes of every statement, the blob hashes, the expected projections; written to a temporary file, fsynced, renamed into `pending/`. | yes |
| 3 | Install each statement under its hash, create-exclusive. "Already exists with identical bytes" is success. | yes, before step 4 |
| 4 | Rename the record from `pending/` to `done/` (or delete it; §3.4). | yes |
| 5 | Update projections (indexes, heads, caches). | no; failure here is `needs repair` (§3.5) |

The statements are signed **before** step 2, outside the protocol. Signing is pure (it needs the key and
the canonical body) and may fail; a failure before step 2 leaves the previous state and possibly an
unreferenced blob.

### 3.2 Atomic units per operation

| Operation | Unit (one journal record) | Preconditions checked before step 2 |
|---|---|---|
| `publish` (new bytes) | blob + `authored` + `holds` (+ `observed` for a capture) by one key | the pre-pin check named by the statement ran and its outcome is recorded (claims-model note §8); predecessor in the key's log resolved (§4.1) |
| `publish` of a withheld artifact | `authored` only; the blob is installed but no `holds` is written | as above |
| reveal (`holds` for withheld bytes) | `holds` | blob present and hashes to the statement's hash |
| resource genesis | genesis statement | none beyond signing |
| resource edition | one edition statement | every member and the predecessor edition it names are held (else refuse, name the fetch; claims-model note §8) |
| `run --publish` | output blobs + `authored` or `reproduced` + `holds` | execution record complete |
| `pull` (package) | the package's **admitted set**: every blob and statement the validation core admitted | validation ran over the whole package first (claims-model note §11); refusals are reported with package scope; the admitted set is committed as one unit |
| anchor, claim, submit, settle, retract, corroborate | one statement each | as the owning note specifies |
| `gc --release <hash>` | `holds` with `withdrawn: true`; the blob is deleted after step 4 | the operator's current `holds` for the hash is a serving one (§6.2) |

An operation that needs two keys (a k-of-n edition) is two operations: each controller's statement is its
own unit. The edition is authorized when the reader holds enough of them, which is a view, not a write.

The anchor that `publish` places before bytes leave the machine (claims-model note §10) is a *following*
operation on the same key's log: the authored statement must exist to be anchored. `push` refuses while the
anchor operation for the statements it would carry is absent or `pending`.

### 3.3 Crash at each point (C-core-125, P-10)

| Crash after | Durable state | On next store open |
|---|---|---|
| step 1 | previous state plus unreferenced blobs | nothing to do; `gc` may remove the blobs after the grace window (§6.1.1) |
| step 2 | a `pending/` record; no statement installed | replay steps 3–5; the operation is reported as committed |
| step 3, partially | `pending/` record; some statements installed | replay 3 (idempotent) then 4–5 |
| step 4 | `done/` record; projections stale | replay 5; until then the record's operation shows `committed, needs repair` |
| step 5, partially | `done/`, projections inconsistent | `repair` (§3.5); every reader treats projections as untrusted until `repair` completes |

`status` lists every `pending/` record by operation id and kind, and every `done/` record that has not
reached step 5 (C-core-125). A statement that is in a `pending/` record but not yet installed under its hash
is **not** visible to any read surface: readers resolve from installed statements only, and recovery runs
before the first read. There is therefore no window in which a half-published artifact resolves or lists.

### 3.4 Recovery

Recovery is a **journal replay**, chosen over a full scan because the record carries the signed bytes and
replay is therefore complete without consulting anything else. Every command that opens the store for
reading or writing first lists `pending/` and `done/`-without-projection records and replays them, in
record-creation order. Replay is idempotent at every step. A record whose statements fail signature
verification on replay (which can only mean the record itself is corrupt) is moved to quarantine and
reported; no statement from it is installed (C-core-126: nothing without a verified signature is shown as
anyone's word). `done/` records are kept until their projections have been rebuilt, then deleted (§12,
decided 3). A record duplicates the statements it installed, which by then live under their own hashes, and
every open lists the journal, so keeping records would double statement storage and slow every open. The
operation id is therefore known while its record exists and, afterwards, only to the optional operation
history (§3.6), which no answer reads.

A full scan (`fsck`, §6.3) remains available for the case the journal itself is lost: it reconstructs
projections from installed statements. It cannot recover a `pending/` operation whose record is gone; that
operation never reached its commit point and is reported as absent, not as failed.

### 3.5 Projection failure: `committed, needs repair`

A failure in step 5 (index write error, disk full after the statements landed, a crash) leaves the
operation committed. The implementation:

- reports `committed, needs repair` with the operation id and the projection that failed (C-core-138: what
  failed, what is still known, what is committed, the next step `repair`);
- never deletes or hides the committed statements;
- marks the affected projections untrusted, so a read that would consult them either recomputes from
  statements or prints `needs repair` beside its answer, never a stale answer as if fresh (I4).

`repair [<operation-id>|--all]` recomputes projections from blobs and statements. It invents nothing: it
never signs, never rewrites a statement, never reinterprets a statement of one kind as another. Its exit is
0 when every projection equals a cold rebuild, non-zero with the differing projection named otherwise.

### 3.6 Operation history (optional)

An implementation may keep a local **operation history**: one appended line per committed operation with the
operation id, kind, the ids of the statements it installed, the blob hashes and the local time, written after
step 4. It answers "what arrived together, and when" on this machine (a `history` command shows it). It is a
convenience log, not part of the store:

- **not authoritative and never read by an answer.** No read surface, `explain`, projection, gate or
  conformance answer consults it; deleting or editing it changes nothing any other command prints (P-07,
  C-core-146);
- **never transported**, and never a source for `repair` or `fsck`;
- **best-effort.** A crash after step 4 may lose the last line; the operation is committed regardless, and
  `status` does not read the history to decide what is unfinished;
- **bounded by local policy**, by size or age, and declared (§7 `history`);
- the local time it records is the operator's clock and evidence of nothing beyond this machine (a received
  statement's time is its signed `ts` and its anchors).

## 4. Concurrent writers

### 4.1 Per-key logs and sequence

Each statement names, inside its signed body, the hash of its predecessor in the same key's log (`prev`;
the wire-format note fixes the field name and encoding). The first statement names none. The per-key head
is a projection: the statement in that key's log with no successor.

Writing a statement to one's own log is: resolve the head, sign a body naming it, run the commit protocol.
Between "resolve the head" and step 3 a second process using the same key may do the same. Because
statements are create-exclusive and distinct bodies have distinct hashes, **both land**. The result is two
statements naming the same predecessor.

### 4.2 Fork detection and display (C-core-127)

At read time the log is reconstructed from installed statements. A predecessor with two or more successors
is a **fork point**:

- the log display shows `FORK` at that point, listing every branch tip with its statement hash;
- every statement on every branch is valid, resolves, and counts (I3: no line is lost; I5: evidence is
  retained);
- an answer that depends on *which* branch is current (a resource edition from a controller whose log forked
  below it) shows the branch in its explanation and, where the branches conflict, `contested` (claims-model
  note §3.1);
- the key's owner clears the fork by signing a statement whose `prev` is one tip and whose `merges` names
  every other tip (wire-format note §7). The fork clears when every tip is an ancestor of one statement,
  the rule a merge edition follows for a resource (claims-model note §8). A statement that follows one tip
  and names no other leaves `FORK` shown, because following a branch says nothing about whether the signer
  saw the others (C-core-127a). The cleared branches stay in the log, displayed as merged. Nothing is
  deleted;
- a statement whose `merges` names a line the reader does not hold is `detached` until that line arrives,
  like one whose `prev` is not held (wire-format note §7, "Gaps"; C-core-127b). A branch the
  owner does not recognise is not merged: the answer to it is a `revoke_key`, which cuts every line outside
  its own history whatever its reason (claims-model note §4.1). The tool's `revoke` builds that history by
  reason. For a soft reason (`superseded`, `cessation_of_operation`) the owner is retiring a key it still
  controls, so `revoke` merges every tip it holds and nothing is cut by accident. For a hard reason it merges
  nothing on its own: it lists every tip, marks the ones this machine did not write, and the owner picks
  which to keep and which line is `last_good`. Folding a thief's tips into the owner's history would make
  them count. `revoke` offers the three documented reasons with no default, and refuses to run
  non-interactively without `--reason`.

A fork is never a refusal: no gate may refuse a statement because its signer's log has forked (I7 applies to
the signer's own relayers too). A fork is also not a claim of misbehaviour; it is what two honest processes
produce.

### 4.3 Local writer lock

An implementation holds an advisory, per-key, process-scoped lock around "resolve head → sign → step 3" so
that two of *its own* processes on one machine do not fork casually. The lock is an optimization:

- a writer that cannot acquire it waits a bounded time, then proceeds without it and may fork;
- a filesystem without advisory locks, a second machine sharing the key, or a crash holding the lock all
  degrade to "may fork", never to "may lose a line";
- the lock is never consulted at read time and never recorded in any statement.

### 4.4 Same blob, two publishers (C-core-128)

Two processes publishing the same bytes, same or different keys, concurrently: step 1 installs one blob
(the second installer's rename finds the destination, re-hashes it, matches, discards its temporary copy);
step 3 installs one statement each (different keys) or, for the same key and identical body, one statement
that both report as committed. Committed bytes are never overwritten, replaced or unlinked by a loser: no
rollback in this protocol ever removes an object the operation did not create in its own step 1 or 3, and
step 1 and 3 objects are never removed at all (a blob the operation installed is left for `gc`).

### 4.5 Package pulls

Two concurrent `pull`s of overlapping packages each commit their admitted set. Overlap is idempotent at every
step. A hub's gate (CI on a base revision) sees a package as one unit (claims-model note §11) and never
observes a partial install because step 3 of a `pull` completes before any projection the gate reads.

## 5. Caches and indexes

### 5.1 Keys

Every projection entry is keyed on, and only on:

| Component | What it is | Why |
|---|---|---|
| input digests | the statement hashes and blob hashes the projection read | a same-size, same-mtime rewrite of a statement file changes its hash and misses the cache (C-core-129, #74 row 8) |
| policy digest | hash of the reader's trust, admission, execution and reference policy | a policy change is a different answer, cited in `explain` (P-11) |
| evaluator version | the version of the code that computed the projection | a new evaluator may fold differently; old entries are dead |
| time context | the reader's evaluation time where the answer depends on it (shelf life, finality, future-timestamp refusal) | absent from entries for time-independent answers |

Forbidden as key components: file paths (beyond locating the object), modification times, sizes, inode
numbers, row counts, directory listing order, transport order. An index that decides freshness by comparing
a count of files to a count of rows is non-conforming.

### 5.2 Cold-rebuild equivalence (C-core-129, P-07)

For every read surface and every fixture: delete every projection, rerun, compare. The outputs must be
byte-identical in their state tokens, values, exit codes and `explain` contents (timing and progress lines
excepted). A restore of blobs plus statements from backup, with no projections, must rebuild them without a
prompt on the first command and return the pre-backup answers.

An implementation that stores projections in a database treats the database file as a projection: its
absence is a cold start, its corruption is `needs repair`, its contents are never consulted for anything
blobs plus statements could answer.

### 5.3 Invalidation list

An entry is dropped (or ignored, which is equivalent) when any of the following changes:

1. any statement hash in its input set (a new statement by any key that the projection *would* read is a new
   input, so a projection records the query it answered, not only the statements it found);
2. any blob hash in its input set;
3. the policy digest;
4. the evaluator version;
5. the time context, for time-dependent entries;
6. a `repair` or `fsck --rebuild` that names its projection;
7. the signature-verification cache entry for any statement in its input set (a verification cache is keyed
   on statement hash plus verifier version only, and holds only "verified" or "failed", never a value).

A conformance run does not rely on that cache. Every signature a case reports on is verified in the run
under test, starting from a cold store; a cached "verified" is an optimization for daily use, not evidence
of conformance. One case checks the cache itself: a warm answer equals a cold one, and a changed verifier
version misses (C-core-129a).

Nothing else invalidates. In particular, the passage of time does not invalidate a time-independent entry,
and a `gc` (§6) does not invalidate anything, because `gc` removes no input of any valid projection.

## 6. Garbage collection and local deletion

### 6.1 What may be deleted

| Object | May `gc` delete it? | Condition |
|---|---|---|
| projection, any | yes | always; the next read rebuilds |
| `done/` journal record whose projections are rebuilt | yes | always |
| blob referenced by no installed statement and no `pending/` record | yes | outside the grace window (§6.1.1) |
| blob referenced by an installed statement | **no** | — |
| blob referenced only by the operator's own `holds` | only on explicit request naming the hash | §6.2 |
| statement, any | **never** | — |
| `pending/` journal record | **never** by `gc`; only recovery or quarantine (§3.4) | — |

#### 6.1.1 The grace window (§12, decided 2)

A blob installed in step 1 is referenced by nothing until the record of step 2 names it. The grace window
keeps `gc` from deleting it in between:

- **Measured from the last install or reuse.** §2 step 5 refreshes the window of an existing blob it reuses,
  so republishing bytes this store once released is protected exactly like new bytes.
- **Re-checked at deletion.** `gc` decides from a listing but, immediately before removing each blob,
  re-checks that no installed statement and no `pending/` record names it and that its window has expired;
  a blob that gained a reference since the listing is kept.
- **Configurable.** The window is local policy (default 24 h), printed by `gc` in its plan and in the
  durability declaration (§7). A value below 1 h is refused unless given for one run (`gc --grace <d>`), when
  the operator knows nothing else is writing to the store. The window has to outlast the longest interval
  between step 1 and step 2 of any operation on this store; one that does not is the residual case.
- **The residual case is caught, not silent.** Step 2 refuses to write a record naming a blob that is not
  held (nothing committed, the publish retried). If `gc` removes a blob between that check and the record,
  step 5 finds it missing, reports `committed, needs repair: blob <hash> missing` (§3.5) and `fsck` lists it
  as an unresolved reference; re-installing the bytes repairs it. No statement is ever lost.

A pre-step-1 `intent/` record (a lease, as container runtimes use) would remove the window at the cost of a
journal write and delete on every operation, and stale intents after a crash would need an expiry of their
own. It is not adopted; an implementation may add one as long as `gc` honours both.

`gc` prints what it would delete, with hashes and sizes, and deletes only with `--apply`. Its dry run states
its side effects exactly ("no deletion; no registry change").

### 6.2 Local deletion is not erasure

Deleting a local blob changes **availability**: the hash remains a valid reference, every statement about it
remains valid, and every other holder's copy is unaffected. The tool therefore:

- refuses to delete a blob the operator's own current `holds` references unless the request names the hash
  (`gc --release <hash>`). A release signs a `holds` with `withdrawn: true` (wire-format note §5) and deletes
  the blob **in one operation**: the withdrawal is the operation's statement, the blob is removed only after
  the commit point, and a crash leaves either the blob and no withdrawal, or the withdrawal and a blob `gc`
  may then remove. Availability and assertion move together; a release that cannot sign (no key, signing
  refused) deletes nothing. A blob held under no current `holds` of the operator's (never served, or already
  withdrawn) needs no release;
- never deletes a statement for any reason, including retraction (claims-model note §13: retraction is
  display) or a takedown; a hub that must stop serving bytes deletes the blob under its own admission policy
  and keeps the statements;
- reports a referenced-but-absent blob as `unavailable (not held locally)`, never as invalid, corrupt or
  retracted.

### 6.3 `fsck`

`fsck` scans blobs plus statements and reports, as distinct classes: byte corruption (a blob that hashes
wrong; C-core-123), invalid authentication (a statement whose signature fails), unresolved references (a
statement naming a blob, predecessor or edition not held), projection drift (a projection that differs from
a cold rebuild), and unreferenced storage (GC candidates). It never changes authoritative state; `--rebuild`
recomputes projections, `--quarantine` moves corrupt blobs aside (§2 step 5). It never invents a signature
and never reads a statement of an unknown kind as any known kind.

## 7. Durability declaration

An implementation ships a durability statement, printed by `status --durability` and recorded with every
conformance result (CONFORMANCE "how a result is recorded"):

| Field | Values | Meaning |
|---|---|---|
| `file_sync` | `fsync` · `fdatasync` · `none` | what step 2 and step 3 do before rename |
| `dir_sync` | `fsync` · `none` | whether the containing directory is synced after rename |
| `rename` | `atomic` · `best-effort` | whether rename-into-place is atomic on the declared filesystem, as POSIX.1-2024 `rename()` specifies |
| `exclusive_create` | `link` · `O_EXCL` · `db-unique` · `none` | the create-exclusive primitive behind §2 step 4 and §3 step 3. `link` and `O_EXCL` mean the POSIX.1-2024 `link()` (fails with `EEXIST`) and `open(O_CREAT\|O_EXCL)` semantics |
| `same_filesystem` | `required` · `checked` · `assumed` | whether the temporary directory is verified to share the destination filesystem |
| `locks` | `advisory` · `none` | §4.3 |
| `gc_grace` | duration | the grace window in force (§6.1.1; local policy, default 24 h) |
| `history` | `off` · `on (<bound>)` | whether the optional operation history is kept, and its size or age bound (§3.6) |
| `assumes` | free text | filesystem assumptions (POSIX rename semantics, no network filesystem, …) |

A declaration of `none` or `best-effort` is conforming. What is not conforming is behaving as if a guarantee
held that was not declared: P-10 compares the *reported* commit state with the *recoverable* state under the
declared guarantees, and an implementation that declares `file_sync: none` must still satisfy C-core-125 on
the crash model its declaration implies (process crash, not power loss).

## 8. Bounded scans

Every scan (forbidden-key and secret lint, archive inspection, provenance traversal, validation depth) has a
documented limit with a name and a value. When a scan does not complete:

- each unscanned unit is listed as `unscanned (<limit-name>=<value>)`: an archive member over the size
  limit, a member in an unsupported compression, a truncated member, a nesting level past the bound
  (C-core-130);
- the enclosing result is `incomplete`, never `clean` or `ok`; a release policy that requires a clean scan
  refuses under **reader policy**, naming the unscanned units, and says so rather than reporting corruption
  (C-core-131, I4, I8);
- a limit hit mid-run is an operational refusal with the limit, its value and the scope it cut (which members,
  which depth) in the message; partial results already produced stay marked `incomplete`.

Limits are read from the reader's policy, are part of the policy digest (§5.1), and are printed by
`status --limits`. An implementation that silently truncates a scan is non-conforming regardless of what it
printed for the parts it did read.

## 9. External holds

A `holds` statement may name a location outside any hub (claims-model note §11). Fetching from it:

1. runs the install path of §2 with the statement's hash as the expectation; the location is a hint and the
   transport is binary-safe (#64). Each location is an RFC 3986 URI (wire-format note §5). When the statement
   declares the size (`content.size`), a fetch that delivers a different number of bytes is refused before
   the hash is computed, and a fetch that runs past the declared size is cut off there; the OCI descriptor
   rule ("verify size before digest") applied to a hold;
2. on match, installs the blob; from then on the local store serves it and every operation treats it exactly
   as a blob from a package (C-core-120: "fetched-and-verified");
3. on mismatch, refuses (intrinsic), names both hashes and the location, installs nothing, and leaves the
   `holds` statement valid as the holder's word;
4. on unreachable, reports `unavailable (holder's word: <location>)` and installs nothing.

Fetching never publishes a `holds` of one's own: holding bytes and asserting that one serves them are
different acts. A hub carrying statements and external holds only is a conforming store whose every blob is
in state `unavailable (not held locally)` until fetched.

## 10. Relationship to the alpha

| Alpha primitive | Kept? | Why |
|---|---|---|
| content-addressed blob directory, read-only files | kept | correct idea; the install path around it changes |
| hash the source, then `copyfile`, reuse an existing destination unverified (#74 row 1) | dropped | §2: hash the bytes written, verify before reuse |
| temp-file + rename for manifests, `link` for create-exclusive | kept as the primitive | §2 step 4 and §3 step 3 use the same create-exclusive rename |
| `publish` = write manifest, append ledger, update index, with a rollback that unlinks a manifest it may not own (#74 row 2) | dropped | §3: one journal-backed protocol; rollback never removes a committed object; projections that fail are `needs repair` |
| per-key append-only `.jsonl` log, head read unlocked, `prev` outside the signature (#74 row 3) | dropped | §4: one file per statement, predecessor inside the signed body, forks visible |
| shared mutable manifest per artifact | dropped | a projection at most (claims-model note §4) |
| SQLite index with freshness by row count; ledger and anchor caches keyed on path, mtime and size (#74 row 8) | dropped | §5: digest-keyed, cold-rebuild equivalent |
| `fsck` (byte corruption, chain, attribution) | kept, extended | §6.3 adds projection drift and unreferenced storage as classes |

The alpha stays as it is (#71). Blobs carry across a rebuild unchanged because their hashes do; statements and
projections do not.

## 11. Out of scope

Wire format of statements, journal records and packages (field names, canonical encoding, signature scheme).
Execution-time staging and confinement (the execution note; this note covers only installing outputs).
Anchor submission and proof verification (the time note). Size policy values (#9). Hub discovery and layout
(#66). Encryption at rest, multi-host replication of one key's store, and database engines beyond the
semantics stated in §1 and §5.2.

## 12. Open questions

1. ~~**Fork clearing.**~~ **Decided:** the clearing statement names every other tip in `merges`, an
   optional signed envelope field beside the single `prev` (wire-format note §7). "Cleared" then means
   every tip is an ancestor of one statement, the same rule as a merge edition (claims-model note §8), and a
   reader can tell "cleared" from "the signer never saw the other branch" (§4.2).
2. ~~**Grace window versus pending records.**~~ **Decided (2026-10-16):** the grace window, measured from the
   last install or reuse, re-checked at deletion, configurable with a 1 h floor (§6.1.1). No per-operation
   `intent/` record: it costs a write on every publish of a hub that ingests thousands a day and needs its
   own expiry after a crash.
3. ~~**Journal retention.**~~ **Decided (2026-10-16):** delete `done/` records once projections are rebuilt
   (§3.4), plus an optional, non-authoritative operation history that no answer reads (§3.6). Keeping
   records would duplicate every statement and slow every open; an operation id in `explain` would have been
   an answer that a deleted cache changes (P-07).
4. ~~**Verification cache trust.**~~ **Decided:** a conformance run re-verifies every signature it reports
   on, from a cold store; the cache stays for daily use, and C-core-129a checks that it agrees with a cold
   run (§5.3).
5. ~~**Release of own `holds`.**~~ **Decided (2026-10-16):** `gc --release` signs a `holds` with
   `withdrawn: true` and deletes the blob in one operation (§6.2), so availability and assertion move
   together. Chosen over a reminder after the fact, which left a signed claim to serve bytes the operator had
   already deleted.
