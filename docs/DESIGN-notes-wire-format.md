# Design note: wire format

**Status:** proposed · **Companion to:** the claims-model note (§15, "wire format") · **Covers:** canonical
encoding, the statement envelope, statement identity, the signature scheme, the kind vocabulary's field
names, extensions, per-key logs, content hashing, and test vectors. Serves conformance cases C-core-02a,
C-core-03, C-core-04, C-core-08 to C-core-14, C-core-77, C-core-83, C-core-105, C-core-106, C-core-117,
C-core-127, C-core-127a, C-core-127b, C-core-141, C-core-143, C-core-144, P-02.

## 0. Summary

- A statement is one JSON object, the **envelope**: `rc`, `kind`, `signer`, `alg`, `seq`, `prev`, `ts`,
  `body`, optional `merges` and `crit`, and `sig`. Everything except `sig` is signed. Nothing rides outside.
- The **signed string** is the DSSE pre-authentication encoding (PAE) of the canonical JSON of the envelope
  minus `sig`, with payload type `application/vnd.research-commons.<kind>.v<major>+json`.
- **Statement id** = full lowercase hex sha256 of the signed string. Short forms are display aliases only.
- **Canonical JSON** is RFC 8785 (JCS) output over the I-JSON (RFC 7493) subset, further restricted to
  integers, with duplicate keys refused, depth ≤ 16, statement ≤ 64 KiB. No Unicode normalisation.
- **Times** are RFC 3339 date-times in one canonical spelling (the XML Schema 1.1 `dateTime` canonical
  mapping): up to 9 fractional digits, no trailing zeros, UTC with `Z`. A measurement recorded in another
  timescale names it with a FITS time-scale code. Times are compared parsed, never as text.
- **One signature**, two required algorithms: `ed25519` (the default for new keys) and `eip191-secp256k1`
  (the alpha primitive, kept for blockchain-linked identities). Every reader verifies both. Any encoding of a
  valid signature over one signed string is the same statement. Unknown `alg` is retained and grants nothing.
- `prev` and `seq` are inside the signature, so a same-key fork is two signed lines, not a relayer's edit.
  A later line clears the fork by naming the other tips in `merges`, also signed (§7).
- Unknown fields are retained and ignored. A `crit` member the reader does not implement makes the whole
  statement `unsupported`: retained, never evaluated. An unknown `rc` major is `unsupported` the same way.
- Content identity is sha256 of the exact bytes, written as an OCI digest, `sha256:<64 hex>`. Statement ids
  are bare 64 hex (§8). Vectors in §9 were computed, not typed.

**Standards first.** Where a published standard already defines something this note needs, the note adopts it
and states the profile (the subset it allows) instead of writing a rule of its own. A home-grown rule is used
only where no standard fits or where adopting one would break an invariant of the claims-model note, and each
such place says why. A deliberate departure from an adopted standard is named where it occurs.

| Need | Standard adopted | Profile or departure |
|---|---|---|
| signed-string framing | DSSE v1.0.2 protocol, PAE | the PAE string is the message the algorithm signs; DSSE's JSON envelope is not used (§2) |
| canonical JSON | RFC 8785, JSON Canonicalization Scheme (JCS) | output restricted to integers (§1); input refused rather than repaired where §1 says so |
| JSON subset | RFC 7493, I-JSON §2.2 (number range), §2.3 (unique names) | integers only, \|n\| ≤ 2^53 − 1 |
| date-time syntax | RFC 3339 §5.6 (an Internet profile of ISO 8601) | `T` and `Z` upper case, no numeric offsets, ≤ 9 fractional digits (§1.1) |
| one spelling per instant | W3C XML Schema 1.1 Part 2 §3.3.7, `dateTimeCanonicalMap` | adopted for the fraction; departs by admitting second `60` (XSD has no leap seconds) |
| timescales | FITS 4.0 §9.2.1, Table 30 (Rots et al. 2015, A&A 574, A36) | the non-deprecated codes only (§1.1) |
| leap seconds | RFC 3339 §5.7; CGPM 2022 Resolution 4 | accepted as written, never normalised |
| time intervals | ISO 8601 start/end intervals; RFC 9581 §5 | two fields, half-open `[from, to)` (§5 `window`) |
| content hash | SHA-256, FIPS 180-4 (free text: RFC 6234), written as an OCI image-spec digest | `sha256:` + 64 lowercase hex (RFC 4648 §8 base16); statement ids bare (§8) |
| licences | SPDX 3.0.1 Annex B license expressions | stored verbatim; free terms via `LicenseRef-` (§5) |
| link relations | RFC 8288 §2.1; IANA Link Relations registry | annotation only, read by no resolver (§5 `describes`) |
| locations of bytes | RFC 3986 URIs | hints, never dereferenced during verification (§5 `holds`) |
| media types | RFC 6838 | |
| geographic position | RFC 5870 `geo:` URI (WGS 84, `u=` uncertainty) | GeoJSON is not used: its coordinates are decimals, which §1 forbids |
| image digest, platform | OCI image-spec descriptor digest; OCI image-index platform values | string form `<os>/<arch>[/<variant>]` (execution note §4) |
| chain id | CAIP-2 | a label; the referent's block hash is the pin |
| signature | Ed25519, RFC 8032 §5.1 (pure), verified per FIPS 186-5 §7.7 with SP 800-186 App. D.1.3.2 key validation; EIP-191 `personal_sign` over secp256k1 | both required; one pinned Ed25519 verification rule (§4); EIP-191 kept from the alpha |
| folded lines in §9 | RFC 8792 §7, single-backslash strategy | |

## 1. Canonical encoding

The canonical form of a JSON value is the byte string produced by these rules. Two implementations that
disagree on one byte produce different statement ids, so every rule below is a conformance obligation.

| Rule | Obligation | On violation at parse |
|---|---|---|
| encoding | UTF-8, no BOM, no trailing newline | refuses (intrinsic: malformed statement) |
| object keys | sorted as RFC 8785 §3.2.3 sorts them: by the key's UTF-16 code units, compared as unsigned integers. This differs from code-point or UTF-8 byte order only for keys holding characters above U+FFFF; V10 in §9 pins the difference. No duplicates (RFC 7493 §2.3) | duplicate key: refuses (intrinsic) |
| whitespace | none outside strings | not an error on input; canonicalisation removes it |
| numbers | integers only, `-?(0|[1-9][0-9]*)`, magnitude ≤ 2^53 − 1 (the I-JSON range, RFC 7493 §2.2); no fraction, exponent, `NaN`, `Infinity`, `-0`. A count that can exceed the range (a 64-bit byte count, a large chain height) is a decimal string, as I-JSON recommends | refuses (intrinsic) |
| decimals | a string plus a unit field: `{"value":"120.0","unit":"degF"}`; the note never interprets the string | n/a |
| strings | RFC 8785 §3.2.2.2: `\"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`, and lowercase `\u00xx` for the other control characters U+0000–U+001F; every other code point raw as UTF-8, never `\uXXXX`-escaped; no `/` escaping | invalid UTF-8 or a lone surrogate: refuses (intrinsic) |
| string normalisation | none. Bytes are as the signer gave them. `é` (U+00E9) and `e` + U+0301 are different strings and give different ids | n/a |
| `null` vs absent | distinct. `"prev":null` is required in a first statement; everywhere else an absent field means "not stated" and a `null` field is refused by that field's schema unless the kind table lists `null` as a value | refuses (intrinsic) where the schema says so |
| booleans | `true` / `false` | |
| arrays | order is significant and preserved. A kind that treats a list as a set (`controllers`, `predecessors`, `crit`) says so and refuses duplicates and members not sorted by the key order above | refuses (intrinsic) |
| nesting | depth ≤ 16 (the envelope object is depth 1) | refuses (operational: `depth limit 16`) |
| size | signed string ≤ 65 536 bytes. The bound is on the statement, not the data: anything list-shaped and large (a per-request fetch log, a member list of thousands) belongs in a blob the statement hashes (§5, source referent) | refuses (operational: `size limit 65536`) |
| top level | the envelope is an object; anything else is not a statement | refuses (intrinsic) |

The canonical form is **what the signer signed**, so a reader never re-canonicalises a received statement
and signs or hashes the result. It canonicalises the received envelope minus `sig`, prepends the domain
tag, and checks that string against `sig`. A received line whose bytes are not already canonical is admitted
when its canonical form verifies, and is stored canonical; the reader's log holds exactly one byte form per
statement. This is why C-core-04 (local tree, hub pull, archive; permuted; duplicated) yields one view: every
delivery canonicalises to the same bytes and the same id.

Any RFC 8785 implementation produces the canonical bytes of a statement that meets the table: every vector in
§9 was checked against one. The note's additions sit on either side of JCS. Input that JCS would accept but
this note refuses (a fraction, a duplicate key, excess depth) is refused before canonicalisation; times are
checked as field values (§1.1), because JCS never rewrites a string.

Parsers that keep the last duplicate key (most language defaults) do not conform. The conformance test for
C-core-12 feeds `{"licence":"MIT","licence":"CC0-1.0"}` inside a body and expects an intrinsic refusal with
the key named, and a reader state digest unchanged before and after.

### 1.1 Time values

Every field this note types as `ts` is one string in one profile. That covers the envelope `ts`, `capture.at`,
the referent `at`, the window bounds `from` and `to`, `finality.state_at_capture.captured_at`, and the key
events' `effective`. A field typed `date` (for example `frozen_before`) is an RFC 3339 `full-date`.

| Rule | Obligation | On violation |
|---|---|---|
| syntax | RFC 3339 §5.6 `date-time`, with `T` and `Z` in upper case. Offset `Z` only: `+00:00` and other numeric offsets are refused, so an instant has one spelling | refuses (intrinsic: malformed statement) |
| fraction | 0 to 9 digits after the seconds. Canonical per XML Schema 1.1 `dateTimeCanonicalMap`: no trailing zeros, and no `.` when the fraction is zero. `12:00:00.5Z` conforms; `12:00:00.50Z`, `12:00:00.0Z` and a tenth digit do not | refuses (intrinsic) |
| leap second | second `60` is admitted at 23:59:60 on the last day of a month (RFC 3339 §5.7), in UTC only, as written. The note keeps no leap-second table and never normalises `:60` to the next minute. CGPM 2022 Resolution 4 ends new leap seconds by 2035; historical data still carries them | refuses (intrinsic) at any other position |
| timescale | UTC unless the referent says otherwise (below) | |
| comparison | parsed to (UTC calendar second, nanoseconds), never compared as text: `…00.5Z` sorts after `…00.25Z` though its string sorts before it. A `:60` instant sorts after `:59` and before the next minute | a wrong order is a conformance failure (C-core-105, C-core-106) |
| precision | an implementation that cannot hold nanoseconds must keep the string; parsing through a millisecond date type silently changes the instant and does not conform. Anything finer than a nanosecond belongs in the content | |

**Timescales.** The envelope `ts` and `capture.at` are always UTC: they are the signer's and the observer's
clock claims. A phenomenon or method referent may carry `timescale`, a code from FITS 4.0 Table 30, when the
measured times (the referent `at`, the window bounds) were recorded in another scale. The admitted codes are
`TAI`, `TT`, `TDB`, `TCG`, `TCB`, `UT1`, `UTC`, `GPS` and `LOCAL`, optionally followed by a realisation in
parentheses as FITS allows (`TT(BIPM08)`, `UTC(NIST)`). FITS's deprecated codes (`TDT`, `IAT`, `ET`, `GMT`)
are not admitted. When `timescale` is present and is not `UTC` or a UTC realisation, the referent's times
carry no `Z`, because `Z` asserts UTC; this is the FITS `datetime` form, and second `60` is refused in those
scales. `GPS` is admitted although RFC 9581 §3.4 advises converting it to TAI (GPS = TAI − 19 s), because
physics data arrives labelled that way and the note never converts. A reader compares times in different
scales only if it holds a conversion; otherwise the comparison is `not comparable`, never a guess. Time
uncertainty is not a field yet (§11).

## 2. The envelope

```text
{
  "rc":       "rc/1",                 format tag: "rc/" + major version      required
  "kind":     "authored",             statement kind (§5)                    required
  "signer":   "0x<40 lowercase hex>", key identity (recover-to-address)     required
  "alg":      "eip191-secp256k1",     signature algorithm (§4)               required
  "seq":      0,                      position in the signer's log (§7)      required
  "prev":     null | "<64 hex>",      id of the signer's previous statement  required (null only at seq 0)
  "merges":   ["<64 hex>"],           other tips of the signer's own log (§7)  optional
  "ts":       "2026-10-12T20:00:00Z", signer-asserted time, UTC, §1.1                      required
  "crit":     ["x_escrow"],           extension names the reader must know (§6)   optional
  "body":     { ... },                kind-specific content (§5)             required
  "sig":      "0x<130 hex>"           the signature                          required on the wire
}
```

**What is signed.** Every field except `sig`. The **signed string** is

```text
PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
type            = "application/vnd.research-commons." kind ".v" major "+json"
body            = canonical(envelope without "sig")
SP = one 0x20 byte · LEN = the byte length in decimal ASCII, no leading zeros
```

This is the pre-authentication encoding of DSSE (Dead Simple Signing Envelope, v1.0.2, protocol.md), the
framing in-toto, Sigstore, TUF and PyPI attestations sign. The **payload type** is the domain tag. It is
derived from `rc` and `kind`, so a statement whose type does not match its own `rc` and `kind` fields cannot
verify: a reader that recomputes the type from the fields and recovers a different signer refuses with
`bad signature`. The type keeps a signature over an `authored` from ever verifying as an `anchors`, and keeps
every other signed object the tool might one day add (a policy digest, a local receipt) out of the statement
namespace by giving it a different type. Both lengths are signed, so no choice of body bytes can shift where
the type ends.

What is adopted is the framing only. DSSE's JSON envelope (base64 `payload`, `signatures[]`) is not the wire
form: a statement is one canonical JSON line in its signer's log (§7), with `sig` beside the signed fields.
DSSE's rule to reject an unsupported payload type is replaced by this note's retain-as-`unsupported` (§6).
Any DSSE library that accepts a caller-supplied signing function can therefore rebuild the exact bytes a
statement's signature covers. Under `eip191-secp256k1` the PAE string is the EIP-191 message (§4).

The payload types are vendor-tree media types (RFC 6838 §3.2). They are not registered with IANA yet;
registration is the project's decision and changes nothing on the wire.

**Why `prev` and `seq` are inside the signature.** In the alpha the chain link was set at commit and left
outside the signature so that chaining could not invalidate a signature. The claims-model note turns that
around: a per-key log is "a hash chain only that key extends" (I3), and a same-key concurrent append must
"become a visible fork, not a lost line" (§12). Both need the link to be the signer's word. With `prev`
signed, two lines that both chain after one id are two signed statements by the same key, a `FORK` the key
cannot disown and a relayer cannot manufacture by re-linking. With `prev` outside, a relayer could re-chain
lines and a reader could not tell a rewrite from a race (C-core-127, C-core-14).

**Why `merges` is beside `prev`, not instead of it.** A log is a chain with occasional forks, not a general
graph: `prev` stays one id, so `seq` continuity, gap detection and the single-chain reading are unchanged, and
a fork's other tips are named in a separate list. The idea is Ethereum's ommers (a block names one parent and,
separately, other blocks it has seen), with the difference that every id in `merges` is the signer's own line,
so naming it is the signer's word that the branch is theirs (§7).

**`ts` is a claim, not a bound.** It is signed so that it is unambiguously the signer's assertion, and it
orders nothing on its own (claims-model note §10). A `ts` more than 300 seconds ahead of the writer's clock
is refused at write time (C-core-105); a `ts` earlier than the `ts` of the statement at `prev` is admitted and
flagged `incoherent` (C-core-106). Both comparisons use parsed times (§1.1).

## 3. Statement identity

`id = sha256(signed string)`, rendered as 64 lowercase hex characters, with no prefix (§8 says why ids carry
none). The id covers the payload type, every envelope field and the whole body, and excludes `sig`.
Consequences, each a test:

- Two statements from one key that differ in one field (a reason, a TTL, an unknown extension) have two ids,
  and neither is a replay of the other (C-core-02a first pair, C-core-11).
- One signed string with two different valid signature encodings has one id (C-core-02a second pair,
  C-core-10, P-02). The second delivery is a no-op; the stored `sig` is the canonical encoding (§4).
- Flipping one byte anywhere in the signed string changes the id and breaks the signature (C-core-09).
- The id of a genesis statement is the resource id (C-core-77); the id of an edition is its edition hash
  (C-core-78); `prev` and `predecessors` and `head` are ids, never digests.

**Display aliases.** A surface may print the first 12 hex characters of an id or of a content digest (after
the `sha256:` prefix) as a label. An alias is accepted as input only when exactly one held object matches;
zero matches is `not found` and two or more is an error that lists every candidate full hash and selects
nothing (C-core-03). Aliases are never written into a statement: every reference field in §5 is a full id or
digest, and a 12-character value where a full one is required is a malformed statement.

## 4. Signature scheme

Two algorithms are required of every implementation. Every reader verifies both; a writer signs with one.

| `alg` | `signer` | Signed bytes | Signature | Verification |
|---|---|---|---|---|
| `ed25519` | `ed25519:` + 64 lowercase hex, the 32-byte RFC 8032 public key | the signed string (§2, the PAE string) as UTF-8 bytes, signed by pure Ed25519 (RFC 8032 §5.1.6; no prehash, no context) | 64 bytes `R ‖ S` as 128 lowercase hex (no `0x`) | the pinned rule below; failure is `bad signature` (intrinsic) |
| `eip191-secp256k1` | `0x` + 40 lowercase hex, the Ethereum address | EIP-191 `personal_sign`: keccak256 of `"\x19Ethereum Signed Message:\n" + len + msg`, where `msg` is the signed string (§2, the PAE string) as UTF-8 bytes and `len` is its byte length in decimal | 65 bytes `r ‖ s ‖ v` as `0x` + 130 lowercase hex | recover the secp256k1 public key, keccak-derive the address, compare with `signer`; mismatch is `bad signature` (intrinsic) |

`alg` and the `signer` prefix must agree: an `ed25519` statement whose `signer` is an address, or the reverse,
is malformed. **New keys default to `ed25519`.** `eip191-secp256k1` is for identities linked to a blockchain
account: a person signing from a hardware wallet, or an agent that holds custody of its own assets and pays or
is paid for work. Neither is ranked above the other by any rule in this note.

**Ed25519 verification is pinned.** RFC 8032 permits two verification equations and leaves key validation
open, and deployed libraries disagree on crafted signatures: on the twelve edge cases of the
`ed25519-speccheck` suite, OpenSSL, BoringSSL, Go and pyca accept cases 0–3 and 11, libsodium accepts only
case 3, and ZIP-215 verifiers accept 0–5 and 8–11. Two readers that disagree on whether a signature is valid
would hold different logs, so a conforming reader uses exactly this rule (FIPS 186-5 §7.7, with the full
public-key validation of SP 800-186 App. D.1.3.2 applied to both points):

1. `S`, the second 32 bytes read little-endian, is below the group order `L`; otherwise refuse.
2. `A` (the public key) and `R` (the first 32 bytes) are canonical encodings: the low 255 bits, read
   little-endian, are below p = 2^255 − 19. Each decodes to a curve point.
3. `A` and `R` are each in the prime-order subgroup: not the identity, and `[L]P` is the identity. This
   refuses every small-order and mixed-order point.
4. The equation `[S]B = R + [k]A` holds, with `k` = SHA-512(`R ‖ A ‖ M`) read little-endian.

Step 2 uses RFC 8032 §5.1.3 decoding as written: an `x` of zero with the sign bit set is not a valid encoding.
Steps 1–3 are cheap checks a reader runs before any stock verifier; step 4 is then the same in every library,
because a prime-order `A` and `R` make the cofactored and cofactorless equations agree. Under this rule all
twelve speccheck cases are refused (OpenSSL alone accepts five of them), and honest signatures from any RFC
8032 signer verify. Checked for this note with OpenSSL 3.5 (Node), pyca `cryptography` 50 and `@noble/curves`
1.9 in front of the pre-checks, and an independent Python implementation of steps 1–3. A reader that cannot
run the pre-checks does not conform. The speccheck cases are in the vectors file as negative vectors (§9).

Rules:

- **`signer` is the identity.** A statement whose signature does not verify under its `signer` (for
  `eip191-secp256k1`, whose recovered address differs from it) is refused as `bad signature`, which is also
  how "signer names A but signed by B" fails (C-core-14). Upper-case hex and EIP-55 checksummed addresses are
  malformed: the canonical form is lowercase.
- **Equivalent encodings are one statement, stored in one form.** An Ed25519 signature has exactly one
  encoding under the pinned rule (step 1 refuses `S ≥ L`), so the question arises only for
  `eip191-secp256k1`. There, `v` may arrive as 27/28 or 0/1; `s` may
  arrive in high form (above n/2, the form EIP-2 refuses for Ethereum transactions). A reader accepts every
  valid encoding, verifies it, and writes the **canonical encoding**: low-`s` and `v` ∈ {27, 28}. The id,
  which does not include `sig`, is the same either way. So every reader's log holds the same bytes for a
  statement, signature included, whichever encoding arrived first (§1). The vectors in §9 show two encodings
  of one signature verifying to one id; each is stored as V1's `sig`.
- **Unknown `alg`.** Retained in the signer's log as `unsupported`, displayed as such, never evaluated: it
  grants nothing, counts in no projection, and is not an error on `pull`. Adding an algorithm is a minor
  format change; a reader implementing it later re-evaluates retained lines (I5).
- **The key is a commons identity, not a payment wallet.** EIP-191 prefixing guarantees a statement can never
  be a valid transaction; the reverse discipline (never reuse a wallet key as a commons key) is the signer's,
  and §4.1 gives the reasons. An identity that wants to be linked to its payment account says so explicitly.
- **How a key was made is invisible here.** A randomly generated key and one derived from a seed phrase
  produce the same `signer` and the same signatures; no rule in this note can tell them apart or depends on
  the difference. §4.1 is guidance for writers, not a conformance requirement.
- **Private keys never appear** in any statement, log, error or test fixture other than disposable keys
  minted for a test run. The vector keys in §9 are derivable from public strings and are therefore public.

### 4.1 Key generation and custody (guidance)

Nothing in this subsection is checked by a reader. It is what the reference tool does and recommends.

- **Ed25519 keys are generated from a 32-byte seed, and the seed is what is stored** (RFC 8032 §5.1.5: the
  signing scalar is derived from a hash of the seed). Keeping the seed, not only the expanded scalar, keeps a
  post-quantum migration path open (§4.2).
- **Deriving keys from a seed phrase is optional.** A holder who wants one backup for several keys may derive
  them from a BIP-39 mnemonic: Ed25519 keys by SLIP-0010, which derives hardened children only and keeps each
  child a seed; secp256k1 keys by BIP-32 on **hardened paths only** (BIP-32 itself warns that a parent
  extended public key plus any non-hardened child private key reveals the parent private key and the whole
  tree below it). A Commons key gets its own branch, never an asset account's path. ERC-1581 proposed such a
  branch for non-wallet keys (`m/43'/60'/1581'/…`) but is stagnant; the reference tool names its path in its
  own documentation and treats it as a convention, not a format.
- **The mnemonic is the identity.** Whoever holds it can sign as every key derived from it, past and future.
  For an agent it belongs in the same custody as the agent's funds, never in a configuration file.
- **Rotation after compromise uses fresh entropy.** A `rotate_key` to a successor derived from the same seed
  is fine for routine rotation; after a `revoke_key` with reason `key_compromise`, a successor from the same
  seed is compromised with it.
- **Never reuse a payment key as a Commons key.** Four reasons:
  1. *Exposure.* A Commons key signs often and from automated code; a custody key should sign rarely, ideally
     on a device after review. One key means a leak anywhere in the busier path is a leak of the funds.
  2. *Permanent linkage.* Every statement publishes its `signer`, and logs are append-only and replicated. A
     payment key would tie the whole research record to the account's full financial history, irreversibly.
  3. *Coupled recovery.* A compromised Commons key is answered by `revoke_key`; a compromised payment key by
     moving funds at once. One key turns two recoveries into one emergency, and hands an attacker who came in
     through the signing path the assets as well.
  4. *Signing-oracle risk.* EIP-191's prefix stops a statement being a transaction, but a signer that holds a
     wallet key and signs messages for Commons can be induced to sign other messages with financial effect
     (EIP-712 permits and approvals, for example). A Commons signer should hold no key that can.
- **Linking an identity to its account, deliberately.** An identity that wants the link either derives both
  keys from one seed on separate hardened branches (one backup, a link it can prove when it chooses), or
  publishes it once: the Commons key signs a `describes` naming the account address, and the account signs a
  matching message. Either way each key keeps its own exposure and its own revocation.

### 4.2 Quantum horizon

Both required algorithms rest on elliptic-curve discrete logarithms, which a large enough quantum computer
breaks (Shor's algorithm): given a public key, it recovers the private key. Every statement publishes the
public key (`ed25519`) or lets anyone recover it (`eip191-secp256k1`), so both are fully exposed from the
first signature. NIST's transition draft (IR 8547 ipd, Table 2) lists ECDSA and EdDSA as quantum-vulnerable
and disallows both after 2035. Ed25519 has one structural advantage: its private key is a hash of a seed, so a
holder can later prove knowledge of the seed in zero knowledge with a quantum-safe proof system and authorize
a new key, even after the old public key is broken (Baldimtsi, Chalkias et al., "Post-Quantum Readiness in
EdDSA Chains", FC 2026). BIP-32 secp256k1 keys offer no such witness. That is research today, not a mechanism
here.

What protects this format does not depend on the curve:

1. **Anchors outlast signatures.** An `anchors` bound verified to a block before a break proves the covered
   prefix existed then. A forger after a break can sign new statements but cannot place them under an earlier
   anchor. Proof-of-work and SHA-256 are not broken by Shor; Grover's algorithm halves SHA-256's preimage
   security to 128 bits.
2. **Rotation to a post-quantum algorithm before a break.** `ml-dsa-65` (ML-DSA, FIPS 204, final since August
   2024; public key 1 952 bytes, signature 3 309 bytes) is reserved as the next `alg` value. Adding it is a
   minor change (§6): the PAE string is algorithm-neutral and readers retain unknown algorithms as
   `unsupported`. Holders migrate with the existing `rotate_key`, signed by the classical key while it is
   still trustworthy. The sizes fit the 64 KiB statement bound.
3. **A possible cutoff policy.** A reader's policy could name a date after which a classical signature
   counts only where a verified anchor from before that date covers it, showing later classical statements as
   `quantum-unprotected`. The mechanism would need nothing new (anchors and policy already exist). Whether to
   adopt it, and with what date, is deliberately left open (§12): the state of post-quantum research does not
   yet support choosing a cutoff, and the question is for participants to discuss.

For `eip191-secp256k1` identities the migration also depends on the linked chain's own post-quantum plans,
which are unsettled (EIP-7932, a registry for additional signature algorithms, is a draft). The holder's
Commons key and its assets face the same problem and can migrate together.


## 5. Kinds and body fields

Kinds are the closed vocabulary of claims-model note §4; this section fixes their body field names (snake
case) and types. `R` = required, `O` = optional. `digest` = a content digest, `sha256:` + 64 lowercase hex
(§8). `key` = a `signer` value of either algorithm (§4): `ed25519:` + 64 lowercase hex, or `0x` + 40 lowercase
hex. `id` = a statement id, 64 lowercase hex with no prefix (§3). `ts` = a time value (§1.1); `date` = an RFC
3339 `full-date`. A kind listed here with a missing `R` field is a malformed statement (intrinsic), with one
exception the note itself makes: an `observed` whose `referent` lacks a field its class requires is valid,
admitted, and shown `unpinned` (claims-model note §5.3.1). A kind not listed here is stored and displayed as
`unknown kind` and grants nothing (C-core-13).

**Shared body objects**

| Object | Fields |
|---|---|
| `content` | `digest` digest R · `size` integer R (the exact byte length) · `media_type` string O (an RFC 6838 media type, `type/subtype` with optional parameters, as in an HTTP `Content-Type`) |
| `provenance` | `workflow` digest R · `inputs` list of digest R (order preserved) · `environment` object O (the environment record's standard forms, execution note §4: `image_digest` an OCI digest, `sha256:` + 64 hex; `platform` `<os>/<arch>[/<variant>]` with Go `GOOS`/`GOARCH` and OCI variant values; `harness_commit` full lowercase commit hex) |
| `window` | `from` ts R · `to` ts R. Half-open, `[from, to)`: an instant equal to `to` is outside. The start-and-end form of an ISO 8601 time interval and of RFC 9581 §5 periods, written as two fields so each is checked as a time value (§1.1). The same shape wherever a window appears |
| disclosures (on `authored`, `observed`) | `licence` string O (an SPDX license expression, SPDX 3.0.1 Annex B; terms with no SPDX identifier are named by a `LicenseRef-` id whose text is cited in `licence_texts`, below. Stored as written, never case-normalised; an expression the reader cannot parse displays `unknown`, C-core-67) · `attribution` string O · `availability` object O (`redistribution` `"permitted"`/`"restricted"`/`"withheld"` R, `obtainable` boolean R, `withheld_until` string O, a condition in prose or a task or edition reference, claims-model note §7) · `replication` `"bytes"`/`"protocol"`/`"none"` O · `comparator` digest O · `sampling` object O (`n` integer R, the total · `unit` string R, e.g. `runs`, `slots`, `records` · `groups` list of {`name` string R, `n` integer R} O, one per arm, names unique · `window` O · `dispersion` object O) · `shelf_life_days` integer O · `pre_registration` `"exploratory"` or absent O · `fulfills` object O (`resource` id, `edition` id) · `intended_for` object O (`resource` id R, `edition` id R, `edition_applied` id R, `outcome` `"ok"`/`"unchecked"` R) · `description` string O |
| `finality` | `rule` string R · `rule_source` string O (a digest when the document is held, else a location) · `state_at_capture` object R (`depth` integer, or `run` string, or `captured_at` ts) |
| `licence_texts` (on `authored`, `observed`) | object O mapping each `LicenseRef-` id used in `licence` to its source, as for `rule_source`: a digest when the text is held as a blob, else a location (an RFC 3986 URI). Displayed `cited (text held)` or `cited (location only, unverified)`; an id with no entry is `cited (no source)`. Terms the author may not republish are cited by location |

**Kinds**

| `kind` | Body fields |
|---|---|
| `authored` | `content` R · `type` string R (`dataset`, `workflow`, `skill`, `synthesis`, `report`, `other`) · `provenance` O · disclosures O · `supersedes` digest O (the author's own earlier blob) · `extends` digest O |
| `observed` | `content` R · `class` R, exactly one of `exact-bytes` / `source` / `phenomenon` / `method` / `none-yet` (a list, or any second class field, is malformed; C-core-35) · `referent` object R, keys per class: exact-bytes `chain_id` string (a CAIP-2 chain id, e.g. `bip122:` + the first 32 hex of the genesis block hash), `block_hash` string (the block hash in the chain's display form, 64 lowercase hex; it names a block, not bytes this note hashes), `depth` integer; source, either one request (`endpoint` string, `parameters` object, `response_digest` digest) or a batch (`requests` object: `digest` digest of a request log carried inside `content`, `format` string naming its layout, `count` integer; each log entry carries endpoint, parameters, status, time and response digest), never both; phenomenon `instrument` string (a persistent identifier URI when the instrument has one, else free text), `location` string (an RFC 5870 `geo:` URI: WGS 84 latitude, longitude and optional altitude in metres, with `u=` uncertainty in metres; compared per RFC 5870 §3.4.4, numerically, never as text), `place` string O (a human label beside the coordinates), `at` ts, `timescale` string O (§1.1); method `method_edition` id, `environment` object (`image_digest`, `platform`, `harness_commit`), `system` object R with free keys (whatever identifies the measured system and changes the apparatus under the observer, e.g. a model pin, a provider, a routing era; values are strings), `inputs` list of digest O (the protocol's pinned inputs: scenario edition, seed set, configuration; order preserved), `window` (the shared object above), `timescale` string O (§1.1); none-yet: any · `capture` object R (`at` ts R, `evidence` `"self-asserted"`/`"anchored-at-capture"`/`"witnessed"`/`"device-attested"` R, `operator` string O, `instrument` string O, `witnesses` list of key O, `attestation` object O) · `finality` O (exact-bytes and source only) · disclosures O |
| `holds` | `content` R · `locations` list of string O (RFC 3986 URIs: `https:` URLs or content-addressed URIs; a hint, never authenticated, never dereferenced during verification) |
| `describes` | `about` object R (exactly one of `content` digest, `statement` id, `resource` id) · `tags` list of string O · `note` string O · `links` list of object O (`rel` string R, one of `content`/`statement`/`resource`/`url` R). `rel` is a relation type registered in the IANA Link Relations registry (compared case-insensitively, RFC 8288 §2.1.1) or an absolute URI (§2.1.2). A link is the signer's annotation and grants nothing: no resolver reads `rel`, so `predecessor-version` on a `describes` is never a supersession |
| `reproduced` | `of` id R (the `authored` reproduced) · `result` `"match"`/`"diverged"`/`"not-comparable"` R · `content` R (the bytes this run produced) · `provenance` R · `comparator` digest O · `report` digest O (divergence report) |
| `corroborates` | `of` id R (the `observed`) · `result` id R (the derived corroboration result's `authored`) · `verdict` `"supports"`/`"contradicts"`/`"inconclusive"` R · `model` string R (agreement model name or hash) · `cohort` object R (`rule` string, or `hand_picked` true) · `shares` list of string O (what this shares with the original: feed, operator, instrument) · `cause` string O (for `inconclusive`) |
| `refutes` | `of` id R · `evidence` digest R · `note` string O |
| `retracts` | `of` id R (the signer's own `authored`/`observed`) · `reason` string O |
| `anchors` | `head` id R (a statement in the signer's own log) · `head_seq` integer R · `proof` object R (`scheme` string R, `digest` digest R of the proof bytes, `quality_claimed` string O). A `head` in another key's log is malformed |
| `genesis` | `type` `"collection"`/`"task"`/`"series"` R · `name` string R · `controllers` list of key R (set) · `rule` object R (`any_one` true, or `k_of_n` {`k` integer}) · `forked_from` id O |
| `edition` | `resource` id R · `predecessors` list of id R (set; the genesis id for the first edition; several for a merge) · `contents` object R (`members` list of {`content` or `resource` or `statement`, `role` string} O, `schema` digest O, `rules` list of {`dialect` string, `expr` string} O, `contract` object O, `selection` `"curated"`/`"rule-based"`/`"completeness"` O, `frozen_before` object O (exactly one of `date` date, `height` integer, `run` string: the same units as `finality.state_at_capture`, so the declared boundary is compared with the boundary the members' finality rules compute in the same unit, and a declared unit different from the computed one is `not comparable`, never converted), `controllers` and `rule` O for a controller change) |
| `intent` · `progress` · `withdraw` · `submit` · `decide` | all: `task` id R · `edition` id R. `submit`: `result` digest R, `salt` string O, `self_declared_independence` boolean O. `decide`: `submissions` list of id R, `verdict` `"accept"`/`"reject"` R, `evaluations` list of digest O, `supersedes` id O. `progress`: `note` string O |
| `rotate_key` · `revoke_key` | `rotate_key`: `successor` key R, `effective` ts O. `revoke_key`: `reason` R, one of `key_compromise` / `superseded` / `cessation_of_operation` / `unspecified` (the RFC 5280 §5.3.1 CRL reason codes that apply to a signing key, in snake case), `note` string O, `effective` ts O. Both are statements by the old key about itself. Only `key_compromise` casts doubt on statements before `effective`; what a reader does with that doubt is its policy (claims-model note §4) |

Every `R` field of a listed kind is checked at every gate by the one validation core (C-core-109). Field
semantics (what `match` means, how a rule is evaluated) belong to the claims-model note and the profile notes;
this table fixes only names, types and presence.

## 6. Extensions and versioning

- **Unknown fields are retained and ignored.** They are inside the signature and the id (C-core-02a, 09), are
  stored byte-exact, are never displayed as anything but the signer's opaque field, and never influence a
  default, grade or exit code. Names beginning `x_` are reserved for extensions; a future minor revision never
  claims an `x_` name.
- **`crit`** takes its name and structure from JOSE's `crit` header (RFC 7515 §4.1.11; COSE's label 2,
  RFC 9052 §3.1, is the same idea). It is a sorted, duplicate-free, non-empty list of top-level body field
  names. Each must be present in the body and must be an extension name, never a field this note defines;
  a `crit` that breaks any of these rules is malformed. A reader that does not implement every listed name
  treats the statement as **`unsupported`**: retained in the log (it is a valid signed line and still
  chains), displayed with the unknown names, and evaluated under no interpretation at all. It is not an
  `authored` with the field dropped; it is nothing yet. **Departure from JOSE:** JOSE makes such a message
  invalid. Here it is retained, because a statement a reader cannot evaluate today may be evaluated by the
  same reader after an upgrade (I5), and refusal is reserved for intrinsic faults (I8).
- **Format tag.** `rc/<major>`. A reader implements one major. A statement with another major is
  `unsupported` in the same way: retained, chained, never evaluated, never an error on `pull`. A statement
  with a malformed `rc` (not `rc/` + positive integer) is intrinsic malformed.
- **Minor changes** (new optional field, new `alg`, new kind) do not bump the major, and never reinterpret
  existing signed bytes. A change that would (a required field added, a type changed, a kind's meaning
  changed) bumps the major, which changes every payload type and so every id.

## 7. Per-key logs

A **log** is the sequence of statements by one `signer`, stored as a file of canonical lines (one statement
per line, LF-terminated) or carried as a stream; the storage note owns the file layout, this note owns the
line contract.

- `seq` starts at 0 and increases by exactly 1 along `prev`. The first statement has `prev: null` and
  `seq: 0`. Every other statement has `prev` = the id of the statement at `seq - 1` in the same log.
- **Ownership rule.** Every line in a log named for key K has `signer` = K and verifies under K. A line whose
  `signer` is another key, wherever it was delivered, is refused (intrinsic: `line in another key's log`)
  and K's chain is unchanged (C-core-14). The refusal scope is that line.
- **Append-only.** Nothing held is ever replaced or removed by a delivery. A delivered line at a held `seq`
  with a different id is a second line by the same key at that position, which only the key can sign (its
  `prev` is inside the signature): it is a fork, retained and shown as below, never a refusal. There is no
  `rewritten history` refusal; the alpha needed one because its chain link was outside the signature.
- **Forks.** Two valid lines by K with the same `prev` are both retained and the log shows `FORK` at that
  point (C-core-127). Neither is refused; neither is the tip; later statements choose a branch by `prev`.
- **Clearing a fork: `merges`.** A line may carry `merges`, a list of ids of other statements in K's own log
  that it absorbs, beside its single `prev`. It is a set: non-empty, sorted, no duplicates, never containing
  `prev`, and every entry a statement by K with a `seq` lower than this line's. `seq` is still `prev`'s plus 1.
  A `merges` that breaks a rule is malformed (intrinsic). A fork **clears** when every tip at it is an
  ancestor of one line through `prev` and `merges` links: the rule a merge edition follows for a resource
  (claims-model note §8), so "cleared" means one thing for logs and resources (C-core-127a). A line that
  follows one tip and names no other leaves the fork shown: following a branch is not acknowledging the
  others. Naming a line is the signer's statement that it is theirs; a branch the signer does not recognise
  is answered with `revoke_key` (`key_compromise`), not merged. An entry the reader does not hold makes the
  line `detached` exactly as an unresolved `prev` does (C-core-127b). V11–V12 in §9 are a fork and its
  clearing.
- **Gaps.** A line whose `prev` matches nothing held is retained as `detached`: it may follow statements
  the reader has not received yet. It is that key's signed word, and nothing more until it chains:
  - an `authored` or `observed` that is detached is attributed to its signer (the signature alone settles
    who said it) and is shown, but counts toward no grade, corroboration, quorum, priority or default;
  - every other kind is retained and shown and is not evaluated at all: a detached `edition` is no
    approval, a detached `decide` settles nothing, a detached `anchors` bounds nothing, a detached
    `rotate_key` or `revoke_key` is not yet in force;
  - the reason is the missing stretch. It may hold a `revoke_key` with `key_compromise`, a `rotate_key`, or
    an earlier edition, any of which changes what the detached line means; attribution survives that,
    authority does not;
  - the display names the gap (`detached: waiting for seq 37–40 of <key>`), and a pull that receives a
    detached line asks the same source for the missing range before reporting;
  - once the gap fills, the line is evaluated like any other; nothing about it was decided while it waited.
  (C-core-143.)
- **Ordering.** The log's order is `seq`, never file order or `ts`. Duplicates by id are dropped on write.
- **Anchors** bound only the signer's own prefix up to `head` (C-btc-04); an `anchors` whose `head` is not in
  the signer's log is malformed.

## 8. Content hashing

A blob's identity is its **digest**: SHA-256 over its exact bytes, written in the OCI image-spec digest form
`sha256:` + 64 lowercase hex, with no transcoding and no newline handling (C-core-117). Upper-case hex, a
missing prefix, or a prefix other than `sha256:` in an `rc/1` statement is malformed. `content.size` is the
exact length, and a fetch checks the size before the digest (storage note §9). The empty blob is valid:
`sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, size 0. A fetched blob is verified
against the full digest before it is installed; the display alias is never used for that check. The `content`
object is therefore an OCI descriptor in all but field spelling (`digest`, `size`, `media_type`), and its
digest is the name the blob has in an OCI blob tree (`blobs/sha256/<hex>`, storage note §1.1).

**Why content digests carry the algorithm and statement ids do not.** A content digest names bytes that also
live outside this format, in registries, archives and other stores, where a second algorithm for the same
bytes is ordinary; the prefix says how to check it, and a future algorithm is a new prefix (a minor change,
§6). A statement id is the digest of a signed string whose payload type already names the format version
(§2), and `prev` must equal exactly the id the signer computed. Its algorithm is fixed by the major version,
and changing it changes every id regardless, so a prefix would be a second place to declare the algorithm
that could only ever disagree with the first.

## 9. Test vectors

The normative vectors are the JSON file `DESIGN-notes-wire-format.vectors.json` beside this note: each
positive vector's exact signed string, byte count, id and signature; the equivalent signature encodings of
V1; the Ed25519 log (E1–E2) with its key; and each negative vector's exact input bytes with its required
result. The Ed25519 edge cases NE1–NE12 are the `ed25519-speccheck` suite (Apache-2.0), copied with their
source named. The blocks below are rendered from
that file for reading. Where the two differ, the file is right and this note has a bug.

Computed with Python 3 `hashlib` and the alpha signer (`viem` `signMessage`) in a throwaway directory; every
hash below is pasted from that run. Each signed string was also checked byte-identical to two independent
implementations: an RFC 8785 canonicaliser (the Python `jcs` package) on the parsed envelope, and the DSSE PAE
function of the Python `securesystemslib` package (1.5.1) on the payload type and canonical body. The signing
key is the **disposable, public** key `sha256("research-commons wire-format test key 1")` as a 32-byte hex
scalar, whose address is `0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a`. Never use it for anything else. Vectors
V1–V8 form one log (`seq` 0–7), extended by V9–V10 (`seq` 8–9); each `prev` is the previous vector's id. V11
is a second line after V9 (`seq` 9), so the log forks there; V12 (`seq` 10) follows V10 and names V11 in
`merges`, which clears the fork. Long
lines are folded per RFC 8792 §7 (single backslash): a trailing `\` means the line continues with no newline,
and leading spaces on the continuation are not part of the content. A signed string contains no LF: the
separators are the four spaces of the PAE header.

**V1 authored (derived, with provenance)**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 700 bytes:
DSSEv1 49 application/vnd.research-commons.authored.v1+json 636 {"alg":"eip191-secp256k1","body":{"a\
vailability":{"obtainable":true,"redistribution":"permitted"},"content":{"digest":"sha256:2b2b2b2b2b\
2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b","size":4096},"licence":"CC-BY-4.0","provenan\
ce":{"inputs":["sha256:1111111111111111111111111111111111111111111111111111111111111111","sha256:222\
2222222222222222222222222222222222222222222222222222222222222"],"workflow":"sha256:c0c0c0c0c0c0c0c0c\
0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"},"type":"dataset"},"kind":"authored","prev":null,"r\
c":"rc/1","seq":0,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:00:00Z"}
id:  4b54e578d523dc33ae9814af7f837f6c2acec48cd2420704788ba866d9b0f1cf
sig: 0x1ca247faed0dceef2817c7384c20b872c4d75c90689f4eeb70ceda062078a6bd78a1\
     d362854278c098f826a3f5600197379c0e1e5a199cc93db6a7ab8d4178661b
```

Equivalent encodings of this signature, both recovering the same signer, both the same statement (C-core-10):
`v` as `00` instead of `1b`, and the high-`s` form `0x1ca2…a6bd` ‖
`875e2c9d7abd873f6707d95c0a9ffe678312cec8552f0372821bb6e142f4c8db` ‖ `1c`. A reader stores either as V1's
`sig` above (§4).

**V2 observed (exact-bytes, chain referent, finality)**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 762 bytes:
DSSEv1 49 application/vnd.research-commons.observed.v1+json 698 {"alg":"eip191-secp256k1","body":{"c\
apture":{"at":"2026-10-12T20:04:30Z","evidence":"self-asserted","instrument":"node v27.0","operator"\
:"runner-7"},"class":"exact-bytes","content":{"digest":"sha256:7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7\
a7a7a7a7a7a7a7a7a7a7a7a7a7a","size":812},"finality":{"rule":"confirmations>=6","state_at_capture":{"\
depth":3}},"referent":{"block_hash":"00000000000000000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
a","chain_id":"bip122:000000000019d6689c085ae165831e93","depth":3}},"kind":"observed","prev":"4b54e5\
78d523dc33ae9814af7f837f6c2acec48cd2420704788ba866d9b0f1cf","rc":"rc/1","seq":1,"signer":"0xf71e7c9c\
ce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:05:00Z"}
id:  904eca8851b275b994f60e538ead7e59922f77aa1917698a9f33050eed067335
sig: 0xd02bbb327c29d6515456b02bb7ac22f7d8490b0eb44d4ae1d283907066e4bb99065a\
     e581680cf6261529628bdd9c77cb97b3792b732be5361e55d835e6cbf7f31b
```

No `rule_source`: displayed as `observer's convention`; referent status `provisional (3; final at 6)`.

**V3 holds (external location)**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 504 bytes:
DSSEv1 46 application/vnd.research-commons.holds.v1+json 443 {"alg":"eip191-secp256k1","body":{"cont\
ent":{"digest":"sha256:2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b","size":4096\
},"locations":["https://mirror.example/blobs/2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\
b2b2b2b2b"]},"kind":"holds","prev":"904eca8851b275b994f60e538ead7e59922f77aa1917698a9f33050eed067335\
","rc":"rc/1","seq":2,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:06:0\
0Z"}
id:  ad1efcc1e1245d4ad674787855fbc037340e06be727d4391fc3ba08d8166e61f
sig: 0x2e075d84bb675138c01a23ea1a1137244376ae25c2c51e0aed93ef9c9ce6948f63b1\
     2beb7968dfd3bbe3ba91bcc6a5f052d39a9d96497752031657b225c58ed71c
```

**V4 describes (Unicode, control characters, nested lists and objects)**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 583 bytes:
DSSEv1 50 application/vnd.research-commons.describes.v1+json 518 {"alg":"eip191-secp256k1","body":{"\
about":{"content":"sha256:2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"},"links"\
:[{"content":"sha256:7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a","rel":"relate\
d"}],"note":"line1\nline2\ttab \u0001 ctl","tags":["météo","日本語","\"quoted\""]},"kind":"describes","\
prev":"ad1efcc1e1245d4ad674787855fbc037340e06be727d4391fc3ba08d8166e61f","rc":"rc/1","seq":3,"signer\
":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:07:00Z"}
id:  a79e1a3ac6af2c09a65796aea07860c06045d5945c7a75a82c8d3e9d8b4e41b1
sig: 0xd0e05a4f2d52d36ce807055c6fe51ec5f259d2093801d1452941749cf16099bc4f5b\
     759b0410c6645d28d18a73bec230a26e1d07937a69d7e1f049c5170e3ce01b
```

`météo` is NFC (U+00E9) and is emitted raw, 6 bytes; `\n`, `\t` and `\u0001` are the only escapes. The same
body with `météo` in NFD (`e` + U+0301) has id
`0292c327ec21dc78a31e0020011349453056533e5a4d26ec0eb03a2e81086878`: a different statement, by rule (no
normalisation).

**V5 genesis (collection, 2-of-2)**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 469 bytes:
DSSEv1 48 application/vnd.research-commons.genesis.v1+json 406 {"alg":"eip191-secp256k1","body":{"co\
ntrollers":["0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","0xabababababababababababababababababababab\
"],"name":"station-readings","rule":{"k_of_n":{"k":2}},"type":"collection"},"kind":"genesis","prev":\
"a79e1a3ac6af2c09a65796aea07860c06045d5945c7a75a82c8d3e9d8b4e41b1","rc":"rc/1","seq":4,"signer":"0xf\
71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:08:00Z"}
id:  864c74292cac8b3ffb123c739ab210f3374b4731f2d9343eb2aa189c5fba827f
sig: 0xcfb40d5361f421448eb71bf02f0689838ce245f1153adb350978a2c1d5d9d3e47ccf\
     8a5f6903539877eaa65feaf9a5addc7bfb43e7c5191929821518117c26731b
```

The resource id is this statement's id (C-core-77). `controllers` is a set, sorted by the key order of §1.

**V6 edition (first edition; rule-based selection; frozen_before)**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 705 bytes:
DSSEv1 48 application/vnd.research-commons.edition.v1+json 642 {"alg":"eip191-secp256k1","body":{"co\
ntents":{"frozen_before":{"date":"2026-09-01"},"members":[{"content":"sha256:7a7a7a7a7a7a7a7a7a7a7a7\
a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a","role":"segment"}],"rules":[{"dialect":"rc-rules/1","expr\
":"sampling.n >= 30"}],"selection":"rule-based"},"predecessors":["864c74292cac8b3ffb123c739ab210f337\
4b4731f2d9343eb2aa189c5fba827f"],"resource":"864c74292cac8b3ffb123c739ab210f3374b4731f2d9343eb2aa189\
c5fba827f"},"kind":"edition","prev":"864c74292cac8b3ffb123c739ab210f3374b4731f2d9343eb2aa189c5fba827\
f","rc":"rc/1","seq":5,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:09:\
00Z"}
id:  de91bae32078c52cd55500b21ddaeadb7915bbdafe9f8d60059e47d56c570c30
sig: 0x3d9119a04c479deb2acde04d214f2b5831071283aff46e7bfc49eb7ce9559e3832d5\
     7f3b1184bd4f6ca27f8bb1bb589c41d7d5f8a6e603b7c41d0a2c4228cdc21c
```

Under the 2-of-2 rule this edition is one approval and is not yet the tip (C-core-82).

**V7 anchors**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 486 bytes:
DSSEv1 48 application/vnd.research-commons.anchors.v1+json 423 {"alg":"eip191-secp256k1","body":{"he\
ad":"de91bae32078c52cd55500b21ddaeadb7915bbdafe9f8d60059e47d56c570c30","head_seq":5,"proof":{"digest\
":"sha256:d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0","scheme":"ots"}},"kind":\
"anchors","prev":"de91bae32078c52cd55500b21ddaeadb7915bbdafe9f8d60059e47d56c570c30","rc":"rc/1","seq\
":6,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:10:00Z"}
id:  fc2aa53bff0006025c05d4bdb826a1a79e7cdf59149fdeeefe022e176640e80d
sig: 0x48daaf1615853bcd7943e493372193938e4c36f7cd93b3ee6a98ae2dbb8553ba4240\
     dc1cac7501209a0a48fa00cdcf1d2cb8a669052e0fa12fc3eb3f6b64bb181b
```

The proof bytes are a separate blob; this statement binds the log prefix through `seq` 5 to them. Quality is
whatever the reader verifies, never a label here (C-core-107).

**V8 authored with an unknown extension and a `crit` member**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 487 bytes:
DSSEv1 49 application/vnd.research-commons.authored.v1+json 423 {"alg":"eip191-secp256k1","body":{"c\
ontent":{"digest":"sha256:e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1","size":1\
0},"type":"report","x_escrow":{"until":"2027-01-01"},"x_note":"ignored"},"crit":["x_escrow"],"kind":\
"authored","prev":"fc2aa53bff0006025c05d4bdb826a1a79e7cdf59149fdeeefe022e176640e80d","rc":"rc/1","se\
q":7,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:11:00Z"}
id:  97296c2e5e1cc833943b702f067da29544ef03ae09af906e15ba733d8764398f
sig: 0x69a2188be2a7b21a9496f20fc67c54f6bde600fa0a72e0f273344be57891ef127957\
     c36ccacb466154cea9be7415c09bf9b2909da7bb00118029c906d2982e271c
```

A reader without `x_escrow` retains this as `unsupported`; `x_note` alone would be retained and ignored. The
`crit` list is sorted and inside the signature.

**V9 observed (phenomenon; sub-second times; a TAI referent)**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 663 bytes:
DSSEv1 49 application/vnd.research-commons.observed.v1+json 599 {"alg":"eip191-secp256k1","body":{"c\
apture":{"at":"2026-10-12T20:11:58.25Z","evidence":"self-asserted","instrument":"daq-7"},"class":"ph\
enomenon","content":{"digest":"sha256:3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c\
3c","size":2048},"referent":{"at":"2026-10-12T20:12:35.000000012","instrument":"daq-7","location":"g\
eo:39.7392,-104.9903,1609;u=5","place":"bench-3","timescale":"TAI"}},"kind":"observed","prev":"97296\
c2e5e1cc833943b702f067da29544ef03ae09af906e15ba733d8764398f","rc":"rc/1","seq":8,"signer":"0xf71e7c9\
cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:12:00Z"}
id:  b0d5761fc890ed6ea143f1e29e9d8debe77ed7bc19f38cde6fd494da0022b203
sig: 0x3c21dbb37d0c6983353d48a176ca6349b872b59f229bae63fe936e9f7eae0eac2efe\
     c84e8566142c8a16683665f50f5c6dc97aea61cec052490e797bc2d13c631b
```

`capture.at` carries a fraction of two digits and the referent `at` one of nine; neither has trailing zeros.
The referent names `timescale` `TAI`, so its `at` carries no `Z`; the envelope `ts` and `capture.at` are UTC.

**V10 describes (key order above U+FFFF)**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 443 bytes:
DSSEv1 50 application/vnd.research-commons.describes.v1+json 378 {"alg":"eip191-secp256k1","body":{"\
about":{"content":"sha256:3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c"},"tags":\
["sort-order"],"x_😀":"astral","x_ｱ":"bmp"},"kind":"describes","prev":"b0d5761fc890ed6ea143f1e29e9d8d\
ebe77ed7bc19f38cde6fd494da0022b203","rc":"rc/1","seq":9,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1\
c4750e7a","ts":"2026-10-12T20:13:00Z"}
id:  5e80f25a49fa7cc73f0a5f2eef185bfccd9d61da3acc8c0da5f798dcc5ccb944
sig: 0xe9d01a5ac5bfd66c6116265d86c71eadef5fdcd03aacd6509948bb51a01b6c7d1208\
     bd4cb64f422a6e85292df673f3d62451d7ce7f2ca0d697ae98bf9d589b301b
```

The two extension keys are `x_` + U+1F600 and `x_` + U+FF71. RFC 8785 compares UTF-16 code units, where
U+1F600 begins with the surrogate 0xD83D and so sorts before U+FF71; code-point or UTF-8 byte order puts it
after. A canonicaliser that sorts by code point produces a different string and a different id (N11).

**V11 holds (a second line after V9: the log forks at seq 9)**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 504 bytes:
DSSEv1 46 application/vnd.research-commons.holds.v1+json 443 {"alg":"eip191-secp256k1","body":{"cont\
ent":{"digest":"sha256:3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c","size":2048\
},"locations":["https://mirror.example/blobs/3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3\
c3c3c3c3c"]},"kind":"holds","prev":"b0d5761fc890ed6ea143f1e29e9d8debe77ed7bc19f38cde6fd494da0022b203\
","rc":"rc/1","seq":9,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:13:0\
0Z"}
id:  93fe6f768c4188c40a706089d82c5fd29711b9b1e1dfb32d4eaec7b29d561e8d
sig: 0x40f5612de57ee0a66517000991a358b3b1ccde59eb378a3edc8c9a1393e49df44010\
     fe83e9ade231a9784f2a207fa303530e842f2826412eb134841c23ce89421c
```

**V12 describes (`merges`: clears the fork; `prev` = V10, `merges` = [V11])**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 492 bytes:
DSSEv1 50 application/vnd.research-commons.describes.v1+json 427 {"alg":"eip191-secp256k1","body":{"\
about":{"content":"sha256:3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c"},"tags":\
["fork-cleared"]},"kind":"describes","merges":["93fe6f768c4188c40a706089d82c5fd29711b9b1e1dfb32d4eae\
c7b29d561e8d"],"prev":"5e80f25a49fa7cc73f0a5f2eef185bfccd9d61da3acc8c0da5f798dcc5ccb944","rc":"rc/1"\
,"seq":10,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:14:00Z"}
id:  63dcdd4efdc8b8b1ae8633d4fa5cce0ab12df3f408b4ac5676f61b7bd2095411
sig: 0x9d9fa533baaa9eee03568acec9ab3d9a10fb22a9a765e5a215fe34543dee3f142f9a\
     f6767f0fced279b2ebe8f681b1f082d836379f7a972d4a9be99b8bd9219d1b
```

**Ed25519 vectors.** A second log, signed by a second disposable public key: seed = sha256 of
`research-commons wire-format test key 2 (ed25519)`, public key
`f9e6e12ad6036f6c19ebe6c6cf64f4e26c40b63eeab2cd19f4dd947657b25fe5`. E2 rotates that key to the secp256k1 test
key, so rotation across algorithms is exercised. Ed25519 signatures are bare hex, with no `0x`.

**E1 authored (ed25519)**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 395 bytes:
DSSEv1 49 application/vnd.research-commons.authored.v1+json 331 {"alg":"ed25519","body":{"content":{\
"digest":"sha256:5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e","size":512},"lice\
nce":"CC0-1.0","type":"dataset"},"kind":"authored","prev":null,"rc":"rc/1","seq":0,"signer":"ed25519\
:f9e6e12ad6036f6c19ebe6c6cf64f4e26c40b63eeab2cd19f4dd947657b25fe5","ts":"2026-10-14T18:00:00Z"}
id:  37614f5d085342c609e50383f78cf89564326616a1e0535440d67dc9af5c44d2
sig: f64e85a9a341fd25c9918c0a2db3505e740b4b64841c4835e3e5539edfa0f7a2\
     3f20b691c33cfee0e9cfb8a223fba1af143e8626238428e4a0e9eaa8cae3ad03
```

**E2 rotate_key (ed25519 → eip191-secp256k1; fractional `ts`)**

```text
NOTE: '\' line wrapping per RFC 8792

signed string, 414 bytes:
DSSEv1 51 application/vnd.research-commons.rotate_key.v1+json 348 {"alg":"ed25519","body":{"effectiv\
e":"2026-10-14T18:01:00.5Z","successor":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a"},"kind":"rotate\
_key","prev":"37614f5d085342c609e50383f78cf89564326616a1e0535440d67dc9af5c44d2","rc":"rc/1","seq":1,\
"signer":"ed25519:f9e6e12ad6036f6c19ebe6c6cf64f4e26c40b63eeab2cd19f4dd947657b25fe5","ts":"2026-10-14\
T18:01:00.5Z"}
id:  a3a49f04392a3f969be4226f0a2ab45788ede846605749c633e9cfa6a81ae262
sig: 04c41721f540bc834196689ef30ac85271ea8b32bb64031d324de43eb3daff84\
     ac12eca38c0f9da1898659fd0fe24e3473760bddeb7e39b94972e7c3e427b409
```

**Negative vectors.** The exact input bytes of each are in the vectors file; the table names them by hash.
`delivered` inputs are handed to the parser as stored log lines; the others pair a signed string with a
signature.

| | Input (exact bytes in the vectors file) | Required result |
|---|---|---|
| N1 duplicate key | delivered bytes sha256 `f4e49971b82b09d6a118d772e3154e07bfda9b4562943bc83420e75194182d6f` (791 bytes) | intrinsic: malformed statement (duplicate key "licence"); no line written |
| N2 NaN | delivered bytes sha256 `9b5693b6934269bea5839f653b09de0f6ce6ff583ca61c321f02be2e86bdecd3` (776 bytes) | intrinsic: malformed statement (non-finite number) |
| N3 float | delivered bytes sha256 `96f3c9c3dfd42036ddc606ac615632fbd4b87299f4669fbe21cf2dcaeb576173` (776 bytes) | intrinsic: malformed statement (non-integer number) |
| N4 depth | delivered bytes sha256 `c6bafac17836da9a173f93b8f303207295a521de73e517ba2a831f05b5ce751d` (103 bytes) | operational: depth limit 16, scope this object |
| N5 wrong log | delivered bytes sha256 `55ef02a7ae948502be825541bae493bc0a546bd457d050f1dae7b465f8ea863f` (777 bytes), into the log named for `0xabababababababababababababababababababab` | intrinsic: line in another key's log |
| N6 tag mismatch | signed string sha256 `d5d7bd2dbf3fcadcb02e23e6e356740a33ae2bdbeb28e6d01daabc6cf6834397` with the `sig` given | intrinsic: bad signature (recovers a different address) |
| N7 flipped byte | signed string sha256 `4e299d080ecd89751f650cfe6263256c578051622b4e10dcb7a6a3a7b80d545e` with the `sig` given | intrinsic: bad signature; no field displayed as the signer's (C-core-09) |
| N8 trailing zero | signed string sha256 `4d64caf7249cf405d8641bc553a7d419da33fe2342c9750ce1475d423b4570d8` with the `sig` given | intrinsic: malformed statement (non-canonical time) |
| N9 ten fraction digits | signed string sha256 `056ccd6fbbcaabedeac60c26980edee029801674415a19431b031860bfb4f0a5` with the `sig` given | intrinsic: malformed statement (non-canonical time) |
| N10 numeric offset | signed string sha256 `123f27ab51b65021f429a39afd76b2e7ad3bbbd5c5ff9f481b3dfa723bd26e07` with the `sig` given | intrinsic: malformed statement (non-canonical time) |
| N11 code-point key order | signed string sha256 `628c61bfb535cf4640c08404022f964dd70fc439b7cb8632289eeb487d2cc113` with the `sig` given | intrinsic: bad signature (the reader's JCS form of the envelope is V10's string, which this signature does not cover) |
| N12 leap second outside UTC | signed string sha256 `173b5dfa6f76df98c6a9aad856340ade4dbd6803b5e19d466400557161ad5d77` with the `sig` given | intrinsic: malformed statement (second 60 outside UTC) |
| N13 Z on a TAI time | signed string sha256 `3d9b0d38479c58a8a7b87042222a1dd9b5198803c40f0e30770336cbeeb50adf` with the `sig` given | intrinsic: malformed statement (Z asserts UTC; the referent names TAI) |
| NE1–NE12 Ed25519 edge cases | the twelve `ed25519-speccheck` cases (small-order and mixed-order points, `S ≥ L`, non-canonical encodings), key, message and signature in the vectors file | intrinsic: bad signature; each refused by step 1 or 3 of the pinned rule (§4), as the file records |
| NE13 alg / signer mismatch | E1 with `alg` `eip191-secp256k1`, signed by the Ed25519 key over that string; signed string sha256 `3f3015a8d6f763f449d9b7f306acff3a8bd5b3bfc610645b55577b8d6f98a5dc` | intrinsic: malformed statement (`alg` and `signer` disagree) |

Empty content, for §8: `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, size 0.

## 10. Relationship to the alpha

| Kept | Dropped | Why |
|---|---|---|
| EIP-191 `personal_sign` over a canonical JSON string; secp256k1 recover-to-address; the lowercase address as identity; sorted keys + no-separator JSON (now specified as RFC 8785; the alpha's code-point sort agrees with it for every key below U+10000) | | one maintained primitive, already deployed, already understood; no new crypto (claims-model note §15 asks for a wire format, not a new signature scheme) |
| | the v1 `sig` over a five-field subset | left `task`, `result`, `tier`, `reason` and every later field unsigned (#10, #45) |
| | `sig2` as a second signature beside `sig` | two signatures over one line invite stripping and downgrade; one signature over everything leaves a relayer only omission (claims-model note §2, §14) |
| | `prev` outside the signature, set at commit | a chain nobody signs is a chain anybody can re-link (§2 above; I3; claims-model note §12) |
| | the untagged signed string | every signed string is now a DSSE PAE string over a per-kind payload type, so no two statement kinds, and no future signed object, share a signing domain |
| | `ensure_ascii` escaping of non-ASCII | raw UTF-8 is shorter, and one rule ("escape only control characters and the two JSON specials") is easier to implement identically across languages |
| | short ids in statements | every reference is a full id or digest (I1); aliases are display only |
| | unsigned lines with `addr: null` | an unsigned line is a local draft, never a statement (claims-model note §11) |

Alpha ledgers and manifests are not readable by this format and are refused as malformed, with no synthesis
of statements from them (C-core-141). Content hashes carry over unchanged.

## 11. Out of scope

Log file layout, sharding and atomic append (storage note); the proof formats behind `anchors.proof` and
what makes a bound `bitcoin` quality (#59); the rule dialect named by `edition.contents.rules[].dialect` and
the member-schema dialect (rule and schema note); the comparator and agreement-model identifiers named by
`comparator` and `corroborates.model` (comparison note); attestation object contents under
`capture.attestation` (attestation note); package and transport framing on `pull`/`push` (storage note);
size limits larger than the single-statement bound (size policy, #9); time uncertainty, which can arrive later
as an optional field (a minor change, §6) modelled on RFC 9581 §3.5.4 and FITS 4.0 §9.4.3.

## 12. Decisions and open questions

**Decided (2026-10-13).** These were open questions in the first draft.

- **Integer bound** (was Q1). Keep the I-JSON range, \|n\| ≤ 2^53 − 1, and write larger counts as decimal
  strings, as RFC 7493 §2.2 recommends. No field this note defines needs more, and raising the bound would
  push big-integer parsing onto every implementation.
- **Time precision** (was Q3). Every time field allows up to nine fractional digits in one canonical spelling,
  with an optional FITS timescale on measurement referents (§1.1). The first draft's "whole seconds in `ts`,
  fractions only in `capture.at`" would have made two time types.
- **Canonical JSON.** RFC 8785 is the canonicalisation. The first draft's code-point key order differed from
  it for keys above U+FFFF (V10, N11).
- **Two required algorithms** (was Q2, 2026-10-14). `ed25519`, the default for new keys, with a pinned
  verification rule; and `eip191-secp256k1` for blockchain-linked identities (§4). Key generation, custody and
  linking are guidance (§4.1); the post-quantum plan is §4.2.
- **Signature encodings** (was Q1, 2026-10-14). Accept every valid encoding; store the canonical one (low-`s`,
  `v` ∈ {27, 28}), so logs are byte-identical across readers (§4).
- **`crit`** (2026-10-14). Renamed from `critical`, with JOSE's structural rules and one stated departure
  (§6).
- **Revocation reasons** (2026-10-14). A closed list from RFC 5280 §5.3.1 (§5).
- **Fork clearing** (storage note Q1, 2026-10-14). An optional signed `merges` list beside the single `prev`
  names the other tips a line absorbs; a fork clears when every tip is an ancestor of one line, as for
  editions. Chosen over making `prev` a list, which would have broken `seq` continuity, every vector and the
  single-chain reading for a case that is the exception (§2, §7; V11–V12).
- **Detached lines** (was Q3, 2026-10-14). Attributed but counted toward nothing (`authored`, `observed`),
  or not evaluated at all (every other kind), until the line chains; the gap is named (§7).
- **DSSE framing** (was Q4, 2026-10-14). The signed string is DSSE PAE with a per-kind payload type (§2).
- **Content digests** (was Q5, 2026-10-14). Content hashes are OCI digests, `sha256:<hex>`; statement ids
  stay bare, because their algorithm is fixed by the major version (§8).
- **`frozen_before`** (review, 2026-10-14). Takes the finality-state units (date, height or run) (§5).
- **Licence texts** (review, 2026-10-14). Cited by digest when held, else by location (§5).
- **Segments are members** (2026-10-16). `edition.contents` has no `segments` field: a segment is a member
  with role `segment`, and its boundary comes from its own statement's finality, which is what the
  claims-model note §8 computes (V6, C-core-101 – C-core-103).
- **No `rewritten history` refusal** (2026-10-16). With `prev` signed, a different line at a held `seq` can
  only be the key's own, so it is a fork (§7). A relayer's package that leaves lines out is covered by
  "packages make no completeness claims" (claims-model note §11, C-core-01).
- **Test vectors as data** (2026-10-14). The normative vectors live in a JSON file beside this note
  (`DESIGN-notes-wire-format.vectors.json`); the blocks in §9 are rendered from it.

**Open.**

1. **The quantum horizon (open for discussion).** The project does not yet take a position on a cutoff for
   classical signatures; the current state of post-quantum research does not support selecting one, and this
   question is open so participants can discuss it. Questions for that discussion:
   - Should the format ever ship a default cutoff date, or leave any cutoff to each reader's policy? What
     evidence (a demonstrated cryptanalytically relevant quantum computer, a standards body's deadline such as
     NIST IR 8547's 2035, or something else) should trigger one?
   - Which ML-DSA parameter set should be the reserved value (`ml-dsa-44` or `ml-dsa-65`), or should the
     choice wait, given FN-DSA (FIPS 206) is still in draft?
   - Should a statement be able to carry two signatures (classical and post-quantum) during a transition, and
     what would that do to statement identity and the one-signature rule?
   - Should Ed25519 holders be encouraged to keep their seeds specifically for the zero-knowledge migration
     route (§4.2), while that research matures?
