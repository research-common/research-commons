# Design note: wire format

**Status:** proposed · **Companion to:** the claims-model note (§15, "wire format") · **Covers:** canonical
encoding, the statement envelope, statement identity, the signature scheme, the kind vocabulary's field
names, extensions, per-key logs, content hashing, and test vectors. Serves conformance cases C-core-02a,
C-core-03, C-core-04, C-core-08 to C-core-14, C-core-77, C-core-83, C-core-117, C-core-127, C-core-141, P-02.

## 0. Summary

- A statement is one JSON object, the **envelope**: `rc`, `kind`, `signer`, `alg`, `seq`, `prev`, `ts`,
  `body`, optional `critical`, and `sig`. Everything except `sig` is signed. Nothing rides outside.
- The **signed string** is `rc/<major>/<kind>` + LF + the canonical JSON of the envelope minus `sig`.
- **Statement id** = full lowercase hex sha256 of the signed string. Short forms are display aliases only.
- **Canonical JSON** is sorted keys, no whitespace, integers only, UTF-8 as given (no normalisation),
  duplicate keys refused, depth ≤ 16, statement ≤ 64 KiB.
- **One signature**, one required algorithm: `eip191-secp256k1` (the alpha primitive). Any encoding of a
  valid signature over one signed string is the same statement. Unknown `alg` is retained and grants nothing.
- `prev` and `seq` are inside the signature, so a same-key fork is two signed lines, not a relayer's edit.
- Unknown fields are retained and ignored. A `critical` member the reader does not implement makes the whole
  statement `unsupported`: retained, never evaluated. An unknown `rc` major is `unsupported` the same way.
- Content identity is sha256 of the exact bytes, full hex. Vectors in §9 were computed, not typed.

## 1. Canonical encoding

The canonical form of a JSON value is the byte string produced by these rules. Two implementations that
disagree on one byte produce different statement ids, so every rule below is a conformance obligation.

| Rule | Obligation | On violation at parse |
|---|---|---|
| encoding | UTF-8, no BOM, no trailing newline | refuses (intrinsic: malformed statement) |
| object keys | sorted by Unicode code point of the key string (equivalently: by UTF-8 bytes); no duplicates | duplicate key: refuses (intrinsic) |
| whitespace | none outside strings | not an error on input; canonicalisation removes it |
| numbers | integers only, `-?(0|[1-9][0-9]*)`, magnitude < 2^53; no fraction, exponent, `NaN`, `Infinity`, `-0` | refuses (intrinsic) |
| decimals | a string plus a unit field: `{"value":"120.0","unit":"degF"}`; the note never interprets the string | n/a |
| strings | JSON strings; escaped as `\"`, `\\`, `\n`, `\r`, `\t`, `\b`, `\f`, and `\u00XX` for other control characters U+0000–U+001F; every other code point is emitted raw as UTF-8, never `\uXXXX`-escaped; no `/` escaping | invalid UTF-8 or a lone surrogate: refuses (intrinsic) |
| string normalisation | none. Bytes are as the signer gave them. `é` (U+00E9) and `e` + U+0301 are different strings and give different ids | n/a |
| `null` vs absent | distinct. `"prev":null` is required in a first statement; everywhere else an absent field means "not stated" and a `null` field is refused by that field's schema unless the kind table lists `null` as a value | refuses (intrinsic) where the schema says so |
| booleans | `true` / `false` | |
| arrays | order is significant and preserved. A kind that treats a list as a set (`controllers`, `predecessors`, `critical`) says so and refuses duplicates and unsorted members in that list | refuses (intrinsic) |
| nesting | depth ≤ 16 (the envelope object is depth 1) | refuses (operational: `depth limit 16`) |
| size | signed string ≤ 65 536 bytes. The bound is on the statement, not the data: anything list-shaped and large (a per-request fetch log, a member list of thousands) belongs in a blob the statement hashes (§5, source referent) | refuses (operational: `size limit 65536`) |
| top level | the envelope is an object; anything else is not a statement | refuses (intrinsic) |

The canonical form is **what the signer signed**, so a reader never re-canonicalises a received statement
and signs or hashes the result. It canonicalises the received envelope minus `sig`, prepends the domain
tag, and checks that string against `sig`. A received line whose bytes are not already canonical is admitted
when its canonical form verifies, and is stored canonical; the reader's log holds exactly one byte form per
statement. This is why C-core-04 (local tree, hub pull, archive; permuted; duplicated) yields one view: every
delivery canonicalises to the same bytes and the same id.

Parsers that keep the last duplicate key (most language defaults) do not conform. The conformance test for
C-core-12 feeds `{"licence":"MIT","licence":"CC0-1.0"}` inside a body and expects an intrinsic refusal with
the key named, and a reader state digest unchanged before and after.

## 2. The envelope

```text
{
  "rc":       "rc/1",                 format tag: "rc/" + major version      required
  "kind":     "authored",             statement kind (§5)                    required
  "signer":   "0x<40 lowercase hex>", key identity (recover-to-address)     required
  "alg":      "eip191-secp256k1",     signature algorithm (§4)               required
  "seq":      0,                      position in the signer's log (§7)      required
  "prev":     null | "<64 hex>",      id of the signer's previous statement  required (null only at seq 0)
  "ts":       "2026-10-12T20:00:00Z", signer-asserted time, RFC 3339 UTC, whole seconds, "Z"   required
  "critical": ["x_escrow"],           extension names the reader must know (§6)   optional
  "body":     { ... },                kind-specific content (§5)             required
  "sig":      "0x<130 hex>"           the signature                          required on the wire
}
```

**What is signed.** Every field except `sig`. The **signed string** is

```text
rc/<major>/<kind> LF canonical(envelope without "sig")
```

The first line is the **domain tag**. It is derived from `rc` and `kind`, so a statement whose tag does not
match its own `rc` and `kind` fields cannot verify: a reader that recomputes the tag from the fields and
recovers a different signer refuses with `bad signature`. The tag keeps a signature over an `authored` from
ever verifying as an `anchors`, and keeps every other signed object the tool might one day add (a policy
digest, a local receipt) out of the statement namespace by giving them a different first line.

**Why `prev` and `seq` are inside the signature.** In the alpha the chain link was set at commit and left
outside the signature so that chaining could not invalidate a signature. The claims-model note turns that
around: a per-key log is "a hash chain only that key extends" (I3), and a same-key concurrent append must
"become a visible fork, not a lost line" (§12). Both need the link to be the signer's word. With `prev`
signed, two lines that both chain after one id are two signed statements by the same key, a `FORK` the key
cannot disown and a relayer cannot manufacture by re-linking. With `prev` outside, a relayer could re-chain
lines and a reader could not tell a rewrite from a race (C-core-127, C-core-14).

**`ts` is a claim, not a bound.** It is signed so that it is unambiguously the signer's assertion, and it
orders nothing on its own (claims-model note §10). A `ts` more than 300 seconds ahead of the writer's clock
is refused at write time (C-core-105); a `ts` earlier than the `ts` of the statement at `prev` is admitted and
flagged `incoherent` (C-core-106).

## 3. Statement identity

`id = sha256(signed string)`, rendered as 64 lowercase hex characters, with no prefix. The id covers the
domain tag, every envelope field and the whole body, and excludes `sig`. Consequences, each a test:

- Two statements from one key that differ in one field (a reason, a TTL, an unknown extension) have two ids,
  and neither is a replay of the other (C-core-02a first pair, C-core-11).
- One signed string with two different valid signature encodings has one id (C-core-02a second pair,
  C-core-10, P-02). The second delivery is a no-op; the stored `sig` is whichever arrived first.
- Flipping one byte anywhere in the signed string changes the id and breaks the signature (C-core-09).
- The id of a genesis statement is the resource id (C-core-77); the id of an edition is its edition hash
  (C-core-78); `prev` and `predecessors` and `head` are ids.

**Display aliases.** A surface may print the first 12 hex characters of an id or a content hash as a label.
An alias is accepted as input only when exactly one held object matches; zero matches is `not found` and
two or more is an error that lists every candidate full hash and selects nothing (C-core-03). Aliases are
never written into a statement: every reference field in §5 is a full hash, and a 12-character value where a
64-character one is required is a malformed statement.

## 4. Signature scheme

One algorithm is required of every implementation, and it is the alpha's primitive, kept unchanged:

| `alg` | Signed bytes | Signature | Verification |
|---|---|---|---|
| `eip191-secp256k1` | EIP-191 `personal_sign`: keccak256 of `"\x19Ethereum Signed Message:\n" + len + msg`, where `msg` is the signed string (§2) as UTF-8 bytes and `len` is its byte length in decimal | 65 bytes `r ‖ s ‖ v` as `0x` + 130 lowercase hex | recover the secp256k1 public key, keccak-derive the address, compare case-insensitively with `signer`; mismatch is `bad signature` (intrinsic) |

Rules:

- **`signer` is the identity.** It is the lowercase `0x` + 40-hex address. A statement whose `signer` differs
  from the recovered address is refused as `bad signature`, which is also how "signer names A but signed by B"
  fails (C-core-14). Checksummed or uppercase `signer` is malformed (canonical form is lowercase).
- **Equivalent encodings are one statement.** `v` may arrive as 27/28 or 0/1; `s` may arrive in high form.
  A reader normalises for verification only (low-`s`, `v` ∈ {27, 28}) and never changes the id, which does
  not include `sig`. The vectors in §9 show two encodings of one signature verifying to one id. A reader
  that refuses the high-`s` form is permitted (it is an encoding choice) but then refuses it as `bad
  signature`, never as a second statement.
- **Unknown `alg`.** Retained in the signer's log as `unsupported`, displayed as such, never evaluated: it
  grants nothing, counts in no projection, and is not an error on `pull`. Adding an algorithm is a minor
  format change; a reader implementing it later re-evaluates retained lines (I5).
- **The key is a commons identity, not a payment wallet.** EIP-191 prefixing guarantees a statement can never
  be a valid transaction; the reverse discipline (never reuse a wallet key as a commons key) is the signer's.
- **Private keys never appear** in any statement, log, error or test fixture other than disposable keys
  minted for a test run. The vector key in §9 is derivable from a public string and is therefore public.

## 5. Kinds and body fields

Kinds are the closed vocabulary of claims-model note §4; this section fixes their body field names (snake
case) and types. `R` = required, `O` = optional. `hash` = 64 lowercase hex (sha256). `key` = lowercase `0x`
+ 40 hex. `id` = a statement id (hash). `ts` = RFC 3339 UTC, whole seconds, `Z`. A kind listed here with a
missing `R` field is a malformed statement (intrinsic), with one exception the note itself makes: an
`observed` whose `referent` lacks a field its class requires is valid, admitted, and shown `unpinned`
(claims-model note §5.3.1). A kind not listed here is stored and displayed as `unknown kind` and grants
nothing (C-core-13).

**Shared body objects**

| Object | Fields |
|---|---|
| `content` | `sha256` hash R · `bytes` integer R · `media_type` string O |
| `provenance` | `workflow` hash R · `inputs` list of hash R (order preserved) · `environment` object O (`image_digest` string, `platform` string, `harness_commit` string) |
| disclosures (on `authored`, `observed`) | `licence` string O (SPDX expression or `LicenseRef-*`) · `attribution` string O · `availability` object O (`redistribution` `"permitted"`/`"restricted"`/`"withheld"` R, `obtainable` boolean R, `withheld_until` string O) · `replication` `"bytes"`/`"protocol"`/`"none"` O · `comparator` hash O · `sampling` object O (`n` integer R, the total · `unit` string R, e.g. `runs`, `slots`, `records` · `groups` list of {`name` string R, `n` integer R} O, one per arm, names unique · `window` object O · `dispersion` object O) · `shelf_life_days` integer O · `pre_registration` `"exploratory"` or absent O · `fulfills` object O (`resource` id, `edition` id) · `intended_for` object O (`resource` id R, `edition` id R, `edition_applied` id R, `outcome` `"ok"`/`"unchecked"` R) · `description` string O |
| `finality` | `rule` string R · `rule_source` string O (a hash when the document is held, else a location) · `state_at_capture` object R (`depth` integer, or `run` string, or `captured_at` ts) |

**Kinds**

| `kind` | Body fields |
|---|---|
| `authored` | `content` R · `type` string R (`dataset`, `workflow`, `skill`, `synthesis`, `report`, `other`) · `provenance` O · disclosures O · `supersedes` hash O (the author's own earlier blob) · `extends` hash O |
| `observed` | `content` R · `class` R, exactly one of `exact-bytes` / `source` / `phenomenon` / `method` / `none-yet` (a list, or any second class field, is malformed; C-core-35) · `referent` object R, keys per class: exact-bytes `chain_id` string, `block_hash` hash, `depth` integer; source, either one request (`endpoint` string, `parameters` object, `response_sha256` hash) or a batch (`requests` object: `sha256` hash of a request log carried inside `content`, `format` string naming its layout, `count` integer; each log entry carries endpoint, parameters, status, time and response hash), never both; phenomenon `instrument` string, `location` object, `at` ts; method `method_edition` id, `environment` object (`image_digest`, `platform`, `harness_commit`), `system` object R with free keys (whatever identifies the measured system and changes the apparatus under the observer, e.g. a model pin, a provider, a routing era; values are strings), `inputs` list of hash O (the protocol's pinned inputs: scenario edition, seed set, configuration; order preserved), `window` object (`from` ts, `to` ts); none-yet: any · `capture` object R (`at` ts R, `evidence` `"self-asserted"`/`"anchored-at-capture"`/`"witnessed"`/`"device-attested"` R, `operator` string O, `instrument` string O, `witnesses` list of key O, `attestation` object O) · `finality` O (exact-bytes and source only) · disclosures O |
| `holds` | `content` R · `locations` list of string O (URLs or content-addressed URIs; a hint, never authenticated) |
| `describes` | `about` object R (exactly one of `content` hash, `statement` id, `resource` id) · `tags` list of string O · `note` string O · `links` list of object O (`rel` string R, one of `content`/`statement`/`resource`/`url` R) |
| `reproduced` | `of` id R (the `authored` reproduced) · `result` `"match"`/`"diverged"`/`"not-comparable"` R · `content` R (the bytes this run produced) · `provenance` R · `comparator` hash O · `report` hash O (divergence report) |
| `corroborates` | `of` id R (the `observed`) · `result` id R (the derived corroboration result's `authored`) · `verdict` `"supports"`/`"contradicts"`/`"inconclusive"` R · `model` string R (agreement model name or hash) · `cohort` object R (`rule` string, or `hand_picked` true) · `shares` list of string O (what this shares with the original: feed, operator, instrument) · `cause` string O (for `inconclusive`) |
| `refutes` | `of` id R · `evidence` hash R · `note` string O |
| `retracts` | `of` id R (the signer's own `authored`/`observed`) · `reason` string O |
| `anchors` | `head` id R (a statement in the signer's own log) · `head_seq` integer R · `proof` object R (`scheme` string R, `sha256` hash R of the proof bytes, `quality_claimed` string O). A `head` in another key's log is malformed |
| `genesis` | `type` `"collection"`/`"task"`/`"series"` R · `name` string R · `controllers` list of key R (set) · `rule` object R (`any_one` true, or `k_of_n` {`k` integer}) · `forked_from` id O |
| `edition` | `resource` id R · `predecessors` list of id R (set; the genesis id for the first edition; several for a merge) · `contents` object R (`members` list of {`content` or `resource` or `statement`, `role` string} O, `schema` hash O, `rules` list of {`dialect` string, `expr` string} O, `contract` object O, `selection` `"curated"`/`"rule-based"`/`"completeness"` O, `frozen_before` string O, `segments` list O, `controllers` and `rule` O for a controller change) |
| `intent` · `progress` · `withdraw` · `submit` · `decide` | all: `task` id R · `edition` id R. `submit`: `result` hash R, `salt` string O, `self_declared_independence` boolean O. `decide`: `submissions` list of id R, `verdict` `"accept"`/`"reject"` R, `evaluations` list of hash O, `supersedes` id O. `progress`: `note` string O |
| `rotate_key` · `revoke_key` | `rotate_key`: `successor` key R, `effective` ts O. `revoke_key`: `reason` string O, `effective` ts O. Both are statements by the old key about itself |

Every `R` field of a listed kind is checked at every gate by the one validation core (C-core-109). Field
semantics (what `match` means, how a rule is evaluated) belong to the claims-model note and the profile notes;
this table fixes only names, types and presence.

## 6. Extensions and versioning

- **Unknown fields are retained and ignored.** They are inside the signature and the id (C-core-02a, 09), are
  stored byte-exact, are never displayed as anything but the signer's opaque field, and never influence a
  default, grade or exit code. Names beginning `x_` are reserved for extensions; a future minor revision never
  claims an `x_` name.
- **`critical`** is a sorted, duplicate-free list of top-level body field names. A reader that does not
  implement every listed name treats the statement as **`unsupported`**: retained in the log (it is a valid
  signed line and still chains), displayed with the unknown names, and evaluated under no interpretation at
  all. It is not an `authored` with the field dropped; it is nothing yet. A `critical` name that is absent
  from the body is malformed.
- **Format tag.** `rc/<major>`. A reader implements one major. A statement with another major is
  `unsupported` in the same way: retained, chained, never evaluated, never an error on `pull`. A statement
  with a malformed `rc` (not `rc/` + positive integer) is intrinsic malformed.
- **Minor changes** (new optional field, new `alg`, new kind) do not bump the major, and never reinterpret
  existing signed bytes. A change that would (a required field added, a type changed, a kind's meaning
  changed) bumps the major, which changes every domain tag.

## 7. Per-key logs

A **log** is the sequence of statements by one `signer`, stored as a file of canonical lines (one statement
per line, LF-terminated) or carried as a stream; the storage note owns the file layout, this note owns the
line contract.

- `seq` starts at 0 and increases by exactly 1 along `prev`. The first statement has `prev: null` and
  `seq: 0`. Every other statement has `prev` = the id of the statement at `seq - 1` in the same log.
- **Ownership rule.** Every line in a log named for key K has `signer` = K and verifies under K. A line whose
  `signer` is another key, wherever it was delivered, is refused (intrinsic: `line in another key's log`)
  and K's chain is unchanged (C-core-14). The refusal scope is that line.
- **Append-only.** A held log is a prefix of any accepted update. A delivery whose lines at a held `seq`
  differ by id is `rewritten history` (intrinsic) for the package, and the held lines stay valid.
- **Forks.** Two valid lines by K with the same `prev` are both retained and the log shows `FORK` at that
  point (C-core-127). Neither is refused; neither is the tip; later statements choose a branch by `prev`.
- **Gaps.** A line whose `prev` matches nothing held is retained as `detached` (it may precede a delivery
  the reader has not received) and chains nothing until its predecessor arrives. It is still that key's
  signed word; what it grants is computed only once it chains, except that an `authored`/`observed` is
  attributed to its signer regardless.
- **Ordering.** The log's order is `seq`, never file order or `ts`. Duplicates by id are dropped on write.
- **Anchors** bound only the signer's own prefix up to `head` (C-btc-04); an `anchors` whose `head` is not in
  the signer's log is malformed.

## 8. Content hashing

A blob's identity is `sha256` over its exact bytes, 64 lowercase hex, no prefix, no transcoding, no
newline handling (C-core-117). `content.bytes` is the exact length. The empty blob is valid:
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, 0 bytes. A fetched blob is verified
against the full hash before it is installed; the display alias is never used for that check.

## 9. Test vectors

Computed with Python 3 `hashlib` and the alpha signer (`viem` `signMessage`) in a throwaway directory; every
hash below is pasted from that run. The signing key is the **disposable, public** key
`sha256("research-commons wire-format test key 1")` as a 32-byte hex scalar, whose address is
`0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a`. Never use it for anything else. Vectors V1–V8 form one log
(`seq` 0–7); each `prev` is the previous vector's id. In the signed strings a trailing `\` means the line
continues with no newline; the only LF in a signed string is the one after the domain tag.

**V1 authored (derived, with provenance)**

```text
signed string, 623 bytes:
rc/1/authored
{"alg":"eip191-secp256k1","body":{"availability":{"obtainable":true,"redistribution":"permitted"},"c\
ontent":{"bytes":4096,"sha256":"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"},"\
licence":"CC-BY-4.0","provenance":{"inputs":["111111111111111111111111111111111111111111111111111111\
1111111111","2222222222222222222222222222222222222222222222222222222222222222"],"workflow":"c0c0c0c0\
c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"},"type":"dataset"},"kind":"authored","prev\
":null,"rc":"rc/1","seq":0,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20\
:00:00Z"}
id:  05de3ce4f0f7fadfcc40876f3c1c7148e56e5337707cb568478bbbf2c7be7510
sig: 0x4e4bf385047f8fc613dfa31f342f8f64c2e33f7de672512b8465b2e49e51613a1120\
     b36d665741d245cc2c4b8680fbca0c752f523b6f8ca3b8972d73572734a61c
```

Equivalent encodings of this signature, both recovering the same signer, both the same statement
(C-core-10): `v` as `01` instead of `1c` (`…2734a601`), and the high-`s` form
`0x4e4b…613a` ‖ `eedf4c9299a8be2dba33d3b4797f0434ae39ad9473d91398073b3119790f0c9b` ‖ `1b`.

**V2 observed (exact-bytes, chain referent, finality)**

```text
signed string, 706 bytes:
rc/1/observed
{"alg":"eip191-secp256k1","body":{"capture":{"at":"2026-10-12T20:04:30Z","evidence":"self-asserted",\
"instrument":"node v27.0","operator":"runner-7"},"class":"exact-bytes","content":{"bytes":812,"sha25\
6":"7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a"},"finality":{"rule":"confirmat\
ions>=6","state_at_capture":{"depth":3}},"referent":{"block_hash":"00000000000000000002aaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","chain_id":"bip122:000000000019d6689c085ae165831e93","depth":3}},"k\
ind":"observed","prev":"05de3ce4f0f7fadfcc40876f3c1c7148e56e5337707cb568478bbbf2c7be7510","rc":"rc/1\
","seq":1,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:05:00Z"}
id:  e4ff6c2e4b0f1d32a72aa0e52ffaeba8cf49bdee395f175c1ac5ee7db7c0b053
sig: 0xd0c6f4213e9847a1fc661ba6937f94a3a03136c766ab18055953e8582e0552402620\
     f0564501640ed92df7b9414744138ee7a22af0a7c6dc916f7c3d38d161411c
```

No `rule_source`: displayed as `observer's convention`; referent status `provisional (3; final at 6)`.

**V3 holds (external location)**

```text
signed string, 448 bytes:
rc/1/holds
{"alg":"eip191-secp256k1","body":{"content":{"bytes":4096,"sha256":"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b\
2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"},"locations":["https://mirror.example/blobs/2b2b2b2b2b2b2b2b2b2b2b\
2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"]},"kind":"holds","prev":"e4ff6c2e4b0f1d32a72aa0e52ffaeba\
8cf49bdee395f175c1ac5ee7db7c0b053","rc":"rc/1","seq":2,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c\
4750e7a","ts":"2026-10-12T20:06:00Z"}
id:  8aedd7280a997830c1e64d49c6053a3da49a21b213528be1e618269f97b569c6
sig: 0x2a057f7c29c727ae44e914f39163855f1adf948070bf07840cd7a2ac643d2c0e3b0f\
     7c17ebc85a86ca84d5ef5f0213093c0658aa2920ccbb7010480308a5f7551c
```

**V4 describes (Unicode, control characters, nested lists and objects)**

```text
signed string, 520 bytes:
rc/1/describes
{"alg":"eip191-secp256k1","body":{"about":{"content":"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b\
2b2b2b2b2b2b2b2b2b"},"links":[{"content":"7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a\
7a7a7a","rel":"see-also"}],"note":"line1\nline2\ttab \u0001 ctl","tags":["météo","日本語","\"quoted\""]\
},"kind":"describes","prev":"8aedd7280a997830c1e64d49c6053a3da49a21b213528be1e618269f97b569c6","rc":\
"rc/1","seq":3,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:07:00Z"}
id:  0d5843900399dad623038da22a16a1f51d5c9c7d759d23c637dfa2fa7e76014a
sig: 0xcdd4fb81a635ad583e75832c2b846a33503b69a86fb738c99f0cc2a3f41bf8fe79d6\
     baee1c196a1a064b55e70990d56f70c4c0d74c9f339afd184b926f5080401c
```

`météo` is NFC (U+00E9) and is emitted raw, 6 bytes; `\n`, `\t` and `\u0001` are the only escapes. The same
body with `météo` in NFD (`e` + U+0301) has id
`b1563de222319d5e33fa58ec60f87573a7c181e388cc51feb78769c76405f58d`: a different statement, by rule (no
normalisation).

**V5 genesis (collection, 2-of-2)**

```text
signed string, 419 bytes:
rc/1/genesis
{"alg":"eip191-secp256k1","body":{"controllers":["0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","0xaba\
babababababababababababababababababab"],"name":"station-readings","rule":{"k_of_n":{"k":2}},"type":"\
collection"},"kind":"genesis","prev":"0d5843900399dad623038da22a16a1f51d5c9c7d759d23c637dfa2fa7e7601\
4a","rc":"rc/1","seq":4,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-10-12T20:08\
:00Z"}
id:  4513d8b1f8c66fac5ea3185feb72195fef0dfb71e67c65e5cea5d94a27612d65
sig: 0x3bc7a3e6c5d509645d542f26db89219f7dd52e6fbf6ac765af7726354b2e667313c1\
     ce7f9550347b059c9e138ad326475b32dde42fecba2138f8a7dd184d43971b
```

The resource id is this statement's id (C-core-77). `controllers` is a set: here sorted by byte order.

**V6 edition (first edition; rule-based selection; frozen_before)**

```text
signed string, 639 bytes:
rc/1/edition
{"alg":"eip191-secp256k1","body":{"contents":{"frozen_before":"2026-09-01","members":[{"content":"7a\
7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a","role":"segment"}],"rules":[{"dialec\
t":"rc-rules/1","expr":"sampling.n >= 30"}],"selection":"rule-based"},"predecessors":["4513d8b1f8c66\
fac5ea3185feb72195fef0dfb71e67c65e5cea5d94a27612d65"],"resource":"4513d8b1f8c66fac5ea3185feb72195fef\
0dfb71e67c65e5cea5d94a27612d65"},"kind":"edition","prev":"4513d8b1f8c66fac5ea3185feb72195fef0dfb71e6\
7c65e5cea5d94a27612d65","rc":"rc/1","seq":5,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","t\
s":"2026-10-12T20:09:00Z"}
id:  daa820dcaaa9e2ccbe2c1f0df2693b6fd544723a534d219db213d25f5d840f8e
sig: 0x1b866dd8c8e5aac55cdc75f9a53e1825a46499e334d3fc8a60afab0428e4b6d42150\
     76a649074439e880530e1a55d2cffa5038e7fece2f99c22d6d225ddfaa9a1c
```

Under the 2-of-2 rule this edition is one approval and is not yet the tip (C-core-82).

**V7 anchors**

```text
signed string, 429 bytes:
rc/1/anchors
{"alg":"eip191-secp256k1","body":{"head":"daa820dcaaa9e2ccbe2c1f0df2693b6fd544723a534d219db213d25f5d\
840f8e","head_seq":5,"proof":{"scheme":"ots","sha256":"d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d\
0d0d0d0d0d0d0d0d0d0"}},"kind":"anchors","prev":"daa820dcaaa9e2ccbe2c1f0df2693b6fd544723a534d219db213\
d25f5d840f8e","rc":"rc/1","seq":6,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2026-1\
0-12T20:10:00Z"}
id:  da3bcb52749da54467e9756b28fd62faee77b3f97a3eb85f5a349bb242aef10f
sig: 0xda1e8f7a156da2f3920e238e08deca118de40293cd7ddd33f9a51359f4edf40162fa\
     2f9f93d17b612820a0e913e1a1b09e2f1a10f6a21803e5cad801c1ca82161b
```

The proof bytes are a separate blob; this statement binds the log prefix through `seq` 5 to them. Quality is
whatever the reader verifies, never a label here (C-core-107).

**V8 authored with an unknown extension and a `critical` member**

```text
signed string, 435 bytes:
rc/1/authored
{"alg":"eip191-secp256k1","body":{"content":{"bytes":10,"sha256":"e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1\
e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"},"type":"report","x_escrow":{"until":"2027-01-01"},"x_note":"ignored\
"},"critical":["x_escrow"],"kind":"authored","prev":"da3bcb52749da54467e9756b28fd62faee77b3f97a3eb85\
f5a349bb242aef10f","rc":"rc/1","seq":7,"signer":"0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a","ts":"2\
026-10-12T20:11:00Z"}
id:  7f9a7de1059c0ceb3c6dca91c06ae3fa5cdb2d43aba95833976a3a8484d09bfb
sig: 0xb0d610bd8aa70debccffbf337b6bf8a218ece32c99a057210815a99671e4f0b77a09\
     e56fdb1a29d31d72669f34b9fd8bdb2b4473244011a403349a53d71c73621b
```

A reader without `x_escrow` retains this as `unsupported`; `x_note` alone would be retained and ignored. The
`critical` list is sorted and inside the signature.

**Negative vectors** (each must reach the parser; the test logs the sha256 of the delivered bytes):

| | Delivered bytes (sha256 of the exact bytes) | Required result |
|---|---|---|
| N1 duplicate key | V1's body with `"licence":"MIT","licence":"CC0-1.0"`; delivered sha256 `fb7e780d945169e5b8a60c19b6a954608efe99900fb41c9cb4340c876ca5933c` | intrinsic: malformed statement (`duplicate key "licence"`); no line written |
| N2 NaN | `{"body":{"content":{"bytes":NaN,…` ; sha256 `8d7a0dadc36cc5401f39066044c2c6f5f2135efc01a1b1523377503b17b806f7` | intrinsic: malformed statement (`non-finite number`) |
| N3 float | `"bytes":1.0` ; sha256 `0219b2fdb3a1cdcb0b062baa5706f668ecac5cd8afd95f4e95a8c3a7a455e89b` | intrinsic: malformed statement (`non-integer number`) |
| N4 depth | `{"a":` × 17 + `1` + `}` × 17 (103 bytes); sha256 `c6bafac17836da9a173f93b8f303207295a521de73e517ba2a831f05b5ce751d` | operational: `depth limit 16`, scope this object |
| N5 wrong log | V1 delivered into a log named for `0xabab…abab` | intrinsic: `line in another key's log` |
| N6 tag mismatch | V1's signed string with first line `rc/1/anchors` and V1's `sig` | intrinsic: `bad signature` (recovers a different address) |
| N7 flipped byte | V1 with `"CC-BY-4.0"` → `"CC-BY-4.1"` and V1's `sig` | intrinsic: `bad signature`; no field displayed as the signer's (C-core-09) |

Empty content, for §8: `sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

## 10. Relationship to the alpha

| Kept | Dropped | Why |
|---|---|---|
| EIP-191 `personal_sign` over a canonical JSON string; secp256k1 recover-to-address; the lowercase address as identity; `sort_keys` + no-separator JSON | | one maintained primitive, already deployed, already understood; no new crypto (claims-model note §15 asks for a wire format, not a new signature scheme) |
| | the v1 `sig` over a five-field subset | left `task`, `result`, `tier`, `reason` and every later field unsigned (#10, #45) |
| | `sig2` as a second signature beside `sig` | two signatures over one line invite stripping and downgrade; one signature over everything leaves a relayer only omission (claims-model note §2, §14) |
| | `prev` outside the signature, set at commit | a chain nobody signs is a chain anybody can re-link (§2 above; I3; claims-model note §12) |
| | the untagged signed string | every statement now begins with `rc/<major>/<kind>`, so no two statement kinds, and no future signed object, share a signing domain |
| | `ensure_ascii` escaping of non-ASCII | raw UTF-8 is shorter, and one rule ("escape only control characters and the two JSON specials") is easier to implement identically across languages |
| | short ids in statements | every reference is a full hash (I1); aliases are display only |
| | unsigned lines with `addr: null` | an unsigned line is a local draft, never a statement (claims-model note §11) |

Alpha ledgers and manifests are not readable by this format and are refused as malformed, with no synthesis
of statements from them (C-core-141). Content hashes carry over unchanged.

## 11. Out of scope

Log file layout, sharding and atomic append (storage note); the proof formats behind `anchors.proof` and
what makes a bound `bitcoin` quality (#59); the rule dialect named by `edition.contents.rules[].dialect` and
the member-schema dialect (rule and schema note); the comparator and agreement-model identifiers named by
`comparator` and `corroborates.model` (comparison note); attestation object contents under
`capture.attestation` (attestation note); package and transport framing on `pull`/`push` (storage note);
size limits larger than the single-statement bound (size policy, #9).

## 12. Open questions

1. **Integer bound.** This note caps integers at |n| < 2^53 so every JSON parser agrees; a 64-bit
   `content.bytes` or a chain height above that would have to be a string. Raise to 2^63 and require
   big-integer parsing, or keep 2^53 and accept string-typed large counts?
2. **High-`s` signatures.** Accept-and-normalise (this note) lets one statement arrive in several byte forms
   that a byte-level dedupe will not catch before the id check. Refusing high-`s` outright would make the
   signature bytes canonical too. Which does the storage note's dedupe path want?
3. **`ts` precision.** Whole seconds keep the canonical form one string; sub-second capture times would then
   live only inside `capture.at` of `observed`. Should `capture.at` allow fractional seconds while the
   envelope `ts` does not?
4. **A second algorithm at launch.** Ed25519 would free implementations from keccak and secp256k1 and from
   the Ethereum address derivation. Add `ed25519` as a second *required* algorithm now, or as the first minor
   extension once a second implementation exists?
5. **Detached lines.** §7 attributes an `authored` or `observed` to its signer even while `prev` is
   unresolved, because attribution is the signature's job and chaining is the time-bound's job. Should any
   other kind (`anchors`, `edition`) be evaluated at all before it chains?
