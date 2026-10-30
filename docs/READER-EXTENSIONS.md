# Opt-in critical-extension validation

This is an implementation design note for the next-format Go reader in `internal/wire`,
not an extension specification. **No concrete extension is implemented or enabled.**
It defines no extension body layout, authorization rule, new signature algorithm, or
resolver behavior. The existing wire-format extension rules are unchanged.

## Small, local API

- `wire.Read(line)` keeps its existing signature and uses an empty registry.
- A zero-valued `wire.Reader` behaves identically to `wire.Read`.
- `wire.NewReader(map[string]wire.ExtensionValidator)` returns a configured reader or
  a configuration error. It copies the map, rejects nil validators, and accepts names
  under the existing `crit` rule: an `x_` prefix, with no additional name grammar.
- `(*wire.Reader).Read(line)` uses that reader's fixed registry.
- `wire.ExtensionValidator` is `func(envelope *canon.Object) error`. The argument is a
  private deep copy of the signature-verified envelope **without `sig`**, including
  `body`, `crit`, kind, signer, sequence, linkage, timestamp, and any extra fields.
  The callback finds its named member inside `body` and can check it against the
  envelope. Returning nil accepts that extension; any non-nil error refuses the
  entire statement as an intrinsic malformed-statement refusal naming the extension.

There is no global registration function, received-data registration mechanism,
plugin loader, or production registration. Registry construction is a deliberate
local code decision, not something a peer's data can request. Existing log, store,
resolver, and writer callers still use the empty-registry `wire.Read`; this change
does not silently opt any of them into new semantics.

## Ordering and invariants

The reader keeps its existing parse, envelope, canonicalization/size, base-schema,
body-time, and signature checks and their refusal ordering. Extension validation is
an additional step after successful signature verification, not a replacement for
any check.

1. Validate the envelope and `crit` structure as before. When present, `crit` must be
   a nonempty, sorted, duplicate-free list of `x_` body-member names, each actually
   present. A registered name does not excuse a missing member or malformed list.
   Absent `crit` remains legal because it is optional; a body extension that is not
   listed is retained and ignored, even if a validator for that name exists.
2. For a supported major and signature algorithm, preflight **every** `crit` name.
   If even one is unregistered, skip **all** base-body and extension interpretation.
   Verify the signature and retain the statement as `Unsupported`, with the same
   signed bytes, ID, linkage, and complete `crit` reason as the empty-registry path.
   A bad signature still refuses it. A known prefix of a mixed list never runs.
3. If every critical name is registered, run the existing base-kind schema and body
   time checks, preserving schema results such as unpinned referent fields. An
   extension cannot bypass required base fields or make an invalid base time valid.
   An unknown kind still has no base schema and remains `UnknownKind`, never `Valid`.
4. Verify the signature. Only then invoke each listed validator, in the already
   validated `crit` order (wire UTF-16 key order). Known extensions on an unknown
   kind must still validate, but successful callbacks cannot give that kind meaning.
   The first callback error returns a refusal and no statement; later callbacks do
   not run.

Unknown major/algorithm handling is unchanged: those statements remain unsupported
and unverified under the existing linkage contract, and no extension callback runs.
The registry never supplies cryptography or adds a base kind.

## Purity and tradeoffs

Validators are trusted, in-process local code. They **must be deterministic,
side-effect-free, and safe for concurrent calls**: no I/O, registration, state changes,
or resolver actions. This API is a validation hook, not an effect or transformation
hook. It does not sandbox callback code, roll back its external side effects, or
recover programmer panics. Such callbacks must not be installed.

Each callback receives a separate deep copy, including nested arrays and objects.
Mutating or retaining that snapshot cannot change the returned statement, its body,
canonical line, signed string, ID, or another callback's input. Callbacks return only
an error; there is no result that can rewrite a status or grant authority. This costs
one bounded-envelope copy per invoked extension, in exchange for avoiding shared
mutable parser state and a larger bespoke context API. Only explicitly configured
readers pay this cost. Caller-owned registration maps are copied too, though callback
closures themselves must obey the purity contract.

Base schema/time refusal still precedes signature refusal, preserving existing
behavior when both are bad. Callbacks run after verification to avoid exposing even
locally installed extension code to unauthenticated input. Full support preflight is
separate from validation so an unsupported mixture cannot trigger partial callback
effects or base-body interpretation.

## Integration boundary and tests

`Verified` means the signature was checked; it does **not** mean the body is safe to
evaluate. A verified `Unsupported` statement must still chain and be retained, but
consumers must not read its body for semantic decisions. `UnknownKind` likewise grants
no known-kind behavior. The registry does not change or replace downstream status
guards. Future integration must deliberately select a reader and separately implement
and review any resolver semantics; it must not infer those semantics from registry
membership alone.

Focused tests cover empty-reader equivalence, both existing signature algorithms,
all base kinds, body times, unknown kinds, malformed `crit`, mixed support lists,
callback refusal and ordering, immutable snapshots, registry isolation, concurrent
reads, UTF-16 ordering, and unsupported-line chaining in both delivery orders.
Handlers and synthetic extension values exist only in tests. Writer wire bytes,
signature algorithms, dependencies, and the protocol specification are unchanged.
