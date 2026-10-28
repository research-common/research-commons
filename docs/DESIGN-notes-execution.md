# Design note: execution profiles

**Status:** proposed · **Companion to:** the claims-model note (§15, "execution profiles: runtimes,
confinement mechanism, limits") · **Covers:** that §15 item; claims-model note §4 (`reproduced`), §5.2
(derivation groups, the environment record), §11 ("admission is not execution"), §12 (the sandbox bullets), §13 (exits 3
and 5, `timeout`); conformance cases C-exec-01 through C-exec-16 (incl. C-exec-13a, C-exec-13b), plus C-core-32 (the environment record as a method
referent) and C-core-133 (exits 3 and 5).

## 0. Summary

- A workflow is a pinned description of a computation: code by hash, inputs by hash, runtime and image by
  digest, parameters, network requirement, resource profile. Anything unpinned is disclosed and keeps the
  output out of every derivation group.
- Two profiles. `sandbox` is the default and the only profile a foreign workflow may run under. `native` runs
  only the reader's own workflows, only under an explicit grant, and is never a fallback.
- The sandbox includes staging. Every host-side join of a peer-supplied name is confined before the step
  starts and when outputs are read back; the refusal is intrinsic and names the path.
- Caps on CPU, memory, pids, disk and wall time are enforced by the kernel *during* execution. A timeout kills
  the container and every descendant, cleans staging, and reports `timeout` with resources used (exit 3: the
  reader's own limit stopped the check, so it could not check; exit 5 is reserved for environment mismatch).
- Every run writes an environment record. It travels on the `authored` statement of a derived artifact and on
  every `reproduced` statement, and `verify` compares it field by field.
- `bytes` workflows are judged by byte equality; `protocol` workflows by the comparator their own `authored`
  statement names, `unchecked` if none. Nondeterminism is a reported result, never a hidden one.
- Nothing from the host crosses the boundary unless a reader policy grant names it: no environment variables,
  no credentials, no network. Workflows and comparators share the boundary.
- A new environment produces a new `reproduced` statement. Nothing is restamped; the original stays.

## 1. What a workflow pins

A workflow is a blob (its spec) plus the `authored` statement its author signs over that blob. The spec pins
the computation; the statement carries the author's disclosures about it, including the replication mode and
comparator that derivers inherit (claims-model note §5.2). An implementation reads both and refuses to run a
spec whose pins are incomplete for the claim being made.

| field | in | value | if missing |
|---|---|---|---|
| `code` | spec | hash of the executable bytes (script, archive) or inline steps hashed with the spec | refuse (intrinsic: malformed workflow) |
| `inputs` | spec | map name → full content hash | an input named by anything else (tag, URL, path) is `unpinned` |
| `interpreter` | spec | runtime name and version constraint the step is invoked under | refuse |
| `image` | spec | image reference **and** per-platform manifest digest | `sandbox` refuses (reader policy: no image) |
| `parameters` | spec | literal values passed to the step, hashed with the spec | none (empty map) |
| `network` | spec | `none` · `required: [endpoints]` | `none` |
| `resources` | spec | the profile the step needs: `cpus`, `memory`, `pids`, `disk`, `wall_time` | implementation floor, shown as `undeclared` |
| `outputs` | spec | map name → relative file name inside the output directory | refuse |
| `replication` | statement | `bytes` · `protocol` · `none` | undeclared → every derivation under it is `unchecked` |
| `comparator` | statement | full hash of a comparator skill, plus its parameters | `protocol` derivations are `unchecked` |
| `environment_match` | statement | which environment-record fields a re-run must equal (§4) | `bytes`: image digest + platform; `protocol`: none |

Rules:

1. **Provenance is the pair (workflow hash, input hashes).** A run whose spec has any `unpinned` input emits
   an `authored` statement with the unpinned input listed and `provenance: partial`. It joins no derivation
   group and `verify` exits 4 (nothing to re-run) naming the input (C-exec-03). The run itself is not refused:
   partial provenance is disclosed, not forbidden.
2. **A spec never carries the replication mode or comparator.** They are single-party fields of the workflow's
   `authored` statement so that they are signed by the author and amendable only by the author (claims-model
   note §4, §5.2). An implementation that finds them in the spec body ignores them there and displays
   `replication: declared in spec body, ignored`.
3. **A network requirement makes the workflow an acquisition.** Its outputs are observations, not derivations:
   `run --publish` emits `observed` statements whose capture record is filled from the run (endpoint list,
   time window, environment record). A run that makes more than one request writes a request log into its
   output (endpoint, parameters, status, time and response hash per request) and the statement pins it by
   hash, format and count (wire-format note §5, source referent), so a capture of thousands of requests is
   one statement, never `authored` with provenance (§11, decided 2). They join no derivation group and
   carry no T0/T1. This is the mechanical form of "network access lives in `observed`, determinism in
   `corroborates`" (claims-model note, appendix; C-exec-14). A `network: none` workflow whose step opens a
   connection fails inside the sandbox (§2.1) and the run result is `failed`, never `match`.
4. **Pins are compared, not trusted.** The image digest in the spec is checked against the image actually
   pulled; a mismatch refuses the run (intrinsic: hash mismatch) before anything is staged.

## 2. Profiles

A profile is the mechanism under which a step runs. The invocation chooses it (`run --profile sandbox|native`;
default `sandbox`). The implementation never changes the chosen profile on its own: if the chosen profile
cannot run, the run is refused and the refusal names the class. There is no fallback in either direction.

| | `sandbox` | `native` |
|---|---|---|
| who may run under it | any workflow | only workflows whose `authored` statement is signed by a key the reader's execution policy lists as its own |
| grant needed | executable admission for the workflow's signer (§2.3) | executable admission **and** a `native` grant naming the workflow hash or `own: all` |
| runtime | OCI container from the pinned image digest | the host's interpreter |
| network | `none` unless the spec declares `required` and policy grants it | same rule; enforced by the host's own means and recorded as `enforced: no` |
| host environment | nothing crosses (§6) | nothing crosses; `PATH` and `HOME` are passed and recorded |
| caps | enforced during execution by the kernel (§2.2) | best effort; the record says `caps: advisory` |
| environment record | `profile: sandbox`, image digest, platform | `profile: native`, platform, interpreter versions, host-recorded fields |
| display | grade as computed | grade as computed, suffixed `(native)` on every surface that prints it |

### 2.1 The `sandbox` profile

An implementation that declares the `execution` profile in its conformance statement supports `sandbox`. The
confinement mechanism is an OCI-compatible container runtime; the obligations below are what a test observes,
not how the runtime is driven.

- **Image.** The container is created from the digest the spec pins. A reader policy allowlist, if present,
  is digest-pinned too and fails closed: an allowlist entry that cannot be resolved to a digest refuses
  (operational) rather than admitting by name.
- **Mounts.** Three, and only three: the input directory read-only; the output directory writable; a scratch
  tmpfs with a size cap. The root filesystem is read-only. No host path, socket or device is mounted. The
  workflow's own code is placed in the input directory.
- **Network.** `none` is the container's network mode when the spec declares `none` or nothing. `required`
  is honoured only when reader policy grants network to this workflow hash; otherwise the run is refused
  (reader policy: network) before staging. A granted run records the grant and the endpoint list it declared.
- **Process.** The step runs as an unprivileged user with every capability dropped, under an init process
  that reaps descendants, with the pid cap applied to the container's cgroup.
- **Identity of the boundary.** The run record names the boundary (`sandbox: oci, image <digest>`) so that
  C-exec-12's "the run record names the sandbox boundary" is a field, not prose.

### 2.2 Caps enforced during execution

Each cap is applied by the kernel to the container's cgroup or filesystem before the step starts, so it trips
while the step runs, not after it has finished. A host-side check after the fact (the output-size walk the
alpha did) may remain as a second check; it is never the only one.

The kernel enforces the disk cap (a write fails inside the container), but a size-capped filesystem raises no
event that says so: the step just sees a failed write. Which token the run gets (`failed: operational: disk`,
`failed: <exit n>` or `timeout`) is therefore the implementation's own classification, from the filesystem's
fill level while the step runs and when it exits or is killed. That classification is a heuristic; an
implementation documents it as one (I11), and it never changes what the cap enforced.

| cap | mechanism | when tripped | result token | exit (`verify`) |
|---|---|---|---|---|
| `cpus` | cgroup cpu quota | throttled, not killed | (none; wall time absorbs it) | |
| `memory` | cgroup memory limit, no swap | the step is killed by the kernel | `failed: operational: memory` | 3 |
| `pids` | cgroup pids limit | fork fails inside the container | `failed: operational: pids` | 3 |
| `disk` | output directory on a size-capped filesystem; scratch tmpfs size | write fails inside the container | `failed: operational: disk` | 3 |
| `wall_time` | the implementation's timer; on expiry it kills the **container**, not its client process | the container and every descendant are gone before the result is written | `timeout` | 3 |

Cap values come from two places: the spec's resource profile (what the step says it needs) and reader policy
(the most the reader allows). The run uses the spec's values when they are at or under the policy ceiling. If
the spec asks for more than the policy ceiling, the run is refused (reader policy: resources) naming both
numbers; the implementation never silently runs the step under a smaller cap than it declared, because the
resulting failure would be indistinguishable from a workflow defect.

**Running below the declared profile is the reader's explicit choice** (§11, decided 3). An invocation may ask
for it (`run --below-profile`; never a default, never a fallback). The step then runs under the reader's
ceiling for each cap the spec exceeds, and the environment record carries both values for each such cap
(`caps` in force and `declared`). A cap that trips gives `failed: operational: <cap> (below declared
profile)`, or `timeout (below declared profile)` for wall time, exit 3, and the next step names the declared
value: run where it is available. A run that completes is compared as any other: `match` is an ordinary
`match`, and the record shows it ran below the declaration. A failure under this flag is never read as a
defect of the workflow, and resource use stays outside the grade (§4).

After any cap trips: staging is removed, no output is read back, no statement is emitted, and the result is
written with the resources used up to the kill (`wall_time`, `peak_rss`, `pids_peak`, `bytes_written`). The
implementation verifies cleanup by checking that the container no longer exists and that no process remains
in its cgroup, and records the check (C-exec-10, C-exec-11).

### 2.3 Executable admission

Holding a workflow is not permission to run it (claims-model note §11). The reader's execution policy grants
execution per signer key or per workflow hash. Trust level, hub endorsement and task beneficiary status grant
nothing: a workflow signed by a key at the reader's highest trust level with no execution grant is refused
under `reader policy: executable admission`, and the refusal shows the trust level beside the missing grant
so the reader sees why trust did not suffice (C-exec-07). The same grant structure covers comparators.

### 2.4 The `native` profile

`native` exists for the author's own development loop and for a reader who deliberately accepts host
execution of its own code. It is never chosen for the reader: a `sandbox` invocation whose runtime is
unreachable is refused with `operational: sandbox runtime unavailable`, and a process audit shows nothing was
spawned (C-exec-06). The three conditions for `native` are checked before staging: the profile was named in
the invocation, the workflow's author key is the reader's own under its policy, and the policy carries a
`native` grant covering this workflow. Failing any one refuses under reader policy, naming the condition.

A native run records `profile: native` and the host facts it can measure (§4). Its grade is computed by the
same rules as any other run and displayed with the suffix `(native)` on every surface that prints a grade:
`T0 (native)`. The suffix is part of the grade display, not a disclosure, because it describes how the
derivation was performed. It does not change the grade's rank or any exit code.

A native result is re-derivable only by rebaseline (§8): a stranger's `verify` of it exits 5 (environment
mismatch: `profile native ≠ sandbox`) unless that reader's own policy accepts native records, in which case
the mismatch is still named and the comparison proceeds under the reader's stated choice.

**Native records join derivation groups** (§11, decided 1). A native `authored` or `reproduced` is a member of
its group for every reader, displayed with `(native)`; the exit-5 rule above keeps it from being mistaken for
a sandbox reproduction. Keeping groups sandbox-only would hide the record from the group display without
making it any less the author's statement.

### 2.5 Declaring support

An implementation's conformance statement lists, under the `execution` profile, the runtimes it supports:
`sandbox: oci` and optionally `native`. `explain` on any run record prints the same list beside the profile
used. A case for a runtime the implementation does not list is reported `unsupported`, not omitted.

## 3. Staging confinement

The sandbox is not only the container. Before the step runs, the host writes attachments, inputs and the
workflow's code into the input directory under names a peer chose; after it runs, the host reads outputs
under names the spec chose. Each of those joins is an opportunity to read or write outside staging, and #67
showed that the container flags establish nothing if the host side is loose. This section is the boundary.

**Every host-side join of a peer-supplied name** (attachment names, input names, output names, comparator
file names, archive member names during extraction) goes through one confinement function (I12). It refuses:

| name | reason shown |
|---|---|
| empty, non-string, or containing NUL | `unsafe path: malformed name` |
| absolute (`/…`, a drive prefix, `\\…`) or beginning with `~` | `unsafe path: absolute` |
| any `..` component, after normalising `\` to `/` | `unsafe path: traversal` |
| any existing component that is a symlink | `unsafe path: symlink component` |
| resolving outside the directory for any other reason (case folding, alias, mount) | `unsafe path: resolves outside directory` |
| a device, socket, fifo or other non-regular target | `unsafe path: not a regular file` |

The refusal class is **intrinsic** (claims-model note §11: unsafe paths), the scope is the named path in the
named workflow or run, and the message prints the name verbatim with control characters escaped. Refusal
happens before the container is created (for inputs and attachments) and before any byte is read (for
outputs), so a canary file outside the root is never touched (C-exec-08, C-exec-09).

**Outputs are regular files.** When the step finishes, the host walks the declared outputs through the same
function. A symlink the step created inside the output directory is caught by the symlink-component check on
read-back, because the function examines the real filesystem after the step, not the spec's text. A missing
or non-regular output makes the run result `incomplete output`: no statement is emitted, nothing is hashed,
and the token is never `match` (C-exec-09). A hard link is a regular file and is admitted; its bytes are
hashed like any other.

**Inputs are read-only.** The input mount is read-only and the host verifies each input's hash after staging
and before the step starts, so a step cannot change what provenance says it consumed.

**Archive members** extracted during staging are joined by the same function, member by member; an archive
whose member name fails is refused as a whole (intrinsic: unsafe path, scope the member), with nothing
extracted.

## 4. The environment record

Every run writes one environment record. It is carried, unchanged, on the `authored` statement of each output
when the run is a first derivation, on the `reproduced` statement when it is a re-run (§5), and on `observed`
statements when the workflow is an acquisition (§1 rule 3). The wire-format note fixes the encoding (its §5,
"Execution objects"); this note fixes the fields and their meaning. Two fields complete the table: `boundary`
(the sandbox boundary that confined the run, which C-exec-12 requires the record to name) and `cleanup` (the
result of the post-kill check, §2.2).

| field | meaning | required under |
|---|---|---|
| `profile` | `sandbox` · `native` | both |
| `image.reference`, `image.digest` | image name and the per-platform manifest digest actually run. `image.digest` is an OCI digest string (OCI image-spec, descriptor §Digests): `sha256:` + 64 lowercase hex | `sandbox` |
| `platform` | OS and architecture of the execution as `<os>/<arch>[/<variant>]`, with `os` and `arch` from Go's `GOOS`/`GOARCH` values and `variant` from the OCI image-index `platform.variant` list (`linux/amd64`, `linux/arm64/v8`); the string the OCI tooling accepts for `--platform` | both |
| `harness_commit` | the commit of the harness that launched the run, as full lowercase hex (40 for a SHA-1 repository, 64 for SHA-256), never an abbreviation or a tag | both, when the harness is a repository |
| `runtime` | container runtime name and version (sandbox); interpreter name and version (native) | both |
| `interpreter` | the interpreter the step was invoked under, with its version as reported inside the environment | both |
| `declared_deps` | the spec's dependency declarations, verbatim | both |
| `caps` | the cap values in force: `cpus`, `memory`, `pids`, `disk`, `wall_time`; `advisory: true` under native; for a run below the declared profile (§2.2), each lowered cap also carries the spec's `declared` value | both |
| `network` | `none` · `granted: [endpoints]` | both |
| `grants` | names (never values) of policy grants that crossed the boundary (§6) | both |
| `peak_rss_bytes` | peak resident memory of the container cgroup (or the process tree, native). Under `sandbox` it is always measured: the cgroup reports it, and an implementation that cannot read it does not conform to the profile (§11, decided 5). `unmeasured` is allowed under `native` only | both |
| `wall_time_ms` | from container start to exit or kill | both |
| `exit_status` | the step's exit code, or `killed: <cap>` | both |
| `result` | the run result token (§5.2) | both |
| `staging_check` | `ok` or the intrinsic refusal that stopped the run | both |

Rules:

- **Standard forms.** Following the wire-format note's standards-first rule (its §0), digest and platform
  use the OCI forms above, so the record holds the strings `docker inspect`, `crane digest` and OCI
  registries print, and two records compare by string equality. Platform strings are compared as written:
  `linux/arm64` and `linux/arm64/v8` are different strings, so a record pins the variant whenever the runtime
  reports one.
- **Measured, not copied.** `image.digest`, `platform`, `runtime`, `peak_rss_bytes` and `wall_time_ms` are
  taken from the runtime after the run, never from the spec. A value the implementation could not measure is
  written as `unmeasured`, never as zero or as the spec's number; for `peak_rss_bytes` that is a `native`
  record only.
- **Comparison.** `verify` compares the fields the workflow's `environment_match` names (§1) between the
  pinned record and the record of the re-run. A difference in any named field is an environment mismatch:
  exit 5, the field named, and the byte comparison is reported as `not compared (environment mismatch)`.
  Fields not named are displayed side by side and never cause exit 5.
- **The record is a method referent.** A method-class observation (claims-model note §5.3.1) that pins its
  execution environment uses this record under the same field names, so one `explain` shows the same shape
  for a benchmark observation and for the derivation that analysed it (C-core-32).
- **Resource use is never a grade input.** Peak RSS and wall time are shown beside the grade and inside
  `explain`; a run that used more than another is not thereby worse.

## 5. Determinism and the result token

### 5.1 What `run --publish` emits

| the runner holds for `(W, inputs)` | emitted |
|---|---|
| no `authored` of its own, bytes `X` produced | `authored` for `X` with provenance and the environment record (C-exec-02) |
| its own `authored` for the same bytes `X` | `reproduced: match` pointing at that statement, with the new environment record; no second `authored` (C-exec-01) |
| its own `authored` for different bytes `Y` | `reproduced: diverged` (or `match` under the comparator, §5.3) pointing at it; `Y`'s `authored` stays |
| another key's `authored` for the same provenance | `authored` for its own bytes; the group display handles the rest (claims-model note §5.2) |

A `reproduced` statement always carries: the statement it reproduces (by hash), the workflow and input
hashes, the output hashes it produced, the result token, and the environment record. Its `result` is one of
`match`, `diverged` and `not comparable`, so a re-run whose comparison is `unchecked` (different bytes under
`protocol` with no comparator, or under an undeclared mode, §5.3) emits no `reproduced`: `run` reports the
token and says why nothing was published, and the reader's own record of the run is unaffected.

### 5.2 Result tokens

The run result is one token from this table. It is written into the environment record and printed by every
surface that shows the run; the `verify` exit codes are the claims-model note's (§13).

| token | meaning | `verify` exit |
|---|---|---|
| `match` | re-derivation agrees with the pinned result under the workflow's replication mode | 0 |
| `diverged` | it does not | 1 |
| `unchecked` | no comparison could be made under the declared mode (no comparator; mode undeclared) | 3 |
| `not comparable` | the comparator ran and reported the pair outside its domain (unit or shape mismatch) | 3 |
| `incomplete output` | a declared output is missing or not a regular file | 3 |
| `failed: <exit n>` | the step exited non-zero | 3 |
| `failed: operational: <cap>` | a cap other than wall time stopped the step; resources used recorded | 3 |
| `timeout` | wall-time cap; container and descendants killed; resources used recorded | 3 |
| `… (below declared profile)` | either of the two rows above, in a run the reader chose to run below the spec's profile (§2.2) | 3 |
| `environment mismatch: <field>` | a field named by `environment_match` differs between pin and re-run | 5 |

Exit 1 is reserved for a comparison that ran to completion and disagreed: a script reads it as "the pinned
result is refuted". A step that exits non-zero, leaves a declared output missing, or is stopped by a cap has
compared nothing, so it exits 3 and the token says which kind of "could not check" it was. Exit 5 is only an
environment mismatch: the environment the pin declares differs from, or is not available in, the one that
ran. The table is the claims-model note's §13 vocabulary applied to runs.

**An environment mismatch is checked first.** When a re-run in an environment that differs from the pin also
fails, times out or produces different bytes, the token is `environment mismatch: <field>` and the exit is 5:
a run outside the environment the pin declares says nothing about the pin, so its failure or its bytes are
shown and never read as a 3 or a 1 (§4, "not compared (environment mismatch)").

**A failure in the pinned environment is evidence about the claim, not the bytes.** When a `bytes` workflow's
re-run fails or leaves outputs missing in an environment that matches the pin, `explain` says in words that the
determinism claim may be weaker than declared (a hidden dependency, nondeterminism in the step); the pinned
bytes are not thereby shown wrong, and the earlier statements stay as they are. If the re-run is the author's
own, the correction is the same as for `diverged` (§5.3): the author amends its `authored` statement to
`protocol` with a comparator, or to `none`. The tool never makes that amendment on the author's behalf.

A refusal before the step starts (unsafe path, missing grant, unavailable runtime, image digest mismatch) is
not a result token: it is a refusal in the named class with its scope, and no run record is written.

### 5.3 Comparison by replication mode

| the workflow's `authored` declares | identical bytes | different bytes |
|---|---|---|
| `bytes` | `match`, T0 | `diverged`; the display adds "an environment differs or the determinism claim is wrong" and shows both environment records side by side |
| `protocol` with comparator `K` | `match (identical bytes)`; shown as `identical bytes (protocol workflow)`, no T0, no copy flag | `K` runs sandboxed on the two outputs: `match` (T1 under `K`) · `diverged` · `not comparable` |
| `protocol` without comparator | `unchecked` | `unchecked`; the display says the workflow declares no comparator |
| undeclared | `unchecked` | `unchecked` |

The comparator is the one named on the workflow's own `authored` statement, amended only by the workflow's
author. A runner cannot supply a different comparator at run time; a `--comparator` flag, if offered for
exploration, produces a `describes` statement ("compared under K′: …"), never a `reproduced`. The comparator
runs under the same profile and boundary as the workflow (§6), with the two outputs as its only inputs and no
network, and its own environment record is nested inside the `reproduced` statement.

**The comparator interface**. A comparator is a workflow spec (§1) with exactly two inputs, named
`a` and `b`, which the reader fills with the two outputs in ascending digest order; no network; and exactly
one output, named `verdict`, whose bytes are `match`, `diverged` or `not comparable`, optionally followed by
one line feed. Anything else (other bytes, a failed step, a cap stopping it, a spec that does not have this
shape) makes the comparison `unchecked`, with the reason. A comparator's own `authored` declares
`replication: bytes`: a comparison has one answer per pair (claims-model note §5.2), and a reader that caches
comparator results relies on it; a comparator that declares anything else is not run, and every comparison
under it is `unchecked`. The alpha's interface (`<comparator> <expected> <actual>`, exit 0 or 1) has no
`not comparable` and is not carried forward.

**Nondeterminism is a result.** A `bytes` workflow that produces different bytes across two runs in the same
environment is reported exactly as the table says: `diverged`, both records visible, the earlier statement
untouched (C-exec-13). The implementation never re-runs until it matches, never picks the majority of several
runs, and never downgrades the declared mode on the author's behalf. The author corrects the claim by amending
its own `authored` statement to `protocol` (with a comparator) or `none`.

## 6. Credentials and host environment

The boundary is deny-by-default in both profiles:

- **No host environment variable crosses.** The step sees the spec's declared `env` map, the fixed names the
  implementation sets (`IN_<name>`, `OUT_DIR`), and nothing else. Under `native`, `PATH` and `HOME` are also
  passed because an unpinned host needs them to find an interpreter; they are recorded, not trusted.
- **Grants are explicit and named.** Reader policy may grant a workflow hash a named secret or a named host
  resource (`grants: {API_TOKEN: <source>}`); the grant crosses as the named variable, and the environment
  record lists the **name** only. Values never appear in records, logs, errors or statements (claims-model
  note §13).
- **Same boundary for comparators.** A comparator is fetched code and gets the same treatment: no host
  environment, its parameters as named variables, no network, no grants unless policy names the comparator
  hash.
- **Network is a grant, not an inference.** An input that happens to be a URL grants nothing; only the spec's
  declared `network: required` plus a policy grant opens the network, and then only as declared. "Only as
  declared" needs per-endpoint egress control (a filtering proxy or firewall rules for the container). An
  implementation that can only open the network as a whole says so: the record's `network` carries
  `enforced: "all"` instead of `"per-endpoint"`, and the display shows `network granted (not limited to the
  declared endpoints)`.

C-exec-12 is the test: a canary variable, a canary file and a canary listener; the run record names the
boundary; none of the three is reached.

## 7. `run --publish` and disclosures

`run --publish` accepts the complete disclosure set that `publish` accepts, per output, and the set difference
between the two commands' accepted disclosures is empty (#21; C-exec-05). Disclosures are supplied per output
name (`--licence out1=CC-BY-4.0`); an output with none supplied carries none and displays licence `unknown`
(C-exec-04). Nothing is inherited: not from the workflow's own statement, not from the inputs, not from a
sibling output. Publishing with partial disclosures needs no flag, because a missing disclosure is a disclosed
state (claims-model note §7), not an error.

The provenance block (workflow hash, input hashes, environment record) is written by the tool from the run
and cannot be supplied or overridden on the command line.

## 8. Image pinning and rebaseline

An image is pinned by its per-platform manifest digest, so that `linux/amd64` and `linux/arm64` builds of one
tag are two environments. The record stores the digest run, and `environment_match` for `bytes` workflows
includes it by default, so a re-run on another architecture is an environment mismatch (exit 5), not a
`diverged`.

**Platform-independent results are declared by narrowing `environment_match`** (§11, decided 4). An author
who claims the bytes do not depend on the platform drops `platform` (and, if it applies, the image digest)
from the workflow's `environment_match`. A re-run on another architecture is then compared on bytes:
`match` or `diverged`, with both records side by side. There is no third token such as `match (platform
differs)`: the claim is the author's, signed on the workflow, and a `diverged` on another platform is
evidence against it like any other.

**Rebaseline is a new statement, never an edit.** When an author or any runner re-runs a workflow under a new
environment (a rebuilt image, a new architecture, sandbox where the original was native), the run emits a
`reproduced` statement with the new record and the result token computed under the workflow's mode. The
original `authored` statement and its record are untouched (I3). The group display accumulates them:
`derived by 1 · reproduced under 2 environments: 1 match, 1 diverged`, with `explain` showing each record.
There is no operation that stamps a new environment onto an old statement, and no "superseding" artifact is
created for a byte-different rebaseline: the new bytes, if the runner wants them as a result in their own
right, are a new `authored` statement with its own provenance.

A workflow author who wants to move the baseline amends its own `authored` statement on the workflow to pin
the new image digest; derivations under the old pin stay valid under the old pin.

## 9. Relationship to the alpha

| alpha primitive | kept / dropped | why |
|---|---|---|
| one confinement function for every host-side join (#67) | **kept as the model**; extended with device-file and regular-file checks | the fix is right; the design makes it the boundary rather than a patch |
| digest-pinned image allowlist that fails closed | kept | a name is not an environment |
| scrubbed environment for both profiles, declared `env` only | kept; grants added as the only way in | undeclared host state is undeclared input |
| comparators run under the invoking run's profile | kept; same boundary made explicit | fetched code is fetched code |
| default profile `native` with sandbox opt-in | **dropped**; `sandbox` is the default and `native` needs a grant | a silent host run is an undeclared environment |
| native fallback with a warning when the runtime is unavailable (#25's first half) | **dropped**; refusal instead | a warning is still a fallback |
| environment record = `{mode, image, digest}`; missing record read as native | **dropped**; full record (§4), required on every statement | the record is the pin |
| client-side timeout that kills the client process | **dropped**; the container is killed and cleanup verified | the step kept running after the client gave up |
| output-size check after the run | demoted to a second check; kernel caps during execution | a cap that trips after the fact caps nothing |
| scratch mounted writable with inputs inside it | **dropped**; inputs read-only, outputs separate | a step could rewrite what provenance says it read |
| `rebaseline` that restamps the exec record or publishes a superseding artifact | **dropped**; `reproduced` statements (§8) | statements are immutable; a restamp is a rewrite |
| peak RSS not recorded (#25's second half) | **added** as `peak_rss_bytes`, `unmeasured` when unavailable | resource use belongs in the record |
| spec-level `tier` and `comparator` | **dropped** from the spec; replication mode and comparator live on the workflow's `authored` statement | single-party fields are signed by their party |

## 10. Out of scope

- The wire encoding of the environment record and of `reproduced` (wire-format note).
- Statistical comparator dialects and what a comparator may report beyond its three outcomes.
- Attestation of the execution environment (TEE receipts); a record is the runner's word, shown as such.
- Multi-step pipelines and caching of intermediate outputs across workflows.
- Distributed or remote execution; this note's boundary is one host.

## 11. Decisions and open questions

**Decided (2026-10-16).** All five.

1. **Native records across readers.** Admitted into derivation groups, displayed `(native)`; a stranger's
   `verify` names the profile mismatch and exits 5 unless its policy accepts native records (§2.4).
2. **Acquisition workflows.** `network: required` workflows emit `observed` only (§1 rule 3). The capture /
   derivation line the claims-model note draws is kept.
3. **Spec profile versus reader ceiling.** Refusal stays the default; a reader may opt in to running below the
   declared profile, and a resulting cap failure is `… (below declared profile)`, exit 3 (§2.2, §5.2).
4. **Cross-architecture `bytes` results.** No third token; an author who claims platform independence drops
   `platform` from `environment_match` (§8).
5. **Peak RSS as a requirement.** Always measured under `sandbox` (a conformance requirement); `unmeasured`
   only under `native` (§4).

The questions as first asked:

1. **Native records across readers.** Should a `reproduced` or `authored` with `profile: native` be admitted
   into a derivation group at all for readers other than its author, or displayed only as the author's own
   record beside the group? This note admits it and lets `environment_match` produce exit 5; the alternative
   keeps groups sandbox-only.
2. **Acquisition workflows.** This note makes a `network: required` workflow emit `observed` only (§1 rule 3).
   The alternative is to allow `authored` with `replication: none`, which keeps one statement kind for all
   `run --publish` output at the cost of blurring the capture/derivation line the claims-model note draws.
3. **Spec profile versus reader ceiling.** When the spec's resource profile exceeds the reader's ceiling the
   run is refused. Should a reader instead be able to run under its smaller cap and have a resulting cap
   failure recorded as `failed: operational: <cap> (below declared profile)`, so a reproduction attempt on a
   small machine is still evidence?
4. **Cross-architecture `bytes` results.** The default makes an arm64 re-run of an amd64 pin an environment
   mismatch. Is `match (platform differs)` a useful third outcome for workflows whose authors declare the
   result platform-independent, or does that reintroduce a determinism claim the tool cannot check?
5. **Peak RSS as a requirement.** Under `sandbox` the cgroup makes `peak_rss_bytes` measurable everywhere the
   profile can run. Should `unmeasured` be refused for the sandbox profile (a conformance failure), leaving
   it allowed only under `native`?
