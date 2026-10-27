# Execution policy file (`rc-exec-policy/0`)

`commons verify <digest> --rerun --exec-policy <file>` re-runs a blob's recorded derivation on this machine and
compares the result with what was pinned. A re-run executes code, so it happens only when the reader asks for it
(`--rerun`) and only under the reader's own policy, read from this file. Without `--exec-policy` nothing runs and
the re-run is reported `unchecked` (exit 3), never a pass. `--exec-policy` without `--rerun` exits 2.

**Status: provisional.** The execution design note says what an execution policy decides, not how it is
written down; this file format is the tool's own and versioned (`rc-exec-policy/0`). It will change, with a new
tag. A file with a different `format` is refused.

## Format

One strict JSON object, at most 1 MiB (UTF-8, no duplicate members, integers only). Parsing is strict: a
member this version does not define, a member of the wrong shape, or a malformed value exits 2 with nothing
run. No member is ignored.

| member | value | meaning |
|---|---|---|
| `format` | `"rc-exec-policy/0"` (required) | the format tag |
| `exec_signers` | array of signers (`ed25519:` + 64 characters, or `0x` + 40 characters; the prefix and length are checked at read, the signer is compared as written) | keys whose workflows may run |
| `exec_workflows` | array of content digests (`sha256:` + 64 lowercase hex) | workflow spec blobs that may run, whoever signed them |
| `network` | array of content digests | workflows granted the network their spec declares (only the endpoints the spec lists) |
| `images` | array of image digests | allowlist of OCI images; a run whose image is not listed is refused |
| `ceiling` | object | the most the reader allows per resource cap |

`ceiling` members are `cpus` (milli-CPUs), `memory` (bytes), `pids`, `disk` (bytes) and `wall_time`
(milliseconds); each a non-negative integer, and any other name is refused. A cap not named is not limited by the
reader. A workflow whose spec declares more than the ceiling is refused, naming both numbers.

All members except `format` are optional. **Every grant is explicit: an absent member grants nothing.** A
workflow runs only if its author is in `exec_signers` or its spec digest is in `exec_workflows`. Trust in a key
(or a hub's endorsement) is never permission to execute.

Details worth knowing:

- `images` entries are not checked when the file is read, but an entry that is not a digest makes every run that
  consults the list refuse (the list fails closed). An empty `images` array is read as no `images` member, that
  is, no allowlist; to restrict runs, list the digests you accept.
- Only the sandbox profile is run. A workflow with no pinned image is refused before it starts.

## Not expressible yet

- Native (unsandboxed) runs and accepting native records from others: the format has no member for them, so a
  re-run is always sandboxed.
- Secret or host-resource grants: there is no place in the file for them, and secret values are never written
  in a policy.
- Your own keys, and running below a workflow's declared resource profile.

These are deliberately absent rather than defaulted: a member that is not listed above is refused, so a file
written for a later version fails here instead of being silently under-applied.

## Example

```json
{
  "format": "rc-exec-policy/0",
  "exec_signers": ["ed25519:0000000000000000000000000000000000000000000000000000000000000000"],
  "images": ["sha256:1111111111111111111111111111111111111111111111111111111111111111"],
  "ceiling": {"memory": 2147483648, "wall_time": 600000}
}
```
