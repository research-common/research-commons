# Getting started

Ten minutes, from nothing to two stores that agree. Every command below was run against this tool. The background
is in the [README](README.md); the reasoning is in [`docs/WHY.md`](docs/WHY.md).

**Mental model.** A *store* is a directory (it holds a marker file, `rc-store`). You publish *signed statements*
into it: "I authored these bytes, under this licence". A reader never takes another store's word: `pull` judges every
object, and `verify` answers from the statements the reader itself holds.

## 1. Install

```bash
go install github.com/research-common/research-commons/cmd/commons@v0.5.0-alpha.1
commons --version
commons help                    # every command; `commons help <command>` for its options
```

Or build from a clone of the `next` branch: `go build -o commons ./cmd/commons`. Go 1.26+; Windows is not supported.

## 2. Make a store and a key

```bash
mkdir demo && cd demo
commons init a
commons key new --out k.key
```

`init` prints `result: created`. `key new` writes a key file (mode 0600, never overwritten) and prints your **signer**,
`ed25519:<64 hex>`. Share the signer; never the file. The tool keeps no copy and has no default key location, so back
the file up once, somewhere only you can read, and don't reuse a payment key.

## 3. Publish something

```bash
echo "hello commons" > data.txt
cd a
COMMONS_KEY=../k.key commons publish --kind authored --content ../data.txt --licence CC0-1.0
```

(or pass `--key ../k.key`). One command signs two statements, `authored` and `holds`, and commits them with the bytes
in one journal record: `committed: yes`. Add `--dry-run` first to see what would be signed without writing anything.

```bash
commons list
```

shows the blob (`sha256:…`), `authorship: sole author`, and each disclosure: here the licence is `CC0-1.0`, the rest
`undeclared`. `commons show <digest>` shows the same for one blob.

## 4. Verify

```bash
commons verify sha256:<digest>
echo $?                         # 0
```

Exit 0 means checked and passed: the statements held support the answer. Exit codes (`commons help exits`): 0 ok,
1 checked and wrong, 2 did not start, 3 could not check, 4 nothing to re-run, 5 environment mismatch. Everything
is stated "within statements you hold": nothing is claimed about statements this store never received.

## 5. Pull into a second store

```bash
cd .. && commons init b && cd b
commons pull ../a
commons verify sha256:<digest>  # exit 0: same answer, from b's own copy
commons fsck                    # scanned: blobs 1, statements 2 · clean: yes
```

`pull` takes a store directory or a `.tar`/`.tar.gz` of one. It prints a verdict for every object and an exit status
(0 all admitted, 1 something refused, the rest still committed). The line `rc-store … not applied · control-plane change:
needs maintainer review` on a pull is expected: the marker file is reported, not applied. Use `commons pull --dry-run`
to judge a package without installing it.

If the source is a git checkout (it has a `.git`), `pull` refuses the `.git` entry and exits 1; pass
`--from-checkout` to skip it as transport metadata. To pull under your own rules (a trust floor, overrides), write a
reader policy: [`docs/READER-POLICY.md`](docs/READER-POLICY.md).

## 6. Keep going

- `commons fsck` any time you suspect damage; `commons status` shows unfinished operations and what the filesystem
  guarantees (`--limits` lists the scan limits).
- A blob made by a script can carry `--provenance` (workflow, inputs, environment); `verify --rerun --exec-policy
  <file>` re-runs it in a sandbox under *your* policy: [`docs/EXEC-POLICY.md`](docs/EXEC-POLICY.md).
- Tasks others can claim: `commons publish task --help`. Rules for how editions are read: the
  [claims model](docs/DESIGN-notes-claims-model.md).
- Fetch bytes a `holds` statement points at: `commons fetch --help`.

## 7. Share it as a hub

A hub is a git repository whose tree is a store. Create one from the
[hub template](https://github.com/research-common/research-commons-hub-template) ("Use this template" on GitHub), or
`git init` a store directory and commit it. Collaborators clone it and `commons pull` from the clone (add
`--from-checkout`). The template's `hub-check` workflow runs `commons hub check` on every pull request, as the hub's
CI; run it yourself in the hub directory first (it needs at least one commit; `--base <rev>` checks only a change).
`hub check` writes nothing.

What is not built yet, and what may change: [`docs/KNOWN-LIMITS.md`](docs/KNOWN-LIMITS.md).
