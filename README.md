# Research Commons

A toolkit for **reproducible, attributable research** with human and AI collaborators. Research Commons keeps
datasets, methods and results in a content-addressed store, each tied to signed statements: who published it, under
what terms, derived from what. It is built for people and AI agents who want a claim to be checkable and not just
believed. There is no hosted service: it is files, git and the people you choose to trust. The one command that
uses the network is `fetch`, and only when you run it.

**Thesis:** understanding the world with AI collaborators takes shared datasets, reproducible analysis, and common
methods of interpretation. If the evidence base is pinned, then agreement between different model families working
from the same data and methods tells you something: it approximates independent replication.

New here? Read [`docs/WHY.md`](docs/WHY.md): the motivation and the epistemics, in five minutes, with no CLI.

## Status

**0.5.0-alpha.6: the sixth alpha of the next format.** The next format is a clean break from the 0.4 alpha: a
signed, append-only statement log per key, a store directory (`rc-store/1`), and a Go command-line tool. It is
alpha: **the format may still change between alpha releases**, and so may `--json` output, key files and execution
policy files (all marked provisional). The fixed-root identity profile is a candidate under review: its **reader is
active** (`rc/2` statements are verified and identity actors evaluated from the statements you hold), and so is
its **writer**: `commons identity new|grant|cut` administer an identity and `publish --as <identity> --grant <id>`
acts for one, signed from a key file or through an external-signing package (`--prepare`, then `package show` and
`key sign` on a machine that holds the key and no store, then `--complete`); no hardware or wallet connector yet.
`show <key>` prints a delegate key's own key events beside every grant naming it and that grant's state; every
identity answer is relative to the statements held (`freshness: not_established`: no claim that no cut exists).
`anchor stamp` and `anchor upgrade` write Bitcoin time evidence for your own log through the calendars you name
(no default list); `push` sends a hub checkout's commits with `git push` once the hub's verdicts and the anchor and
withheld-bytes checks are clean. There is no importer from the old format.

The previous alpha (Python CLI, hubs, ledgers) lives on the `main` branch and the `v0.4.0-alpha.1` tag. It gets
security fixes only. This README and everything under `docs/` marked otherwise describe the new format.

What the tool does not do yet is listed, with a test behind each line, in [`docs/KNOWN-LIMITS.md`](docs/KNOWN-LIMITS.md).
Read it before you rely on an answer.

## Install

Requires Go 1.26 or newer. Developed and tested on Linux; **Windows is not supported** (the sandbox and store use Unix file semantics, and the tool does not build there).

```bash
go install github.com/research-common/research-commons/cmd/commons@v0.5.0-alpha.6
commons --version
```

From Python (a thin wrapper that bundles the binary in platform wheels and gives you the `commons` command; see
[`python/README.md`](python/README.md)): `pip install research-commons`. Not on PyPI until the maintainers publish a release's wheels.

From source:

```bash
git clone https://github.com/research-common/research-commons.git
cd research-commons && git switch next
go build -o commons ./cmd/commons
```

Pre-built binaries will be attached to the GitHub release once release builds are published; until then, build from
source. The module has three direct runtime dependencies (`golang.org/x/sys` comes in indirectly through `golang.org/x/crypto`).

## The quick loop

Two stores, one signed publication carried from one to the other, checked on arrival. Every command below was run
against this tool.

```bash
commons init a                                   # a store: a directory holding rc-store
commons key new --out k.key                      # a signing key file (mode 0600, never overwritten)
echo "hello commons" > data.txt
cd a
COMMONS_KEY=../k.key commons publish --kind authored --content ../data.txt --licence CC0-1.0
commons list                                     # the blob, "sole author", licence CC0-1.0
commons verify sha256:<digest from list>         # exit 0: checked and passed
cd .. && commons init b && cd b
commons pull ../a                                # admit a's statements and bytes under this reader's policy
commons verify sha256:<digest>                   # exit 0 here too: the same answer from the statements b holds
commons fsck                                     # clean: yes
```

Signing commands take the key from `--key <file>` or `COMMONS_KEY`; there is no default location. Back the key file up
once, somewhere only you can read. [`GETTING-STARTED.md`](GETTING-STARTED.md) walks through this loop step by step.

Every answer is a function of the statements the store holds, and says so (`status scope: within statements you hold`).
Nothing is run, fetched or trusted implicitly: a re-run needs `--rerun` and an execution policy, and a pull judges every
object before it is installed.

## Commands

`commons help <command>` prints the options of one command. Exit codes: `commons help exits`; the state tokens a
result can carry: `commons help outputs`. Both are in [`docs/CLI-OUTPUTS.md`](docs/CLI-OUTPUTS.md). Every command
takes `--json`, which prints one JSON object (an RFC 9457 problem-details object on error).

| command | what it does |
|---|---|
| `init` | create a store in a directory |
| `key new` / `key show` | generate a signing key file / print its signer (never the key) |
| `package show` | check an external-signing package written by `--prepare` (every member derived from its envelope recomputed, as `--complete` does) and print what a signature would cover: summary, signer, alg, proposed id, `pae_sha256` (`--pae-out <file>` writes the PAE bytes for a non-CLI signer; an advisory when `ts` is >300 s ahead of the local clock); reads no store |
| `key sign` | sign an external-signing package's PAE bytes with a key file, after `package show`'s checks and only when the key is the package's signer; writes the signature `--complete --signature` reads (same future-`ts` advisory; still signs); reads no store |
| `publish` | sign and commit a statement: authored (with bytes), holds, describes, retracts, or a draft |
| `publish task` | create a task, or publish a new edition of one |
| `publish grant` | as a task edition's coordinator, grant a key for that edition (refused when the grant would have no effect) |
| `revoke` | revoke your signing key, keeping the history you choose |
| `rotate` | retire your signing key and name its successor |
| `anchor stamp` | timestamp a line of your log: submit its id to the OpenTimestamps calendars you name (`--calendar`, no default list) and commit the pending proof with an `anchors` statement; every calendar failing appends nothing and prints whether the line's standing requires an anchor |
| `anchor upgrade` | complete pending anchors: ask your calendars for the Bitcoin path of each pending proof, merge it in, and commit the upgraded proof with a new `anchors` statement for the same head; still pending appends nothing |
| `anchor headers sync` / `anchor status` | validate Bitcoin block headers from a file you obtain and persist them as this reader's chain view / report that view |
| `pull` | admit a package (a store directory or a tar archive) under this reader's policy |
| `fetch` | obtain blobs from the locations a `holds` statement names, verified by full hash |
| `list` / `show` | the blobs, resources and statements the store holds (`list`: one line each), with authorship, grade and disclosures; an observation's referent status (finality, read through the source profiles the store's policy pins) and corroboration status; for a resource (its genesis id), an edition id or an approval id, the resource view: controllers and rule, current edition and the chain behind it, every edition with its approvals, any `FORK`, members, and the check of a completeness claim; a statement on a fork of its signer's log, the fork (`FORK` with its tips, or `merged`); for a task, its terms, readiness, every submission (`counted`, `undecided`, `not counted`, with every reason), grants, bound refutations and decisions |
| `verify` | check a blob or statement from the statements held; `--rerun` re-runs a derivation under your policy; for a task, exit 0 when readiness is `ready`, `not ready` or settled by review and no decisions conflict, else 3 |
| `run` | run a held workflow under your execution policy (`--exec-policy`) and print the result token, the environment record and the outputs; `--publish` signs what it emits (`authored` on a first derivation, `reproduced` over your own `authored` of the same workflow and inputs, `observed` for a workflow that requires the network) with per-output disclosures (`--licence out=CC-BY-4.0`) and the output blobs, as one unit |
| `explain` | the statements, policy, evaluator and time context behind every token shown; `--since <file>` names what changed since an earlier `explain --json`, and why |
| `fsck` | re-hash blobs, re-read statements, resolve references, check the journal; list every fork of a held key log (`FORK` or `merged`, informational) |
| `status` | recovery state, unfinished operations, the durability declaration (`--limits` for scan limits); a row per open `FORK` of a held key log |
| `history` | the operations this store finished, newest first (`--op`, `--limit`): a local, best-effort log under `journal/` that nothing else reads and no pull carries |
| `gc` | list (default) or delete unreferenced blobs outside the grace window |
| `hub check` | check a change to a hub as the hub's CI does; writes nothing |
| `push` | in a git checkout of a hub: judge the commits as the hub's CI would, refuse a statement whose standing requires an anchor until an `anchors` line covers it, or a withheld blob before its reveal; when all is clean, `git push` the judged commit to `--branch` (default: the base's branch), never forced; `--dry-run` sends nothing |

## Hubs

A hub is a git repository holding a store, so collaborators `git clone` it and `commons pull` it. The
[hub template](https://github.com/research-common/research-commons-hub-template) carries a `hub-check` CI workflow
that runs `commons hub check` on every pull request. `commons hub check` needs the hub to be a git repository with at
least one commit.

To contribute, publish inside a clone of the hub, `anchor stamp` what needs an anchor, commit, and run
`commons push --branch <your-branch>` (or `--remote <your fork> --base origin/main --branch <your-branch>`), then
open a pull request from that branch. `push` answers what the hub's CI will, plus the anchor-before-transport and
withheld-bytes checks that only the sender can make, and sends the commit it judged only when all of that is clean
(`--dry-run` to see the answer without sending). It never forces: if the hub's branch moved on, fetch, rebase your
data commits onto it, and push again. Pushing straight to the hub's default branch works where the hub allows it.

## Documentation

| | |
|---|---|
| [`docs/WHY.md`](docs/WHY.md) | why this exists; the epistemics |
| [`GETTING-STARTED.md`](GETTING-STARTED.md) | the two-store loop, step by step |
| [`docs/DESIGN-notes-claims-model.md`](docs/DESIGN-notes-claims-model.md) | the claims model: authorship, editions, corroboration, tasks |
| [`docs/DESIGN-notes-wire-format.md`](docs/DESIGN-notes-wire-format.md) | statements on the wire, canonical form, signatures |
| [`docs/DESIGN-notes-storage.md`](docs/DESIGN-notes-storage.md) | the store layout, journal, recovery, locking |
| [`docs/DESIGN-notes-execution.md`](docs/DESIGN-notes-execution.md) | sandboxed re-execution |
| [`docs/DESIGN-notes-bitcoin-time.md`](docs/DESIGN-notes-bitcoin-time.md) | time evidence from Bitcoin |
| [`docs/DESIGN-notes-fixed-root-identity.md`](docs/DESIGN-notes-fixed-root-identity.md) | the candidate identity profile (reader and writer active) |
| [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) | the test plan: every required outcome and what covers it |
| [`docs/CLI-OUTPUTS.md`](docs/CLI-OUTPUTS.md) | exit codes, state tokens, error shape |
| [`docs/KNOWN-LIMITS.md`](docs/KNOWN-LIMITS.md) | open gaps, each with a test |
| [`docs/READER-POLICY.md`](docs/READER-POLICY.md) | the reader policy file (`pull --policy`, `verify --policy`) |
| [`docs/EXEC-POLICY.md`](docs/EXEC-POLICY.md) | the execution policy file (`verify --rerun`, `run`) |
| [`docs/KEY-FILES.md`](docs/KEY-FILES.md) | the key file format and how to keep keys |
| [`docs/READER-EXTENSIONS.md`](docs/READER-EXTENSIONS.md) | critical extensions (only the candidate identity profile's `x_identity_v1` is registered) |
| [`internal/README.md`](internal/README.md) | package map, build and test commands |

Documents describing the 0.4 alpha say so in their first line and are kept for reference.

## Contributing, security, licence

- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md) (sign-off, tests, review). Releases: [`docs/RELEASING.md`](docs/RELEASING.md).
- Security: report privately, see [`SECURITY.md`](SECURITY.md). Please don't open a public issue for a vulnerability.
- Change history: [`CHANGELOG.md`](CHANGELOG.md).
- Licence: code is Apache-2.0 ([`LICENSE`](LICENSE)); documentation under `docs/` is CC-BY-4.0
  ([`docs/LICENSE-docs`](docs/LICENSE-docs)).
