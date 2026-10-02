# Collaborating on a topic

**TL;DR — don't fork the tool to collaborate. Create a hub, and have collaborators clone
the hub.**

Research Commons keeps **code** and **data** in separate repositories:

| Repository | Holds | Who has it | How it changes |
|---|---|---|---|
| **Tool** (`research-commons`) | `bin/commons`, `lib/`, tests, docs. **No artifacts.** | Everyone, once | Ordinary code review: PRs to the tool repo. You update it by running `git pull` in your tool checkout, deliberately. |
| **Hub** (one per topic or community) | `registry/` (manifests, signed ledgers, anchors) and `store/` (content-addressed blobs). **No code.** | Everyone working on the topic | Through the ingest gate: `commons push` / `commons pull` and CI-checked PRs. Data only. |

Why the split: a hub pull brings in content signed by *other people*. If code lived in the
same repo, every data pull would also be a code update from a peer, and the next `commons`
command you ran would be their code. That actually happened in testing before the split.
Now `commons pull` refuses any incoming change outside `registry/` and `store/` unless you
explicitly pass `--allow-code`, and hub CI rejects such PRs. The only code you run is code
you pulled into your tool checkout on purpose.

## Roles

- **Reader:** clones the tool and a hub. Reads, verifies, re-derives. Needs no key.
- **Contributor:** has a key and publishes into a hub clone, then contributes by PR or by
  giving a maintainer a remote to pull from.
- **Hub lead (maintainer):** owns a hub. Decides whom to trust (their own local
  `peers.json`), ingests contributions, and **endorses** by republishing the collection.

There's no central authority. Anyone can create a hub, a collection id is a content hash
(so it can't be squatted), and each host decides for itself whom it trusts.

## 0. Everyone: install the tool once

```bash
git clone https://github.com/research-common/research-commons.git ~/research-commons
cd ~/research-commons && npm ci             # viem, for signing (reading needs only python3)
export PATH="$HOME/research-commons/bin:$PATH"
tests/run-all.sh cold-path                  # smoke test
```

`commons` finds its data root in this order:
1. `$COMMONS_ROOT`, if set.
2. The nearest directory above your current directory that contains a `.commons-hub`
   marker (i.e. "I'm inside a hub clone").
3. Otherwise, the tool checkout. With no registry there, `commons` stops and tells you so;
   it doesn't quietly create data inside the tool.

`commons hub where` prints which data root is in use and why.

## 1. Mint an identity (contributors and leads)

```bash
mkdir -p ~/.commons && chmod 700 ~/.commons
python3 -c "import secrets;print('0x'+secrets.token_hex(32))" > ~/.commons/signing.key
chmod 600 ~/.commons/signing.key
export COMMONS_SIGNING_KEY=~/.commons/signing.key   # a path, never the key itself
export COMMONS_AGENT=<your-handle>
commons peer whoami                                 # your address; this is what you share
```

One key per person, never shared: two people on one key count as a single signer, which
defeats replication quorums. Keep the key outside every repo.

## 2. Hub lead: create the hub

```bash
commons hub init ~/hubs/my-topic --name "My topic" --tool-repo research-common/research-commons
cd ~/hubs/my-topic
commons peer add "$(commons peer whoami | head -1)" --agent-id "$COMMONS_AGENT" --trust full --note me
```

`hub init` creates a data-only repo with a `.commons-hub` marker, `.gitignore` (local-only
policy files never replicate), a README explaining the hub, and
`.github/workflows/hub-check.yml`, the CI gate described in step 5.

Publish the evidence, then the collection (the topic's front door):

```bash
commons publish dataset data.csv "Dataset: …" --license CC0-1.0 --obtainability open \
  --criteria "captured from <source> on <date> via <method>"
# … workflows / reports / wiki / method skills as needed …
commons publish collection collection.json "Collection: <topic>" --license CC-BY-4.0
git add -A && git commit -m "hub: initial collection"
```

A collection's licence covers only its own curation text (`scope`/`task_criteria`),
never the artifacts it lists — see `docs/LICENSING-artifacts.md` for the full
recommendation table across artifact types.

**If your topic has field names nobody should publish, declare them in the collection spec**
rather than trusting each contributor to remember:

```json
{"scope": "…", "maintainers": [...], "members": [...],
 "ingest": {"forbidden_keys": ["account_id", "provider_id", "provider_key", "job_id"]}}
```

Anything published with `--link part-of:<your-cl-id>` is then checked against that list on
the *contributor's* machine, before the bytes are pinned — which is the only point at which
the leak is still preventable. `hub check` re-applies it in CI as a backstop, reading the
policy from `--base` so a PR cannot relax the policy and add a violating artifact in one
commit. The list is a floor, not a guarantee: it matches whole field names, so `acct` gets
through where `account_id` does not. Details in the README under **Topic-scoped forbidden
field names**.

`collection.json` shape: see **Collections** in the tool README. It needs `scope`,
`maintainers` (with your address), `members`, and ideally `task_criteria` and
`open_questions`.

Publish the hub. For example, create an empty GitHub repo and then:

```bash
git remote add origin git@github.com:<you>/my-topic-hub.git
commons push origin          # gated push: fsck, licensing, obtainability, local-only state
```

On GitHub, turn on branch protection for `main` and require the `hub-check` status.
The workflow runs on `pull_request_target`, so it always comes from `main`: a PR can't
rewrite its own check. It reads PR content as data only and never executes anything from it.
The tool repo is public, so the workflow needs no secrets or deploy keys to check it out.

**Pin the tool.** `hub init --tool-ref` sets the ref CI checks out (default `main`). For a
hub other people rely on, pin it to a release tag's full commit SHA instead, so a change
upstream can't alter what your gate accepts. Bump it deliberately, in its own PR.

Add yourself (handle + address) to the hub README's maintainer table, so contributors know
whose signatures endorse what.

## 3. Contributor: join a hub

```bash
git clone https://github.com/<lead>/my-topic-hub.git && cd my-topic-hub
commons list --type collection
commons collection show <cl-id>          # what's endorsed, what's claimed, what's wanted
commons queue --collection <cl-id>       # open tasks
```

Send the lead your address (`commons peer whoami`), for example by opening an issue on the
hub. The lead registers you in **their** `peers.json`. Nothing in the hub repo grants
trust; trust is always local.

Optionally trust the lead's key in your own checkout, so `log --verify` shows their
entries as known:
`commons peer add 0x<lead> --agent-id <lead> --trust full --note "hub lead"`.

## 4. Contributor: contribute

Work on a branch, publish from inside your clone, and link your work to the collection:

```bash
git checkout -b my-contribution
commons publish report analysis.md "Report: …" --link cites:ds-… --link part-of:cl-…
git add registry store && git commit -s -m "contrib: …"
commons hub check --base origin/main      # the same gate CI will run
```

Then either:
- **PR (the normal route):** push the branch to your fork of the *hub* (not the tool) and
  open a pull request, or
- **Pull model:** push to any git remote you control and give the lead the URL and branch.

`part-of:cl-…` shows your artifact under the collection as **CLAIMED** straight away. It
becomes **ENDORSED** when a maintainer republishes the collection with it as a member.
Claiming membership is free; endorsement is what counts.

**The `part-of` link also applies the collection's ingest policy to your bytes**, if it has
one. Hubs handling operational telemetry can declare field names they refuse — identifiers
like `account_id` that deanonymise a contributor rather than credentials the general lint
would catch. A hit refuses the publish and there is no override: publish the anonymised
export instead. If you see

```
error: cl-… declares an ingest policy (ingest_policy) but its spec is not held here
```

then run `commons fetch cl-…` to get the policy and retry. `--allow-unchecked-ingest`
publishes without applying it, and records that choice in the ledger where `verify` and
`status` will show it. Prefer the fetch: this gate refuses rather than warns precisely
because a leak cannot be taken back once the bytes replicate.

If the collection you name has been superseded, you get a warning naming the current
version: link that one instead, or your claim is listed only under the retired id. The policy
applied is still the union of every maintainer-signed version from the one you named onward,
so naming an old id never escapes a policy a maintainer added later. See the README's
**Topic-scoped forbidden field names**.

## 5. Hub lead: review and ingest

CI (`hub-check`) has already checked that the PR:
- touches only `registry/` and `store/` (plus inert hub metadata such as README.md),
- deletes nothing and only appends to ledgers,
- writes each signer's entries only into that signer's own log, all with valid signatures,
- has blobs that match their hashes, and tracks no local-only files.

CI can't decide trust; that belongs to your local `peers.json`. So **ingest through the
gate rather than clicking "Merge"**:

```bash
cd ~/hubs/my-topic
git remote add alice https://github.com/alice/my-topic-hub.git   # once per contributor
commons pull alice --branch my-contribution --dry-run   # what would be accepted, and why not
commons pull alice --branch my-contribution             # trust-checked merge
commons collection show <cl-id>                         # their work appears as CLAIMED
commons collection add-member <cl-id> <artifact-id> --role instance   # endorse
git add -A && git commit -m "hub: endorse …" && commons push origin
```

`add-member` republishes the collection with the member added and `"supersedes": ["cl-<old>"]`
in the spec, through the same lint as `publish collection`. The hand-edit it replaces is
editing the spec (members, plus that `supersedes` line) and running `commons publish collection
collection.json "…"`, which still works if you prefer it. The lineage lives in the spec, not
in a `--link`: it is part of the signed content, so nobody can strip it from your collection
later (#39). A `--link supersedes:…` the spec does not declare is refused. What the command adds is the checks
a hand-edit cannot make for you:

- it **refuses a retired base**. Adding to a superseded version republishes a spec that
  predates every endorsement since, and the result is well-formed and correctly signed,
  so the dropped members simply stop being endorsed with nothing reporting it. Only a
  maintainer-signed supersede retires a collection, so a fork nobody follows cannot block
  your curation. `--allow-retired-base` overrides it — deliberately its own flag and not
  `--force`, so waving through one refusal never waves through the other;
- it changes **nothing but `members` and `supersedes`** — your key order and any keys the tool doesn't
  know about are left alone;
- it **warns on a role** that appears nowhere else in the spec, since roles are free text
  and a typo silently files the member under a bucket you did not mean;
- it refuses a non-maintainer's update up front, because subscribers only follow a
  maintainer-signed supersede (so an outsider's "update" is a fork). `--force` publishes
  it anyway.

Each refusal has its own opt-in rather than one blanket `--force`, following
`--allow-secrets` and `--allow-undisclosed`: the two cost different amounts, and forking
as a non-maintainer is visible and recoverable in a way that silently dropping
endorsements is not.

Passing `--role` for an existing member changes that member's role. There is no
`remove-member`: de-endorsing should stay a deliberate republish.

GitHub closes the PR as merged once its commits land on `main`.

Trust levels, per contributor: `datasets-only` (the default for new people: data and
reports, but no executable workflows or skills) or `full` (may ship executable methods).
Executable artifacts from anyone below `full` are refused at ingest.

## FAQ

**Should I fork the tool repo?** Only to change the *tool*, and then send a PR upstream.
Don't put collections in a tool fork. A tool fork with data in it is a hub that also
carries code, which is exactly the layout the split removes.

**My collaborators: fork the original tool, or my fork?** Neither, for collaboration. They
clone the one upstream tool and clone (or fork) **your hub**. If you've changed the tool,
get it merged upstream, or tell them explicitly to use your tool fork. Either way it's a
decision about code, not about the topic.

**Can one hub hold several collections?** Yes. A hub is a transport and trust boundary,
and a collection is a topic. Split into separate hubs when the people or the trust differ,
not when the topic does.

**Can an artifact be in two hubs?** Yes. Ids are content hashes, so the same bytes have the
same id everywhere. Pull between hubs like any other remote; both collections can list it.

**Why not just merge the PR on GitHub?** Merging skips the trust check (CI doesn't know
your `peers.json`). For a hub whose lead personally knows every contributor, it's
tolerable. For anything open to strangers, ingest with `commons pull`.

**What if a PR has to touch non-data files?** Hub metadata edits (README, LICENSE) are
allowed and flagged for review. Maintainers changing the hub's own CI push that change
directly to `main` and accept one red `hub-check` run on that commit. Anything else (code, CI workflows) is refused by both
CI and `pull`. After you've reviewed it, `commons pull … --allow-code` overrides the
refusal, and it says exactly which files it merged.

**Can I publish a task and claim it myself (e.g. to pre-register a run)?** Yes. Nothing
requires the claimant to differ from the beneficiary, and a signed, anchored, immutable task
spec is a better timestamp for a design than a git commit. But tasks must be T0/T1/T2
(`publish task` refuses T3: an observation is not commissionable work), so this fits
judged or reproducible work and fits a measurement campaign badly. A lighter
pre-registration convention for self-directed runs is under discussion
(research-common/research-commons#3).

**Can I ask other people to go and measure something (collect T3 captures)?** Not as a T3
task yet (a dedicated observation-task kind is proposed, not built). Workaround that works today: publish a **T2** task whose *prose*
`criteria` is a protocol-conformance rubric (no `criteria_list`, which would make each
submitter grade their own capture), set `max_claims` to the number of contributors you want,
and have each contributor submit their capture as an attested T3 dataset (`submit` doesn't
check that the result tier matches the task tier). Review each one and `accept` it. Caveats: the
first `accept` settles the task, so further accepts need `accept --force` (each is still a
signed ledger event plus an `accepted` link). When every submission is a T3 capture,
`status` shows an `observations:` count (captures, distinct signers) instead of a congruence
verdict, because different observations are expected to differ.
Accepting a capture means "it followed the protocol", never "the observation is true".

**How old is a collection member?** `list`, `search`, and `collection show` label the
available clock: `[obs 5mo]` uses the observation time declared in an attestation;
`[pub 3d]` uses the self-declared publish time when no observation timestamp is present.
`list --json` carries absolute `observed`/`created` values, not a moving age. The label is
not a signature-verification result: use `commons verify <id>` for that check. Even a valid
signature does not prove the observation's time. Ages are advisory; they never change tiers
or exit codes. Shelf-life windows and a `[stale]` policy are separate, not implemented here
(research-common/research-commons#4).

**Legacy single-repo layout?** A checkout that holds code and a registry together (the
layout before the tool/hub split) still works: with no marker and no `COMMONS_ROOT`, the
tool checkout is the data root. The
same `pull` guard applies there, so a peer can't update your code through a data pull.
