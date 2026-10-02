# Getting started: your first hub and collection

Ten minutes, from zero to a published collection that others can clone. Every command
below was run against fresh clones of the tool and a new hub. The roles, the review flow,
and the "who forks what" FAQ are in [`docs/COLLABORATING.md`](docs/COLLABORATING.md).

**Mental model:** this repo is the *tool* (code only). Your collection lives in a *hub*,
a separate data-only git repo that you create. Collaborators clone your hub, not a fork of
the tool.

## 1. Install the tool

```bash
git clone https://github.com/research-common/research-commons.git ~/research-commons
cd ~/research-commons && npm ci             # viem, for signing
export PATH="$HOME/research-commons/bin:$PATH"
tests/run-all.sh cold-path                  # smoke test
```

## 2. Mint your signing identity

```bash
mkdir -p ~/.commons && chmod 700 ~/.commons
python3 -c "import secrets;print('0x'+secrets.token_hex(32))" > ~/.commons/signing.key
chmod 600 ~/.commons/signing.key
export COMMONS_SIGNING_KEY=~/.commons/signing.key   # a PATH, never the key itself
export COMMONS_AGENT=<your-handle>                  # attribution name in the ledger
commons peer whoami                                 # your address: share this, never the key
```

## 3. Create a hub

Use the template repo's "Use this template" button on GitHub and clone the result, or
create one locally:

```bash
commons hub init ~/hubs/my-topic --name "My topic"
cd ~/hubs/my-topic
commons hub where                                   # → ~/hubs/my-topic
commons peer add "$(commons peer whoami | head -1)" --agent-id "$COMMONS_AGENT" --trust full --note me
```

`peers.json` (your trust list) is git-ignored by design. No one else can decide whom your
checkout trusts.

## 4. Publish the evidence first

```bash
commons publish dataset data.csv "Dataset: what it is" \
  -d "Where it came from, when, how it was captured" -t my-topic \
  --license CC0-1.0 --obtainability open \
  --criteria "Captured from <source> on <date> via <method>"   # T3 attestation text
# → ds-xxxxxxxx
commons publish report analysis.md "Report: …" --link cites:ds-xxxxxxxx
# → rp-xxxxxxxx
```

A deterministic `workflow` turns a claim into something readers can re-derive
byte-for-byte (T0). See **Verification tiers** and **Provenance rules** in the README.

## 5. Publish the collection (the front door)

```json
{
  "scope": "One paragraph: what this topic is and what belongs here.",
  "maintainers": [{"agent": "<your-handle>", "addr": "0x<your address>"}],
  "members": [
    {"id": "ds-xxxxxxxx", "role": "primary-dataset"},
    {"id": "rp-xxxxxxxx", "role": "report"}
  ],
  "task_criteria": "What work you want from others, and what you don't.",
  "open_questions": ["What would most improve this collection?"]
}
```

```bash
commons publish collection collection.json "Collection: <topic>" --license CC-BY-4.0
commons collection show cl-xxxxxxxx
```

Ids are content hashes, so every edit gives a new id. To revise, add
`"supersedes": ["cl-old"]` to the spec and publish it (or use `commons collection add-member`,
which does both).

## 6. Check and publish the hub

```bash
commons hub check              # blobs, signatures, per-signer logs, no local-only files
commons fsck --availability    # every dataset declares license + obtainability
commons render-site --out site/browse   # optional: what readers will see (git-ignored)
git add -A && git commit -s -m "hub: first collection"
git remote add origin git@github.com:<you>/my-topic-hub.git
commons push origin            # gated push
```

On GitHub, protect `main` and require the `hub-check` status (it needs no secrets). Then
add your handle and address to the hub README's maintainer table, and share the **hub** URL
with your collaborators. They follow COLLABORATING.md §3–4.

## Ground rules

- **One key per person, never shared.** Two people on one key count as a single signer.
- **Hubs hold data, never code.** `pull` and hub CI both refuse anything else.
- **No secrets in content.** Publishing runs a secret lint. Don't override it lightly.
- **Licenses:** tool code is Apache-2.0 and docs are CC-BY-4.0. Each dataset declares its
  own SPDX id (CC0-1.0 is the simplest choice). Sign off commits with `git commit -s` (DCO).
