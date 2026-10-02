# Releasing

This is a private-alpha tool, currently `<1.0.0`. SemVer 2.0.0 §4 licenses `0.y.z` ("initial
development") to change anything at any release with no MAJOR bump; this project layers a small
set of local conventions on top of that permissive baseline so PATCH vs. MINOR is predictable.

## Two independent version numbers

`commons --version` prints **both**, distinctly, because they answer different questions and
move at different rates:

```
commons 0.2.0-alpha.1 (schema rc.v1)
```

- **Tool version** (`VERSION` file at the repo root, one line, e.g. `0.2.0-alpha.1`) — governs
  the CLI surface: subcommands, flags, exit-code contract, and `hub check`/`hub-check.yml` gate
  semantics. This is what a hub maintainer pins by SHA/tag.
- **`SCHEMA`** (`bin/commons`, currently `"rc.v1"`) — governs the on-disk manifest/ledger/peer-
  record shape. Checked by major token only (`check_schema()`): unknown minors within a known
  major are accepted (readers ignore unknown fields), `v0.1` manifests with no `schema` field are
  grandfathered, and an unknown major is a hard refusal.

**Keep these independent.** Rebasing `SCHEMA` onto the tool's SemVer would force every tool PATCH
release (bugfixes, CLI ergonomics) to imply a data-format bump it doesn't need. The two numbers
can and should move at different rates: tool `0.2.0` → `0.2.1` → `0.3.0` while `SCHEMA` stays
`rc.v1` throughout, until an actual manifest-shape change forces `rc.v2`.

## Bump rules while `<1.0.0`

- **PATCH** (`0.2.0` → `0.2.1`): bug fixes with no CLI/output/exit-code surface change a script
  could reasonably depend on.
- **MINOR** (`0.2.x` → `0.3.0`): new subcommands/flags, new artifact types, any change — even
  additive — to `hub check`'s pass/fail semantics (hub CI treats the exit code as a gate), or a
  `SCHEMA` major bump (`rc.v1` → `rc.v2`) landing alongside code that requires it.
- **MAJOR stays `0`** for all of the above. SemVer's 0.y.z rule permits breaking changes without
  a major bump pre-1.0 — that's what pre-1.0 is *for*. Don't manufacture `1.0.0` early just
  because a change is breaking.
- **Prerelease label** (`-alpha.N`): increments (`alpha.1` → `alpha.2` → …) while the current
  MINOR is still being shaken out after its first tag. Drop the label (plain `0.2.0`) once a
  prerelease has survived a hub-check cycle or two without a revert.

Use the SemVer-conventional **dotted** prerelease form (`0.2.0-alpha.1`, not `0.2.0-alpha-1`), so
later releases sort numerically (`alpha.2` < `alpha.10`) under SemVer precedence rules instead of
comparing as strings.

### Criteria for `1.0.0`

A proposal, not a schedule — final go/no-go is the project owner's call:

1. The `SCHEMA_MAJOR` compatibility policy has been exercised at least once (a real `rc.v1` →
   `rc.v2` migration has happened and the grandfathering path was tested against real data).
2. The open trust-boundary issues affecting the signed ledger and the ingest gate are closed —
   shipping `1.0.0` with any of those open would be a false stability signal on exactly the
   properties the tool exists to guarantee.
3. The hub-template CI is SHA-pinned with a documented upgrade path (below) and a lockfile
   exists, so "the API is stable" also means "the thing that consumes the API stopped floating."
4. Repo visibility / public launch has happened or is imminent.

## Release steps

1. Update `CHANGELOG.md`: turn the `UNRELEASED` section for the target version into a dated
   entry, confirm the "Pending before tag" PRs have actually merged (drop the section if empty),
   and refresh "Known issues" against `gh issue list -R research-common/research-commons --state open`.
2. Update `VERSION` (and `package.json`'s `"version"` field — keep them equal; a test asserts
   this) to the new version string.
3. Commit, push, open a PR, get it merged to `main` (this repo is PR-first per `AGENTS.md`/
   `CONTRIBUTING.md` — never commit directly to `main`).
4. Tag the release PR's **squash commit** on `main` (not the release-prep branch tip, which
   never lands on `main`):
   ```bash
   git switch main && git pull --ff-only
   git tag -a v0.2.0-alpha.1 <squash-sha> -m "v0.2.0-alpha.1: first tagged release"
   git push origin v0.2.0-alpha.1
   ```
   Tags are `v`-prefixed (`v0.2.0-alpha.1`), matching the CHANGELOG's un-prefixed section
   headers (`## [0.2.0-alpha.1]`).
5. Cut the GitHub release from the tag:
   ```bash
   gh release create v0.2.0-alpha.1 --repo research-common/research-commons \
     --title "v0.2.0-alpha.1" --prerelease \
     --notes-file <(awk '/^## \[0.2.0-alpha.1\]/{on=1; print; next} on && /^(## \[|\[[^]]+\]: )/{exit} on' CHANGELOG.md)
   ```
   `--prerelease` matters: it's GitHub's own signal for an `-alpha`/`-beta`/`-rc` suffixed tag,
   and lines up with SemVer's pre-release precedence (`0.2.0-alpha.1` sorts before `0.2.0`).
6. Bump the hub template's pin (separate repo, `research-commons-hub-template`, also PR-first):
   pin `hub-check.yml`'s tool checkout by the **full 40-char commit SHA** (immutable), with the
   tag as a trailing comment for human skimmability (`ref: <sha>  # v0.2.0-alpha.1`), switch
   `npm install` to `npm ci` so the lockfile is actually enforced, and bump the copied
   `package-lock.json` if the template vendors one.

## Ordering relative to open PRs

Prefer merging PRs that fix trust-boundary bugs (signed ledger, ingest gate) *before* cutting a
tag, so the tag's CHANGELOG entry lists the fix under "Fixed" rather than "Known issues" — a
better first impression for the audience (hub maintainers deciding whether to pin the tag) the
tag exists for. Don't let that block the tag indefinitely, though: if a fix has no PR open yet
and no ETA, ship the tag with it under "Known issues" and follow up with the next PATCH/MINOR.
