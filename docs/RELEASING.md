# Releasing

This tool is `<1.0.0`. SemVer 2.0.0 §4 licenses `0.y.z` ("initial development") to change
anything at any release with no MAJOR bump; this project layers a few conventions on top so that
PATCH vs. MINOR is predictable.

## Branches and tags

- **`next`** holds the Go tool. Every `0.5.x` tag is cut from `next`, and stays there until the
  format cutover (when `next` replaces `main`).
- **`main`** holds the Python alpha, in maintenance mode. A security fix to it ships as `0.4.x`,
  tagged from `main`. The last alpha release is `v0.4.0-alpha.1`.

## Version numbers

There is **one** tool version, and one separate format identifier.

- **Tool version**: the `VERSION` file at the repository root, one line, e.g. `0.5.0-alpha.1`.
  The binary embeds it, and `commons --version` prints it. This is what a hub maintainer pins.
- **Wire major** (`rc/1`): the format tag that appears in the bytes the tool writes and reads.
  It is the constant `Major` in `internal/wire/wire.go`. It is not printed by `--version` or by
  anything else, and it does not move with the tool version: tool `0.5.0` → `0.5.1` → `0.6.0`
  all keep `rc/1` until a change to the format itself forces `rc/2`. A candidate `rc/2` identity
  profile exists in the tree but is not active.

Keep the two independent. Tying the wire major to the tool's SemVer would make every bug-fix
release imply a format change it doesn't need.

## Bump rules while `<1.0.0`

The next format is released as **`0.5.0-alpha.1`**, a MINOR bump from `0.4.x`. `1.0.0` is kept to
mean the format is frozen; the clean break is signalled by the format tag, the changelog and the
README, not by the major number.

- **PATCH** (`0.5.0` → `0.5.1`): bug fixes with no command, flag, output or exit-code change a
  script could reasonably depend on.
- **MINOR** (`0.5.x` → `0.6.0`): new commands or flags, changed output shapes, any change to
  `hub check`'s pass/fail semantics (hub CI treats the exit code as a gate), or a wire major bump
  landing alongside code that requires it.
- **MAJOR stays `0`.** Don't manufacture `1.0.0` early because a change is breaking.
- **Prerelease label** (`-alpha.N`): increments (`alpha.1` → `alpha.2` → …) while the current
  MINOR is still being shaken out. Drop the label once a prerelease has survived a hub-check
  cycle or two without a revert.

Use the dotted prerelease form (`0.5.0-alpha.1`, not `0.5.0-alpha-1`) so `alpha.2` sorts before
`alpha.10` under SemVer precedence.

### Criteria for `1.0.0` (current plan)

A plan, not a schedule; the maintainers make the final call and may revise this list.
`1.0.0` means **the format is frozen**:

1. The wire major is stable: no open design question can still change the bytes of an existing
   `rc/1` object, and the design notes' open questions are closed or explicitly deferred.
2. The core conformance cases are all covered (none pending, none untested), with the remaining
   partial cases each naming what is left.
3. The two-hub drill passes: two independent hubs exchange, verify and resolve the same
   artifacts, scripted and repeatable.
4. Windows is decided: supported and tested, or documented as unsupported.

## Release steps

1. **Changelog.** In `CHANGELOG.md`, turn `[Unreleased]` into a dated entry for the target
   version, and refresh "Known issues" against
   `gh issue list -R research-common/research-commons --state open`.
2. **Version.** Set `VERSION` to the new version string (and the Python package's two version declarations, step 8). The binary embeds it (root
   `version.go`), so an unstamped `go build ./cmd/commons` reports it; release builds may still
   override it with `-ldflags "-X main.version=…"`.
3. **PR.** Open a PR into `next` and get it merged. It is squash-merged; the PR title and
   description become the commit message.
4. **Check the unstamped build.** Module-proxy tags are permanent: once a tag has been fetched
   by the Go module proxy it cannot be retracted. Before tagging, from the squash commit, build
   without stamping and confirm the version:
   ```bash
   git switch next && git pull --ff-only
   go build -o /tmp/commons ./cmd/commons && /tmp/commons --version
   ```
   The output must show the `VERSION` file's value, not `devel` or an empty string.
5. **Tag.** Tag the squash commit on `next` with a signed annotated tag and push it:
   ```bash
   git tag -s -a v0.5.0-alpha.1 <squash-sha> -m "v0.5.0-alpha.1"
   git push origin v0.5.0-alpha.1
   ```
   Tags are `v`-prefixed; CHANGELOG headers are not (`## [0.5.0-alpha.1]`).
6. **GitHub release.** Cut it from the tag as a prerelease (`--prerelease` is GitHub's own
   signal for an `-alpha`/`-beta`/`-rc` tag):
   ```bash
   gh release create v0.5.0-alpha.1 --repo research-common/research-commons \
     --title "v0.5.0-alpha.1" --prerelease \
     --notes-file <(awk '/^## \[0.5.0-alpha.1\]/{on=1; print; next} on && /^(## \[|\[[^]]+\]: )/{exit} on' CHANGELOG.md)
   ```
7. **Binaries.** Publishing the release runs `.github/workflows/release.yml`, which builds
   linux/darwin × amd64/arm64 archives, writes `SHA256SUMS`, attests build provenance, and uploads
   them to the release. The workflow refuses a tag that differs from `VERSION`. When it finishes,
   check the assets before announcing:
   ```bash
   gh release download v0.5.0-alpha.1 --repo research-common/research-commons \
     --pattern 'SHA256SUMS' --pattern '*.tar.gz'
   sha256sum -c SHA256SUMS
   gh attestation verify <archive> --repo research-common/research-commons
   ```
   A dry run (Actions → release → Run workflow) builds and checksums without attesting or
   uploading.
8. **Python wheels** (manual; nothing in CI builds or uploads them). The Python package in `python/` carries the
   binary in one platform wheel per release archive. Its version must already equal `VERSION` mapped to
   PEP 440 (`0.5.0-alpha.3` → `0.5.0a3`): set `version` in `python/pyproject.toml` and `__version__` in
   `python/src/research_commons/__init__.py` in the step-2 version PR, or the build refuses. After step 7,
   with the checks passed:
   ```bash
   mkdir rel && cd rel
   gh release download <tag> --repo research-common/research-commons \
     --pattern 'SHA256SUMS' --pattern '*.tar.gz'
   cd .. && python3 python/scripts/build_wheels.py rel --out dist/wheels
   ```
   The script checks every archive against `SHA256SUMS` before opening it, refuses a version, platform or
   binary-format mismatch, and prints a digest per wheel; building twice gives identical bytes. Install one
   wheel in a clean virtualenv and run `commons --version` before uploading. **Publishing to PyPI is a
   maintainer action** (a trusted publisher configured on the `research-commons` project; no API token in
   the repository), done from the tagged commit.
9. **Hub template pin.** In `research-commons-hub-template`, on its `next` branch, set
   `TOOL_REF` to the tag's **full 40-character commit SHA** (immutable), with the tag as a
   trailing comment (`# v0.5.0-alpha.1`).

## Ordering relative to open PRs

Prefer merging PRs that fix trust-boundary bugs (signature checks, the ingest gate) *before*
cutting a tag, so the changelog lists the fix under "Fixed" rather than "Known issues". Don't let
that block a tag indefinitely: if a fix has no PR open and no ETA, tag with it under "Known
issues" and follow up with the next PATCH or MINOR.
