# Security policy

## Reporting a vulnerability

Please report privately through GitHub's **private vulnerability reporting**: open the repository's *Security* tab and
choose *Report a vulnerability*. Don't open a public issue or pull request for a suspected vulnerability.

Include what you did, what you expected, what happened, the tool version (`commons --version`) and, where you can, a
small package or statement that reproduces it. A report without a polished proof of concept is still welcome.

## What is in scope

- Anything where the tool admits, verifies or reports as passed what it should refuse: signature or hash checks,
  canonical-form and parsing of received bytes, authorship and edition resolution, trust-floor and policy gates.
- `pull`/`fetch` handling hostile input: path traversal, symlinks and special files, archive members, size and scan
  limits, memory or disk exhaustion, requests to unintended hosts.
- The execution sandbox (`verify --rerun`): escapes, or reading and writing outside what the policy grants.
- The fixed-root identity profile (`rc/2`), which is active and frozen: acceptance of an identity grant or cut that
  should be refused, or an identity actor evaluated wrongly from the statements held.
- Key handling: key files created with the wrong mode, keys written to output or logs.
- The release process: release artifacts that don't match their checksums or provenance attestation, or an
  unpinned action in this repository's workflows.

Out of scope: gaps already listed in [`docs/KNOWN-LIMITS.md`](docs/KNOWN-LIMITS.md); an attacker who already holds your
key file or can write to your store directory; denial of service by a user running the tool on their own huge input
without the documented limits; findings that
need a modified build.

## Supported versions

| version | status |
|---|---|
| 1.0.0-rc.x (branch `next`) | supported: fixes land on `next` and ship in the next candidate |
| 0.5.0-alpha.x | superseded by the release candidate: upgrade |
| 0.4.x (Python alpha, branch `main`) | security fixes only, until the cutover |
| older | unsupported |

The format is frozen for 1.0. Between release candidates only fixes and wording change; a security fix that would
change the bytes of a frozen format means a new candidate, and the advisory will say so.

## What to expect

This is a small, volunteer-run project. We aim to acknowledge a report within **about a week** and to tell you what we
decided after that; fixes for confirmed issues are prioritised, but we can't promise a date. We will credit you in the
changelog unless you ask us not to. There is **no bug bounty**.
