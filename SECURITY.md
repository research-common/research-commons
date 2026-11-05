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
- Key handling: key files created with the wrong mode, keys written to output or logs.
- The release process: tampered release artifacts or an unpinned CI action in the hub template.

Out of scope: gaps already listed in [`docs/KNOWN-LIMITS.md`](docs/KNOWN-LIMITS.md); an attacker who already holds your
key file or can write to your store directory; denial of service by a user running the tool on their own huge input
without the documented limits; the fixed-root identity profile, which is a candidate and not enabled; findings that
need a modified build.

## Supported versions

| version | status |
|---|---|
| 0.5.x (alpha, branch `next`) | best effort: fixes land on `next` and ship in the next alpha |
| 0.4.x (Python alpha, branch `main`) | security fixes only |
| older | unsupported |

The format is alpha and may change between releases: a fix may change what the tool accepts.

## What to expect

This is a small, volunteer-run project. We aim to acknowledge a report within **about a week** and to tell you what we
decided after that; fixes for confirmed issues are prioritised, but we can't promise a date. We will credit you in the
changelog unless you ask us not to. There is **no bug bounty**.
