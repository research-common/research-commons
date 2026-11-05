# Known limits

Generated from `internal/cli/limits_test.go` by `RC_UPDATE_DOCS=1 go test -run TestDocumentedLimits ./internal/cli`.
Do not edit by hand.

Every gap below is documented where users read it, and each has a test asserting the gap is still open
(conformance case C-core-07). The test fails when the quoted words leave their file or when the probe finds
the gap closed, so the documentation and this list change with the code.

| id | limit | where users read it | the test checks (holds while open) | closed when |
|---|---|---|---|---|
| L-01 | Priority needs time evidence this reader verified, and no command verifies Bitcoin time: every multi-author construction is `contested` (#59) | `docs/DESIGN-notes-claims-model.md`<br>`CHANGELOG.md` | two keys claim one blob, each with an anchor whose proof parses: `verify` exits 3, authorship `contested`, each anchor's time state `backend-unconfigured` | a chain backend verifies one claimant's bound strictly earlier: `default author` |
| L-02 | No chain backend or header sync, and no command opens the receipt store: no anchor is ever verified, and every answer is clock-free | `internal/README.md`<br>`docs/CLI-OUTPUTS.md` | no registered command starts with `anchor`; `explain` says no chain backend is configured | an `anchor headers sync` / `anchor status` command (bitcoin-time note §10) and a configurable backend |
| L-03 | Seed-phrase (mnemonic) key derivation | `docs/KEY-FILES.md`<br>`commons key new --help` | no command or option mentions a mnemonic, seed phrase or words | a key command or option that derives a key from a phrase |
| L-04 | Native (unsandboxed) re-runs and secret or host-resource grants are not expressible in an execution policy | `docs/EXEC-POLICY.md`<br>`docs/EXEC-POLICY.md` | a policy with a `native` or a `secrets` member is refused before any work (exit 2); the same policy without it is accepted (control) | a member for native runs or secret grants |
| L-05 | The task contract grammar is provisional: only the provisional profile is read; any other contract leaves readiness `unchecked` | `commons publish task --help` | `publish task` with a contract of any other profile prints readiness `unchecked`, naming the profile it reads | a specified contract grammar this reader reads |
| L-06 | No rule or schema dialect is specified: an edition rule or member schema is always `unchecked` | `docs/DESIGN-notes-claims-model.md` | the publisher's pre-pin check is built with no rule dialect | a dialect note and a dialect shipped in the reader |
| L-07 | Fixed-root identity (`rc/2`) is a review candidate, not enabled: an `rc/2` line is an unverified other-major line | `docs/DESIGN-notes-fixed-root-identity.md`<br>`internal/README.md` | the format major is 1, and a signed `rc/2` line reads as `unsupported` and unverified | activating the profile (the major moves, or the reader verifies `rc/2`) |
| L-08 | No critical extension is implemented: any statement marking one critical is kept, verified and `unsupported` | `docs/READER-EXTENSIONS.md` | a signed statement with `crit: [x_ext]` reads verified and `unsupported`, naming the extension | a registered extension in the production reader |
| L-09 | Key and execution-policy file formats are provisional (version 0) and expected to change before a stable release | `docs/KEY-FILES.md`<br>`docs/EXEC-POLICY.md` | the key file tag is `rc-key/0` and the execution policy tag is `rc-exec-policy/0` | a stable (`/1`) tag for either format |
| L-10 | `fetch` dials https (and http on request) only, through no proxy: a holds naming an `ipfs:`, object-store or `file:` location is never fetched | `commons fetch --help` | an `ipfs:`, an `s3:` and a `file:` location are refused before dialling with every opt-in given | a transport for another scheme, or proxy support |
