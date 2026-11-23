# Hardware compatibility

Generated from the report files in `docs/hardware-reports/` by
`RC_UPDATE_DOCS=1 go test -run TestHardwareReports ./internal/cli`. Do not edit by hand: add a report file.

This page records what people have **observed** when signing with a hardware device. It is not a list of
supported devices: what the tool supports, and what it does not do yet, is in
[`KNOWN-LIMITS.md`](KNOWN-LIMITS.md). A row says that one person ran the steps below on one device, firmware
and host, with one build of the tool, on one day.

No hardware is needed to use the tool. Every command works with a key file.

**Reports are wanted**, for any device, firmware or host not listed, and for a listed one with a newer build.
A report that something fails is worth as much as one that it works.

## What has been observed

| device | firmware, app | host | key kind | route | tool | read | sign | reject | timeout | disconnect | size | revoke | rotate | evidence | by | report |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Ledger Nano S Plus (emulator) | firmware Speculos emulator; Ethereum 1.23.0 | Ubuntu 24.04 x86_64 | `eip191-secp256k1` | connector | 1.0.0-rc.1 `f48fe26` | pass | pass | pass | pass | pass | pass | pass | pass | signed line (shows a key, not a device) | maintainers, 2026-11-21 | [file](hardware-reports/ledger-nanosp-emulator-ethereum-1.23.0-linux-2026-11-21.json) |
| Ledger Nano X | firmware not recorded; Ethereum 1.19.3 | Ubuntu 24.04 x86_64 | `eip191-secp256k1` | connector | 0.5.0-alpha.7 `6dc5f1e` | pass | pass | pass | not run | not run | pass | not run | not run | none | maintainers, 2026-11-16 | [file](hardware-reports/ledger-nanox-ethereum-1.19.3-linux-2026-11-16.json) |
| Ledger Nano X | firmware not recorded; Ethereum 1.19.3 | Ubuntu 24.04 x86_64 | `eip191-secp256k1` | connector | 1.0.0-rc.1 `bf563e0` | pass | pass | pass | pass | pass | not run | pass | pass | none | maintainers, 2026-11-20 | [file](hardware-reports/ledger-nanox-ethereum-1.19.3-linux-2026-11-20.json) |
| Ledger Nano X (emulator) | firmware Speculos emulator; Ethereum 1.23.0 | Ubuntu 24.04 x86_64 | `eip191-secp256k1` | connector | 1.0.0-rc.1 `f48fe26` | pass | pass | pass | pass | pass | pass | pass | pass | signed line (shows a key, not a device) | maintainers, 2026-11-21 | [file](hardware-reports/ledger-nanox-emulator-ethereum-1.23.0-linux-2026-11-21.json) |
| Yubico YubiKey 5 (USB-C) | firmware 5.4.3; OpenPGP 3.4 | Ubuntu 24.04 x86_64 | `ed25519` | package | 1.0.0-rc.1 `4ba33cf` | n/a | pass | n/a | n/a | n/a | pass | n/a | n/a | none | maintainers, 2026-11-20 | [file](hardware-reports/yubikey-5-5.4.3-openpgp-ed25519-linux-2026-11-20.json) |
| Yubico YubiKey 5 (USB-C) | firmware 5.4.3; OpenPGP 3.4 | Ubuntu 24.04 x86_64 | `eip191-secp256k1` | package | 1.0.0-rc.1 `4ba33cf` | n/a | pass | n/a | n/a | n/a | n/a | n/a | n/a | none | maintainers, 2026-11-20 | [file](hardware-reports/yubikey-5-5.4.3-openpgp-secp256k1-linux-2026-11-20.json) |
| Yubico YubiKey 5C | firmware 5.4.3; OpenPGP not recorded | macOS 27.2 arm64 | `ed25519` | package | 1.0.0-rc.1 `7c3b916` | n/a | pass | n/a | n/a | n/a | pass | n/a | n/a | none | brandon-eigenlabs (reported), 2026-11-18 | [file](hardware-reports/yubikey-5c-5.4.3-openpgp-ed25519-macos-2026-11-18.json) |
| Yubico YubiKey 5C | firmware 5.4.3; OpenPGP not recorded | macOS 27.2 arm64 | `eip191-secp256k1` | package | 1.0.0-rc.1 `7c3b916` | n/a | pass | n/a | n/a | n/a | n/a | n/a | n/a | none | brandon-eigenlabs (reported), 2026-11-18 | [file](hardware-reports/yubikey-5c-5.4.3-openpgp-secp256k1-macos-2026-11-18.json) |

How to read a row:

- **route**: `connector` means the tool talked to the device itself (`--ledger`). `package` means the tool wrote
  a signing package, something else had the device sign it, and the tool completed it.
- **by**: "(reported)" marks a report from a contributor that the maintainers have not repeated.
- **evidence**: "signed line" means the report carries the inception signed in the sign step, and the test
  behind this page checked its signature. That shows a key signed in the tool's format. It cannot show which
  device or firmware held the key, on an emulator row or a hardware row: that part is the reporter's word.
- A step that does not apply to a route or a device reads n/a. The notes in the report file say why.

## Not yet observed

Reports for these would fill the largest gaps:

- Ledger Nano S Plus, Flex and Stax as hardware (the Nano S Plus row above is the emulator).
- A Ledger on macOS or Windows. The USB connector is built for Linux only (L-20).
- Ethereum app versions other than 1.19.3 on hardware.
- A rejection of a `revoke` or `rotate` request on hardware.
- YubiKey firmware 5.7 or later, and the PIV applet.
- Any other device that can produce an Ed25519 or an EIP-191 secp256k1 signature over bytes the tool prepares.

## Before you test

- **Use a key that holds nothing and means nothing.** On a Ledger, a throwaway passphrase or an account number
  you use for nothing else. On a card, an empty slot. Never overwrite a slot that holds a key.
- **Work in a new, empty store** (`commons init` in a new directory). Nothing in the drill needs a hub.
- **Do not post** serial numbers, or an address or key that you use for anything else.
- The drill signs a `revoke_key` and a `rotate_key` for the throwaway keys. That is the point of those steps.

## The drill for a device with a connector (Ledger)

Use two paths you use for nothing else, for example `m/44'/60'/7'/0/0` and `m/44'/60'/8'/0/0`, written
`<path>` and `<path2>` below. Open the Ethereum app on the device first.

| step | run | pass when |
|---|---|---|
| read | `commons key show --ledger --ledger-path <path>` | exit 0, and it prints the app, its version and a signer; call the signer `<signer>` |
| sign | `commons identity new --prepare i.pkg --signer <signer>`, then `commons key sign --package i.pkg --ledger --ledger-path <path> --out i.sig` and approve on the device, then `commons identity new --complete i.pkg --signature i.sig`, then `commons fsck` | every command exits 0 and `fsck` reports clean |
| reject | the same `key sign` with `--out r.sig`, rejected on the device | exit 1, and `r.sig` does not exist |
| timeout | the same `key sign` with `--ledger-timeout 5s --out t.sig`, left alone; afterwards reject the review on the device | exit 3 saying the device did not answer in time, and `t.sig` does not exist |
| disconnect | the same `key sign` with `--out u.sig`; unplug the device while the review is on its screen | exit 3, and `u.sig` does not exist |
| size | `commons revoke --ledger --ledger-path <path> --expect-signer <signer> --reason key_compromise --last-good none --note <text>`, once with 7,000 characters of text (reject it on the device) and once with 8,000 | the first is offered for review; the second exits 3 before any review; `fsck` still clean. If your device differs, say at what size |
| revoke | the same `revoke` without `--note`, first with `--dry-run`, then for real and approved | the dry run exits 0 and asks for no approval; the real one exits 0 and `fsck` is clean |
| rotate | `commons key new --out succ.key`, read the signer at `<path2>`, then `commons rotate --ledger --ledger-path <path2> --expect-signer <that signer> --successor <the new key's signer>`, approved | exit 0 and `fsck` is clean |

After a step that leaves a review on the device, finish or reject it there before the next command.

## A device without a connector

A device the tool cannot talk to can still be reported through the package route: `--prepare` writes the
bytes to sign, your own program has the device sign them, and `--complete` verifies and commits. Only the
sign and size steps apply; the others read n/a. Say in the notes what drove the device, and link to the
script. If the device has no screen, say so: the only review is then `commons package show` on the host.

## Limits seen on devices

- **Ledger, Ethereum app:** a message of 7,652 bytes was offered for review and one of 7,653 was refused, on
  app 1.19.3 (hardware) and 1.23.0 (emulator).
- **YubiKey, OpenPGP applet, `ed25519`:** the card signs the message itself and refuses one longer than
  3,072 bytes (firmware 5.4.3). An edition's signed bytes grow with its member list, about 22 members at that
  size. So a key that approves the editions of a large collection should not be an `ed25519` key on such a
  card. An `eip191-secp256k1` key on the card signs a digest and has no such limit; firmware below 5.7.0
  carries Yubico advisory YSA-2024-03 for that curve.

## Sending a report

Copy a file in [`hardware-reports/`](hardware-reports/), change it, and open a pull request with it and
the regenerated page. If you would rather not open a pull request, open an issue with the "Hardware test
report" form and a maintainer will add the file, marked as reported.

The fields:

| field | meaning |
|---|---|
| `format` | `hardware-report/1` |
| `id` | the file's name without `.json`: lowercase, ending in the date |
| `date`, `by` | the day of the run, and a name to credit (a GitHub handle is fine) |
| `source` | `contributor`; a maintainer changes it to `maintainer` only after repeating the run |
| `device` | `vendor`, `model`, `emulator` (true or false), `firmware`, `app`, `app_version`; write "not recorded" for what you do not know |
| `host` | `os` and `arch` |
| `tool` | `version` and `commit`, both from `commons --version`. A build from a source archive prints `commit: unknown`: give the commit of the release or of the checkout (`git rev-parse HEAD`) instead. For a build of a pull request, give its head commit and say so in the notes |
| `route`, `alg` | `connector` or `package`; `ed25519` or `eip191-secp256k1`. On the connector route, read and sign are never `n/a`. On the package route, every step but sign and size is `n/a` |
| `steps` | one of `pass`, `fail`, `not-run`, `n/a` for each of the eight steps |
| `notes` | what differed, sizes, status words. Required when a step failed |
| `links` | an issue or a script, optional |
| `evidence.line` | optional: the inception the device signed in the sign step, copied whole from the one file under `statements/<signer>/` at that point |

The test behind this page refuses a report with a missing or unknown field, and verifies `evidence.line` with
the reader every store uses. A report whose line does not verify is not merged.

## Keeping it current

Each row is dated and names the build it was run with. A row for an old build is not wrong; it is old.
A new run is a new file: old files are not edited, so the page keeps its history. A release that changes
a connector runs the drill again ([`RELEASING.md`](RELEASING.md), step 11).
