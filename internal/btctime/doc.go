// Package btctime is the bitcoin-time profile (docs/DESIGN-notes-bitcoin-time.md): receiver-local verification of
// `anchors` statements whose `proof_format` is `ots-detached-v1`, an OpenTimestamps detached proof checked against
// Bitcoin block headers the reader validated itself.
//
// The pieces, in the order a proof meets them:
//
//   - ots.go: the `ots-detached-v1` parser of note §5.1, bounded during parsing (§12), which replays every
//     commitment operation and yields the (calculated digest, attestation) pairs;
//   - header.go: 80-byte headers, compact targets, proof of work and work, exactly as Bitcoin Core computes them;
//   - chain.go: a headers-only chain (§6.1): genesis or an explicit local bootstrap, exact retargeting, median time
//     past, future-time admission, version rules, greatest-chainwork selection, and immutable snapshots (ChainView);
//   - verify.go: the binding checks of §4, attestation selection of §5, the local policy of §7, and the evidence
//     record and state tokens of §8.1, §10;
//   - adapter.go: the resolver's TimeVerifier, so priority among rival claims reads reader-verified bounds only;
//   - publish.go: stamp-at-publish (§2): the anchors statement is appended before anything is transported.
//
// Nothing in this package opens a network connection. Headers arrive through Chain.Add from whatever explicit
// sync command the reader runs; calendars and transports are interfaces the writer supplies. Reads touch the
// snapshot and the blobs the reader already holds, nothing else (§9.4, C-btc-25).
//
// Not built yet: the receipt store of §9 (every read here re-derives the verdict from the snapshot, so nothing is
// cached across snapshots), an operator-node provider (§6.2), and the commands of §10.
package btctime
