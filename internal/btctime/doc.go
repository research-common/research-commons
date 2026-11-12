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
//     each held header is a compact node (its raw bytes once, cumulative work as an in-place 256-bit value, u256.go);
//   - verify.go: the binding checks of §4, attestation selection of §5, the local policy of §7, and the evidence
//     record and state tokens of §8.1, §10;
//   - adapter.go: the resolver's TimeVerifier, so priority among rival claims reads reader-verified bounds only;
//   - publish.go: stamp-at-publish (§2): the anchors statement is appended before anything is transported;
//   - location.go, receipt.go: the receipt store of §9: receiver-local state under the git directory Git resolves
//     (or an explicitly configured directory, else none), receipts binding every §9.2 field by content hash,
//     the five eligibility checks of §9.3 on every read, the immutable binding kept apart from chain eligibility,
//     and a receipt that is corrupt, copied, foreign or of an unknown version never trusted. A receipt is a cache:
//     every answer equals the cold one.
//
// The receipt store is opt-in at this level: a Verifier reads every proof cold unless the caller sets
// Verifier.Receipts. The read commands set it whenever the reader has a header database: read-write when the state
// directory is writable, read-only (receipts used, none written, nothing created) otherwise. Measured, a small proof
// (a few hundred bytes, the common case) verifies faster cold than through the cache, which reads, parses and
// authenticates a receipt and re-hashes the proof bytes on every read anyway (check 1 of §9.3); the cache only pays
// for large proofs. Either way every answer is the cold one (P-07).
//
// Receiver-local state is never read or written through a symbolic link (fsguard.go).
//
// Nothing in this package opens a network connection. Headers arrive through Chain.Add from whatever explicit
// sync command the reader runs; calendars and transports are interfaces the writer supplies. Reads touch the
// snapshot and the blobs the reader already holds, nothing else (§9.4, C-btc-25).
//
//   - headerdb.go: the header database of §6.1/§9.1 in the same receiver-local state: headers persisted whole
//     (temporary, sync, rename, under a lock), re-validated through Chain.Add on every load, and refused whole when
//     foreign, of another network, of an unknown version, corrupt or tampered. Sync reads raw headers from a
//     source the operator chose (a file today), bounded and cancellable; a header that fails validation stops it.
//
// Not built yet: an operator-node provider (§6.2), a network header source, and the persisted policy of §9.1.
package btctime
