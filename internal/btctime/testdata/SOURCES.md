# Fixture sources

Fetched once, by hand, and checked in; no test contacts a network.

## `mainnet-356832-359000.headers`

2169 consecutive Bitcoin mainnet block headers, heights 356 832 to 359 000 inclusive, 80 raw bytes each
(173 520 bytes; sha256 `9d7de8d0322761a515ff5544d6aa5f7bf67d85b4b8bfe43f2f943fac94f4a74a`).

- Source: an Electrum protocol server (`blockchain.block.headers`, the electrs/esplora backend of blockstream.info),
  fetched 2026-10-18.
- Cross-checked against a second, independent explorer (mempool.space REST API): the display hashes at heights
  356 832, 358 391 and 359 000, and block 358 391's Merkle root, time and bits, agree. The `prev` linkage of every
  header is checked by the tests themselves, and every header's proof of work and retarget are re-validated.
- 356 832 = 177 × 2016 starts a retarget period, and 358 848 = 178 × 2016 is inside the range, so the exact retarget
  rule is exercised on real data. 90 headers in the range have a lower `nTime` than their predecessor.
- `WorkBelow` used by the tests (chainwork through height 356 831) = `0x6f293e337e48534b58620`: the sum of
  2016 × work(bits) over the 177 earlier retarget periods, computed from the period-start headers, and equal to the
  `chainwork` an independent explorer (blockchair) reports for block 356 831.

## `hello-world.txt.ots`, `bad-stamp.txt.ots`

Example proofs from the OpenTimestamps client repository (`examples/`, master at the time of fetching). They are
machine output (hashes, operation tags and a block height), used here as data only; no OpenTimestamps code is
included.

- `hello-world.txt.ots` stamps sha256(`Hello World!\n`) =
  `03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340` and attests Bitcoin block 358 391
  (display hash `000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319`). The tree's calculated
  digest equals that header's Merkle root.
- `bad-stamp.txt.ots` claims the same height, but its calculated digest is not block 358 391's Merkle root: the
  library's own example of a proof that fails verification.

## `mainnet-358391.txids`

The 1433 transaction ids of block 358 391, display order, one per line, from the blockstream.info REST API
(`/block/<hash>/txids`), identical to mempool.space's list. The test recomputes the block's Merkle root from them
and checks it equals the header's, an independent cross-check of the digest the proof reaches (§13 item 8).
