# Anchor trust: read-side containment

An anchor JSON file is replicated data, not a receiver's verification verdict. Its
`created`, `confirmed_at`, `anchored`, `bitcoin_blocks`, `ots_proof`, and
`verified_locally` fields cannot establish independent time merely by existing.

## Failure addressed

Previously, a peer could add a root-consistent JSON checkpoint over its own later
publish, choose an earlier `created`, and write `anchored: confirmed` with a block
number. Without any proof or signed anchor event, readers would assign Bitcoin
quality and choose the copier as first publisher. They could also report the honest
publisher as the party whose priority assertion lacked anchor coverage. Root
consistency and transport through hub CI were not proof verification.

## Read-side contract

1. Recompute the root from well-shaped log names and head hashes. A malformed or
   mismatched checkpoint contributes no bound.
2. Require a verified signed `anchor` event binding the checkpoint filename's id
   and root. The event must physically occur in the log named after that signer.
   Both signatures are checked when `sig2` is present; older v1 events remain usable.
3. Cover only the signer's own log prefix, whose recorded head must precede that
   anchor event. A signature over a multi-log checkpoint does not grant the signer
   the ability to checkpoint other identities for priority purposes.
4. Use the signed event's `ts`, not mutable JSON dates, as the local checkpoint
   time. This authenticates whose assertion it is, **not whether the time is true**.
   An event whose `ts` is earlier than any line it covers is ignored: the log's own
   order shows that line existed first, so the event cannot lend it an earlier date.
5. All currently supported bounds have `local` quality, displayed as self-declared.
   JSON claims of confirmation or local verification never upgrade quality. The
   reader does not invoke a block explorer or infer trust from peer registration.
6. Evidence quality sorts before timestamp, including when comparing different
   publishers. This preserves the intended Bitcoin-over-local ordering for a future
   verified source; no current input produces Bitcoin quality.

Unsigned checkpoints remain operationally useful over `local-unsigned.jsonl` and
the legacy unsigned log. They cannot authenticate signed events transported into
those logs, nor unsigned lines carrying an `addr`: such a line names a key without
proving it holds that key, and a bound would let it pose as that key's
pre-publication `derivation-commit`. Unsigned lines written by this tool carry
`addr: null`, so drift coverage is unaffected. Whether lifecycle commands should
accept unsigned events naming a key at all is a separate ingest question. This preserves unsigned publishing's drift warning without allowing
unsigned metadata to confer signed derivation priority.

## What this does not promise

- A malicious signer can still backdate its own signed event, provided it also
  backdates the lines it covers so its log stays self-consistent. Local bounds are
  assertions, so local ordering is useful for honest peers, not secure adjudication
  between adversaries. Do not build edit authority on local first-publisher order.
  This rules out adjudicating metadata authority by anchored first-publisher order
  (#47 option 1), and the signed-manifest design (#43) has withdrawn its matching
  tie-break. For an artifact frozen by several publishers, the remaining routes are
  adoption under local trust and signed views, until a receiver-local Bitcoin
  verifier exists.
- Bitcoin proofs remain available as artifacts, but `anchor-upgrade` only inspects
  proof labels. `anchor-verify` checks structural consistency and can inspect OTS
  attestations; success does not authenticate a block or establish its time.
- Existing `confirmed` checkpoints intentionally lose Bitcoin quality. There is
  no grandfathering based on who wrote them or where they were received.
- `pull` and `hub check --base` can still transport malformed or proofless anchor
  files. They no longer gain time authority merely by being transported. Adding
  per-file refusals is a separate ingest/CI compatibility change.
- This does not change commit-reveal policy or local-only tie settlement policy.

## Followups requiring a block-time design

A real Bitcoin-quality bound needs a receiver-side verifier that checks the proof's
commitment to the exact root-file bytes, verifies the attestation against a trusted
Bitcoin chain, and uses that block's time. Proof inspection or a successful command
exit alone is insufficient. Receiver verification receipts must be local-only,
cannot arrive through federation, and must be invalidated when bound inputs change.

The block evidence source (operator node, a validated headers-only light client,
or an explicitly trusted third-party service) is not silently chosen here. A full
node is not required: a headers client can validate proof of work, difficulty,
linkage and chain selection, then supply the header whose Merkle root the OTS
attestation must match. Chain membership, confirmations and reorg handling still
need an explicit policy. Until that verifier exists, fail closed: no Bitcoin-quality
priority.

An authenticated header's `nTime` is a consensus-constrained miner timestamp, not
an exact wall-clock oracle. A complete priority policy should distinguish chain
position from UTC time rather than presenting the latter as an exact creation bound.

`tests/test-anchor-trust.sh` covers metadata forgery, signature/id/root/log scope,
malformed input, quality ordering, unsigned operational coverage, and a fabricated
checkpoint transported through `hub check --base` and `pull`. It also checks that a
forged checkpoint cannot give a derivation commit an authenticated bound or grant
commit-reveal quorum credit against a checkpointed publisher, that an unsigned line
claiming an `addr` gets no bound, and that a signed anchor event dated before a line
it covers neither seizes first publisher nor flags the honest publisher.

`status` reports a TIME DISCREPANCY as a disagreement between assertions to
investigate. It does not tell readers to discount either peer, because a local
checkpoint is itself an assertion.
