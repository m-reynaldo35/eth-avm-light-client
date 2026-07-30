# eth-avm-light-client

An Ethereum → Algorand light-client verifier: BLS12-381 sync-committee
signature verification and SSZ/MPT state-proof verification on the AVM
(Algorand Virtual Machine).

This project grew out of an empirical benchmarking spike that measured real
AVM opcode-budget costs for BLS12-381 curve operations and Ethereum
Merkle-Patricia-Trie proof verification against real mainnet data. Those
findings (and the honest gaps they exposed — see below) drive every design
decision here. The original spike is preserved, unmodified, in
`tests/fixtures/spike-reference/`.

## Status

Early scaffold stage. See [`ROADMAP.md`](./ROADMAP.md) for the current module
status and what's being worked on next — that file is the single source of
truth for project state across sessions.

## Architecture

Two composable tracks:
- **Trust root** (BLS12-381 sync-committee signatures + SSZ Merkle branches)
  produces a trusted `(committeeRoot, stateRoot, receiptsRoot)`.
- **State proofs** (MPT inclusion proofs for accounts, storage, receipts/logs)
  verify against that trusted root.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for language choice, spec-fidelity
policy, and standing engineering decisions, and
[`docs/design/`](./docs/design/) for the per-module design docs.

## Why this matters — what the spike found

The spike proved feasibility (a full account+storage proof costs ~6,827
opcode budget / 0.010 ALGO, ~27x headroom in a single atomic group; a
512-key sync-committee update fits in one 16-txn atomic group with a small
optimization) but also surfaced two real gaps that this project exists to
close:

1. **Security gap**: a naive MPT verifier can be built that hash-chains
   correctly but never actually checks the proven key against the trie path
   — it would accept a proof for the *wrong* key. See `docs/design/005-*.md`.
2. **The >4096B receipt problem**: real Ethereum receipts for log-heavy
   transactions RLP-encode past the AVM's hard 4096-byte value cap — a
   receipt-trie leaf embeds the whole receipt, so it can't even be pushed to
   the stack, let alone hashed, with a naive approach. See `docs/design/007-*.md`.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## License

MIT — see [`LICENSE`](./LICENSE).
