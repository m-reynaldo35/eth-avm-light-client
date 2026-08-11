# Architecture

## What this is

A light-client bridge from Ethereum to the Algorand Virtual Machine (AVM),
split into two composable tracks:

- **Track A — trust root**: verifies Ethereum sync-committee BLS12-381
  aggregate signatures and SSZ Merkle branches on-chain, producing a trusted,
  rolling `(committeeRoot, stateRoot, receiptsRoot)` anchor.
- **Track B — state proofs**: given a trusted root from Track A, verifies
  Ethereum Merkle-Patricia-Trie (MPT) inclusion proofs (account, storage,
  receipt/log) against it.

Module boundaries and the dependency graph between them are defined in
`ROADMAP.md` and the full plan at `/home/mark/.claude/plans/peppy-cuddling-snail.md`.
This document records the standing decisions that apply across every module.

## Language: Algorand Python (Puya), with inline `Op` for hot paths

Contracts are authored in Algorand Python (Puya) rather than raw TEAL or
PyTeal. Rationale: this is a public repo meant to attract external
contributors, and typed, readable Python is far more approachable at
12-module scale than hand-written TEAL. The original spike's hand-written
TEAL remains in `tests/fixtures/spike-reference/` purely as an empirical
reference for opcode budget numbers — it is not a style to imitate for
production modules.

Exception: budget-critical inner loops where every opcode counts (the RLP
decoder's item-extraction loop, MSM chunking/combination) may drop to Puya's
`Op` low-level opcode access instead of higher-level Puya constructs, when a
design doc explicitly justifies it with a measured budget comparison. This is
the exception, not the default — most contract code should be ordinary Puya.

## Full Ethereum consensus-spec compliance

The sync-committee/SSZ track (M3, M4) is built against real Ethereum
consensus-spec test vectors (BLS domain-separation tag, signing-root
construction, SSZ generalized indices, fork field layouts) from the start.
There is no "stub the signature check, prove AVM mechanics only" phase — a
design doc for M3 or M4 is not approvable until it cites real spec test
vectors, not just AVM-side byte-shape matching.

## No cost claim without a real `simulate` response

Every opcode-budget number that appears in a design doc or README must trace
to an actual `/v2/transactions/simulate` response, using the harness pattern
already proven in `tests/fixtures/spike-reference/avm_bls_bench.py` and
`mpt_bench.py` (generalized in module M11). Estimated or documented-table
budget numbers are not sufficient on their own — the spike itself found real
measured costs run ~5-6 above documented per-opcode costs due to operand-load
overhead, and that a naive doc reading can be off by 2x (see
`tests/fixtures/spike-reference/RESULTS.md` section 6).

## Contract versioning

Versioning is gated by AVM/consensus-protocol compatibility, not plain
semver: three axes (AVM/protocol, consensus fork, proof system), identified
by the approval-program SHA-256 that CI already computes and diffs per PR —
never a hand-typed number (docs/design/012-docs-packaging-release.md §3).
The real supported Ethereum fork range is **Deneb, Electra, Fulu**
(`deploy/forks.py::FORK_FIELD_COUNTS`) — correcting this section's earlier
guess of "Altair/Capella/Deneb" — with **Gloas explicitly excluded** per
contract, for two different measured reasons (a budget ceiling for M4, a
hard argument-size cap for M8). See
[`docs/versioning.md`](./docs/versioning.md) for the full scheme, the
per-contract fork decision table, and the standing 1,212-byte M4 bytecode
headroom.

## Deployed vs. test-only contracts

Every module that is meant to run for real is a **permanently deployed,
manifest-pinned** app — `deploy/plans/*.py`, `deploy/manifests/*.json`.
Anything that says "NEVER deploy to mainnet" in its own module docstring
(`contracts/*/bench_app.py`) is reference/test infrastructure only, compiled
on demand by the test suite or the relayer, never something `deploy apply`
touches. `contracts/receipt/anchored_app.py::Mpt7AnchoredReceiptApp`
(`deploy/plans/m7_anchored.py`) is the newest member of the first group —
the permanent combination of M7's T1+T2 receipt walk with M8's anchor
check, replacing the test-only, compiled-per-call `AnchorReceiptProbe` for
that path (docs/design/014-t2-against-anchor.md §4.1). Like
`TrustedRootAnchor`, its compiled bytecode is genuinely
network-specific — `contracts/state_anchor/handoff.py::ANCHOR_APP_ID` is
patched to the real M8 app id at build time (TP-M8-4), so its
`approval_sha256` pin is per-manifest, not a single global constant the way
`Mpt6ComposerApp`/`Mpt7ReceiptApp`'s are (`deploy/versions.json`).

## CI: two workflows from commit one

- `ci-offline.yml` — lint + unit tests against pinned, recorded fixtures
  (`tests/fixtures/`). Runs on every PR. No live docker/RPC dependency.
- `ci-live.yml` — manual/nightly job that brings up a dev-mode `algod`
  container (same recipe as the spike's `README.md`) and hits public
  Ethereum RPC, mirroring the spike's real-data validation style. Must be run
  manually and pass before any module is marked "Released" in `ROADMAP.md`.
  A "Released" claim must **cite the run id** it passed on, not merely
  assert that one exists (docs/design/011-test-harness-ci.md §15.4 item 2;
  the first real, green run of this workflow's real body was G1-M12, run
  [31229821639](https://github.com/m-reynaldo35/eth-avm-light-client/actions/runs/31229821639)
  — every scheduled run before it had executed only the scaffold placeholder
  commit, docs/design/012-docs-packaging-release.md §0).

Module M11 owns ratifying and extending this policy as the test surface
grows.
