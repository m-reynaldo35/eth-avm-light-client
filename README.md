# eth-avm-light-client

An Ethereum → Algorand light-client **verifier**: real BLS12-381
sync-committee signature verification and SSZ/Merkle-Patricia-Trie
state-proof verification, implemented as Algorand Python (Puya) smart
contracts on the Algorand Virtual Machine (AVM). **"Verified" here means
Ethereum's sync-committee light-client trust model, not full-node
security**: sync-committee messages are not slashable, a 2/3 majority of
the current 512-member committee can sign a lie at no on-chain cost, and
detecting that is an off-chain, social process this project's contracts
cannot perform — this is Ethereum's own light-client trust model, not a
defect in this implementation (008 §5.3/§15.6; see
[`docs/security.md`](./docs/security.md) for the full picture). This
project grew out of an empirical benchmarking spike that measured real AVM
opcode-budget costs for BLS12-381 curve operations and Ethereum
Merkle-Patricia-Trie proof verification against real mainnet data; that
spike is preserved unmodified in `tests/fixtures/spike-reference/`.

[![ci-offline](https://github.com/m-reynaldo35/eth-avm-light-client/actions/workflows/ci-offline.yml/badge.svg)](https://github.com/m-reynaldo35/eth-avm-light-client/actions/workflows/ci-offline.yml)

Green means the offline test suite (fixed fixtures, no live network) passed
on the latest push — the same thing 011 §1.3 says a green tick means: pure
computation on committed inputs, not a live-network claim, and not
something that expires with the date. The badge intentionally does **not**
point at `ci-live.yml` (the manual/nightly job that hits real mainnet):
`ci-live`'s green has a date on it and a badge that silently tracked the
nightly would be exactly the "green tick over an echo" failure mode this
project's own `ARCHITECTURE.md` was written to forbid, with a longer fuse.

## Status

All twelve original modules implemented, plus a 013 (real security) revision
and a 014/M13 extension, real mainnet-deployed and tagged `v1.0.0`. This
table replaces an earlier "Early scaffold stage" status line that had gone
stale. Every "proven" cell below cites a run id, a round, an app id, or a
test suite — see [`ROADMAP.md`](./ROADMAP.md) for the full session-by-session
history.

| module | what it is | proven | not proven / open |
|---|---|---|---|
| M1 | BLS12-381 point codec, MSM, pairing | real spec test vectors, offline suite | — |
| M2 | On-chain RLP decoder | offline suite | G2/G4/G5/G6 gates open (performance, not correctness) |
| M3 | SSZ Merkle branch verifier, fork-agnostic gindex derivation | offline suite; gindices reproduce 7 independently-confirmed real values | — |
| M4 `SyncCommitteeVerifier` | Sync-committee update verifier | real mainnet, app `3670310452`; a real 512-member committee installed and finalized, a full receipt proved end-to-end (013, commit `ee9ef6c`) | Gloas fork row not yet supported by design (§3.3); `deploy verify` reports a real, permanent, structural 366100 µALGO install-vs-steady-state slack (`docs/security.md`), not a defect |
| M5 | MPT path-walker / node verifier | real live submission | 3 budget-gate targets open — **real measured numbers, not the design targets**: 5,116 opcode account walk (target < 3,276), 1,813 opcode receipt walk (target < 1,121), 1,969 B (target ≤ 1,400 B) |
| M6 `Mpt6ComposerApp` | Account & storage proof composer | real mainnet, app `3670312896`; a real submitting client (`prove_account`), two live proofs (`C_INCLUDED`, `C_ABSENT_ACCOUNT`) | — |
| M7 `Mpt7ReceiptApp` | Receipt/log proof verifier (T1+T2) | real mainnet, app `3670577356` (redeployed 2026-08-11, closing a real box-squatting gap — the original `3665914633` is abandoned, see `docs/security.md`); a real paid x402 endpoint at `https://x402endpoint-nu.vercel.app` | T3 (ZK tier, ~2.2% of real receipts) designed but unimplemented — no coverage number is published here until a real proof exists at the deployed tier (see below) |
| M8 `TrustedRootAnchor` | Trusted-root anchor (fork table + block-root ring) | real mainnet, app `3670310865`; 11 of 22 error codes closed with live tests, the remaining 2 proven genuinely unreachable (not merely deferred) | `TrustedRootAnchor`'s equivocation latch is not covered by the monitoring workflow below |
| M9 | Off-chain relayer/client (`relayer/`) | live-tested end to end (sync → anchor → prove), real mainnet | one gate (`G1-M9`) is real, measured, and structurally unsatisfiable except on a low-absenteeism day — quarantined, see `CHANGELOG.md` |
| M10 | Deployment & box-storage schema tooling (`deploy/`) | real mainnet deploy → verify → M9 pipeline, multiple times over (013, 014, the M7 redeploy) | governance on every real deploy so far has been a disposable deployer key, not yet a multisig/hardware signer (`docs/operating.md`'s O-M10-3) |
| M11 | Real-data test harness & CI (`tests/harness/`) | `ci-offline.yml` real and green on every push; `ci-live.yml` real and green, run [31493546100](https://github.com/m-reynaldo35/eth-avm-light-client/actions/runs/31493546100) (643 passed/1 skipped/2 deselected) | — |
| M12 | Docs & packaging / release prep | `v1.0.0` tagged, all nine release-readiness rows closed (`docs/release.md`) | — |
| M13 | T2 receipt proofs against an M8 anchor, and the T1 migration onto the same permanent contract | real mainnet, `Mpt7AnchoredReceiptApp` app `3670553866`; both T1 and T2 proved end-to-end through the live, real-USDC-paid production service | — |
| — | Live monitoring | `.github/workflows/monitor.yml` checks the live service and mainnet apps every 30 minutes, alerts via a real GitHub issue | see M8's row above for the one thing it doesn't cover |

## Install

**As a library/CLI** (the untrusted off-chain client — see
[`docs/security.md`](./docs/security.md) for what "untrusted" means here):

```
pip install eth-avm-relayer
```

This installs only `relayer/` and its four real runtime dependencies
(`py-algorand-sdk`, `rlp`, `pycryptodome`, `py_ecc` — measured: ~20
packages total in a clean venv, down from 59 before this release, see
`CHANGELOG.md`). **It does not contain the Algorand contracts** — the
wheel has zero non-`.py` files and the verifier is bytecode already on
Algorand, not something this package ships (§4.2). Two verbs need more
than the wheel provides and raise a named error if you reach them without
it: `prove_receipt(against_anchor=True)` and deploying the donor pair —
see the checkout path below.

**As a checkout** (contracts, the deploy tool, and the two verbs above):

```
git clone https://github.com/m-reynaldo35/eth-avm-light-client
cd eth-avm-light-client
pip install -e ".[test,contracts]"
```

`contracts` pins `puyapy==5.9.0` exactly — **do not** `pip install puya`,
which fetches a different, incompatible package (a real trap this project
hit once, 007 §14.6).

The `service` extra (`pip install -e ".[service]"`) is for
`service/x402_endpoint/`'s own FastAPI dependencies, not for `relayer/`
itself — `relayer/` imports none of them, enforced by an AST-based test.

## Quickstart

```
eth-avm-relayer status
# or, from a checkout:
python -m relayer status
```

Reads M4/M8's real, live, currently-anchored state from the deployment
named in the committed manifest below. Needs no signer and sends nothing —
this is the CI/audit path (see [`docs/quickstart.md`](./docs/quickstart.md)
for every other verb, both CLIs' real `--help` output, and what does and
does not need a checkout).

## Live deployment

The only mainnet deployment this project currently makes any claim about
is `Mpt7ReceiptApp` and its donor pair — recorded, byte-for-byte verifiable,
in [`deploy/manifests/mainnet-v1.0.json`](./deploy/manifests/mainnet-v1.0.json):

| contract | app id | code id (approval sha256) |
|---|---|---|
| `Mpt7ReceiptApp` | `3665914633` | `f7a846ff33314d8f9ecc48e85584327f13e9cb808a3650b30e69339c7fcdc9d2` |
| `DonorIssuer` | `3666047636` | `e9a262c034240536a1fc65f5fd832d032b4e21984219d9b9792f607d2a8e13fd` |
| `DonorCallee` | `3666047587` | `ed90f0d2da1f1d1abd773c45230651a292a90edbc12a7bf859a493a12a640ce7` |

Anyone can independently confirm the bytecode running at these app ids is
the bytecode this repository's CI diffs on every push, with no signer and
no repo access beyond a checkout:

```
python -m deploy verify --target deploy/targets/mainnet.json
python -m deploy resolve --network mainnet --fork fulu --json
```

`M4`/`M8`/`M6` are **not** deployed to mainnet (`deploy/targets/mainnet.json`
declares `"deploy": false` for all three) — a multisig/hardware governance
signer is a precondition this repository does not waive, see
[`docs/operating.md`](./docs/operating.md). **A scheduled check runs every
30 minutes** (`.github/workflows/monitor.yml`) against both the live
service's `/health` and `deploy verify` against this mainnet target, and
files a real GitHub issue on a genuine failure — see
[`docs/security.md`](./docs/security.md) for exactly what that does and
does not cover (there is still no uptime target and no on-call rotation).
A `CODE_MISMATCH` verdict from `resolve` means the app was reprogrammed
out from under this record; treat it as loud and final, never as a
warning.

## Supported forks

`SyncCommitteeVerifier` and `TrustedRootAnchor` support **Deneb, Electra,
and Fulu** (`deploy/forks.py::FORK_FIELD_COUNTS`). **Gloas is explicitly
not supported** — for two different, measured reasons, not one: M4's
depth-11 sync-committee branch (738 opcode budget) exceeds the 700
single-call limit its current install flow assumes, and M8's depth-11
execution-layer branch pushes its `HISTORICAL` mode's argument payload over
the AVM's hard 2,048-byte cap. `deploy` refuses, client-side, to build an
`append_fork_row` call for Gloas on either contract — this is a tool-side
refusal only; a governance key holder using a raw client bypasses it. See
[`docs/versioning.md`](./docs/versioning.md) for the full three-axis scheme
and the fork decision table this repeats in miniature.

## What this does not do

- **No T3/ZK tier ships.** No prover, no trusted-setup provisioning, no
  circuit differential corpus. About 2.2% of real receipts (of a 94,667-
  receipt, 300-block sample, `tests/fixtures/spike-reference/coverage_sample_300blocks.json`)
  need it and currently cannot be proven on-chain by this project. **No T3
  coverage percentage is published here or anywhere under `docs/`** until a
  real proof exists at the deployed tier (007 §10).
- **The receipt-leaf size problem is real, not a naive-approach artifact.**
  A log-heavy Ethereum receipt can RLP-encode past the AVM's 4,096-byte
  stack-value cap — it can't even be pushed to the stack, let alone hashed,
  with a naive approach. Software hashing is possible at a measured 109.2
  opcode-budget/byte (007 §2.4), and the tiered T1/T2 split (007 §3.1) is
  how this project actually closes the gap for everything except the T3
  slice above. `tests/fixtures/spike-reference/MPT_RESULTS.md` §5.3 predates
  that split and is preserved unmodified as the original spike record.
- **The code-window guard (Gloas exclusion, above) is tool-side only.** It
  is not enforced on chain; a contract change would be needed to close that
  gap (`O-M12-1`).
- **CI never touches the mainnet deployment.** `deploy verify` can, and is
  documented as runnable — but it is a command a human runs, not a job that
  runs itself.
- **Monitoring is a 30-minute scheduled check, not an on-call program.**
  `.github/workflows/monitor.yml` checks the live Vercel service's
  `/health` and `deploy verify` against the mainnet apps, alerting via a
  real GitHub issue on genuine failure (see `docs/security.md`). M8's
  equivocation latch (`conflict != 0`) is still not covered — a real,
  named gap, not folded into this workflow's scope.
- See [`docs/release.md`](./docs/release.md) for the full, dated
  release-readiness checklist this release was cut against, including
  every open gate above stated with its measured numbers.

## Costs (measured, not projected, unless noted)

- Full account+storage proof (spike figure, `tests/fixtures/spike-reference/`):
  ~6,827 opcode budget / 0.010 ALGO, ~27x headroom in a single atomic group.
- M5's own, later, security-fixed measurements (different code, different
  numbers — see the status table above): 5,116 opcode 8-node account walk,
  1,813 opcode 3-node receipt walk.
- A 512-key sync-committee update fits in one 16-transaction atomic group.
- `SyncCommitteeVerifier` compiles to 6,980 B — 85.2% of the 8,192 B
  per-application bytecode cap, leaving 1,212 B of headroom for a future
  fork's code change before it cascades into every M8 consumer.
- A testnet deploy-and-drive run (this release's own acceptance gate) is
  **projected** at ≈24–32 ALGO of test tokens locked, depending on
  `ring_n`, plus ≈0.03 ALGO in fees — see `docs/release.md`.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) and
[`docs/release.md`](./docs/release.md) for the release process.

## Design docs

Every module has a design doc under [`docs/design/`](./docs/design/),
each stating what in it is `measured` versus `projected` at design time —
see [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the standing engineering
decisions that apply across all of them.

## License

MIT — see [`LICENSE`](./LICENSE).
