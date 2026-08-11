# Security and trust model

This page exists so [`README.md`](../README.md)'s own trust-model
paragraph can stay three sentences. Read this before depending on anything
in this repository for anything that matters.

## TP-M8-1 — the trust model, in full (008 §5.3, normative per §15.6)

**"Verified on Algorand" means the Ethereum sync-committee light-client
trust model, not full-node security.** Concretely:

- Sync-committee messages are **not slashable**. There is no economic
  penalty on Ethereum's consensus layer for a sync-committee member
  signing something false.
- A **2/3 majority of the current 512-member sync committee can sign a
  lie at no on-chain cost**, and this project's contracts have no way to
  detect that on their own — detection is an off-chain, social process
  (independent full nodes, block explorers, other light clients disagreeing)
  exactly as it is for every other Ethereum light client.
- This is **Ethereum's own light-client trust model**, not a defect
  specific to this implementation. Running a full Ethereum node gives you
  a strictly stronger guarantee than any light client, including this one.
- Therefore: **"verifier"** in this project's name and documentation means
  "verifies a BLS aggregate signature and a Merkle-Patricia-Trie inclusion
  proof against a root that a sync committee attested to" — not "makes
  Ethereum state trustless to depend on." Treat any sentence that implies
  otherwise as a bug in the documentation, not a claim about the contracts.

## Component-by-component trust, inherited from each module's own design doc

| component | trust status | what that means |
|---|---|---|
| M1–M8 (the on-chain contracts) | **the verifier.** Bytecode on Algorand; the thing this project actually ships trust in, bounded by TP-M8-1 above. | An app id's `code_id` (approval-program SHA-256) is the only thing that identifies which bytecode you are trusting — see [`docs/versioning.md`](./versioning.md). |
| M9 `relayer/` (009 §1.3) | **untrusted.** It assembles proof shapes and submits transactions; the contracts re-derive and check everything it claims. | A malicious or buggy relayer can waste your fees or fail to advance state; it cannot make the contracts accept a false root. |
| M10 `deploy/` (010 §1.3) | **trusted** — the one trusted component in this project. | It runs governance calls (fork-row appends, ring init, funding) with a real signer. Its own manifest is *not* a trust anchor (010 §9.5, below); `verify` re-derives from chain state. |
| M11 `tests/harness/` (011 §1.3) | **claim-making.** A green CI run is evidence a claim held at the moment it ran, on the fixtures/network it ran against — nothing more, nothing that transfers to a later day. | See "what a green tick means" below. |
| M12 (this documentation) | **claim-*publishing*.** Strictly worse than claim-making: the reader has no repo context and will not read design docs to find a caveat. | Every mechanism on this page and in `tests/harness/test_doc_claims.py` (Suite N) exists because of this. |

## What a green tick means

- **`ci-offline` green** (the badge on the README): pure computation against
  committed, pinned fixtures passed on the latest push. It never touches a
  live network and its result does not expire with the date.
- **`ci-live` green**: a real run, on a real day, against real public
  Ethereum RPC/beacon endpoints and a real dev-mode Algorand node, passed.
  It has a date on it. A release cites the specific run id it relied on
  (`CHANGELOG.md`) rather than asserting "CI passes" as a standing fact.
  `README.md`'s badge intentionally does not point here.
- **A quarantine entry** (`tests/harness/quarantine.toml`) is a **known,
  unproven claim with an expiry date** — not a passing test and not a
  hidden one. See `CHANGELOG.md` for the current entry.

## The manifest is a pointer, never a truth (010 §9.5)

`deploy/manifests/*.json` records "this app id is the one we mean" — it is
**not signed and not authoritative**. `deploy verify`/`deploy resolve`
re-derive everything they can from live chain state and the pinned
`code_id`; a tampered or stale manifest produces a `verify` **failure**,
not a silent redirection. That property is the entire reason a manifest is
safe to commit at all.

## `CODE_MISMATCH` is the single most important failure mode to understand

`deploy resolve`'s four verdicts include `CODE_MISMATCH`: the live
approval program at a recorded app id no longer hashes to the pinned
`code_id`. This is not hypothetical — this project has already had a
mainnet app (`3664247481`, the pre-fix `Mpt7ReceiptApp`) go from "live and
exploitable by anyone" to "does not exist" between one measurement and the
next, and separately proved by direct experiment that an
`on_completion_gate: "unrestricted"` contract can be reprogrammed by any
account for one transaction fee (010 §9.1). `CODE_MISMATCH` **always exits
non-zero and is never downgraded to a warning** — it is the only signal
that distinguishes "the app you audited" from "an app that happens to be
at that id today."

## The code-window guard is tool-side only

`deploy` refuses, client-side, to build an `append_fork_row` call for a
fork listed in a contract's `code_window.unsupported` (currently Gloas, on
both `SyncCommitteeVerifier` and `TrustedRootAnchor`) — see
[`docs/versioning.md`](./versioning.md). **This is enforced by the tool,
not the chain.** A governance key holder submitting `append_fork_row`
directly through any other client bypasses this refusal entirely. Closing
that gap needs a chain-side gindex/depth bound, which is a contract change
and is out of scope for this release (`O-M12-1`).

## Nothing is monitored

Stated plainly, once, so it does not need restating elsewhere: **no
automated system watches the live mainnet app, the live Vercel service at
`https://x402endpoint-nu.vercel.app`, or `TrustedRootAnchor`'s equivocation
latch (`conflict != 0`, which 009 §8.5 classifies `PAGE_A_HUMAN`).** There
is no health check, no alerting, no uptime target, and no owner on call.
This is why Bazaar discovery registration was declined for this release
(a directory listing is a stronger availability claim than this project
can currently back) — see `CHANGELOG.md`.

## Known live findings (014): one fixed everywhere, one fixed in source only

Two real defects in already-shipped code were found while building [014
(T2 receipt proofs against an M8 anchor)](design/014-t2-against-anchor.md),
disclosed here explicitly rather than buried inside a new module's own row:

**`AnchorReceiptProbe` had no `on_completion` guard (fixed, `bd3f2a7`).**
`contracts/state_anchor/bench_app.py`'s `AnchorReceiptProbe` — the only
mechanism that drives `prove_receipt(against_anchor=True)` on a T1 leaf —
was missing the `assert Txn.on_completion == NoOp` guard every other bench
app in this repo carries. Live-verified: `UpdateApplication` with an
always-approve program was **accepted**. Because `EthAvmClient` deploys a
fresh probe in one transaction and submits the real proof group in a
*separate* one, this was a real, observable, exploitable window on
mainnet — any account could hijack the probe between the two and have a
fabricated `MODE_AGAINST_ANCHOR` log accepted as a proven Ethereum fact,
bypassing every other check in the chain (BLS, SSZ, the keccak hash chain,
`ANCHOR_APP_ID`'s compile-time binding — none of them run if the program
itself is not the one you audited). Fixed with the standard one-line guard;
re-verified live (`UpdateApplication`/`DeleteApplication` both rejected).

**`mpt7_stage_open` had no box-name squatting protection (fixed
everywhere, `2026-08-11`).**
`contracts/receipt/box.py::mpt7_stage_open` called `op.Box.create` without
first deleting any pre-existing box under the same (permissionless, by
design — see [014 §7.1](design/014-t2-against-anchor.md)) name. Since
`box_create` fails hard on a size mismatch, anyone could pre-create a box
at the wrong size under a name the driver was about to use and break every
honest T2 proof that picked it. Fixed (delete-before-create) in this
repo's source tree, and the off-chain box-name derivation
(`relayer/drivers/m7_receipt.py::derive_t2_box_name`) now adds a block
component and a random nonce so a name can no longer be pre-computed
either. The original live mainnet `Mpt7ReceiptApp` (`3665914633`) could not
receive this fix in place — its own `on_completion` guard (the fix above,
applied everywhere the same day) makes it permanently un-updatable — so a
fresh app was deployed instead: **`3670577356`**, compiled from this fixed
source, `deploy verify` reports `OK`. The old app `3665914633` is
abandoned (still live on-chain, still squattable in principle, but no
longer referenced by any manifest, service config, or this project's own
tooling) rather than deleted, since a bare `Contract` has no delete-and-
recover path for its retained MBR.

## `deploy verify`'s M4 slack-balance finding (expected, not a bug)

`deploy verify` reports mainnet M4 (`3670310452`) with 366,100 µALGO of
"unexpected slack" above its own minimum balance (§10.4/G8-M10's stranded-
funds check). Root cause, confirmed against real account state: M4 was
funded to `20,227,000` µALGO — `deploy/plans/m4.py`'s `FUND_STAGE_MICROALGO
["install"]`, the *install-time peak* MBR requirement (§4.1's MBR table),
which must be met **before** a committee install can run at all, since
Algorand requires the balance to already cover a transaction's requirements
at submission time, not after. Once that real install completed and
settled, the *steady-state* minimum dropped to `19,860,900` — the
difference, `366,100`, is unavoidable slack, not a funding-calculation
error: there is no way to fund exactly the steady-state amount and still
have enough headroom for the transient peak the install itself requires.
Per §10.4, a bare `Contract` app account has no withdrawal path, so this
slack is permanent. `deploy verify`'s `FAIL` here is the tooling correctly
reporting a known, structural cost of the install mechanism — not a
regression to fix.

## Packaged wheel vs. checkout

The published `eth-avm-relayer` wheel contains only `relayer/` — 35 `.py`
files and zero data files (measured). It is the **untrusted off-chain
client** described above, not the verifier, and it does not contain any
Algorand bytecode. `prove_receipt(against_anchor=True)` and deploying the
donor pair need a source checkout with `puyapy` on `PATH` and raise a
named `MissingContractsSource` error (not a bare `FileNotFoundError`) if
reached from a wheel-only install — see
[`docs/quickstart.md`](./quickstart.md).
