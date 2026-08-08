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

## Packaged wheel vs. checkout

The published `eth-avm-relayer` wheel contains only `relayer/` — 35 `.py`
files and zero data files (measured). It is the **untrusted off-chain
client** described above, not the verifier, and it does not contain any
Algorand bytecode. `prove_receipt(against_anchor=True)` and deploying the
donor pair need a source checkout with `puyapy` on `PATH` and raise a
named `MissingContractsSource` error (not a bare `FileNotFoundError`) if
reached from a wheel-only install — see
[`docs/quickstart.md`](./quickstart.md).
