# Contract versioning

This page is `ARCHITECTURE.md`'s "Contract versioning" section, written
long-form for a consumer rather than a reviewer. The full design reasoning
lives in
[`docs/design/012-docs-packaging-release.md`](./design/012-docs-packaging-release.md)
§3; this page states the scheme and how to use it.

## Why not semver

A semver string answers "did the API change." A consumer of this project
actually needs to know four different things: is the bytecode at a given
app id the bytecode I audited; which Ethereum forks can it verify, and is
that the same as what its operator has told it about; which AVM/protocol
version were its opcode budgets measured against; and if I compile against
it, what breaks when it is redeployed. Semver answers none of these.

A hand-maintained version number is also precisely the artifact class this
project has already measured going wrong: a prior pass found three real
prose-vs-code drifts (a global key named `ring_n` in prose vs. `ring_size`
on chain; a box documented at 321 B and shipped at 320 B; a creator MBR
documented at 378,000 µALGO against a real 406,500) simply by generating a
schema instead of writing one by hand. So the rule here is the same one:
**generate, never type.** Every identifier below is a value CI already
computes and diffs byte-for-byte on every push — never a number a human
increments.

## The three axes

| axis | what it pins | mutable after deploy? | where it lives |
|---|---|---|---|
| **A — AVM / protocol** | `avm_version`, and the `go-algorand` build every budget/cap in this repo was measured against | no (bytecode) | `avm_version: 10` in every `deploy/schema/*.schema.json`; the build is pinned in `.github/workflows/ci-live.yml`'s `ALGOD_IMAGE` comment (`go-algorand 4.7.4, commit 91cbddcd, rel/stable`) |
| **B — consensus fork** | which Ethereum forks a deployment can verify | partly — see below | `contracts/*/forks.py` tables (on chain, mutable) and the bytecode's structural limits (immutable) |
| **C — proof system** | for a future ZK tier only: `(circuit source, gnark version, curve, setup, verifying key) → logicsig address` | no | nowhere — **empty in this release**, because no ZK tier ships (`O-M9-1`) |

Axis B is two windows, not one, and this is the part worth understanding
carefully:

- The **table window** is what a specific *deployment's* on-chain fork
  table currently says. It is mutable, governance-gated, append-only, and
  per-deployment.
- The **code window** is what the *bytecode* can structurally execute. It
  is immutable and per-bytecode.
- **The effective supported range is their intersection, and nothing on
  chain computes that intersection.** `append_fork_row` validates epoch
  monotonicity, a sentinel, and table capacity — **not the gindices at
  all**. A row for a fork the bytecode cannot execute is appendable today
  and would fail at `submit_update`/`anchor_historical` time (a budget or
  argument-size rejection), not at governance time when a human is
  watching. `deploy` closes the part of this it can: it refuses,
  client-side, to build an `append_fork_row` call for a fork in a
  contract's `code_window.unsupported`. **This refusal is tool-side only.**
  A governance key holder using a raw client bypasses it entirely; closing
  that properly needs a chain-side bound, which is a contract change and
  is not part of this release (`O-M12-1`).

M3 (the SSZ/gindex layer) needs no fork axis at all: `gindex` is a runtime
parameter and M3 contains no fork-conditional code. A consensus fork that
only moves a gindex is a table update to M4/M8, never an M3 redeployment.
M2, M5, M6, and M7 join M3 on the AVM-only side for a structural reason of
their own: they verify execution-layer RLP and Merkle-Patricia-Trie
encodings, which no consensus fork has moved.

## What a new Ethereum fork actually costs, per contract

| fork event | M1/M2/M3/M5/M6/M7 | M4 `SyncCommitteeVerifier` | M8 `TrustedRootAnchor` | consumers compiled against M8 |
|---|---|---|---|---|
| a fork moves a gindex, depth unchanged | nothing | one `append_fork_row`, ~1,000 µALGO | one `append_fork_row`, ~1,000 µALGO | nothing |
| a fork deepens a branch past a *budget* ceiling (e.g. a depth-11 sync-committee branch at 738 opcodes, over the 700 single-call limit) | nothing | table row + a relayer group-sizing change; no redeploy | see next row | nothing |
| a fork deepens a branch past an *argument-size* cap (e.g. a depth-11 execution-layer branch over the hard 2,048 B app-arg cap) | nothing | — | **redeploy** — a structural change, not a table row | **recompile and redeploy all** — `ANCHOR_APP_ID` is a compiled-in immediate |
| a fork restructures the proof entirely | nothing | table row | **redeploy** | **recompile and redeploy all** |
| the fork table fills (M8: 8 rows, ~4 years at mainnet's historical fork rate; M4: 16 rows, ~8 years) | nothing | redeploy once full | redeploy once full | recompile and redeploy all |
| a wrong row was appended | nothing | **redeploy** — append-only, no editor, no deleter | **redeploy** | recompile and redeploy all |

**In-place table update is the ordinary case and covers every fork this
project has actually seen.** The boundary between "table update" and
"redeploy" is a measured budget or protocol-cap boundary, not a spec
boundary, and it is per-contract — which is why the two contracts carry
*different* code windows below, and why a single project-wide "supported
forks" list would be a lie.

## The standing budget: `SyncCommitteeVerifier`'s 1,212-byte headroom

`SyncCommitteeVerifier` compiles to **6,980 bytes — 85.2% of the 8,192 B
per-application bytecode cap**, leaving **1,212 bytes** of headroom. A
future fork that requires an M4 *code* change (not just a table row) has
1,212 bytes to fit in. If it does not fit, the change cascades into M8
(whose `m4_app_id` is write-once) and from there into every M8 consumer,
whose `ANCHOR_APP_ID` is a compiled-in immediate (`consumers_bound_at_compile_time`
in `deploy/versions.json`). This number is generated fresh into
`versions.json`'s `bytecode_cap_headroom_bytes` field every time the schema
is regenerated — never hand-copied.

## The real, current fork range — and the correction it replaces

**Deneb, Electra, Fulu** (`deploy/forks.py::FORK_FIELD_COUNTS = {"deneb":
28, "electra": 37, "fulu": 38}`, and every `deploy/targets/*.json`).
`ARCHITECTURE.md` originally guessed "Altair/Capella/Deneb" before the
range was known from M3/M4 — that guess is now corrected in both
`ARCHITECTURE.md` and here. **Gloas is excluded on both M4 and M8**, for
the two different reasons in the table above, each cited in
`deploy/versions.json`'s `code_window.reason` field for its contract.

## `deploy/versions.json` — reading it

Generated by `python -m deploy schema` (the same command that regenerates
the four contract schemas), committed, and diffed by `ci-offline.yml`'s
`contracts` job on every push. Its primary key per contract is `code_id`
(the approval-program SHA-256) — never hand-typed, always read from the
same pinned artifact `deploy verify` checks against chain state, which is
why a version and a verification can never disagree.

```jsonc
{
  "versions_version": 1,
  "release": null,               // the ONE hand-set field; set at tag time by docs/release.md
  "avm": {"version": 10, "measured_against": "go-algorand 4.7.4 (91cbddcd, rel/stable)"},
  "contracts": {
    "TrustedRootAnchor": {
      "code_id": "9b790b33f2116a5ccbbe07ce2d9ac040c8c1897c695ca2725b7d99956522d57d",
      "fork_axis": "table",
      "code_window": {"supported": ["deneb","electra","fulu"], "unsupported": ["gloas"], "reason": "..."},
      "consumers_bound_at_compile_time": true,
      "redeploy_cascades_to": ["every M8 consumer"]
    }
    // ... SyncCommitteeVerifier, Mpt7ReceiptApp, Mpt6ComposerApp, MptSegmentApp, DonorIssuer, DonorCallee
  }
}
```

`fork_axis: "none"` is an **asserted claim**, not an omission — a test
greps that contract's source for any fork-table constant to make sure the
claim cannot rot silently (Suite V, `tests/harness/test_versions.py`).

## Discovery: `deploy resolve`

```
python -m deploy resolve --network mainnet --fork fulu --json
```

Read-only, needs no signer, and refuses rather than guesses. Four
verdicts:

- **`USABLE`** — deployed, and its live approval hash matches the pin.
- **`NOT_DEPLOYED`** — not present in this network's manifest.
- **`FORK_UNSUPPORTED`** — the requested fork is outside this contract's
  code window (a property of the bytecode, checked even for a contract
  that is not deployed anywhere on the network).
- **`CODE_MISMATCH`** — deployed, but the live approval hash is not the
  pinned one. **Always exits non-zero.** This is the only signal that
  distinguishes "the app you audited" from "an app that happens to be at
  that id today" (010 §9.1 proved by direct experiment that this can
  happen to an unrestricted contract; a mainnet app in this very project
  has already gone from live to nonexistent between two measurements).

Layer 1 (the table window) is `deploy inspect --target <t> --app m4|m8 --forks`,
which decodes the on-chain fork table directly. Layer 2 (the code window)
is the `code_id` pin above. Layer 3 (which app id is "ours") is the
committed manifest — see [`docs/operating.md`](./operating.md).

## Two version numbers that must never be conflated

| number | what it versions | who sets it |
|---|---|---|
| `[project] version` in `pyproject.toml` | the **Python distribution** (the client library and CLI) | a human, ordinary semver, at release time |
| `versions.json`'s `code_id` per contract | the **deployed bytecode** | generated from the compiled artifact |
| `versions.json`'s `release` | the tag that ties the two together, for a given snapshot in time | the release runbook, once, at tag time |

A client at a newer semver talking to bytecode cut at an older tag is a
normal, supported situation — the ABI is frozen by the contracts'
bytecode, not by the Python package version. `versions.json.release` is
the only field that ever claims the two were cut together, and only at
that one moment.
