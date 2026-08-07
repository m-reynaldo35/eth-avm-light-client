# 010 — M10: Deployment & box-storage schema tooling

**Status**: Design drafted, awaiting human review.
**Depends on**: M4, M6, M7, M8 (the four deployable contracts) and M9 (the
relayer that drives them) — all five now **implemented, live-proven against
real mainnet data, and committed** (`git log`: `028e18e`, `1148ae4`, `86a5e87`,
`35f64e6`, `83b4fb8`, `6b88acb`). Their box schemas, global-state schemas,
governance surfaces and creation-order constraints are frozen by their *code*,
not by their design docs, and this document targets the code.
**Consumed by**: M11 (real-data harness & CI — a from-scratch deploy is what
`ci-live.yml` needs before it can assert anything), M12 (release: the README's
quickstart is a deployment), the x402 service, and a human operator.
**Design-time convention, inherited**: every number below is labelled
**measured** (a real `simulate`/`send`/`account_info` response, cited to where
it came from) or **projected** (an estimate this document owns, which an
implementation pass must replace with a real response). `ARCHITECTURE.md`'s
rule applies unchanged.

> **Numbers new to this document.** §4, §10 and §9 contain measurements taken
> *while writing this design doc*, against the same real dev-mode algod at
> `localhost:4051` this project has used all along, with `puyapy` 5.9.0. They
> are labelled **measured (this pass)**. Three of them contradict numbers
> currently in the repo's own docs, and one of them is a live security defect
> in a contract that is **deployed on Algorand mainnet right now**. Those are
> §3.3, §9.1 and §10.4.

---

## 0. The question, stated first

M9 asked "is this a refactor or a build?" and answered *both, split cleanly*.
M10 has to answer the same question, because the same trap is set: a great deal
of real, working deployment logic exists in this repo already, and none of it
is a deployment tool.

Five separate places already compile a contract with `puyapy`, hand the TEAL to
algod, and create an application:

`tests/sync_committee/conftest.py`, `tests/state_anchor/conftest.py`,
`relayer/group/donors.py`, `relayer/client.py::_deploy_anchor_receipt_probe`,
and `bench/composer_bench.py`. Between them they have deployed
`SyncCommitteeVerifier` **168 times** and `TrustedRootAnchor` **448 times** on
the local dev network (**measured (this pass)**: counted by matching
approval-program SHA-256 against the creator accounts' `created-apps` lists).
Every one of those deployments was ad hoc, none produced a durable record of
what was deployed, and two of them over-fund the app account by more than an
order of magnitude.

So the scoping question is:

> **Is M10 (a) a thin CLI over logic that already exists, (b) genuinely new
> engineering, or (c) both — and where exactly does the line fall?**

**The answer, stated up front, and defended in §2:**

> **(c) — both, and the split is unusually clean, because the two halves do not
> even share a failure mode.**
>
> **The thin half (~40% of the work): promotion.** Compiling with `puyapy`,
> compiling TEAL through algod, funding an app account, building an
> `ApplicationCreateTxn` with the right `extra_pages` and box references,
> issuing a governance call, deploying the `DonorIssuer`/`DonorCallee` pair —
> all of this exists, works, and has been exercised hundreds of times. M10
> promotes it into `deploy/` and deletes the copies it can.
>
> **The new half (~60% of the work): three things that exist nowhere.**
> 1. **A generated, versioned schema artifact** (§3) — a machine-readable
>    description of every box family, global-state key, record layout and MBR
>    cost, **generated from the contracts' own `constants.py` rather than
>    hand-written**, so it cannot drift. This is the plan's own "concrete
>    schema for M8/M4 state", and §3.3 shows it would already have caught three
>    real doc-vs-code drifts that exist in this repo today.
> 2. **A deployment manifest plus a converge-by-diff engine** (§7) — the
>    idempotency/resumability story. The finding here is that **deployment
>    already has on-chain cursors** (`ring_cursor`, `fork_count`, the box list,
>    `min-balance`), and the *only* fact that is not recoverable from chain
>    state is the app id itself. So the manifest records identity and nothing
>    else, and §7.4 shows even identity is recoverable by approval-program hash.
> 3. **A fork-row generator** (§5.5) — every gindex derived from real SSZ field
>    lists, never typed by a human. 008 §15.4 item 2 demands this; §5.5 shows
>    it is ~30 lines on top of `relayer/ssz/`, and reproduces all seven real
>    gindices this project has independently confirmed.
>
> **And one thing M10 must decide rather than inherit** (§6.4): whether it
> owns redeploying, upgrading or monitoring the **live mainnet app id
> `3664247481`**. It does not — but not for the reason anyone expected. §9.1
> establishes, by real live experiment, that that contract can be
> **hijacked or destroyed by any account on Algorand**, so "responsible
> upgrade tooling" for it is the wrong question; the right one is whether it
> should be deployed to mainnet again at all in its current shape.

**Three things this document has to get right**, in order of how much damage
getting them wrong does:

1. **The gindex/fork-table seeding path** (§5.5, §9.2). A wrong `g_receipts_root`
   in M8's fork table produces a *valid-looking* anchor over the wrong 32 bytes,
   which then authenticates every downstream receipt proof. **This is the single
   highest-leverage attack surface in the entire project, and it lives in M10**,
   not in any contract. It must be generated and cross-checked, never typed.
2. **The funding recipe** (§7.1). Box MBR is charged to the *app account*, whose
   address is not knowable until the create transaction confirms. The recipe
   this repo uses today works on a quiet devnet and is a real, unbounded
   financial risk on a public network. §7.1 replaces it with a measured
   two-stage recipe that bounds a lost race to 0.3349 ALGO.
3. **Being honest that M10 is trusted** (§1.3). M9's document opens by
   insisting the relayer is untrusted. M10 is the exact inverse: it is the one
   component in this project whose mistakes are not caught by anything
   downstream.

---

## 1. Scope, non-goals, trust preconditions

### 1.1 In scope

1. **Compiling and deploying** the four deployable contracts —
   `SyncCommitteeVerifier` (M4), `Mpt6ComposerApp` (M6), `Mpt7ReceiptApp` (M7),
   `TrustedRootAnchor` (M8) — plus the `DonorIssuer`/`DonorCallee` budget pair
   M4/M7/M8's groups need (§5.6).
2. **Funding** each app account to its real, computed minimum balance, at each
   lifecycle stage, with the app-id-prediction problem handled safely (§7.1).
3. **Opening the boxes deployment owns**: M8's ring (`ring_init_chunk` × ⌈N/8⌉)
   and both fork boxes (created by `create()` itself). **Not** M4's committee
   key boxes — those belong to an install session, which is M9's (`§1.2`).
4. **Seeding governance state**: both fork tables, with generated gindices;
   confirming the `gov` address is the intended one and not the deployer's.
5. **A versioned, generated box/state schema artifact** (§3), consumable by a
   deploy tool, a monitoring tool, M11's CI, or a future auditor, without
   reverse-engineering `constants.py`.
6. **A deployment manifest** and an idempotent, resumable `plan`/`apply`/
   `verify` cycle over it (§7, §8).
7. **Inspection**: decode a deployed app's real global state and real boxes
   through the schema (§8.3). This is what makes a deployment auditable by
   someone who did not perform it.

### 1.2 Non-goals (explicit)

- **No contract changes.** M10 compiles `contracts/` unmodified. The one
  exception is the compile-time constant patch TP-M8-4 *requires* of every M8
  consumer (`handoff.ANCHOR_APP_ID`), which is a build-time substitution into a
  temporary copy — the mechanism `tests/state_anchor/conftest.py::patched_repo_copy`
  and `relayer/drivers/m7_receipt.py::patched_probe_source` already implement
  (§5.7). M10 never edits a file in `contracts/` in place.
- **No committee install.** M4's `bootstrap` → `install_open_keys` →
  `install_open_session` → 64 × `install_chunk` → `install_finalize` sequence is
  **M9's**, driven by `EthAvmClient.sync(install=True)`, and it is already
  live-proven end to end (M9's G2-M9, four fresh 512-member installs). M10 stops
  at "funded, governed, and ready for M9 to drive". 009 §15.4 draws the line in
  exactly this place and this document keeps it there.
- **No anchoring, no proving, no relaying.** M10 never calls `anchor_*`,
  `submit_update`, or any M5/M6/M7 walk mode.
- **No trusted-setup provisioning for T3/ZK.** 007 §8.4 assigns M10 the PPOT
  ceremony fetch-and-checksum and the ≈537 MB proving-key conversion. **Deferred
  with T3 itself** (§15, `O-M10-1`), on the same grounds M9 deferred T3 proving:
  provisioning an 18 GB ceremony for a tier no shipped code can prove is dead
  weight. The requirement is recorded, not silently dropped.
- **No T2 box sweeper.** 007 §8.4 asks for one; §11.6 shows it cannot currently
  be needed (T2 opens and closes its box inside one atomic group), and §8.3's
  `inspect --boxes` reports any anomalous staging box rather than sweeping it.
  Same treatment 008 §15.4 item 5 gave M8's own non-existent sweeper.
- **No key custody.** M10 takes an `algosdk`-compatible signer or none at all.
  `plan` and `verify` work with **no signer configured** (§8.2) — measured
  (this pass): `SimulateRequest(allow_empty_signatures=True)` returns both the
  app id that would be assigned and the exact min-balance shortfall, with no key
  anywhere.
- **No app registry contract.** A runtime-resolvable app-id registry is
  rejected for v1 (§15, `O-M10-5`): TP-M8-4 deliberately requires consumers to
  bind the anchor app id at *compile* time, and a registry would reintroduce
  precisely the substitution attack that binding exists to prevent.
- **No mainnet deployment in v1's acceptance gate.** §6.4 and §15 gap 3.

### 1.3 Trust preconditions — M10 is trusted, and this is not a footnote

009 §1.3 opens by establishing that M9 is untrusted, and lists, mechanism by
mechanism, what stops a lying relayer. **M10 is the inverse**, and the honest
statement is uncomfortable:

> Every guarantee M1–M8 provide is conditional on the deployed artifact being
> the audited artifact, with the right fork table, the right governance key,
> the right `m4_app_id`, and consumers compiled against the right anchor id.
> **Nothing downstream re-checks any of those.** M10 is where they are decided.

| M10 decides | What re-checks it | Consequence if M10 is wrong |
|---|---|---|
| Which bytecode is deployed | **Nothing on-chain** | The whole project is decorative |
| M8's `m4_app_id` | Nothing — TP-M8-7 states plainly that M8 cannot verify on-chain that `m4_app_id` is really M4 | M8 anchors against an attacker's "finality" |
| Fork-table gindices | The on-chain fold verifies *against the supplied gindex*; it cannot know the gindex is wrong (008 §12.6, `N9` checks only the branch's length against the gindex) | A structurally valid proof over the **wrong 32 bytes** of the beacon state |
| `gov` address | Nothing | Governance can `revoke`, `freeze`, or (M8) `renounce` |
| `ring_n` | Write-once at create, no setter (asserted in `test_core.py`) | Wrong `N` ⇒ redeploy; **no resize exists**, by design (008 §6.2) |
| Consumers' compiled-in `ANCHOR_APP_ID` | The consumer's own `N2` check — against whatever id it was compiled with | A consumer bound to a fake anchor verifies nothing |
| `genesis_validators_root` (M4) | Write-once at create, no setter | Every signing root is computed against the wrong domain |

**Three mitigations, all of which are M10's own deliverables**, because there is
nowhere else to put them:

1. **Generate, never type** (§5.5). Every gindex, every box name, every size
   comes from code that also produced the contract's own constants.
2. **Verify the counterparty by program hash** before binding to it (§5.4):
   before calling M8's `create(governance, m4_app_id, ring_n)`, fetch
   `application_info(m4_app_id)` and assert its approval program hashes to the
   pinned `SyncCommitteeVerifier` hash. This turns TP-M8-7's "the deployer must
   check" from a sentence in a design doc into a line of code that fails closed.
3. **`deploy verify` is runnable by anyone** (§8.3), against a deployment they
   did not perform, using only public algod reads. That is the only real
   defence against item 1 of this table, and it is why the schema artifact has
   to be a committed file rather than a function inside the deploy tool.

---

## 2. What already exists — the inventory, file by file

### 2.1 The inventory

| Existing location | Lines | What it really is | Live-proven? | M10 verdict |
|---|---:|---|---|---|
| `tests/sync_committee/conftest.py::SyncCommitteeLiveHarness` | ~200 | puyapy compile + ARC-4 `create` with args + the probe-fund-create app-id prediction recipe + `submit`/`call_group` | Yes — every M4 live test, 168 real deployments | **Promote the recipe, replace the prediction (§7.1)** |
| `tests/state_anchor/conftest.py::Arc4Harness` | ~230 | The same, generalised over any ARC-4 contract via the ARC-56 method table, plus `_auto_boxes_for` (box refs derived from `ring_n` + `block_number`) | Yes — 448 real deployments | **Promote; `_auto_boxes_for` becomes schema-driven (§3)** |
| `tests/state_anchor/conftest.py::puya_compile` / `patched_repo_copy` | ~45 | `puyapy` subprocess → `{class: {approval, clear, arc56}}`; TP-M8-4's compile-time id patch into a temp tree | Yes | **Promote (§5.7)** |
| `relayer/group/donors.py` | 110 | `puya_compile_contracts`, `compile_teal`, `deploy_donor_pair`, `donor_transaction_with_signer` — already outside `tests/`, already importable | Yes — every M9 live test | **Reuse verbatim, do not reimplement (§5.6)** |
| `relayer/client.py::_deploy_anchor_receipt_probe` | ~30 | Compile-with-patched-`ANCHOR_APP_ID` then `ApplicationCreateTxn(extra_pages=1)` | Yes — G6-M9 | **Generalise into `deploy/create.py` (§5.7)** |
| `bench/composer_bench.py::deploy_app` | ~20 | Raw-contract deploy for M5/M6 bench drivers | Yes — G2-M6/G3-M6 | **Promote** |
| `tests/state_anchor/test_live_e2e.py` (fixtures) | ~40 | The real M8 `create` → `ring_init_chunk` → `append_fork_row` order | Yes — G5-M8 | **Promote as the M8 plan (§5.3)** |
| `relayer/group/boxes.py::plan_box_refs` | 168 | The closed-form box-reference rule, **measured exactly correct** by M9's Suite BX | Yes | **Reuse verbatim (§5.3)** |
| `relayer/ssz/beacon_state.py`, `execution_payload.py` | 455 | Real SSZ field lists and composed-gindex derivation | Yes — G1-M8, three real `anchor_historical` submissions | **Reuse as the gindex generator's engine (§5.5)** |
| — | 0 | **A schema artifact** | — | **Does not exist** |
| — | 0 | **A deployment manifest / any record of what was deployed** | — | **Does not exist** |
| — | 0 | **A gindex generator** (all seven live values are hand-entered constants in test files) | — | **Does not exist** |
| — | 0 | **An MBR model** (every funding figure in this repo is a hand-picked round number) | — | **Does not exist** |
| `deploy/` | 0 | `.gitkeep`, created by the scaffold commit `51dd033` and never touched since | — | **M10's home** |

### 2.2 The verdict, and why it is not "write a deploy script"

The promotion half is genuinely thin, and pretending otherwise would pad this
module. But the four "does not exist" rows are not thin, and three of them are
*correctness* infrastructure rather than convenience:

- Without the **gindex generator**, §1.3's highest-leverage attack is mitigated
  by nothing but care. `FINALITY_GINDEX = 169` is currently a literal in
  `tests/sync_committee/test_live_e2e_finality.py`, copied by hand into
  `tests/relayer/test_live_relayer.py`, and re-typed a third time as
  `[0, 802, 803, 806, 69]` in `tests/relayer/test_live_relayer.py::env_a_anchor`.
  Three hand-copies of the most security-critical constants in the project.
- Without the **MBR model**, funding is guesswork. **Measured (this pass)**: the
  M8 harness funds 15,000,000 µALGO for a deployment whose real `min-balance` is
  **777,700** — 19.3× over, and (§10.4) **not recoverable**.
- Without the **manifest**, a deployment is a thing that happened in a terminal.
  The live mainnet M7 app id `3664247481` exists in this repo only as prose in
  `ROADMAP.md` and three design docs; there is no machine-readable record of its
  network, creator, governance, program hash, or deployment round anywhere.
- Without the **schema artifact**, `_auto_boxes_for` (a test helper) is the
  closest thing this project has to a statement of M8's box layout, and it lives
  in a `conftest.py`.

### 2.3 Four real defects the consolidation fixes

Each is verifiable in the tree today; none is hypothetical.

**D1 — the app-id prediction recipe is unsafe on any public network.**
`tests/sync_committee/conftest.py::create` deploys a throwaway probe app to learn
the ledger's `TxnCounter`, predicts `probe_id + 2`, sends ~45 ALGO to that
predicted address, then creates. Its own docstring concedes the recipe holds only
"on a quiet, single-actor dev-mode network", and wraps it in a 5-attempt retry
loop because it *does* race. On a devnet a lost race costs fake ALGO. **On
mainnet a lost race sends the funding Payment to a stranger's application
account, permanently** (§10.4: there is no recovery path from an app account).
The exposure with the current recipe is ~45 ALGO for M4 and 15–140 ALGO for M8.
§7.1 replaces it with a measured recipe whose worst case is **0.3349 ALGO**.

**D2 — the deployed drivers accept `UpdateApplication` and `DeleteApplication`
from any account.** §9.1 has the live proof and the mainnet consequence. No
deploy tooling can fix it, but deploy tooling is what makes it visible, and
§13's Suite S asserts the current state so that a future contract fix flips a
test rather than going unnoticed.

**D3 — `extra_pages` is guessed.** **Measured (this pass)**:
`Mpt6ComposerApp` is 2,676 B and `bench/composer_bench.py` deploys it with
`extra_pages=3`, two pages more than it needs.
`SyncCommitteeVerifier` is 6,980 B and `conftest.py` uses `extra_pages=3`, which
is exactly right — but by coincidence, not by computation, and 6,980 B leaves
only **1,212 B** of headroom under the 8,192 B cap, which nobody in this project
has ever recorded. §4.6 makes `extra_pages` a computed field of the schema.

**D4 — three hand-copies of the fork-table constants.** §2.2 above; §5.5 fixes it.

---

## 3. The schema artifact — the plan's "concrete schema for M8/M4 state"

### 3.1 Generated, not written

The plan's M10 line asks for "concrete schema for M8/M4 state". The tempting
reading is "write down the box names in a markdown table". That is what
`docs/design/004-sync-committee.md` §8.2 and `docs/design/008-trusted-root-anchor.md`
§6.1–§6.3 already do, and §3.3 below shows all three of those tables are now
**wrong in at least one field each**, because the code moved and the prose did
not.

**Decision: the schema artifact is a JSON file per contract, checked into the
repo, and produced by a generator that imports the contracts' own constants.**

```python
# deploy/schema/generate.py  -- runs as ordinary Python, no algod, no puyapy
from contracts.sync_committee.constants import (
    KEY_BOX_BYTES, KEYS_PER_BOX, BOXES_PER_COMMITTEE,
    SESSION_BOX_BYTES, G1_UNCOMPRESSED_BYTES, MIN_BOX_REFS_FOR_INSTALL_OPEN, ...)
from contracts.sync_committee.forks import FORKS_BOX_NAME, FORKS_BOX_BYTES, FORK_ROW_BYTES
from contracts.state_anchor.constants import (
    RECORD_LEN, OFF_VERSION, OFF_FLAGS, OFF_BLOCK_NUMBER, ..., RING_BOX_PREFIX, ...)
```

**Verified (this pass)**: `from contracts.sync_committee.constants import
KEY_BOX_BYTES` works in a plain CPython process — importing `algopy` at module
scope is fine outside a Puya compilation, which is why 20+ files in `tests/`
already do it. So the generator needs no compilation step and no parsing of
Python source. It is an import and a `json.dump`.

The ARC-56 artifacts (`SyncCommitteeVerifier.arc56.json`,
`contracts/state_anchor/TrustedRootAnchor.arc56.json` — the latter already
committed as G8-M8) supply the method surface and the global-state schema, and
the generator reads them rather than restating them.

### 3.2 The format

One file per deployable contract, `deploy/schema/<Contract>.schema.json`:

```jsonc
{
  "schema_version": 1,
  "contract": "TrustedRootAnchor",
  "source": "contracts/state_anchor/anchor_app.py",
  "design_doc": "docs/design/008-trusted-root-anchor.md",
  "program": {
    "approval_bytes": 3027, "clear_bytes": 4,
    "approval_sha256": "…",              // pinned; §7.4 recovery + §5.4 counterparty check
    "min_extra_pages": 1,
    "avm_version": 10,
    "on_completion_gate": "NoOp only"     // §9.1's security matrix, machine-checkable
  },
  "global_state": {
    "schema": {"ints": 9, "bytes": 1},
    "creator_mbr_microalgo": 406500,
    "keys": [
      {"key": "ring_size", "type": "uint64", "mutability": "write-once-at-create",
       "note": "008 §6.2 calls this `ring_n`; the on-chain key is `ring_size` (§3.3 drift 1)"},
      {"key": "frozen", "type": "uint64", "mutability": "governance", "initial": 1},
      … ]
  },
  "boxes": [
    {"family": "ring",
     "name": {"prefix": "68:3a", "key": "itob(el_block_number & (ring_size-1))",
              "name_bytes": 10},
     "value_bytes": 154,
     "mbr_microalgo": 68100,
     "count": "ring_size",
     "created_by": "ring_init_chunk", "deleted_by": null,
     "lifetime": "permanent — no deleter exists (§10.4)",
     "record": {"length": 154, "fields": [
        {"offset": 0,   "length": 1,  "name": "version"},
        {"offset": 1,   "length": 1,  "name": "flags",
         "bits": {"0": "FLAG_REVOKED", "1": "FLAG_HISTORICAL", "2": "FLAG_PINNED"}},
        {"offset": 2,   "length": 8,  "name": "el_block_number", "encoding": "uint64-be"},
        {"offset": 10,  "length": 8,  "name": "beacon_slot",     "encoding": "uint64-be"},
        {"offset": 18,  "length": 32, "name": "el_state_root"},
        {"offset": 50,  "length": 32, "name": "el_receipts_root"},
        {"offset": 82,  "length": 32, "name": "beacon_block_root"},
        {"offset": 114, "length": 32, "name": "finality_root"},
        {"offset": 146, "length": 8,  "name": "anchored_round",  "encoding": "uint64-be"}]}},
    {"family": "fork_table",
     "name": {"literal": "forks8", "name_bytes": 6},
     "value_bytes": 320, "mbr_microalgo": 132900, "count": 1,
     "created_by": "create", "deleted_by": null,
     "row": {"length": 40, "capacity": 8, "count_in": "global:fork_count",
             "fields": [
        {"offset": 0,  "length": 8, "name": "activation_epoch"},
        {"offset": 8,  "length": 8, "name": "g_state_root"},
        {"offset": 16, "length": 8, "name": "g_receipts_root"},
        {"offset": 24, "length": 8, "name": "g_block_number"},
        {"offset": 32, "length": 8, "name": "g_block_roots_base"}]}},
    … ],
  "deploy": {
    "create_signature": "create(address,uint64,uint64)void",
    "create_creates_boxes": ["forks8"],
    "mbr_at_create_microalgo": 232900,
    "ordering": ["m4 must already exist (m4_app_id is write-once)"],
    "init_calls": [
      {"method": "ring_init_chunk", "repeat": "ceil(ring_size/8)", "max_boxes_per_call": 8,
       "cursor": "global:ring_cursor", "completion": "ring_cursor == ring_size ⇒ frozen := 0"},
      {"method": "append_fork_row", "repeat": "len(fork_rows)",
       "cursor": "global:fork_count", "append_only": true,
       "boxes": ["forks8"]}]
  },
  "invariants": [
    "ring_size is a nonzero power of two (asserted at create)",
    "no method takes a ring_size/resize argument (asserted against the ARC-56 method list)"
  ]
}
```

Four properties this format is chosen for, each load-bearing:

1. **Every byte count and every offset is imported, never retyped.** A change to
   `KEYS_PER_BOX` propagates to `value_bytes`, `mbr_microalgo` and the funding
   plan in one step.
2. **Box *names* are described as a construction rule, not a list**, because
   M4's key boxes are keyed by an install generation and M8's by a block-number
   residue. `inspect` uses the rule in reverse to decode a real box list.
3. **Lifetime and deleter are explicit fields.** §10.4's whole finding —
   that "recoverable MBR" is false for the shipped contracts — is a
   `"deleted_by": null` in the artifact, where a reviewer can see it, rather
   than a sentence three design docs got wrong.
4. **The record layout travels with the schema**, so `attest`'s 154-byte reply
   and a ring box's contents are decodable by a monitoring tool that has never
   read `contracts/state_anchor/record.py`.

### 3.3 Three real drifts the artifact would already have caught

**Measured (this pass)**, by reading the committed ARC-56 artifact and the
compiled contracts against the design docs:

| # | Doc says | Code says | Effect |
|---|---|---|---|
| 1 | 008 §6.2: global key `ring_n` | On-chain key is **`ring_size`** (`TrustedRootAnchor.arc56.json`) | `relayer/client.py::_m8_ring_n` reads `b"ring_size"` and is right; anyone reading only the design doc writes a `KeyError` |
| 2 | 008 §6.3: `forks8` value **321 B**, MBR **133,300** | `FORKS_BOX_BYTES = 40 × 8 = ` **320 B**, MBR **132,900** | 400 µALGO per deployment, and a wrong `box_create` length would fail outright |
| 3 | 008 §6.2: "8 uint64s + 1 byte-slice ⇒ **378,000** µALGO" creator MBR | ARC-56 schema is **9 ints + 1 byte** (`fork_count` is missing from §6.2's table) ⇒ **406,500** µALGO | Under-funds the *creator* account by 28,500 µALGO |

None is catastrophic. That is the point: these are the drifts that survive when
the schema lives in prose, and they accumulate. A generated artifact plus §13's
`X-1` regeneration gate makes them impossible rather than unlikely.

### 3.4 CI gate

`python -m deploy schema --check` regenerates every artifact in memory and diffs
against the committed files, exiting non-zero on any difference. This runs in
`ci-offline.yml` (no algod, no network — the generator is a pure import), and it
is **G3-M10**. It is the same discipline 008's G8-M8 established for the ARC-56
artifact, generalised: the ARC-56 file covers the *method* surface; the schema
file covers the *storage* surface, which ARC-56 does not describe at all.

---

## 4. The real schemas — measured

Everything in this section is read from the shipped code and, where marked,
confirmed against a real deployed app on the dev network.

### 4.1 M4 — `SyncCommitteeVerifier`

**Global state**: 13 uint64 + 7 byte-slices (**measured (this pass)**, from the
compiled ARC-56). Creator MBR = `100,000 + 13×28,500 + 7×50,000` =
**820,500 µALGO**. Keys: `gov`, `gvr`, `fin_slot`, `fin_root`,
`fin_state_root`, `att_slot`, `att_state_root`, `cur_gen`, `cur_period`,
`next_gen`, `next_period`, `next_committee_root_trusted`,
`next_committee_root_period`, `inst_state`, `inst_gen`, `inst_period`,
`inst_root`, `inst_cursor`, `fork_count`, `gen_counter`.

**Boxes** (`contracts/sync_committee/install.py:91–111`, `forks.py:21–24`):

| family | name | name B | value B | MBR µALGO | count | created by | deleted by |
|---|---|---:|---:|---:|---:|---|---|
| fork table | `forks` | 5 | 576 (16 rows × 36) | **234,900** | 1 | `create()` | never |
| committee keys | `k:` ‖ `itob(gen)` ‖ `itob(j)[7:8]` | 11 | 6,144 | **2,464,500** | 8 per generation | `install_open_keys` | `install_abort`, `retire` |
| install session | `s:` ‖ `itob(gen)` | 10 | 424 | **176,100** | 1 per in-flight session | `install_open_session` | `install_finalize`, `install_abort` |
| aggregate | `a:` ‖ `itob(gen)` | 10 | 96 | **44,900** | 1 per installed generation | `install_finalize` | `retire` |

**MBR by lifecycle stage** (formula `2,500 + 400×(name+value)` plus the
100,000 app-account base):

| stage | boxes present | app-account min-balance | evidence |
|---|---|---:|---|
| just created | `forks` | **334,900** | **measured** — a real created-but-uninstalled app on the devnet reports `min-balance: 334900` |
| install in flight | `forks` + 8 × `k` + `s` | **20,227,000** | formula |
| one generation installed | `forks` + 8 × `k` + `a` | **20,095,800** | **measured** — three real fully-installed devnet apps all report `min-balance: 20095800`, exactly matching the formula |
| period rollover (two generations, one installing) | above + 8 × `k` + `s` | **≈ 40,119,100** | formula |

`tests/sync_committee/conftest.py::APP_FUNDING_MICROALGO = 45,000,000` is
therefore *correct* for the rollover peak with 4.88 ALGO to spare — but it is a
hand-picked round number, and 24.9 ALGO of it sits idle and unrecoverable
(§10.4) in the single-generation case that every live test actually exercises.

**Box-reference accounting** for the install group is already solved and
**measured exactly correct** by M9's Suite BX: `MIN_BOX_REFS_FOR_INSTALL_OPEN = 25`
(`8 × 6,144 + 424 = 49,576 B`, `⌈49,576/2,048⌉ = 25`), reproduced by
`relayer.group.boxes.plan_box_refs`. M10 reuses that function; it does not
restate the arithmetic.

### 4.2 M8 — `TrustedRootAnchor`

**Global state**: 9 uint64 + 1 byte-slice (**measured**, ARC-56). Creator MBR =
`100,000 + 9×28,500 + 50,000` = **406,500 µALGO** (§3.3 drift 3).

**Boxes** (`contracts/state_anchor/constants.py:48–66`):

| family | name | name B | value B | MBR µALGO | count | created by | deleted by |
|---|---|---:|---:|---:|---:|---|---|
| fork table | `forks8` | 6 | 320 (8 rows × 40) | **132,900** | 1 | `create()` | never |
| ring slot | `h:` ‖ `itob(block & (ring_size−1))` | 10 | 154 | **68,100** | `ring_size` | `ring_init_chunk` | **never — no deleter exists** |
| pinned | `p:` ‖ `itob(block_number)` | 10 | 186 | **80,900** | unbounded | `pin` (self-funded) | `unpin` (refunds the payer) |

**MBR by stage**:

| stage | app-account min-balance | evidence |
|---|---:|---|
| just created (`forks8` only) | **232,900** | formula |
| ring initialised, `N = 8` | **777,700** | **measured** — two real devnet `TrustedRootAnchor` apps report `min-balance: 777700`, exactly matching `100,000 + 132,900 + 8×68,100` |
| ring initialised, `N = 128` | **8,949,700** | formula, same shape |

008 §7.8's "total locked at `N=128`: **9.328 ALGO**" becomes **9.3562 ALGO**
(8.9497 app account + 0.4065 creator), with the components redistributed by
§3.3's drifts 2 and 3. And "**All of it recoverable** (delete the boxes, delete
the app)" is **false** — §10.4.

### 4.3 M7 — `Mpt7ReceiptApp`

No global state (`StateSchema(0,0)`), no permanent boxes, no governance surface,
nothing to initialise. Its only deployment-relevant fact is the **T2 staging
box**: name exactly 8 bytes (the contract asserts `fixed.length == 10`, i.e.
name(8) ‖ len(2)), value = the leaf length in `[1943, 4096]`, MBR
`2,500 + 400×(8 + leaf_len)`, **maximum 1,644,100 µALGO** at a 4,096 B leaf.
Created by `MODE_STAGE_OPEN`, deleted by `mpt7_stage_close` **inside the same
atomic group**.

The relayer funds `2,500 + 400×(8+leaf) + 200,000` to the app account *per T2
proof* (`relayer/drivers/m7_receipt.py:138`). Since deleting the box releases the
MBR *requirement* but not the ALGO, and since M7 has no withdrawal path, **every
T2 proof strands ~0.2 ALGO of headroom plus whatever the previous proof left**.
§5.4 replaces this with a one-time float sized to the worst case.

### 4.4 M6 — `Mpt6ComposerApp` (and M5's `MptSegmentApp`)

No global state, no boxes, no governance, no funding. Deployment is a single
`ApplicationCreateTxn`. Their budget donors are **self-issued** (`donor_count`
= arg2, `donor_app_id` = arg3 on every segment, 009 §7.1), so the only
deployment-time dependency is that a `DonorCallee` app id exists to point at.

> **Real finding, stated plainly because it is uncomfortable and this project's
> convention is to state those**: `EthAvmClient.prove_account`
> (`relayer/client.py:237`) **never submits a transaction**. It fetches
> `eth_getProof`, segments it, and returns a status derived entirely off-chain.
> There is no `test_l5` function in `tests/relayer/test_live_relayer.py` — the
> file's test functions are `test_l1`, `test_l2`, `test_l3`, `test_l4`,
> `test_l6`, `test_l7`, `test_l8`. So **G4-M9 ("a real `eth_getProof` account+
> storage proof commits live") is not closed**, contrary to the summary line at
> the head of `ROADMAP.md`'s M9 row; what was closed is an off-chain fetch and
> segmentation. The consequence for M10 is concrete: **M6 has no client that
> drives it**, so a deploy tool will happily create an `Mpt6ComposerApp` that
> nothing calls. M10 still deploys it (M11 needs it, and `bench/composer_bench.py`
> drives it for real), and §15 gap 4 records the gap rather than papering over it.

### 4.5 The `DonorIssuer` / `DonorCallee` pair

**Measured (this pass)**: 48 B and 4 B of approval program respectively;
`extra_pages=0`; no state; no funding beyond the 100,000 µALGO app base each.
They are infrastructure, not verification logic — 009 §1.2 already establishes
the rule (source imported, never rewritten), and `relayer/group/donors.py`
already implements the deploy. M10 calls it (§5.6).

### 4.6 Program sizes and `extra_pages` — all measured (this pass)

Real `puyapy` 5.9.0 output compiled through a real algod `/v2/teal/compile`.
`min_extra_pages = ⌈(approval + clear)/2048⌉ − 1`.

| contract | approval B | clear B | min `extra_pages` | repo uses | headroom under 8,192 B |
|---|---:|---:|---:|---:|---:|
| `SyncCommitteeVerifier` | **6,980** | 4 | **3** | 3 ✅ | **1,212 B (15%)** |
| `Mpt7ReceiptApp` | **3,104** | 4 | **1** | 1 ✅ | 5,088 B |
| `TrustedRootAnchor` | **3,027** | 4 | **1** | 1 ✅ | 5,165 B |
| `Mpt6ComposerApp` | **2,676** | 4 | **1** | **3** ⚠️ over by 2 | 5,516 B |
| `MptSegmentApp` | **1,987** | 4 | **0** | — | 6,205 B |
| `DonorIssuer` | 48 | 4 | 0 | 0 ✅ | — |
| `DonorCallee` | 4 | 4 | 0 | 0 ✅ | — |

Two of these cross-check numbers already in the repo exactly — `TrustedRootAnchor`
3,027 B (ROADMAP's M8 row) and `Mpt7ReceiptApp` 3,104 B (ROADMAP's M7 row) — and
`Mpt6ComposerApp` 2,676 B matches `bench/composer_results.json`'s
`real_driver_bytes`. **`SyncCommitteeVerifier`'s 6,980 B has never been recorded
anywhere in this project.** It is the largest contract in the repo, it sits at
85% of the per-app bytecode cap, and it is worth M12 and any future M4 revision
knowing that before someone adds a method.

---

## 5. The deployment sequences

One sub-section per contract, giving the exact call order, the box references,
and the funding checkpoints. These are transcriptions of what already works
(§2.1's evidence column), not new protocol.

### 5.1 The ordering constraint graph

```
DonorCallee ──▶ DonorIssuer          (issuer needs the callee's id in its args, not at create)
        │
        ├──────────────────────────────────────────────┐
        ▼                                              ▼
SyncCommitteeVerifier (M4) ──▶ TrustedRootAnchor (M8) ──▶ any M8 consumer
   create/fund/fork rows          m4_app_id is                (compiled with
                                  WRITE-ONCE at create         ANCHOR_APP_ID
                                                               patched, §5.7)
Mpt7ReceiptApp (M7)      independent
Mpt6ComposerApp (M6)     independent
```

Only one hard edge exists, and it is hard for a structural reason: M8's
`m4_app_id` is write-once with no setter (`contracts/state_anchor/anchor_app.py:86`),
so **M8 cannot be created before M4 exists**. Everything else is parallel.

The second edge — consumers compiled against M8's id — is the one 008 §15.4
item 4 calls "the most consequential operational decision in M8": it means an M8
redeploy forces a **recompile and redeploy of every consumer**. §6.5 makes that
concrete.

### 5.2 M4 — `SyncCommitteeVerifier`

```
1.  compile          puyapy → TEAL → algod /v2/teal/compile   (6,980 B, extra_pages=3)
2.  predict + fund   §7.1's two-stage recipe, stage 1: 334,900 µALGO
3.  create(governance: address, genesis_validators_root: byte[32])
                     extra_pages=3, global schema (13,7), boxes=[(0, b"forks")]
                     ⇒ creator pays 820,500 µALGO global-state MBR
4.  top up           to 20,227,000 (single install) or 40,119,100 (rollover headroom)
                     — safe now, the real app id is known
5.  append_fork_row(activation_epoch, fork_version[4], finality_gindex,
                    current_sc_gindex, next_sc_gindex)  × one per supported fork
                     boxes=[(0, b"forks")], sender MUST be `gov`
6.  STOP.            bootstrap/install is M9's `sync(install=True)`.
```

Step 5's arguments are **generated** (§5.5), never typed. Note the row shape is
5-tuple with a **4-byte `fork_version`** in the middle — structurally different
from M8's 5-uint64 row (§5.3 step 6). A tool that assumes one shape produces a
row the other contract will reject or, worse, silently mis-parse; §5.5's
generator emits both from one source and the schema artifact declares both.

### 5.3 M8 — `TrustedRootAnchor`

```
1.  compile          3,027 B, extra_pages=1
2.  verify counterparty:  application_info(m4_app_id).approval-program SHA-256
                     == the pinned SyncCommitteeVerifier hash            ← §1.3 mitigation 2
3.  predict + fund   stage 1: 232,900 µALGO
4.  create(governance: address, m4_app_id: uint64, ring_n: uint64)
                     extra_pages=1, global schema (9,1), boxes=[(0, b"forks8")]
                     ring_n MUST be a nonzero power of two (asserted; rejects 7)
                     ⇒ `frozen` starts at 1, `ring_cursor` at 0
5.  top up           to 100,000 + 132,900 + ring_n × 68,100
6.  ring_init_chunk(k) × ⌈ring_n/8⌉, k ≤ 8, boxes = the 8 ring boxes for that chunk
                     governance-only; asserts ring_cursor + k <= ring_size;
                     sets frozen := 0 when ring_cursor == ring_size
7.  append_fork_row(activation_epoch, g_state_root, g_receipts_root,
                    g_block_number, g_block_roots_base) × one per supported fork
                     boxes=[(0, b"forks8")], sender MUST be `gov`
8.  assert           frozen == 0, ring_cursor == ring_size, fork_count == len(rows)
```

**Step 6's group shape is already proven at the extreme.** G5-M8 committed a real,
non-simulated **16-transaction** `ring_init_chunk` group filling all 128 boxes at
`N=128`, and `relayer.group.boxes.plan_box_refs` reproduces that shape exactly
(M9's P-1). The binding constraint is term 1 of the box-reference rule (128
distinct boxes ⇒ 128 refs ⇒ 16 transactions), not the pooled byte budget
(19,712 B ⇒ 10 refs). **`N = 256` therefore needs two groups**, and 008 §7.8's
recommendation of `N = 128` exists partly so M10's tooling stays at one — a
constraint this document honours but does not depend on, because
`ring_init_chunk` is resumable through `ring_cursor` (§7.3) and multi-group init
is a loop, not a redesign.

`ring_n = 8` (every current test's scale) is one transaction and 777,700 µALGO;
`ring_n = 128` (008's recommendation) is 16 transactions and 8,949,700 µALGO.
Both are `--ring-n` values in the target file, defaulting to **128** per 008 §7.8.

### 5.4 M7 — `Mpt7ReceiptApp`

```
1.  compile          3,104 B, extra_pages=1
2.  create           no create-time boxes ⇒ NO pre-funding, NO id prediction needed
3.  fund (optional)  one T2 float: 100,000 base + 1,644,100 worst-case staging box
4.  no governance calls exist.
```

M7's deployment is the trivial one — which is exactly why it is the one that
reached mainnet ad hoc and still worked. It is also the one with the security
defect (§9.1) and no way to recover the float (§10.4).

The float replaces the relayer's current per-proof funding
(`relayer/drivers/m7_receipt.py:138`): with the app account pre-funded to the
worst case once, `_submit_t2_receipt`'s Payment can be dropped to zero when
`account_info(app).amount − min-balance ≥ required`, saving a transaction slot
in a group that 008 §9.3 already worried about. **Flagged for a future M9 revision**
(§14), not changed here — M10 supplies the float and the check.

### 5.5 The fork tables — generated, never typed

008 §15.4 item 2: *"Seeding the fork table, generated by `get_generalized_index`,
never hand-entered."* This is the requirement §1.3 identifies as the highest-
leverage in the project, and it turns out to be nearly free.

**Verified (this pass)**: every gindex this project uses is already derivable
from field lists that `relayer/ssz/` carries today.

```python
from relayer.ssz.beacon_state import FULU_FIELDS, BEACON_STATE_DEPTH   # 38 fields, depth 6
i = FULU_FIELDS.index("finalized_checkpoint")      # 20 → gindex 64+20 = 84
                                                   #      → Checkpoint.root = 84*2+1 = 169
FULU_FIELDS.index("current_sync_committee")        # 22 → 86
FULU_FIELDS.index("next_sync_committee")           # 23 → 87
FULU_FIELDS.index("block_roots")                   #  5 → 69   (g_block_roots_base)
```

Run against the real committed field list, this reproduces **169 / 86 / 87 / 69**
— the exact four values `tests/sync_committee/test_live_e2e_finality.py` and
`tests/relayer/test_live_relayer.py` currently hard-code, and the exact value
`83b4fb8` independently re-derived for Fulu by counting real spec fields.
`relayer/ssz/execution_payload.py::deep_branch` already returns the composed
**802 / 803 / 806** for `state_root` / `receipts_root` / `block_number`, and it
is the code three real `anchor_direct`/`anchor_historical` submissions were built
on.

So `deploy/forks.py` is:

```python
def m4_fork_row(fork: str) -> tuple[int, bytes, int, int, int]:
    """(activation_epoch, fork_version, finality_gindex,
        current_sc_gindex, next_sc_gindex) — every gindex DERIVED."""

def m8_fork_row(fork: str) -> tuple[int, int, int, int, int]:
    """(activation_epoch, g_state_root, g_receipts_root,
        g_block_number, g_block_roots_base) — every gindex DERIVED."""
```

with three normative rules:

1. **Per-fork field lists, each asserted against a real fetched spec.**
   `relayer/ssz/beacon_state.py` carries Fulu's 38 fields only; Deneb's list
   (whose `g_block_roots_base` is **37** = `32 + 5`, i.e. depth 5, versus
   Electra/Fulu's **69** = `64 + 5`) must be added, and asserted the way
   `relayer/ssz/block_body.py:314` already asserts real `BeaconBlockBody` field
   order against live data. §15 gap 5.
2. **Cross-check before trusting.** The generator emits, alongside each row, the
   two independent confirmations `83b4fb8` performed by hand: folding
   `block_hash` must reproduce the spec-published
   `EXECUTION_BLOCK_HASH_GINDEX_DENEB = 812`, and the composed folds must
   reproduce a real published `body_root`. If either fails, the tool refuses to
   append the row.
3. **`activation_epoch` comes from a live `/eth/v1/config/spec`**, cross-checked
   against `eth-clients/mainnet`'s published config — the exact three-way
   confirmation `tests/state_anchor/test_forks.py` performs for
   `DENEB_FORK_EPOCH = 269568` / `ELECTRA_FORK_EPOCH = 364032`, promoted from a
   test into the tool. Never a literal in a config file.

**And the two row shapes are genuinely different** — M4's carries a 4-byte
`fork_version` and three sync-committee/finality gindices; M8's carries four
execution/state gindices and no fork version. Both are declared in the schema
artifact (§3.2) and encoded by generated code; nothing in M10 assumes one shape.

### 5.6 Donors

`relayer.group.donors.deploy_donor_pair(algod, sender, sk, repo_root=…)` already
does this and is already outside `tests/`. **M10 imports it. It does not
reimplement it, and it does not copy it into `deploy/`.** The pair's ids go into
the manifest, and from there into `RelayerConfig.donor_issuer_id` /
`donor_callee_id`, which is the whole reason M9's config has those fields.

Reusing rather than reinventing is the decision 009 §1.2 already made for M9
("it *may* deploy the existing pair … the source is imported, never rewritten"),
and the same reasoning applies unchanged one module up.

### 5.7 Consumers bound at compile time (TP-M8-4)

Any contract that imports `contracts/state_anchor/handoff.py` embeds
`ANCHOR_APP_ID` as a `pushint` immediate — verified by direct TEAL inspection in
M8's own pass, and adversarially tested against a `FakeAnchor` with an identical
ARC-4 selector. So deploying such a consumer is a **compile-after-M8** step:

```
patched = patched_repo_copy(anchor_app_id)      # temp tree, contracts/ untouched
puyapy(patched/contracts/…/consumer.py, PYTHONPATH=patched)
create(...)
```

Both `tests/state_anchor/conftest.py::patched_repo_copy` and
`relayer/drivers/m7_receipt.py::patched_probe_source` implement exactly this;
M10 promotes one of them into `deploy/create.py` and records
`{"bound_to": {"m8_app_id": …}}` in the manifest entry, because a consumer's
binding is otherwise invisible from its bytecode without recompiling to compare.

Today the only such consumer is `AnchorReceiptProbe`
(`contracts/state_anchor/bench_app.py`), which is explicitly test-only. M6 and
M7's own deployed contracts are **not** yet wired to M8 — 008 §9.2 scoped that
out and M9 inherited it as its gap (c). M10 must not pretend otherwise: the
schema artifact records `Mpt7ReceiptApp` as **unanchored**, and §14 hands the
integration on unchanged.

---

## 6. Environments

### 6.1 Three networks, one code path, keyed by genesis hash

```jsonc
// deploy/targets/localnet.json
{"network": {"algod_url": "http://localhost:4051", "token": "aaaa…",
             "genesis_id": "dockernet-v1", "genesis_hash": "…"},
 "governance": "<address>",
 "contracts": {"m4": {"deploy": true, "genesis_validators_root": "0x4b36…fe95"},
               "m8": {"deploy": true, "ring_n": 128},
               "m7": {"deploy": true, "t2_float": true},
               "m6": {"deploy": true}},
 "forks": ["deneb", "electra", "fulu"]}
```

**Normative: every manifest and every target records the network's genesis hash,
and `apply`/`verify` refuse to act if the connected algod's genesis hash differs.**
This is not ceremony. A testnet manifest applied against a mainnet algod would
happily create a second M8 pointing at a testnet M4 app id that on mainnet is
some unrelated stranger's application — the precise shape of §1.3's row 2. It is
one comparison and it makes that class of accident impossible. **G7-M10.**

### 6.2 Localnet (dev-mode algod)

The environment this entire project has been validated against: dev-mode algod
in Docker at `:4051`, kmd at `:4052`, `unencrypted-default-wallet`. Everything in
§5 runs here, unmodified, and §13's Suite D and Suite E are localnet suites.

One localnet-specific property M10 depends on and should say so: **instant
finality and a single actor** make §7.1's app-id prediction essentially
deterministic. On any other network it is a race, which is why §7.1 bounds the
loss rather than assuming the prediction holds.

### 6.3 Testnet

Supported, and *recommended before any mainnet action*, with two differences the
tool must handle rather than discover:

- **No kmd, no default wallet.** The signer comes from a mnemonic or an external
  signer, and the account must be funded from a faucet before `apply`. `plan`
  prints the exact total (§10) so the faucet ask is one number.
- **The prediction race is real.** §7.1's staged funding is what makes a lost
  race cost 0.33 ALGO of test tokens instead of 45.

Testnet is also where a real, non-devnet run of §13's Suite E *should* happen
before v1. It is **not** in M10's acceptance gate — see §15 gap 3, stated as a
gap rather than quietly assumed.

### 6.4 Mainnet, and the live app `3664247481`

`Mpt7ReceiptApp` is deployed on Algorand mainnet at app id **`3664247481`**
(round 63789985), it is what `service/x402_endpoint/` charges 0.01 USDC to call,
and real USDC has moved through it. So the question the task poses — *what does
redeploying/upgrading/monitoring that responsibly look like?* — is a real
question about a real, financially-live contract.

**The answer this document gives, and the reason it is not the expected one:**

1. **Monitoring is in scope and is cheap.** `deploy verify --target mainnet` and
   `deploy inspect --app m7 --json` need only public algod reads: is the app
   still there, does its approval program still hash to the pinned value, are
   there any stranded staging boxes, what is the app account's balance. All of
   that works today against a public algod endpoint and belongs in M10. **This
   is the only mainnet capability v1 ships.**
2. **Upgrading is not in scope, because `Mpt7ReceiptApp` has no upgrade
   *authority* — it has an upgrade *hole*.** §9.1: **measured (this pass)**,
   any account on the network can replace its program via `ApplicationUpdateTxn`
   or destroy it via `ApplicationDeleteTxn`. Building "responsible upgrade
   tooling" for a contract anyone can already overwrite is building a lock for a
   door that is off its hinges.
3. **Redeploying the current `Mpt7ReceiptApp` to mainnet is refused by this
   design.** `deploy apply` against a mainnet genesis hash **must refuse** any
   contract whose schema declares `"on_completion_gate": "unrestricted"`, with a
   message naming §9.1. That is a one-line policy and it is the correct one: the
   contract's own module docstring already says *"NEVER deploy to mainnet
   as-is"*, and it was deployed to mainnet anyway, because nothing enforced it.
   **M10 is what enforces it.**
4. **What the service should do about the live app is a decision for the human,
   flagged not made** — the same treatment 008 §15.3 item 9 gave the x402
   pre-payment problem. §9.1 lays out the three options and their real costs.

### 6.5 Migration — the redeploy cost, made concrete

008 §15.4 item 4 asks M10 to *"document the migration, not just the flag"*.
Here it is, in transactions and ALGO:

| trigger | what must be redeployed | why | real cost |
|---|---|---|---|
| New Ethereum fork | nothing — `append_fork_row` on both tables | Both tables are append-only and capacity is 16 (M4) / 8 (M8) rows | 2 × 1,000 µALGO |
| Fork table **full** (>8 M8 rows) | M8 **and every consumer** | No row deleter, no capacity change without a code change | full M8 MBR + consumer redeploys |
| A **wrong** row was appended | M8 **and every consumer** | Append-only; a row cannot be edited or removed. §11.4 | as above |
| `ring_n` change | M8 **and every consumer** | Write-once; changing `N` silently remaps every residue (008 §6.2) | 8.95 ALGO at N=128, unrecoverable |
| `renounce()` then a fork | M8 **and every consumer** | Renouncing makes the fork table permanently frozen | as above |
| M4 contract bugfix | M4 **and M8** (write-once `m4_app_id`) **and every consumer** | Cascades down the whole graph of §5.1 | ~21 + ~9 ALGO, unrecoverable |
| M7/M6 contract change | just that app | Stateless, unbound | ~0.1 ALGO |

**The `renounce()` recommendation this document makes**: do **not** renounce on a
first deployment. 008 §5.7's argument for renouncing (removing governance from
the trust model) is real, but so is the fact that this project has amended both
fork tables' *values* three times in two sessions while getting them right, and
`renounce()` converts the cheapest possible correction (1,000 µALGO) into the
most expensive (a full cascade). Renounce when a deployment has survived a real
fork transition unamended. `deploy` exposes `renounce` as an explicit,
interactive, never-scripted subcommand that prints this table first — **`O-M10-4`
is deliberately *not* automated**.

---

## 7. Idempotency and resumption

### 7.1 The only genuinely non-idempotent step is `create` — and how to make it safe

M4's `create()` and M8's `create()` both call `forks_box_create()` in their body,
so the app account must already hold box MBR *at the moment the create executes*,
before the app id — and therefore the address — is knowable.

The repo's existing answer (`tests/sync_committee/conftest.py`) is a throwaway
probe app to read the ledger's `TxnCounter`, `predicted = probe_id + 2`, fund
that address with the *full* 45 ALGO, create, and retry on mismatch. §2.3's D1
explains why that is a devnet-only recipe.

**M10's recipe, measured end to end this pass:**

```
1.  simulate the create transaction, unfunded, with allow_empty_signatures=True
    → the response carries BOTH:
        txn-results[0].txn-result.application-index   = the id it would assign, I0
        failure-message: "... balance 0 below min 334900"  = the exact MBR needed
2.  fund get_application_address(I0 + n) with exactly that amount,
    where n = the number of transactions you will send before the create (here: 1,
    the funding Payment itself, which consumes a TxnCounter slot)
3.  send the real create; assert the assigned id == I0 + n
4.  now that the id is known for certain, top up to the full stage requirement
```

**Measured (this pass)**, run against real dev-mode algod:

- `simulate` of an unfunded `SyncCommitteeVerifier` create returned
  `application-index: 186092` and the failure message
  `"account … balance 0 below min 334900 (0 assets)"`.
- Funding `get_application_address(186093)` with **exactly 334,900 µALGO** and
  then sending the create produced app id **186093** — the prediction held —
  with the app account ending at `amount == min-balance == 334900`, **funded to
  the byte, nothing stranded**.
- A first attempt that funded `I0` rather than `I0 + 1` failed with the real
  protocol error, confirming the off-by-one is the funding Payment's own counter
  slot — the same `+2` the conftest documents (probe + payment), less one because
  there is no probe.

Four things this buys, all real:

| | probe recipe (today) | simulate recipe (M10) |
|---|---|---|
| Throwaway app created per deploy | 1 | **0** |
| Extra fee | 1,000 µALGO | **0** |
| Funding requirement | hand-picked constant | **read from the protocol's own error** |
| Loss if the prediction races | up to **45 ALGO**, permanently | **0.3349 ALGO**, permanently |
| Works with no signer | no | **yes** (`allow_empty_signatures=True`) |

**The race is narrowed, not eliminated** (§15 gap 2): Algorand has no mechanism to
reserve an application id. What M10 can and must do is bound the loss, assert the
id afterwards, and never proceed on a mismatch.

### 7.2 The manifest records identity, and only identity

```jsonc
// deploy/manifests/<genesis_id>.json
{"manifest_version": 1,
 "network": {"genesis_id": "mainnet-v1.0", "genesis_hash": "wGHE2…"},
 "apps": {
   "m4": {"app_id": 186093, "created_round": 8270, "txid": "ICB3…",
          "approval_sha256": "…", "schema_version": 1,
          "creator": "…", "governance": "…",
          "genesis_validators_root": "0x4b36…"},
   "m8": {"app_id": 186101, …, "bound_to": {"m4_app_id": 186093}, "ring_n": 128},
   "m7": {"app_id": 3664247481, …},
   "m6": {"app_id": …},
   "donor_issuer": {"app_id": …}, "donor_callee": {"app_id": …}}}
```

Nothing about *progress* is recorded — no "fork rows appended: 2", no "ring
initialised: true". That is deliberate, and it is the same principle M9 §9.1
arrived at the hard way for M4's install session (*"the on-chain state machine
**is** the checkpoint; a local progress file would be a second source of truth
that can disagree with the chain, which is strictly worse"*), applied one level
up. The manifest answers only the question chain state cannot: **which app id is
ours.**

### 7.3 Converge-by-diff — the on-chain cursors deployment actually has

The task's framing was that deployment "doesn't have an equivalent on-chain
cursor for which governance calls have landed". **It does — every step has one:**

| step | on-chain predicate ("has this landed?") | source |
|---|---|---|
| app exists and is ours | `application_info(id)` approval SHA-256 == pinned | algod |
| fork box exists | `application_boxes(id)` contains `forks` / `forks8` | **verified (this pass)** — `/v2/applications/{id}/boxes` really does enumerate `[forks8, h:…×8]` for a real deployed anchor |
| app account funded | `account_info(app_addr).amount >= required` and `>= min-balance` | algod |
| ring initialised | `ring_cursor == ring_size` **and** `frozen == 0` | global state |
| ring partially initialised | `ring_cursor` **is the resume index** — `ring_init_chunk(k)` asserts `ring_cursor + k <= ring_size` | 008 §7.7 designed it for exactly this |
| fork rows appended | `fork_count` **plus** the decoded rows from the fork box | global state + box read, decoded via §3's schema |
| governance correct | `gov` global == target | global state |
| M4 install progress | `inst_state` / `inst_cursor` (M9's, not M10's) | 009 §9.1 |

So `deploy apply` is **not** a script with a resume flag. It is:

```
desired = target file + generated fork rows + computed MBR
actual  = read chain state through the schema
plan    = desired − actual        # a list of transactions, possibly empty
apply   = send plan, then re-read and assert actual == desired
```

Run it twice and the second run sends **zero transactions** (**G2-M10**). Kill it
anywhere and re-run: it recomputes the diff and continues (**G6-M10**). Neither
property needs a state file, and neither can go stale.

**The one subtlety, and it is sharp**: fork rows are append-only and strictly
increasing (`append_fork_row` asserts both, in both contracts). So the diff is
not a set difference — it is a **prefix check**. If the on-chain rows are a
prefix of the desired rows, append the remainder. If any already-appended row
*disagrees* with the desired table, that is **FATAL** — `apply` must stop and
say "redeploy required" (§6.5), never append on top and never ignore it. §11.4.

### 7.4 When the manifest is lost

Recoverable, with no local state, using the pinned approval hashes:

```
for app in account_info(creator)["created-apps"]:
    if sha256(app.params["approval-program"]) == pinned[contract]:
        candidate.append(app.id)
```

**Verified (this pass)** against the real devnet: this recovers **168**
`SyncCommitteeVerifier` and **448** `TrustedRootAnchor` instances, with each
app's full approval-program bytes returned inline by `account_info`. Ambiguity
(more than one match, as here) is resolved by the schema-driven `inspect`
comparing global state against the target: the right M8 is the one whose
`m4_app` points at the right M4 and whose `gov` is the configured address.

This is 008 §15.4 item 3's "pin M4's approval-program hash in deployment config"
doing double duty: the pin is both the counterparty check (§5.3 step 2) and the
recovery key. `deploy recover --creator ADDR` is §8.2's subcommand for it.

### 7.5 What genuinely has no cursor

**Funding Payments.** A Payment leaves no trace saying "this was the ring-MBR
top-up". The predicate is a *balance comparison*, not a history scan — `apply`
tops up to `required − current` and a re-run computes zero. That is idempotent by
construction and needs no cursor, but it is worth stating that this is the one
step where the tool reasons about a level rather than an event, and therefore the
one step where an operator's own unrelated transfer into an app account changes
the plan.

---

## 8. Interface

### 8.1 Shape: a library with a CLI over it

Same call M9 §8.1 made, same order of priority: `deploy.apply(target, algod,
signer) -> Manifest` is the product (M11's CI imports it); the CLI is an
`argparse` shell that adds no logic.

**Home**: `deploy/`, the directory the scaffold commit created and left empty —
not a subpackage of `relayer/`. Two reasons, both concrete: `deploy/` must import
`contracts.*` (and therefore `algopy`) for the schema generator, which
`relayer/` is forbidden to do by G8-M9's AST-enforced rule; and `deploy/` shells
out to `puyapy`, which a relayer running on an operator's laptop must not
require.

**Dependency direction: `deploy` imports `relayer`, never the reverse.**
`relayer.group.donors` (deploy), `relayer.group.boxes.plan_box_refs` (ring
groups), `relayer.ssz.*` (gindices), `relayer.sources.beacon` (fork epochs).
Enforced by the same AST import test that enforces G8-M9.

### 8.2 The CLI

```
python -m deploy plan     --target targets/localnet.json           # prints the diff, sends nothing
python -m deploy apply    --target targets/localnet.json [--yes]
python -m deploy verify   --target targets/localnet.json           # asserts on-chain == desired
python -m deploy inspect  --app m8 [--boxes] [--json]              # decode state + boxes via §3
python -m deploy schema   [--check]                                # regenerate / CI drift gate
python -m deploy recover  --creator ADDR                           # rebuild a lost manifest (§7.4)
python -m deploy fund     --app m4 --stage install|rollover
python -m deploy renounce --app m8                                 # interactive, prints §6.5 first
```

Global flags: `--manifest`, `--json`, `--dry-run`, `--verbose`.

**`plan`, `verify`, `inspect` and `schema` require no signer** and send nothing
— §7.1's simulate-based prediction is what makes even `plan`'s app-id and
funding figures real without a key. This is the CI path, the audit path, and the
"check someone else's deployment" path, and per 009 §18 item 16's precedent it is
a first-class requirement, not a bolt-on.

### 8.3 `inspect` — why it is a deliverable and not a convenience

```
$ python -m deploy inspect --app m8 --boxes
TrustedRootAnchor  app 186101  (mainnet-v1.0)   approval sha256 3f9a… ✓ matches pin
  gov          ABCD…WXYZ  ✓ target
  m4_app       186093     ✓ matches manifest m4, approval hash ✓
  ring_size    128        ring_cursor 128  frozen 0  ✓ initialised
  fork_count   3          conflict 0
  boxes        130 found / 129 expected            ⚠
    forks8            320 B   3 rows
      [0] epoch 269568  g_state 802  g_receipts 803  g_number 806  g_roots_base 37
      [1] epoch 364032  …
    h:…              154 B × 128, 41 written, 87 unwritten (version=0)
      h:0000000000000009  block 25694857  slot 14933248  DIRECT
                          receipts_root 0x8f3a…  round 63789993
    t2000000010000    ⚠ unrecognised — matches Mpt7ReceiptApp's staging-box shape (007 §8.4)
```

Three things this makes possible that nothing in the repo can do today:
an auditor can check a deployment they did not perform (§1.3 mitigation 3); a
monitoring job can alert on `conflict != 0` (M8's `N20` equivocation latch, which
009 §8.5 classifies PAGE_A_HUMAN and which nothing currently watches); and a
stranded T2 staging box becomes a **reported anomaly** rather than the sweeper
007 §8.4 asked for (§11.6).

---

## 9. Adversarial notes

### 9.1 The headline: three deployed contracts accept `UpdateApplication` and `DeleteApplication` from anybody

**Measured (this pass), on real dev-mode algod, not reasoned about:**

`Mpt7ReceiptApp`'s approval program begins:

```teal
txn ApplicationID
bnz main_after_if_else@2
intc_0 // 1
return
main_after_if_else@2:
txn NumAppArgs
bnz main_after_if_else@4
intc_0 // 1
return
```

There is **no `txn OnCompletion` anywhere in the program** (`grep -c OnCompletion`
⇒ 0). Every application call with zero app args returns 1, whatever its
on-completion action and whoever sent it. Real experiment:

1. Deployed `Mpt7ReceiptApp` from account A.
2. From a **different** account B, sent `ApplicationUpdateTxn` with a 4-byte
   `int 1; return` program and no app args. **Confirmed, round 8266.** The
   deployed approval program is now 4 bytes of attacker-chosen code.
3. Deployed a fresh instance, funded its app account with 1,000,000 µALGO, then
   from account B sent `ApplicationDeleteTxn` with no app args. **Confirmed,
   round 8269.** The app is gone; the 1,000,000 µALGO is still sitting at the
   (now orphaned) application address, reachable by nobody, ever.

`grep -c OnCompletion` is **0** for `MptSegmentApp` (M5) and `Mpt6ComposerApp`
(M6) too — same shape, same hole. By contrast, `SyncCommitteeVerifier` and
`TrustedRootAnchor` both begin with

```teal
txn OnCompletion
!
assert
```

so **M4 and M8 are immutable and undeletable by construction** — Puya's
`ARC4Contract` router rejects every on-completion but `NoOp`, and neither
contract declares an update or delete method.

**The consequence, stated without softening**: the `Mpt7ReceiptApp` at mainnet
app id `3664247481`, which `service/x402_endpoint/main.py` charges real USDC to
query, can be reprogrammed by any Algorand account for the price of one
transaction fee. Its on-chain verification result is not trustworthy against an
active attacker, independently of everything M1–M8 prove. Nothing in this
project's threat model covered this, because every design doc reasoned about what
the *program* checks and none reasoned about who may *replace* the program.

**M10's response, in scope:**

- The schema artifact carries `"on_completion_gate"`, derived by inspecting the
  compiled TEAL for the `txn OnCompletion; !; assert` prologue.
- `deploy apply` **refuses** to deploy an `"unrestricted"` contract to a mainnet
  genesis hash (§6.4 item 3).
- §13's Suite S asserts the current matrix on every run — M4/M8 reject, M5/M6/M7
  accept — so the day a contract revision closes the hole, a test *changes*
  rather than staying silently green.

**Out of scope, and flagged to the human, with the three real options:**

| option | cost | effect |
|---|---|---|
| Leave it | 0 | The live x402 service's verification is defeasible by anyone |
| Add `assert Txn.on_completion == NoOp` to M5/M6/M7's drivers, redeploy | ~4 lines, one redeploy each, ~0.1 ALGO | Closes it. M7's app id changes ⇒ the service's `M7_APP_ID` changes |
| Take the mainnet app down deliberately (delete it yourself, since you can) | 1 txn | Removes a live, hijackable endpoint until it is fixed |

This document recommends **option 2, promptly**, and notes that it is a contract
change and therefore an M7-revision task, not something M10 may do under its own
scope boundary — the same boundary 008's pass respected when it declined to edit
M6/M7's contracts.

### 9.2 A wrong gindex is indistinguishable from a right one

Restating §1.3's row 3 as an attack, because it is the one M10 uniquely enables:
an operator who appends `g_receipts_root = 802` instead of `803` produces an M8
that anchors the execution `state_root` **into the `el_receipts_root` field** of
every record. `N19` passes (the branch really does verify), `N9` passes (the
depth matches), `attest` returns a well-formed 154-byte record, and every
downstream receipt proof then walks a trie rooted at 32 bytes that are not a
receipts root — failing closed, loudly, in the best case, and in the worst case
succeeding against an attacker-chosen trie the operator was tricked into
anchoring. §5.5's generation-plus-cross-check is the only defence, and
**G4-M10** is the gate.

### 9.3 Governance retention

Both contracts' `gov` starts as whatever `create` was told. If a deployment
script defaults it to the deployer's own hot key — which every current fixture in
this repo does (`h.create(h.sender, …)`, `anchor.create([sender, …])`) — then a
compromised laptop can `freeze` M8, `revoke` any anchor, or append a fork row.
`deploy apply` **must** require `governance` explicitly in the target file and
**must** warn when it equals the signer, rather than defaulting silently.

### 9.4 Funding a predicted address

§7.1's residual: the funding Payment is irreversible and goes to an address
derived from a predicted id. M10 bounds it to the create-time MBR (0.2329–0.3349
ALGO) and asserts the id afterwards. An operator running `apply` on a busy
network with a large `--ring-n` must still top up *after* the id is confirmed —
which is why §5.3's step 5 is a separate step and not folded into step 3.

### 9.5 The manifest is not a trust anchor

It records app ids; it is not signed and it is not authoritative. `verify`
re-derives everything it can from chain state and pinned hashes, so a tampered
manifest produces a `verify` failure rather than a silent redirection. This is
the one place M10's own output is treated as untrusted input.

---

## 10. Cost — what a deployment actually costs

Fees at the 1,000 µALGO minimum. MBR figures are **measured** where §4 says so,
otherwise from the protocol formula `2,500 + 400×(name + value)` — which §4.1 and
§4.2 confirm reproduces real `min-balance` readings **exactly** in three
independent cases.

### 10.1 Fees

| step | txns | µALGO |
|---|---:|---:|
| M4: simulate (free) + fund + create + 3 fork rows | 5 | 5,000 |
| M4: top-up to install level | 1 | 1,000 |
| M8: fund + create + `ring_init_chunk` ×16 (N=128) + 3 fork rows + top-up | 22 | 22,000 |
| M7: create (+ optional float payment) | 2 | 2,000 |
| M6: create | 1 | 1,000 |
| Donor pair: 2 creates | 2 | 2,000 |
| **Total deployment fees** | **33** | **33,000 = 0.033 ALGO** |

For scale: one M4 committee install (M9's, not M10's) is **≈ 2.71 ALGO** in fees
alone. Deployment fees are noise; **MBR is the entire cost**.

### 10.2 MBR — the real number

| account | item | µALGO |
|---|---|---:|
| creator | M4 global state (13 ints, 7 bytes) | 820,500 |
| creator | M8 global state (9 ints, 1 byte) | 406,500 |
| M4 app | base + `forks` | 334,900 |
| M4 app | 8 key boxes + aggregate (one generation, **measured**) | 19,760,900 |
| M8 app | base + `forks8` | 232,900 |
| M8 app | ring at N=128 | 8,716,800 |
| M7 app | base | 100,000 |
| M7 app | T2 float (worst-case 4,096 B leaf) | 1,644,100 |
| M6 app | base | 100,000 |
| donors | 2 × base | 200,000 |
| | **total locked** | **32,316,600 ≈ 32.3 ALGO** |

At `ring_n = 8` (the test scale) the M8 ring drops to 544,800 and the total to
**≈ 24.1 ALGO**. Without the T2 float, subtract 1.64.

### 10.3 What this project currently funds, versus what it needs

**Measured (this pass)**, from real deployed apps on the dev network:

| harness constant | funds | real requirement | over-funded by |
|---|---:|---:|---:|
| `tests/sync_committee/conftest.py::APP_FUNDING_MICROALGO` | 45,000,000 | 20,095,800 (installed) | 24.9 ALGO |
| `test_live_e2e.py` M8 `fund_app` (N=8) | 15,000,000 | 777,700 | **14.2 ALGO (19.3×)** |
| `test_live_e2e.py` M8 `fund_app` (N=128) | 140,000,000 | 8,949,700 | **131 ALGO (15.6×)** |
| `relayer/drivers/m7_receipt.py:138` T2 | leaf MBR + 200,000, **per proof** | leaf MBR, once | 0.2 ALGO per proof, cumulative |

On a devnet this is free. §10.4 is why it would not be elsewhere.

### 10.4 The correction: MBR is **not** recoverable for the shipped contracts

Four separate documents in this repo describe this MBR as recoverable —
001 §4.5 (*"a one-time ~19.7 ALGO of **recoverable** box MBR"*), 004 §8.2,
008 §6.2 (*"recoverable on app deletion"*) and §7.8 (*"**All of it recoverable**
(delete the boxes, delete the app)"*), and 009 §12 (*"**≈ 19.7 ALGO,
recoverable**"*).

**For the contracts as shipped, that is false.** Deleting a box releases the
min-balance *requirement*; the ALGO stays in the **app account**. Getting it out
needs either an inner Payment or app deletion, and:

- `SyncCommitteeVerifier`: no `itxn` anywhere in `verifier.py`, and its ARC-4
  router asserts `OnCompletion == NoOp` ⇒ **cannot be deleted, cannot pay out**.
- `TrustedRootAnchor`: exactly one outbound Payment exists —
  `unpin`'s refund of a *pin* box's MBR to the recorded payer. The **ring boxes
  have no deleter at all**, and the app cannot be deleted ⇒ the ring's 8.72 ALGO
  at N=128 is locked permanently.
- `Mpt7ReceiptApp` / `Mpt6ComposerApp` / `MptSegmentApp`: no payout path either —
  and the only mechanism that *could* recover their balances is the very
  `DeleteApplication` hole §9.1 documents, which, as measured, **leaves the
  balance at the orphaned app address anyway** (1,000,000 µALGO went in, the app
  was deleted, the balance stayed, nobody can reach it).

So the honest statement, which M10's schema artifact encodes as
`"lifetime": "permanent"` / `"deleted_by": null`, is:

> **Box MBR is reusable within an app (M4's `retire`/`install_abort` genuinely
> free the space for a later generation), but it is never withdrawable. Every
> µALGO sent to any of these five app accounts is spent, not lent.**

Which is precisely why §7.1's fund-to-the-byte recipe matters, and why §10.3's
19× over-funding is a real cost on any network where ALGO is real. **G8-M10**
gates it: after `apply`, `amount − min-balance` must be zero for every app except
the declared T2 float.

Whether to *change* the contracts to make MBR recoverable (a `gov`-only sweep
method) is a contract-design question for a future revision, named here as
`O-M10-6` because M10 is the module that makes it visible.

---

## 11. Edge cases

**11.1 `ring_n` not a power of two.** Rejected at create (`assert n & (n-1) == 0`;
`test_ring_n_must_be_power_of_two` proves it rejects 7). `deploy plan` must reject
it *client-side first*, before spending a funding Payment on an app that will
never be created.

**11.2 `ring_n = 256`.** 32 `ring_init_chunk` transactions ⇒ **two** atomic
groups. Legal and resumable (`ring_cursor`), but it breaks 008 §7.8's
"one group, appears atomically" argument. `plan` prints the group count; the
target file may set it; the default stays 128.

**11.3 A partially initialised ring.** Inert by design (008 §7.7: `N10` blocks
anchoring while `ring_cursor < ring_size`, `frozen` starts at 1). Resume by
re-running `apply`. No special path needed — this is exactly what §7.3's diff
computes.

**11.4 An already-appended fork row disagrees with the target.** **FATAL.**
Append-only, strictly increasing, no editor, no deleter. `apply` stops with
"on-chain fork row *i* is `(…)`, target is `(…)`; the table cannot be corrected
in place — see §6.5". It must never append a "corrected" row on top: the lookup
takes the *last* row with `activation_epoch <= epoch`, so a duplicate epoch is
rejected outright and a later epoch would leave the wrong row live for every
earlier epoch.

**11.5 M8 created against a wrong `m4_app_id`.** Write-once, no setter ⇒
redeploy. §5.3 step 2's program-hash check is what stops it, and it is the only
thing that can.

**11.6 A stranded T2 staging box.** Cannot arise from the shipped client: the
box is opened and closed inside one atomic group, and groups are atomic (009
§9.2). It *could* arise from a future client that splits staging across groups.
`inspect --boxes` reports any box matching the staging shape as an anomaly
(§8.3). **No sweeper is built** — the same call 008 §15.4 item 5 made for M8's
own boxes, recorded so a future pass does not build one speculatively.

**11.7 The donor pair already exists on the target network.** Reuse from the
manifest; do not redeploy. If the manifest is absent, recover by program hash
(§7.4); the pair is 48 B and 4 B, so a duplicate costs 0.2 ALGO and is not
harmful, but it does mean the manifest is the source of truth for which pair the
relayer is configured with.

**11.8 `apply` run against the wrong network.** Refused on genesis-hash
mismatch (§6.1). **G7-M10.**

**11.9 An app account with a balance the tool did not send** (an operator's own
transfer, or a leftover T2 float). `apply` computes a *top-up*, never a target
balance, so extra funds are left alone; `verify`'s G8-M10 check reports them
rather than trying to reclaim them (it cannot — §10.4).

**11.10 `renounce()` already called on the target M8.** Every governance step in
the diff becomes impossible. `plan` must detect `gov == zero address` and report
the whole governance section as unreachable, rather than sending calls that will
fail `N23`.

**11.11 Deploying a consumer before M8 exists.** §5.7 — the compile step needs
M8's real id. `plan` orders the graph (§5.1) and refuses to compile a consumer
whose `bound_to` app is not yet in the manifest.

**11.12 The fork table is full.** M4 capacity 16 rows, M8 capacity 8
(`FORK_TABLE_CAPACITY`). At mainnet's historical rate (~2 forks/year) M8's 8 rows
are ~4 years. `plan` warns at `fork_count >= capacity − 2`, because the remedy
(§6.5) is a full cascade and needs planning, not discovery.

---

## 12. What M10 explicitly does not resolve, from other modules' hand-offs

Answering these in one place mirrors 009 §15.3, and every row cites the section
that owns it.

**From 008 §15.4 (M8's own "flagged for M10" list), all six:**

| # | Flagged | Resolution |
|---|---|---|
| 1 | Choosing and funding `N`; the 16-txn `ring_init` group plus prior funding | §5.3, §10.2. Default `N = 128` per 008 §7.8; `ring_init_chunk` group built by `plan_box_refs`, funding by §7.1's staged recipe |
| 2 | Seeding the fork table, generated, never hand-entered | §5.5 — **generated**, and shown to reproduce all seven real gindices from `relayer/ssz/`'s existing field lists |
| 3 | Pinning M4's approval-program hash | §5.3 step 2 (counterparty check) **and** §7.4 (manifest recovery) — the pin does double duty |
| 4 | The `renounce()` decision and its migration cost | §6.5's table, and the recommendation **not** to renounce on a first deployment; `renounce` stays an interactive subcommand, never scripted (`O-M10-4`) |
| 5 | No box sweeper is needed | Confirmed, §11.6 — and extended: none is needed for M7's T2 boxes either, for a *different* reason (atomicity, not inertness) |
| 6 | Deployment MBR 9.328 ALGO at `N = 128`, all recoverable | **Corrected twice**: the figure is **9.3562** (§4.2, §3.3 drifts 2–3), and "recoverable" is **false** (§10.4) |

**From 007 §8.4 (M7):**

| Flagged | Resolution |
|---|---|
| Box schema and MBR policy for T2 staging boxes | §4.3, §5.4 — an 8-byte name, `2,500 + 400×(8+leaf)`, max 1,644,100 µALGO, funded once as a float rather than per proof |
| A sweep for stranded staging boxes | §11.6 — not needed today; `inspect` reports, does not sweep |
| The trusted-setup artifact (≈537 MB proving key, ≈18 GB ceremony, fetch-and-checksum, ~40 min Lagrange build) | **Deferred with T3 itself**, §1.2 and `O-M10-1`. Recorded in full so it is not lost; gated on T3 shipping, exactly as M9 gated the proving service |

**From 004 (M4) and 001 (M1):**

| Flagged | Resolution |
|---|---|
| 004 §1.2: "Box schema deployment/MBR tooling — M10 (M4 specifies the schema; M10 owns provisioning it)" | §4.1, §5.2, §10.2 — and the schema is now generated from M4's own constants rather than restated (§3) |
| 001 §4.5/§10: "Sizing, box naming, and session resumability are M4/M10" | Sizing and naming: §3, §4.1. Session resumability is **M9's** (`inst_cursor`, 009 §9.1) — M10 funds the boxes, M9 fills them |
| 001 §4.5: "a one-time ~19.7 ALGO of **recoverable** box MBR" | The 19.7 figure is confirmed exactly (19,760,900 µALGO **measured**); "recoverable" is **corrected** (§10.4) |

**From 009 §15.4 (M9's hand-off to M10):**

| Flagged | Resolution |
|---|---|
| M9 reads app ids; never creates apps, funds `N`, seeds fork tables, pins M4's program hash | All four are M10's and all four are in §5/§7 |
| `GroupPlan` is reusable for M10's deployment groups; `plan_box_refs` is what a `ring_init` at arbitrary `N` needs | **Taken up** — §5.3 uses `plan_box_refs` verbatim and §8.1 makes `deploy → relayer` the dependency direction |
| 008 §15.4's `renounce()` migration remains M10's | §6.5 |

**From M9's own honest gaps (b) and (c)** — which `ROADMAP.md`'s M9 row says
"M10 … can absorb without re-opening this pass's own scope":

| Gap | Verdict |
|---|---|
| (b) Resuming an M4 install stuck in `VALIDATED`/`OPENING_BOXES` raises `NotImplementedError` | **Not M10's.** It is reachable only through `install_begin`'s rollover flow, which is an *install* concern; M10's diff stops at "funded and governed". Handed back to a future M9 revision, explicitly, rather than absorbed silently |
| (c) A T2 receipt combined with an M8 anchor has no deployed contract to drive it | **Not M10's either** — it needs a contract that combines M7's box-staging path with `mpt7_result_against_anchor`, which does not exist. M10 will deploy it the day it exists (§5.7's mechanism is already general); building it is an M7-revision task |

---

## 13. Test plan

Per the plan's Verification section, a module touching real data validates
against real data. **M10's real-data test is a real deployment**: a from-scratch
deploy of all four contracts against real dev-mode algod, then M9 driving real
mainnet data through it end to end. Suites follow the M5 §9 / M6 §11 / M7 §9 /
M8 §13 / M9 §13 numbering convention.

### 13.1 Suite X — the schema artifact, offline (`ci-offline.yml`)

Pure imports. No algod, no network, no `puyapy`.

| id | test | expectation |
|---|---|---|
| X-1 | `deploy schema --check` | regenerates byte-identically; **G3-M10** |
| X-2 | Every box `value_bytes` in the artifact vs the contract's own constant | equal for `forks`(576), `forks8`(320), `k:`(6,144), `s:`(424), `a:`(96), `h:`(154), `p:`(186) |
| X-3 | Record-offset table vs `contracts/state_anchor/constants.py` | all nine `OFF_*` match; `RECORD_LEN == 154` |
| X-4 | MBR model vs the protocol formula for every family | 234,900 / 2,464,500 / 176,100 / 44,900 / 132,900 / 68,100 / 80,900 |
| X-5 | `min_extra_pages` vs the compiled sizes | 3 / 1 / 1 / 1 / 0 (§4.6) |
| X-6 | Global-state schema vs the ARC-56 artifacts | M4 (13,7) ⇒ 820,500; M8 (9,1) ⇒ 406,500 |
| X-7 | Both fork-row shapes round-trip | M4's 36 B with a 4-byte `fork_version`; M8's 40 B all-uint64 — encode/decode against `_read_row`'s own field order |

### 13.2 Suite G — gindex generation, offline

| id | test | expectation |
|---|---|---|
| G-1 | `m4_fork_row("fulu")` | `finality_gindex=169`, `current_sc=86`, `next_sc=87` — reproducing `test_live_e2e_finality.py`'s hand-entered constants **from the field list** |
| G-2 | `m8_fork_row("fulu")` | `802 / 803 / 806 / 69` |
| G-3 | `m8_fork_row("deneb")` | `802 / 803 / 806 / **37**` — the two-row trap's other half (008 §3.4, `test_forks.py` F6) |
| G-4 | The `block_hash` cross-check | folds to the spec-published `EXECUTION_BLOCK_HASH_GINDEX_DENEB = 812`; generator refuses to emit a row if it does not |
| G-5 | Field-list drift | Fulu's list is 38 entries; a live `/eth/v1/config/spec` fetch confirms `DENEB_FORK_EPOCH=269568`, `ELECTRA_FORK_EPOCH=364032` (skips if unreachable, as `test_forks.py` already does) |
| G-6 | Negative: a deliberately corrupted field list | generator **refuses**, does not emit a plausible-looking wrong gindex |

### 13.3 Suite D — deployment, live devnet (`ci-live.yml`)

| id | test | expectation |
|---|---|---|
| D-1 | `apply` from empty state | all six apps created; `frozen==0`, `ring_cursor==ring_size`, `fork_count` correct, `gov` correct |
| D-2 | `apply` again immediately | **zero transactions sent**; **G2-M10** |
| D-3 | Kill after `create`, before fork rows; re-run | appends exactly the missing rows; **G6-M10** |
| D-4 | Kill mid `ring_init_chunk` (N=128, after 7 of 16); re-run | resumes at the real `ring_cursor`, no duplicate box creates |
| D-5 | Delete the manifest; `recover --creator ADDR` | rebuilds it by approval-hash match, disambiguating by `m4_app`/`gov`; matches the deleted file |
| D-6 | `apply --target testnet.json` against the devnet algod | **refused** on genesis-hash mismatch; **G7-M10** |
| D-7 | Post-`apply` balance check | `amount − min-balance == 0` for M4/M8/M6/donors, `== float` for M7; **G8-M10** |
| D-8 | Predicted vs measured MBR at every stage | equals `account_info(app).min-balance` exactly — 334,900 / 20,095,800 / 232,900 / 777,700; **G5-M10** |
| D-9 | `verify` against a deployment made by a *different* process | passes using only public reads and pinned hashes |
| D-10 | `plan` with **no signer configured** | full diff, real predicted app ids and funding figures, zero transactions |
| D-11 | Two-stage funding, race path | fund the *wrong* predicted id deliberately; `apply` detects the id mismatch, refuses to continue, and reports a bounded 0.3349 ALGO loss — never proceeds with an app it did not fund |

### 13.4 Suite S — the security matrix, live devnet

| id | test | expectation |
|---|---|---|
| S-1 | `ApplicationUpdateTxn`/`ApplicationDeleteTxn` against M4 and M8, from the creator **and** from a stranger | **all four rejected** |
| S-2 | The same against M5/M6/M7 drivers | **currently accepted** — asserted as the known state (§9.1), with the test naming the defect so a future fix flips it |
| S-3 | `apply --target mainnet-shaped` with an `"unrestricted"` contract | **refused** before any transaction (§6.4 item 3) |
| S-4 | M8 `create` with an `m4_app_id` whose program hash is not M4's | **refused client-side**, before the funding Payment |
| S-5 | Target where `governance == signer` | warns loudly; `--yes` still required |
| S-6 | Fork row disagreeing with an already-appended on-chain row | FATAL, no append attempted (§11.4) |
| S-7 | Tampered manifest (app id swapped for a `FakeAnchor`) | `verify` fails on the approval-hash pin, not on behaviour |

### 13.5 Suite E — the real end-to-end gate

One test, and it is the module's reason to exist:

> **E-1 (G1-M10).** From an empty devnet: `deploy apply`, then construct a
> `RelayerConfig` **from the manifest alone, with no hand-edited field**, and
> drive M9 through `sync(install=True)` → `sync(update=True)` → `anchor()` →
> `prove_receipt(against_anchor=True)` against **real, live mainnet data**.
> Assertions: on-chain `fin_slot`/`fin_root`/`fin_state_root` match the real
> fetched update; `attest` returns an `el_receipts_root` byte-identical to the
> real EL block's; and the recovered receipt fields match a real
> `eth_getBlockReceipts` response byte-for-byte.

Every one of those steps is already proven individually (M9's G2/G3/G5/G6-M9,
M8's G1-M8). What has **never** happened is any of them starting from a
deployment that a tool produced rather than a pytest fixture — and that is
exactly the claim M10 exists to make. Expected wall-clock: ~15–25 minutes,
dominated by the 64 real `install_chunk` submissions.

---

## 14. Acceptance gates

| Gate | Statement | How judged |
|---|---|---|
| **G1-M10** | A from-scratch deploy of all four contracts + donors, fully funded and governed, drives M9's full real-mainnet-data pipeline from the manifest alone | E-1, real submissions, not `simulate` |
| **G2-M10** | `apply` is idempotent — a second run sends **zero** transactions | D-2 |
| **G3-M10** | The schema artifact regenerates byte-identically in CI | X-1, `ci-offline.yml` |
| **G4-M10** | Every fork-row gindex is **generated**, and reproduces all seven independently-confirmed real values (169/86/87/802/803/806/69, plus Deneb's 37) | G-1…G-4 |
| **G5-M10** | Predicted MBR equals real `min-balance` at every lifecycle stage of every contract | D-8 |
| **G6-M10** | A killed deploy resumes with no local progress file beyond the identity manifest, and duplicates nothing | D-3, D-4 |
| **G7-M10** | `apply`/`verify` refuse a genesis-hash mismatch | D-6 |
| **G8-M10** | No stranded funds: `amount − min-balance` is zero for every app but the declared T2 float | D-7 |
| **G9-M10** | The §9.1 security matrix is asserted, not assumed, and mainnet deployment of an unrestricted contract is refused | S-1, S-2, S-3 |
| **G10-M10** | No cost number in the implementation report lacks a real response behind it | `ARCHITECTURE.md`'s standing rule |

---

## 15. Honest gaps and deferred work

**Gaps this design knowingly leaves open:**

1. **M10 cannot fix §9.1.** The `UpdateApplication`/`DeleteApplication` hole in
   M5/M6/M7's drivers is a contract defect. M10 detects it, refuses to deploy it
   to mainnet, and asserts it in a test — but the live mainnet app `3664247481`
   stays hijackable until an M7 revision adds four lines. This is the largest
   real risk this document surfaces and the one it is least able to close.
2. **The app-id prediction race is narrowed, not eliminated** (§7.1). Algorand
   offers no id reservation. The residual exposure is one create-time MBR
   (0.2329–0.3349 ALGO) per lost race, and `apply` refuses to continue on a
   mismatch — but on a busy network the retry loop is real.
3. **No testnet or mainnet run is in the acceptance gate.** G1-M10 is a devnet
   deployment carrying real mainnet *data*. That matches how M4/M7/M8/M9 were
   all validated, and it is genuinely weaker than a real public-network
   deployment. §6.3 recommends a testnet run before v1; M12 should require one.
4. **M6 still has no client that submits.** §4.4 — `prove_account` never sends a
   transaction and `test_l5` does not exist. `ROADMAP.md`'s M9 row already
   correctly lists G4-M9 as not closed; this is worth restating plainly here
   since M10 deploys `Mpt6ComposerApp` without anything in its own gates
   exercising it end to end. M10 deploys `Mpt6ComposerApp` anyway (M11 and
   `bench/composer_bench.py` need it) but nothing in M10's own gates exercises
   it end to end, and it would be dishonest to imply otherwise.
5. **Only Fulu's `BeaconState` field list exists** in `relayer/ssz/`. Deneb's
   (and Electra's, which coincides with Fulu's at depth 6) must be added for
   G-3, against a real fetched spec. Since `/eth/v2/debug/beacon/states/{slot}`
   404s near the ~15-month-old Deneb→Electra boundary (008 §17, 009 §16 gap 4),
   the field list can be confirmed against the published spec source but the
   *fold* cannot be re-derived from live archive data — the same ceiling
   `test_forks.py` already hit.
6. **The MBR "recoverable" correction is documented, not fixed** (§10.4).
   Making it recoverable is a contract change (`O-M10-6`).
7. **`inspect`'s decoding is only as right as the schema.** If a contract's
   constants change without regenerating, X-1 catches it in CI — but a
   deployment made from an older schema version is decoded by a newer one only
   because every layout here has so far been append-compatible. A real schema
   *migration* story (version N artifact decoding a version N−1 deployment) is
   not designed here and is `O-M10-7`.

**Deferred (`O-M10-*`), each measurement- or event-gated:**

| id | idea | gate |
|---|---|---|
| `O-M10-1` | T3 trusted-setup provisioning: fetch + checksum the ≈18 GB ceremony, convert, persist the ≈537 MB proving key (007 §8.4) | only when T3 ships a prover |
| `O-M10-2` | A T2 box sweeper | only if a stranded staging box is ever observed by `inspect` |
| `O-M10-3` | Multi-sig / hardware governance signer | before any mainnet deployment holding real value |
| `O-M10-4` | Automating `renounce()` | **deliberately never** — §6.5 |
| `O-M10-5` | An on-chain app registry so consumers resolve ids at runtime | rejected for v1: contradicts TP-M8-4's compile-time binding |
| `O-M10-6` | A `gov`-only MBR sweep method on M4/M8, and an `OnCompletion` gate on M5/M6/M7 | contract changes; M7/M4 revision work that M10 makes visible |
| `O-M10-7` | Schema-version migration (decode an older deployment with a newer artifact) | when the first backward-incompatible layout change lands |
| `O-M10-8` | Deploy from a pinned, reproducible build (vendored `puyapy`, hash-locked) rather than whatever is on `PATH` | when a second person deploys |

---

## 16. File layout

```
deploy/
  __init__.py
  __main__.py              python -m deploy
  cli.py                   argparse shell (§8.2)
  config.py                DeployTarget: network, governance, ring_n, forks, per-app flags
  manifest.py              read/write/verify, keyed by genesis hash (§7.2)
  compile.py               puyapy → TEAL → algod compile, SHA-256 pinning   ← promotes 5 copies
  create.py                §7.1's simulate-predict-fund-create recipe;
                           TP-M8-4's patched-consumer compile (§5.7)
  mbr.py                   the MBR model, driven by the schema (§4, §10)
  forks.py                 gindex generation + per-fork field lists (§5.5)  ← THE new correctness work
  diff.py                  desired − actual → a transaction list (§7.3)
  inspect.py               decode global state + boxes through the schema (§8.3)
  plans/
    m4.py  m6.py  m7.py  m8.py  donors.py     one per contract, §5.2–§5.6
  schema/
    generate.py                               imports contracts.*.constants (§3.1)
    SyncCommitteeVerifier.schema.json
    TrustedRootAnchor.schema.json
    Mpt7ReceiptApp.schema.json
    Mpt6ComposerApp.schema.json
  targets/
    localnet.json  testnet.json  mainnet.json
  manifests/
    <genesis_id>.json                         committed for public deployments; §9.5

tests/deploy/
  test_schema.py           Suite X
  test_forks_gindex.py     Suite G
  test_deploy_live.py      Suite D
  test_security_matrix.py  Suite S
  test_end_to_end.py       Suite E (G1-M10)
```

**Files this module changes elsewhere** (small, and each for a stated reason):

- `tests/sync_committee/conftest.py`, `tests/state_anchor/conftest.py` — their
  `create`/`puya_compile`/`patched_repo_copy` helpers become thin wrappers over
  `deploy.*`, so there is one deployment recipe rather than three. *Rebasing the
  live test files themselves onto the tool is M11's* (009 §15.4 already assigns
  the analogous rebasing job to M11); M10 does not touch the test bodies.
- `ROADMAP.md` — M10's row, plus the correction §10.4 requires to four
  documents' "recoverable" language (the M9 row's own G4-M9 status is already
  accurate and needs no change, per §15 item 4).
- `.gitignore` — `deploy/manifests/*.local.json` for private deployments.

**Nothing under `contracts/` is modified.** Same scope boundary M8's and M9's
passes kept.

---

## 17. Implementer checklist (normative MUSTs)

1. `deploy/` **MUST** import `relayer` (donors, `plan_box_refs`, `relayer.ssz`,
   `relayer.sources.beacon`) and **MUST NOT** be imported *by* `relayer`.
   `relayer/`'s existing no-`algopy`/no-`tests.*` rule (G8-M9) stays enforced;
   `deploy/` is allowed both.
2. **MUST** generate every schema artifact from `contracts/**/constants.py` by
   import. **MUST NOT** hand-write any byte count, offset, box name or MBR
   figure into the artifact.
3. **MUST** generate every gindex from real SSZ field lists (§5.5) and **MUST**
   refuse to emit a fork row whose `block_hash` cross-check does not reproduce
   `EXECUTION_BLOCK_HASH_GINDEX_DENEB = 812`. **MUST NOT** accept a gindex from
   a config file or a command-line flag.
4. **MUST** handle both fork-row shapes explicitly — M4's `(uint64, byte[4],
   uint64, uint64, uint64)` and M8's five `uint64`s. **MUST NOT** assume one.
5. **MUST** use §7.1's simulate-predict-fund-create recipe, funding **only** the
   create-time MBR before the id is confirmed, and **MUST** assert the assigned
   app id afterwards, aborting on mismatch. **MUST NOT** deploy a throwaway probe
   app or hardcode a `TxnCounter` offset.
6. **MUST** compute `extra_pages` from the real compiled size. **MUST NOT** ship
   a constant.
7. **MUST** verify the counterparty's approval-program hash before passing an
   app id into a write-once field (M8's `m4_app_id`).
8. **MUST** record the network genesis hash in every manifest and **MUST** refuse
   to `apply`/`verify` against a different one.
9. **MUST** compute the plan as a diff against on-chain state (`ring_cursor`,
   `fork_count` + decoded rows, box list, balances). **MUST NOT** keep a local
   progress file. The manifest records identity only.
10. **MUST** treat a disagreeing already-appended fork row as FATAL and **MUST
    NOT** append a correction on top.
11. **MUST** use `relayer.group.boxes.plan_box_refs` for the `ring_init_chunk`
    groups. **MUST NOT** ship a fixed box-reference constant — it has been wrong
    twice in this codebase already (009 §18 item 2).
12. **MUST** reuse `relayer.group.donors.deploy_donor_pair`. **MUST NOT**
    reimplement or copy it.
13. **MUST** require `governance` explicitly in the target and **MUST** warn when
    it equals the signer.
14. **MUST** refuse to deploy any contract whose schema declares
    `"on_completion_gate": "unrestricted"` to a mainnet genesis hash (§6.4), and
    **MUST** assert the §9.1 security matrix in Suite S.
15. **MUST** fund to the computed minimum, and **MUST** report
    `amount − min-balance` after `apply` (G8-M10). **MUST NOT** describe box MBR
    as recoverable anywhere in the tool's output or docs (§10.4).
16. **MUST** work with no signer for `plan`, `verify`, `inspect` and `schema`,
    using `allow_empty_signatures=True`.
17. **MUST** patch `handoff.ANCHOR_APP_ID` into a temporary copy when compiling
    any M8 consumer, and **MUST** record `bound_to` in the manifest. **MUST NOT**
    edit any file under `contracts/`.
18. **MUST** keep `renounce` interactive and unscripted, printing §6.5's
    migration table first.
19. **MUST** cite a real `simulate`/`send`/`account_info` response for every cost
    number in the implementation report (`ARCHITECTURE.md`).
20. **MUST** update `ROADMAP.md` to record: M10's own results, the
    MBR-recoverability correction across 001/004/008/009 (§10.4), the three
    schema drifts (§3.3), `SyncCommitteeVerifier`'s never-recorded 6,980 B
    compiled size (§4.6), and — first, and in its own sentence — the §9.1
    mainnet finding.
