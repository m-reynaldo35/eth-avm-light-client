# 008 — M8: Trusted-root anchor contract

**Status**: Design drafted, awaiting human review.
**Depends on**: M3 (SSZ Merkle branch verifier), M4 (sync-committee update
verifier), and — for its consumers, not for itself — M6 and M7.
**Consumed by**: M6 (`R_state`), M7 (`receipts_root`), M9 (relayer), M10
(deployment tooling).
**Design-time convention, inherited**: every number below is labelled
**measured** (a real `simulate`/`send` response already in this repo, cited to
its file) or **projected** (an estimate this document owns and an
implementation pass must replace). `ARCHITECTURE.md`'s rule applies: no cost
claim ships without a real response behind it.

---

## 0. The question, stated first

`service/x402_endpoint/main.py`, lines 87–97, live on Algorand mainnet against
app id `3664247481`, moving real USDC through GoPlausible's facilitator:

```python
receipts_root_hex = header["receiptsRoot"]
...
if "0x" + root_hash.hex() != receipts_root_hex:
    raise HTTPException(status_code=500, detail="reconstructed receiptsRoot does not match the RPC block header")
```

That comparison checks that *our* trie reconstruction agrees with *the RPC's own
header*. It does not check that the RPC told the truth. The service's own module
docstring says so, in the project's own words:

> *"Honest, documented gap (TP-M7-2, unchanged from the design doc): M8
> ("Trusted-root anchor contract") does not exist yet, so this service trusts the
> `receiptsRoot` it reads out of the RPC's own block header response — it is NOT
> yet anchored on-chain via a trustless consensus proof."*

So a payer today buys a real Algorand transaction that really walks a real Merkle-Patricia
trie and really verifies `keccak256(node) == expected` at every hop — all of it
conditional on one unverified 32-byte string that a single HTTP endpoint handed
the relayer. Everything M1–M7 built is a **conditional** statement, and M8 is the
module that discharges the condition.

**M8's job, stated as one sentence:** take a beacon block header that M4 has
already proven is FFG-finalized under a 2/3 sync-committee signature, prove by
SSZ Merkle branch (M3) that a specific Ethereum execution block's
`receipts_root`, `state_root` and `block_number` are inside that beacon block,
write the result into Algorand box storage keyed by execution block number, and
expose it to M6/M7 through a hand-off a malicious relayer cannot substitute.

**Three things this document has to get right, in order of how much damage
getting them wrong does:**

1. **The finality semantics** (§5). This is the actual root-of-trust question for
   the entire project, and the honest answer is less comfortable than the
   marketing version. It is stated in full, including the part where Ethereum
   does not slash sync-committee messages.
2. **The hand-off to M6/M7** (§8.3–§8.6). If a relayer can point a consumer at an
   anchor app of its own, M8 is decorative. The AVM has no cross-app box read, so
   this is not a one-liner.
3. **Retention and eviction** (§7) — `ROADMAP.md`'s named M8 open question, and
   the one with a real ALGO price tag on both answers.

---

## 1. Scope, non-goals, trust preconditions

### 1.1 In scope

1. **The beacon→execution bridge.** Given a 112-byte SSZ `BeaconBlockHeader`
   whose `hash_tree_root` equals a root M4 has verified, prove
   `execution_payload.state_root`, `execution_payload.receipts_root` and
   `execution_payload.block_number` against the header's `body_root` using M3's
   fold at fork-gated, composed generalized indices (§3).
2. **`is_valid_light_client_header`'s execution branch.** M4 §12.3 item 2
   explicitly does not perform it and assigns it here. §3 is that check, composed
   deeper than the spec's version for reasons §3.1 prices.
3. **Historical reach.** Anchoring an execution block older than the currently
   finalized one, via `BeaconState.block_roots` — an 8,192-slot (~27.3 h) window
   from any finalized header (§4).
4. **Persistent, keyed root history** in Algorand box storage, with a decided and
   priced retention/eviction policy (§7).
5. **A frozen, ARC-56-publishable ABI** for M6, M7, M9 and M10 (§8), including
   the two permitted consumer hand-offs and their attack traces.
6. **A governance surface that can censor but cannot forge** (§5.7), plus an
   equivocation latch (§5.5).

### 1.2 Non-goals (explicit)

Each of these is a real thing someone will ask for. Each is out, with a reason
and, where the reason is cost, the arithmetic.

| # | Not doing | Why |
|---|---|---|
| NG1 | **Pre-Altair forks** | No sync committee exists before Altair, so there is no light-client protocol to descend from. M4 is Altair+ by construction; M8 inherits it. |
| NG2 | **Pre-Bellatrix forks** | `BeaconBlockBody` has no `execution_payload` field before Bellatrix. There is nothing to bridge to. `EXECUTION_PAYLOAD_GINDEX = 25` first exists at Bellatrix (003 §2.4). |
| NG3 | **Gloas** | Gloas restructures the block body: 003 §2.4 measures `EXECUTION_BLOCK_HASH_GINDEX_GLOAS = 2856` at **depth 11**, and 004 §4.5 states plainly that *"the Gloas row is not approved by this document."* M8 does not approve it either. §10.5 additionally shows depth-11 branches push HISTORICAL mode's argument payload over the 2,048-byte cap, so Gloas is not merely unapproved — it needs a structural change (§17, O-M8-4). |
| NG4 | **Archive mode: anchoring blocks more than 8,192 slots behind the finalized header** | Requires descending `BeaconState.historical_summaries`, a `List[HistoricalSummary, 16777216]`. §4.4 does the arithmetic: composed depth ≈ **43**, `103 + 83·43 =` **3,672** budget and **1,376 bytes** of branch — which alone exceeds two-thirds of the argument cap. Deferred with numbers, not hand-waved (§17, O-M8-3). |
| NG5 | **Anchoring the optimistic/attested header** | §5.2. A sync committee attesting a head block is a materially weaker statement than a sync committee attesting that a block is FFG-finalized, and the difference is exactly the security M8 exists to provide. |
| NG6 | **`block_hash`, `transactions_root`, `withdrawals_root`, `logs_bloom`** | v2. The record's `version` byte (§6.1 offset 0) exists so this is a format bump, not a redesign. §17 O-M8-2 prices `transactions_root` and explains why it is the one that actually buys something (it makes receipt *exclusion* meaningful, answering 007 §8.3). |
| NG7 | **Fraud proofs, challenge games, bonded relayers, slashing** | M8 has exactly two remediations: the governance `revoke` (§5.7) and the `conflict` latch (§5.5). Anything richer is a protocol, not a contract, and it belongs in a document that does not also have to ship. |
| NG8 | **Any economic mechanism** — anchoring fees, MBR amortisation across queries, paying the relayer | M10's, and arguably a product decision rather than an engineering one. §7.5's pinned tier is a *mechanism* for someone to pay MBR; it sets no price. |
| NG9 | **Multiple execution chains / multiple M4 instances per M8 deployment** | `m4_app_id` is immutable at create (§6.2) precisely so it cannot be a parameter (§11, S3). One chain per deployment. Deploy twice for two chains. |
| NG10 | **Cross-app box reads** | Not a choice — §8.5: the AVM has no opcode for it. Listed here so a reviewer does not spend time looking for the "obvious" design. |
| NG11 | **Verifying the beacon *state* beyond `block_roots`** | Balances, validator sets, `historical_summaries` — all out. `block_roots` is in because §4 needs exactly it and nothing else. |
| NG12 | **Re-verifying M4's BLS signature** | M8 reads M4's *result*. Re-doing the pairing would cost 55,474 measured (004 §9.1) per anchor, for zero additional security: M4's global state is only written by a path that already did it. |

### 1.3 Trust preconditions

House convention (M5 §1.3, M6 §1.3, M7 §1.3): a numbered list of things M8 does
not prove and a consumer must know it is assuming.

- **TP-M8-1 (the ceiling of this entire project, and it lives here).**
  **Ethereum does not slash sync-committee messages.** A validator who signs a
  conflicting `SyncAggregate` faces no protocol penalty. So the statement M8
  ultimately anchors is *"342 of 512 pseudo-randomly-sampled validators asserted
  that this beacon block is finalized"*, and those 342 risked nothing by
  asserting it. This is **weaker than Casper FFG economic finality**, which is
  backed by ≥1/3 of total stake being slashable, and it is weaker than running a
  full node. It is inherited from Ethereum's own light-client protocol, not
  introduced by this project — but M8 is the first module where it becomes a
  *user-visible* guarantee rather than an internal one, so it is stated here in
  full rather than buried. §5.3 says what M8 does about it (anchor only
  finalized headers; expose `anchored_round` so consumers can impose their own
  maturity window; latch equivocation; allow governance to revoke) and says
  plainly that none of those make it unconditional.
- **TP-M8-2 (the bootstrap root, inherited).** M4's `bootstrap()` is
  governance-supplied and weak-subjectivity-based (004 §7.3). Every committee
  since descends from it by verified rollover. If the bootstrap root was wrong,
  every anchor is wrong, and nothing on-chain can tell.
- **TP-M8-3 (the fork table is governance-supplied, and it *is* a soundness
  surface).** §3.3's table maps an epoch to the generalized indices M8 folds at.
  A governance address that appends a row with `receipts_root_gindex` set to
  802 (which is `state_root`'s position) would cause M8 to anchor the EL state
  root *as* the receipts root, with a perfectly valid Merkle proof. This is the
  one place governance can break soundness rather than merely liveness, and
  §5.7 is honest about it: rows are append-only with strictly-increasing
  activation epochs (so history cannot be rewritten), the table's contents are
  covered by acceptance gate **G4-M8** (re-derivation with
  `get_generalized_index` against pinned official vectors), and `renounce()`
  exists so an operator can make the table permanently immutable once it covers
  the deployed fork horizon.
- **TP-M8-4 (consumers must bind the anchor app id at compile or create time).**
  §8.3/§8.4. If `ANCHOR_APP_ID` is a call parameter in M6 or M7, a relayer
  supplies its own anchor app and the whole module is bypassed. This is 007
  TP-M7-7's shape exactly, and §11 S4 traces it. **Any implementation that makes
  it a parameter, box value, or mutable global is a critical defect** — stated in
  those words so a reviewer can grep for it, in the same spirit as 007's S3/Z6.
- **TP-M8-5 (an anchor is a statement about a block, not about the head).** M8
  never asserts that an anchored block is recent, canonical-as-of-now, or the
  best available. It asserts that at Algorand round `A.anchored_round`, the
  finalized beacon chain contained this execution block. Freshness policy is the
  consumer's; §6.1 carries `anchored_round` and `beacon_slot` so the consumer can
  have one.
- **TP-M8-6 (eviction is not revocation).** A record that has aged out of the
  ring (§7.3) is not false — it is unknown. `attest` fails closed on absence, and
  the failure is a *distinct* error code (`N12`) from the revoked case (`N13`)
  precisely so a consumer or relayer can tell "re-anchor it" from "do not touch
  this". Conflating them is a real bug class.
- **TP-M8-7 (M4's global state is read, not proven).** M8 reads
  `fin_slot`/`fin_root`/`fin_state_root` out of M4's global state with
  `app_global_get_ex` (§8.2). It trusts that the app at `m4_app_id` is the real,
  reviewed M4 — which is guaranteed by `m4_app_id` being immutable *and by the
  deployer having checked what is deployed there*. M8 cannot verify M4's
  bytecode on-chain. M10 owns pinning the approval-program hash in deployment
  tooling.

---

## 2. Where M8 sits — the trust chain, end to end

### 2.1 The five links

```
   [1]  weak-subjectivity bootstrap root                          M4 bootstrap()  — TP-M8-2
          │  governance-supplied, once
          ▼
   [2]  sync committee for period P, installed and hash-committed  M1 + M3 + M4
          │  512 BLS pubkeys, hash_tree_root checked against a verified update
          ▼
   [3]  2/3 aggregate BLS signature over a signing root            M1 §3 + M4 §3
          │  real ETH DST, fork_version at signature_slot-1
          ▼
   [4]  finality branch: finalized_checkpoint.root proven against
        attested_header.state_root at FINALIZED_ROOT_GINDEX        M3 fold, M4 §6.1
          │  ⇒ M4 global state: (fin_slot, fin_root, fin_state_root)
          ▼
════════ M8 STARTS HERE ═══════════════════════════════════════════════════════
          │
   [5a] hash_tree_root(BeaconBlockHeader) == fin_root              M8 §3, reusing
          │  ⇒ body_root, state_root, slot are now trusted         M4's header.py
          ▼
   [5b] (HISTORICAL only) BeaconState.block_roots[slot % 8192]     M8 §4
          │  proven against fin_state_root ⇒ an older body_root
          ▼
   [5c] execution_payload.{state_root, receipts_root, block_number}
          │  proven against body_root at composed gindices          M8 §3, M3 fold
          ▼
   [6]  box `h:<block_number & (N-1)>`  ←  the anchor record A      M8 §6, §7
          │
          ├──► M6  MODE_A_INIT arg 4  (R_state)                     M8 §9.1
          └──► M7  mpt7_result_from_group want_receipts_root        M8 §9.2
                    └──► service/x402_endpoint/main.py               M8 §9.3
```

### 2.2 What each upstream link already proved — measured, cited

| link | module | status | the number that matters |
|---|---|---|---|
| [2] committee install | M4 §8, §16 | Implemented, live | box-ref cap **8/txn**, pooled write budget **2,048 B per box reference across the group** — both measured against real algod (004 §16.2) |
| [3] BLS aggregate | M1, M4 | Implemented, live | `hash_to_g2` **17,443**, `verify_aggregate_signature` **55,474** (004 §9.1, measured) |
| [4] finality branch | M3 fold | Implemented | Puya fold cost `103 + 83·depth`, **exact on 4 measured points** (004 §2.5) |
| [5c] the fold M8 needs | M3 | Implemented, unchanged | depth 9 ⇒ **850** budget, depth 18 ⇒ **1,597**, depth 19 ⇒ **1,680** (same formula) |
| [6] box write | M4 §16, M7 | Implemented, live | box MBR `2,500 + 400·(name+value)` µALGO charged to the **app account**, needing a funding Payment (M7, real finding; `m7_relayer.py` line 119 encodes it) |

**M8 writes no new cryptography.** Every primitive it needs is already
implemented, tested against official consensus-spec vectors, and — for M3's fold
and M4's `hash_tree_root_beacon_block_header` — already compiled by Puya and
measured. M8's novelty is entirely in *which* gindices, *what* finality rule,
*where* the bytes go, and *how* a consumer reads them back. That is a design
document's job, and it is why §3–§8 are longer than the code will be.

### 2.3 The gap M8 closes, in M7's own source

For precision, the three lines in the live service that change, and what they
become. Full diff-shaped treatment in §9.3.

| `main.py` today | after M8 |
|---|---|
| L87 `receipts_root_hex = header["receiptsRoot"]` | still fetched, but demoted to a **hint used to build the proof**; it is no longer the thing the answer rests on |
| L93–97 `if "0x" + root_hash.hex() != receipts_root_hex: 500` | kept as a cheap pre-flight, but the *authoritative* comparison moves on-chain: M7 asserts `R.receipts_root == anchor_receipts_root(A)` inside the AVM (§9.2) |
| L105–110 response body | gains `beacon_slot`, `anchored_round`, `anchor_app_id`, `anchor_mode` — the payer can now independently check the chain of custody |

---

## 3. The beacon → execution bridge

### 3.1 Two candidate bridges, and why the deep fold wins

The consensus spec's own `is_valid_light_client_header` proves the **whole**
`ExecutionPayloadHeader` at `EXECUTION_PAYLOAD_GINDEX = 25` (depth 4) against
`header.beacon.body_root`, then reads `receipts_root` out of the payload header
in the clear. Doing that on-chain requires computing
`hash_tree_root(ExecutionPayloadHeader)` inside the AVM.

**Candidate A — spec-shaped: merkleize the payload header, one shallow fold.**

| component | count | Puya budget | basis |
|---|---:|---:|---|
| 17 fields → 32 leaves, tree | 31 `sha256` | ~3,100 | 004 §9.1's all-in ~100/`sha256` for chunked SSZ hashing (**projected**) |
| `logs_bloom` `Vector[byte,256]` → 8 chunks | 7 `sha256` | ~700 | same |
| `extra_data` `List[byte,32]` + `mix_in_length` | 1 `sha256` | ~100 | M3 §2.11 measured the `mix_in_length` step at 164 hand-TEAL |
| fold at gindex 25, depth 4 | — | **435** | **measured**, 004 §2.5 |
| | | **≈ 4,335** | |

plus ~500 bytes of argument (the payload header's fixed part is dominated by
`logs_bloom` at 256 B), plus a **new, fork-volatile SSZ container merkleization
module** that has to be re-derived every time `ExecutionPayload` gains a field.

**Candidate B — the deep fold: compose the gindices, prove each field directly.**

Generalized indices compose. 003 §4.5 says so explicitly and tells M8 to prefer
it:

> *"Prefer a **single deep gindex** into the nested container … over two chained
> branches … one fold at depth ~9 replaces two folds at depth 4 + 5 — cheaper,
> and it removes an intermediate root that would otherwise have to be trusted or
> re-checked."*

| component | count | Puya budget | basis |
|---|---:|---:|---|
| fold at 802 (`state_root`), depth 9 | 1 | **850** | `103 + 83·9`, **measured formula** (004 §2.5) |
| fold at 803 (`receipts_root`), depth 9 | 1 | **850** | same |
| fold at 806 (`block_number`), depth 9 | 1 | **850** | same |
| | | **2,550** | |

plus 3 × 288 = 864 bytes of branch argument. **1.7× cheaper, no new
merkleization code, no new fork-volatile container definition** — the only
fork-dependent object is a table of integers, which M4 already proved is a
tractable thing to maintain on-chain (004 §4.3).

> **Decision: Candidate B.** M8 folds each anchored field independently from
> `body_root` at a composed, fork-gated generalized index. §17 O-M8-1 shows how
> to fuse the `state_root`/`receipts_root` pair back into one depth-8 fold for a
> further measured-basis saving of **933**, and §10.5 explains why that
> optimisation is *recommended* rather than optional once HISTORICAL mode's
> argument budget is taken into account.

**A note on what Candidate B does *not* cost.** 003 §4.5's warning about "an
intermediate root that would otherwise have to be trusted" does not apply to
`body_root` here: M8 does not receive `body_root` as an argument. It receives the
112-byte header, recomputes `hash_tree_root(BeaconBlockHeader)`, asserts it
equals M4's `fin_root`, and *then* slices `body_root` out of bytes [80:112] of
the same buffer. There is no trust gap — the intermediate is re-derived, not
asserted. And the header must be supplied anyway (§4 needs its `state_root`,
§6.1 needs its `slot`), so this costs nothing extra in arguments.

### 3.2 The composed generalized indices — derived, not copied

`BeaconBlockBody` has 10 (Bellatrix), 11 (Capella), 12 (Deneb) or 13 (Electra,
Fulu) fields. All round up to **16 leaves, depth 4**, and `execution_payload` is
field index 9 in every one of them:

```
EXECUTION_PAYLOAD_GINDEX = 16 + 9 = 25          (Bellatrix … Fulu)
```

which is exactly the value 003 §2.4 measured at 301 hand-TEAL / 435 Puya.

`ExecutionPayload` has 14 (Bellatrix), 15 (Capella) or 17 (Deneb, Electra, Fulu)
fields, rounding to **16 leaves (depth 4)** through Capella and **32 leaves
(depth 5)** from Deneb. Composition is
`g_composed = 25 · 2^d_payload + field_index`, total depth `4 + d_payload`.

| field | index | Bellatrix/Capella (d=4, **depth 8**) | Deneb/Electra/Fulu (d=5, **depth 9**) |
|---|---:|---:|---:|
| `state_root` | 2 | **402** | **802** |
| `receipts_root` | 3 | **403** | **803** |
| `block_number` | 6 | **406** | **806** |
| `block_hash` (v2, NG6) | 12 | *412* | *812* |
| `transactions_root` (v2, O-M8-2) | 13 | *413* | *813* |

**Two independent checks that this composition is right, both against numbers
this project already measured rather than against prose:**

- `block_hash` composes to **412** at Capella. The consensus spec publishes
  `EXECUTION_BLOCK_HASH_GINDEX = 412`, and 003 §2.4 measured a depth-8 fold at
  that index at 549 hand-TEAL. ✅
- `block_hash` composes to **812** at Deneb. The spec publishes
  `EXECUTION_BLOCK_HASH_GINDEX_DENEB = 812`, and 003 §2.4 measured a depth-9 fold
  at that index at 612. ✅

Two published anchors, at two different depths, both reproduced by the same
arithmetic. That is why the derivation is trustworthy — and it is *still* not
good enough to ship on:

> **Normative, and this document's most important instruction to the
> implementer.** 003 §4.5 says: *"M8 must not copy any gindex from this document
> — it must derive them with `get_generalized_index` against a pinned spec
> version and pin the official vectors alongside."* That instruction applies to
> the table above as well as to 003's own. Acceptance gate **G4-M8** (§14) is
> exactly this: the deployed table must be regenerated by
> `get_generalized_index` from a pinned `consensus-specs` checkout, and the
> generated values compared to the deployed rows, with the comparison run in CI.
> Appendix A gives the script shape.

### 3.3 The two-dimensional fork table

003 §4.5 warned that M8's gindices are *"fork-dependent in a second way"*. They
are, and §4 adds a third dimension. The deployed table (box `forks8`,
governance-appended, append-only, strictly increasing `activation_epoch` — all
three rules lifted verbatim from M4 §4.3/§4.4, which are implemented and tested):

| column | width | meaning | varies with |
|---|---:|---|---|
| `activation_epoch` | 8 B | first epoch this row applies to | — |
| `g_state_root` | 8 B | composed gindex of `execution_payload.state_root` | `ExecutionPayload` field count |
| `g_receipts_root` | 8 B | composed gindex of `execution_payload.receipts_root` | same |
| `g_block_number` | 8 B | composed gindex of `execution_payload.block_number` | same |
| `g_block_roots_base` | 8 B | gindex of `BeaconState.block_roots` **as a container field**, before the depth-13 vector index is composed in (§4.1) | `BeaconState` field count |
| **row width** | **40 B** | | |

`BeaconState` field counts: 28 at Deneb (→ 32 leaves, depth 5, `block_roots` at
field index 5 ⇒ gindex **37**), 37 at Electra and 38 at Fulu (→ 64 leaves, depth
6 ⇒ gindex **69**). This column changes at a *different* fork boundary from the
execution columns, which is the whole reason it is a separate column and not a
derived constant.

Table sizing: 1 count byte + 8 rows × 40 B = **321 B**, box name `forks8` (6 B),
MBR `2,500 + 400 × 327 =` **133,300 µALGO = 0.1333 ALGO**. Eight rows covers
Bellatrix, Capella, Deneb, Electra, Fulu with three spare for forks not yet
specified; if more are ever needed the box is resizable by governance before
`renounce()` (§5.7).

### 3.4 The two-row trap

**This is the M8 analogue of M4 §3.1's `fork_version` at `signature_slot - 1`
trap, and an implementer will get it wrong.**

In HISTORICAL mode (§4), a single `anchor_historical` call touches **two beacon
slots**: `fin_slot`, the slot of the finalized header M4 vouches for, and
`t_slot`, the slot of the older target header being anchored. They can be up to
8,192 slots (256 epochs) apart, which is far more than enough to straddle a fork
boundary.

> **Normative rule N-FORK:**
> - `g_block_roots_base` MUST be selected by the row for **`epoch(fin_slot)`**,
>   because it describes the shape of the `BeaconState` whose root is
>   `fin_header.state_root`.
> - `g_state_root`, `g_receipts_root`, `g_block_number` MUST be selected by the
>   row for **`epoch(t_slot)`**, because they describe the shape of the
>   `BeaconBlockBody` and `ExecutionPayload` of the *target* block.
> - In DIRECT mode `fin_slot == t_slot` and the distinction collapses. It is
>   still two lookups in the code, so that HISTORICAL cannot silently reuse the
>   wrong one.

Both boundaries are real and both are testable against real chain data:

| boundary | what changes | straddle-able within 8,192 slots? |
|---|---|---|
| **Capella → Deneb** | `ExecutionPayload` 15 → 17 fields ⇒ EL gindices 403 → 803, depth 8 → 9 | Yes, for ~27 h after the fork |
| **Deneb → Electra** | `BeaconState` 28 → 37 fields ⇒ `g_block_roots_base` 37 → 69, `block_roots` fold depth 18 → 19 | Yes, same window. EL gindices are **unchanged** across this one, which is exactly what makes it a trap: a test that only exercises Deneb→Electra will not catch an implementation that uses one row for everything. |

Suite F (§13.2) requires a test at **each** boundary, and specifically requires
the Deneb→Electra case, because the Capella→Deneb case fails loudly (a depth-8
branch cannot fold to a depth-9 position — the relayer simply cannot produce
siblings that hash to `body_root`) while the Deneb→Electra case fails *silently
in the wrong direction*: a depth-18 fold using the Deneb base against an Electra
state root just does not verify, so the failure is a false negative (liveness),
not a false positive. Both are bugs; only one is findable by staring at a
success case.

### 3.5 Leaves: what is a chunk, and what is derived on-chain

M3's fold takes a 32-byte leaf. Three of M8's four anchored quantities are
already 32-byte SSZ chunks; one is not.

| field | SSZ type | leaf chunk | how M8 obtains it |
|---|---|---|---|
| `state_root` | `Bytes32` | the 32 bytes verbatim | supplied as an argument; the fold binds it |
| `receipts_root` | `Bytes32` | the 32 bytes verbatim | same |
| `block_number` | `uint64` | **little-endian 8 bytes, right-padded with 24 zero bytes** | **derived on-chain** from a `uint64` argument |

> **Normative rule N-CHUNK: `block_number`'s leaf chunk MUST be constructed
> on-chain from a native `uint64` argument. M8 MUST NOT accept the 32-byte chunk
> directly.**
>
> This is M5 §5.2's rule ("derive the index from the key itself, never from a
> caller-supplied argument") transplanted, and M6 TP-M6-2's rule ("take the
> preimage, never the derived key"). The mechanism is identical: if the caller
> supplied the chunk, M8 would have to *decode* a block number back out of it to
> use as a box key, and a caller that controls both the chunk and the decode has
> a place to inject a mismatch. Taking the `uint64` and constructing the chunk
> means the box key and the Merkle-proven value are the same object by
> construction.
>
> `contracts/sync_committee/header.py:le64` already implements the
> byte-reversal, is already tested against real consensus-spec vectors, and
> already carries M4's warning that `op.itob` is big-endian while SSZ is not.
> **Import it; do not reimplement it.** M4 §3.1 calls this "trap 1" and M3 §2.11
> hit the same trap in `mix_in_length`; it has now bitten twice in this
> codebase and this is the third opportunity.

The chunk is therefore `le64(block_number) ‖ op.bzero(24)`, 32 bytes.

### 3.6 Reusing M4's header code verbatim

`contracts/sync_committee/header.py` already contains, implemented and tested
against real vectors:

- `hash_tree_root_beacon_block_header(header)` — the 5-field, 8-leaf,
  7-`sha256` fold, with M4's own docstring documenting the exact 112-byte
  layout (`slot` [0:8] LE, `proposer_index` [8:16] LE, `parent_root` [16:48],
  `state_root` [48:80], `body_root` [80:112]).
- `header_slot(header)` — `header[0:8]` little-endian → `UInt64`.
- `le64` / `be64_from_le`.

> **Normative: M8 imports these four subroutines. It does not reimplement any of
> them.** Program size is not the reason (§10.8 shows M8 has room); *divergence*
> is the reason. A second implementation of the header layout is a second place
> for the offsets to be wrong, and M4 §3 is a first-hand account of how a
> self-consistent test suite fails to notice exactly that class of error.

---

## 4. Historical mode — reaching back 8,192 slots

### 4.1 Why this section exists at all

M4 §7.4 and §12.3 item 5 are explicit: **M4 keeps only the latest finalized
tuple.** It has no history; retention is M8's problem. And M8 reads M4's
*current* global state (§8.2). Composing those two facts gives an unpleasant
consequence:

> Without HISTORICAL mode, M8 could only ever anchor the execution block inside
> **the single beacon header M4 currently holds**. Miss the window — because the
> relayer was down, or because M4 advanced between the anchor being requested and
> the group being submitted — and that execution block is unanchorable **forever**.

That is fatal for the actual product. `service/x402_endpoint/main.py` takes
`block_number` as a path parameter: a payer asks about whatever block they care
about, which is essentially never the one M4 finalized thirty seconds ago.

The consensus spec solves this the same way every light client does:
`BeaconState.block_roots`, a `Vector[Root, SLOTS_PER_HISTORICAL_ROOT]` with
`SLOTS_PER_HISTORICAL_ROOT = 8192`. Proving into it from a finalized state root
turns one anchored finality event into a **27.3-hour window** of anchorable
history (8,192 slots × 12 s).

### 4.2 Exactly what `block_roots[i]` contains, and the window it defines

Getting this off by one is the kind of error that produces a design that works on
every test and is wrong at slot boundaries, so here is the derivation from
`process_slots`/`process_slot` rather than from memory:

```
process_slots(state, target):
    while state.slot < target:
        process_slot(state)          # ← writes block_roots
        [epoch processing]
        state.slot += 1
    # then process_block(state, block)

process_slot(state):
    ...
    state.block_roots[state.slot % SLOTS_PER_HISTORICAL_ROOT] =
        hash_tree_root(state.latest_block_header)
```

`process_slot` runs with `state.slot` still at the *previous* slot, and
`latest_block_header` is the header of the most recent block processed. So:

> **`block_roots[j mod 8192]` holds `hash_tree_root` of the header of the most
> recent block at slot ≤ j.** If a block exists at slot `j`, that is exactly
> block `j`'s header root. If slot `j` was skipped, it is the root of an earlier
> block, whose own header carries an earlier `slot`.

And in the post-state of the block at `fin_slot` — which is the state whose root
is `fin_header.state_root` — `block_roots` covers indices for slots
**`[fin_slot − 8192, fin_slot − 1]`**. Block `fin_slot`'s own root is not written
until the *next* `process_slot`.

> **Normative window rule N-WINDOW:**
> `t_slot < fin_slot` **and** `fin_slot − t_slot ≤ 8192`.
>
> Both asserts are belt-and-braces: the Merkle fold is the real defence (a target
> outside the window is simply not in the vector, so no branch verifies). They
> are kept anyway, for M6 §4.5's stated reason — a cheap assert that makes the
> intended invariant legible at the site where it matters is worth its opcodes,
> and it converts an obscure "branch did not verify" into a named error code
> (`N16`).
>
> DIRECT mode is the `t_slot == fin_slot` case, which N-WINDOW *rejects* — hence
> two methods, not one with a flag. DIRECT skips §4 entirely and takes
> `body_root` straight from the finalized header.

### 4.3 The index must be derived on-chain

The composed gindex for a `block_roots` entry is:

```
g = g_block_roots_base · 2^13  +  (t_slot mod 8192)
    total depth = depth(g_block_roots_base) + 13
```

| fork | `g_block_roots_base` | base depth | composed depth | Puya fold cost |
|---|---:|---:|---:|---:|
| Bellatrix … Deneb | 37 | 5 | **18** | `103 + 83·18 =` **1,597** |
| Electra, Fulu | 69 | 6 | **19** | `103 + 83·19 =` **1,680** |

> **Normative rule N-INDEX: `t_slot mod 8192` MUST be derived on-chain from the
> target header's own `slot` field (`header_slot(target_header)`, i.e. bytes
> [0:8] of a buffer whose `hash_tree_root` is about to be checked). M8 MUST NOT
> accept a vector index as an argument.**
>
> This is M5 §5.2's `nibble_at(key, depth)` rule, third occurrence in this
> codebase. **Any implementation that takes an index parameter is a critical
> defect**, in the same sense 007 flags a caller-supplied log offset. §11 S9
> traces it.
>
> Pleasant consequence: the skipped-slot case handles itself. If slot `j` was
> skipped and the relayer supplies the header of the earlier block at `j' < j`,
> M8 derives `j' mod 8192`, and `block_roots[j' mod 8192]` genuinely is that
> block's root (a block existed at `j'`). The record is labelled with `j'`, which
> is the truth. No special case, no assert, no test hole.

### 4.4 The order of operations in HISTORICAL mode

```
1.  read (fin_slot, fin_root, fin_state_root) from M4 global state    [N4, N5]
2.  assert fin_root  != 0                                             [N5]
3.  assert htr(fin_header) == fin_root                                [N6]
4.  fin_state_root := fin_header[48:80]
    (cross-check against M4's fin_state_root global — redundant, kept, [N7])
5.  t_root  := htr(target_header)                                     [—]
    t_slot  := header_slot(target_header)
6.  assert t_slot < fin_slot and fin_slot - t_slot <= 8192            [N16]
7.  row_state := fork_row(epoch(fin_slot))          ← N-FORK          [N17]
    row_exec  := fork_row(epoch(t_slot))            ← N-FORK          [N17]
8.  g := row_state.g_block_roots_base * 8192 + (t_slot mod 8192)      ← N-INDEX
    assert_valid_merkle_branch(leaf=t_root, branch=arg, gindex=g,
                               expected_root=fin_state_root)          [N18]
9.  body_root := target_header[80:112]
10. three folds against body_root at row_exec's gindices              [N19]
11. write the record                                                  [§7]
```

Step 4's cross-check is the M6 §5.3 "redundant field cross-check" convention:
`fin_header.state_root` is already bound by step 3, and M4's
`fin_state_root` global is already bound by M4 having written it from the same
header. Comparing them costs ~20 budget and catches a whole class of
"the relayer supplied a header from the wrong M4 epoch" mistakes as a named
error rather than as a mysterious branch failure four steps later.

### 4.5 Beyond 8,192 slots — deferred, with the arithmetic

`BeaconState.historical_summaries` (Capella+) is
`List[HistoricalSummary, HISTORICAL_ROOTS_LIMIT = 16777216]`, one entry appended
per 8,192-slot period, each a container `{block_summary_root, state_summary_root}`.
Reaching an arbitrary historical block through it composes:

| leg | depth | note |
|---|---:|---|
| `BeaconState` → `historical_summaries` | 5 or 6 | field 27 (Deneb) / 36 (Electra) |
| list index within `2^24` limit | 24 | plus `mix_in_length` on the list root |
| `HistoricalSummary` → `block_summary_root` | 1 | 2 fields |
| `Vector[Root, 8192]` index | 13 | |
| **total** | **≈ 43** | |

- Fold cost: `103 + 83·43 =` **3,672** budget (**projected** from the measured
  formula).
- Branch payload: `43 × 32 =` **1,376 bytes**, which is **67 % of the entire
  2,048-byte per-transaction argument cap** before the two 112-byte headers, the
  three EL branches (864 B) and the EL leaves are counted. It does not fit in one
  transaction and it does not fit in two without a log-chain hand-off.
- Plus a `mix_in_length` step on the list root (M3 §2.11, measured 164
  hand-TEAL), and the list length itself becomes an argument the contract must
  bind.

> **Deferred as O-M8-3 (§17), not refused.** The mechanism is sound and this
> project has the pieces. The reason it is out of v1 is that it needs a
> two-transaction log-chain hand-off (M5 §7.4's mechanism, which M8 v1 otherwise
> does not need at all — see §8.1), which roughly doubles M8's own contract
> surface for a capability that the x402 service does not need: `main.py` serves
> queries about blocks people are currently interested in, and "currently
> interested in" is overwhelmingly inside 27 hours. When it *is* needed, §7.5's
> pinned tier is the cheaper answer for a known-in-advance block: pin it while
> it is still inside the window, for 0.0809 ALGO, and it never expires.

---

## 5. Finality semantics — the actual root-of-trust question

### 5.1 What M4 hands over, and what it means

M4 §7.4, on a successful update:

```
LightClientUpdateVerified(
    finalized_slot, finalized_beacon_root, finalized_state_root,
    attested_slot, attested_state_root, participation, signature_slot)
```

and globals `fin_slot`, `fin_root`, `fin_state_root`, `att_slot`,
`att_state_root`.

The two headers are **not** interchangeable, and the difference is the whole
subject of this section:

| | `attested_header` | `finalized_header` |
|---|---|---|
| what the sync committee signed | this header's root, directly, in the `SyncAggregate` | nothing directly |
| how M4 knows it | BLS aggregate verification (004 §6.1) | an M3 Merkle branch at `FINALIZED_ROOT_GINDEX` against `attested_header.state_root` (004 §6.1 step 9) |
| what it asserts | "the committee saw this block" | "the beacon state that the committee saw records this block as the finalized checkpoint" |
| Casper FFG status | none; may be reorged by the fork-choice rule at any time | **finalized**: reverting it requires ≥1/3 of total stake to be slashed |
| M4 writes it? | yes, `att_slot`/`att_state_root` | yes, `fin_slot`/`fin_root`/`fin_state_root`, and only on a 2/3-participation update (004 §6.3) |

### 5.2 M8 anchors the finalized header only. Never the attested one.

> **Decision, and it is the central one in this document: an anchor record may
> only ever descend from `fin_root`. M8 does not read `att_slot` or
> `att_state_root`. There is no method, mode, flag, or governance override that
> anchors an attested header.**

The reasoning, in the order the objections come:

1. **An attested header is explicitly optimistic.** The consensus spec calls the
   corresponding light-client field `optimistic_header` and the accompanying
   store field `optimistic_header` for a reason. It can be reorged by ordinary,
   non-malicious fork choice — no attack required, just a missed slot and a
   proposer boost. Anchoring it would mean writing roots that routinely become
   wrong.
2. **The reorg-handling problem largely disappears.** §5.4's immutability rule
   is only defensible because a finalized block does not revert under ordinary
   operation. If M8 anchored attested headers it would need a rollback path,
   which means anchors would be mutable, which means a consumer could not treat
   `attest`'s answer as final within its own transaction group — and *that*
   would push a re-check onto every consumer, which is exactly the kind of
   check-you-must-not-forget that M6 TP-M6-3 and M7 TP-M7-1 exist to eliminate.
3. **The latency cost is real and acceptable.** Finality lags the head by two
   epochs, ~64 slots, ~12.8 minutes. For M7's use case — proving that a
   transaction receipt exists — a 13-minute delay is not merely tolerable, it is
   *appropriate*: nobody should be paid out on an unfinalized Ethereum receipt.
   The x402 service can and should return a clear "not yet finalized" for a
   too-recent block (§9.3) rather than a fast wrong answer.
4. **`justified` is not offered either.** A justified-but-not-finalized
   checkpoint is one round of FFG voting away from finality and is not slashable
   to revert. It buys ~6.4 minutes of latency for a materially weaker guarantee.
   Out.

### 5.3 The uncomfortable part: sync-committee messages are not slashable

Everything above is about Casper FFG. But **M8 does not observe FFG directly** —
it observes a sync committee's *claim* about FFG, and the claim is unbonded.

Concretely, the strongest true statement M8 can make about an anchor record is:

> *At Algorand round `A.anchored_round`, at least 342 of the 512 validators in
> the sync committee for period `period(fin_slot)` — a committee whose membership
> is itself hash-committed by an unbroken chain of such attestations back to a
> governance-supplied bootstrap root — signed a message whose beacon state
> records execution block `A.el_block_number` as descending from a finalized
> checkpoint. And those 342 validators forfeit nothing if that message was a
> lie.*

Ethereum imposes no slashing condition on `SyncCommitteeMessage` /
`SyncAggregate`. A colluding 2/3 of one committee — 342 validators out of a
million-plus, pseudo-randomly sampled but *known 256 epochs in advance* — can
sign a fabricated header, and M1's pairing check, M3's fold, M4's finality branch
and M8's execution bridge would all pass, in that order, correctly. There is no
check to add. This is the light-client protocol's own security model and it is
why the specification calls the resulting object a *light* client.

**What M8 does about it, and what each measure is actually worth:**

| measure | § | what it buys | what it does not buy |
|---|---|---|---|
| Anchor only FFG-finalized headers | §5.2 | Raises the required lie from "this is the head" to "this is finalized". A committee that lies about finality is doing something categorically detectable by any full node — the fabricated finalized checkpoint contradicts the real chain — so the lie is *loud*. | Nothing on-chain notices. Detection is off-chain, by anyone watching. |
| `anchored_round` in the record | §6.1 | Lets a consumer impose its own maturity window — "I will not act on an anchor less than 1,000 Algorand rounds old" — creating a window in which an off-chain watcher can call `revoke`. | Consumers who do not impose one get nothing. M8 deliberately does not impose a global one (§5.6). |
| Governance `revoke` | §5.7 | A real remediation path for a detected bad anchor, in ~4 seconds. | Requires someone to be watching, and it is governance — a liveness dependency and a censorship vector. |
| The `conflict` latch | §5.5 | Catches on-chain the specific case where two *different* execution blocks are anchored at the same height, which is the observable signature of an equivocating committee. Fails the whole contract closed. | Only fires if the attacker anchors *both* branches. An attacker who anchors only the lie triggers nothing. |
| Per-committee `participation` floor | 004 §6.3 | Already enforced by M4 at 2/3. | 2/3 of 512 is 342 unbonded signatures. That is the number. |

> **This document does not claim M8 provides full-node security, and any README
> or marketing copy derived from it must not either.** 007 §8.6 already flags
> documentation-correction duty to M12; this is a second item for that list, and
> a more important one than the keccak correction: **`README.md` must state the
> sync-committee trust assumption in the same breath as the words "trustless" or
> "verified".**

### 5.4 Reorg handling: the immutability rule

A finalized execution block does not change. Therefore:

> **Normative rule N-IMMUT: an anchor record, once written for a given
> `el_block_number`, is never overwritten with different content. It is only ever
> (a) re-written identically, which is a no-op success, (b) evicted wholesale by
> a strictly greater block number claiming its ring residue, or (c) revoked by
> governance (which clears no bytes — it sets a flag).**

The four cases at a ring residue `i = el_block_number & (N−1)`, with `E` the
record currently in box `h:i`:

| case | condition | action | code |
|---|---|---|---|
| empty slot | `E.version == 0` | write | — |
| **idempotent re-anchor** | `E.el_block_number == new` and all 154 bytes except `anchored_round` are identical | **succeed, write nothing** | — |
| **equivocation** | `E.el_block_number == new` and any anchored field differs | **latch `conflict := 1` and FAIL the transaction** | `N20` |
| eviction | `E.el_block_number < new` | overwrite | — |
| regression | `E.el_block_number > new` | **reject** | `N21` |

**A lemma that makes eviction unambiguous.** The ring admission rule (§7.4)
requires `new > hi_block − N`, and the ring holds `N` residues. Within any window
of `N` consecutive block numbers every residue is distinct, so at most one
in-window block maps to residue `i`. Therefore the "regression" case can only
arise from an *out-of-window* attempt, which §7.4 already rejects earlier and
more cheaply — `N21` is a defence-in-depth code that a correct relayer never
sees. Stating it rather than omitting it, because "unreachable" asserts that turn
out to be reachable are how M4 §16 started.

**Idempotence matters operationally.** Two relayers racing to anchor the same
block is the *normal* case for a service with more than one instance, and it must
not be an error. §11 S15 confirms the racing case cannot be turned into a denial
of service.

### 5.5 The conflict latch

`conflict` is a global `uint8`, initially 0, set by the equivocation case above,
and **never cleared except by `gov_clear_conflict()`**.

> **While `conflict != 0`, `attest`, `anchor_direct`, `anchor_historical`, `pin`
> all fail (`N22`). Only `unpin`, `revoke` and the governance methods work.**

Fail-closed, deliberately. The state being latched is *"two mutually exclusive
statements about Ethereum both arrived carrying valid consensus proofs"*, which
means one of TP-M8-1, TP-M8-2 or TP-M8-3 has been violated, and continuing to
serve roots from a contract in that state is worse than serving none.

**Is this a denial-of-service vector?** No, and the reason is worth stating
precisely: reaching the equivocation branch requires producing *two* anchor
records for the same `el_block_number`, each of which required a full valid
`hash_tree_root == fin_root` chain against M4's current global state. An attacker
who can do that already controls a 2/3 sync-committee majority, i.e. already owns
the module. There is no cheap path to the latch. §11 S16.

### 5.6 Maturity is the consumer's choice, not M8's

An obvious-looking alternative is for M8 to refuse to serve an anchor until it is
`K` Algorand rounds old, giving watchers a revocation window. **Rejected**, for
two reasons:

1. **It breaks same-group anchor-then-consume**, which §10.4 shows is the primary
   and cheapest integration: the relayer anchors and M7 reads the anchor in the
   same atomic group, for a *net negative* opcode-budget cost. A maturity delay
   would force every first-time query to be two groups separated by K rounds,
   turning a one-shot x402 request into a stateful, resumable job. That is a
   large product cost for a security property that, per §5.3, only helps if
   somebody is watching.
2. **There is no correct global K.** A 0.01 USDC receipt query and a bridge
   withdrawal want different numbers by orders of magnitude.

So `anchored_round` is in the record (§6.1) and the check is one comparison the
consumer writes, exactly like M6 TP-M6-3's `want_*` arguments. §8.7 provides
`anchor_assert_mature(a, min_rounds)` as an accessor so that a consumer that
wants a maturity policy does not have to reimplement `Global.round` arithmetic —
but, unlike the `want_*` arguments, it is **not** mandatory, because there is no
defensible default to force. This asymmetry is deliberate and is called out again
in §19's checklist.

### 5.7 Governance: revoke, freeze, renounce

| method | who | effect | soundness or liveness? |
|---|---|---|---|
| `append_fork_row(...)` | gov | appends a row; `activation_epoch` must strictly exceed the last row's | **soundness** — TP-M8-3, the one dangerous one |
| `revoke(block_number)` | gov | sets `FLAG_REVOKED` on the ring and/or pinned record. Does not delete, does not alter the anchored fields. | liveness |
| `freeze()` / `unfreeze()` | gov | `frozen := 1`; blocks `anchor_*` and `pin`; **does not block `attest`** on already-anchored records | liveness |
| `gov_clear_conflict()` | gov | clears the §5.5 latch after off-chain investigation | liveness (it re-opens a contract that failed closed) |
| `ring_init_chunk(k)` | gov | §7.7; only callable while `ring_cursor < N` | — |
| `renounce()` | gov | sets `gov` to the zero address, permanently. Every method above becomes uncallable. | converts all of the above into "no" |

> **The property to state and to test (§13.4, Suite S): governance has no write
> path to an anchored root's value.** There is no `gov_set_root`, no
> `gov_override`, no admin escape hatch. Governance can stop M8 and can mark
> records untrustworthy; it cannot make M8 say something false about a block —
> **except** through `append_fork_row`, and that exception is TP-M8-3, stated
> rather than minimised.

`renounce()` is the answer to TP-M8-3 for an operator who wants it: once the fork
table covers every fork the deployment will see, renouncing makes the contract
fully immutable and removes governance from the trust model entirely. The
trade-off is explicit and is the operator's to make: a future fork then requires
a **redeploy plus a re-anchor of anything that matters**, because the new
deployment starts with an empty ring and a new app id (which every consumer has
compiled in as a constant, per TP-M8-4 — so a redeploy is a consumer redeploy
too). M10 owns documenting that migration. It is not cheap, and pretending
otherwise would be the kind of gap this project's docs exist to not have.

---

## 6. Data model

### 6.1 The anchor record `A` — fixed 154 bytes

Fixed-width and self-describing, following M5's `W` (101 B), M6's `C` (248 B) and
M7's `R` (240 B). Fixed width is what makes `op.extract` with immediate operands
cheap and makes off-chain parsing (M9) a byte-offset table rather than a decoder.

| off | len | field | notes |
|---:|---:|---|---|
| 0 | 1 | `version` | `1`. **`0` means "this box has never been written"** — the zero-filled state of a pre-created ring box. This is why version is at offset 0 and why it is checked first. |
| 1 | 1 | `flags` | bit0 `FLAG_REVOKED`, bit1 `FLAG_HISTORICAL` (0 = DIRECT), bit2 `FLAG_PINNED`. Bits 3–7 reserved, MUST be zero. |
| 2 | 8 | `el_block_number` | uint64 **big-endian**. Merkle-bound at `g_block_number` (§3.5). Also the box key. |
| 10 | 8 | `beacon_slot` | uint64 BE. The slot of the header the EL fields were proven from — `t_slot`, not `fin_slot`. |
| 18 | 32 | `el_state_root` | Merkle-bound at `g_state_root`. M6's `R_state`. |
| 50 | 32 | `el_receipts_root` | Merkle-bound at `g_receipts_root`. M7's `receipts_root`. |
| 82 | 32 | `beacon_block_root` | `hash_tree_root(target_header)`. Provenance: the exact beacon block this record descends from. Not consumed by M6/M7; consumed by anyone auditing an anchor against a beacon API. |
| 114 | 32 | `finality_root` | `fin_root` as read from M4 at write time. In DIRECT mode this equals `beacon_block_root`; in HISTORICAL mode it is the *newer* finalized header the target was proven from. **This is the field that makes an anchor independently auditable**: with these two roots and `beacon_slot`, an auditor can replay the entire proof off-chain from a beacon API. |
| 146 | 8 | `anchored_round` | `Global.round` at write. §5.6. |
| | **154** | | |

Endianness note: `el_block_number` and `beacon_slot` are stored **big-endian**
because they are compared against `op.itob` output and used as box-key
components, both of which are big-endian in the AVM. They are *proven* against
little-endian SSZ chunks (§3.5). The conversion happens exactly once, in `le64`,
and this document flags the mismatch here because it is the fourth appearance of
the SSZ-vs-AVM endianness trap in this codebase (M3 §2.11, M4 §3.1 trap 1, M4
`header.py:le64`'s own docstring, and now this).

### 6.2 Global state

| key | type | mutable? | meaning |
|---|---|---|---|
| `gov` | bytes (32) | gov, and `renounce()` | governance address; zero address = renounced |
| `m4` | uint64 | **never** — write-once at create | M4's app id. TP-M8-7, §11 S3. |
| `ring_n` | uint64 | **never** — write-once at create | `N`, MUST be a power of two |
| `ring_cursor` | uint64 | during init only | §7.7; anchoring is blocked until `ring_cursor == ring_n` |
| `hi_block` | uint64 | on advancing anchor | highest `el_block_number` in the ring |
| `hi_slot` | uint64 | on advancing anchor | `beacon_slot` of that record |
| `n_anchored` | uint64 | on every write | monotone counter, telemetry only |
| `frozen` | uint64 | gov | 1 blocks `anchor_*`/`pin`; starts at 1 |
| `conflict` | uint64 | latch + gov | §5.5 |

**Creator MBR**: 8 uint64s + 1 byte-slice ⇒ `100,000 + 8×28,500 + 1×50,000 =`
**378,000 µALGO = 0.378 ALGO**, charged to the creating account, recoverable on
app deletion.

`ring_n` being a power of two is not cosmetic: the residue is then
`el_block_number & (ring_n − 1)`, three opcodes, versus a `%` (still cheap, but
the mask also makes §5.4's distinctness lemma trivially true and is checked at
create with `assert ring_n & (ring_n - 1) == 0`).

**`ring_n` is immutable for a load-bearing reason, not for convenience.**
Changing `N` silently remaps every existing residue: a record written at
`1000 & 127 = 104` would be looked up at `1000 & 255 = 232` after a resize, so
every existing anchor becomes simultaneously unreachable *and* liable to be
mistaken for a different block's slot. Making it a governance knob would be a
correctness bug wearing a feature's clothes. Resizing means redeploying (§5.7's
migration note).

### 6.3 Boxes

| box | name | value | MBR (µALGO) | count |
|---|---|---:|---:|---:|
| ring slot | `h:` ‖ `itob(i)` — **10 B** | `A`, 154 B | `2,500 + 400×164 =` **68,100** | `N` |
| pinned | `p:` ‖ `itob(block_number)` — **10 B** | `A` ‖ `payer` (32 B) — **186 B** | `2,500 + 400×196 =` **80,900** | unbounded, each self-funded |
| fork table | `forks8` — 6 B | 321 B | `2,500 + 400×327 =` **133,300** | 1 |

All charged to the **app account**, per M7's real finding (`m7_relayer.py`
lines 116–120). Funding Payments to the app address are therefore part of
`ring_init` and `pin`, never of `anchor_*` (§7.7, §7.5) — which is a genuine
simplification over M7's T2 path, where every oversized-leaf proof had to carry
its own funding transaction.

### 6.4 Error codes

House convention (M5 `W*`, M6 `A*`, M7 `L*`): M8 uses `N*`.

| code | condition |
|---|---|
| `N1` | `anchor_from_group`: `gi >= Txn.group_index` |
| `N2` | `anchor_from_group`: `prev.app_id != ANCHOR_APP_ID` — **TP-M8-4, the critical one** |
| `N3` | `anchor_from_group`: predecessor's `app_args(0)` is not the `attest` selector |
| `N4` | M4 app id in the foreign-apps array does not match the immutable `m4` global |
| `N5` | M4's `fin_root` is zero — no finality yet (M4 §12.3 item 3, M3 §7.5) |
| `N6` | `hash_tree_root(fin_header) != fin_root` |
| `N7` | `fin_header.state_root` disagrees with M4's `fin_state_root` global (§4.4 step 4) |
| `N8` | header argument is not exactly 112 bytes |
| `N9` | a branch argument's length is not a multiple of 32, or does not match the depth implied by the gindex (M3 §7.2/§7.3) |
| `N10` | `ring_cursor != ring_n` — ring not initialised |
| `N11` | `frozen != 0` |
| `N12` | `attest`: no record for that block number (**absence — TP-M8-6**) |
| `N13` | `attest`: record is revoked (**distinct from N12 on purpose**) |
| `N14` | `attest`: `version` is not 1 |
| `N15` | `attest`/`anchor_from_group`: `el_block_number != want_block_number` |
| `N16` | HISTORICAL: N-WINDOW violated (`t_slot >= fin_slot` or gap > 8192) |
| `N17` | no fork row for the requested epoch (epoch precedes the first `activation_epoch`) |
| `N18` | `block_roots` branch does not verify against `fin_state_root` |
| `N19` | an execution-field branch does not verify against `body_root` |
| `N20` | **equivocation**: conflicting content at the same block number (§5.4) |
| `N21` | ring regression: existing record's block number exceeds the new one (§5.4) |
| `N22` | `conflict` latch is set (§5.5) |
| `N23` | governance-only method called by a non-`gov` sender, or after `renounce()` |
| `N24` | `pin`/`unpin`: MBR funding Payment missing, underfunded, or not addressed to the app account; or `unpin` sender is not the recorded payer |

---

## 7. Retention and eviction — `ROADMAP.md`'s M8 open question, answered

> *M8's row, since 2026-07-30: "Root-history retention/eviction policy (real
> storage-cost tradeoff)."*

### 7.1 The real MBR arithmetic

Algorand box MBR is `2,500 + 400 × (len(name) + len(value))` µALGO, locked
against the **app account** for as long as the box exists, refunded on
`box_delete`. For M8's 154-byte record under a 10-byte name that is
**68,100 µALGO = 0.0681 ALGO per anchored block**, and it is *locked capital*,
not a fee — the operator does not spend it, but cannot use it either.

The number that settles the design:

> Ethereum produces **7,200 blocks/day**. Anchoring every block would lock
> `7,200 × 0.0681 =` **490 ALGO per day, forever**, growing without bound. At 30
> days that is 14,700 ALGO. **Retain-everything is not a policy, it is an
> unfunded liability.**

So the design space is bounded from the start, and the real question is not
"how much history" but "what is history *for*".

### 7.2 The reframing that makes this tractable

**Retention is a cache, not a correctness requirement.**

The primary integration (§10.4) is *anchor-then-consume in the same atomic
group*: the relayer submits one group containing `anchor_direct` (or
`anchor_historical`), then `attest`, then M7's walk segments. In that shape the
record's lifetime needs to be exactly one group — zero rounds. Retention exists
for two secondary reasons only:

1. **Repeat queries.** The second person to ask about block *B* should not pay
   for a second anchoring group. That is worth real money: §10.7 prices
   anchoring at 0.009–0.015 ALGO in fees against M7's 0.01 USDC toll.
2. **Asynchronous consumers.** A consumer that cannot control group shape
   (§8.4's inner-call path) needs the record to already exist.

Neither is a *correctness* requirement, and recognising that is what makes a
small, fixed-size, fully-prepaid ring the right answer instead of an unbounded
self-funding store.

### 7.3 Decision: a fixed-size prepaid hot ring, plus an opt-in pinned tier

> **Retention policy, normative:**
>
> **Tier 1 — the hot ring.** `N` boxes named `h:<i>`, `i = el_block_number &
> (N−1)`, **all created once at deployment** and never created or deleted again.
> MBR is paid once by the deployer. Eviction is implicit: writing block *B*
> overwrites whatever previously occupied residue `B & (N−1)`. The ring holds a
> sliding window of the most recent `N` anchored block numbers, enforced by §7.4.
>
> **Tier 2 — pinned records.** `p:<block_number>`, created on demand by anyone
> who sends a Payment covering the 80,900 µALGO MBR to the app account in the
> same group. Never evicted. Deletable only by the recorded payer (refunding
> them) or by governance (also refunding them). Unbounded in count, bounded in
> cost by being individually prepaid.
>
> **Recommended `N` = 128.**

Why this shape rather than the two obvious alternatives:

| alternative | why not |
|---|---|
| **One box per anchored block, MBR paid by the anchoring relayer, refunded on delete** | Three real problems. (a) *Who deletes?* Nothing gives a relayer an incentive to clean up, so boxes strand and the app account's locked MBR grows monotonically — the 490 ALGO/day figure with extra steps. (b) It puts a `box_create` + funding Payment into **every** anchoring group, which is exactly the pattern M7's T2 path found most awkward (`m7_relayer.py` lines 116–121: name generation, MBR computation, a Payment inserted at index 0, and every subsequent group index shifted by one). (c) A sweeper is a whole extra piece of infrastructure, and a sweeper that can delete is a sweeper that can be tricked into deleting. |
| **A single append-only box holding a rolling array of records** | 32,768 B box cap ⇒ 212 records max, so the bound exists either way. But M4 §16.2 measured that touching an existing box charges the pooled write budget the box's **full declared size** once per box per group, regardless of the slice touched. A 32 kB rolling box would burn `⌈32768/2048⌉ =` **16 box references** — twice the 8-per-transaction structural cap — on **every single anchor and every single read**, forcing a multi-transaction group for what is a 154-byte update. The 154-byte-per-box design charges 154 B. This is the single strongest quantitative argument in this section and it comes directly from M4's live measurements, not from theory. |

The second row is worth restating as a general finding: **M4 §16.2's
full-declared-size charging rule makes many small boxes strictly better than few
large ones for random-access workloads**, which inverts the usual intuition and
inverts M4's own committee-box reasoning (004 §8.2 chose 8 × 6,144 B boxes for
*sequential* access, where the full-size charge is amortised across a whole
committee walk). M8's access pattern is a single random 154-byte read. Different
pattern, opposite answer, same measurement underneath.

### 7.4 The ring admission rule

Without a rule, a relayer anchoring scattered historical blocks (which §4 makes
possible over a 27-hour window) would thrash the ring: anchoring block
21,000,000 would evict whatever recent block shares its residue, and the ring
would stop being a coherent window of anything.

> **Normative rule N-ADMIT: a ring write requires `el_block_number > hi_block −
> N`** (with the `hi_block == 0` bootstrap case admitting anything).
> **Anything older must use the pinned tier.**
>
> On a write with `el_block_number > hi_block`, `hi_block` and `hi_slot` advance
> together, and the contract asserts they advance *consistently*:
> `beacon_slot > hi_slot`. Execution block numbers and beacon slots both increase
> strictly along a canonical chain (skipped slots make the *gaps* uneven, never
> the *direction*), so a violation is equivocation evidence and takes the same
> path as §5.5.

Consequences, all good:

- The ring is exactly "the last `N` anchored block numbers", by construction.
- §5.4's distinctness lemma holds, so eviction is unambiguous and `N21` is
  unreachable through the honest path.
- Historical anchoring still works and still costs one group — it just lands in
  the pinned tier, where the requester pays for the storage they are asking the
  contract to hold. That is the correct incidence: transient recent traffic is
  subsidised by the operator's one-time ring MBR; durable requests for old blocks
  are paid for by whoever wants them durable.

### 7.5 The pinned tier

```
pin(block_number)        # group: [Payment(app_addr, >= 80,900 µALGO), pin(...)]
unpin(block_number)      # inner Payment refunds the recorded payer
```

`pin` accepts a block number that is **either** already in the ring **or**
anchored by an `anchor_*` call earlier in the same group. The second form is the
important one: `[Payment, anchor_historical, pin]` is a single group that
durably anchors an arbitrary block inside the 27-hour window, for
`0.0809 ALGO` of locked MBR plus `0.015 ALGO` of fees.

The payer's 32-byte address is stored at offset 154 of the pinned record.
`unpin` refunds **only** that address, via an inner Payment; governance may call
`unpin` but the refund destination is not governance's to choose. That is a
deliberate, one-line property that makes "governance cannot steal" true by
construction rather than by promise.

**Griefing analysis.** Unbounded pins grow the app account's total MBR
requirement, but every pin is fully prepaid by its own Payment in its own
atomic group, so the app account can never be driven below its requirement by
pinning. An underfunded Payment makes `box_create` fail, which fails the group,
which leaves nothing behind. There is no state to strand. (Contrast M7's T2
staging boxes, which *can* be stranded by a group that aborts after
`MODE_STAGE_OPEN` — 007 §8.4 assigns the sweep to M10. M8's boxes need no sweep,
and that is a direct consequence of never creating a box outside a group that
also funds it.)

### 7.6 What a consumer does when a root has been evicted

`attest` fails with **`N12` (absent)**, which TP-M8-6 requires be distinct from
**`N13` (revoked)**. The correct handling differs completely:

| code | meaning | relayer/consumer action |
|---|---|---|
| `N12` | unknown — never anchored, or aged out of the ring | **Re-anchor.** If the block is within 8,192 slots of the current finality: `anchor_historical`, 0.015 ALGO, one group, done. If it is older: it is outside v1's reach (NG4/O-M8-3) and the service must return a defined "out of anchorable range" answer, not an error. |
| `N13` | anchored, then revoked by governance | **Do not re-anchor, do not serve.** Governance revoked it for a reason (§5.7); re-anchoring the identical content would produce the identical record, and silently un-revoking it by rewriting the box would defeat the mechanism. **Normative: a ring write MUST NOT clear `FLAG_REVOKED` for the same `el_block_number`; only eviction by a different block number clears the box.** This is a real implementation trap — the natural "just overwrite the record" code path clears the flag. §13.4 S-REV tests it. |

`service/x402_endpoint/main.py` maps these to distinct HTTP responses in §9.3.

### 7.7 Ring initialisation — one group of 16, plus a prior funding transaction

At `N = 128`, using M4 §16's proven pattern:

- **Box-reference cap is 8 per transaction** (004 §16.2, structural, confirmed by
  the literal protocol error `tx.Boxes too long, max number of box references is
  8`). ⇒ 8 `box_create`s per transaction ⇒ **16 transactions** for 128 boxes.
- **16 is exactly the atomic-group cap.** It fits, with nothing to spare.
- **Pooled write budget**: `128 × 154 = 19,712 B` of creates against
  `16 txns × 8 refs × 2,048 B = 262,144 B` available. 7.5 % utilisation. ✅ Not
  the binding constraint here, in contrast to M4's install (49,576 B needing a
  minimum of 25 references).
- **Opcode**: ~8 × 30 + routing ≈ **350 per call** (**projected**) against 700.
  No donor calls needed — the only path in M8 that needs none.
- **Fees**: 16 × 1,000 = **0.016 ALGO**.
- **Funding**: `128 × 68,100 =` **8,716,800 µALGO = 8.7168 ALGO** to the app
  address. This does **not** fit in the group (a 17th transaction), so it is sent
  **beforehand**, in its own transaction.

> **Why funding-in-a-prior-transaction is safe here, when M4 §16.3 needed
> atomicity.** M4's argument was that a *partially opened box set must never be
> observable on-chain*, because a half-installed committee is a real, exploitable
> intermediate state. M8's ring has no such state: `ring_cursor < ring_n` blocks
> every anchoring path with `N10`, `frozen` starts at 1, and an uncreated ring box
> makes `attest` fail with `N12`. A partially initialised ring is **inert**, and
> `ring_cursor` makes initialisation resumable from wherever it stopped — the same
> resumption discipline M4 §12.4 item 5 requires of `inst_cursor`. Different
> hazard, different answer, and the reasoning is recorded rather than the
> conclusion copied.

`ring_init_chunk(k)` asserts `k == ring_cursor` (M4's `install_chunk` cursor
convention, 004 §12.4 item 4), creates 8 boxes, advances the cursor, and on
reaching `ring_n` sets `frozen := 0`.

### 7.8 Choosing `N`

| `N` | ring MBR | window (blocks) | wall clock @ 12 s | init txns | init groups |
|---:|---:|---:|---|---:|---:|
| 64 | **4.358 ALGO** | 64 | 12.8 min | 8 | 1 |
| **128** | **8.717 ALGO** | 128 | **25.6 min** | 16 | 1 |
| 256 | **17.434 ALGO** | 256 | 51.2 min | 32 | 2 |
| 1024 | **69.734 ALGO** | 1024 | 3.4 h | 128 | 8 |

Total v1 deployment MBR at `N = 128`:

| item | ALGO |
|---|---:|
| creator global-state MBR (§6.2) | 0.378 |
| app account base MBR | 0.100 |
| ring, 128 boxes | 8.717 |
| `forks8` box | 0.133 |
| **total locked** | **9.328** |

**All of it recoverable** (delete the boxes, delete the app).

> **Recommendation: `N = 128`.** Reasoning, in the order it actually mattered:
> (1) 16 init transactions is exactly one atomic group, which keeps M10's
> deployment tooling to a single group and makes the whole ring appear atomically
> — a real operational simplification worth constraining `N` for; (2) 25.6 minutes
> comfortably exceeds Ethereum's ~12.8-minute finality lag, so the ring always
> covers the entire "already finalized but still recent" band that a live service
> queries most; (3) 8.7 ALGO is **less than half** of M4's own per-committee box
> MBR of ~19.7 ALGO (004 §8.2) and less than a quarter of holding current+next at
> 39.4 — so M8 does not become the project's dominant capital cost; (4) it is a
> power of two, per §6.2.
>
> An operator running a high-traffic service should measure the real
> re-anchoring rate before paying for `N = 1024`; §16 lists this as an honest gap,
> because this document has **no real traffic data** and is choosing `N` from
> structural arguments alone.

---

## 8. Interface — the freezable ABI

### 8.1 Shape: ARC-4 methods, not M5's raw app-args

M5 §7.3, M6 §6.1 and M7 §5.1 all chose raw application arguments with a 4-byte
selector and a mode byte, deliberately, because a *segmented* walk needs to
squeeze every byte out of the 2,048-byte argument budget and ARC-4's framing is
pure overhead when you are 13 bytes from the cap (M6 §7.1).

**M8 has no segmentation.** §10.5 shows its largest call — HISTORICAL, with two
headers, four branches and three leaves — lands at 1,780 B of 2,048. It fits in
one transaction, so the reason for raw args evaporates, and the reasons for ARC-4
apply:

- **M9 and M10 are blocked on a frozen ABI** (`ROADMAP.md` M9 row: *"Design can
  start once M4/M6/M7/M8 ABIs are frozen"*). An ARC-4 contract emits an ARC-56
  JSON file that *is* the frozen ABI, machine-readable, versioned, and diffable
  in CI. A raw-args convention is a paragraph in a design document.
- **M4 is already ARC-4** (004 §7.3) and M8 sits directly next to it in the
  trust chain, reads its globals, and shares its governance patterns.
- **`attest`'s ARC-4 return log is what the consumer hand-off reads** (§8.3), and
  ARC-4's `0x151f7c75 ‖ value` return convention is precisely the envelope M5
  §7.4's `mpt_state_from_prev` already parses. Using ARC-4 means the hand-off
  reuses a mechanism that has been live-tested rather than defining a fifth
  logging convention in this codebase.

> **Decision: ARC-4 throughout. The frozen artefact is
> `contracts/state_anchor/*.arc56.json`, and G8-M8 (§14) requires it to be
> committed and CI-diffed.**

### 8.2 The ARC-4 surface

```python
class TrustedRootAnchor(ARC4Contract):

    # ---- one-time setup ------------------------------------------------
    @arc4.abimethod(create="require")
    def create(self, governance: arc4.Address,
               m4_app_id: arc4.UInt64,
               ring_n: arc4.UInt64) -> None: ...
        # ring_n MUST be a power of two (§6.2). m4_app_id and ring_n are
        # write-once and immutable thereafter -- TP-M8-7, §11 S3.
        # frozen := 1, ring_cursor := 0, conflict := 0.

    @arc4.abimethod
    def ring_init_chunk(self, k: arc4.UInt64) -> None: ...
        # governance only; asserts k == ring_cursor; creates 8 boxes;
        # sets frozen := 0 when ring_cursor reaches ring_n (§7.7).

    @arc4.abimethod
    def append_fork_row(self, activation_epoch: arc4.UInt64,
                        g_state_root: arc4.UInt64,
                        g_receipts_root: arc4.UInt64,
                        g_block_number: arc4.UInt64,
                        g_block_roots_base: arc4.UInt64) -> None: ...
        # governance only; append-only; activation_epoch must strictly exceed
        # the last row's -- M4 §4.3's rules verbatim. TP-M8-3.

    # ---- anchoring -----------------------------------------------------
    @arc4.abimethod
    def anchor_direct(self,
        fin_header:        arc4.StaticBytes[Literal[112]],
        el_state_root:     arc4.StaticBytes[Literal[32]],
        el_receipts_root:  arc4.StaticBytes[Literal[32]],
        el_block_number:   arc4.UInt64,
        state_branch:      arc4.DynamicBytes,   # packed 32*depth
        receipts_branch:   arc4.DynamicBytes,
        number_branch:     arc4.DynamicBytes,
    ) -> arc4.StaticBytes[Literal[154]]: ...
        # Anchors the execution block inside the header M4 currently holds as
        # finalized. Returns (and therefore logs) the record A.

    @arc4.abimethod
    def anchor_historical(self,
        fin_header:        arc4.StaticBytes[Literal[112]],
        target_header:     arc4.StaticBytes[Literal[112]],
        block_roots_branch: arc4.DynamicBytes,  # packed 32*(18 or 19)
        el_state_root:     arc4.StaticBytes[Literal[32]],
        el_receipts_root:  arc4.StaticBytes[Literal[32]],
        el_block_number:   arc4.UInt64,
        state_branch:      arc4.DynamicBytes,
        receipts_branch:   arc4.DynamicBytes,
        number_branch:     arc4.DynamicBytes,
    ) -> arc4.StaticBytes[Literal[154]]: ...
        # §4. N-WINDOW, N-INDEX and N-FORK all apply.

    # ---- the consumer-facing read -- THE hot path ----------------------
    @arc4.abimethod
    def attest(self, block_number: arc4.UInt64) -> arc4.StaticBytes[Literal[154]]: ...
        # Reads the ring (then the pinned tier) and RETURNS the record, which
        # ARC-4 logs as 0x151f7c75 || 154 bytes. Fails N12/N13/N14/N22.
        # This is what §8.3's hand-off reads out of the group.

    @arc4.abimethod(readonly=True)
    def get_anchor(self, block_number: arc4.UInt64) -> arc4.StaticBytes[Literal[154]]: ...
        # Same semantics, marked readonly, for off-chain callers and for the
        # inner-call hand-off (§8.4).

    # ---- pinned tier ---------------------------------------------------
    @arc4.abimethod
    def pin(self, block_number: arc4.UInt64, payment: gtxn.PaymentTransaction) -> None: ...
    @arc4.abimethod
    def unpin(self, block_number: arc4.UInt64) -> None: ...

    # ---- governance ----------------------------------------------------
    @arc4.abimethod
    def revoke(self, block_number: arc4.UInt64) -> None: ...
    @arc4.abimethod
    def freeze(self) -> None: ...
    @arc4.abimethod
    def unfreeze(self) -> None: ...
    @arc4.abimethod
    def gov_clear_conflict(self) -> None: ...
    @arc4.abimethod
    def renounce(self) -> None: ...

    # ---- group plumbing ------------------------------------------------
    @arc4.abimethod
    def noop_budget(self) -> None: ...
        # 004 §7.3's method, same role: a group filler that carries box
        # references and adds 700 to the pool. Asserts nothing, writes nothing.
    @arc4.abimethod
    def donor(self) -> None: ...
        # inner-call target for budget donation; 18 to issue, +700 to the pool
        # (004 §2.4, measured).
```

**Reading M4.** `anchor_*` reads M4's globals with
`op.AppGlobal.get_ex_uint64(m4_app, b"fin_slot")` and
`op.AppGlobal.get_ex_bytes(m4_app, b"fin_root")` / `b"fin_state_root"`, where
`m4_app` comes from the foreign-apps array and is asserted equal to the immutable
`m4` global (`N4`). **No inner call.** This matters: 004 §12.3 item 1 records
that M4's `submit_update` consumes all 256 of a group's inner transactions for
budget donation, so M4 can never inner-call M8 — but nothing stops M8 reading
M4's state, and a foreign global read is a handful of opcodes against an inner
call's whole transaction. 004 §12.3's recommended integrations ("readonly getter
in a later group transaction, or co-deploy") are both superseded by this simpler
one, which was available all along and which this design pass is recording as the
answer to that flagged question.

### 8.3 The consumer hand-off, primary: the group log-chain

The mechanism is M5 §7.4's `mpt_state_from_prev`, which is implemented,
live-tested (honest pass and forged reject, both against real algod), and
measured at 8 budget in hand-TEAL. **One line changes.**

```python
# contracts/state_anchor/handoff.py  -- IMPORTED BY M6 AND M7

ANCHOR_APP_ID: Final[UInt64] = UInt64(<compile-time constant>)   # TP-M8-4
ATTEST_SELECTOR: Final[Bytes] = Bytes(<ARC-4 selector of attest(uint64)>)

@subroutine
def anchor_from_group(gi: UInt64, want_block_number: UInt64) -> Bytes:
    """Recover and validate an anchor record produced by transaction `gi` of
    THIS group. Returns the 154-byte record A.

    assert gi < Txn.group_index                                    -> "N1"
    prev = gtxn.ApplicationCallTransaction(gi)
    assert prev.app_id == ANCHOR_APP_ID                            -> "N2"
    assert prev.app_args(0) == ATTEST_SELECTOR                     -> "N3"
    log = prev.last_log
    assert log.length == 6 + 154 and log[:4] == ARC4_RETURN_PREFIX -> "N4b"
    a = op.extract(log, 6, 154)
    assert a[0] == VERSION_1                                       -> "N14"
    assert a[1] & FLAG_REVOKED == 0                                -> "N13"
    assert a[2:10] == op.itob(want_block_number)                   -> "N15"
    return a
    """
```

**The single difference from M5's version, and it is the whole security
argument.** M5 asserts `prev.app_id == Global.current_application_id` — same app,
so no constant is needed. M8's hand-off is **cross-app**, so the assert becomes
`prev.app_id == ANCHOR_APP_ID`, and that constant must not be reachable by the
caller.

> **TP-M8-4, restated as an implementation instruction: `ANCHOR_APP_ID` MUST be a
> compile-time constant in the consumer's program, or an immutable global written
> once at the consumer's `create`. It MUST NOT be a method parameter, a mutable
> global, a box value, or read from the foreign-apps array without comparison.
> Any implementation that makes it caller-influenceable is a critical defect.**
>
> This is exactly 007 TP-M7-7's rule for the AlgoPlonk verifier logicsig address,
> and 007 §6.2/Z6 flags it in these words: *"A different verifying key yields a
> different program yields a different address. Any implementation that makes the
> verifier address a parameter, box value, or mutable global is a critical
> defect."* Same shape, same words, second occurrence. §11 S4 traces it.

`want_block_number` is **mandatory**, for M6 §6.6's and M7 §5.3's reason: a
consumer must bind the anchor to the block it actually asked about, and the
cheapest way to make that unforgettable is to refuse to compile a call that omits
it. `anchor_from_group` has no overload without it.

### 8.4 The consumer hand-off, secondary: the inner-call getter

For a consumer that cannot place an `attest` transaction adjacent to its own:

```python
@subroutine
def anchor_by_inner_call(want_block_number: UInt64) -> Bytes:
    """Inner-call ANCHOR_APP_ID's get_anchor(block_number) and validate the
    returned record. Same N13/N14/N15 checks; N2's role is played by the
    inner call's own app_id field, which is ANCHOR_APP_ID by construction.
    """
```

Requirements on the calling transaction: `ANCHOR_APP_ID` in `foreign_apps`, and
`(ANCHOR_APP_ID, "h:" ‖ itob(residue))` in the `boxes` array — foreign-app box
references *are* declarable there; what does not exist is an opcode letting the
caller *read* the box directly (§8.5).

**Cost, and it is counter-intuitive.** An inner app call costs **18 to issue**
and contributes **+700 to the group's opcode pool** (004 §2.4, measured). The
callee's own work is ~260 (§10.4). So `anchor_by_inner_call` is
**net +422 budget**, i.e. it *pays for itself and donates the change*. Its real
costs are one fee (1,000 µALGO), one foreign-app slot, and one box reference.

**Both mechanisms are equally safe** given TP-M8-4, and the document says so
rather than pretending one is stronger:

| | log-chain (§8.3) | inner call (§8.4) |
|---|---|---|
| binds the app | explicit `prev.app_id == ANCHOR_APP_ID` assert | structural — you called it |
| can point at the wrong thing | yes, `gi`; caught by `N15` | no `gi` exists |
| group-shape coupling | requires `attest` earlier in the group | none |
| budget | +700 (the `attest` txn) − 260 − ~95 = **net +345** | +700 − 18 − 260 = **net +422** |
| extra fee | 1,000 µALGO (the `attest` transaction) | 1,000 µALGO (the inner call) |
| precedent in this repo | M5 §7.4, live-tested, honest-pass and forged-reject both proven | none — M8 would be the first cross-app inner call in this codebase |

> **Recommendation: the log-chain is primary** — solely because it reuses a
> mechanism this project has already proven against real algod, and because M6's
> and M7's relayers already build multi-transaction groups and know how to place
> a transaction. The inner-call path is specified, permitted, and worth
> implementing, but §16 records honestly that it has no live precedent here and
> §13.4 gates it with its own forged-app test.

### 8.5 Why not a cross-app box read

There is no such opcode. `box_get`/`box_extract`/`box_replace`/`box_create`/
`box_del` all operate on boxes owned by the **currently executing application**;
the `boxes` array's `app_index` field controls which app's boxes are *referenced*
(and therefore budgeted and resolvable), not which app may read them. A foreign
app's box can only be read by that app executing, which means an inner call
(§8.4) or the group log-chain (§8.3).

Recorded explicitly because it is the design a reviewer will reach for first, and
because 007 §2.1 established the house standard for this kind of claim:
**enumerate the opcode surface from the compiler's own table rather than asserting
absence from memory.** An implementation pass should do exactly that here and
record the result in `bench/anchor_results.json` — it is one probe, and it
converts a paragraph of prose into a fact. §13.6 B4.

### 8.6 Why not co-deploy M8 into M6/M7's app

The obvious way to make it a plain `box_get` is to put M8's boxes in the same
application as M6/M7. Ruled out by **measured** program sizes against the
**8,192-byte per-call cap**:

| program | bytes | source |
|---|---:|---|
| M2 (RLP) own contribution | 839 | `bench/rlp_results.json`, `bare_estimate_bytes` |
| M5 (MPT) own contribution | 1,969 | `bench/mpt_results.json`, `m5_own_contribution_bytes` |
| M6 own contribution | 573 | `bench/composer_results.json`, `m6_own_contribution_vs_m2_m5_bytes` |
| **`Mpt6ComposerApp` — the real deployable M6 driver** | **2,676** | `composer_results.json`, `real_driver_bytes` |
| **M7's deployed mainnet app (id 3664247481)** | **3,104** | ROADMAP M7 row, "compiles clean with `puyapy` (3,104 B)" |
| M8's own estimate (§10.8) | ~2,200 (**projected**) | |

M7 + M8 co-deployed ≈ 5,300 B, which *does* fit — but M6 §13.2 already warned:

> *"after M2 + M5 + M6 (~4,300 B est.), M8 and M7 share ~3,900 B of the 8,192 B
> per-call cap."*

and the real driver numbers make that tighter than the estimate: M6's driver
(2,676) + M7's app (3,104) = 5,780 B before M8 writes a line, leaving 2,412 B
against a ~2,200 B estimate — a **9 % margin on a projected number**, in a
codebase where M5 missed its own size gate by 40 % (1,969 B against a 1,400 B
target) and M3's Puya costs came in 40 % over hand-TEAL.

M6 §13.2 also names the second obstacle: *"`mpt6_state_from_prev` asserts
`prev.app_id == Global.current_application_id`, so splitting M6 across two apps
would require rethinking the hand-off."* Co-deploying M8 into M6/M7 does not
split M6, but it does mean any *future* split has to move M8's boxes too — box
ownership is not portable between apps, so a co-deployed M8 could never be
redeployed without losing its ring.

> **Decision: M8 is a separate application.** The consumer pays one extra
> transaction (§8.3) or one inner call (§8.4), both of which are **net-positive**
> on opcode budget, and gains: independent redeployability, a fork-table
> governance surface that is not entangled with M6/M7's, and 8,192 bytes of its
> own.

### 8.7 Field accessors

Published alongside `anchor_from_group` in `contracts/state_anchor/handoff.py`,
so no consumer ever writes an offset literal:

```python
@subroutine
def anchor_state_root(a: Bytes) -> Bytes:      # a[18:50]   -- M6's R_state
@subroutine
def anchor_receipts_root(a: Bytes) -> Bytes:   # a[50:82]   -- M7's receipts_root
@subroutine
def anchor_block_number(a: Bytes) -> UInt64:   # btoi(a[2:10])
@subroutine
def anchor_beacon_slot(a: Bytes) -> UInt64:    # btoi(a[10:18])
@subroutine
def anchor_beacon_root(a: Bytes) -> Bytes:     # a[82:114]
@subroutine
def anchor_finality_root(a: Bytes) -> Bytes:   # a[114:146]
@subroutine
def anchor_round(a: Bytes) -> UInt64:          # btoi(a[146:154])
@subroutine
def anchor_assert_mature(a: Bytes, min_rounds: UInt64) -> None:
    """assert Global.round - anchor_round(a) >= min_rounds.
    NOT mandatory -- §5.6 explains why there is no defensible default, and
    why this is the one consumer-side check M8 does not force."""
```

---

## 9. What M6, M7 and the x402 service change

### 9.1 M6 — one line, exactly where §13.2 predicted

M6 §13.2 called this in advance:

> *"The swap point is `MODE_A_INIT`'s `arg 4`. M6 v1 takes `R_state` as an
> argument under TP-M6-1. M8's contract replaces that read with a lookup in its
> own root history and asserts the result — a one-line change at exactly one
> site. Design M8's anchor read to return a 32-byte root so this stays a
> substitution."*

It stays a substitution. `anchor_state_root(anchor_from_group(gi, block_number))`
returns 32 bytes.

Two changes, both small, and the second is the one that matters:

1. `MODE_A_INIT` gains an alternative entry that derives `R_state` from an anchor
   record instead of reading `arg 4`. The walk itself is untouched.
2. **`mpt6_result_from_group`'s `want_state_root` must be fed from the anchor,
   on-chain.** M6 §13.2: *"TP-M6-3 is M8's to enforce on-chain.
   `mpt6_result_from_group`'s three `want_*` arguments are where M8 supplies its
   anchored root and the application's intended address/slot. §5.4's residual
   attack is defeated there and nowhere else."*

Note what is *not* required: the walk may still be *initialised* from an
argument-supplied root, because if that root differs from the anchored one, the
result-time comparison fails. The binding happens at exactly one site, which is
the property M6 designed for.

### 9.2 M7 — `mpt7_result_against_anchor`

M7 §5.3's existing surface:

```python
mpt7_result_from_group(gi, want_receipts_root, want_tx_index, want_log_index)
```

gains a sibling that removes the caller's ability to choose the root at all:

```python
@subroutine
def mpt7_result_against_anchor(gi: UInt64, anchor_gi: UInt64,
                               want_block_number: UInt64,
                               want_tx_index: UInt64,
                               want_log_index: UInt64) -> ...:
    """TP-M7-2, discharged. Derives want_receipts_root from the anchor record
    produced by transaction `anchor_gi`, then delegates to
    mpt7_result_from_group. There is no receipts_root parameter."""
    a = anchor_from_group(anchor_gi, want_block_number)
    return mpt7_result_from_group(gi, anchor_receipts_root(a),
                                  want_tx_index, want_log_index)
```

This closes 007's S2 exactly as 007 §6.1 anticipated it would:

> *S2 | Supply a genuine receipt from a different block | **rejected at the
> consumer** | … M7 alone cannot detect it; **that is M8's job (§8.1)**.*

With `mpt7_result_against_anchor`, the consumer names a *block number*, not a
root. Supplying a genuine receipt from a different block now fails inside the
AVM, because the only root the result is allowed to match is the one M8 proved
for that block number.

007 §8.3's second request — *"a transaction-count bound per block would make
receipt exclusion meaningful"* — is answered but **not shipped in v1**: §17
O-M8-2 shows that anchoring `transactions_root` (gindex 813 at Deneb) makes
`R_ABSENT` meaningful, because an exclusion walk in the transactions trie for
index `i` proves `i >= tx_count`, and the transactions trie is keyed identically
to the receipts trie (`rlp(index)`) so M5's existing `mpt_key_from_tx_index` and
exclusion machinery apply unchanged. Cost: +1 depth-9 fold (**850**), +32 B of
record (+**0.0128 ALGO** MBR per ring slot, +1.638 ALGO at N=128), +290 B of
argument, and a `version = 2` record. Deferred, priced, and the reasoning is
recorded so the v2 decision is a decision rather than a rediscovery.

### 9.3 `service/x402_endpoint/` — the real diff

**`m7_relayer.py`.** `prove_receipt`'s signature changes from taking
`receipts_root: bytes` to taking `block_number: int`, and the group it builds
gains one or two transactions at the front:

```
today:                          after M8 (cache hit):        after M8 (cache miss):
  [MODE_INIT + nodes]             [attest(block)]              [anchor_direct|historical]
  [8 × filler NoOp]               [MODE_INIT + nodes]          [attest(block)]
                                  [8 × filler NoOp]            [MODE_INIT + nodes]
                                                               [8 × filler NoOp]
                                                               (+ 8–14 donor inner calls
                                                                  issued by the anchor txn)
```

Group-size check against the 16-transaction cap, using M7's real numbers
(`m7_relayer.py`: T2's worst case is a funding Payment + 1 `MODE_INIT` + up to 2
`MODE_NEXT` + `STAGE_OPEN` + 2 chunked writes + `STAGE_WALK` + 8 fillers = **15
transactions**, confirmed live at round 15):

| shape | txns today | + M8 | total | fits 16? |
|---|---:|---:|---:|:--:|
| T1 cache hit | 9 | +1 (`attest`) | 10 | ✅ |
| T1 cache miss | 9 | +2 | 11 | ✅ |
| T2 cache hit | 15 | +1 | 16 | ✅ **exactly** |
| **T2 cache miss** | 15 | +2 | **17** | ❌ |

> **A real, concrete finding for M9: the T2 cache-miss path does not fit one
> group.** The fix is not to shrink M7 — it is to **anchor in a separate,
> preceding group**, which is safe because an anchor is durable state, not a
> group-local log. `attest` then reads it in the T2 group as a cache hit at 16
> transactions. That is a two-group flow, and the relayer must handle the
> anchoring group failing independently. Alternatively the 8 filler NoOps can be
> replaced by donor *inner* calls issued from an existing transaction (M5 §16.3's
> mechanism, already implemented as `_issue_donors`), which frees 8 slots and
> makes everything fit — **this is the better fix** and it is flagged for M9 in
> §15.3. Either way it is a real constraint discovered at design time rather than
> at submission time, which is the point of doing the arithmetic.

**`main.py`.** Lines 87–110 become, in shape:

```python
    receipts_root_hex = header["receiptsRoot"]          # now a HINT only
    root_hash, nodes = build_receipts_trie_and_path(receipts, tx_index)
    if "0x" + root_hash.hex() != receipts_root_hex:
        raise HTTPException(500, "reconstructed receiptsRoot does not match the RPC block header")
        # kept as a cheap pre-flight -- it catches our own bugs before we
        # spend a group. It is NO LONGER the security boundary.

    result = prove_receipt(ac, M7_APP_ID, M8_APP_ID, relayer_addr, relayer_sk,
                           block_number, tx_index, log_index, nodes)
    #                      ^^^^^^^^^^^^ block_number, not root_hash

    return {
        "block_number": block_number,
        "receipts_root": receipts_root_hex,
        "receipts_root_anchored": result["anchor"]["el_receipts_root"],   # NEW
        "anchor": {                                                        # NEW
            "app_id": M8_APP_ID,
            "beacon_slot": result["anchor"]["beacon_slot"],
            "beacon_block_root": result["anchor"]["beacon_block_root"],
            "finality_root": result["anchor"]["finality_root"],
            "anchored_round": result["anchor"]["anchored_round"],
            "mode": "DIRECT" | "HISTORICAL",
        },
        "verified_by": f"Algorand app {M7_APP_ID} against anchor {M8_APP_ID}, round {...}",
        "result": result,
    }
```

and the module docstring's honest-gap paragraph (lines 15–20) is **deleted**,
which is the actual deliverable.

Three new response paths the service must define, because they are real states
and returning 500 for them would be wrong:

| condition | HTTP | body |
|---|---|---|
| block is newer than M4's current `fin_slot` (not yet finalized) | **425 Too Early** | `{"reason": "not_yet_finalized", "finalized_block": <hi_block>, "retry_after_s": 780}` |
| block is more than 8,192 slots behind finality (NG4) | **501 Not Implemented** | `{"reason": "outside_anchorable_window", "window_slots": 8192}` |
| `attest` returned `N13` (revoked) | **409 Conflict** | `{"reason": "anchor_revoked"}` — **must not** auto-re-anchor (§7.6) |

> **x402 note:** the payment middleware settles *before* the handler runs
> (`PaymentMiddlewareASGI`, `main.py` line 76). A 425 or 501 therefore means the
> payer paid 0.01 USDC for a non-answer. That is a **product** decision this
> document flags rather than makes: either pre-check finality before the priced
> route (a free `/anchorable/{block}` endpoint the client is expected to call
> first), or accept it. §15.3 flags it for M9/M10. It is exactly the kind of
> thing that is obvious at design time and infuriating in production.

### 9.4 What M9 owns

- **Choosing DIRECT vs HISTORICAL.** Pure optimisation, no safety content — a
  relayer that always uses HISTORICAL is correct, just 0.006 ALGO more expensive
  per anchor and unable to anchor the newest finalized block (N-WINDOW requires
  `t_slot < fin_slot`). Same shape as M4 §12.4 item 3's `mode` hint.
- **Building the branches.** `state_branch`, `receipts_branch`, `number_branch`
  and `block_roots_branch` come from a beacon API's SSZ representation. M9 must
  compute them with a real SSZ library (`remerkleable` / pyspec) against the
  **same pinned spec version** as the fork table (G4-M8), and must **not**
  hardcode depths — the branch length is implied by the gindex and is checked
  on-chain (`N9`).
- **Donor sizing.** M5 §16.3 / M6 §7.6's procedure verbatim: `simulate` with zero
  donors, read the real consumed figure, size, then verify with an actual
  `send_transactions`, never with `simulate` alone.
- **Cache policy.** Call `get_anchor` (readonly, free, off-chain) before building
  a group; skip the anchoring transactions on a hit. This is where the ring's
  value is actually realised.
- **Idempotent retries.** §5.4 guarantees re-anchoring identical content is a
  no-op success, so a relayer may safely retry a group whose confirmation it
  missed. It must **not** treat `N20` as retryable — that is the equivocation
  latch and it must page a human.
- **Two-group flow for T2 cache misses** (§9.3), or the donor-inner-call fix.

---

## 10. Budget and group arithmetic

### 10.1 The measured inputs

Every line below is traceable to a real response already in this repo.

| quantity | value | source |
|---|---:|---|
| Puya SSZ fold | **`103 + 83·depth`**, exact on depths 4/5/6/7 | 004 §2.5, **measured** |
| `sha256` | flat **35** | 003 §2.2, **measured** |
| all-in per-`sha256` for chunked SSZ hashing in Puya | ~**100** | 004 §9.1's 900-for-9 line, **projected** |
| ARC-4 routing + per-arg length guard | **44** per arg | 004 §9.1, **measured** |
| ARC-4 `DynamicArray` unpack wrapper overhead | **+209** over the bare fold | 004 §2.5, **measured** (644 vs 435) |
| fork-table lookup | ~**100** | 004 §9.1's 200-for-2 line, **projected** |
| top-level app call contributes | **700** | RESULTS.md §4, **measured** |
| inner app call contributes | **+700**, costs **18** to issue | 004 §2.4, **measured** |
| inner-txn cap | **256 per group** | 004 §2.7, **measured** (257 fails) |
| box-reference cap | **8 per transaction**, structural | 004 §16.2, **measured** |
| pooled box byte budget | **2,048 B per box reference, across the group** | 004 §16.2, **measured** |
| touching an existing box charges | its **full declared size**, once per box per group | 004 §16.2/§16.5, **measured** |
| assembly allowance on projected sums | **+10 %** | 004 §9.1's convention |

### 10.2 DIRECT anchor

| line | budget | basis |
|---|---:|---|
| ARC-4 routing + 7 args + 3 `DynamicBytes` unpacks | 300 | 004 §9.1 (44/arg) + §2.5 (+209/unpack, amortised) — **projected** |
| 3 × `app_global_get_ex` from M4 + `N4`/`N5` asserts | 60 | **projected** |
| `hash_tree_root_beacon_block_header` (7 `sha256`) | 700 | 004 §9.1's ~100/`sha256` — **projected**; directly measurable, the code exists |
| fork-row lookup (`forks8`) | 100 | 004 §9.1 — **projected** |
| fold @ `g_state_root`, depth 9 | **850** | `103+83·9`, **measured formula** |
| fold @ `g_receipts_root`, depth 9 | **850** | same |
| fold @ `g_block_number`, depth 9 | **850** | same |
| `le64(block_number) ‖ bzero(24)` chunk build (N-CHUNK) | 100 | **projected**; `le64` is a Puya byte loop |
| record assembly, 154 B from 9 pieces | 120 | M6 §7.3's ~60/repack for 248 B — **projected** |
| ring residue, `box_get`, conflict/idempotence compare, `box_replace` | 200 | **projected** |
| `hi_block`/`hi_slot`/`n_anchored` writes | 50 | **projected** |
| `N10`/`N11`/`N22`/N-ADMIT asserts | 80 | **projected** |
| **subtotal** | **4,260** | |
| **+10 % assembly allowance** | **4,686** | |

Group: 1 top-level call + `I` donor inner calls gives `700 + 682·I` net.

| `I` | net usable | headroom over 4,686 |
|---:|---:|---:|
| 6 | 4,792 | 2 % — minimum, too thin |
| **8** | **6,156** | **31 %** — recommended |
| 10 | 7,520 | 60 % |

> **DIRECT: one top-level transaction, 8 donor inner calls. Fees 9 × 1,000 =
> 0.009 ALGO.**

Note what is *absent*: no multi-segment walk, no log hand-off inside M8, no
funding Payment, no second group. **M8's anchoring path is the simplest group
shape any module in this project has produced** — a direct consequence of the
work being three Merkle folds rather than a trie walk.

### 10.3 HISTORICAL anchor

| line | budget | basis |
|---|---:|---|
| everything in §10.2's subtotal | 4,260 | |
| `hash_tree_root(target_header)`, 7 `sha256` | 700 | **projected** |
| second fork-row lookup (N-FORK) | 100 | **projected** |
| `header_slot` + `mod 8192` (N-INDEX) + composed gindex | 110 | **projected**; `be64_from_le` is a byte loop |
| fold @ `block_roots[i]`, **depth 19** (Electra/Fulu worst case) | **1,680** | `103+83·19`, **measured formula** |
| N-WINDOW asserts + `N7` cross-check | 40 | **projected** |
| **subtotal** | **6,890** | |
| **+10 %** | **7,579** | |

| `I` | net usable | headroom |
|---:|---:|---:|
| 11 | 8,202 | 8 % — minimum |
| **14** | **10,248** | **35 %** — recommended |

> **HISTORICAL: one top-level transaction, 14 donor inner calls. Fees 15 × 1,000
> = 0.015 ALGO.**

At depth 18 (Bellatrix…Deneb) the fold is 1,597 instead of 1,680, subtotal 6,807,
×1.1 = 7,488 — inside the same recommendation. Sizing on the deeper case means
one donor count works across the fork boundary, which matters because the relayer
picks `I` before it knows which row applies.

### 10.4 Consumer-side cost — net negative, which is the headline

| line | budget | basis |
|---|---:|---|
| `attest` routing + `uint64` arg | 100 | **projected** |
| ring residue + `box_get` (154 B against the pool) | 45 | **projected** |
| `version`/`flags`/`conflict`/block-number checks | 90 | **projected** |
| ARC-4 return log of 154 B | 25 | **projected** |
| **`attest`'s own consumption** | **260** | |
| **`attest`'s contribution as a top-level call** | **+700** | **measured** |
| **net to the group** | **+440** | |
| `anchor_from_group` in the consumer's program (`N1`–`N3`, `N13`–`N15`, extract) | **~95** | **projected**; M5 §7.4 measured the same-app analogue at **8** hand-TEAL, M6 measured a full segment boundary (which also repacks state and logs) at **211** Puya. 95 sits between, closer to the light end because there is no repack. |
| **net effect of the whole anchor check on an M7 group** | **+345** | |

> **Adding M8's trust check to an M7 proof group makes the group's opcode budget
> *larger*, not smaller.** It costs one transaction (1,000 µALGO), one box
> reference of the 8 available on that transaction, and nothing else.
>
> This is worth stating plainly because the intuitive expectation — "trustless
> costs more" — is wrong here, and it removes the only rational argument for
> leaving TP-M7-2 open. The reason is structural: on the AVM, opcode budget is
> granted *per application call*, so any mechanism that adds an app call to a
> group adds budget, and `attest` does far less work than the 700 it brings.

### 10.5 Argument-size ceilings

Per-transaction application-argument cap: **2,048 bytes** (004 §7.3, M5 §7.2's
measured usable budget 1,942 B after framing). Argument *count* cap: 16.

| call | components | bytes |
|---|---|---:|
| **`anchor_direct`** | selector 4 + header 112 + 2 roots 64 + `uint64` 8 + 3 branches (288+2 each) 870 | **1,058** |
| **`anchor_historical`** | the above + target header 112 + `block_roots` branch (19×32 + 2) 610 | **1,780** |
| `anchor_historical` at depth 18 | as above with 18×32 | 1,748 |
| `attest` | selector 4 + `uint64` 8 | **12** |

`anchor_historical` at 1,780 of 2,048 leaves **268 bytes (13 %)**. That is real
but thin, and it has two consequences worth stating:

1. **O-M8-1 (§17) is upgraded from "nice" to "recommended".** Fusing the
   `state_root`/`receipts_root` pair into one depth-8 fold removes an entire
   290-byte branch, taking HISTORICAL to **1,490 B (27 % headroom)** and DIRECT to
   **768 B**, while also saving **933 budget**. It costs one extra `sha256` (35)
   and one carefully-ordered concatenation.
2. **It is a hard argument against Gloas (NG3) beyond "unapproved".** At Gloas's
   depth 11 (003 §2.4), each EL branch becomes 352 B and the `block_roots` branch
   grows too; `anchor_historical` lands at roughly **1,972 B + the deeper state
   branch**, over the cap. Gloas support therefore requires a two-transaction
   log-chain split (O-M8-4), which is the same mechanism O-M8-3 needs — so
   whichever of the two lands first pays for the other.

### 10.6 Box references and the pooled byte budget

Per 004 §16.2, the two real constraints are 8 references per transaction and
2,048 B of pooled write budget per reference across the group.

| operation | refs | declared bytes touched | pooled budget available | utilisation |
|---|---:|---:|---:|---:|
| `anchor_direct` / `anchor_historical` | 2 (`h:<i>`, `forks8`) | 154 + 321 = **475** | 2 × 2,048 = 4,096 | **12 %** |
| `attest` | 1 (`h:<i>`) | **154** | 2,048 | **8 %** |
| `pin` | 1 (`p:<n>` create) | **186** | 2,048 | 9 % |
| `ring_init_chunk` ×16 | 8 each | 128 × 154 = 19,712 | 262,144 | **8 %** |

> **M8 is the first module in this project that is not box-constrained.** M4
> needed a minimum of 25 pooled references and a three-way split of its install
> call to get under the caps (004 §16.3); M7's T2 path needed a funding Payment,
> a create, chunked writes and a 9-transaction group (007 §3.4). M8 uses 2
> references at 12 % of their budget. The reason is the 154-byte record: M4
> §16.2's full-declared-size charging rule, which was a liability for 6,144-byte
> committee boxes, is a non-event for a 154-byte one. §7.3 already used this to
> reject the rolling-array alternative; it is restated here because it is the
> single design property that keeps the anchoring group to one transaction.

### 10.7 ALGO cost per operation

| operation | app calls | fees | MBR |
|---|---:|---:|---:|
| deploy + ring init (N=128) | 1 create + 16 init | 0.017 | **9.328 locked** (recoverable) |
| `anchor_direct` | 1 + 8 inner | **0.009** | 0 |
| `anchor_historical` | 1 + 14 inner | **0.015** | 0 |
| `attest` (the consumer's cost) | 1 | **0.001** | 0 |
| `pin` | 1 + 1 Payment | 0.002 | **0.0809 locked** (refundable) |
| `unpin` | 1 + 1 inner Payment | 0.002 | −0.0809 released |

For scale, against this project's own measured figures: one M4 sync-committee
update is **0.264 ALGO** (004 §9.3), M6's composite storage read is **0.020
ALGO** (006 §7.5), M5's account walk group is 0.010–0.020. **M8's anchoring is
the cheapest real operation in the project, and `attest` is an order of magnitude
below that.**

Against the product: M7's x402 toll is 0.01 USDC (`main.py`
`PRICE_MICRO_USDC = 10000`). A cache-hit query adds `0.001 ALGO` of anchor cost;
a cache-miss adds `0.010–0.016 ALGO`. Whether that clears the toll depends on
ALGO's price and on the cache-hit rate, neither of which this document knows —
**§16 records it as an honest gap**, and notes that it is the same style of
analysis 007 §14.8 did for the ZK tiers with real trigger rates, which is the
model to follow once there is traffic.

### 10.8 Program size

| component | bytes | basis |
|---|---:|---|
| M3 `merkle.py` fold + `merkleize.py` `zero_hash` table | ~600 | **projected**; 003 §2.4 measured the *fold-only* program at 157 B hand-TEAL, and 003 §5.5 notes a 64-entry `zero_hash` table would be 2,048 B — **M8 needs only a small prefix, and must embed only that prefix** (003 §7.4). Flagged: an implementer who copies the full table burns a quarter of the cap for nothing. |
| M4 `header.py` (`htr`, `header_slot`, `le64`, `be64_from_le`) | ~350 | **projected** |
| fork table read + N-FORK | ~200 | **projected** |
| record assembly + ring/pin box logic | ~450 | **projected** |
| governance + `ring_init` + `pin`/`unpin` | ~350 | **projected** |
| ARC-4 router, 15 methods | ~250 | **projected**, scaled from 004 |
| **M8 total** | **≈ 2,200** | vs the **8,192 B** cap ⇒ **73 % headroom** |
| `handoff.py` — the part M6/M7 *import* | **≈ 250** | **projected**; this is the number that matters for M7's 3,104 B → 3,354 B |

G7-M8 (§14) gates the deployed app at ≤ 8,192 B and `handoff.py`'s own
contribution at ≤ 400 B, measured M5-style as a combined probe diffed against a
baseline probe (`bench/mpt_results.json`'s `G5_M5_compiled_size` methodology).

---

## 11. Adversarial trace

Format follows 007 §6.1. Every row is a concrete thing a malicious relayer or
service operator does, not a category.

| # | attack | outcome | why |
|---|---|---|---|
| **S1** | Fabricate a `receipts_root` and anchor it | **rejected** | The depth-9 fold at `g_receipts_root` must produce `body_root`, which must equal bytes [80:112] of a header whose `hash_tree_root` equals M4's `fin_root`. Forging requires a `sha256` preimage attack. |
| **S2** | Anchor a *genuine* `receipts_root` from a different block | **rejected** | The fold is against *this* block's `body_root`. (Note: many blocks share the empty-trie root `0x56e8…421d`; that is not an attack — the fold still binds it to this block, and the record is correct.) |
| **S3** | Deploy `FakeM4` with an attacker-chosen `fin_root`, pass it in `foreign_apps` | **rejected — `N4`** | `m4_app_id` is **write-once at create** (§6.2) and every read asserts the foreign app matches it. **If it were a parameter, this attack wins outright and M8 is decorative.** TP-M8-7. |
| **S4** | Deploy `FakeAnchor` exposing an `attest`-shaped method returning an attacker-chosen record; point M7's `anchor_gi` at it | **rejected — `N2`, and only because of TP-M8-4** | `ANCHOR_APP_ID` is a compile-time constant in the consumer. **This is the single most important line in the whole hand-off.** Identical in shape to 007's Z6 (attacker-supplied verifier logicsig). A reviewer should grep M6/M7 for any path by which this value is reachable from a method argument, foreign-app index, box, or mutable global. |
| **S5** | Anchor a genuine old block, then serve it as if it were current | **rejected at the consumer — `N15`** | `el_block_number` is Merkle-bound at `g_block_number` (N-CHUNK) *and* is the box key *and* is compared against the consumer's mandatory `want_block_number`. Three independent bindings. |
| **S6** | Supply M4's *attested* header instead of the finalized one | **rejected — `N6`** | M8 reads only `fin_root`. `htr(att_header) != fin_root` for any header M4 did not finalize. There is no code path that reads `att_slot`/`att_state_root` (§5.2). |
| **S7** | Anchor before M4 has ever finalized anything | **rejected — `N5`** | `fin_root == 0` is refused. M4 §12.3 item 3 asked for exactly this, and M3 §7.5 established that a zero root is legitimate data elsewhere so it cannot be caught generically. |
| **S8** | HISTORICAL with a target more than 8,192 slots back | **rejected — `N18`, with `N16` as belt-and-braces** | The vector genuinely does not contain it; no branch verifies. `N16` converts an obscure fold failure into a named error. |
| **S9** | HISTORICAL supplying a hand-picked `block_roots` index | **impossible — no such parameter** | N-INDEX derives it from `header_slot(target_header)`. **Any implementation that adds an index parameter is a critical defect** (M5 §5.2's rule, third occurrence). |
| **S10** | Use a fork row whose gindices belong to a different fork so a different field lands at the proven position | **rejected** | Across the Capella→Deneb boundary depths differ (8 vs 9), so the branch length itself is wrong (`N9`) and no siblings exist that fold correctly. Within a fork, the columns are fixed by the table. The residual risk is a **mis-entered table**, which is TP-M8-3, gated by G4-M8. |
| **S11** | **The two-row trap** — use `epoch(fin_slot)`'s row for the EL gindices when `t_slot` is in an earlier fork | **rejected if N-FORK is implemented; SILENTLY WRONG-BY-LIVENESS if not** | §3.4. Fails closed either way (a wrong gindex just does not verify), so this is a liveness bug, not a soundness one — but it is a liveness bug that only manifests within 27 hours of a fork, i.e. at the worst possible moment. Suite F tests both boundaries. |
| **S12** | Replay an `attest` log from an *earlier group* | **rejected — `N1`** | `gtxn` addresses only the current group, and `gi < Txn.group_index` is asserted. M5 §7.4's W13, unchanged. |
| **S13** | Consume a revoked record | **rejected — `N13`** | Checked in `attest` *and* again in `anchor_from_group`, deliberately: a consumer that somehow obtained a record through another path still cannot use a revoked one. |
| **S14** | Governance writes a false root | **impossible by construction** | There is no method that writes an anchored field. Governance can `revoke`, `freeze`, `gov_clear_conflict`, `append_fork_row`, `renounce`. Only `append_fork_row` touches soundness (TP-M8-3), and `renounce()` closes even that. |
| **S15** | Two relayers race to anchor the same block, to fail one of them | **both succeed** | §5.4's idempotence rule: identical content is a no-op success, not `N20`. `anchored_round` is excluded from the comparison precisely so the second writer does not trip the equivocation latch on a timestamp. **This exclusion is load-bearing and easy to omit.** |
| **S16** | Deliberately trip the `conflict` latch to DoS the contract | **not cheaply reachable** | Requires two mutually inconsistent records for the same block number, each carrying a full valid chain to M4's current `fin_root`. An attacker who can produce that already controls a 2/3 sync-committee majority and does not need a DoS. §5.5. |
| **S17** | Fund `pin` with a Payment addressed elsewhere, or short | **rejected — `N24`** | Receiver must be the app account and amount must cover the MBR. An underfunded `box_create` fails the group, leaving nothing behind (§7.5). |
| **S18** | `unpin` someone else's pin to steal the MBR refund | **rejected — `N24`** | The refund destination is the 32-byte payer address stored *in the record*, not the sender and not a parameter. Even governance-initiated `unpin` refunds the recorded payer. |
| **S19** | Overwrite a revoked record with an identical re-anchor to clear the revocation | **rejected** | §7.6's normative rule: a ring write MUST NOT clear `FLAG_REVOKED` for the same `el_block_number`; only eviction by a *different* block number clears the box. The naïve "just overwrite" implementation gets this wrong; S-REV (§13.4) tests it. |
| **S20** | Anchor a block whose `block_number` chunk was crafted with dirty bytes in the 24-byte pad | **impossible — no such parameter** | N-CHUNK: M8 builds the chunk from a `uint64`. There is no way to present a 32-byte chunk. |

---

## 12. Edge cases

**12.1 The genesis / first-anchor case.** `hi_block == 0` admits any block number
(§7.4). Immediately after `ring_init` the entire ring is `version == 0`, so the
first `N` anchors all take the "empty slot" path. No special code, but Suite R
must exercise it: an off-by-one in "is this box empty" is the most likely
`version`-byte bug.

**12.2 A block with no logs / an empty receipts trie.** `receipts_root` is the
empty-trie root. Perfectly anchorable, and correct. M7 already returns
`R_ZERO_LOGS` as a legitimate verdict (007 §5.4). Nothing special here, recorded
so nobody adds a well-meaning "reject the empty root" check — which would be
wrong, and which is the M3 §7.5 mistake ("a zero leaf is legitimate") in a new
place.

**12.3 A skipped beacon slot.** Handled with no special case, by N-INDEX deriving
the vector index from the target header's own slot (§4.3). Worth an explicit test
(Suite H) because "handled by construction" claims are exactly the ones that turn
out to be false.

**12.4 `fin_slot` advancing between `simulate` and `send`.** The relayer sizes
donors and builds the group against M4's state at simulate time; by submission,
M4 may have advanced (a new `submit_update` landed). DIRECT then fails `N6` —
the header no longer matches `fin_root`. **This is normal, not exceptional**, and
M9 must retry rather than treat it as an error. It is also a strong practical
argument for preferring HISTORICAL for anything that is not the very newest
block: a HISTORICAL anchor is valid against *any* finalized header newer than the
target, so it survives M4 advancing, whereas DIRECT is valid against exactly one.
**Flagged for M9 (§15.3) as a real operational preference that inverts the naïve
"use the cheaper mode" instinct.**

**12.5 The fork table has no row for the requested epoch.** `N17`. Happens if a
fork activates and governance has not appended the row — a pure liveness failure,
correctly. It is also what `renounce()` makes permanent, which §5.7 states.

**12.6 A branch whose length does not match the gindex's depth.** `N9`, and M3
§7.2/§7.3 already specify the check (length must be a multiple of 32 and must
equal `32 · depth(gindex)`). M8 must use M3's *asserting* wrapper
(`assert_valid_merkle_branch`), not the bare fold, per M3 §7.6's "assert, never
return bool".

**12.7 `depth = 0`.** Cannot arise: every gindex in §3.2's table is ≥ 402. M3
§7.1 handles it anyway. Recorded for completeness.

**12.8 An execution block number that is not monotone with the beacon slot.**
Rejected by N-ADMIT's paired advance check, and routed to §5.5's latch. Cannot
happen on a canonical chain.

**12.9 `ring_n == 1`.** Legal (a power of two) and degenerate: every anchor
evicts the previous one and the ring is a single-slot cache. Not rejected —
there is no principled minimum, and a deployment that only ever does same-group
anchor-then-consume genuinely does not need more. Recorded so a reviewer does not
mistake it for an oversight. `ring_n == 0` is rejected at create.

**12.10 An anchor whose target header is the genesis block.** `t_slot == 0`,
`fin_slot - 0 <= 8192` only holds for the first 8,192 slots of the chain. Not
reachable on mainnet today. No special case.

---

## 13. Test plan

Suites and numbering follow M5 §9 / M6 §11 / M7 §9. **Every "real" fixture below
must come from real mainnet data**, per `ARCHITECTURE.md`'s rule and this
project's practice of pinning official consensus-spec vectors rather than
self-generated ones.

### 13.1 Suite A — the real anchor (pinned)

**The headline fixture is already in this repository.**
`tests/fixtures/rlp/nodes.json` pins Ethereum mainnet block **25,639,768** with:

```json
"state_root":    "0xde97a8349a6496353877597fd35732f6705ee836b2d00b6c367fa8acd2c53329",
"receipts_root": "0x6490277f4254f8d51780f05201c5a9a9985a5d4c3d207a68eda643dc099e710b"
```

and it is the same block M7's live mainnet test used (ROADMAP M7 row: *"tx 31,
block 25,639,768, the design doc's own pinned example"*, verified against app id
3664247481).

| # | test | asserts |
|---|---|---|
| **A1** | DIRECT anchor of the beacon block containing EL block 25,639,768 | `A.el_receipts_root == 0x6490…710b` and `A.el_state_root == 0xde97…3329` — **byte-identical to the values M2/M5/M6/M7 have been testing against since M2** |
| **A2** | The full end-to-end chain: `anchor_direct` → `attest` → M7's `mpt7_result_against_anchor` for tx 31, log 0, in one group | `R_INCLUDED`, and the receipts root M7 walked came from A1's anchor, not from an argument |
| **A3** | `get_anchor` (readonly, off-chain) returns the identical 154 bytes | the two read paths agree |
| **A4** | Decode `A` off-chain against §6.1's offset table | M9's parser is correct; mirrors M6 §13.3's "three byte comparisons" convention |

> **A1/A2 together are the module's reason for existing**, and they are gated as
> **G1-M8**. If A2 passes with a real, non-simulated submission, TP-M7-2 is
> closed and `main.py`'s honest-gap docstring can be deleted.

### 13.2 Suite F — the fork table and the two-row trap

| # | test | asserts |
|---|---|---|
| **F1** | Regenerate all gindices with `get_generalized_index` against a pinned `consensus-specs` checkout; compare to the deployed rows | **G4-M8**. Must run in CI (M11). |
| **F2** | `g_block_hash` regenerates to 412 (Capella) and 812 (Deneb) | cross-checks the composition against the two values the spec itself publishes (§3.2) |
| **F3** | `append_fork_row` with a non-increasing `activation_epoch` | rejected (M4 §4.3's rule) |
| **F4** | `append_fork_row` from a non-governance sender, and after `renounce()` | `N23` both times |
| **F5** | **Capella→Deneb straddle**: `fin_slot` in Deneb, `t_slot` in Capella | the *Capella* EL row is used; anchoring succeeds; using the Deneb row fails |
| **F6** | **Deneb→Electra straddle**: `fin_slot` in Electra, `t_slot` in Deneb | the *Electra* `g_block_roots_base` (69, depth 19) and the *Deneb* EL row (803, depth 9) are used **in the same call**. **This is §3.4's trap and the single most important test in Suite F.** |
| **F7** | Epoch before the first row | `N17` |

### 13.3 Suite H — historical mode

| # | test | asserts |
|---|---|---|
| **H1** | HISTORICAL anchor of a target 1 slot behind finality | succeeds; `FLAG_HISTORICAL` set |
| **H2** | Target exactly 8,192 slots behind | succeeds (boundary, inclusive) |
| **H3** | Target 8,193 slots behind | `N18`/`N16` |
| **H4** | Target *equal to* `fin_slot` | `N16` — HISTORICAL is not a superset of DIRECT (§4.2) |
| **H5** | **Skipped slot**: target header's slot `j'`, with `j' + 1 … j` skipped | the derived index `j' mod 8192` verifies; the record carries `j'` (§4.3) |
| **H6** | Attempt to supply a vector index as an argument | **there is no such parameter** — a source-level review item, and a grep in CI |
| **H7** | `fin_header.state_root` disagreeing with M4's `fin_state_root` global | `N7` |

### 13.4 Suite S — security

Every row of §11 gets a test. The ones that need naming because they are easy to
skip or easy to write wrongly:

| # | test | asserts |
|---|---|---|
| **S-M4** | Deploy a `FakeM4` with an attacker-chosen `fin_root`; pass it in `foreign_apps` | `N4` (S3) |
| **S-APP** | Deploy a `FakeAnchor` returning an attacker-chosen 154-byte record with a valid ARC-4 envelope; point a consumer's `anchor_gi` at it | `N2` (S4). **Must be written against the real consumer contract, not against a test harness** — the property under test is that the consumer's constant is unreachable. |
| **S-ATT** | Supply M4's attested header | `N6` (S6) |
| **S-ZERO** | M4 with `fin_root == 0` | `N5` (S7) |
| **S-IDEM** | Two identical anchors of the same block, from different senders, in different rounds | both succeed; `conflict` stays 0 (S15). Confirms `anchored_round` is excluded from the comparison. |
| **S-CONF** | Two anchors of the same block number with different `el_receipts_root` (derived fixture — real chain data cannot produce this) | `N20`; `conflict` latches; a subsequent `attest` fails `N22`; `gov_clear_conflict` restores service |
| **S-REV** | `revoke`, then `attest` (→`N13`), then re-anchor identical content, then `attest` again | **still `N13`** (S19). The flag must survive the rewrite. |
| **S-GOV** | Enumerate every method; assert none writes an anchored field | S14. A source-level review item plus a mutation test. |
| **S-PIN** | `unpin` from a non-payer; `pin` with a Payment to a wrong receiver; `pin` underfunded | `N24` ×3 (S17, S18) |
| **S-GRP** | Point `anchor_from_group` at a transaction from a previous group, and at a later transaction in the same group | `N1` both times (S12) |

### 13.5 Suite R — retention and eviction

| # | test | asserts |
|---|---|---|
| **R1** | Anchor `N + 1` consecutive blocks | the oldest is evicted; `attest` on it → `N12`; all others intact |
| **R2** | Anchor a block at `hi_block − N` (just outside the window) | rejected by N-ADMIT |
| **R3** | Anchor at `hi_block − N + 1` (just inside) | succeeds, evicts nothing newer |
| **R4** | The §5.4 distinctness lemma, exhaustively at `N = 8` | no two in-window block numbers share a residue |
| **R5** | `pin` a ring record, then evict it from the ring | `attest` still succeeds from the pinned tier |
| **R6** | `[Payment, anchor_historical, pin]` in one group | one-group durable anchoring of an old block (§7.5) |
| **R7** | `unpin` | MBR refunded to the recorded payer, box deleted, `attest` falls back to the ring (or `N12`) |
| **R8** | `ring_init_chunk` out of order, twice, and after completion | cursor discipline holds (M4's `install_chunk` convention) |
| **R9** | Anchor before `ring_cursor == ring_n` | `N10` |
| **R10** | **Live**: full 16-transaction `ring_init` group at `N = 128` against real algod | **G5-M8**. Real submission, not `simulate` — M4 §16's whole lesson is that box-reference and pooled-budget errors only appear for real. |

### 13.6 Suite B — budget, live

Following M5 §9.6 / M6 §11.4 / M7 §9.7, and `ARCHITECTURE.md`'s rule that no
number ships without a real response. Results land in
`bench/anchor_results.json`.

| # | measurement | replaces the projection in |
|---|---|---|
| **B1** | `anchor_direct`, real submission, donors sized from a prior `simulate` | §10.2's 4,686 |
| **B2** | `anchor_historical` at depth 18 **and** depth 19 | §10.3's 7,579 |
| **B3** | `attest` in isolation, and `anchor_from_group` isolated by diffing a consumer that calls it against one that does not | §10.4's 260 and 95. **M6's G4-M6 asked for exactly this isolation and it was not delivered (M6's ROADMAP row: "G4-M6 (segment-boundary cost isolation) not separated out, same as M5"). M8 must not make it three.** |
| **B4** | Enumerate the opcode surface from the compiler's table; confirm no cross-app box-read opcode exists | §8.5's claim |
| **B5** | `hash_tree_root_beacon_block_header` in isolation | §10.2's 700 — the largest single projected line |
| **B6** | Compiled size of the deployed app and of `handoff.py`'s contribution, M5-style diff | §10.8 |
| **B7** | End-to-end: A2's full group, real submission, real round | **G1-M8** |

---

## 14. Acceptance gates

| gate | criterion | why this bar |
|---|---|---|
| **G1-M8** | A2 passes via a **real, non-simulated submission**: `anchor_direct` → `attest` → M7 `R_INCLUDED` for block 25,639,768 tx 31, in one group, with the receipts root taken from the anchor | This is the module. M5/M6/M7 all held themselves to "real submission, not simulate" and all three found things simulate hid. |
| **G2-M8** | `anchor_direct` ≤ **6,000** budget measured | §10.2 projects 4,686; a 28 % allowance over a projection this document owns. M3 came in 40 % over hand-TEAL and M5 came in 2× over target; M6 came in **under**. This bar is set to be informative rather than automatic. |
| **G3-M8** | `anchor_historical` ≤ **9,500** budget measured, at depth 19 | §10.3 projects 7,579, same allowance |
| **G4-M8** | Every deployed gindex regenerates from `get_generalized_index` against a pinned spec checkout, **in CI** | TP-M8-3, 003 §4.5's explicit instruction. The one gate that protects against a soundness bug governance could introduce. |
| **G5-M8** | `ring_init` at `N = 128` commits as a **real** 16-transaction group | 004 §16 is a first-hand account of why box-reference arithmetic must be confirmed live |
| **G6-M8** | `attest` + `anchor_from_group` measured at ≤ **500** combined, and the **net** effect on an M7 group measured as **positive** | §10.4's headline claim. If it is false, the integration argument changes. |
| **G7-M8** | Deployed app ≤ 8,192 B; `handoff.py`'s own contribution ≤ 400 B, measured M5-style | §10.8; the second number is what M6/M7 pay |
| **G8-M8** | `contracts/state_anchor/*.arc56.json` committed and CI-diffed | M9/M10 are blocked on a frozen ABI (`ROADMAP.md`) |
| **G9-M8** | Every `N*` code in §6.4 has at least one test that produces it | M5/M6/M7 all shipped error-code tables; none gated coverage of them. M8 does. |
| **G10-M8** | Suites F5, F6, H5, S-APP, S-REV, S-IDEM all pass | The six tests that cover the traps this document found at design time. Named individually so they cannot be quietly dropped. |

---

## 15. `ROADMAP.md` questions resolved, and what is handed on

### 15.1 M8's own row

> *"Root-history retention/eviction policy (real storage-cost tradeoff)"*

**Resolved, in four parts:**

1. **Retain-everything is priced and rejected**: 0.0681 ALGO/block × 7,200
   blocks/day = **490 ALGO/day of locked MBR, unbounded**. Not a policy (§7.1).
2. **The reframe that makes it tractable**: retention is a **cache**, not a
   correctness requirement, because the primary integration is same-group
   anchor-then-consume with a zero-round record lifetime (§7.2).
3. **The policy**: a fixed, fully-prepaid ring of `N = 128` boxes with implicit
   modular eviction and a window-admission rule, plus an unbounded, individually
   self-funded pinned tier for durable requests (§7.3–§7.5). **9.328 ALGO of
   locked, recoverable MBR at deployment; zero MBR on the anchoring path.**
4. **Who pays**: the operator pays once for the hot ring (a fixed cost, not a
   growing one); a requester who wants a specific old block held durably pays
   0.0809 ALGO for it and can reclaim it. Consumers who hit an evicted root get
   `N12` and re-anchor for 0.015 ALGO (§7.6).

**And a fifth thing the ROADMAP row did not ask for but which the analysis
produced**: M4 §16.2's full-declared-size box charging rule **inverts the usual
many-small-vs-few-large tradeoff** for random-access workloads. A 32 kB rolling
array would burn 16 box references — twice the structural per-transaction cap —
on every single read. 154-byte boxes burn one. This is the quantitative reason
the ring is shaped the way it is, and it is a reusable finding for M10.

### 15.2 Questions this pass closes for other modules

- **M7's TP-M7-2** — *"`receipts_root` must come from M8's anchor, not from the
  relayer"* — has a mechanism (§9.2), a cost (**net +345 budget**, +1 transaction,
  §10.4), and a gate (G1-M8).
- **M7 §8.3's first bullet** — *"M8 must anchor `receiptsRoot`, and must make it
  queryable by block identity"* — answered: the record is keyed by
  `el_block_number`, which is itself Merkle-bound (N-CHUNK), so "queryable by
  block identity" is not a labelling convention but a proven property.
- **M7 §8.3's second bullet** — the transaction-count bound for meaningful
  exclusion — answered as O-M8-2, with the mechanism (exclusion walk in the
  transactions trie, same key encoding, M5's machinery unchanged) and the price
  (850 budget, 32 B/record, a `version = 2` bump).
- **M6 §13.2's four bullets** — all four: the swap point stays a one-line
  substitution because `anchor_state_root` returns 32 bytes; TP-M6-3 is enforced
  by feeding `want_state_root` from the anchor on-chain; reorg/freshness policy is
  §5; and the program-size question is resolved by **not** co-deploying, with the
  measured numbers that force it (§8.6).
- **M4 §12.3's five bullets** — item 1 (no inner call available from
  `submit_update`) is resolved better than M4 suggested: M8 reads M4's globals
  with `app_global_get_ex`, needing neither an inner call nor co-deployment
  (§8.2). Item 2 (`is_valid_light_client_header`) is §3. Item 3 (zero roots) is
  `N5`. Item 4 (key on `finalized_slot`) is **respectfully deviated from**: M8
  keys on `el_block_number` and *carries* `beacon_slot`, because every consumer —
  M6, M7, and `main.py`'s own path parameter — asks in EL block numbers, and a
  slot-keyed store would force every consumer to do a slot↔block translation that
  nothing on-chain could verify. The deviation is explicit, and `beacon_slot` in
  the record means nothing is lost. Item 5 (retention is M8's) is §7.
- **M3 §4.5's instruction to M8** — both halves honoured: the single deep gindex
  is chosen with the arithmetic that justifies it (§3.1), and the
  two-dimensional fork table exists (§3.3), with a third dimension M3 did not
  anticipate (`BeaconState`'s shape, §3.4).

### 15.3 Flagged for M9 (relayer)

1. **The ABI is frozen by §8.2** and the record layout by §6.1. M9 can start
   now, ahead of implementation, per `ROADMAP.md`'s M9 row.
2. **The T2 cache-miss group does not fit 16 transactions** (§9.3). Fix by
   replacing M7's 8 filler NoOps with donor *inner* calls (M5's `_issue_donors`,
   already implemented) — recommended — or by anchoring in a preceding group.
3. **Prefer HISTORICAL for anything that is not the newest block** (§12.4). This
   inverts the naïve "use the cheaper mode" instinct: a DIRECT anchor is valid
   against exactly one finalized header and breaks if M4 advances between
   `simulate` and `send`; a HISTORICAL anchor is valid against any newer one.
4. **Cache before you build.** `get_anchor` is readonly and free off-chain.
5. **Donor sizing**: M5 §16.3's procedure verbatim — `simulate` with zero
   donors, size, then verify with a real `send_transactions`.
6. **`N12` and `N13` are not the same thing** (TP-M8-6, §7.6). Re-anchor on
   `N12`; never on `N13`.
7. **`N20` is not retryable.** It is the equivocation latch. Page a human.
8. **Branches must be generated against the same pinned spec version as the
   fork table** (G4-M8), and depths must never be hardcoded.
9. **The x402 pre-payment problem** (§9.3): the middleware settles before the
   handler runs, so a not-yet-finalized or out-of-window block means the payer
   paid for a 425/501. Either add a free `/anchorable/{block}` pre-check
   endpoint or accept it. **This is a product decision, flagged not made.**

### 15.4 Flagged for M10 (deployment & box-schema tooling)

1. **Choosing and funding `N`** (§7.8), and the 16-transaction `ring_init` group
   plus its prior funding transaction (§7.7).
2. **Seeding the fork table**, generated by `get_generalized_index`, never
   hand-entered (G4-M8, TP-M8-3).
3. **Pinning M4's approval-program hash** in deployment config. TP-M8-7: M8
   cannot verify on-chain that `m4_app_id` is the real M4; the deployer must.
4. **The `renounce()` decision and its migration cost** (§5.7): renouncing makes
   the contract immutable and removes governance from the trust model, at the
   price that a future fork needs a redeploy — and, because TP-M8-4 requires
   consumers to compile the anchor app id in, a **consumer redeploy too**. This
   is the most consequential operational decision in M8 and M10 must document the
   migration, not just the flag.
5. **No box sweeper is needed** (§7.5), unlike M7's T2 staging boxes (007 §8.4).
   Recorded so M10 does not build one.
6. **Deployment MBR: 9.328 ALGO at `N = 128`**, all recoverable.

### 15.5 Flagged for M11 (test harness & CI)

1. **G4-M8 must run in CI** — the gindex regeneration. It is the only gate
   standing between a governance typo and a silently wrong anchored root.
2. **The Deneb→Electra straddle fixture (F6)** requires real beacon data from
   both sides of a real fork boundary. That is a new fixture class for this
   repo — everything so far has been single-fork.
3. **`bench/anchor_results.json`** joins the four existing bench files.
4. **G9-M8** (every error code exercised) is a coverage discipline M1–M7 did not
   have; M11 owns keeping it true as codes are added.

### 15.6 Flagged for M12 (docs & release)

**`README.md` must state TP-M8-1 in the same breath as the words "trustless" or
"verified".** Sync-committee messages are not slashable; a 2/3 committee majority
can lie at no cost; this is Ethereum's light-client model, not a defect in this
implementation, and it is not full-node security. 007 §8.6 already assigned M12 a
documentation-correction list; this belongs at the top of it, above the keccak
correction, because it is the only item on that list that affects what a user
should believe.

---

## 16. Honest gaps

Things this document does not know, stated rather than smoothed over.

1. **Every non-fold budget line is projected.** The three fold costs come from a
   measured formula that was exact on four points; everything else — the 700 for
   `hash_tree_root`, the 260 for `attest`, the 95 for `anchor_from_group` — is an
   estimate this document owns. Suite B replaces all of them. On this project's
   track record, projections have missed **both** ways (M3: 40 % over; M5: 2×
   over on a gate; M6: **under**), so the direction of the error is genuinely
   unknown.
2. **`N = 128` is chosen from structural arguments, not from traffic.** There is
   no data on cache-hit rates because the service has never run with an anchor.
   §7.8's reasoning (one init group, covers the finality lag, under half of M4's
   MBR) is sound but it is not measurement. An operator should re-derive `N` after
   a month of real queries — and, per §6.2, that means a **redeploy**, which is
   an argument for erring larger initially that this document has deliberately
   not taken.
3. **The economics are unpriced.** §10.7 gives ALGO costs; it does not say
   whether 0.01 USDC covers them, because that needs an ALGO price and a
   cache-hit rate. 007 §14.8 did exactly this analysis for the ZK tiers once real
   trigger rates existed; the same is owed here and cannot be done yet.
4. **The inner-call hand-off (§8.4) has no precedent in this codebase.** The
   log-chain path reuses a live-tested mechanism; the inner-call path is
   specified from first principles and its budget claim (+422 net) is projected
   from M4's measured donor numbers rather than measured directly.
5. **No real Deneb→Electra straddle fixture exists yet.** F6 is the most
   important test in Suite F and it needs data this repo does not have.
6. **`hash_tree_root(BeaconBlockHeader)` has never been measured in isolation.**
   It is implemented and tested for *correctness* (M4), but 004 §9.1 only ever
   projected its cost as part of a 900-budget line covering nine hashes. It is
   M8's largest single projected line (700 of 4,260). B5 measures it.
7. **The `historical_summaries` path (O-M8-3) is designed but not derived.** §4.5
   gives a composed depth of ≈43 from field counts; the exact gindex has not been
   generated with `get_generalized_index`, and the `mix_in_length` handling for
   the list root is described rather than specified.
8. **M8 cannot verify M4's bytecode** (TP-M8-7). The immutable `m4_app_id`
   prevents substitution *after* deployment; it proves nothing about what was
   deployed. This is a real hole that only deployment tooling can close, and only
   for someone who trusts the deployer.
9. **The 425/501 x402 pre-payment problem (§9.3) is flagged, not solved.**
10. **`conflict`'s fail-closed blast radius has not been reasoned about
    operationally.** §5.5 argues it is not cheaply reachable. It does not say
    what an operator actually does at 3 a.m. when it fires — there is no runbook,
    and `gov_clear_conflict` is a governance call that presupposes governance is
    reachable and awake.

---

## 17. Deferred optimisations and extensions (`O-M8-*`)

| id | what | value | cost | status |
|---|---|---|---|---|
| **O-M8-1** | **Paired fold.** `state_root` (index 2) and `receipts_root` (index 3) are siblings; compute `h = sha256(state_root ‖ receipts_root)` on-chain and do **one depth-8 fold of `h` at gindex 401** instead of two depth-9 folds. | **−933 budget** (`2×850` → `767 + 35`) and **−290 argument bytes**, taking HISTORICAL from 1,780 B to 1,490 B (§10.5) | one `sha256`, and the concatenation order is load-bearing (index 2 is the **left** child — reversed, it fails closed) | **Recommended, not v1-normative.** Should be implemented and measured in the same pass; promoted to normative if B1/B2 confirm the saving. |
| **O-M8-2** | **Anchor `transactions_root`** (gindex 813 at Deneb, 413 at Capella), `version = 2` record | Makes receipt **exclusion** meaningful, answering 007 §8.3: an exclusion walk in the transactions trie for index `i` proves `i >= tx_count`, and that trie is keyed identically (`rlp(index)`) so M5's existing machinery applies unchanged | +850 budget, +32 B/record (+**1.638 ALGO** ring MBR at N=128), +290 argument bytes | Deferred to v2. The `version` byte at offset 0 exists for this. |
| **O-M8-3** | **Archive mode** via `historical_summaries` | Removes the 8,192-slot horizon entirely | composed depth ≈ **43**, fold **3,672**, branch **1,376 B** ⇒ needs a two-transaction log-chain split (§4.5) | Deferred. §7.5's pinned tier is the cheaper answer for known-in-advance blocks. |
| **O-M8-4** | **Gloas support** | Future-proofing | Depth 11 EL branches push HISTORICAL over the 2,048 B cap (§10.5); needs the same two-transaction split as O-M8-3 | Deferred, and **explicitly not approved** (NG3, 004 §4.5) |
| **O-M8-5** | **Batch anchoring**: one call anchoring `k` consecutive blocks from one finalized header | Amortises the 700-budget `hash_tree_root(fin_header)` and the routing across `k` blocks | Each additional block still costs 3 folds (2,550) + a record + a box reference; the box-reference cap of 8/txn bounds `k` at ~6. Saving is ~15 %. | Deferred; the saving does not justify the interface complexity, and the arithmetic is recorded so it is not re-derived. |
| **O-M8-6** | **Drop `finality_root` from the record** (32 B) | −0.0128 ALGO/slot MBR (−1.638 ALGO at N=128) | Loses off-chain auditability of HISTORICAL anchors (§6.1) | **Rejected**, recorded because the MBR pressure makes it tempting. Auditability is worth 1.6 ALGO. |

---

## 18. File layout

```
contracts/state_anchor/                 # the directory already exists, empty
    __init__.py
    constants.py     # N* error codes, flags, record offsets, VERSION_1,
                     #   ATTEST_SELECTOR, ring/pin box-name prefixes
    forks.py         # the §3.3 two-dimensional table: box layout, append,
                     #   epoch->row lookup. Mirrors contracts/sync_committee/forks.py
    bridge.py        # §3 + §4: htr checks, N-CHUNK, N-INDEX, N-FORK,
                     #   the folds. Imports M3 merkle.py and M4 header.py.
    record.py        # §6.1: assemble/parse A; the ring residue; §5.4's
                     #   idempotence / equivocation / eviction decision
    box.py           # ring + pinned tier, ring_init cursor, MBR asserts
    handoff.py       # §8.3/§8.4/§8.7 -- THE FILE M6 AND M7 IMPORT.
                     #   ANCHOR_APP_ID lives here as a compile-time constant.
    anchor_app.py    # the ARC-4 contract of §8.2
    bench_app.py     # Suite B probes, mirroring contracts/*/bench_app.py

tests/state_anchor/
    test_bridge.py            # Suite A
    test_forks.py             # Suite F  (F6 = the two-row trap)
    test_historical.py        # Suite H
    test_security.py          # Suite S
    test_retention.py         # Suite R
    test_handoff_live.py      # S-APP + G1-M8 end-to-end, real submission
    test_budget.py            # Suite B -> bench/anchor_results.json

tests/fixtures/state_anchor/
    finality_update.json      # real beacon API LightClientFinalityUpdate
    block_25639768.json       # the beacon block containing the pinned EL block,
                              #   with execution branches generated by remerkleable
    straddle_deneb_electra.json   # F6
    gindices.json             # G4-M8's generated table

bench/
    anchor_bench.py
    anchor_results.json
```

**Nothing in `contracts/primitives/`, `contracts/mpt/`, `contracts/composer/` or
`contracts/receipt/` changes**, except the two integration sites named in §9.1
and §9.2, both of which are additive (a new subroutine and a new mode) rather
than modifications to tested paths.

---

## 19. Implementer checklist (normative MUSTs)

1. **MUST** import `hash_tree_root_beacon_block_header`, `header_slot`, `le64`
   and `be64_from_le` from `contracts/sync_committee/header.py`. **MUST NOT**
   reimplement the 112-byte header layout (§3.6).
2. **MUST** derive `block_number`'s 32-byte leaf chunk on-chain from a `uint64`
   argument (N-CHUNK, §3.5). **MUST NOT** accept a 32-byte chunk.
3. **MUST** derive the `block_roots` vector index on-chain from
   `header_slot(target_header)` (N-INDEX, §4.3). **MUST NOT** accept an index
   parameter. *Any implementation that does is a critical defect.*
4. **MUST** select `g_block_roots_base` by `epoch(fin_slot)` and the three
   execution gindices by `epoch(t_slot)`, as two separate lookups (N-FORK, §3.4).
5. **MUST** read `fin_slot`/`fin_root`/`fin_state_root` from the app whose id
   equals the immutable `m4` global, asserting the match (`N4`, §8.2). `m4_app_id`
   **MUST** be write-once at create.
6. **MUST** refuse a zero `fin_root` (`N5`, §11 S7).
7. **MUST NOT** read M4's `att_slot` or `att_state_root` anywhere (§5.2).
8. **MUST** make `ANCHOR_APP_ID` a compile-time constant or create-time-immutable
   global in every consumer (TP-M8-4, §8.3). *Any implementation that makes it
   caller-influenceable is a critical defect.*
9. **MUST** make `want_block_number` a mandatory parameter of
   `anchor_from_group` and `anchor_by_inner_call`, with no overload omitting it
   (§8.3, following M6 §6.6 and M7 §5.3).
10. **MUST** exclude `anchored_round` from the §5.4 idempotence comparison
    (§11 S15). Including it turns a normal relayer race into an equivocation
    latch.
11. **MUST NOT** clear `FLAG_REVOKED` on a same-block-number rewrite; only
    eviction by a different block number clears the box (§7.6, §11 S19).
12. **MUST** use M3's *asserting* wrapper, never the bare fold, and **MUST** let
    M3 check branch length against the gindex's depth (`N9`, M3 §7.6, §12.6).
13. **MUST** embed only the prefix of M3's `zero_hash` table that M8 actually
    needs (003 §7.4, §10.8). The full 64-entry table is 2,048 B of an 8,192 B cap.
14. **MUST** keep `N12` (absent) and `N13` (revoked) as distinct codes, all the
    way out to the HTTP response (TP-M8-6, §7.6, §9.3).
15. **MUST** make `ring_n` a power of two, write-once, and **MUST NOT** expose a
    resize (§6.2).
16. **MUST** refund `unpin` only to the payer address stored in the record, never
    to the sender and never to a parameter (§7.5, §11 S18).
17. **MUST** fail `attest`, `anchor_*` and `pin` closed while `conflict != 0`
    (`N22`, §5.5).
18. **MUST** generate the deployed fork table with `get_generalized_index`
    against a pinned spec checkout and gate it in CI (G4-M8). **MUST NOT** copy
    any gindex from §3.2 of this document (003 §4.5).
19. **MUST** size donor counts from a real `simulate`, then confirm with a real
    `send_transactions` — never `simulate` alone (M5 §16.3, M6 §7.6).
20. **MUST** record every measured number in `bench/anchor_results.json` and
    label every remaining estimate as projected, replacing §10's table rather
    than annotating it.
21. **SHOULD** implement and measure O-M8-1 (the paired fold) in the same pass,
    and promote it to normative if the saving confirms (§10.5, §17).
22. **MUST NOT** add a global maturity requirement to `attest`; maturity is
    `anchor_assert_mature`'s, and it is the consumer's choice (§5.6). This is the
    one consumer-side check M8 deliberately does not force, and the asymmetry
    with rule 9 is intentional.

---

## Appendix A — deriving the generalized indices

The script G4-M8 requires, in shape. It must run against a pinned
`consensus-specs` checkout and its output must be diffed against the deployed
fork table in CI.

```python
# tests/fixtures/state_anchor/generate_gindices.py
from eth2spec.deneb  import mainnet as deneb
from eth2spec.electra import mainnet as electra
from eth2spec.fulu    import mainnet as fulu

def rows(spec, name):
    gi = spec.get_generalized_index
    B, P, S = spec.BeaconBlockBody, spec.ExecutionPayload, spec.BeaconState
    return {
        "fork": name,
        "g_state_root":       gi(B, "execution_payload", "state_root"),
        "g_receipts_root":    gi(B, "execution_payload", "receipts_root"),
        "g_block_number":     gi(B, "execution_payload", "block_number"),
        "g_block_roots_base": gi(S, "block_roots"),
        # cross-checks against values the spec itself publishes:
        "_check_block_hash":  gi(B, "execution_payload", "block_hash"),
        "_check_exec_payload": gi(B, "execution_payload"),
    }
```

Required assertions:

- `_check_exec_payload == 25` for every fork Bellatrix…Fulu.
- `_check_block_hash == spec.EXECUTION_BLOCK_HASH_GINDEX` where the spec defines
  it (**412** at Capella, **812** at Deneb) — two independent published anchors
  at two different depths, which is what makes §3.2's composition trustworthy.
- Branch depth `= floor(log2(gindex))` matches the fixture branch lengths, so a
  fixture and a table can never silently disagree.

## Appendix B — fixture derivation

**The anchor fixture must be the beacon block containing Ethereum mainnet block
25,639,768**, so that Suite A's assertions are byte comparisons against
`tests/fixtures/rlp/nodes.json`'s already-pinned
`0x6490277f…099e710b` (receipts) and `0xde97a834…d2c53329` (state) — the same
values M2, M5, M6 and M7 have all been tested against, and the same block M7's
live mainnet run used against app id 3664247481.

Derivation (all from public endpoints, all pinned into the repo as JSON):

1. `GET /eth/v1/beacon/light_client/finality_update` → the finalized
   `BeaconBlockHeader` (112 B SSZ), plus the update M4 needs to reach it.
2. Find the beacon slot whose `execution_payload.block_number == 25639768`
   (`GET /eth/v2/beacon/blocks/{slot}`), and keep the full block body.
3. Compute the three execution branches with `remerkleable`/pyspec against the
   gindices from Appendix A — **not** by hand, and **not** copied from §3.2.
4. For HISTORICAL fixtures, additionally fetch a *later* finalized header and
   compute the `block_roots` branch against its `state_root`, using
   `get_generalized_index(BeaconState, 'block_roots')` composed with
   `t_slot % 8192`.
5. For F6, repeat steps 1–4 with `fin_slot` in Electra and `t_slot` in Deneb.

Every branch must be independently verified off-chain (`is_valid_merkle_branch`
from the spec) before it is committed, following M3 §2.10's discipline of
validating against the spec's own implementation rather than against this
project's.

---

*End of 008. This document is a design, not an implementation. No contract code
was written or modified in the pass that produced it, and `ROADMAP.md` was
deliberately left untouched for the human review step.*
