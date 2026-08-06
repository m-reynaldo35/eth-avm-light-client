# 009 — M9: Off-chain relayer / client

**Status**: Design drafted, awaiting human review.
**Depends on**: M4, M6, M7, M8 — all four now **implemented, live-proven against
real mainnet data, and committed** (`git log`: `028e18e`, `1148ae4`, `86a5e87`,
`35f64e6`, `83b4fb8`). Their ABIs are frozen by their *code*, not by their design
docs, and this document targets the code.
**Consumed by**: `service/x402_endpoint/` (M7's live x402 service), M10
(deployment & box-schema tooling), M11 (real-data test harness & CI), and a human
operator.
**Design-time convention, inherited**: every number below is labelled
**measured** (a real `simulate`/`send` response already in this repo, cited to its
file) or **projected** (an estimate this document owns, which an implementation
pass must replace with a real response). `ARCHITECTURE.md`'s rule applies
unchanged.

---

## 0. The question, stated first

M9 is the first module in this project whose implementation **already exists**.

Not in the sense that a previous pass wrote it deliberately — in the sense that
eight separate files, written for eight separate reasons across five sessions,
between them already fetch real Ethereum data from real public endpoints, decode
it into the exact byte shapes M4/M6/M7/M8 accept, chunk it under the real
argument and box caps, pool opcode budget across a real atomic group, and submit
it for real. Every one of those things has been done against live mainnet data
and confirmed by a real, non-simulated Algorand submission. None of it is in one
place, none of it is reusable, and two of the eight files are inside a `tests/`
tree that a deployable relayer cannot import.

So the scoping question is not "how do we build a relayer". It is:

> **Is M9 a refactor of the code this project already has, a fresh
> implementation, or some of both — and where exactly does the line fall?**

Every prior design doc in this repo answers its own analogous question rather
than ignoring it (M5 §7.3 "args vs. boxes, decided, with the arithmetic"; M6 §8
exclusion; M7 §4 the oversized leaf; M8 §7 retention). This one is M9's.

**The answer, stated up front, and defended in §2:**

> **M9 is a genuine refactor for four of its six concerns, a rewrite for one, and
> new construction for one.** Concretely: **promote** the two RPC clients, the
> receipts-trie reconstructor and the two SSZ merkleizers (~1,660 lines that
> already work) into a new `relayer/` package; **rewrite** `m7_relayer.py`'s
> hand-rolled group construction against a new generic group planner; **build
> from nothing** an `eth_getProof` client for M6 and the group planner itself,
> which is the only genuinely hard new engineering in this module.
>
> **M9 does not subsume `service/x402_endpoint/`.** That directory is a
> separately-deployed artifact (Vercel serverless, `vercel.json`, its own
> `requirements.txt` pulling FastAPI and `x402-avm`, its own `.env.example`, its
> own funded hot mnemonic). The dependency is **inverted, not merged**: after
> M9, the service imports `relayer` and shrinks to `main.py` plus config. §2.3
> gives the four reasons.

**Three things this document has to get right**, in order of how much damage
getting them wrong does:

1. **The box-reference arithmetic** (§7.4). This is the single most valuable
   thing M9 can contribute, because the existing code gets it wrong *right now*,
   in a way that has already deselected four live tests twice with two different
   error numbers. §7.4 derives the closed form, explains both observed failures
   exactly, and shows the current 2-transaction `submit_update` group is
   **structurally incapable** of carrying the references a worst-case real
   committee needs.
2. **Refusing to unify the four ABIs** (§8.3). The four target contracts differ
   in argument encoding, budget-donation convention, box requirements,
   statefulness and result envelope. A forced-uniform `submit(proof)` would hide
   exactly the things an operator has to reason about.
3. **The trust posture** (§1.3). M9 is **untrusted**. Nothing it does may be
   load-bearing for soundness. Where it *is* load-bearing for something (liveness,
   fee cost, or an operator's mental model), this document says so explicitly.

---

## 1. Scope, non-goals, trust preconditions

### 1.1 In scope

1. **Fetching real chain data.** Execution-layer JSON-RPC (`eth_getProof`,
   `eth_getBlockReceipts`, `eth_getBlockByNumber`) and consensus-layer beacon-API
   light-client endpoints (`bootstrap`, `updates`, `finality_update`), both over
   a retried endpoint pool.
2. **Assembling proofs.** Receipts-trie reconstruction (M7), account/storage
   proof segmentation (M6), SSZ Merkle branch construction for the beacon→
   execution bridge and the `block_roots` fold (M8), sync-committee key
   decompression and committee-root merkleization (M4).
3. **Assembling atomic groups.** One reusable planner that sizes opcode-budget
   donation, box references, argument chunking and transaction count against the
   real, measured AVM caps — replacing four divergent copy-pasted implementations.
4. **Submitting and interpreting.** `simulate` first, size from the real consumed
   figure, then a real `send_transactions`; decode the resulting log envelopes
   (three different envelope shapes, §8.5) into typed results; classify failures
   as retryable, fatal, or page-a-human.
5. **A CLI** over the same library, for operators and for M10/M11.

### 1.2 Non-goals (explicit)

- **No new on-chain contract.** M9 compiles nothing and deploys nothing to
  mainnet. It *may* deploy the existing `DonorIssuer`/`DonorCallee` pair
  (`contracts/sync_committee/bench_app.py`) on a network where they are absent,
  because they are infrastructure, not verification logic — but the source is
  imported, never rewritten (`tests/state_anchor/conftest.py::deploy_donor_pair`
  already establishes this exact rule).
- **No deployment tooling.** Creating and funding M4/M6/M7/M8 apps, choosing and
  funding M8's ring `N`, seeding fork tables, and pinning M4's approval-program
  hash are **M10's** (008 §15.4). M9 *reads* deployed app ids from config.
- **No T3/ZK proving.** 007 §8.2 says "M9 becomes a proving service"; this
  document **defers that** (§16, `O-M9-1`) and scopes v1 to T1/T2, on the strength
  of 007 revision 8's real population sample: **97.5% of 94,667 real receipts
  across 300 real blocks are T1/T2; only 2.2% need any ZK tier.** M9 v1 must
  *classify* a T3 receipt correctly and refuse it cleanly (007 §8.2's "must never
  swallow `R_INCOMPLETE`"), not prove it. The proving queue, the Go runtime and
  the ≥64 GB host are a separate deliverable.
- **No consensus-layer p2p.** No gossip, no `is_better_update` ranking, no fork
  choice (004 §1.2 already assigns these to M9 but they are not needed to drive
  the deployed contracts; see §16, `O-M9-3`).
- **No key management beyond a signer interface.** M9 takes an
  `algosdk`-compatible signer or none at all. Custody is the operator's.
- **No Solidity ABI decoding.** M6 takes a final 32-byte slot. Mapping-key
  derivation (`keccak256(pad32(holder) ‖ pad32(k))`) is a documented three-line
  helper (006 §13.3), not a Solidity front end.

### 1.3 Trust preconditions

**M9 is untrusted, and this is the whole point of M1–M8.** Every claim M9 makes
is re-derived on-chain from data the contract itself binds:

| M9 supplies | What stops M9 lying about it |
|---|---|
| Proof nodes | M5 `keccak256(node) == W.expected` at every hop, and the child index is derived from the key on-chain (005 §5, the security fix this project exists for) |
| `receipts_root` for a walk | M8's `mpt7_result_against_anchor` derives it from the anchor record; **there is no `receipts_root` parameter** (`contracts/state_anchor/handoff.py`) |
| Merkle branches | M3's asserting fold against a gindex from the on-chain fork table (008 §12.6, `N9`) |
| Uncompressed BLS points | M1's recompress-and-compare trust boundary (`g1_bind`), 001 §4.4 |
| `mode` (M4 direct/complement) | 004 §5.5: a wrong hint only wastes M9's own budget |
| DIRECT vs HISTORICAL (M8) | 008 §9.4: pure optimisation, no safety content |
| Chunk sizes, donor counts, box refs | Fee and liveness only; a wrong value fails the group, it cannot make a false statement true |

**Three places where M9 *is* load-bearing, stated plainly:**

1. **Liveness.** If M9 stops, the anchor goes stale and nothing new is provable.
   No safety consequence; a total availability one.
2. **Lying by omission.** M9 chooses *which* block to anchor and *which* receipt
   to prove. It cannot forge an answer, but it can decline to produce one. §11.
3. **Wall-clock sanity** (004 §12.4 item 1). M4 has no clock and cannot check
   `current_slot >= signature_slot`. M9 must not forward an update it knows to be
   from the future. This is the one genuinely *normative* soundness-adjacent duty
   M9 carries, and §6.1 makes it a hard assert, not a warning.

---

## 2. What already exists — the inventory, file by file

### 2.1 The inventory

| Existing file | Lines | What it really is | Live-proven? | M9 verdict |
|---|---:|---|---|---|
| `service/x402_endpoint/eth_rpc.py` | 43 | Retried public-RPC pool, execution layer. `get_block_receipts` / `get_block_header` only. | Yes — real mainnet USDC flow through the x402 service | **Promote + extend** |
| `service/x402_endpoint/eth_beacon_rpc.py` | 461 | Beacon light-client REST client **plus** M4 argument transforms (`SubmitUpdateArgs`, `BootstrapArgs`, `install_chunks`) | Yes — `tests/sync_committee/test_live_e2e_finality.py`, 4/4 | **Promote + split + fix** |
| `service/x402_endpoint/trie_proof.py` | 119 | Real receipts-trie rebuild + root-to-leaf path, any block/tx | Yes — M7 mainnet app `3664247481` | **Promote verbatim** |
| `service/x402_endpoint/m7_relayer.py` | 181 | Hand-built T1/T2 transaction lists for one deployed `Mpt7ReceiptApp` | Yes — rounds 7, 10, 15 | **Rewrite against §7** |
| `service/x402_endpoint/main.py` | 116 | FastAPI + x402 middleware + one priced route | Yes | **Keep, invert dependency** |
| `tests/state_anchor/real_ssz.py` | 140 | Real `ExecutionPayload` SSZ tree + deep composed branches | Yes — G1-M8 | **Promote** |
| `tests/state_anchor/real_beacon_state.py` | 938 | Full 38-field Fulu `BeaconState` merkleizer (~2.33M real validators in ~24 s), `block_roots` fold, `BeaconBlockBody` fold | Yes — three real `anchor_historical` submissions | **Promote** |
| `tests/*/conftest.py` + 4 live test files | ~1,400 | Group assembly: donor issuance, box padding, chunking, simulate-then-send, log parsing | Yes, repeatedly | **Generalize — the new work** |
| — | 0 | **An `eth_getProof` client** | — | **Does not exist** |

`grep -rn "eth_getProof" --include=*.py` returns exactly one live hit outside
docs: `tests/fixtures/spike-reference/pull_eth_data.py`, a frozen one-shot spike
script the scaffold commit explicitly marks read-only reference. **M6 — the only
module with a fully implemented, live-submitted, under-budget on-chain
composite — has no off-chain client at all.** That is the largest single gap in
this project's real usability today, and it is invisible from the ROADMAP because
M6's own row is green.

### 2.2 The verdict, and why it is not "rewrite it all"

Rewriting would discard ~1,660 lines of code whose *value is not the code*, it is
the dozen real, expensive findings baked into it: the exact JSON shapes Capella+
light-client responses use; that live `finality_branch` has **7** entries and not
the vendored vectors' 6; that `optimistic_update` structurally cannot feed
`submit_update`; the AVM G2 limb order being the reverse of every reference
serializer (004 §12.4 item 2); that a plain block endpoint carries no
`execution_branch` for an arbitrary historical slot; that the real Fulu
`BeaconState` has **38** fields. Each of those cost a live session to learn. A
rewrite re-learns them.

Rewriting *is* right for `m7_relayer.py`, and only for it, because its value **is**
the code and the code is wrong in shape: it hardcodes `N_FILLERS = 8`, raises
`M7Error("MODE_NEXT splitting not implemented in this relayer yet")` for any T1
node set over 2,000 bytes, and inlines transaction construction in a way that
cannot accept M8's `attest` transaction without editing the function body — which
is exactly the change 008 §9.3 says is required.

### 2.3 Why `service/x402_endpoint/` is not subsumed

Four reasons, in order of weight:

1. **Different artifact, different lifecycle.** `vercel.json` pins
   `main.py` with `maxDuration: 60`; `.vercelignore` and `.secrets/` scope the
   directory to one serverless deployment. M9 is a library plus a CLI that must
   run on an operator's laptop, in CI, and inside M10's deploy scripts.
2. **Different dependency set.** The service needs `fastapi`, `uvicorn`,
   `x402-avm[fastapi,avm]`. A relayer library must not drag an HTTP framework and
   a payments SDK into `import relayer`.
3. **Different trust posture.** The service holds a funded hot mnemonic
   (`RELAYER_MNEMONIC`) and takes payment. M9 must be usable with **no signer at
   all** — `--dry-run` builds and simulates a group without ever holding a key,
   which is how M11 will run it in CI and how an auditor reproduces a claim.
4. **The 60-second wall.** An M4 committee install is 64 real `install_chunk`
   submissions (measured, `test_live_e2e_finality.py`); it cannot run inside a
   Vercel function. Any design that puts the relayer *inside* the service is
   structurally limited to the one operation that happens to be fast.

**But the current arrangement is genuinely wrong and M9 fixes it.**
`service/x402_endpoint/eth_beacon_rpc.py` — a module in a *deployed service* —
does this at line 83:

```python
from tests.bls.test_codec import _g1_uncompressed, _g2_uncompressed
from tests.sync_committee import reference as ref
```

A production module importing a pytest test module. The helpers are pure and
correct; their *location* is the defect. Promoting them to `relayer/codec/`
resolves it, and is on its own sufficient justification for the move.

**After M9, `service/x402_endpoint/` contains:** `main.py`, `.env.example`,
`vercel.json`, `.vercelignore`, `requirements.txt` (gaining `-e ../..` or the
published package), and nothing else. The four `.py` modules move.

### 2.4 Three real defects in the existing code that this consolidation fixes

These are not hypotheticals; each is verifiable in the tree today.

**D1 — `install_chunks`' default is unusable against the real ABI.**
`eth_beacon_rpc.py:425` defaults `chunk_size=64` "to match `KEYS_PER_BOX`". At 64
members that is a 3,072-byte `compressed` blob and a 6,144-byte `uncompressed`
blob — both far past the **2,048-byte total app-argument cap** measured in M5
§7.2. The real live install
(`test_live_e2e_finality.py:155`) uses `CHUNK_SIZE = 8` and **does not call
`install_chunks` at all**, hand-rolling the loop instead; the only caller of
`install_chunks` in the repo is `test_live_beacon_fetch.py:157`, which never
submits. So the one packaged chunking helper this project has is a helper nobody
can use. It also corrects 004 §12.4 item 4's estimate: the real figure is **8
members per transaction, not ~12**.

**D2 — `m7_relayer.py` cannot split a T1 node set.** `prove_receipt` raises
rather than emitting `MODE_NEXT` continuations above 2,000 bytes, even though
`Mpt7ReceiptApp` implements `MODE_NEXT` and it was proven live at round 10. Any
receipt whose branch nodes sum past that — common for a deep receipts trie — is
rejected by the client, not by the chain.

**D3 — `_choose_mode_and_boxes` uses the wrong cost model.** It picks the mode
with *fewer boxes*, then declares one reference per box. That is the direct cause
of the recurring, live-data-dependent `box read budget (N) exceeded` failures
that have deselected M4's live tests twice, with two different `N`. §7.4 derives
the correct model, and explains both observed numbers exactly.

---

## 3. A stale premise in the plan's own M9 description, corrected

The plan (`peppy-cuddling-snail.md`) describes M9 as chunking "to the 42-point MSM
boundary and the 16-outer/256-inner group ceiling (both sized in RESULTS.md)".
The second half is correct and load-bearing. **The first half is stale**, and an
implementation pass that took it literally would build the wrong thing.

The 42-point boundary is real (`RESULTS.md` §2: 42 × 96 B = 4,032 B fits the
4,096-byte value cap; 43 does not) but **the shipped M4 does not use
`ec_multi_scalar_mul` on any path M9 drives**:

- Per-update aggregation is the fused bitfield loop, `contracts/sync_committee/
  bitfield.py`, box-gather + `ec_add`, **measured 217/point** (004 §2.3's
  implementer note: "M4 does not actually use `g1_sum_blob` on the per-update
  path").
- The install path accumulates a `running_sum` with `ec_add` inside
  `install_process_chunk` (`contracts/sync_committee/install.py`), verified
  against the committed `aggregate_pubkey` at `install_finalize`.
- 004 §2.3 measured the chain at 42 points as **10,182** vs MSM's **10,611** —
  the chain wins, and M1 §6.4's measure-then-branch rule keeps it as the default.

**The real chunk boundaries M9 must respect** — none of which is 42:

| Boundary | Real value | Source |
|---|---|---|
| App arguments, total bytes per txn | **2,048** | M5 §7.2, literal protocol error |
| App arguments, count per txn | **16** | M5 §7.2 |
| M4 `install_chunk` members per txn | **8** (8 × 144 B = 1,152 B) | `test_live_e2e_finality.py:155`, 64 real submissions |
| M6 `MODE_A_INIT` node bytes | **1,943** (9 node args) | 006 §6.3 |
| M6 other modes | **2,019** (11 node args) | 006 §6.3 |
| M7 T1/T2 leaf boundary | **1,942** | `m7_relayer.py:25` (`ARG_BUDGET`), 007 §3.1 |
| M7 T2 box-write chunk | **1,900** | `m7_relayer.py:131`, proven live at round 15 |
| Top-level txns per group | **16** | `RESULTS.md` §4 |
| Inner txns per group (shared) | **256** | `RESULTS.md` §4 |
| Net usable pooled budget | **185,792** | 004 §2.4 (190,400 − 256 × 18) |
| Box refs per txn | **8** | 004 §16.2, literal protocol error |
| Pooled box budget per ref | **2,048 B** | 004 §16.2 |

The 42-point boundary keeps exactly one relevance to M9: it is why a 512-member
committee cannot be delivered in one call at all, which is why the install session
exists. It is not a chunking parameter M9 computes with.

> **Correction for `ROADMAP.md`:** M9's row inherits "chunks to the 42-point MSM
> boundary" from the plan. That should be struck; §3's table is the real list.

---

## 4. Architecture

### 4.1 Where it lives

`relayer/`, the directory the scaffold commit (`51dd033`) created and left empty
with a `.gitkeep`. Imported as `relayer.*`, matching this repo's existing
flat-top-level-package convention (`contracts.mpt.walk`, `tests.sync_committee.
reference`).

### 4.2 Layers

```
                    ┌──────────────────────────────────────────┐
  operator ───────▶ │ relayer/cli.py        (argparse, --json)  │
                    └────────────────────┬─────────────────────┘
  x402 service ────▶┌────────────────────▼─────────────────────┐
  M10 deploy   ────▶│ relayer/client.py     EthAvmClient        │  facade: 4 verbs
  M11 CI       ────▶└────────────────────┬─────────────────────┘
                    ┌────────────────────▼─────────────────────┐
                    │ relayer/drivers/  m4_ m6_ m7_ m8_         │  ABI-specific, NOT unified (§8.3)
                    └───────┬───────────────────────┬──────────┘
            ┌───────────────▼──────────┐  ┌─────────▼──────────────┐
            │ relayer/proofs/  ssz/    │  │ relayer/group/          │  THE new work (§7)
            │   codec/                 │  │   budget boxes planner  │
            └───────────────┬──────────┘  └─────────┬──────────────┘
            ┌───────────────▼──────────┐  ┌─────────▼──────────────┐
            │ relayer/sources/  pool   │  │ algosdk (algod)         │
            │  eth_rpc  beacon  cache  │  └────────────────────────┘
            └──────────────────────────┘
```

### 4.3 Dependency rules (normative)

1. `relayer/` **must not** import `tests.*` (fixes D-2.3), `algopy`, `fastapi`,
   `x402`, or `pytest`.
2. `relayer/sources/`, `relayer/codec/`, `relayer/ssz/`, `relayer/proofs/` **must
   not** import `algosdk`. They are pure: bytes in, bytes out. This is what makes
   the whole proof-assembly half testable offline against pinned fixtures, which
   is M11's `ci-offline.yml` requirement.
3. Only `relayer/group/`, `relayer/drivers/`, `relayer/client.py` and
   `relayer/cli.py` touch `algosdk` or the network's algod.
4. `remerkleable` stays a **dev/test** dependency, used to cross-validate
   `relayer/ssz/` (as `real_beacon_state.py` already does, bit-for-bit at small
   scale), never a runtime one — constructing millions of View objects for a real
   `BeaconState` was measured to be needlessly slow and was already rejected.
5. Runtime deps: `py-algorand-sdk`, `rlp`, `pycryptodome`, `py_ecc`. Nothing else.

---

## 5. The data-sources layer

### 5.1 The pool primitive

`eth_rpc.py::rpc` and `eth_beacon_rpc.py::_get_json` are the *same* retry shape
written twice (the latter's docstring says so). `relayer/sources/pool.py` extracts
it once:

```python
class EndpointPool:
    def __init__(self, urls, *, headers, tries=4, timeout=20,
                 inter_endpoint_sleep=0.15, inter_pass_sleep=1.0): ...
    def request(self, make_request, accept) -> Any: ...
        # walks the whole pool once per attempt; accumulates every real error;
        # raises PoolExhausted(path, attempts, errors) with ALL of them.
```

Preserved behaviours, each of which was learned the hard way and must not be
lost: the `User-Agent: curl/8.0` header (several public endpoints 403 urllib's
default); accumulating errors rather than swallowing them; treating a JSON-RPC
response with `result: null` as a failure and moving on, not as success.

**Endpoint pools are config, with the current live-proven lists as defaults.**
Execution: `ethereum-rpc.publicnode.com`, `eth.drpc.org`, `eth.merkle.io`,
`1rpc.io/eth`, `eth-mainnet.public.blastapi.io`. Consensus:
`unstable.mainnet.beacon-api.nimbus.team`,
`testing.mainnet.beacon-api.nimbus.team`, `lodestar-mainnet.chainsafe.io`,
`www.lightclientdata.org` — with `eth_beacon_rpc.py`'s recorded observation kept
in a comment: **Nimbus's two answered every request** during the sessions that
built M4's and M8's live tests; Lodestar 503'd at least once and is kept because
"a 503 today is not a 503 tomorrow".

### 5.2 Execution layer — `relayer/sources/eth_rpc.py`

Promoted, plus the methods M9 needs that do not exist yet:

| Method | Consumer | Status |
|---|---|---|
| `eth_getBlockByNumber` | M7, M8 (EL fields to anchor) | exists |
| `eth_getBlockReceipts` | M7 (trie rebuild) | exists |
| **`eth_getProof(address, [slot], block)`** | **M6** | **new** |
| `eth_getTransactionReceipt` | M7 fast path / `tx_index` lookup | new, trivial |

`eth_getProof`'s response shape is already pinned in this repo — `tests/fixtures/
spike-reference/eth_data.json`, pulled by `pull_eth_data.py` for USDT/Binance-8 —
so the decoder can be written and unit-tested offline before it ever runs live,
and the live client can be differentially tested against that exact fixture.

### 5.3 Consensus layer — `relayer/sources/beacon.py`

Promoted from `eth_beacon_rpc.py`, **split three ways** along the dependency rule
in §4.3:

- `relayer/sources/beacon.py` — the four `fetch_*` calls, plus `/eth/v1/config/
  spec`, `/eth/v1/beacon/genesis`, `/eth/v2/beacon/blocks/{slot}` and
  `/eth/v2/debug/beacon/states/{slot}` (the last two are what M8's HISTORICAL
  fixture needs and are currently only reachable from `test_live_historical.py`).
- `relayer/codec/` — `_decode_header`, `_decode_branch`,
  `_g1_compressed_to_avm`, `_g2_compressed_to_avm`, `_committee_root`, and the
  `_g1_uncompressed`/`_g2_uncompressed` helpers currently imported **from
  `tests.bls.test_codec`**.
- `relayer/drivers/m4_sync_committee.py` — `SubmitUpdateArgs`, `BootstrapArgs`,
  `transform_*`, and a **fixed** `install_chunks` (D1).

Two invariants carried forward verbatim because they are correctness properties,
not style:

- **Never hardcode a branch depth.** Concatenate whatever nodes the response
  actually contains; the deployed fork table is what must carry the right
  gindex/depth. Live "fulu" `finality_branch` has 7 entries where the Altair
  vendored vectors have 6.
- **`optimistic_update` cannot produce `submit_update` args.** It carries no
  `finalized_header`/`finality_branch`; `submit_update` always merkle-checks a
  finality leaf, including the zero-leaf case. `transform_optimistic_update`
  returns decoded fields only, and M9's API must never accept it where a
  `SubmitUpdateArgs` is expected.

### 5.4 What the beacon API will and will not serve

Recorded here because it *constrains M9's feature set*, not merely its
implementation:

| Endpoint | Real behaviour observed | Consequence for M9 |
|---|---|---|
| `light_client/bootstrap/{root}` | **404 `"LC bootstrap unavailable"`** on both reachable Nimbus endpoints for an arbitrary ~20 h-old header root (M8 §17 gap-closing pass) | M9 **cannot** bootstrap from an arbitrary root on demand. Bootstrap roots must come from the small retained checkpoint set, or from a checkpoint-sync source the operator names. §6.1. |
| `light_client/updates?start_period=` | Returned real archived headers straddling a **~15-month-old** fork boundary (better retention than expected) | Period-update walking back over many periods is viable. |
| `/eth/v2/debug/beacon/states/{slot}` | **404** near a ~15-month-old boundary; **~956 MB** JSON when it does answer, for current slots | HISTORICAL anchoring works for recent slots only; the full-state path needs a streaming/caching policy (§5.5), not a naive `json.load`. |
| `/eth/v2/beacon/blocks/{slot}` | No precomputed `execution_branch` for an arbitrary slot — only light-client responses carry one | M9 must build the depth-4 `BeaconBlockBody` fold itself. Already implemented in `real_beacon_state.py`; §6.4 promotes it. |

### 5.5 Caching

`tests/state_anchor/.cache/` already exists for exactly this (added to
`.gitignore` in `83b4fb8`) because a ~956 MB `BeaconState` fetch is not something
to repeat. M9 formalises it as `relayer/sources/cache.py`: a content-addressed
on-disk cache keyed by `(endpoint_kind, path, slot_or_block)`, with
`--no-cache`/`--cache-dir` on the CLI. Immutable-by-construction responses
(a state at a finalized slot, a block's receipts) are cached indefinitely;
`finality_update` is never cached.

---

## 6. The proof-assembly layer

### 6.1 M4 — committee and update

**Bootstrap.** `transform_bootstrap` exists and works. What M9 adds is the
**checkpoint policy** §5.4 forces: `bootstrap(root)` may 404, so M9 takes the
trusted root from config (`--trusted-block-root`, or a checkpoint-sync URL) and
**fails loudly** rather than silently substituting a different, fetchable root.
Substituting the root is precisely the thing the whole bootstrap ceremony exists
to prevent an unattended process from doing.

**Install.** 512 members, `CHUNK_SIZE = 8` (§3), 64 `install_chunk` submissions,
each its own group, each `[DonorIssuer(40), install_chunk]` — measured
`CHUNK_DONORS = 40` against a "≥ ~26 measured minimum". Preceded by the
box-opening group (§7.4) and followed by `install_finalize` with 15 donors.
**Resumable**: §9.1.

**Update.** `transform_finality_update`, plus three checks M9 owns:

1. **Wall clock** (004 §12.4 item 1, and §1.3 above): assert
   `signature_slot <= slot_now(genesis_time) + 1`. Refuse to forward a
   future-dated update. Hard assert.
2. **Monotonicity**: skip the submission entirely if
   `finalized_slot <= on-chain fin_slot` — M4 rejects it, and paying ~0.15 ALGO
   to be rejected is avoidable.
3. **Mode and box plan from the real bitfield** — §7.4, which is where this gets
   interesting.

**Committee rollover.** A period boundary needs a `next_sync_committee` proof,
which only `/light_client/updates` carries — `finality_update` never does
(`transform_finality_update` sets the zero/empty sentinel deliberately). M9's
update loop must therefore poll `updates` at period boundaries and
`finality_update` otherwise. 004 §10.3 (period crossed mid-session) is the edge
case; §10.4 here restates M9's half.

### 6.2 M6 — `eth_getProof`, the part that does not exist

New module, `relayer/proofs/account.py`. Given `(address, slot, block)`:

1. `eth_getProof` → `accountProof[]`, `storageProof[0].proof[]`, plus the
   `balance`/`nonce`/`codeHash`/`storageHash` M9 uses **only to cross-check its
   own understanding**, never as an input the contract trusts.
2. Segment in **path order** under 006 §6.3's caps — and the caps genuinely
   differ per mode: `MODE_A_INIT` gets **1,943 B / 9 node args**, every other mode
   **2,019 B / 11**. 006 §7.1's 13-byte finding means "2,048 minus a round number"
   produces a different and sometimes invalid split; the packer must use the real
   fixed-overhead figures (105 B and 29 B).
3. Emit `[A_INIT, A_NEXT…, B_INIT, B_NEXT…]` with `prev_gi` chained to the actual
   group index of the producing transaction — **not** `group_index - 1`, since
   donor/filler transactions may sit between segments (`mpt6_state_from_prev`
   accepts any earlier index).
4. Handle the four terminal shapes without phase B: `C_ABSENT_ACCOUNT` and
   `C_ABSENT_SLOT_EMPTY_TRIE` need **zero** phase-B segments (006 §6.4). Emitting
   them anyway would produce a group that fails on a correct chain state.
5. Mapping-key helper: `slot = keccak256(pad32(holder) ‖ pad32(k))`, with the
   repo's own pinned example (`0x0be16d71…5f36` = Binance-8 in USDT's `balances`
   at declaration slot 2) as its doctest.

Reference target: the real 5-transaction USDT/Binance-8 group in 006 §6.5 —
1,596 / 1,596 / 540 node bytes across three phase-A segments, 15 self-issued
donors on segment 0, **measured 12,202** total. M9's packer, run on the same
fixture, must reproduce that segmentation exactly. That is G3-M9 (§14).

### 6.3 M7 — receipts trie and the tier classifier

`trie_proof.py` promotes verbatim to `relayer/proofs/receipts_trie.py`. New
alongside it, `relayer/proofs/classify.py`:

```python
Tier = Literal["T1", "T2", "T3_UNSUPPORTED"]

def classify(leaf: bytes, logs: list[bytes]) -> Tier:
    if len(leaf) <= 1942:   return "T1"          # ARG_BUDGET, 007 §3.1
    if len(leaf) <= 4096:   return "T2"          # AVM value cap
    return "T3_UNSUPPORTED"
```

007 §8.2 / revision 3's ZK-B9 is explicit that a T3 **tier** is a pair
`(N, LOGMAX)` and that `max(len(encoded log_i))` matters as much as `leaf_len` —
two real receipts (tx 73, tx 6) sit inside a tier's leaf bound and outside its log
bound, and tx 73's leaf is *smaller* than tx 76's while needing a larger tier.
Since v1 does not prove T3 (§1.2), M9 records both dimensions on the result and
returns a structured refusal, so that adding T3 later is a change of verdict, not
a change of interface.

**The `R_INCOMPLETE` disambiguation** (007 §8.2) is M9's alone: only the relayer
knows whether the walk stopped because nodes were withheld (its own bug) or
because the terminal node is oversized. `m7_relayer.py` already gets the first
half right — it raises on `R_INCOMPLETE` as "relayer bug, not a receipt fact" —
and M9 keeps that, adding the second half.

**`R_ABSENT` is never "no such transaction"** without a transaction-count bound
(007 §1.2, §8.2). M9 returns `R_ABSENT` verbatim with an explicit
`bounded_by_tx_count: false`.

### 6.4 M8 — the SSZ branch builders

`tests/state_anchor/real_ssz.py` and `real_beacon_state.py` are the single
largest piece of real value currently trapped in the test tree: a hand-rolled
merkleizer that matched a real beacon node's own `state_root` **byte-for-byte**
across all 38 real Fulu fields including ~2.33 M real validators, cross-validated
against `remerkleable` at small scale, running in ~24 s. They become:

- `relayer/ssz/merkleize.py` — `merkleize_with_limit`, `mix_in_length`,
  `zero_hash`, the packing helpers, `Bitlist`/`Bitvector` decoding including the
  real SSZ delimiter bit.
- `relayer/ssz/execution_payload.py` — the payload tree and `deep_branch`, which
  composes gindices **802/803/806** for `state_root`/`receipts_root`/
  `block_number` (008 §3.2, independently cross-checked three ways before being
  trusted: composed gindices matched the doc, folding `block_hash` reproduced the
  spec-published `EXECUTION_BLOCK_HASH_GINDEX_DENEB = 812`, and all three folds
  reproduced the real published `body_root`).
- `relayer/ssz/beacon_state.py` — the 38-field tree and `block_roots_fold_branch`.
- `relayer/ssz/block_body.py` — the depth-4 `BeaconBlockBody` fold, needed
  because §5.4 shows an arbitrary historical slot has no precomputed branch.

**Normative, from 008 §9.4 and G4-M8:** M9 must **never** hardcode a branch depth
or a `g_block_roots_base`; both come from the on-chain fork table's row for the
right epoch, and the branch length is implied by the gindex and re-checked
on-chain (`N9`). The real values M9 must be able to reproduce, not assume:
Deneb `g_block_roots_base = 37`, Electra and Fulu `= 69` — Fulu's 38 fields still
round to 64 leaves, which is *why* it matches Electra, and that identity was
**shown**, not assumed, in `83b4fb8`.

### 6.5 DIRECT vs HISTORICAL — the decision rule

008 §9.4 makes this pure optimisation, and 008 §12.4 then inverts the naïve
instinct. M9's rule:

```
if target_block is the newest finalized EL block:      DIRECT
elif fin_slot - t_slot < 8192:                          HISTORICAL
else:                                                   NotAnchorable(outside_window)
```

**Why HISTORICAL is the default for everything else,** despite costing more
(measured **5,761** vs **3,588–3,652**, and ~0.006 ALGO more): a DIRECT anchor is
valid against **exactly one** finalized header, so if M4 advances between M9's
`simulate` and its `send` the group fails `N6`. A HISTORICAL anchor is valid
against **any** newer finalized header. 008 §12.4 calls the DIRECT race "normal,
not exceptional". This project has already watched the chain move forward between
runs three times in one session (`83b4fb8`: three separate real
`anchor_historical` submissions against three different live checkpoints).

**The window is real and short.** 8,192 slots ≈ **27.3 h**. `test_live_historical.
py` targets `t_slot = fin_slot - 6000` (~20 h) for headroom. M8's own G1-M8 note
records the consequence bluntly: mainnet block 25,639,768 — 007's *own pinned
example* — was ~11 days old and **no longer anchorable by any v1 mode**. M9 must
surface `outside_anchorable_window` as a first-class result, not an exception,
because it is a permanent property of a block, not a transient failure.

---

## 7. The group-assembly layer — the real new work

### 7.1 Four contracts, three budget conventions

This is the concrete form of "how do you handle four very different ABI shapes
with one coherent interface". The differences are not cosmetic:

| Target | Args | Budget donation | Who issues | Evidence |
|---|---|---|---|---|
| M4 `SyncCommitteeVerifier` | **ARC-4** | external `DonorIssuer` sibling → inner calls to `DonorCallee`; also has `noop_budget()` / `donor()` | relayer, extra txn | `test_live_e2e_finality.py::_issue_donor_txn`; 40 / 15 / 150 donors measured |
| M5 `MptSegmentApp`, M6 `Mpt6ComposerApp` | **raw** | **self-issued**: `donor_count` = arg2, `donor_app_id` = arg3 on every segment | the contract | `contracts/composer/bench_app.py::_issue_donors`; 14 donors measured |
| M7 `Mpt7ReceiptApp` | **raw** | **8 filler NoOp calls** — no donor args exist in its ABI | relayer, 8 extra txns | `m7_relayer.py:27` `N_FILLERS = 8` |
| M8 `TrustedRootAnchor` | **ARC-4** | external `DonorIssuer` sibling (M4's, reused verbatim) | relayer, extra txn | `tests/state_anchor/conftest.py::donor_txn`; 20 donors measured |

**M9's first real decision: drive M7 with an external `DonorIssuer` sibling, never
with filler NoOps.** This requires **no change to `Mpt7ReceiptApp`**, because
opcode budget pools across every application call in a group regardless of which
app it targets — proven live in this repo, where M4's `DonorIssuer` donates to a
*different* app (`TrustedRootAnchor`) in `test_live_e2e.py` and
`test_live_historical.py`. The gain is exact and large:

| | slots consumed | budget contributed |
|---|---:|---:|
| 8 filler NoOps (today) | **8 of 16** | 8 × 700 = 5,600 |
| 1 `DonorIssuer` with 8 inners | **1 of 16** | 8 × 682 = 5,456 net |

This is precisely the fix 008 §15.3 item 2 calls "the better fix" and hands to
M9, and it resolves 008 §9.3's headline finding — **the T2 cache-miss group at 17
transactions does not fit 16**. Rebuilt with a donor sibling:

| shape | txns today | with donor sibling | + M8 `attest` | fits 16? |
|---|---:|---:|---:|:--:|
| T1 cache hit | 9 | 2 | 3 | ✅ |
| T1 cache miss | 9 | 2 | 4 | ✅ |
| T2 cache hit | 15 | 8 | 9 | ✅ |
| **T2 cache miss** | **17 ✗** | 8 | **10** | ✅ |

The two-group fallback 008 §9.3 also describes is no longer needed. It stays
documented as `O-M9-2` in case a future group grows past 16 for another reason.

**What is NOT unified:** M5/M6 keep self-issuing. Changing them would mean editing
deployed contract code for no benefit — their `donor_count`/`donor_app_id` args
already give the relayer full control, and the mechanism is measured and working
(006 §7.6, real 14-donor 16-txn submission). M9 models this as a **property of the
driver**, not a special case in the planner:

```python
class BudgetConvention(Enum):
    SELF_ISSUED   = auto()   # M5, M6: planner writes donor_count/donor_app_id into args
    DONOR_SIBLING = auto()   # M4, M7, M8: planner prepends a DonorIssuer transaction
```

Two values, both live-proven, no third. The planner reads the driver's convention
and does the right thing; no caller ever branches on it.

### 7.2 Donor sizing — the procedure, verbatim

M5 §16.3, M6 §7.6 and 008 §9.4/§15.3 all specify the identical procedure, and it
is already implemented three times. Once, in `relayer/group/budget.py`:

```
1. Build the group with n_donors = 1 (never 0 — a zero-donor group can fail
   structurally before it reports a budget figure).
2. simulate with extra_opcode_budget generously set; read the REAL
   app-budget-consumed.
3. n_donors = ceil((consumed - base) / 682) + margin
      base   = 700 * (number of application calls already in the group)
      682    = measured net yield per donor inner call (004 §2.4)
      margin = 4, matching test_live_historical.py:719's real formula
4. Rebuild and submit for REAL. Never conclude from `simulate` alone.
```

Step 4 is not pedantry: M5 §16.3 records a segment that simulated fine and failed
outright with `dynamic cost budget exceeded` on real submission.

**Do not use `app-budget-added` from the simulate response.** Under
`extra-opcode-budget` each app call is credited 320,700 and the field reports
2,886,300 at n=8 (004 §2.4). Consumed-side differencing is the only honest read.

**Real measured donor counts, as the planner's starting hints** (all from real
submissions in this repo): `install_chunk` 40, `install_finalize` 15,
`submit_update` 150 (≥ ~131 minimum, complement mode), `anchor_direct` 12,
`anchor_historical` 20, M6 composite 14, M7 T1 walk ~6.

**The inner-call ceiling is shared and is 256 per group.** A 150-donor
`submit_update` group has 106 inner slots left, not 256. The planner must track
this — it is the one budget cap that is *global to the group* rather than
per-transaction.

### 7.3 The two box caps, and why one number is not enough

`contracts/sync_committee/constants.py` lines 110–153 are the authoritative
statement, measured, with the literal protocol errors:

- **`MAX_BOX_REFS_PER_TXN = 8`** — structural transaction-field validation,
  rejected *before the program runs*: `"tx.Boxes too long, max number of box
  references is 8"`.
- **`BOX_WRITE_BUDGET_BYTES_PER_REF = 2048`** — a byte budget **pooled across the
  whole atomic group**, credited 2,048 B per declared reference. Duplicate
  references to the same box, in the same or a sibling transaction, **count
  again**. References to boxes that are never touched (pure padding) count too.
- **The charge is the box's FULL DECLARED SIZE, once per box per group**,
  regardless of how few bytes `box_extract`/`box_replace` touches (004 §16.5).

A client that reasons about only the first cap builds groups that fail on the
second, and vice versa. `_choose_mode_and_boxes` reasons about neither — it
minimises *box count*, which is not the quantity that binds.

### 7.4 `plan_box_refs` — the closed form, and the failure it explains

**The rule, three terms:**

```
distinct  = set of boxes any transaction in the group will touch
bytes     = Σ declared_size(b) for b in distinct        # FULL size, once per box
refs      = max(len(distinct), ceil(bytes / 2048))
txns_min  = ceil(refs / 8)
FAIL if txns_min + real_txns > 16
```

Term 1 (every touched box must be named at least once) and term 2 (the pooled
byte budget) bind in *different* situations, which is exactly why one constant has
never worked. Two real examples from this repo, with different binding terms:

**Example A — M8 `ring_init_chunk` at N = 128 (term 1 binds).**
128 distinct boxes × 154 B = 19,712 B → term 2 gives ⌈19,712/2,048⌉ = **10 refs**;
term 1 gives **128**. `refs = 128`, `txns_min = 16`. G5-M8's real, non-simulated
submission used **exactly a 16-transaction group** and filled all 128 boxes. The
rule reproduces the shipped shape exactly.

**Example B — M4 `submit_update` (term 2 binds, catastrophically).**
`forks` is 576 B (`contracts/sync_committee/forks.py:24`); each key box
`k:<gen>:<j>` is **6,144 B** (`KEYS_PER_BOX × 96`); the aggregate box `a:<gen>` is
96 B. For `k` distinct key boxes touched:

```
bytes = 6144·k + 576 (+96 in complement mode)
refs  = ceil(bytes / 2048)  ≈  3k + 1
```

| k | refs required | txns required | what `_choose_mode_and_boxes` declares |
|--:|--:|--:|--:|
| 1 | 4 | 1 | 2 |
| 2 | 7 | 1 | 3 |
| 3 | 10 | 2 | 4 |
| 5 | 16 | 2 | 6 |
| **8** | **25** | **4** | **9** |

**This explains both observed live failures exactly.**
`test_live_e2e.py` reported `box read budget (6144) exceeded` — 6,144 = 2,048 × 3,
i.e. **3 declared refs**, which is `_choose_mode_and_boxes`' output for two key
boxes plus `forks`, against a real requirement of 12,864 B.
`test_live_historical.py` reported `box read budget (18432) exceeded` — 18,432 =
2,048 × **9 refs**, its output for all eight key boxes plus `forks`, against a
requirement of 49,728 B. The ROADMAP calls this "a DIFFERENT number from
`test_live_e2e.py`'s own (6144), confirming this really is live-data-dependent".
It is: `k` is a function of the live participation bitfield. **The budget is not
mysterious — it is `2048 × refs_declared`, and the current code declares too few.**

**And the workaround is provably insufficient.** `test_live_historical.py:330`
does `padded_box_refs = (box_refs + box_refs)[:16]`, giving 16 refs = 32,768 B
across the 2-transaction `[DonorIssuer, submit_update]` group. That covers
⌊(32,768 − 576)/6,144⌋ = **5 key boxes**. It works when the participation pattern
happens to cluster into ≤5 boxes and fails otherwise — which is precisely the
observed intermittency.

> **Real finding, and a real correction to the shipped test harness:** the
> 2-transaction `[DonorIssuer, submit_update]` group is **structurally incapable**
> of carrying a worst-case update. 8 key boxes need 25 references; two
> transactions can carry 16. **M4's per-update group needs at least four
> transactions** — `[DonorIssuer, noop_budget, noop_budget, submit_update]`, 32
> reference slots ≥ 25. `noop_budget()` exists for exactly this: 004 §7.3 defines
> it as "a group filler that carries box references and adds 700 to the pool".
> M9 must size the group from the bitfield. **A fixed group shape has been shown
> wrong twice in this codebase; a third fixed constant would be wrong a third
> time.**

The same arithmetic reproduces the contract's own already-computed constant as a
consistency check: box-opening writes 8 × 6,144 + 424 = 49,576 B →
⌈49,576/2,048⌉ = **25**, which is `MIN_BOX_REFS_FOR_INSTALL_OPEN` exactly.
`constants.py:136` notes that the *read* pool was "only spot-checked for a single
small chunk (§16.5), not re-derived" — **this section is that derivation**, and
M9's implementation must carry it as a real, tested function rather than a
comment.

**Two honest caveats, both inherited from 004 §16.5, neither resolved here:**
(a) it is *not confirmed* that the write pool and the read pool are the same pool;
M9's planner computes them separately and takes the max, which is correct under
either reading and wasteful under only one. (b) Whether the per-box charge is
truly once-per-group under repeated touches across *different transactions* is
measured only for the single-transaction case. Both are Suite BX in §13.

### 7.5 Mode selection, corrected

Given §7.4, `_choose_mode_and_boxes`' "fewer boxes wins" rule is wrong twice
over. M9's replacement:

```python
def choose_mode(bits: bytes, gen: int) -> tuple[int, list[BoxRef], int]:
    direct     = {i // 64 for i in set_bits(bits)}
    complement = {i // 64 for i in clear_bits(bits)}
    # 1. real pooled cost, not box count
    cost_d = 6144*len(direct)     + 576
    cost_c = 6144*len(complement) + 576 + 96      # complement also reads a:<gen>
    # 2. tie-break on OPCODE cost, which box count cannot see (217/point, 004 §2.3)
    if cost_d == cost_c:
        return (0, ...) if popcount(bits) <= 512 - popcount(bits) else (1, ...)
    return (0, ...) if cost_d < cost_c else (1, ...)
```

With realistic ~90% participation the ~51 absentees are usually spread over all 8
boxes, so **both modes touch all 8 boxes and the pooled costs tie** — at which
point the current rule picks arbitrarily and the corrected rule picks the cheaper
walk. That is a genuine, if secondary, budget win on top of the correctness fix.

### 7.6 The planner

```python
@dataclass(frozen=True)
class PlannedTxn:
    kind: Literal["app_call", "payment", "donor_issuer", "filler"]
    app_id: int
    args: list[bytes] | None          # raw-arg contracts
    method: str | None                # ARC-4 contracts
    method_args: list | None
    box_refs: list[BoxRef]
    foreign_apps: list[int]
    fee: int

@dataclass(frozen=True)
class GroupPlan:
    txns: list[PlannedTxn]
    result_index: int                 # whose log carries the answer
    donor_count: int
    convention: BudgetConvention
    total_fee_microalgo: int
    def check(self) -> None: ...      # asserts every ceiling in §3's table
```

`GroupPlan.check()` is the single place every real cap is enforced, and it must
assert, never warn: ≤16 transactions; ≤256 inner calls; ≤8 box refs per
transaction; `plan_box_refs` satisfied; ≤2,048 argument bytes and ≤16 arguments
per transaction; every `prev_gi` pointing at a transaction that actually produces
a log; fee ≥ min-fee × (1 + inner calls) on each donor transaction.

Building a plan is **pure** — no network. That makes the whole planner unit
testable offline against pinned fixtures (`ci-offline.yml`), which no part of the
current group-building code is.

### 7.7 Submission

`relayer/group/submit.py` implements one loop for every driver:

```
plan → simulate(n_donors=1) → size (§7.2) → re-plan → simulate (assert clean)
     → send_transactions → wait_for_confirmation → parse logs → typed result
```

with `--dry-run` stopping after the second simulate. **`allow_unnamed_resources`
is deliberately NOT used** in the real path: it papers over exactly the box-
reference planning §7.4 exists to get right, and a group that only works with it
will fail against a node that does not permit it.

### 7.8 Log envelopes — three shapes, one decoder

| Producer | Envelope | Total |
|---|---|---:|
| M5 / M6 | `0x151f7c75 ‖ len(2) ‖ W(101) ‖ C(248)` | **355 B** |
| M7 | `0x151f7c75 ‖ len(2) ‖ W(101) ‖ R(240)` | **347 B** |
| M8 `attest` | `0x151f7c75 ‖ A(154)` — **no length field** | **158 B** |

M8's is different because `TrustedRootAnchor` is a real `ARC4Contract` and Puya's
auto-generated return log for a fixed-size `StaticArray[Byte, 154]` carries no
length prefix — a real finding confirmed against a live algod probe before
`handoff.py` was written against it, and precisely the kind of thing a client that
assumes one envelope gets wrong. `relayer/group/logs.py` carries all three
explicitly, keyed by producer, and asserts the length before slicing.

---

## 8. Interface

### 8.1 Shape: a library, with a CLI over it

**Both, and in that order.** The library is the product (the x402 service, M10 and
M11 all consume it programmatically); the CLI is a thin `argparse` shell that adds
no logic. Anything the CLI can do, the library can do; the CLI never reaches past
`EthAvmClient`.

### 8.2 The facade

```python
@dataclass
class RelayerConfig:
    algod_url: str; algod_token: str
    m4_app_id: int | None; m6_app_id: int | None
    m7_app_id: int | None; m8_app_id: int | None
    donor_issuer_id: int | None; donor_callee_id: int | None
    eth_rpcs: list[str]; beacon_apis: list[str]
    signer: TransactionSigner | None = None      # None ⇒ dry-run only
    cache_dir: Path | None = None
    max_group_txns: int = 16

class EthAvmClient:
    def sync(self) -> SyncResult: ...                       # M4
    def anchor(self, block: int | Literal["latest"]) -> AnchorResult: ...   # M8
    def prove_account(self, address, slot, block) -> AccountResult: ...     # M6
    def prove_receipt(self, block, tx_index, log_index) -> ReceiptResult: ...  # M7 (+M8)
    def status(self) -> Status: ...                         # read-only, free
```

Five verbs. `status()` is readonly and costs nothing — it calls M4's
`get_finalized()` and M8's `get_anchor()` (both `readonly=True`) and is what
008 §9.4's "cache before you build" rule is built on: **`get_anchor` before
planning, and skip the anchoring transactions on a hit.** That is where M8's ring
actually pays for itself, and it is M9's job to realise it.

### 8.3 Four drivers, deliberately not unified

The four contracts differ along five axes at once:

| | M4 | M6 | M7 | M8 |
|---|---|---|---|---|
| Encoding | ARC-4 | raw args | raw args | ARC-4 |
| Budget | donor sibling | self-issued | **fillers → donor sibling (§7.1)** | donor sibling |
| Boxes | 8 key + session + total + forks | none | T2 staging only | ring + pin + forks |
| Stateful | **yes** — install session | no | T2 box lifecycle | yes — ring |
| Result | global state + event | 355 B log | 347 B log | **158 B** log + box |
| Groups per operation | **66** (install) | 1 | 1 | 1 |

**Decision: no unified `submit(proof)` method.** A uniform signature would have to
carry a discriminated union and would hide the axes above — the exact things an
operator needs to see. What *is* unified is everything beneath: one pool, one
codec set, one SSZ library, one planner, one budget sizer, one box planner, one
submit loop, one log decoder, one error taxonomy. The drivers are thin, and their
job is precisely to encode the differences the table shows.

This is the same call M7 §5.1 made about M6's bridge ("M7 does not need M6's
bridge... M7 needs M6's segment driver *shape*") and M8 §8.6 made about
co-deployment: **share the mechanism, not the surface.**

### 8.4 The CLI

```
python -m relayer status
python -m relayer sync [--bootstrap-root 0x… | --checkpoint-url …] [--install] [--update]
python -m relayer anchor --block latest|N [--mode auto|direct|historical]
python -m relayer prove account --address 0x… --slot 0x… [--block N]
python -m relayer prove receipt --block N --tx-index I --log-index L [--against-anchor]
python -m relayer plan …            # build + simulate, print the GroupPlan, submit nothing
```

Global flags: `--dry-run`, `--json`, `--config`, `--no-cache`, `--verbose`.
`--json` on every verb, because M10 and M11 are machine consumers.

### 8.5 Results and the error taxonomy

Results are frozen dataclasses that keep the on-chain verdict distinct from the
transport outcome. The distinction matters most for M7, where 007 §5.4's core
safety property is that `R_ABSENT`/`R_NO_SUCH_LOG`/`R_ZERO_LOGS` are **legitimate
verdicts delivered by a successful transaction**, never failures — proven live at
round 7. `m7_relayer.py` already gets this right and M9 keeps it.

```python
class Retryability(Enum):
    RETRY_NOW        # transient: endpoint 5xx, pool exhaustion, algod timeout
    RETRY_REPLANNED  # chain moved: M4 advanced (N6), fin_slot changed, group stale
    FATAL            # will never succeed as-is: outside window, T3 tier, no fork row
    PAGE_A_HUMAN     # N20 — M8's equivocation latch
```

The classification table (each row cites the contract that raises it):

| Condition | Class | Rule |
|---|---|---|
| `PoolExhausted` | RETRY_NOW | back off; if the whole pool is down, do **not** silently fall back to one endpoint |
| algod `simulate` disagrees with `send` | RETRY_REPLANNED | re-simulate, re-size donors |
| M8 `N6` (fin header changed) | RETRY_REPLANNED | 008 §12.4 — **normal, not exceptional**; prefer HISTORICAL next attempt (§6.5) |
| M8 `N12` (absent) | RETRY_REPLANNED | re-anchor |
| M8 `N13` (revoked) | **FATAL** | 008 §15.3 item 6: `N12` and `N13` are not the same thing; **never** re-anchor on `N13` |
| M8 `N20` (conflict latch) | **PAGE_A_HUMAN** | 008 §15.3 item 7 — equivocation, not a retry |
| M8 `N17` (no fork row) | FATAL | governance action needed (M10) |
| M4 monotonicity / stale update | FATAL for that update | fetch a newer one |
| M4 install group failed mid-session | RETRY_REPLANNED | resume from `inst_cursor`, §9.1 |
| Leaf > 4,096 B | FATAL (`T3_UNSUPPORTED`) | §6.3; surfaced, never swallowed |
| `fin_slot − t_slot > 8192` | FATAL (`outside_anchorable_window`) | permanent property of the block |
| `R_INCOMPLETE` | **relayer bug** | raise loudly; never a receipt fact |

**Idempotence is what makes retrying safe**, and it is a property of the
contracts, not of M9: 008 §5.4 guarantees re-anchoring identical content is a
no-op success, so a group whose confirmation M9 missed can be safely resubmitted.
M9 relies on that and must not invent its own dedupe layer.

---

## 9. State, resumption, idempotence

### 9.1 M4's install session — the client half of an on-chain state machine

M4 already has a resumable session on-chain: `inst_state`
(`VALIDATED → OPENING_BOXES → INSTALLING`) plus an `inst_cursor`, and 004 §12.4
item 5 states the rule — *"a failed group leaves the cursor where it was, and
resumption is a retry from `inst_cursor`, not a restart"*.

**Does M9 need matching client-side resume logic? Yes, but it needs no client-side
state.** M9 reads `inst_state` and `inst_cursor` out of M4's global state and
resumes from there. The on-chain state machine **is** the checkpoint; a local
progress file would be a second source of truth that can disagree with the chain,
which is strictly worse. Concretely:

```
state = read_global(m4)
if state.inst_state == NONE:            run bootstrap group
if state.inst_state == VALIDATED:       run [install_open_keys, install_open_session] group
if state.inst_state == OPENING_BOXES:   ditto (the group is atomic — it either
                                        completed or left no observable trace)
if state.inst_state == INSTALLING:      resume install_chunk at inst_cursor
then                                    install_finalize
```

The atomicity of the box-opening group is what makes the third line safe: 004 §16
notes that atomicity, *not* the `inst_state` guard, is what prevents a partially
opened box set from ever being observable.

A 66-group operation (one combined bootstrap+box-opening group, 64 `install_chunk`
groups, one `install_finalize` group — the exact shape
`test_live_e2e_finality.py::installed_committee` submits) that resumes from chain
state is also what makes the CLI's `--install` idempotent:
running it twice is safe, and running it after a crash is the normal path.

### 9.2 Everything else is single-group and stateless

M6, M7 (T1), and M8 are one group each; a failure means nothing happened. M7's T2
path is the exception — it creates a staging box — and it closes it in the same
group (`mpt7_stage_close`), so an aborted group leaves no box and no MBR stranded.
007 §8.4 flags a box sweeper for M10 anyway, for the case where a group commits
partially through a *different* failure mode; M9 does not build one.

### 9.3 The one place M9 must re-touch a box

004 §16.5's full-declared-size-per-touch charge matters to resumption in exactly
one place: a resumed `install_chunk` at `inst_cursor` re-touches a key box that a
previous, failed group had already referenced. The charge is per group, so a fresh
group pays the full 6,144 B again — meaning **the resumed group needs the same 4
box references per `install_chunk` call that the original did**, not fewer.
`boxes=[(0, kb), (0, sb), (0, kb), (0, sb)]` in the live test is that deliberate
duplication, and M9's planner must reproduce it from §7.4's rule rather than
copying the literal list.

---

## 10. Edge cases

**10.1 The chain moves between fetch and submit.** Already observed live three
times in one session. DIRECT anchoring fails `N6`; M4's update becomes stale. Both
are `RETRY_REPLANNED`, and §6.5's HISTORICAL preference exists to make the anchor
case survive it outright.

**10.2 A partial atomic group.** Cannot happen — groups are atomic. What *can*
happen is a **sequence** of groups partially completing (M4's install). §9.1.

**10.3 Endpoint pool exhaustion.** `PoolExhausted` carries every real error from
every attempt, as `_get_json` already does. Two rules: never silently degrade to a
single endpoint (a partitioned or lying endpoint is exactly what a pool defends
against), and **never proceed with an unverified value** — if M9 cannot fetch the
data, it stops. It does not guess.

**10.4 The sync-committee period boundary.** `finality_update` never carries a
`next_sync_committee` proof. Crossing a period without having installed the next
committee from a `/light_client/updates` response leaves M4 unable to verify. M9's
update loop must fetch `updates` at period boundaries. 004 §10.3 owns the
on-chain half.

**10.5 A block with no logs.** `R_ZERO_LOGS` is a verdict, and the empty-trie
`receipts_root` is perfectly anchorable (008 §12.2). M9 must not add a
well-meaning "reject the empty root" check.

**10.6 A skipped beacon slot.** Handled on-chain by deriving the `block_roots`
index from the target header's own slot (008 §4.3). M9's fixture builder must
still handle a slot with no block by walking back, since it is choosing `t_slot`.

**10.7 A receipt whose leaf is exactly 1,942 or 4,096 bytes.** Boundary values on
both classifier edges; both must be tested, and `1943` must classify as T2.

**10.8 `tx_index` not in the block.** `build_receipts_trie_and_path` raises
`KeyError`; M9 maps it to a 404-shaped `FATAL`, never to `R_ABSENT` — those mean
different things (§6.3).

**10.9 An account that does not exist.** `eth_getProof` returns a valid exclusion
proof; M6 answers `C_ABSENT_ACCOUNT` with **zero phase-B segments** (006 §8.1).
M9 must not emit them.

**10.10 M9 run with no signer.** Every verb works up to and including the second
`simulate`, then reports the plan. This is the CI and audit path, and it must not
be an afterthought bolted on later.

**10.11 The x402 pre-payment problem** (008 §15.3 item 9). The payment middleware
settles *before* the handler runs, so a not-yet-finalized or out-of-window block
means the payer paid for a 425/501. **This document does not decide it** — it is a
product decision for the service, not the relayer. What M9 *provides* is the thing
that makes either choice implementable: `EthAvmClient.status()` is free, readonly
and answers "is this block anchorable right now", so the service can expose a free
`/anchorable/{block}` pre-check if it chooses to.

---

## 11. Adversarial notes — what an untrusted relayer can and cannot do

M9 cannot forge a verdict; §1.3 lists the contract-side reasons. What it *can* do,
and what an operator should know:

1. **Withhold.** Never submit, or submit only favourable blocks. Undetectable
   from on-chain state alone; mitigated only by anyone else being able to run M9.
   This is the strongest argument for M9 being a clean, runnable, documented
   library rather than a service-internal module.
2. **Anchor selectively.** M8's ring is finite (`N`); a relayer that anchors
   uninteresting blocks can evict an interesting one. 008 §7.5's pinned tier is
   the answer, and it is a *consumer* action, not M9's.
3. **Front-run its own anchor.** Anchoring, then revoking via governance, is a
   governance-key attack, not a relayer one (008 §5.7).
4. **Spend the operator's ALGO.** Fees are real (§12). A misconfigured donor count
   or an unbounded retry loop is a financial bug. `GroupPlan.total_fee_microalgo`
   is computed **before** submission for exactly this, and the CLI prints it under
   `--dry-run`.

One thing M9 must **not** do, stated because it would be tempting: never re-derive
`receipts_root` from RPC and pass it to M7 when an M8 anchor is available. The
whole point of `mpt7_result_against_anchor` is that no such parameter exists. If
M9 is configured with an `m8_app_id`, `prove_receipt` must use the anchored path;
falling back to the RPC-supplied root silently would reintroduce exactly the gap
`83b4fb8` closed.

---

## 12. Cost — what M9 actually spends

All figures **measured** unless marked projected; fees at the 1,000 µALGO min fee.

| Operation | Group shape | Fee (µALGO) |
|---|---|---:|
| `submit_update` (M4) | `[DonorIssuer(150), noop_budget×2, submit_update]` | 154,000 |
| `install_chunk` × 64 | `[DonorIssuer(40), install_chunk]` each | 64 × 42,000 = 2,688,000 |
| `install_finalize` | `[DonorIssuer(15), install_finalize]` | 17,000 |
| Box-opening group | `[bootstrap, install_open_keys, install_open_session, noop_budget]` | 4,000 |
| `anchor_direct` (M8) | `[DonorIssuer(12), anchor_direct]` | 14,000 |
| `anchor_historical` (M8) | `[DonorIssuer(20), anchor_historical]` | 22,000 |
| M6 composite | 5 segments, 14 self-issued donors | 19,000 |
| M7 T1 + anchor | `[DonorIssuer(6), attest, MODE_INIT, MODE_AGAINST_ANCHOR]` | 10,000 |

**Per-update steady state ≈ 0.154 ALGO.** A committee install is a one-off
**≈ 2.71 ALGO** in fees per generation, plus box MBR: 8 key boxes at 6,144 B plus
the session box, `2,500 + 400 × (name + size)` each ⇒ **≈ 19.7 ALGO, recoverable**
(projected from the MBR formula; the live harness funds 45 ALGO,
`tests/sync_committee/conftest.py::APP_FUNDING_MICROALGO`). M8's ring at `N = 128`
is **9.328 ALGO**, all recoverable (008 §10.7) — M10's to fund, not M9's.

M7 T2 additionally needs a transient box MBR of `2,500 + 400 × (8 + leaf_len)` —
**≈ 1.65 ALGO at a 4,096 B leaf** — paid to the **app account, not the sender**, in
the same group before `MODE_STAGE_OPEN`. That finding cost a live debugging cycle
(`m7_relayer.py:11`) and the planner must encode it, not rediscover it.

---

## 13. Test plan

Per the plan's Verification section, M9 is named among the modules that **must
validate against real mainnet fixtures — real block, real trie rebuild, real root
match — not synthetic data**. Suites follow M5 §9 / M6 §11 / M7 §9 / M8 §13
numbering conventions.

### 13.1 Suite P — the planner, offline (`ci-offline.yml`)

Pure, no network, no algod. This suite is the reason §7.6 makes planning pure.

| id | test | expectation |
|---|---|---|
| P-1 | `plan_box_refs` on M8 `ring_init_chunk`, N=128 | 128 refs, 16 txns — reproduces G5-M8's shipped shape |
| P-2 | `plan_box_refs` on `submit_update`, k = 1…8 | 4, 7, 10, 13, 16, 19, 22, **25** refs; ≥4 txns at k=8 |
| P-3 | `plan_box_refs` on the box-opening group | **25**, equal to `MIN_BOX_REFS_FOR_INSTALL_OPEN` |
| P-4 | Replay the two observed failures: 3 refs at k=2, 9 refs at k=8 | planner rejects both **before** building |
| P-5 | M6 segmentation of the pinned USDT/Binance-8 proof | exactly 006 §6.5's 5 segments: 1,596 / 1,596 / 540 node bytes |
| P-6 | M6 segmentation with `MODE_A_INIT`'s 1,943 B vs others' 2,019 B | a node set that fits one and not the other splits differently — proves the 13-byte finding is honoured |
| P-7 | M7 T1 splitting across `MODE_INIT` + `MODE_NEXT` | fixes D2; `prev_gi` chains to the real producing index |
| P-8 | `GroupPlan.check()` negatives | 17 txns, 9 box refs on one txn, 2,049 arg bytes, 17 args, 257 inner calls — each rejected with its own error |
| P-9 | Tier classifier at 1,942 / 1,943 / 4,096 / 4,097 | T1 / T2 / T2 / T3_UNSUPPORTED |
| P-10 | Donor sizing arithmetic against 004 §2.4's measured table | matches `test_live_historical.py:719`'s real formula |

### 13.2 Suite R — real data, offline against pinned fixtures

| id | test | expectation |
|---|---|---|
| R-1 | `build_receipts_trie_and_path` on the pinned block | root matches the real `receiptsRoot`; tx 31's 3-node path byte-identical to M7's fixture |
| R-2 | `eth_getProof` decode against `tests/fixtures/spike-reference/eth_data.json` | 8 account nodes + 9 storage nodes, matching M2's own G6 bench inputs |
| R-3 | `relayer/ssz/` vs `remerkleable` at small scale | bit-for-bit across packed uint64/uint8 lists, fixed vectors, container lists, `Bitlist`/`Bitvector` with the real delimiter bit, `n == limit`, partial final chunk — i.e. `real_beacon_state.py`'s existing cross-validation, promoted |
| R-4 | `_decode_header` / `_decode_branch` on recorded live "fulu" JSON | 112-byte headers; 7-node `finality_branch`; 6-node committee branches |
| R-5 | G1/G2 decompression round-trip | AVM limb order (`c0` first) — the **reverse** of every reference serializer (004 §12.4 item 2) |
| R-6 | `install_chunks(chunk_size=8)` | every blob ≤ 2,048 B with ARC-4 framing; `chunk_size=64` rejected at the API, not at algod (D1) |

### 13.3 Suite L — live, real mainnet, real submissions (`ci-live.yml`)

Reusing this project's established live pattern: a dev-mode algod in Docker, real
public endpoints, a module-scoped expensive fixture, real non-simulated
submissions, and re-running against fresh live data for reproducibility.

| id | test | expectation |
|---|---|---|
| **L-1** | `EthAvmClient.sync()` end to end on a fresh app: bootstrap → box-opening → 64 `install_chunk` → `install_finalize` → `submit_update` | on-chain `fin_slot`/`fin_root`/`fin_state_root` match the live beacon data exactly. **The equivalent of `test_live_e2e_finality.py`, driven entirely by M9 rather than by hand-rolled test code.** |
| **L-2** | L-1's `submit_update` when the live bitfield touches **all 8 key boxes** | **succeeds** — the test that has failed twice. Must be run on live data and, if the live participation does not produce k=8, forced by choosing the mode that does. This is G1-M9. |
| **L-3** | `anchor(latest)` → DIRECT; `anchor(fin_slot − 6000)` → HISTORICAL | both commit for real; `attest` returns `el_receipts_root` byte-identical to the real EL block's |
| **L-4** | `prove_receipt(block, tx, log, against_anchor=True)` on a **dynamically selected** real tx from the just-anchored block | recovered `(status, tx_type, n_topics, address, data_hash)` match `eth_getBlockReceipts` byte-for-byte. Selection must be dynamic — a hardcoded `tx_index` only works for one block and this fixture anchors a fresh one every run (`83b4fb8`) |
| **L-5** | `prove_account` for USDT/Binance-8 at a **current** block | `C_INCLUDED`, real balance. First live M6 submission from a real `eth_getProof` rather than a pinned fixture — **M6 has never been exercised this way** |
| **L-6** | M7 **T2** driven by M9's planner with a `DonorIssuer` sibling instead of 8 fillers | commits in ≤10 transactions (§7.1's table), same on-chain log as the 15-txn filler version |
| **L-7** | Resume: kill `sync --install` mid-way, re-run | resumes from `inst_cursor`, completes, `install_finalize` succeeds |
| **L-8** | Chain-moves race: `simulate` a DIRECT anchor, wait for M4 to advance, `send` | fails `N6`, classified `RETRY_REPLANNED`, and the retry with HISTORICAL succeeds |
| **L-9** | Pool exhaustion: point every endpoint at an unreachable host | `PoolExhausted` carrying **every** attempted URL and error; **no submission attempted** |
| **L-10** | `--dry-run` with **no signer configured** | full plan + simulate + printed fee, zero transactions sent |

### 13.4 Suite BX — the box-budget model itself

The two caveats §7.4 leaves open, closed by measurement rather than left as
comments:

| id | test | expectation |
|---|---|---|
| BX-1 | Is the write pool the same pool as the read pool? Group that both creates and extracts, with refs sized for each hypothesis | one hypothesis fails; record which. Closes 004 §16.5's flagged precision gap |
| BX-2 | Is the full-size charge really once per group across **different transactions**? Two txns each extracting the same 6,144 B box, refs sized for one charge | pass ⇒ once per group; fail ⇒ once per touch, and §7.4's formula needs a multiplier |
| BX-3 | Duplicate refs to the same box in the same txn | each counts (already assumed by `install_chunk`'s `[(0,kb),(0,sb),(0,kb),(0,sb)]`) |

### 13.5 Suite S — the relayer's own security properties

| id | test | expectation |
|---|---|---|
| S-1 | Configure `m8_app_id`, then attempt an RPC-rooted receipt proof | **refused** — §11's last paragraph |
| S-2 | Feed a future-dated `signature_slot` | refused client-side before submission (§1.3) |
| S-3 | Feed a `transform_optimistic_update` result where `SubmitUpdateArgs` is expected | type error, never a malformed submission |
| S-4 | `N13` (revoked anchor) | classified FATAL; **no** automatic re-anchor |
| S-5 | `N20` (conflict latch) | classified PAGE_A_HUMAN; process exits non-zero, loudly |

---

## 14. Acceptance gates

| Gate | Statement | How judged |
|---|---|---|
| **G1-M9** | A real `submit_update` commits when the live bitfield touches **all 8 key boxes** | L-2, real submission, not `simulate` |
| **G2-M9** | `EthAvmClient.sync()` reproduces `test_live_e2e_finality.py`'s result end to end, driven only by M9 | L-1 |
| **G3-M9** | M9's M6 packer reproduces 006 §6.5's 5-segment split byte-for-byte | P-5, offline |
| **G4-M9** | A real `eth_getProof` account+storage proof commits live | L-5 — first ever for M6 |
| **G5-M9** | M7 T2 commits in ≤10 transactions using a donor sibling | L-6; closes 008 §9.3 |
| **G6-M9** | A real receipt verified against a real M8 anchor, driven by M9 | L-4 |
| **G7-M9** | Every planner cap is asserted, and every negative in P-8 is rejected before any network call | P-8 |
| **G8-M9** | `relayer/` imports no `tests.*`, no `algopy`, no `fastapi`, no `x402`; `sources`/`codec`/`ssz`/`proofs` import no `algosdk` | an import-graph test in `ci-offline.yml` |
| **G9-M9** | `service/x402_endpoint/` contains only `main.py` + config after the move, and the live x402 route still works | a real paid request, as `86a5e87` did |
| **G10-M9** | No cost number in this doc's implementation report lacks a real response behind it | `ARCHITECTURE.md`'s standing rule |

---

## 15. Questions resolved, and what is handed on

### 15.1 M9's own ROADMAP row

> *"Design can start once M4/M6/M7/M8 ABIs are frozen, ahead of their
> implementations landing."*

**Resolved, and better than the row assumed.** All four are implemented, live-
tested and committed, so M9 targets **real, live-proven code** rather than design-
doc pseudocode. Three places where the code and the docs differ, and the code
wins:

1. M4 gained `install_open_keys` / `install_open_session` after 004 was written
   (004 §16). M9 targets the six-method install flow.
2. M8's `attest` return log is **158 B with no length field**, not 008 §8.3's
   assumed 160 B (§7.8).
3. M8's `m4_app` parameter compiles to ARC-56 `uint64`, **not** a reference type —
   the app id must be passed as a plain integer *and* separately listed in
   `foreign_apps`. A client reaching for `algopy.Application` ergonomics gets it
   wrong, which is why `submit_with_donor(..., apps=[h.app_id])` exists in the
   live test.

The row's inherited "Depends on: M5, M3" is also stale — M9 drives M4, M6, M7, M8;
M3 and M5 are reached only through them.

### 15.2 The plan's own M9 sentence

Two of its three clauses hold; one is stale. **"Chunks to the 42-point MSM
boundary" is struck** — the shipped M4 uses an `ec_add` chain on both paths and
never calls `ec_multi_scalar_mul` (§3). "16-outer/256-inner group ceiling" and
"submits against M4/M6/M7/M8's frozen ABIs" both hold and are load-bearing.

### 15.3 Inherited questions, answered

**From 004 §12.4 (M4):**

| # | Question | Resolution |
|---|---|---|
| 1 | M9 owns wall-clock sanity | §1.3, §6.1 — a hard assert against `slot_now(genesis_time)`, not a warning |
| 2 | M9 owns off-chain decompression, AVM G2 limb order | §5.3 `relayer/codec/`, promoted from the pytest tree; R-5 |
| 3 | M9 owns `mode` selection and donor sizing | §7.5 (corrected cost model) and §7.2 (one implementation) |
| 4 | M9 owns install chunking; *"~12 members per transaction"* | §3 — the real figure is **8**, from 64 real submissions. Corrected |
| 5 | M9 must handle install-session abandonment | §9.1 — resume from on-chain `inst_cursor`; **no client-side state file** |

**From 006 §13.3 (M6):**

| # | Question | Resolution |
|---|---|---|
| 1 | ABI frozen by §6.3/§3.3/§3.4 | targeted; P-5/P-6 |
| 2 | Relayer owns segmentation, and the caps differ per mode | §6.2 uses 105 B / 29 B fixed overheads, never "2,048 minus a round number" |
| 3 | Relayer owns donor sizing and must fund txn 0 | §7.2, and `GroupPlan` computes fees per transaction |
| 4 | Relayer owns Solidity mapping-key derivation | §6.2 step 5, with the repo's own pinned example as its doctest |
| 5 | Off-chain verification is 3 byte comparisons + a phase check | `AccountResult` exposes offsets 2/34/54 and `phase == 3` |

**From 007 §8.2 (M7):**

| # | Question | Resolution |
|---|---|---|
| 1 | Classify T1/T2/T3 before submitting; a tier is `(N, LOGMAX)` | §6.3 records both dimensions; v1 refuses T3 cleanly |
| 2 | M9 owns disambiguating `R_INCOMPLETE` | §6.3, §8.5 — surfaced, never swallowed |
| 3 | M9 builds the T2 staging group and funds box MBR | §12 — MBR to the **app** account, in the same group |
| 4 | M9 becomes a proving service | **Deferred, with a reason**: 007 rev. 8's real sample says 2.2% of receipts need it. `O-M9-1` |
| 5 | Setup must be computed once per tier and persisted | out of scope with (4) |
| 6 | A proof must never outlive its statement | out of scope with (4); recorded so it is not lost |
| 7 | Never present `R_ABSENT` as "no such transaction" | §6.3 — `bounded_by_tx_count: false` on the result |

**From 008 §9.4 / §15.3 (M8):**

| # | Question | Resolution |
|---|---|---|
| 1 | Choosing DIRECT vs HISTORICAL | §6.5 — HISTORICAL is the default for anything but the newest block |
| 2 | Building the branches with a real SSZ library, no hardcoded depths | §6.4 — promote `real_ssz.py`/`real_beacon_state.py`; depths from the on-chain fork row |
| 3 | Donor sizing, `simulate` then real send | §7.2 |
| 4 | Cache policy — `get_anchor` before building | §8.2 `status()`; this is where the ring pays for itself |
| 5 | Idempotent retries; `N20` is not retryable | §8.5's taxonomy; `N20` ⇒ PAGE_A_HUMAN |
| 6 | `N12` ≠ `N13` | §8.5 — re-anchor on `N12`, **never** on `N13` |
| 7 | T2 cache-miss does not fit 16 txns | §7.1 — **solved**, 10 txns via a donor sibling, no contract change |
| 8 | The x402 pre-payment problem | §10.11 — flagged, not decided; M9 supplies the free pre-check primitive |

### 15.4 Handed on

**To M10.** M9 reads app ids; it never creates apps, funds `N`, seeds fork tables
or pins M4's program hash. `GroupPlan` is reusable for M10's own deployment
groups, and `plan_box_refs` (§7.4) is exactly what a `ring_init` at arbitrary `N`
needs. 008 §15.4's `renounce()` migration remains M10's.

**To M11.** Suite P is pure and belongs in `ci-offline.yml` from day one. Suite L
is the natural body of `ci-live.yml`, and L-2 should gate any claim that M4 works
on live data. M11 should also own **rebasing the four existing live test files
onto M9** rather than leaving five copies of group assembly — that is the real
end state, and doing it inside M9's pass would be scope creep.

**To M12.** The CLI is the first user-facing surface this project has; the README's
quickstart should be `python -m relayer status` against a public deployment.

**To a future M7 revision.** If T3 ships, §6.3's classifier and §8.5's
`T3_UNSUPPORTED` are the seam it plugs into. Nothing else in M9 changes shape.

---

## 16. Honest gaps and deferred work

**Gaps this design knowingly leaves open:**

1. **T3/ZK proving is not in v1** (§1.2). Defensible on 007 revision 8's real
   numbers (2.2% of real receipts), but it means a small, real slice of Ethereum
   receipts is unreachable through M9 v1, and the CLI must say so rather than
   time out.
2. **The write-pool/read-pool question is inherited, not resolved** (§7.4's
   caveat a). Suite BX closes it by measurement; until it runs, M9's planner is
   conservative in a way that may cost a transaction slot it did not need.
3. **`anchor_by_inner_call` remains unimplemented** on-chain (008 §16 gap 3), so
   M9 drives only the log-chain hand-off. If it ever lands, M9 gains a second
   path.
4. **Deneb→Electra straddle data is no longer fetchable** (008 §17): mainnet is
   long past both forks and `/eth/v2/debug/beacon/states/{slot}` 404s near that
   boundary. M9 cannot build a live two-fork-row fixture either; `test_forks.py`'s
   synthetic-fold-with-real-constants approach is the ceiling.
5. **No p2p, no `is_better_update` ranking** (§1.2). M9 trusts a beacon API's
   choice of update. Since the update is verified on-chain, this is a liveness
   and freshness question, not a soundness one — but it does mean M9's view of
   "best" is whatever its endpoint pool serves.
6. **The 66-group install has never been driven by one program.** It has been
   driven by a pytest fixture, which is not the same thing: a fixture cannot be
   interrupted and resumed, and §9.1's resume path is therefore designed but
   unexercised until L-7 runs.

**Deferred optimisations (`O-M9-*`), measurement-gated:**

| id | idea | gate |
|---|---|---|
| `O-M9-1` | T3 proving service: queue, Go runtime, ≥64 GB host, persisted per-tier proving keys | only if real demand exceeds the 2.2% figure |
| `O-M9-2` | Two-group anchor+prove flow (008 §9.3's alternative) | only if a group grows past 16 for a new reason |
| `O-M9-3` | p2p light-client sync and `is_better_update` ranking | only if endpoint-pool freshness proves inadequate |
| `O-M9-4` | Parallel `install_chunk` submission (64 independent groups) | measure wall-clock first; `inst_cursor` is sequential, so this needs contract-side thought, not just client-side |
| `O-M9-5` | Persist a local anchor index to avoid repeated `get_anchor` round-trips | only if `status()` latency shows up |

---

## 17. File layout

```
relayer/
  __init__.py
  config.py                 RelayerConfig, env + file loading
  errors.py                 Retryability, PoolExhausted, NotAnchorable, TierUnsupported
  client.py                 EthAvmClient (§8.2)
  cli.py                    argparse shell (§8.4)
  sources/
    pool.py                 EndpointPool (§5.1)         ← extracted from 2 copies
    eth_rpc.py              + eth_getProof              ← promoted, extended
    beacon.py               fetchers only               ← promoted, split
    cache.py                content-addressed disk cache
  codec/
    bls.py                  G1/G2 (de)compression, AVM limb order  ← out of tests.bls
    header.py               _decode_header, _decode_branch          ← promoted
    committee.py            _committee_root                          ← promoted
  ssz/
    merkleize.py            ← tests/state_anchor/real_beacon_state.py (generic core)
    execution_payload.py    ← tests/state_anchor/real_ssz.py
    beacon_state.py         38-field Fulu tree, block_roots fold
    block_body.py           depth-4 BeaconBlockBody fold
  proofs/
    receipts_trie.py        ← service/x402_endpoint/trie_proof.py (verbatim)
    account.py              NEW: eth_getProof → M6 segments
    classify.py             NEW: T1/T2/T3 tier classifier
  group/
    budget.py               donor sizing, BudgetConvention (§7.1–§7.2)
    boxes.py                plan_box_refs (§7.4)        ← THE fix
    planner.py              PlannedTxn, GroupPlan, check() (§7.6)
    donors.py               locate/deploy DonorIssuer + DonorCallee
    submit.py               simulate → size → simulate → send (§7.7)
    logs.py                 three envelopes, one decoder (§7.8)
  drivers/
    m4_sync_committee.py    SubmitUpdateArgs, BootstrapArgs, fixed install_chunks
    m6_account_storage.py
    m7_receipt.py           ← rewrite of m7_relayer.py
    m8_anchor.py            DIRECT/HISTORICAL selection (§6.5)

tests/relayer/
  test_plan_boxes.py        Suite P
  test_segmentation.py      Suite P
  test_real_fixtures.py     Suite R
  test_live_relayer.py      Suite L
  test_box_budget_model.py  Suite BX
  test_security.py          Suite S

service/x402_endpoint/      main.py, .env.example, vercel.json, requirements.txt
                            (the four .py modules move out; §2.3)
```

**Files deleted by this module** (their content promoted, not lost):
`service/x402_endpoint/eth_rpc.py`, `eth_beacon_rpc.py`, `trie_proof.py`,
`m7_relayer.py`. **Files that stay in `tests/` and gain an import from `relayer/`
instead of a private copy**: `tests/state_anchor/real_ssz.py`,
`real_beacon_state.py` become thin shims or are deleted once their tests import
`relayer.ssz`.

---

## 18. Implementer checklist (normative MUSTs)

1. `relayer/` **MUST NOT** import `tests.*`, `algopy`, `fastapi`, `x402` or
   `pytest`. `sources`/`codec`/`ssz`/`proofs` **MUST NOT** import `algosdk`.
   Enforced by a test (G8-M9).
2. **MUST** implement `plan_box_refs` as §7.4's three-term rule, and **MUST NOT**
   ship any fixed box-reference constant anywhere. A fixed constant has been wrong
   twice already.
3. **MUST** size M4's per-update group's transaction count from the real bitfield.
   The 2-transaction shape is insufficient at k = 8 and **MUST NOT** be the
   default.
4. **MUST** size donors by `simulate` with `n_donors = 1`, read the real consumed
   figure, then verify with a real `send_transactions` — never `simulate` alone.
   **MUST NOT** read `app-budget-added`.
5. **MUST** drive M7 with a `DonorIssuer` sibling, not 8 filler NoOps.
6. **MUST NOT** pass `allow_unnamed_resources` on the real submission path.
7. **MUST** assert `signature_slot <= slot_now + 1` before forwarding an update.
8. **MUST** default to HISTORICAL for any block that is not the newest finalized
   one, and **MUST** treat `N6` as `RETRY_REPLANNED`, not an error.
9. **MUST** call `get_anchor` (free, readonly) before planning an anchor group.
10. **MUST** classify `N13` as FATAL and `N20` as PAGE_A_HUMAN. **MUST NOT**
    auto-re-anchor on either.
11. **MUST NOT** pass an RPC-derived `receipts_root` to M7 when an `m8_app_id` is
    configured.
12. **MUST** derive every gindex, branch depth and `g_block_roots_base` from the
    on-chain fork table. **MUST NOT** hardcode any of them.
13. **MUST** chunk `install_chunk` at 8 members. `chunk_size` values that exceed
    2,048 B of arguments **MUST** be rejected by the API, not by algod.
14. **MUST** resume M4's install from on-chain `inst_cursor`. **MUST NOT** keep a
    local progress file.
15. **MUST** surface `R_ABSENT` / `R_NO_SUCH_LOG` / `R_ZERO_LOGS` as verdicts on a
    successful transaction, and **MUST** raise on `R_INCOMPLETE` as a relayer bug.
16. **MUST** work with no signer configured, up to and including `simulate`.
17. **MUST** compute `GroupPlan.total_fee_microalgo` before submission and expose
    it under `--dry-run`.
18. **MUST** decode all three log envelopes (355 / 347 / **158** B) by producer,
    asserting length before slicing.
19. **MUST** cite a real `simulate`/`send` response for every cost number in the
    implementation report (`ARCHITECTURE.md`).
20. **MUST** update `ROADMAP.md`'s M9 row to strike the stale "42-point MSM
    boundary" and the stale "Depends on: M5, M3" (§15.1, §15.2).
