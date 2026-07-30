# MPT Proof Verification on the AVM — Empirical Opcode-Budget Results

Follow-up to the BLS12-381 sync-committee spike. Same method: deploy a minimal
AVM v10 program per operation, run it through `/v2/transactions/simulate` with a
large `extra-opcode-budget`, read the **real** `app-budget-consumed` back. Every
number below traces to an actual simulate response produced by
`run_mpt_measurements.py` against `mpt_bench.py`. All verifier programs
**cryptographically pass** (`assert keccak256(node)==parent_ref` at every hop) on
real mainnet data — they are correct MPT verifiers, not cost stubs.

## Environment

- Dev-mode Algorand localnet ("future" protocol), algod `:4051`, kmd `:4052`,
  token `64×'a'`, `EnableDeveloperAPI=true` — the prior spike's harness, reused.
- AVM `#pragma version 10`. `extra_pages=3` (program cap 8192 B).
- Simulate `extra-opcode-budget = 320,000` (cap). Baseline call shows
  `app-budget-added = 320,700` = 700 base + 320,000 extra. Baseline consumed = 2.

## Real data used (nothing synthetic)

| Field | Value |
|---|---|
| RPC providers | `eth.merkle.io`, `ethereum-rpc.publicnode.com`, `eth.drpc.org` (public, no key) |
| Block | **25,639,768** (`0x1873b58`), mainnet |
| stateRoot | `0xde97a8349a6496353877597fd35732f6705ee836b2d00b6c367fa8acd2c53329` |
| receiptsRoot | `0x6490277f4254f8d51780f05201c5a9a9985a5d4c3d207a68eda643dc099e710b` |
| Contract proved | **USDT** `0xdAC17F958D2ee523a2206206994597C13D831ec7` (huge storage trie) |
| Storage holder | Binance 8 `0xF977814e90dA44bFA03b6295A0616a897441aceC` (balances slot 2) |
| storage_key | `0x0be16d71963429204d70543701f859c43526c316ac005c10114f4694ca405f36` |
| storage value | `0x3f1ca131081cf8` |
| account proof | **8 nodes**, sizes `[532,532,532,532,532,532,436,104]` (7 branch + 1 leaf) |
| storage proof | **9 nodes**, sizes `[532,532,532,532,532,468,83,83,40]` (8 branch + 1 leaf) |
| receipt proof | **3 nodes**, sizes `[308,532,690]` (2 branch + 1 leaf), tx index 31, 2 logs |

Validation anchors (all real): account node 0 `keccak256 == stateRoot`;
the full receipts trie was **rebuilt from all 137 block receipts and its root
reproduces the real `receiptsRoot` exactly**; the composite storage verifier
links `stateRoot → account leaf → storageRoot → storage leaf` and every
`assert` holds.

---

## 1. Cost table (every number = one real simulate response)

### keccak256 cost curve

| input | push-only consumed | +keccak consumed | **keccak cost** |
|---:|---:|---:|---:|
| 32 B | 5 | 135 | **130** |
| 128 B | 5 | 135 | **130** |
| 532 B | 5 | 135 | **130** |
| 1024 B | 5 | 135 | **130** |
| 4096 B | — | 135 | **130** |

**keccak256 is FLAT at 130 regardless of input size** (32 B and 4096 B cost the
same). It does not meter by byte. This is the cheap part.

### RLP branch decode in TEAL (on-chain parse, no native opcode)

Extract one child from a real 532-byte branch node (header parse + item skip
loop), whole program incl. push+callsub:

| operation | consumed |
|---|---:|
| branch → extract item[0] | 62 |
| branch → extract item[8] | 318 |
| branch → extract item[15] | 542 |

RLP-decode cost is **O(child index)** — the skip loop re-walks items from the
start, so item[15] is ~9× item[0]. There is no native RLP opcode; this is pure
TEAL.

### Full proofs (real paths, verifiers pass)

| proof | nodes | **budget consumed** | per node | program bytes | passes? |
|---|---:|---:|---:|---:|:--:|
| account (stateRoot → account leaf) | 8 | **3,276** | 409.5 | 4,144 | ✅ |
| storage, composite (stateRoot → account → storageRoot → slot) | 8+9 = 17 | **6,827** | 401.6 | 7,649 | ✅ |
| receipt/log (receiptsRoot → receipt leaf) | 3 | **1,121** | 373.7 | ~2,700 | ✅ |

### keccak vs RLP split (same real account path, isolated)

| component | consumed | share |
|---|---:|---:|
| keccak-only walk (8× keccak + compare + assert) | 1,075 | 33% |
| RLP-only walk (8× on-chain item extract) | 2,202 | 67% |
| sum | 3,277 | — |
| full account proof (measured) | 3,276 | 100% |

**RLP decoding is the dominant cost — ~2× keccak, ~67% of the per-node total.**
Optimize the TEAL RLP parser, not the hashing. (Confirms the task's suspicion
that RLP-in-TEAL is the nasty part.)

---

## 2. Single-group feasibility verdict — arithmetic shown

On-chain budget model (from the prior spike, re-confirmed here): **there is no
`extra-opcode-budget` on-chain** — that is simulate-only. Real pooled budget =
`700 × (top-level app calls + inner app calls)`. Inner txns cap = **256 per
group**, shared. A 16-txn atomic group therefore tops out at
**16 + 256 = 272 app calls = 190,400 pooled opcode budget.**

| proof | measured budget | % of 190,400 ceiling | min app-calls `⌈b/700⌉` | fits one 16-txn group? |
|---|---:|---:|---:|:--:|
| account | 3,276 | 1.72 % | 5 | ✅ (58 per group) |
| **account + storage (full state read)** | **6,827** | **3.59 %** | **10** | ✅ **(27 per group)** |
| receipt/log | 1,121 | 0.59 % | 2 | ✅ (169 per group) |

**VERDICT: a complete account+storage proof fits in a single 16-txn atomic group
with ~27× headroom.** 190,400 / 6,827 ≈ **27 independent full storage reads per
group.** Budget is nowhere near the binding constraint.

The binding per-call constraint is **program size, not budget**: one full
storage proof's embedded node constants + verifier code = 7,649 B, just under the
8,192 B cap (2 KB base + 3 extra pages). So **one app call ≈ one storage proof**.
To batch more, add worker app calls (each its own 8 KB program) or pass nodes as
app-call arguments (≤ 4096 B each) instead of embedded constants — either keeps
you inside the same group.

## 3. ALGO cost per verification

Min fee = 1000 µAlgo (0.001 ALGO) per app call, top-level or inner. Cost =
`⌈budget/700⌉` app calls (one worker + budget-donor no-op calls):

| verification | app calls needed | **cost** |
|---|---:|---:|
| account proof | 5 | **0.005 ALGO** |
| **account + storage proof** | 10 | **0.010 ALGO** |
| receipt/log proof | 2 | **0.002 ALGO** |

For scale: even reading 27 storage slots in one maxed-out group ≈ 0.272 ALGO.
State reads are ~10–40× cheaper than the sync-committee BLS update (0.11–0.28
ALGO) that produced the verified header in the first place.

## 4. Worst-case depth — does it change the verdict?

Grounded in the real USDT proof (account depth 8, storage depth 9) and Ethereum
state-trie facts: the account trie holds ~250 M+ accounts (avg depth ≈ log₁₆ ≈ 7,
sparse worst ≈ 9–10); a high-activity contract like USDT (millions of holders)
has a storage trie of comparable depth — the real proof here is already depth 9.
Realistic worst case ≈ account 10 + storage 12 = 22 nodes.

At the measured ~410 budget/node: 22 × 410 ≈ **9,020 budget = 13 app calls =
0.013 ALGO = 4.7 % of the 190,400 ceiling.** **Worst-case depth does NOT change
the single-group verdict** — even a pathologically deep read fits ~21× over in
one group, and program size (≈ one proof/call) remains the real limiter, not
budget.

## 5. Doc-gap / non-obvious-trap notes (what a naive reader gets wrong)

1. **`keccak256` is flat 130, not size-metered.** A reader expecting gas-style
   per-byte hashing would massively over-budget. 32 B and 4096 B are identical.
   Hashing is cheap; the docs' single "130" number is literally the whole story.

2. **RLP decode has no native opcode and is the real cost (~67%).** It must be
   hand-written in TEAL, and its cost is **O(branch child index)** — item[15]
   costs ~9× item[0] because the skip loop restarts from the list head each call.
   A naive "RLP decode is O(1)" assumption is wrong; batching many extractions
   from one node is where a real implementation should cache offsets.

3. **The 4096-byte value cap is a HARD RUNTIME limit, not a warning.** A 4097-byte
   `bytec` fails with `logic eval error: bytec_0 produced …`. Nodes (≤ 532 B) are
   fine, BUT — **9 of the 137 receipts in this real block RLP-encode to > 4096 B
   (max 157,274 B).** A receipt-trie *leaf* embeds the whole receipt, so for a
   log-heavy receipt you **cannot even materialize or `keccak256` the leaf node**
   → naive log proofs are **infeasible** for such receipts without restructuring
   (e.g. proving against a re-hashed sub-commitment). This is the biggest trap and
   is invisible if you only test a small receipt.

4. **No `extra-opcode-budget` on-chain — it is simulate-only.** The 6,827-budget
   storage proof looks like it "fits in 700" if you eyeball a single call; it does
   not. On-chain you only get `700 × app-calls`, pooled across the group, so you
   must add ~9 budget-donor app calls. Measuring with simulate's 320 k budget and
   forgetting this is an easy way to under-cost by 10×.

5. **Program size (8192 B), not budget, is the binding per-call constraint.** One
   full storage proof of embedded constants + parser ≈ 7,649 B ≈ one call. Budget
   headroom is 27×, but you run out of program bytes at ~1 proof/call. Plan to
   pass nodes as app-args or split across worker calls.

6. **Typed receipts (EIP-2718) break naive RLP.** A receipts-trie leaf value is
   `type_byte ‖ rlp(payload)`, **not** a pure RLP list. `rlp_decode` on the raw
   leaf value fails — you must strip the leading type byte (0x01/0x02/0x03) first
   before decoding `[status, cumGas, bloom, logs]`. Confirmed while rebuilding the
   trie (root only matched once the type-prefix was handled).

7. **`extra_pages` max is 3** (4 pages × 2048 = 8192 B) and **simulate
   `extra-opcode-budget` caps at 320,000** — both re-confirmed here
   (`app-budget-added = 320,700`).

## Bottom line

Ethereum state reads on the AVM are **cheap and single-group-feasible**: a full
account+storage proof is **6,827 opcode budget / 0.010 ALGO**, 3.6 % of one
16-txn group's ceiling, ~27 reads per group, and worst-case depth doesn't change
that. The only real hazard is **log proofs against large receipts colliding with
the 4096-byte value cap** — that needs a design workaround, not more budget.
