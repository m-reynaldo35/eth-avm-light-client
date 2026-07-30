# Empirical AVM BLS12-381 opcode-budget measurement — results

Measured 2026-07-29 against a dedicated dev-mode `algorand/algod:latest`
container (go-algorand 4.7.3, "future" consensus protocol — BLS opcodes
enabled). Every number below traces to a real `/v2/transactions/simulate`
response (see `run_measurements.py`, `probe_*.py`). "Gross" = the minimal
one-opcode program's total consumption; "isolated" = opcode-only cost after
subtracting operand-load/glue overhead.

## 1. Results table

| Operation | inputs | gross consumed | isolated opcode | published v10 |
|---|---|---:|---:|---:|
| `ec_add BLS12_381g1` | 2×G1 | 211 | 205 | 205 ✓ |
| `ec_map_to BLS12_381g1` | 1×Fp(48B) | 1955 | 1950 | 1950 ✓ |
| `ec_subgroup_check BLS12_381g1` | 1×G1 | 1855 | 1850 | 1850 ✓ |
| `ec_pairing_check BLS12_381g1` (1 pair) | 1×G1+1×G2 | 33006 | 33000 | 13000+20000 ✓ |
| `ec_pairing_check BLS12_381g1` (2 pairs) | 2×G1+2×G2 | 53006 | 53000 | 13000+40000 ✓ |
| `ec_multi_scalar_mul` (8 pts) | 768B+256B | 7266 | 7260 | 6500+95·8 ✓ |
| `ec_multi_scalar_mul` (21 pts) | 2016B+672B | 8501 | 8495 | 6500+95·21 ✓ |
| `ec_multi_scalar_mul` (42 pts) | 4032B+1344B | 10496 | 10490 | 6500+95·42 ✓ |
| `ec_multi_scalar_mul` (43 pts) | 4128B pts | FAIL | — | value >4096B |

Raw evidence (2-pair pairing): `{"app-budget-added": 320700, "app-budget-consumed": 53006}`
— `added` = 320000 extra-opcode-budget + 700 base per app call.

## 2. The 4096-byte MSM boundary

- AVM value cap is exactly 4096 bytes: pushing 4097 fails with
  `bytec_0 produced a too big (4097) byte-array`.
- 43 G1 points = 4128 bytes fails **at the push**, before `ec_multi_scalar_mul`
  even runs — it's the generic value cap, not an MSM-specific limit.
- **Maximum G1 points per `ec_multi_scalar_mul` call = 42** (42×96 = 4032B;
  43×96 = 4128B > 4096B). Matches the raw arithmetic exactly, no hidden
  encoding overhead. This is the chunk size for aggregating a 512-key
  sync committee.

## 3. Byte encoding (verified by round-trip against py_ecc, not just "no error")

- **G1 = 96 bytes uncompressed, X‖Y big-endian, no flag/compression/sign bits.**
  Confirmed by logging `ec_add`'s output and matching py_ecc's `add(P,Q)`
  byte-for-byte. Infinity = 96 zero bytes.
- **G2 = 192 bytes**, each Fp2 coordinate as `c0‖c1` big-endian, i.e.
  `X.c0‖X.c1‖Y.c0‖Y.c1` (each limb 48B). Determined empirically: only this
  limb order satisfies the pairing identity e(P,Q)·e(−P,Q)=1 via
  `ec_pairing_check`; the reversed (c1-first) order fails. Garbage/off-curve
  G2 input is rejected, proving the op actually validates.
- **MSM argument order = points-then-scalars** (points pushed first, scalars
  on top); scalars are exactly 32 bytes each. Verified 2·P1+3·P2+4·P3 against
  py_ecc byte-exact.
- **`ec_map_to BLS12_381g1` input = one 48-byte Fp**; output lands in the
  prime-order subgroup (subgroup check → 1).

## 4. Inner-app-call budget pooling & group ceiling

- Top-level pooling is linear: G app calls in a group → G×700 pooled.
  A full 16-txn group of top-level calls = 11,200 budget.
- Inner app calls also pool +700 each: outer with N inner calls →
  (1+N)×700. Verified N=0→700, 1→1400, 2→2100, 4→3500, 8→6300.
- Max inner txns per app call = 256 (N=256 → 179,900 succeeds; N=257 fails).
- The inner-txn cap is per GROUP (shared), = 256 — not per app call:
  16 outer × 16 inner = 256 total inner succeeds (190,400 budget);
  16×17 = 272 inner fails.
- **Practical ceiling of one 16-txn atomic group = 16 top-level + 256 inner
  = 272 app calls = 190,400 opcode budget.**
- Simulate's own `extra-opcode-budget` knob is capped at 320,000 — this is a
  simulate-only testing feature, it does not exist on-chain.

## 5. Sync-committee update budget (512 G1 keys)

Chunk size 42 → ⌈512/42⌉ = 13 MSM calls (12×42 + 1×8):

| Component | count | budget |
|---|---|---:|
| MSM 42-pt chunks | 12 × 10,490 | 125,880 |
| MSM 8-pt final chunk | 1 × 7,260 | 7,260 |
| combine 13 partials (`ec_add`) | 12 × 205 | 2,460 |
| hash-to-curve (`ec_map_to g1`) | 1 × 1,950 | 1,950 |
| `ec_pairing_check` (2 pairs) | 1 × 53,000 | 53,000 |
| **Total** | | **190,550** |

**App calls:** 190,550 ÷ 700 = **273 app-call transactions** (700 confirmed
as the real per-call base via `app-budget-added`).

**ALGO fee:** on-chain there is no fee-bump-for-budget — opcode budget comes
only from app-call txns (top-level or inner), each min fee 1000 µAlgo.
**273 × 0.001 = 0.273 ALGO** per update. The simulate `extra-opcode-budget`
knob does not translate to an on-chain fee mechanism.

**Feasibility:** 273 calls is 1 over the single-group ceiling of 272 → as
specified, needs 2 atomic groups. Swapping the 8-key final MSM chunk for 7
`ec_add`s saves 5,825 budget → 184,725 → **264 app calls, fits in ONE 16-txn
group, 0.264 ALGO**. A sync-committee light client is feasible on Algorand
within a single atomic group with this trivial optimization.

**Ethereum-real caveat:** Eth signatures are G2, so the message hashes to
G2 — `ec_map_to BLS12_381g2` = 8,150 (not 1,950). That raises the total to
196,750 → 282 app calls / 0.282 ALGO (≈2 groups). The table above uses the
task-specified G1 map_to; this is the honest real-world adjustment for an
actual Ethereum sync-committee implementation.

## 6. Divergence from published docs

Measured isolated costs match the go-algorand v10 cost table exactly
(ec_add 205, map_to 1950, subgroup 1850, pairing 13000+10000/96B,
MSM 6500+95/32B). Three practical traps a naive reader hits:

1. Real `app-budget-consumed` runs ~5–6 above the documented per-opcode cost
   (operand loads + program glue) — budgeting straight off the table
   under-counts slightly per call.
2. Pairing "13000 + 10000 per 96 bytes of B": for the g1 variant, B holds
   G2 points at 192 bytes each, so it's 20,000 per pair, not 10,000 — an
   easy 2× misread. (Measured: 1 pair 33,000; 2 pairs 53,000 confirm this.)
3. `extra-opcode-budget` is simulate-only and capped at 320,000 — not a way
   to buy budget on mainnet; on-chain you pay via app-call transactions
   (each 0.001 ALGO).

## Reproducing

See `README.md` for localnet bring-up. Run `run_measurements.py` for the
main table, `probe_encoding.py` for the G2 limb-order/MSM-arg-order checks,
`probe_pooling.py` / `probe_inner.py` for the group-budget-pooling findings.
`avm_bls_bench.py` is the reusable core module (algod/kmd clients, TEAL
assembly, compile, simulate-with-extra-budget, real BLS point encoders via
py_ecc) — generic enough to benchmark other AVM opcodes going forward.
