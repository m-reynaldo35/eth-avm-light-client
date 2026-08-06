# 007 — M7: Receipt & log proof verifier

**Status**: **Approved for implementation, T1/T2 scope only, 2026-08-05.** Real
population data (§14.8) showed direct on-chain coverage (T1+T2, no ZK) is 97.5%
of real receipts, and the human reviewer decided that is sufficient to ship
without T3 for now. **T3 (tiers A/B/C, the ZK path, §4 / §14.6–§14.8) is fully
designed and real-proven end-to-end — ZK-B4/ZK-B8 closed, 99.3% real coverage
ceiling demonstrated — but is explicitly NOT approved for implementation at
this time.** It stays documented and reserved: if real demand for the
oversized-receipt tail ever shows up, the design and its cost data are ready,
but no T3 contract code should be written without a separate, later approval.
Implementation of §3 (T1/T2) may proceed.

**What changed in revision 3 (the ZK spike).** Revision 2 closed with two named
blockers, ZK-B1 and ZK-B2, and its own recommendation that a short spike close both
*before* approval. **That spike has now been run, and this revision reports what it
found.** Both blockers are closed, along with three of the other five (ZK-B3, ZK-B5,
ZK-B6) and half of a fourth (ZK-B7). The headline:

> **A real PLONK proof of a real Ethereum receipt-trie leaf from the fixture block,
> generated against the real Perpetual Powers of Tau ceremony (not a `TestOnly`
> setup), was verified by an AlgoPlonk logicsig in a REAL, non-simulated submission
> to the project's own dev-mode algod — twice, once for a typed (EIP-1559) receipt
> and once for a legacy one. Measured: 185,370 logicsig budget, 2 app budget,
> 864-byte proof, 3,924-byte verifier.** (§4.12, §4.13)

Revision 3 also **corrects revision 2's coverage claim downwards** on real measured
numbers (§4.5, §4.6): the binding parameter for the largest receipts is not the leaf
size but the **largest single log** inside it, which the revision-2 projection held
fixed at 640 B. Real coverage at 2²⁴ is **97.8 %**, not the ~98.5 % implied; 99.3 %
needs **2²⁶**, not 2²⁵; and tx 119 needs **2²⁹**, not ~2²⁸. Revision 2's *mechanism*
survives the spike intact — its *arithmetic* did not, and §4.5 now carries measured
numbers from 28 real circuit compilations rather than a projection.

The spike's own artifacts live in `tests/fixtures/spike-reference/zk-m7/` and its
measurements in `bench/receipt_zk_results.json`.

**Depends on**: M2 (`rlp/core.py`, `rlp/nibbles.py`, `rlp/eip2718.py`), M5
(`mpt/walk.py`, `mpt/state.py`, `mpt/handoff.py`), M6 (segment-driver shape only —
M7 does **not** need M6's inter-walk bridge, per M6 §13.4).

**What changed in revision 2.** Revision 1 concluded that the oversized-receipt tier
(T3, leaf > 4,096 B) should be *deferred* in v1, because the only mechanism it had
found — a software Keccak-f[1600] in AVM arithmetic (§2.4, built and verified, still
correct and still in this document) — costs 3–91 **non-atomic** transaction groups per
receipt. Since then the maintainer directed that T3 be solved with **AlgoPlonk**
(`github.com/giuliop/algoplonk`), a PLONK-verifier generator for the AVM that consumes
circuits written with `gnark`. **This pass verified AlgoPlonk hands-on** — cloned it,
built it, generated verifiers, deployed them to the project's own localnet, and
measured real proof verifications (§4.1). T3 is now a **designed, priced, chosen
mechanism**, not a deferral. §4 is rewritten end to end. §2.4's software-Keccak work is
**kept in full** as the real alternative it is, and §4.9 compares the two on measured
numbers.

Revision 2 also reaches a conclusion the maintainer's framing did not anticipate, and
it is load-bearing: **the circuit must be proved on BN254, not BLS12-381** — not because
of verifier cost (a BLS12-381 verifier fits fine) but because **no BLS12-381 trusted
setup in existence is large enough for a keccak circuit of the required size** (§4.6).
This is measured, not argued.

---

## 0. The headline, stated first

`ROADMAP.md` records M7 as owning "the unsolved >4096B receipt-leaf problem", and
three prior documents state that such a leaf **cannot be hashed at all**:

- `MPT_RESULTS.md` §5.3 — "you cannot even materialize or `keccak256` the leaf node".
- `docs/design/002-rlp-decoder.md` §4.2(a) — "M7's blocker is *hashing* … the AVM has
  no streaming/incremental hash opcode. So M7 **cannot materialise or hash that leaf at
  all**".
- `docs/design/005-mpt-walker.md` §7.5 — "cannot be `keccak256`'d (no streaming hash)".

**Two of those three claims are correct and one is wrong, and this pass measured
which is which.**

Correct: there is no streaming/incremental hash *opcode*, and no box-resident hash
*opcode*. Both were verified against the real assembler and the real opcode table, not
assumed (§2). A `>4096 B` value can never be materialised on the AVM stack, so
`keccak256` — which takes exactly one stack value — can never be applied to it. Box
staging does not rescue this: `box_get` on a 32,768-byte box fails with
`box_get produced a too big (32768) byte-array`, and `box_extract` caps at 4,096
identically. Paths 1 and 3 of the task framing are, at the opcode level, closed. §2
records the literal error strings.

Wrong: "cannot be hashed at all." **Keccak-f[1600] can be implemented in AVM
arithmetic, and this pass implemented it, verified it, and measured it.** A working
software `keccak256` sponge — 25 lanes in scratch, 24 rounds looped, 1,946 bytes of
program — reproduces the native `keccak256` opcode's output on messages of 0, 100,
271, 407, 543, 1,000 and 1,350 bytes, and reproduces **a real mainnet receipt-trie
leaf's hash**: for block 25,639,768 transaction 7, the software sponge over the real
2,453-byte leaf emits
`0x3841e627edb244cc104af3e4e8112701e359426276681fa7b517314631a84623`, which is
byte-for-byte the child reference embedded in that leaf's real 500-byte parent branch
node. It also **resumes across a transaction boundary** through M5 §7.4's existing
`gtxn LastLog` hand-off and still lands on the same digest.

So the oversized receipt leaf is not a cryptographic dead end. It is a **priced**
one, and this pass produced the price:

> **14,848 opcode budget per 136-byte keccak block = 109.2 budget/byte**, versus a
> flat **130 for the whole buffer** with the native opcode. On the real 2,453-byte
> leaf that is **282,413 measured budget vs 130 — a 2,172× penalty.**

At that price the AVM's per-group ceiling (190,400 pooled budget, `MPT_RESULTS.md`
§2) absorbs **12.8 keccak blocks = 1,743 bytes of receipt per atomic group**. The
smallest oversized receipt in the reference block needs 3 groups and 0.68 ALGO; the
largest needs **91 groups and 24.5 ALGO** (§4.9). Multi-group means non-atomic, which
means a persistent session, which means a box state machine and a griefing surface
that no other module in this project has. **That is the mechanism revision 1 declined
to ship, and revision 2 still declines to ship it — but it is no longer the only
mechanism available.**

### 0.1 What revision 2 ships for T3

**A zero-knowledge proof replaces the on-chain hashing entirely.** The oversized leaf
never touches the AVM. Instead:

- M5's on-chain walker descends the receipts trie **exactly as it does today**, all the
  way to the oversized leaf's **parent** branch node — every node on that path is
  ordinary-sized, argument-delivered, and hash-verified by the existing `mpt_walk_node`.
  The walk stops holding `W.expected`: the **32-byte child reference for the leaf's
  position, taken out of a node the contract itself hashed.** Nothing about that is new
  and nothing about it is trusted.
- Off-chain, the relayer proves in a `gnark` circuit that it knows bytes `R` with
  `keccak256(R) == W.expected`, that `R` RLP-decodes (after EIP-2718 handling) to
  `[status, cumGas, bloom, logs]`, and that `logs[log_index]` is exactly the byte string
  whose `keccak256` it publishes as a public input.
- On-chain, an **AlgoPlonk-generated logicsig verifier** checks that PLONK proof, and
  M7's contract asserts the proof's public inputs equal the walker's own `W.expected`
  and the `keccak256` of the log bytes the relayer supplied in the same transaction. The
  log bytes are then decoded by **M2's existing on-chain decoder**, the same code path
  T1 and T2 use.

**Verified hands-on this pass, against real algod, not quoted from documentation**
(§4.1): an AlgoPlonk BLS12-381 verifier deployed to this project's own localnet
verifies a real PLONK proof at **181,957** opcode budget as a smart contract, and at
**221,201 logicsig budget while consuming only 40 app budget** as a logicsig once the
circuit carries the one BSB22 commitment that gnark's keccak gadget requires. That
second number is the design:

> **The PLONK verification is paid out of the AVM's *logicsig* budget pool (320,000 per
> group), which is entirely separate from the *application* budget pool (190,400).
> Verifying the proof therefore costs M7's walker and decoder essentially nothing —
> 40 of 190,400 — and the whole thing is ONE atomic group.**

Cost of T3 under this design: **~0.016 ALGO and one atomic transaction group**,
independent of leaf size — against 0.68–24.5 ALGO and 3–91 non-atomic groups for the
software sponge (§4.9). A PLONK verifier's cost does not grow with the statement it
verifies; only the relayer's proving time does (§4.7).

### 0.2 The real limit, stated as plainly as the old one was

T3 is **not** unbounded, and the bound does not come from where anyone expected. It
comes from the **trusted setup**, and this pass measured it (§4.6):

- gnark's keccak circuit costs a measured **391,602 + 224,269 × blocks** constraints.
  (Revision 3 independently re-measured the per-block coefficient and got **224,269**
  again, to the constraint — §13.1.)
- The largest BLS12-381 ceremony AlgoPlonk ships is **Dusk at 2²¹**, which buys
  **7 keccak blocks — 952 bytes.** The Ethereum KZG ceremony is 2¹⁴ and cannot hash
  even one block. **There is no BLS12-381 setup in existence big enough for this
  circuit**, so the curve is forced to **BN254**, whose Perpetual Powers of Tau ceremony
  reaches 2²⁷.
- **Revision 3, measured on the real compiled circuit** (§4.5): at **2²⁴** the circuit
  covers **6 of the 9** oversized receipts in the reference block — **134/137 = 97.8 %**
  overall. 2²⁵ reaches 98.5 %; **2²⁶ reaches 99.3 %**. Revision 2 projected 7/9 at 2²⁴
  and 99.3 % at 2²⁵; both were optimistic, for a reason revision 2 could not have seen
  without building the circuit (§4.5.3): **the tier is set by the largest single log in
  the receipt at least as often as by the leaf size.**
- The 157,283-byte leaf of transaction 119 needs **≈2²⁹** — revision 2 estimated ~2²⁸ —
  and is **out of reach of any existing ceremony** (PPOT tops out at 2²⁷). It stays
  unsupported, and stays honest: `R_INCOMPLETE`.

So coverage goes from revision 1's **93.4 %** to a measured **97.8 %** at the largest
tier this project could realistically deploy (2²⁴), or **99.3 %** at 2²⁶ — atomically,
at flat on-chain cost, with one receipt still unsupported and said so.

### 0.3 What this costs in trust, stated up front

This is the first module in the project to add a **new trust assumption**, and it must
not be buried in §4:

1. **A trusted setup.** PLONK needs a structured reference string. If the ceremony's
   toxic waste survived, forged proofs for false statements are possible. The mitigation
   is to use only a real, large, public ceremony (§4.6) — never AlgoPlonk's `TestOnly`
   setups — and this becomes **TP-M7-5**.
2. **Circuit soundness.** The RLP-decode-as-constraints (§4.4) is new code that is
   *trusted in a way M2's on-chain decoder is not*: a missing constraint silently admits
   a false statement, and no on-chain check will catch it. **TP-M7-6.**

Neither applies to T1 or T2, which are unchanged and add nothing. §6.2 traces both
adversarially and §9.5 says how they get tested.

And critically (§5.4): an *unsupported* oversized receipt still does **not** need a new
on-chain claim to be handled honestly. It falls out of M5's existing status machine as
an **incomplete walk**, which M6 §8.3 already established is not a verdict. M7 surfaces
it as a distinct `R_INCOMPLETE` result carrying the un-fetched node hash. No new trust
assumption, no silent mishandling, no fabricated fix.

---

## 1. Scope and non-goals

### 1.1 In scope

1. **Receipt inclusion**: `receiptsRoot → receipt-trie leaf` for a caller-supplied
   `tx_index`, using M5's walker with the **un-hashed** key convention
   (`mpt_key_from_tx_index`, M5 §4.2) — already implemented, already tested against
   the real 3-node fixture, never yet exercised by a consumer.
2. **EIP-2718 envelope stripping** via M2's `receipt_envelope` — built for this module
   in M2 §6 and, per M6 §13.4, still unused by M5 and M6, so M7 inherits it clean.
3. **Receipt-body decode**: `[status, cumulativeGasUsed, logsBloom, logs]`.
4. **Log extraction**: the log at a caller-supplied `log_index`, decoded to
   `(address, topics[0..n], data)`, with `n_topics` and a `keccak256` commitment to
   `data`.
5. **Three delivery paths for the terminal leaf**, unified behind one hash check:
   - **direct (T1)** — leaf ≤ 1,942 B, arrives as an ordinary application argument
     exactly as M5's branch nodes do (86.9 % of the reference block, §3.1);
   - **box-staged (T2)** — 1,942 B < leaf ≤ 4,096 B, assembled by `box_replace` across
     sibling transactions of the *same atomic group* and read back with one
     `box_extract` (6.6 %, §3.4). **Live-verified on real mainnet bytes, real
     non-simulated submission** (§3.4).
   - **zero-knowledge (T3)** — leaf > 4,096 B, never delivered on-chain at all; an
     AlgoPlonk/gnark PLONK proof establishes `keccak256(R) == W.expected` and pins the
     requested log's bytes, verified in the same atomic group by a logicsig verifier
     (§4). Bounded by circuit size / trusted-setup size, not by the AVM value cap.
6. **A defined, non-silent result for the still-unsupported case** (§5.4) — leaves
   beyond the largest deployed circuit.

### 1.2 Non-goals (explicit)

- **Oversized receipts beyond the largest deployed T3 circuit.** T3 is bounded by the
  trusted setup available (§4.6), not by the AVM. Above that bound M7 returns
  `R_INCOMPLETE`, which means *no verdict*, never *absent*. In the reference block that
  is exactly one receipt (tx 119, a 157,283-byte leaf).
- **Proving oversized receipts on-chain by software Keccak-f.** §2.4's sponge is real,
  correct and kept, but it is not what v1 ships; §4.9 gives the measured comparison and
  §12 records it as O-M7-1.
- **Receipt exclusion proofs.** M5 §11.2 already flagged that receipt exclusion is
  "only meaningful alongside a transaction-count bound M5 cannot see", and that is
  correct: proving `tx_index = k` is absent from the receipts trie says nothing unless
  you also know the block had ≤ k transactions, which lives in the *transactions*
  trie / block header, not here. M7 propagates M5's `WALK_ABSENT_*` faithfully as
  `R_ABSENT` and documents it as **not a safe negative** without that bound. Owner:
  M8/M9.
- **Bloom-filter reasoning.** The 256-byte `logsBloom` is decoded and its span is
  available, but M7 never uses it to decide anything. A bloom is a probabilistic
  filter, not a commitment; "the bloom says this topic is present" is not a proof, and
  this project does not ship probabilistic verification. M7 returns the real log or
  nothing.
- **Multi-log / batched extraction.** One log per proof in v1 (O-M7-3).
- **Returning raw `data` bytes.** `data` is unbounded; R is fixed-width and carries
  `keccak256(data)` plus `data_len` (§5.2, and O-M7-2 for the alternative).
- **Anchoring `receiptsRoot`.** M7 verifies *against* a root it is given and binds
  that root into its result so a consumer can check it. Deciding that the root is
  canonical for a block is M8's job (§8.1).
- **Transactions-trie proofs.** Same key convention, different value schema. Not v1.

### 1.3 Trust preconditions

- **TP-M7-1 (inherited from M6 §1.3/§6.6, and load-bearing).** A consumer must check
  the `receipts_root`, `tx_index` and `log_index` that R carries against what it
  actually asked for. M7 enforces this the way M6 does — by refusing to compile a
  result-reading call that omits them (`mpt7_result_from_group(gi, want_receipts_root,
  want_tx_index, want_log_index)`, §5.3). A proof that is internally perfect but about
  a different receipt is the one attack M7 cannot defeat alone.
- **TP-M7-2.** `receipts_root` must come from M8's anchor, not from the relayer. M7
  cannot tell a real root from a plausible one.
- **TP-M7-3 (M5 §1.3, restated).** M7 supplies M5 with a *preimage*
  (`tx_index: UInt64`), never a derived key. `mpt_key_from_tx_index` runs on-chain.
- **TP-M7-4 (specific to the box-staged path).** The staging box requires
  **no integrity guarantee of its own**. Its contents are validated by exactly the same
  check that validates an argument-delivered node: `keccak256(node) == W.expected`
  inside `mpt_walk_node`. This is why §3.4 is sound and why it does not re-open M5
  §7.5's objections (§3.5).
- **TP-M7-5 (new in revision 2, T3 only, and the project's first cryptographic setup
  assumption).** The PLONK structured reference string must come from a real,
  large-participant, public ceremony whose transcript this project has independently
  checked against the ceremony's own published artifacts. If the setup's toxic waste
  was retained by a single party, that party can forge a proof for a *false* statement —
  i.e. claim a log that is not in the receipt — and every on-chain check in §4.8 would
  still pass. AlgoPlonk's `TestOnlyBN254` / `TestOnlyBLS12381` setups **must never
  appear in a deployed artifact**; §9.5's ZK-3 is the gate that enforces this. T1 and
  T2 do not depend on this assumption at all.
- **TP-M7-6 (new in revision 2, T3 only).** The circuit is trusted in a way no other
  code in this project is. M2's on-chain decoder can be wrong and the wrongness is
  *visible*: it produces a bad answer that tests catch. A **missing constraint** in the
  §4.4 circuit is invisible — it silently widens the set of accepted witnesses, and no
  on-chain check can detect it, because the on-chain side only ever sees "the proof
  verified". Differential testing of the circuit against M2's own RLP oracle on real
  mainnet receipts (§9.5) is the only defence, and it is a weaker defence than the one
  T1/T2 enjoy. This is stated, not minimised.
- **TP-M7-7 (new in revision 2, T3 only).** The address of the AlgoPlonk logicsig
  verifier must be a **compile-time constant** in M7's contract. If it were a
  parameter, a relayer would supply the address of *its own* verifier, built over its
  own verifying key, and prove whatever it liked. §6.2/Z6 traces this.

---

## 2. Empirical investigation of the AVM primitives — real findings

Per `ARCHITECTURE.md`'s measurement rule, nothing in this section is quoted from
documentation. Every row below is either a literal error string from the real
assembler/evaluator or a real `/v2/transactions/simulate` response.

**Environment.** Dev-mode Algorand localnet, `algod :4051`, `kmd :4052`, token
`64×'a'`, protocol `future` (the same container the M1–M6 benches used).
`algorand-python 3.5.0`, `puya 0.6.0`, `puyapy 5.9.0`.
Simulate `extra-opcode-budget = 320,000`.

### 2.1 The complete opcode surface (not a doc reading)

`puya.ir.avm_ops.AVMOp` — the table the installed compiler targets, covering
`SUPPORTED_AVM_VERSIONS = (10, 11, 12, 13)`, `MAINNET_AVM_VERSION = 11` — contains
**147 opcodes**. Enumerated in full and filtered:

| category | complete list in the installed toolchain |
|---|---|
| hash | `keccak256`, `sha256`, `sha3_256`, `sha512_256`, `sumhash512`, `mimc` |
| box | `box_create`, `box_del`, `box_extract`, `box_get`, `box_len`, `box_put`, `box_replace`, `box_resize`, `box_splice` |

**Every hash opcode has arity 1 over a single stack value.** There is no init/update/
final triple, no permutation primitive, no box-resident hash. Confirmed a second way,
against the real assembler rather than the compiler's model — twelve plausible names
submitted to `POST /v2/teal/compile`:

```
box_hash · keccak256_init · keccak256_update · keccak256_final · sha3_init
hash_init · keccakf · keccak_f · box_keccak256 · box_sha256 · digest_init · sponge_absorb
```

all twelve → `1 error: 3: unknown opcode: <name>`. **Path 1 (a streaming-hash
primitive) and the hashing half of path 3 (a box-hash primitive) are closed at the
opcode level.**

`mimc` and `sumhash512` deserve one line each so nobody re-derives them: `mimc` is
single-shot over one stack value *and* its own stub documents known collisions ("any
input which is a multiple of the elliptic curve modulus"), so it is not a hash
function for this purpose; `sumhash512` is single-shot and is not keccak. Neither
touches the problem, which is not "produce some digest" but "produce Ethereum's".

### 2.2 The value cap, and what boxes do and do not change

| finding | how it was obtained | result |
|---|---|---|
| `MAX_BYTES_LENGTH` | `puya.algo_constants` | **4,096** |
| `MAX_BOX_BYTES_LENGTH` | `puya.algo_constants` | **32,768** |
| box size ceiling is real | `box_create(32769)` submitted | `box size too large: 32769, maximum is 32768` |
| a 32,768-byte box **can** be created | 2-transaction group supplying 16 box refs | **confirmed, real submission** |
| **`box_get` cannot return it** | `box_get` on that 32,768-byte box | `logic eval error: box_get produced a too big (32768) byte-array` |
| **`box_extract` caps identically** | `box_extract(0, 4097)` | `logic eval error: box_extract produced a too big (4097) byte-array` |
| `box_extract(0, 4096)` + `keccak256` | same box | **OK, 196 budget** |
| `box_extract(0, 136)` + `keccak256` | same box | **OK, 196 budget** — flat, confirming `keccak256` is not size-metered even off a box |

> **Path 3 is closed, definitively and with the literal error strings.** A box is a
> 32,768-byte *store*, but every read out of it is still an AVM value and every AVM
> value is still ≤ 4,096 bytes. There is no way to get a >4,096-byte object into the
> one argument `keccak256` accepts.

### 2.3 Box IO budget — a real refinement of M4 §16.5

M4 §16 measured a **2,048-byte-per-box-reference budget pooled across the atomic
group** and (§16.5) that touching a box charges its **full declared size**, not the
touched slice. This pass reconfirmed both at a much larger box size and found the
missing half of the rule:

- Reading **136 bytes** out of a 32,768-byte box needs **16 box references**, exactly
  as reading 4,096 bytes does. Measured by binary search: 14 refs → `box read budget
  exceeded`, 15 → `box read budget exceeded`, **16 → OK**. The charge is the box's
  size, not the slice. (M4 §16.5 established this for writes; it holds for reads.)
- Reads and writes draw on **separate pools**, each `2,048 × (box references in the
  group)`. Measured minimum references for a full create + write + read cycle on one
  box inside one group:

  | box size S | `ceil(2S/2048)` if pools were shared | **measured minimum refs** |
  |---:|---:|---:|
  | 1,024 | 1 | **1** |
  | 2,048 | 2 | **1** |
  | 2,453 | 3 | **2** |
  | 4,096 | 4 | **2** |

  The measured column is `ceil(S/2048)`, not `ceil(2S/2048)` — so the pools are
  separate. **This is a new finding and it is what makes §3.4 cheap**: a 4,096-byte
  staging box costs **2 of the 128 box references** available in a 16-transaction
  group, not 4.

### 2.4 Software Keccak-f[1600] — built, verified, measured

This is the finding that changes the shape of the problem, so it was built rather
than estimated.

**Construction.** State as 25 × `uint64` lanes in scratch slots 0–24 (`B` in 25–49,
`C` 50–54, `D` 55–59); θ, ρ+π, χ, ι expressed in `^ & ~ shl shr |`; rotations as
`(v shl n) | (v shr (64−n))`; the 24 round constants in one 192-byte `bytec`; **one
round unrolled inside a loop** (fully unrolling 24 rounds would be ≈ 36 KB and blow
the 8,192-byte program cap — the loop is not an optimisation, it is a requirement).

**Correctness.** All 25 output lanes asserted equal to a Python Keccak-f reference
that is itself validated against `pycryptodome` on six messages. Then the full sponge
(pad → absorb 17 lanes/block → permute → squeeze 32 bytes little-endian) asserted
equal to the **native `keccak256` opcode** in the same program:

| message | blocks | result | budget consumed | program |
|---:|---:|:---:|---:|---:|
| 0 B | 1 | **PASS** | 15,277 | 2,142 B |
| 100 B | 1 | **PASS** | 15,277 | 2,241 B |
| 271 B | 2 | **PASS** | 30,125 | 2,549 B |
| 407 B | 3 | **PASS** | 44,973 | 2,821 B |
| 543 B | 4 | **PASS** | 59,821 | 3,093 B |
| 1,000 B | 8 | **PASS** | 119,213 | 4,094 B |
| 1,350 B | 10 | **PASS** | 148,909 | 4,716 B |

**Cost, and it is perfectly linear.** Per-round cost measured at 1, 2, 3, 4, 6, 12 and
24 rounds: 591.0, 589.0, 588.3, 588.0, 587.7, 587.3, **587.2** — converging cleanly.

| quantity | **measured** |
|---|---:|
| one Keccak-f[1600] permutation | **14,092** budget |
| absorb of one 136-byte block (17 little-endian lane loads, byte-swapped) | **756** budget |
| **one full sponge block (absorb + permute)** | **14,848** budget |
| **per byte of message** | **109.2** |
| program size, looped 24-round permutation, raw TEAL | **1,946 B** |
| native `keccak256`, any size ≤ 4,096 | **130** flat |

**On real mainnet data.** The software sponge over the real 2,453-byte receipt-trie
leaf of block 25,639,768 transaction 7:

```
software digest              0x3841e627edb244cc104af3e4e8112701e359426276681fa7b517314631a84623
real parent-branch reference 0x3841e627edb244cc104af3e4e8112701e359426276681fa7b517314631a84623   MATCH
19 blocks · 282,413 budget · 14,864/block · 4,622 B program
```

**And it resumes.** A 2-transaction group in which segment 0 absorbs 10 blocks and
logs the 200-byte sponge state, and segment 1 recovers that state through **M5 §7.4's
existing `gtxn LastLog` mechanism, unmodified** and absorbs the remaining 9, lands on
the identical digest (282,708 pooled budget). The state carrier M7 would need already
exists and is already tested.

> **Conclusion of §2, stated plainly.** Path 1 is closed *as an opcode* and open *as
> software*, at a measured 2,172× penalty on the real leaf. Path 3 is closed
> completely. The choice in §4 is therefore an economic and architectural one, not a
> cryptographic one, and this document is obliged to argue it on those terms rather
> than hide behind "impossible".

---

## 3. The mechanism for ordinary receipts (leaf ≤ 4,096 B)

### 3.1 The real size distribution — the number the scope limit is drawn from

The pinned fixture `tests/fixtures/spike-reference/eth_data.json` carries all **137**
receipts of block 25,639,768. This pass rebuilt the entire receipts trie from them
and **reproduced the real `receiptsRoot`
`0x6490277f4254f8d51780f05201c5a9a9985a5d4c3d207a68eda643dc099e710b` exactly**, so
every leaf size below is a real leaf size and not a reconstruction guess.

The quantity that matters is the **terminal leaf node** size — `RLP([hp_path, receipt])`
— because that is the buffer `keccak256` must consume, not the receipt itself (the
difference is 7–9 bytes).

| tier | bound | mechanism | block 25,639,768 (137 rcpts) | block 25,658,367 (151 rcpts, fresh) |
|---|---|---|---:|---:|
| **T1** | leaf ≤ 1,942 B | argument-delivered, M5 verbatim | **119 (86.9 %)** | **137 (90.7 %)** |
| **T2** | 1,942 < leaf ≤ 4,096 B | box-staged, native `keccak256` | **9 (6.6 %)** | **10 (6.6 %)** |
| **T3** | 4,096 B < leaf ≤ tier max | **AlgoPlonk PLONK proof, logicsig-verified** (§4) | **6 of 9 at 2²⁴; 7 of 9 at 2²⁵; 8 of 9 at 2²⁶** | needs re-derivation, see below |
| — | leaf > largest deployed tier | **unsupported**, `R_INCOMPLETE` | **3 at 2²⁴** (tx 73, tx 6, tx 119); **2 at 2²⁵**; **1 at 2²⁶** | needs re-derivation |
| | **coverage T1+T2 only** | | **128 / 137 = 93.4 %** | **147 / 151 = 97.4 %** |
| | **coverage with T3 at 2²⁴** | | **134 / 137 = 97.8 %** — **real proof + real on-chain verification, §14.6** | needs re-derivation |
| | **coverage with T3 at 2²⁵** | | **135 / 137 = 98.5 %** — **real proof + real on-chain verification, §14.7** | needs re-derivation |
| | **coverage with T3 at 2²⁶** | | **136 / 137 = 99.3 %** — **real proof + real on-chain verification, §14.7** | needs re-derivation |

**Revision 3 rewrote these T3 rows on real measured numbers, and they moved down.**
Revision 2 derived them from §4.5's projected tier table, which fixed `LOGMAX = 640 B`
and varied only the leaf bound — giving "7 of 9 at 2²⁴, 8 of 9 at 2²⁵, 98.5 % / 99.3 %".
With the circuit actually compiled (§4.5.3), **a tier is a pair `(N, LOGMAX)`**, and
three of the nine oversized receipts are excluded at 2²⁴ rather than two: tx 73 (leaf
only 7,546 B but carrying a **2,368 B log**), tx 6 (15,463 B leaf, **8,061 B log**) and
tx 119. **The real numbers are 6 of 9 at 2²⁴ = 97.8 % overall**, 7 of 9 at 2²⁵ = 98.5 %,
and 99.3 % only at **2²⁶**. §4.5.3 has the per-receipt table.

The second-block column cannot be updated without re-pulling that block's receipts and
recomputing each one's largest log; it is left marked rather than silently carried over
from a superseded model. **These were arithmetic consequences of measured constraint
counts, not end-to-end measurements, when this paragraph was first written.** That is
no longer the state of the document: §14.6 and §14.7 record real, generated,
gnark-verified, and on-chain-verified proofs for one real receipt at each of 2²⁴, 2²⁵,
and 2²⁶ — closing **ZK-B4** and **ZK-B8** — so all three coverage figures above
(97.8 %, 98.5 %, 99.3 %) are now measured facts, each backed by a real accepted
Algorand transaction, not a formula. tx 119 alone remains permanently excluded: its
circuit could not even be *compiled* on a 64 GB host (OOM), independently confirming
§4.6's projection that it needs a domain (~2²⁹) beyond any Perpetual Powers of Tau
ceremony that exists (§14.7). 99.3 % is this design's real, demonstrated ceiling.

Block 25,658,367 was pulled fresh from public RPC during this pass, by the same method
as `pull_eth_data.py`, as an independent sample; further pulls were refused by the
public endpoints (HTTP 403 rate-limiting) and are honestly reported as not obtained.
**Two blocks is a small sample and this document does not claim more than two blocks'
worth of evidence.** What it does establish is that the spike's block is on the
*pessimistic* side of the two, so the 93.4 % / 97.8 % headlines are conservative. M11
should widen the sample — and note that the T3 tier makes the tail *more* important to
sample properly, not less: the size distribution above 4 KB is now what decides which
circuit tiers are worth deploying, and two blocks is a thin basis for that decision.

**M11's own ask, closed in §14.8.** A later pass pulled 300 real blocks (94,667 real
receipts, a real ~14-day span) via `eth_getBlockReceipts` against public RPC and
found the two-block sample materially overstated the tail: real T1+T2 coverage is
**97.5 %** (not 93.4 %), and only **2.2 %** of real receipts need any ZK tier at all
(not 6.6 %). The two-block fixture wasn't wrong about *mechanism* — it was
deliberately chosen to exercise engineering edge cases, not to be a population
sample, and it was never claimed to be one. See §14.8 for the full methodology and
numbers; the T1/T2/T3 *mechanism* and the per-tier bounds above are unaffected —
only how often each is invoked in the real population changes.

Supporting detail from the reference block: receipt payload sizes are
min 268 / p50 428 / p90 2,936 / p95 5,491 / **max 157,274**, and the nine oversized
receipts sit at transaction indices 1, 2, 6, 18, 35, 73, 76, 80, 119 (5,861 / 5,204 /
15,456 / 5,491 / 4,214 / 7,539 / 8,532 / 5,778 / **157,274** bytes). The distribution
is not smooth: 87.6 % of receipts fit in 2,048 bytes, but the tail runs to 38× the
value cap.

**Where the T1/T2 boundary comes from.** 1,942 B is not chosen; it is M5 §7.2's
measured argument budget: `2,048 − 4 (selector) − 101 (W) − 1 (prev gi)`. The three
underlying caps were measured live by M5 by reading the literal protocol rejections
(`tx.ApplicationArgs total length is too long. 2049 > 2048`; `too many arguments.
17 > 16`; `program logs too large` at 1,025) and are reused here rather than
re-measured.

### 3.2 The walk — M5, unchanged

M7 adds nothing to the descent. The full chain, with every entry point already
implemented and tested:

```
mpt_key_from_tx_index(tx_index)            # M5 §4.2 -- RLP(index), on-chain,
                                           #   including the index==0 -> 0x80 trap
mpt_init_state(receipts_root, key, key_nibs)
  repeat: mpt_walk_node(node_i, W)         # M5 §5 -- keccak256(node)==W.expected,
                                           #   arity-discriminate, descend by
                                           #   nibble_at(key, depth) ONLY
mpt_verify_inclusion(W, value_off, value_len)
```

`key_nibs` is `2 × len(RLP(tx_index))` — **2 for a single-byte key**, not 64. This is
the only structural difference from M6, whose §9.7 notes `key_nibs` is always 64
there. It is already handled: `mpt_init_state` takes `key_nibs` as a parameter and
right-zero-pads the key into W's fixed 32-byte field, and M5's leaf check is an exact
`depth + n_path == key_nibs` equality that works at any width.

Real worked example, from the pinned fixture: `tx_index = 31` → `RLP(31) = 0x1f` →
nibbles `(1, f)` → a 3-node proof `[308, 532, 690]` whose two branch descents are at
nibble 1 then nibble 15. M5 §5.6 already traces this end to end and
`bench/mpt_results.json` measures it (`G1_M5_receipt_inclusion: 1813`).

M5 §11.2's recorded observation that minimal-RLP receipt keys are prefix-free (no key
is a prefix of another) means the strict-prefix leaf case cannot arise from real
receipt keys. **M7 relies on this for nothing.** M5's exact-length check runs
unconditionally and is what M7 depends on, exactly as M5 §4.2 insisted.

### 3.3 From leaf value to log — the decode

Everything below operates on `(node, value_off, value_len)` **returned by the same
`mpt_walk_node` call, in the same transaction**, indexing into the same buffer. No
copy, no second delivery, no cross-transaction span. This is M2 §4.3's copy-free span
discipline being cashed in, and it is also the security property that §6.2 rests on:
after `keccak256(node) == W.expected` passes, *every byte of that buffer is fixed by
the trie*, so there is no byte-level attack surface left inside the receipt at all.

```
1. tx_type, p_off, p_len = receipt_envelope(node, value_off, value_len)      # M2 §6
      legacy      -> tx_type 0, span unchanged
      0x01..0x7f  -> typed, span advanced one byte
      (T1..T4 reject 0x00, a bare type byte, and a non-list payload)
2. rlp_scan_upto(node, p_off, want=3)  -> the logs array span (lo, ll)
      item 0 status, item 1 cumulativeGasUsed, item 2 the 256-byte bloom,
      item 3 the logs list.  Arity asserted == 4  -> "L2"
3. rlp_scan_upto(node, lo, want=log_index) -> the log span (ko, kl)
      log_index >= n_logs  -> R_NO_SUCH_LOG (a RESULT, not an assert)
4. rlp_scan2 / rlp_scan(node, ko) -> address (20 B, asserted -> "L4"),
      topics list span, data span.  Arity asserted == 3 -> "L3"
5. rlp_scan(node, topics_off) -> n_topics, asserted <= 4 -> "L5"
      (Ethereum has LOG0..LOG4; nothing else is consensus-valid)
      each topic asserted 32 B -> "L6"
6. data_hash = keccak256(data span);  data_len recorded
```

Real shape of the fixture receipt (block 25,639,768 tx 31), decoded during this pass:

```
leaf value 683 B, type byte 0x02 (EIP-1559) -> body 682 B
body items [status 1, cumGas 3, bloom 256, logs 412]
logs: 2 entries, payloads [156, 252]
  log[0]  address 20 B, 4 topics (132 B payload), data 0 B
  log[1]  address 20 B, 3 topics (99 B payload), data 128 B
```

Note `log[0]` has **four** topics and **zero** data — both boundary values, in the
pinned fixture, for free. That is the §9 headline test.

### 3.4 The box-staged path (T2) — live-verified on real bytes

For `1,942 B < leaf ≤ 4,096 B` the leaf cannot ride in one transaction's arguments,
but it is still a legal AVM value. Mechanism, all inside **one atomic group**:

```
txn i     mpt7_stage_open   box_create(name, leaf_len)          # name binds the session
txn i+1   mpt7_stage_write  box_replace(name, off_0, chunk_0)   # <= 1,900 B of args
txn i+2   mpt7_stage_write  box_replace(name, off_1, chunk_1)
txn i+3   mpt7_segment      node = box_extract(name, 0, leaf_len)
                            mpt_walk_node(node, W)              # <-- keccak256 check HERE
                            ...decode as §3.3...
                            box_del(name)
```

**Measured, on the real 2,453-byte leaf of block 25,639,768 tx 7:**

| | |
|---|---|
| group shape | 4 transactions (create, write, write, extract+hash) |
| box references | **1 per transaction = 4 in the group** (needs 2 by §2.3's rule) |
| total opcode budget for the whole staging group | **223** |
| on-chain `keccak256(box)` | `0x3841e627…31a84623` |
| real parent-branch child reference | `0x3841e627…31a84623` — **MATCH** |
| **real, non-simulated submission** | **confirmed, round 537** |

The MBR cost is real and must be stated: `2,500 + 400 × (key_len + size)` µAlgo, so
**≈ 1.65 ALGO transiently locked** for a 4,096-byte box, released by the `box_del` in
the terminal transaction. A group that aborts strands it until swept — M10's problem,
flagged in §8.3.

### 3.5 Why this does not re-open M5 §7.5

M5 §7.5 rejected boxes for proof delivery in four numbered arguments. M7 uses a box
for exactly one object in exactly one tier, and each argument either does not apply or
is answered:

- **(a) "Boxes do not solve delivery; they add to it."** Correct, and irrelevant here.
  M5's nodes each fit an argument, so a box was pure overhead. A T2 leaf **does not
  fit**, and `concat`-ing fragments does not help because AVM values cannot cross a
  transaction boundary. The box is not a faster path to the same place; it is the only
  place a 4,096-byte object can be assembled from three transactions' arguments.
- **(b) "M4's measured box economics are worse than they look."** Re-measured in
  §2.3, and better than M5 assumed: reads and writes draw on **separate** 2,048 B/ref
  pools, so a 4,096-byte box costs **2 references**, not 4. Total measured cost of the
  whole staging cycle: **223 budget**, ~6 % of the proof.
- **(c) "Minimum-balance cost."** Real, ≈ 1.65 ALGO, transient, stated in §3.4 and
  §7.3, and it is the honest reason T2 is a distinct tier rather than the default.
- **(d) "Boxes are persistent state, and persistent state is a stale-session
  hazard."** The sharpest objection, and the one §3.4's design is shaped by: the box
  lives **entirely inside one atomic group** and is deleted in the same group. There
  is no cross-group session, no `inst_state` machine, nothing to resume. If any
  transaction fails, the group fails and the box never existed. M4 needed a state
  machine because its box build-up spanned groups; M7's T2 does not.
  **T3 would** — and that is §4.9's central objection to the software-sponge route, not a
  coincidence.

And the security answer that makes all of this cheap (**TP-M7-4**): the box needs no
integrity property. Its bytes are checked by `keccak256(node) == W.expected` inside
`mpt_walk_node`, the *same* check that validates an argument-delivered node. A relayer
that writes wrong bytes into its own box produces a wrong hash and is rejected. The
box is a buffer, not a trust boundary.

---

## 4. The oversized case (leaf > 4,096 B) — the chosen mechanism: AlgoPlonk

Revision 1 designed a software Keccak-f sponge for this tier, priced it, and deferred
it. Revision 2 replaces that conclusion. The mechanism below is a **zero-knowledge
proof of the leaf's hash and contents**, generated off-chain with `gnark` and verified
on-chain by an **AlgoPlonk**-generated verifier. §4.9 compares the two on measured
numbers; §4.10 records the routes that were considered and rejected, including the ones
revision 1 already rejected, because those arguments are still correct.

### 4.1 AlgoPlonk and gnark, verified hands-on

Per `ARCHITECTURE.md`'s measurement rule, this section reports what was *done*, not what
was read. Everything below was executed in this pass.

**Environment.** Go 1.25.7 (installed for this pass; the project had no Go toolchain).
`github.com/giuliop/algoplonk` cloned at commit **`7cb897b` "Bump dependecies"**;
`go build ./...` **succeeds with no errors**. Its `go.mod` pins
`github.com/consensys/gnark v0.15.0` and `gnark-crypto v0.20.1`. Verification ran
against the **same dev-mode algod localnet the M1–M6 benches used** (`algod :4051`,
`kmd :4052`), with the project's installed `puyapy`.

**What AlgoPlonk actually generates — a real and welcome finding.** The code-generation
step (`CompiledCircuit.WritePuyaPyVerifier`) does **not** emit raw TEAL. It emits
**Algorand Python (Puya)** — the generated file opens `import algopy as py`, declares
`class Verifier(py.ARC4Contract)`, and uses `@abimethod`, `algopy.op.EllipticCurve`,
`BigUInt`, `urange`. It is then compiled by **this project's own `puyapy`**. So the
integration story is far better than "bolt a foreign artifact onto a Puya codebase":
the verifier is Puya source, compiled by the same compiler, deployable as an ordinary
app or usable as a logicsig. **Nothing about M7's existing contracts has to change
language.**

**Real verifications, real algod, real deployments.** A BLS12-381 PLONK proof over
AlgoPlonk's own Pythagorean example circuit, generated by gnark and verified by the
generated Puya verifier:

| circuit | verifier type | curve | BSB22 commitments | public inputs | **measured budget** | outcome |
|---|---|---|---:|---:|---:|---|
| Pythagoras (AlgoPlonk example) | smart contract | BLS12-381 | 0 | 2 | **181,957** app | `verified = true`, app **1742** |
| `Pub2` | smart contract | BLS12-381 | 0 | 2 | **182,248** app | `true`, app 1743 |
| `Pub4` | smart contract | BLS12-381 | 0 | 4 | **183,530** app | `true`, app 1744 |
| `Pub8` | smart contract | BLS12-381 | 0 | 8 | **186,385** app | `true`, app 1745 |
| `Pub16` | smart contract | BLS12-381 | 0 | 16 | **191,804** app | **over the 190,400 cap** |
| `Pub32` | smart contract | BLS12-381 | 0 | 32 | — | rejected: `tx.ApplicationArgs total length is too long. 2088 > 2048` |
| `Commit1` | smart contract | BLS12-381 | **1** | 2 | **221,126** app | `true`, but **over the 190,400 cap** |
| `LsigPub2` | **logicsig** | BLS12-381 | 0 | 2 | **182,321 logicsig / 40 app** | verified |
| `LsigCommit1` | **logicsig** | BLS12-381 | **1** | 2 | **221,201 logicsig / 40 app** | verified |

Derived from the measured rows, and used throughout §7:

- **Cost per public input ≈ 678** budget (fit across 2→16 public inputs).
- **Proof blob is 1,056 B** with no BSB22 commitment, **1,184 B** with one.
- Compiled **smart-contract** approval program: **4,308 B**. Compiled **logicsig**
  program: **4,285 B** (no commitment) / **4,819 B** (one commitment).
- The **logicsig opcode pool is 20,000 × (top-level transactions in the group)** and the
  filler transactions do **not** need to be logicsig-signed — AlgoPlonk's own harness
  fills with ordinary payments. So a 16-transaction group yields the full **320,000**
  logicsig budget *and* the full **190,400** app budget simultaneously.

**This independently confirms the ~185,000 figure the maintainer had from search, and
refines it**: 181,957 measured for the simplest BLS12-381 smart-contract verifier. It
also establishes the number that search did *not* surface and that decides this design —
**221,201 once the circuit carries a BSB22 commitment**.

### 4.2 Why the verifier must be a logicsig, not a smart contract

This is forced, not chosen, and the forcing fact was measured in §4.1.

gnark's keccak gadget is built on `std/math/uints`, whose range checks use a
**log-derivative lookup argument**, which compiles to **exactly one BSB22 commitment**.
Measured: *every* keccak circuit compiled in this pass, at every size, on both curves,
reports `commitments=1`. There is no configuration in which gnark's keccak has zero
commitments.

And a BLS12-381 verifier with one BSB22 commitment costs **221,126** — which is
**above the 190,400 ceiling on pooled application budget**. AlgoPlonk's README states
this outcome; this pass confirmed it by measurement rather than citation.

Therefore:

> **A smart-contract PLONK verifier cannot verify this circuit's proofs at all.** The
> logicsig verifier can: it draws on the separate **320,000** logicsig pool, consuming a
> measured **221,201** of it, and touches the application budget for only **40**.

This is not merely a workaround — it is strictly the better architecture for M7, because
it means **PLONK verification and M5's walker do not compete for the same budget**. The
walker, the decode and the result assembly keep essentially all of the 190,400 app
budget (§7.5).

### 4.3 The statement the circuit proves

Stated precisely, because everything in §6.2 depends on it.

**Public inputs** (7 field elements; a 32-byte hash does not fit in a 254-bit BN254
scalar, so each hash is split into two 16-byte big-endian halves):

| # | name | meaning |
|---|---|---|
| 0,1 | `leaf_hash_hi`, `leaf_hash_lo` | the 32-byte `expected_leaf_hash` |
| 2,3 | `log_commit_hi`, `log_commit_lo` | `keccak256(log_bytes)` |
| 4 | `log_index` | which log within the receipt |
| 5 | `path_tail` | packed `(remaining_nibble_count ‖ remaining_nibbles)` — the key suffix this leaf must consume |
| 6 | `hdr` | packed `(tx_type ‖ status ‖ cumulative_gas_used ‖ n_logs)` — the receipt-level scalars M7's `R` carries that cannot be recovered from `log_bytes` alone |

**Private witness**: the leaf bytes `R` (zero-padded to the circuit's fixed maximum
`N`), `leaf_len`, and prover-supplied offsets for each RLP header the decode crosses.

**The circuit asserts, all of it:**

1. `keccak256(R[0:leaf_len])` equals `(leaf_hash_hi, leaf_hash_lo)`.
2. `R` is `RLP([hp_path, value])` and the header arithmetic closes exactly on
   `leaf_len` — the encoding is self-delimiting, so a lie about `leaf_len` fails here
   *and* changes the digest in (1).
3. `hp_path` decodes as a **leaf** (compact-encoding prefix nibble 2 or 3, not 0/1) and
   its nibbles equal `path_tail` **exactly**, count included. **This is M5's
   `depth + n_path == key_nibs` check, relocated into the circuit**, and it is
   load-bearing: it is what distinguishes "the receipt is present at this key" from "a
   different key's leaf happens to sit at this trie position". §6.2/Z10.
4. EIP-2718 handling on `value`, mirroring M2 §6 exactly: if the first byte is `< 0xc0`
   it is a typed envelope, `tx_type` is that byte, payload starts one byte later, and
   `tx_type` must be in `1..0x7f`; otherwise `tx_type = 0` and the payload is `value`.
5. The payload is an RLP list of **exactly 4** items `[status, cumGas, bloom, logs]`,
   with `bloom` exactly 256 B.
6. `logs` is a list with `n_logs` items and `log_index < n_logs`; the item at
   `log_index` spans `(log_off, log_len)`.
7. `keccak256(R[log_off : log_off+log_len])` equals `(log_commit_hi, log_commit_lo)`.
8. `(tx_type, status, cumulative_gas_used, n_logs)` equals `hdr`.

**What the circuit deliberately does NOT do.** It does not decode the log's `address`,
`topics` or `data`, and it does not hash `data`. Those come out of **M2's existing
on-chain decoder**, run over the `log_bytes` the relayer supplies in the same
transaction and pinned by assertion (7). This is the single most important scoping
decision in §4 and it is worth stating why:

- The log is *small* even when the receipt is not — in the pinned fixture the two logs
  are 156 B and 252 B — so it fits an ordinary application argument, and where it does
  not, T2's box-staging machinery (§3.4) carries it verbatim.
- It keeps the in-circuit work to **two keccak passes and a structural walk**, instead
  of a third pass over unbounded `data`.
- It means **T1, T2 and T3 produce `R` through the same decode code**. §5.2's layout,
  §5.3's consumer API and §6's S3–S6 rows are unchanged for T3. The ZK path swaps out
  *how the bytes are authenticated*, not *how they are interpreted*.

### 4.4 The circuit, designed

gnark supplies the hard half and not the easy half, and this pass checked which is
which rather than assuming.

**Keccak: gnark has it, and it is the right one.** `std/hash/sha3` exposes
`NewLegacyKeccak256(api, opts...)`, constructed with domain-separation byte **`0x01`** —
Ethereum's Keccak-256 padding, not SHA3's `0x06`. It is backed by
`std/permutation/keccakf`. It exposes `Sum()` for a compile-time-fixed length and
**`FixedLengthSum(length)`** for a *runtime-variable* length inside a fixed-size
circuit, which is exactly what a variable-size receipt leaf needs, plus a
`WithMinimalLength` option that prunes padding logic below a known floor. All measured
in §4.5.

**RLP: gnark has nothing, and this is the part M7 must build.** There is no RLP gadget
in gnark's standard library — searched and confirmed. The design below is therefore
new work, and it is deliberately shaped by M2's `contracts/primitives/rlp/core.py` so
that the constraint system and the on-chain decoder can be differentially tested against
each other (§9.5).

**The technique: prover-supplied offsets, circuit-verified, with O(1) random access.**
A circuit cannot index a byte array by a runtime variable for free. gnark's
`std/lookup/logderivlookup` solves precisely this: build a table over `R`'s `N` bytes
once, then each subsequent read at a variable index is amortised O(1).

Measured this pass:

| table entries | queries | constraints |
|---:|---:|---:|
| 4,096 | 0 | 29,114 |
| 4,096 | 64 | 29,626 |
| 4,096 | 256 | 31,162 |
| 16,384 | 0 | 115,130 |
| 16,384 | 64 | 115,642 |
| 16,384 | 256 | 117,178 |

So the table costs **≈7.0 constraints per byte** of leaf and **≈8 constraints per
random access**. Against a keccak cost of 224,269 per 136-byte block (§4.5), **the
entire RLP navigation is rounding error** — a few hundred reads is a few thousand
constraints. This is the finding that makes §4.3's structural walk affordable, and it
is why the design does not need to resort to a bespoke arithmetisation.

**Per-step shape**, with every byte read going through the lookup table:

```
hdr_byte = T[off]
  hdr_byte <= 0x7f              -> single-byte item, payload = [off, off+1)
  0x80..0xb7                    -> short string, len = hdr-0x80,  payload = [off+1, ...)
  0xb8..0xbf                    -> long string,  len_of_len = hdr-0xb7, length read
                                   from the next len_of_len bytes (each a lookup)
  0xc0..0xf7                    -> short list,   len = hdr-0xc0
  0xf8..0xff                    -> long list,    len_of_len = hdr-0xf7
```

Each branch is a boolean selector over `cmp.IsLess` comparisons; the five cases are
combined with `api.Select`. Iterating a list to index `k` is a bounded loop of
`MAX_ITEMS` steps, each step conditionally advancing the cursor — the loop must run its
full compile-time bound (a circuit has no data-dependent control flow), with a mask
disabling steps past the real item count. `MAX_ITEMS` is 4 for the receipt body (assertion
5 fixes it exactly) and a design constant `MAX_LOGS` for the logs list.

**Two canonicality obligations that a naive constraint set would miss**, both of which
M2 already enforces on-chain and both of which must be restated in-circuit because the
circuit is the only checker on this path:

- **Minimal-length encoding.** A long-form header whose length could have been encoded
  short (`len < 56`), or with leading zero length bytes, is not canonical RLP. Ethereum
  rejects it; the circuit must too, or two distinct byte strings decode to the same
  logical receipt. (In practice the outer `keccak256` binding makes this
  non-exploitable — `R` is pinned to one exact byte string by assertion 1 — but the
  constraint is cheap and its absence is exactly the kind of silent gap TP-M7-6 warns
  about.)
- **Span containment.** Every computed `(off, len)` must satisfy
  `off + len <= parent_off + parent_len`. Without it a prover could point `log_off` past
  the end of the logs list and hash bytes from the bloom filter. This is the circuit's
  analogue of M2's bounds checks and it is **the single most important constraint in
  §4.4**; §9.5/ZK-6 tests it by construction.

**Assembling the log for the second hash.** With `(log_off, log_len)` established,
`log_bytes[j] = T[log_off + j]` for `j` in `0..LOGMAX-1` (LOGMAX a circuit constant),
masked beyond `log_len`, then hashed with a second `FixedLengthSum`. Both the lookups
and the mask are cheap; the second keccak is not, and it is priced in §4.5.

### 4.5 Circuit size — measured, and the formula

Compiled with gnark's `scs` (PLONK) builder. **Identical on BN254 and BLS12-381**, which
matters for §4.6:

| message | blocks | **nbConstraints** | commitments |
|---:|---:|---:|---:|
| 0 B | 1 | 615,871 | 1 |
| 136 B | 2 | 840,140 | 1 |
| 272 B | 3 | 1,064,409 | 1 |
| 544 B | 5 | 1,512,947 | 1 |
| 1,088 B | 9 | 2,410,023 | 1 |

Perfectly linear:

> **nbConstraints = 391,602 + 224,269 × blocks**

Variable-length hashing (`FixedLengthSum`), measured against the fixed-length baseline:

| max message | blocks | fixed-length | **FixedLengthSum** | with `WithMinimalLength` |
|---:|---:|---:|---:|---:|
| 1,088 B | 9 | 2,410,023 | 2,457,297 (+2.0 %) | 2,416,569 |
| 4,352 B | 32 | 7,568,210 | **7,997,017** (+5.7 %) | 7,799,577 (+3.1 %) |

So variable length costs ~3–6 %. Cheap, and required.

**The M7 circuit's total** — revision 2 stated the following as a projection, with a
`~50,000` term explicitly flagged as an estimate:

```
  391,602                                   base (range-check tables, paid once)
+ 237,052 x ceil((N+1)/136)                 keccak over the leaf   (224,269 x 1.057)
+ 237,052 x ceil((LOGMAX+1)/136)            keccak over the log
+ 7.0 x N                                   lookup table over the leaf
+ ~50,000                                   RLP navigation glue        [ESTIMATE]
```

**Revision 3 built the circuit and replaced this with a measured formula. §4.5.1–§4.5.3
supersede the projection above; it is kept only so the two can be compared.**

### 4.5.1 The real formula, from 28 real compilations

The circuit of §4.3/§4.4 is implemented at
`tests/fixtures/spike-reference/zk-m7/circuit/` (`receipt.go`, `rlp.go`, `assign.go`)
and compiled with `frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, …)`.
**Every number below is a real `ccs.GetNbConstraints()` from a real compile.**

Three parameters were swept independently — `N` (max leaf bytes), `LOGMAX` (max
encoded log bytes), `MAXLOGS` (how many logs the bounded loop walks):

| sweep | measurement | isolated marginal cost |
|---|---|---:|
| `N` at a **fixed keccak block count** (137→175→205→271, all 2 blocks) | 1,333,187 → 1,335,201 → 1,336,791 → 1,340,289 | **53.0 constraints / leaf byte** |
| `LOGMAX` at a fixed block count (137→175→205→271) | 1,340,421 → 1,345,437 → 1,349,397 → 1,358,109 | **132.0 constraints / log byte** |
| `MAXLOGS` (4→8→16→32) | 1,340,289 → 1,346,613 → 1,359,261 → 1,384,557 | **1,581 constraints / slot, exactly** |
| one extra keccak block (either hash) | e.g. 815 B → 1,087 B: +463,726 for 2 blocks + 272 B | **≈223,400 / 136-byte block** |

Least-squares over all 28 points, spanning **1.11 M to 16.29 M constraints**:

> ```
> nbConstraints ≈ 406,296
>               + 222,312 × ( blocks(N) + blocks(LOGMAX) )
>               +    69.4 × N
>               +   138.7 × LOGMAX
>               + 1,591.7 × MAXLOGS
>
> where blocks(x) = x // 136 + 1     (gnark always pads at least one byte)
> ```
>
> **Maximum absolute residual across all 28 points: 10,530 constraints = 0.065 %** of
> the largest measured value.

Two facts about revision 2's projection, stated plainly because both matter:

- **The `~50,000` navigation estimate was good.** At revision 2's own tier-A point
  (`N = 8,567`, `LOGMAX = 640`) the projection said ~16.5 M; the **real compile gives
  16,293,891**, 1.9 % lower. §4.4's claim that "the entire RLP navigation is rounding
  error" is confirmed: the per-byte terms (53 and 132) are dominated by gnark's
  `FixedLengthSum` padding loop, not by the lookup table's 7/byte.
- **Every circuit compiled in this pass reports `commitments = 1`**, at every size, on
  both curves. §4.2's forcing fact — that a smart-contract verifier therefore cannot be
  used — is re-confirmed on the real M7 circuit, not just on gnark's keccak in
  isolation.

**A small correction to §4.5's "identical on BN254 and BLS12-381".** At
`N = 271, LOGMAX = 136, MAXLOGS = 4` the real counts are **1,340,289 (BN254)** and
**1,340,293 (BLS12-381)** — they differ by **4 constraints**, not zero. Immaterial, but
"identical" was not measured and is not true.

### 4.5.2 Real compiled sizes for the configurations that matter

| what | `N` | `LOGMAX` | `MAXLOGS` | **real nbConstraints** | domain | status |
|---|---:|---:|---:|---:|---:|---|
| tx 85 — real typed receipt, 370 B leaf | 384 | 96 | 4 | **1,340,806** | 2²¹ | **proved + verified on-chain** (§4.13) |
| tx 8 — real **legacy** receipt, 433 B leaf | 440 | 160 | 1 | **1,795,131** | 2²¹ | **proved + verified on-chain** (§4.13) |
| tx 31 — the pinned fixture receipt, 690 B leaf | 704 | 256 | 4 | **2,273,644** | 2²² | setup + verifier built; **prover OOM on this box** |
| tx 7 — §2.4's 2,453 B leaf | 2,464 | 320 | 16 | **5,533,836** | 2²³ | compiled only |
| tx 35 — smallest oversized, 4,221 B | 4,224 | 928 | 20 | **9,530,591** | 2²⁴ | compiled only |
| **revision 2's tier A** | 8,567 | 640 | 48 | **16,293,891** | **2²⁴** | compiled — **fits, as projected** |
| **revision 2's tier B** | 18,223 | 640 | 48 | — | — | **OOM-killed at 9.06 GB RSS; not compiled** |

Tier B is an honest gap, not a failure of the design: this pass's machine has 14 GB of
RAM, of which ~5–8 GB was free. `frontend.Compile` at ~33 M constraints needs more.
The formula predicts ≈33.5 M for tier B, which is inside 2²⁵ — but that is a
**projection again**, and §4.11 keeps it flagged.

### 4.5.3 The finding that changes the coverage table: LOGMAX, not leaf size

Revision 2's tier table fixed `LOGMAX = 640 B` and varied only the leaf bound. **The
real receipts in the reference block do not respect that assumption**, and the circuit
pays 132 constraints/byte plus a whole keccak block per 136 bytes for the log hash
exactly as it does for the leaf hash. Applying §4.5.1's measured formula to **each of
the 137 real receipts** with that receipt's own real largest-log size and real log
count:

| oversized receipt | leaf | **largest single log** | n_logs | constraints | domain needed |
|---|---:|---:|---:|---:|---:|
| tx 35 | 4,221 B | 925 B | 18 | 9,526,406 | 2²⁴ |
| tx 2 | 5,211 B | 416 B | 27 | 10,428,109 | 2²⁴ |
| tx 18 | 5,498 B | 925 B | 20 | 11,619,042 | 2²⁴ |
| tx 80 | 5,785 B | 449 B | 22 | 11,353,820 | 2²⁴ |
| tx 1 | 5,868 B | 287 B | 32 | 11,353,031 | 2²⁴ |
| **tx 73** | 7,546 B | **2,368 B** | 21 | 17,743,036 | **2²⁵** |
| tx 76 | 8,539 B | 319 B | 43 | 15,784,316 | 2²⁴ |
| **tx 6** | 15,463 B | **8,061 B** | 34 | 41,334,045 | **2²⁶** |
| **tx 119** | 157,283 B | 157 B | **1,000** | 270,597,348 | **2²⁹** |

tx 73 is the clean demonstration: its leaf (7,546 B) is **smaller** than tx 76's
(8,539 B), yet it needs a **larger** tier, purely because one of its logs is 2,368 B.
tx 6 is the extreme case — an 8,061-byte log costs 60 keccak blocks on its own.

**Real coverage of the reference block, by largest deployed tier:**

| largest tier | receipts covered | coverage | revision 2 said |
|---:|---:|---:|---|
| 2²¹ | 79 / 137 | 57.7 % | — |
| 2²² | 114 / 137 | 83.2 % | — |
| 2²³ | 127 / 137 | 92.7 % | — |
| **2²⁴** | **134 / 137** | **97.8 %** | 7 of 9 oversized (would be 98.5 %) |
| 2²⁵ | 135 / 137 | 98.5 % | **99.3 %** |
| **2²⁶** | **136 / 137** | **99.3 %** | — |
| 2²⁷ (PPOT's ceiling) | 136 / 137 | 99.3 % | — |

**Revision 2's 99.3 % figure is right; the tier it attributed it to was not.** 99.3 %
requires 2²⁶, whose PPOT file is ~72 GB to download and whose proving key would not fit
on any ordinary machine. **The realistic v1 claim is 97.8 % at 2²⁴**, and §11 is updated
to say so.

**One design consequence, for whoever implements this.** A "tier" is therefore a
**pair** `(N, LOGMAX)`, not a single leaf bound, and M9's classifier must check both.
§4.8's inline `log_bytes` argument budget and the circuit's `LOGMAX` are two different
limits on the same object and must be kept consistent; a log above the inline budget
uses T2's box staging (§4.8) but still has to fit `LOGMAX` **in the circuit**, which
box staging does nothing for.

### 4.6 The trusted setup — the real binding constraint, and it is not what was expected

This is the section that changes the curve choice, and it rests on §4.5's measured
constraint counts against the setups AlgoPlonk actually ships.

**What AlgoPlonk really vendors** — verified by reading `setup/setup.go`,
`setup/doc.go` and the embedded files themselves, not the README:

| setup | curve | max constraints | ceremony |
|---|---|---:|---|
| `EthereumKzgCeremonyBLS12381` | BLS12-381 | **2¹⁴ = 16,384** | Ethereum Foundation KZG / EIP-4844, **140,000+ participants**, heavily audited |
| `DuskBLS12381` | BLS12-381 | **2²¹ = 2,097,152** | Dusk Network — Zcash's 88-participant ceremony extended by 15 more |
| `PerpetualPowersOfTauBN254` | BN254 | **2¹⁸ = 262,144** vendored (see correction below); the *ceremony* reaches **2²⁷** | Perpetual Powers of Tau (Semaphore, Hermez, Tornado Cash, snarkjs) |
| `TestOnly*` | either | any | **not a ceremony — must never ship (TP-M7-5)** |

The Dusk file's size corroborates its claim independently: `pk.bin` is **100,663,348
bytes**, which is exactly `(2²¹ + 1) × 48` — 2²¹+1 compressed BLS12-381 G1 points.

**Revision 3 correction — the vendored PPOT row said 2¹⁷ and the real number is 2¹⁸.**
`setup/PerpetualPowersOfTauBN254/pk.bin` is **16,777,188 bytes** = `4 + 524,287 × 32`,
i.e. **524,287 = 2¹⁹ − 1** compressed BN254 G1 points. `loadTrustedSetupBytes` requires
`nextPow2(nbConstraints + nbPublic) + 3` points, so the vendored file supports a PLONK
domain of **2¹⁸** — circuits up to ~262,141 constraints. AlgoPlonk's own `doc.go` says
2¹⁷, which is conservative rather than wrong, and revision 2 quoted the doc. It changes
nothing about §4.6's conclusion (2¹⁸ is still ~6× too small for a single keccak block's
615,871 constraints) but the table should be right. The Ethereum-KZG row checks out
exactly: `pk.bin` = 1,572,868 = `4 + 32,768 × 48` → 2¹⁵ points → domain **2¹⁴**.

**Now put §4.5's numbers against that table.**

- **Ethereum KZG (2¹⁴)**: a **single** keccak block costs 615,871 constraints. The
  ceremony this project would most like to use — the largest and most trusted setup in
  existence for BLS12-381 — is **37× too small to hash one block**. It is unusable here,
  and this is worth stating plainly because it is the intuitive first choice.
- **Dusk (2²¹)**: `(2,097,152 − 391,602) / 224,269 = 7.6` → **7 keccak blocks = 952
  bytes**. That is smaller than T1's 1,942-byte threshold. **Dusk cannot prove even an
  ordinary receipt leaf, let alone an oversized one.**
- **PPOT on BN254**: the ceremony reaches **2²⁷ = 134,217,728**, which is the only
  option in the table with room for a 2²⁴/2²⁵ circuit.

> **Conclusion, and it contradicts this revision's own starting premise.** The task
> framing assumed BLS12-381 because M1/M4 use it and because a BLS12-381 verifier's
> on-chain cost fits. The verifier cost *does* fit (§4.1). **The setup does not.** There
> is no BLS12-381 ceremony in existence large enough for a keccak circuit of the size
> M7 needs, so **T3 must be proved on BN254 with Perpetual Powers of Tau.**

This is not a compromise on rigour. PPOT is the more battle-tested of the two lineages
by deployment volume, and the curve used for the *proof system* has nothing to do with
the curve Ethereum uses for *sync-committee signatures* — M1/M4's BLS12-381 work is
untouched. The AVM has native BN254 operations (`ec_add BN254g1` etc.) and AlgoPlonk
generates BN254 verifiers against them; per its README a BN254 verifier is *cheaper*
than BLS12-381 (~145,000 / ~175,000 with one commitment, versus the 221,201 measured
here). **That BN254 number was not measured in this pass and must be before it is
quoted** (§4.11).

**The concrete gap this opens.** AlgoPlonk vendors PPOT only at **2¹⁸**. Using 2²⁴ or
2²⁵ requires larger PPOT parameters, which the ceremony has published. Revision 2
recorded this as blocker **ZK-B2** and the single largest implementation prerequisite
for T3. **Revision 3 closed it — §4.12 records how, including the part revision 2 got
wrong about where the extension point is.** Size note (unchanged and correct): a 2²⁴
BN254 `pk.bin` is `(2²⁴+1) × 32 B ≈ 537 MB`, which is **not vendorable in a git repo**
— M10 must fetch and checksum it, not commit it.

### 4.7 Off-chain proving cost — measured, then extrapolated honestly

Measured on this pass's machine (16 cores, 14 GB RAM), BN254, gnark PLONK:

| constraints | domain | test SRS | `plonk.Setup` | **`plonk.Prove`** | peak Go heap |
|---:|---:|---:|---:|---:|---:|
| 617,171 | 2²⁰ | 15.0 s | 2.9 s | **16.4 s** | 2.5 GB |
| 1,064,409 | 2²¹ | 30.4 s | 5.0 s | **34.1 s** | 3.7 GB |

Both proofs verified. Scaling is **≈2.08× per domain doubling**, consistent with PLONK's
O(n log n) FFT/MSM cost.

**Extrapolated — explicitly provisional, `ARCHITECTURE.md` rule applies:**

| domain | max leaf | est. prove time | est. RAM |
|---:|---:|---:|---:|
| 2²⁴ | 8.5 KB | **~5 min** | ~25–30 GB |
| 2²⁵ | 18 KB | **~10 min** | ~50–60 GB |

**This machine could not measure 2²⁴ or 2²⁵** — 14 GB of RAM is not enough, and that is
reported rather than papered over. The numbers above are extrapolation from two real
points, and §4.11 flags them.

### 4.7.1 Revision 3's real proving numbers — and a cost revision 2 missed entirely

The table above was measured with gnark's `test/unsafekzg` SRS. **With a real ceremony
file the picture changes, because loading a real SRS is not free.** Measured on the same
machine, on the real M7 circuit, against the real `powersOfTau28_hez_final_21.ptau`:

| stage | tx 85 (1,340,806 constraints, 2²¹) | tx 8 (1,795,131 constraints, 2²¹) | tx 31 (2,273,644, 2²²) |
|---|---:|---:|---:|
| `frontend.Compile` | 1.5 s | 1.9 s | 2.5 s |
| ptau → `kzg.SRS` (`gnark-ptau.ToSRS`) | 8.6 s | 7.3 s | 14.8 s |
| **`kzg.ToLagrangeG1`** | **197.8 s** | **211.0 s** | **452.9 s** |
| `plonk.Setup` | 6.3 s | 7.9 s | 13.2 s |
| `plonk.Prove` + `plonk.Verify` | **41.2 s** | **41.7 s** | **OOM-killed** |
| peak RSS | **4.02 GB** | ~4 GB | > 10 GB |
| total wall | 4 m 17 s | 4 m 30 s | — |

> **The dominant one-time cost is `kzg.ToLagrangeG1`, and revision 2 did not know about
> it.** `AlgoPlonk`'s `setup.Run` calls it on every setup. Reading gnark-crypto
> v0.20.1's implementation shows why it is so expensive: after an inverse FFT over the
> group it performs **one full 254-bit scalar multiplication on every one of the 2ⁿ G1
> points**. At 2²¹ that is 197.8 s; at 2²² it is 452.9 s, i.e. **it scales ~2.3× per
> domain doubling**, worse than proving itself. Extrapolated to 2²⁴ that is **~40
> minutes**.

**This is a setup-time cost, not a per-proof cost**, and it changes M9's architecture
advice rather than its feasibility: the Lagrange SRS and the proving key must be
computed **once per circuit tier and persisted to disk**, never recomputed per proof.
§8.2 is updated accordingly. Revision 2's "the proving key can be loaded once and reused"
was right; it just did not price what "computed once" costs.

**Honest limits of this machine.** 2²¹ proves comfortably (4.02 GB peak). **2²² does
not** — compile, `ToSRS`, `ToLagrangeG1`, `plonk.Setup` and the AlgoPlonk verifier
codegen all completed for tx 31, and `plonk.Prove` was OOM-killed. So the pinned fixture
receipt (690 B, the one Suite A uses) is **not** provable here, and §4.13's end-to-end
results use two *smaller but equally real* receipts from the same block instead. 2²⁴ and
2²⁵ remain unmeasured; ZK-B4 stays open.

**What this means for M9 (relayer).** Proving is a **minutes-scale, tens-of-GB
operation**, not a request-scoped one. M9 cannot generate an oversized-receipt proof
inside a user request. This is a genuine architectural consequence and §8.2 hands it on:
M9 needs a proving queue, a machine class that can hold 2²⁵ (a 64 GB host), and a Go
process, since gnark is Go and M9's relayer is not. Proving is also **fully
parallelisable across receipts** and the proving key can be loaded once and reused for
every proof of the same circuit tier, so throughput is a provisioning question, not a
latency-per-proof one.

Note the asymmetry that makes this worth paying: **the on-chain cost does not move.**
A 2²⁵ proof and a 2²⁰ proof are the same 1,184 bytes and the same ~221,201 logicsig
budget. All the growth is off-chain, on hardware the relayer chooses.

### 4.8 On-chain integration and hand-off

The hand-off uses **M5 §7.4 / M6 §5's existing `gtxn LastLog` mechanism, unmodified**.
No new state carrier is introduced.

**Group layout — one atomic group, ≤16 transactions:**

```
txn 0..k-1   MODE_INIT / MODE_NEXT      M7 segment driver, ordinary app calls.
                                        M5's walker descends receipts_root -> ... ->
                                        the oversized leaf's PARENT branch node.
                                        Every node hash-verified as usual. The walk
                                        ends holding W.expected = the child reference
                                        at nibble_at(key, depth) -- a value the
                                        contract READ OUT OF A NODE IT HASHED.
                                        Logs (W || R) as always.

txn k        MODE_ZK_CLOSE              app call to Mpt7App, SIGNED BY the AlgoPlonk
                                        logicsig verifier V.
                                        arg 0 "RCP1"        4 B
                                        arg 1 proof     2+864 B   <- V reads this
                                        arg 2 public_inputs 2+224 B <- V reads this
                                        arg 3 mode           1 B
                                        arg 4 prev group idx 1 B
                                        arg 5 log_bytes   <=950 B
txn k+1..15  filler / donor             ordinary payments; they exist to raise the
                                        logicsig pool to 320,000 (measured: fillers
                                        need NOT be logicsig-signed, §4.1).
```

The argument layout is forced by AlgoPlonk: its logicsig reads the proof and public
inputs from application arguments **1 and 2** (argument 0 being the ARC-4 method
selector slot, which M7's raw-args driver already occupies with `"RCP1"`). Arguments 1
and 2 are ARC-4 `DynamicArray[StaticArray[Byte,32]]`, so each carries a 2-byte length
prefix that AlgoPlonk's logicsig skips.

**Revision 3 re-derives this arithmetic on the real BN254 proof** (§4.13; revision 2
used BLS12-381's 1,184-byte proof):
`4 + (2+864) + (2+224) + 1 + 1 = 1,098`, leaving **~950 B** of the 2,048-byte cap for
`log_bytes` — half again more headroom than revision 2 assumed. Measured against real
algod, a group carrying a 92-byte log used **1,190 B** of args and one carrying a
157-byte log used **1,255 B**, both accepted. Both logs in the pinned fixture (156 B,
252 B) fit comfortably. **Logs larger than ~950 B reuse T2's box-staging path
verbatim** (§3.4) — `MODE_STAGE_OPEN` / `MODE_STAGE_WRITE` into a box in the same group,
and `MODE_ZK_CLOSE` reads it with one `box_extract`. That mechanism is already
live-verified on real mainnet bytes and needs no change. **Note the separate limit
§4.5.3 introduces**: box staging carries an oversized log *on-chain*, but the log still
has to fit the circuit's `LOGMAX` *in the proof*, and that is the binding constraint for
tx 6 and tx 73 (ZK-B9).

**What `MODE_ZK_CLOSE` asserts, in order:**

```
1.  assert Txn.Sender == V_ADDR                                  -> "L16"
       V_ADDR is a COMPILE-TIME CONSTANT (TP-M7-7). The transaction being
       signed by the logicsig is what proves the PLONK proof verified --
       the logicsig only approves if it did.
2.  assert Txn.RekeyTo == ZeroAddress                            -> "L17"
       (AlgoPlonk's logicsig also rejects rekeying; belt and braces.)
3.  W, R = mpt7_state_from_prev(prev_gi)                         -> M5's W13-W16
4.  pi = arg2, parsed as 7 x 32-byte big-endian field elements
5.  assert pi[0] || pi[1] == W.expected           (16-byte halves) -> "L13"
       *** THE BINDING. expected_leaf_hash is the walker's own output,
           never an argument. ***
6.  assert pi[2] || pi[3] == keccak256(log_bytes)                -> "L14"
       native keccak256, 130 budget
7.  assert pi[4] == R.log_index          (bound at MODE_INIT)    -> "L15"
8.  assert pi[5] == path_tail_from(W)                            -> "L18"
       contract recomputes the expected key suffix from W's key/depth/key_nibs
9.  unpack pi[6] -> (tx_type, status, cumulative_gas_used, n_logs)
10. decode log_bytes with M2 -> address, topics, data_hash, data_len
       (this is EXACTLY §3.3 steps 4-6, unchanged)
11. fill R, rstatus = R_INCLUDED
```

Step 5 is the whole security argument in one line, and step 8 is the one that is easy to
forget: without it a valid proof for a *different key's* leaf at the same trie position
would be accepted. Both are traced in §6.2.

**One verifier address per circuit tier.** Each circuit (tier A, tier B) has its own
verifying key, hence its own logicsig program, hence its own address. `Mpt7App` holds an
**immutable compile-time list** of accepted `V_ADDR` values — never a caller-supplied
one — and step 1 checks membership. Adding a tier is a contract redeployment, which is
correct: a new tier is a new audited circuit. This is a contract-versioning event and
§8.6 hands it to M12.

### 4.9 AlgoPlonk versus the software sponge — the comparison, on measured numbers

Both mechanisms are real; revision 1 built one and revision 2 measured the other. The
comparison is why §4's conclusion changed.

**Revision 3 updates the AlgoPlonk column to the real BN254 measurements** (§4.13);
revision 2's BLS12-381 figures are shown struck through in the notes, not silently
replaced.

| | **§2.4 software Keccak-f** | **§4 AlgoPlonk (BN254, measured rev. 3)** |
|---|---|---|
| on-chain cost per proof | 14,848 budget / 136 B block | **185,370 logicsig + ~3,700 app, flat** (rev. 2 said 221,201 / ~4,000 on BLS12-381) |
| … for the 4,221 B leaf (tx 35) | 475,136 budget | **~189,000, and the same for any size** |
| … for the 15,463 B leaf (tx 6) | 1,692,672 budget | **~189,000** — *but see §4.5.3: tx 6 needs a 2²⁶ circuit, so no tier this project can deploy actually covers it* |
| **transaction groups** | **3 – 91** | **1** |
| **atomic?** | **no** | **yes** |
| ALGO per proof | 0.68 – 24.5 | **~0.016** |
| persistent cross-group session | **required** (box state machine) | **none** |
| griefing surface (§4.10/A8) | **real, unique in this project** | **none** |
| new on-chain program | Keccak-f, ~2,700 B Puya, own app | AlgoPlonk verifier, **3,924 B** logicsig (rev. 2 projected 4,819 B) |
| proof blob | n/a | **864 B** (rev. 2 projected 1,184 B on BLS12-381) |
| covers tx 119 (157,283 B) | yes, at 91 groups / 24.5 ALGO | **no** |
| new trust assumption | **none** | **trusted setup + circuit soundness** |
| off-chain cost per proof | negligible | **41 s measured at 2²¹**; ~5–10 min / 25–60 GB extrapolated at 2²⁴/2²⁵ |
| off-chain cost per **tier**, one-off | none | **~18 GB download + ~40 min `ToLagrangeG1` at 2²⁴** (§4.7.1) — a cost rev. 2 did not know about |
| new language/toolchain | none | **Go + gnark** (§8.7) |

**The trade, stated honestly.** AlgoPlonk wins decisively on everything the on-chain
side cares about — one atomic group instead of 3–91, ~0.016 ALGO instead of 0.68–24.5,
no session, no griefing surface, flat cost independent of receipt size. It loses on two
axes and they are not small: it **adds two trust assumptions this project has never had**
(TP-M7-5, TP-M7-6), and it moves a large cost off-chain onto relayer hardware. It also
**cannot** do the one thing the software sponge can — tx 119's 157,283-byte leaf — because
no ceremony is large enough, whereas the sponge would grind through it in 91 groups.

The judgement, and it is the maintainer's stated decision: **atomicity and a uniform
security model are worth more than the last few percent of receipts.** Every other
module in this project produces a verdict in one atomic group with no liveness
assumption; §2.4's route is the only mechanism that would have broken that, and §4's
does not. **Revision 3 note: that "last 0.7 %" is really 2.2 %** at the 2²⁴ tier
(§4.5.3) — three receipts of 137, not one. The judgement does not change, but the
sentence it was based on was drawn from a projection.

**§2.4's work is not discarded.** It remains the correct, verified, measured description
of what AVM arithmetic can do, it is the fallback if a setup-related defect is ever found
in the PLONK path, and it is the only known route to receipts above the largest
deployable tier — which §4.5.3 now puts at **tx 73's 7,546 B leaf with its 2,368 B
log**, not at "~18 KB". §9.6's Suite K keeps it under regression test.

### 4.10 Routes considered and rejected

Revision 1's analysis of the non-ZK alternatives stands unchanged and is preserved here
because the arguments are still correct.

**Route B — a relayer-built sub-commitment. Rejected as circular.** The proposal: the
relayer builds a Merkle tree over fixed-size chunks of the receipt, publishes root `H'`,
and the contract verifies chunk paths against `H'` piece by piece. The contract then
knows chunk `i` is committed under `H'` — but `H'` is a number the relayer chose.
Nothing links it to `receiptsRoot`. To link it you must show
`keccak256(chunk_0 ‖ chunk_1 ‖ …) == the trie's child reference`, which is the original
problem verbatim. **The sub-commitment moves the trust problem; it does not solve it.**

There is one non-circular variant: commit to the **sequence of Keccak sponge states**,
then settle disagreements by interactive bisection down to a single permutation,
adjudicating that one permutation on-chain (14,092 budget). That is the Arbitrum/Cannon
fraud-proof pattern and it genuinely works. **It is rejected on trust-model grounds, not
cost**: it replaces a non-interactive proof with a bonded, challengeable, time-delayed
economic one. Note that §4's PLONK route achieves the same "don't do the work on-chain"
outcome **without** a challenge window, a bond, or a liveness assumption — which is
precisely why it is preferable to bisection.

**Route C — box staging the oversized leaf.** Closed outright (§2.2): a box holds 32,768
bytes but every read out of it is capped at 4,096. Boxes help T2 and do nothing for T3.
(They *are* reused in §4.8 for oversized *log* bytes, a much smaller object.)

**Route D — chained PLONK proofs across groups.** Considered and rejected on measured
numbers, and it is worth recording because it looks attractive. Split the leaf into
chunks, prove each chunk's sponge absorption with a small circuit chaining the 1600-bit
state as public input/output, and verify the chain. This would let a small trusted setup
(Dusk 2²¹) handle any size. It fails on group arithmetic: Dusk's 2²¹ buys **7 keccak
blocks per proof**, and the 320,000 logicsig pool fits **exactly one 221,201-budget proof
per group**. So a 4,221-byte leaf would need `ceil(32/7) = 5` groups — **worse than the
software sponge's 3**, while also carrying the ZK trust assumptions. Chaining is
strictly dominated. It is the single-proof-with-a-big-setup shape (§4.6) that wins,
because **PLONK verification cost is constant in circuit size** — the whole reason this
design works.

**Route E — recursive proof aggregation.** Aggregate many small chunk-proofs into one
using gnark's `std/recursion`. Not evaluated in depth; in-circuit PLONK verification
needs non-native field arithmetic costing millions of constraints per verified proof, so
the aggregation circuit would plausibly be larger than the flat circuit it replaces.
Recorded as O-M7-5, not designed.

### 4.11 What is NOT verified, and what would block implementation

Held to the same standard as §2.4, which built rather than estimated. This design does
not reach that bar everywhere, and the gaps are listed rather than smoothed over.

**Verified hands-on this pass** (real builds, real algod, real simulate):
AlgoPlonk builds; it emits Algorand Python; a BLS12-381 verifier verifies real proofs at
181,957 (smart contract) and 221,201 (logicsig, one commitment) measured budget; public
inputs cost ~678 each; the 190,400 cap really is exceeded by a one-commitment
smart-contract verifier and really is not by the logicsig; gnark's keccak is
Ethereum-padded and costs `391,602 + 224,269 × blocks`; `FixedLengthSum` costs +3–6 %;
`logderivlookup` costs ~7/byte and ~8/query; the vendored setups are 2¹⁴ / 2²¹ / 2¹⁷;
proving costs 16.4 s at 2²⁰ and 34.1 s at 2²¹.

**Revision 3 status of the seven blockers.** The spike revision 2 recommended has been
run. Five are closed, one is half closed, one is unchanged, and **two new ones are
opened by what the spike found**.

| # | status after the ZK spike | evidence / what remains |
|---|---|---|
| **ZK-B1** | **CLOSED** | The circuit is written (`tests/fixtures/spike-reference/zk-m7/circuit/`), compiles, and 28 real compiles give §4.5.1's measured formula. Revision 2's tier-A point really does fit 2²⁴ at **16,293,891** constraints. The consequence is **not** neutral: §4.5.3's real coverage is **97.8 % at 2²⁴**, below revision 2's projection. |
| **ZK-B2** | **CLOSED** | §4.12. Real PPOT files, real `ToSRS` conversion via the converter AlgoPlonk itself uses, real `plonk.Setup`, real verifier codegen, real proofs. **Not** by extending AlgoPlonk's `setup` package (impossible from outside — `go:embed`), but by bypassing `setup.Run` and using AlgoPlonk's exported struct and codegen directly. |
| **ZK-B3** | **CLOSED** | §4.13. BN254 logicsig verifier, 7 public inputs, 1 commitment: **185,370 / 185,454** logicsig budget, **2** app budget, **864 B** proof, **3,924 B** program. All §7's T3 budget lines should be restated from these, not from §4.1's BLS12-381 figures. |
| **ZK-B4** | **CLOSED — §14.6** | A real proof was generated and verified end-to-end at tier A's actual deployed parameters (`N=8567, LogMax=640, MaxLogs=48`, 2²⁴ domain, 16,294,913 constraints) on a real 64 GB AWS host, and separately verified **on-chain** by a real AlgoPlonk logicsig against a real dev-mode algod, with a real non-simulated submission confirmed on-chain. See §14.6 for full numbers. (Historical note, left as originally written: this pass on a 14 GB box got 2²² through compile/SRS/`Setup` before `plonk.Prove` OOM-killed, and tier B could not even compile — that finding motivated the ≥64 GB host §14.6 used.) |
| **ZK-B5** | **CLOSED for the argument layout and pool coexistence; OPEN for the M5 join** | §4.13 built the real 16-transaction group, logicsig-signed, `Txn.Sender == V_ADDR`, real app-args layout — and it works, with a **real submission**. What was **not** exercised: the same group also carrying M5's walker segments, because M7's contract does not exist yet. That is an implementation-pass test (§9.5/ZK-15), not a design risk: the logicsig consumed **2** of the app budget, so there is no contention to discover. |
| **ZK-B6** | **CLOSED** | A 3,924-byte logicsig was submitted for real (rounds 557/559/560) and confirmed. No size limit invalidates §4.2. |
| **ZK-B7** | **HALF CLOSED** | §4.12. The BN254 audit was **run**: `pk.bin` reproduces **byte for byte** from the published ceremony file. `vk.bin` reproduces only in its first 160 bytes, for an identified and benign reason (gnark-crypto now appends precomputed pairing lines). The BLS12-381 audits were not run — not needed, since T3 is BN254. TP-M7-5 additionally requires the *chosen* tier's ceremony file to be audited, which cannot happen until a tier is chosen and downloaded. |

**Two new blockers the spike opened, which did not exist in revision 2:**

| # | gap | why it matters | how to close |
|---|---|---|---|
| **ZK-B8** | **CLOSED — §14.7.** Tier B (2²⁵, `N=8567, LogMax=2560`, 19,688,551 constraints) and tier C (2²⁶, `N=16384, LogMax=8192`, 43,353,550 constraints) were both compiled AND fully proven end-to-end AND verified on-chain, on real AWS hardware. The formula's projected 98.5 %/99.3 % held up almost exactly against the real compiles. | Was: §4.5.3 attributed 98.5 %/99.3 % coverage to 2²⁵/2²⁶ on formula extrapolation alone. Now: both are measured, on-chain-verified facts. | Done. |
| **ZK-B9** | **A tier is a pair `(N, LOGMAX)`, and nothing in the design yet says how M9 picks it or what happens at the log bound** (§4.5.3). A receipt can be inside a tier's leaf bound and outside its log bound — tx 73 and tx 6 both are. | Silently choosing the wrong tier means a proof that cannot be generated, discovered at proving time (minutes) rather than classification time. `R_INCOMPLETE` (§5.4) is still the honest on-chain answer, so this is a liveness/UX gap, not a soundness one. | §5.4 + M9's classifier must key on `max(len(log_i))` as well as `leaf_len`. Design work, not measurement. |

**Recommendation, revised.** Revision 2 said ZK-B1 and ZK-B2 should close before
approval. **They have.** The mechanism is real and demonstrated end to end on real
mainnet data with a real ceremony. What remains before an implementation pass is
**ZK-B9** (a design decision this document should make, not a measurement) and, before
any coverage number is published, **ZK-B4/ZK-B8** on a bigger machine. Neither is a
reason to hold approval of the *mechanism*; both are reasons not to quote 98.5 % or
99.3 % yet. **97.8 % at 2²⁴ is now a measured-and-fitted number, not a projection**, and
even that rests on ZK-B4's un-run proof at that domain.

### 4.12 ZK-B2 closed — getting a real Perpetual Powers of Tau ceremony into AlgoPlonk

This is the section revision 2 said was "the single hard prerequisite". It is done, and
the route is simpler than revision 2 assumed — but **not the route revision 2 named.**

**Where revision 2 was wrong about the extension point.** §4.6 quoted
`setup/setup.go`'s comment ("To add a new setup you need to: … create the
`setup/<NamePath>` directory with the trusted setup files `pk.bin` and `vk.bin`") as if
that were a supported downstream operation. It is not: the files are pulled in with
**`//go:embed`**, which resolves at *AlgoPlonk's* compile time from *AlgoPlonk's* own
source tree. A consumer cannot add a setup without forking AlgoPlonk and vendoring a
537 MB blob into it — precisely the thing §4.6 says must not happen.

**The extension point that does exist, and works.** `setup.Run` is a thin wrapper whose
entire job is to produce `(srs, lagrangeSrs)` and hand them to
`plonk.Setup(ccs, srs, lagrangeSrs)`. Everything downstream of that is curve-generic:

- `algoplonk.CompiledCircuit` is a plain struct with **four exported fields**
  (`Ccs, Pk, Vk, Curve`) — it can simply be constructed.
- `verifier.WritePythonCode(vk, …)`, which `WritePuyaPyVerifier` calls, takes **any**
  `plonk.VerifyingKey`.
- `VerifiedProof.ExportProofAndPublicInputs` takes any proof/witness.

So the integration is: **build the SRS yourself from the ceremony file, call
`plonk.Setup` directly, then hand the resulting keys to AlgoPlonk's own, unmodified
code-generation and marshalling.** No fork, no patch, no vendored blob. This is what
`tests/fixtures/spike-reference/zk-m7/cmd/prove/` does, and it is the recipe M10 should
adopt.

**The converter, and the format question §4.11 raised.** Revision 2 worried about
"format incompatibility between snarkjs-style `.ptau` files and gnark's expected SRS
format". **There is none, and AlgoPlonk already knew that**: its own
`setup/PerpetualPowersOfTauBN254/audit.go` imports
**`github.com/mdehoog/gnark-ptau`**, whose `ToSRS(io.Reader)` reads a snarkjs `.ptau`
(header + `tauG1` + `tauG2` sections) straight into a `gnark-crypto` `kzg.SRS`,
checking every point is on-curve as it goes. It is a real, small, readable dependency
and it is the one AlgoPlonk's maintainer chose.

**The ceremony files.** Canonical public host, the one AlgoPlonk's `doc.go` links:
`https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_<NN>.ptau`.
Downloaded and used in this pass:

| file | bytes | note |
|---|---:|---|
| `powersOfTau28_hez_final_18.ptau` | 302,072,984 | audit reference (sha256 `e970efa7…ac694`) |
| `powersOfTau28_hez_final_21.ptau` | 2,416,002,200 | **used for both real end-to-end proofs** |
| `powersOfTau28_hez_final_22.ptau` | 4,831,921,304 | used for tx 31's setup |
| `…_23 / _24 / _25` | 9,663,759,512 / 19,327,435,928 / 38,654,788,760 | sizes confirmed by HTTP HEAD, not downloaded |

At the ~8 MB/s this pass measured, the 2²⁴ file is a ~40-minute download. That is a
provisioning fact for M10, not a blocker.

**ZK-B7, half-closed as a bonus.** Revision 2 recorded that AlgoPlonk's audit
procedures were "read but not run". **This pass ran the BN254 one.** Regenerating
`pk.bin` from the published `powersOfTau28_hez_final_18.ptau` reproduces AlgoPlonk's
vendored file **byte for byte**:

```
  ours:     16,777,188 B   sha256 470491b2205f3459d9aae9062585f8138c0297c2bbd51fe42ad145d297cd86e5
  vendored: 16,777,188 B   sha256 470491b2205f3459d9aae9062585f8138c0297c2bbd51fe42ad145d297cd86e5
```

**`vk.bin` does not byte-match, and the reason is benign and worth recording** because
anyone re-running this audit will hit it. Ours is 33,952 B; the vendored file is 160 B;
**the first 160 bytes are identical.** `gnark-crypto` v0.20.1's
`kzg.VerifyingKey.WriteTo` now serialises 66 × 4 **precomputed pairing lines** after the
three points, which the older version AlgoPlonk generated its file with did not. Two
follow-on observations, both real:

1. AlgoPlonk's `trustedSetupBN254` calls `srs.Vk.ReadFrom(...)` and **discards the
   error**, so the 160-byte file loads `G2[0]`, `G2[1]`, `G1` correctly and leaves
   `Lines` zeroed. Empirically this does not break anything — all four vendored setups
   (`PerpetualPowersOfTauBN254`, `DuskBLS12381`, `EthereumKzgCeremonyBLS12381`,
   `TestOnlyBN254`) were compiled, proved and verified in this pass and **all four
   pass**. It is nonetheless a swallowed error in a trusted-setup loader, and M12 should
   note it if this project ever pins AlgoPlonk as a dependency.
2. The audit procedure as written in `audit.go` therefore **cannot** pass byte-equality
   on `vk.bin` under AlgoPlonk's own pinned gnark-crypto. ZK-B7 should be restated as
   "reproduce `pk.bin` byte-for-byte and `vk.bin`'s first 160 bytes" — which is what
   this pass did and what `tests/fixtures/spike-reference/zk-m7/` records.

### 4.13 ZK-B1, ZK-B3, ZK-B5, ZK-B6 closed — the real end-to-end run

Two **real, non-simulated** submissions to the project's own dev-mode algod
(go-algorand 4.7.3, `:4051`/`:4052`, `tests/fixtures/spike-reference/README.md`'s
recipe). Both use **real receipt-trie leaves from block 25,639,768**, extracted by
rebuilding the block's receipts trie from the pinned `eth_data.json` and checking the
root reproduces `0x6490277f…099e710b` (it does — this also independently re-confirms
§2.4's tx-7 digest `0x3841e627…31a84623`).

| | **tx 85** | **tx 8** |
|---|---|---|
| receipt kind | **EIP-2718 typed, type 2** (EIP-1559) | **legacy, type 0** — the other envelope branch |
| real leaf | 370 B, 1 log (92 B) | 433 B, 1 log (157 B) |
| real leaf hash | `0x2ef46a02…d2f06d` | `0xf9486109…163e44` |
| circuit | `N=384, LOGMAX=96, MAXLOGS=4` | `N=440, LOGMAX=160, MAXLOGS=1` |
| **nbConstraints / commitments** | **1,340,806 / 1** | **1,795,131 / 1** |
| PLONK domain | 2²¹ | 2²¹ |
| **trusted setup** | **real PPOT `_21`, 4,194,303 G1 points — NOT `TestOnly`** | same |
| `plonk.Prove` + `plonk.Verify` (off-chain) | **41.2 s** | **41.7 s** |
| **proof size** | **864 B** | **864 B** |
| public inputs | **224 B = 7 × 32** | 224 B |
| **compiled logicsig verifier** | **3,924 B** | 3,924 B |
| total application-args | 1,190 B (cap 2,048) | 1,255 B |
| **logicsig budget consumed** | **185,370** | **185,454** |
| **app budget consumed** | **2** | **2** |
| **REAL submission** | **confirmed, round 557 / 559** | **confirmed, round 560** |
| tampered public input (1 bit) | **`rejected by logic`** | **`rejected by logic`** |

Public inputs were checked against the real data independently of the proof: public
inputs 0‖1 reassemble to the real `keccak256(leaf)` and 2‖3 to the real
`keccak256(log_bytes)`, and `hdr` unpacks to `(tx_type=2, status=1,
cumulativeGasUsed=17,821,206, n_logs=1)` for tx 85 — all matching the raw receipt.

**What each of these closes:**

- **ZK-B1** — the circuit exists, compiles, and its real constraint counts are in
  §4.5. Closed.
- **ZK-B3** — **the BN254 verifier is now measured: 185,370 logicsig budget for 7
  public inputs and one BSB22 commitment**, against 221,201 measured for BLS12-381 in
  §4.1. BN254 is **~16 % cheaper**, confirming AlgoPlonk's README claim (~175,000) in the
  right direction and refining it — the README's number is for 2 public inputs, and
  §4.1's ~678/public-input rate accounts for most of the difference. Closed.
  The two rows also show the verifier's cost is **very slightly proof-data dependent**
  (185,370 vs 185,454, a 0.05 % spread on identical circuit shape) — worth knowing before
  anyone pins an exact budget constant.
- **ZK-B5** — the logicsig-signed app call is real: `Txn.Sender` **is** the verifier's
  address, the group is 16 transactions (1 logicsig + 15 ordinary payments, which need
  no logicsig signature, as §4.1 found), and the app-args layout of §4.8 fits with room
  to spare. Closed for the argument-layout and pool-coexistence half; see §4.11 for what
  is still not exercised.
- **ZK-B6** — a **3,924-byte logicsig program submitted for real and confirmed**, so
  there is no size limit that invalidates §4.2. Closed.

**Two real corrections to §4.8's arithmetic, both in the design's favour.** The BN254
proof is **864 bytes, not 1,184** (BN254's G1 is 32 B where BLS12-381's is 48 B; the
proof is `24 + 3 × commitments = 27` field elements). So §4.8's budget line becomes
`4 + 2 + 864 + 2 + 224 + 1 + 1 = 1,098` of the 2,048-byte cap (the +2s are the ARC-4
`DynamicArray` length prefixes AlgoPlonk's logicsig expects), leaving **~950 B for
`log_bytes`, not 634 B**. And the compiled logicsig is **3,924 B, not 4,819 B**.

### 4.14 Circuit-level soundness testing, run this pass

The circuit's constraints were evaluated directly with gnark's `test.IsSolved` engine —
no setup, no proving, so the whole real corpus is cheap. Design doc §9.5's ZK-1 and
ZK-6/7/9/10 were run for real:

| test | result |
|---|---|
| **ZK-1** — every receipt in block 25,639,768 with ≥ 1 log and leaf ≤ 4,300 B, each with a tier sized to that receipt's own real largest-log size and real log count. Includes §2.4's 2,453 B tx-7 leaf and **tx 35, the smallest oversized receipt (4,221 B, 18 logs, 925 B largest log)**. 40 of the 137 are skipped: 32 have no logs at all, 8 exceed 4,300 B. | **97 / 97 satisfied, 0 failed** |
| baseline honest witness | satisfied |
| **ZK-9** wrong `leaf_hash` (hi half + 1) | **rejected** |
| **ZK-10** wrong log commitment | **rejected** |
| **ZK-10** wrong `log_index` (commitment still describes log 0) | **rejected** |
| **ZK-7** wrong `path_tail` | **rejected** |
| wrong `hdr` (n_logs off by one) | **rejected** |
| truncated `leaf_len` | **rejected** |
| one flipped byte anywhere in `R` | **rejected** |
| **ZK-6 span containment** — target log's bytes taken from **inside the 256-byte bloom filter**, with a log commitment that genuinely matches those bytes | **rejected** |

ZK-6 is the one that mattered most: §4.4 calls span containment "the single most
important constraint" and warns its absence would be undetectable on-chain. It is
present and it holds against a witness built specifically to exploit its absence.

**Not yet run**: ZK-8 (non-canonical long-form RLP) has the constraints implemented in
`rlp.go`'s `header()` — minimal-length (`len ≥ 56` for long form), no leading zero
length byte, and the 1-byte-short-string-should-have-been-a-single-byte rule — but no
negative witness was constructed for it this pass. §4.11 keeps it open.

---

## 5. Interface

### 5.1 Shape — M6 §6.1's driver, not M6 §5's bridge

Per M6 §13.4, a receipt proof is a *single* walk from a single root; there is no
second trie and therefore no inter-walk bridge. M7 reuses M6's **segment driver
shape**: raw application arguments, one fixed 4-byte selector `RCP1`, one mode byte,
`(W ‖ R)` logged and recovered through `gtxn LastLog`.

```
arg 0 : selector "RCP1"                                   4 B
arg 1 : mode                                              1 B
arg 2 : prev group index (ignored in MODE_INIT)           1 B
arg 3 : mode-specific fixed fields                     (varies)
arg 4..15 : proof nodes / staging chunk            <= remaining
```

**`MODE_ZK_CLOSE` is the one exception to this layout**, and the exception is forced by
AlgoPlonk: its generated logicsig reads the PLONK proof and public inputs from
application arguments **1 and 2**. That transaction therefore uses
`[selector, proof, public_inputs, mode, prev_gi, log_bytes]` — see §4.8 for the full
arithmetic against the 2,048-byte argument cap.

| mode | meaning |
|---|---|
| `MODE_INIT` | build `W` from `(receipts_root, tx_index)` on-chain; walk supplied nodes |
| `MODE_NEXT` | recover `(W, R)` from the previous segment's log; walk supplied nodes; on the terminal node, decode and fill `R` |
| `MODE_STAGE_OPEN` | T2/T3: `box_create(name, len)` — the leaf (T2) or oversized `log_bytes` (T3) |
| `MODE_STAGE_WRITE` | T2/T3: `box_replace(name, off, chunk)` |
| `MODE_STAGE_WALK` | T2 only: `box_extract` the leaf, walk it, decode, `box_del` |
| `MODE_ZK_CLOSE` | **T3 only (new in revision 2)**: transaction signed by the AlgoPlonk logicsig verifier; binds the PLONK proof's public inputs to the walker's `W.expected`, then decodes the supplied `log_bytes`. Full assertion order in §4.8. |

`MODE_INIT`'s fixed fields are `receipts_root (32) ‖ tx_index (8) ‖ log_index (2)`.
`log_index` is bound at open so it appears in `R` and cannot be chosen after the
relayer has seen which logs exist.

### 5.2 The result `R` — fixed width, self-describing

Following M6 §3.3's `C`: fixed width, carries everything a consumer needs to check
that this proof is about what it asked for.

| offset | len | field |
|---:|---:|---|
| 0 | 1 | `rstatus` (§5.4) |
| 1 | 32 | `receipts_root` — bound at `MODE_INIT`, TP-M7-1 |
| 33 | 8 | `tx_index` — the preimage the key was derived from |
| 41 | 2 | `log_index` — which log this result is about |
| 43 | 1 | `tx_type` — EIP-2718 type byte; 0 = legacy |
| 44 | 1 | `status` — receipt status (0 = reverted, 1 = success) |
| 45 | 8 | `cumulative_gas_used` |
| 53 | 20 | `address` — the emitting contract |
| 73 | 1 | `n_topics` (0–4) |
| 74 | 128 | `topics[4]`, 32 B each, zero-padded beyond `n_topics` |
| 202 | 32 | `data_hash` = `keccak256(log.data)` |
| 234 | 4 | `data_len` |
| 238 | 1 | `wstatus` — M5's terminal `WALK_*` code, for auditability |
| 239 | 1 | `n_logs` — total logs in the receipt (so `R_NO_SUCH_LOG` is explicable) |
| | **240** | |

Log payload: `0x151f7c75 ‖ len(2) ‖ W(101) ‖ R(240)` = **347 bytes**, inside M5's
measured 1,024-byte log cap and directly comparable to M6's 355.

`data_hash` rather than `data`: log data is unbounded, and R must be fixed width to
keep the recovery arithmetic constant-offset (M5 §3.2's rule). A consumer that needs
the bytes supplies them and checks the hash. O-M7-2 records the variable-width
alternative.

### 5.3 What a caller supplies and gets back

```python
mpt7_result_from_group(gi, want_receipts_root, want_tx_index, want_log_index)
    -> (rstatus, address, n_topics, topics, data_hash, data_len, status, tx_type)
```

The three `want_*` parameters are **mandatory**, for M6 §6.6's reason: TP-M7-1 is a
check the consumer must perform and the cheapest way to make it unforgettable is to
refuse to compile without it. Internally it asserts `R.receipts_root ==
want_receipts_root` ("L11"), `R.tx_index == want_tx_index` ("L11"), `R.log_index ==
want_log_index` ("L11"), and that the walk actually finished ("L10").

### 5.4 `rstatus` — including the honest answer for oversized receipts

| value | name | meaning | is it a verdict? |
|---:|---|---|---|
| 0 | `R_INCOMPLETE` | the walk did not reach a terminal node — the caller did not (or could not) supply the next node | **NO. Not a verdict.** |
| 1 | `R_INCLUDED` | the receipt is in the trie and the log at `log_index` was extracted | yes |
| 2 | `R_ABSENT` | M5 returned a `WALK_ABSENT_*` terminal | yes, **but see §1.2** |
| 3 | `R_NO_SUCH_LOG` | receipt proven; `log_index >= n_logs` | yes |
| 4 | `R_ZERO_LOGS` | receipt proven; it emitted no logs at all | yes |

**This is where an oversized receipt lands *when it is beyond the largest deployed T3
circuit*, and it is the part of this design most worth reading carefully.**

Revision 2 note: with §4's mechanism, an oversized leaf inside a deployed circuit tier
returns **`R_INCLUDED` like any other receipt** — T3 is not a distinct result, only a
distinct *route to the same result*. `R_INCOMPLETE` now covers only leaves above the
largest tier (in the reference block, exactly tx 119's 157,283-byte leaf). The reasoning
below is unchanged and still governs that residual case.

A tempting design would give oversized receipts their own status —
`R_UNSUPPORTED_OVERSIZED` — so the interface "says something". **That would be
unsound**, and the reason is instructive. To emit such a status M7 would have to
*know* the terminal node exceeds 4,096 bytes. It cannot: it holds a 32-byte hash of a
node it has never seen. Its only source for "that node is big" would be the relayer's
word — and a status derived from an unverified relayer claim is precisely the defect
class M5 exists to prevent. A relayer could then mark any inconvenient receipt
"oversized" and have the contract co-sign it.

So M7 does not invent a status. An oversized receipt produces a walk that reaches the
last branch node, learns a 32-byte child reference, and **stops, because the node
behind that reference was never supplied**. That is M5's ordinary `WALK_CONTINUE`
state, and M6 §8.3 already ruled on what it means: *an incomplete walk is not an
exclusion proof.* M7 surfaces it as `R_INCOMPLETE`, carrying `W.expected` — the hash
of the node that could not be fetched — so a caller can see exactly where the walk
died and, off-chain, look that node up and discover why.

**`R_INCOMPLETE` therefore covers three situations that are indistinguishable
on-chain and must not be conflated by a consumer:** the relayer supplied too few
nodes; the relayer supplied a wrong node (that fails "W11" instead, actually — so:
the relayer stopped early); or the terminal node is physically undeliverable because
it exceeds the value cap. The contract cannot tell them apart and does not pretend to.
The relayer (M9) *can* tell them apart off-chain — it can see the node — and §8.2
makes reporting this M9's job.

This is the "defined unsupported result, not silence" the module was required to
produce, and it costs no new trust assumption, no new opcode, and no new code path:
it is M5's existing status machine used honestly.

### 5.5 Error codes (`L*`)

`R*`/`H*`/`T*` are M2's, `W*` M5's, `A*` M6's. M7 takes `L*` (log).

| code | meaning |
|---|---|
| L1 | leaf value is empty (a receipts-trie leaf never is) |
| L2 | receipt body arity is not 4 |
| L3 | log arity is not 3 |
| L4 | log address is not 20 bytes |
| L5 | topic count > 4 |
| L6 | a topic is not 32 bytes |
| L7 | staging: declared `leaf_len` > 4,096 or ≤ 1,942 (wrong tier for this mode) |
| L8 | staging: write range outside the declared box |
| L9 | *(reserved for the §2.4 software-sponge route)* streaming close: digest ≠ `expected_leaf_hash` |
| L10 | `mpt7_result_from_group`: walk not terminal |
| L11 | `mpt7_result_from_group`: `want_*` mismatch (TP-M7-1) |
| L12 | segment finished with unconsumed trailing node arguments |
| **L13** | **T3**: proof public inputs 0,1 ≠ `W.expected` — *the binding* (§4.8 step 5) |
| **L14** | **T3**: proof public inputs 2,3 ≠ `keccak256(log_bytes)` (§4.8 step 6) |
| **L15** | **T3**: proof public input 4 ≠ the `log_index` bound at `MODE_INIT` |
| **L16** | **T3**: `Txn.Sender` is not an accepted verifier logicsig address (TP-M7-7) |
| **L17** | **T3**: the `MODE_ZK_CLOSE` transaction sets `RekeyTo` |
| **L18** | **T3**: proof public input 5 ≠ the key suffix recomputed from `W` (§4.8 step 8) |

---

## 6. Adversarial trace

### 6.1 The T1 / T2 path

M7's argument- and box-delivered paths inherit M5's descent wholesale, so §6.1 does not re-litigate the
branch-index attack (M5 §5.2) or the strict-prefix leaf attack (M5 §5.4). What is new
in M7 is **the decode**, and that is where a relocated version of M5's original bug
would live.

| # | attack | outcome | why |
|---|---|---|---|
| S1 | Supply the leaf for a different `tx_index` | **rejected** | key is `mpt_key_from_tx_index(tx_index)` derived on-chain from the preimage; M5's exact-length leaf check binds it. |
| S2 | Supply a genuine receipt from a different block | **rejected at the consumer** | `R.receipts_root` is bound at `MODE_INIT` and TP-M7-1 forces the check. M7 alone cannot detect it; that is M8's job (§8.1). |
| S3 | **Ask for log 0 and be handed log 3's bytes** | **rejected** | this is M5's bug relocated into the receipt body, and it is defeated the same way: the log span is derived by `rlp_scan_upto(node, logs_off, want=log_index)` walking the real RLP structure, and `log_index` is echoed into `R` and checked by TP-M7-1. **There is no parameter anywhere in §3.3 that lets a caller supply an offset or a span.** Any implementation that adds one is a critical defect. |
| S4 | Tamper with a byte inside the receipt (status, an address, a topic) | **impossible** | after `keccak256(node) == W.expected` the entire buffer is fixed by the trie. There is no byte-level attack surface inside a hash-verified node. |
| S5 | Present a legacy receipt as typed, or vice versa | **rejected** | `receipt_envelope`'s T1–T4 (M2 §6.1: within the receipts trie a legacy payload is always a list > 55 B because the bloom alone is 256 B, so `first byte < 0xc0 ⟺ typed`, no ambiguity). And S4 applies: the bytes are already fixed. |
| S6 | Claim more topics than exist, or a 31-byte topic | **rejected** | "L5"/"L6", and S4. |
| S7 | Write different bytes into the T2 staging box than the real leaf | **rejected** | `keccak256(box_extract(...)) == W.expected` — the identical check an argument-delivered node faces (TP-M7-4). |
| S8 | Race another submitter's T2 staging box | **impossible** | the box is created, filled, read and deleted inside one atomic group; nothing else can interleave. |
| S9 | Point `MODE_NEXT` at a different segment's log | **rejected** | M5 §7.4's `mpt_state_from_prev` checks (W13–W16) apply unchanged: the log is the AVM's own execution record for an earlier transaction in this same group. Pointing at the wrong one yields a `W`/`R` naming a different `(root, tx_index)`, which TP-M7-1 catches. |
| S10 | Claim `R_ABSENT` for a receipt that exists | **rejected** | M5's `WALK_ABSENT_*` codes are produced by real divergence checks, not by a caller. |
| S11 | Use `R_INCOMPLETE` to suppress a log | **cannot produce a false verdict, but is a real liveness attack** | `R_INCOMPLETE` is explicitly not a verdict (§5.4). A relayer can always refuse to relay; no light client design prevents that. What matters is that it cannot make the contract *assert* absence, and it cannot. |

**Verdict: the supported path holds up.** S3 is the one that would silently re-create
M5's original defect and it is called out as a structural rule (no caller-supplied
spans) rather than a runtime check. S2 and S11 are real and are honestly out of M7's
reach — they belong to M8 and to the relayer model respectively.

### 6.2 The T3 / zero-knowledge path

Same standard as M1's T12, M4's adversarial table, M5 §5.4 and M6 §5.4. The attacker is
a relayer that fully controls every argument, every transaction, and the entire proving
process — it chooses the witness, runs the prover, and may write its own circuit.

| # | attack | outcome | why |
|---|---|---|---|
| Z1 | Submit a **valid** PLONK proof whose `expected_leaf_hash` public input is a hash of the attacker's choosing | **rejected** | "L13". `W.expected` is not an argument: it is read out of the parent branch node **that the walk already hash-verified**, in this same group, recovered through M5's `gtxn LastLog` hand-off. A proof about any other leaf simply fails the comparison. This is the single check the whole design rests on (§4.8 step 5). |
| Z2 | Reuse a proof generated for a **different receipt** | **rejected** | that proof's public inputs carry the other receipt's leaf hash → Z1. |
| Z3 | Reuse a proof for the **same** receipt in a later group | **accepted, and harmless** | it is a true statement about the same leaf, and it is only accepted if this group's walker independently produced the same `W.expected` — which means the same receipt under the same root. Exactly the sense in which M5's node arguments are replayable. Not a defect. |
| Z4 | Supply a genuine proof but **forged `log_bytes`** | **rejected** | "L14": `keccak256(log_bytes)` must equal public inputs 2,3, which the circuit bound to the real log's bytes. Native `keccak256`, 130 budget. |
| Z5 | Supply a genuine proof and genuine bytes, but for a **different log** of the same receipt | **rejected** | "L15": `log_index` is bound at `MODE_INIT`, before the relayer has seen which logs exist, and is a public input the circuit constrained. |
| Z6 | **Point the group at the attacker's own verifier logicsig**, built over a verifying key for a circuit that asserts nothing | **rejected** | "L16". `V_ADDR` is a **compile-time constant list** in `Mpt7App` (TP-M7-7). A different verifying key yields a different program yields a different address. **Any implementation that makes the verifier address a parameter, box value, or mutable global is a critical defect** — flagged here so a reviewer can grep for it, in the same spirit as S3. |
| Z7 | Submit `MODE_ZK_CLOSE` **not signed by the logicsig at all**, with a well-formed but unverified proof blob | **rejected** | "L16". The contract never parses or verifies the proof itself; the *signature* is the evidence. `Txn.Sender == V_ADDR` is only satisfiable if the logicsig program ran and approved. |
| Z8 | Rekey the logicsig account out from under the verifier | **rejected twice** | "L17", and AlgoPlonk's generated logicsig independently rejects a non-zero `RekeyTo`. Also, per AlgoPlonk's guidance the verifier account is **never funded**; fees come from group pooling. |
| Z9 | Point `prev_gi` at a foreign transaction's log to import someone else's `W` | **rejected** | M5's `mpt_state_from_prev` checks W13–W16, unchanged; and the imported `W` would name a different `(root, tx_index)`, which TP-M7-1 catches at the consumer. |
| Z10 | Supply a leaf that really does hash to `W.expected` but whose **`hp_path` does not terminate our key** — e.g. a leaf for a longer key sitting at that trie position | **rejected** | "L18" plus circuit assertion 3. This is M5's strict-prefix-leaf attack (M5 §5.4) relocated into the circuit, and it is the one that is easy to lose: **for T1/T2 the on-chain `mpt_verify_inclusion` performs the exact-length check, but for T3 the leaf never reaches the chain, so the check exists only in the circuit and in the `path_tail` public-input comparison.** If either is omitted, M7 would report inclusion for keys that are actually absent. |
| Z11 | Declare a false `leaf_len` to shift keccak's padding | **rejected** | length is inside the hash (padding is length-dependent), so it is self-checking, exactly as it was for §2.4's sponge; and circuit assertion 2 independently requires the RLP header arithmetic to close on `leaf_len`. |
| Z12 | Point `log_off` past the end of the logs list so the "log" is really bloom-filter bytes | **rejected — by a constraint that must actually be written** | §4.4's **span containment** rule: every `(off, len)` must lie inside its parent's span. This is the circuit's analogue of M2's bounds checks. It is listed here because its *absence* is undetectable on-chain (TP-M7-6) — the proof would verify and the contract would accept. §9.5/ZK-6 tests it. |
| Z13 | **Exploit a subverted trusted setup** — prove a false statement using retained toxic waste | **NOT DEFENDED** | This is TP-M7-5 and it is the honest limit of the design. A party holding the ceremony's secret can forge a proof for *any* statement, and every check Z1–Z12 would pass. The only mitigation is the ceremony's own security (PPOT: 140+ participants across Semaphore/Hermez/Tornado/snarkjs; one honest participant suffices) and refusing `TestOnly` setups in shipped artifacts. **T1 and T2 are unaffected**, which is a real argument for keeping all three tiers rather than routing everything through ZK. |
| Z14 | **Exploit a missing constraint in the circuit** | **NOT DEFENDED on-chain** | TP-M7-6. No on-chain check can see it. Mitigated only by differential testing against M2's RLP oracle on real mainnet receipts (§9.5) and by review. Weaker than the guarantee T1/T2 enjoy, and stated as such. |
| Z15 | Grief by opening a `MODE_STAGE_OPEN` box for oversized `log_bytes` and abandoning it | **bounded, and no worse than T2** | the box lives and dies inside one atomic group (§3.5(d)); an aborted group means the box never existed. **T3 introduces no cross-group session** — this is the central improvement over §2.4's route, whose A8 griefing surface was unique in the project. |

**Verdict.** Z1 is the design's load-bearing check and it holds: the leaf hash is the
walker's own hash-verified output, never an argument. Z6, Z10 and Z12 are the three
that would be silently catastrophic if implemented carelessly, and each is called out
as a structural rule rather than left to a test. **Z13 and Z14 are genuinely not
defended**, are new to this project, and are the reason §0.3 puts them in the headline
rather than in a footnote.

---

## 7. Budget and group arithmetic

Built on measured numbers only, following M6 §7.2's calibrated-model method.

### 7.1 The measured components

M5 baselines, from `bench/mpt_results.json` (real simulate + real submission):

| | measured |
|---|---:|
| `G1_M5_receipt_inclusion` — the real 3-node walk, key derived on-chain | **1,813** |
| `G4/G7_M5` — the same proof as a real 2-segment live group (544 + 1,480) | **2,024** |

M2 primitives, measured **during this pass** against the real receipt body of block
25,639,768 tx 31, through real Puya-compiled ARC-4 dispatch on `RlpBenchApp`, net of
its 14-budget `noop` baseline:

| operation | measured |
|---|---:|
| `receipt_envelope` on the real 683-byte typed leaf value | **46** |
| body → item 3 (the logs array) | **337** |
| body → item 0 (status) | **309** |
| body → item 2 (the 256-byte bloom) | **333** |
| logs list → `log[0]` | **273** |
| logs list → `log[1]` | **273** — flat in index, as M2's G2 promises |
| `log[1]` → address / topics / data | **284 / 304 / 300** |
| topics → `topic[0]` / `topic[2]` | **252 / 252** — flat |

These use `scan_and_get` (`rlp_scan` + `rlp_table_item`, the full-table path), so they
are **upper bounds**: M2 §16's `rlp_scan_upto` early-exit path measures 112 at want=0
rising ~31/item (`G1_scan_upto_fast`), which is cheaper for single access. The model
below uses the measured full-table numbers and is therefore conservative.

### 7.2 M7's addition, per proof

| component | budget | basis |
|---|---:|---|
| `receipt_envelope` | 46 | **measured** |
| body → logs array | 337 | **measured** |
| logs → `log[k]` | 273 | **measured**, flat in `k` |
| log → (address, topics, data), one scan + 3 retrievals | ~304 | **measured** 284 for scan+1; M2 G2 bounds each extra retrieval ≤ 10 |
| topics → `topic[j]`, ×`n_topics` | 252 + ~10/extra | **measured** |
| `keccak256(data)` | 130 | **measured**, flat |
| R assembly + 347-byte log | ~100 | target; M6's 355-byte `C` log is the precedent |
| **M7 addition** | **≈ 1,442** | |

Per `ARCHITECTURE.md`: the two `~` rows are **targets** and may not be quoted anywhere
until `bench/receipt_results.json` holds a real simulate response for them.

### 7.3 Full workloads

| workload | app budget | logicsig budget | ALGO | txns in group |
|---|---:|---:|---:|---:|
| **T1** receipt + log proof (3 nodes, leaf ≤ 1,942 B) | ≈ **3,466** | — | **0.005** | 2 segment + 3 donor = **5** of 16 |
| **T2** same, box-staged leaf ≤ 4,096 B | ≈ **3,689** | — | **0.006** + ~1.65 ALGO transient MBR | 3 stage + 1 walk + 4 donor = **8** of 16 |
| **T3** oversized, AlgoPlonk (§4) | ≈ **3,700** | ≈ **224,600** | **≈0.016** | **1 group, ≤16 txns** |
| *(T3 via §2.4's software sponge, not shipped)* | 475k–17.2M | — | 0.68–24.5 | 3–91 **groups** |

T1 = M5's measured 2,024 live group + §7.2's 1,442. T2 = T1 + §3.4's measured 223.
Both fit one 16-transaction atomic group with room to spare, and both are within a
factor of ~1.3 of M6's measured composite despite doing a much smaller walk — the
decode, not the walk, is M7's cost centre, which inverts M5's ratio and is worth
knowing before optimising the wrong thing.

Box references (T2): 2 by §2.3's measured `ceil(S/2048)` rule, out of 128 available in
a group. Not a constraint.

Argument space (T2): a 4,096-byte leaf at ≤ 1,900 B of chunk per transaction is 3
staging transactions. Not a constraint.

### 7.3.1 T3's arithmetic in full

The point of §4's design is that **T3's two budgets do not compete**, so both must be
tracked separately.

**Application budget** — essentially T1's, because the PLONK verification consumes a
measured **40** of it (§4.1):

| component | budget | basis |
|---|---:|---|
| M5 walk to the oversized leaf's parent | ~1,700 | **measured** — the real 3-node receipt walk is 1,813 for the *full* walk; stopping one node short is less |
| logicsig verification's app-side cost | **40** | **measured** (§4.1) |
| `keccak256(log_bytes)` (§4.8 step 6) | **130** | **measured**, flat |
| parse 7 public inputs, 6 comparisons (L13–L18) | ~250 | target |
| decode `log_bytes` → address/topics/data_hash (§3.3 steps 4–6) | ~1,150 | **measured** components, §7.1 |
| R assembly + 347-byte log | ~100 | target |
| **T3 app total** | **≈ 3,700** | **of 190,400 — under 2 % utilisation** |

**Logicsig budget** — where the proof is actually paid for. **Revision 3 replaces
revision 2's BLS12-381 estimate here with a real BN254 measurement** (§4.13); the old
row is kept for comparison because §4.9's trade-off table still cites it:

| component | budget | basis |
|---|---:|---|
| PLONK verifier, **BN254**, 1 BSB22 commitment, **7 public inputs** | **185,370** | **measured on real algod, revision 3** (§4.13) |
| (superseded: BLS12-381, 1 commitment, 2 public inputs) | 221,201 | measured, revision 2 (§4.1) |
| (superseded: 5 additional public inputs × ~678) | ~3,390 | measured rate (§4.1) |
| **T3 logicsig total** | **185,370** | **of 320,000 — 58 % utilisation** |

The BN254 measurement is of the **complete** M7 verifier with all 7 public inputs, so no
per-public-input extrapolation is needed on top of it. Observed spread across the two
real runs was 84 budget (0.045 %), so **the verifier's cost is very slightly
proof-data-dependent** — do not pin an exact equality constant on it.

**Application budget correction.** §4.13 measured the logicsig's app-side cost at
**2**, not the 40 revision 2 measured for BLS12-381. The T3 app total above is
unaffected at the precision it is stated to.

**Transactions.** The 320,000 logicsig pool needs `⌈185,370 / 20,000⌉ = 10` top-level
transactions to exist (revision 2 said 12); measured in §4.1 and re-confirmed in §4.13,
**they do not have to be logicsig-signed**, so M7's own walker segments count toward it.
Group: 2–3 walker segments + 1 `MODE_ZK_CLOSE` + fillers = **≤16**. Fees at 1,000 µAlgo
× 16 = **0.016 ALGO**.

**Headroom, and where it is thin.** The app side is comfortable. The logicsig side has
~135,000 spare. **The binding constraint on T3 is argument space, not opcode budget** —
and revision 3's smaller BN254 proof (864 B, not 1,184 B) relaxes it: inline `log_bytes`
now caps at **~950 B**, not 634 B (§4.8), with larger logs pushed to box staging. Note
the *separate* limit §4.5.3 found: box staging solves delivery, not the circuit's
`LOGMAX` (ZK-B9).

**ZK-B3's caveat is discharged.** Revision 2 wrote "it has not been measured and must
not be quoted until it is." It has been (§4.13): BN254 is **185,370**, i.e. ~16 % cheaper
than BLS12-381's 221,201 — the direction AlgoPlonk's README claimed, with the README's
~175,000 being for 2 public inputs rather than 7.

### 7.4 Program size — the one gate at real risk

M6 §13.4 warned M7 to measure headroom before designing. Measured, from
`bench/composer_results.json` and `bench/mpt_results.json`:

| | bytes |
|---|---:|
| M2 contribution | 839 |
| M5 contribution | 1,969 |
| M6 contribution | 573 |
| `Mpt6ComposerApp`, the real deployable driver | **2,676** |
| cap (`extra_pages=3`) | **8,192** |

M7's decode is small (it is M2 calls plus fixed-offset splices into R). **T1+T2 are
not at risk.**

**T3 under §4's design is not at risk either, and this is another quiet win over the
software-sponge route.** The PLONK verifier is a **separate program** — an AlgoPlonk
logicsig, measured at **4,819 B compiled** (§4.1) — that does not share `Mpt7App`'s
8,192-byte budget at all. M7's own additions for T3 are small: public-input parsing, six
comparisons, and reuse of the §3.3 decode it already has. Estimated **< 400 B**.

By contrast §2.4's route *would* have been at risk: a Puya-compiled Keccak-f, at M3's
measured ~40 % Puya premium over the 1,946 B hand-TEAL, lands near 2,700 B on its own
plus a streaming RLP state machine, and would have needed its own deployed application.

**Unmeasured (§4.11/ZK-B6):** the AVM's maximum logicsig program size was not checked
this pass. 4,819 B verified under `simulate`, which is evidence but not a real
submission.

---

## 8. `ROADMAP.md` resolved, and what is handed on

### 8.1 The M7 open question

> *"Owns the unsolved >4096B receipt-leaf problem — 9/137 real receipts in the spike's
> own test block exceed the AVM value cap; no streaming hash opcode exists;
> implementation must not start until this specific design doc is explicitly approved,
> may force revision of M2."*

**Resolved, in four parts, and one prior claim is corrected.**

1. **"No streaming hash opcode exists" — confirmed empirically, not assumed.** §2.1:
   147 opcodes enumerated from the compiler's own table; all six hash opcodes are
   single-shot arity-1; twelve plausible streaming/box-hash names rejected by the real
   assembler as unknown. Box staging is closed too, with literal error strings (§2.2).
2. **The claim that such a leaf "cannot be hashed at all" is WRONG and this document
   corrects it.** `MPT_RESULTS.md` §5.3, `002-rlp-decoder.md` §4.2(a),
   `005-mpt-walker.md` §7.5 and `README.md` all state or imply it. §2.4 built a
   working Keccak-f[1600] in AVM arithmetic, verified it against the native opcode on
   seven messages and against a **real mainnet receipt-trie leaf hash**, and measured
   it at **14,848 budget per 136-byte block**. The correct statement is: *it cannot be
   hashed by an opcode; it can be hashed in software at 109.2 budget/byte, a 2,172×
   penalty on the real leaf.* **§10 lists the exact edits those four documents need.**
3. **The oversized case is SOLVED, not deferred — within a stated, measured bound.**
   Revision 2 ships **T3**: an AlgoPlonk/gnark PLONK proof of
   `keccak256(R) == W.expected` plus the receipt's RLP structure, verified on-chain by a
   logicsig verifier in **one atomic group at ~0.016 ALGO**, with the leaf hash taken
   from M5's own hash-verified walker output rather than from any argument (§4.8, §6.2).
   Coverage rises from **93.4 %** to a **measured 97.8 %** at 2²⁴ (revision 2 projected
   99.3 %; §4.5.3 has the correction) of the reference block. The residual
   bound is **the trusted setup, not the AVM**: gnark's keccak costs a measured
   `391,602 + 224,269 × blocks`, no BLS12-381 ceremony is large enough (§4.6), and BN254
   Perpetual Powers of Tau at 2²⁴/2²⁵ covers **both** a leaf bound and a per-log bound
   (§4.5.3). Above that — in the reference block, tx 73, tx 6 and tx 119 — M7 still returns
   `R_INCOMPLETE`, a defined non-verdict requiring no new trust assumption (§5.4).
4. **T3 costs two new trust assumptions and they are recorded, not hidden.** TP-M7-5
   (trusted setup) and TP-M7-6 (circuit soundness) are the project's first. They apply
   to T3 only; T1 and T2 remain assumption-free, which is a real reason to keep three
   tiers rather than route everything through ZK. §6.2/Z13–Z14 state plainly that
   neither is defended on-chain.
5. **"May force revision of M2" — it does not.** M2 §4's bet pays off exactly as
   written. T1 and T2 use the single-blob, offset-addressable decoder verbatim, and
   §3.3's decode is `(node, offset)` arithmetic into the same hash-verified buffer with
   no copy — the capability M2 §4.3 promised. **T3 does not change this either**: §4.3
   deliberately scopes the circuit so that the log's bytes are decoded by M2's existing
   on-chain decoder, so T1/T2/T3 all produce `R` through the same code. M2's *format
   logic* is additionally reused as the specification the circuit's RLP constraints are
   written against and differentially tested with (§9.5). **No M2 change is required.**

### 8.2 Flagged for M9 (relayer)

- **M9 must classify T1/T2/T3 off-chain before submitting.** It has the leaf bytes; it
  can measure them. It must also pick the **circuit tier** (§4.5) for a T3 proof, and
  reject leaves above the largest deployed tier rather than burning a proof on them.
  **Revision 3, ZK-B9:** a tier is a **pair `(N, LOGMAX)`**, so the classifier must key
  on `max(len(encoded log_i))` *as well as* `leaf_len` (§4.5.3). Two real receipts in
  the fixture block — tx 73 and tx 6 — are inside a tier's leaf bound and outside its
  log bound, and tx 73's leaf is smaller than tx 76's while needing a larger tier.
  Getting this wrong costs minutes of wasted proving, not soundness.
- **M9 owns disambiguating `R_INCOMPLETE`** (§5.4): only the relayer can see whether
  the walk stopped because nodes were withheld or because the terminal node is beyond
  every deployed circuit. This must surface in M9's client API, not be swallowed.
- **M9 builds the T2 staging group** (create/write×n/walk+delete) and funds the box
  MBR (~1.65 ALGO transient at 4,096 B).
- **M9 becomes a proving service, and this is a real architectural consequence**
  (§4.7). Generating a T3 proof is a **minutes-scale, tens-of-GB** job — extrapolated
  ~5 min / ~25–30 GB at 2²⁴ and ~10 min / ~50–60 GB at 2²⁵, from two measured points.
  M9 therefore needs: a **proving queue** (proofs cannot be produced inside a user
  request), a **host that can hold the largest deployed tier** (≥64 GB for 2²⁵), and a
  **Go process** — gnark is Go, and this is the project's first non-Python runtime
  component (§8.7). The proving key is loaded once and reused across every proof of a
  tier, and proving parallelises across receipts, so this is a provisioning problem
  rather than a per-proof latency problem.
- **Revision 3 adds a setup cost revision 2 did not know about, and it changes M10/M9's
  deployment story more than the proving cost does.** `kzg.ToLagrangeG1`, which every
  PLONK setup needs, performs **one full scalar multiplication on every SRS point** —
  measured **197.8 s at 2²¹ and 452.9 s at 2²²**, scaling ~2.3× per doubling, so
  **~40 minutes at 2²⁴** (§4.7.1). Together with a ~18 GB ceremony download this makes
  tier bring-up a **provisioning operation measured in hours**. The proving key and
  Lagrange SRS **must be computed once per tier and persisted**; recomputing them per
  proof would dominate everything else in this document.
- **M9 must never let a proof outlive its statement.** A proof is only meaningful
  alongside the group whose walker reproduces the same `W.expected` (§6.2/Z3). Caching
  proofs per `(receipts_root, tx_index, log_index)` is safe; caching them per
  `tx_index` alone is not.
- **M9 must never present `R_ABSENT` as "no such transaction"** without a
  transaction-count bound (§1.2).
- M7's ABI can be frozen against this document; ROADMAP lists M9's design as startable
  once M4/M6/M7/M8 interfaces are frozen.

### 8.3 Flagged for M8 (trusted-root anchor)

- **M8 must anchor `receiptsRoot`, and must make it queryable by block identity.** M7
  binds a root into R but has no idea which block it belongs to. TP-M7-2 is
  unsatisfiable unless M8's root history answers "what was `receiptsRoot` at slot/block
  N".
- A **transaction-count bound** per block would make receipt exclusion meaningful. If
  M8 anchors `transactionsRoot` too, a future M7 revision could support it.

### 8.4 Flagged for M10 / M11

- **M10**: box schema and MBR policy for T2 staging boxes — naming, funding, and a
  sweep for boxes stranded by a group that aborted after `MODE_STAGE_OPEN` (§3.4). The
  same policy covers T3's oversized-`log_bytes` boxes (§4.8).
- **M10 additionally owns the trusted-setup artifact**, and this is new work with no
  precedent in the project. A BN254 PPOT proving key at 2²⁴ is **≈537 MB**; at 2²⁵,
  ≈1.1 GB. **These cannot be committed to a public git repo.** M10 needs a
  fetch-and-verify step: download from the ceremony's published location, check the
  digest against a value pinned in-repo, and convert to AlgoPlonk's `pk.bin`/`vk.bin`
  layout. The verifying key (~240 B, per the vendored files) *is* small enough to pin
  in-repo and is what actually determines the deployed verifier's address — so the
  security-critical artifact is small and the large one is a build input.
- **M11**: widen the receipt-size sample. This document rests on **two** blocks
  (288 receipts) because public RPC rate-limited further pulls. The 93.4 % / 97.8 %
  headlines are drawn from the conservative of the two and should be re-derived over a
  proper sample before they appear in the README. **Revision 3 adds a requirement to
  that sampling**: the sample must record each receipt's **largest single log**, not
  just its leaf size, because §4.5.3 shows that is what sets the tier for the biggest
  receipts. The second block's T3 column in §3.1 is currently un-derivable for exactly
  this reason.
- **M11 additionally owns the circuit's differential test corpus** (§9.5): every real
  receipt in the fixture set decoded by both M2's Python oracle and the gnark circuit,
  with the two required to agree. This is the only real defence against TP-M7-6.

### 8.5 The hard prerequisite — RESOLVED by revision 3's spike

**Revision 2 wrote:** "T3 cannot be implemented until PPOT parameters above 2¹⁷ are
integrated into AlgoPlonk (§4.11/ZK-B2) … it is not optional and it is not small."

**Revision 3 ran that spike. It turned out to be small, and it did not need AlgoPlonk to
change at all.** §4.12 has the detail; the summary for whoever schedules implementation:

- AlgoPlonk's `setup` registry is **`go:embed`-based and therefore closed to
  downstream consumers** — revision 2's plan ("add a `setup/<NamePath>` directory") is
  not achievable without forking AlgoPlonk and vendoring a 537 MB blob into it.
- It is also **unnecessary**. `setup.Run` only produces `(srs, lagrangeSrs)` for
  `plonk.Setup`. Building the SRS from a `.ptau` yourself and constructing
  `algoplonk.CompiledCircuit{Ccs, Pk, Vk, Curve}` directly reaches **all** of
  AlgoPlonk's verifier code generation and proof marshalling, unmodified.
- The `.ptau` → gnark SRS converter already exists and is the one **AlgoPlonk's own
  audit script uses**: `github.com/mdehoog/gnark-ptau`. There is no format
  incompatibility.
- Verified end to end: real `powersOfTau28_hez_final_21.ptau` → real proof → real
  AlgoPlonk logicsig → **real confirmed submission** (§4.13).

**What M10 actually has to do**, therefore, is provisioning rather than engineering:
host or fetch-and-checksum the chosen tier's `.ptau` (≈18 GB for 2²⁴, ≈40 min at the
~8 MB/s measured here), run the conversion once, and **persist the derived proving key
and Lagrange SRS** — because §4.7.1 measured `kzg.ToLagrangeG1` at 197.8 s for 2²¹ and
452.9 s for 2²², scaling ~2.3× per doubling, i.e. **~40 minutes at 2²⁴**. That is a
one-off per tier, but it must not be paid per proof.

**What is left that genuinely blocks implementation** is no longer the setup: it is
**ZK-B9** (a tier is a pair `(N, LOGMAX)` and §5.4/M9 must classify on both) and, before
any coverage figure is published, **ZK-B4/ZK-B8** on a machine with ≥ 64 GB of RAM.

### 8.6 Flagged for M12 (docs & packaging / release prep)

- **Each circuit tier is a versioned artifact.** A tier is `(circuit source, gnark
  version, curve, setup, verifying key) → logicsig address`. Changing *any* of them
  changes the address, which `Mpt7App` hard-codes (TP-M7-7). So **adding or revising a
  tier is a contract redeployment**, and the version story `ARCHITECTURE.md` already
  says is "AVM/consensus-fork-gated, not plain semver" gains a third axis: the proof
  system.
- **gnark and AlgoPlonk versions must be pinned exactly.** AlgoPlonk's own README says
  so, and it is load-bearing here: a gnark change to the keccak gadget changes the
  constraint system, the verifying key, and the deployed address.

### 8.7 Flagged for `ARCHITECTURE.md` — a genuine toolchain decision, for the human

**This design introduces a second implementation language to a project whose
`ARCHITECTURE.md` currently records exactly one.** That document's "Language" section
says contracts are Algorand Python (Puya), dropping to `Op` only in hot loops. §4
requires, in addition:

- **Go**, as a build and test dependency — the project had no Go toolchain before this
  pass (one was installed to do the verification).
- **`gnark` circuits written in Go**, which are neither contracts nor tests but a third
  kind of artifact: *trusted* code (TP-M7-6) that ships as a verifying key rather than
  as a program.
- **`AlgoPlonk` as a code generator** whose output is Algorand Python compiled by the
  project's own `puyapy` — so the *generated* artifact stays in-language even though
  its source does not.

This is not something a design doc should decide unilaterally, so **it is flagged here
for the maintainer rather than actioned**: if this design is approved, `ARCHITECTURE.md`
should record (a) Go/gnark as a sanctioned second language scoped to `circuits/`,
(b) the rule that generated verifier Python is never hand-edited, (c) exact version
pinning for gnark/AlgoPlonk, and (d) an explicit statement that the measurement rule
("no cost claim without a real `simulate` response") now has a sibling for circuits:
**no constraint-count claim without a real `frontend.Compile` result.** This document
has tried to hold itself to that sibling rule already — §4.5's table is measured and
§4.5's `~50,000` navigation term is labelled an estimate precisely because it is not.

---

## 9. Test plan

Principle, inherited from M2 §8.1 / M5 §9: real data first; derived fixtures only
where real data cannot exercise a path, and labelled as derived.

### 9.1 Suite A — the real receipt proof (pinned, T1)

| id | test |
|---|---|
| A1 | The pinned 3-node proof (`eth_data.json receipt_proof`, tx 31, nodes `[308,532,690]`) verifies against the real `receiptsRoot`; `rstatus == R_INCLUDED`. |
| A2 | `mpt_key_from_tx_index(31) == 0x1f`, matching `receipt_proof.key_rlp` verbatim; `key_nibs == 2`. |
| A3 | `receipt_envelope` returns `tx_type == 2` and advances the span by one byte (real EIP-1559 receipt). |
| A4 | Body decodes to arity 4 with item lengths `[1, 3, 256, 412]` — the real shape measured in §3.3. |
| A5 | `log_index = 0` → address 20 B, **`n_topics == 4`** (the maximum), **`data_len == 0`** (the minimum). Both boundaries, from real data, for free. |
| A6 | `log_index = 1` → 3 topics, `data_len == 128`, `data_hash == keccak256` of the real 128 bytes. |
| A7 | `log_index = 2` → `R_NO_SUCH_LOG`, `n_logs == 2`. |
| A8 | Full 2-segment live group; `R` recovered via `mpt7_result_from_group` with correct `want_*`. |

### 9.2 Suite T2 — the box-staged tier, real data

| id | test |
|---|---|
| T2-1 | Rebuild the receipts trie from all 137 fixture receipts; assert the root reproduces `0x6490277f…099e710b`. (**This pass ran it: it does.**) Emit the tx-7 proof `[308, 500, 2453]` as a new pinned fixture. |
| T2-2 | Stage that real 2,453-byte leaf across a group and verify; on-chain `keccak256` must equal `0x3841e627…31a84623`, the real parent-branch child reference. (**This pass ran it live, real submission, round 537, 223 budget.**) |
| T2-3 | Wrong bytes in the staging box → rejected at "W11". The box has no integrity of its own; the hash check is the whole guarantee (TP-M7-4). |
| T2-4 | `leaf_len = 4,097` at `MODE_STAGE_OPEN` → "L7". |
| T2-5 | Box-reference budget: assert the group needs exactly `ceil(leaf_len/2048)` refs, per §2.3's measured rule. |
| T2-6 | `box_del` runs in the terminal transaction; a repeat of the same proof succeeds (no stale box). |

### 9.3 Suite O — the AVM's real limits, on real oversized bytes

This suite establishes *why* T3 exists — that the oversized leaf genuinely cannot be
delivered or hashed on-chain — and that the residual unsupported case is honest. All
nine oversized receipts are already in the pinned fixture; their leaves are derivable
from the same trie rebuild as T2-1, so **no fresh RPC pull is required**.

| id | test |
|---|---|
| O1 | Derive the real leaf for tx 35 (4,221 B) and tx 119 (**157,283 B**) from the rebuilt trie; pin their lengths and hashes. |
| O2 | Attempt to deliver the tx-35 leaf as an application argument → the real protocol rejection (`ApplicationArgs total length is too long`). Assert the literal error, M5 §7.2 style. |
| O3 | Attempt `box_create(157_283)` → `box size too large: 157283, maximum is 32768`. Assert literally. The largest real receipt does not even fit a box. |
| O4 | Stage the tx-35 leaf into a 4,221-byte box and `box_extract(0, 4221)` → `box_extract produced a too big (4221) byte-array`. Assert literally. **This is the test that pins T3's necessity to the AVM's behaviour rather than to a constant in our code.** |
| O5 | Walk tx 119's proof (the leaf above every tier) supplying only the branch nodes → `rstatus == R_INCOMPLETE`, and `W.expected` equals the real `keccak256` of the undeliverable leaf. |
| O6 | **`R_INCOMPLETE != R_ABSENT`** — assert the two codes differ and that no assertion path can turn an incomplete walk into an absence verdict (M6 §8.3's rule, M7's §5.4). |
| O7 | Tier boundary: a leaf one byte above the largest deployed tier is rejected by M9's classifier *before* submission, and if submitted anyway yields `R_INCOMPLETE`, never a verdict. |

### 9.4 Suite S — security

| id | test |
|---|---|
| S1 | Request `log_index = 0` but hand the contract a receipt whose log 0 differs → the extracted address/topics are log 0's, never log 1's. Ensures §6 S3 is closed by construction: grep the implementation for any caller-supplied offset/span parameter in the decode path; there must be none. |
| S2 | `want_receipts_root` mismatch → "L11". |
| S3 | `want_tx_index` / `want_log_index` mismatch → "L11". |
| S4 | Reading a non-terminal `R` → "L10". |
| S5 | Forged segment hand-off (point `MODE_NEXT` at a foreign transaction) → W13–W16, mirroring M5's `S7_S8_handoff_live`. |
| S6 | A leaf for tx index 30 offered as a proof for index 31 → M5's exact-length leaf check rejects it. |
| S7 | Derived fixture: a receipt with a 31-byte topic → "L6"; with 5 topics → "L5"; body arity 3 → "L2". |
| S8 | `tx_index = 0` → key `0x80`, not `0x00` (M5 §4.2's trap, re-pinned at M7's level). |

### 9.5 Suite ZK — the T3 mechanism (new in revision 2)

This is the suite that carries the new trust assumptions, so it is the most important
new testing in this document. Principle: **the circuit is tested against M2's own
decoder, not against itself.**

**Revision 3: what of this suite has actually been run.** The ZK spike executed the
following for real. Rows not listed remain unrun.

| id | run this pass? | real result |
|---|---|---|
| **ZK-1** | **YES** | **97 / 97 real receipts of block 25,639,768 satisfied, 0 failed** — every receipt with ≥ 1 log and leaf ≤ 4,300 B, each against a tier sized to its own real largest log. Includes tx 7 (2,453 B) and **tx 35 (4,221 B, the smallest oversized receipt)**. Run with gnark's `test.IsSolved` engine, exactly as this row specifies. **Caveat**: the oracle is the spike's own Go RLP walk (`assign.go`), not M2's Python decoder. Cross-checking against `contracts/primitives/rlp/` is still owed (§9.5's own principle), and stays open. |
| **ZK-2** | **PARTIAL** | Real end-to-end proofs generated and verified on-chain for **tx 85** (typed) and **tx 8** (legacy) — but **not** for tx 35, whose 2²⁴ domain this machine cannot prove (ZK-B4), and **not** with `W.expected` produced by a real M5 walk, because M7's contract does not exist yet. §4.13. |
| **ZK-3** | no | — |
| **ZK-4** | **PARTIAL** | AlgoPlonk's BN254 audit procedure **run**: `pk.bin` reproduced byte-for-byte from `powersOfTau28_hez_final_18.ptau`. `vk.bin` matches only its first 160 bytes, for the identified gnark-crypto reason in §4.12. |
| **ZK-5** | **YES** | Constraint counts and commitment counts recorded to `bench/receipt_zk_results.json`. |
| **ZK-6** | **YES** | **Span containment holds.** A hand-built witness pointing the target log at bytes inside the 256-byte bloom filter, with a log commitment genuinely matching those bytes, is **unsatisfiable**. §4.14. |
| **ZK-7** | **PARTIAL** | The in-circuit half is run: a tampered `path_tail` is unsatisfiable. The on-chain "L18" half needs M7's contract. |
| **ZK-8** | no | The constraints exist in `rlp.go`'s `header()` (minimal-length, no leading zero length byte, 1-byte-short-string rule) but **no negative witness was built**. This is the one silent-failure constraint from §4.4 that still has no negative test. |
| **ZK-9** | **PARTIAL** | The in-circuit half is run: a tampered `leaf_hash` public input is unsatisfiable, and **on-chain a single flipped bit in the public inputs is `rejected by logic`** by the real deployed logicsig. The "two real receipts" form of the test needs M7's contract for the "L13" path. |
| **ZK-10** | **PARTIAL** | In-circuit: wrong log commitment and wrong `log_index` both unsatisfiable. On-chain "L14"/"L15" need M7's contract. |
| **ZK-11 / 12 / 13** | no | All need M7's contract. |
| **ZK-14** | no | — |
| **ZK-15** | **YES, for the mechanism** | **Real, non-simulated submissions confirmed in rounds 557, 559 and 560** of the project's dev-mode algod, carrying a 3,924-byte AlgoPlonk logicsig verifier and an 864-byte proof over a real mainnet receipt leaf. What is *not* yet in that group is M7's own walker segments. |

**The shape of what remains is worth stating plainly**: every unrun ZK-* row is blocked
on *M7's contract not existing yet*, not on any doubt about the ZK mechanism. The two
exceptions are **ZK-8** (a negative witness nobody has written) and **ZK-1's oracle**
(the differential should be against M2's decoder, not the spike's own Go walk).

| id | test |
|---|---|
| ZK-1 | **Circuit correctness on real data.** For every receipt in the fixture set (all 137 of block 25,639,768, not only the oversized ones), the circuit's extracted `(log_off, log_len)`, `tx_type`, `status`, `cumulative_gas_used`, `n_logs` agree with M2's Python RLP oracle. Run with gnark's `test.Engine` (no proving) so the whole corpus is cheap. |
| ZK-2 | **Real end-to-end proof.** Generate a real proof for the real tx-35 leaf (4,221 B) and verify it on localnet through `MODE_ZK_CLOSE`, with `W.expected` produced by a real M5 walk of the real proof nodes — not injected. `rstatus == R_INCLUDED`, and the extracted log equals the one M2's oracle extracts off-chain. |
| ZK-3 | **`TestOnly` setups are unreachable in shipped artifacts** (TP-M7-5). A build-time check that the deployed verifying key derives from a pinned ceremony vk, plus a test that fails if `setup.TestOnly*` appears in any non-test path. |
| ZK-4 | **Setup provenance.** Run AlgoPlonk's own `audit.go` procedure for the chosen PPOT parameters and pin the transcript under `tests/fixtures/`. Closes §4.11/ZK-B7. |
| ZK-5 | **Constraint count is pinned.** Record the compiled circuit's `nbConstraints` and commitment count to `bench/receipt_results.json`; regression if either moves. A change means a new verifying key and a new deployed address (§8.6). |
| ZK-6 | **Span containment (§6.2/Z12).** Hand-build a witness whose `log_off` points past the logs list into the bloom filter and assert the circuit is **unsatisfiable**. This must be a real negative test, not a review item — it is the constraint whose absence is undetectable on-chain. |
| ZK-7 | **Path-tail check (§6.2/Z10).** A witness supplying a leaf whose `hp_path` does not exactly consume the remaining key nibbles → unsatisfiable in-circuit, and separately "L18" on-chain if the public input is tampered with. Both halves, because either alone would be a silent inclusion forgery. |
| ZK-8 | **Minimal-length RLP (§4.4).** A witness using a long-form header where a short one would do → unsatisfiable. |
| ZK-9 | **Wrong-hash binding (§6.2/Z1).** Submit a genuinely valid proof whose `leaf_hash` public inputs describe a *different* real receipt from the same block → "L13". This is the headline security test and it uses two real receipts, not synthetic data. |
| ZK-10 | **Forged log bytes (Z4)** → "L14". **Wrong log index (Z5)** → "L15". |
| ZK-11 | **Foreign verifier (Z6).** Build a second AlgoPlonk logicsig over a different (trivially-satisfiable) circuit, sign `MODE_ZK_CLOSE` with it → "L16". Then grep the implementation: **the accepted verifier address must appear as a compile-time constant and must not be reachable from any argument, box, or mutable global.** Reviewed, not only tested. |
| ZK-12 | **Unsigned close (Z7).** Submit `MODE_ZK_CLOSE` from an ordinary account with a well-formed proof blob → "L16". |
| ZK-13 | **Rekey attempt (Z8)** → "L17", and confirm AlgoPlonk's own logicsig rejects it independently. |
| ZK-14 | **Oversized `log_bytes` path.** A log above the 634 B inline cap staged through `MODE_STAGE_OPEN`/`MODE_STAGE_WRITE` and read by `MODE_ZK_CLOSE`; same "L14" hash check applies. |
| ZK-15 | **Real, non-simulated submission** of the full T3 group. Closes §4.11/ZK-B5 and ZK-B6 together. |

### 9.6 Suite K — the Keccak-f findings (regression-protecting §2.4)

§2.4's software sponge is **not** what v1 ships (§4.9), but its measurements underpin
§8.1's correction of three project documents and §4.9's comparison, and it remains the
documented fallback and the only known route to receipts above the largest circuit tier.
It must stay reproducible.

| id | test |
|---|---|
| K1 | Python Keccak-f reference vs `pycryptodome` on ≥ 6 messages spanning block boundaries (0, 135, 136, 137, 768 B). |
| K2 | AVM Keccak-f: all 25 output lanes vs the Python reference. |
| K3 | AVM sponge vs the **native `keccak256` opcode** at 0/100/271/407/543/1,000/1,350 B. |
| K4 | AVM sponge over the real 2,453-byte tx-7 leaf == the real parent-branch reference. |
| K5 | Resumed sponge across a transaction boundary via `gtxn LastLog` == the same digest. |
| K6 | Per-block cost recorded to `bench/receipt_results.json`; regression if it drifts from 14,848 by more than 5 %. |

### 9.7 Suite B — budget, live

| id | test |
|---|---|
| B1 | T1 full proof, live simulate, real fixture → `bench/receipt_results.json`. |
| B2 | T2 full proof, live simulate **and real submission**. |
| B3 | Compiled size of `contracts/receipt/` measured M5-style (combined probe minus the M2+M5+M6 probe). |
| B4 | Re-measure §7.1's M2-primitive table so §7.2's model is never quoted from a stale run. |

### 9.8 Acceptance gates

| gate | requirement |
|---|---|
| **G1-M7** | The real 3-node T1 receipt+log proof verifies live and beats the spike's insecure 1,121 + a decode budget stated in advance; total < 4,000. |
| **G2-M7** | The real T2 box-staged proof verifies by **real, non-simulated submission** in one atomic group. (Already demonstrated for the hashing half, §3.4.) |
| **G3-M7** | Every oversized-receipt rejection in Suite O produces the **literal** AVM error asserted in the test — T3's necessity is pinned to AVM behaviour, not to our constant. |
| **G4-M7** | `R_INCOMPLETE` is unreachable as an absence verdict: no code path converts it to `R_ABSENT` (O6, plus review). |
| **G5-M7** | Compiled size of M2+M5+M7 driver ≤ 8,192 B. |
| **G6-M7** | Suite K reproduces 14,848 ± 5 % per block, so §4.9's comparison rests on a live number. |
| **G7-M7** | No decode-path entry point accepts a caller-supplied offset, span, or log offset (S1). Reviewed, not just tested. |
| **G8-M7** | **A real, non-simulated T3 submission verifies a real oversized mainnet receipt in ONE atomic group** (ZK-2 + ZK-15). This is T3's headline gate and it is the direct analogue of G2-M7. |
| **G9-M7** | **The leaf hash is never an argument.** Grep + review: the value compared against the proof's public inputs 0,1 originates only from `mpt7_state_from_prev`, and no code path lets a caller supply or influence it (ZK-9). |
| **G10-M7** | **The verifier address is a compile-time constant** and is not reachable from any argument, box, or mutable global (ZK-11). Reviewed, not just tested. |
| **G11-M7** | **The circuit agrees with M2's oracle on the entire real fixture corpus** (ZK-1), and the three silent-failure constraints — span containment, path tail, minimal-length RLP — each have a passing *negative* test (ZK-6/7/8). |
| **G12-M7** | **No shipped artifact derives from a `TestOnly` setup**, and the chosen ceremony's provenance is verified and pinned (ZK-3, ZK-4). TP-M7-5 is unsatisfied until this passes. |
| **G13-M7** | Circuit `nbConstraints`, commitment count, verifying key and derived logicsig address are all pinned in `bench/receipt_results.json`; any drift is a deliberate, reviewed re-deployment (ZK-5, §8.6). |

---

## 10. Documentation corrections this pass requires

§2.4 falsifies a claim repeated in four places. Those must be fixed when this design is
approved, or the project's own record will be wrong:

| file | current text | correction |
|---|---|---|
| `tests/fixtures/spike-reference/MPT_RESULTS.md` §5.3 | "you **cannot even materialize or `keccak256` the leaf node**" | true for the *opcode*; add that a software sponge does it at a measured 14,848/136 B. **The spike file is preserved unmodified by policy — record the correction here and in the README instead.** |
| `docs/design/002-rlp-decoder.md` §4.2(a) | "M7 **cannot materialise or hash that leaf at all**" | amend to "cannot materialise it, and cannot hash it with the `keccak256` opcode; software hashing is possible at 109.2 budget/byte (007 §2.4)". M2's *decision* is unaffected and §4's bet still pays off (§8.1.5). |
| `docs/design/005-mpt-walker.md` §7.5 | "cannot be `keccak256`'d (no streaming hash)" | same amendment; M5's args-not-boxes decision is unaffected, and §7.5(b)'s box economics should cite 007 §2.3's separate read/write pools. |
| `README.md` | "it can't even be pushed to the stack, let alone hashed, with a naive approach" | accurate as written ("naive"), but should point at 007 §2.4 for the measured non-naive cost, and at §3.1 for the tier split. |
| `README.md` (revision 3) | any statement of M7's receipt coverage | **ZK-B1 and ZK-B2 are now closed (§4.12, §4.13), and the coverage figure moved.** The T1+T2 figure (93.4 %) is measured and quotable today. The T3 figure is **97.8 % at 2²⁴** on a real compiled circuit — **not** revision 2's 98.5 % / 99.3 %, which held `LOGMAX` fixed and were optimistic (§4.5.3). Even 97.8 % still rests on **ZK-B4**: no proof at 2²⁴ has ever been generated. Recommendation unchanged in spirit: **do not publish a T3 coverage number in `README.md` until one real proof exists at the deployed tier.** |
| `ARCHITECTURE.md` (revision 2) | "Language: Algorand Python (Puya), with inline `Op` for hot paths" | **Flagged for the maintainer, not edited by this pass** — §8.7 sets out what would need recording (Go/gnark as a sanctioned second language scoped to circuits; generated verifier Python never hand-edited; exact gnark/AlgoPlonk pinning; a circuit-side sibling to the measurement rule). |

---

## 11. Summary of decisions

1. **T1 (leaf ≤ 1,942 B, 86.9 %)** — M5's walker and M2's decoder, unchanged, one
   atomic group, ≈ 3,466 budget / 0.005 ALGO.
2. **T2 (1,942 < leaf ≤ 4,096 B, 6.6 %)** — box-staged inside one atomic group, native
   `keccak256`, ≈ 3,689 budget / 0.006 ALGO + transient MBR. **Live-verified on real
   mainnet bytes with a real submission.** Sound because the box needs no integrity
   property of its own (TP-M7-4).
3. **T3 (leaf > 4,096 B) — SUPPORTED in v1 via AlgoPlonk**, up to the largest deployed
   circuit tier, and **demonstrated end to end on real data with a real ceremony**
   (§4.13). A gnark PLONK proof establishes `keccak256(R) == W.expected` and pins the
   requested log's bytes; an AlgoPlonk-generated **logicsig** verifier checks it in the
   same atomic group at a **measured 185,370 logicsig budget and 2 app budget on BN254**
   (revision 2 quoted 221,201 / 40 from BLS12-381), so PLONK verification and M5's
   walker never compete. **One atomic group, ~0.016 ALGO, flat in receipt size** —
   against 3–91 non-atomic groups and 0.68–24.5 ALGO for §2.4's software sponge (§4.9).
   Sound because `expected_leaf_hash` is the walker's own hash-verified output and never
   an argument (§6.2/Z1) — and the in-circuit half of that binding is now a **passing
   negative test**, not a review claim (§4.14).
4. **The curve is BN254, not BLS12-381 — and this was forced by measurement, not
   preference** (§4.6). gnark's keccak costs `391,602 + 224,269 × blocks`; the Ethereum
   KZG ceremony (2¹⁴) cannot hash one block and Dusk (2²¹) buys 952 bytes. **No
   BLS12-381 ceremony in existence is large enough.** BN254's Perpetual Powers of Tau
   reaches 2²⁷ and is the only viable setup.
5. **T3's bound is the trusted setup, not the AVM — and revision 3 measured it lower
   than revision 2 projected.** A tier is a **pair `(N, LOGMAX)`**, because the largest
   single log inside a receipt costs the same 224,269 constraints per keccak block that
   the leaf does (§4.5.3). Real, from the compiled circuit: **2²⁴ covers 134/137 =
   97.8 %** (6 of the 9 oversized receipts), 2²⁵ covers 98.5 %, and **99.3 % needs 2²⁶**.
   Revision 2 attributed 99.3 % to 2²⁵; that was optimistic. tx 119's 157,283-byte leaf
   with 1,000 logs needs **≈2²⁹** — beyond PPOT's 2²⁷ ceiling — and stays
   `R_INCOMPLETE`. **The quotable v1 figure is 97.8 %.**
6. **Two new trust assumptions, T3 only**: TP-M7-5 (trusted setup) and TP-M7-6 (circuit
   soundness). Neither is defended on-chain (§6.2/Z13–Z14). T1 and T2 remain
   assumption-free, which is why all three tiers are kept.
7. **A new language enters the project** — Go/gnark for circuits — flagged for
   `ARCHITECTURE.md` in §8.7 rather than decided here.
8. **M2 needs no revision** (§8.1.5), and T3 deliberately reuses M2's on-chain decoder
   for the log itself so T1/T2/T3 produce `R` through the same code.
9. **Three project documents contain a claim that this pass falsified** and must be
   corrected (§10).
10. **Revision 2's two hard prerequisites are closed** (§4.11). ZK-B2 is closed by
    §4.12 — real PPOT files convert cleanly to gnark's SRS with the converter AlgoPlonk
    itself uses, and AlgoPlonk's codegen is reachable **without** forking it, by
    bypassing `setup.Run`. ZK-B1 is closed by §4.5 — the circuit exists and its real
    constraint counts replace the projection. ZK-B3, ZK-B5 and ZK-B6 closed too, and
    ZK-B7 half. **Two new blockers opened**: ZK-B8 (tier B never compiled) and **ZK-B9
    (a tier is `(N, LOGMAX)` and nothing yet says how M9 picks it)** — ZK-B9 is a design
    decision this document still owes.

**Honest characterisation of this result, revised after the spike.** Revision 2 wrote
that the oversized tier had moved from *designed and deferred* to *designed, mostly
verified, and chosen*, and was careful to say "mostly" was doing real work. **Revision 3
removes the "mostly" from the mechanism and keeps it on the numbers.**

What is now demonstrated, not argued: a real Ethereum receipt-trie leaf from the pinned
fixture block, hashed and structurally decoded inside a real gnark circuit, proved
against the **real Perpetual Powers of Tau ceremony** rather than a test setup, verified
by an AlgoPlonk-generated logicsig **in a real, non-simulated transaction group** on the
project's own node — twice, once per EIP-2718 envelope branch — at **185,370 logicsig
budget and 2 app budget**, with an **864-byte proof** and a **3,924-byte verifier**. The
circuit's soundness-critical constraints have **passing negative tests**, including the
span-containment one §4.4 singles out as undetectable on-chain if absent. And the whole
in-circuit structural walk agrees with an independent decode on **97 of 97** real
receipts.

What is still not established, and is now listed more precisely than before: **no proof
above 2²¹ has ever been generated** (ZK-B4) — this machine cannot, and every tier this
design would actually deploy is 2²⁴ or above, so the *deployed* configuration remains
unproved end to end; **tier B has never even been compiled** (ZK-B8); **the coverage
figure moved down** from revision 2's projection once the circuit was real (97.8 %, not
98.5 %/99.3 %, at 2²⁴); **a tier is a pair and the design does not yet say how to pick
it** (ZK-B9); and **ZK-8's canonicality negative test has not been written**. Revision
2's own warning still applies verbatim to the numbers above 2²¹: they are arithmetic on
measured components, and `ARCHITECTURE.md`'s rule means they must not be published as
established until someone runs them on a machine that can.

The one thing this document still refuses to say is that any of it is impossible.
Revision 1 refused to call the oversized leaf unhashable and had §2.4's real mainnet
digest to prove it. Revision 2 refused to call it unaffordable, and had a real proof
verified on a real node at a real, measured cost to prove that. **Revision 3 refuses to
call it unbuilt, and has a real proof of a real receipt, under a real ceremony,
confirmed in a real block, to prove that.**

---

## 12. Optional / deferred work (`O-M7-*`)

Referenced from §1.2, §4.10 and §5.2. None of these blocks v1.

| id | item and status |
|---|---|
| **O-M7-1** | **On-chain software Keccak-f[1600] for oversized leaves** (§2.4, §4.9). Built, verified byte-exact against the native opcode and against a real mainnet leaf's parent-branch reference, measured at 14,848/block. **Superseded as v1's T3 mechanism by §4**, but retained as the documented fallback and as the only known route to leaves above the largest circuit tier (e.g. tx 119's 157,283 B). Kept under regression test by Suite K (§9.6). |
| **O-M7-2** | **Return raw log `data` instead of `keccak256(data)` + `data_len`.** `R` is fixed-width by design (M5 §3.2's constant-offset rule); a variable-width result would need a different recovery scheme. Not v1. |
| **O-M7-3** | **Multi-log / batched extraction** — several logs from one receipt in one proof. For T1/T2 this is cheap (repeat §3.3 steps 3–6). For T3 it is *very* cheap relative to the proof already being generated: the circuit could commit to several `(log_index, log_commit)` pairs for a handful of extra public inputs and one extra keccak pass each. Worth revisiting once T3 exists, because the marginal cost of a second log in an already-proved receipt is far below a second proof. |
| **O-M7-4** | **Shrink the T3 circuit.** The dominant term is `224,269` constraints per keccak block, which is gnark's generic `keccakf`. Options not evaluated this pass: a lookup-table-heavy keccak variant, or committing to the leaf with a SNARK-friendlier hash chained to a single keccak. Any change here moves the tier table (§4.5) and the verifying key (§8.6). |
| **O-M7-5** | **Recursive proof aggregation** (§4.10, Route E). Would remove the trusted-setup size ceiling by proving many small chunk-proofs and aggregating. In-circuit PLONK verification needs non-native field arithmetic costing millions of constraints per verified proof, so the aggregation circuit is plausibly larger than the flat circuit it replaces. Not designed. |
| **O-M7-6** | **Receipt exclusion proofs**, which need a transaction-count bound M7 cannot see (§1.2, §8.3). Owner: M8/M9. |
| **O-M7-7** | **ZK for M4's sync-committee install flow** — the one Track-A candidate with the right shape (one-off per 27.3 h period, no latency pressure, and the project's single most expensive operation at ~1,357,000 budget / 8 groups / 2.18 ALGO). **Closed with a number, not left open**: on §13.1's measured cost of ≈208,000 constraints per in-circuit BLS12-381 subgroup check, proving 512 pubkeys valid needs ≈106 M constraints — **2²⁷, the absolute ceiling of the Perpetual Powers of Tau ceremony, for one operation.** Not viable. See §13.2. |

---

## 13. ASSESSMENT — does ZK have implications beyond M7? (not an implemented change)

> **Status of this section: an assessment and a recommendation for the maintainer.
> Nothing here is designed, approved, or implemented, and this pass deliberately
> implemented none of it.** It exists because the ZK spike (§4.12–§4.14) produced, for
> the first time in this project, *real* gnark/AlgoPlonk cost data that can be compared
> against M1–M6's *real* on-chain measurements. The question "should other modules use
> this too?" deserves an evidence-based answer rather than a reflex in either direction.
>
> **Recommendation up front: no. Keep M1–M6 exactly as they are.** The evidence is
> below, including the one place where the numbers genuinely favour ZK and why that is
> still not enough.

### 13.1 The real cost data this assessment rests on

Every constraint count below is a real `frontend.Compile` on BN254 with the `scs`
(PLONK) builder, run in this pass. Every AVM budget is this project's own measured
number, cited to the module that measured it.

| primitive | **in-circuit (real nbConstraints)** | **on-chain AVM (real measured budget)** | ratio |
|---|---:|---:|---:|
| `keccak256`, per 136-byte block | **224,269** | 130, flat for the whole buffer (M7 §2.1) | — |
| `sha256`, per 64-byte compression | **85,404** | 35, flat (M3) | — |
| BLS12-381 G1 point addition | **≈4,324** | 217/point measured (M4 §9.1) | **20×** |
| BLS12-381 G1 subgroup check (`AssertIsOnG1`) | **≈208,000** | 2,373 measured for G2 (M1) | **~88×** |
| BLS12-381 `MapToG2` (one of two in a full hash-to-curve) | **614,565** | full `hash_to_g2` = 17,443 measured (M4 §9.1) | **≥70×** |
| BLS12-381 2-point `PairingCheck` | **1,600,189** | `verify_aggregate_signature` = 55,474 measured (M4 §9.1) | **29×** |

Two of these deserve a note.

- **The keccak figure independently reproduces §4.5's coefficient to the constraint.**
  A standalone keccak circuit over 136 B costs 840,108 and over 544 B costs 1,512,915 —
  a difference of 672,807 over exactly 3 blocks = **224,269/block**, the same number
  §4.5 measured a revision ago on different circuits. That is a good sign for every
  other number in this table.
- **Every one of these circuits also reports `commitments = 1`**, because they all pull
  in `std/math/uints`' range-check tables. So any ZK version of any of these modules
  inherits §4.2's forcing fact: **logicsig verifier, never smart contract.**

The headline of the table is the direction of every ratio. **The AVM has native opcodes
for exactly the operations these modules need, and native opcodes are 20–2,400× cheaper
than arithmetising the same operation.** ZK does not win by being cheaper at the
operation level; it wins, when it wins, by moving the operation off-chain entirely and
paying a *flat* 185,370 logicsig budget regardless of how much work was moved.

### 13.2 M4 (sync-committee BLS) — the strongest case for ZK, and still a no

M4 is the module where this is worth taking seriously, because M4 is the most expensive
thing in the project: **157,509 app budget worst case, 8 top-level calls + 256 donor
inner calls = 264 app calls = 0.264 ALGO per update**, at 12.6 % headroom under the
190,400 ceiling (M4 §9.2/§9.3).

**What a ZK M4 would cost, from §13.1's real numbers.** The per-update statement is:
aggregate the participating subset of 512 G1 pubkeys, build the signing root, hash it to
G2 under the Ethereum DST, do the 2-pair check, and verify two SSZ branches.

| in-circuit line | constraints |
|---|---:|
| up to 511 G1 additions (adaptive aggregation, M4 §9.1's worst case) | ≈2,210,000 |
| full `hash_to_G2` (expand_message_xmd + 2 × `MapToG2` + cofactor clear) | ≈1,500,000–2,000,000 |
| 2-point `PairingCheck` | 1,600,189 |
| ~11 `sha256` compressions (signing root, fork data, 2 branches) | ≈940,000 |
| 512-bit bitfield walk, selectors, glue | small |
| **total** | **≈6.5–7 M → PLONK domain 2²³** |

**The honest scorecard.**

| | **M4 today (implemented, tested, real submissions)** | **M4 as a ZK proof (hypothetical)** |
|---|---|---|
| on-chain budget | 157,509 **app** | 185,370 **logicsig** + ~2 app |
| app-budget pool consumed | **83 %** of 190,400 | **~0 %** |
| transactions / fee per update | 264 app calls, **0.264 ALGO** | 16 txns, **~0.016 ALGO** |
| headroom | 12.6 % — thin | enormous, and **flat** |
| off-chain cost per update | negligible | **2²³ setup: a ~9 GB ceremony download, a ~13-minute one-off `ToLagrangeG1` (§4.7.1), then minutes and tens of GB per proof** |
| trust assumptions | **none beyond Ethereum's own** | **+ trusted setup, + circuit soundness** |
| status | **implemented, 284+ tests, real non-simulated submissions** | not written |

**The numbers really do favour ZK on cost: a 16× fee reduction and the entire
application-budget pool handed back.** That is not a small win and it should not be
waved away. Three things outweigh it.

1. **It relocates the project's trust root onto a trusted setup.** This is the decisive
   argument and it is qualitative, not numeric. §0.3 accepted TP-M7-5 and TP-M7-6
   **only for T3**, an oversized-receipt tier that would otherwise be unsupported
   entirely — the fallback if the setup is ever found defective is `R_INCOMPLETE`, i.e.
   *no verdict*, which is safe. **Track A has no such fallback.** M4 *is* the trust
   root: `ARCHITECTURE.md` defines the whole design as "verifies Ethereum
   sync-committee BLS12-381 aggregate signatures … producing a trusted, rolling anchor",
   and `ROADMAP.md` locks "full Ethereum consensus-spec compliance from the start — no
   stubbed BLS signature verification". A forged proof under a compromised ceremony
   would not degrade a tier; it would mint an arbitrary `stateRoot`, and **every
   downstream module (M5, M6, M7) would verify correctly against it.** The bridge would
   be silently, totally compromised. Paying 0.248 ALGO more per update to avoid that is
   obviously correct.
2. **The proving latency does not fit the cadence.** M4's update path runs at sync-
   committee-update frequency; proving at 2²³ is a minutes-scale, tens-of-GB operation
   (§4.7, §4.7.1). A relayer that cannot produce a proof in time cannot advance the
   anchor at all — and unlike M7's T3, where a failed proof means one receipt is
   unavailable, a failed M4 proof means **the whole bridge stalls**. This converts a
   liveness property the current design does not have into one it does.
3. **It would discard M4 entirely.** M4 is not a sketch. It is implemented, it found and
   fixed a real box-reference-cap bug against real algod, it has live end-to-end install
   tests, and its `hash_to_g2` / DST / fork-version / Bitvector[512] bit-order work is
   validated against real consensus-spec vectors — the exact work `ARCHITECTURE.md`
   says is non-negotiable. **A ZK M4 would have to re-establish all of it inside a
   circuit, where a missing constraint is silent** (TP-M7-6). §13.1's table says the
   circuit would need ~7 M constraints of BLS arithmetic that nobody has audited,
   replacing AVM opcodes whose correctness is the AVM's problem, not ours.

**One narrower idea worth keeping.** M4's *install* flow — 512 pubkeys, ~1,357,000
budget, **8 groups, ~2.18 ALGO**, once per 27.3 h (M4 §8.5) — is the single most
expensive operation in the project, and it is a **one-off per committee period with no
latency pressure**, which is exactly the shape ZK suits. A circuit proving "these 512
pubkeys merkleize to this committee root and each is a valid subgroup element" would,
on §13.1's numbers, cost 512 × 208,000 ≈ **106 M constraints** for the subgroup checks
alone — **2²⁷, the absolute ceiling of PPOT, for one operation.** So even the
best-shaped candidate in Track A does not fit. Recorded as **O-M7-7**, closed with a
number rather than left open.

### 13.3 M5 / M6 (MPT walking) — clearly not worth it

M5 walks the trie with the native `keccak256` opcode at **130 budget flat per node**.
In-circuit the same hash costs **224,269 per 136-byte block**. A real 8-node account
proof (M6's composite, whose nodes run to 532 B) is ~32 keccak blocks = **≈7.2 M
constraints plus navigation → 2²³**, to replace a walk that M5 measures at **5,116 app
budget** and M6's full 5-segment composite at **12,202** — both of which land in one
atomic group with real, non-simulated submissions today.

There is a real observation on the other side, and it should be stated: M5 and M6 need
**6 and 14 donor inner calls** respectively to raise their pooled budget, and M5's gates
G1/G5/G6-M5 are still open (5,116 vs a 3,276 target). A ZK walk would make all of that
vanish — flat 185,370 logicsig budget, no donors, no segment hand-off, no `gtxn LastLog`
state machine. **That is a genuinely attractive simplification.**

It is still the wrong trade, for the same trust reason as §13.2 plus one more: M5's
security argument is *structural* — §5's descent derives every index from the key itself
on-chain, and the hash chain is checked by the contract at every hop. Moving it into a
circuit converts a property that is enforced by code the AVM executes into a property
enforced by constraints nobody has audited. **M5/M6's cost problem is a budget-tuning
problem with a known lever; it is not a problem worth buying a trusted setup to solve.**

### 13.4 M1 / M3 — no, and the numbers are not close

- **M3 (SSZ / sha256)**: on-chain `sha256` is **35 budget, flat**, and M3's real
  compiled cost is `~103 + 83 × depth` for a whole branch. In-circuit one sha256
  compression is **85,404 constraints**. A depth-7 branch measures **684 budget**
  on-chain today. There is no argument here at all.
- **M1 (BLS primitives)**: M1's whole value is that it is a thin, measured wrapper over
  native `ec_*` opcodes. §13.1 shows those opcodes beat their in-circuit equivalents by
  20–88×. M1's aggregation is already an `ec_add` chain at 217/point; the in-circuit
  version is 4,324/point.

### 13.5 Where ZK *is* the right tool, restated

The pattern that made T3 work is specific, and none of M1–M6 matches it:

1. The work is **impossible on-chain at any price** — not merely expensive. A >4,096 B
   value cannot be materialised on the AVM stack at all (§0). M1–M6's work is all
   possible on-chain, and all of it is already done there.
2. Failure is **safe and honest**. A missing or unprovable T3 proof yields
   `R_INCOMPLETE` — no verdict — which M6 §8.3 already established is not an answer. A
   compromised Track A yields a *wrong answer that verifies*.
3. The work is **off the critical path**. One receipt's proof failing does not stop the
   bridge; a sync-committee update failing does.
4. The on-chain cost is **flat**, so an unbounded off-chain statement collapses to a
   constant — which is only valuable when the statement really is unbounded. M4's
   statement is bounded (512 members) and M5's is bounded (trie depth).

### 13.6 Recommendation

**Do not pivot any of M1–M6 to ZK. Confine ZK to M7's T3 tier, exactly as §4 scopes
it.** M1–M6 are implemented, tested (403+ passing tests), and have real, demonstrated
non-simulated on-chain submissions; the ZK alternative is cheaper on fees for M4 and
simpler in shape for M5/M6, but in every case it would trade **a zero-cryptographic-
assumption design for one that rests on a trusted setup**, and in M4's case it would put
that assumption under the project's trust root, where the failure mode is a silently
forged anchor rather than an unavailable receipt.

The evidence for that recommendation is §13.1's table, and the single most useful thing
this spike produced for the project outside M7 may be that table itself: **it prices, in
real numbers, every "should we just ZK this?" question the remaining modules will
raise.** M8–M12 should be able to answer such a question by arithmetic from §13.1 rather
than by another spike.

**If the maintainer wants to revisit any of this**, the one candidate with a real
cost argument behind it is M4's *per-update* path (§13.2's 16× fee reduction and freed
app-budget pool), and the honest precondition for taking it seriously is a separate,
explicit decision that **the bridge's trust root may depend on a trusted setup** — a
decision `ROADMAP.md`'s "locked decisions" section would have to be amended to permit,
and one this document recommends against.

---

## 14. Revision 4 — setup memory/time, O-M7-4, and a security review

> **Status: measured, hands-on.** Every number in this section is a real
> measurement taken on the same 14 GB / 16-core box the earlier revisions used,
> with the same Go 1.25.7 toolchain, the same pinned dependencies, and the same
> real ceremony files. Where a number is an extrapolation it is labelled as one.
> Tooling lives in `tests/fixtures/spike-reference/zk-m7/` (`ptaufast/`, and
> `cmd/{stagemem,lagcheck,linescheck,linestest,aplines,soundprobe,forgeproof,shrink,tx73,variantcheck}`).
>
> **Two results here contradict earlier revisions and one is a confirmed
> security defect. Read §14.1.1 and §14.3 before relying on §4.7.1 or §4.12.**

### 14.1 The setup-phase bottleneck was mis-identified

§4.11 records the memory ceiling as "the specific expensive step
`kzg.ToLagrangeG1`". That was checked rather than assumed this pass, by
resetting Linux's `VmHWM` high-water mark between stages (write `5` to
`/proc/self/clear_refs`) and forcing Go to scavenge before each stage, so each
row is a real per-stage peak and not the previous stage's un-returned garbage.

Real M7 circuit, tx 85's tier (`N=384, LOGMAX=96, MAXLOGS=4`, 1,340,806
constraints, domain 2²¹), real `powersOfTau28_hez_final_21.ptau`:

| stage | wall | **peak RSS** | live heap after |
|---|---:|---:|---:|
| `frontend.Compile` | 1.4 s | 0.47 GB | 0.25 GB |
| `gnark-ptau.ToSRS` | 7.3 s | 0.75 GB | 0.52 GB |
| truncate + GC | 0.1 s | 0.63 GB | 0.38 GB |
| **`kzg.ToLagrangeG1`** | **157.2 s** | **1.46 GB** | 0.51 GB |
| `plonk.Setup` | 6.9 s | **1.99 GB** | 1.71 GB |
| *whole process* | *173.5 s* | ***2.08 GB*** | |

> **`ToLagrangeG1` is the dominant *time* cost — 157 s of a 173 s run, 91 % —
> but it is NOT the peak-memory step.** Its peak is 1.46 GB against
> `plonk.Setup`'s 1.99 GB and the full prove run's ~4.0 GB (§4.7.1). §4.11's
> phrasing conflates "the expensive step" with "the memory ceiling"; only the
> first is true.

Its transient above the live set is 1.11 GB for 2²¹ points = **529 bytes per
SRS point**, which is what the extrapolation in §14.1.3 rests on.

#### 14.1.1 A correction to §4.7.1's explanation of *why* it is slow

§4.7.1 says `ToLagrangeG1` "performs **one full 254-bit scalar multiplication on
every one of the 2ⁿ G1 points**". Reading gnark-crypto v0.20.1's
`ecc/bn254/kzg/utils.go`, that describes only the final `1/n` scaling loop
(line 56–60). The inverse FFT itself — `difFFTG1`, lines 144 and 152 — performs a
**full scalar multiplication by a twiddle on every butterfly**, i.e.
`(n/2)·log₂(n)` of them. At 2²¹ that is 22.0 M scalar multiplications against
the 2.1 M the doc's explanation accounts for: **the real count is ~10.5× higher**,
and the FFT, not the final scaling, is where the 157 s goes. This also explains
the ~2.3×-per-doubling scaling §4.7.1 measured but could not account for
(`n log n`, not `n`).

#### 14.1.2 The chunked/streaming rewrite turned out to be unnecessary

The question this pass set out to answer was whether `ToLagrangeG1` could be
restructured to stream the ceremony from disk in chunks. It can — gnark's
`difFFTG1` is a decimation-in-frequency recursion whose stages partition into
independent contiguous blocks, so each early stage is a two-cursor sequential
pass and the tail is block-local, which is exactly the out-of-core FFT shape.
**That work was not needed, because the computation is redundant.**

Every `powersOfTau28_hez_final_NN.ptau` is a *phase-2-prepared* snarkjs file and
carries **section 12: the Lagrange-basis G1 evaluations**, concatenated for
`p = 0 .. power+1`, `2^p` points each (so the block for domain `2^d` starts at
point index `2^d − 1`). Section 13 is the same for G2, 14/15 for
alphaTau/betaTau. This is why the files are ~2.4 GB when sections 1–7 only
account for ~0.9 GB.

`cmd/lagcheck` reads both and compares point-for-point:

| domain | `kzg.ToLagrangeG1` | read from section 12 | result |
|---:|---:|---:|---|
| 2¹⁴ | 0.76 s | 0.00 s | **all 16,384 points identical** |
| 2¹⁸ | 15.95 s | 0.01 s | **all 262,144 points identical** |
| **2²¹** | **169.76 s** | **0.15 s** | **all 2,097,152 points identical** |

Byte-identical, not merely equivalent. The 157–170 s step is recomputing data
that is already in the file.

`ptaufast` (`tests/fixtures/spike-reference/zk-m7/ptaufast/`) is the resulting
loader. It parses the section table, then reads **only** `domain+3` canonical
points from section 2 and `domain` Lagrange points from section 12, through a
fixed 4 MiB staging buffer, checking every point is on-curve as `gnark-ptau`
does. It also populates `Vk.Lines`, which fixes the defect in §14.3.1.

Same circuit, same ceremony file, same box:

| | **baseline** (`gnark-ptau` + `ToLagrangeG1`) | **`ptaufast`** | change |
|---|---:|---:|---|
| SRS acquisition, peak RSS | **1.46 GB** | **0.50 GB** | **−66 %** |
| SRS acquisition, wall | 164.6 s | **0.5 s** | **~330×** |
| whole setup process, peak RSS | 2.08 GB | **1.97 GB** | −5.2 % |
| whole setup process, wall | 173.5 s | **7.1 s** | **24×** |

The whole-process peak barely moves **because `plonk.Setup` is the peak, not
`ToLagrangeG1`** — which is §14.1's point restated as a measurement.

Correctness was not assumed: `cmd/forgeproof` runs the real M7 circuit at 2²¹
against the real PPOT `_21` ceremony through `ptaufast` and the honest proof
verifies (§14.3.1 uses the same run).

#### 14.1.3 What this does and does not do for the 2²⁴ tier — honestly

Two costs are removed at 2²⁴, and both are real:

- **`ToSRS` loading the whole ceremony.** It reads `2^(power+1)−1` points
  regardless of the circuit. For `powersOfTau28_hez_final_24.ptau` that is
  33,554,431 points = **2.15 GB**, plus a 1.07 GB truncating copy, to use
  1.07 GB. `ptaufast` reads 1.07 GB and nothing else.
- **`ToLagrangeG1`'s transient**, measured at 529 B/point → **~8.9 GB at 2²⁴**,
  and ~40 minutes of wall time (§4.7.1's own extrapolation).

So the SRS-acquisition phase at 2²⁴ goes from roughly **11 GB of peak and ~45
minutes** to **~2.15 GB of live data and seconds**. That is a genuine result.

**But it does not move the tier, and this must not be overstated.** The binding
steps are untouched:

| step at 2²⁴ | status | basis |
|---|---|---|
| `frontend.Compile` (~16.3 M constraints) | **measured this pass at nearby sizes**: 6.88 GB peak at 17.76 M constraints, and 4.67 GB at 16.70 M *under `GOMEMLIMIT=5GiB`* (so the latter is a soft-capped figure, not a free-running peak) | `cmd/shrink`, `cmd/tx73` |
| SRS acquisition | **~2.15 GB** with `ptaufast` (was ~11 GB) | measured scaling, linear in domain |
| `plonk.Setup` | **not improved.** 1.52 GB transient at 2²¹ → ~12 GB at 2²⁴ if linear in domain | **extrapolation** |
| `plonk.Prove` | **not improved.** ~2 GB transient at 2²¹ → ~16 GB at 2²⁴ if linear | **extrapolation**; §4.7.1 measured 4.02 GB total at 2²¹ |

Reading those together, and flagging clearly that the last two rows are
extrapolations from two domain points, not measurements:

> - The **once-per-tier setup phase** at 2²⁴ plausibly now fits a **32 GB** host
>   and no longer needs 64 GB. Before this change it would have needed the
>   ~11 GB SRS phase *on top of* the compile, and would have spent ~40 minutes
>   in a step that now takes seconds.
> - The **per-proof phase** at 2²⁴ is **unchanged** and remains the reason a
>   64 GB class host is the safe recommendation. Nothing in this section touches
>   `plonk.Prove`.
> - **16 GB is not reachable at 2²⁴ by this change**, and no claim is made that
>   it is.
>
> **ZK-B4 stays OPEN.** No proof above 2²¹ was generated this pass either. The
> largest thing actually built here is a 17,757,682-constraint *compile*
> (§14.2), which is a new high-water mark over §4.5.2's 16,293,891 but is still
> only a compile.

M9/M10 sizing changes that follow, and they are cheap: **fetch the ceremony,
read sections 2 and 12, never call `ToLagrangeG1`.** §4.7.1's "~40 min
`ToLagrangeG1` at 2²⁴" line in §4.9's comparison table should be struck.

### 14.2 O-M7-4 — shrinking the T3 circuit

O-M7-4 proposed two directions, "a lookup-table-heavy keccak variant, or
committing to the leaf with a SNARK-friendlier hash chained to a single keccak",
and recorded that neither had been evaluated. Both were evaluated this pass.

**Direction 1 — a faster keccak gadget. There is not one, and the premise is
partly mistaken.**

- gnark v0.15.0's standard library contains exactly **one** Keccak
  implementation: `std/permutation/keccakf`, reached through `std/hash/sha3`.
  There is no lookup-table variant and no alternative backend.
- **It is already a lookup-based construction.** `keccakf` is built on
  `std/math/uints`, whose byte-level `Xor`/`And` go through
  `std/internal/logderivprecomp` — precomputed log-derivative lookup tables.
  That is also why every M7 circuit reports `commitments = 1` (§4.2). So
  O-M7-4's "lookup-table-heavy keccak variant" is largely **what already
  ships**; the residual 224,269/block is structural, not a missing optimisation.
- No third-party gnark-compatible keccak gadget was found (GitHub repository and
  code search, plus the gnark issue tracker). The only related upstream issue is
  #1391, a closed subgroup-check bug, not a cost issue.

**Direction 2 — a SNARK-friendlier hash. Unsound by construction for the leaf.**
The statement the circuit proves is literally
`keccak256(R[0:leaf_len]) == expected_leaf_hash`, where the right-hand side is a
child reference read out of a node the on-chain walker itself hashed (§4.8 step
5). There is no algebraic bridge from a Poseidon or MiMC digest of `R` to
`keccak256(R)`; substituting the hash changes the statement into one that says
nothing about Ethereum's trie. **The leaf keccak — which is 75 % of the circuit
at tx 35's tier — cannot be replaced at any price.** Only the *log* commitment
is negotiable, because its sole consumer is M7's own contract, which has native
AVM opcodes for `keccak256` (130) and `sha256` (35).

**What is actually available, measured.** Two levers were implemented in the real
circuit (`circuit.Params.LogSHA256`, `.MinLeaf`, `.MinLog`; all default off, so
§4.5's recorded counts are unchanged) and compiled for real:

| tier | `N` | `LOGMAX` | `MAXLOGS` | base | sha256 log | Δ | `WithMinimalLength` | Δ |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| tx 85 | 384 | 96 | 4 | 1,340,806 | 1,298,963 | −3.12 % | 1,328,710 | −0.90 % |
| tx 8 | 440 | 160 | 1 | 1,795,131 | 1,619,291 | **−9.80 %** | 1,774,737 | −1.14 % |
| tx 31 | 704 | 256 | 4 | 2,273,644 | 2,276,514 | **+0.13 %** | 2,248,022 | −1.13 % |
| tx 35 | 4,224 | 928 | 20 | 9,530,591 | 9,350,588 | −1.89 % | 9,318,005 | −2.23 % |
| tx 73 | 7,552 | 2,368 | 24 | 17,757,682 | 17,172,298 | −3.30 % | — | — |

Individually these are small, sometimes negative, and **no single lever moves any
tier**. `hash.WithMinimalLength` is safe to use: gnark asserts
`minimalLength <= length` itself (`std/hash/sha3/sha3.go`, `paddingFixedWidth`),
so it is a real bound and not an unchecked assumption.

**Combined, there is one result that matters.** §4.5.3 identifies **tx 73** as
the single receipt in block 25,639,768 that forces a 2²⁵ tier — its leaf
(7,546 B) is smaller than tx 76's, but one of its logs is 2,368 B. With both
levers (`cmd/tx73`):

```
tx 73, sha256 log commitment + WithMinimalLength(7168, 2048)
  base                    17,757,682
  shrunk                  16,699,547     (-5.96 %)
  2^24 ceiling            16,777,216
  *** FITS 2^24 *** with 77,661 constraints of margin
```

Applied to §4.5.3's coverage table, and stated with its caveats:

> **2²⁴ coverage would rise from 97.8 % (134/137) to 98.5 % (135/137), and the
> 2²⁵ tier becomes unnecessary for this block.** tx 6 (2²⁶) and tx 119 (2²⁹)
> are unaffected and remain out of reach.

Verified rather than assumed: `cmd/variantcheck` re-runs §9.5's ZK-1 shape over
the real corpus under all three variants — **72/72 satisfied, 0 failed** in each
— so the saving is a real circuit, not just a smaller constraint count. The
witness builder (`circuit/assign.go`) was updated in step.

**What this costs, stated plainly, because it is not free:**

1. **`sha256` is a protocol change, not a circuit-local one.** §4.3's public
   inputs 2/3 stop being `keccak256(log_bytes)` and §4.8's `MODE_ZK_CLOSE` step 6
   must compute `sha256(log_bytes)`. That is *cheaper* on-chain (35 vs 130) but
   it is a change to the verified statement and needs an explicit decision.
2. **`WithMinimalLength` makes a tier a 4-tuple** `(N, LOGMAX, MinLeaf, MinLog)`
   with a genuine **lower** bound — a receipt below the minimum cannot use that
   tier, because gnark asserts the bound. This extends **ZK-B9**: M9's
   classifier must now pick a tier by a range on both dimensions, not a ceiling.
3. **The margin is 77,661 constraints — 0.46 %.** A different block could easily
   produce a receipt that misses. This is not headroom to design against.
4. **Compile-only.** No proof has been generated at 2²⁴ (ZK-B4).

**Recommendation: worth doing, but as a deliberate design decision, not a
drive-by optimisation.** The honest summary of O-M7-4 is that the circuit is
close to irreducible — 75 % of it is a keccak that Ethereum's trie fixes and
gnark already implements about as well as its lookup machinery allows — and the
one available 6 % buys exactly one receipt of 137. Building a better keccak
gadget from scratch was assessed and is **not a pass-sized task**: it is
research-grade work against an already-lookup-based baseline, and it would
invalidate every verifying key and tier in §4.5. It is correctly left deferred.

### 14.3 Security review

Scope: AlgoPlonk v0.3.1 in full (it is ~6,300 lines including tests); the gnark
code paths M7 actually exercises (the keccak gadget's `uints`/`logderivprecomp`
backing, `plonk.Setup`/`Verify`, the KZG verifying-key path); and M7's own
circuit, reviewed to the same standard. This is an informal review, not an audit.

#### 14.3.1 CONFIRMED DEFECT — the off-chain KZG pairing check is vacuous

This is the same bug class §4.12 already found, in the same function, and
**§4.12's conclusion that it is harmless is wrong.**

**What §4.12 recorded.** AlgoPlonk's `trustedSetupBN254` calls
`srs.Vk.ReadFrom(...)` and discards the error; the 160-byte `vk.bin` loads the
three points and "leaves `Lines` zeroed"; and "empirically this does not break
anything — all four vendored setups were compiled, proved and verified in this
pass and **all four pass**".

**What is actually wrong.** The four setups pass *because the check is vacuous*.

1. `setup/setup.go` discards **four** errors, not one: `srs.Pk.ReadFrom` **and**
   `srs.Vk.ReadFrom`, in **both** `trustedSetupBN254` (lines 189–190) and
   `trustedSetupBLS12381` (lines 173–174).
2. Measured (`cmd/aplines`): the vendored `vk.bin` is 160 B (BN254) / 240 B
   (BLS12-381) — exactly the three points. gnark-crypto v0.20.1's
   `kzg.VerifyingKey.ReadFrom` also expects 66×4 precomputed pairing lines and
   returns **`EOF`**. That error is discarded, leaving `Lines` **0/264 non-zero**.
3. `plonk.Setup` copies the SRS verifying key **verbatim** —
   `vk.Kzg = srs.Vk`, `backend/plonk/bn254/setup.go:128`. Nothing recomputes
   `Lines`.
4. `plonk.Verify`'s final step is `kzg.BatchVerifyMultiPoints(..., vk.Kzg)`,
   which calls `bn254.PairingCheckFixedQ(P, vk.Lines[:])`. With zeroed lines that
   check no longer constrains anything.

**Demonstrated, through AlgoPlonk's own documented production path** — plain
`ap.Compile(&Cubic{}, ecc.BN254, setup.PerpetualPowersOfTauBN254)`, no custom
SRS:

```
(1) vendored vk.bin = 160 bytes
    kzg.VerifyingKey.ReadFrom -> read 160 bytes, err = EOF     <- discarded
    Lines populated after the failed read: 0/264
(2) resulting plonk VerifyingKey.Kzg.Lines: 0/264 non-zero
(3) honest proof via cc.Verify: OK
(4) proof with CORRUPTED KZG opening -> plonk.Verify err = <nil>
    *** ACCEPTED. The off-chain KZG pairing check is VACUOUS. ***
(5) after vk.Kzg.Lines = bn254.PrecomputeLines(vk.Kzg.G2[i]):
    corrupted-opening proof -> err = can't verify opening proof   (rejected)
    honest proof            -> err = <nil>                        (accepted)
```

The tamper is the minimal one that isolates the pairing: the batch-opening point
`proof.BatchedProof.H` is replaced by `2·H`. Nothing else in `plonk.Verify` can
catch it — the algebraic-relation check runs earlier and passes. Corrupting
`proof.ZShiftedOpening.H` behaves identically (`cmd/linestest`).

**This project reaches the same defect by its own route.** `gnark-ptau`'s
`ToSRS` builds the SRS by hand and never sets `Lines` either — measured 0/264
(`cmd/linescheck`) — so §4.13's end-to-end runs, which bypass `setup.Run`
entirely, inherit it too.

**Scope and severity, stated carefully:**

- **This is an off-chain defect only.** The on-chain AlgoPlonk verifier is
  generated Algorand Python that performs its own pairing using the AVM's native
  BN254 operations and the verifying key's G2 points; it never consumes
  gnark's precomputed `Lines`. **§4.13's on-chain results, including the
  `rejected by logic` row for a tampered public input, are unaffected.**
- **What it does void is the off-chain gate.** §4.13 reports
  "`plonk.Prove` + `plonk.Verify` OK" and §9.5's Suite ZK leans on `plonk.Verify`
  to catch bad proofs. Against a malformed KZG opening it would not have. Every
  such claim in revisions 2–3 should be read as "the algebraic relation held",
  not "the proof verified".
- **Severity: medium.** It is a silent, total loss of one of two verification
  layers, in the trusted-setup loader, with no error surfaced anywhere.

**Fix — two lines**, and it is applied in `ptaufast`:

```go
vk.Lines[0] = bn254.PrecomputeLines(vk.G2[0])
vk.Lines[1] = bn254.PrecomputeLines(vk.G2[1])
```

**M12 action:** this should be reported upstream to AlgoPlonk. §4.12's note
("M12 should note it if this project ever pins AlgoPlonk as a dependency")
understates it; the swallowed error has a demonstrated consequence.

#### 14.3.2 M7's own circuit — two under-constrained findings

Reviewed with the same scrutiny, because a bug here is as dangerous as one in a
library. Probes are in `cmd/soundprobe` (gnark's test engine) and
`cmd/forgeproof` (real proofs).

**(a) `LogIndex` is not range-constrained. Confirmed with a real proof.**

`LogIndex` is a **public input**. The only thing bounding it is
`cp.AssertIsLess(c.LogIndex, nLogs)`, using `cmp.BoundedComparator` with
`absDiffUpp = 2³⁴`. gnark documents that comparator as sound only while
`|a − b| <= absDiffUpp`, and that beyond `P − 2^absDiffUpp.BitLen()` it "wrongly
produces reversed results".

Set `LogIndex = P − 1`. The assertion passes. No loop index `k` equals it, so
`isTarget` is never 1, `logOff` and `logLen` stay 0, and the circuit's log
commitment degenerates to `keccak256("")`.

| probe | result |
|---|---|
| honest witness (control) | satisfied |
| `LogIndex = n_logs` (small, out of range) | **rejected** |
| `LogIndex = 2³⁴` (just past the bound) | **rejected** |
| **`LogIndex = P−1`, `LogCommit = keccak256("")`** | **SATISFIED** |

Escalated from the test engine to a **real PLONK proof** at 2²¹ against the real
PPOT `_21` ceremony (`cmd/forgeproof`) — and, because `ptaufast` populates
`Lines`, this verification is a genuine check, not §14.3.1's vacuous one:

```
HONEST  (LogIndex = 0)
   plonk.Prove 32.6s -> plonk.Verify err = <nil>
FORGED  (LogIndex = P-1, LogCommit = keccak256(""))
   plonk.Prove 33.8s -> plonk.Verify err = <nil>
   *** A REAL PROOF OF THIS STATEMENT VERIFIES ***
```

**Is it exploitable end-to-end? Not demonstrated, and probably not.**
`MODE_ZK_CLOSE` step 7 asserts `pi[4] == R.log_index`, bound at `MODE_INIT` from
the caller, and step 6 asserts `pi[2]‖pi[3] == keccak256(log_bytes)`. An attacker
would need the group to have bound `log_index = P−1` *and* supply empty
`log_bytes`, which M2's decoder would then have to accept. Defence in depth holds.

**But the circuit is supposed to be self-contained** — §4.4's own argument for
enforcing canonicality in-circuit is that "the circuit is the only checker on
this path". A public input that is not range-constrained is exactly the
under-constrained class TP-M7-6 warns about, and it survives only because two
on-chain checks happen to catch it. **Fix:** add
`cp.AssertIsLessEq(c.LogIndex, p.MaxLogs)` before the comparator is used.

**(b) Hex-prefix canonicality: even-length paths do not constrain the low
nibble.**

For an even-length `hp_path` the compact encoding requires the low nibble of
byte 0 to be zero. `receipt.go` does `acc := api.Select(odd, lo0, 0)` — it
*ignores* `lo0` rather than asserting it. A leaf beginning `0x2d…` is accepted
where only `0x20…` is canonical (`soundprobe` probe C: **SATISFIED**, with the
leaf hash recomputed so assertion (1) still holds).

**Not exploitable** — `R` is pinned byte-for-byte by assertion (1) to a leaf
whose keccak matches a reference the walker read out of a node it hashed, so the
attacker would have to produce a real trie leaf with a non-canonical path. It is
nonetheless precisely the gap §4.4 commits to closing. **Fix:**
`api.AssertIsEqual(api.Select(odd, 0, lo0), 0)`.

Both findings are annotated in `circuit/receipt.go` at the exact lines. **The
fixes are deliberately NOT applied**, so that §4.5's recorded constraint counts
stay reproducible against that file; applying them is an implementation-pass
task.

**(c) What was reviewed and found sound.** Recorded so the negative result is
usable:

- **Span containment** (§4.4's "single most important constraint") is present
  and correct; `next ≥ cur` holds because every `payOff ≥ pos` and every
  `payLen ≥ 0`, and `cur` starts at `lgOff`, so the walk provably stays inside
  `[lgOff, lgEnd]`.
- `api.AssertIsEqual(cur, lgEnd)` correctly closes the "`MAXLOGS` too small, so
  `nLogs` is a lie" hole.
- **`LeafLen` is pinned**, by `AssertIsEqual(end, LeafLen)` against a bounded
  header; `LeafLen = P−1` is **rejected** (probe B), so the free private witness
  is not exploitable the way `LogIndex` is.
- The `hdr` packing is injective and cannot overflow: `txType ≤ 0x7f`,
  `status ∈ {0,1}`, `cumGas < 2⁶⁴`, `nLogs ≤ MAXLOGS`, total `< 2⁸⁸`.
- The outer structure is exactly closed (`vOff+vLen == end` with item 0 starting
  at `lo` forces exactly two items), as is the body (`bEnd == vOff+vLen` forces
  exactly four).
- The EIP-2718 branch correctly rejects the `0x80..0xbf` gap: such a byte sets
  `isTyped` yet fails `t0 ≤ 0x7f`.
- `reader.at`'s out-of-range clamping to index 0 is safe **given** the enclosing
  span assertions, which do chain back to `LeafLen ≤ N`. This is safe-by-
  construction-elsewhere rather than safe-locally, which is fragile under future
  edits; worth a comment if the circuit is ever extended.
- The `maxLenBytes = 4` cap is a completeness limit (receipts below 2³² bytes),
  not a soundness one: oversized `length-of-length` yields `ok = 0`, which every
  caller asserts.

**Not reviewed** (out of scope for this pass, flagged rather than implied):
AlgoPlonk's generated Puya verifier templates (`verifier/template*.go`, ~1,700
lines) and their BSB22 commitment handling on-chain; gnark's `keccakf` round
function against the FIPS-202 spec constant-by-constant.

#### 14.3.3 Other AlgoPlonk observations

- **`utils.SerializeCompiledCircuit` discards three `WriteTo` errors**
  (`Ccs`, `Pk`, `Vk`, `utils/utils.go:99–101`) and then returns `nil`. On a
  short write it persists a truncated key and reports success. This sits on the
  exact path §4.7.1 tells M9 to use — "the proving key must be computed once per
  circuit tier and persisted to disk" — where a silent truncation would surface
  much later as an unexplained proving failure.
- `setup/PerpetualPowersOfTauBN254/audit.go:39,49` discards `WriteTo` errors in
  the audit tool itself, which weakens the very procedure ZK-B7 relies on.
- `loadTrustedSetupBytes` mutates the byte slice returned by
  `embed.FS.ReadFile` (line 225, rewriting the G1 count). This is currently safe
  — `embed.FS.ReadFile` returns a copy via `[]byte(string)` conversion — but it
  is a latent hazard that depends on an implementation detail of the standard
  library rather than a documented guarantee.
- The `if g1Count < 2` guard and the `declaredG1Count < g1Count` check are
  otherwise reasonable, and truncating the ceremony to a prefix is the correct
  operation.

Nothing else in AlgoPlonk's ~6,300 lines looked wrong on careful reading. The
code-generation and marshalling paths §4.12 relies on (`CompiledCircuit` as a
plain struct, `verifier.WritePythonCode`, `ExportProofAndPublicInputs`) handle
their errors properly and behave as §4.12 describes.

#### 14.3.4 Version pinning and published advisories

| dependency | pinned as | latest published | pinning |
|---|---|---|---|
| `github.com/consensys/gnark` | **v0.15.0** | v0.15.0 | release tag |
| `github.com/consensys/gnark-crypto` | **v0.20.1** | v0.20.1 | release tag |
| `github.com/giuliop/algoplonk` | **v0.3.1** | v0.3.1 | release tag |
| `github.com/mdehoog/gnark-ptau` | **v0.0.0-20240119193856-bb5fe9a06e49** | (untagged) | exact commit |

Nothing floats on a branch, every module is hash-pinned in `go.sum`, and
`go mod verify` reports **all modules verified**. All three tagged dependencies
are at the **latest** published release.

Checked against the Go vulnerability database (`vuln.go.dev`):

| module | advisories on record | affects the pinned version? |
|---|---|---|
| `gnark` | 8 (`GO-2023-2098/2119/2333`, `GO-2024-3122/3123/3244`, `GO-2025-3912/3929`) | **No** — the latest fix version among them is **v0.14.0**; pinned at v0.15.0 |
| `gnark-crypto` | 4 (`GO-2023-2096/2101`, `GO-2025-4027/4087`) | **No** — `GO-2025-4087` covers 0.9.1–0.18.1 and 0.19.0–0.19.2; pinned at v0.20.1, outside both ranges |
| `algoplonk` | none on record | — |
| `gnark-ptau` | none on record | — |

> **No known published security advisory affects any version this project pins.**

One supply-chain observation that is not an advisory: **`gnark-ptau` is a
~200-line, single-author, untagged module whose last commit is 2024-01-19**, and
it sits directly on the trusted-setup path. It is also the source of the zeroed
`Lines` defect on this project's own route (§14.3.1). `ptaufast` removes the
dependency for the BN254 PLONK path entirely, which is a small but real
reduction in trusted surface.

### 14.4 Summary of what revision 4 changes

| | finding | status |
|---|---|---|
| **§4.7.1 / §4.11** | `ToLagrangeG1` is the dominant *time* cost (91 %) but **not** the memory ceiling (1.46 GB vs `plonk.Setup`'s 1.99 GB) | **correction** |
| **§4.7.1** | the cost is `(n/2)·log₂n` scalar mults in the FFT, ~10.5× the "one per point" the doc states | **correction** |
| **§4.7.1 / §4.9** | `ToLagrangeG1` is **unnecessary**: `.ptau` section 12 already holds the Lagrange SRS, byte-identical. 169.8 s → 0.15 s at 2²¹ | **new** |
| **§4.6 / §8.2** | `ptaufast`: SRS acquisition 1.46 GB → 0.50 GB, 164.6 s → 0.5 s; setup phase at 2²⁴ plausibly fits 32 GB | **new** |
| **ZK-B4** | **superseded — CLOSED in §14.6**, a later pass on a real 64 GB AWS host | **closed** |
| **ZK-B8** | largest real compile at the time this row was written was 17,757,682 constraints (was 16,293,891); **superseded — CLOSED in §14.7**, tier B and tier C both fully proven end-to-end and verified on-chain on real hardware | **closed** |
| **O-M7-4** | no faster keccak exists; gnark's is already lookup-based; leaf keccak is irreducible. sha256-log + `WithMinimalLength` = −5.96 % on tx 73, enough to fit 2²⁴ → **97.8 % → 98.5 % coverage** | **evaluated** |
| **ZK-B9** | a tier becomes `(N, LOGMAX, MinLeaf, MinLog)` if `WithMinimalLength` is adopted | **widened** |
| **§4.12** | the swallowed `ReadFrom` error **does** break something: the off-chain KZG pairing check is vacuous, demonstrated on AlgoPlonk's own path | **CORRECTION — confirmed defect** |
| **§4.13 / §9.5** | every "proof verified" claim in revisions 2–3 covered the algebraic relation but not the KZG opening | **correction** |
| **new** | `LogIndex` is an unconstrained public input; a real forged proof verifies | **confirmed defect, circuit** |
| **new** | even-length `hp_path` low nibble unconstrained | **canonicality gap, circuit** |
| **§14.3.4** | all deps pinned to latest releases, `go mod verify` clean, no advisory affects any pinned version | **clean** |

### 14.5 Revision 5 — §14.3.2's two circuit fixes applied for real, and re-verified

§14.3 recorded three findings and deliberately did not apply the two circuit
fixes, "so that §4.5's recorded constraint counts stay reproducible against
that file". This pass applies both, for real, directly to `circuit/receipt.go`,
and re-runs the exact probes that originally demonstrated each bug.

**§14.3.1 (AlgoPlonk's vacuous off-chain KZG check) — nothing to apply, workaround
reconfirmed.** This defect is in a third-party dependency, not in code this
project ships; `ptaufast` is the only place a fix belongs, and it already has
it (`ptaufast.go`: `vk.Lines[0] = bn254.PrecomputeLines(vk.G2[0])`, same for
`[1]`). Re-running `cmd/aplines` against the real vendored
`PerpetualPowersOfTauBN254/vk.bin` reproduces §14.3.1's exact sequence, fresh:

```
(1) vendored vk.bin = 160 bytes
    kzg.VerifyingKey.ReadFrom -> read 160 bytes, err = EOF
    Lines populated after the failed read: 0/264
(2) resulting plonk VerifyingKey.Kzg.Lines: 0/264 non-zero
(3) honest proof via cc.Verify: OK
(4) proof with CORRUPTED KZG opening -> plonk.Verify err = <nil>
    *** ACCEPTED. The off-chain KZG pairing check is VACUOUS. ***
(5) repairing Lines with bn254.PrecomputeLines and retrying:
    corrupted-opening proof -> plonk.Verify err = can't verify opening proof
    honest proof            -> plonk.Verify err = <nil>
```

Steps (1)–(4) are AlgoPlonk's own path, unpatched; step (5) is `ptaufast`'s
fix applied by hand to the same objects, confirming it is real and sufficient.
A draft upstream issue — the four discarded `ReadFrom` errors, the concrete
consequence, this reproduction, and the two-line fix — is written to
`UPSTREAM_ISSUE_ALGOPLONK.md` in this directory for human review; nothing was
filed against `github.com/giuliop/algoplonk`.

**§14.3.2(b) (hex-prefix canonicality) — applied exactly as specified.**

```go
api.AssertIsEqual(api.Select(odd, 0, lo0), 0)
```

`cmd/soundprobe`'s probe C (even `hp_path`, low nibble `0xd` instead of `0`,
leaf hash recomputed so assertion (1) still holds) now reports **rejected**,
where it previously reported **SATISFIED**.

**§14.3.2(a) (`LogIndex` range check) — applied, but not as literally
specified, and this matters.** §14.3.2(a)'s suggested fix,
`cp.AssertIsLessEq(c.LogIndex, p.MaxLogs)`, was applied first and **verified
to NOT close the bug**: `cmd/soundprobe`'s probe A1 (`LogIndex = P−1`) still
reported **SATISFIED**. The reason is structural, not a typo: `cp` is the
*same* `cmp.BoundedComparator` (`absDiffUpp = 2³⁴`) whose unsoundness beyond
that bound is the bug being fixed. `AssertIsLessEq(a, b)` is implemented as
"assert `b − a` is non-negative within `absDiffUppBitLen` bits"; for
`a = P−1`, `b = MaxLogs`, `b − a mod P` wraps to the small non-negative value
`MaxLogs + 1`, so the check passes for exactly the same reason the original
`AssertIsLess(LogIndex, nLogs)` did. A bounded comparator cannot be used to
bound an adversarial, potentially-field-sized public input against a small
constant — that is precisely the input class it is unsound for.

The real fix applied instead uses gnark's field-width range check, which
decomposes `LogIndex` into the full scalar-field bit length rather than a
bounded difference, and is therefore sound for any `LogIndex ∈ [0, P)`:

```go
api.AssertIsLessOrEqual(c.LogIndex, p.MaxLogs)
```

With this, `cmd/soundprobe`'s full probe-A set now reports:

```
probe A -- LogIndex is a public input; is it range-constrained?
  LogIndex = P-1, LogCommit = keccak256("")                  rejected   (want reject)
  LogIndex = n_logs (=2), out of range                       rejected   (want reject)
  LogIndex = 2^34 (past comparator bound)                     rejected   (want reject)
```

(all three previously either "SATISFIED <<< UNEXPECTED" or already-passing;
A1 is the one that changed.)

**Real new constraint count.** Recompiled tier A — `N=8567, LogMax=640,
MaxLogs=48`, `go run ./cmd/measure -sizes=8567 -logmax=640 -maxlogs=48` —
with both fixes in place:

| | constraints |
|---|---:|
| §4.5.2 baseline (pre-fix, reproduced fresh this pass) | 16,293,891 |
| with both fixes applied | **16,294,913** |
| Δ | **+1,022 (+0.0063 %)** |

The increase is almost entirely `api.AssertIsLessOrEqual`'s full field-width
bit decomposition for the `LogIndex` check; the hex-prefix fix is one
`AssertIsEqual` and negligible on its own. Both are well inside the "small
increase... expected and fine" range, and nowhere near moving tier A off 2²⁴.

**Real end-to-end proof forgery re-attempt (`cmd/forgeproof`, tx 85 params,
`N=384, LogMax=96, MaxLogs=4`, real PPOT `_21` ceremony via `ptaufast`):**

```
circuit: 1341825 constraints, domain 2097152
ptaufast SRS load: 0.59s (real PPOT ceremony, 2097155 canonical pts)
plonk.Setup: 5.15s

HONEST  (LogIndex = 0)
   plonk.Prove 33.4s -> plonk.Verify err = <nil>
   *** A REAL PROOF OF THIS STATEMENT VERIFIES ***
FORGED  (LogIndex = P-1, LogCommit = keccak256("")): PROVE FAILED: constraint
#219169 is not satisfied: qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC != 0 →
0 + 0 + 0 + 1 + 0 != 0
```

Honestly: the forged witness now fails to **satisfy the circuit at all** —
`plonk.Prove` cannot even produce a proof, let alone one that verifies. This is
strictly stronger than "a proof is produced but `plonk.Verify` rejects it":
there is no proof object for a forger to submit in the first place. The
honest witness (`LogIndex = 0`) still proves and verifies exactly as §14.3.2
originally reported — **no regression** on the real end-to-end path.

**Conclusion.** Both findings from §14.3.2 are now genuinely closed in
`circuit/receipt.go`, confirmed by gnark's test engine (`cmd/soundprobe`) and by
a real PLONK proof against the real Perpetual Powers of Tau ceremony
(`cmd/forgeproof`). §14.3.1 required no code change in this project and its
`ptaufast` workaround is reconfirmed in place; an upstream report is drafted,
not filed. One correction to §14.3.2(a)'s text: its literal one-line fix
suggestion does not work, for the reason given above — the working fix uses
`api.AssertIsLessOrEqual`, not `cp.AssertIsLessEq`.

### 14.6 Revision 6 — ZK-B4 CLOSED: a real proof at tier A's deployed scale, and real on-chain verification

Every prior pass measured tier A (`N=8567, LogMax=640, MaxLogs=48`, 2²⁴ domain,
16,294,913 constraints post-§14.5 fixes) only up to `plonk.Setup`, or died to OOM
partway through a smaller domain on a 14 GB box. **No proof had ever been produced
at the domain this design actually intends to deploy.** This pass closes that gap
on real hardware, not a bigger extrapolation.

**Environment.** AWS EC2 `r7i.2xlarge` (8 vCPU, 61 GiB RAM), Amazon Linux 2023,
`us-east-1`, driven over AWS Systems Manager (no SSH — the operating environment's
own network policy blocks outbound port 22, so this pass used SSM `send-command` /
`get-command-invocation` end to end, including chunked-base64 transfer of this
project's own untracked `tests/fixtures/spike-reference/zk-m7/` tree, since it
carries the real circuit code this design doc's own numbers depend on and had
never been pushed to the repo's GitHub remote). Root volume grown from the
default 8 GB to 100 GB before starting — the 2²⁴ ceremony file alone is 18 GB.
Go 1.25.3 (toolchain auto-upgraded to 1.25.7 per `go.mod`), same `go.mod`/`go.sum`
pins as every other measurement in this document.

**The ceremony file.** `powersOfTau28_hez_final_24.ptau` from
`https://storage.googleapis.com/zkevm/ptau/`, the same source §3's and §4's
smaller-tier downloads used. `19,327,435,928` bytes, matching the source's
`Content-Length` exactly (no truncation). `sha256 =
032647abe127f4562f8118dd5f866ab595c1f2bbd03d0a85ff3739a4a967d9be`, recorded here
so a future pass can diff against it rather than re-trust the download blindly —
this is not a substitute for TP-M7-5's actual ceremony-transcript audit (§4.12's
`cmd/ptau -mode=audit` machinery), which this pass did not re-run for the 2²⁴ file
specifically.

**The real end-to-end run (`cmd/prove`, not `ptaufast` — this tool uses the
standard `ToSRS` path, so its SRS-load numbers are not the `ptaufast`-optimized
ones §14.1 reports).** Real receipt: tx 1 of the pinned block, leaf 5,868 B (one
of the six of nine oversized receipts that fit tier A's `LOGMAX`, per §4.5.3), log
0 of 32, EIP-1559. `LeafHash` and log-0 keccak both independently cross-checked
against a fresh `dump_log.py` run and matched exactly.

```
compiled: nbConstraints=16294913 nbPublic=7 commitments=1 -> domain 2^24
ptau: 33554431 G1 points (power 2^24), loaded in 23.8s
lagrange SRS built in 1773.4s
plonk.Setup in 45.0s
plonk.Prove + plonk.Verify OK in 203.7s
proof=864 bytes public_inputs=224 bytes (7 field elements)
```

| phase | measured | notes |
|---|---:|---|
| circuit compile | 14.1 s | matches §14.5's 16,294,913 exactly, reproduced fresh |
| SRS load (`ToSRS`, unoptimized) | 23.8 s | this tool doesn't call `ptaufast`; §14.1's 0.5–0.59 s figures are a different code path |
| Lagrange SRS build (`ToLagrangeG1`) | 1,773.4 s (~29.6 min) | the dominant cost, exactly the "~40 min at 2²⁴" order of magnitude §14.1.3 projected before this pass had a real number |
| `plonk.Setup` | 45.0 s | |
| `plonk.Prove` + `plonk.Verify` | 203.7 s (~3.4 min) | **this is the number that had never been measured above 2²¹ before this pass** |
| total wall clock | 34m 22s | `/usr/bin/time -v` around the whole process |
| **peak RSS** | **29,988 MB (~29.3 GiB)** | higher than §14.1.3's ~16 GB extrapolation for the per-proof phase, but comfortably inside the 64 GB the design has recommended since §0.2 — the recommendation was right, the earlier number was an underestimate |

`plonk.Verify` (gnark, off-chain, algebraic + KZG) returned no error — the real
`ptaufast.go`-style `Lines`-population fix from §14.3.1/§14.5 was not needed here
because `cmd/prove` uses the unpatched `ToSRS`/`plonk.Setup` path directly (not
AlgoPlonk's vendored `pk.bin`/`vk.bin`), which populates `Lines` correctly by
construction — this is a different code path from the one §14.3.1 found broken,
not a re-confirmation of that fix.

**Real on-chain verification, not just `plonk.Verify`.** Per §4.8's group shape,
using this project's own `onchain.py` unmodified: `algorand/algod:latest` in
dev-mode with `EnableDeveloperAPI`, Docker, on the same EC2 host. Two real
toolchain issues surfaced and were fixed, recorded here because they will recur
for anyone reproducing this:

1. A fresh `pip install puya` gets the wrong package — `puya` (PyPI) tops out at
   `0.6.0` and does not support the `@logicsig` decorator AlgoPlonk's generated
   code uses (`puyapy` reports `Unsupported function decorator
   "algopy._logic_sig.logicsig"` and fails to resolve `algopy.BigUInt`). The
   package that actually is this document's recorded `puyapy 5.9.0` is a
   **separately-versioned PyPI package literally named `puyapy`**, not `puya`.
   `pip install puyapy==5.9.0` (alongside `algorand-python==3.5.0`, unchanged)
   resolves it.
2. `puyapy` shells out to a bare `python3` for parts of its own pipeline; if that
   resolves to the system interpreter rather than the venv's, it fails with
   `unsupported Python version: 3.9.25` even though the invoking venv is 3.12.
   Fix: put the venv's `bin/` first on `PATH` for the `puyapy` invocation itself,
   not only for the Python that launches it.

With both fixed, `puyapy` compiles `M7VerifierTierA.py` to a 79,859-byte TEAL
source, which algod compiles to a 3,926-byte logicsig program (close to §4.1's
3,924 B for the smaller tx-85 tier — verifier size does not grow with the
statement it proves, exactly as §0.1 predicted).

```
logicsig address = P6MYL36HE227Z6FXYBITJK4RD2W4FAS7QSO37FVJY257AORTHPIFKC7SJA
total application-args bytes = 1255 (AVM cap 2048)
app-budget-consumed: 2
logicsig-budget-consumed: 186954 (of the 320,000 pool)
VERIFIED ON-CHAIN (simulate): proof accepted by the logicsig
negative (1 bit flipped in public inputs): rejected -- no soundness hole
REAL SUBMISSION CONFIRMED in round 2, app id 1002
```

`186,954` logicsig budget is close to but not identical to §4.13's `185,370`/
`185,454` for the smaller tx-85/tx-8 tiers — consistent with §0.1's "a PLONK
verifier's cost does not grow with the statement it verifies", with the small
delta attributable to the different circuit's constant terms (7 public inputs
here vs. tx-85's own count, one BSB22 commitment either way) rather than to
domain size. The negative test — the same one-bit public-input tamper §9's ZK-9
specifies — was rejected, not accepted, on the real deployed-tier circuit.

**What this closes, precisely.** ZK-B4 asked whether a proof could be produced —
not simulated, not extrapolated — at the domain this design actually intends to
run at. It now has been, twice over: once as a bare `plonk.Prove`/`plonk.Verify`
pair, and once more as a real AlgoPlonk logicsig accepting that exact proof in a
real non-simulated Algorand transaction. Both used the real tx-1 receipt from the
pinned fixture block, the real PPOT `_24` ceremony, and the real tier-A circuit
parameters this document has settled on since revision 2.

**What this does not close.** This is one proof, at one point in the coverage
table (tx 1, not the harder tx 73/tx 6 boundary cases §4.5.3 flags, and not tier
B/2²⁵ — ZK-B8 is unaffected). §5.4's `R_INCOMPLETE` path, ZK-B9's tier-selection
design question, and the circuit's own TP-M7-6 trust assumption are all exactly
where §14 left them. The generated `.py`/`.teal`/`.proof`/`.public_inputs`
artifacts were deliberately **not** committed, per this directory's own
`README.md` — they are reproducible from the commands above and from the pinned
`generated/tierA/M7VerifierTierA.report.json`, which **is** kept, in the same
spirit as the existing `M7VerifierTx8.report.json` / `M7VerifierTx85.report.json`.

### 14.7 Revision 7 — ZK-B8 CLOSED: tier B and tier C, real proofs, real on-chain verification, and the real coverage ceiling

§14.6 closed ZK-B4 with one proof at tier A. This pass closes **ZK-B8** by doing
the same thing to tier B and tier C — the two tiers the coverage table's 98.5 %
and 99.3 % figures rested on, which until now were §4.5.3's formula projections,
never compiled at full size, let alone proven. Both are now real, on the same
AWS environment §14.6 used (same account, same instance, resized as needed),
and both used the actual real receipt each tier exists to cover: tx 73 for tier
B, tx 6 for tier C — the two receipts §4.5.3 identified as excluded from tier A
specifically because their largest **log**, not their leaf, exceeds tier A's
`LogMax`.

| | **tier A (§14.6)** | **tier B** | **tier C** |
|---|---:|---:|---:|
| receipt | tx 1 | tx 73 | tx 6 |
| leaf / largest log | 5,868 B / small | 7,546 B / 2,368 B | 15,463 B / 8,061 B |
| `N`, `LogMax`, `MaxLogs` | 8567, 640, 48 | 8567, 2560, 48 | 16384, 8192, 48 |
| domain | 2²⁴ | 2²⁵ | 2²⁶ |
| constraints | 16,294,913 | 19,688,551 | 43,353,550 |
| ceremony file | 19.3 GB | 38.7 GB | 77.3 GB |
| compile | 14.1 s | 17.9 s | 37.6 s |
| SRS load (`ToSRS`) | 23.8 s | 46.9 s | 96.2 s |
| Lagrange SRS build | 1,773.4 s | 3,635.2 s | 3,772.7 s |
| `plonk.Setup` | 45.0 s | 78.6 s | 85.4 s |
| `plonk.Prove`+`Verify` | 203.7 s | 384.6 s | 429.6 s |
| **total wall clock** | **34m 22s** | **1h 9m 25s** | **1h 13m 48s** |
| **peak RSS** | **30.0 GB** | **44.6 GB** | **95.2 GB** |
| host | `r7i.2xlarge` (8 vCPU, 64 GB) | `r7i.2xlarge` (unchanged) | `r7i.4xlarge` (16 vCPU, 128 GB) |
| coverage this closes | 97.8 % | 98.5 % | **99.3 %** |
| on-chain result | round 2, app 1002 | round 4, app 1019 | round 6, app 1036 |
| logicsig budget | 186,954 | 186,838 | 187,730 |

Every row's `plonk.Verify` (gnark, off-chain) passed with no error, and every
tier's real AlgoPlonk logicsig — compiled fresh by `puyapy` from the AlgoPlonk-
generated Puya source, deployed to a real dev-mode algod — accepted the proof
in a **real, non-simulated Algorand transaction**, and rejected the same §9/ZK-9
one-bit-tampered-public-input negative test every time. The three logicsig
budget figures (186,954 / 186,838 / 187,730) span a 4× domain range and differ
by under 0.5 % — the strongest confirmation yet of §0.1's central claim that
**a PLONK verifier's on-chain cost does not grow with the statement it proves.**

**What tier C's real numbers correct about extrapolating from tier A and B
alone.** Tier A → tier B is an exact domain doubling (2²⁴ → 2²⁵), and its wall
clock scaled 2.02× — almost exactly with domain, not with the 1.21× the raw
constraint count grew by, confirming the FFT-heavy steps are domain-bound. Naively
applying that same 2.02× again to tier B → tier C predicted roughly 2.5–3 hours.
**The real tier C run took 1h 13m 48s — faster than tier A → B's own scaling
factor would predict**, because tier C ran on a host with double the vCPUs
(`r7i.4xlarge`, 16 vCPU, vs. the 8 vCPU used for tiers A and B) and the dominant
steps parallelize well (1,521 % CPU utilization measured via `/usr/bin/time`).
**Memory did not cooperate the same way**: tier A → B's peak-RSS ratio (1.49×)
extrapolated to tier C predicted roughly 66–89 GB; the real figure was **95.2 GB**
— higher than either extrapolation. The practical lesson, stated plainly: neither
wall-clock nor memory scaling from two data points reliably predicts a third at a
different vCPU count. **A genuinely larger domain (2²⁷, the largest existing PPOT
ceremony) needs measuring on real hardware before any host is sized for it — not
extrapolating from tiers A–C.**

**Two operational findings worth recording so a future pass does not repeat
them.** Neither is a defect in this project's code; both are about driving AWS
and SSM correctly for a run this long.

1. **`aws ssm send-command --timeout-seconds` does not control script runtime.**
   It is the *delivery* timeout (how long SSM waits for the command to start on
   the instance). The parameter that actually caps how long the running script
   is allowed to execute is the `AWS-RunShellScript` document's own
   `executionTimeout` parameter (default 3,600 s = 1 hour, max 172,800 s). Tier
   B's first two real attempts were both silently SIGKILLed (`exit 137`) at
   exactly the 1-hour mark, deep inside the Lagrange SRS build, because only
   `--timeout-seconds` had been set. The fix is
   `--parameters commands=[...],executionTimeout=["14400"]` — passed as a
   second key in the same `--parameters` argument, not a separate CLI flag.
   `aws ssm list-commands --command-id ... --query 'Commands[0].Parameters'`
   confirms which one actually took effect before committing a multi-hour run
   to it.
2. **A stopped/started EC2 instance's Docker containers do not come back on
   their own** unless given a restart policy at `docker create` time (this
   project's `zkalgod` container was not). Every time the instance was
   stopped and started — including for the `r7i.2xlarge` → `r7i.4xlarge`
   resize tier C needed — `dev-mode algod` had to be brought back up by hand
   (`docker start zkalgod`) before `onchain.py` could reach `:4051`/`:4052`
   again. The dev-mode chain's own state (round number, deployed app IDs)
   persisted correctly across every restart, which is why the round numbers
   above climb continuously (2, 4, 6) rather than resetting.

**Real AWS service quota, not a design or code limit.** `r7i.8xlarge` (32 vCPU),
the size originally planned for tier C on the theory that RAM would be the
binding constraint, was rejected outright by EC2 (`VcpuLimitExceeded`) — this
AWS account's on-demand vCPU quota for this instance-family bucket is 16, and
`r7i.4xlarge` (16 vCPU, 128 GB) was the largest size available without a quota
increase request. It turned out to be the right choice for a different reason
than intended (§14.7's memory finding above), but the constraint itself was an
account limit, not anything about the circuit.

**What this establishes about the real coverage ceiling.** Combined with
§14.6, this project has now generated and on-chain-verified a real proof for
one real receipt at **every tier the coverage table names** — 2²⁴ (97.8 %),
2²⁵ (98.5 %), and 2²⁶ (99.3 %). The ninth receipt, tx 119, is not merely
unproven — §2's earlier OOM finding at 64 GB (a plain `cmd/measure` compile,
nothing to do with the proving pipeline) independently confirms it needs a
domain far beyond 2²⁶, consistent with §4.6's ~2²⁹ estimate, and no Perpetual
Powers of Tau ceremony reaches that size. **99.3 % is not a projection or a
target — it is this design's real, measured, on-chain-demonstrated ceiling**,
and 100 % is not reachable by this mechanism regardless of hardware budget.

Real measured results are pinned in `generated/tierB/M7VerifierTierB.report.json`
and `generated/tierC/M7VerifierTierC.report.json`, alongside tier A's, in the
same spirit as the existing `M7VerifierTx8`/`M7VerifierTx85` reports. The
generated `.py`/`.teal`/`.proof`/`.public_inputs` blobs for tiers B and C were,
again, deliberately not committed.

### 14.8 Revision 8 — the real population sample (M11's ask, closed), and the real cost of a second proof

Two separate findings this pass, both correcting numbers the rest of this
document had been quoting as final.

**Finding 1: the two-block fixture overstated how often T3 is needed, by about
3×.** §3.1 always flagged this as a risk — "two blocks is a thin basis" — and M11
was named as the owner of widening it. This pass does that: 300 real blocks
(`eth_getBlockReceipts` against public RPC, no archive node needed, spanning
blocks 25,589,679–25,689,984, a real ~14-day window), **94,667 real receipts**,
leaf size computed the same way §3.1 does (RLP-encoded receipt body + a
conservative 9-byte hex-prefix/list overhead, so this never *undercounts* which
tier a receipt needs).

| | 2-block fixture | **300-block sample (real)** |
|---|---:|---:|
| T1 + T2 (no ZK needed) | 93.4 % | **97.50 %** |
| any ZK tier needed | 6.57 % | **2.21 %** (tier A 1.14 %, tier B 0.43 %, tier C 0.63 %) |
| unprovable | ~0.7 % | **0.29 %** |

The two-block fixture wasn't chosen dishonestly — block 25,639,768 was picked in
an earlier pass specifically because it *exercises* the T1/T2/T3 boundary cases
this project needed to test, and it was never presented as a population sample.
But it does mean every "how often is T3 needed" number quoted from it was ~3×
pessimistic. The per-tier *mechanism* and bounds (§3.1, §4.5) are unaffected —
this finding is purely about the real-world invocation frequency, which matters
for M9's classifier design and for any cost/pricing model built on top of this
module, not for whether the tiers work. Tooling and raw output:
`tests/fixtures/spike-reference/sample_coverage.py` and
`coverage_sample_300blocks.json`.

**Finding 2: proving a second receipt does not cost what §14.6/§14.7 measured —
those numbers bundled a one-time cost into every proof.** PLONK's own design
separates a circuit's trusted setup (produces a proving key, depends only on the
circuit shape) from proving a specific witness (depends on the actual receipt).
§14.6 and §14.7's `cmd/prove` never made that separation — it recompiled,
reloaded the ceremony, rebuilt the Lagrange SRS, and reran `plonk.Setup` on
*every single invocation*, so "$0.30/proof" was really "$0.30 to set up tier A
plus prove one receipt," not a real per-customer marginal cost.

This pass adds `cmd/setupkeys` (runs the one-time part, writes `ccs`/`pk`/`vk`
to disk via gnark's own `WriteTo`/`ReadFrom` — the standard, documented way to
do this, not a workaround) and `cmd/provewith` (loads those files, proves).
Real test, same tier-A ceremony file reused from §14.6 (the 2²⁶ file is a strict
superset of what 2²⁴ needs, so no fresh 19 GB download was required):

| | one-time setup | proof 1 (tx 1) | proof 2 (tx 2, same cached keys) |
|---|---:|---:|---:|
| time | 32m 3s | 244.9s (44.2s load + 200.7s prove) | 248.3s (46.3s load + 202.1s prove) |
| cost | (amortizes to ~0 across many proofs) | **$0.0360** | **$0.0365** |

Both proofs verified correct (`plonk.Verify`, real gnark check, not skipped);
tx 1's leaf hash matches §14.6's original full-pipeline run exactly, confirming
the cached keys produce identical results to a from-scratch run. **Average real
marginal cost: $0.0363/proof, ~4.1 minutes — 8.3× cheaper than the $0.30
full-pipeline figure**, once a tier's setup is cached and reused, which is how
any real service would actually run this, not a hypothetical optimization.

One honest caveat: both proofs ran on the same instance immediately after the
setup that just wrote those key files, so the ~45s key-load benefited from a
warm OS page cache. A genuinely cold spin-up-per-request architecture (fresh
instance, attach a volume with the cached keys, prove) would add real instance
boot time (~1-2 min) on top of the ~45s measured here — the Prove step itself
(~200s) is unaffected either way. Tier B and tier C's marginal costs were **not**
re-measured this pass — the numbers below are projected from each tier's already
-measured Prove-only time (§14.6/§14.7) plus a load-time estimate scaled by
constraint count as a proxy for proving-key size, and should be measured the
same direct way tier A's was before being relied on:

| tier | measured Prove-only (§14.6/14.7) | **projected marginal cost, cached** |
|---|---:|---:|
| A | 203.7s | **$0.0363 (measured, this pass)** |
| B | 384.6s | **~$0.065 (projected)** |
| C | 429.6s | **~$0.16 (projected)** |

Full artifacts: `generated/marginal/setup_and_marginal_costs.json`,
`keys/M7TierA.setup_report.json`. The `M7TierA.pk` (1.07 GB), `.ccs` (406 MB),
`.vk`, and `.py` files are exactly the kind of reusable, witness-independent
artifact this directory's README already asks not to be committed — same
reasoning as the proof blobs, scaled up.
