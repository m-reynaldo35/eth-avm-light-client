# 003 — M3: SSZ Merkle branch verifier

**Module**: M3 · **Status**: Design Drafted · **Depends on**: scaffold ·
**Consumed by**: M4 (sync-committee update verifier), M8 (trusted-root anchor)
**Author**: design pass, 2026-07-30

---

## 0. Executive summary

M3 is the generic SSZ Merkle-branch primitive: given a leaf hash, a sibling
array, and a generalized index, fold to a root and compare it against a
caller-supplied expected root. It is the SSZ counterpart of M5's MPT
path-walker, and it is the last unmeasured piece of Track A.

Everything below is backed by real `/v2/transactions/simulate` responses
produced during this design pass. Headline results:

| Finding | Value | §  |
|---|---|---|
| **`sha256` AVM cost** | **35, flat for all input sizes 32 B → 4096 B** | 2.2 |
| `sha256` vs `keccak256` | 35 vs 130 — SSZ hashing is **3.71× cheaper** than MPT hashing | 2.3 |
| Exact branch-verify cost model | `53 + 61·depth + 2·z` (z = left-child levels), **validated exactly on 15 measured gindices** | 2.5 |
| Every real light-client branch | 299–488 budget → **fits in one 700-budget app call**, no budget donors | 2.4 |
| Single-app-call depth ceiling | **depth ≤ 10** (worst case 683); depth 11 = 746 → 2 calls | 2.6 |
| Official spec-vector validation | **38/38** `single_merkle_proof` vectors across 6 forks verify on-chain | 2.10 |
| 512-pubkey committee merkleization | **69,078 budget / 99 app calls / 0.099 ALGO** (resolves M1 §10.1) | 2.7 |
| Fork decision | **Do not pin a fork.** gindex is a runtime `UInt64` parameter | 4 |

The single most important *security* statement in this document is §6: M3
proves "*some* node at the position named by `gindex` folds to this root". It
proves nothing about *which field* that is. The gindex is therefore a
consensus-critical constant that M4/M8 must supply from a fork-gated table they
control, **never** from relayer-supplied data. This is the same class of bug as
M5's inherited security fix (trusting a caller-supplied step list).

---

## 1. Scope and non-goals

### 1.1 In scope

1. **`compute_merkle_branch_root(leaf, branch, gindex) -> root`** — the fold.
   Bit-exact with the consensus spec's `compute_merkle_branch_root`
   (`specs/phase0/beacon-chain.md`).
2. **`assert_valid_merkle_branch(leaf, branch, gindex, root)`** — the fold plus
   the equality assertion and the length invariant. Mirrors
   `is_valid_merkle_branch`, in `assert`-form (see §7.6 on why not `bool`).
3. **`assert_valid_normalized_merkle_branch(leaf, branch, gindex, root)`** —
   mirrors the light-client spec's `is_valid_normalized_merkle_branch`,
   including the must-be-zero check on leading padding slots. This is the form
   M4 should call; see §3.5 and §4.4.
4. **Generalized-index decomposition** — `floorlog2` / `get_subtree_index`
   equivalents derived on-chain from `gindex` via `bitlen` (§3.1).
5. **Zero-hash table** — `ZERO_HASHES[i]`, the root of an all-zero subtree of
   depth `i`, needed for SSZ list/vector padding to the next power of two
   (§7.4).
6. **`merkleize_stack`** — incremental O(depth)-scratch merkleization of a chunk
   stream, plus `mix_in_length`. Required because M1 §10.1 hands M3 the job of
   merkleizing 512 committee pubkeys on-chain, and because a full leaf layer
   does not fit in an AVM value (§2.8).

### 1.2 Non-goals

- **The specific generalized indices for any proof type.** M3 never names
  `NEXT_SYNC_COMMITTEE_GINDEX`, `FINALIZED_ROOT_GINDEX`, or
  `EXECUTION_PAYLOAD_GINDEX`. It takes `gindex` as a parameter and has no
  fork-conditional code. **M4 owns** the sync-committee and finality gindices
  and their fork gating; **M8 owns** the beacon-block-root →
  `ExecutionPayload.state_root`/`receipts_root` gindices. §4.5 specifies exactly
  what those modules must supply and §5.4 gives the plug-in point.
- **SSZ serialization/deserialization.** M3 hashes 32-byte chunks. Turning a
  `BeaconBlockHeader` or a `SyncCommittee` into chunks is the caller's job
  (M4/M8), and mostly the relayer's (M9).
- **`hash_tree_root` of arbitrary containers.** M3 exports the merkleization
  *primitive* (§1.1.6); it does not carry SSZ type schemas. No fork-versioned
  field layout ever enters this module — that is the whole point of §4.
- **Multiproofs.** Verifying several leaves against one root with a shared
  sibling set (`verify_merkle_multiproof`) is not in v1. Each proof is
  independent. §7.7 records why and what it would cost.
- **`keccak256` / MPT.** Different tree, different hash, different module
  (M2/M5). §2.3 exists only to stop anyone reaching for the wrong opcode.

---

## 2. Empirical baseline

Per `ARCHITECTURE.md`, no number in this document is quoted from
documentation. Every figure below traces to a real simulate response.

### 2.1 Environment

- Dev-mode Algorand localnet, **`go-algorand 4.7.3.stable` (commit `4d11e2e9`)**,
  consensus protocol `future`, algod `:4051`, kmd `:4052`, token `64×'a'`,
  `EnableDeveloperAPI=true` — the spike's container recipe
  (`tests/fixtures/spike-reference/README.md`), reused unmodified.
- AVM `#pragma version 10`, `extra_pages=3`.
- Simulate `extra-opcode-budget = 320,000`; `app-budget-added = 320,700`
  (= 700 base + 320,000 extra) on every response, confirming the spike's cap.
- Baseline `int 1; return` consumes **2**. A bare `bytecblock`+`bytec` push
  consumes **5**.
- Harness: same pattern as `avm_bls_bench.py` / `mpt_bench.py` (assemble minimal
  TEAL → `/v2/teal/compile` → `simulate` → read `app-budget-consumed`).

### 2.2 `sha256` cost curve — the number this module was blocked on

Isolated by differencing a push-only program against the same program with the
opcode appended.

| input | push-only consumed | +`sha256` consumed | **`sha256` cost** |
|---:|---:|---:|---:|
| 32 B | 5 | 40 | **35** |
| 64 B | 5 | 40 | **35** |
| 128 B | 5 | 40 | **35** |
| 512 B | 5 | 40 | **35** |
| 1024 B | 5 | 40 | **35** |
| 4096 B | 5 | 40 | **35** |

> **`sha256` is FLAT at 35, regardless of input size.** It does not meter by
> byte. 32 B and 4096 B cost identically.

This is the same shape the spike found for `keccak256`, but a different
constant. The 64 B row is the one that matters: it is exactly a two-child-hash
pair, i.e. one internal node of an SSZ tree. **One SSZ tree level costs 35 for
the hash itself**; the rest of the per-level cost is glue (§2.5).

### 2.3 All four AVM hash opcodes, for comparison

| opcode | measured cost | flat? | used by |
|---|---:|:--:|---|
| **`sha256`** | **35** | yes | **SSZ / consensus layer (this module)** |
| `sha512_256` | 45 | yes | Algorand-native hashing (not used here) |
| `keccak256` | 130 | yes | Ethereum MPT (M2/M5/M7) |
| `sha3_256` | 130 | yes | **nothing — see the trap below** |

Two notes for the implementer:

1. **SSZ hashing is 3.71× cheaper than MPT hashing.** This inverts the intuition
   carried over from the spike, where hashing was "the cheap part" at 130. On
   the SSZ side it is cheaper still, and — unlike MPT — there is no RLP decode
   sitting next to it consuming 67% of the budget. Track A's SSZ leg is
   genuinely inexpensive; its cost is entirely BLS (M1/M4).
2. **`sha3_256` and `keccak256` cost exactly the same (130) and are different
   functions.** Keccak-256 and NIST SHA3-256 differ only in padding. Reaching
   for the wrong one produces wrong roots at *identical budget*, so a cost
   regression test will never catch it. SSZ needs `sha256` — neither of these.

### 2.4 Branch verification at real, published generalized indices

Measured in the **real deployment shape**: proof data arriving as application
arguments (`leaf`, packed `branch` blob, big-endian `gindex`, `root`), not as
embedded program constants. Program is **157 bytes, fixed, independent of
depth** — depth is a runtime loop bound, so program size never grows.

| gindex | consensus-spec name | forks | depth | **budget** | app-args | 1 call? |
|---:|---|---|---:|---:|---:|:--:|
| 25 | `EXECUTION_PAYLOAD_GINDEX` | Bellatrix…Fulu | 4 | **301** | 200 B | ✅ |
| 27 | `blob_kzg_commitments` (list root) | Fulu, EIP-7805 | 4 | **299** | 200 B | ✅ |
| 54 | `CURRENT_SYNC_COMMITTEE_GINDEX` | Altair…Deneb | 5 | **362** | 232 B | ✅ |
| 55 | `NEXT_SYNC_COMMITTEE_GINDEX` | Altair…Deneb | 5 | **360** | 232 B | ✅ |
| 86 | `CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA` | Electra, Fulu | 6 | **425** | 264 B | ✅ |
| 87 | `NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA` | Electra, Fulu | 6 | **423** | 264 B | ✅ |
| 105 | `FINALIZED_ROOT_GINDEX` | Altair…Deneb | 6 | **425** | 264 B | ✅ |
| 169 | `FINALIZED_ROOT_GINDEX_ELECTRA` | Electra, Fulu | 7 | **488** | 296 B | ✅ |
| 412 | `EXECUTION_BLOCK_HASH_GINDEX` | Capella | 8 | **549** | 328 B | ✅ |
| 735 | `FINALIZED_ROOT_GINDEX_GLOAS` | Gloas | 9 | **606** | 360 B | ✅ |
| 812 | `EXECUTION_BLOCK_HASH_GINDEX_DENEB` | Deneb | 9 | **612** | 360 B | ✅ |
| 221184 | `blob_kzg_commitment[i]` | Deneb…Fulu | 17 | **1,118** | 616 B | ❌ (2) |
| 2856 | `EXECUTION_BLOCK_HASH_GINDEX_GLOAS` | Gloas | 11 | **738** | 424 B | ❌ (2) |
| 2945 | `CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS` | Gloas | 11 | **738** | 424 B | ❌ (2) |
| 2946 | `NEXT_SYNC_COMMITTEE_GINDEX_GLOAS` | Gloas | 11 | **738** | 424 B | ❌ (2) |

**Every gindex the current light-client protocol actually uses (25 / 86 / 87 /
169 on Fulu; 25 / 54 / 55 / 105 on Altair…Deneb) costs 301–488 budget and fits
inside a single 700-budget app call with 200+ to spare.** For context, the
spike's cheapest MPT proof (a 3-node receipt path) was 1,121 and needed 2 calls;
a full account+storage read was 6,827 and needed 10.

### 2.5 Exact cost model

The per-level cost differs by 2 depending on child side, because the
left-child case needs one extra stack shuffle. Fitting the measurements:

> **`budget = 53 + 61·depth + 2·z`**
> where `z` = the number of **0** bits among the low `depth` bits of `gindex`
> (i.e. the number of levels at which the running node is a *left* child).
> Equivalently `53 + 63·depth − 2·popcount(get_subtree_index(gindex))`.

This is not a fit-with-residuals; it reproduces **every** measured value
exactly. Verification against the measured table:

| gindex | depth | index bits (LSB→) | z | predicted | measured |
|---:|---:|---|---:|---:|---:|
| 25 | 4 | 1,0,0,1 | 2 | 53+244+4 = **301** | 301 ✅ |
| 27 | 4 | 1,1,0,1 | 1 | 53+244+2 = **299** | 299 ✅ |
| 54 | 5 | 0,1,1,0,1 | 2 | 53+305+4 = **362** | 362 ✅ |
| 55 | 5 | 1,1,1,0,1 | 1 | 53+305+2 = **360** | 360 ✅ |
| 105 | 6 | 1,0,0,1,0,1 | 3 | 53+366+6 = **425** | 425 ✅ |
| 169 | 7 | 1,0,0,1,0,1,0 | 4 | 53+427+8 = **488** | 488 ✅ |
| 221184 | 17 | …3 ones, 14 zeros | 14 | 53+1037+28 = **1,118** | 1,118 ✅ |
| 2^41 | 41 | all zeros | 41 | 53+2501+82 = **2,636** | 2,636 ✅ |
| 2^61 | 61 | all zeros | 61 | 53+3721+122 = **3,896** | 3,896 ✅ |

**Use `53 + 63·depth` for conservative budgeting** (the all-left worst case).
Branch shape is public data, so this cost variation leaks nothing.

### 2.6 The single-app-call depth ceiling

On-chain there is no `extra-opcode-budget` — the spike established that it is
simulate-only. Real pooled budget is `700 × (top-level + inner app calls)`.
Measured at both extremes of the same depth:

| depth | all-right index (cheapest) | all-left index (worst case) | fits in 700? |
|---:|---:|---:|:--:|
| 9 | 602 | 620 | ✅ |
| **10** | 663 | **683** | ✅ **(boundary)** |
| **11** | 724 | **746** | ❌ |
| 12 | 785 | 809 | ❌ |
| 13 | 846 | 872 | ❌ |
| 17 | 1,090 | 1,124 | ❌ |

> **Depth ≤ 10 verifies in a single app call. Depth ≥ 11 requires two.**

Caveat the implementer must respect: 683 of 700 leaves only 17 for ARC-4 method
routing, argument decode, and any surrounding logic. **Treat depth ≤ 8 as the
comfortable single-call regime and budget one donor call from depth 9 up.** All
of Altair…Fulu's light-client gindices are depth ≤ 7, so this is free headroom
today; Gloas at depth 11 will require a donor call regardless (§4.3).

### 2.7 Committee merkleization — resolving M1 §10.1

Design doc 001 §10.1 hands M3 a new cross-module dependency: merkleizing 512
compressed pubkeys on-chain for the install-time SSZ check, estimated at "~1,023
`sha256`". That estimate is **exactly right** in hash count, and now priced.

Measured with the O(depth)-scratch incremental merkle-stack algorithm (§5.5),
`hash_tree_root(Vector[BLSPubkey, n])` (one `sha256` per pubkey for
`sha256(pubkey48 ‖ zero16)`, then `n−1` internal combines):

| leaves | depth | `sha256` calls | **budget** | per `sha256` | app calls @700 | ALGO |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 1 | 3 | 228 | 76.0 | 1 | 0.001 |
| 16 | 4 | 31 | 2,118 | 68.3 | 4 | 0.004 |
| 64 | 6 | 127 | 8,598 | 67.7 | 13 | 0.013 |
| 128 | 7 | 255 | 17,238 | 67.6 | 25 | 0.025 |
| 256 | 8 | 511 | 34,518 | 67.5 | 50 | 0.050 |
| **512** | **9** | **1,023** | **69,078** | **67.5** | **99** | **0.099** |

> **A 512-pubkey `SyncCommittee` merkleizes for 69,078 budget = 99 app calls =
> 0.099 ALGO.** That is 36% of a single 16-txn group's 190,400 ceiling, so it
> fits in one group — but it is not free, and it recurs once per sync-committee
> period (~27 h).

Two qualifications, stated so they are not silently assumed away:

- This measurement **excludes box-read cost**. Pubkeys live in boxes per 001
  §10.2 (8 boxes × 64 keys); `box_extract` budget is M1's probe **P12b** and is
  additive on top of 69,078. The merkleization *arithmetic* is what is measured
  here, using an in-program byte source; `sha256` is input-size-flat and
  `extract3` is content-independent, so the arithmetic figure is exact.
- Marginal cost is **67.5 per `sha256`**, i.e. 35 for the hash and ~32.5 of glue
  (extract, concat, dynamic `loads`/`stores`, bitmask carry). Glue is roughly as
  expensive as the hash. This is the same lesson as the spike's §6 —
  operand-load overhead dominates cheap opcodes.

### 2.8 A full leaf layer does not fit in an AVM value

| payload | result |
|---|---|
| 4,096 B (128 chunks) | **OK** |
| 4,128 B (129 chunks) | **REJECTED** — `bytec_0 produced a too big (4128) byte-array` |
| 16,384 B (512 chunks — one pubkey leaf layer) | **REJECTED** — `approval program too long. max len 8192 bytes` |

The spike's 4096-byte value cap re-confirmed, with the same error shape it
found for `ec_multi_scalar_mul`. Consequence, and it is a design constraint not
a footnote:

> **Layer-at-a-time merkleization is impossible above 128 leaves.** 512 × 32 B =
> 16,384 B cannot be held in one AVM value. M3 **must** use the incremental
> merkle-stack algorithm (§5.5), which needs only `depth+1 = 10` scratch slots
> of 32 B. Any implementation that tries to buffer a layer will fail at 129
> leaves — and will pass a 128-leaf test.

### 2.9 Deep branches and the app-arg ceiling

| depth | budget | app-arg total | result |
|---:|---:|---:|---|
| 41 | 2,636 | 1,384 B | OK |
| 50 | 3,203 | 1,672 B | OK |
| 60 | 3,833 | 1,992 B | OK |
| **61** | **3,896** | **2,024 B** | **OK (last depth that fits)** |
| 62 | — | 2,056 B | **REJECTED: `tx.ApplicationArgs total length is too long. 2056 > 2048`** |
| 63 | — | 2,088 B | **REJECTED** (same) |

`MaxAppTotalArgLen = 2048` is a **transaction-level** limit, not an AVM one — it
rejects before evaluation, so `app-budget-consumed` is 0 and there is no logic
error to catch. With the 4-argument layout of §5.4 the ceiling is **depth 61**.

This is far above anything SSZ needs (the deepest published gindex is 221184,
depth 17), so it is a non-issue in practice — but it is recorded because a
future caller passing several branches in one call shares the same 2,048-byte
budget across *all* arguments. **Two depth-17 branches (616 B each) plus
overhead already consume more than half of it.** If M8 ever batches proofs, they
must go in boxes, not args.

For reference, the same fold with data embedded as program constants instead of
args measures `~30 + 61·depth` (depth 0 → 30, 5 → 327, 16 → 996, 32 → 1,972,
63 → 3,871) — cheaper by ~23 fixed, but it forces a per-proof program and is not
the deployment shape. Ignore it; §2.4/§2.5 are normative.

### 2.10 Validation against official consensus-spec test vectors

`ARCHITECTURE.md` makes citing real spec vectors a condition of approval for M3.
Done, not deferred.

Source: **`ethereum/consensus-spec-tests` release `v1.6.0-beta.0`**,
`minimal.tar.gz`, all `single_merkle_proof` suites. Format per
`tests/formats/light_client/single_merkle_proof.md`: each case is
`proof.yaml` (`leaf`, `leaf_index` = the generalized index, `branch`) beside an
`object.ssz_snappy`.

**Result: 38/38 vectors verify on-chain, across 6 forks.**

| fork | vectors | gindices exercised | depths |
|---|---:|---|---|
| altair | 3 | 54, 55, 105 | 5, 5, 6 |
| bellatrix | 3 | 54, 55, 105 | 5, 5, 6 |
| capella | 4 | 25, 54, 55, 105 | 4, 5, 5, 6 |
| deneb | 8 | 25, 54, 55, 105, 221184 ×4 | 4–6, 17 |
| electra | 8 | 25, 86, 87, 169, 221184 ×4 | 4, 6, 6, 7, 17 |
| fulu | 8 | 25, 27 ×4, 86, 87, 169 | 4, 6, 6, 7 |
| eip7805 | 4 | 27 ×4 | 4 |

Three independent checks were applied to every vector:

1. **Length invariant.** `len(branch) == floorlog2(gindex)` held for all 38.
   This corroborates the depth-derivation rule of §3.1 against published data
   rather than against my own arithmetic.
2. **Spec-reference agreement.** The verbatim `compute_merkle_branch_root` from
   `specs/phase0/beacon-chain.md` was run in Python, and the on-chain fold was
   asserted equal to it. The AVM implementation is bit-exact with the spec on
   real spec data.
3. **Cross-proof root convergence.** Within each fork, the three `BeaconState`
   proofs (`current_sync_committee`, `next_sync_committee`, `finality_root`) are
   generated from one **md5-identical** `object.ssz_snappy`. Their folded roots
   must therefore be byte-identical. They are, for all six forks — three
   different leaves at three different gindices and two different depths
   converging on one root:

| fork | converged `hash_tree_root(BeaconState)` |
|---|---|
| altair | `fc9b7ed1e03e48aedb91aa1372a0969bd408fcaa15003937f59fe54f81b83b3c` |
| bellatrix | `83dc29428eaabbbca463c9e28c2783bcd4c9adca0155ac80563df266c6d7a73a` |
| capella | `459eed23bb94dc52a0c7e374a0acae5c5ad5fa0209507e7379d5f000610e8ac1` |
| deneb | `506a5f1ba411211d75d153868e083546735360c9cb002d36c19365a848bb0b23` |
| electra | `a5c63f50136afb2ac758cc8c7fc11d3c0ff418f411522eba1cf4b7ac815523ab` |
| fulu | `6c4e538c2805f3aa233bf00ded4ea76ca7eab5188251d3da85df97e2e0b1224e` |

Check 3 is the strong one: a wrong sibling ordering convention, a wrong bit
test, or an off-by-one in depth would make the three roots disagree. They agree
to the byte on all six forks.

**What this does NOT yet prove, and the test plan must close (T4).** The
expected root fed to the on-chain verifier was the folded root, not an
independently computed `hash_tree_root(object.ssz_snappy)`. So the on-chain fold
is proven bit-exact against the spec reference *and* mutually consistent across
proofs, but not yet tied to an independent SSZ implementation's root. Closing it
requires snappy decompression plus a fork-aware SSZ schema for `BeaconState`.
**Do not reach for `eth2spec` on PyPI — it is pinned at 0.11.3 and predates
Altair entirely** (no `BeaconState` with sync committees). Use `remerkleable`
with the container definitions, or `make pyspec` from a `consensus-specs`
checkout. This is T4 and it is a **blocking** item for M3 being marked *Tested*
— though not for this design being approved, since checks 1–3 already establish
correctness of the algorithm this document specifies.

### 2.11 `mix_in_length`

`hash_tree_root` of an SSZ `List`/`Bitlist` is
`sha256(merkle_root ‖ uint256_le(length))`. Measured as a complete program
(byte-reverse of `itob` output + zero-pad + concat + `sha256` + compare):
**164 budget, constant across `length` ∈ {0, 1, 512, 2^40}**.

The trap: `itob` yields **8-byte big-endian**; SSZ needs **32-byte
little-endian**. The length must be byte-reversed and right-padded with 24 zero
bytes. Getting the endianness wrong yields a wrong root at identical cost.

### 2.12 Raw simulate evidence

Verbatim response for the official Electra `finality_root_merkle_proof` vector
(`gindex = 169`, depth 7, index 41), verified on-chain:

```json
{
  "eval-overrides": { "extra-opcode-budget": 320000 },
  "last-round": 5,
  "txn-groups": [
    {
      "app-budget-added": 320700,
      "app-budget-consumed": 488,
      "txn-results": [
        {
          "app-budget-consumed": 488,
          "txn-result": {
            "application-index": 1006,
            "pool-error": "",
            "txn": {
              "sig": "UO5GWyLl4Qbii7mD/hWfQ0Q6t4ar/sTP5j0KmPFYqZa18kQApcgg8papWOoa/ra8M1i1xj8fc0/vEJvifl33Bw==",
              "txn": {
                "apaa": [
                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABfbwKvKSGCktIaabZKeUp8CHOz4PVGEZcoY3BujL3zcS+oIdvyQ8NF3CJ9CZL54iVLrzXdrNKzvmE3yNWfqUO+ACwf5bwL1i228pmlgvKoCm1XSMzILn7YQ+rwrgc590rrQz6SN1qeYAfZ6GIpTZLkrNhf2Y6B3Kz96NGQUQG5IaqpPUwLosr46dz64L7fQ6dI7kE5Hhjk9kX+WEIle6Q3lTAkxt7WflQmUCWMWDR872QKwrslTG32vDr5vzwaH3o=",
                  "AAAAAAAAAKk=",
                  "pcY/UBNq+yrHWMyMf8EdPA/0GPQRUi66HPS3rIFVI6s="
                ],
                "apap": "CiADIAEANhoANQA2GgIXNQE0AYECD0Q0AZMjCTUDNhoBFSIKNQQ2GgEVIhgkEkQ0BDQDD0Q0BDQDCTUFJDUGNAY0BRJAABY2GgE0BiILIlgyAxJENAYjCDUGQv/iJDUCNAI0AxJAACw2GgE0BTQCCCILIlg0ATQCkSMaQAAHNABMUEIAAzQAUAE1ADQCIwg1AkL/zDQANhoDEkQjQw==",
                "apep": 3, "apsu": "CoEBQw==", "fee": 1000, "fv": 5,
                "gen": "dockernet-v1",
                "gh": "lULN5/Srm4sHDF/5d8U/UwVtHtlExpVPsOOKHzAjQ34=",
                "lv": 1005,
                "snd": "VN23V5ISN52V532G7E7YEFAYZT6H3HIQVEHDJ6J4XSFKAZ4JPN6Z5CSAAA",
                "type": "appl"
              }
            }
          }
        }
      ]
    }
  ],
  "version": 2
}
```

Decoding `apaa`: arg0 = leaf = 32 zero bytes (this vector's
`finalized_checkpoint.root` is genuinely zero — see §7.5); arg1 = the 7×32 B
packed branch, whose first entry is also all-zero; arg2 = `0x00000000000000a9`
= 169; arg3 = the expected root `a5c63f50…` matching §2.10's Electra row.
`app-budget-consumed = 488` matches §2.4 and §2.5.

Appendix A holds the exact TEAL behind `apap`, as the normative reference
semantics for §5.

---

## 3. SSZ Merkle mechanics: the normative algorithm

### 3.1 Generalized index → depth and subtree index

A generalized index encodes depth and position in one integer. For a node at
depth `d` and position `i ∈ [0, 2^d)`:

```
gindex = 2^d + i
```

So `gindex` in binary is a leading `1` followed by exactly `d` bits which are
`i`, and read left-to-right after the leading `1` those bits are the path from
the root (0 = left, 1 = right).

```
depth = floorlog2(gindex) = bitlen(gindex) - 1
index = get_subtree_index(gindex) = gindex mod 2^depth
```

On the AVM, `bitlen` gives this directly for a `UInt64` — no loop, no table.
`gindex = 1` → `depth = 0` → the leaf *is* the root (§7.1).

**Do not materialize `index`.** For every `i ∈ [0, depth)`, bit `i` of `gindex`
equals bit `i` of `index`, because `gindex = 2^depth + index` and
`index < 2^depth` — the added `2^depth` only sets bit `depth`. So the fold can
test bits of `gindex` directly and never compute `gindex − 2^depth`. This is
worth two opcodes per verification and, more importantly, removes a subtraction
that could underflow on a malformed `gindex`.

### 3.2 Sibling ordering: **leaf-to-root**. Normative.

> **`branch[0]` is the sibling of the leaf itself (deepest). `branch[depth-1]`
> is the sibling at the level immediately below the root (shallowest).**

This is the consensus spec's convention, from
`compute_merkle_branch_root`, and it is confirmed by all 38 official vectors
(§2.10). Pick this and never revisit it; the opposite convention produces a
plausible-looking wrong root and only a real test vector catches it.

### 3.3 The fold

Verbatim from `specs/phase0/beacon-chain.md`:

```python
def compute_merkle_branch_root(leaf, branch, depth, index) -> Root:
    value = leaf
    for i in range(depth):
        if index // (2**i) % 2:
            value = hash(branch[i] + value)     # node is a RIGHT child
        else:
            value = hash(value + branch[i])     # node is a LEFT child
    return Root(value)

def is_valid_merkle_branch(leaf, branch, depth, index, root) -> bool:
    if depth != len(branch):
        return False
    return compute_merkle_branch_root(leaf, branch, depth, index) == root
```

Restated as M3 implements it, with `gindex` in place of `(depth, index)`:

```
depth := bitlen(gindex) - 1
require len(branch) == depth * 32                    # §7.3
node  := leaf
for i in 0 .. depth-1:
    sibling := branch[32*i : 32*i+32]
    if (gindex >> i) & 1 == 1:                       # node is a RIGHT child
        node := sha256(sibling ‖ node)
    else:                                            # node is a LEFT child
        node := sha256(node ‖ sibling)
require node == expected_root
```

`hash` is **`sha256`** — not `keccak256`, not `sha512_256`, not `sha3_256`
(§2.3).

### 3.4 Worked example on a real vector

Official `electra/light_client/single_merkle_proof/BeaconState/finality_root_merkle_proof`:

- `gindex = 169`, `bitlen(169) = 8`, so `depth = 7`, `index = 169 − 128 = 41`.
- `169 = 0b10101001`; low 7 bits = `0101001` = 41. Bits, LSB first
  (`i = 0…6`): `1, 0, 0, 1, 0, 1, 0`.
- Fold: level 0 right, levels 1–2 left, level 3 right, level 4 left, level 5
  right, level 6 left.
- `len(branch) = 7 = depth` ✅
- Result: `a5c63f50136afb2ac758cc8c7fc11d3c0ff418f411522eba1cf4b7ac815523ab`,
  which equals the root the fork's other two `BeaconState` proofs converge on
  (§2.10) — and `app-budget-consumed = 488` (§2.12).

Sanity-check the cost model too: `z = 4` zero bits among the low 7, so
`53 + 61·7 + 2·4 = 488`. ✅

### 3.5 Normalized branches

The light-client spec wraps the fold once more
(`specs/altair/light-client/sync-protocol.md`):

```python
def is_valid_normalized_merkle_branch(leaf, branch, gindex, root) -> bool:
    depth = floorlog2(gindex)
    index = get_subtree_index(gindex)
    num_extra = len(branch) - depth
    for i in range(num_extra):
        if branch[i] != Bytes32():
            return False
    return is_valid_merkle_branch(leaf, branch[num_extra:], depth, index, root)
```

Why this exists, and why M4 wants it: the wire types are fixed-size vectors
sized for the *deepest supported* fork —
`NextSyncCommitteeBranch = Vector[Bytes32, floorlog2(NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA)]`,
6 entries. A pre-Electra proof only needs 5. The shallower proof is **left-padded
with zero `Bytes32` slots**, and the verifier uses the trailing `depth` entries
while requiring every leading padding slot to be exactly zero.

Two things to get right:

- The padding slots are **not tree levels**. They are unused vector slots. Do
  not try to fold them.
- The must-be-zero check is an **anti-malleability requirement, not cosmetic**.
  Without it, a relayer could stuff arbitrary bytes into unused slots and mint
  distinct wire encodings that all verify — breaking any dedup, replay, or
  update-ranking logic M4/M9 build on the encoded update's hash.

Measured cost of normalization: **+18 budget per extra padding slot** (depth-5
proof: 360 with 0 extras, 378 with 1, 414 with 3). Negligible.

---

## 4. Fork-versioning decision

### 4.1 The question

SSZ container layouts shift across forks, moving the generalized index of a
given field. Should M3 hardcode one fork's gindices (say Capella-or-later) with
a documented upgrade path, or be fork-parameterized from day one?

### 4.2 The evidence

Not hypothetical. Real, published values:

| constant | Altair…Deneb | Electra, Fulu | Gloas |
|---|---:|---:|---:|
| `CURRENT_SYNC_COMMITTEE_GINDEX` | 54 (d5) | **86 (d6)** | **2,945 (d11)** |
| `NEXT_SYNC_COMMITTEE_GINDEX` | 55 (d5) | **87 (d6)** | **2,946 (d11)** |
| `FINALIZED_ROOT_GINDEX` | 105 (d6) | **169 (d7)** | **735 (d9)** |
| `EXECUTION_PAYLOAD_GINDEX` | 25 (d4) | 25 (d4) | **removed** |
| execution `block_hash` gindex | 412 (Capella, d8) → 812 (Deneb, d9) | 812 (d9) | **2,856 (d11)** |

Electra pushed `BeaconState` past 32 fields, so its tree deepened from 5 to 6
and every field gindex moved. Gloas restructures again and moves them by an
order of magnitude — and *replaces* the `execution_payload` proof with a proof
of `signed_execution_payload_bid.message.parent_block_hash`.

Three further facts settle it:

1. **The spec itself is runtime fork-parameterized.** Electra's light-client
   spec does not redefine a constant; it introduces accessor *functions*:

   ```python
   def next_sync_committee_gindex_at_slot(slot: Slot) -> GeneralizedIndex:
       epoch = compute_epoch_at_slot(slot)
       if epoch >= ELECTRA_FORK_EPOCH:
           return NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA
       return NEXT_SYNC_COMMITTEE_GINDEX
   ```

   A conforming light client resolves the gindex **per slot at runtime**. A
   verifier with a compile-time constant cannot implement the spec.

2. **Mainnet is on Fulu** (`FULU_FORK_EPOCH = 411392`, 2025-12-03; Electra was
   364032, 2025-05-07). So the gindices v1 must handle *today* are the
   Electra set — 86 / 87 / 169 — not Capella's. A doc that hardcoded
   "Capella-or-later" would ship broken on day one.

3. **Bootstrapping crosses fork boundaries.** A light client starting from a
   historical trusted checkpoint walks sync-committee periods forward. Crossing
   the Electra boundary means verifying pre-Electra updates at 55/105 and
   post-Electra updates at 87/169 **within one sync run, against the same
   contract**. A single hardcoded set cannot do this at all.

### 4.3 The decision

> **M3 does not target any fork. `gindex` is a runtime `UInt64` parameter and
> M3 contains no fork-conditional code, no fork constants, and no SSZ field
> layouts. The fork→gindex mapping is M4's and M8's, resolved from the update's
> slot per the spec's `*_gindex_at_slot` pattern.**

The cost of this generality is essentially zero, which is what makes the
decision easy rather than a tradeoff:

- Program size is **157 bytes, fixed and depth-independent** (§2.4) — depth is a
  loop bound, so parameterization costs no program bytes.
- Depth derivation is one `bitlen` and one subtraction.
- Hardcoding could at best save the `bitlen` and the length check — under 10
  budget out of 301–488. There is no performance argument.

Against that, hardcoding would put a consensus-critical constant into immutable
bytecode, requiring a **contract redeployment and root-anchor migration at every
fork that moves a field**. `ARCHITECTURE.md` already flags contract versioning
as fork-gated rather than semver; runtime parameterization keeps the fork gate
in M4's mutable state (box/global), where it can be updated by governance
without touching the verifier. It moves a hard-fork event from "redeploy the
verifier and re-anchor" to "write a new row in a table".

**Declared v1 fork range: Altair through Fulu inclusive, and M3 imposes no
bound.** M3's supported range is exactly whatever M4/M8 put in their tables;
this design pass has verified on-chain execution at every published gindex from
Altair through Gloas (§2.4), so M3 needs no change for Gloas either.

**Gloas advance warning for M4:** at depth 11 a sync-committee branch measures
738 budget — **over the 700 single-call limit** (§2.6). M4's group-sizing
arithmetic must not assume "one branch = one app call" survives Gloas. It costs
one extra donor call per branch, which is 0.001 ALGO, but it must be *planned*
rather than discovered at the fork.

### 4.4 Consequences for the interface

1. `gindex: UInt64` is a required explicit parameter on every entry point. No
   defaults, no overloads that omit it. A default is how a fork constant sneaks
   back in.
2. Prefer the **normalized** entry point (§3.5) at the M4 boundary. It is what
   makes one contract accept both a depth-5 pre-Electra branch and a depth-6
   Electra branch in the same fixed-width wire slot.
3. `UInt64` bounds the supported depth at 63; the app-arg layout bounds it at 61
   (§2.9). The deepest published gindex is 221184 (depth 17). Ample.

### 4.5 What M4 and M8 must supply — the plug-in point

M3 is done when it verifies a branch at a caller-named position. The following
is explicitly **out of M3's scope and in the consumer's**:

**M4 must** maintain a fork-gated gindex table equivalent to the spec's
`finalized_root_gindex_at_slot` / `current_sync_committee_gindex_at_slot` /
`next_sync_committee_gindex_at_slot`, keyed on the epoch of the update's slot,
holding at minimum: `(105, 169)` for finality and `(54/55, 86/87)` for the sync
committees, with the Gloas row `(735, 2945/2946)` addable without a code change.
The fork epochs are themselves consensus constants and must come from the same
pinned config M4 uses for the BLS fork-version/DST.

**M8 must** define the beacon-block-root → execution-layer bridge gindices. Two
notes from this design pass:

- Prefer a **single deep gindex** into the nested container
  (`get_generalized_index(BeaconBlockBody, 'execution_payload', 'receipts_root')`)
  over two chained branches (body → payload, then payload → field). Generalized
  indices compose, so one fold at depth ~9 replaces two folds at depth 4 + 5 —
  cheaper, and it removes an intermediate root that would otherwise have to be
  trusted or re-checked. The spec does exactly this for
  `EXECUTION_BLOCK_HASH_GINDEX` (412 at Capella, 812 at Deneb, depth 8 and 9,
  both measured in §2.4 at 549 and 612).
- Those gindices are **fork-dependent in a second way**: 412 → 812 between
  Capella and Deneb because `ExecutionPayload` itself gained fields. M8 needs a
  two-dimensional table, or must derive the composed index from the container
  version. **M8 must not copy any gindex from this document** — it must derive
  them with `get_generalized_index` against a pinned spec version and pin the
  official vectors alongside.

---

## 5. Interface (Puya)

File: `contracts/primitives/ssz/merkle.py`. Ordinary Puya throughout — no
`Op`-level escape hatch is justified here (`ARCHITECTURE.md` permits it only
with a measured budget comparison, and §2.4/§2.6 show comfortable headroom at
every real depth).

Representation decisions, both load-bearing:

- **`branch` is a packed `Bytes` blob of `32·n`, not an array type.** This is
  what §2.4's numbers measure. An `arc4.DynamicArray[arc4.StaticBytes[32]]`
  carries a 2-byte length prefix and per-element decode cost. Convert **once**
  at the ARC-4 boundary and pass packed `Bytes` inward.
- **`gindex` is `UInt64`.** Not `arc4.UInt64`, not `Bytes`. `bitlen` and shifts
  need a native integer.

### 5.1 Core fold

```python
@subroutine
def compute_merkle_branch_root(
    leaf: Bytes,        # exactly 32 bytes
    branch: Bytes,      # packed siblings, 32*depth bytes, LEAF-TO-ROOT (§3.2)
    gindex: UInt64,     # >= 1
) -> Bytes:
    """Fold `leaf` up through `branch` to a root, per the consensus spec's
    compute_merkle_branch_root (§3.3).

    Preconditions (all asserted, not assumed):
      * len(leaf) == 32
      * gindex >= 1
      * len(branch) % 32 == 0
      * len(branch) // 32 == bitlen(gindex) - 1     # exact, not >=
    Returns: the 32-byte computed root. gindex == 1 returns `leaf` unchanged.
    """
```

### 5.2 Asserting wrapper — the normal entry point

```python
@subroutine
def assert_valid_merkle_branch(
    leaf: Bytes, branch: Bytes, gindex: UInt64, expected_root: Bytes,
) -> None:
    """compute_merkle_branch_root(...) == expected_root, or the program fails.

    Deliberately returns None, not bool. See §7.6.
    """
```

### 5.3 Normalized wrapper — what M4 should call

```python
@subroutine
def assert_valid_normalized_merkle_branch(
    leaf: Bytes, branch: Bytes, gindex: UInt64, expected_root: Bytes,
) -> None:
    """Spec `is_valid_normalized_merkle_branch` (§3.5), in assert form.

    `branch` may be LONGER than depth. The leading
    `len(branch)//32 - depth` slots are padding and MUST each be 32 zero
    bytes; the trailing `depth` slots are the real siblings.

    Asserted:
      * len(branch) % 32 == 0
      * len(branch) // 32 >= depth          # >= here, == in §5.1
      * every padding slot == 32 zero bytes
    """
```

Implementation note worth 30-odd budget across a committee install: compare a
32-byte slot against zero using the 32 zero bytes that `global ZeroAddress`
already provides, rather than materializing a `bytecblock` zero constant. This
is what Appendix A's measured program does.

### 5.4 ARC-4 boundary (for M4/M8 and for the test harness)

```python
class SSZVerifier(ARC4Contract):
    @arc4.abimethod
    def verify_branch(
        self,
        leaf: arc4.StaticBytes[typing.Literal[32]],
        branch: arc4.DynamicArray[arc4.StaticBytes[typing.Literal[32]]],
        gindex: arc4.UInt64,
        expected_root: arc4.StaticBytes[typing.Literal[32]],
    ) -> None:
        """Thin ARC-4 shell over §5.3. Unpacks `branch` to packed Bytes once.

        Exists for the measurement harness and for M4/M8 called as an external
        app. The primary integration path is M4/M8 importing the §5.1-§5.3
        subroutines directly into their own program — an inner app call would
        add a whole 700-budget call's worth of overhead to a 301-488 budget
        operation, which is absurd. Prefer subroutine inlining.
        """
```

> **The gindex plug-in point is this signature.** M4 and M8 call these
> subroutines with a gindex they resolved from their own fork table (§4.5). M3
> never chooses a gindex.

### 5.5 Merkleization primitives

```python
@subroutine
def zero_hash(depth: UInt64) -> Bytes:
    """Root of an all-zero subtree of the given depth. zero_hash(0) is 32 zero
    bytes; zero_hash(i) = sha256(zero_hash(i-1) || zero_hash(i-1)).

    Implement as a precomputed table of the first ~64 values as program
    constants, NOT by recomputing on demand: on-demand costs 67.5 per level
    (§2.7) where a table lookup is a few opcodes. 64 * 32 = 2,048 program bytes,
    which is affordable within the 8,192-byte cap; if a caller only needs a
    known small range, embed only that prefix. See §7.4.
    """

@subroutine
def merkleize_stack_push(state: Bytes, filled: UInt64, chunk: Bytes) -> tuple[Bytes, UInt64]:
    """Incremental merkleization. `state` is a packed stack of at most
    `depth+1` 32-byte nodes; `filled` is a bitmask of occupied stack levels.
    Push one 32-byte chunk, carrying/combining while the target level is
    occupied. MUST be used instead of buffering a layer -- a full 512-leaf
    layer is 16,384 bytes and exceeds the 4096-byte AVM value cap (§2.8).

    Scratch requirement is depth+1 slots of 32 bytes: 10 for a 512-leaf tree.
    Measured marginal cost: 67.5 budget per sha256 (§2.7).
    """

@subroutine
def mix_in_length(root: Bytes, length: UInt64) -> Bytes:
    """sha256(root || uint256_le(length)) -- the SSZ List/Bitlist tail.

    `length` is 32-byte LITTLE-endian. `itob` produces 8-byte BIG-endian, so it
    must be byte-reversed and right-padded with 24 zero bytes. Measured: 164
    budget for the whole step (§2.11).
    """
```

---

## 6. Security: the gindex is the entire security property

This section is normative for M4 and M8 and is the one thing a reviewer should
check hardest.

**What M3 proves.** Given `(leaf, branch, gindex, root)` and a successful
`assert_valid_merkle_branch`: there exists a Merkle tree, consistent with
`root`, in which the 32-byte value `leaf` sits at the position named by
`gindex`.

**What M3 does not prove.** That `gindex` is the position of the field the
caller cares about. That `leaf` is a `SyncCommittee` root rather than a slot
number, a withdrawal, or an attacker-chosen 32 bytes that happen to live
somewhere in `BeaconState`.

**The attack, if the gindex is attacker-controlled.** Suppose M4 accepted
`gindex` from the relayer alongside the branch. The relayer picks a *real*,
honestly-finalized `BeaconState`, chooses any leaf position in it whose value it
likes — say a `historical_root`, or a validator field, or one of the many zero
leaves — supplies the genuine branch for that position, and gets M3 to return
success. Every hash checks out; the branch is real; the root is real. M4 then
installs that 32 bytes as `next_sync_committee_root`. The relayer has just
substituted a committee root of its choosing under a genuine finalized root,
with no forgery anywhere. The branch verification did its job perfectly and
proved nothing useful.

Hence:

> **NORMATIVE.** `gindex` MUST be supplied by the verifying module from a
> fork-gated constant table it controls, resolved from the update's slot. It
> MUST NOT come from relayer-supplied calldata, from a box a relayer can write,
> or from any value derived from the proof itself. M4/M8 MUST NOT expose an
> entry point that takes both a branch and a caller-chosen gindex from the same
> untrusted source.

This is structurally the same defect as M5's inherited security fix — "the
spike's verifier never checks the extracted child index against the real key
nibbles; the expected path must be derived on-chain, not trusted from a
caller-supplied step list." Same shape, different tree: **the position must come
from the protocol, never from the prover.** M3's contribution is to make the
position an explicit, unavoidable, un-defaulted parameter (§4.4.1) so that the
question "where did this gindex come from?" is impossible to skip at every call
site.

Second-order requirements:

- **Zero-slot malleability.** The must-be-zero check on normalized padding
  (§3.5) is a security requirement, not tidiness. Skipping it lets a relayer
  mint many distinct encodings of one semantically identical update.
- **The expected root must itself be trusted.** M3 compares against a
  caller-supplied root; it has no opinion on provenance. For M4 the root is the
  attested header's `state_root` (trusted only after BLS verification); for M8 it
  is the anchored root. An M3 call whose `expected_root` came from the same
  untrusted blob as the branch proves nothing.
- **Do not branch on validity.** §7.6.

---

## 7. Edge cases

### 7.1 `depth = 0` (`gindex = 1`) — leaf is the root

`gindex = 1` means the root itself: `depth = bitlen(1) − 1 = 0`, the branch is
empty, and the fold executes zero iterations, so `root == leaf`.

Measured: **30 budget**, `branch` length 0, verifier passes when
`leaf == expected_root` and fails otherwise.

**Decision: accept it.** It is arithmetically consistent, it is what the spec's
loop does, and rejecting it would require a special case that could mask a
caller bug. But note that a depth-0 "proof" is a tautology — it asserts
`leaf == root` and nothing more. Because the gindex is never
caller-controlled (§6), no attacker can *reach* this path; a `gindex` of 1 in
M4/M8 would be a table bug, and §8's T9 exists to catch it.

`gindex = 0` is **invalid** and MUST be rejected: `bitlen(0) = 0`, so
`depth = 0 − 1` underflows to `2^64 − 1`. Assert `gindex >= 1` before computing
depth. This is the one input that turns a well-formed-looking call into a
catastrophic loop bound, so it gets its own assertion rather than relying on the
length check.

### 7.2 Length mismatch between branch and claimed depth

Strict form (§5.1) requires `len(branch) // 32 == depth` **exactly** — matching
the spec's `if depth != len(branch): return False`.

Both failure directions are tested and rejected:

| case | measured result |
|---|---|
| branch shorter than depth (3 siblings, `gindex = 55` ⇒ depth 5) | **rejected**, `assert failed pc=52` |
| branch length not a multiple of 32 (truncated by 3 bytes) | **rejected**, `assert failed pc=46` |
| branch longer than depth (4 siblings vs depth 5, constants form) | **rejected**, `assert failed pc=224` |

A too-long branch must not be silently truncated, and a too-short one must not
be zero-extended — either would let a prover control the effective depth. The
normalized form (§5.3) relaxes `==` to `>=` **only** in combination with the
must-be-zero check on the excess, which is what keeps it safe.

### 7.3 Non-multiple-of-32 branch length

Asserted explicitly (`len(branch) % 32 == 0`) rather than left to integer
division. Without it, a 63-byte branch would floor to 1 sibling and silently
discard 31 bytes of prover-supplied data — a malleability vector.

### 7.4 Zero-hash padding for non-power-of-two lengths

SSZ merkleizes a list/vector of `n` chunks into a tree of depth
`ceil(log2(n))`, padding the missing leaves with **zero hashes**: level 0
padding is 32 zero bytes, level `i` padding is
`zero_hash(i) = sha256(zero_hash(i-1) ‖ zero_hash(i-1))`.

Why this matters to M3 even though M3 doesn't build container trees:

1. **Verification side (no action needed).** A branch through a partially-filled
   subtree simply contains `zero_hash(i)` as the sibling at level `i`. The fold
   is oblivious. Confirmed on real data: several official vectors carry
   all-zero siblings, and one (Electra `finality_root`) has both an all-zero
   leaf *and* an all-zero `branch[0]`, and verifies at 488 (§2.12). **The
   verifier must never special-case a zero sibling or a zero leaf.**
2. **Merkleization side (action needed).** `merkleize_stack` (§5.5) must pad with
   `zero_hash(i)` at the level where the shortfall occurs — *not* with 32 zero
   bytes at every level. Padding a level-3 gap with `zero_hash(0)` yields a
   wrong root. This is the classic SSZ merkleization bug, and it is invisible
   whenever `n` is a power of two, so the test plan pins non-power-of-two `n`
   explicitly (T7).
3. **`Vector` vs `List`.** A `Vector[T, N]` merkleizes to `ceil(log2(N))` depth
   with no length mixed in. A `List[T, N]` merkleizes to the depth implied by
   the **type limit `N`**, not the runtime length, and then mixes in the length
   (§2.11). Using the runtime length to size the tree is a second classic bug
   that yields wrong roots for every non-full list.

### 7.5 Zero leaf is legitimate

The official Electra/Fulu `finality_root_merkle_proof` vectors have
`leaf = 0x00…00`, because a genesis-adjacent state has
`finalized_checkpoint.root == 0`. **M3 must accept a zero leaf** — it is
well-formed data.

But the *caller* must not: an all-zero finalized root means "nothing finalized
yet", and M4 must reject it as a state transition rather than anchor it. This is
an M4 requirement recorded here because M3 is where the tempting place to add
the check is, and it belongs one layer up (M3 has no idea what the leaf means).

### 7.6 Assert, never return `bool`

Every M3 entry point that checks validity returns `None` and fails the program
on mismatch. Rationale, carried from 001 §7.4: a `bool` return invites
`if not valid: ...` at the call site, and one missing branch is a silent
total-verification bypass. There is no legitimate caller that wants to continue
after a failed Merkle check.

`compute_merkle_branch_root` (§5.1) returns the root, because computing a root is
a meaningful operation independent of comparison — but it still asserts its own
structural preconditions.

### 7.7 Multiproofs — deferred, with numbers

Verifying `k` leaves against one root independently costs
`k · (53 + ~63·depth)`. A true multiproof shares interior nodes and would cost
roughly one fold plus the extra leaves' distinct path segments. For M4's actual
shape — 2 to 3 proofs per update at depth 6–7, ~900–1,400 budget total — the
saving is a few hundred budget against a per-update cost dominated by BLS
(~125,000–177,000 per 001 §9.2). **Not worth the correctness risk in v1.**
Revisit only if a future module needs many proofs against one root; M7's
receipt-log work is the plausible candidate.

### 7.8 Depth bounds

`gindex: UInt64` permits depth ≤ 63; the §5.4 app-arg layout caps it at 61
(§2.9). Deepest published gindex is 221184 (depth 17). Assert
`bitlen(gindex) <= 62` to keep the failure mode a clean assertion rather than an
arg-length rejection with no logic error (§2.9). No real proof comes close.

---

## 8. Test plan

Split per the project's two-CI policy. The offline tier runs against pinned
fixtures and a pure-Python reference; the live tier runs against dev-mode
`algod`. `algopy_testing` does emulate `sha256`, so unlike M1 the *majority* of
M3 is genuinely offline-testable — the live tier exists for budget measurement
and end-to-end confirmation.

Fixture generator: `tests/ssz/generate_fixtures.py`, reusing
`tests/fixtures/spike-reference/mpt_bench.py`'s harness core (algod/kmd clients,
`compile_teal`, `simulate_create`, `_parse_sim`) unmodified, plus the app-args
`simulate_create_args` variant added during this design pass.

> **Authoritative test data is `ethereum/consensus-spec-tests`, not
> hand-rolled trees.** Pin release `v1.6.0-beta.0` (or later) and vendor the
> `single_merkle_proof` subset — 38 cases, a few hundred KB — into
> `tests/fixtures/ssz/consensus-spec-tests/`. Hand-built trees are permitted
> only for the structural negative cases (T8–T10) that the official suite does
> not cover, and must never substitute for a real vector where one exists.
> Extraction recipe that works without a full checkout:
> `curl -sL <release>/minimal.tar.gz | tar -xz --wildcards '*single_merkle_proof*'`.

| # | Test | Tier | Asserts |
|---|---|---|---|
| T1 | **Official vectors, all forks** | offline + live | All 38 `single_merkle_proof` cases verify. Covers gindices 25, 27, 54, 55, 86, 87, 105, 169, 221184 at depths 4–17 across altair/bellatrix/capella/deneb/electra/fulu/eip7805. **Already passing 38/38** (§2.10); this test pins it. |
| T2 | **Length invariant on real data** | offline | `len(branch) == floorlog2(leaf_index)` for every official vector. Guards the §3.1 depth rule against published data. |
| T3 | **Spec-reference equivalence** | offline + live | On-chain fold == verbatim Python `compute_merkle_branch_root` for every vector, byte-exact. |
| T4 | **Independent root** ⚠️ **blocking for *Tested*** | offline | Decompress `object.ssz_snappy` and compute `hash_tree_root(object)` with an independent SSZ implementation; assert it equals the folded root. Closes the §2.10 gap. **`eth2spec` on PyPI is 0.11.3 and predates Altair — unusable.** Use `remerkleable` + fork-aware container defs, or `make pyspec`. Needs `cramjam`/`python-snappy`. |
| T5 | **Cross-proof convergence** | offline | For each fork, the 3 `BeaconState` proofs fold to one identical root (§2.10). Catches sibling-order and bit-test errors that T1 alone would not. |
| T6 | **Ordering-convention regression** | offline | Feed a reversed sibling array; assert **rejection**. Locks §3.2 so a refactor cannot silently adopt root-to-leaf. This is the single highest-value negative test. |
| T7 | **Zero-hash padding** | offline + live | `merkleize_stack` over non-power-of-two `n` ∈ {1, 3, 5, 7, 9, 17, 31, 33, 100, 511} matches a `remerkleable` reference. Explicitly assert that padding a level-`i` gap with `zero_hash(0)` instead of `zero_hash(i)` produces a **different** root (§7.4.2). Include `Vector` vs `List` sizing (§7.4.3) and `mix_in_length` (§2.11). |
| T8 | **Length-mismatch rejection** | live | Branch shorter than depth → rejected; longer than depth (strict form) → rejected; not a multiple of 32 → rejected. All three measured as rejecting in §7.2; pin the assertion sites. |
| T9 | **Degenerate gindex** | offline + live | `gindex = 0` → rejected (no underflow to depth 2^64−1); `gindex = 1` → accepted iff `leaf == root`; `bitlen(gindex) > 62` → rejected as an assertion, not an arg-length failure. |
| T10 | **Tampering** | live | Flip one byte in one sibling → rejected. Wrong gindex with a correct branch (55 → 54, flipping level-0 order) → rejected. Both measured as rejecting during this design pass. |
| T11 | **Normalized branches** | offline + live | Depth-5 proof in a 6-slot vector verifies; with 3 extra zero slots verifies; **a non-zero byte in any padding slot is rejected** (§3.5 malleability). Measured rejecting. |
| T12 | **Zero leaf / zero sibling** | offline | The Electra + Fulu `finality_root` vectors (zero leaf *and* zero `branch[0]`) verify. Guards against an over-eager "reject empty hash" check (§7.5). |
| T13 | **Committee merkleization** | live | `hash_tree_root(Vector[BLSPubkey, 512])` from box-resident pubkeys matches a `remerkleable` reference; assert 129 leaves does not hit the 4096-byte cap failure of §2.8. Consumes M1's §10.1 handoff end to end. |
| T14 | **Budget regression** | live | Every §2.4 / §2.6 / §2.7 figure re-measured and asserted equal, with the real simulate response recorded into the fixture set. Also asserts the §2.5 closed-form model still predicts exactly — a cheap, very sharp canary for accidental opcode-level changes. |

### 8.1 A note on what T14 buys

The §2.5 cost model predicts every measured value exactly. Asserting the *model*
rather than a table of constants means any change in the fold's opcode
sequence — including a Puya codegen change — shows up as a single clear
failure. It is worth more than the individual budget assertions.

---

## 9. ROADMAP open questions resolved

M3's row lists three inherited items.

**Q1 — "New territory, not in spike." RESOLVED.** The spike never touched SSZ or
`sha256`. This design pass built the harness (reusing the spike's core
unmodified), measured every relevant cost (§2), and validated a working on-chain
verifier against **38/38 official `ethereum/consensus-spec-tests`
`single_merkle_proof` vectors across 6 forks** (§2.10), with three-way root
convergence per fork. M3 is no longer unexplored territory; the remaining
unknown is narrow and named (T4).

**Q2 — "Must measure `sha256` AVM opcode cost from scratch." RESOLVED.**
**`sha256` = 35, flat from 32 B to 4096 B** (§2.2). Also measured for
comparison: `sha512_256` = 45, `keccak256` = 130 (re-confirming the spike's
number, which validates the harness), `sha3_256` = 130. Derived and validated
downstream: the exact branch-verify cost model `53 + 61·depth + 2·z` (§2.5), the
depth ≤ 10 single-app-call ceiling (§2.6), and 67.5 per `sha256` for
merkleization glue (§2.7).

**Q3 — "Pin target fork(s) (Altair/Capella/Deneb field layout differs)."
RESOLVED — by declining to pin.** §4. `gindex` is a runtime `UInt64` parameter;
M3 contains no fork constants and no field layouts. The justification is not
merely "flexibility is nice": (a) the spec itself resolves gindices at runtime
per slot via `*_gindex_at_slot`, so a compile-time constant cannot conform;
(b) mainnet is on **Fulu**, so the Electra gindices (86/87/169) are what v1 needs
*today* and a "Capella-or-later" hardcode would ship broken; (c) a light client
bootstrapping from a historical checkpoint must verify pre- and post-Electra
updates **in one run against one contract**, which no single hardcoded set can
do. The cost of generality is under 10 budget out of 301–488 and **zero program
bytes** (157 B, depth-independent), so there was no tradeoff to weigh.

### 9.1 Questions resolved for *other* modules

**M1 probe P12 (first half) — RESOLVED.** 001 §12 lists "`sha256` cost" as
blocking §8 (`expand_message_xmd_sha256`) and §9.2's budget table.
**`sha256` = 35, flat** (§2.2). P12's second half (box-read budget for a
4,032-byte `box_extract`) remains M1's.

**M1 §10.1's cross-module dependency on M3 — RESOLVED and priced.** Merkleizing
512 compressed pubkeys is **1,023 `sha256` = 69,078 budget = 99 app calls =
0.099 ALGO** (§2.7), 36% of one group's ceiling, plus box-read cost (P12b). M1's
"~1,023 `sha256`" hash count was exactly right. Newly discovered constraint that
M1's design did not anticipate: **the leaf layer cannot be buffered** (16,384 B
vs the 4,096 B value cap, §2.8), so this must use incremental merkle-stack
merkleization, not a layer-at-a-time loop.

**M4's group sizing — informed.** Each SSZ branch M4 needs costs 301–488 today
and fits in one app call. Against 001 §9.2's ~125,000–177,000 BLS-dominated
update budget, **M3's contribution is under 0.5%** — M4 should treat SSZ
verification as free and size groups on BLS alone. One advance warning: at Gloas
the sync-committee gindices move to depth 11 = **738 budget, over the 700
single-call limit** (§4.3), so "one branch = one app call" does not survive that
fork.

**M8 — informed, not resolved.** §4.5 specifies what M8 must define and
recommends a single deep composed gindex over two chained branches, with the
spec's own `EXECUTION_BLOCK_HASH_GINDEX` (412 Capella / 812 Deneb, measured at
549 / 612) as precedent. M8's own listed open question (root-history retention)
is untouched by M3.

**M12's contract-versioning story — informed.** Because M3 is fork-agnostic, the
fork gate lives entirely in M4/M8 mutable state. A consensus fork that moves a
gindex requires **a table update, not an M3 redeployment**. M12 should therefore
version M3 on AVM version only, and version M4/M8 on supported fork range.

**Not resolved, deliberately:** the specific gindices for any proof type (M4/M8,
§1.2 and §4.5); real BLS DST and signing-root vectors (M4's own listed
question); anything MPT (M2/M5/M7).

---

## 10. File layout

```
contracts/primitives/ssz/
    __init__.py        # re-exports the public surface in §5
    merkle.py          # §5.1-§5.3 fold, asserting + normalized wrappers
    merkleize.py       # §5.5 zero_hash table, merkleize_stack, mix_in_length
    harness.py         # §5.4 ARC-4 app wrapping each primitive, for
                       # simulate-based measurement and live tests only --
                       # not deployed
tests/ssz/
    reference.py           # pure-Python mirror: compute_merkle_branch_root,
                           # is_valid_normalized_merkle_branch, zero_hash,
                           # merkleize -- checked against remerkleable
    generate_fixtures.py   # spike harness + official vectors -> fixtures
    test_merkle.py         # T1-T3, T5, T6, T8-T12
    test_merkleize.py      # T7, T13
    test_budget.py         # T14 (live tier)
tests/fixtures/ssz/
    consensus-spec-tests/  # vendored single_merkle_proof subset, release-pinned
    *.json                 # pinned inputs, expected roots, measured budgets
```

---

## 11. Measurement backlog

Unlike M1, **no design decision in this document rests on an unmeasured
number** — §2 covers every cost that §4–§7 rely on. The following are
completeness items for the implementation, not design blockers.

| # | Probe | Blocks |
|---|---|---|
| Q1 | `box_extract` budget for a 4,032-byte read (shared with M1 P12b) | the additive term on §2.7's 69,078 |
| Q2 | Real Puya-generated fold vs. Appendix A's hand-written TEAL — does codegen inflate the §2.5 model? | §2.6's depth ≤ 10 ceiling; T14's model assertion |
| Q3 | ARC-4 routing + argument-decode overhead for §5.4 | the 17-budget margin at depth 10 (§2.6) |
| Q4 | `zero_hash` table lookup vs. on-demand recomputation, measured | §5.5's table recommendation |
| Q5 | Cost of the §5.3 normalized path when `num_extra = 0` vs. §5.2 strict — is one wrapper enough? | possible simplification of §5 to a single entry point |

---

## 12. Implementer checklist (normative MUSTs)

1. **`sha256`.** Not `keccak256`, not `sha512_256`, not `sha3_256`. `sha3_256`
   costs the same 130 as `keccak256` and is a different function — neither is
   SSZ's (§2.3).
2. **`branch[0]` is the leaf's sibling.** Leaf-to-root, always (§3.2). T6 exists
   to catch a reversal.
3. **Bit `i` of `gindex`, not of a materialized `index`.** `1` ⇒ node is a
   **right** child ⇒ `sha256(sibling ‖ node)` (§3.1, §3.3).
4. **Assert `gindex >= 1` before computing depth.** `bitlen(0) - 1` underflows
   to `2^64 − 1` (§7.1).
5. **Assert `len(branch) % 32 == 0`** — never let integer division silently
   discard prover bytes (§7.3).
6. **Strict form asserts `== depth`; normalized form asserts `>= depth` AND that
   every leading padding slot is 32 zero bytes.** The zero check is a security
   requirement (§3.5, §6).
7. **Never buffer a merkleization layer.** 512 × 32 B = 16,384 B exceeds the
   4,096-byte value cap; a 128-leaf test will pass and 129 will fail (§2.8). Use
   `merkleize_stack` (§5.5).
8. **Pad a level-`i` gap with `zero_hash(i)`, not with 32 zero bytes** (§7.4.2).
   Invisible when `n` is a power of two.
9. **Size a `List`'s tree from the type limit `N`, not the runtime length**, then
   `mix_in_length` (§7.4.3). `mix_in_length` needs 32-byte **little-endian**
   length; `itob` gives 8-byte big-endian (§2.11).
10. **Accept a zero leaf and zero siblings** — real vectors have them (§7.5).
11. **Assert; never return `bool`** from a validity check (§7.6).
12. **`gindex` is a required, un-defaulted parameter, and callers MUST source it
    from a fork-gated table, never from relayer input.** This is the module's
    security property; see §6. If you find yourself adding a default value for
    `gindex`, stop — that is a fork constant re-entering M3.

---

## Appendix A — measured reference implementation

The exact TEAL behind every §2.4/§2.5/§2.6 figure and the §2.12 response.
Included as **normative reference semantics** for §5 and as the artifact the
budget claims trace to — not as a style to imitate (`ARCHITECTURE.md`: production
code is ordinary Puya). Args: `0` = leaf, `1` = packed branch, `2` = big-endian
`gindex`, `3` = expected root. Implements the **normalized** form (§3.5).
Compiled size 157 bytes, independent of depth.

```
#pragma version 10
txna ApplicationArgs 0
store 0                     // node := leaf
txna ApplicationArgs 2
btoi
store 1                     // gindex
load 1
int 2
>=
assert                      // gindex >= 2 here; gindex == 1 is the depth-0 path
load 1
bitlen
int 1
-
store 3                     // depth := floorlog2(gindex)
txna ApplicationArgs 1
len
int 32
/
store 4                     // supplied sibling count
txna ApplicationArgs 1
len
int 32
%
int 0
==
assert                      // branch length is a multiple of 32
load 4
load 3
>=
assert                      // at least `depth` siblings supplied
load 4
load 3
-
store 5                     // num_extra
int 0
store 6
zeroloop:                   // every leading padding slot must be 32 zero bytes
load 6
load 5
==
bnz zerodone
txna ApplicationArgs 1
load 6
int 32
*
int 32
extract3
global ZeroAddress          // 32 zero bytes, cheaper than a bytec constant
==
assert
load 6
int 1
+
store 6
b zeroloop
zerodone:
int 0
store 2                     // level i := 0
sszloop:
load 2
load 3
==
bnz sszdone
txna ApplicationArgs 1       // sibling := branch[num_extra + i]
load 5
load 2
+
int 32
*
int 32
extract3
load 1                       // bit i of gindex
load 2
shr
int 1
&
bnz sszright
load 0                       // bit 0: node is LEFT  -> sha256(node || sibling)
swap
concat
b sszhash
sszright:
load 0                       // bit 1: node is RIGHT -> sha256(sibling || node)
concat
sszhash:
sha256
store 0
load 2
int 1
+
store 2
b sszloop
sszdone:
load 0
txna ApplicationArgs 3
==
assert
int 1
return
```

The `bnz sszright` asymmetry is the source of §2.5's `2·z` term: the left-child
path needs an extra `swap`.

## Appendix B — reproducing the measurements

1. Bring up dev-mode `algod` per `tests/fixtures/spike-reference/README.md`
   (ports 4051/4052, token `64×'a'`, `EnableDeveloperAPI=true`, protocol
   `future`). Verified against `go-algorand 4.7.3.stable`.
2. Vendor the official vectors:
   `curl -sL https://github.com/ethereum/consensus-spec-tests/releases/download/v1.6.0-beta.0/minimal.tar.gz | tar -xz --wildcards '*single_merkle_proof*'`
   (~468 MB streamed; extracts 38 cases).
3. Drive Appendix A's program with the harness core from
   `tests/fixtures/spike-reference/mpt_bench.py`, adding an
   `app_args=`-carrying `simulate_create` variant, and read
   `app-budget-consumed`.

Isolated opcode costs (§2.2, §2.3) use the spike's differencing method: compile
a `bytecblock` + `bytec` push-only program, then the same program with the
opcode appended, and subtract.
