# 001 — M1: BLS12-381 point codec & MSM/pairing wrapper

**Module**: M1 · **Status**: Design Drafted · **Depends on**: scaffold ·
**Consumed by**: M4 (sync-committee update verifier)
**Author**: design pass, 2026-07-30

---

## 1. Scope and non-goals

### 1.1 In scope

M1 is the *curve-level* primitive layer. It knows about BLS12-381 points, field
elements, byte encodings, and AVM opcode budgets. It knows **nothing** about
Ethereum semantics.

1. **Byte-format codec**: the AVM's uncompressed point encodings, the Ethereum /
   ZCash compressed wire encodings, and conversion between them in the *only*
   direction the AVM can afford (uncompressed → compressed).
2. **Point validity**: subgroup-check wrappers for G1 and G2, infinity
   detection, negation.
3. **The binding primitive** (`g1_bind` / `g2_bind`) — the security-critical
   join between relayer-supplied uncompressed bytes and a commitment-derived
   compressed value. This is the module's most important export; see §4.
4. **Aggregation / MSM**: chunk-oriented point summation over arbitrary N,
   inside the 4096-byte value cap and the 42-point MSM cap, with a documented
   cost model that picks between `ec_add` chains and `ec_multi_scalar_mul`.
5. **`hash_to_g2(msg, dst)`**: RFC 9380 `hash_to_curve` for the
   `BLS12381G2_XMD:SHA-256_SSWU_RO_` suite, with the DST supplied *by the
   caller* (see §8 for why this lands in M1 and what stays M4's).
6. **Pairing assembly**: a `fast_aggregate_verify`-shaped primitive
   `verify_aggregate_signature(agg_pubkey, msg_point, signature) -> bool`.

### 1.2 Non-goals

- **DST and signing-root correctness.** M1 hashes whatever bytes it is given
  with whatever DST it is given. That the message is
  `compute_signing_root(BeaconBlockHeader, compute_domain(DOMAIN_SYNC_COMMITTEE, fork, genesis_validators_root))`
  and the DST is `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` is **M4's**
  responsibility, validated against consensus-spec vectors. M1 must not
  hard-code either.
- **Where trusted compressed pubkeys come from.** M1's binding primitive takes
  the committed compressed bytes as a parameter. Establishing that those bytes
  are SSZ-committed under a trusted root is M3/M4's job. M1 states the
  obligation normatively (§4.6) and nothing more.
- **Committee lifecycle / rotation / storage schema.** Boxes, sessions, and
  period rollover are M4/M8/M10. §10 records the implications M1's design
  forces on them, marked informative.
- **Participation-bitfield decoding, `MIN_SYNC_COMMITTEE_PARTICIPANTS`,
  fork-version handling.** M4.
- **On-chain point decompression.** Ruled out; see §4.2.
- **BN254.** The AVM supports it; we never use it.

---

## 2. Empirical baseline

### 2.1 Facts inherited from the spike (measured, do not re-derive)

Source: `tests/fixtures/spike-reference/RESULTS.md` (every row traces to a real
`/v2/transactions/simulate` response).

| Fact | Value |
|---|---|
| AVM value cap | exactly 4096 bytes (4097 fails at the push) |
| G1 uncompressed | 96 B, `X ‖ Y` big-endian, no flag bits; infinity = 96 zero bytes |
| G2 uncompressed | 192 B, `X.c0 ‖ X.c1 ‖ Y.c0 ‖ Y.c1`, 48 B limbs — **c0 first** |
| MSM arg order | points first, scalars second; scalars exactly 32 B big-endian |
| MSM max G1 points | **42** (42×96 = 4032 ≤ 4096; 43×96 = 4128 fails *at the push*) |
| `ec_add BLS12_381g1` | 205 isolated / 211 gross |
| `ec_subgroup_check BLS12_381g1` | 1850 |
| `ec_map_to BLS12_381g1` | 1950; output passes subgroup check ⇒ cofactor is cleared |
| `ec_pairing_check BLS12_381g1`, 1 pair | 33,000 |
| `ec_pairing_check BLS12_381g1`, 2 pairs | 53,000 (⇒ 13,000 + 20,000/pair) |
| `ec_multi_scalar_mul` (n G1 pts) | 6500 + 95·n (verified at n = 8, 21, 42) |
| `keccak256` (32–1024 B input) | 130, flat (from `results.json`) |
| Base opcode budget | 700 per app call, pooled across the group |
| Inner app calls | +700 each; **256 inner txns per GROUP**, not per call |
| One 16-txn group ceiling | 16 + 256 = 272 app calls = **190,400** budget |
| `extra-opcode-budget` | simulate-only, capped 320,000, **no on-chain analogue** |

### 2.2 Facts this design uses that are NOT yet measured

Per `ARCHITECTURE.md` ("No cost claim without a real `simulate` response"),
these are flagged as claims-in-waiting, not established numbers. Every one has a
probe assigned in §12. **No design decision below is load-bearing on an
unmeasured number**; where one would be, the decision is written as a
measure-then-branch rule.

| Quantity | Provisional (published/derived) | Why we need it |
|---|---|---|
| `ec_map_to BLS12_381g2` | 8150 — cited in `RESULTS.md` §5 prose but **has no measured row in the results table** | dominates `hash_to_g2` |
| `ec_add BLS12_381g2` | ~205 | one add inside `hash_to_g2` |
| `ec_subgroup_check BLS12_381g2` | ~2750 | per-update signature validation |
| `ec_scalar_mul BLS12_381g1` | unknown | decides the general-MSM trailing-chunk rule (§6.5) |
| `sha256` | 35 flat | `expand_message_xmd` (9 calls); shared with M3 |
| `b-`, `b>`, `b^`, `bzero`, `extract3` | 10–20 / 1 | codec glue |
| Puya per-iteration loop glue for an `ec_add` accumulation loop | unknown | **decides §6.4** (`ec_add` chain vs. MSM) |
| Whether `ec_*` ops reject off-curve / non-subgroup operands, and whether they *error* or *return 0* | partially known (spike: garbage G2 in `ec_pairing_check` is rejected) | depth-of-defense claim in §4.5 |
| Net budget gain per inner "donor" app call (700 − issuance − inner program) | unknown | §9 group sizing |
| Byte-math operand length caps (`b%` ≤ 64 B?) | documented 64 B | kills/unlocks an optimization (§4.3) |

---

## 3. Byte-format contracts

Constants (verified in this design pass against the published compressed
generator `0x97f1d3a7…`, which the rules below reproduce exactly):

```
p        = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624
           1eabfffeb153ffffb9feffffffffaaab                      (381 bits)
HALF_P   = (p-1)/2
         = 0x0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b12
           0f55ffff58a9ffffdcff7fffffffd555
NEG_G1_GENERATOR (96 B, AVM uncompressed) =
  17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac58
  6c55e83ff97a1aeffb3af00adb22c6bb                                  (X)
  114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac4236
  4e6f38ba0ecb751bad54dcd6b939c2ca                                  (p − Y)
```

Because `p < 2^381`, the top three bits of any valid X's first byte are always
zero — that is what makes the compressed flag bits free.

### 3.1 Boundary table

| Boundary | Format | Size |
|---|---|---|
| Ethereum wire / SSZ leaf, G1 pubkey | compressed, flags in byte 0 | 48 B |
| Ethereum wire, G2 signature | compressed, flags in byte 0 | 96 B |
| AVM `ec_*` operand, G1 | `X ‖ Y` | 96 B |
| AVM `ec_*` operand, G2 | `X.c0 ‖ X.c1 ‖ Y.c0 ‖ Y.c1` | 192 B |
| AVM scalar | big-endian, zero-padded | 32 B |
| AVM `ec_map_to` input, Fp2 | `c0 ‖ c1` (**confirm by probe**, §12) | 96 B |

### 3.2 Compressed encoding rules (ZCash/Eth, both curves)

Byte 0 carries three flags in its top bits:

- `0x80` — compression flag, always 1 in the compressed form.
- `0x40` — infinity flag. When set, all remaining bits MUST be zero.
- `0x20` — sign-of-Y flag.

G1: `compressed = (X[0] | flags) ‖ X[1..48]`; sign flag set iff `Y > HALF_P`.
Compressed infinity = `0xc0` followed by 47 zero bytes.

G2: `compressed = (X.c1[0] | flags) ‖ X.c1[1..48] ‖ X.c0`; sign flag set iff
`Y.c1 > HALF_P`, or (`Y.c1 == 0` and `Y.c0 > HALF_P`) — i.e. Fp2 elements are
compared lexicographically as `(c1, c0)`. Compressed infinity = `0xc0` followed
by 95 zero bytes.

### 3.3 The limb-order trap (read this before writing any G2 code)

> **The AVM's G2 limb order is the reverse of Ethereum's.** The AVM wants
> `c0` first (spike-measured: `a0a1` satisfies the pairing identity, `a1a0`
> errors). The ZCash serialization Ethereum adopts — and therefore `py_ecc`'s
> `G2_to_signature`, `blst`, `gnark-crypto`, and every consensus client — puts
> `c1` (the imaginary part) **first**.

Any implementer who copies a reference library's serializer will produce points
the AVM rejects, or worse, silently mis-ordered ones. `g2_compress` must
therefore perform an explicit limb swap, and there is a mandatory regression
test (§11, T2) that pins `a1a0` as *failing*.

---

## 4. The compressed-vs-uncompressed trust boundary

This is the module's central decision. It is stated as a chain of claims.

### 4.1 The problem

Ethereum serializes pubkeys as 48-byte compressed G1 and signatures as 96-byte
compressed G2. `SyncCommittee` — the thing SSZ-committed in the beacon state —
is `{ pubkeys: Vector[BLSPubkey, 512], aggregate_pubkey: BLSPubkey }` where
`BLSPubkey` is **48 compressed bytes**. So the only committee data our trust
root can ever cover is *compressed*. Every AVM `ec_*` opcode takes
*uncompressed*. Something has to bridge the two.

### 4.2 On-chain decompression is not merely expensive — it is unimplementable

Decompression means recovering `Y = ±sqrt(X³ + 4) mod p`, i.e. a modular
exponentiation by `(p+1)/4` (381 bits). The AVM has no modexp opcode, and
square-and-multiply would need ~381 iterations of `b*` + `b%` on 48-byte limbs
— three orders of magnitude past the 190,400 single-group ceiling for a *single*
point, before considering 512 of them. For G2 the Fp2 square root is worse
still.

It is in fact strictly worse than "expensive": the AVM's byte-math ops accept
operands of at most 64 bytes, and `x * x` for a 48-byte `x` produces up to 96
bytes, which cannot then be fed to `b%`. A modular reduction of a 96-byte
product needs a hand-rolled multi-limb reduction. **On-chain decompression is
off the table permanently, not pending a budget improvement.**

### 4.3 …but *compression* is nearly free

Going the other way needs no square root at all. Given a 96-byte uncompressed
G1 point, computing its compressed form is: take `X`, compare `Y` against
`HALF_P` (one 48-byte `b>`), OR two or three bits into byte 0. Tens of budget
units, not thousands. Same for G2 plus a limb swap.

This is the classic verify-don't-compute asymmetry, and it is the whole design:
**the relayer computes the square root off-chain for free; the contract verifies
the result by re-compressing and comparing against a committed value.**

> Note for later: the same 64-byte operand cap that kills decompression also
> kills a *cheap on-curve check* (`Y² == X³ + 4` needs a 96 B mod 48 B
> reduction). If probe P10 (§12) shows `b%` tolerates a 96-byte dividend, a
> ~200-budget on-curve check becomes available as a possible replacement for the
> 1850-budget `ec_subgroup_check` at install time. Do not build on this; it is
> recorded as a future optimization with its security argument in §4.5.

### 4.4 Does `ec_subgroup_check` alone suffice? **No — and the failure is total.**

The question posed to this design pass deserves an unambiguous answer.

`ec_subgroup_check BLS12_381g1` decides one predicate: *are these 96 bytes a
point of the curve lying in the prime-order-r subgroup?* It is a
**well-formedness** predicate, not an **authenticity** predicate. It says
nothing about *which* point.

Concretely, if the only on-chain check on relayer-supplied pubkeys were the
subgroup check, the following attack succeeds completely:

1. Relayer generates its own secret keys `sk'_1..sk'_512`.
2. It submits `P'_i = sk'_i · G1` as the "committee pubkeys". Every one passes
   `ec_subgroup_check` — they are perfectly valid G1 points.
3. It picks an arbitrary attacker-chosen beacon header, computes the real
   signing root over it, and signs with `Σ sk'_i`.
4. `hash_to_g2` and `ec_pairing_check` both succeed, because the signature is
   *genuinely valid* — just under the wrong keys.
5. The contract accepts a fabricated trust root. Everything downstream
   (Track B account/storage/receipt proofs) is now attacker-controlled.

So: subgroup check catches garbage, off-curve points, and small-subgroup
mischief. It does **not** and cannot catch key substitution. Authenticity must
come from a commitment.

### 4.5 The decision: `bind = subgroup_check ∧ recompress-and-compare`

**Recommendation (normative).**

- The relayer supplies uncompressed points off-chain-decompressed. There is no
  on-chain decompression.
- Every relayer-supplied G1 point that is supposed to be a *specific committee
  member's key* is admitted only through:

  ```
  g1_bind(uncompressed_96, committed_compressed_48):
      assert not g1_is_infinity(uncompressed_96)        # fail-closed, §10.1
      assert ec_subgroup_check(BLS12_381g1, uncompressed_96)
      assert g1_compress(uncompressed_96) == committed_compressed_48
  ```

- `committed_compressed_48` MUST be a value the contract has already verified
  against a trusted SSZ root (M3). Passing relayer-supplied compressed bytes
  makes the binding vacuous.

**Why this is sound and complete.** Given a committed `X` and a committed sign
bit, there are exactly two curve points with that `X` (`Y` and `p − Y`), and the
sign bit selects one. So compressed → uncompressed is injective on-curve, and
recompressing a *validated* point and matching the committed 48 bytes proves the
point is bit-for-bit the one the beacon chain committed to. The relayer's only
remaining freedom is to fail.

**Why the subgroup check is still needed even though X is pinned.**
Recompression reads `X` and the *sign* of `Y`; it never checks `Y² = X³ + 4`. A
relayer could submit `(X_correct, Y_bogus)` where `Y_bogus` happens to sit on the
same side of `HALF_P` — recompression would pass with an off-curve point, and
off-curve operands open invalid-curve attacks against the subsequent MSM and
pairing. The subgroup check closes this (it must decode the point, which
validates the curve equation, before testing its order). Probes P6–P8 (§12)
pin down whether the `ec_*` ops themselves also reject such operands; we treat
any such behaviour as defence in depth and never as the primary control.

**Costed.** `g1_bind` ≈ 1850 (subgroup) + ~50 (recompress + compare) ≈ **1900**
per key. For 512 keys ≈ **973,000** budget — 5.1× the 190,400 single-group
ceiling.

That number is the reason for the one remaining structural decision:

> **Bind once per committee, not once per update.** The uncompressed committee
> is validated at install time (spanning several atomic groups, once per
> ~27-hour sync-committee period) and cached in box storage. Per-update
> aggregation then reads points the *contract itself* wrote and validated, and
> needs no binding, no subgroup check, and no compressed data at all.

The alternative — keep only compressed keys on-chain and re-bind per update —
costs ~973,000 budget ≈ 1.39 ALGO in app-call fees *every update*, versus a
one-time ~19.7 ALGO of **recoverable** box MBR (400 µA/byte × 512 × 96 B). It
breaks even after ~14 updates and there is at least one update per period.
Caching wins decisively. Sizing, box naming, and session resumability are M4/M10
(§10).

### 4.6 The signature is a different case — no binding needed

The G2 signature is not committed to anything; it is fresh data. If a relayer
substitutes a different signature, the pairing check simply fails. So the
signature needs only well-formedness:

```
g2_validate(sig_192):
    assert not g2_is_infinity(sig_192)
    assert ec_subgroup_check(BLS12_381g2, sig_192)
```

`g2_bind` is still specified (§5) because M4 may want it for
`aggregate_pubkey`-style committed G2 values in future forks, but the sync
committee has no committed G2.

### 4.7 API hygiene

`g1_validate` / `g2_validate` are *deliberately* named
`*_validate_wellformed_only` in the source (aliased in docs for readability) so
that a future caller cannot reach for a validity check while believing it got an
authenticity check. §4.4 is quoted verbatim as the docstring of both functions.

---

## 5. Interface (Puya)

Ships as a **compile-time subroutine library** — plain Python modules under
`contracts/primitives/bls/`, imported into M4's contract, *not* a separately
deployed app. An inner app call per primitive would pay itxn issuance overhead
and force every value through the 4096-byte argument/return marshalling for no
benefit. (The budget-donor inner-call pattern in §9 is unrelated and orthogonal.)

A thin ARC-4 **harness app** (`contracts/primitives/bls/harness.py`) wraps each
primitive as an ABI method so the test suite can measure real
`app-budget-consumed` per primitive via `simulate` — that is how §12's
measurement backlog gets satisfied.

Implementation note: verify the exact `algopy` stub names against the installed
version before writing code (`python -c "import algopy.op as o; print(dir(o.EllipticCurve))"`).
If they differ from what is written below, use the real `algopy.op` equivalents —
do **not** hand-roll TEAL for these calls.

### 5.1 `contracts/primitives/bls/codec.py`

```python
from algopy import Bytes, BigUInt, UInt64, subroutine, op
from algopy.op import EC, EllipticCurve

FP_BYTES     = 48
G1_BYTES     = 96
G2_BYTES     = 192
SCALAR_BYTES = 32
G1_COMPRESSED_BYTES = 48
G2_COMPRESSED_BYTES = 96

FIELD_MODULUS: BigUInt      # p
HALF_P: BigUInt             # (p-1)/2
NEG_G1_GENERATOR: Bytes     # 96 B, §3
G1_INFINITY: Bytes          # 96 zero bytes
G2_INFINITY: Bytes          # 192 zero bytes

@subroutine
def pad_fp(b: Bytes) -> Bytes:
    """Left-pad to exactly 48 bytes.

    MANDATORY after any BigUInt/byte-math round-trip: AVM byte-math results are
    minimal-width (leading zeros stripped), so `p - y` may be < 48 bytes and
    would corrupt a concatenated point encoding.
    """

@subroutine
def g1_is_infinity(p: Bytes) -> bool: ...      # p == G1_INFINITY, len asserted 96
@subroutine
def g2_is_infinity(p: Bytes) -> bool: ...      # p == G2_INFINITY, len asserted 192

@subroutine
def g1_negate(p: Bytes) -> Bytes:
    """96 B -> 96 B. X ‖ pad_fp(p - Y). Infinity maps to itself."""

@subroutine
def g2_negate(p: Bytes) -> Bytes:
    """192 B -> 192 B. Negates both Y limbs independently. Infinity -> itself."""

@subroutine
def g1_compress(p: Bytes) -> Bytes:
    """AVM uncompressed 96 B -> Ethereum/ZCash compressed 48 B. §3.2.
    Does NOT validate the point; only `*_bind` / `*_validate` do that."""

@subroutine
def g2_compress(p: Bytes) -> Bytes:
    """AVM uncompressed 192 B -> Ethereum/ZCash compressed 96 B.
    Performs the c0/c1 limb swap — see the trap in §3.3."""

@subroutine
def g1_validate_wellformed_only(p: Bytes) -> None:
    """assert ec_subgroup_check(BLS12_381g1, p). NOT an authenticity check —
    see design doc 001 §4.4 before using this instead of g1_bind."""

@subroutine
def g2_validate_wellformed_only(p: Bytes) -> None: ...

@subroutine
def g1_bind(uncompressed: Bytes, committed_compressed: Bytes) -> None:
    """THE trust boundary. §4.5.

    Admits `uncompressed` (96 B, relayer-supplied) as the genuine point behind
    `committed_compressed` (48 B). Rejects infinity, non-subgroup/off-curve
    input, and any point whose compressed form differs from the commitment.

    CALLER OBLIGATION: `committed_compressed` MUST already be verified against
    a trusted SSZ root. Relayer-supplied compressed bytes make this vacuous.
    Budget: ~1900.
    """

@subroutine
def g2_bind(uncompressed: Bytes, committed_compressed: Bytes) -> None: ...
```

### 5.2 `contracts/primitives/bls/aggregate.py`

```python
G1_MAX_POINTS_PER_VALUE = 42   # 4096 B AVM value cap  (42*96 = 4032)
G1_MAX_POINTS_PER_ARG   = 21   # 2048 B total app-arg cap (21*96 = 2016)
G2_MAX_POINTS_PER_VALUE = 21   # 21*192 = 4032

@subroutine
def assert_g1_blob(blob: Bytes) -> UInt64:
    """len % 96 == 0 and len <= 4032; returns the point count. §7 boundary rules."""

@subroutine
def g1_sum_blob(blob: Bytes) -> Bytes:
    """ec_add chain over 1..42 concatenated G1 points -> 96 B.
    n == 0 -> G1_INFINITY (no opcodes). n == 1 -> the point, unchanged."""

@subroutine
def g1_accumulate(acc: Bytes, blob: Bytes) -> Bytes:
    """acc + Σ blob. Pass G1_INFINITY as the initial acc; the implementation
    short-circuits an infinity acc to save one ec_add (§7.1)."""

@subroutine
def g1_accumulate_negated(acc: Bytes, blob: Bytes) -> Bytes:
    """acc − Σ blob. For complement aggregation (§10.3)."""

@subroutine
def g1_msm_chunk(points: Bytes, scalars: Bytes) -> Bytes:
    """One ec_multi_scalar_mul call. Asserts len(points) <= 4032,
    len(points) % 96 == 0, len(scalars) == 32 * (len(points)/96).
    General-scalar path only — for all-ones scalars use g1_accumulate (§6.4)."""

@subroutine
def g1_msm_accumulate(acc: Bytes, points: Bytes, scalars: Bytes) -> Bytes: ...

@subroutine
def chunk_count(n: UInt64, chunk_size: UInt64) -> UInt64:
    """ceil(n / chunk_size). Off-chain relayers must use the identical rule."""
```

### 5.3 `contracts/primitives/bls/hash_to_curve.py`

```python
@subroutine
def expand_message_xmd_sha256(msg: Bytes, dst: Bytes, out_len: UInt64) -> Bytes:
    """RFC 9380 §5.3.1. Asserts out_len <= 255*32 and len(dst) <= 255."""

@subroutine
def hash_to_g2(msg: Bytes, dst: Bytes) -> Bytes:
    """RFC 9380 hash_to_curve, suite BLS12381G2_XMD:SHA-256_SSWU_RO_.
    Returns a 192 B AVM-order G2 point in the prime-order subgroup.
    The DST is a PARAMETER — picking the right one is M4's job (§8)."""
```

### 5.4 `contracts/primitives/bls/pairing.py`

```python
@subroutine
def pairing_check_2(a0: Bytes, b0: Bytes, a1: Bytes, b1: Bytes) -> bool:
    """ec_pairing_check(BLS12_381g1, a0‖a1, b0‖b1):
    true iff e(a0,b0) · e(a1,b1) == 1. a* are 96 B G1, b* are 192 B G2.
    Pairs are index-aligned (pinned by probe P5, §12). Budget 53,000."""

@subroutine
def verify_aggregate_signature(
    agg_pubkey: Bytes, msg_point: Bytes, signature: Bytes
) -> bool:
    """fast_aggregate_verify core: e(agg_pubkey, msg_point) == e(G1, signature),
    checked as e(agg_pubkey, msg_point) · e(−G1, signature) == 1.

    Asserts none of the three operands is infinity (§10.1) and that the
    signature is subgroup-valid. Returns the pairing result so the caller can
    choose whether to assert. Does NOT check that msg_point is the hash of the
    right message under the right DST — that is M4's (§8).
    """
```

Note `−G1` is the compile-time constant `NEG_G1_GENERATOR` (§3), so the
negation is free; there is never a reason to negate `agg_pubkey` or the
signature at runtime here.

---

## 6. Aggregation and MSM chunking

### 6.1 Why chunking is unavoidable

512 uncompressed G1 pubkeys are 49,152 bytes. That exceeds:

- the 4096-byte AVM **value** cap (⇒ at most 42 points can exist in one value),
- the 2048-byte total **app-arg** cap (⇒ at most 21 points delivered per txn),
- the 32,768-byte **box** cap (⇒ at least 2 boxes), and
- the 1024-byte-per-box-reference **read budget** (⇒ 48 box refs to read all of
  it; a 16-txn group provides 16 × 8 = 128).

So every API in §5.2 is chunk-oriented, and the chunk size is a property of the
*data source*, not of the algorithm:

| Source | Max G1 points per call |
|---|---|
| app args | 21 (2048 B arg cap) |
| `box_extract` / value | 42 (4096 B value cap) |
| `ec_multi_scalar_mul` operand | 42 (same cap) |

### 6.2 Chunking for arbitrary N (general scalars)

```
CHUNK = 42
k     = ceil(N / CHUNK)
chunk i covers points [i*CHUNK, min((i+1)*CHUNK, N))
acc   = G1_INFINITY
for i in 0..k-1:  acc = g1_msm_accumulate(acc, points_i, scalars_i)
```

Cost = `Σ_i (6500 + 95·n_i) + (k−1)·205` = `6500·k + 95·N + 205·(k−1)`.

Since `95·N` is invariant and the per-call `6500` is size-independent, **the
only lever is minimising k**, and `k = ceil(N/42)` is already minimal.
Rebalancing chunk sizes (e.g. 13 chunks of ~40 instead of 12×42 + 1×8) changes
nothing. Verification against the spike: N = 512 → k = 13 →
`84,500 + 48,640 + 2,460 = 135,600`, matching `RESULTS.md` §5's
`125,880 + 7,260 + 2,460` exactly.

### 6.3 Partial-sum combination order

G1 is abelian, so order is mathematically irrelevant. Use **sequential
left-to-right accumulation**. Do *not* build a combination tree: there is no
parallelism to exploit on the AVM, and a tree costs the same `k−1` adds while
requiring `O(log k)` live 96-byte intermediates. Sequential accumulation keeps
exactly one 96-byte accumulator live, which matters for the resumable-session
design in §10.2 (one accumulator is one 96-byte global-state value; global
byteslice values allow 128 B).

### 6.4 The generalised trailing-chunk optimization: for all-ones scalars, do not use MSM at all

`RESULTS.md` §5 found that swapping the 8-point trailing MSM chunk for 7
`ec_add`s saved 5,825 budget and pulled a 512-key update from two groups into
one. That optimization generalises much further than the spike's footnote
suggests, and the generalisation is this module's main budget contribution.

Aggregating pubkeys is summation — **every scalar is 1**. So `ec_scalar_mul` is
never needed and MSM's whole value proposition disappears. Comparing the two
paths for a chunk of `n ≤ 42` points, using only spike-measured isolated costs:

| n | `ec_add` chain `(n−1)·205` | MSM `6500 + 95n` |
|---:|---:|---:|
| 2 | 205 | 6,690 |
| 10 | 1,845 | 7,450 |
| 42 | 8,405 | 10,490 |
| 61 | 12,300 | 12,295 ← crossover |
| 512 (chunked) | **104,755** | 135,600 |

The crossover is at n ≈ 61, which is **beyond the 42-point cap**, so:

> **For scalar-1 aggregation, an `ec_add` chain beats `ec_multi_scalar_mul` at
> every reachable chunk size.** For 512 points it saves **30,845** budget
> (22.7%) against the spike's chunked-MSM plan — 44 app calls, 0.044 ALGO.

Two secondary advantages: the `ec_add` path never builds the 1,344-byte scalar
blob (pure overhead in the MSM path), and it does not require the 42 points to
be *contiguous*, so it composes with box reads at any offset.

**The one thing that could reverse this, and the measure-then-branch rule.**
The table compares opcode costs, not loop costs. The MSM path pays its glue once
per 42 points; the `ec_add` path pays it 42 times. Break-even:

```
42·g = 10,490 − 42·205 = 1,880   ⇒   g = 44.8 budget per iteration
```

> **Decision rule for the implementer.** Implement `g1_accumulate` as an
> `ec_add` chain (default) *and* measure real per-iteration glue with probe P9.
> If measured glue < 45/iteration, keep the chain. If ≥ 45, switch
> `g1_accumulate` internally to `g1_msm_chunk` with an all-ones scalar blob —
> the signature does not change. Record the measured number and the resulting
> choice in the fixture set; that measurement is a merge requirement.

Expectation (not a claim): a Puya loop of `extract3` + counter arithmetic +
`ec_add` should land around 10–20, comfortably under 45. If it does not, the
first remedy is dropping that specific loop to raw `Op` — exactly the exception
`ARCHITECTURE.md` reserves for "MSM chunking".

### 6.5 Trailing-chunk rule for the *general* (non-unit-scalar) MSM path

For genuinely arbitrary scalars, replacing a trailing chunk of `t` points costs
`t · (cost(ec_scalar_mul) + 205)` versus `6500 + 95t`. `ec_scalar_mul
BLS12_381g1` has never been measured (§2.2, probe P4). Therefore:

- Ship `g1_msm_chunk` with **no** trailing-chunk special case initially.
- Probe P4 measures `ec_scalar_mul`; if `cost + 205 < (6500 + 95t)/t` for small
  `t`, add the specialisation behind the existing signature and record the
  threshold `t` in the fixtures.

This path is not on the sync-committee critical path (§6.4 removes it from
there); it exists so M1 is a complete primitive layer.

---

## 7. Edge cases

### 7.1 Infinity

- **Encoding**: G1 infinity = 96 zero bytes, G2 = 192 zero bytes (spike-verified
  for G1 via `ec_add`). Compressed infinity = `0xc0 ‖ zeros`.
- **`g1_bind` / `g2_bind` / `verify_aggregate_signature` reject infinity,
  fail-closed.** Rationale: with `agg_pubkey = O`, the pairing identity
  degenerates to `e(−G1, S) == 1`, which holds iff `S == O` — so an
  infinity/infinity pair would verify against *any* message. The BLS spec's
  `KeyValidate` likewise rejects an infinity pubkey. `eth_fast_aggregate_verify`
  permits the empty-participant/infinity-signature case, but the light-client
  spec's `MIN_SYNC_COMMITTEE_PARTICIPANTS` check excludes it — enforcing that is
  M4's, and M1 fails closed regardless.
- `g1_sum_blob`/`g1_accumulate` **produce** infinity legitimately (N = 0, or a
  set summing to zero). That is not an error inside the aggregation layer; it is
  caught at the pairing boundary. Documented explicitly so an implementer does
  not "helpfully" assert inside the accumulator.
- Whether `ec_subgroup_check` returns 1 for infinity, and whether
  `ec_pairing_check` accepts infinity operands, is measured by probes P6–P7.
  M1's behaviour does not depend on the answer (it rejects infinity before
  reaching either op), but the answer must be recorded.
- `g1_negate(O) == O` and `g2_negate(O) == O` must be special-cased: `p − 0 = p`
  is not a valid coordinate.

### 7.2 N = 0 and N = 1

- `N = 0`: `g1_sum_blob(b"")` returns `G1_INFINITY` with zero opcodes.
  `assert_g1_blob` permits a zero-length blob.
- `N = 1`: return the single point unchanged — **zero** `ec_add`s. Note the
  contrast: `g1_msm_chunk` with one point still costs 6,595, another reason
  §6.4's default is the chain.
- `g1_accumulate(G1_INFINITY, blob)` must skip the initial add (short-circuit on
  an infinity accumulator), so summing 512 points costs 511 adds, not 512.

### 7.3 The 42/43-point boundary

The spike established that 43 points fail **at the push**, not inside the
opcode: `bytec_0 produced a too big (4097) byte-array`. Implications:

- The failure is a generic value-cap violation, so it is *not* MSM-specific and
  applies equally to `ec_add`-chain blobs, box extracts, and concatenations.
- A 4,128-byte value cannot exist at all — so a "43-point blob" can never be
  passed in and then rejected by a length check; the caller's `concat` or
  `box_extract` errors first. `assert_g1_blob`'s `len <= 4032` check is
  therefore a *contract-clarity and off-by-one* guard (catching e.g. 4,000-byte
  non-multiples), not the mechanism that stops 43 points.
- App args cap total arg length at 2,048 B, so args-delivered chunks max out at
  **21** points, not 42. An implementer who assumes 42 everywhere will produce a
  relayer that cannot submit. Both constants are exported (§5.2) and the
  relayer (M9) must use the same ones.
- Test T5 pins all of: n = 41 ok, n = 42 ok, n = 43 rejected (and *where* it is
  rejected), 4,032 B ok, 4,033 B rejected, non-multiple-of-96 rejected.

### 7.4 Subgroup-check failures

- `ec_subgroup_check` returns a bool for a decodable point; malformed/off-curve
  input may instead **error** (the spike saw `ec_pairing_check` reject garbage
  G2 outright). Handle both uniformly by wrapping in `assert` — an errored
  opcode fails the txn, a `false` result fails the assert. Never branch on the
  bool.
- A bind failure is unrecoverable within the txn (by design: fail-closed). M4
  must not catch or soften it; a relayer that supplies a bad point gets its
  group rejected.
- On-curve-but-not-in-G1 points exist (the G1 cofactor is 126 bits) and are
  exactly what the subgroup check exists to reject. Test T3 includes a
  deliberately constructed cofactor-subgroup point.

### 7.5 Coordinate range

A relayer could supply `X ≥ p` or `Y ≥ p`. Point decoding inside the `ec_*` ops
should reject this; probe P8 confirms. If it turns out not to, add an explicit
`BigUInt(X) < FIELD_MODULUS` check to `*_bind` (two `b<` ops, ~40 budget). Note
that a non-canonical `X ≥ p` would also fail the recompress comparison unless
`X`'s top three bits were zero *and* it matched the commitment, so the binding
path is already narrow here; the exposure is in `*_validate_wellformed_only`.

---

## 8. `hash_to_g2` and the M1/M4 boundary

`verify_aggregate_signature` needs the message as a G2 point. That point cannot
come from the relayer: if it did, the relayer could supply an arbitrary G2 point
and sign it, forging trivially. **`hash_to_g2` must run on-chain**, and there is
no cheap inverse to verify a supplied point against, so this is compute, not
verify.

**Decision: `hash_to_g2` lives in M1**, implemented as the generic RFC 9380
`hash_to_curve` for `BLS12381G2_XMD:SHA-256_SSWU_RO_`, with `dst` as a runtime
parameter and **no Ethereum constant hard-coded anywhere in M1**. Rationale: it
is pure curve/field mechanics, identical to the rest of M1, and M4 should not
have to reimplement SSWU plumbing to get a signature verified.

The split of responsibility is therefore:

- **M1 owns *how*** — RFC 9380 mechanics, validated against RFC 9380's own
  published vectors with the RFC's `QUUX-V01-CS02-…` DST.
- **M4 owns *what*** — that `msg` is the correct signing root and `dst` is
  `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, validated against Ethereum
  consensus-spec vectors.

Implementation shape:

```
hash_to_g2(msg, dst):
    uniform = expand_message_xmd_sha256(msg, dst, 256)   # ell=8 blocks, 9 sha256
    e0..e3  = [ BigUInt(uniform[64i : 64i+64]) % p  for i in 0..3 ]   # 4 b%
    u0      = pad_fp(e0) ‖ pad_fp(e1)      # Fp2 = c0 ‖ c1, AVM order
    u1      = pad_fp(e2) ‖ pad_fp(e3)
    return ec_add(BLS12_381g2, ec_map_to(BLS12_381g2, u0),
                               ec_map_to(BLS12_381g2, u1))
```

Two things make this correct and cheap:

1. `b%` with a 64-byte dividend and 48-byte modulus is within the byte-math
   operand cap — hash-to-field reduction is legal AVM arithmetic even though
   general modular arithmetic is not (§4.2).
2. **Cofactor clearing commutes with the addition.** RFC 9380 specifies
   `clear_cofactor(map_to_curve(u0) + map_to_curve(u1))`, and `h·(Q0+Q1) =
   h·Q0 + h·Q1`, so if the AVM's `ec_map_to` already clears the cofactor — which
   the spike proved for G1 (its output passes the subgroup check) — then
   `map_to(u0) + map_to(u1)` is exactly the spec's output. Probe P2 confirms
   this for G2, plus bit-exactness against `py_ecc.bls.hash_to_curve.hash_to_G2`.
   If P2 shows the cofactor is *not* cleared for G2, add one
   `ec_scalar_mul(BLS12_381g2, R, h2)`; the signature does not change.

Provisional cost: `9 · sha256 (~315) + 4 · b% (~80) + 2 · ec_map_to g2 (16,300)
+ 1 · ec_add g2 (~205)` ≈ **~17,000**, dominated by the two G2 maps. Note this
is 8.4× the G1 figure the spike used for convenience; `RESULTS.md` §5's caveat
is correct and the 8,150 figure itself still needs its own measured row (P1).

**Fallback if the M4 designer prefers to own hash-to-curve**: move
`hash_to_curve.py` to M4 verbatim. `verify_aggregate_signature`'s signature is
unchanged — it takes `msg_point`, never a message. Nothing else in M1 depends on
it.

---

## 9. Interaction with the group and inner-call budget ceiling

### 9.1 Inner app calls are budget *donors*, not work partitions

The spike measured that budget pools across a group and that inner app calls add
700 each, capped at 256 inner txns **per group**, giving 272 × 700 = 190,400.
The consequence for chunking is easy to get wrong:

> Work does not need to be partitioned across calls to use pooled budget. One
> program can consume the entire pool. The standard pattern is: the heavy call
> issues N cheap no-op inner app calls purely to raise the pool, then runs the
> aggregation loop in a single program with a single accumulator.

This is much simpler than splitting aggregation across 16 top-level calls, which
would need cross-txn accumulator state *and* would still only reach 11,200
budget on its own (inner donors are mandatory to reach 190,400 either way).

Caveat requiring measurement (P11): each donor call costs `itxn_begin` +
`itxn_field`s + `itxn_submit` + the callee program's own execution. The *net*
gain is `700 − issuance − callee`, and if issuance is ~50–100 the effective
ceiling is meaningfully below 190,400. M4 cannot size its group without this
number.

### 9.2 Revised single-group feasibility for a 512-key update

Using only measured opcode costs plus the flagged provisionals, and **excluding
loop glue, box-read opcodes, and M3's SSZ work**:

| Component | Budget | Basis |
|---|---:|---|
| Aggregate 512 pubkeys, `ec_add` chain (§6.4) | 104,755 | measured 205 × 511 |
| `hash_to_g2` (§8) | ~17,000 | provisional, P1/P2 |
| `ec_pairing_check`, 2 pairs | 53,000 | measured |
| `ec_subgroup_check` on the signature (G2) | ~2,750 | provisional, P3 |
| **Total** | **~177,505** | ⇒ 254 app calls |
| *Complement variant (§10.3), worst case 256 adds* | **~125,230** | ⇒ 179 app calls |

Against the 272-call ceiling that is 18 calls of headroom for the direct path
and 93 for the complement path — where the spike's honest real-G2 estimate was
282 calls / two groups. So:

> **M1's `ec_add`-chain aggregation plausibly returns the real-G2
> sync-committee update to a single atomic group.** This is a *plausibility*
> claim, not a shipped number: glue, box reads, and M3's per-update branch
> verification (a few dozen `sha256`, small) are not in the table, and 18 calls
> of headroom is thin. M4 owns the final 1-vs-2-group call, after P1/P2/P3/P9/P11.

Per-update box read budget for the direct path: 512 × 96 = 49,152 B needs 48 box
references at 1,024 B each; a 16-txn group supplies 128 (duplicate references to
the same box each add 1,024, which is the standard way to raise the read pool).
The complement path needs ≤ 24. Comfortable either way.

### 9.3 Recommendation: do not architect against the ceiling

Because committee *install* (§4.5, ~973,000 budget + ≥25 txns just to deliver
49 KB through the 2,048 B-per-txn arg cap) cannot fit one group under any
design, M4 needs a **resumable session** (a progress counter plus a 96-byte
partial accumulator in state, finalised only when complete) regardless. Once
that machinery exists, the per-update path should use it too rather than depend
on 18 calls of headroom. M1 supports this for free: sequential accumulation
(§6.3) keeps exactly one 96-byte accumulator, which fits a global-state
byteslice.

---

## 10. Implications for M4 *(informative — not normative for M1)*

Recorded because they justify M1's API shape, which *is* normative.

**10.1 Install-time flow.**
1. M3 verifies the SSZ branch committing `SyncCommittee{pubkeys[512],
   aggregate_pubkey}` under a trusted root. Note this requires merkleizing 512
   compressed pubkeys on-chain (1,024 chunks ⇒ ~1,023 `sha256`) — a real
   install-time cost M3/M4 must budget, and a new cross-module dependency this
   design creates.
2. For each `i`: `g1_bind(uncompressed[i], compressed[i])`, then write
   `uncompressed[i]` into a box at offset `96·i`.
3. Compute `Σ uncompressed[i]` (511 `ec_add`s) and assert it equals the bound
   decompression of the committed `aggregate_pubkey`. This is a free
   cross-check that the whole committee installed correctly, and it caches the
   full aggregate needed by §10.3.

**10.2 Storage.** 512 × 96 = 49,152 B needs ≥ 2 boxes (32,768 B cap). Prefer 8
boxes of 64 keys (6,144 B) for box-reference granularity. MBR is 400 µA/byte ⇒
~19.7 ALGO per committee, **locked and recoverable**, not spent; boxes are
rewritten each period rather than reallocated. Holding current + next
simultaneously roughly doubles it.

**10.3 Adaptive direct/complement aggregation.** Participation is a bitfield
over a fixed committee, and the full aggregate is cached (§10.1 step 3), so
`Σ_participants = Σ_all − Σ_non-participants`. M4 should compute
`popcount(bits)` and pick:

- `popcount ≤ 256` → direct summation (`g1_accumulate`)
- `popcount > 256` → complement (`g1_accumulate_negated` from the cached total)

This caps aggregation at 256 `ec_add`s ≈ 52,480 instead of 511 ≈ 104,755, and
halves worst-case box reads. Participation is honest data (a relayer cannot
inflate it without a matching signature it cannot forge), so this is a pure win
with no adversarial worst case beyond the 256 bound. It is why
`g1_accumulate_negated` exists in §5.2.

**10.4 What M4 must still resolve.** Real DST and signing-root construction
against consensus-spec vectors; `MIN_SYNC_COMMITTEE_PARTICIPANTS`; fork-version
handling; the final group-count decision; session/rotation lifecycle.

---

## 11. Test plan

Split along the project's two-CI policy: pure byte-math is unit-testable
offline; anything touching `ec_*` needs `algod`. `algopy_testing` does not
emulate the EC opcodes, so the offline tier tests a **Python reference
implementation** of each pure-byte primitive against `py_ecc`, plus **pinned
fixtures** recorded from real simulate runs; the live tier re-runs them against
localnet.

Fixture generator: `tests/bls/generate_fixtures.py`, reusing
`tests/fixtures/spike-reference/avm_bls_bench.py` (algod/kmd clients, TEAL
assembly, simulate-with-extra-budget, `g1_uncompressed` / `g2_uncompressed` /
`scalar_be`) unmodified. Outputs `tests/fixtures/bls/*.json` with inputs,
expected outputs, and measured `app-budget-consumed`.

| # | Test | Tier | Asserts |
|---|---|---|---|
| T1 | Codec round-trip, 100 random `k·G1` and `k·G2` | offline + live | `g1_compress(avm_bytes) == py_ecc.G1_to_pubkey(P)`; same for `G2_to_signature`. Pins the AVM↔Ethereum bridge in the direction we actually implement. |
| T2 | **Limb-order regression** | live | `a0a1`-ordered G2 satisfies `e(P,Q)·e(−P,Q)==1`; `a1a0`-ordered **fails**. Locks §3.3 so a future refactor cannot silently adopt the ZCash order. |
| T3 | Validity | live | subgroup-valid point → ok; off-curve → rejected; deliberately constructed cofactor-subgroup point → rejected; record error-vs-`false` for each. |
| T4 | Sign-bit boundary | offline + live | points with `Y` just above/below `HALF_P`, and `P`/`−P` pairs, compress with the right `0x20` bit. Includes the known-answer check that the generator compresses to `0x97f1d3a7…`. |
| T5 | 42/43 boundary (§7.3) | live | n = 41, 42 ok; n = 43 fails *at the push*, and the failure message is recorded; 4,032 ok / 4,033 rejected / non-multiple-of-96 rejected; the 21-point app-arg limit is exercised via a real txn. |
| T6 | Aggregation vs `py_ecc` | offline ref + live | N ∈ {0, 1, 2, 41, 42, 43, 64, 100, 512}; N=0 → infinity, N=1 → identity with zero adds; chunk-boundary crossing is byte-exact. |
| T7 | MSM | live | the spike's exact `2·P1 + 3·P2 + 4·P3` vector; chunked N=100 with random scalars vs `py_ecc`; mismatched points/scalars length rejected. |
| T8 | Negation / infinity | offline + live | `g1_negate(g1_negate(P)) == P`; `negate(O) == O`; `g1_compress(O) == 0xc0‖0*47` matches `py_ecc.G1_to_pubkey(None)`. |
| T9 | `expand_message_xmd` | offline | RFC 9380 Appendix K vectors, exact. |
| T10 | `hash_to_g2` | live | RFC 9380 `BLS12381G2_XMD:SHA-256_SSWU_RO_` vectors (msgs `""`, `"abc"`, `"abcdef0123456789"`, the long/`a…` cases) with the RFC's DST, byte-exact against `py_ecc.bls.hash_to_curve.hash_to_G2`. |
| T11 | End-to-end aggregate verify | live | `py_ecc.bls.G2ProofOfPossession`: generate k keypairs, sign one message, `Aggregate`; assert `verify_aggregate_signature` true. Then false for: wrong message, one substituted pubkey, signature from another key, infinity pubkey, infinity signature. |
| T12 | **Trust-boundary attack test** | live | Executable form of §4.4: build a fully-forged update with attacker-generated keys; assert `g1_validate_wellformed_only` **passes** on every forged key and `verify_aggregate_signature` **succeeds**; then assert `g1_bind` against the real committed compressed keys **rejects** it. This test is the security argument; it must fail loudly if anyone ever swaps `g1_bind` for a bare subgroup check. |
| T13 | Budget measurement | live | Every §12 probe, recorded into the fixture set with the real simulate response. |

### 11.1 Dependency to flag for M4

`py_ecc` can generate real subgroup-valid points *and* real BLS signatures, so
M1's tests can cover full signature verification end to end (T11) without
Ethereum data. What `py_ecc` **cannot** validate is that we hash the right bytes
under the right domain — a self-consistent M1 would pass T11 with a wrong DST.

> **M4 dependency**: real Ethereum consensus-layer test vectors (the
> `general/*/bls/` and `altair/light_client/*` suites from
> `ethereum/consensus-spec-tests`) are required to validate DST and
> signing-root construction. Sourcing and pinning them is M4's blocker, not
> M1's, and M1's tests must not be read as covering it. `ARCHITECTURE.md`
> already makes citing those vectors a condition of M4's design approval.

---

## 12. Measurement backlog (must land with the implementation)

No design decision above depends on an unmeasured number without a
measure-then-branch rule, but per `ARCHITECTURE.md` none of these may be quoted
as fact until measured. Each is a probe in the style of
`spike-reference/probe_encoding.py`, run against the M1 harness app (§5).

| # | Probe | Blocks |
|---|---|---|
| P1 | `ec_map_to BLS12_381g2` cost (`RESULTS.md` §5's 8,150 has no measured row) | §8 cost, M4 group sizing |
| P2 | Does `ec_map_to BLS12_381g2` clear the cofactor? Fp2 input limb order? Bit-exact vs `py_ecc`? | §8 correctness |
| P3 | `ec_subgroup_check BLS12_381g2`, `ec_add BLS12_381g2` costs | §9.2 |
| P4 | `ec_scalar_mul BLS12_381g1` cost | §6.5 |
| P5 | Pairing pair-alignment: `A=[G1, −2G1]`, `B=[2G2, G2]` must pass and the swapped assignment must fail (the spike's probe used equal `B` entries and so did not distinguish) | §5.4 |
| P6 | `ec_subgroup_check` on infinity; `ec_pairing_check` with infinity operands | §7.1 |
| P7 | Off-curve G1 into `ec_add` / `ec_multi_scalar_mul` / `ec_subgroup_check`: error or `false`? | §7.4 depth-of-defence |
| P8 | Non-canonical coordinate `X ≥ p`: accepted or rejected? | §7.5 |
| P9 | **Per-iteration glue of the `ec_add` accumulation loop** (compare 42-point chain vs. one 42-point MSM, end to end, in real Puya output) | **§6.4 decision rule** |
| P10 | Byte-math operand caps: does `b%` accept a 96-byte dividend? | unlocks the §4.3 on-curve optimization |
| P11 | Net budget gain per no-op donor inner app call | §9.1, M4 group sizing |
| P12 | `sha256` cost; box-read budget consumed by a 4,032-byte `box_extract` | §8, §9.2 |

---

## 13. ROADMAP open questions resolved

M1's row in `ROADMAP.md` lists two inherited open questions.

**Q1 — "Compressed (Eth wire format) vs. uncompressed (AVM opcode) trust
boundary." RESOLVED.** §4. Off-chain decompression by the relayer; on-chain
decompression is unimplementable, not just costly (§4.2 — the 64-byte byte-math
operand cap, not only the budget). The trust boundary is
**`ec_subgroup_check` + recompress-and-compare against an SSZ-committed
compressed value**, exported as `g1_bind`/`g2_bind`. Explicitly answered along
the way: **subgroup check alone is not sufficient** — it is a well-formedness
predicate, and a relayer substituting its own valid keypair defeats it
completely (§4.4, with T12 as the executable proof). Authenticity comes from the
commitment; the subgroup check remains necessary to stop off-curve `Y` values
that recompression would not catch. Structural consequence: bind once per
committee into box storage (~973,000 budget, several groups, once per ~27 h),
never per update.

**Q2 — "Use real G2 map-to-curve cost (8150), not G1 (1950)." RESOLVED, with a
correction.** §8 designs `hash_to_g2` against G2 throughout, and §9.2's budget
table uses ~17,000 for hash-to-curve (two G2 maps) rather than 1,950. The
correction: **8,150 is itself an unmeasured number** — `RESULTS.md` cites it in
prose but has no measured row, so it is a published-table figure and
`ARCHITECTURE.md` forbids shipping it as fact. Probe P1 fixes this.

**Partially informs M4's row — "finalize 1-vs-2-group call with real G2 numbers
(~282 calls / 2 groups)."** M1 contributes: (a) the `ec_add`-chain aggregation
that saves 30,845 budget over chunked MSM (§6.4), (b) the adaptive complement
option that halves the worst case (§10.3), (c) the cached-committee design that
removes 973,000 budget from the per-update path (§4.5). Together these bring the
provisional real-G2 update to ~177,505 / 254 calls direct or ~125,230 / 179
complement, against the 272-call ceiling — plausibly **one** group where the
spike concluded two. The decision stays M4's, gated on P1/P2/P3/P9/P11.

**Not resolved, deliberately (§1.2):** real BLS DST and signing-root vs.
consensus-spec vectors (M4's own listed open question; §11.1 restates it as a
dependency).

**New dependency this design creates**: M3 must merkleize 512 compressed
pubkeys on-chain (~1,023 `sha256`) for the install-time SSZ check in §10.1, and
M1's `expand_message_xmd_sha256` shares M3's unmeasured `sha256` cost (P12).

---

## 14. File layout

```
contracts/primitives/bls/
    __init__.py        # re-exports the public surface in §5
    codec.py           # §5.1 constants, compress, negate, validate, bind
    aggregate.py       # §5.2 chunk guards, ec_add chains, MSM chunking
    hash_to_curve.py   # §5.3 expand_message_xmd + hash_to_g2
    pairing.py         # §5.4 pairing_check_2, verify_aggregate_signature
    harness.py         # ARC-4 app wrapping each primitive, for simulate-based
                       # measurement and live tests only — not deployed
tests/bls/
    reference.py           # pure-Python mirror of codec.py, checked vs py_ecc
    generate_fixtures.py   # py_ecc + spike harness -> tests/fixtures/bls/*.json
    test_codec.py  test_aggregate.py  test_hash_to_curve.py
    test_pairing.py  test_trust_boundary.py   # T12
tests/fixtures/bls/
    *.json             # pinned inputs, expected outputs, measured budgets
```

## 15. Implementer checklist (normative MUSTs)

1. `pad_fp` after **every** byte-math/`BigUInt` round-trip — AVM byte-math
   results are minimal-width (§5.1).
2. `g2_compress` swaps `c0`/`c1`; never copy a reference library's G2
   serializer (§3.3).
3. Never branch on an `ec_subgroup_check` bool — always `assert` (§7.4).
4. Never expose a bind-free path to callers who need authenticity; keep the
   `*_validate_wellformed_only` name and the §4.4 docstring (§4.7).
5. Reject infinity in `*_bind` and `verify_aggregate_signature`; **allow** it as
   an aggregation *output* (§7.1).
6. Hard-code no Ethereum constant — no DST, no domain, no fork version (§1.2).
7. Default `g1_accumulate` to the `ec_add` chain; run P9 and record the result
   before merge (§6.4).
8. Every budget number in code comments, README, or a follow-up doc must cite a
   fixture containing a real simulate response (§12).
