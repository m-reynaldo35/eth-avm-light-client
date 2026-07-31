"""BLS12-381 aggregation and MSM chunking.

Design doc: docs/design/001-bls-primitives.md, §5.2, §6, §7.

§6.4's decision rule is normative (implementer checklist §15 item 7):
`g1_accumulate` defaults to an `ec_add` chain, because for scalar-1
aggregation (pubkey summation) an `ec_add` chain beats
`ec_multi_scalar_mul` at every chunk size reachable under the 42-point value
cap -- the crossover the doc computes (n ~ 61) sits beyond that cap. Whether
that decision survives a *measured* per-iteration Puya loop-glue number
(probe P9, §12) is a separate, empirical question; see the fixture generator
and this module's test suite for the measured result (or its absence) at
implementation time.
"""

from algopy import Bytes, UInt64, subroutine, urange
from algopy.op import EC, EllipticCurve

from .codec import G1_BYTES, SCALAR_BYTES, g1_infinity, g1_is_infinity, g1_negate

# ---------------------------------------------------------------------------
# Chunking constants (§6.1)
# ---------------------------------------------------------------------------
G1_MAX_POINTS_PER_VALUE = 42  # 4096 B AVM value cap  (42*96 = 4032)
G1_MAX_POINTS_PER_ARG = 21  # 2048 B total app-arg cap (21*96 = 2016)
G2_MAX_POINTS_PER_VALUE = 21  # 21*192 = 4032

G1_VALUE_CAP_BYTES = G1_MAX_POINTS_PER_VALUE * G1_BYTES  # 4032


@subroutine
def assert_g1_blob(blob: Bytes) -> UInt64:
    """len % 96 == 0 and len <= 4032; returns the point count (§7 boundary
    rules). Note (§7.3): this is a contract-clarity / off-by-one guard, not
    the mechanism that stops 43-point blobs -- a 4,128-byte value cannot be
    constructed at all, so the 4096-byte value cap itself is the true
    backstop; this assert catches e.g. a 4,000-byte non-multiple-of-96 blob.
    """
    length = blob.length
    assert length % G1_BYTES == 0
    assert length <= G1_VALUE_CAP_BYTES
    return length // G1_BYTES


@subroutine
def g1_sum_blob(blob: Bytes) -> Bytes:
    """`ec_add` chain over 1..42 concatenated G1 points -> 96 B.

    n == 0 -> `G1_INFINITY` (no opcodes). n == 1 -> the point, unchanged
    (zero `ec_add`s, §7.2).
    """
    n = assert_g1_blob(blob)
    if n == 0:
        return g1_infinity()
    acc = blob[0:G1_BYTES]
    for i in urange(1, n):
        pt = blob[i * G1_BYTES : i * G1_BYTES + G1_BYTES]
        acc = EllipticCurve.add(EC.BLS12_381g1, acc, pt)
    return acc


@subroutine
def g1_accumulate(acc: Bytes, blob: Bytes) -> Bytes:
    """acc + Sum(blob). Pass `G1_INFINITY` as the initial acc; the
    implementation short-circuits an infinity acc to save one `ec_add`
    (§7.1, §7.2): summing 512 points from an infinity accumulator costs 511
    adds, not 512.
    """
    assert acc.length == G1_BYTES
    n = assert_g1_blob(blob)
    if n == 0:
        return acc
    if g1_is_infinity(acc):
        running = blob[0:G1_BYTES]
        start_index = UInt64(1)
    else:
        running = acc
        start_index = UInt64(0)
    for i in urange(start_index, n):
        pt = blob[i * G1_BYTES : i * G1_BYTES + G1_BYTES]
        running = EllipticCurve.add(EC.BLS12_381g1, running, pt)
    return running


@subroutine
def g1_accumulate_negated(acc: Bytes, blob: Bytes) -> Bytes:
    """acc - Sum(blob). For complement aggregation (§10.3): negating the
    summed blob once (cheap byte-math) and combining with `acc` in a single
    `ec_add` is equivalent to negating every point individually, at a
    fraction of the cost -- `-(P1+...+Pn) == -P1-...-Pn`.
    """
    assert acc.length == G1_BYTES
    n = assert_g1_blob(blob)
    if n == 0:
        return acc
    neg_sum = g1_negate(g1_sum_blob(blob))
    if g1_is_infinity(acc):
        return neg_sum
    return EllipticCurve.add(EC.BLS12_381g1, acc, neg_sum)


@subroutine
def g1_msm_chunk(points: Bytes, scalars: Bytes) -> Bytes:
    """One `ec_multi_scalar_mul` call. Asserts len(points) <= 4032,
    len(points) % 96 == 0, len(scalars) == 32 * (len(points)/96).

    General-scalar path only -- for all-ones scalars (pubkey aggregation),
    use `g1_accumulate` instead (§6.4): MSM's per-call overhead makes it
    strictly worse than an `ec_add` chain in that case.
    """
    assert points.length <= G1_VALUE_CAP_BYTES
    assert points.length % G1_BYTES == 0
    n = points.length // G1_BYTES
    assert scalars.length == n * SCALAR_BYTES
    return EllipticCurve.scalar_mul_multi(EC.BLS12_381g1, points, scalars)


@subroutine
def g1_msm_accumulate(acc: Bytes, points: Bytes, scalars: Bytes) -> Bytes:
    """acc + msm_chunk(points, scalars), short-circuiting an infinity acc
    the same way `g1_accumulate` does.
    """
    assert acc.length == G1_BYTES
    chunk = g1_msm_chunk(points, scalars)
    if g1_is_infinity(acc):
        return chunk
    return EllipticCurve.add(EC.BLS12_381g1, acc, chunk)


@subroutine
def chunk_count(n: UInt64, chunk_size: UInt64) -> UInt64:
    """ceil(n / chunk_size). Off-chain relayers must use the identical rule
    (§5.2) so chunk boundaries agree between contract and relayer.
    """
    assert chunk_size > 0
    return (n + chunk_size - 1) // chunk_size
