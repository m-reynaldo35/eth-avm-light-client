"""Tests T1, T4, T8 (docs/design/001-bls-primitives.md §11) plus the live
half of T2 (limb-order regression) and T3 (validity).

Offline portion (T1, T4, T8) runs against `reference.py` + `py_ecc`, no
`algod` required. Live portion additionally exercises the compiled
`BlsHarness` app via `conftest.live_harness` against real `ec_*` opcodes.
"""

from __future__ import annotations

import random

import pytest
from py_ecc.optimized_bls12_381 import G1, G2, add, is_inf, multiply, neg, normalize

from . import reference as ref


def _bool_from_abi(b: bytes) -> bool:
    return bool(b[0] & 0x80)


# ---------------------------------------------------------------------------
# T1 -- codec round-trip, offline: g1_compress/g2_compress vs py_ecc's own
# G1_to_pubkey / G2_to_signature compressors.
#
# NOTE on py_ecc module choice: `py_ecc.bls.point_compression.compress_G1`/
# `compress_G2` (the reference oracle for this file) operate on the
# *optimized* (projective X,Y,Z) point representation
# (`py_ecc.optimized_bls12_381`), NOT the plain affine `py_ecc.bls12_381`
# module. All point construction below therefore uses the optimized module,
# with `normalize()` applied only when building our own AVM-order bytes.
# ---------------------------------------------------------------------------


def _to_affine(P):
    """Accepts either an already-affine 2-tuple (x, y) (e.g. from the plain
    `py_ecc.bls12_381` module) or a projective 3-tuple (X, Y, Z) (from
    `py_ecc.optimized_bls12_381`) and returns affine (x, y). `None` is
    accepted as the point at infinity."""
    if P is None:
        return None
    if len(P) == 2:
        return P
    if is_inf(P):
        return None
    return normalize(P)


def _g1_uncompressed(P) -> bytes:
    affine = _to_affine(P)
    if affine is None:
        return ref.G1_INFINITY
    x, y = affine
    return int(x).to_bytes(48, "big") + int(y).to_bytes(48, "big")


def _g2_uncompressed(P) -> bytes:
    """AVM order: X.c0 || X.c1 || Y.c0 || Y.c1."""
    affine = _to_affine(P)
    if affine is None:
        return ref.G2_INFINITY
    x, y = affine
    xc, yc = x.coeffs, y.coeffs
    return (
        int(xc[0]).to_bytes(48, "big")
        + int(xc[1]).to_bytes(48, "big")
        + int(yc[0]).to_bytes(48, "big")
        + int(yc[1]).to_bytes(48, "big")
    )


def test_t1_g1_compress_matches_py_ecc_100_random_points():
    from py_ecc.bls.point_compression import compress_G1

    rng = random.Random(1)
    for _ in range(100):
        k = rng.randrange(1, ref.FIELD_MODULUS)
        P = multiply(G1, k)
        avm_bytes = _g1_uncompressed(P)
        got = ref.g1_compress(avm_bytes)
        want = compress_G1(P).to_bytes(48, "big")
        assert got == want


def test_t1_g2_compress_matches_py_ecc_100_random_points():
    from py_ecc.bls.point_compression import compress_G2

    rng = random.Random(2)
    for _ in range(100):
        k = rng.randrange(1, ref.FIELD_MODULUS)
        P = multiply(G2, k)
        avm_bytes = _g2_uncompressed(P)
        got = ref.g2_compress(avm_bytes)
        z1, z2 = compress_G2(P)  # (X.c1 | flags, X.c0) -- see compress_G2's docstring
        want = z1.to_bytes(48, "big") + z2.to_bytes(48, "big")
        assert got == want


# ---------------------------------------------------------------------------
# T4 -- sign-bit boundary, offline: known-answer generator compression, and
# Y just above/below HALF_P.
# ---------------------------------------------------------------------------


def test_t4_generator_compresses_to_known_answer():
    # design doc §3: "the published compressed generator 0x97f1d3a7..."
    g1_avm = _g1_uncompressed(G1)
    compressed = ref.g1_compress(g1_avm)
    assert compressed[:4].hex() == "97f1d3a7"


def test_t4_sign_bit_p_and_neg_p_pairs():
    rng = random.Random(3)
    for _ in range(20):
        k = rng.randrange(1, ref.FIELD_MODULUS)
        P = multiply(G1, k)
        Pneg = neg(P)
        cp = ref.g1_compress(_g1_uncompressed(P))
        cn = ref.g1_compress(_g1_uncompressed(Pneg))
        # exactly one of P, -P has Y > HALF_P (they can't be equal unless
        # Y == 0, impossible for BLS12-381's odd-order-ish field here)
        assert (cp[0] & 0x20) != (cn[0] & 0x20)
        # X byte (top 3 bits masked by flags) must match between the two,
        # since P and -P share X.
        assert (cp[0] & 0x1F) == (cn[0] & 0x1F)
        assert cp[1:] == cn[1:]


def test_t4_y_exactly_half_p_boundary():
    # Construct a case at the boundary is impractical without solving for a
    # specific X; instead assert the comparison rule itself: HALF_P + 1 sets
    # the flag, HALF_P does not (per the doc's "sign flag set iff Y > HALF_P").
    x_bytes = (1).to_bytes(48, "big")
    below = x_bytes + ref.HALF_P.to_bytes(48, "big")
    above = x_bytes + (ref.HALF_P + 1).to_bytes(48, "big")
    assert ref.g1_compress(below)[0] & 0x20 == 0
    assert ref.g1_compress(above)[0] & 0x20 == 0x20


# ---------------------------------------------------------------------------
# T8 -- negation / infinity, offline.
# ---------------------------------------------------------------------------


def test_t8_g1_negate_involution():
    rng = random.Random(4)
    for _ in range(20):
        k = rng.randrange(1, ref.FIELD_MODULUS)
        P = _g1_uncompressed(multiply(G1, k))
        assert ref.g1_negate(ref.g1_negate(P)) == P


def test_t8_g2_negate_involution():
    rng = random.Random(5)
    for _ in range(20):
        k = rng.randrange(1, ref.FIELD_MODULUS)
        P = _g2_uncompressed(multiply(G2, k))
        assert ref.g2_negate(ref.g2_negate(P)) == P


def test_t8_negate_infinity_is_infinity():
    assert ref.g1_negate(ref.G1_INFINITY) == ref.G1_INFINITY
    assert ref.g2_negate(ref.G2_INFINITY) == ref.G2_INFINITY


def test_t8_compress_infinity_matches_py_ecc():
    from py_ecc.bls.point_compression import compress_G1
    from py_ecc.optimized_bls12_381 import Z1

    assert ref.g1_compress(ref.G1_INFINITY) == ref.G1_COMPRESSED_INFINITY
    assert compress_G1(Z1).to_bytes(48, "big") == ref.G1_COMPRESSED_INFINITY


def test_t8_pad_fp_roundtrip():
    assert ref.pad_fp(b"\x01") == b"\x00" * 47 + b"\x01"
    assert ref.pad_fp(b"") == b"\x00" * 48
    full = b"\xff" * 48
    assert ref.pad_fp(full) == full


# ---------------------------------------------------------------------------
# Live tier: T1/T4/T8 re-run against the compiled contract; T2 (limb-order
# regression, mandatory); T3 (validity: subgroup-valid ok, off-curve
# rejected, cofactor-subgroup point rejected).
# ---------------------------------------------------------------------------


def test_t1_live_g1_compress_matches_reference(live_harness):
    P = multiply(G1, 12345)
    avm_bytes = _g1_uncompressed(P)
    r = live_harness.call("g1_compress", avm_bytes)
    assert r.ok, r.failure
    got = r.return_value[2:]  # strip ABI byte[] 2-byte length prefix
    assert got == ref.g1_compress(avm_bytes)


def test_t2_live_limb_order_regression(live_harness):
    """Mandatory regression (§3.3, §11 T2): a0a1-ordered (AVM/c0-first) G2
    satisfies the pairing identity; a1a0-ordered (ZCash/c1-first) FAILS.
    Locks the limb order so a future refactor cannot silently adopt the
    wrong (reference-library) order.
    """
    P, Q = G1, G2
    negP = neg(P)

    def g2_avm_order(pt, swap: bool) -> bytes:
        x, y = pt[0], pt[1]
        xc, yc = x.coeffs, y.coeffs
        if swap:
            return (
                int(xc[1]).to_bytes(48, "big")
                + int(xc[0]).to_bytes(48, "big")
                + int(yc[1]).to_bytes(48, "big")
                + int(yc[0]).to_bytes(48, "big")
            )
        return _g2_uncompressed(pt)

    a0 = _g1_uncompressed(P)
    a1 = _g1_uncompressed(negP)
    b0_correct = g2_avm_order(Q, swap=False)
    b1_correct = g2_avm_order(Q, swap=False)
    r_correct = live_harness.call("pairing_check_2", a0, b0_correct, a1, b1_correct)
    assert r_correct.ok, r_correct.failure
    assert _bool_from_abi(r_correct.return_value) is True

    b0_wrong = g2_avm_order(Q, swap=True)
    b1_wrong = g2_avm_order(Q, swap=True)
    r_wrong = live_harness.call("pairing_check_2", a0, b0_wrong, a1, b1_wrong)
    # The wrongly-ordered bytes should either error outright or return False;
    # either way it must NOT report the pairing identity as true.
    wrong_passed = r_wrong.ok and _bool_from_abi(r_wrong.return_value)
    assert not wrong_passed, "a1a0 (ZCash/reference-library) limb order must NOT verify"


def test_t3_live_subgroup_valid_point_accepted(live_harness):
    P = multiply(G1, 999)
    r = live_harness.call("g1_validate_wellformed_only", _g1_uncompressed(P))
    assert r.ok, r.failure


def test_t3_live_off_curve_point_rejected(live_harness):
    garbage = b"\x01" + b"\x00" * 95
    r = live_harness.call("g1_validate_wellformed_only", garbage)
    assert not r.ok


def _cofactor_subgroup_g1_point(seed: int):
    """Deterministically constructs a point on the BLS12-381 G1 curve that
    is NOT in the prime-order-r subgroup (§7.4: "the G1 cofactor is 126
    bits and are exactly what the subgroup check exists to reject").

    Method: sample a random on-curve point P_full over the full group
    (order H1*r, generically); S = r * P_full then has order dividing the
    126-bit cofactor H1, and since gcd(H1, r) == 1 for BLS12-381, the only
    point with order dividing both H1 and r is the identity -- so any
    nonzero S is on-curve but outside the prime-order subgroup.
    """
    from py_ecc.bls12_381 import FQ, Z1, is_on_curve, multiply
    from py_ecc.bls12_381 import b as curve_b
    from py_ecc.bls12_381 import field_modulus as p
    from py_ecc.bls12_381 import curve_order as r

    h1 = 0x396C8C005555E1568C00AAAB0000AAAB  # standard BLS12-381 G1 cofactor
    rng = random.Random(seed)
    for _ in range(1000):
        x = FQ(rng.randrange(1, p))
        rhs = x**3 + FQ(curve_b)
        if pow(int(rhs), (p - 1) // 2, p) != 1:
            continue  # not a quadratic residue -- no on-curve Y for this X
        y = FQ(pow(int(rhs), (p + 1) // 4, p))
        if y * y != rhs:
            continue
        p_full = (x, y)
        assert is_on_curve(p_full, curve_b)
        s = multiply(p_full, r)
        if s is None or s == Z1:
            continue
        assert is_on_curve(s, curve_b)
        assert multiply(s, h1) in (None, Z1)  # order divides h1, confirming cofactor-torsion
        return s
    raise AssertionError("failed to construct a cofactor-subgroup point in 1000 tries")


def test_t3_live_cofactor_subgroup_point_rejected(live_harness):
    """G1's cofactor is 126 bits (§7.4): a point on the curve but NOT in the
    prime-order-r subgroup must be rejected by `g1_validate_wellformed_only`
    even though it IS a genuine on-curve point (unlike the garbage-bytes
    case in `test_t3_live_off_curve_point_rejected`, which fails the curve
    equation itself)."""
    s = _cofactor_subgroup_g1_point(seed=7)
    r = live_harness.call("g1_validate_wellformed_only", _g1_uncompressed(s))
    assert not r.ok, "a cofactor-subgroup (non-prime-order) point must be rejected"
