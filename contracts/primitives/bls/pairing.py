"""BLS12-381 pairing assembly.

Design doc: docs/design/001-bls-primitives.md, §5.4, §7.1.
"""

from algopy import Bytes, subroutine
from algopy.op import EC, EllipticCurve

from .codec import (
    G1_BYTES,
    G2_BYTES,
    g1_is_infinity,
    g2_is_infinity,
    neg_g1_generator,
)


@subroutine
def pairing_check_2(a0: Bytes, b0: Bytes, a1: Bytes, b1: Bytes) -> bool:
    """`ec_pairing_check(BLS12_381g1, a0||a1, b0||b1)`:
    true iff e(a0,b0) . e(a1,b1) == 1. a* are 96 B G1, b* are 192 B G2.

    Pairs are index-aligned (pinned by probe P5, §12). Budget ~53,000.
    """
    assert a0.length == G1_BYTES
    assert a1.length == G1_BYTES
    assert b0.length == G2_BYTES
    assert b1.length == G2_BYTES
    a = a0 + a1
    b = b0 + b1
    return EllipticCurve.pairing_check(EC.BLS12_381g1, a, b)


@subroutine
def verify_aggregate_signature(
    agg_pubkey: Bytes, msg_point: Bytes, signature: Bytes
) -> bool:
    """`fast_aggregate_verify` core:
    e(agg_pubkey, msg_point) == e(G1, signature), checked as
    e(agg_pubkey, msg_point) . e(-G1, signature) == 1.

    Asserts none of the three operands is infinity (§7.1: with
    `agg_pubkey = O`, the pairing identity degenerates to
    `e(-G1, S) == 1`, which holds iff `S == O` -- an infinity/infinity pair
    would otherwise verify against *any* message) and that the signature is
    subgroup-valid. Returns the pairing result so the caller can choose
    whether to assert.

    Does NOT check that `msg_point` is the hash of the right message under
    the right DST -- that is M4's (§8). Does NOT bind `agg_pubkey` to any
    committed committee -- that is `g1_bind`'s job, done by the caller
    before this is invoked, once per committee (§4.5).

    `-G1` is the compile-time constant `neg_g1_generator()` (§3), so the
    negation is free; there is never a reason to negate `agg_pubkey` or the
    signature at runtime here.
    """
    assert not g1_is_infinity(agg_pubkey)
    assert not g2_is_infinity(msg_point)
    assert not g2_is_infinity(signature)
    assert EllipticCurve.subgroup_check(EC.BLS12_381g2, signature)
    return pairing_check_2(agg_pubkey, msg_point, neg_g1_generator(), signature)
