"""Test T11 -- end-to-end aggregate verify (docs/design/001-bls-primitives.md
§11). Live tier only: needs real `ec_pairing_check` / `ec_subgroup_check`.

Uses `py_ecc.bls.G2ProofOfPossession` to generate real keypairs and a real
BLS signature (per §11.1: py_ecc can generate real subgroup-valid points
and real signatures, so this covers full signature verification end to end
-- but NOT that we hashed the right bytes under the right DST; that is
M4's dependency on real consensus-spec vectors, restated here rather than
silently assumed covered).
"""

from __future__ import annotations

import pytest
from py_ecc.bls import G2ProofOfPossession as bls_pop
from py_ecc.bls12_381 import curve_order

from . import reference as ref
from .test_codec import _g1_uncompressed, _g2_uncompressed

DST = bls_pop.DST  # BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ -- used ONLY
# to generate a realistic signature via py_ecc; M1 itself never hard-codes
# this (§1.2, §8) -- the harness call below passes msg_point, not msg+dst.


def _keypair(seed: int):
    # BLS secret keys are scalars mod the curve order r, not the field
    # modulus p (a common and dangerous mix-up).
    sk = (seed * 0xDEADBEEF + 1) % curve_order
    if sk == 0:
        sk = 1
    pk = bls_pop.SkToPk(sk)
    return sk, pk


def _hash_to_g2_point_bytes(msg: bytes) -> bytes:
    """Compute the same msg_point py_ecc's Sign would hash to, so we can
    feed it directly to `verify_aggregate_signature` (which takes a point,
    not a message -- §8's M1/M4 split). `hash_to_G2` and `_g2_uncompressed`
    both operate on py_ecc's *optimized* (projective) point representation
    (see test_codec.py's module docstring) -- no manual normalize needed
    here, `_g2_uncompressed` does it internally.
    """
    from py_ecc.bls.hash_to_curve import hash_to_G2

    point = hash_to_G2(msg, DST, bls_pop.xmd_hash_function)
    return _g2_uncompressed(point)


def test_t11_live_valid_aggregate_signature_verifies(live_harness):
    msg = b"eth-avm-verifier T11 valid case"
    sks_pks = [_keypair(i) for i in range(1, 5)]
    sks = [sk for sk, _ in sks_pks]
    pks = [pk for _, pk in sks_pks]

    signatures = [bls_pop.Sign(sk, msg) for sk in sks]
    agg_sig = bls_pop.Aggregate(signatures)
    agg_pk = bls_pop._AggregatePKs(pks)

    assert bls_pop.FastAggregateVerify(pks, msg, agg_sig)  # sanity vs py_ecc itself

    agg_pk_point = _pk_bytes_to_g1_point(agg_pk)
    msg_point_bytes = _hash_to_g2_point_bytes(msg)
    sig_bytes = _sig_bytes_to_g2_avm(agg_sig)

    r = live_harness.call(
        "verify_aggregate_signature", agg_pk_point, msg_point_bytes, sig_bytes
    )
    assert r.ok, r.failure
    assert r.return_value[0] & 0x80 != 0


def _pk_bytes_to_g1_point(pk_bytes: bytes) -> bytes:
    from py_ecc.bls.point_compression import decompress_G1

    pt = decompress_G1(int.from_bytes(pk_bytes, "big"))
    return _g1_uncompressed(pt)


def _sig_bytes_to_g2_avm(sig_bytes: bytes) -> bytes:
    from py_ecc.bls.point_compression import decompress_G2

    z1 = int.from_bytes(sig_bytes[:48], "big")
    z2 = int.from_bytes(sig_bytes[48:], "big")
    pt = decompress_G2((z1, z2))
    return _g2_uncompressed(pt)


def _setup_valid_case(msg: bytes = b"eth-avm-verifier T11 base case"):
    sks_pks = [_keypair(i) for i in range(11, 15)]
    sks = [sk for sk, _ in sks_pks]
    pks = [pk for _, pk in sks_pks]
    signatures = [bls_pop.Sign(sk, msg) for sk in sks]
    agg_sig = bls_pop.Aggregate(signatures)
    agg_pk = bls_pop._AggregatePKs(pks)
    return msg, sks, pks, agg_sig, agg_pk


def test_t11_live_wrong_message_rejected(live_harness):
    msg, sks, pks, agg_sig, agg_pk = _setup_valid_case()
    agg_pk_point = _pk_bytes_to_g1_point(agg_pk)
    sig_bytes = _sig_bytes_to_g2_avm(agg_sig)
    wrong_msg_point = _hash_to_g2_point_bytes(b"a completely different message")

    r = live_harness.call(
        "verify_aggregate_signature", agg_pk_point, wrong_msg_point, sig_bytes
    )
    verified = r.ok and (r.return_value[0] & 0x80 != 0)
    assert not verified


def test_t11_live_substituted_pubkey_rejected(live_harness):
    msg, sks, pks, agg_sig, agg_pk = _setup_valid_case()
    _, other_pk = _keypair(999)
    tampered_pks = [other_pk] + pks[1:]
    tampered_agg_pk = bls_pop._AggregatePKs(tampered_pks)

    agg_pk_point = _pk_bytes_to_g1_point(tampered_agg_pk)
    msg_point_bytes = _hash_to_g2_point_bytes(msg)
    sig_bytes = _sig_bytes_to_g2_avm(agg_sig)

    r = live_harness.call(
        "verify_aggregate_signature", agg_pk_point, msg_point_bytes, sig_bytes
    )
    verified = r.ok and (r.return_value[0] & 0x80 != 0)
    assert not verified


def test_t11_live_signature_from_another_key_rejected(live_harness):
    msg, sks, pks, agg_sig, agg_pk = _setup_valid_case()
    other_sk, _ = _keypair(1000)
    wrong_sig = bls_pop.Sign(other_sk, msg)

    agg_pk_point = _pk_bytes_to_g1_point(agg_pk)
    msg_point_bytes = _hash_to_g2_point_bytes(msg)
    sig_bytes = _sig_bytes_to_g2_avm(wrong_sig)

    r = live_harness.call(
        "verify_aggregate_signature", agg_pk_point, msg_point_bytes, sig_bytes
    )
    verified = r.ok and (r.return_value[0] & 0x80 != 0)
    assert not verified


def test_t11_live_infinity_pubkey_rejected(live_harness):
    msg, sks, pks, agg_sig, agg_pk = _setup_valid_case()
    msg_point_bytes = _hash_to_g2_point_bytes(msg)
    sig_bytes = _sig_bytes_to_g2_avm(agg_sig)

    r = live_harness.call(
        "verify_aggregate_signature", ref.G1_INFINITY, msg_point_bytes, sig_bytes
    )
    assert not r.ok, "infinity agg_pubkey must be rejected (§7.1 fail-closed)"


def test_t11_live_infinity_signature_rejected(live_harness):
    msg, sks, pks, agg_sig, agg_pk = _setup_valid_case()
    agg_pk_point = _pk_bytes_to_g1_point(agg_pk)
    msg_point_bytes = _hash_to_g2_point_bytes(msg)

    r = live_harness.call(
        "verify_aggregate_signature", agg_pk_point, msg_point_bytes, ref.G2_INFINITY
    )
    assert not r.ok, "infinity signature must be rejected (§7.1 fail-closed)"
