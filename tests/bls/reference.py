"""Pure-Python mirror of contracts/primitives/bls/codec.py + aggregate.py +
hash_to_curve.py, checked against py_ecc.

This is NOT the on-chain implementation -- it is a bit-for-bit re-expression
of the same algorithm in plain Python/int arithmetic, used so the offline CI
tier (no algod) can pin the exact byte-level behaviour (§11 of
docs/design/001-bls-primitives.md) against py_ecc as the reference oracle,
before ever touching real `ec_*` opcodes on localnet.

Keep this file's logic in lockstep with the Puya source: any change to
codec.py's compression/negation/padding rules must be mirrored here, or the
offline tests stop meaning anything.
"""

from __future__ import annotations

import hashlib

from py_ecc.bls12_381 import field_modulus as PY_ECC_FIELD_MODULUS

FP_BYTES = 48
G1_BYTES = 96
G2_BYTES = 192
SCALAR_BYTES = 32
G1_COMPRESSED_BYTES = 48
G2_COMPRESSED_BYTES = 96

FIELD_MODULUS = PY_ECC_FIELD_MODULUS
# Sanity: this must equal the literal p pinned in codec.py.
FIELD_MODULUS_INT = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
assert FIELD_MODULUS == FIELD_MODULUS_INT, "reference.py field modulus drifted from py_ecc"

HALF_P = (FIELD_MODULUS - 1) // 2
HALF_P_INT = 0x0D0088F51CBFF34D258DD3DB21A5D66BB23BA5C279C2895FB39869507B587B120F55FFFF58A9FFFFDCFF7FFFFFFFD555
assert HALF_P == HALF_P_INT, "reference.py HALF_P drifted from codec.py"

NEG_G1_GENERATOR_HEX = (
    "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac5"
    "86c55e83ff97a1aeffb3af00adb22c6bb"
    "114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac423"
    "64e6f38ba0ecb751bad54dcd6b939c2ca"
)

G1_INFINITY = bytes(G1_BYTES)
G2_INFINITY = bytes(G2_BYTES)
G1_COMPRESSED_INFINITY = bytes([0xC0]) + bytes(G1_COMPRESSED_BYTES - 1)
G2_COMPRESSED_INFINITY = bytes([0xC0]) + bytes(G2_COMPRESSED_BYTES - 1)

INFINITY_FLAG_BYTE = 0x40
COMPRESSION_FLAG_BYTE = 0x80
SIGN_FLAG_BYTE = 0x20


def pad_fp(b: bytes) -> bytes:
    assert len(b) <= FP_BYTES
    if len(b) == FP_BYTES:
        return b
    return b"\x00" * (FP_BYTES - len(b)) + b


def g1_is_infinity(p: bytes) -> bool:
    assert len(p) == G1_BYTES
    return p == G1_INFINITY


def g2_is_infinity(p: bytes) -> bool:
    assert len(p) == G2_BYTES
    return p == G2_INFINITY


def g1_negate(p: bytes) -> bytes:
    assert len(p) == G1_BYTES
    if g1_is_infinity(p):
        return p
    x = p[:FP_BYTES]
    y = int.from_bytes(p[FP_BYTES:G1_BYTES], "big")
    neg_y = pad_fp(_int_to_min_bytes((FIELD_MODULUS - y) % FIELD_MODULUS))
    return x + neg_y


def g2_negate(p: bytes) -> bytes:
    assert len(p) == G2_BYTES
    if g2_is_infinity(p):
        return p
    x = p[: 2 * FP_BYTES]
    y_c0 = int.from_bytes(p[2 * FP_BYTES : 3 * FP_BYTES], "big")
    y_c1 = int.from_bytes(p[3 * FP_BYTES : 4 * FP_BYTES], "big")
    neg_y_c0 = pad_fp(_int_to_min_bytes((FIELD_MODULUS - y_c0) % FIELD_MODULUS))
    neg_y_c1 = pad_fp(_int_to_min_bytes((FIELD_MODULUS - y_c1) % FIELD_MODULUS))
    return x + neg_y_c0 + neg_y_c1


def _int_to_min_bytes(v: int) -> bytes:
    """Mirrors AVM byte-math minimal-width output (leading zeros stripped)."""
    if v == 0:
        return b""
    length = (v.bit_length() + 7) // 8
    return v.to_bytes(length, "big")


def g1_compress(p: bytes) -> bytes:
    assert len(p) == G1_BYTES
    if g1_is_infinity(p):
        return G1_COMPRESSED_INFINITY
    x = bytearray(p[:FP_BYTES])
    y = int.from_bytes(p[FP_BYTES:G1_BYTES], "big")
    sign_flag = SIGN_FLAG_BYTE if y > HALF_P else 0
    x[0] = x[0] | COMPRESSION_FLAG_BYTE | sign_flag
    return bytes(x)


def g2_compress(p: bytes) -> bytes:
    assert len(p) == G2_BYTES
    if g2_is_infinity(p):
        return G2_COMPRESSED_INFINITY
    x_c0 = p[0 * FP_BYTES : 1 * FP_BYTES]
    x_c1 = bytearray(p[1 * FP_BYTES : 2 * FP_BYTES])
    y_c0 = int.from_bytes(p[2 * FP_BYTES : 3 * FP_BYTES], "big")
    y_c1 = int.from_bytes(p[3 * FP_BYTES : 4 * FP_BYTES], "big")
    sign_is_set = (y_c1 > HALF_P) or (y_c1 == 0 and y_c0 > HALF_P)
    sign_flag = SIGN_FLAG_BYTE if sign_is_set else 0
    x_c1[0] = x_c1[0] | COMPRESSION_FLAG_BYTE | sign_flag
    # THE LIMB SWAP (§3.3): c1 first, then c0.
    return bytes(x_c1) + x_c0


def g1_sum(points: list[bytes]) -> bytes:
    """Reference-level `g1_sum_blob`: pure summation (no ec_add opcode
    involved -- delegates to py_ecc's `add` on decoded affine points)."""
    # NOTE: py_ecc's point arithmetic here uses the *optimized* (projective
    # X,Y,Z) representation (py_ecc.optimized_bls12_381), not the plain
    # affine py_ecc.bls12_381 module -- see test_codec.py's module docstring
    # for the same distinction.
    from py_ecc.optimized_bls12_381 import Z1
    from py_ecc.optimized_bls12_381 import add as ecc_add

    if not points:
        return G1_INFINITY
    acc = _g1_from_avm(points[0])
    for p in points[1:]:
        acc = ecc_add(acc, _g1_from_avm(p))
    return _g1_to_avm(acc)


def _g1_from_avm(p: bytes):
    from py_ecc.fields import optimized_bls12_381_FQ as FQ
    from py_ecc.optimized_bls12_381 import Z1

    if p == G1_INFINITY:
        return Z1
    x = int.from_bytes(p[:FP_BYTES], "big")
    y = int.from_bytes(p[FP_BYTES:G1_BYTES], "big")
    return (FQ(x), FQ(y), FQ(1))


def _g1_to_avm(pt) -> bytes:
    from py_ecc.optimized_bls12_381 import is_inf, normalize

    if pt is None or is_inf(pt):
        return G1_INFINITY
    x, y = normalize(pt)
    return pad_fp(_int_to_min_bytes(int(x))) + pad_fp(_int_to_min_bytes(int(y)))


def expand_message_xmd_sha256(msg: bytes, dst: bytes, out_len: int) -> bytes:
    """RFC 9380 §5.3.1, mirrors expand_message_xmd_sha256 in hash_to_curve.py."""
    assert len(dst) <= 255
    b_in_bytes = hashlib.sha256().digest_size  # 32
    ell = -(-out_len // b_in_bytes)  # ceil
    assert ell <= 255
    dst_prime = dst + len(dst).to_bytes(1, "big")
    z_pad = b"\x00" * hashlib.sha256().block_size  # 64
    l_i_b_str = out_len.to_bytes(2, "big")
    msg_prime = z_pad + msg + l_i_b_str + b"\x00" + dst_prime
    b0 = hashlib.sha256(msg_prime).digest()
    b1 = hashlib.sha256(b0 + b"\x01" + dst_prime).digest()
    uniform = b1
    b_prev = b1
    for i in range(2, ell + 1):
        xored = bytes(a ^ c for a, c in zip(b0, b_prev))
        b_i = hashlib.sha256(xored + bytes([i]) + dst_prime).digest()
        uniform += b_i
        b_prev = b_i
    return uniform[:out_len]
