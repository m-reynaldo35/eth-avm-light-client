"""G1/G2 (de)compression in AVM limb order (design doc §5.3, R-5).

Promoted out of `tests/bls/test_codec.py`'s `_g1_uncompressed`/
`_g2_uncompressed` (proven against M1's own T1/T8, `tests/bls/test_pairing.
py`'s live pairing checks) rather than re-derived -- 009 §2.3 names this
exact import (`from tests.bls.test_codec import _g1_uncompressed,
_g2_uncompressed` inside a DEPLOYED service module) as the concrete defect
this promotion fixes.

AVM G2 limb order is `X.c0 || X.c1 || Y.c0 || Y.c1` -- the REVERSE of every
reference serializer (ZCash/IETF wire order is c1-first). This is 004
§12.4 item 2 and the single most-cited "trap" in this codebase's BLS
handling; getting it backwards produces a point that decompresses to a
value on the curve but the WRONG one, which is exactly the kind of bug a
naive byte-for-byte port would introduce silently.
"""
from __future__ import annotations

from py_ecc.bls.point_compression import decompress_G1, decompress_G2

G1_UNCOMPRESSED_INFINITY = bytes(96)
G2_UNCOMPRESSED_INFINITY = bytes(192)


def _strip0x(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def _to_affine(point):
    """Accepts an affine 2-tuple or an optimized projective 3-tuple
    (py_ecc.optimized_bls12_381); returns affine (x, y) or None for
    infinity. Mirrors `tests/bls/test_codec.py::_to_affine` exactly."""
    if point is None:
        return None
    if len(point) == 2:
        return point
    from py_ecc.optimized_bls12_381 import is_inf, normalize

    if is_inf(point):
        return None
    return normalize(point)


def g1_uncompressed_avm(point) -> bytes:
    """py_ecc G1 point (affine or optimized-projective) -> 96-byte AVM
    uncompressed form (`x(48) || y(48)`, big-endian)."""
    affine = _to_affine(point)
    if affine is None:
        return G1_UNCOMPRESSED_INFINITY
    x, y = affine
    return int(x).to_bytes(48, "big") + int(y).to_bytes(48, "big")


def g2_uncompressed_avm(point) -> bytes:
    """py_ecc G2 point -> 192-byte AVM order: `X.c0 || X.c1 || Y.c0 || Y.c1`."""
    affine = _to_affine(point)
    if affine is None:
        return G2_UNCOMPRESSED_INFINITY
    x, y = affine
    xc, yc = x.coeffs, y.coeffs
    return (
        int(xc[0]).to_bytes(48, "big")
        + int(xc[1]).to_bytes(48, "big")
        + int(yc[0]).to_bytes(48, "big")
        + int(yc[1]).to_bytes(48, "big")
    )


def g1_compressed_to_avm(hex_compressed: str) -> tuple[bytes, bytes]:
    """48-byte compressed (ZCash/IETF) G1 hex -> `(compressed_48B,
    uncompressed_96B_AVM)`."""
    comp = _strip0x(hex_compressed)
    assert len(comp) == 48
    pt = decompress_G1(int.from_bytes(comp, "big"))
    uncompressed = g1_uncompressed_avm(pt)
    assert len(uncompressed) == 96
    return comp, uncompressed


def g2_compressed_to_avm(hex_compressed: str) -> bytes:
    """96-byte compressed G2 signature hex -> 192-byte AVM-uncompressed G2,
    the exact format M4's `submit_update(..., signature: Bytes192, ...)`
    argument expects."""
    sig = _strip0x(hex_compressed)
    assert len(sig) == 96
    z1 = int.from_bytes(sig[:48], "big")
    z2 = int.from_bytes(sig[48:], "big")
    pt = decompress_G2((z1, z2))
    out = g2_uncompressed_avm(pt)
    assert len(out) == 192
    return out
