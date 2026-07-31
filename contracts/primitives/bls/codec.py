"""BLS12-381 byte-format codec: compress/uncompress-adjacent primitives, point
validity, negation, and the compressed<->uncompressed trust boundary.

Design doc: docs/design/001-bls-primitives.md, §3-§4, §5.1, §7, §15.

Implementation note on module "constants" (see design doc §5, implementer
instruction to verify real stub names before writing code): Puya does not
support module-scope assignment of `algopy`-typed values (`Bytes(...)`,
`BigUInt(...)`) -- only plain Python literals (`int`, `str`, `bytes`) survive
as module-level "unsupported statement type at module level" is raised
otherwise (verified empirically against puyapy 5.9.0). So every `: BigUInt` /
`: Bytes` constant sketched in the design doc's §5.1 interface is implemented
here as a plain-Python literal plus a zero-argument `@subroutine` accessor
that constructs the typed value on demand. Callers within this package use the
accessor functions (`field_modulus()`, `half_p()`, etc.), never the raw
literals directly.
"""

from algopy import BigUInt, Bytes, UInt64, subroutine, op
from algopy.op import EC, EllipticCurve

# ---------------------------------------------------------------------------
# Sizes (§3.1 boundary table)
# ---------------------------------------------------------------------------
FP_BYTES = 48
G1_BYTES = 96
G2_BYTES = 192
SCALAR_BYTES = 32
G1_COMPRESSED_BYTES = 48
G2_COMPRESSED_BYTES = 96

# ---------------------------------------------------------------------------
# Curve constants (§3), as plain-Python literals -- see module docstring.
# ---------------------------------------------------------------------------

# p, the BLS12-381 base field modulus (381 bits).
FIELD_MODULUS_INT = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB

# HALF_P = (p-1)/2. Used as the compressed-encoding sign-of-Y threshold (§3.2).
HALF_P_INT = 0x0D0088F51CBFF34D258DD3DB21A5D66BB23BA5C279C2895FB39869507B587B120F55FFFF58A9FFFFDCFF7FFFFFFFD555

# -G1 generator, 96 B AVM-uncompressed (X || p-Y). §3, used by pairing.py so
# that `verify_aggregate_signature` never needs a runtime negation of the
# relayer-supplied agg_pubkey/signature.
NEG_G1_GENERATOR_HEX = (
    "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac5"
    "86c55e83ff97a1aeffb3af00adb22c6bb"
    "114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac423"
    "64e6f38ba0ecb751bad54dcd6b939c2ca"
)

G1_INFINITY_HEX = "00" * G1_BYTES
G2_INFINITY_HEX = "00" * G2_BYTES
G1_COMPRESSED_INFINITY_HEX = "c0" + "00" * (G1_COMPRESSED_BYTES - 1)
G2_COMPRESSED_INFINITY_HEX = "c0" + "00" * (G2_COMPRESSED_BYTES - 1)

INFINITY_FLAG_BYTE = 0x40
COMPRESSION_FLAG_BYTE = 0x80
SIGN_FLAG_BYTE = 0x20


@subroutine
def field_modulus() -> BigUInt:
    """p, the BLS12-381 base field modulus."""
    return BigUInt(FIELD_MODULUS_INT)


@subroutine
def half_p() -> BigUInt:
    """(p-1)/2 -- the compressed-encoding sign-of-Y threshold (§3.2)."""
    return BigUInt(HALF_P_INT)


@subroutine
def neg_g1_generator() -> Bytes:
    """-G1, 96 B AVM-uncompressed. Compile-time constant; see §3, §5.4 note."""
    return Bytes.from_hex(NEG_G1_GENERATOR_HEX)


@subroutine
def g1_infinity() -> Bytes:
    """G1 point at infinity, AVM-uncompressed encoding: 96 zero bytes."""
    return Bytes.from_hex(G1_INFINITY_HEX)


@subroutine
def g2_infinity() -> Bytes:
    """G2 point at infinity, AVM-uncompressed encoding: 192 zero bytes."""
    return Bytes.from_hex(G2_INFINITY_HEX)


@subroutine
def g1_compressed_infinity() -> Bytes:
    """G1 point at infinity, Ethereum/ZCash compressed encoding: 0xc0 || 47
    zero bytes (§3.2)."""
    return Bytes.from_hex(G1_COMPRESSED_INFINITY_HEX)


@subroutine
def g2_compressed_infinity() -> Bytes:
    """G2 point at infinity, Ethereum/ZCash compressed encoding: 0xc0 || 95
    zero bytes (§3.2)."""
    return Bytes.from_hex(G2_COMPRESSED_INFINITY_HEX)


@subroutine
def pad_fp(b: Bytes) -> Bytes:
    """Left-pad to exactly 48 bytes.

    MANDATORY after any BigUInt/byte-math round-trip (implementer checklist
    §15 item 1): AVM byte-math results are minimal-width (leading zeros
    stripped), so `p - y` may be < 48 bytes and would corrupt a concatenated
    point encoding if used unpadded.
    """
    length = b.length
    assert length <= FP_BYTES
    if length == FP_BYTES:
        return b
    return op.bzero(UInt64(FP_BYTES) - length) + b


@subroutine
def g1_is_infinity(p: Bytes) -> bool:
    """True iff `p` (96 B AVM-uncompressed G1) is the point at infinity."""
    assert p.length == G1_BYTES
    return p == g1_infinity()


@subroutine
def g2_is_infinity(p: Bytes) -> bool:
    """True iff `p` (192 B AVM-uncompressed G2) is the point at infinity."""
    assert p.length == G2_BYTES
    return p == g2_infinity()


@subroutine
def g1_negate(p: Bytes) -> Bytes:
    """96 B -> 96 B. X || pad_fp(p - Y). Infinity maps to itself (§7.1: `p-0`
    is not a valid coordinate, so infinity must be special-cased)."""
    assert p.length == G1_BYTES
    if g1_is_infinity(p):
        return p
    x = p[:FP_BYTES]
    y = p[FP_BYTES:G1_BYTES]
    neg_y = pad_fp((field_modulus() - BigUInt.from_bytes(y)).bytes)
    return x + neg_y


@subroutine
def g2_negate(p: Bytes) -> Bytes:
    """192 B -> 192 B. Negates both Y limbs (Y.c0, Y.c1) independently, in
    AVM order (X.c0 || X.c1 || Y.c0 || Y.c1). Infinity -> itself."""
    assert p.length == G2_BYTES
    if g2_is_infinity(p):
        return p
    x = p[: 2 * FP_BYTES]
    y_c0 = p[2 * FP_BYTES : 3 * FP_BYTES]
    y_c1 = p[3 * FP_BYTES : 4 * FP_BYTES]
    neg_y_c0 = pad_fp((field_modulus() - BigUInt.from_bytes(y_c0)).bytes)
    neg_y_c1 = pad_fp((field_modulus() - BigUInt.from_bytes(y_c1)).bytes)
    return x + neg_y_c0 + neg_y_c1


@subroutine
def g1_compress(p: Bytes) -> Bytes:
    """AVM uncompressed 96 B -> Ethereum/ZCash compressed 48 B (§3.2).

    Does NOT validate the point; only `*_bind` / `*_validate_wellformed_only`
    do that (§5.1 note -- compression alone is not a validity check).
    """
    assert p.length == G1_BYTES
    if g1_is_infinity(p):
        return g1_compressed_infinity()
    x = p[:FP_BYTES]
    y = p[FP_BYTES:G1_BYTES]
    y_val = BigUInt.from_bytes(y)
    sign_flag = UInt64(SIGN_FLAG_BYTE) if y_val > half_p() else UInt64(0)
    flag_byte = op.getbyte(x, 0) | UInt64(COMPRESSION_FLAG_BYTE) | sign_flag
    return op.setbyte(x, 0, flag_byte)


@subroutine
def g2_compress(p: Bytes) -> Bytes:
    """AVM uncompressed 192 B -> Ethereum/ZCash compressed 96 B.

    Performs the c0/c1 limb swap -- see the trap in design doc §3.3: the
    AVM's G2 limb order (c0 first) is the REVERSE of Ethereum/ZCash's (c1
    first). Copying a reference library's G2 serializer produces silently
    wrong points here; this function must emit `X.c1 || X.c0`, not
    `X.c0 || X.c1`. Pinned by test T2 (mandatory regression, §11).
    """
    assert p.length == G2_BYTES
    if g2_is_infinity(p):
        return g2_compressed_infinity()
    x_c0 = p[0 * FP_BYTES : 1 * FP_BYTES]
    x_c1 = p[1 * FP_BYTES : 2 * FP_BYTES]
    y_c0 = p[2 * FP_BYTES : 3 * FP_BYTES]
    y_c1 = p[3 * FP_BYTES : 4 * FP_BYTES]
    y_c1_val = BigUInt.from_bytes(y_c1)
    y_c0_val = BigUInt.from_bytes(y_c0)
    # Fp2 elements compared lexicographically as (c1, c0) -- §3.2.
    sign_is_set = (y_c1_val > half_p()) or (
        y_c1_val == BigUInt(0) and y_c0_val > half_p()
    )
    sign_flag = UInt64(SIGN_FLAG_BYTE) if sign_is_set else UInt64(0)
    flag_byte = op.getbyte(x_c1, 0) | UInt64(COMPRESSION_FLAG_BYTE) | sign_flag
    x_c1_flagged = op.setbyte(x_c1, 0, flag_byte)
    # THE LIMB SWAP: Ethereum/ZCash wire order is c1 first, then c0 -- the
    # reverse of the AVM's internal c0-first order used above when slicing.
    return x_c1_flagged + x_c0


@subroutine
def g1_validate_wellformed_only(p: Bytes) -> None:
    """Well-formedness ONLY. NOT an authenticity check.

    `ec_subgroup_check` decides one predicate: is `p` a point of the curve
    lying in the prime-order-r subgroup? It says nothing about *which* point.
    A relayer can generate its own keypair, submit the public key here, and
    it will pass -- see design doc 001 §4.4 for the full forged-committee
    attack this does NOT catch. Use `g1_bind` instead whenever the caller
    needs to know a point is a *specific*, previously-committed key. This
    name is deliberately not `g1_validate` (§4.7 / implementer checklist
    item 4) so no caller mistakes this for an authenticity check.
    """
    assert p.length == G1_BYTES
    assert EllipticCurve.subgroup_check(EC.BLS12_381g1, p)


@subroutine
def g2_validate_wellformed_only(p: Bytes) -> None:
    """Well-formedness ONLY. NOT an authenticity check. See
    `g1_validate_wellformed_only` and design doc 001 §4.4 / §4.7.
    """
    assert p.length == G2_BYTES
    assert EllipticCurve.subgroup_check(EC.BLS12_381g2, p)


@subroutine
def g1_bind(uncompressed: Bytes, committed_compressed: Bytes) -> None:
    """THE trust boundary (§4.5) -- the security-critical function of this
    module.

    Admits `uncompressed` (96 B, relayer-supplied) as the genuine point
    behind `committed_compressed` (48 B). Rejects infinity, non-subgroup /
    off-curve input, and any point whose compressed form differs from the
    commitment.

    CALLER OBLIGATION: `committed_compressed` MUST already be verified
    against a trusted SSZ root (M3). Passing relayer-supplied compressed
    bytes makes this binding vacuous -- the caller, not this function, is
    responsible for that invariant. Budget: ~1900 (§4.5).
    """
    assert not g1_is_infinity(uncompressed)
    assert EllipticCurve.subgroup_check(EC.BLS12_381g1, uncompressed)
    assert g1_compress(uncompressed) == committed_compressed


@subroutine
def g2_bind(uncompressed: Bytes, committed_compressed: Bytes) -> None:
    """G2 analogue of `g1_bind`. The sync-committee update has no committed
    G2 value today (§4.6 -- the signature is fresh data, not committed), but
    this is specified for future forks that may commit a G2 value.
    """
    assert not g2_is_infinity(uncompressed)
    assert EllipticCurve.subgroup_check(EC.BLS12_381g2, uncompressed)
    assert g2_compress(uncompressed) == committed_compressed
