"""RFC 9380 `hash_to_curve` for `BLS12381G2_XMD:SHA-256_SSWU_RO_`.

Design doc: docs/design/001-bls-primitives.md, §5.3, §8.

Normative boundary (implementer checklist §15 item 6, doc §1.2 / §8): this
module owns *how* -- RFC 9380 mechanics only. It hard-codes NO Ethereum
constant: no domain-separation tag, no fork version, no signing-root
construction. The DST is a runtime parameter supplied by the caller. Which
DST is the *correct* one for Ethereum sync-committee signatures
(`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`) is M4's responsibility,
validated against real consensus-spec test vectors -- M1's own tests (T10)
validate only against RFC 9380's own published vectors and DST.
"""

from algopy import BigUInt, Bytes, UInt64, subroutine, urange, op
from algopy.op import EC, EllipticCurve

from .codec import field_modulus, pad_fp

# SHA-256 block size (bytes) -- used for the Z_pad in expand_message_xmd
# (RFC 9380 §5.3.1).
SHA256_BLOCK_BYTES = 64
# SHA-256 digest size (bytes) -- RFC 9380's `b_in_bytes`.
SHA256_OUTPUT_BYTES = 32
# RFC 9380 caps ell (and therefore DST length in the counter byte) at 255.
MAX_DST_BYTES = 255
MAX_ELL = 255


@subroutine
def expand_message_xmd_sha256(msg: Bytes, dst: Bytes, out_len: UInt64) -> Bytes:
    """RFC 9380 §5.3.1. Asserts out_len <= 255*32 and len(dst) <= 255."""
    assert dst.length <= MAX_DST_BYTES
    assert out_len <= UInt64(MAX_ELL) * SHA256_OUTPUT_BYTES

    ell = (out_len + SHA256_OUTPUT_BYTES - 1) // SHA256_OUTPUT_BYTES
    assert ell >= 1
    assert ell <= MAX_ELL

    # DST_prime = DST || I2OSP(len(DST), 1)
    dst_len_byte = op.itob(dst.length)[7:8]
    dst_prime = dst + dst_len_byte

    # msg_prime = Z_pad || msg || I2OSP(out_len, 2) || I2OSP(0, 1) || DST_prime
    z_pad = op.bzero(SHA256_BLOCK_BYTES)
    l_i_b_str = op.itob(out_len)[6:8]  # 2-byte big-endian length
    zero_byte = op.bzero(UInt64(1))
    msg_prime = z_pad + msg + l_i_b_str + zero_byte + dst_prime

    b0 = op.sha256(msg_prime)

    one_byte = op.itob(UInt64(1))[7:8]
    b_prev = op.sha256(b0 + one_byte + dst_prime)
    uniform = b_prev

    for i in urange(2, ell + 1):
        i_byte = op.itob(i)[7:8]
        b_i = op.sha256((b0 ^ b_prev) + i_byte + dst_prime)
        uniform = uniform + b_i
        b_prev = b_i

    return uniform[:out_len]


@subroutine
def hash_to_g2(msg: Bytes, dst: Bytes) -> Bytes:
    """RFC 9380 hash_to_curve, suite BLS12381G2_XMD:SHA-256_SSWU_RO_.

    Returns a 192 B AVM-order G2 point in the prime-order subgroup. The DST
    is a PARAMETER -- picking the right one is M4's job (§8).

    Correctness relies on two facts recorded in §8: (1) `b%` with a 64-byte
    dividend and 48-byte modulus is legal AVM byte-math (within the
    documented operand cap) even though general modular arithmetic is not;
    (2) cofactor clearing commutes with addition, so if `ec_map_to` already
    clears the G2 cofactor (probe P2 must confirm this empirically -- it is
    NOT assumed here as fact, only as the doc's working hypothesis),
    `map_to(u0) + map_to(u1)` equals the RFC's
    `clear_cofactor(map_to(u0) + map_to(u1))`.
    """
    uniform = expand_message_xmd_sha256(msg, dst, UInt64(256))

    modulus = field_modulus()
    e0 = BigUInt.from_bytes(uniform[0 * 64 : 1 * 64]) % modulus
    e1 = BigUInt.from_bytes(uniform[1 * 64 : 2 * 64]) % modulus
    e2 = BigUInt.from_bytes(uniform[2 * 64 : 3 * 64]) % modulus
    e3 = BigUInt.from_bytes(uniform[3 * 64 : 4 * 64]) % modulus

    # Fp2 = c0 || c1, AVM order (§3.3 -- NOT the Ethereum/ZCash c1-first wire
    # order; this is the ec_map_to G2 *input* encoding, which follows the
    # same AVM convention as ec_add's G2 operand).
    u0 = pad_fp(e0.bytes) + pad_fp(e1.bytes)
    u1 = pad_fp(e2.bytes) + pad_fp(e3.bytes)

    q0 = EllipticCurve.map_to(EC.BLS12_381g2, u0)
    q1 = EllipticCurve.map_to(EC.BLS12_381g2, u1)
    return EllipticCurve.add(EC.BLS12_381g2, q0, q1)
