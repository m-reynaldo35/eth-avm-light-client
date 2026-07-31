"""M1 -- BLS12-381 point codec & MSM/pairing wrapper.

Compile-time subroutine library (design doc docs/design/001-bls-primitives.md
§5): plain Python modules imported into M4's contract, not a separately
deployed app. Re-exports the public surface described in the design doc's
§5 interface section.

M1 is the curve-level primitive layer: byte-format codec, point validity,
the compressed<->uncompressed trust boundary (`g1_bind`/`g2_bind`),
aggregation/MSM, `hash_to_g2`, and pairing assembly. It knows nothing about
Ethereum semantics -- no DST, no domain, no fork version is hard-coded
anywhere in this package (§1.2, §8, implementer checklist §15 item 6).
"""

from .codec import (
    FP_BYTES,
    G1_BYTES,
    G1_COMPRESSED_BYTES,
    G2_BYTES,
    G2_COMPRESSED_BYTES,
    SCALAR_BYTES,
    field_modulus,
    g1_bind,
    g1_compress,
    g1_compressed_infinity,
    g1_infinity,
    g1_is_infinity,
    g1_negate,
    g1_validate_wellformed_only,
    g2_bind,
    g2_compress,
    g2_compressed_infinity,
    g2_infinity,
    g2_is_infinity,
    g2_negate,
    g2_validate_wellformed_only,
    half_p,
    neg_g1_generator,
    pad_fp,
)
from .aggregate import (
    G1_MAX_POINTS_PER_ARG,
    G1_MAX_POINTS_PER_VALUE,
    G1_VALUE_CAP_BYTES,
    G2_MAX_POINTS_PER_VALUE,
    assert_g1_blob,
    chunk_count,
    g1_accumulate,
    g1_accumulate_negated,
    g1_msm_accumulate,
    g1_msm_chunk,
    g1_sum_blob,
)
from .hash_to_curve import expand_message_xmd_sha256, hash_to_g2
from .pairing import pairing_check_2, verify_aggregate_signature

__all__ = [
    # codec.py
    "FP_BYTES",
    "G1_BYTES",
    "G1_COMPRESSED_BYTES",
    "G2_BYTES",
    "G2_COMPRESSED_BYTES",
    "SCALAR_BYTES",
    "field_modulus",
    "half_p",
    "neg_g1_generator",
    "g1_infinity",
    "g2_infinity",
    "g1_compressed_infinity",
    "g2_compressed_infinity",
    "pad_fp",
    "g1_is_infinity",
    "g2_is_infinity",
    "g1_negate",
    "g2_negate",
    "g1_compress",
    "g2_compress",
    "g1_validate_wellformed_only",
    "g2_validate_wellformed_only",
    "g1_bind",
    "g2_bind",
    # aggregate.py
    "G1_MAX_POINTS_PER_VALUE",
    "G1_MAX_POINTS_PER_ARG",
    "G2_MAX_POINTS_PER_VALUE",
    "G1_VALUE_CAP_BYTES",
    "assert_g1_blob",
    "g1_sum_blob",
    "g1_accumulate",
    "g1_accumulate_negated",
    "g1_msm_chunk",
    "g1_msm_accumulate",
    "chunk_count",
    # hash_to_curve.py
    "expand_message_xmd_sha256",
    "hash_to_g2",
    # pairing.py
    "pairing_check_2",
    "verify_aggregate_signature",
]
