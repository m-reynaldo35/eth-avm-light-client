"""ARC-4 harness app wrapping each M1 primitive as an ABI method.

Design doc: docs/design/001-bls-primitives.md, §5, §11, §12.

This app exists ONLY so the test suite can measure real
`app-budget-consumed` per primitive via `/v2/transactions/simulate`
(satisfying §12's measurement backlog) and exercise the primitives against
live `algod` for the tests in §11 that need `ec_*` opcodes
(`algopy_testing` does not emulate them). It is NOT part of M1's production
interface and is never deployed as part of the real bridge -- M4 imports the
`contracts/primitives/bls` subroutines directly into its own contract
(§5's "compile-time subroutine library" decision).

Methods that wrap a `-> None` primitive (`g1_bind`, `g2_bind`,
`g1_validate_wellformed_only`, `g2_validate_wellformed_only`) return
`arc4.Bool(True)` on success; the primitive's internal `assert` makes the
whole transaction fail on rejection, which is exactly the fail-closed
behaviour under test (§7.4: "never branch on an `ec_subgroup_check` bool,
always assert" -- these wrappers preserve that by not converting the assert
into a returned boolean it could be branched on downstream).

The `probe_*` methods below are not part of any primitive's public surface;
they exist to pin down the standalone opcode costs listed in §12's
measurement backlog (P1-P12) that are not already covered by measuring a
named primitive end to end.
"""

from algopy import ARC4Contract, BigUInt, UInt64, arc4, op
from algopy.op import EC, EllipticCurve

from . import codec
from .aggregate import (
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


class BlsHarness(ARC4Contract):
    """Thin ABI wrapper. One method per M1 primitive, plus probe_* methods
    for §12's raw-opcode measurement backlog. Not deployed in production."""

    # -- codec.py -----------------------------------------------------------

    @arc4.abimethod
    def pad_fp(self, b: arc4.DynamicBytes) -> arc4.DynamicBytes:
        return arc4.DynamicBytes(codec.pad_fp(b.native))

    @arc4.abimethod
    def g1_is_infinity(self, p: arc4.DynamicBytes) -> arc4.Bool:
        return arc4.Bool(codec.g1_is_infinity(p.native))

    @arc4.abimethod
    def g2_is_infinity(self, p: arc4.DynamicBytes) -> arc4.Bool:
        return arc4.Bool(codec.g2_is_infinity(p.native))

    @arc4.abimethod
    def g1_negate(self, p: arc4.DynamicBytes) -> arc4.DynamicBytes:
        return arc4.DynamicBytes(codec.g1_negate(p.native))

    @arc4.abimethod
    def g2_negate(self, p: arc4.DynamicBytes) -> arc4.DynamicBytes:
        return arc4.DynamicBytes(codec.g2_negate(p.native))

    @arc4.abimethod
    def g1_compress(self, p: arc4.DynamicBytes) -> arc4.DynamicBytes:
        return arc4.DynamicBytes(codec.g1_compress(p.native))

    @arc4.abimethod
    def g2_compress(self, p: arc4.DynamicBytes) -> arc4.DynamicBytes:
        return arc4.DynamicBytes(codec.g2_compress(p.native))

    @arc4.abimethod
    def g1_validate_wellformed_only(self, p: arc4.DynamicBytes) -> arc4.Bool:
        codec.g1_validate_wellformed_only(p.native)
        return arc4.Bool(True)

    @arc4.abimethod
    def g2_validate_wellformed_only(self, p: arc4.DynamicBytes) -> arc4.Bool:
        codec.g2_validate_wellformed_only(p.native)
        return arc4.Bool(True)

    @arc4.abimethod
    def g1_bind(
        self, uncompressed: arc4.DynamicBytes, committed_compressed: arc4.DynamicBytes
    ) -> arc4.Bool:
        codec.g1_bind(uncompressed.native, committed_compressed.native)
        return arc4.Bool(True)

    @arc4.abimethod
    def g2_bind(
        self, uncompressed: arc4.DynamicBytes, committed_compressed: arc4.DynamicBytes
    ) -> arc4.Bool:
        codec.g2_bind(uncompressed.native, committed_compressed.native)
        return arc4.Bool(True)

    # -- aggregate.py ---------------------------------------------------------

    @arc4.abimethod
    def assert_g1_blob(self, blob: arc4.DynamicBytes) -> arc4.UInt64:
        return arc4.UInt64(assert_g1_blob(blob.native))

    @arc4.abimethod
    def g1_sum_blob(self, blob: arc4.DynamicBytes) -> arc4.DynamicBytes:
        return arc4.DynamicBytes(g1_sum_blob(blob.native))

    # -- test-only box staging -------------------------------------------
    # §6.1/§7.3/§10.2: the AVM's 42-point/4032-byte VALUE cap and the ABI's
    # 2048-byte total-app-args-per-txn cap are two DIFFERENT limits. A
    # 42-point blob is a legal single AVM value but cannot be delivered as
    # app-call arguments in one txn (nor by splitting it across several
    # arguments of the SAME txn -- the 2048B cap is a total over the whole
    # txn, not per-argument). The real delivery mechanism for wide values
    # (§10.1/§10.2) is box storage, written across several txns in one
    # atomic group and then read back as a single value. These methods let
    # the test suite exercise primitives at the true 42/43-point boundary
    # via that same mechanism, without needing a full M4-style contract.

    @arc4.abimethod
    def box_stage_create(self, name: arc4.DynamicBytes, size: arc4.UInt64) -> arc4.Bool:
        created = op.Box.create(name.native, size.native)
        return arc4.Bool(created)

    @arc4.abimethod
    def box_stage_write(
        self, name: arc4.DynamicBytes, offset: arc4.UInt64, chunk: arc4.DynamicBytes
    ) -> arc4.Bool:
        op.Box.replace(name.native, offset.native, chunk.native)
        return arc4.Bool(True)

    @arc4.abimethod
    def box_stage_delete(self, name: arc4.DynamicBytes) -> arc4.Bool:
        existed = op.Box.delete(name.native)
        return arc4.Bool(existed)

    @arc4.abimethod
    def assert_g1_blob_from_box(
        self, name: arc4.DynamicBytes, length: arc4.UInt64
    ) -> arc4.UInt64:
        blob = op.Box.extract(name.native, UInt64(0), length.native)
        return arc4.UInt64(assert_g1_blob(blob))

    @arc4.abimethod
    def g1_sum_blob_from_box(
        self, name: arc4.DynamicBytes, length: arc4.UInt64
    ) -> arc4.DynamicBytes:
        blob = op.Box.extract(name.native, UInt64(0), length.native)
        return arc4.DynamicBytes(g1_sum_blob(blob))

    @arc4.abimethod
    def g1_accumulate(
        self, acc: arc4.DynamicBytes, blob: arc4.DynamicBytes
    ) -> arc4.DynamicBytes:
        return arc4.DynamicBytes(g1_accumulate(acc.native, blob.native))

    @arc4.abimethod
    def g1_accumulate_negated(
        self, acc: arc4.DynamicBytes, blob: arc4.DynamicBytes
    ) -> arc4.DynamicBytes:
        return arc4.DynamicBytes(g1_accumulate_negated(acc.native, blob.native))

    @arc4.abimethod
    def g1_msm_chunk(
        self, points: arc4.DynamicBytes, scalars: arc4.DynamicBytes
    ) -> arc4.DynamicBytes:
        return arc4.DynamicBytes(g1_msm_chunk(points.native, scalars.native))

    @arc4.abimethod
    def g1_msm_accumulate(
        self,
        acc: arc4.DynamicBytes,
        points: arc4.DynamicBytes,
        scalars: arc4.DynamicBytes,
    ) -> arc4.DynamicBytes:
        return arc4.DynamicBytes(
            g1_msm_accumulate(acc.native, points.native, scalars.native)
        )

    @arc4.abimethod
    def g1_msm_accumulate_points_from_box(
        self,
        acc: arc4.DynamicBytes,
        name: arc4.DynamicBytes,
        points_length: arc4.UInt64,
        scalars: arc4.DynamicBytes,
    ) -> arc4.DynamicBytes:
        """Test-only helper -- see the box-staging methods above: lets a
        full 42-point (4032 B) MSM chunk be exercised (points read from a
        pre-staged box) without exceeding the 2048 B total-app-args cap in
        a single ABI call."""
        points = op.Box.extract(name.native, UInt64(0), points_length.native)
        return arc4.DynamicBytes(
            g1_msm_accumulate(acc.native, points, scalars.native)
        )

    @arc4.abimethod
    def chunk_count(self, n: arc4.UInt64, chunk_size: arc4.UInt64) -> arc4.UInt64:
        return arc4.UInt64(chunk_count(n.native, chunk_size.native))

    # -- hash_to_curve.py -----------------------------------------------------

    @arc4.abimethod
    def expand_message_xmd_sha256(
        self, msg: arc4.DynamicBytes, dst: arc4.DynamicBytes, out_len: arc4.UInt64
    ) -> arc4.DynamicBytes:
        return arc4.DynamicBytes(
            expand_message_xmd_sha256(msg.native, dst.native, out_len.native)
        )

    @arc4.abimethod
    def hash_to_g2(
        self, msg: arc4.DynamicBytes, dst: arc4.DynamicBytes
    ) -> arc4.DynamicBytes:
        return arc4.DynamicBytes(hash_to_g2(msg.native, dst.native))

    # -- pairing.py -----------------------------------------------------------

    @arc4.abimethod
    def pairing_check_2(
        self,
        a0: arc4.DynamicBytes,
        b0: arc4.DynamicBytes,
        a1: arc4.DynamicBytes,
        b1: arc4.DynamicBytes,
    ) -> arc4.Bool:
        return arc4.Bool(
            pairing_check_2(a0.native, b0.native, a1.native, b1.native)
        )

    @arc4.abimethod
    def verify_aggregate_signature(
        self,
        agg_pubkey: arc4.DynamicBytes,
        msg_point: arc4.DynamicBytes,
        signature: arc4.DynamicBytes,
    ) -> arc4.Bool:
        return arc4.Bool(
            verify_aggregate_signature(
                agg_pubkey.native, msg_point.native, signature.native
            )
        )

    # -- §12 measurement-backlog probes (not primitives; raw opcode costs) --

    @arc4.abimethod
    def probe_ec_map_to_g2(self, u: arc4.DynamicBytes) -> arc4.DynamicBytes:
        """P1/P2: standalone `ec_map_to BLS12_381g2` cost + bit-exactness."""
        return arc4.DynamicBytes(EllipticCurve.map_to(EC.BLS12_381g2, u.native))

    @arc4.abimethod
    def probe_ec_add_g2(
        self, a: arc4.DynamicBytes, b: arc4.DynamicBytes
    ) -> arc4.DynamicBytes:
        """P3: standalone `ec_add BLS12_381g2` cost."""
        return arc4.DynamicBytes(EllipticCurve.add(EC.BLS12_381g2, a.native, b.native))

    @arc4.abimethod
    def probe_ec_subgroup_check_g2(self, p: arc4.DynamicBytes) -> arc4.Bool:
        """P3: standalone `ec_subgroup_check BLS12_381g2` cost."""
        return arc4.Bool(EllipticCurve.subgroup_check(EC.BLS12_381g2, p.native))

    @arc4.abimethod
    def probe_ec_scalar_mul_g1(
        self, p: arc4.DynamicBytes, k: arc4.DynamicBytes
    ) -> arc4.DynamicBytes:
        """P4: standalone `ec_scalar_mul BLS12_381g1` cost."""
        return arc4.DynamicBytes(
            EllipticCurve.scalar_mul(EC.BLS12_381g1, p.native, k.native)
        )

    @arc4.abimethod
    def probe_pairing_alignment(
        self,
        a0: arc4.DynamicBytes,
        a1: arc4.DynamicBytes,
        b0: arc4.DynamicBytes,
        b1: arc4.DynamicBytes,
    ) -> arc4.Bool:
        """P5: pairing pair-alignment -- caller passes A=[a0,a1], B=[b0,b1]
        so the test can distinguish index-aligned vs. swapped pairing."""
        a = a0.native + a1.native
        b = b0.native + b1.native
        return arc4.Bool(EllipticCurve.pairing_check(EC.BLS12_381g1, a, b))

    @arc4.abimethod
    def probe_ec_add_g1_chain(self, blob: arc4.DynamicBytes) -> arc4.DynamicBytes:
        """P9: measures the real per-iteration Puya loop glue of an
        `ec_add` accumulation loop over `blob` (n concatenated G1 points),
        for comparison against `probe_msm_all_ones` at the same n."""
        return arc4.DynamicBytes(g1_sum_blob(blob.native))

    @arc4.abimethod
    def probe_msm_all_ones(
        self, points: arc4.DynamicBytes, scalars: arc4.DynamicBytes
    ) -> arc4.DynamicBytes:
        """P9: the MSM-chunk side of the same comparison; caller supplies
        an all-ones scalar blob matching `points`' point count."""
        return arc4.DynamicBytes(g1_msm_chunk(points.native, scalars.native))

    @arc4.abimethod
    def probe_donor_noop(self) -> arc4.Bool:
        """P11: minimal-cost inner-call callee, for measuring net budget
        gain per no-op donor inner app call (itxn_begin/field/submit
        overhead vs. the +700 pooled budget it buys)."""
        return arc4.Bool(True)

    @arc4.abimethod
    def probe_sha256(self, data: arc4.DynamicBytes) -> arc4.DynamicBytes:
        """P12: standalone `sha256` cost, various input sizes."""
        return arc4.DynamicBytes(op.sha256(data.native))

    @arc4.abimethod
    def probe_bmod_96_byte_dividend(
        self, dividend_96: arc4.DynamicBytes, modulus_48: arc4.DynamicBytes
    ) -> arc4.DynamicBytes:
        """P10: does `b%` (BigUInt modulo) accept a 96-byte dividend? If it
        does, a ~200-budget on-curve check (Y^2 == X^3+4) becomes possible
        as a future replacement for the 1850-budget `ec_subgroup_check` at
        install time (§4.3 note) -- NOT built on here, recorded only."""
        dividend = BigUInt.from_bytes(dividend_96.native)
        modulus = BigUInt.from_bytes(modulus_48.native)
        return arc4.DynamicBytes((dividend % modulus).bytes)
