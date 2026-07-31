"""ARC-4 boundary and budget-measurement harness for M3 (design doc §5.4).

Two contracts live here, neither of which is the primary integration path:

  * `SSZVerifier(ARC4Contract)` -- the §5.4 shell. A thin ARC-4 wrapper
    around `assert_valid_normalized_merkle_branch`, for external callers and
    the ABI-based test harness. **Not** the recommended way for M4/M8 to
    consume this module: an inner app call would add a whole extra
    700-budget call's worth of overhead on top of a 301-488 budget
    operation, which the design doc calls "absurd" (§5.4). M4/M8 should
    import the `contracts/primitives/ssz/merkle.py` subroutines directly
    into their own approval program instead.

  * `SSZBenchmark(Contract)` -- a bare, non-ARC4-routed contract that
    mirrors Appendix A's raw application-argument layout exactly (arg0 =
    leaf, arg1 = packed branch, arg2 = big-endian gindex, arg3 = expected
    root). This exists ONLY to reproduce design doc §2.4/§2.5/§2.6's budget
    figures against Puya-compiled code, for a fair apples-to-apples
    comparison with Appendix A's hand-written TEAL reference (§11 Q2: "does
    Puya codegen inflate the cost model?"). The ARC-4 shell above adds ABI
    routing and array-decode overhead that is real but orthogonal to that
    question. Neither contract here is meant to be deployed in production.

  * `MerkleizeBenchmark(Contract)` -- exercises §5.5's `merkleize_stack_push`
    / `merkleize_stack_finalize` / `mix_in_length` end to end for a small
    number of chunks passed as a single packed app arg (bounded by the
    2,048-byte app-arg ceiling, so at most ~60 chunks per call -- this is
    NOT the 512-pubkey/99-app-call committee shape design doc §2.7
    measured; it exists to prove the merkleize primitives compile and
    execute correctly on real algod and to get a real, if smaller-scale,
    marginal-sha256-cost data point, not to reproduce §2.7's own figure.
    Logs both the plain (Vector-style) merkleized root and the
    length-mixed (List-style) root so a test can compare each against an
    independent `remerkleable` reference.
"""
import typing

from algopy import ARC4Contract, Bytes, Contract, Txn, UInt64, arc4, log, op, subroutine, urange

from .merkle import assert_valid_normalized_merkle_branch
from .merkleize import merkleize_stack_finalize, merkleize_stack_push, mix_in_length

_Bytes32 = arc4.StaticArray[arc4.Byte, typing.Literal[32]]


@subroutine
def _unpack_branch(branch: arc4.DynamicArray[_Bytes32]) -> Bytes:
    """Convert the ARC-4 boundary's array encoding to the packed `Bytes`
    blob the §5.1-§5.3 primitives expect, in one extract -- not a
    per-element decode loop. A `DynamicArray` of a static-size element type
    encodes as a 2-byte big-endian length prefix followed by the elements
    back-to-back with no per-element offsets, so stripping the prefix is
    the entire conversion (design doc §5: "Convert once at the ARC-4
    boundary and pass packed Bytes inward").
    """
    encoded = branch.bytes
    return encoded[2 : encoded.length]


class SSZVerifier(ARC4Contract, avm_version=10):
    """§5.4's ARC-4 shell. Exists for external callers and the measurement
    harness; see the module docstring for why this is not the integration
    path M4/M8 should use in production.
    """

    @arc4.abimethod
    def verify_branch(
        self,
        leaf: _Bytes32,
        branch: arc4.DynamicArray[_Bytes32],
        gindex: arc4.UInt64,
        expected_root: _Bytes32,
    ) -> None:
        """Thin ARC-4 wrapper over `assert_valid_normalized_merkle_branch`.

        NORMATIVE (design doc §6): `gindex` here is whatever the calling
        transaction supplied -- this method does not and cannot enforce
        that it came from a fork-gated table. Any caller of this external
        entry point is responsible for that provenance guarantee; it is
        not a property this contract can verify from inside itself. See
        `merkle.py`'s docstrings for the full warning.
        """
        packed_branch = _unpack_branch(branch)
        assert_valid_normalized_merkle_branch(
            leaf.bytes, packed_branch, gindex.as_uint64(), expected_root.bytes
        )


class SSZBenchmark(Contract, avm_version=10):
    """Bare raw-app-arg benchmark contract -- see module docstring. Not
    part of the public interface; used only by `tests/ssz/test_budget.py`
    to re-measure design doc §2.4-§2.6 against Puya-generated TEAL.
    """

    def approval_program(self) -> UInt64:
        leaf = Txn.application_args(0)
        branch = Txn.application_args(1)
        gindex = op.btoi(Txn.application_args(2))
        expected_root = Txn.application_args(3)
        assert_valid_normalized_merkle_branch(leaf, branch, gindex, expected_root)
        return UInt64(1)

    def clear_state_program(self) -> UInt64:
        return UInt64(1)


class MerkleizeBenchmark(Contract, avm_version=10):
    """Bare raw-app-arg benchmark for §5.5's merkleize primitives -- see
    module docstring. Not part of the public interface.

    Args: arg0 = big-endian UInt64 `n` (number of real chunks), arg1 =
    packed chunks (32*n bytes), arg2 = big-endian UInt64 target `depth`
    (must satisfy 2**depth >= n). Logs the plain merkleized root followed
    by the length-mixed root (mixing in `n` as the List-style length).
    """

    def approval_program(self) -> UInt64:
        n = op.btoi(Txn.application_args(0))
        chunks = Txn.application_args(1)
        depth = op.btoi(Txn.application_args(2))

        zero32 = op.Global.zero_address.bytes
        state = Bytes()
        for _i in urange(depth + 1):
            state += zero32
        filled = UInt64(0)

        for i in urange(n):
            offset = i * 32
            chunk = chunks[offset : offset + 32]
            state, filled = merkleize_stack_push(state, filled, chunk)

        vector_root = merkleize_stack_finalize(state, filled, depth)
        list_root = mix_in_length(vector_root, n)

        log(vector_root)
        log(list_root)
        return UInt64(1)

    def clear_state_program(self) -> UInt64:
        return UInt64(1)
