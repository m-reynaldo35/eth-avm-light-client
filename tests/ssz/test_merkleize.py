"""Offline tests for contracts/primitives/ssz/merkleize.py, per design doc
§8's test plan (T7, and the offline portion of T13). Cross-checked against
`remerkleable` -- an independent SSZ implementation -- not just against
this project's own pure-Python `tests/ssz/reference.py` mirror.

T7 pins design doc §7.4's two classic SSZ merkleization bugs:
  1. Padding a level-i gap with zero_hash(0) instead of zero_hash(i)
     (invisible whenever the chunk count is a power of two -- hence the
     non-power-of-two n's below).
  2. Sizing a List's tree from the runtime length instead of the type
     limit N.
"""
import hashlib
import math

import pytest
from algopy import Bytes, UInt64
from remerkleable.byte_arrays import Bytes32
from remerkleable.complex import List, Vector

from contracts.primitives.ssz.merkleize import (
    merkleize_stack_finalize,
    merkleize_stack_push,
    mix_in_length,
    zero_hash,
)
from tests.ssz import reference

NON_POWER_OF_TWO_NS = [1, 3, 5, 7, 9, 17, 31, 33, 100, 511]
TYPE_LIMIT = 1024
TYPE_LIMIT_DEPTH = 10  # ceil(log2(1024))


def _chunk(i: int) -> bytes:
    return hashlib.sha256(i.to_bytes(8, "big")).digest()


def _ceil_log2(n: int) -> int:
    return 0 if n <= 1 else (n - 1).bit_length()


def _push_all(chunks: list[bytes], depth: int):
    zero32 = b"\x00" * 32
    state = Bytes(zero32 * (depth + 1))
    filled = UInt64(0)
    for c in chunks:
        state, filled = merkleize_stack_push(state, filled, Bytes(c))
    return state, filled


# --------------------------------------------------------------------------
# zero_hash table itself.
# --------------------------------------------------------------------------
def test_zero_hash_table_matches_reference(ctx):
    ref = reference.zero_hashes(20)
    for i in range(21):
        assert zero_hash(UInt64(i)).value == ref[i], f"zero_hash({i}) mismatch"


def test_zero_hash_rejects_out_of_range_depth(ctx):
    with pytest.raises(Exception):
        zero_hash(UInt64(64))


# --------------------------------------------------------------------------
# T7: Vector-style merkleization vs remerkleable, for non-power-of-two n.
# Depth here is ceil(log2(n)) -- the Vector's own size IS n, so the tree is
# sized directly from it (there is no separate "type limit" for a Vector).
# --------------------------------------------------------------------------
@pytest.mark.parametrize("n", NON_POWER_OF_TWO_NS)
def test_t7_vector_merkleization_matches_remerkleable(ctx, n):
    chunks = [_chunk(i) for i in range(n)]
    depth = _ceil_log2(n)

    state, filled = _push_all(chunks, depth)
    onchain_root = merkleize_stack_finalize(state, filled, UInt64(depth)).value

    class V(Vector[Bytes32, n]):
        pass

    expected = V(*[Bytes32(c) for c in chunks]).hash_tree_root()
    assert onchain_root == expected, f"n={n}, depth={depth}: root mismatch vs remerkleable"

    # Cross-check against the pure-Python reference too.
    ref_root = reference.merkleize_chunks(chunks, depth)
    assert onchain_root == ref_root


# --------------------------------------------------------------------------
# T7 (continued): the classic bug this test plan exists to catch --
# padding a level-i gap with zero_hash(0) instead of zero_hash(i) must
# produce a DIFFERENT (wrong) root whenever n is not a power of two.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("n", [5, 9, 17, 33, 100])
def test_t7_wrong_zero_padding_gives_a_different_root(ctx, n):
    # NOTE: n of the form 2**depth - 1 (e.g. 3, 7, 15, 31...) at the
    # minimal depth = ceil(log2(n)) are degenerate for this specific
    # negative test: the push accumulator ends up with every bit of
    # `filled` set (no level is ever left unpadded), so the buggy and
    # correct padding paths coincide by construction. The values below all
    # leave at least one bit of `filled` unset, which is confirmed to
    # actually change the result before asserting rejection.
    chunks = [_chunk(i) for i in range(n)]
    depth = _ceil_log2(n)
    state, filled = _push_all(chunks, depth)
    correct_root = merkleize_stack_finalize(state, filled, UInt64(depth)).value

    # Reference implementation of the classic bug: pad every gap with
    # zero_hash(0) (32 zero bytes) regardless of level, instead of
    # zero_hash(level).
    def buggy_finalize(chunks, depth):
        node = b"\x00" * 32
        f = 0
        acc = []
        # mirror merkleize_stack_push's carry logic in pure python, but
        # record per-level "filled" nodes the same way, then finalize with
        # the bug.
        state = [b"\x00" * 32] * (depth + 1)
        for chunk in chunks:
            node = chunk
            level = 0
            while (f >> level) & 1:
                node = hashlib.sha256(state[level] + node).digest()
                f ^= 1 << level
                level += 1
            state[level] = node
            f |= 1 << level
        node = b"\x00" * 32  # BUG: always zero_hash(0), never zero_hash(level)
        for level in range(depth):
            if (f >> level) & 1:
                node = hashlib.sha256(state[level] + node).digest()
            else:
                node = hashlib.sha256(node + (b"\x00" * 32)).digest()  # BUG
        return node

    buggy_root = buggy_finalize(chunks, depth)
    assert buggy_root != correct_root, (
        f"n={n}: buggy zero_hash(0)-everywhere padding coincidentally matched "
        "the correct root -- this should only happen for n a power of two"
    )


# --------------------------------------------------------------------------
# T7 (continued) + §7.4 item 3: List sizing from the TYPE LIMIT, not the
# runtime length, then mix_in_length. Uses a fixed generous TYPE_LIMIT for
# every n, so a bug that sizes the tree from n instead of the type limit
# would be caught by every single case here (all n share one correct
# depth, TYPE_LIMIT_DEPTH, that has nothing to do with n's own bit length).
# --------------------------------------------------------------------------
@pytest.mark.parametrize("n", NON_POWER_OF_TWO_NS)
def test_t7_list_sizing_from_type_limit_and_mix_in_length(ctx, n):
    chunks = [_chunk(i) for i in range(n)]

    state, filled = _push_all(chunks, TYPE_LIMIT_DEPTH)
    vector_root = merkleize_stack_finalize(state, filled, UInt64(TYPE_LIMIT_DEPTH))
    list_root = mix_in_length(vector_root, UInt64(n)).value

    class L(List[Bytes32, TYPE_LIMIT]):
        pass

    expected = L(*[Bytes32(c) for c in chunks]).hash_tree_root()
    assert list_root == expected, f"n={n}: List root mismatch vs remerkleable"


def test_t7_list_wrong_depth_from_runtime_length_gives_different_root(ctx):
    # The classic bug: size the tree from n (runtime length) instead of
    # the type limit. Confirm it disagrees with the type-limit-correct
    # root for a value of n whose own bit-length differs from
    # TYPE_LIMIT_DEPTH.
    n = 33
    chunks = [_chunk(i) for i in range(n)]
    wrong_depth = _ceil_log2(n)  # BUG: from n, not the type limit
    assert wrong_depth != TYPE_LIMIT_DEPTH

    state, filled = _push_all(chunks, wrong_depth)
    buggy_root = mix_in_length(merkleize_stack_finalize(state, filled, UInt64(wrong_depth)), UInt64(n)).value

    state2, filled2 = _push_all(chunks, TYPE_LIMIT_DEPTH)
    correct_root = mix_in_length(merkleize_stack_finalize(state2, filled2, UInt64(TYPE_LIMIT_DEPTH)), UInt64(n)).value

    assert buggy_root != correct_root


# --------------------------------------------------------------------------
# mix_in_length: endianness trap (§2.11) -- a wrong-endian length must
# yield a different root even though the byte length is identical.
# --------------------------------------------------------------------------
def test_mix_in_length_matches_reference_and_endianness_matters(ctx):
    root = _chunk(0)
    for length in [0, 1, 512, 2**40]:
        onchain = mix_in_length(Bytes(root), UInt64(length)).value
        expected = reference.mix_in_length(root, length)
        assert onchain == expected, f"length={length}"

    # Wrong-endian regression: manually mixing in the BIG-endian encoding
    # of a nonzero length must NOT match the correct (little-endian) root.
    length = 512
    correct = mix_in_length(Bytes(root), UInt64(length)).value
    wrong_endian = hashlib.sha256(root + length.to_bytes(32, "big")).digest()
    assert correct != wrong_endian
