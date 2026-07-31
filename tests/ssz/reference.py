"""Pure-Python reference mirror of the M3 SSZ Merkle primitives.

Verbatim ports of `specs/phase0/beacon-chain.md`'s `compute_merkle_branch_root`
and the light-client spec's `is_valid_normalized_merkle_branch`
(docs/design/003-ssz-verifier.md §3.3, §3.5), used by the offline test suite
(T3: "on-chain fold == verbatim Python reference, byte-exact") and to build
expected values for merkleization tests (T7) alongside `remerkleable`.

This module has NO dependency on algopy/algorand-python-testing -- it is a
plain-Python check, independent of the AVM implementation, on purpose.
"""
from __future__ import annotations

import hashlib


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def floorlog2(gindex: int) -> int:
    assert gindex >= 1, "gindex must be >= 1"
    return gindex.bit_length() - 1


def get_subtree_index(gindex: int) -> int:
    depth = floorlog2(gindex)
    return gindex - 2**depth


def compute_merkle_branch_root(leaf: bytes, branch: list[bytes], depth: int, index: int) -> bytes:
    """Verbatim port of the spec function of the same name."""
    assert len(leaf) == 32
    value = leaf
    for i in range(depth):
        if (index // (2**i)) % 2:
            value = sha256(branch[i] + value)
        else:
            value = sha256(value + branch[i])
    return value


def compute_merkle_branch_root_gindex(leaf: bytes, branch: list[bytes], gindex: int) -> bytes:
    """Design doc §3.3's restatement, with `gindex` in place of `(depth, index)`."""
    assert gindex >= 1, "gindex must be >= 1"
    depth = floorlog2(gindex)
    assert len(branch) == depth, "branch length must equal depth exactly"
    node = leaf
    for i in range(depth):
        sibling = branch[i]
        if (gindex >> i) & 1:
            node = sha256(sibling + node)
        else:
            node = sha256(node + sibling)
    return node


def is_valid_merkle_branch(leaf: bytes, branch: list[bytes], depth: int, index: int, root: bytes) -> bool:
    if depth != len(branch):
        return False
    return compute_merkle_branch_root(leaf, branch, depth, index) == root


def is_valid_normalized_merkle_branch(leaf: bytes, branch: list[bytes], gindex: int, root: bytes) -> bool:
    """Verbatim port of the light-client spec function of the same name
    (design doc §3.5)."""
    depth = floorlog2(gindex)
    index = get_subtree_index(gindex)
    num_extra = len(branch) - depth
    if num_extra < 0:
        return False
    for i in range(num_extra):
        if branch[i] != b"\x00" * 32:
            return False
    return is_valid_merkle_branch(leaf, branch[num_extra:], depth, index, root)


def zero_hashes(max_depth: int) -> list[bytes]:
    """zh[0] = 32 zero bytes; zh[i] = sha256(zh[i-1] || zh[i-1])."""
    zh = [b"\x00" * 32]
    for _ in range(max_depth):
        prev = zh[-1]
        zh.append(sha256(prev + prev))
    return zh


def merkleize_chunks(chunks: list[bytes], depth: int) -> bytes:
    """Reference full-tree merkleization of `chunks` into a tree of the
    given `depth` (`2**depth >= len(chunks)`), padding missing leaves with
    `zero_hash(0)` at the leaf layer and combining upward -- the
    layer-at-a-time definition SSZ specifies, used here (in pure Python,
    where the 4096-byte AVM value cap does not apply) purely as an
    independent check on `merkleize_stack_push`/`merkleize_stack_finalize`.
    """
    zh = zero_hashes(depth)
    layer = list(chunks) + [zh[0]] * (2**depth - len(chunks))
    for level in range(depth):
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(sha256(layer[i] + layer[i + 1]))
        layer = next_layer
    return layer[0] if layer else zh[depth]


def mix_in_length(root: bytes, length: int) -> bytes:
    length_le_32 = length.to_bytes(32, "little")
    return sha256(root + length_le_32)


def merkleize_stack_push_ref(state: list[bytes], filled: int, chunk: bytes) -> tuple[list[bytes], int]:
    """Pure-Python mirror of `merkleize_stack_push`, operating on a list of
    32-byte nodes instead of a packed Bytes blob, for use as an independent
    cross-check inside the offline test suite."""
    node = chunk
    level = 0
    f = filled
    state = list(state)
    while (f >> level) & 1:
        node = sha256(state[level] + node)
        f ^= 1 << level
        level += 1
    while len(state) <= level:
        state.append(b"\x00" * 32)
    state[level] = node
    f |= 1 << level
    return state, f


def merkleize_stack_finalize_ref(state: list[bytes], filled: int, depth: int) -> bytes:
    zh = zero_hashes(depth)
    node = zh[0]
    for level in range(depth):
        if (filled >> level) & 1:
            node = sha256(state[level] + node)
        else:
            node = sha256(node + zh[level])
    return node
