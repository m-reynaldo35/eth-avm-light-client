"""Pure-Python synthetic fixture generator for M8's non-headline test
suites. Builds SELF-CONSISTENT SSZ Merkle trees (real `sha256` folds,
bit-exact with `contracts/primitives/ssz/merkle.py`'s on-chain algorithm and
`contracts/sync_committee/header.py`'s beacon-header layout) with
arbitrary, test-chosen leaf VALUES at arbitrary field POSITIONS -- e.g. "put
this exact 32-byte receipts_root leaf at gindex 803" -- so every fold this
module's tests exercise is a genuine Merkle proof of the on-chain algorithm,
even though the tree's OTHER leaves and the beacon header's other fields are
synthetic, not real chain data.

Mirrors this codebase's own established precedent for this kind of gap (M6
ROADMAP row: "absent-slot test uses derived (not real eth_getProof)
fixtures"). The ONE headline test that must use real, live chain data
end-to-end is `tests/state_anchor/test_live_e2e.py` -- everything here is
explicitly the OTHER kind of test.
"""
from __future__ import annotations

import hashlib
import os


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def le64(x: int) -> bytes:
    return x.to_bytes(8, "little")


def build_tree(depth: int, position_to_leaf: dict[int, bytes], default_leaf: bytes = b"\x00" * 32):
    """Builds a depth-`depth` binary Merkle tree (2**depth leaves), with
    `position_to_leaf` overriding specific leaf positions. Returns
    `(root, branch_for)` where `branch_for(position)` returns the
    leaf-to-root-ordered sibling bytes (`depth * 32` bytes) M3's
    `assert_valid_merkle_branch` expects."""
    n = 1 << depth
    leaves = [position_to_leaf.get(i, default_leaf) for i in range(n)]
    layers = [leaves]
    cur = leaves
    while len(cur) > 1:
        nxt = [sha256(cur[2 * i] + cur[2 * i + 1]) for i in range(len(cur) // 2)]
        layers.append(nxt)
        cur = nxt
    root = cur[0]

    def branch_for(position: int) -> bytes:
        b = b""
        idx = position
        for layer in layers[:-1]:
            sib_idx = idx ^ 1
            b += layer[sib_idx]
            idx //= 2
        return b

    return root, branch_for


def htr_beacon_header(slot: int, proposer_index: int, parent_root: bytes, state_root: bytes, body_root: bytes) -> bytes:
    """Bit-exact with `hash_tree_root_beacon_block_header` (header.py)."""
    slot_chunk = le64(slot) + b"\x00" * 24
    proposer_chunk = le64(proposer_index) + b"\x00" * 24
    zero_leaf = b"\x00" * 32
    l0 = sha256(slot_chunk + proposer_chunk)
    l1 = sha256(parent_root + state_root)
    l2 = sha256(body_root + zero_leaf)
    l3 = sha256(zero_leaf + zero_leaf)
    n0 = sha256(l0 + l1)
    n1 = sha256(l2 + l3)
    return sha256(n0 + n1)


def make_header(slot: int, proposer_index: int, parent_root: bytes, state_root: bytes, body_root: bytes) -> tuple[bytes, bytes]:
    header = le64(slot) + le64(proposer_index) + parent_root + state_root + body_root
    root = htr_beacon_header(slot, proposer_index, parent_root, state_root, body_root)
    return header, root


# Test fork row (§3.3 shape; NOT real consensus-spec gindices -- these are
# arbitrary depth-9 positions chosen for these synthetic tests only. The
# REAL, G4-M8-derived gindices are exercised in test_live_e2e.py against
# the real `forks.py` table built from real live data.)
G_STATE_ROOT = 512 + 290  # depth 9, position 290
G_RECEIPTS_ROOT = 512 + 291
G_BLOCK_NUMBER = 512 + 294
EXEC_DEPTH = 9

G_BLOCK_ROOTS_BASE = 32 + 5  # depth 5 container position (Deneb-shaped)
BLOCK_ROOTS_VECTOR_DEPTH = 13


def build_execution_tree(state_root: bytes, receipts_root: bytes, block_number: int):
    """Returns `(body_root, state_branch, receipts_branch, number_branch)`
    for the synthetic depth-9 execution tree used by every non-live M8
    test."""
    number_leaf = le64(block_number) + b"\x00" * 24
    body_root, branch_for = build_tree(
        EXEC_DEPTH,
        {290: state_root, 291: receipts_root, 294: number_leaf},
    )
    return body_root, branch_for(290), branch_for(291), branch_for(294)


def build_block_roots_tree(t_slot: int, target_root: bytes):
    """Returns `(fin_state_root, block_roots_branch)` for a synthetic
    HISTORICAL-mode `block_roots` tree with `target_root` placed at
    `t_slot mod 8192`."""
    residue = t_slot % 8192
    fin_state_root, branch_for = build_tree(BLOCK_ROOTS_VECTOR_DEPTH, {residue: target_root})
    return fin_state_root, branch_for(residue)


def random32() -> bytes:
    return os.urandom(32)


def compose_block_roots_gindex(g_block_roots_base: int, t_slot: int) -> int:
    """Bit-exact mirror of `bridge.py`'s on-chain `block_roots_gindex`:
    `g = g_block_roots_base * 8192 + (t_slot mod 8192)`. Used by the fork-
    boundary fixture (`tests/state_anchor/test_forks.py`, F6) to build a
    synthetic `block_roots` branch at the SAME composed gindex the deployed
    contract will independently derive on-chain from `g_block_roots_base`
    (a fork-table column) and `t_slot` (the target header's own slot) --
    never precomputed off-chain and handed over as a final gindex argument,
    exactly N-INDEX's own rule (§4.3)."""
    return g_block_roots_base * 8192 + (t_slot % 8192)


def build_tree_at_gindex(gindex: int, leaf: bytes):
    """Generic depth-`bitlen(gindex)-1` tree with `leaf` placed at the
    position `gindex` composes to. Used directly for the fork-boundary
    fixture's `block_roots` tree, where the total depth differs (18 vs 19)
    depending on which fork's `g_block_roots_base` is folded at -- exactly
    the property F6 exists to exercise. Returns `(root, branch)`."""
    assert gindex >= 1
    depth = gindex.bit_length() - 1
    position = gindex - (1 << depth)
    root, branch_for = build_tree(depth, {position: leaf})
    return root, branch_for(position)
