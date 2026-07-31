"""
docs/design/005-mpt-walker.md §5.1 (mpt_descend) + §9.5 suite D1: the fused
branch skip loop's duplicated per-item stride arithmetic must agree with
M2's canonical `rlp_item_header` on every item of every real fixture node.
"""
import algopy_testing
import pytest
from algopy import Bytes, UInt64

from contracts.mpt.descend import mpt_descend
from contracts.primitives.rlp.core import KIND_LIST, KIND_STR, rlp_item_header, rlp_scan
from tests.reference import mpt_ref


# ---------------------------------------------------------------------------
# Arity discrimination on real fixtures: a 17-item branch and a 2-item
# ext/leaf must be told apart correctly, and the discrimination must be
# unconditional (works regardless of item 0's own shape, §5.1's stated
# reason for NOT using a shape-based test).
# ---------------------------------------------------------------------------
def test_arity_17_on_real_branch_node(eth_data):
    node = bytes.fromhex(eth_data["proof"]["accountProof"][0][2:])
    with algopy_testing.algopy_testing_context():
        arity, _o0, _l0, _k0, ow, lw, kw = mpt_descend(Bytes(node), UInt64(0), UInt64(10))
        assert int(arity) == 17
        # pinned: item 10 of accountProof[0] is the real next-hop child hash
        assert int(lw) == 32 and int(kw) == KIND_STR


def test_arity_2_on_real_leaf_node(eth_data):
    node = bytes.fromhex(eth_data["proof"]["accountProof"][7][2:])
    with algopy_testing.algopy_testing_context():
        arity, o0, l0, _k0, o1, l1, k1 = mpt_descend(Bytes(node), UInt64(0), UInt64(0))
        assert int(arity) == 2
        assert (int(o1), int(l1), int(k1)) == (34, 70, KIND_STR)


def test_arity_2_on_real_receipt_leaf_with_zero_nibble_path(eth_data):
    """receipt_proof.nodes[2]: 2-item leaf whose path encodes ZERO nibbles
    (§5.4's third worked row) -- still must discriminate as arity 2."""
    node = bytes.fromhex(eth_data["receipt_proof"]["nodes"][2][2:])
    with algopy_testing.algopy_testing_context():
        arity, o0, l0, _k0, o1, l1, _k1 = mpt_descend(Bytes(node), UInt64(0), UInt64(0))
        assert int(arity) == 2
        assert int(l0) == 1  # single-byte compact path (0x20 -- leaf, even, 0 nibbles)


# ---------------------------------------------------------------------------
# §5.1's W9: requesting an item beyond the branch payload fails cleanly.
# ---------------------------------------------------------------------------
def test_w9_want_beyond_payload_rejected(eth_data):
    node = bytes.fromhex(eth_data["proof"]["accountProof"][0][2:])
    with algopy_testing.algopy_testing_context():
        with pytest.raises(Exception, match="W9"):
            mpt_descend(Bytes(node), UInt64(0), UInt64(16) + UInt64(1))


# ---------------------------------------------------------------------------
# D1 (mandatory, §9.5): for EVERY branch node across the real fixtures, the
# fused skip loop must agree with the canonical rlp_scan + rlp_item_header
# path on every item's (content_off, content_len, kind).
# ---------------------------------------------------------------------------
def _real_branch_nodes(eth_data):
    out = []
    p = eth_data["proof"]
    for i, h in enumerate(p["accountProof"]):
        node = bytes.fromhex(h[2:])
        if len(node) > 100:  # cheap arity-17 pre-filter; real check below
            out.append((f"accountProof[{i}]", node))
    for i, h in enumerate(p["storageProof"][0]["proof"]):
        node = bytes.fromhex(h[2:])
        if len(node) > 100:
            out.append((f"storageProof[0].proof[{i}]", node))
    rp = eth_data["receipt_proof"]
    for i, h in enumerate(rp["nodes"]):
        node = bytes.fromhex(h[2:])
        if len(node) > 100:
            out.append((f"receipt_proof.nodes[{i}]", node))
    return out


def test_d1_fused_loop_agrees_with_canonical_path_every_item(eth_data):
    checked_nodes = 0
    for label, node in _real_branch_nodes(eth_data):
        with algopy_testing.algopy_testing_context():
            table, n = rlp_scan(Bytes(node), UInt64(0))
            if int(n) != 17:
                continue  # not actually a branch node (long leaf/extension)
            checked_nodes += 1
            for want in range(17):
                arity, _o0, _l0, _k0, ow, lw, kw = mpt_descend(Bytes(node), UInt64(0), UInt64(want))
                assert int(arity) == 17, f"{label} want={want}"
                # canonical path
                from contracts.primitives.rlp.core import rlp_table_item
                c_off, c_len, c_kind = rlp_table_item(Bytes(node), table, UInt64(want))
                assert (int(ow), int(lw), int(kw)) == (int(c_off), int(c_len), int(c_kind)), (
                    f"{label} item {want}: mpt_descend={int(ow), int(lw), int(kw)} "
                    f"canonical={int(c_off), int(c_len), int(c_kind)}")
    assert checked_nodes >= 15  # sanity: we actually exercised real branch nodes


def test_d1_agrees_with_python_oracle(eth_data):
    for label, node in _real_branch_nodes(eth_data):
        with algopy_testing.algopy_testing_context():
            table, n = rlp_scan(Bytes(node), UInt64(0))
            if int(n) != 17:
                continue
            for want in (0, 1, 4, 8, 10, 13, 15, 16):
                arity, o0, l0, k0, ow, lw, kw = mpt_descend(Bytes(node), UInt64(0), UInt64(want))
                o_arity, o_o0, o_l0, o_k0, o_ow, o_lw, o_kw = mpt_ref.mpt_descend(node, 0, want)
                assert (int(arity), int(o0), int(l0), int(k0), int(ow), int(lw), int(kw)) == (
                    o_arity, o_o0, o_l0, o_k0, o_ow, o_lw, o_kw), f"{label} want={want}"
