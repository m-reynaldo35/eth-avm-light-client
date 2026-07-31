"""
docs/design/005-mpt-walker.md §9.4 remaining suite E/X items: node-shape
assertions (W5/W6/W7), the inline-descent bound (W8, E8), the "ran out of
nodes" trap (X5), unconsumed trailing nodes (W10/X6), the terminal-walk
guard (W12), and E1/E9's real-data boundary facts.
"""
import algopy_testing
import pytest
from algopy import Bytes, UInt64

from contracts.mpt.descend import mpt_arity_discriminate, mpt_descend
from contracts.mpt.state import (
    WALK_CONTINUE,
    WALK_INCLUDED,
    mpt_init_state,
    w_status,
)
from contracts.mpt.walk import mpt_branch_hop, mpt_extension_hop, mpt_leaf_hop, mpt_walk_node


# ---------------------------------------------------------------------------
# E1: item 16's span on every real branch node is (len(node), 0) -- offset
# EQUALS the node length, length zero. mpt_descend must return this
# span without panicking (extract3 at end-of-buffer with length 0 is
# legal; getbyte there is not -- M2 E2's fact, restated for M5's own
# item-16 read path).
# ---------------------------------------------------------------------------
def test_e1_item16_span_at_end_of_real_branch_node(eth_data):
    node = bytes.fromhex(eth_data["proof"]["accountProof"][0][2:])
    with algopy_testing.algopy_testing_context():
        arity, _o0, _l0, _k0, ov, lv, kv = mpt_descend(Bytes(node), UInt64(0), UInt64(16))
        assert int(arity) == 17
        assert int(ov) == len(node) and int(lv) == 0
        assert int(ov) == 532  # pinned, matches M2's own E2 vector


# ---------------------------------------------------------------------------
# W5 (§16.2 update): mpt_walk_node routes to mpt_branch_hop ONLY when
# mpt_arity_discriminate has already determined arity == 17 for this exact
# node/start -- so a genuine 2-item node can never reach mpt_branch_hop
# through normal routing. Before the §16.2 performance fix, mpt_branch_hop
# independently re-derived arity itself (a second, fully redundant decode
# of the SAME node) and asserted "W5" if it disagreed -- a defense that,
# per this test file's own original comment, was ALREADY unreachable via
# mpt_walk_node's normal routing and only exercisable by calling
# mpt_branch_hop directly, out of its calling convention. §16.2 removed
# that redundant internal re-derivation (it was real, measured, avoidable
# work -- see docs/design/005-mpt-walker.md §16.2): mpt_branch_hop now
# takes the ALREADY-discriminated item spans and trusts them, rather than
# re-decoding node/start a second time to re-confirm what the caller
# already established once. What this test now pins is the guarantee that
# actually matters: mpt_arity_discriminate correctly identifies a genuine
# 2-item (leaf) node as arity == 2, which is what makes mpt_branch_hop
# structurally unreachable for it in the only real call path
# (mpt_walk_node). A caller that hand-constructs mismatched arguments and
# calls mpt_branch_hop directly (bypassing mpt_arity_discriminate
# entirely, as the old test did) is outside mpt_branch_hop's documented
# precondition (see its docstring) and gets no runtime defense for that
# misuse -- an intentional, documented trade for removing a genuinely
# dead-on-every-real-path check from the hot loop.
# ---------------------------------------------------------------------------
def test_w5_retired_arity_discriminate_correctly_rejects_2_item_node_as_branch(eth_data):
    leaf = bytes.fromhex(eth_data["proof"]["accountProof"][7][2:])
    with algopy_testing.algopy_testing_context():
        arity, _payload_end, _o0, _l0, _k0, _o1, _l1, _k1 = mpt_arity_discriminate(
            Bytes(leaf), UInt64(0))
        assert int(arity) == 2, (
            "a genuine 2-item leaf node must discriminate as arity 2, which "
            "is what makes mpt_walk_node's routing to mpt_branch_hop "
            "structurally impossible for this node -- the guarantee W5 used "
            "to re-verify redundantly inside mpt_branch_hop itself")


# ---------------------------------------------------------------------------
# W6: a branch child reference that is neither empty, 32 bytes, nor a list.
# Constructed: a branch node whose slot 0 is a short (non-empty, non-32)
# string -- structurally well-formed RLP, just not a value MPT ever
# produces for a child slot.
# ---------------------------------------------------------------------------
def _branch17(slot0_encoded: bytes) -> bytes:
    import rlp as pyrlp
    items = [slot0_encoded] + [b"\x80"] * 15 + [b"\x80"]
    return pyrlp.encode(items)


def test_w6_branch_child_ref_bad_length_rejected():
    import rlp as pyrlp
    node = _branch17(pyrlp.encode(b"\x01\x02\x03"))  # 3-byte string, not 0/32
    with algopy_testing.algopy_testing_context():
        w = mpt_init_state(Bytes(bytes(32)), Bytes(bytes(32)), UInt64(64))  # key nibble 0 == 0
        arity, payload_end, o0, l0, k0, o1, l1, k1 = mpt_arity_discriminate(Bytes(node), UInt64(0))
        assert int(arity) == 17
        with pytest.raises(Exception, match="W6"):
            mpt_branch_hop(Bytes(node), o0, l0, k0, o1, l1, k1, payload_end, w)


def test_w6_branch_child_ref_kind_byte_rejected():
    """A single raw byte < 0x80 in a branch slot: KIND_BYTE, not KIND_STR
    or KIND_LIST -- also invalid."""
    import rlp as pyrlp
    node = _branch17(b"\x05")  # RLP self-encodes bytes < 0x80 as themselves
    with algopy_testing.algopy_testing_context():
        w = mpt_init_state(Bytes(bytes(32)), Bytes(bytes(32)), UInt64(64))
        arity, payload_end, o0, l0, k0, o1, l1, k1 = mpt_arity_discriminate(Bytes(node), UInt64(0))
        assert int(arity) == 17
        with pytest.raises(Exception, match="W6"):
            mpt_branch_hop(Bytes(node), o0, l0, k0, o1, l1, k1, payload_end, w)


# ---------------------------------------------------------------------------
# W7: extension node's child slot is empty.
# ---------------------------------------------------------------------------
def test_w7_extension_empty_child_rejected():
    import rlp as pyrlp
    path = bytes([0x00]) + bytes([0xAB])  # even-length extension, 2 nibbles a,b
    node = pyrlp.encode([path, b""])  # empty child slot -- never valid
    with algopy_testing.algopy_testing_context():
        from contracts.mpt.descend import mpt_descend
        arity, o0, l0, _k0, o1, l1, k1 = mpt_descend(Bytes(node), UInt64(0), UInt64(0))
        assert int(arity) == 2
        w = mpt_init_state(Bytes(bytes(32)), bytes_key_ab(), UInt64(4))
        with pytest.raises(Exception, match="W7"):
            mpt_extension_hop(Bytes(node), o0, l0, o1, l1, k1, w)


def bytes_key_ab():
    return Bytes(bytes([0xAB]) + bytes(31))


# ---------------------------------------------------------------------------
# W8/E8: inline-descent chain longer than 8 steps within one node buffer.
# Constructed: a chain of 9 nested single-slot branches, each embedding the
# next (all encodings kept < 32 bytes), so the whole chain lives in one
# supplied buffer and must trip the inline_steps bound before finishing.
# ---------------------------------------------------------------------------
def _build_inline_chain(depth: int):
    """Returns (root_bytes, key_bytes, key_nibs, expected_value) for a
    chain of `depth` single-nibble branch hops, each child EMBEDDED as a
    nested RLP list within its parent, terminating in a leaf. Built as a
    nested Python list structure and RLP-encoded ONCE from the outside in,
    so every level is a genuine embedded list (KIND_LIST, §5.5) -- M5's
    walker routes on RLP kind alone, not on the real ~32-byte MPT embedding
    threshold (that threshold is a trie-BUILDER convention; the walker must
    handle "kind == LIST" mechanically regardless of size), so this
    deliberately-oversized synthetic chain is a valid, hash-committed
    exercise of the inline_steps bound (§5.5's own stated purpose: "so a
    malformed-but-hash-committed input cannot loop") even though a real MPT
    encoder would never produce nesting this deep this cheaply."""
    import rlp as pyrlp
    value = b"\x42"
    nibble = 0x0
    leaf_path = bytes([0x20])  # leaf, even, 0 nibbles
    node_struct = [leaf_path, value]
    key_nibbles = []
    for _ in range(depth):
        items = [b""] * 17
        items[nibble] = node_struct  # nested list == embedded child
        node_struct = items
        key_nibbles.append(nibble)
    node = pyrlp.encode(node_struct)
    assert len(node) < 4096
    key_nibs = depth
    key_bytes = bytearray(32)
    for i, nib in enumerate(key_nibbles):
        byte_i, is_hi = divmod(i, 2)
        if is_hi == 0:
            key_bytes[byte_i] |= (nib << 4)
        else:
            key_bytes[byte_i] |= nib
    return node, bytes(key_bytes), key_nibs, value


def test_e8_inline_chain_of_8_succeeds():
    node, key, key_nibs, value = _build_inline_chain(8)
    with algopy_testing.algopy_testing_context():
        from Crypto.Hash import keccak
        h = keccak.new(digest_bits=256); h.update(node); root = h.digest()
        w = mpt_init_state(Bytes(root), Bytes(key), UInt64(key_nibs))
        w, voff, vlen = mpt_walk_node(Bytes(node), w)
        assert int(w_status(w)) == WALK_INCLUDED
        assert bytes(node[int(voff):int(voff) + int(vlen)]) == value


def test_w8_inline_chain_of_9_rejected():
    node, key, key_nibs, value = _build_inline_chain(9)
    with algopy_testing.algopy_testing_context():
        from Crypto.Hash import keccak
        h = keccak.new(digest_bits=256); h.update(node); root = h.digest()
        w = mpt_init_state(Bytes(root), Bytes(key), UInt64(key_nibs))
        with pytest.raises(Exception, match="W8"):
            mpt_walk_node(Bytes(node), w)


# ---------------------------------------------------------------------------
# W11: the hash-chain check itself (TP-M5-3 backstop) -- also covered by
# S1/S7 with real data; this is a minimal direct check.
# ---------------------------------------------------------------------------
def test_w11_hash_mismatch_rejected(eth_data):
    node = bytes.fromhex(eth_data["proof"]["accountProof"][0][2:])
    with algopy_testing.algopy_testing_context():
        w = mpt_init_state(Bytes(bytes(32)), Bytes(bytes(32)), UInt64(64))  # wrong root
        with pytest.raises(Exception, match="W11"):
            mpt_walk_node(Bytes(node), w)


# ---------------------------------------------------------------------------
# W12: cannot extend an already-terminal walk.
# ---------------------------------------------------------------------------
def test_w12_cannot_extend_terminal_walk(mpt_scenarios_by_name, mpt_nodes_by_label):
    sc = mpt_scenarios_by_name["F2_F4_prefix_sharing_pair"]
    root = bytes.fromhex(sc["root"])
    node = mpt_nodes_by_label[sc["nodes"][0]]
    key = bytes.fromhex(sc["short_key"]["key"])
    with algopy_testing.algopy_testing_context():
        w = mpt_init_state(Bytes(root), Bytes(key), UInt64(sc["short_key"]["key_nibs"]))
        w, _voff, _vlen = mpt_walk_node(Bytes(node), w)
        assert int(w_status(w)) == WALK_INCLUDED
        with pytest.raises(Exception, match="W12"):
            mpt_walk_node(Bytes(node), w)  # already terminal -- cannot extend


# ---------------------------------------------------------------------------
# X5: the one real exclusion trap -- a truncated node list (fewer nodes
# than the real path needs) must NOT be mistaken for a verdict. The raw
# walker itself just reports WALK_CONTINUE; it is the segment driver's job
# (bench_app.py) to refuse to treat that as absence. This test pins the
# raw-walker half of that contract.
# ---------------------------------------------------------------------------
def test_x5_truncated_real_proof_yields_continue_not_a_verdict(eth_data):
    proof = eth_data["proof"]
    root = bytes.fromhex(eth_data["stateRoot"][2:])
    nodes = [bytes.fromhex(h[2:]) for h in proof["accountProof"]]
    with algopy_testing.algopy_testing_context():
        from contracts.mpt.state import mpt_key_from_address
        key = mpt_key_from_address(Bytes(bytes.fromhex(proof["address"][2:])))
        w = mpt_init_state(Bytes(root), key, UInt64(64))
        for node in nodes[:3]:  # supply only 3 of the real 8 nodes
            w, _voff, _vlen = mpt_walk_node(Bytes(node), w)
        assert int(w_status(w)) == WALK_CONTINUE
        assert int(w_status(w)) != WALK_INCLUDED
        for absent_code in (2, 3, 4, 5):
            assert int(w_status(w)) != absent_code, (
                "a truncated proof must never present as ANY terminal status")
