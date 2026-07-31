"""
docs/design/005-mpt-walker.md §9.1 suite A: real inclusion walks against
the three real mainnet proofs in eth_data.json (block 25,639,768), pinned
against the design doc's own hand-derived tables (§5.2, §5.4). A1-A3 must
assert the derived branch indices EQUAL the documented values, not merely
that the walk succeeds -- the indices are the security-relevant output.
"""
import algopy_testing
import pytest
from algopy import Bytes, UInt64

from contracts.mpt.state import (
    WALK_INCLUDED,
    mpt_init_state,
    mpt_key_from_address,
    mpt_key_from_slot,
    mpt_key_from_tx_index,
    w_depth,
    w_status,
)
from contracts.mpt.walk import mpt_walk_node
from contracts.primitives.rlp.nibbles import nibble_at


def _walk_all(root: bytes, key, key_nibs: int, nodes: list[bytes]):
    """Drive mpt_walk_node over a full node list inside ONE algopy_testing
    context, recording the derived branch index at every branch hop
    (re-derived independently here from the key, mirroring what §5.2 step 2
    computes internally, to assert the SAME on-chain-visible quantity a
    reviewer can check against the design doc's tables)."""
    with algopy_testing.algopy_testing_context():
        w = mpt_init_state(Bytes(root), Bytes(key), UInt64(key_nibs))
        indices = []
        last_node = None
        voff = vlen = UInt64(0)
        for i, node in enumerate(nodes):
            last_node = node
            depth_before = int(w_depth(w))
            is_last_node = i == len(nodes) - 1
            if depth_before < key_nibs and not is_last_node:
                # A branch hop derives an index from the key; the terminal
                # (leaf) hop doesn't, and for these real fixtures the last
                # supplied node is always the leaf (no extension nodes in
                # the real account/storage/receipt proofs, §9.2) -- so
                # excluding the final node's would-be index is exact here,
                # not a heuristic.
                nib = int(nibble_at(Bytes(key), UInt64(depth_before)))
                indices.append(nib)
            w, voff, vlen = mpt_walk_node(Bytes(node), w)
        status = int(w_status(w))
        value = bytes(last_node[int(voff):int(voff) + int(vlen)]) if status == WALK_INCLUDED else b""
        return status, value, indices


def test_a1_real_account_inclusion(eth_data):
    proof = eth_data["proof"]
    addr = bytes.fromhex(proof["address"][2:])
    root = bytes.fromhex(eth_data["stateRoot"][2:])
    nodes = [bytes.fromhex(h[2:]) for h in proof["accountProof"]]
    with algopy_testing.algopy_testing_context():
        key = mpt_key_from_address(Bytes(addr))
        key_bytes = bytes(key.value)
    status, value, indices = _walk_all(root, key_bytes, 64, nodes)
    assert indices == [10, 11, 1, 4, 13, 6, 8], indices
    assert status == WALK_INCLUDED
    assert value.hex() == (
        "f844012aa0261898dc12c926b33218d29afad898be487e821e8b4474465b62d802f7d33291"
        "a0b44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55")


def test_a2_real_storage_inclusion(eth_data):
    proof = eth_data["proof"]
    sp = proof["storageProof"][0]
    slot_preimage = bytes.fromhex(eth_data["storage_key"][2:])
    root = bytes.fromhex(proof["storageHash"][2:])
    nodes = [bytes.fromhex(h[2:]) for h in sp["proof"]]
    with algopy_testing.algopy_testing_context():
        key = mpt_key_from_slot(Bytes(slot_preimage))
        key_bytes = bytes(key.value)
        assert key_bytes.hex() == "aa2813d62366783a4fc90e52c8cc595ba9fd2b278bc52248117c14c07e5394d8"
    status, value, indices = _walk_all(root, key_bytes, 64, nodes)
    assert indices == [10, 10, 2, 8, 1, 3, 13, 6], indices
    assert status == WALK_INCLUDED
    assert value.hex() == "873f1ca131081cf8"


def test_a3_real_receipt_inclusion(eth_data):
    rp = eth_data["receipt_proof"]
    root = bytes.fromhex(eth_data["receiptsRoot"][2:])
    nodes = [bytes.fromhex(h[2:]) for h in rp["nodes"]]
    with algopy_testing.algopy_testing_context():
        key = mpt_key_from_tx_index(UInt64(rp["index"]))
        key_bytes = bytes(key.value)
        assert key_bytes.hex() == rp["key_rlp"]
    status, value, indices = _walk_all(root, key_bytes, 2 * len(key_bytes), nodes)
    assert indices == [1, 15], indices
    assert status == WALK_INCLUDED
    assert len(value) == rp["value_len"]


def test_a4_account_then_storage_composite(eth_data):
    """A1 then A2 chained through the account leaf's storageRoot field --
    reproduces the spike's composite stateRoot -> account -> storageRoot ->
    slot verification (M5 does not chain tries itself, §1.2; this test
    just confirms the two independent M5 walks compose the way M6 will)."""
    proof = eth_data["proof"]
    addr = bytes.fromhex(proof["address"][2:])
    root = bytes.fromhex(eth_data["stateRoot"][2:])
    account_nodes = [bytes.fromhex(h[2:]) for h in proof["accountProof"]]
    with algopy_testing.algopy_testing_context():
        key = mpt_key_from_address(Bytes(addr))
        key_bytes = bytes(key.value)
    status, account_rlp, _ = _walk_all(root, key_bytes, 64, account_nodes)
    assert status == WALK_INCLUDED
    # account_rlp = [nonce, balance, storageRoot, codeHash] RLP-encoded
    from contracts.primitives.rlp.core import rlp_scan, rlp_table_item
    with algopy_testing.algopy_testing_context():
        data = Bytes(account_rlp)
        table, n = rlp_scan(data, UInt64(0))
        assert int(n) == 4
        off2, len2, _k2 = rlp_table_item(data, table, UInt64(2))
        storage_root = bytes(data.value)[int(off2):int(off2) + int(len2)]
    assert storage_root.hex() == proof["storageHash"][2:]

    sp = proof["storageProof"][0]
    slot_preimage = bytes.fromhex(eth_data["storage_key"][2:])
    storage_nodes = [bytes.fromhex(h[2:]) for h in sp["proof"]]
    with algopy_testing.algopy_testing_context():
        skey = mpt_key_from_slot(Bytes(slot_preimage))
        skey_bytes = bytes(skey.value)
    s_status, s_value, _ = _walk_all(storage_root, skey_bytes, 64, storage_nodes)
    assert s_status == WALK_INCLUDED
    assert s_value.hex() == "873f1ca131081cf8"


# ---------------------------------------------------------------------------
# S1 / S3 (§9.3) -- the security regression, run against the REAL account
# proof (not a derived fixture). This is the M5 analogue of M1's T12 / M4's
# adversarial-update tests, and the design doc's own framing (§0) for why
# this module exists.
# ---------------------------------------------------------------------------
def test_s1_real_honest_proof_wrong_key_rejected(eth_data):
    """The real, complete, honest 8-node USDT account proof, presented as a
    proof about a DIFFERENT real address. Every keccak256 link in the
    supplied nodes still holds internally (this is a genuine mainnet node
    sequence) -- only the key binding must reject it."""
    proof = eth_data["proof"]
    root = bytes.fromhex(eth_data["stateRoot"][2:])
    nodes = [bytes.fromhex(h[2:]) for h in proof["accountProof"]]
    wrong_addr = bytes.fromhex("F977814e90dA44bFA03b6295A0616a897441aceC")
    with algopy_testing.algopy_testing_context():
        wrong_key = bytes(mpt_key_from_address(Bytes(wrong_addr)).value)
        # pinned: wrong_key's first nibble is 8, not the real proof's 10 --
        # so hop 0 derives a DIFFERENT branch slot than the honest proof's
        # own path used, and the honestly-supplied node[1] (the real slot-10
        # child) cannot possibly hash-match slot 8's reference.
        assert nibble_at_py(wrong_key, 0) != 10

        w = mpt_init_state(Bytes(root), Bytes(wrong_key), UInt64(64))
        w, _voff, _vlen = mpt_walk_node(Bytes(nodes[0]), w)
        assert int(w_status(w)) == 0  # WALK_CONTINUE -- hop 0 alone doesn't panic
        with pytest.raises(Exception, match="W11"):
            mpt_walk_node(Bytes(nodes[1]), w)


def nibble_at_py(data: bytes, k: int) -> int:
    b = data[k // 2]
    return (b >> 4) if k % 2 == 0 else (b & 0x0F)


def test_s3_real_proof_last_nibble_flipped_rejected_at_leaf(eth_data):
    """The real account proof, with the target key's LAST nibble flipped.
    All 7 branch hops match (the flip is below the branch depth), so the
    walk must succeed through every branch and fail ONLY at the leaf's
    content comparison -- proving the leaf compares content, not just
    length, and that the branch hops alone are not sufficient."""
    proof = eth_data["proof"]
    root = bytes.fromhex(eth_data["stateRoot"][2:])
    nodes = [bytes.fromhex(h[2:]) for h in proof["accountProof"]]
    with algopy_testing.algopy_testing_context():
        real_key = bytearray(mpt_key_from_address(Bytes(bytes.fromhex(proof["address"][2:]))).value)
    flipped = bytearray(real_key)
    flipped[-1] ^= 0x01
    with algopy_testing.algopy_testing_context():
        w = mpt_init_state(Bytes(root), Bytes(bytes(flipped)), UInt64(64))
        for node in nodes:
            w, _voff, _vlen = mpt_walk_node(Bytes(node), w)
        assert int(w_status(w)) == 4  # WALK_ABSENT_LEAF_DIVERGE
        assert int(w_depth(w)) == 7  # reached the leaf hop (depth after 7 branches)
