"""
docs/design/006-account-storage-proof.md §11.1 suite A -- A-M6-1 (the
headline) and A-M6-2 (offline reference): the real USDT/Binance-8 composite,
driven end to end through M6's OWN decode path (`mpt6_bridge_account` /
`mpt6_account_body`), not M2's raw `rlp_scan`/`rlp_table_item` the way
`test_mpt_real_walks.py::test_a4_account_then_storage_composite` already
does. A-M6-2 is exactly that comparison: proving M6's own decode path
produces the identical `storageRoot` the pre-existing M5-level composite
test already established.

Every field in §11.1's pinned table is asserted here, not just "the walk
succeeded" -- per the design doc's own instruction that "a walk can succeed
for the wrong reason".
"""
import algopy_testing
from algopy import Bytes, UInt64

from contracts.composer.bridge import mpt6_bridge_account, mpt6_bridge_storage
from contracts.composer.state import (
    C_INCLUDED,
    PHASE_A_OK,
    PHASE_DONE,
    c_address,
    c_awalk,
    c_balance,
    c_code_hash,
    c_cstatus,
    c_nonce,
    c_phase,
    c_slot,
    c_state_root,
    c_storage_root,
    c_swalk,
    c_value,
    mpt6_init_composite,
)
from contracts.mpt.state import (
    WALK_INCLUDED,
    mpt_init_state,
    mpt_key_from_address,
    mpt_key_from_slot,
    w_status,
)
from contracts.mpt.walk import mpt_walk_node
from contracts.primitives.rlp.nibbles import nibble_at


def _drive_walk(root: bytes, key: bytes, nodes: list[bytes]):
    """Mirrors test_mpt_real_walks.py's `_walk_all`: drives mpt_walk_node
    across the full node list, recording each branch hop's derived index."""
    w = mpt_init_state(Bytes(root), Bytes(key), UInt64(64))
    indices = []
    last_node = None
    voff = vlen = UInt64(0)
    for i, node in enumerate(nodes):
        last_node = node
        from contracts.mpt.state import w_depth
        depth_before = int(w_depth(w))
        is_last = i == len(nodes) - 1
        if depth_before < 64 and not is_last:
            indices.append(int(nibble_at(Bytes(key), UInt64(depth_before))))
        w, voff, vlen = mpt_walk_node(Bytes(node), w)
    return w, last_node, voff, vlen, indices


def test_a_m6_1_headline_real_composite_via_mpt6_bridge(eth_data):
    proof = eth_data["proof"]
    address = bytes.fromhex(proof["address"][2:])
    state_root = bytes.fromhex(eth_data["stateRoot"][2:])
    account_nodes = [bytes.fromhex(h[2:]) for h in proof["accountProof"]]
    slot_preimage = bytes.fromhex(eth_data["storage_key"][2:])
    sp = proof["storageProof"][0]
    storage_nodes = [bytes.fromhex(h[2:]) for h in sp["proof"]]

    with algopy_testing.algopy_testing_context():
        akey = bytes(mpt_key_from_address(Bytes(address)).value)
        assert akey.hex() == "ab14d68802a763f7db875346d03fbf86f137de55814b191c069e721f47474733"

        c = mpt6_init_composite(Bytes(state_root), Bytes(address), Bytes(slot_preimage))
        assert int(c_phase(c)) == 0

        w_a, last_account_node, voff, vlen, a_indices = _drive_walk(state_root, akey, account_nodes)
        assert a_indices == [10, 11, 1, 4, 13, 6, 8], a_indices
        assert int(w_status(w_a)) == WALK_INCLUDED
        assert (voff, vlen) == (34, 70)

        c = mpt6_bridge_account(c, w_status(w_a), Bytes(last_account_node), voff, vlen)
        assert int(c_cstatus(c)) == 1  # C_PENDING_STORAGE
        assert int(c_phase(c)) == PHASE_A_OK
        assert bytes(c_storage_root(c).value).hex() == proof["storageHash"][2:]
        assert bytes(c_code_hash(c).value).hex() == proof["codeHash"][2:]
        assert bytes(c_nonce(c).value) == int(proof["nonce"], 16).to_bytes(32, "big")
        assert bytes(c_balance(c).value) == int(proof["balance"], 16).to_bytes(32, "big")
        assert int(c_awalk(c)) == WALK_INCLUDED

        # §5.2 step 6: the storage key is derived from C.slot (the PREIMAGE),
        # never from C.storage_root -- this is the exact on-chain step
        # MODE_B_INIT performs, reproduced here at the subroutine level.
        skey = bytes(mpt_key_from_slot(c_slot(c)).value)
        assert skey.hex() == "aa2813d62366783a4fc90e52c8cc595ba9fd2b278bc52248117c14c07e5394d8"

        w_b, last_storage_node, voff2, vlen2, s_indices = _drive_walk(
            bytes(c_storage_root(c).value), skey, storage_nodes)
        assert s_indices == [10, 10, 2, 8, 1, 3, 13, 6], s_indices
        assert int(w_status(w_b)) == WALK_INCLUDED
        assert (voff2, vlen2) == (32, 8)
        assert last_storage_node[voff2:voff2 + vlen2].hex() == "873f1ca131081cf8"

        c = mpt6_bridge_storage(c, w_status(w_b), Bytes(last_storage_node), voff2, vlen2)
        assert int(c_cstatus(c)) == C_INCLUDED
        assert int(c_phase(c)) == PHASE_DONE
        assert int(c_swalk(c)) == WALK_INCLUDED

        want_value = b"\x00" * 25 + bytes.fromhex("3f1ca131081cf8")
        assert bytes(c_value(c).value) == want_value

        # §3.3's self-describing header, TP-M6-3's basis.
        assert bytes(c_state_root(c).value) == state_root
        assert bytes(c_address(c).value) == address
        assert bytes(c_slot(c).value) == slot_preimage


def test_a_m6_2_offline_reference_matches_existing_m5_composite(eth_data):
    """A-M6-2: M6's own decode path (`mpt6_account_body`, via the bridge)
    must produce the IDENTICAL storageRoot that
    `test_mpt_real_walks.py::test_a4_account_then_storage_composite`
    already independently established by chaining the same two walks
    through M2's raw `rlp_scan`/`rlp_table_item`."""
    from tests.unit.test_mpt_real_walks import _walk_all

    proof = eth_data["proof"]
    address = bytes.fromhex(proof["address"][2:])
    root = bytes.fromhex(eth_data["stateRoot"][2:])
    account_nodes = [bytes.fromhex(h[2:]) for h in proof["accountProof"]]

    with algopy_testing.algopy_testing_context():
        key = bytes(mpt_key_from_address(Bytes(address)).value)
    status, account_rlp, _ = _walk_all(root, key, 64, account_nodes)
    assert status == WALK_INCLUDED

    with algopy_testing.algopy_testing_context():
        from contracts.primitives.rlp.core import rlp_scan, rlp_table_item
        data = Bytes(account_rlp)
        table, n = rlp_scan(data, UInt64(0))
        off2, len2, _k2 = rlp_table_item(data, table, UInt64(2))
        m2_storage_root = bytes(data.value)[int(off2):int(off2) + int(len2)]

    last_account_node = account_nodes[-1]

    # The real comparison: mpt6_account_body directly (M6's own decode).
    from contracts.composer.account import mpt6_account_body
    with algopy_testing.algopy_testing_context():
        storage_root_m6, _ch, _n32, _b32 = mpt6_account_body(Bytes(last_account_node), UInt64(34), UInt64(70))
        assert bytes(storage_root_m6.value) == m2_storage_root
