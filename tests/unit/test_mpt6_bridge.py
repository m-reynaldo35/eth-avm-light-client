"""
docs/design/006-account-storage-proof.md §5.1 (the bridge), §8.1
(C_ABSENT_ACCOUNT), §8.2 (C_ABSENT_SLOT), §9.1 (the empty-trie
short-circuit -- E-M6-1, E-M6-2), §9.2 (C_ZERO_ENTRY). Exercises
`mpt6_bridge_account`/`mpt6_bridge_storage` directly against the real
composite state produced by `mpt6_init_composite`, using the SAME real
account leaf `test_mpt6_account_body.py` already pins.
"""
import algopy_testing
from algopy import Bytes, UInt64

from contracts.composer.bridge import EMPTY_CODE_HASH, EMPTY_TRIE_ROOT, mpt6_bridge_account, mpt6_bridge_storage
from contracts.composer.state import (
    C_ABSENT_ACCOUNT,
    C_ABSENT_SLOT,
    C_ABSENT_SLOT_EMPTY_TRIE,
    C_INCLUDED,
    C_PENDING_ACCOUNT,
    C_PENDING_STORAGE,
    C_ZERO_ENTRY,
    PHASE_A,
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
    WALK_ABSENT_LEAF_DIVERGE,
    WALK_INCLUDED,
)

_STATE_ROOT = bytes(range(32))
_ADDRESS = bytes(range(20))
_SLOT = bytes(range(32, 64))


def _c0():
    return mpt6_init_composite(Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT))


def test_bridge_account_included_real_body(eth_data):
    """§5.1 step 3: WALK_INCLUDED fires the real account-body decode and
    writes storage_root/code_hash/nonce/balance, transitioning to
    C_PENDING_STORAGE / PHASE_A_OK -- using the real USDT account leaf."""
    node = bytes.fromhex(eth_data["proof"]["accountProof"][7][2:])
    proof = eth_data["proof"]
    with algopy_testing.algopy_testing_context():
        c0 = _c0()
        c1 = mpt6_bridge_account(c0, UInt64(WALK_INCLUDED), Bytes(node), UInt64(34), UInt64(70))
        assert int(c_cstatus(c1)) == C_PENDING_STORAGE
        assert int(c_phase(c1)) == PHASE_A_OK
        assert bytes(c_storage_root(c1).value).hex() == proof["storageHash"][2:]
        assert bytes(c_code_hash(c1).value).hex() == proof["codeHash"][2:]
        assert bytes(c_nonce(c1).value) == int(proof["nonce"], 16).to_bytes(32, "big")
        assert bytes(c_balance(c1).value) == int(proof["balance"], 16).to_bytes(32, "big")
        # IMMUTABLE fields survive the bridge untouched.
        assert bytes(c_state_root(c1).value) == _STATE_ROOT
        assert bytes(c_address(c1).value) == _ADDRESS
        assert bytes(c_slot(c1).value) == _SLOT
        assert int(c_awalk(c1)) == WALK_INCLUDED


def test_bridge_account_absent_x_m6_1_style():
    """§8.1: any WALK_ABSENT_* status terminates the composite immediately
    with the consensus-defined non-existent-account constants -- no phase
    B, node bytes not even consulted."""
    with algopy_testing.algopy_testing_context():
        c0 = _c0()
        c1 = mpt6_bridge_account(c0, UInt64(WALK_ABSENT_LEAF_DIVERGE), Bytes(b"\x00"), UInt64(0), UInt64(0))
        assert int(c_cstatus(c1)) == C_ABSENT_ACCOUNT
        assert int(c_phase(c1)) == PHASE_DONE
        assert bytes(c_storage_root(c1).value) == EMPTY_TRIE_ROOT
        assert bytes(c_code_hash(c1).value) == EMPTY_CODE_HASH
        assert bytes(c_nonce(c1).value) == b"\x00" * 32
        assert bytes(c_balance(c1).value) == b"\x00" * 32
        assert bytes(c_value(c1).value) == b"\x00" * 32
        assert int(c_awalk(c1)) == WALK_ABSENT_LEAF_DIVERGE
        # Immutable header fields still present -- a consumer CAN check
        # C.address even for an absent account (TP-M6-3 doesn't require
        # inclusion).
        assert bytes(c_address(c1).value) == _ADDRESS


def test_e_m6_1_empty_storage_trie_short_circuit():
    """E-M6-1/§9.1: an account whose real body's storageRoot equals
    EMPTY_TRIE_ROOT terminates AT THE BRIDGE with C_ABSENT_SLOT_EMPTY_TRIE,
    PHASE_DONE, zero phase-B segments -- proving the special case actually
    fires rather than falling through to phase B (which §9.1 shows would
    abort inside M2 with 'R1')."""
    # A derived, well-formed 4-item account body whose storageRoot IS
    # EMPTY_TRIE_ROOT (any real EOA, or an untouched contract).
    body_payload = b"\x01\x2a" + b"\xa0" + EMPTY_TRIE_ROOT + b"\xa0" + EMPTY_CODE_HASH
    node = bytes([0xF8, len(body_payload)]) + body_payload  # long-form header (payload > 55 B)
    with algopy_testing.algopy_testing_context():
        c0 = _c0()
        c1 = mpt6_bridge_account(c0, UInt64(WALK_INCLUDED), Bytes(node), UInt64(0), UInt64(len(node)))
        assert int(c_cstatus(c1)) == C_ABSENT_SLOT_EMPTY_TRIE
        assert int(c_phase(c1)) == PHASE_DONE
        assert bytes(c_storage_root(c1).value) == EMPTY_TRIE_ROOT
        assert bytes(c_value(c1).value) == b"\x00" * 32


def test_e_m6_1_starting_phase_b_against_empty_trie_would_abort_r1():
    """E-M6-1's second half: demonstrate the special case is load-bearing,
    not cosmetic -- starting a REAL M5 walk against EMPTY_TRIE_ROOT with the
    only node that can possibly hash to it (the single byte 0x80) aborts
    inside M2's rlp_list_header with 'R1', NOT a defined M5 absence code.
    This is exactly why §5.1/§9.1 special-case it before phase B exists."""
    import pytest
    from contracts.mpt.state import mpt_init_state
    from contracts.mpt.walk import mpt_walk_node
    with algopy_testing.algopy_testing_context():
        w0 = mpt_init_state(Bytes(EMPTY_TRIE_ROOT), Bytes(_SLOT), UInt64(64))
        with pytest.raises(Exception, match="R1"):
            mpt_walk_node(Bytes(b"\x80"), w0)


def test_bridge_storage_included_real_value(eth_data):
    """§4.4/§8.2: WALK_INCLUDED on the storage walk normalises the real
    Binance-8 value and sets C_INCLUDED, PHASE_DONE."""
    sp = eth_data["proof"]["storageProof"][0]
    node = bytes.fromhex(sp["proof"][8][2:])
    with algopy_testing.algopy_testing_context():
        c0 = _c0()
        c1 = mpt6_bridge_storage(c0, UInt64(WALK_INCLUDED), Bytes(node), UInt64(32), UInt64(8))
        assert int(c_cstatus(c1)) == C_INCLUDED
        assert int(c_phase(c1)) == PHASE_DONE
        want = int(sp["value"], 16).to_bytes(32, "big")
        assert bytes(c_value(c1).value) == want
        assert int(c_swalk(c1)) == WALK_INCLUDED


def test_bridge_storage_absent_slot():
    """§8.2: any WALK_ABSENT_* on the storage walk is C_ABSENT_SLOT, value
    stays 32 zero bytes -- 'absent <=> zero', a normal positive result."""
    with algopy_testing.algopy_testing_context():
        c0 = _c0()
        c1 = mpt6_bridge_storage(c0, UInt64(WALK_ABSENT_LEAF_DIVERGE), Bytes(b"\x00"), UInt64(0), UInt64(0))
        assert int(c_cstatus(c1)) == C_ABSENT_SLOT
        assert int(c_phase(c1)) == PHASE_DONE
        assert bytes(c_value(c1).value) == b"\x00" * 32
        assert int(c_swalk(c1)) == WALK_ABSENT_LEAF_DIVERGE


def test_e_m6_4_bridge_zero_entry():
    """E-M6-4/§9.2: a storage leaf whose value item is the RLP empty string
    is C_ZERO_ENTRY, not C_ABSENT_SLOT -- distinguishable via `cstatus`
    even though both carry a zero `C.value`."""
    node = bytes(31) + b"\x80"
    with algopy_testing.algopy_testing_context():
        c0 = _c0()
        c1 = mpt6_bridge_storage(c0, UInt64(WALK_INCLUDED), Bytes(node), UInt64(31), UInt64(1))
        assert int(c_cstatus(c1)) == C_ZERO_ENTRY
        assert bytes(c_value(c1).value) == b"\x00" * 32


def test_c0_starts_pending_account_phase_a():
    with algopy_testing.algopy_testing_context():
        c0 = _c0()
        assert int(c_phase(c0)) == PHASE_A
        assert int(c_cstatus(c0)) == C_PENDING_ACCOUNT
        assert bytes(c_state_root(c0).value) == _STATE_ROOT
        assert bytes(c_address(c0).value) == _ADDRESS
        assert bytes(c_slot(c0).value) == _SLOT
        assert bytes(c_storage_root(c0).value) == b"\x00" * 32
        assert bytes(c_value(c0).value) == b"\x00" * 32
