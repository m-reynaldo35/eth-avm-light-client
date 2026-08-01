"""
docs/design/006-account-storage-proof.md §5.4, §11.2 suite S -- the
mandatory security regression tests. §5.4 traces ONE attack in detail (a
relayer with an honest, complete, correctly hash-chained proof for a
DIFFERENT trie trying to get it accepted as the target's storage) and one
residual (a genuinely valid composite about the WRONG contract). This file
is M6's whole reason to exist, restated as tests.

S-M6-2's "a second real contract's fixture data" note: `eth_data.json`
(pulled once, offline, from a single `eth_getProof` call) contains exactly
ONE contract's storage proof (USDT/Binance-8). There is no live RPC access
in this environment to pull a second real `eth_getProof`. Per the task's
own documented fallback ("a second real contract's fixture data if
available ... or derive a second realistic fixture if not"), S-M6-2 below
substitutes the real, honest, fully hash-chained 3-node RECEIPT proof from
the SAME eth_data.json pull -- genuine mainnet bytes, genuinely hash-chained
to a genuine Ethereum root (`receiptsRoot`), just a different trie/root than
USDT's `storageHash`. This is arguably a STRONGER demonstration than a
second account's storage proof would be: it proves the defence is not
"proof shaped like account storage" but "hash-chained to the wrong root",
exactly the mechanism M5's W11 is (§5.4's own argument: "There is no
argument, field, or transaction the relayer can vary to change
`W_B.expected` short of producing a preimage collision on keccak256").
"""
import algopy_testing
import pytest
from algopy import Bytes, UInt64

from contracts.composer.bridge import mpt6_bridge_account
from contracts.composer.handoff import mpt6_result_from_group, mpt6_state_from_prev, mpt6_log_state, SEGMENT_SELECTOR
from contracts.composer.state import (
    C_PENDING_STORAGE,
    PHASE_A_OK,
    PHASE_DONE,
    c_phase,
    c_slot,
    c_state_root,
    c_storage_root,
    mpt6_init_composite,
    c_with_phase,
)
from contracts.mpt.state import (
    WALK_INCLUDED,
    mpt_init_state,
    mpt_key_from_address,
    mpt_key_from_slot,
    mpt_key_from_tx_index,
    w_status,
)
from contracts.mpt.walk import mpt_walk_node

SELECTOR = Bytes(SEGMENT_SELECTOR)


def _real_account_walk(eth_data):
    """Drive the real, honest, complete USDT account walk to WALK_INCLUDED,
    bridge it, and return the resulting C (cstatus=C_PENDING_STORAGE,
    phase=PHASE_A_OK, storage_root = the real USDT storageHash)."""
    proof = eth_data["proof"]
    address = bytes.fromhex(proof["address"][2:])
    state_root = bytes.fromhex(eth_data["stateRoot"][2:])
    slot_preimage = bytes.fromhex(eth_data["storage_key"][2:])
    account_nodes = [bytes.fromhex(h[2:]) for h in proof["accountProof"]]

    key = mpt_key_from_address(Bytes(address))
    w = mpt_init_state(Bytes(state_root), key, UInt64(64))
    last_node = None
    voff = vlen = UInt64(0)
    for node in account_nodes:
        last_node = node
        w, voff, vlen = mpt_walk_node(Bytes(node), w)
    assert int(w_status(w)) == WALK_INCLUDED

    c = mpt6_init_composite(Bytes(state_root), Bytes(address), Bytes(slot_preimage))
    c = mpt6_bridge_account(c, w_status(w), Bytes(last_node), voff, vlen)
    assert int(c_phase(c)) == PHASE_A_OK
    assert int(c.value[0]) == C_PENDING_STORAGE  # cstatus byte, sanity
    return c, state_root, address, slot_preimage


# ---------------------------------------------------------------------------
# S-M6-2 -- THE test M6 exists for.
# ---------------------------------------------------------------------------
def test_s_m6_2_honest_different_trie_proof_rejected_at_w11(eth_data):
    """The relayer holds a genuine phase-A result for USDT (C.storage_root
    = the real USDT storageHash), and an HONEST, COMPLETE, fully
    hash-chained real mainnet MPT proof for a DIFFERENT trie (the 3-node
    receipt proof, root = receiptsRoot != USDT's storageHash). Attempting
    to walk it as phase B, using `mpt_init_state(C.storage_root, ...)`
    exactly as MODE_B_INIT does, must reject the FIRST node with M5's
    W11 -- 'keccak256(node) != expected' -- because the node's real hash
    does not equal `C.storage_root`."""
    with algopy_testing.algopy_testing_context():
        c, _state_root, _address, _slot = _real_account_walk(eth_data)
        storage_root = c_storage_root(c)

        rp = eth_data["receipt_proof"]
        wrong_trie_nodes = [bytes.fromhex(h[2:]) for h in rp["nodes"]]
        wrong_trie_key = mpt_key_from_tx_index(UInt64(rp["index"]))

        # Exactly MODE_B_INIT's step 7: mpt_init_state(C.storage_root, skey, 64).
        # (key_nibs is 64 in the real MODE_B_INIT since it always derives a
        # keccak256 storage key; using the receipt key's own natural nibble
        # count here doesn't matter -- the rejection happens at the FIRST
        # node's hash check, before any key-nibble comparison is reached.)
        w_b = mpt_init_state(storage_root, wrong_trie_key, UInt64(64))
        with pytest.raises(Exception, match="W11"):
            mpt_walk_node(Bytes(wrong_trie_nodes[0]), w_b)


def test_s_m6_2_spike_oracle_the_same_node_sequence_WOULD_have_passed(eth_data):
    """M5 §9.3's rule, quoted in the design doc: 'a rejection test that
    does not demonstrate the old code passing is not a regression test for
    this bug.' Demonstrates the naive/insecure composer's failure mode
    directly: if `storageRoot` were taken as a caller argument (the spike's
    own approach, §5.5's rejected alternative) instead of read from `C`,
    the IDENTICAL honest receipt-proof node sequence walks to WALK_INCLUDED
    against ITS OWN (correct) root -- proving the attack is not "the nodes
    are dishonest", it's "the root was forgeable"."""
    rp = eth_data["receipt_proof"]
    receipts_root = bytes.fromhex(eth_data["receiptsRoot"][2:])
    nodes = [bytes.fromhex(h[2:]) for h in rp["nodes"]]
    with algopy_testing.algopy_testing_context():
        key = mpt_key_from_tx_index(UInt64(rp["index"]))
        w = mpt_init_state(Bytes(receipts_root), key, UInt64(2) * key.length)
        for node in nodes:
            w, _voff, _vlen = mpt_walk_node(Bytes(node), w)
        assert int(w_status(w)) == WALK_INCLUDED  # the "naive composer" would have accepted this


# ---------------------------------------------------------------------------
# S-M6-1 -- structural: MODE_B_INIT's own recovery subroutine takes no
# root/key/storageRoot/slot argument at all.
# ---------------------------------------------------------------------------
def test_s_m6_1_state_from_prev_takes_no_root_or_slot_argument():
    import inspect
    sig = inspect.signature(mpt6_state_from_prev)
    assert list(sig.parameters) == ["gi"], (
        "mpt6_state_from_prev must take ONLY a group index -- any additional "
        "parameter here would be a caller-suppliable channel for storage_root, "
        "exactly the attack §5.4 traces")


def test_s_m6_1_no_forbidden_parameter_names_on_handoff_entry_points():
    import inspect
    forbidden = ("root", "storage_root", "key", "slot", "storageroot")
    # mpt6_result_from_group's want_* parameters are the CONSUMER's
    # expectation to check against, not a value used to build a walk state
    # -- explicitly exempted, exactly like M5's test_mpt_structural.py
    # exempts mpt_descend's `want`.
    exempt = {"want_state_root", "want_address", "want_slot"}
    for fn in (mpt6_state_from_prev,):
        for name in inspect.signature(fn).parameters:
            if name in exempt:
                continue
            lowered = name.lower()
            for f in forbidden:
                assert f not in lowered, f"{fn.__qualname__} has forbidden parameter '{name}'"


# ---------------------------------------------------------------------------
# S-M6-3 -- the residual: a genuinely valid composite about the WRONG
# contract, defeated by the CALLER's own TP-M6-3 check, not by M6 itself.
# ---------------------------------------------------------------------------
def test_s_m6_3_wrong_contract_composite_is_true_but_rejected_by_consumer(eth_data):
    """A relayer runs TWO honest phase-A walks in one group -- the real
    USDT one, and a second, fabricated-but-internally-consistent phase-A
    result for a DIFFERENT address (eth_data.json contains only USDT's real
    account proof, so per the task's documented fallback a second address's
    phase-A/phase-B segments are synthesized directly at the C level rather
    than sourced from a second real eth_getProof -- what's under test here
    is entirely `mpt6_result_from_group`'s header check, which does not
    depend on either walk's own soundness, only on `C.address`).
    `MODE_B_INIT` then points `prev_gi` at the WRONG one. Both halves of
    §5.4's claim, exactly as it states them:
    (a) the hand-off itself is structurally valid against the wrong
        segment too -- A11-A16 all pass for `gi` pointing at the OTHER
        address's phase-A segment, exactly as they would for USDT's;
    (b) a genuinely COMPLETE (`PHASE_DONE`) composite for the wrong
        address is a TRUE statement about that address (accepted when the
        consumer asks about `other_address`) but is rejected with A18 when
        the consumer asks about `usdt_address` -- the check that resolves
        the substitution belongs to the consumer (TP-M6-3), and only it."""
    from algopy import op

    proof = eth_data["proof"]
    usdt_address = bytes.fromhex(proof["address"][2:])
    state_root = bytes.fromhex(eth_data["stateRoot"][2:])
    slot_preimage = bytes.fromhex(eth_data["storage_key"][2:])
    other_address = bytes.fromhex("F977814e90dA44bFA03b6295A0616a897441aceC")

    with algopy_testing.algopy_testing_context() as ctx:
        c_usdt, _sr, _addr, _slot = _real_account_walk(eth_data)
        w0 = mpt_init_state(Bytes(state_root), Bytes(bytes(32)), UInt64(64))
        log_usdt = mpt6_log_state(w0, c_usdt)

        # The other address's phase-A-in-progress segment (mid-composite --
        # what MODE_B_INIT's own recovery step would see).
        c_other_mid = mpt6_init_composite(Bytes(state_root), Bytes(other_address), Bytes(slot_preimage))
        c_other_mid = c_with_phase(c_other_mid, UInt64(PHASE_A_OK))
        c_other_mid = op.replace(c_other_mid, UInt64(86), Bytes(bytes(range(32))))
        log_other_mid = mpt6_log_state(w0, c_other_mid)

        # The other address's TERMINAL segment -- a genuinely COMPLETE,
        # correctly-shaped composite (as if phase B had also run to
        # completion for it): PHASE_DONE, cstatus=C_INCLUDED, a value.
        from contracts.composer.state import C_INCLUDED
        c_other_done = op.replace(c_other_mid, UInt64(1), Bytes(bytes([PHASE_DONE])))
        c_other_done = op.replace(c_other_done, UInt64(0), Bytes(bytes([C_INCLUDED])))
        c_other_done = op.replace(c_other_done, UInt64(214), Bytes(bytes(range(1, 33))))
        log_other_done = mpt6_log_state(w0, c_other_done)

        app = ctx.any.application()
        seg0 = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log_usdt,))
        seg1 = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log_other_mid,))
        seg2 = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log_other_done,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([seg0, seg1, seg2, this], active_txn_index=3):
            # (a) the hand-off itself succeeds against the WRONG segment --
            # A11-A16 all pass for gi=1, exactly as they would for gi=0.
            w_rec, c_rec = mpt6_state_from_prev(UInt64(1))
            assert int(c_phase(c_rec)) == PHASE_A_OK
            assert bytes(c_rec.value)[34:54] == other_address  # C.address, raw offset per §3.3

            # (b) the terminal wrong-contract composite IS a true statement
            # about the OTHER address -- accepted when asked about it.
            cstatus, _value = mpt6_result_from_group(
                UInt64(2), Bytes(state_root), Bytes(other_address), Bytes(slot_preimage))
            assert int(cstatus) == C_INCLUDED

            # ...but rejected with A18 when asked about USDT -- the ONLY
            # thing that catches the substitution, exactly as §5.4 states.
            with pytest.raises(Exception, match="A18"):
                mpt6_result_from_group(UInt64(2), Bytes(state_root), Bytes(usdt_address), Bytes(slot_preimage))
