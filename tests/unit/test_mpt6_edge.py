"""
docs/design/006-account-storage-proof.md §11.2 S-M6-4, §11.3 X-M6-1/X-M6-2/
E-M6-2/E-M6-5. Covers the driver-level hand-off misuse cases and the
edge cases not already exercised in test_mpt6_bridge.py /
test_mpt6_handoff.py / test_mpt6_security.py.
"""
import algopy_testing
import pytest
from algopy import Bytes, UInt64, op

from contracts.composer.bridge import EMPTY_TRIE_ROOT, mpt6_bridge_account
from contracts.composer.handoff import SEGMENT_SELECTOR, mpt6_log_state, mpt6_result_from_group, mpt6_state_from_prev
from contracts.composer.state import (
    PHASE_A,
    PHASE_A_OK,
    PHASE_B,
    c_phase,
    c_storage_root,
    c_with_phase,
    mpt6_init_composite,
)
from contracts.mpt.state import WALK_INCLUDED, mpt_init_state, w_status
from contracts.mpt.walk import mpt_walk_node

SELECTOR = Bytes(SEGMENT_SELECTOR)
OTHER_SELECTOR = Bytes(b"XXXX")

_STATE_ROOT = bytes(range(32))
_ADDRESS = bytes(range(20))
_SLOT = bytes(range(32, 64))


def _w0():
    return mpt_init_state(Bytes(_STATE_ROOT), Bytes(bytes(range(32))[::-1]), UInt64(64))


def _mode_b_init_prologue(w_a, c):
    """Reproduces bench_app.py's MODE_B_INIT prologue exactly (§5.2 steps
    1-9, minus the group-hand-off recovery which callers do separately),
    so A15/A8 can be exercised as a focused unit test without spinning up
    the full Contract class."""
    assert int(c_phase(c)) == PHASE_A_OK, "A15"
    assert int(w_status(w_a)) == WALK_INCLUDED, "A16"
    assert bytes(w_a.value)[1:33] == bytes(c.value)[2:34], "A7"
    assert bytes(c_storage_root(c).value) != EMPTY_TRIE_ROOT, "A8"


# ---------------------------------------------------------------------------
# X-M6-1 / X-M6-2 -- a truncated walk yields NO verdict, twice.
# ---------------------------------------------------------------------------
def test_x_m6_1_truncated_phase_a_no_verdict():
    """A phase-A walk that never reached a terminal status leaves
    `C.phase == PHASE_A` -- `mpt6_result_from_group` must refuse it (A17),
    not report absence."""
    with algopy_testing.algopy_testing_context() as ctx:
        c = mpt6_init_composite(Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT))
        assert int(c_phase(c)) == PHASE_A
        log0 = mpt6_log_state(_w0(), c)
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A17"):
                mpt6_result_from_group(UInt64(0), Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT))


def test_x_m6_2_truncated_phase_b_no_verdict():
    """Same trap, one trie down: `C.phase == PHASE_B` (bridge fired,
    account included, but the storage walk never reached a terminal
    status) also yields no verdict."""
    with algopy_testing.algopy_testing_context() as ctx:
        c = mpt6_init_composite(Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT))
        c = c_with_phase(c, UInt64(PHASE_B))
        log0 = mpt6_log_state(_w0(), c)
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A17"):
                mpt6_result_from_group(UInt64(0), Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT))


# ---------------------------------------------------------------------------
# S-M6-4 -- MODE_B_INIT hand-off misuse, all four forms.
# ---------------------------------------------------------------------------
def test_s_m6_4a_prev_gi_points_at_a_later_transaction():
    with algopy_testing.algopy_testing_context() as ctx:
        log0 = mpt6_log_state(_w0(), mpt6_init_composite(Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT)))
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A11"):
                mpt6_state_from_prev(UInt64(1))  # points at itself, not a predecessor


def test_s_m6_4b_prev_gi_points_at_a_call_to_a_different_app():
    with algopy_testing.algopy_testing_context() as ctx:
        log0 = mpt6_log_state(_w0(), mpt6_init_composite(Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT)))
        this_app = ctx.any.application()
        other_app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=other_app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=this_app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A12"):
                mpt6_state_from_prev(UInt64(0))


def test_s_m6_4c_prev_gi_points_at_a_non_m6_transaction():
    """'A non-M6 transaction' -- a call to the RIGHT app that used a
    DIFFERENT selector (i.e. not a segment call at all, as far as
    `mpt6_state_from_prev` can tell -- the only on-chain signal it has)."""
    with algopy_testing.algopy_testing_context() as ctx:
        log0 = mpt6_log_state(_w0(), mpt6_init_composite(Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT)))
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(OTHER_SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A13"):
                mpt6_state_from_prev(UInt64(0))


def test_s_m6_4d_prev_gi_points_at_a_segment_still_in_phase_a():
    """The predecessor's hand-off recovery itself succeeds (A11-A14 all
    pass -- it IS a genuine M6 segment), but `MODE_B_INIT`'s own A15 check
    refuses it: phase A hasn't even bridged yet, let alone reached
    PHASE_A_OK."""
    with algopy_testing.algopy_testing_context() as ctx:
        c = mpt6_init_composite(Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT))
        assert int(c_phase(c)) == PHASE_A  # still walking, bridge never fired
        w0 = _w0()
        log0 = mpt6_log_state(w0, c)
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            w_rec, c_rec = mpt6_state_from_prev(UInt64(0))  # A11-A14 all pass
            with pytest.raises(AssertionError, match="A15"):
                _mode_b_init_prologue(w_rec, c_rec)


# ---------------------------------------------------------------------------
# E-M6-2 -- MODE_B_INIT forced against EMPTY_TRIE_ROOT.
# ---------------------------------------------------------------------------
def test_e_m6_2_mode_b_init_against_empty_trie_root_rejected():
    """§9.1's second side of the guard: even if a caller somehow reached
    MODE_B_INIT with `C.storage_root == EMPTY_TRIE_ROOT` (the bridge is
    supposed to have already terminated the composite in this case, §9.1's
    E-M6-1), MODE_B_INIT's own A8 check independently refuses to start a
    walk against it."""
    with algopy_testing.algopy_testing_context():
        c = mpt6_init_composite(Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT))
        c = c_with_phase(c, UInt64(PHASE_A_OK))
        c = op.replace(c, UInt64(86), Bytes(EMPTY_TRIE_ROOT))  # storage_root := EMPTY_TRIE_ROOT
        w_a = mpt_init_state(Bytes(_STATE_ROOT), Bytes(_ADDRESS + b"\x00" * 12), UInt64(64))
        # Give w_a a matching root/status so A7/A16 pass and A8 is what fires.
        w_a = op.replace(w_a, UInt64(0), Bytes(bytes([WALK_INCLUDED])))
        w_a = op.replace(w_a, UInt64(1), Bytes(_STATE_ROOT))
        with pytest.raises(AssertionError, match="A8"):
            _mode_b_init_prologue(w_a, c)


# ---------------------------------------------------------------------------
# E-M6-5 -- a one-node account proof: the bridge fires on the FIRST (and
# only) supplied node, in the same call, no second segment needed.
# ---------------------------------------------------------------------------
def test_e_m6_5_one_node_account_proof_bridges_in_a_single_hop():
    """A synthetic state trie of exactly one leaf, covering all 64 key
    nibbles from depth 0 (reachable on testnets/derived fixtures, §9.5 --
    not on mainnet, where USDT's account sits at depth 7). One
    `mpt_walk_node` call reaches WALK_INCLUDED directly; the bridge fires
    on that same node buffer with no second supplied node and no second
    transaction, exactly as §9.5 requires: 'the mode machine handles it
    with no special case'."""
    key = bytes(range(1, 33))
    compact_path = b"\x20" + key  # even-length leaf hex-prefix, all 64 nibbles
    sr = bytes(range(64, 96))
    ch = bytes(range(96, 128))
    account_body = bytes([0xF8, 0x44]) + b"\x01\x2a" + b"\xa0" + sr + b"\xa0" + ch
    leaf = (
        bytes([0xF8, 0x6A])
        + bytes([0x80 + 33]) + compact_path
        + bytes([0xB8, len(account_body)]) + account_body
    )
    with algopy_testing.algopy_testing_context():
        root = op.keccak256(Bytes(leaf))
        c = mpt6_init_composite(root, Bytes(bytes(20)), Bytes(bytes(32)))
        w0 = mpt_init_state(root, Bytes(key), UInt64(64))
        w1, voff, vlen = mpt_walk_node(Bytes(leaf), w0)
        assert int(w_status(w1)) == WALK_INCLUDED
        c1 = mpt6_bridge_account(c, w_status(w1), Bytes(leaf), voff, vlen)
        assert int(c_phase(c1)) == PHASE_A_OK
        assert bytes(c_storage_root(c1).value) == sr
