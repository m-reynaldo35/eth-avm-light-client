"""
docs/design/006-account-storage-proof.md §5.2 (`mpt6_state_from_prev`,
A11-A16) and §6.6 (`mpt6_result_from_group`, A17/A18, TP-M6-3). Structurally
mirrors `tests/unit/test_mpt_handoff.py`'s M5 coverage, extended to the
longer (W || C) payload and the composite-specific phase/header checks.
"""
import algopy_testing
import pytest
from algopy import Bytes, UInt64

from contracts.composer.handoff import (
    ARC4_RETURN_PREFIX,
    LOG_LEN_M6,
    SEGMENT_SELECTOR,
    mpt6_log_state,
    mpt6_result_from_group,
    mpt6_state_from_prev,
)
from contracts.composer.state import PHASE_A_OK, PHASE_DONE, c_address, c_phase, c_slot, c_state_root
from contracts.mpt.state import W_LEN, mpt_init_state, w_key, w_root

SELECTOR = Bytes(SEGMENT_SELECTOR)
OTHER_SELECTOR = Bytes(b"XXXX")

_STATE_ROOT = bytes(range(32))
_ADDRESS = bytes(range(20))
_SLOT = bytes(range(32, 64))


def _w0():
    return mpt_init_state(Bytes(_STATE_ROOT), Bytes(bytes(range(32))[::-1]), UInt64(64))


def _c0_done():
    """A fabricated terminal C with a realistic header, phase=PHASE_DONE."""
    from contracts.composer.state import mpt6_init_composite, c_with_phase
    c = mpt6_init_composite(Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT))
    return c_with_phase(c, UInt64(PHASE_DONE))


def _c0_phase_a_ok():
    from contracts.composer.state import mpt6_init_composite, c_with_phase
    c = mpt6_init_composite(Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT))
    return c_with_phase(c, UInt64(PHASE_A_OK))


def test_log_state_round_trip_shape():
    with algopy_testing.algopy_testing_context():
        w0 = _w0()
        c0 = _c0_done()
        log = mpt6_log_state(w0, c0)
        assert log.length == LOG_LEN_M6 == 355
        assert bytes(log.value[:4]) == ARC4_RETURN_PREFIX
        length_field = int.from_bytes(bytes(log.value[4:6]), "big")
        assert length_field == W_LEN + 248 == 349
        assert bytes(log.value[6:6 + W_LEN]) == bytes(w0.value)
        assert bytes(log.value[6 + W_LEN:]) == bytes(c0.value)


def test_honest_handoff_recovers_identical_w_and_c():
    with algopy_testing.algopy_testing_context() as ctx:
        w0 = _w0()
        c0 = _c0_done()
        log0 = mpt6_log_state(w0, c0)
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            w_rec, c_rec = mpt6_state_from_prev(UInt64(0))
        assert bytes(w_rec.value) == bytes(w0.value)
        assert bytes(c_rec.value) == bytes(c0.value)
        assert bytes(w_root(w_rec).value) == bytes(w_root(w0).value)
        assert bytes(w_key(w_rec).value) == bytes(w_key(w0).value)


def test_a11_predecessor_must_precede_this_transaction():
    with algopy_testing.algopy_testing_context() as ctx:
        log0 = mpt6_log_state(_w0(), _c0_done())
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A11"):
                mpt6_state_from_prev(UInt64(1))


def test_a12_predecessor_must_be_a_call_to_this_application():
    with algopy_testing.algopy_testing_context() as ctx:
        log0 = mpt6_log_state(_w0(), _c0_done())
        this_app = ctx.any.application()
        other_app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=other_app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=this_app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A12"):
                mpt6_state_from_prev(UInt64(0))


def test_a13_predecessor_must_have_used_segment_selector():
    with algopy_testing.algopy_testing_context() as ctx:
        log0 = mpt6_log_state(_w0(), _c0_done())
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(OTHER_SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A13"):
                mpt6_state_from_prev(UInt64(0))


def test_a14_forged_log_bytes_rejected():
    """S-M6-5: a predecessor to the right app with the right selector, but
    whose LastLog is not a well-formed 355-byte composite log -- exactly
    what a relayer forging depth/root/storage_root would have to produce."""
    with algopy_testing.algopy_testing_context() as ctx:
        app = ctx.any.application()
        forged = Bytes(b"\xff" * LOG_LEN_M6)
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(forged,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A14"):
                mpt6_state_from_prev(UInt64(0))


def test_a14_wrong_length_log_rejected():
    """S-M6-5's other half: a genuine M5-shaped 107-byte log (correct
    prefix, WRONG length for M6) presented where a 355-byte composite log
    is expected -- must be rejected, not silently truncated/misread."""
    with algopy_testing.algopy_testing_context() as ctx:
        app = ctx.any.application()
        short_log = Bytes(ARC4_RETURN_PREFIX + b"\x00\x65" + b"\x00" * 101)
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(short_log,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A14"):
                mpt6_state_from_prev(UInt64(0))


# ---------------------------------------------------------------------------
# §6.6 mpt6_result_from_group -- TP-M6-3, A17/A18.
# ---------------------------------------------------------------------------
def test_a17_incomplete_composite_yields_no_verdict():
    """X-M6-1/X-M6-2's structural defence: a recovered C whose phase is NOT
    PHASE_DONE (the walk never reached a terminal status) must be refused
    -- 'a walk that never reaches a terminal status yields no result at
    all', M5's X5 lifted to the composite."""
    with algopy_testing.algopy_testing_context() as ctx:
        c_pending = _c0_phase_a_ok()  # phase == PHASE_A_OK, not PHASE_DONE
        log0 = mpt6_log_state(_w0(), c_pending)
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A17"):
                mpt6_result_from_group(UInt64(0), Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT))


def test_a18_state_root_mismatch_rejected():
    with algopy_testing.algopy_testing_context() as ctx:
        log0 = mpt6_log_state(_w0(), _c0_done())
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        wrong_root = bytes(range(1, 33))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A18"):
                mpt6_result_from_group(UInt64(0), Bytes(wrong_root), Bytes(_ADDRESS), Bytes(_SLOT))


def test_a18_address_mismatch_rejected():
    """TP-M6-3's load-bearing half: this is exactly the check that defeats
    §5.4's residual attack (S-M6-3) -- a technically complete, correctly
    hash-chained composite about the WRONG address must be caught here."""
    with algopy_testing.algopy_testing_context() as ctx:
        log0 = mpt6_log_state(_w0(), _c0_done())
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        wrong_address = bytes(range(1, 21))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A18"):
                mpt6_result_from_group(UInt64(0), Bytes(_STATE_ROOT), Bytes(wrong_address), Bytes(_SLOT))


def test_a18_slot_mismatch_rejected():
    with algopy_testing.algopy_testing_context() as ctx:
        log0 = mpt6_log_state(_w0(), _c0_done())
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        wrong_slot = bytes(range(1, 33))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="A18"):
                mpt6_result_from_group(UInt64(0), Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(wrong_slot))


def test_result_from_group_accepts_matching_header_and_returns_cstatus_value():
    with algopy_testing.algopy_testing_context() as ctx:
        from contracts.composer.state import C_INCLUDED, c_cstatus, c_value
        from contracts.composer.bridge import mpt6_bridge_storage
        from contracts.mpt.state import WALK_INCLUDED
        c = _c0_phase_a_ok()
        node = bytes(31) + b"\x2a"  # RLP self-encoded byte 0x2a (< 0x80)
        c_terminal = mpt6_bridge_storage(c, UInt64(WALK_INCLUDED), Bytes(node), UInt64(31), UInt64(1))
        assert int(c_cstatus(c_terminal)) == C_INCLUDED
        log0 = mpt6_log_state(_w0(), c_terminal)
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            cstatus, value = mpt6_result_from_group(UInt64(0), Bytes(_STATE_ROOT), Bytes(_ADDRESS), Bytes(_SLOT))
        assert int(cstatus) == C_INCLUDED
        assert bytes(value.value) == b"\x00" * 31 + b"\x2a"
