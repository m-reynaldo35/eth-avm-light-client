"""
docs/design/005-mpt-walker.md §7.4: the segment hand-off verification. W13-
W16 exercised directly and offline (no live algod needed for the negative
cases -- algopy_testing's transaction-group emulation is sufficient); the
honest-hand-off-passes / forged-hand-off-rejected pair is also re-run live
against a real deployed contract in bench/mpt_bench.py (S8, per the design
doc's "must be re-demonstrated against the real contract").
"""
import algopy_testing
from algopy import Bytes, UInt64
import pytest

from contracts.mpt.handoff import ARC4_RETURN_PREFIX, LOG_LEN, mpt_log_state, mpt_state_from_prev
from contracts.mpt.state import mpt_init_state, w_key, w_root

SELECTOR = Bytes(b"MPT1")
OTHER_SELECTOR = Bytes(b"XXXX")


def _w0():
    return mpt_init_state(Bytes(bytes(range(32))), Bytes(bytes(range(32))[::-1]), UInt64(64))


def test_mpt_log_state_round_trip():
    with algopy_testing.algopy_testing_context():
        w0 = _w0()
        log = mpt_log_state(w0)
        assert log.length == LOG_LEN == 107
        assert bytes(log.value[:4]) == ARC4_RETURN_PREFIX
        assert bytes(log.value[6:]) == bytes(w0.value)


def test_honest_handoff_recovers_identical_state():
    with algopy_testing.algopy_testing_context() as ctx:
        w0 = _w0()
        log0 = mpt_log_state(w0)
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            recovered = mpt_state_from_prev(UInt64(0), SELECTOR)
        assert bytes(recovered.value) == bytes(w0.value)
        assert bytes(w_root(recovered).value) == bytes(w_root(w0).value)
        assert bytes(w_key(recovered).value) == bytes(w_key(w0).value)


def test_w13_predecessor_must_precede_this_transaction():
    """Pointing `gi` at yourself (or anything not strictly before you) is
    rejected -- a caller cannot claim to be its own predecessor."""
    with algopy_testing.algopy_testing_context() as ctx:
        w0 = _w0()
        log0 = mpt_log_state(w0)
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="W13"):
                mpt_state_from_prev(UInt64(1), SELECTOR)


def test_w14_predecessor_must_be_a_call_to_this_application():
    with algopy_testing.algopy_testing_context() as ctx:
        w0 = _w0()
        log0 = mpt_log_state(w0)
        this_app = ctx.any.application()
        other_app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=other_app, app_args=(SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=this_app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="W14"):
                mpt_state_from_prev(UInt64(0), SELECTOR)


def test_w15_predecessor_must_have_invoked_the_segment_method():
    with algopy_testing.algopy_testing_context() as ctx:
        w0 = _w0()
        log0 = mpt_log_state(w0)
        app = ctx.any.application()
        prev = ctx.any.txn.application_call(app_id=app, app_args=(OTHER_SELECTOR,), logs=(log0,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="W15"):
                mpt_state_from_prev(UInt64(0), SELECTOR)


def test_w16_forged_log_bytes_rejected():
    """The core forged-hand-off case: a predecessor transaction to the
    right app, with the right selector, but whose last log is NOT a
    well-formed walk-state log (wrong length or wrong ARC4 prefix) --
    exactly what an attacker forging depth/expected/key would have to
    produce if they could not simply overwrite the log itself (which they
    can't -- the log is the AVM's own execution record)."""
    with algopy_testing.algopy_testing_context() as ctx:
        app = ctx.any.application()
        forged = Bytes(b"\xff" * 107)
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(forged,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="W16"):
                mpt_state_from_prev(UInt64(0), SELECTOR)


def test_w16_wrong_length_log_rejected():
    with algopy_testing.algopy_testing_context() as ctx:
        app = ctx.any.application()
        short_log = Bytes(ARC4_RETURN_PREFIX + b"\x00\x0a" + b"\x00" * 10)
        prev = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,), logs=(short_log,))
        this = ctx.any.txn.application_call(app_id=app, app_args=(SELECTOR,))
        with ctx.txn.create_group([prev, this], active_txn_index=1):
            with pytest.raises(Exception, match="W16"):
                mpt_state_from_prev(UInt64(0), SELECTOR)
