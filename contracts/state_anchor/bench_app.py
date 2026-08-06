"""contracts/state_anchor/bench_app.py -- test-only infrastructure for M8's
live/security suites. NEVER deploy to mainnet (mirrors every other module's
own bench_app.py in this codebase).

Three probes:

  * `M4Probe` -- a minimal stand-in for M4's global state
    (`fin_slot`/`fin_root`/`fin_state_root`), settable by ANY sender (this
    is a TEST harness, not a security boundary of its own). Used two ways:
    (a) the HONEST case, set to real values so M8's own bridge logic can be
    exercised without paying for a full real BLS-verified M4 install on
    every test; (b) the S-M4 adversarial case (§11 S3, TP-M8-7) -- deploy
    one of these, point `TrustedRootAnchor.anchor_direct`'s `m4_app`
    argument at it, and confirm `N4` fires because `m4_app.id != self.m4`
    (the immutable global set at M8's OWN `create()`), regardless of what
    this probe's globals say.
  * `FakeAnchor` -- §11 S4 / TP-M8-4: an ARC4Contract exposing an
    `attest(uint64)` method with the IDENTICAL selector and a VALID ARC-4
    return envelope, returning an attacker-chosen 154-byte record.
    `handoff.ANCHOR_APP_ID` being a compile-time constant (not reachable
    from this probe's app id) is what makes a consumer built against
    `handoff.py` reject it via `N2` -- proven in
    `tests/state_anchor/test_security.py`'s `test_forged_app_id_rejected`.
  * `AnchorReceiptProbe` -- the real §9.2 proof. Combines M7's OWN,
    UNMODIFIED receipt-walk subroutines (`contracts.receipt.*`, imported
    read-only, never edited) with M8's `mpt7_result_against_anchor`
    (`contracts/state_anchor/handoff.py`) in ONE new deployed app, so the
    same-app assert inside `mpt7_result_from_group`'s `mpt7_state_from_prev`
    (`prev.app_id == Global.current_application_id`) is satisfied by
    construction: the walk and the anchor-bound result check are two modes
    of the SAME app, exactly mirroring how `Mpt7ReceiptApp` itself chains
    MODE_INIT -> MODE_NEXT. This is real, compiled, ARC-4-free-args code
    (M7's own convention, §8.1's reasoning) proving the actual security
    property M8 exists to add -- without touching a single line of
    `contracts/receipt/*.py`.
"""

import typing

from algopy import ARC4Contract, Bytes, Contract, Txn, UInt64, arc4, log, op, subroutine

from contracts.mpt.state import (
    WALK_ABSENT_BRANCH_TERM,
    WALK_ABSENT_EMPTY_SLOT,
    WALK_ABSENT_EXT_DIVERGE,
    WALK_ABSENT_LEAF_DIVERGE,
    WALK_CONTINUE,
    WALK_INCLUDED,
    mpt_init_state,
    mpt_key_from_tx_index,
    w_status,
)
from contracts.mpt.walk import mpt_walk_node
from contracts.receipt.decode import mpt7_log_at, mpt7_receipt_body
from contracts.receipt.handoff import SEGMENT_SELECTOR, mpt7_log_state, mpt7_state_from_prev
from contracts.receipt.state import (
    R_ABSENT,
    R_INCLUDED,
    R_NO_SUCH_LOG,
    R_ZERO_LOGS,
    mpt7_init_result,
    r_log_index,
    r_rstatus,
    r_with_terminal,
)
from contracts.state_anchor.constants import ARC4_RETURN_PREFIX, RECORD_LEN, VERSION_1
from contracts.state_anchor.handoff import ATTEST_SELECTOR, mpt7_result_against_anchor

# re-export for convenience of test harnesses that only need budget donors
from contracts.sync_committee.bench_app import DonorCallee, DonorIssuer  # noqa: F401


class M4Probe(ARC4Contract, avm_version=10):
    """NOT M4. A settable stand-in exposing the exact three global-state
    keys M8's `bridge.read_m4_finalized` reads (`fin_slot`/`fin_root`/
    `fin_state_root`) -- see this module's own docstring for the two ways
    it is used."""

    @arc4.abimethod(create="require")
    def create(self) -> None:
        self.fin_slot = UInt64(0)
        self.fin_root = op.bzero(UInt64(32))
        self.fin_state_root = op.bzero(UInt64(32))

    @arc4.abimethod
    def set_finalized(
        self, fin_slot: arc4.UInt64, fin_root: arc4.StaticArray[arc4.Byte, typing.Literal[32]], fin_state_root: arc4.StaticArray[arc4.Byte, typing.Literal[32]]
    ) -> None:
        self.fin_slot = fin_slot.native
        self.fin_root = fin_root.bytes
        self.fin_state_root = fin_state_root.bytes


class FakeAnchor(ARC4Contract, avm_version=10):
    """§11 S4 / TP-M8-4 adversarial probe: an `attest`-shaped method with
    the identical 4-byte selector (`handoff.ATTEST_SELECTOR`) and a valid
    ARC-4 return envelope, returning WHATEVER 154-byte record the caller
    supplies at call time -- i.e. fully attacker-controlled content. The
    only thing that can possibly stop a consumer from trusting this is
    `ANCHOR_APP_ID` being a compile-time constant that does not equal this
    probe's app id."""

    @arc4.abimethod(create="require")
    def create(self) -> None:
        pass

    @arc4.abimethod
    def attest(self, block_number: arc4.UInt64, forged_payload: arc4.StaticArray[arc4.Byte, typing.Literal[154]]) -> arc4.StaticArray[arc4.Byte, typing.Literal[154]]:
        return forged_payload


MODE_INIT = 0
MODE_NEXT = 1
MODE_AGAINST_ANCHOR = 5


@subroutine
def _finalize_if_terminal_probe(w: Bytes, r: Bytes, node: Bytes, value_off: UInt64, value_len: UInt64) -> Bytes:
    """Identical logic to `contracts.receipt.bench_app._finalize_if_terminal`
    -- duplicated here (not imported, since the source is a private,
    underscore-prefixed helper) rather than modifying `contracts/receipt/`
    to export it. Byte-for-byte the same decode/status mapping."""
    status = w_status(w)
    if status == UInt64(WALK_CONTINUE):
        return r
    zero_addr = op.bzero(UInt64(20))
    zero_topics = op.bzero(UInt64(128))
    zero_hash = op.bzero(UInt64(32))
    zero_gas = op.bzero(UInt64(8))
    if status == UInt64(WALK_INCLUDED):
        tx_type, rstat, cum_gas8, logs_table, n_logs = mpt7_receipt_body(node, value_off, value_len)
        log_index = r_log_index(r)
        if n_logs == UInt64(0):
            return r_with_terminal(r, UInt64(R_ZERO_LOGS), status, tx_type, rstat, cum_gas8,
                                    zero_addr, UInt64(0), zero_topics, zero_hash, UInt64(0), n_logs)
        if log_index >= n_logs:
            return r_with_terminal(r, UInt64(R_NO_SUCH_LOG), status, tx_type, rstat, cum_gas8,
                                    zero_addr, UInt64(0), zero_topics, zero_hash, UInt64(0), n_logs)
        address, n_topics, topics128, data_hash, data_len = mpt7_log_at(node, logs_table, log_index)
        return r_with_terminal(r, UInt64(R_INCLUDED), status, tx_type, rstat, cum_gas8,
                                address, n_topics, topics128, data_hash, data_len, n_logs)
    assert (status == UInt64(WALK_ABSENT_EMPTY_SLOT) or status == UInt64(WALK_ABSENT_EXT_DIVERGE)
            or status == UInt64(WALK_ABSENT_LEAF_DIVERGE) or status == UInt64(WALK_ABSENT_BRANCH_TERM)), "L23"
    return r_with_terminal(r, UInt64(R_ABSENT), status, UInt64(0), UInt64(0), zero_gas,
                            zero_addr, UInt64(0), zero_topics, zero_hash, UInt64(0), UInt64(0))


@subroutine
def _walk7_probe(r: Bytes, w: Bytes, first_node_arg: UInt64) -> tuple[Bytes, Bytes]:
    n = Txn.num_app_args
    i = first_node_arg
    cur_w = w
    cur_r = r
    while i < n:
        assert w_status(cur_w) == UInt64(WALK_CONTINUE), "L12"
        node = Txn.application_args(i)
        cur_w, voff, vlen = mpt_walk_node(node, cur_w)
        cur_r = _finalize_if_terminal_probe(cur_w, cur_r, node, voff, vlen)
        i += UInt64(1)
    return cur_w, cur_r


class AnchorReceiptProbe(Contract):
    """The real §9.2 proof, self-contained: a receipt walk (M7's own,
    unmodified subroutines) PLUS an anchor-bound result check
    (`mpt7_result_against_anchor`) in one deployed app, so
    `mpt7_result_from_group`'s same-app assert is satisfied honestly.

    Raw args (mirrors `Mpt7ReceiptApp` exactly for MODE_INIT/MODE_NEXT;
    adds MODE_AGAINST_ANCHOR):
        MODE_INIT (0):            arg3 = receipts_root(32) || tx_index(8 BE) || log_index(2 BE)
        MODE_NEXT (1):            arg2 = prev_gi
        MODE_AGAINST_ANCHOR (5):  arg2 = prev_gi (the walk's own last txn);
                                   arg3 = anchor_gi(8 BE) || want_block_number(8 BE)
                                          || want_tx_index(8 BE) || want_log_index(2 BE)
    """

    def approval_program(self) -> bool:
        if Txn.application_id.id == UInt64(0):
            return True
        if Txn.num_app_args == UInt64(0):
            return True

        mode = op.btoi(Txn.application_args(1))
        prev_gi = op.btoi(Txn.application_args(2))

        if mode == MODE_INIT:
            fixed = Txn.application_args(3)
            assert fixed.length == UInt64(42)
            receipts_root = op.extract(fixed, UInt64(0), UInt64(32))
            tx_index = op.btoi(op.extract(fixed, UInt64(32), UInt64(8)))
            log_index = op.extract_uint16(fixed, UInt64(40))
            key = mpt_key_from_tx_index(tx_index)
            key_nibs = key.length * UInt64(2)
            w = mpt_init_state(receipts_root, key, key_nibs)
            r = mpt7_init_result(receipts_root, tx_index, log_index)
            final_w, final_r = _walk7_probe(r, w, UInt64(4))
            log(mpt7_log_state(final_w, final_r))
            return True

        if mode == MODE_NEXT:
            w, r = mpt7_state_from_prev(prev_gi)
            final_w, final_r = _walk7_probe(r, w, UInt64(4))
            log(mpt7_log_state(final_w, final_r))
            return True

        assert mode == UInt64(MODE_AGAINST_ANCHOR)
        fixed = Txn.application_args(3)
        assert fixed.length == UInt64(26)
        anchor_gi = op.btoi(op.extract(fixed, UInt64(0), UInt64(8)))
        want_block_number = op.btoi(op.extract(fixed, UInt64(8), UInt64(8)))
        want_tx_index = op.btoi(op.extract(fixed, UInt64(16), UInt64(8)))
        want_log_index = op.extract_uint16(fixed, UInt64(24))
        rstatus, address, n_topics, topics128, data_hash, data_len, status, tx_type = (
            mpt7_result_against_anchor(prev_gi, anchor_gi, want_block_number, want_tx_index, want_log_index)
        )
        out = (
            op.itob(rstatus) + address + op.itob(n_topics) + topics128 + data_hash
            + op.itob(data_len) + op.itob(status) + op.itob(tx_type)
        )
        log(Bytes(ARC4_RETURN_PREFIX) + out)
        return True

    def clear_state_program(self) -> bool:
        return True
