"""
contracts/receipt/bench_app.py -- design doc §5.1: the real segmented,
raw-args, one-atomic-group M7 driver (`Mpt7ReceiptApp`), T1/T2 scope only
(approved 2026-08-05; MODE_ZK_CLOSE and every T3-only code path are
deliberately not implemented here -- see docs/design/007-receipt-log-proof.md's
top status note). Mirrors `contracts/composer/bench_app.py`'s role for M6,
adapted for a SINGLE walk (§5.1: "there is no second trie and therefore no
inter-walk bridge") rather than M6's two-phase account+storage composite.

NEVER deploy to mainnet as-is (same scoping M5/M6's own bench-app drivers
carry): like M5/M6, M7's library code has no root-anchoring policy of its
own (M8's job) -- this class exists so real `/v2/transactions/simulate` and
real submitted-group numbers can be attributed to M7's own subroutines, and
so the mechanism can be exercised live against real receipts (task: test on
testnet/devnet).

Args (raw, always, §5.1):
  arg0 = SEGMENT_SELECTOR ("RCP1", 4B)
  arg1 = mode (1B)
  arg2 = prev_gi (1B) -- ignored in MODE_INIT
  arg3 = mode-specific fixed fields (varies, see each mode below)
  arg4..N = proof nodes (MODE_INIT/MODE_NEXT) or one staging chunk
            (MODE_STAGE_WRITE) -- unused for MODE_STAGE_OPEN/MODE_STAGE_WALK

  MODE_INIT (0):        arg3 = receipts_root(32) || tx_index(8 BE) || log_index(2 BE)
  MODE_NEXT (1):        arg3 unused; arg2 = prev_gi
  MODE_STAGE_OPEN (2):  arg3 = name(8) || leaf_len(2 BE)
  MODE_STAGE_WRITE (3): arg3 = name(8) || offset(2 BE); arg4 = chunk
  MODE_STAGE_WALK (4):  arg3 = name(8) || leaf_len(2 BE); arg2 = prev_gi

Every mode that produces or advances (W, R) logs it via mpt7_log_state
(§5.1's own convention, mirroring M5/M6). MODE_STAGE_OPEN/MODE_STAGE_WRITE
touch only the box, not W/R, and do not log -- the (W, R) a later
MODE_STAGE_WALK recovers via `prev_gi` is whichever EARLIER transaction in
the group actually produced it (MODE_INIT or MODE_NEXT), not necessarily
`Txn.group_index - 1`; `mpt7_state_from_prev` already allows any earlier
index, so this needs no special-casing here.
"""
from algopy import Bytes, Contract, OnCompleteAction, Txn, UInt64, log, op, subroutine

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
from contracts.receipt.box import (
    mpt7_stage_close,
    mpt7_stage_open,
    mpt7_stage_read,
    mpt7_stage_write,
)
from contracts.receipt.decode import mpt7_log_at, mpt7_receipt_body
from contracts.receipt.handoff import SEGMENT_SELECTOR, mpt7_log_state, mpt7_state_from_prev
from contracts.receipt.state import (
    R_ABSENT,
    R_INCLUDED,
    R_INCOMPLETE,
    R_NO_SUCH_LOG,
    R_ZERO_LOGS,
    mpt7_init_result,
    r_log_index,
    r_rstatus,
    r_with_terminal,
)

MODE_INIT = 0
MODE_NEXT = 1
MODE_STAGE_OPEN = 2
MODE_STAGE_WRITE = 3
MODE_STAGE_WALK = 4


@subroutine
def _finalize_if_terminal(w: Bytes, r: Bytes, node: Bytes, value_off: UInt64, value_len: UInt64
                           ) -> Bytes:
    """§3.3/§5.4: if this hop's walk state `w` just went terminal, decode
    the receipt and fill R; if `w` is still WALK_CONTINUE, return `r`
    unchanged (still R_INCOMPLETE). Shared by MODE_INIT/MODE_NEXT's node
    loop and MODE_STAGE_WALK's single box-sourced node -- the decode logic
    is identical regardless of where the terminal node came from (TP-M7-4:
    by the time this runs, `mpt_walk_node` has already verified
    `keccak256(node) == w.expected`, whether `node` arrived as a plain
    argument or via `box_extract`)."""
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

    # every WALK_ABSENT_* code -> R_ABSENT (§5.4), no receipt to decode
    assert (status == UInt64(WALK_ABSENT_EMPTY_SLOT) or status == UInt64(WALK_ABSENT_EXT_DIVERGE)
            or status == UInt64(WALK_ABSENT_LEAF_DIVERGE) or status == UInt64(WALK_ABSENT_BRANCH_TERM)), "L23"
    return r_with_terminal(r, UInt64(R_ABSENT), status, UInt64(0), UInt64(0), zero_gas,
                            zero_addr, UInt64(0), zero_topics, zero_hash, UInt64(0), UInt64(0))


@subroutine
def _walk7(r: Bytes, w: Bytes, first_node_arg: UInt64) -> tuple[Bytes, Bytes]:
    """Walk every remaining raw application arg as a supplied node (M5's
    `_walk_remaining_args` / M6's `_walk6` pattern), finalizing R the
    instant the walk reaches a terminal M5 status.

    Trailing unconsumed node arguments after a terminal status are
    rejected -> "L12" (inherited from M5/M6, unchanged)."""
    n = Txn.num_app_args
    i = first_node_arg
    cur_w = w
    cur_r = r
    while i < n:
        assert w_status(cur_w) == UInt64(WALK_CONTINUE), "L12"
        node = Txn.application_args(i)
        cur_w, voff, vlen = mpt_walk_node(node, cur_w)
        cur_r = _finalize_if_terminal(cur_w, cur_r, node, voff, vlen)
        i += UInt64(1)
    return cur_w, cur_r


class Mpt7ReceiptApp(Contract):
    """NOT a production app (mirrors M5/M6 §1.2) -- reference driver only,
    for measuring and testing §3/§5's T1/T2 mechanism live."""

    def approval_program(self) -> bool:
        assert Txn.on_completion == OnCompleteAction.NoOp, "L1"
        if Txn.application_id.id == UInt64(0):
            return True
        if Txn.num_app_args == UInt64(0):
            return True

        selector = Txn.application_args(0)
        assert selector == Bytes(SEGMENT_SELECTOR), "L11"
        mode = op.btoi(Txn.application_args(1))
        prev_gi = op.btoi(Txn.application_args(2))

        if mode == MODE_INIT:
            fixed = Txn.application_args(3)
            assert fixed.length == UInt64(42), "L20"
            receipts_root = op.extract(fixed, UInt64(0), UInt64(32))
            tx_index = op.btoi(op.extract(fixed, UInt64(32), UInt64(8)))
            log_index = op.extract_uint16(fixed, UInt64(40))

            key = mpt_key_from_tx_index(tx_index)
            key_nibs = key.length * UInt64(2)
            w = mpt_init_state(receipts_root, key, key_nibs)
            r = mpt7_init_result(receipts_root, tx_index, log_index)
            final_w, final_r = _walk7(r, w, UInt64(4))
            log(mpt7_log_state(final_w, final_r))
            return True

        if mode == MODE_NEXT:
            w, r = mpt7_state_from_prev(prev_gi)
            assert r_rstatus(r) == UInt64(R_INCOMPLETE), "L22"
            final_w, final_r = _walk7(r, w, UInt64(4))
            log(mpt7_log_state(final_w, final_r))
            return True

        if mode == MODE_STAGE_OPEN:
            fixed = Txn.application_args(3)
            assert fixed.length == UInt64(10), "L20"
            name = op.extract(fixed, UInt64(0), UInt64(8))
            leaf_len = op.extract_uint16(fixed, UInt64(8))
            mpt7_stage_open(name, leaf_len)
            return True

        if mode == MODE_STAGE_WRITE:
            fixed = Txn.application_args(3)
            assert fixed.length == UInt64(10), "L20"
            name = op.extract(fixed, UInt64(0), UInt64(8))
            offset = op.extract_uint16(fixed, UInt64(8))
            chunk = Txn.application_args(4)
            mpt7_stage_write(name, offset, chunk)
            return True

        assert mode == MODE_STAGE_WALK, "L20"
        fixed = Txn.application_args(3)
        assert fixed.length == UInt64(10), "L20"
        name = op.extract(fixed, UInt64(0), UInt64(8))
        leaf_len = op.extract_uint16(fixed, UInt64(8))

        w, r = mpt7_state_from_prev(prev_gi)
        assert r_rstatus(r) == UInt64(R_INCOMPLETE), "L22"
        node = mpt7_stage_read(name, leaf_len)
        w2, voff, vlen = mpt_walk_node(node, w)
        r2 = _finalize_if_terminal(w2, r, node, voff, vlen)
        mpt7_stage_close(name)
        log(mpt7_log_state(w2, r2))
        return True

    def clear_state_program(self) -> bool:
        return True
