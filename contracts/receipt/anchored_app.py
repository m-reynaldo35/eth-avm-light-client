"""contracts/receipt/anchored_app.py -- design doc 014 §4: `Mpt7AnchoredReceiptApp`,
the permanent, deployed combination of M7's T1 raw-arg walk, M7's T2
box-staged walk, and M8's `mpt7_result_against_anchor` anchor check, as ONE
app with six modes. Promotes `contracts/state_anchor/bench_app.py`'s
test-only, compiled-per-call `AnchorReceiptProbe` (§4.1): the SAME
MODE_INIT/MODE_NEXT/MODE_AGAINST_ANCHOR logic, plus MODE_STAGE_OPEN/
MODE_STAGE_WRITE/MODE_STAGE_WALK copied verbatim from `contracts/receipt/
bench_app.py`'s `Mpt7ReceiptApp` (§4.2/§4.3). Lives here, not under
`contracts/state_anchor/`, because it IS an M7 verifier that happens to
import one M8 helper, and because leaving it inside a file whose module
docstring says "NEVER deploy to mainnet" is precisely how a never-deploy
artefact gets deployed (§4.1).

M7's subroutines are imported, never edited (§1.2's own discipline,
inherited unchanged).

Raw args (identical wire format to `Mpt7ReceiptApp`/`AnchorReceiptProbe`,
§4.2 -- mode numbers deliberately match `Mpt7ReceiptApp`'s so the two
contracts never diverge and `relayer/drivers/m7_receipt.py`'s existing arg
builders work against both unchanged):
    MODE_INIT (0):            arg3 = receipts_root(32) || tx_index(8 BE) || log_index(2 BE)
    MODE_NEXT (1):            arg3 unused; arg2 = prev_gi
    MODE_STAGE_OPEN (2):      arg3 = name(8) || leaf_len(2 BE)
    MODE_STAGE_WRITE (3):     arg3 = name(8) || offset(2 BE); arg4 = chunk
    MODE_STAGE_WALK (4):      arg3 = name(8) || leaf_len(2 BE); arg2 = prev_gi
    MODE_AGAINST_ANCHOR (5):  arg2 = prev_gi (the walk's own last txn);
                              arg3 = anchor_gi(8 BE) || want_block_number(8 BE)
                                     || want_tx_index(8 BE) || want_log_index(2 BE)

§14 item 3 (normative): this contract is deployed ONCE per network and
pinned in the deploy manifest (`deploy/plans/m7_anchored.py`) -- never
compiled and deployed fresh per proof, which is what made `AnchorReceiptProbe`
both expensive (§4.1's table: ~1.74 ALGO abandoned per T2 proof) and, before
§5.1's fix, hijackable in the window between its own deploy transaction and
the proof group. `handoff.ANCHOR_APP_ID` is patched into `contracts/
state_anchor/handoff.py` at BUILD time (`deploy.compile.patched_repo_copy`,
TP-M8-4's compile-time-binding requirement, unchanged), not per call.
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
from contracts.receipt.handoff import mpt7_log_state, mpt7_state_from_prev
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
from contracts.state_anchor.constants import ARC4_RETURN_PREFIX
from contracts.state_anchor.handoff import mpt7_result_against_anchor

MODE_INIT = 0
MODE_NEXT = 1
MODE_STAGE_OPEN = 2
MODE_STAGE_WRITE = 3
MODE_STAGE_WALK = 4
MODE_AGAINST_ANCHOR = 5


@subroutine
def _finalize_if_terminal_anchored(w: Bytes, r: Bytes, node: Bytes, value_off: UInt64, value_len: UInt64) -> Bytes:
    """Byte-for-byte `AnchorReceiptProbe._finalize_if_terminal_probe` /
    `Mpt7ReceiptApp._finalize_if_terminal` -- duplicated here for the exact
    reason both existing copies duplicate it rather than import one
    another (an underscore-prefixed, non-exported private helper), not
    re-derived."""
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
def _walk7_anchored(r: Bytes, w: Bytes, first_node_arg: UInt64) -> tuple[Bytes, Bytes]:
    n = Txn.num_app_args
    i = first_node_arg
    cur_w = w
    cur_r = r
    while i < n:
        assert w_status(cur_w) == UInt64(WALK_CONTINUE), "L12"
        node = Txn.application_args(i)
        cur_w, voff, vlen = mpt_walk_node(node, cur_w)
        cur_r = _finalize_if_terminal_anchored(cur_w, cur_r, node, voff, vlen)
        i += UInt64(1)
    return cur_w, cur_r


class Mpt7AnchoredReceiptApp(Contract):
    """The permanent §14 verifier: T1 walk, T2 box-staged walk, and the
    M8 anchor check, as one deployed app (§4.1/§4.2/§4.3)."""

    def approval_program(self) -> bool:
        assert Txn.on_completion == OnCompleteAction.NoOp, "L1"
        if Txn.application_id.id == UInt64(0):
            return True
        if Txn.num_app_args == UInt64(0):
            return True

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
            final_w, final_r = _walk7_anchored(r, w, UInt64(4))
            log(mpt7_log_state(final_w, final_r))
            return True

        if mode == MODE_NEXT:
            w, r = mpt7_state_from_prev(prev_gi)
            final_w, final_r = _walk7_anchored(r, w, UInt64(4))
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

        if mode == MODE_STAGE_WALK:
            # §14 item 5: `Mpt7ReceiptApp`'s own "L22" -- absent from
            # `AnchorReceiptProbe`'s MODE_NEXT -- carried in here.
            fixed = Txn.application_args(3)
            assert fixed.length == UInt64(10), "L20"
            name = op.extract(fixed, UInt64(0), UInt64(8))
            leaf_len = op.extract_uint16(fixed, UInt64(8))
            w, r = mpt7_state_from_prev(prev_gi)
            assert r_rstatus(r) == UInt64(R_INCOMPLETE), "L22"
            node = mpt7_stage_read(name, leaf_len)
            w2, voff, vlen = mpt_walk_node(node, w)
            r2 = _finalize_if_terminal_anchored(w2, r, node, voff, vlen)
            mpt7_stage_close(name)
            log(mpt7_log_state(w2, r2))
            return True

        assert mode == UInt64(MODE_AGAINST_ANCHOR), "L20"
        fixed = Txn.application_args(3)
        assert fixed.length == UInt64(26), "L20"
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
