"""
contracts/mpt/handoff.py -- §7.4's group-internal hand-off verification.

A segmented walk (§7.3) spans multiple transactions in one atomic group.
The walk state W a segment PRODUCES must be recovered by its successor from
the group's own execution record (`gtxn ... LastLog`), never trusted as a
caller-supplied argument -- otherwise a relayer could forge `depth`,
`expected`, or `key` between segments and the entire §5 apparatus would be
worthless (the bug relocated to the segment boundary instead of the branch
descent). This is the piece that keeps the key-binding fix intact across a
multi-transaction walk.

Log format (§7.4): a segment logs its terminal/continuation W as
`0x151f7c75 || <2-byte big-endian length> || W` -- 4 + 2 + 101 = 107 bytes,
the ARC4-return-log convention, chosen so the hand-off is verifiable purely
by reading the predecessor transaction's LastLog with no shared state and
no box.
"""
from algopy import Bytes, Global, Txn, UInt64, gtxn, subroutine, op

from contracts.mpt.state import W_LEN

ARC4_RETURN_PREFIX = b"\x15\x1f\x7c\x75"
LOG_LEN = 4 + 2 + W_LEN  # 107


@subroutine
def mpt_log_state(w: Bytes) -> Bytes:
    """Encode W for logging: 4-byte ARC4 return-prefix + 2-byte big-endian
    length + the 101 raw W bytes (§7.4)."""
    assert w.length == UInt64(W_LEN), "W16"
    length_b = op.extract(op.itob(UInt64(W_LEN)), UInt64(6), UInt64(2))
    return Bytes(ARC4_RETURN_PREFIX) + length_b + w


@subroutine
def mpt_state_from_prev(gi: UInt64, selector: Bytes) -> Bytes:
    """Recover the walk state transaction `gi` of THIS group actually
    produced (§7.4). `selector` is the raw method-identifying application
    arg 0 the calling segment method expects its predecessor to have used
    (this reference implementation's raw-args layout, §7.3 -- see
    bench_app.py's `SEGMENT_SELECTOR`).

    assert gi < Txn.group_index                            -> "W13" (must precede us)
    assert prev.app_id == Global.current_application_id     -> "W14"
    assert prev.app_args(0) == selector                      -> "W15"
    assert prev's last log is a well-formed 107-byte walk-state log -> "W16"

    `W_in` is thus NOT trusted from the caller; it is read from a
    transaction the AVM itself executed as part of this same group. The
    caller chooses only WHICH transaction to point at (`gi`); pointing at
    the wrong one yields a W that names a different (root, key), which
    §3.2 makes self-evident to whatever consumes the final W.
    """
    assert gi < Txn.group_index, "W13"
    prev = gtxn.ApplicationCallTransaction(gi)
    assert prev.app_id == Global.current_application_id, "W14"
    assert prev.app_args(0) == selector, "W15"
    log = prev.last_log
    assert log.length == UInt64(LOG_LEN), "W16"
    assert op.extract(log, UInt64(0), UInt64(4)) == Bytes(ARC4_RETURN_PREFIX), "W16"
    return op.extract(log, UInt64(6), UInt64(W_LEN))
