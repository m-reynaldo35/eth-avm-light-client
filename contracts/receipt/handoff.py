"""
contracts/receipt/handoff.py -- design doc §5.1 (recovering (W, R) across a
transaction boundary) and §5.3 (the consumer-side check TP-M7-1 requires).

Structurally identical to M6's own `mpt6_state_from_prev`
(contracts/composer/handoff.py), which is itself structurally identical to
M5's `mpt_state_from_prev` -- same four checks, same log envelope, a
different-length payload. M7 uses M6's fixed-selector convention (§5.1: "one
fixed 4-byte selector RCP1, one mode byte"), not M5's caller-supplied
selector -- there is no second selector M7 would ever need to pass in,
exactly the reasoning M6's own handoff.py docstring already gives for
choosing this shape.

The security argument (mirrors M6 §5.4, restated for a single walk): a
consumer recovers R EXCLUSIVELY via `mpt7_result_from_group`, which reads it
out of the group's own `LastLog` -- never from an argument. A relayer that
could forge what this function returns could hand a consumer a result about
a different receipt than the one it asked for; it cannot, because the log it
reads is the AVM's own execution record for a transaction already committed
earlier in this same atomic group, and `mpt7_result_from_group`'s mandatory
`want_*` parameters (TP-M7-1) additionally force the consumer to check that
the recovered R is even about the receipt it meant to ask for.
"""
from algopy import Bytes, Global, Txn, UInt64, gtxn, subroutine, op

from contracts.mpt.state import W_LEN
from contracts.receipt.state import (
    R_LEN,
    r_address,
    r_data_hash,
    r_data_len,
    r_log_index,
    r_n_topics,
    r_receipts_root,
    r_rstatus,
    r_status,
    r_topics,
    r_tx_index,
    r_tx_type,
)

ARC4_RETURN_PREFIX = b"\x15\x1f\x7c\x75"
SEGMENT_SELECTOR = b"RCP1"  # ReCeiPt, v1 (§5.1)
LOG_LEN_M7 = 4 + 2 + W_LEN + R_LEN  # 347


@subroutine
def mpt7_log_state(w: Bytes, r: Bytes) -> Bytes:
    """Encode (W, R) for logging (§5.1): the same `0x151f7c75 || <2-byte BE
    length> || payload` envelope M5/M6 use, `payload = W(101) || R(240)` =
    341 bytes, full log 4 + 2 + 341 = 347 bytes.

    assert w.length == W_LEN -> "L19"
    assert r.length == R_LEN -> "L19"
    (L19 reused for logging's own precondition, mirroring M5's "W16"/M6's
    reuse of "A14" for the identical purpose.)
    """
    assert w.length == UInt64(W_LEN), "L19"
    assert r.length == UInt64(R_LEN), "L19"
    payload_len = UInt64(W_LEN + R_LEN)
    length_b = op.extract(op.itob(payload_len), UInt64(6), UInt64(2))
    return Bytes(ARC4_RETURN_PREFIX) + length_b + w + r


@subroutine
def mpt7_state_from_prev(gi: UInt64) -> tuple[Bytes, Bytes]:
    """§5.1: recover (W, R) that transaction `gi` of THIS group actually
    produced, by reading its `LastLog` -- never trusted as a caller
    argument.

    assert gi < Txn.group_index                            -> "L11"
    assert prev.app_id == Global.current_application_id     -> "L11"
    assert prev.app_args(0) == SEGMENT_SELECTOR              -> "L11"
    assert prev.last_log.length == 347                       -> "L19"
    assert prev.last_log[0:4] == 0x151f7c75                  -> "L19"

    (Reusing "L11" for all three hand-off preconditions and "L19" for the
    log-envelope checks mirrors M6's own choice to fold several structural
    checks under one or two codes rather than minting one per line -- the
    checks are load-bearing regardless of how finely their failure codes
    are split.)
    """
    assert gi < Txn.group_index, "L11"
    prev = gtxn.ApplicationCallTransaction(gi)
    assert prev.app_id == Global.current_application_id, "L11"
    assert prev.app_args(0) == Bytes(SEGMENT_SELECTOR), "L11"
    log = prev.last_log
    assert log.length == UInt64(LOG_LEN_M7), "L19"
    assert op.extract(log, UInt64(0), UInt64(4)) == Bytes(ARC4_RETURN_PREFIX), "L19"
    w = op.extract(log, UInt64(6), UInt64(W_LEN))
    r = op.extract(log, UInt64(6 + W_LEN), UInt64(R_LEN))
    return w, r


@subroutine
def mpt7_result_from_group(gi: UInt64, want_receipts_root: Bytes, want_tx_index: UInt64,
                            want_log_index: UInt64
                            ) -> tuple[UInt64, Bytes, UInt64, Bytes, Bytes, UInt64, UInt64, UInt64]:
    """§5.3: recover and validate a TERMINAL result produced by transaction
    `gi` of this group. Returns
    (rstatus, address, n_topics, topics128, data_hash, data_len, status, tx_type).

    assert R.rstatus != R_INCOMPLETE          -> "L10" (§5.4: an incomplete
                                                          walk is not a verdict)
    assert R.receipts_root == want_receipts_root -> "L11" } TP-M7-1, and the
    assert R.tx_index      == want_tx_index      -> "L11" } reason this
    assert R.log_index     == want_log_index     -> "L11" } subroutine takes
                                                             three mandatory
                                                             arguments

    The three `want_*` parameters are MANDATORY, not optional -- same
    reasoning as M6's `mpt6_result_from_group`: TP-M7-1 is a check the
    consumer must perform, and refusing to compile without it is the
    cheapest way to make it unforgettable.
    """
    w, r = mpt7_state_from_prev(gi)
    assert r_rstatus(r) != UInt64(0), "L10"  # 0 == R_INCOMPLETE
    assert r_receipts_root(r) == want_receipts_root, "L11"
    assert r_tx_index(r) == want_tx_index, "L11"
    assert r_log_index(r) == want_log_index, "L11"
    return (
        r_rstatus(r), r_address(r), r_n_topics(r), r_topics(r),
        r_data_hash(r), r_data_len(r), r_status(r), r_tx_type(r),
    )
