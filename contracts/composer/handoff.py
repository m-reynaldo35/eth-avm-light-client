"""
contracts/composer/handoff.py -- design doc §5.2 (recovering (W, C) across a
transaction boundary) and §6.6 (the consumer-side check TP-M6-3 requires).

`mpt6_state_from_prev` is structurally identical to M5's own
`mpt_state_from_prev` (contracts/mpt/handoff.py) -- same four checks, same
log envelope, a longer payload. It is deliberately NOT a thin wrapper around
M5's version: M5's takes `selector` as a parameter, but the design doc's own
§5.2 pseudocode hardcodes `SEGMENT_SELECTOR` inside the subroutine (M6's
selector is a single fixed 4-byte constant across all four modes, §6.1
point 1 -- there is no second selector M6 would ever need to pass in), so
this implementation follows the design doc's literal signature
(`mpt6_state_from_prev(gi) -> (W, C)`, no selector argument) rather than
reusing M5's more general one.

The security argument (§5.4, restated): `MODE_B_INIT`
(contracts/composer/bench_app.py) recovers `storage_root` EXCLUSIVELY via
this function, reading it out of `C` recovered from `gtxn ... LastLog` --
never from an argument. A relayer that could forge what this function
returns could redirect phase B at a trie of its own choosing; it cannot,
because the log it reads is the AVM's own execution record for a
transaction already committed earlier in this same atomic group.
"""
from algopy import Bytes, Global, Txn, UInt64, gtxn, subroutine, op

from contracts.composer.state import (
    C_LEN,
    PHASE_DONE,
    c_address,
    c_cstatus,
    c_phase,
    c_slot,
    c_state_root,
    c_value,
)
from contracts.mpt.state import W_LEN

ARC4_RETURN_PREFIX = b"\x15\x1f\x7c\x75"
SEGMENT_SELECTOR = b"ACS1"  # Account + Contract Storage, v1 (§6.2)
LOG_LEN_M6 = 4 + 2 + W_LEN + C_LEN  # 355


@subroutine
def mpt6_log_state(w: Bytes, c: Bytes) -> Bytes:
    """Encode (W, C) for logging (§3.4): the SAME `0x151f7c75 || <2-byte BE
    length> || payload` envelope M5's `mpt_log_state` uses, with a longer
    payload -- `payload = W(101) || C(248)` = 349 bytes, so the full log is
    4 + 2 + 349 = 355 bytes. The payload offset (6) is identical to M5's,
    so `mpt6_state_from_prev`'s recovery arithmetic below is M5's own
    recovery arithmetic, unchanged, just applied to a longer slice.

    assert w.length == W_LEN -> "A14"
    assert c.length == C_LEN -> "A14"
    (A14 reused here for logging's own pre-condition, exactly mirroring
    M5's own `mpt_log_state` reusing "W16" for the identical purpose --
    both codes mean "not a well-formed walk/composite log", whether being
    written here or read back by `mpt6_state_from_prev`.)
    """
    assert w.length == UInt64(W_LEN), "A14"
    assert c.length == UInt64(C_LEN), "A14"
    payload_len = UInt64(W_LEN + C_LEN)
    length_b = op.extract(op.itob(payload_len), UInt64(6), UInt64(2))
    return Bytes(ARC4_RETURN_PREFIX) + length_b + w + c


@subroutine
def mpt6_state_from_prev(gi: UInt64) -> tuple[Bytes, Bytes]:
    """§5.2: recover (W, C) that transaction `gi` of THIS group actually
    produced, by reading its `LastLog` -- never trusted as a caller
    argument. Structurally identical to M5's `mpt_state_from_prev`: same
    four checks, same log envelope, a longer (349-byte instead of 101-byte)
    payload.

    assert gi < Txn.group_index                            -> "A11"
    assert prev.app_id == Global.current_application_id     -> "A12"
    assert prev.app_args(0) == SEGMENT_SELECTOR              -> "A13"
    assert prev.last_log.length == 355                       -> "A14"
    assert prev.last_log[0:4] == 0x151f7c75                  -> "A14"

    The caller chooses only WHICH transaction to point at (`gi`); pointing
    at the wrong one yields a `C` that names a different
    (state_root, address, slot) -- which §3.3 makes self-evident to
    whatever consumes the final `C` (TP-M6-3, `mpt6_result_from_group`
    below, and §5.4's S-M6-3 test).
    """
    assert gi < Txn.group_index, "A11"
    prev = gtxn.ApplicationCallTransaction(gi)
    assert prev.app_id == Global.current_application_id, "A12"
    assert prev.app_args(0) == Bytes(SEGMENT_SELECTOR), "A13"
    log = prev.last_log
    assert log.length == UInt64(LOG_LEN_M6), "A14"
    assert op.extract(log, UInt64(0), UInt64(4)) == Bytes(ARC4_RETURN_PREFIX), "A14"
    w = op.extract(log, UInt64(6), UInt64(W_LEN))
    c = op.extract(log, UInt64(6 + W_LEN), UInt64(C_LEN))
    return w, c


@subroutine
def mpt6_result_from_group(gi: UInt64, want_state_root: Bytes,
                            want_address: Bytes, want_slot: Bytes
                            ) -> tuple[UInt64, Bytes]:
    """§6.6: recover and validate a TERMINAL composite result produced by
    transaction `gi` of this group. Returns (cstatus, value32).

    assert C.phase == PHASE_DONE            -> "A17" (§8.3: no verdict from
                                                        an incomplete walk)
    assert C.state_root == want_state_root  -> "A18" } TP-M6-3, and the
    assert C.address    == want_address     -> "A18" } reason this
    assert C.slot       == want_slot        -> "A18" } subroutine takes
                                                         three arguments

    The three `want_*` parameters are MANDATORY, not optional -- TP-M6-3 is
    a check the consumer must perform, and the cheapest way to make it
    unforgettable is to refuse to compile without it (§6.6's own framing).
    §5.4's residual attack (a relayer aims a genuinely valid composite at
    the WRONG contract by pointing `MODE_B_INIT` at a different account
    walk's segment) is defeated HERE, by the caller comparing `want_address`
    against what this function returns having verified -- and nowhere else.
    """
    _w, c = mpt6_state_from_prev(gi)
    assert c_phase(c) == UInt64(PHASE_DONE), "A17"
    assert c_state_root(c) == want_state_root, "A18"
    assert c_address(c) == want_address, "A18"
    assert c_slot(c) == want_slot, "A18"
    return c_cstatus(c), c_value(c)
