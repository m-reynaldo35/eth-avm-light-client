"""M6 driver (design doc §6.2, §7.1, §8.3): `Mpt6ComposerApp` -- raw args,
SELF_ISSUED budget convention (`donor_count`/`donor_app_id` written into
every segment's own args, per `contracts/composer/bench_app.py`'s real
dispatch), one atomic group, no boxes.

Wire format (`contracts/composer/bench_app.py`'s real dispatch, unchanged
by this driver -- M9 does not edit deployed contract code):

    arg0 = SEGMENT_SELECTOR "ACS1" (4B)
    arg1 = mode (0=A_INIT, 1=A_NEXT, 2=B_INIT, 3=B_NEXT)
    arg2 = donor_count
    arg3 = donor_app_id
    MODE_A_INIT:  arg4=state_root(32B) arg5=address(20B) arg6=slot(32B) arg7..=nodes
    other modes:  arg4=prev_gi(8B BE) arg5..=nodes

`relayer.proofs.account.segment_account_proof` already decides WHICH nodes
go in which segment and whether phase B runs at all (§6.2 point 4); this
driver only turns that `AccountSegments` result into the raw wire args.
"""
from __future__ import annotations

from dataclasses import dataclass

from relayer.proofs.account import AccountSegments, Segment

SEGMENT_SELECTOR = b"ACS1"
_MODE_NUM = {"A_INIT": 0, "A_NEXT": 1, "B_INIT": 2, "B_NEXT": 3}


@dataclass(frozen=True)
class RawCall:
    args: list[bytes]
    produces_log: bool = False


def plan_composer_calls(segs: AccountSegments, *, donor_app_id: int, donor_count: int) -> list[RawCall]:
    """Builds the raw `Mpt6ComposerApp` call sequence for one account(+
    storage) walk. `prev_gi` for each _NEXT/_INIT-after-phase-A segment is
    filled in by the CALLER once it knows the real group index each
    producing transaction will occupy (§6.2 point 3: "chained to the
    actual group index of the producing transaction -- not `group_index -
    1`, since donor/filler transactions may sit between segments"). This
    function returns calls with `prev_gi` left as a placeholder
    (`_PENDING_PREV_GI`); `relayer.group.planner` / the caller resolves it
    against the final transaction ordering before signing."""
    calls: list[RawCall] = []
    donor_count_b = donor_count.to_bytes(8, "big")
    donor_app_b = donor_app_id.to_bytes(8, "big")
    phase_a_last_index: int | None = None
    for i, seg in enumerate(segs.segments):
        mode_b = bytes([_MODE_NUM[seg.mode]])
        if seg.mode == "A_INIT":
            args = [SEGMENT_SELECTOR, mode_b, donor_count_b, donor_app_b,
                    segs.state_root, segs.address, segs.slot] + seg.nodes
        elif seg.mode == "A_NEXT":
            args = [SEGMENT_SELECTOR, mode_b, donor_count_b, donor_app_b,
                    _PENDING_PREV_GI] + seg.nodes
        else:  # B_INIT / B_NEXT
            args = [SEGMENT_SELECTOR, mode_b, donor_count_b, donor_app_b,
                    _PENDING_PREV_GI] + seg.nodes
        # Every Mpt6ComposerApp mode logs (W, C) unconditionally
        # (`contracts/composer/bench_app.py`'s dispatch calls
        # `log(mpt6_log_state(...))` on every path), so every segment call
        # produces a log a later segment/consumer may chain to.
        calls.append(RawCall(args=args, produces_log=True))
        if seg.mode in ("A_INIT", "A_NEXT"):
            phase_a_last_index = i
    return calls


_PENDING_PREV_GI = b"\x00\x00\x00\x00\x00\x00\x00\x00"


def resolve_prev_gi(calls: list[RawCall], group_offset: int) -> list[RawCall]:
    """Replaces each `_PENDING_PREV_GI` placeholder with the real group
    index of the immediately-preceding segment call, once `group_offset`
    (how many transactions -- donors, funding, etc. -- precede the first
    segment call in the final group) is known. Mirrors §6.2 point 3
    exactly: chains to the ACTUAL producing index, not a fixed offset."""
    out: list[RawCall] = []
    prev_real_index: int | None = None
    for i, call in enumerate(calls):
        real_index = group_offset + i
        args = list(call.args)
        if _PENDING_PREV_GI in args:
            assert prev_real_index is not None, "A_NEXT/B_INIT/B_NEXT with no preceding segment call"
            idx = args.index(_PENDING_PREV_GI)
            args[idx] = prev_real_index.to_bytes(8, "big")
        out.append(RawCall(args=args, produces_log=call.produces_log))
        prev_real_index = real_index
    return out


def decode_result_from_log(log_bytes: bytes) -> dict:
    """`mpt6_log_state`'s envelope: `0x151f7c75 || len(2) || W(101) ||
    C(248)`, 355 B total (§7.8)."""
    from relayer.group.logs import Producer, decode_log

    decoded = decode_log(log_bytes, Producer.M5_M6)
    c = decoded.payload
    assert len(c) == 248, f"M6 composite C must be 248 B, got {len(c)}"
    return {
        "cstatus": c[0],
        "phase": c[1],
        "state_root": c[2:34].hex(),
        "address": c[34:54].hex(),
        "slot": c[54:86].hex(),
        "storage_root": c[86:118].hex(),
        "code_hash": c[118:150].hex(),
        "nonce": int.from_bytes(c[150:182], "big"),
        "balance": int.from_bytes(c[182:214], "big"),
        "value": c[214:246].hex(),
        "awalk": c[246],
        "swalk": c[247],
    }
