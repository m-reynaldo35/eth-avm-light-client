"""The anchor record `A` (§6.1): assembly, field accessors, and the §5.4
idempotence/equivocation/eviction decision that ring writes and pin writes
both need.

Fixed 154-byte buffer, following M5's `W`, M6's `C`, M7's `R`: every
accessor is a constant-offset extract/getbyte, every mutation elsewhere
splices only the field that changes.
"""

from algopy import Bytes, UInt64, subroutine, op

from contracts.state_anchor.constants import (
    FLAG_HISTORICAL,
    FLAG_REVOKED,
    OFF_ANCHORED_ROUND,
    OFF_BEACON_BLOCK_ROOT,
    OFF_BEACON_SLOT,
    OFF_BLOCK_NUMBER,
    OFF_FINALITY_ROOT,
    OFF_FLAGS,
    OFF_RECEIPTS_ROOT,
    OFF_STATE_ROOT,
    OFF_VERSION,
    RECORD_LEN,
    VERSION_1,
)


@subroutine(inline=True)
def byte1(v: UInt64) -> Bytes:
    return op.extract(op.itob(v), UInt64(7), UInt64(1))


@subroutine(inline=True)
def a_version(a: Bytes) -> UInt64:
    return op.getbyte(a, UInt64(OFF_VERSION))


@subroutine(inline=True)
def a_flags(a: Bytes) -> UInt64:
    return op.getbyte(a, UInt64(OFF_FLAGS))


@subroutine(inline=True)
def a_is_revoked(a: Bytes) -> bool:  # noqa: FBT001 -- mirrors house bool-return accessors
    return (a_flags(a) & UInt64(FLAG_REVOKED)) != UInt64(0)


@subroutine(inline=True)
def a_is_historical(a: Bytes) -> bool:  # noqa: FBT001
    return (a_flags(a) & UInt64(FLAG_HISTORICAL)) != UInt64(0)


@subroutine(inline=True)
def a_block_number(a: Bytes) -> UInt64:
    return op.btoi(op.extract(a, UInt64(OFF_BLOCK_NUMBER), UInt64(8)))


@subroutine(inline=True)
def a_beacon_slot(a: Bytes) -> UInt64:
    return op.btoi(op.extract(a, UInt64(OFF_BEACON_SLOT), UInt64(8)))


@subroutine(inline=True)
def a_state_root(a: Bytes) -> Bytes:
    return op.extract(a, UInt64(OFF_STATE_ROOT), UInt64(32))


@subroutine(inline=True)
def a_receipts_root(a: Bytes) -> Bytes:
    return op.extract(a, UInt64(OFF_RECEIPTS_ROOT), UInt64(32))


@subroutine(inline=True)
def a_beacon_block_root(a: Bytes) -> Bytes:
    return op.extract(a, UInt64(OFF_BEACON_BLOCK_ROOT), UInt64(32))


@subroutine(inline=True)
def a_finality_root(a: Bytes) -> Bytes:
    return op.extract(a, UInt64(OFF_FINALITY_ROOT), UInt64(32))


@subroutine(inline=True)
def a_anchored_round(a: Bytes) -> UInt64:
    return op.btoi(op.extract(a, UInt64(OFF_ANCHORED_ROUND), UInt64(8)))


@subroutine
def build_record(
    historical: bool,  # noqa: FBT001
    block_number: UInt64,
    beacon_slot: UInt64,
    state_root: Bytes,
    receipts_root: Bytes,
    beacon_block_root: Bytes,
    finality_root: Bytes,
    anchored_round: UInt64,
) -> Bytes:
    """Assemble a fresh record (§6.1). `version = 1` always; `flags` carries
    only `FLAG_HISTORICAL` -- a freshly anchored record is never revoked or
    pinned at the moment of anchoring (revocation/pinning are separate,
    later operations on an existing record)."""
    assert state_root.length == UInt64(32), "N20-shape"
    assert receipts_root.length == UInt64(32), "N20-shape"
    assert beacon_block_root.length == UInt64(32), "N20-shape"
    assert finality_root.length == UInt64(32), "N20-shape"
    flags = UInt64(FLAG_HISTORICAL) if historical else UInt64(0)
    return (
        byte1(UInt64(VERSION_1))
        + byte1(flags)
        + op.itob(block_number)
        + op.itob(beacon_slot)
        + state_root
        + receipts_root
        + beacon_block_root
        + finality_root
        + op.itob(anchored_round)
    )


@subroutine
def record_content_matches(existing: Bytes, candidate: Bytes) -> bool:  # noqa: FBT001
    """§5.4's idempotence comparison: every field EXCEPT `anchored_round`
    (offset 146:154, §11 S15 -- a normal relayer race must never trip the
    equivocation latch on a timestamp) AND the `FLAG_REVOKED` bit of
    `flags` (§7.6/§11 S19 -- a revoked record's flag is not part of the
    anchor's own "content"; comparing it would make the naive "just
    overwrite" implementation clear the flag on an identical re-anchor,
    exactly the bug §7.6 names and forbids).

    Both existing and candidate are asserted 154 bytes by their callers
    (existing always is, being box-sourced from an already-created ring
    slot; candidate always is, being `build_record`'s own output).
    """
    e_flags_masked = a_flags(existing) & ~UInt64(FLAG_REVOKED)
    c_flags_masked = a_flags(candidate) & ~UInt64(FLAG_REVOKED)
    if e_flags_masked != c_flags_masked:
        return False
    # Compare everything else: version, block_number, beacon_slot, the four
    # 32-byte roots -- i.e. offsets [0:1] union [2:146], skipping [1:2]
    # (flags, already compared above) and [146:154] (anchored_round).
    if a_version(existing) != a_version(candidate):
        return False
    if op.extract(existing, UInt64(2), UInt64(144)) != op.extract(candidate, UInt64(2), UInt64(144)):
        return False
    return True


@subroutine
def record_len_check(a: Bytes) -> None:
    assert a.length == UInt64(RECORD_LEN), "N20-shape"


@subroutine(inline=True)
def a_matches_block_number(a: Bytes, block_number: UInt64) -> bool:  # noqa: FBT001
    return a_block_number(a) == block_number
