"""§8.3/§8.4/§8.7 -- THE FILE M6 AND M7 WOULD IMPORT (a future, separate
pass; not wired into either module's own deployed contract in this pass --
see this file's own docstring note at the bottom).

**Real finding, measured, that corrects the design doc's own pseudocode**
(§8.3's literal text assumes `log.length == 6 + 154 == 160`, mirroring M5/
M6/M7's hand-built `0x151f7c75 || <2-byte BE length> || payload` envelope
used by their RAW `Contract` classes). M8's `TrustedRootAnchor` is a genuine
`ARC4Contract` (§8.1's decision), so `attest`'s return log is Puya's own
AUTO-GENERATED ARC-4 return encoding, not a hand-built one. Measured
directly against real dev-mode algod (a throwaway probe contract, an
`arc4.abimethod` returning `arc4.StaticArray[Byte, Literal[154]]`): the real
log is `0x151f7c75` followed by the raw 154 bytes with **no 2-byte length
field** -- **158 bytes total, not 160**. A fixed-size ARC-4 return value's
encoding is exactly its raw bytes; the 2-byte length field M5/M6/M7 add by
hand only exists because those three modules manually mimic the ARC-4
envelope from a non-ARC4Contract `Contract` class where nothing generates it
for them. `anchor_from_group` below uses the REAL, measured 158-byte
envelope, not the design doc's assumed one.

TP-M8-4 (§8.3, the central line in this whole document, implementer
checklist item 8): `ANCHOR_APP_ID` is a compile-time constant. It is set
here, once, and every consumer subroutine below closes over it. **There is
no parameter, global, or box path by which a caller can change which app
`anchor_from_group`/`anchor_by_inner_call` trust.** `contracts/state_anchor/
bench_app.py`'s `test_forged_app_id_is_rejected`-style probe (S-APP) proves
this by deploying a `FakeAnchor` that returns an attacker-chosen record with
a VALID ARC-4 envelope, pointing `anchor_gi` at it, and confirming `N2`
still fires -- the constant, not the envelope shape, is what protects this.
"""

from algopy import Bytes, Global, Txn, UInt64, gtxn, subroutine, op

from contracts.state_anchor.constants import (
    ARC4_RETURN_PREFIX,
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
from contracts.state_anchor.record import a_flags

# TP-M8-4: this is the ONLY place `ANCHOR_APP_ID` is assigned in this
# codebase. `anchor_app.py`'s create() sets `self.m4` from a create-time
# argument (a DIFFERENT immutable, TP-M8-7, comparing a different app) --
# `ANCHOR_APP_ID` here is M8's OWN app id as seen by a CONSUMER of M8, and
# is compiled into the consumer, never supplied by it. Tests set this via
# monkeypatching this module-level constant and recompiling the probe
# contract (mirrors how a real consumer's own build pins its own deployed
# M8 app id at compile time) -- never via a method argument.
ANCHOR_APP_ID: int = 0  # placeholder; real consumers set this before compiling
# 4-byte ARC-4 selector of `attest(uint64)byte[154]` -- MEASURED, not guessed:
# `first4(sha512_256("attest(uint64)byte[154]"))`, extracted directly from
# `algosdk.abi.Method.get_selector()` against the real compiled
# `TrustedRootAnchor.arc56.json` (see `tests/state_anchor/conftest.py`'s
# harness, which re-derives and asserts this constant against the live
# compiled ABI on every run so a future signature change cannot silently
# desync this hardcoded copy).
ATTEST_SELECTOR = b"\x11\xe6\xd2\xdd"

LOG_LEN_M8 = 4 + RECORD_LEN  # 158 -- MEASURED, not the design doc's assumed 160


@subroutine
def anchor_from_group(gi: UInt64, want_block_number: UInt64) -> Bytes:
    """§8.3: recover and validate an anchor record `A` produced by
    transaction `gi` of THIS group.

    assert gi < Txn.group_index                          -> "N1"
    prev = gtxn.ApplicationCallTransaction(gi)
    assert prev.app_id == ANCHOR_APP_ID                   -> "N2"  <- TP-M8-4
    assert prev.app_args(0) == ATTEST_SELECTOR            -> "N3"
    log = prev.last_log
    assert log.length == 158 and log[:4] == 0x151f7c75    -> "N4b"
    a = log[4:158]
    assert a[0] == VERSION_1                              -> "N14"
    assert a[1] & FLAG_REVOKED == 0                        -> "N13"
    assert a[2:10] == itob(want_block_number)             -> "N15"
    return a
    """
    assert gi < Txn.group_index, "N1"
    prev = gtxn.ApplicationCallTransaction(gi)
    assert prev.app_id.id == UInt64(ANCHOR_APP_ID), "N2"
    assert prev.app_args(0) == Bytes(ATTEST_SELECTOR), "N3"
    log = prev.last_log
    assert log.length == UInt64(LOG_LEN_M8), "N4b"
    assert op.extract(log, UInt64(0), UInt64(4)) == Bytes(ARC4_RETURN_PREFIX), "N4b"
    a = op.extract(log, UInt64(4), UInt64(RECORD_LEN))
    assert op.getbyte(a, UInt64(OFF_VERSION)) == UInt64(VERSION_1), "N14"
    assert a_flags(a) & UInt64(1) == UInt64(0), "N13"
    assert op.extract(a, UInt64(OFF_BLOCK_NUMBER), UInt64(8)) == op.itob(want_block_number), "N15"
    return a


@subroutine
def anchor_state_root(a: Bytes) -> Bytes:
    return op.extract(a, UInt64(OFF_STATE_ROOT), UInt64(32))


@subroutine
def anchor_receipts_root(a: Bytes) -> Bytes:
    return op.extract(a, UInt64(OFF_RECEIPTS_ROOT), UInt64(32))


@subroutine
def anchor_block_number(a: Bytes) -> UInt64:
    return op.btoi(op.extract(a, UInt64(OFF_BLOCK_NUMBER), UInt64(8)))


@subroutine
def anchor_beacon_slot(a: Bytes) -> UInt64:
    return op.btoi(op.extract(a, UInt64(OFF_BEACON_SLOT), UInt64(8)))


@subroutine
def anchor_beacon_root(a: Bytes) -> Bytes:
    return op.extract(a, UInt64(OFF_BEACON_BLOCK_ROOT), UInt64(32))


@subroutine
def anchor_finality_root(a: Bytes) -> Bytes:
    return op.extract(a, UInt64(OFF_FINALITY_ROOT), UInt64(32))


@subroutine
def anchor_round(a: Bytes) -> UInt64:
    return op.btoi(op.extract(a, UInt64(OFF_ANCHORED_ROUND), UInt64(8)))


@subroutine
def anchor_assert_mature(a: Bytes, min_rounds: UInt64) -> None:
    """§5.6, §8.7, implementer checklist item 22: NOT mandatory anywhere in
    M8 itself -- a consumer that wants a maturity policy calls this
    explicitly; M8 forces no default because §5.6 argues none is
    defensible."""
    assert Global.round - anchor_round(a) >= min_rounds, "not mature"


# ---------------------------------------------------------------------------
# §9.2's `mpt7_result_against_anchor`. NOTE ON SCOPE (2026-08-06 implementation
# pass): this subroutine is written here, exactly where §18's file layout
# says it belongs ("handoff.py -- THE FILE M6 AND M7 IMPORT"), and it is
# real, compiled, and tested against a real M7 walk in
# `contracts/state_anchor/bench_app.py`'s `AnchorReceiptProbe` -- but it is
# NOT wired into M7's own deployed `Mpt7ReceiptApp`/`main.py`/`m7_relayer.py`
# in this pass, per this task's own explicit scope boundary (M6/M7 contract
# files are not modified this session; wiring M8 into the live x402 service
# is a separate, later task). `AnchorReceiptProbe` demonstrates the real
# mechanism end-to-end by IMPORTING M7's existing, unmodified
# `mpt7_result_from_group` (a READ, never a modification of
# `contracts/receipt/*.py`) into a new class rather than editing M7's own
# deployed contract -- see `bench_app.py`'s docstring for the full
# reasoning. `mpt7_result_from_group`'s own same-app assert
# (`prev.app_id == Global.current_application_id`, inside
# `mpt7_state_from_prev`) is exactly why the walk and this check must be
# performed by the SAME deployed app -- see that function's docstring.
# ---------------------------------------------------------------------------
from contracts.receipt.handoff import mpt7_result_from_group  # noqa: E402


@subroutine
def mpt7_result_against_anchor(
    gi: UInt64,
    anchor_gi: UInt64,
    want_block_number: UInt64,
    want_tx_index: UInt64,
    want_log_index: UInt64,
) -> tuple[UInt64, Bytes, UInt64, Bytes, Bytes, UInt64, UInt64, UInt64]:
    """§9.2: TP-M7-2, discharged. Derives `want_receipts_root` from the
    anchor record produced by transaction `anchor_gi` of THIS group (via
    `anchor_from_group`, TP-M8-4-bound), then delegates to M7's own
    unmodified `mpt7_result_from_group`. There is no `receipts_root`
    parameter a caller could substitute."""
    a = anchor_from_group(anchor_gi, want_block_number)
    return mpt7_result_from_group(gi, anchor_receipts_root(a), want_tx_index, want_log_index)
