"""The fork-gated gindex + fork-version table (§4). Row encode/decode,
append validation, and the two slot-keyed lookups §4.4 requires: fork
version at `epoch(signature_slot - 1)`, gindices at `epoch(attested_slot)`
-- two different slots, never collapsed (§15 item 2).

Row shape (§4.3), 36 bytes, stored in box `forks`, append-only:
    activation_epoch: uint64 (8B, big-endian box-internal encoding --
                               NOT an SSZ chunk, so no endianness trap here)
    fork_version:      byte[4]
    finality_gindex:   uint64 (8B)
    current_sc_gindex: uint64 (8B)
    next_sc_gindex:    uint64 (8B)

Gindices are never read from calldata (§15 item 6) -- this table, populated
only through `append_fork_row`'s governance-gated, monotonic-epoch,
non-sentinel-epoch checks, is the ONLY source `submit_update` may use.
"""

from algopy import Bytes, UInt64, subroutine, urange, op

FORK_ROW_BYTES = 36
FORK_TABLE_CAPACITY = 16  # rows; §4.4 "linear scan of <= 10 rows" + headroom
FORKS_BOX_NAME = b"forks"
FORKS_BOX_BYTES = FORK_ROW_BYTES * FORK_TABLE_CAPACITY  # 576 B

UINT64_MAX = 2**64 - 1


@subroutine
def forks_box_create() -> None:
    _created = op.Box.create(Bytes(FORKS_BOX_NAME), UInt64(FORKS_BOX_BYTES))


@subroutine
def _row_offset(index: UInt64) -> UInt64:
    return index * FORK_ROW_BYTES


@subroutine
def _read_row(index: UInt64) -> tuple[UInt64, Bytes, UInt64, UInt64, UInt64]:
    off = _row_offset(index)
    raw = op.Box.extract(Bytes(FORKS_BOX_NAME), off, UInt64(FORK_ROW_BYTES))
    activation_epoch = op.btoi(raw[0:8])
    fork_version = raw[8:12]
    finality_gindex = op.btoi(raw[12:20])
    current_sc_gindex = op.btoi(raw[20:28])
    next_sc_gindex = op.btoi(raw[28:36])
    return activation_epoch, fork_version, finality_gindex, current_sc_gindex, next_sc_gindex


@subroutine
def append_fork_row(
    fork_count: UInt64,
    activation_epoch: UInt64,
    fork_version: Bytes,
    finality_gindex: UInt64,
    current_sc_gindex: UInt64,
    next_sc_gindex: UInt64,
) -> UInt64:
    """Append one row; returns the new `fork_count`. Caller (`verifier.py`)
    is responsible for the governance-sender check -- this subroutine
    enforces only the table's own invariants (§4.3):

      * `activation_epoch` MUST strictly exceed the previous row's (append-
        only, strictly increasing) -- also rejects a second row at the same
        epoch.
      * `activation_epoch` MUST NOT be the `uint64` max sentinel (the
        "temporary stub" `FULU_FORK_EPOCH` §4.3 warns about).
      * The table MUST NOT overflow its fixed capacity.
      * `fork_version` MUST be exactly 4 bytes.
    """
    assert fork_version.length == 4
    assert activation_epoch != UInt64(UINT64_MAX), "sentinel epoch rejected"
    assert fork_count < UInt64(FORK_TABLE_CAPACITY), "fork table full"
    if fork_count > UInt64(0):
        prev_epoch, _pv, _pf, _pc, _pn = _read_row(fork_count - 1)
        assert activation_epoch > prev_epoch, "activation_epoch must strictly increase"

    off = _row_offset(fork_count)
    row = (
        op.itob(activation_epoch)
        + fork_version
        + op.itob(finality_gindex)
        + op.itob(current_sc_gindex)
        + op.itob(next_sc_gindex)
    )
    op.Box.replace(Bytes(FORKS_BOX_NAME), off, row)
    return fork_count + UInt64(1)


@subroutine
def _find_row_index_for_epoch(fork_count: UInt64, epoch: UInt64) -> tuple[bool, UInt64]:
    """Linear scan (§4.4: `table_lookup` is a linear scan of <= 10 rows,
    projected ~20 budget/row). Returns (found, index of the LAST row with
    `activation_epoch <= epoch`) -- rows are appended in strictly
    increasing `activation_epoch` order, so the last such row is the most
    recent fork active at `epoch`.
    """
    found = False
    best_index = UInt64(0)
    for i in urange(fork_count):
        row_epoch, _v, _f, _c, _n = _read_row(i)
        if row_epoch <= epoch:
            best_index = i
            found = True
    return found, best_index


@subroutine
def lookup_fork_version(fork_count: UInt64, epoch: UInt64) -> Bytes:
    """`fork_version` at `epoch` (§4.4). May match a below-Altair row (§4.3:
    those rows exist ONLY so this lookup can return `GENESIS_FORK_VERSION`
    for the single update whose `signature_slot - 1` falls before Altair).
    """
    found, idx = _find_row_index_for_epoch(fork_count, epoch)
    assert found, "no fork row active at this epoch"
    _e, fork_version, _f, _c, _n = _read_row(idx)
    return fork_version


@subroutine
def lookup_gindices(fork_count: UInt64, epoch: UInt64) -> tuple[UInt64, UInt64, UInt64]:
    """`(finality_gindex, current_sc_gindex, next_sc_gindex)` at `epoch`
    (§4.4). MUST NOT match a below-Altair row -- those rows carry zero
    gindices and are asserted-rejected here (§4.3: "carry no gindices and
    MUST never be selected by a gindex lookup").
    """
    found, idx = _find_row_index_for_epoch(fork_count, epoch)
    assert found, "no fork row active at this epoch"
    _e, _v, finality_gindex, current_sc_gindex, next_sc_gindex = _read_row(idx)
    assert finality_gindex != UInt64(0), "matched row carries no gindices (pre-Altair)"
    return finality_gindex, current_sc_gindex, next_sc_gindex
