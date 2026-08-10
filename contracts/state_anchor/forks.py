"""The §3.3 two-dimensional fork-gated gindex table. Mirrors
`contracts/sync_committee/forks.py` structurally (row encode/decode, append
validation, epoch->row lookup) -- the M8 analogue keeps the same append-only,
strictly-increasing-`activation_epoch` discipline (TP-M8-3), but each row
carries four composed generalized indices instead of M4's fork-version +
three sync-committee gindices, because M8 folds against `body_root`/
`fin_state_root` directly rather than checking a BLS signing domain.

Gindices are never read from calldata (N-FORK, §3.4; §15 item 18) -- this
table, populated only through `append_fork_row`'s governance-gated,
monotonic-epoch checks, is the ONLY source `bridge.py` may use.

Row shape (§3.3), 40 bytes, stored in GLOBAL STATE keyed by
`FORK_ROW_KEY_PREFIX + itob(index)[7:8]` (docs/design/013 §3.1/§3.3 -- moved
off box storage so create()'s MBR is charged to the creator, not the app's
own not-yet-existent account), append-only:
    activation_epoch:   uint64 (8B, big-endian box-internal encoding --
                                 NOT an SSZ chunk, no endianness trap here)
    g_state_root:        uint64 (8B)
    g_receipts_root:      uint64 (8B)
    g_block_number:       uint64 (8B)
    g_block_roots_base:  uint64 (8B)

`g_block_roots_base` is the gindex of `BeaconState.block_roots` AS A
CONTAINER FIELD, before `t_slot mod 8192` is composed in (§3.3, §4.3) --
composition happens on-chain in `bridge.py`, never precomputed off-chain and
supplied as a full composed value, so a governance row addition can only ever
change which container-field position is trusted, never smuggle in an
attacker-composed final gindex through this table alone (that composition
step is exactly N-INDEX's job, and it is public/derivable from
`header_slot`, not from an argument).
"""

from algopy import Bytes, UInt64, subroutine, urange, op

from contracts.state_anchor.constants import (
    FORK_ROW_BYTES,
    FORK_ROW_KEY_PREFIX,
    FORK_TABLE_CAPACITY,
    UINT64_MAX,
)


@subroutine
def _row_key(index: UInt64) -> Bytes:
    return Bytes(FORK_ROW_KEY_PREFIX) + op.itob(index)[7:8]


@subroutine
def _read_row(index: UInt64) -> tuple[UInt64, UInt64, UInt64, UInt64, UInt64]:
    raw, exists = op.AppGlobal.get_ex_bytes(0, _row_key(index))
    assert exists, "fork row missing"
    assert raw.length == UInt64(FORK_ROW_BYTES), "fork row wrong length"
    activation_epoch = op.btoi(raw[0:8])
    g_state_root = op.btoi(raw[8:16])
    g_receipts_root = op.btoi(raw[16:24])
    g_block_number = op.btoi(raw[24:32])
    g_block_roots_base = op.btoi(raw[32:40])
    return activation_epoch, g_state_root, g_receipts_root, g_block_number, g_block_roots_base


@subroutine
def append_fork_row(
    fork_count: UInt64,
    activation_epoch: UInt64,
    g_state_root: UInt64,
    g_receipts_root: UInt64,
    g_block_number: UInt64,
    g_block_roots_base: UInt64,
) -> UInt64:
    """Append one row; returns the new `fork_count`. Caller (`anchor_app.py`)
    is responsible for the governance-sender check -- this subroutine
    enforces only the table's own invariants (§3.3, TP-M8-3, M4 §4.3's rules
    verbatim):

      * `activation_epoch` MUST strictly exceed the previous row's.
      * `activation_epoch` MUST NOT be the `uint64` max sentinel.
      * The table MUST NOT overflow its fixed 8-row capacity.
      * every gindex MUST be >= 2 (bitlen >= 2, i.e. depth >= 1) -- a gindex
        of 0 or 1 cannot be a real composed field position (§12.7 notes
        depth 0 cannot arise for any real M8 field).
    """
    assert activation_epoch != UInt64(UINT64_MAX), "N17-sentinel"
    assert fork_count < UInt64(FORK_TABLE_CAPACITY), "fork table full"
    assert g_state_root >= UInt64(2), "g_state_root must be a real composed gindex"
    assert g_receipts_root >= UInt64(2), "g_receipts_root must be a real composed gindex"
    assert g_block_number >= UInt64(2), "g_block_number must be a real composed gindex"
    assert g_block_roots_base >= UInt64(2), "g_block_roots_base must be a real composed gindex"
    if fork_count > UInt64(0):
        prev_epoch, _s, _r, _n, _b = _read_row(fork_count - 1)
        assert activation_epoch > prev_epoch, "activation_epoch must strictly increase"

    row = (
        op.itob(activation_epoch)
        + op.itob(g_state_root)
        + op.itob(g_receipts_root)
        + op.itob(g_block_number)
        + op.itob(g_block_roots_base)
    )
    op.AppGlobal.put(_row_key(fork_count), row)
    return fork_count + UInt64(1)


@subroutine
def _find_row_index_for_epoch(fork_count: UInt64, epoch: UInt64) -> tuple[bool, UInt64]:
    """Linear scan (mirrors M4 §4.4). Returns (found, index of the LAST row
    with `activation_epoch <= epoch`) -- rows are appended in strictly
    increasing order, so the last such row is the most recent fork active
    at `epoch`."""
    found = False
    best_index = UInt64(0)
    for i in urange(fork_count):
        row_epoch, _s, _r, _n, _b = _read_row(i)
        if row_epoch <= epoch:
            best_index = i
            found = True
    return found, best_index


@subroutine
def lookup_row(fork_count: UInt64, epoch: UInt64) -> tuple[UInt64, UInt64, UInt64, UInt64]:
    """`(g_state_root, g_receipts_root, g_block_number, g_block_roots_base)`
    at `epoch` (§3.3, §3.4). `N17` if no row is active at this epoch."""
    found, idx = _find_row_index_for_epoch(fork_count, epoch)
    assert found, "N17"
    _e, g_state_root, g_receipts_root, g_block_number, g_block_roots_base = _read_row(idx)
    return g_state_root, g_receipts_root, g_block_number, g_block_roots_base
