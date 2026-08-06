"""
contracts/receipt/state.py -- the result R (design doc §5.2) and its status
discriminator (§5.4).

R is a fixed 240-byte buffer, never variable width -- the same "fixed width,
not variable" rule M5's W (contracts/mpt/state.py) and M6's C
(contracts/composer/state.py) both follow. Every accessor here is a
constant-offset extract3/getbyte; every update elsewhere in this package is
an `op.replace` splice of only the field that changes, M5 §16.2's measured
lesson applied from line one (same discipline M6 already carries forward).

T1/T2 only (design doc's approved scope, 2026-08-05): MODE_ZK_CLOSE and the
T3-only fields/paths §4.8 describes are deliberately not implemented here.
`rstatus` still reserves no T3-specific values (§5.4's table has none), so
nothing about R's shape would need to change if T3 were added later.

Layout (§5.2):
    offset  size  field                mutability
       0      1   rstatus              per-step (R_INCOMPLETE while walking)
       1     32   receipts_root        IMMUTABLE (set at MODE_INIT)
      33      8   tx_index             IMMUTABLE (set at MODE_INIT)
      41      2   log_index            IMMUTABLE (set at MODE_INIT)
      43      1   tx_type              write-once (terminal)
      44      1   status               write-once (terminal)
      45      8   cumulative_gas_used  write-once (terminal)
      53     20   address              write-once (terminal)
      73      1   n_topics             write-once (terminal)
      74    128   topics[4], 32B each  write-once (terminal)
     202     32   data_hash            write-once (terminal)
     234      4   data_len             write-once (terminal)
     238      1   wstatus              write-once (terminal, M5's own code)
     239      1   n_logs               write-once (terminal)
"""
from algopy import Bytes, UInt64, subroutine, op

# --- §5.4 rstatus discriminator ---------------------------------------------
R_INCOMPLETE = 0  # walk not terminal yet -- NOT a verdict (§5.4)
R_INCLUDED = 1
R_ABSENT = 2
R_NO_SUCH_LOG = 3
R_ZERO_LOGS = 4

R_LEN = 240

_OFF_RSTATUS = 0
_OFF_RECEIPTS_ROOT = 1
_OFF_TX_INDEX = 33
_OFF_LOG_INDEX = 41
_OFF_TX_TYPE = 43
_OFF_STATUS = 44
_OFF_CUM_GAS = 45
_OFF_ADDRESS = 53
_OFF_N_TOPICS = 73
_OFF_TOPICS = 74
_OFF_DATA_HASH = 202
_OFF_DATA_LEN = 234
_OFF_WSTATUS = 238
_OFF_N_LOGS = 239

TOPIC_LEN = 32
MAX_TOPICS = 4


@subroutine(inline=True)
def byte1(v: UInt64) -> Bytes:
    """The single low byte of `v` as a 1-byte Bytes -- shared by every
    1-byte field splice in this package (mirrors M5's/M6's own idiom)."""
    return op.extract(op.itob(v), UInt64(7), UInt64(1))


@subroutine(inline=True)
def r_rstatus(r: Bytes) -> UInt64:
    return op.getbyte(r, UInt64(_OFF_RSTATUS))


@subroutine(inline=True)
def r_receipts_root(r: Bytes) -> Bytes:
    return op.extract(r, UInt64(_OFF_RECEIPTS_ROOT), UInt64(32))


@subroutine(inline=True)
def r_tx_index(r: Bytes) -> UInt64:
    return op.btoi(op.extract(r, UInt64(_OFF_TX_INDEX), UInt64(8)))


@subroutine(inline=True)
def r_log_index(r: Bytes) -> UInt64:
    return op.extract_uint16(r, UInt64(_OFF_LOG_INDEX))


@subroutine(inline=True)
def r_tx_type(r: Bytes) -> UInt64:
    return op.getbyte(r, UInt64(_OFF_TX_TYPE))


@subroutine(inline=True)
def r_status(r: Bytes) -> UInt64:
    return op.getbyte(r, UInt64(_OFF_STATUS))


@subroutine(inline=True)
def r_cumulative_gas_used(r: Bytes) -> UInt64:
    return op.btoi(op.extract(r, UInt64(_OFF_CUM_GAS), UInt64(8)))


@subroutine(inline=True)
def r_address(r: Bytes) -> Bytes:
    return op.extract(r, UInt64(_OFF_ADDRESS), UInt64(20))


@subroutine(inline=True)
def r_n_topics(r: Bytes) -> UInt64:
    return op.getbyte(r, UInt64(_OFF_N_TOPICS))


@subroutine(inline=True)
def r_topics(r: Bytes) -> Bytes:
    """All 4 topic slots (128 B), zero-padded beyond n_topics. Callers that
    want a single topic index into this with a 32-byte stride themselves
    (mirrors §5.2's own framing -- there is no separate `r_topic(r, i)`
    accessor because no caller needs one yet; add if M9 does)."""
    return op.extract(r, UInt64(_OFF_TOPICS), UInt64(128))


@subroutine(inline=True)
def r_data_hash(r: Bytes) -> Bytes:
    return op.extract(r, UInt64(_OFF_DATA_HASH), UInt64(32))


@subroutine(inline=True)
def r_data_len(r: Bytes) -> UInt64:
    return op.btoi(op.extract(r, UInt64(_OFF_DATA_LEN), UInt64(4)))


@subroutine(inline=True)
def r_wstatus(r: Bytes) -> UInt64:
    return op.getbyte(r, UInt64(_OFF_WSTATUS))


@subroutine(inline=True)
def r_n_logs(r: Bytes) -> UInt64:
    return op.getbyte(r, UInt64(_OFF_N_LOGS))


@subroutine
def mpt7_init_result(receipts_root: Bytes, tx_index: UInt64, log_index: UInt64) -> Bytes:
    """Build R0 (§5.2): rstatus := R_INCOMPLETE, `receipts_root`/`tx_index`/
    `log_index` fixed for the result's whole lifetime (IMMUTABLE), every
    write-once field zeroed.

    assert receipts_root.length == 32 -> "L20"
    assert tx_index <= 0xFFFFFF        -> "L20" (mirrors W3's own tx-index
        bound in mpt_key_from_tx_index -- keeping R's own copy of the
        preimage inside the same bound it was validated against on
        derivation, not a second independent restriction)
    assert log_index <= 0xFFFF         -> "L20" (R's own field is 2 bytes)

    (L20 is an implementation addition beyond §5.5's own L1-L18 table,
    documented here -- same convention M5's W17-W19 and M6's A20
    established.)
    """
    assert receipts_root.length == UInt64(32), "L20"
    assert tx_index <= UInt64(0xFFFFFF), "L20"
    assert log_index <= UInt64(0xFFFF), "L20"
    rstatus_b = byte1(UInt64(R_INCOMPLETE))
    tx_index_b = op.extract(op.itob(tx_index), UInt64(0), UInt64(8))
    log_index_b = op.extract(op.itob(log_index), UInt64(6), UInt64(2))
    zero32 = op.bzero(UInt64(32))
    return (
        rstatus_b + receipts_root + tx_index_b + log_index_b
        + byte1(UInt64(0)) + byte1(UInt64(0)) + op.bzero(UInt64(8))  # tx_type, status, cum_gas
        + op.bzero(UInt64(20))  # address
        + byte1(UInt64(0)) + op.bzero(UInt64(128))  # n_topics, topics[4]
        + zero32  # data_hash
        + op.bzero(UInt64(4))  # data_len
        + byte1(UInt64(0)) + byte1(UInt64(0))  # wstatus, n_logs
    )


@subroutine
def r_with_rstatus(r: Bytes, rstatus: UInt64) -> Bytes:
    """Splice only the 1-byte rstatus field."""
    return op.replace(r, UInt64(_OFF_RSTATUS), byte1(rstatus))


@subroutine
def r_with_terminal(r: Bytes, rstatus: UInt64, wstatus: UInt64, tx_type: UInt64,
                     status: UInt64, cum_gas: Bytes, address: Bytes, n_topics: UInt64,
                     topics: Bytes, data_hash: Bytes, data_len: UInt64, n_logs: UInt64
                     ) -> Bytes:
    """Splice every terminal field in one pass (§5.2's write-once fields).
    Called exactly once, at the moment a receipt result becomes final
    (R_INCLUDED/R_ABSENT/R_NO_SUCH_LOG/R_ZERO_LOGS) -- mirrors M6's
    `mpt6_bridge_*` firing exactly once per composite (§5.1's structural
    property, restated for a single-walk module).

    assert cum_gas.length == 8  -> "L20"
    assert address.length == 20 -> "L20" (0-length accepted for non-INCLUDED
        results that never decoded a real log -- callers pass op.bzero(20))
    assert topics.length == 128 -> "L20" (same: zero-padded by the caller
        for non-INCLUDED results)
    assert data_hash.length == 32 -> "L20"
    """
    assert cum_gas.length == UInt64(8), "L20"
    assert address.length == UInt64(20), "L20"
    assert topics.length == UInt64(128), "L20"
    assert data_hash.length == UInt64(32), "L20"
    r2 = op.replace(r, UInt64(_OFF_RSTATUS), byte1(rstatus))
    r2 = op.replace(r2, UInt64(_OFF_TX_TYPE), byte1(tx_type))
    r2 = op.replace(r2, UInt64(_OFF_STATUS), byte1(status))
    r2 = op.replace(r2, UInt64(_OFF_CUM_GAS), cum_gas)
    r2 = op.replace(r2, UInt64(_OFF_ADDRESS), address)
    r2 = op.replace(r2, UInt64(_OFF_N_TOPICS), byte1(n_topics))
    r2 = op.replace(r2, UInt64(_OFF_TOPICS), topics)
    r2 = op.replace(r2, UInt64(_OFF_DATA_HASH), data_hash)
    r2 = op.replace(r2, UInt64(_OFF_DATA_LEN), op.extract(op.itob(data_len), UInt64(4), UInt64(4)))
    r2 = op.replace(r2, UInt64(_OFF_WSTATUS), byte1(wstatus))
    r2 = op.replace(r2, UInt64(_OFF_N_LOGS), byte1(n_logs))
    return r2
