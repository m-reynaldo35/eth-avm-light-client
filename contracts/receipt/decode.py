"""
contracts/receipt/decode.py -- the receipt-body decode and log extraction
(design doc §3.3), composed exclusively from M2's public RLP primitives and
M2's `receipt_envelope` (§6). Mirrors `contracts/composer/account.py`'s role
for M6 exactly: everything here operates on a `node` buffer M5's
`mpt_walk_node` has ALREADY verified `keccak256(node) == expected` against a
chain rooted at a trusted root -- so per M2's TP-1, no per-item RLP
canonicality hardening is needed beyond the structural asserts §3.3/§5.5
name (L1-L6).

Two implementation decisions beyond §3.3's literal pseudocode, both
documented here rather than silently made:

1. The receipt body (§3.3 step 2) is decoded as one unrolled 4-item list
   (`rlp_list_header` + 4 chained `rlp_item_header` calls), the same pattern
   `mpt6_account_body` uses for the account body's own 4 items -- not
   `rlp_scan_upto(want=3)` as §3.3's prose suggests, because R needs items 0
   (status) and 1 (cumulative_gas_used) as well as item 3 (the logs list),
   and `rlp_scan_upto` only ever returns the ONE item asked for.

2. The logs array (§3.3 step 3) is decoded with `rlp_scan_n` at a cap of
   `MAX_LOGS_T1T2` (64), not M2's 17-item `rlp_scan` (that cap is MPT's own
   branch arity, unrelated to how many logs a receipt can emit) and not
   `rlp_scan_upto(want=log_index)` (which has no way to report "log_index
   >= n_logs" other than asserting -- and §5.4 requires that comparison
   produce a RESULT, `R_NO_SUCH_LOG`/`R_ZERO_LOGS`, never a failed
   transaction). 64 is generous for T1/T2's own leaf-size ceiling (4,096 B):
   a log needs at least ~23 bytes even empty, so no T1/T2 leaf can hold more
   than roughly 170 logs, and no real Ethereum receipt within that leaf
   size has been observed anywhere near 64 (design doc §14.8's 300-block
   real sample: max real n_logs among T1/T2-sized receipts is far below
   this). A receipt that genuinely exceeds it fails closed on `rlp_scan_n`'s
   own "R3" arity-cap assert, which is correct: that receipt is not really
   representable within T1/T2's size class in the first place.
"""
from algopy import Bytes, UInt64, subroutine, op

from contracts.primitives.rlp.core import (
    rlp_bytes,
    rlp_item_header,
    rlp_list_header,
    rlp_scan,
    rlp_scan_n,
    rlp_table_item,
)
from contracts.primitives.rlp.eip2718 import receipt_envelope

MAX_LOGS_T1T2 = 64


@subroutine
def mpt7_receipt_body(node: Bytes, value_off: UInt64, value_len: UInt64
                       ) -> tuple[UInt64, UInt64, Bytes, Bytes, UInt64]:
    """§3.3 steps 1-2: strip the EIP-2718 envelope, then decode
    rlp([status, cumGas, bloom, logs]) -- loop-free, exactly four items
    (the M7 analogue of M6's `mpt6_account_body`).

    Returns (tx_type, status, cum_gas8, logs_table, n_logs).
    `cum_gas8` is left-zero-padded to 8 bytes (mirrors §4.4's nonce/balance
    32-byte normalisation idiom, scaled to R's own 8-byte field).
    `logs_table`/`n_logs` come from `rlp_scan_n` on item 3's span (decision
    2 above) -- callers pass these straight into `mpt7_log_at`.

    assert leaf value is non-empty        -> "L1"
    assert item3 ends exactly at payload_end -> "L2" (arity == 4, free
        canonicality, same trick as mpt6_account_body's A2)
    assert cum_gas fits in 8 bytes         -> "L21" (implementation
        addition beyond §5.5's L1-L18 table, same convention as M5's
        W17-19/M6's A20 -- gas used per transaction is always far below
        2^64 on real Ethereum, this only guards the field width)
    """
    assert value_len >= UInt64(1), "L1"
    tx_type, p_off, p_len = receipt_envelope(node, value_off, value_len)

    payload_off, payload_end = rlp_list_header(node, p_off)
    o0, l0, _k0 = rlp_item_header(node, payload_off)  # status
    o1, l1, _k1 = rlp_item_header(node, o0 + l0)  # cumulativeGasUsed
    o2, l2, _k2 = rlp_item_header(node, o1 + l1)  # logsBloom (skipped over)
    o3, l3, _k3 = rlp_item_header(node, o2 + l2)  # logs
    assert o3 + l3 == payload_end, "L2"
    assert l1 <= UInt64(8), "L21"

    status = UInt64(0) if l0 == UInt64(0) else op.btoi(rlp_bytes(node, o0, l0))
    cum_gas8 = op.bzero(UInt64(8) - l1) + rlp_bytes(node, o1, l1)

    logs_table, n_logs = rlp_scan_n(node, o3, UInt64(MAX_LOGS_T1T2))
    return tx_type, status, cum_gas8, logs_table, n_logs


@subroutine
def mpt7_log_at(node: Bytes, logs_table: Bytes, log_index: UInt64
                 ) -> tuple[Bytes, UInt64, Bytes, Bytes, UInt64]:
    """§3.3 steps 4-6: decode the log at `log_index` (caller has already
    checked `log_index < n_logs` -- this subroutine does not re-check, it
    trusts the caller made that comparison a RESULT, not an assert, per
    §5.4). A log is `[address, topics, data]`, always exactly 3 items.

    Returns (address20, n_topics, topics128, data_hash32, data_len).
    `topics128` is the fixed 4x32-byte buffer, zero-padded beyond n_topics
    -- the same "materialise the fixed slots, zero-pad the rest" idiom
    `mpt6_account_body`'s nonce/balance normalisation uses.

    assert log arity == 3            -> "L3"
    assert address is 20 bytes       -> "L4"
    assert n_topics <= 4             -> "L5" (Ethereum has LOG0..LOG4;
        nothing else is consensus-valid)
    assert each topic is 32 bytes    -> "L6"
    """
    log_off, _log_len, _log_kind = rlp_table_item(node, logs_table, log_index)
    log_table, log_n = rlp_scan(node, log_off)
    assert log_n == UInt64(3), "L3"

    a_off, a_len, _a_kind = rlp_table_item(node, log_table, UInt64(0))
    assert a_len == UInt64(20), "L4"
    address = rlp_bytes(node, a_off, UInt64(20))

    t_off, _t_len, _t_kind = rlp_table_item(node, log_table, UInt64(1))
    topics_table, n_topics = rlp_scan(node, t_off)
    assert n_topics <= UInt64(4), "L5"

    topics128 = Bytes(b"")
    i = UInt64(0)
    while i < UInt64(4):
        if i < n_topics:
            to, tl, _tk = rlp_table_item(node, topics_table, i)
            assert tl == UInt64(32), "L6"
            topics128 += rlp_bytes(node, to, UInt64(32))
        else:
            topics128 += op.bzero(UInt64(32))
        i += UInt64(1)

    d_off, d_len, _d_kind = rlp_table_item(node, log_table, UInt64(2))
    data_hash = op.keccak256(rlp_bytes(node, d_off, d_len))

    return address, n_topics, topics128, data_hash, d_len
