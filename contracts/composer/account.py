"""
contracts/composer/account.py -- the account-body decode (design doc §4.2)
and the storage-value normalisation (§4.4). Composed EXCLUSIVELY from M2's
public `rlp_list_header` / `rlp_item_header` / `rlp_bytes` (§1.2's non-goal:
M6 copies none of M2's stride arithmetic, so unlike M5's fused branch loop
it carries no differential-test obligation, M2 §2.4).

Both subroutines here operate on a `node` buffer that M5's `mpt_walk_node`
has ALREADY verified `keccak256(node) == expected` against a chain rooted at
a trusted root (TP-M6-4) -- so, per M2's TP-1, no per-item RLP canonicality
hardening is needed. The asserts kept here (A1-A6) are the ones §4.5
explicitly keeps anyway: not defence against a malicious relayer (that
threat is already closed by the hash chain), but a fail-CLOSED backstop
against a root that is not really an Ethereum state root (TP-M6-1 is a
precondition, not a proof) or a genuinely malformed body, so a bad input
fails with a named M6 code instead of misdirecting a debugger toward
`mpt_walk_node`'s W11 in phase B (§4.5 point 1).
"""
from algopy import Bytes, UInt64, subroutine, op

from contracts.primitives.rlp.core import KIND_STR, rlp_bytes, rlp_item_header, rlp_list_header


@subroutine
def mpt6_account_body(node: Bytes, value_off: UInt64, value_len: UInt64
                       ) -> tuple[Bytes, Bytes, Bytes, Bytes]:
    """Decode rlp([nonce, balance, storageRoot, codeHash]) at `value_off` in
    `node` -- the SAME node buffer the account walk's terminal hop already
    verified (§5.1's bridge is the only caller; `node`/`value_off`/
    `value_len` must be `mpt_walk_node`'s own return values for the segment
    that reached WALK_INCLUDED). Loop-free, exactly four items: the 4-item
    analogue of M2's `rlp_scan2` (§4.2).

    Returns (storage_root, code_hash, nonce32, balance32) -- the last two
    already left-zero-padded to 32 bytes (§4.4's normalisation, applied here
    too since §4.2 documents the identical `op.bzero(32 - l) + rlp_bytes`
    idiom for nonce/balance, including the `l == 0` case: a zero nonce or
    zero balance encodes as the RLP empty string, content_len == 0, and
    normalises to 32 zero bytes).

    assert item3 ends exactly at payload_end          -> "A2" (arity == 4, free)
    assert storageRoot is a 32-byte KIND_STR          -> "A3"
    assert codeHash    is a 32-byte KIND_STR          -> "A3"
    assert nonce_len <= 32 and bal_len <= 32          -> "A4"
    assert payload_end <= value_off + value_len       -> "A1"
    """
    payload_off, payload_end = rlp_list_header(node, value_off)
    o0, l0, _k0 = rlp_item_header(node, payload_off)  # nonce
    o1, l1, _k1 = rlp_item_header(node, o0 + l0)  # balance
    o2, l2, k2 = rlp_item_header(node, o1 + l1)  # storageRoot
    o3, l3, k3 = rlp_item_header(node, o2 + l2)  # codeHash
    assert o3 + l3 == payload_end, "A2"
    assert l2 == UInt64(32) and k2 == UInt64(KIND_STR), "A3"
    assert l3 == UInt64(32) and k3 == UInt64(KIND_STR), "A3"
    assert l0 <= UInt64(32) and l1 <= UInt64(32), "A4"
    assert payload_end <= value_off + value_len, "A1"

    storage_root = rlp_bytes(node, o2, UInt64(32))
    code_hash = rlp_bytes(node, o3, UInt64(32))
    nonce32 = op.bzero(UInt64(32) - l0) + rlp_bytes(node, o0, l0)
    balance32 = op.bzero(UInt64(32) - l1) + rlp_bytes(node, o1, l1)
    return storage_root, code_hash, nonce32, balance32


@subroutine
def mpt6_storage_value(node: Bytes, value_off: UInt64, value_len: UInt64
                        ) -> tuple[Bytes, bool]:
    """§4.4: the storage leaf's value span is itself `rlp(uint256)`, not the
    value -- decode ONE more level. Returns (value32, is_zero_entry) where
    `value32` is the 32-byte big-endian normalised word (32 zero bytes when
    `is_zero_entry`, §9.2's `C_ZERO_ENTRY` case, the RLP empty string `0x80`
    present in the trie).

    assert vo + vl == value_off + value_len -> "A6" (canonical: exactly one
        item, fills the whole span -- same free-canonicality trick as A2)
    assert vl <= 32                          -> "A5"
    """
    vo, vl, _vk = rlp_item_header(node, value_off)
    assert vo + vl == value_off + value_len, "A6"
    assert vl <= UInt64(32), "A5"
    if vl == UInt64(0):
        return op.bzero(UInt64(32)), True
    value32 = op.bzero(UInt64(32) - vl) + rlp_bytes(node, vo, vl)
    return value32, False
