"""
contracts/mpt/state.py -- the walk state W (design doc §3.2) and on-chain
key derivation (§4).

W is a fixed 101-byte buffer, never variable width (§3.2's "Fixed width,
not variable" design note): status(1) || root(32) || expected(32) ||
depth(2 BE) || key_nibs(2 BE) || key(32). Every accessor here is a
constant-offset extract3/replace -- there is no length arithmetic on W
anywhere in the hot path.

Key derivation (§4) is the load-bearing half of TP-M5-2: M5 must be given a
PREIMAGE (20-byte address, 32-byte slot, uint64 tx index), never a
pre-derived trie key. There is no entry point in this module that accepts
a caller-supplied derived key -- `mpt_key_from_address`/`mpt_key_from_slot`
hash on-chain, and their length asserts (W1/W2) are what make the two
conventions non-interchangeable at the type level (a 32-byte
already-hashed value is rejected by `mpt_key_from_address`: 32 != 20).
"""
from algopy import Bytes, UInt64, subroutine, op

# --- §3.1 status discriminator ---------------------------------------------
WALK_CONTINUE = 0
WALK_INCLUDED = 1
WALK_ABSENT_EMPTY_SLOT = 2
WALK_ABSENT_EXT_DIVERGE = 3
WALK_ABSENT_LEAF_DIVERGE = 4
WALK_ABSENT_BRANCH_TERM = 5

W_LEN = 101


@subroutine(inline=True)
def w_status(w: Bytes) -> UInt64:
    return op.getbyte(w, UInt64(0))


@subroutine(inline=True)
def w_root(w: Bytes) -> Bytes:
    return op.extract(w, UInt64(1), UInt64(32))


@subroutine(inline=True)
def w_expected(w: Bytes) -> Bytes:
    return op.extract(w, UInt64(33), UInt64(32))


@subroutine(inline=True)
def w_depth(w: Bytes) -> UInt64:
    return op.extract_uint16(w, UInt64(65))


@subroutine(inline=True)
def w_key_nibs(w: Bytes) -> UInt64:
    return op.extract_uint16(w, UInt64(67))


@subroutine(inline=True)
def w_key(w: Bytes) -> Bytes:
    return op.extract(w, UInt64(69), UInt64(32))


@subroutine
def mpt_init_state(root: Bytes, key: Bytes, key_nibs: UInt64) -> Bytes:
    """Build the initial walk state W0 (§3.2): expected := root (the first
    supplied node must hash to the trusted root itself), depth := 0,
    status := WALK_CONTINUE. `key` must already be the DERIVED trie key
    (the caller calls mpt_key_from_address/_slot/_tx_index first -- this
    subroutine never derives a key itself, it only packs one that was
    already derived on-chain), <= 32 bytes; it is right-zero-padded to the
    fixed 32-byte W.key field.
    assert root.length == 32  -> "W18"
    assert key.length <= 32   -> "W19"
    """
    assert root.length == 32, "W18"
    assert key.length <= 32, "W19"
    padded_key = key + op.bzero(UInt64(32) - key.length)
    status_b = op.extract(op.itob(UInt64(WALK_CONTINUE)), UInt64(7), UInt64(1))
    depth_b = op.extract(op.itob(UInt64(0)), UInt64(6), UInt64(2))
    key_nibs_b = op.extract(op.itob(key_nibs), UInt64(6), UInt64(2))
    return status_b + root + root + depth_b + key_nibs_b + padded_key


@subroutine
def w_with_continue(w: Bytes, expected: Bytes, depth: UInt64) -> Bytes:
    """A copy of `w` with status=WALK_CONTINUE and expected/depth updated;
    root/key_nibs/key are IMMUTABLE across a walk (§3.2) and are left
    untouched in place.

    §16.2 (post-approval fix): this used to rebuild the whole 101-byte `W`
    by concatenating 5 pieces every hop -- status(1) + w_root(w) [a 32-byte
    extract-and-recombine of a field that never changes] + expected(32) +
    depth(2) + a 34-byte "tail" extract of key_nibs||key [also never
    changes]. That is real, measured, avoidable work: two of the three
    fields being "rebuilt" are always copied through byte-for-byte
    unchanged. `op.replace` splices only the 1+32+2 = 35 bytes that
    actually change directly into the existing buffer, with no extract of
    the unchanged root/key_nibs/key regions at all."""
    assert expected.length == 32, "W18"
    depth_b = op.extract(op.itob(depth), UInt64(6), UInt64(2))
    status_b = op.extract(op.itob(UInt64(WALK_CONTINUE)), UInt64(7), UInt64(1))
    w2 = op.replace(w, UInt64(0), status_b)
    w2 = op.replace(w2, UInt64(33), expected)
    w2 = op.replace(w2, UInt64(65), depth_b)
    return w2


@subroutine
def w_with_continue_depth_only(w: Bytes, depth: UInt64) -> Bytes:
    """Same as `w_with_continue` but `expected` is left as-is: used when
    continuing an inline/embedded-child descent (§5.5) within the SAME node
    buffer, where there is no new hash to check yet. §16.2: same
    in-place-replace fix as `w_with_continue` -- only status(1) and
    depth(2) actually change."""
    depth_b = op.extract(op.itob(depth), UInt64(6), UInt64(2))
    status_b = op.extract(op.itob(UInt64(WALK_CONTINUE)), UInt64(7), UInt64(1))
    w2 = op.replace(w, UInt64(0), status_b)
    w2 = op.replace(w2, UInt64(65), depth_b)
    return w2


@subroutine
def w_with_terminal(w: Bytes, status: UInt64) -> Bytes:
    """A copy of `w` with the given terminal WALK_ABSENT_*/WALK_INCLUDED
    status; every other field is frozen (a terminal W is never extended,
    W12). §16.2: a single 1-byte `op.replace` in place of an
    extract-and-recombine of the other 100 bytes."""
    status_b = op.extract(op.itob(status), UInt64(7), UInt64(1))
    return op.replace(w, UInt64(0), status_b)


# --- §4.1 state/storage tries: hashed keys ----------------------------------
@subroutine
def mpt_key_from_address(addr: Bytes) -> Bytes:
    """State-trie key for an Ethereum account. assert addr.length == 20 -> "W1"."""
    assert addr.length == 20, "W1"
    return op.keccak256(addr)


@subroutine
def mpt_key_from_slot(slot: Bytes) -> Bytes:
    """Storage-trie key for a storage slot. assert slot.length == 32 -> "W2".
    The caller (M6) is responsible for having computed `slot` itself -- e.g.
    keccak256(pad32(holder) || pad32(mapping_slot)) for a Solidity mapping --
    and for that computation also being on-chain if the holder is untrusted."""
    assert slot.length == 32, "W2"
    return op.keccak256(slot)


# --- §4.2 receipts trie: un-hashed, variable-length RLP index --------------
@subroutine
def mpt_key_from_tx_index(index: UInt64) -> Bytes:
    """Receipts/transactions-trie key = minimal RLP of the index (§4.2):
       index == 0            -> 0x80             (RLP of the empty string)
       1 <= index <= 0x7f     -> the single byte  (RLP single-byte self-encoding)
       0x80 <= index <= 0xff  -> 0x81 || byte
       0x100 <= index <= 0xffff  -> 0x82 || be2(index)
       0x10000 <= index <= 0xffffff -> 0x83 || be3(index)
       index > 0xffffff       -> assert -> "W3"
    Note the index == 0 trap (§4.2): RLP(0) is 0x80 (the empty string),
    NOT 0x00 -- getting this wrong makes every proof about the first
    transaction in a block fail (test R2).
    """
    assert index <= UInt64(0xFFFFFF), "W3"
    if index == UInt64(0):
        return Bytes(b"\x80")
    if index <= UInt64(0x7F):
        return op.extract(op.itob(index), UInt64(7), UInt64(1))
    if index <= UInt64(0xFF):
        return Bytes(b"\x81") + op.extract(op.itob(index), UInt64(7), UInt64(1))
    if index <= UInt64(0xFFFF):
        return Bytes(b"\x82") + op.extract(op.itob(index), UInt64(6), UInt64(2))
    return Bytes(b"\x83") + op.extract(op.itob(index), UInt64(5), UInt64(3))
