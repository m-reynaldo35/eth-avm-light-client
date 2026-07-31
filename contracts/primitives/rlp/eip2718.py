"""
contracts/primitives/rlp/eip2718.py -- EIP-2718 typed-receipt envelope
stripping. See docs/design/002-rlp-decoder.md §6.

The general RLP core (core.py) never sniffs for a type byte -- it is only
sound to do so within the receipts trie, where a legacy receipt payload is
always an RLP list > 55 bytes (the bloom filter alone is 256 bytes), so
`first byte < 0xc0 <=> typed envelope` with no ambiguity. That invariant is
what licenses this module to exist separately from core.py; it is not
assumed, it is the reason `receipt_envelope` is scoped to receipts-trie leaf
values only (see the module it is named after, and the design doc §6.1).
"""
from algopy import Bytes, UInt64, subroutine, op


@subroutine
def receipt_envelope(data: Bytes, off: UInt64, length: UInt64
                      ) -> tuple[UInt64, UInt64, UInt64]:
    """Strip an EIP-2718 type byte from a RECEIPTS-TRIE leaf value.

    Returns (tx_type, payload_off, payload_len):
      tx_type == 0            -> legacy, span returned unchanged
      tx_type in 0x01..0x7f   -> typed, span advanced by one byte
    """
    assert length >= 1, "T1"
    t = op.getbyte(data, off)
    if t >= 0xC0:
        return UInt64(0), off, length  # legacy RLP list
    assert t >= 0x01 and t <= 0x7F, "T2"  # not a valid envelope (incl. 0x00)
    assert length >= 2, "T3"  # type byte with no payload
    assert op.getbyte(data, off + 1) >= 0xC0, "T4"  # payload is not a list
    return t, off + 1, length - 1
