"""
contracts/primitives/rlp -- Puya library for parsing hash-committed Ethereum
RLP / Merkle-Patricia-Trie node bytes into (offset, length) spans.

See docs/design/002-rlp-decoder.md for the full design. This is a library of
module-level `@subroutine`s -- there is no class, no global state, no
scratch-slot convention, and it is NOT itself a deployable application (see
bench_app.py for the measurement-only ARC4 wrapper used by bench/rlp_bench.py).

Trust precondition TP-1 (design doc §1.3, LOAD-BEARING): every byte string
this module parses must already be hash-committed to a root the caller
verifies BEFORE calling in (`assert keccak256(node) == parent_ref`, done by
the caller, not here). This is NOT a hardened parser for untrusted bytes:
per-item RLP canonicality checks are deliberately omitted from the hot path
because non-canonical bytes can never reach this code without breaking that
keccak link. Only structural bounds checks remain, and every one is a real
`assert` -- a malformed input aborts the transaction (fail-closed), it never
yields a wrong span.

Error codes (assert messages) -- two/three-character codes, not prose, per
the design doc's program-size rationale (§7). Mirrored from
docs/design/002-rlp-decoder.md §7's edge-case table:

  R1  rlp_list_header: data[start] is not a list (first byte < 0xc0)
  R2  rlp_list_header / rlp_item_header: content/payload end exceeds
      len(data) -- truncated input
  R3  rlp_scan_n: n_items exceeded max_items (arity cap)
  R4  rlp_scan_n: last scanned item does not end exactly at payload_end
      (trailing garbage or a short last item)
  R5  rlp_table_item: index i out of range for this table
  R6  mpt_node_scan: n_items not in {2, 17}
  R7  rlp_list_header / rlp_item_header / rlp_scan_n: length-of-length > 8
      bytes -- structurally unreachable via a single length-of-length byte,
      kept as an explicit assert so this can never be undefined behaviour
  R8  rlp_list_header: start >= len(data) (zero-length or exhausted input)
  R9  rlp_scan_upto (§16): `want` does not exist in the list -- walked off
      the end of the payload looking for it
  H1  hp_decode: compact-path length < 1
  H2  hp_decode: flag nibble (high nibble of byte 0) > 3
  H3  hp_decode: even-length flag with a non-zero low nibble on byte 0
      (the one canonicality check M2 keeps despite TP-1 -- see design doc)
  H4  hp_decode: extension node encodes zero path nibbles
  T1  receipt_envelope: empty receipt value
  T2  receipt_envelope: type byte not in 0x01..0x7f (includes 0x00 and any
      0x80..0xbf string-prefix byte)
  T3  receipt_envelope: type byte present but no payload byte follows
  T4  receipt_envelope: byte immediately after the type byte is not a list
      prefix (the sniff invariant this module relies on, checked not assumed)

Non-goals (design doc §1.2): no MPT path walking or key-nibble derivation
(M5), no account/receipt semantic field naming (M6/M7), no >4096-byte
receipt-leaf handling (M7), no RLP encoding on-chain, no untrusted-input
hardening (see TP-1 above).

§16 fast paths (added per O-1/O-2 follow-up, gated on G6's real composition
measurement -- see design doc §16 for the full before/after numbers):
`rlp_scan2` (loop-free exact-2-item decode) and `rlp_scan_upto` (early-exit
single-item retrieval) are the recommended entry points for the common MPT
descent shape -- one node, one or two items wanted, visited once. `rlp_scan`/
`rlp_table_item`/`mpt_node_scan` remain unchanged and are still the right
choice for repeated access to the same node or when the full arity check
(R6) is needed.
"""
from contracts.primitives.rlp.core import (
    KIND_BYTE,
    KIND_LIST,
    KIND_STR,
    MAX_ITEMS,
    mpt_node_scan,
    rlp_bytes,
    rlp_item_header,
    rlp_list_header,
    rlp_scan,
    rlp_scan2,
    rlp_scan_n,
    rlp_scan_upto,
    rlp_table_count,
    rlp_table_item,
)
from contracts.primitives.rlp.eip2718 import receipt_envelope
from contracts.primitives.rlp.nibbles import hp_decode, nibble_at, nibbles_equal

__all__ = [
    "KIND_BYTE",
    "KIND_STR",
    "KIND_LIST",
    "MAX_ITEMS",
    "rlp_list_header",
    "rlp_item_header",
    "rlp_scan",
    "rlp_scan_n",
    "rlp_scan2",
    "rlp_scan_upto",
    "rlp_table_item",
    "rlp_table_count",
    "rlp_bytes",
    "mpt_node_scan",
    "hp_decode",
    "nibble_at",
    "nibbles_equal",
    "receipt_envelope",
]
