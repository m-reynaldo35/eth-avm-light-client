"""
tests/reference/rlp_ref.py -- strict Python reference oracle for M2's RLP/MPT
primitives (docs/design/002-rlp-decoder.md §1.1 item 6, §8).

This is the differential-test authority for every on-chain path: the Puya
subroutines in contracts/primitives/rlp/ MUST agree with this module on every
fixture (suite D2) and this module MUST agree with itself across a
property-based corpus produced by `encode_*` below (also used by
tests/fixtures/rlp/extract_fixtures.py to build the offline fixture set).

Unlike the on-chain code, this oracle enforces full RLP *canonicality*
(TP-1 in the design doc: the on-chain code can skip canonicality checks
because non-canonical bytes can never reach it without breaking a keccak
link to a trusted root -- but every fixture must still be proven canonical
off-chain, which is this module's job).

Kind discriminator matches contracts/primitives/rlp/core.py exactly:
    KIND_BYTE = 0   0x00..0x7f  (single byte, span = the byte itself)
    KIND_STR  = 1   0x80..0xbf  (string content, may be length 0)
    KIND_LIST = 2   0xc0..0xff  (whole encoding INCLUDING header, §2.2)
"""
from __future__ import annotations

from dataclasses import dataclass

from Crypto.Hash import keccak

KIND_BYTE = 0
KIND_STR = 1
KIND_LIST = 2


def keccak256(b: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


class RlpError(ValueError):
    """Raised with the same two/three-character code the Puya assert would
    raise, so oracle-negative tests can assert on `.code`."""

    def __init__(self, code: str, msg: str = ""):
        super().__init__(f"{code}: {msg}" if msg else code)
        self.code = code


# ---------------------------------------------------------------------------
# Canonicality (oracle-only -- TP-1 says the on-chain code need not check
# this, but every fixture must be proven canonical here).
# ---------------------------------------------------------------------------
def _check_canonical_string(data: bytes, prefix_pos: int, content_off: int,
                             content_len: int) -> None:
    p = data[prefix_pos]
    if p < 0x80:
        return
    if p < 0xb8:
        # short string 0x80..0xb7: for length 1, content byte must be >= 0x80
        # (otherwise a single byte < 0x80 must self-encode, RLP canonical rule)
        if content_len == 1 and data[content_off] < 0x80:
            raise RlpError("C1", "single byte < 0x80 encoded as short string")
        return
    # long string 0xb8..0xbf: length-of-length bytes must have no leading
    # zero byte, and the length itself must be > 55 (else short form applies)
    ll = p - 0xb7
    lenbytes = data[prefix_pos + 1: prefix_pos + 1 + ll]
    if lenbytes[0] == 0:
        raise RlpError("C2", "long-form length has a leading zero byte")
    if content_len <= 55:
        raise RlpError("C3", "long-form used for a <=55-byte payload")


def _check_canonical_list(data: bytes, prefix_pos: int, payload_len: int) -> None:
    p = data[prefix_pos]
    if p < 0xf8:
        return
    ll = p - 0xf7
    lenbytes = data[prefix_pos + 1: prefix_pos + 1 + ll]
    if lenbytes[0] == 0:
        raise RlpError("C2", "long-form list length has a leading zero byte")
    if payload_len <= 55:
        raise RlpError("C3", "long-form list used for a <=55-byte payload")


# ---------------------------------------------------------------------------
# Core decode primitives -- mirror contracts/primitives/rlp/core.py exactly.
# ---------------------------------------------------------------------------
def rlp_list_header(data: bytes, start: int, *, canonical: bool = True) -> tuple[int, int]:
    """Returns (payload_off, payload_end). Mirrors core.rlp_list_header."""
    if not (len(data) > start):
        raise RlpError("R8", "start >= len(data)")
    p = data[start]
    if not (p >= 0xc0):
        raise RlpError("R1", "not a list")
    if p < 0xf8:
        payload_off = start + 1
        payload_len = p - 0xc0
    else:
        ll = p - 0xf7
        if ll > 8:
            raise RlpError("R7", "length-of-length > 8")
        payload_off = start + 1 + ll
        payload_len = int.from_bytes(data[start + 1:start + 1 + ll], "big")
    payload_end = payload_off + payload_len
    if not (payload_end <= len(data)):
        raise RlpError("R2", "truncated list")
    if canonical:
        _check_canonical_list(data, start, payload_len)
    return payload_off, payload_end


def rlp_item_header(data: bytes, pos: int, *, canonical: bool = True
                     ) -> tuple[int, int, int]:
    """Returns (content_off, content_len, kind). Mirrors core.rlp_item_header.
    KIND_LIST span covers the WHOLE encoding INCLUDING its header (§2.2)."""
    p = data[pos]
    if p < 0x80:
        content_off, content_len, kind = pos, 1, KIND_BYTE
    elif p < 0xb8:
        content_off, content_len, kind = pos + 1, p - 0x80, KIND_STR
        if canonical:
            _check_canonical_string(data, pos, content_off, content_len)
    elif p < 0xc0:
        ll = p - 0xb7
        if ll > 8:
            raise RlpError("R7", "length-of-length > 8")
        content_len = int.from_bytes(data[pos + 1:pos + 1 + ll], "big")
        content_off, kind = pos + 1 + ll, KIND_STR
        if canonical:
            _check_canonical_string(data, pos, content_off, content_len)
    elif p < 0xf8:
        content_off, content_len, kind = pos, 1 + p - 0xc0, KIND_LIST
    else:
        ll = p - 0xf7
        if ll > 8:
            raise RlpError("R7", "length-of-length > 8")
        list_len = int.from_bytes(data[pos + 1:pos + 1 + ll], "big")
        content_off, content_len, kind = pos, 1 + ll + list_len, KIND_LIST
        if canonical:
            _check_canonical_list(data, pos, list_len)

    if not (content_off + content_len <= len(data)):
        raise RlpError("R2", "truncated item")
    return content_off, content_len, kind


MAX_ITEMS_DEFAULT = 17


def rlp_scan_n(data: bytes, start: int, max_items: int = MAX_ITEMS_DEFAULT,
                *, canonical: bool = True) -> tuple[list[int], int]:
    """Returns (header_offsets, n_items) -- header_offsets has n_items+1
    entries, the last being payload_end. Mirrors core.rlp_scan_n exactly,
    including the branch-ordering note (§3.2): p < 0xb8 tested before
    p < 0x80. Canonicality (unlike the Puya version, which relies on TP-1)
    is checked per item here."""
    payload_off, payload_end = rlp_list_header(data, start, canonical=canonical)

    offsets: list[int] = []
    pos = payload_off
    n = 0

    while pos < payload_end:
        if not (n < max_items):
            raise RlpError("R3", "arity cap exceeded")
        offsets.append(pos)
        n += 1

        p = data[pos]
        if p < 0xb8:
            if p < 0x80:
                if canonical:
                    pass  # single-byte self-encoding: always canonical
                pos += 1
            else:
                content_len = p - 0x80
                if canonical:
                    _check_canonical_string(data, pos, pos + 1, content_len)
                pos += 1 + content_len
        elif p < 0xc0:
            ll = p - 0xb7
            if ll > 8:
                raise RlpError("R7", "length-of-length > 8")
            content_len = int.from_bytes(data[pos + 1:pos + 1 + ll], "big")
            if canonical:
                _check_canonical_string(data, pos, pos + 1 + ll, content_len)
            pos += 1 + ll + content_len
        elif p < 0xf8:
            pos += 1 + p - 0xc0
        else:
            ll = p - 0xf7
            if ll > 8:
                raise RlpError("R7", "length-of-length > 8")
            list_len = int.from_bytes(data[pos + 1:pos + 1 + ll], "big")
            if canonical:
                _check_canonical_list(data, pos, list_len)
            pos += 1 + ll + list_len

    if not (pos == payload_end):
        raise RlpError("R4", "last item does not end exactly at payload_end")
    offsets.append(payload_end)
    return offsets, n


def rlp_scan(data: bytes, start: int, *, canonical: bool = True) -> tuple[list[int], int]:
    return rlp_scan_n(data, start, MAX_ITEMS_DEFAULT, canonical=canonical)


def rlp_table_item(data: bytes, table: list[int], i: int) -> tuple[int, int, int]:
    """`table` here is the oracle's in-memory offsets list (one int per
    entry); the Puya version's bound check is `2*i + 2 <= table.length`
    where `table.length` is BYTES (2 bytes/entry) -- the equivalent check
    over this list representation is `i + 1 <= len(table) - 1`."""
    if not (i + 1 <= len(table) - 1):
        raise RlpError("R5", "index out of range")
    pos = table[i]
    return rlp_item_header(data, pos)


def rlp_table_count(table: list[int]) -> int:
    return len(table) - 1


def rlp_bytes(data: bytes, off: int, length: int) -> bytes:
    return data[off:off + length]


def mpt_node_scan(data: bytes, start: int, *, canonical: bool = True
                   ) -> tuple[list[int], int]:
    table, n = rlp_scan(data, start, canonical=canonical)
    if not (n == 2 or n == 17):
        raise RlpError("R6", "MPT node arity must be 2 or 17")
    return table, n


# ---------------------------------------------------------------------------
# Hex-prefix (compact) nibble-path decode -- mirrors nibbles.py exactly.
# ---------------------------------------------------------------------------
def hp_decode(data: bytes, off: int, length: int) -> tuple[bool, int, int]:
    if not (length >= 1):
        raise RlpError("H1", "empty compact path")
    b0 = data[off]
    f = b0 >> 4
    if not (f <= 3):
        raise RlpError("H2", "bad flag nibble")
    if f & 1 == 0:
        if not (b0 & 0x0F == 0):
            raise RlpError("H3", "even flag with dirty low nibble")
    is_leaf = (f & 2) != 0
    skip = 1 if (f & 1) else 2
    nibble_count = 2 * length - skip
    if f & 2 == 0:
        if not (nibble_count >= 1):
            raise RlpError("H4", "zero-nibble extension")
    nib_index = 2 * off + skip
    return is_leaf, nibble_count, nib_index


def nibble_at(data: bytes, k: int) -> int:
    b = data[k // 2]
    return (b >> 4) if (k % 2 == 0) else (b & 0x0F)


def nibbles_equal(a: bytes, a_nib: int, b: bytes, b_nib: int, count: int) -> bool:
    """Mirrors contracts/primitives/rlp/nibbles.py::nibbles_equal exactly,
    including the odd/odd leading-nibble peel (see that function's
    docstring for the design-doc-erratum note this fixes)."""
    if count == 0:
        return True
    if a_nib % 2 == b_nib % 2:
        if a_nib % 2 == 1:
            if nibble_at(a, a_nib) != nibble_at(b, b_nib):
                return False
            a_nib += 1
            b_nib += 1
            count -= 1
            if count == 0:
                return True
        if count % 2 == 0:
            return a[a_nib // 2: a_nib // 2 + count // 2] == b[b_nib // 2: b_nib // 2 + count // 2]
        even_count = count - 1
        if a[a_nib // 2: a_nib // 2 + even_count // 2] != b[b_nib // 2: b_nib // 2 + even_count // 2]:
            return False
        return nibble_at(a, a_nib + even_count) == nibble_at(b, b_nib + even_count)
    for j in range(count):
        if nibble_at(a, a_nib + j) != nibble_at(b, b_nib + j):
            return False
    return True


# ---------------------------------------------------------------------------
# EIP-2718 typed-receipt envelope -- mirrors eip2718.py exactly.
# ---------------------------------------------------------------------------
def receipt_envelope(data: bytes, off: int, length: int) -> tuple[int, int, int]:
    if not (length >= 1):
        raise RlpError("T1", "empty receipt value")
    t = data[off]
    if t >= 0xc0:
        return 0, off, length
    if not (0x01 <= t <= 0x7f):
        raise RlpError("T2", "invalid envelope type byte")
    if not (length >= 2):
        raise RlpError("T3", "type byte with no payload")
    if not (data[off + 1] >= 0xc0):
        raise RlpError("T4", "payload after type byte is not a list")
    return t, off + 1, length - 1


# ---------------------------------------------------------------------------
# Strict RLP encoder (oracle-only) -- for suite D2's supplementary
# property-based corpus (§8.3): "a property-based corpus of RLP produced by
# the oracle's strict encoder". Real fixtures remain the primary gate.
# ---------------------------------------------------------------------------
def encode_length(length: int, offset: int) -> bytes:
    if length < 56:
        return bytes([length + offset])
    lb = length.to_bytes((length.bit_length() + 7) // 8 or 1, "big")
    return bytes([len(lb) + offset + 55]) + lb


def encode_bytes(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    return encode_length(len(b), 0x80) + b


def encode_list(items: list[bytes]) -> bytes:
    payload = b"".join(items)
    return encode_length(len(payload), 0xc0) + payload


@dataclass
class Node:
    """Minimal in-memory representation used only to build derived fixtures
    (extension nodes / embedded children) that eth_data.json does not
    contain -- see §8.2's "known gaps" and
    tests/fixtures/rlp/extract_fixtures.py."""
    items: list[bytes]

    def encode(self) -> bytes:
        return encode_list(self.items)
