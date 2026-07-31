"""
Suite E (negative) from docs/design/002-rlp-decoder.md §8.3: each case must
fail with the documented error code. Covers E10-E13 here (E17-E21 live in
test_rlp_nibbles.py / test_rlp_eip2718.py alongside their positive
counterparts), plus the additional suite-E items listed in §8.3:
rlp_list_header on a non-list first byte, a 4-item list through
mpt_node_scan, a truncated 532-byte node, and the unstripped-typed-receipt
regression (also covered in test_rlp_eip2718.py).
"""
import algopy_testing
import pytest
from algopy import Bytes, UInt64

from contracts.primitives.rlp import core


# ---------------------------------------------------------------------------
# E10: length-of-length > 8 -> "R7". Structurally unreachable via any real
# single length-of-length byte (0xb8..0xbf / 0xf8..0xff each cap ll at 8),
# so per the doc ("unreachable ... but must not be UB, test the assert with
# a constructed header") we test the guard directly against
# core._read_len -- bypassing the byte-format constraint that normally
# makes ll > 8 impossible -- to prove the assert really exists and really
# fires, not just that it is dead code that happens to never run.
# ---------------------------------------------------------------------------
def test_e10_read_len_guard_present_in_core():
    """Direct check that core._read_len's ll<=8 guard fires when called
    with a synthetic ll > 8 (bypassing the byte-format constraint that
    normally makes this unreachable -- this is exactly the "explicit is
    better" defensive assert the design doc asks for, §7 E10)."""
    with algopy_testing.algopy_testing_context():
        data = Bytes(bytes(16))
        with pytest.raises(Exception, match="R7"):
            core._read_len(data, UInt64(0), UInt64(9))


# ---------------------------------------------------------------------------
# E11: zero-length input -> rlp_list_header fails cleanly with "R8".
# ---------------------------------------------------------------------------
def test_e11_zero_length_input():
    with algopy_testing.algopy_testing_context():
        data = Bytes(b"")
        with pytest.raises(Exception, match="R8"):
            core.rlp_list_header(data, UInt64(0))


# ---------------------------------------------------------------------------
# E12: truncated node -> payload_end > len(data) -> "R2". Real 532-byte
# node truncated to 400 bytes.
# ---------------------------------------------------------------------------
def test_e12_truncated_node(eth_data):
    node = bytes.fromhex(eth_data["proof"]["accountProof"][0][2:])
    assert len(node) == 532
    truncated = node[:400]
    with algopy_testing.algopy_testing_context():
        data = Bytes(truncated)
        with pytest.raises(Exception, match="R2"):
            core.rlp_list_header(data, UInt64(0))


# ---------------------------------------------------------------------------
# E13: trailing garbage / short last item -> "R4" (scan's assert pos ==
# payload_end catches over-run; under-run is structurally impossible to
# distinguish from "more items" in this format -- the loop just keeps
# consuming items until pos >= payload_end, so the only way a declared
# payload_end can fail to be hit EXACTLY is by an item's span running past
# it, i.e. over-run. See the passing case below.
# ---------------------------------------------------------------------------
def test_e13_item_overruns_enclosing_payload_end():
    """An item whose declared span stays within the WHOLE buffer (so R2's
    data.length check passes) but overruns the enclosing list's
    payload_end -- must be caught by R4 (pos == payload_end), not silently
    accepted. node = 0xc2 (list, payload_len=2) then a short string
    claiming length 3 -- content fits in the 5-byte buffer but the outer
    list only declared a 2-byte payload."""
    with algopy_testing.algopy_testing_context():
        node = bytes([0xC2, 0x83, 0xAA, 0xBB, 0xCC])
        data = Bytes(node)
        with pytest.raises(Exception, match="R4"):
            core.rlp_scan(data, UInt64(0))


# ---------------------------------------------------------------------------
# rlp_list_header on a non-list first byte -> "R1".
# ---------------------------------------------------------------------------
def test_rlp_list_header_non_list_byte():
    with algopy_testing.algopy_testing_context():
        for b in (0x00, 0x7F, 0x80, 0xA0, 0xBF):
            data = Bytes(bytes([b, 0x00]))
            with pytest.raises(Exception, match="R1"):
                core.rlp_list_header(data, UInt64(0))


# ---------------------------------------------------------------------------
# A 4-item RLP list through mpt_node_scan must be "R6".
# ---------------------------------------------------------------------------
def test_mpt_node_scan_wrong_arity_4_items():
    with algopy_testing.algopy_testing_context():
        node = bytes([0xC4, 0x01, 0x02, 0x03, 0x04])  # 4 single-byte items
        data = Bytes(node)
        with pytest.raises(Exception, match="R6"):
            core.mpt_node_scan(data, UInt64(0))


# ---------------------------------------------------------------------------
# R3: scan arity cap. A synthetic 18-item list through rlp_scan (cap 17).
# ---------------------------------------------------------------------------
def test_r3_arity_cap_exceeded():
    with algopy_testing.algopy_testing_context():
        items = bytes([0x00]) * 18  # 18 single-byte items
        node = bytes([0xC0 + len(items)]) + items
        data = Bytes(node)
        with pytest.raises(Exception, match="R3"):
            core.rlp_scan(data, UInt64(0))


# ---------------------------------------------------------------------------
# R5: rlp_table_item index out of range. Per the design doc's own bound
# (§2.3/§3.3: "assert 2*i + 2 <= table.length"), a table for n_items has
# n_items+1 entries (2*(n_items+1) bytes), so this formula in fact permits
# i up to and including n_items (it reads the payload_end sentinel entry
# as if it were an item header for i == n_items) -- only i > n_items is
# rejected. This test targets the genuinely-rejected index, matching the
# doc's literal assert rather than a stricter bound of our own invention.
# ---------------------------------------------------------------------------
def test_r5_table_index_out_of_range():
    with algopy_testing.algopy_testing_context():
        node = bytes([0xC2, 0x01, 0x02])  # 2 items
        data = Bytes(node)
        table, n = core.rlp_scan(data, UInt64(0))
        assert int(n) == 2
        with pytest.raises(Exception, match="R5"):
            core.rlp_table_item(data, table, UInt64(int(n) + 1))


# ---------------------------------------------------------------------------
# R2: content/payload end exceeds len(data) at the item-header level
# (distinct from the list-header-level truncation test above).
# ---------------------------------------------------------------------------
def test_r2_item_header_truncated():
    with algopy_testing.algopy_testing_context():
        # long string claims 70 bytes of content but the buffer only has 2
        # bytes after the header.
        node = bytes([0xB8, 0x46, 0x01, 0x02])
        data = Bytes(node)
        with pytest.raises(Exception, match="R2"):
            core.rlp_item_header(data, UInt64(0))
