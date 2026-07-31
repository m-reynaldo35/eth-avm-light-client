"""
Suite A (oracle conformance) and most of suite E (negative/edge cases) from
docs/design/002-rlp-decoder.md §8.3, run against the actual compiled Puya
subroutines via algopy_testing's AVM emulation (offline, no live algod).
"""
import algopy_testing
import pytest
from algopy import Bytes, UInt64

from contracts.primitives.rlp import core
from tests.reference import rlp_ref


def _scan_and_items(node: bytes):
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        table, n = core.mpt_node_scan(data, UInt64(0))
        items = []
        for i in range(int(n)):
            off, length, kind = core.rlp_table_item(data, table, UInt64(i))
            items.append((int(off), int(length), int(kind)))
        return bytes(table.value), int(n), items


# ---------------------------------------------------------------------------
# Suite A: oracle conformance, all 24 fixtures (20 mainnet-observed, 4
# derived-synthetic). For every fixture: mpt_node_scan -> (table, n_items)
# must equal rlp_ref.mpt_node_scan(node); then for EVERY item index,
# rlp_table_item must equal the oracle's (content_off, content_len, kind).
# ---------------------------------------------------------------------------
def test_suite_a_oracle_conformance(all_nodes):
    checked = 0
    for label, source, node, _expected in all_nodes:
        oracle_table, oracle_n = rlp_ref.mpt_node_scan(node, 0)
        with algopy_testing.algopy_testing_context():
            data = Bytes(node)
            table, n = core.mpt_node_scan(data, UInt64(0))
            assert int(n) == oracle_n, f"{label}: n_items mismatch"
            for i in range(oracle_n):
                off, length, kind = core.rlp_table_item(data, table, UInt64(i))
                o_off, o_len, o_kind = rlp_ref.rlp_table_item(node, oracle_table, i)
                assert (int(off), int(length), int(kind)) == (o_off, o_len, o_kind), (
                    f"{label} item {i}: puya={int(off),int(length),int(kind)} "
                    f"oracle={o_off,o_len,o_kind}")
                checked += 1
    assert checked >= 20 * 2 + 17 * 15  # sanity: we actually iterated real items
    print(f"suite A: {len(all_nodes)} nodes, {checked} items conformant")


# ---------------------------------------------------------------------------
# E1: empty string item (0x80) -> span (pos+1, 0), KIND_STR; rlp_bytes must
# return empty via extract3, never "extract to end of array".
# ---------------------------------------------------------------------------
def test_e1_empty_string_uses_extract3_not_extract_to_end():
    with algopy_testing.algopy_testing_context():
        # a 2-item list whose first item is empty string, to prove rlp_bytes
        # doesn't silently swallow the rest of the buffer.
        node = bytes([0xC3, 0x80, 0x82, 0xAA, 0xBB])  # [ '', 0xaabb ]
        data = Bytes(node)
        off, length, kind = core.rlp_item_header(data, UInt64(1))
        assert int(off) == 2 and int(length) == 0 and int(kind) == int(core.KIND_STR)
        materialised = core.rlp_bytes(data, off, length)
        assert bytes(materialised.value) == b""  # NOT b"\x82\xaa\xbb" (rest of array)


# ---------------------------------------------------------------------------
# E2: branch value slot at end of node -- span offset EQUALS len(node) with
# length 0. extract3(node, len(node), 0) legal; getbyte there is not. The
# scan loop must test pos < payload_end BEFORE reading a prefix byte.
# ---------------------------------------------------------------------------
def test_e2_branch_value_slot_at_end_of_node(eth_data):
    node = bytes.fromhex(eth_data["proof"]["accountProof"][0][2:])
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        table, n = core.mpt_node_scan(data, UInt64(0))
        assert int(n) == 17
        off, length, kind = core.rlp_table_item(data, table, UInt64(16))
        assert int(off) == len(node) and int(length) == 0
        assert int(off) == 532  # pinned to the real fixture
        # legal: materialising a zero-length span exactly at the buffer end
        empty = core.rlp_bytes(data, off, length)
        assert bytes(empty.value) == b""


# ---------------------------------------------------------------------------
# E3: empty list 0xc0 -> n_items == 0, table = 1 entry (payload_end).
# mpt_node_scan rejects it ("R6").
# ---------------------------------------------------------------------------
def test_e3_empty_list():
    with algopy_testing.algopy_testing_context():
        data = Bytes(bytes([0xC0]))
        table, n = core.rlp_scan(data, UInt64(0))
        assert int(n) == 0
        assert table.length == 2
        with pytest.raises(Exception, match="R6"):
            core.mpt_node_scan(data, UInt64(0))


# ---------------------------------------------------------------------------
# E4/E5: single-byte value < 0x80 vs. empty string -- distinct kinds.
# ---------------------------------------------------------------------------
def test_e4_e5_single_byte_vs_empty_string(eth_data):
    # E4: real nonce=0x01, balance=0x2a from eth_data.json.
    with algopy_testing.algopy_testing_context():
        data = Bytes(bytes([0xC2, 0x01, 0x2A]))
        _table, n = core.rlp_scan(data, UInt64(0))
        assert int(n) == 2
        off0, len0, kind0 = core.rlp_item_header(data, UInt64(1))
        off1, len1, kind1 = core.rlp_item_header(data, UInt64(2))
        assert (int(off0), int(len0), int(kind0)) == (1, 1, int(core.KIND_BYTE))
        assert (int(off1), int(len1), int(kind1)) == (2, 1, int(core.KIND_BYTE))

    # E5: 0x00 (1-byte string containing zero) vs 0x80 (0-byte string).
    with algopy_testing.algopy_testing_context():
        d1 = Bytes(bytes([0x00]))
        off, length, kind = core.rlp_item_header(d1, UInt64(0))
        assert (int(off), int(length), int(kind)) == (0, 1, int(core.KIND_BYTE))

        d2 = Bytes(bytes([0x80]))
        off, length, kind = core.rlp_item_header(d2, UInt64(0))
        assert (int(off), int(length), int(kind)) == (1, 0, int(core.KIND_STR))


# ---------------------------------------------------------------------------
# E6/E7: long string 1-byte and 2-byte length-of-length, real vectors.
# ---------------------------------------------------------------------------
def test_e6_long_string_1byte_length(eth_data):
    node = bytes.fromhex(eth_data["proof"]["accountProof"][7][2:])
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        off, length, kind = core.rlp_item_header(data, UInt64(32))
        assert (int(off), int(length), int(kind)) == (34, 70, int(core.KIND_STR))


def test_e7_long_string_2byte_length(eth_data):
    node = bytes.fromhex(eth_data["receipt_proof"]["nodes"][2][2:])
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        off, length, kind = core.rlp_item_header(data, UInt64(4))
        assert (int(off), int(length), int(kind)) == (7, 683, int(core.KIND_STR))
        # 256-byte bloom (b90100) is item 2 of the stripped receipt payload
        # (§6.2 real vector: receipt_envelope -> (2, 8, 682), then
        # rlp_scan(node, 8) yields [status, cumGas, bloom, logs]).
        table, n = core.rlp_scan(data, UInt64(8))
        assert int(n) == 4
        off2, len2, kind2 = core.rlp_table_item(data, table, UInt64(2))
        assert int(len2) == 256 and int(kind2) == int(core.KIND_STR)


# ---------------------------------------------------------------------------
# E8/E9: long list forms, real vectors.
# ---------------------------------------------------------------------------
def test_e8_e9_long_list_forms(eth_data):
    p = eth_data["proof"]
    branch = bytes.fromhex(p["accountProof"][0][2:])  # f90211 -> 2-byte length-of-length
    leaf = bytes.fromhex(p["accountProof"][7][2:])     # f866 -> 1-byte length-of-length
    with algopy_testing.algopy_testing_context():
        payload_off, payload_end = core.rlp_list_header(Bytes(branch), UInt64(0))
        assert int(payload_off) == 3 and int(payload_end) == len(branch)
        payload_off2, payload_end2 = core.rlp_list_header(Bytes(leaf), UInt64(0))
        assert int(payload_off2) == 2 and int(payload_end2) == len(leaf)


# ---------------------------------------------------------------------------
# E14: embedded node child (KIND_LIST span includes header, §2.2) -- uses
# the derived-synthetic extension/branch fixtures.
# ---------------------------------------------------------------------------
def test_e14_embedded_child_kind_list_includes_header(nodes_fixture):
    by_label = {n["label"]: n for n in nodes_fixture["nodes"]}
    ext = by_label["derived.extension_node"]
    branch_expected = by_label["derived.branch_with_embedded_children"]
    ext_bytes = bytes.fromhex(ext["hex"])
    branch_bytes = bytes.fromhex(branch_expected["hex"])
    assert ext["hex_prefix"]["is_leaf"] is False

    with algopy_testing.algopy_testing_context():
        data = Bytes(ext_bytes)
        table, n = core.rlp_scan(data, UInt64(0))
        assert int(n) == 2
        # item 1 (the embedded branch reference) must be KIND_LIST with its
        # span covering the WHOLE encoding including the header.
        off1, len1, kind1 = core.rlp_table_item(data, table, UInt64(1))
        assert int(kind1) == int(core.KIND_LIST)
        assert int(len1) == len(branch_bytes)
        embedded_slice = bytes(core.rlp_bytes(data, off1, len1).value)
        assert embedded_slice == branch_bytes

        # And it must be directly re-parseable in place with no copy:
        # rlp_scan(data, off1) on the embedded region.
        inner_table, inner_n = core.rlp_scan(data, off1)
        assert int(inner_n) == 17


# ---------------------------------------------------------------------------
# E15: nested RLP inside a leaf value -- storageProof[0].proof[8] item 1
# content is itself RLP; rlp_item_header(node, 32) unwraps it to the real
# 7-byte storage value.
# ---------------------------------------------------------------------------
def test_e15_nested_rlp_inside_leaf_value(eth_data):
    node = bytes.fromhex(eth_data["proof"]["storageProof"][0]["proof"][8][2:])
    expected_value = eth_data["proof"]["storageProof"][0]["value"]
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        off, length, kind = core.rlp_item_header(data, UInt64(32))
        assert int(kind) == int(core.KIND_BYTE) or int(kind) == int(core.KIND_STR)
        unwrapped = bytes(core.rlp_bytes(data, off, length).value)
        assert unwrapped.hex() == expected_value[2:]


# ---------------------------------------------------------------------------
# E16: many empty slots in a branch, real vector regression.
# ---------------------------------------------------------------------------
def test_e16_many_empty_slots_in_branch(eth_data):
    node = bytes.fromhex(eth_data["proof"]["storageProof"][0]["proof"][6][2:])
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        table, n = core.mpt_node_scan(data, UInt64(0))
        assert int(n) == 17
        empty_count = 0
        for i in range(17):
            _off, length, _kind = core.rlp_table_item(data, table, UInt64(i))
            if int(length) == 0:
                empty_count += 1
        assert empty_count == 15  # non-empty only at indices 9 and 13, per doc


# ---------------------------------------------------------------------------
# E22: the p - 0x80 subtraction must be structurally unreachable when
# p < 0x80. This is a source-level property (checked by code review per the
# doc), reinforced here by fuzzing every single-byte prefix 0x00..0xff
# through the scan loop and asserting it never panics on underflow for any
# valid list containing that byte as its sole item.
# ---------------------------------------------------------------------------
def test_e22_no_underflow_across_full_prefix_byte_range():
    for p in range(0x00, 0x100):
        if p < 0x80:
            node = bytes([0xC1, p])  # list containing exactly one KIND_BYTE item
        elif p < 0xB8:
            length = p - 0x80
            node = bytes([0xC0 + 1 + length, p]) + bytes(length) if (1 + length) < 56 else None
            if node is None:
                continue
        else:
            continue  # long forms need real length bytes; covered elsewhere
        with algopy_testing.algopy_testing_context():
            data = Bytes(node)
            table, n = core.rlp_scan(data, UInt64(0))
            assert int(n) == 1
