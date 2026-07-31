"""
Suite D (mandatory, gates the §2.4 duplication) from
docs/design/002-rlp-decoder.md §8.3.

D1: for every item of every fixture node, the inlined scan-loop step and
the standalone `rlp_item_header` subroutine must agree. Concretely: for
item i with header at table[i], `rlp_item_header(data, table[i])` returns
(content_off, content_len, kind); the offset the SCAN LOOP independently
computed for the *next* item (table[i+1], or payload_end for the last
item) must equal what that same triple implies the next offset should be:
  KIND_BYTE -> next = content_off + 1        (== table[i] + 1)
  KIND_STR  -> next = content_off + content_len
  KIND_LIST -> next = table[i] + content_len  (content_off == table[i])
This is the real duplication the design doc flags as "not optional" -- the
scan loop's inline arithmetic must agree with rlp_item_header's
classification on every single item, not just typical ones.

D2: the Puya implementation and tests/reference/rlp_ref.py must agree on
every fixture, every item, the named nested decodes, and a property-based
corpus produced by the oracle's strict encoder.
"""
import random

import algopy_testing
import pytest
from algopy import Bytes, UInt64

from contracts.primitives.rlp import core
from tests.reference import rlp_ref


def _run_d1_on_node(node: bytes, label: str):
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        table, n = core.rlp_scan(data, UInt64(0))
        table_bytes = bytes(table.value)
        n = int(n)
        header_offsets = [int.from_bytes(table_bytes[2 * i:2 * i + 2], "big")
                           for i in range(n + 1)]
        for i in range(n):
            off, length, kind = core.rlp_item_header(data, UInt64(header_offsets[i]))
            off, length, kind = int(off), int(length), int(kind)
            next_from_table = header_offsets[i + 1]
            if kind == int(core.KIND_BYTE):
                expected_next = off + 1
            elif kind == int(core.KIND_STR):
                expected_next = off + length
            else:  # KIND_LIST
                assert off == header_offsets[i], f"{label} item {i}: KIND_LIST off must == header pos"
                expected_next = header_offsets[i] + length
            assert expected_next == next_from_table, (
                f"{label} item {i}: scan-loop next={next_from_table} vs "
                f"rlp_item_header-implied next={expected_next} (kind={kind})")


def test_d1_inlined_vs_standalone_agree_on_every_item(all_nodes):
    checked_nodes = 0
    for label, _source, node, _expected in all_nodes:
        _run_d1_on_node(node, label)
        checked_nodes += 1
    assert checked_nodes == len(all_nodes)


def test_d2_puya_vs_oracle_all_fixtures(all_nodes):
    for label, _source, node, _expected in all_nodes:
        oracle_table, oracle_n = rlp_ref.rlp_scan(node, 0)
        with algopy_testing.algopy_testing_context():
            data = Bytes(node)
            table, n = core.rlp_scan(data, UInt64(0))
            assert int(n) == oracle_n, label
            for i in range(oracle_n):
                off, length, kind = core.rlp_table_item(data, table, UInt64(i))
                o_off, o_len, o_kind = rlp_ref.rlp_table_item(node, oracle_table, i)
                assert (int(off), int(length), int(kind)) == (o_off, o_len, o_kind), label


def test_d2_nested_decode_account_leaf(eth_data):
    """rlp_scan(accountProof[7], 34) -> the 4-item account list."""
    node = bytes.fromhex(eth_data["proof"]["accountProof"][7][2:])
    oracle_table, oracle_n = rlp_ref.rlp_scan(node, 34)
    assert oracle_n == 4
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        table, n = core.rlp_scan(data, UInt64(34))
        assert int(n) == 4
        for i in range(4):
            off, length, kind = core.rlp_table_item(data, table, UInt64(i))
            o_off, o_len, o_kind = rlp_ref.rlp_table_item(node, oracle_table, i)
            assert (int(off), int(length), int(kind)) == (o_off, o_len, o_kind)
        # nonce=0x01, balance=0x2a per eth_data.json proof.nonce/balance
        off0, len0, _k0 = core.rlp_table_item(data, table, UInt64(0))
        nonce_bytes = bytes(core.rlp_bytes(data, off0, len0).value)
        assert int.from_bytes(nonce_bytes, "big") == int(eth_data["proof"]["nonce"], 16)
        off1, len1, _k1 = core.rlp_table_item(data, table, UInt64(1))
        balance_bytes = bytes(core.rlp_bytes(data, off1, len1).value)
        assert int.from_bytes(balance_bytes, "big") == int(eth_data["proof"]["balance"], 16)


def test_d2_nested_decode_storage_value(eth_data):
    """rlp_item_header(proof[8], 32) -> the unwrapped storage value."""
    node = bytes.fromhex(eth_data["proof"]["storageProof"][0]["proof"][8][2:])
    o_off, o_len, o_kind = rlp_ref.rlp_item_header(node, 32)
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        off, length, kind = core.rlp_item_header(data, UInt64(32))
        assert (int(off), int(length), int(kind)) == (o_off, o_len, o_kind)
        assert bytes(core.rlp_bytes(data, off, length).value).hex() == \
            eth_data["proof"]["storageProof"][0]["value"][2:]


def test_d2_nested_decode_stripped_receipt_payload(eth_data):
    """the stripped receipt payload -> 4 items (status, cumGas, bloom, logs)."""
    from contracts.primitives.rlp import eip2718

    node = bytes.fromhex(eth_data["receipt_proof"]["nodes"][2][2:])
    o_tx_type, o_poff, o_plen = rlp_ref.receipt_envelope(node, 7, 683)
    o_table, o_n = rlp_ref.rlp_scan(node, o_poff)
    assert o_n == 4
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        tx_type, poff, plen = eip2718.receipt_envelope(data, UInt64(7), UInt64(683))
        assert (int(tx_type), int(poff), int(plen)) == (o_tx_type, o_poff, o_plen)
        table, n = core.rlp_scan(data, poff)
        assert int(n) == 4 == eth_data["receipt_proof"]["num_logs"] + 2  # sanity, not identity
        for i in range(4):
            off, length, kind = core.rlp_table_item(data, table, UInt64(i))
            o_off, o_len, o_kind = rlp_ref.rlp_table_item(node, o_table, i)
            assert (int(off), int(length), int(kind)) == (o_off, o_len, o_kind)


# ---------------------------------------------------------------------------
# D2 supplementary: property-based corpus of RLP produced by the oracle's
# strict encoder. Real fixtures remain the primary gate (above); this is
# additional coverage over structurally-random-but-canonical RLP lists.
# ---------------------------------------------------------------------------
def _random_canonical_list(rng: random.Random, n_items: int) -> bytes:
    items = []
    for _ in range(n_items):
        choice = rng.random()
        if choice < 0.3:
            items.append(rlp_ref.encode_bytes(bytes([rng.randrange(0, 0x80)])))
        elif choice < 0.6:
            items.append(rlp_ref.encode_bytes(bytes(rng.randrange(0, 60))))
        elif choice < 0.85:
            items.append(rlp_ref.encode_bytes(bytes(rng.randrange(60, 200))))
        else:
            inner = [rlp_ref.encode_bytes(bytes(rng.randrange(0, 10))) for _ in range(rng.randrange(0, 4))]
            items.append(rlp_ref.encode_list(inner))
    return rlp_ref.encode_list(items)


# ---------------------------------------------------------------------------
# D3 (§16, O-1/O-2 follow-up): the new table-free fast paths -- rlp_scan2
# (exact-2-item, no loop) and rlp_scan_upto (early-exit single item) -- must
# agree with the oracle AND with the existing rlp_scan+rlp_table_item path
# on every fixture, exactly like D1/D2 gate the original table-based loop.
# This is the price of adding a second (now third) decode path per the
# design doc §2.4 duplication discipline.
# ---------------------------------------------------------------------------
def test_d3_scan2_agrees_on_every_2item_fixture(all_nodes):
    checked = 0
    for label, _source, node, expected in all_nodes:
        if expected["n_items"] != 2:
            continue
        oracle_table, oracle_n = rlp_ref.rlp_scan(node, 0)
        assert oracle_n == 2, label
        o_off0, o_len0, o_kind0 = rlp_ref.rlp_table_item(node, oracle_table, 0)
        o_off1, o_len1, o_kind1 = rlp_ref.rlp_table_item(node, oracle_table, 1)
        with algopy_testing.algopy_testing_context():
            data = Bytes(node)
            off0, len0, kind0, off1, len1, kind1 = core.rlp_scan2(data, UInt64(0))
            assert (int(off0), int(len0), int(kind0)) == (o_off0, o_len0, o_kind0), label
            assert (int(off1), int(len1), int(kind1)) == (o_off1, o_len1, o_kind1), label
        checked += 1
    assert checked >= 3, "expected at least the 3 known 2-item fixtures"


def test_d3_scan_upto_agrees_on_every_item_of_every_fixture(all_nodes):
    checked_items = 0
    for label, _source, node, expected in all_nodes:
        n_items = expected["n_items"]
        oracle_table, oracle_n = rlp_ref.rlp_scan(node, 0)
        assert oracle_n == n_items, label
        for i in range(n_items):
            o_off, o_len, o_kind = rlp_ref.rlp_table_item(node, oracle_table, i)
            with algopy_testing.algopy_testing_context():
                data = Bytes(node)
                off, length, kind = core.rlp_scan_upto(data, UInt64(0), UInt64(i))
                assert (int(off), int(length), int(kind)) == (o_off, o_len, o_kind), (
                    f"{label} item {i}")
            checked_items += 1
    assert checked_items > 0


def test_d3_scan_upto_rejects_out_of_range_want(all_nodes):
    """want == n_items (one past the last real item) must fail R9, matching
    rlp_table_item's own out-of-range behaviour (R5) for the table path."""
    for label, _source, node, expected in all_nodes:
        n_items = expected["n_items"]
        with algopy_testing.algopy_testing_context():
            data = Bytes(node)
            with pytest.raises(Exception):
                core.rlp_scan_upto(data, UInt64(0), UInt64(n_items))


def test_d2_property_based_corpus():
    rng = random.Random(20260730)
    for trial in range(200):
        n_items = rng.randrange(0, 17)
        node = _random_canonical_list(rng, n_items)
        if len(node) > 4096:
            continue
        oracle_table, oracle_n = rlp_ref.rlp_scan(node, 0)
        assert oracle_n == n_items
        with algopy_testing.algopy_testing_context():
            data = Bytes(node)
            table, n = core.rlp_scan(data, UInt64(0))
            assert int(n) == oracle_n, f"trial {trial}: {node.hex()}"
            for i in range(oracle_n):
                off, length, kind = core.rlp_table_item(data, table, UInt64(i))
                o_off, o_len, o_kind = rlp_ref.rlp_table_item(node, oracle_table, i)
                assert (int(off), int(length), int(kind)) == (o_off, o_len, o_kind), (
                    f"trial {trial} item {i}: {node.hex()}")


def test_d3_property_based_corpus_fast_paths():
    """Same property-based corpus as D2, but exercising rlp_scan2 (on the
    2-item trials) and rlp_scan_upto (on every item of every trial) against
    the oracle -- D3's fast-path counterpart to D2."""
    rng = random.Random(20260730)
    checked_scan2 = 0
    for trial in range(200):
        n_items = rng.randrange(0, 17)
        node = _random_canonical_list(rng, n_items)
        if len(node) > 4096:
            continue
        oracle_table, oracle_n = rlp_ref.rlp_scan(node, 0)
        assert oracle_n == n_items
        with algopy_testing.algopy_testing_context():
            data = Bytes(node)
            for i in range(oracle_n):
                o_off, o_len, o_kind = rlp_ref.rlp_table_item(node, oracle_table, i)
                off, length, kind = core.rlp_scan_upto(data, UInt64(0), UInt64(i))
                assert (int(off), int(length), int(kind)) == (o_off, o_len, o_kind), (
                    f"trial {trial} item {i}: {node.hex()}")
            if oracle_n == 2:
                o_off0, o_len0, o_kind0 = rlp_ref.rlp_table_item(node, oracle_table, 0)
                o_off1, o_len1, o_kind1 = rlp_ref.rlp_table_item(node, oracle_table, 1)
                off0, len0, kind0, off1, len1, kind1 = core.rlp_scan2(data, UInt64(0))
                assert (int(off0), int(len0), int(kind0)) == (o_off0, o_len0, o_kind0), trial
                assert (int(off1), int(len1), int(kind1)) == (o_off1, o_len1, o_kind1), trial
                checked_scan2 += 1
    assert checked_scan2 > 0
