"""
docs/design/007-receipt-log-proof.md §3.3/§9's headline test: the real fixture
receipt at tx 31 (block 25,639,768) -- leaf 690 B (well inside T1), EIP-1559,
2 logs, with log[0] hitting BOTH boundary values the design doc calls out as
important in the same pinned fixture: 4 topics (LOG4, the max Ethereum
allows) and 0 data. log[1] is the complementary case: 3 topics, 128 B data.

`_leaf_value_span` independently locates the leaf's value span (offset,
length) inside the raw leaf bytes using the `rlp` package -- NOT M7's own
`decode.py`, so this is a genuine differential check (M2/M5's own test
conventions: never validate a decoder's output using data prepared by that
same decoder).
"""
import json
import sys
from pathlib import Path

import algopy_testing
import rlp
from algopy import Bytes, UInt64

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from contracts.receipt.decode import mpt7_log_at, mpt7_receipt_body  # noqa: E402
from contracts.receipt.state import R_INCLUDED  # noqa: E402

LEAVES_JSON = REPO_ROOT / "tests" / "fixtures" / "spike-reference" / "zk-m7" / "leaves.json"


def _leaves():
    return json.loads(LEAVES_JSON.read_text())


def _leaf_for(tx: int) -> dict:
    for row in _leaves():
        if row["tx"] == tx:
            return row
    raise AssertionError(f"tx {tx} not found in {LEAVES_JSON}")


def _leaf_value_span(leaf: bytes) -> tuple[int, int]:
    """Independently locate (value_off, value_len) of a 2-item MPT leaf
    node `[hp_path, value]`'s second item, using the `rlp` package's own
    header parsing -- not M2's/M7's decoder. `consume_length_prefix`
    returns `(prefix, type, length, end)` where `end` is the offset of the
    first payload byte and `length` is the payload length; item 1 begins
    exactly where item 0's header+content ends."""
    d = rlp.decode(leaf)
    assert len(d) == 2
    _prefix, _outer_type, _list_len, list_payload_off = rlp.codec.consume_length_prefix(leaf, 0)
    _p0, _t0, l0, o0 = rlp.codec.consume_length_prefix(leaf, list_payload_off)
    item0_end = o0 + l0
    _p1, _t1, value_len, value_off = rlp.codec.consume_length_prefix(leaf, item0_end)
    assert leaf[value_off:value_off + value_len] == d[1]
    return value_off, value_len


def test_headline_tx31_log0_four_topics_zero_data():
    row = _leaf_for(31)
    leaf = bytes.fromhex(row["leaf_hex"])
    value_off, value_len = _leaf_value_span(leaf)
    assert value_len == 683, value_len  # design doc §3.3's own pinned number

    # independent reference: decode log 0 with plain `rlp`, not M7's decoder
    d = rlp.decode(leaf)
    body = rlp.decode(d[1][1:] if d[1][0] < 0xC0 else d[1])
    ref_log0 = body[3][0]
    ref_address, ref_topics, ref_data = ref_log0
    assert len(ref_topics) == 4
    assert ref_data == b""
    from Crypto.Hash import keccak
    h = keccak.new(digest_bits=256)
    h.update(ref_data)
    ref_data_hash = h.digest()

    with algopy_testing.algopy_testing_context():
        tx_type, status, cum_gas8, logs_table, n_logs = mpt7_receipt_body(
            Bytes(leaf), UInt64(value_off), UInt64(value_len))
        assert int(tx_type) == 2  # EIP-1559
        assert int(status) == 1
        assert int(n_logs) == 2

        address, n_topics, topics128, data_hash, data_len = mpt7_log_at(
            Bytes(leaf), logs_table, UInt64(0))
        assert int(n_topics) == 4
        assert int(data_len) == 0
        assert bytes(address.value) == ref_address
        assert bytes(topics128.value)[:128] == b"".join(ref_topics)
        assert bytes(data_hash.value) == ref_data_hash


def test_headline_tx31_log1_three_topics_128B_data():
    row = _leaf_for(31)
    leaf = bytes.fromhex(row["leaf_hex"])
    value_off, value_len = _leaf_value_span(leaf)

    with algopy_testing.algopy_testing_context():
        _tx_type, _status, _cum_gas8, logs_table, n_logs = mpt7_receipt_body(
            Bytes(leaf), UInt64(value_off), UInt64(value_len))
        assert int(n_logs) == 2

        address, n_topics, topics128, data_hash, data_len = mpt7_log_at(
            Bytes(leaf), logs_table, UInt64(1))
        assert int(n_topics) == 3
        assert int(data_len) == 128
        assert len(bytes(address.value)) == 20


def test_no_such_log_index_is_a_result_not_an_assert():
    """§5.4: log_index >= n_logs must be checkable by the CALLER without
    tripping an assert inside mpt7_receipt_body/mpt7_log_at -- this test
    exercises exactly that: n_logs comes back cleanly, and the caller (the
    driver's own _finalize_if_terminal, exercised at the contract level in
    tests/integration) decides R_NO_SUCH_LOG from it."""
    row = _leaf_for(31)
    leaf = bytes.fromhex(row["leaf_hex"])
    value_off, value_len = _leaf_value_span(leaf)

    with algopy_testing.algopy_testing_context():
        _tx_type, _status, _cum_gas8, _logs_table, n_logs = mpt7_receipt_body(
            Bytes(leaf), UInt64(value_off), UInt64(value_len))
        assert int(n_logs) == 2
        # log_index=2 would be R_NO_SUCH_LOG at the driver level -- verified
        # here only that n_logs itself is a plain, assert-free value the
        # caller can compare, per §5.4's requirement.


def test_real_multiple_t1_receipts_decode_without_error():
    """Broader real-data smoke test: every real T1-sized receipt (leaf <=
    1942 B) in the pinned fixture block decodes without tripping any L*
    assert, and n_logs matches the fixture's own independently-recorded
    n_logs field."""
    checked = 0
    for row in _leaves():
        if row["leaf_len"] > 1942:
            continue
        leaf = bytes.fromhex(row["leaf_hex"])
        value_off, value_len = _leaf_value_span(leaf)
        with algopy_testing.algopy_testing_context():
            _tx_type, _status, _cum_gas8, _logs_table, n_logs = mpt7_receipt_body(
                Bytes(leaf), UInt64(value_off), UInt64(value_len))
            assert int(n_logs) == row["n_logs"], (row["tx"], int(n_logs), row["n_logs"])
        checked += 1
    assert checked > 50, checked  # sanity: real fixture actually has plenty of T1 receipts
