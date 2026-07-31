"""
EIP-2718 typed-receipt envelope tests: real vector (§6.2), E20 (type 0x00),
E21 (lone type byte), plus the full T1..T4 assert coverage.
"""
import algopy_testing
import pytest
from algopy import Bytes, UInt64

from contracts.primitives.rlp import eip2718


def test_real_vector_receipt_nodes2(eth_data):
    node = bytes.fromhex(eth_data["receipt_proof"]["nodes"][2][2:])
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        # item 1 of the leaf's 2-item list has span (7, 683)
        tx_type, payload_off, payload_len = eip2718.receipt_envelope(data, UInt64(7), UInt64(683))
        assert (int(tx_type), int(payload_off), int(payload_len)) == (2, 8, 682)


def test_legacy_receipt_passthrough():
    with algopy_testing.algopy_testing_context():
        # a legacy receipt is a plain RLP list >= 0xc0 -- returned unchanged
        node = bytes([0xF8, 0x02, 0x01, 0x02])
        data = Bytes(node)
        tx_type, off, length = eip2718.receipt_envelope(data, UInt64(0), UInt64(4))
        assert (int(tx_type), int(off), int(length)) == (0, 0, 4)


def test_typed_2930_2929_4844_7702_all_accepted():
    with algopy_testing.algopy_testing_context():
        for t in (0x01, 0x02, 0x03, 0x04, 0x7F):
            node = bytes([t, 0xC2, 0x01, 0x02])  # type byte + tiny legacy-shaped list
            data = Bytes(node)
            tx_type, off, length = eip2718.receipt_envelope(data, UInt64(0), UInt64(4))
            assert int(tx_type) == t
            assert int(off) == 1 and int(length) == 3


# ---------------------------------------------------------------------------
# E20: type 0x00 -> "T2".
# ---------------------------------------------------------------------------
def test_e20_type_zero_rejected():
    with algopy_testing.algopy_testing_context():
        node = bytes([0x00, 0xC2, 0x01, 0x02])
        data = Bytes(node)
        with pytest.raises(Exception, match="T2"):
            eip2718.receipt_envelope(data, UInt64(0), UInt64(4))


# ---------------------------------------------------------------------------
# E21: lone type byte, length 1 -> "T3".
# ---------------------------------------------------------------------------
def test_e21_lone_type_byte():
    with algopy_testing.algopy_testing_context():
        data = Bytes(bytes([0x02]))
        with pytest.raises(Exception, match="T3"):
            eip2718.receipt_envelope(data, UInt64(0), UInt64(1))


# ---------------------------------------------------------------------------
# T1: empty receipt value.
# ---------------------------------------------------------------------------
def test_t1_empty_value():
    with algopy_testing.algopy_testing_context():
        data = Bytes(bytes([0x00]))  # any byte, length asserted first
        with pytest.raises(Exception, match="T1"):
            eip2718.receipt_envelope(data, UInt64(0), UInt64(0))


# ---------------------------------------------------------------------------
# T2 (string-prefix range 0x80..0xbf): a string prefix cannot begin a
# receipt envelope, and cannot be a legacy receipt either.
# ---------------------------------------------------------------------------
def test_t2_string_prefix_rejected():
    with algopy_testing.algopy_testing_context():
        for t in (0x80, 0x99, 0xBF):
            data = Bytes(bytes([t, 0x00]))
            with pytest.raises(Exception, match="T2"):
                eip2718.receipt_envelope(data, UInt64(0), UInt64(2))


# ---------------------------------------------------------------------------
# T4: byte after the type byte is not a list prefix.
# ---------------------------------------------------------------------------
def test_t4_payload_not_a_list():
    with algopy_testing.algopy_testing_context():
        node = bytes([0x02, 0x81, 0x05])  # type=2, then a STRING not a list
        data = Bytes(node)
        with pytest.raises(Exception, match="T4"):
            eip2718.receipt_envelope(data, UInt64(0), UInt64(3))


# ---------------------------------------------------------------------------
# Regression pinned for the spike's §5.6 failure: rlp_scan (the general
# core) on a raw typed receipt value WITHOUT stripping the envelope must
# fail with "R1", never silently misparse.
# ---------------------------------------------------------------------------
def test_regression_unstripped_typed_receipt_fails_r1(eth_data):
    from contracts.primitives.rlp import core

    node = bytes.fromhex(eth_data["receipt_proof"]["nodes"][2][2:])
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        # item 1's raw content starts with the type byte 0x02 (< 0xc0) --
        # calling rlp_list_header directly on it (as if it were a plain RLP
        # list, forgetting to strip the envelope) must fail closed.
        with pytest.raises(Exception, match="R1"):
            core.rlp_list_header(data, UInt64(7))
