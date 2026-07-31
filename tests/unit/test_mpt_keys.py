"""
docs/design/005-mpt-walker.md §9.4 suite R (key encoding) + the W1/W2 length
guards from §9.4's R4 and §4.1's "structurally impossible to pass in a
pre-hashed key" claim.
"""
import algopy_testing
import pytest
from algopy import Bytes, UInt64

from contracts.mpt.state import mpt_key_from_address, mpt_key_from_slot, mpt_key_from_tx_index


# ---------------------------------------------------------------------------
# §4.1 real vectors, recomputed independently here (design doc's own table).
# ---------------------------------------------------------------------------
def test_key_from_address_real_vector():
    addr = bytes.fromhex("dAC17F958D2ee523a2206206994597C13D831ec7"[:40])
    with algopy_testing.algopy_testing_context():
        key = mpt_key_from_address(Bytes(addr))
        assert bytes(key.value).hex() == "ab14d68802a763f7db875346d03fbf86f137de55814b191c069e721f47474733"


def test_key_from_slot_real_vector():
    slot = bytes.fromhex("0be16d71963429204d70543701f859c43526c316ac005c10114f4694ca405f36")
    with algopy_testing.algopy_testing_context():
        key = mpt_key_from_slot(Bytes(slot))
        assert bytes(key.value).hex() == "aa2813d62366783a4fc90e52c8cc595ba9fd2b278bc52248117c14c07e5394d8"


# ---------------------------------------------------------------------------
# W1/W2 -- length guards. R4: a 32-byte value fed to mpt_key_from_address
# (as if it were an already-hashed key) is rejected, not silently accepted.
# This is the structural half of TP-M5-2: there is no way to hand M5 a
# pre-derived key through this entry point.
# ---------------------------------------------------------------------------
def test_r4_mpt_key_from_address_rejects_32_byte_input():
    with algopy_testing.algopy_testing_context():
        already_hashed = bytes(32)
        with pytest.raises(Exception, match="W1"):
            mpt_key_from_address(Bytes(already_hashed))


def test_w1_mpt_key_from_address_rejects_19_and_21_bytes():
    with algopy_testing.algopy_testing_context():
        with pytest.raises(Exception, match="W1"):
            mpt_key_from_address(Bytes(bytes(19)))
        with pytest.raises(Exception, match="W1"):
            mpt_key_from_address(Bytes(bytes(21)))


def test_w2_mpt_key_from_slot_rejects_non_32_byte_input():
    with algopy_testing.algopy_testing_context():
        with pytest.raises(Exception, match="W2"):
            mpt_key_from_slot(Bytes(bytes(20)))  # a 20-byte address, wrong convention
        with pytest.raises(Exception, match="W2"):
            mpt_key_from_slot(Bytes(bytes(31)))


def test_mpt_key_from_slot_rejects_20_byte_address_shaped_input():
    """The two conventions are non-interchangeable at the type level (§4.1):
    an address cannot be fed to the slot deriver even though both are
    ultimately keccak256'd -- the length assert alone is the boundary."""
    with algopy_testing.algopy_testing_context():
        addr = bytes.fromhex("dAC17F958D2ee523a2206206994597C13D831ec7"[:40])
        with pytest.raises(Exception, match="W2"):
            mpt_key_from_slot(Bytes(addr))


# ---------------------------------------------------------------------------
# §4.2 / §9.4 suite R -- receipts-trie key encoding.
# ---------------------------------------------------------------------------
def test_r1_tx_index_31_matches_real_fixture():
    with algopy_testing.algopy_testing_context():
        key = mpt_key_from_tx_index(UInt64(31))
        assert bytes(key.value).hex() == "1f"


def test_r2_index_zero_is_0x80_not_0x00():
    """The index == 0 trap (§4.2): RLP(0) is 0x80 (the empty string), NOT
    0x00. Getting this wrong makes every proof about the first transaction
    in a block fail, invisibly, unless tested."""
    with algopy_testing.algopy_testing_context():
        key = mpt_key_from_tx_index(UInt64(0))
        assert bytes(key.value) == b"\x80"
        assert bytes(key.value) != b"\x00"


@pytest.mark.parametrize("index,expected_hex", [
    (1, "01"),
    (0x7F, "7f"),
    (0x80, "8180"),
    (0xFF, "81ff"),
    (0x100, "820100"),
    (0xFFFF, "82ffff"),
    (0x10000, "83010000"),
    (0xFFFFFF, "83ffffff"),
])
def test_r3_minimal_rlp_boundaries(index, expected_hex):
    with algopy_testing.algopy_testing_context():
        key = mpt_key_from_tx_index(UInt64(index))
        assert bytes(key.value).hex() == expected_hex


def test_w3_index_over_0xffffff_rejected():
    with algopy_testing.algopy_testing_context():
        with pytest.raises(Exception, match="W3"):
            mpt_key_from_tx_index(UInt64(0x1000000))


def test_w3_boundary_0xffffff_accepted():
    with algopy_testing.algopy_testing_context():
        key = mpt_key_from_tx_index(UInt64(0xFFFFFF))
        assert bytes(key.value).hex() == "83ffffff"
