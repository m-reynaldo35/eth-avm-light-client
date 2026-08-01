"""
docs/design/006-account-storage-proof.md §4, §11.1 (A-M6-1's body-decode
half), §11.2 (S-M6-6/S-M6-7 malformed-body asserts). Real bytes from
`tests/fixtures/spike-reference/eth_data.json` (block 25,639,768), recomputed
per §4.1's own table -- USDT's real account leaf, whose value span (34, 70)
is what M5's `mpt_leaf_hop` actually returns for this proof (independently
re-confirmed by `test_mpt_real_walks.py::test_a1_real_account_inclusion`,
which pins the same 70-byte body).
"""
import algopy_testing
import pytest
from algopy import Bytes, UInt64

from contracts.composer.account import mpt6_account_body, mpt6_storage_value


def _account_leaf(eth_data) -> bytes:
    return bytes.fromhex(eth_data["proof"]["accountProof"][7][2:])


def _rlp_list(payload: bytes) -> bytes:
    """Correct RLP list-header encoding for any payload length (short OR
    long form) -- used to build derived, hand-constructed account bodies
    below. Naive `0xC0 + len(payload)` is only correct for len < 56; several
    of the malformed bodies below land exactly on or past that boundary."""
    n = len(payload)
    if n < 56:
        return bytes([0xC0 + n]) + payload
    length_bytes = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return bytes([0xF7 + len(length_bytes)]) + length_bytes + payload


def test_a_m6_1_real_account_body_decode_pinned(eth_data):
    """§4.1's full pinned table: exact body item offsets/lengths/kinds, and
    the extracted storageRoot/codeHash/nonce/balance all equal to
    eth_data.json's own independently-fetched values."""
    node = _account_leaf(eth_data)
    proof = eth_data["proof"]
    with algopy_testing.algopy_testing_context():
        storage_root, code_hash, nonce32, balance32 = mpt6_account_body(
            Bytes(node), UInt64(34), UInt64(70))
        assert bytes(storage_root.value).hex() == proof["storageHash"][2:]
        assert bytes(code_hash.value).hex() == proof["codeHash"][2:]
        assert bytes(nonce32.value) == int(proof["nonce"], 16).to_bytes(32, "big")
        assert bytes(balance32.value) == int(proof["balance"], 16).to_bytes(32, "big")


def test_account_body_node_absolute_offsets_match_fixture(eth_data):
    """§4.1's node-absolute cross-check: node[39:71] == storageHash,
    node[72:104] == codeHash -- verified independently of the subroutine,
    directly against the raw node bytes, so a bug that happened to make
    both computations agree on a wrong answer would still be caught."""
    node = _account_leaf(eth_data)
    proof = eth_data["proof"]
    assert node[39:71].hex() == proof["storageHash"][2:]
    assert node[72:104].hex() == proof["codeHash"][2:]
    assert node[34:36] == b"\xf8\x44"  # the account body's own RLP list header
    assert node[36] == 0x01  # nonce KIND_BYTE self-encoding
    assert node[37] == 0x2A  # balance KIND_BYTE self-encoding (42)


def test_a1_decode_past_value_span_rejected(eth_data):
    """A1: a `value_len` too small for the real body's payload_end must be
    rejected -- decoding must not silently read past the span M5 handed
    over even though the bytes beyond it are still hash-committed (§4.2's
    own reasoning)."""
    node = _account_leaf(eth_data)
    with algopy_testing.algopy_testing_context():
        with pytest.raises(Exception, match="A1"):
            mpt6_account_body(Bytes(node), UInt64(34), UInt64(69))  # 1 byte short


def test_a2_five_item_body_rejected():
    """A2: a well-formed RLP list of 5 short items (nonce/balance/
    storageRoot/codeHash/extra) must be rejected -- item3 (codeHash) ends
    before payload_end because a 5th item follows. Derived fixture, S-M6-7."""
    # rlp([0x01, 0x2a, 32-byte, 32-byte, 0x05]) -- 5 items.
    sr = bytes(range(32))
    ch = bytes(range(32, 64))
    body_payload = b"\x01\x2a" + b"\xa0" + sr + b"\xa0" + ch + b"\x05"
    value = _rlp_list(body_payload)
    with algopy_testing.algopy_testing_context():
        with pytest.raises(Exception, match="A2"):
            mpt6_account_body(Bytes(value), UInt64(0), UInt64(len(value)))


def test_a2_three_item_body_rejected():
    """A2: a well-formed RLP list of 3 items (nonce/balance/storageRoot,
    missing codeHash) must be rejected -- rlp_item_header called a 4th time
    reads past payload_end and fails structurally (R2) before A2's own
    assert even gets a chance, which is itself a legitimate rejection of a
    malformed body. Derived fixture, S-M6-7."""
    sr = bytes(range(32))
    body_payload = b"\x01\x2a" + b"\xa0" + sr
    value = _rlp_list(body_payload)
    with algopy_testing.algopy_testing_context():
        with pytest.raises(Exception):
            mpt6_account_body(Bytes(value), UInt64(0), UInt64(len(value)))


def test_a3_short_storage_root_rejected():
    """A3: a body whose storageRoot item is 20 bytes (not 32) must be
    rejected -- §4.5's fail-closed backstop against the silent-wrong-answer
    mode where `rlp_bytes(node, o2, 32)` would read 12 bytes into the
    FOLLOWING item. Derived fixture, S-M6-6."""
    twenty = bytes(range(20))
    ch = bytes(range(32, 64))
    body_payload = b"\x01\x2a" + bytes([0x80 + 20]) + twenty + b"\xa0" + ch
    value = _rlp_list(body_payload)
    with algopy_testing.algopy_testing_context():
        with pytest.raises(Exception, match="A3"):
            mpt6_account_body(Bytes(value), UInt64(0), UInt64(len(value)))


def test_a3_short_code_hash_rejected():
    """A3, the codeHash half: storageRoot is a well-formed 32-byte string,
    codeHash is 20 bytes."""
    sr = bytes(range(32))
    twenty = bytes(range(20))
    body_payload = b"\x01\x2a" + b"\xa0" + sr + bytes([0x80 + 20]) + twenty
    value = _rlp_list(body_payload)
    with algopy_testing.algopy_testing_context():
        with pytest.raises(Exception, match="A3"):
            mpt6_account_body(Bytes(value), UInt64(0), UInt64(len(value)))


def test_a4_oversized_nonce_rejected():
    """A4: a nonce item longer than 32 bytes must be rejected."""
    big_nonce = bytes(range(1, 34))  # 33 bytes
    sr = bytes(range(32))
    ch = bytes(range(32, 64))
    body_payload = bytes([0x80 + 33]) + big_nonce + b"\x2a" + b"\xa0" + sr + b"\xa0" + ch
    value = _rlp_list(body_payload)
    with algopy_testing.algopy_testing_context():
        with pytest.raises(Exception, match="A4"):
            mpt6_account_body(Bytes(value), UInt64(0), UInt64(len(value)))


def test_e_m6_6_multibyte_balance_shifts_storage_root_offset(eth_data):
    """E-M6-6: prove §4.2 decodes item 2 by walking items 0/1 rather than
    assuming a fixed offset, using a DERIVED body whose balance item is
    multi-byte (shifting where storageRoot starts) -- since eth_data.json's
    one real account (USDT) happens to have single-byte nonce/balance, this
    case needs a derived fixture to be exercised at all (§11.3's own
    framing: 'a real fixture from a second eth_getProof' is preferred but
    not available offline, so a realistic derived body is used, matching
    the task's documented fallback for exactly this situation)."""
    proof = eth_data["proof"]
    sr = bytes.fromhex(proof["storageHash"][2:])
    ch = bytes.fromhex(proof["codeHash"][2:])
    big_balance = (2**64 - 1).to_bytes(8, "big")  # 8-byte balance, multi-byte item
    body_payload = b"\x01" + bytes([0x80 + 8]) + big_balance + b"\xa0" + sr + b"\xa0" + ch
    value = _rlp_list(body_payload)
    with algopy_testing.algopy_testing_context():
        storage_root, code_hash, nonce32, balance32 = mpt6_account_body(
            Bytes(value), UInt64(0), UInt64(len(value)))
        assert bytes(storage_root.value) == sr
        assert bytes(code_hash.value) == ch
        assert bytes(balance32.value) == b"\x00" * 24 + big_balance
        assert bytes(nonce32.value) == b"\x00" * 31 + b"\x01"


def test_e_m6_3_zero_balance_normalises_and_is_distinguishable():
    """E-M6-3: a zero balance/nonce (RLP empty string 0x80, content_len==0)
    normalises to 32 zero bytes -- this is the §8.1 discriminator's OTHER
    half (an EXISTING account can have zero balance; the composite tells
    the two apart via `C.awalk`, not via this field being zero)."""
    sr = bytes(range(32))
    ch = bytes(range(32, 64))
    body_payload = b"\x80\x80" + b"\xa0" + sr + b"\xa0" + ch  # nonce=0x80, balance=0x80
    value = _rlp_list(body_payload)
    with algopy_testing.algopy_testing_context():
        storage_root, code_hash, nonce32, balance32 = mpt6_account_body(
            Bytes(value), UInt64(0), UInt64(len(value)))
        assert bytes(nonce32.value) == b"\x00" * 32
        assert bytes(balance32.value) == b"\x00" * 32
        assert bytes(storage_root.value) == sr


# ---------------------------------------------------------------------------
# §4.4 storage-value normalisation.
# ---------------------------------------------------------------------------
def test_a_m6_1_real_storage_value_normalisation(eth_data):
    """§4.4/A-M6-1: the real Binance-8 storage leaf's value span (32, 8)
    decodes one more RLP level to (33, 7), content 3f1ca131081cf8, matching
    eth_data.json's own `storageProof[0].value`."""
    sp = eth_data["proof"]["storageProof"][0]
    node = bytes.fromhex(sp["proof"][8][2:])
    with algopy_testing.algopy_testing_context():
        value32, is_zero = mpt6_storage_value(Bytes(node), UInt64(32), UInt64(8))
        assert not is_zero
        want = int(sp["value"], 16).to_bytes(32, "big")
        assert bytes(value32.value) == want


def test_e_m6_4_present_zero_entry():
    """E-M6-4 (§9.2): the storage leaf's value item is the RLP empty
    string 0x80, present in the trie -- decodes to 32 zero bytes with
    `is_zero_entry = True`, distinguishing `C_ZERO_ENTRY` from
    `C_ABSENT_SLOT` even though both carry a zero value."""
    node = bytes(31) + b"\x80"  # padding, then the RLP empty string at offset 31
    value_off = 31
    with algopy_testing.algopy_testing_context():
        value32, is_zero = mpt6_storage_value(Bytes(node), UInt64(value_off), UInt64(1))
        assert is_zero
        assert bytes(value32.value) == b"\x00" * 32


def test_a5_oversized_storage_value_rejected():
    """A5: a storage value RLP-decoding to more than 32 bytes must be
    rejected (uint256 overflow -- structurally impossible for a real
    Ethereum storage slot, but the assert is kept per TP-M6-1 not being a
    proof, §4.5's reasoning applied identically to §4.4)."""
    big = bytes(range(1, 34))  # 33 bytes
    node = bytes([0x80 + 33]) + big
    with algopy_testing.algopy_testing_context():
        with pytest.raises(Exception, match="A5"):
            mpt6_storage_value(Bytes(node), UInt64(0), UInt64(len(node)))


def test_a6_trailing_garbage_after_value_rejected():
    """A6: the value span contains more than exactly one RLP item -- the
    same free-canonicality trick as A2, specialised to a single item."""
    node = b"\x01\xff"  # item is 1 byte (KIND_BYTE, len=1), but span claims 2
    with algopy_testing.algopy_testing_context():
        with pytest.raises(Exception, match="A6"):
            mpt6_storage_value(Bytes(node), UInt64(0), UInt64(2))
