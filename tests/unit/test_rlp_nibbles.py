"""
Suite B (hex-prefix) and Suite C (nibble comparison) from
docs/design/002-rlp-decoder.md §8.3, plus edge cases E17-E19.
"""
import algopy_testing
import pytest
from algopy import Bytes, UInt64
from Crypto.Hash import keccak

from contracts.primitives.rlp import nibbles


def kec(b: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


# ---------------------------------------------------------------------------
# Suite B: the three §5.3 worked vectors, real mainnet bytes, cross-checked
# against keccak256(address) / keccak256(storage_key).
# ---------------------------------------------------------------------------
def test_vector1_account_leaf_odd_leaf(eth_data):
    node = bytes.fromhex(eth_data["proof"]["accountProof"][7][2:])
    address = bytes.fromhex(eth_data["proof"]["address"][2:])
    key = kec(address)
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        is_leaf, nibble_count, nib_index = nibbles.hp_decode(data, UInt64(3), UInt64(29))
        assert bool(is_leaf) is True
        assert int(nibble_count) == 57
        assert int(nib_index) == 7
        first_nibble = nibbles.nibble_at(data, nib_index)
        assert int(first_nibble) == 8  # key nibble 7 == 0x8 (per §5.3 vector 1)

        # Full cross-check: the compact remainder equals the tail of
        # keccak256(address), and consumed(7) + path(57) == 64.
        key_data = Bytes(key)
        assert bool(nibbles.nibbles_equal(data, nib_index, key_data, UInt64(7),
                                           nibble_count)) is True
        assert 7 + int(nibble_count) == 64


def test_vector2_storage_leaf_even_leaf(eth_data):
    node = bytes.fromhex(eth_data["proof"]["storageProof"][0]["proof"][8][2:])
    storage_key = bytes.fromhex(eth_data["proof"]["storageProof"][0]["key"][2:])
    key = kec(storage_key)
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        is_leaf, nibble_count, nib_index = nibbles.hp_decode(data, UInt64(2), UInt64(29))
        assert bool(is_leaf) is True
        assert int(nibble_count) == 56
        assert int(nib_index) == 6

        key_data = Bytes(key)
        assert bool(nibbles.nibbles_equal(data, nib_index, key_data, UInt64(8),
                                           nibble_count)) is True
        assert 8 + int(nibble_count) == 64


def test_vector3_receipt_leaf_even_leaf_zero_nibbles(eth_data):
    node = bytes.fromhex(eth_data["receipt_proof"]["nodes"][2][2:])
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        # item 0 is the single byte 0x20 at span (3, 1) -- KIND_BYTE.
        is_leaf, nibble_count, nib_index = nibbles.hp_decode(data, UInt64(3), UInt64(1))
        assert bool(is_leaf) is True
        assert int(nibble_count) == 0
        assert int(nib_index) == 8
        # zero-length comparison must short-circuit True regardless of index
        assert bool(nibbles.nibbles_equal(data, nib_index, data, UInt64(0), UInt64(0))) is True


# ---------------------------------------------------------------------------
# Suite C: nibble comparison -- aligned fast path (covered above via the two
# hashed-key leaves), forced-misaligned cases (3)/(4) against the derived
# extension fixture, and mismatch detection at first/middle/last nibble.
# ---------------------------------------------------------------------------
def test_misaligned_fallback_case4(nodes_fixture):
    by_label = {n["label"]: n for n in nodes_fixture["nodes"]}
    ext = by_label["derived.extension_node"]
    ext_bytes = bytes.fromhex(ext["hex"])
    hp = ext["hex_prefix"]
    with algopy_testing.algopy_testing_context():
        data = Bytes(ext_bytes)
        nib_index = UInt64(hp["nib_index"])
        count = UInt64(hp["nibble_count"])
        # Compare the extension path against itself at an ODD starting
        # offset one nibble to the right -- this is relatively misaligned
        # by construction (case 4), and must correctly report a mismatch
        # once the shift causes nibble values to differ (or match if the
        # path happens to be a palindrome-like repeat, so we test both
        # equality-with-self at aligned offset and inequality at a shifted
        # one that provably differs).
        eq_self = nibbles.nibbles_equal(data, nib_index, data, nib_index, count)
        assert bool(eq_self) is True

        shifted = nibbles.nibbles_equal(data, nib_index, data, nib_index + UInt64(1), count)
        # a genuine misalignment: nib_index is even, nib_index+1 is odd ->
        # relative misalignment forces the fallback loop (case 4). The
        # extension path is 6 real hash-derived nibbles; a shift-by-one
        # self-compare is vanishingly unlikely to spuriously match, and
        # this fixture's nibbles are pinned, so this must be False.
        assert bool(shifted) is False


def test_misaligned_case3_odd_tail(nodes_fixture):
    """Case 3: aligned starts, odd count -- aligned extract3 pair for the
    even prefix, then one nibble_at for the final nibble."""
    by_label = {n["label"]: n for n in nodes_fixture["nodes"]}
    leaf_a = by_label["derived.leaf_a(embedded_child,odd_remainder)"]
    node = bytes.fromhex(leaf_a["hex"])
    hp = leaf_a["hex_prefix"]
    assert hp["nibble_count"] % 2 == 1  # this fixture was chosen to be odd
    with algopy_testing.algopy_testing_context():
        data = Bytes(node)
        nib_index = UInt64(hp["nib_index"])
        count = UInt64(hp["nibble_count"])
        eq_self = nibbles.nibbles_equal(data, nib_index, data, nib_index, count)
        assert bool(eq_self) is True

        # flip the last nibble by comparing against a count that overruns
        # into the next (different) byte -- construct a deliberately wrong
        # comparison buffer to prove mismatch detection at the last nibble.
        wrong = bytearray(node)
        last_nibble_byte_idx = (int(nib_index) + int(count) - 1) // 2
        wrong[last_nibble_byte_idx] ^= 0x0F  # flip the low nibble bits
        wrong_data = Bytes(bytes(wrong))
        mismatch = nibbles.nibbles_equal(data, nib_index, wrong_data, nib_index, count)
        assert bool(mismatch) is False


def _pack_nibbles(nibble_list: list[int]) -> bytes:
    """Pack a nibble list 2-per-byte, high nibble first; pads a trailing
    0x0 nibble if the list is odd-length (the pad is never read by a
    correctly-bounded caller)."""
    padded = list(nibble_list)
    if len(padded) % 2:
        padded.append(0)
    out = bytearray()
    for j in range(0, len(padded), 2):
        out.append((padded[j] << 4) | padded[j + 1])
    return bytes(out)


def test_mismatch_detection_first_middle_last_nibble():
    """Exhaustive: an 8-nibble buffer, flip exactly one nibble at the
    first/middle/last position and confirm nibbles_equal catches each one,
    both on the aligned fast path (a_nib=b_nib=0, count=8) and on the
    misaligned fallback loop (a_nib=0 into one buffer, b_nib=1 into a
    second buffer whose nibbles 1..8 are constructed to equal the first
    buffer's nibbles 0..7 -- forcing case 4)."""
    base_nibbles = [1, 2, 3, 4, 5, 6, 7, 8]
    a_bytes = _pack_nibbles(base_nibbles)
    # b's nibble 0 is a throwaway pad; nibbles 1..8 equal base_nibbles.
    b_bytes = _pack_nibbles([0xF] + base_nibbles)

    with algopy_testing.algopy_testing_context():
        a = Bytes(a_bytes)
        b_data = Bytes(b_bytes)
        # sanity: untouched buffers must agree on both paths
        assert bool(nibbles.nibbles_equal(a, UInt64(0), a, UInt64(0), UInt64(8))) is True
        assert bool(nibbles.nibbles_equal(a, UInt64(0), b_data, UInt64(1), UInt64(8))) is True

        for pos in (0, 3, 7):  # first, middle, last of the 8 compared nibbles
            # aligned fast path: mutate a copy of `a` itself
            mutated_a = list(base_nibbles)
            mutated_a[pos] ^= 0xF  # flip all 4 bits of that nibble
            b_aligned = Bytes(_pack_nibbles(mutated_a))
            assert bool(nibbles.nibbles_equal(a, UInt64(0), b_aligned, UInt64(0), UInt64(8))) is False

            # misaligned fallback: mutate the corresponding nibble (pos+1)
            # of the `b_bytes`-shaped buffer -- forces case 4 since a_nib=0
            # (even) but b_nib=1 (odd).
            mutated_b_nibbles = [0xF] + base_nibbles
            mutated_b_nibbles[pos + 1] ^= 0xF
            b_misaligned = Bytes(_pack_nibbles(mutated_b_nibbles))
            assert bool(nibbles.nibbles_equal(a, UInt64(0), b_misaligned, UInt64(1), UInt64(8))) is False


# ---------------------------------------------------------------------------
# Regression: the ODD/ODD leading-nibble-peel case (the design-doc-erratum
# fix -- see nibbles.py::nibbles_equal's docstring). Real vector 1
# (test_vector1_account_leaf_odd_leaf above) already proves this case is
# CORRECT and hits a fast path via the real account leaf's own key material;
# this test independently exercises the peel's mismatch-detection at the
# peeled leading nibble itself, in the remainder, and across both parities
# of the post-peel remainder count (even and odd), which the single real
# vector (57 nibbles, always matching) does not by itself prove.
# ---------------------------------------------------------------------------
def test_odd_odd_leading_nibble_peel():
    # 9 nibbles total: index 0 is a throwaway pad, indices 1..8 are the
    # payload -- so a_nib = b_nib = 1 is ODD in both buffers (same relative
    # offset, matching parity), which is exactly the case nibbles_equal's
    # peel-then-aligned fast path was added for.
    base_nibbles = [1, 2, 3, 4, 5, 6, 7, 8]
    a_bytes = _pack_nibbles([0xA] + base_nibbles)
    b_bytes = _pack_nibbles([0xB] + base_nibbles)  # pad differs -- irrelevant, index 0 unused

    with algopy_testing.algopy_testing_context():
        a = Bytes(a_bytes)
        b = Bytes(b_bytes)

        # count=8 (even): peel leaves a 7-nibble (odd) remainder ->
        # aligned-with-odd-tail sub-branch after the peel.
        assert bool(nibbles.nibbles_equal(a, UInt64(1), b, UInt64(1), UInt64(8))) is True
        # count=7 (odd): peel leaves a 6-nibble (even) remainder -> pure
        # aligned direct-compare sub-branch after the peel.
        assert bool(nibbles.nibbles_equal(a, UInt64(1), b, UInt64(1), UInt64(7))) is True

        for count in (7, 8):
            for pos in range(count):  # position within the compared range
                mutated = list(base_nibbles)
                mutated[pos] ^= 0xF
                b_mut = Bytes(_pack_nibbles([0xB] + mutated))
                result = nibbles.nibbles_equal(a, UInt64(1), b_mut, UInt64(1), UInt64(count))
                assert bool(result) is False, f"count={count} pos={pos} should mismatch"


# ---------------------------------------------------------------------------
# E17: hp_decode bad flag nibble (0x40..0xff) -> "H2".
# ---------------------------------------------------------------------------
def test_e17_bad_flag_nibble():
    with algopy_testing.algopy_testing_context():
        for bad_high in range(0x4, 0x10):
            data = Bytes(bytes([bad_high << 4]))
            with pytest.raises(Exception, match="H2"):
                nibbles.hp_decode(data, UInt64(0), UInt64(1))


# ---------------------------------------------------------------------------
# E18: hp_decode even flag with dirty low nibble -> "H3".
# ---------------------------------------------------------------------------
def test_e18_even_flag_dirty_low_nibble():
    with algopy_testing.algopy_testing_context():
        data = Bytes(bytes([0x21]))  # f=2 (even, leaf) but low nibble = 1 != 0
        with pytest.raises(Exception, match="H3"):
            nibbles.hp_decode(data, UInt64(0), UInt64(1))


# ---------------------------------------------------------------------------
# E19: zero-nibble extension -> "H4".
# ---------------------------------------------------------------------------
def test_e19_zero_nibble_extension():
    with algopy_testing.algopy_testing_context():
        data = Bytes(bytes([0x00]))  # f=0 (even, extension), nibble_count = 0
        with pytest.raises(Exception, match="H4"):
            nibbles.hp_decode(data, UInt64(0), UInt64(1))


# ---------------------------------------------------------------------------
# H1: empty compact path -> "H1".
# ---------------------------------------------------------------------------
def test_h1_empty_compact_path():
    with algopy_testing.algopy_testing_context():
        data = Bytes(bytes([0x20]))
        with pytest.raises(Exception, match="H1"):
            nibbles.hp_decode(data, UInt64(0), UInt64(0))
