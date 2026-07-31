"""T5 (design doc §11, §5.1): the SSZ `Bitvector[512]` bit-order remap.

Fully offline -- pure Python, no algod dependency (matches `ci-offline.yml`).
Mirrors `contracts/sync_committee/bitfield.py`'s `avm_bit_index` and the
fused walk's participant-selection logic (`walk_and_accumulate`) using the
plain-Python oracles already pinned in `reference.py`.

Flagged in the design doc as the "highest-value negative test": a
fully-participating committee (every vendored altair vector, and every
`popcount == 32` row in `test_signing_root.py`'s table) verifies correctly
under EITHER the correct remap or the naive (wrong) one, because every bit
is set either way. Only a partial, asymmetric bitfield can distinguish them
-- so T1-T3's 8/8 passing result says nothing about bit-order correctness,
and this file is what actually pins it.
"""

from __future__ import annotations

from tests.sync_committee import reference as ref

SYNC_COMMITTEE_SIZE = 512
SYNC_COMMITTEE_BITS_BYTES = SYNC_COMMITTEE_SIZE // 8  # 64

# §11 T5's own example set.
ASYMMETRIC_SET = frozenset({0, 1, 8, 63, 511})


def _avm_getbit(data: bytes, i: int) -> bool:
    """`op.getbit(data, i)`: bit 0 is the MOST significant bit of byte 0
    (§5.1). This is exactly `reference.py`'s `naive_msb_first_get` -- kept
    as a separate name here so the test reads as "the real AVM opcode
    applied to the remapped index," not "the known-wrong mapping."
    """
    return ref.naive_msb_first_get(data, i)


def _build_ssz_bitvector(set_indices: frozenset[int], size: int = SYNC_COMMITTEE_SIZE) -> bytes:
    """Builds a `Bitvector[size]` (`size // 8` bytes) with TRUE SSZ
    semantics: bit `i` in byte `i // 8`, LSB-first within that byte."""
    nbytes = size // 8
    out = bytearray(nbytes)
    for i in set_indices:
        out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def _contract_avm_bit_index(i: int) -> int:
    """Re-expression of `contracts/sync_committee/bitfield.py`'s
    `avm_bit_index` subroutine, kept textually parallel to the Puya source
    so a change there is easy to eyeball against this. Cross-checked
    exhaustively against `reference.py`'s own `avm_bit_index` below (T5a)."""
    return (i // 8) * 8 + 7 - (i % 8)


def _select_participants(bits: bytes, remap) -> set[int]:
    """Mirrors `walk_and_accumulate`'s selection predicate (bitfield.py):
    for each SSZ index `i`, the walk tests `op.getbit(bits, remap(i))`.
    `remap = ref.avm_bit_index` is the correct (§5.1) walk;
    `remap = lambda i: i` is the walk with no remap at all (the bug T5
    exists to catch)."""
    return {i for i in range(SYNC_COMMITTEE_SIZE) if _avm_getbit(bits, remap(i))}


def test_t5a_reference_and_contract_formula_agree_exhaustively():
    """`reference.py`'s `avm_bit_index` (used by T1-T3's offline walk) and
    the textual re-expression of `bitfield.py`'s own subroutine must be
    IDENTICAL for every one of the 512 indices -- this is the "keep this
    file's logic in lockstep with bitfield.py" contract `reference.py`'s
    docstring asks for, checked mechanically rather than by eyeball."""
    for i in range(SYNC_COMMITTEE_SIZE):
        assert ref.avm_bit_index(i) == _contract_avm_bit_index(i), i


def test_t5b_correct_remap_round_trips_every_bit():
    """For a `Bitvector[512]` with an intentionally asymmetric bit pattern,
    `getbit(bits, avm_bit_index(i))` (the AVM opcode applied to the §5.1
    remap) recovers the TRUE SSZ bit at every one of the 512 indices --
    not just the 5 that happen to be set."""
    bits = _build_ssz_bitvector(ASYMMETRIC_SET)
    for i in range(SYNC_COMMITTEE_SIZE):
        assert _avm_getbit(bits, ref.avm_bit_index(i)) == (i in ASYMMETRIC_SET), i
        # Cross-check against the independent SSZ-native oracle too.
        assert ref.ssz_bitvector_get(bits, i) == (i in ASYMMETRIC_SET), i


def test_t5c_asymmetric_bitfield_selects_exactly_the_intended_members():
    """§11 T5's own scenario: members {0, 1, 8, 63, 511}. The correctly
    remapped walk selects exactly this set."""
    bits = _build_ssz_bitvector(ASYMMETRIC_SET)
    selected = _select_participants(bits, ref.avm_bit_index)
    assert selected == ASYMMETRIC_SET


def test_t5d_naive_byte_order_only_mapping_selects_a_different_set():
    """THE negative test: `getbit(bits, i)` with NO remap at all (§15 item
    5's forbidden shortcut) selects a set that DIFFERS from the true SSZ
    participant set for this asymmetric bitfield. A verifier built on the
    naive mapping would aggregate the wrong subset of committee pubkeys --
    an aggregate signature check against the wrong subset must fail for
    honest data, which is what makes this "verifies with the wrong keys"
    class of bug externally observable rather than silently wrong."""
    bits = _build_ssz_bitvector(ASYMMETRIC_SET)
    naive_selected = _select_participants(bits, lambda i: i)  # no remap
    assert naive_selected != ASYMMETRIC_SET, (
        "the naive (byte-order-only) mapping accidentally matched the "
        "correct set -- the asymmetric fixture is not asymmetric enough "
        "to catch the bug; strengthen ASYMMETRIC_SET"
    )


def test_t5e_fully_participating_bitfield_cannot_distinguish_the_two_mappings():
    """Documents WHY T1-T3's 8/8-passing vendored vectors (all
    `popcount == 32` / fully participating, per `test_signing_root.py`)
    say nothing about bit-order correctness: a bitfield of all-1-bits
    selects the SAME set under either mapping. This is not a claim the
    contract needs to satisfy -- it is the reason a dedicated asymmetric
    test (T5a-T5d above) is mandatory rather than optional (§5.1, §11 T5)."""
    bits = bytes([0xFF] * SYNC_COMMITTEE_BITS_BYTES)
    correct = _select_participants(bits, ref.avm_bit_index)
    naive = _select_participants(bits, lambda i: i)
    assert correct == naive == set(range(SYNC_COMMITTEE_SIZE))


def test_t5f_single_bit_scan_pins_every_index_individually():
    """Belt-and-suspenders: one bit set at a time, for ALL 512 positions
    (not just the 5-member asymmetric sample), the correct remap selects
    exactly `{i}` and the naive mapping selects a DIFFERENT singleton for
    every `i` not a multiple of 8 minus... concretely: naive and correct
    agree only where `avm_bit_index(i) == i`, i.e. `i % 8 == 7 - i % 8`,
    which has no integer solution -- so they must disagree at EVERY single
    index tested here, a strictly stronger claim than T5d's one example."""
    mismatches = 0
    for i in range(SYNC_COMMITTEE_SIZE):
        bits = _build_ssz_bitvector(frozenset({i}))
        correct = _select_participants(bits, ref.avm_bit_index)
        naive = _select_participants(bits, lambda idx: idx)
        assert correct == {i}
        if naive != {i}:
            mismatches += 1
    assert mismatches == SYNC_COMMITTEE_SIZE, (
        f"expected the naive mapping to disagree at all {SYNC_COMMITTEE_SIZE} "
        f"single-bit positions, got {mismatches}"
    )
