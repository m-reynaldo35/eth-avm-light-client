"""
contracts/primitives/rlp/nibbles.py -- hex-prefix (compact) nibble-path
decode, nibble addressing, and nibble-range comparison with a byte-aligned
fast path. See docs/design/002-rlp-decoder.md §5.

`Op`-level exception (ARCHITECTURE.md, design doc §2.4): scoped to EXACTLY
the per-nibble fallback loop inside `nibbles_equal` (case 4 below).
Everything else in this file is ordinary typed Puya.
"""
from algopy import Bytes, UInt64, subroutine, op


@subroutine
def hp_decode(data: Bytes, off: UInt64, length: UInt64
              ) -> tuple[bool, UInt64, UInt64]:
    """Decode the hex-prefix header of the compact path at data[off:off+length].
    Returns (is_leaf, nibble_count, nib_index) where `nib_index` is the
    ABSOLUTE nibble index into `data` of path nibble 0 (== 2*off + skip).
    """
    assert length >= 1, "H1"
    b0 = op.getbyte(data, off)
    f = b0 >> 4
    assert f <= 3, "H2"
    if f & 1 == 0:
        assert b0 & 0x0F == 0, "H3"
    is_leaf = (f & 2) != 0
    skip = UInt64(1) if (f & 1) != 0 else UInt64(2)
    nibble_count = 2 * length - skip
    if f & 2 == 0:
        assert nibble_count >= 1, "H4"
    nib_index = 2 * off + skip
    return is_leaf, nibble_count, nib_index


@subroutine(inline=True)
def nibble_at(data: Bytes, k: UInt64) -> UInt64:
    """Nibble k of `data` (k=0 is the HIGH nibble of byte 0).

    Forced inline (measured, gate G4): Puya's 'auto' inlining heuristic
    does not inline this into `nibbles_equal`'s several call sites (5 real
    `callsub nibble_at` in the compiled TEAL), each paying real
    proto/frame_dig/retsub call overhead for a 3-opcode body. Forcing
    inline removed that overhead from every call site -- `nibble_at` is
    tiny, so the size cost of duplicating it is small relative to the
    opcode-budget win everywhere it is used in a hot path (the per-nibble
    fallback loop in `nibbles_equal`, and the odd/odd leading-nibble peel).
    """
    b = op.getbyte(data, k // 2)
    return b >> 4 if k % 2 == 0 else b & 15


@subroutine
def nibbles_equal(a: Bytes, a_nib: UInt64,
                   b: Bytes, b_nib: UInt64, count: UInt64) -> bool:
    """Compare `count` nibbles starting at absolute nibble index a_nib in `a`
    against b_nib in `b`. Byte-aligned fast path whenever `a_nib` and `b_nib`
    share the same parity (§5.4) -- for MPT leaves this is provably always
    the case (byte-string keys force `odd <=> consumed-nibbles-odd`), but
    extension nodes have no such guarantee, so the misaligned fallback below
    is real code, not dead code -- it is exercised by the derived extension
    fixtures (§8.2).

    Implementation note (erratum against the design doc's literal §5.4 case
    list, see docs/design/002-rlp-decoder.md discussion): the doc's own
    worked argument for leaves ("the compact remainder always begins at
    compact byte 1 ... and on the key side it begins at nibble c + odd,
    which is even in both cases") relies on comparing the REMAINDER after a
    possibly-odd leading nibble is peeled off -- not on `a_nib`/`b_nib`
    themselves being even. For an ODD leaf (the real accountProof[7] vector:
    nib_index=7, consumed-nibbles=7, both odd), calling this function with
    the full (odd, odd) start pair is exactly the realistic M5 call shape,
    and the doc's own numbers (gate G4, <= 20 budget) assume it hits a fast
    path. The doc's literal 4-case algorithm only ever tests `a_nib % 2 == 0
    and b_nib % 2 == 0`, so it does not: an ODD/ODD pair falls through to
    the O(count) loop below, 150x over budget on the 57-nibble vector. This
    is fixed here by peeling the (matching-parity) leading nibble when both
    starts are odd, after which both starts are even and the remainder is
    the aligned case the doc's prose describes. A genuine relative
    misalignment (`a_nib` and `b_nib` of DIFFERENT parity) has no such fix
    and still takes the per-nibble loop -- that case is real for extension
    nodes and must not be "optimised away" (§5.4).
    """
    if count == 0:
        return True

    if a_nib % 2 == b_nib % 2:
        if a_nib % 2 == 1:
            # Both starts sit mid-byte, at the SAME relative offset: peel
            # the one leading nibble each embeds in a byte's low nibble,
            # then both starts are byte-aligned and the remainder (if any)
            # is the aligned case below. This is the case the design doc's
            # §5.4 prose describes for leaves but the literal case list
            # omits (see note above).
            if nibble_at(a, a_nib) != nibble_at(b, b_nib):
                return False
            a_nib += 1
            b_nib += 1
            count -= 1
            if count == 0:
                return True

        if count % 2 == 0:
            # Aligned fast path: ~5 opcodes total, independent of length.
            return op.extract(a, a_nib // 2, count // 2) == op.extract(b, b_nib // 2, count // 2)

        # Aligned-with-odd-tail: aligned compare for count-1 nibbles, then
        # one nibble_at comparison for the final nibble.
        even_count = count - 1
        if op.extract(a, a_nib // 2, even_count // 2) != op.extract(b, b_nib // 2, even_count // 2):
            return False
        return nibble_at(a, a_nib + even_count) == nibble_at(b, b_nib + even_count)

    # `Op`-level exception (design doc §2.4, scope 2 of 2): genuine relative
    # misalignment (`a_nib`/`b_nib` different parity) -- the per-nibble
    # loop. 2 x nibble_at + compare per nibble. Genuinely reachable for
    # extension nodes; must not be "optimised away" on the strength of the
    # leaf invariant (§5.4).
    i = UInt64(0)
    while i < count:
        if nibble_at(a, a_nib + i) != nibble_at(b, b_nib + i):
            return False
        i += 1
    return True
