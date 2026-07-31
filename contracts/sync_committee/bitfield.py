"""SSZ `Bitvector[512]` bit-order remap and the fused bitfield-walk +
box-gather + `ec_add` adaptive aggregation loop. Design doc §5.

The walk below is the ONLY pass over the bitfield: popcount falls out of
the same loop that gathers and aggregates (§5.2, §15 item 5 -- a separate
popcount pass is forbidden). It is also the ONLY shape the §9 group-sizing
decision is measured against (§5.3) -- do not split it into a bit-test
pass, a box-gather pass, and an `ec_add` pass, even though that would read
more "normal."
"""

from algopy import Bytes, UInt64, subroutine, urange, op
from algopy.op import EC, EllipticCurve

from contracts.primitives.bls.codec import g1_infinity, g1_negate
from contracts.sync_committee.constants import (
    G1_UNCOMPRESSED_BYTES,
    KEYS_PER_BOX,
    SYNC_COMMITTEE_BITS_BYTES,
    SYNC_COMMITTEE_SIZE,
)
from contracts.sync_committee.install import key_box_name, total_box_name


@subroutine
def avm_bit_index(i: UInt64) -> UInt64:
    """SSZ `Bitvector` bit `i` (byte `i//8`, LSB-first within that byte) ->
    the AVM `getbit` index (MSB-first within byte 0) (§5.1, §15 item 5):

        avm_bit_index(i) = (i // 8) * 8 + 7 - (i % 8)

    NOT optional, NOT cosmetic: a fully-participating committee (every
    vendored altair vector) still verifies under the wrong mapping, because
    every bit is set either way -- this only fails the first time real
    mainnet participation is partial (§5.1, T5).
    """
    return (i // UInt64(8)) * UInt64(8) + UInt64(7) - (i % UInt64(8))


@subroutine
def walk_and_accumulate(bits: Bytes, gen: UInt64, complement: bool) -> tuple[Bytes, UInt64]:
    """One fused pass over all `SYNC_COMMITTEE_SIZE` bits.

    In DIRECT mode (`complement=False`) it touches (box-reads + `ec_add`s)
    every member whose bit is SET -- the participants.

    In COMPLEMENT mode (`complement=True`) it touches every member whose
    bit is CLEAR -- the absentees. The caller combines the returned sum
    with the cached `A_total` (`§5.4`: `Σ_participants = A_total -
    Σ_absent`) -- this function does not know about `A_total` and does not
    do that combination, so it is usable identically from either mode.

    Returns `(touched_sum, touched_count)`. `touched_count` is `popcount`
    directly in direct mode, and `SYNC_COMMITTEE_SIZE - popcount` in
    complement mode -- the caller derives `popcount` from it (§5.2), never
    recomputes it.
    """
    assert bits.length == SYNC_COMMITTEE_BITS_BYTES
    acc = g1_infinity()
    have = False
    touched = UInt64(0)
    for i in urange(UInt64(SYNC_COMMITTEE_SIZE)):
        bit_set = op.getbit(bits, avm_bit_index(i)) != UInt64(0)
        touch = (bit_set and not complement) or (not bit_set and complement)
        if touch:
            box_name = key_box_name(gen, i // UInt64(KEYS_PER_BOX))
            pk = op.Box.extract(box_name, (i % UInt64(KEYS_PER_BOX)) * G1_UNCOMPRESSED_BYTES, UInt64(G1_UNCOMPRESSED_BYTES))
            if have:
                acc = EllipticCurve.add(EC.BLS12_381g1, acc, pk)
            else:
                acc = pk
                have = True
            touched += UInt64(1)
    return acc, touched


@subroutine
def aggregate_participants(bits: Bytes, gen: UInt64, mode: UInt64) -> tuple[Bytes, UInt64]:
    """The full §5.4 adaptive decision, composed from `walk_and_accumulate`.

    `mode` is a RELAYER HINT (§5.5), not a security-relevant input: both
    branches compute the same group element from the same contract-owned
    inputs (the bitfield, covered by the signature; the box-resident bound
    keys and `A_total`, both contract-written). A wrong or malicious `mode`
    only wastes the caller's own budget -- it cannot change the aggregate
    this function returns for a given bitfield.

    Returns `(aggregate_pubkey, popcount)`.
    """
    complement = mode == UInt64(1)
    touched_sum, touched = walk_and_accumulate(bits, gen, complement)
    if complement:
        popcount = UInt64(SYNC_COMMITTEE_SIZE) - touched
        a_total = op.Box.extract(total_box_name(gen), UInt64(0), UInt64(G1_UNCOMPRESSED_BYTES))
        agg = EllipticCurve.add(EC.BLS12_381g1, a_total, g1_negate(touched_sum))
        return agg, popcount
    return touched_sum, touched
