"""§6.3/§7: the hot ring, the pinned tier, and ring initialisation. Owns the
box mechanics and the §5.4 write-decision (idempotent / equivocation /
eviction / regression) -- `anchor_app.py` owns only the ARC4 dispatch and
the M4-read / fold sequencing (`bridge.py`).

§5.5's resolution of an AVM-level tension in the design doc, recorded here
because this is the module where it is implemented (documented again in
ROADMAP.md's M8 row): §5.4/§5.5's prose says the equivocation branch must
both "latch conflict := 1" (a state write that must PERSIST) and "FAIL the
transaction". On the AVM, a transaction that fails (returns non-approval)
discards EVERY state change it made, including one made earlier in the same
call -- there is no way to commit a global-state write and then abort the
same call. Latching the flag is the load-bearing property (§5.5: "continuing
to serve roots from a contract in that state is worse than serving none");
failing the specific call that discovers it is not. This module therefore
makes the anchoring call that DETECTS equivocation SUCCEED (so `conflict`
actually commits), while leaving the disputed box untouched -- every
SUBSEQUENT `attest`/`anchor_*`/`pin` call then fails closed via `N22`,
exactly as §5.5 specifies. `ring_admit_and_write` returns an outcome code
rather than asserting on the equivocation path so `anchor_app.py` can commit
the latch and still return a result rather than aborting.
"""

from algopy import Bytes, UInt64, subroutine, urange, op

from contracts.state_anchor.constants import (
    OFF_PIN_PAYER,
    PIN_BOX_PREFIX,
    PINNED_RECORD_LEN,
    RECORD_LEN,
    RING_BOX_PREFIX,
)
from contracts.state_anchor.record import a_block_number, record_content_matches

RING_WRITE_OK = 0  # empty slot or eviction -- new content written
RING_WRITE_IDEMPOTENT = 1  # identical content already present -- no-op
RING_WRITE_EQUIVOCATION = 2  # same block number, DIFFERENT content -- latch, do not write
RING_WRITE_REGRESSION = 3  # existing slot holds a NEWER block number -- reject


@subroutine
def ring_box_name(residue: UInt64) -> Bytes:
    return Bytes(RING_BOX_PREFIX) + op.itob(residue)


@subroutine
def pin_box_name(block_number: UInt64) -> Bytes:
    return Bytes(PIN_BOX_PREFIX) + op.itob(block_number)


@subroutine
def ring_residue(block_number: UInt64, ring_n: UInt64) -> UInt64:
    """`ring_n` is asserted a power of two at `create` (§6.2), so the
    residue is a three-opcode mask, never a `%`."""
    return block_number & (ring_n - UInt64(1))


@subroutine
def ring_init_chunk(cursor: UInt64, k: UInt64) -> UInt64:
    """§7.7: create `k` ring boxes starting at `cursor`, zero-filled
    (`box_create`'s own semantics -- a fresh ring slot's `version` byte is
    0, the "never written" sentinel §6.1 relies on). Returns the new
    cursor."""
    for j in urange(k):
        _created = op.Box.create(ring_box_name(cursor + j), UInt64(RECORD_LEN))
    return cursor + k


@subroutine
def ring_admit_and_write(
    ring_n: UInt64,
    hi_block: UInt64,
    candidate: Bytes,
) -> tuple[UInt64, Bytes]:
    """§5.4 + §7.4, fused. Returns `(outcome, existing_or_written_record)`.

    N-ADMIT (§7.4): `block_number > hi_block - ring_n`, with `hi_block == 0`
    admitting anything (bootstrap case, §12.1). Implemented as
    `candidate_block + ring_n > hi_block` to avoid a `UInt64` underflow when
    `hi_block < ring_n` (the common case for the first `ring_n` anchors).

    The caller (`anchor_app.py`) is responsible for:
      * the paired `beacon_slot > hi_slot` monotonic check when this
        function's return indicates the write actually advanced `hi_block`
        (§7.4) -- that check needs `hi_slot`/the new `beacon_slot`, which
        this function does not take, to keep its own signature focused on
        the ring-slot decision;
      * committing `conflict := 1` on `RING_WRITE_EQUIVOCATION` and
        `assert False, "N21"` on `RING_WRITE_REGRESSION` (this module's
        docstring explains why the equivocation case must NOT assert here).
    """
    new_block = a_block_number(candidate)
    assert new_block + ring_n > hi_block, "N-ADMIT"

    residue = ring_residue(new_block, ring_n)
    box_name = ring_box_name(residue)
    existing = op.Box.extract(box_name, UInt64(0), UInt64(RECORD_LEN))
    ex_block = a_block_number(existing)
    ex_version = op.getbyte(existing, UInt64(0))

    if ex_version == UInt64(0):
        # empty slot (§12.1) -- includes the genuine "never written" case,
        # since ring boxes are zero-filled at ring_init and version 0 is
        # otherwise unreachable (VERSION_1 is the only real value ever
        # written).
        op.Box.replace(box_name, UInt64(0), candidate)
        return UInt64(RING_WRITE_OK), candidate

    if ex_block == new_block:
        if record_content_matches(existing, candidate):
            return UInt64(RING_WRITE_IDEMPOTENT), existing  # §11 S15/S19 -- write nothing
        return UInt64(RING_WRITE_EQUIVOCATION), existing  # §11 S-CONF -- do NOT write

    if ex_block < new_block:
        op.Box.replace(box_name, UInt64(0), candidate)
        return UInt64(RING_WRITE_OK), candidate

    # ex_block > new_block: unreachable via the honest path once N-ADMIT
    # holds (§5.4's distinctness lemma) -- kept as a real, tested defence
    # rather than an unreachable-and-therefore-untested assert (M4 §16's
    # own lesson about "unreachable" asserts that turn out to be reachable).
    return UInt64(RING_WRITE_REGRESSION), existing


@subroutine
def finish_anchor_flow(
    ring_cursor: UInt64,
    ring_n: UInt64,
    frozen: UInt64,
    conflict: UInt64,
    hi_block: UInt64,
    hi_slot: UInt64,
    candidate: Bytes,
) -> tuple[UInt64, Bytes, UInt64, UInt64, UInt64]:
    """Fuses the §7.4/§5.4/§5.5 pre-checks (`N10`/`N11`/`N22`), the ring
    write decision (`ring_admit_and_write`), and the `hi_block`/`hi_slot`
    advance (§7.4's paired monotonic check) into ONE free subroutine that
    `anchor_app.py`'s `anchor_direct`/`anchor_historical` both call, each
    writing the returned values back to its own global state. Returns
    `(new_conflict, result_record, new_hi_block, new_hi_slot, wrote_new)`
    where `wrote_new` is 1 iff `n_anchored` should increment (§5.4: an
    idempotent no-op does not increment it)."""
    assert ring_cursor == ring_n, "N10"
    assert frozen == UInt64(0), "N11"
    assert conflict == UInt64(0), "N22"

    outcome, result = ring_admit_and_write(ring_n, hi_block, candidate)

    if outcome == UInt64(RING_WRITE_EQUIVOCATION):
        # box.py module docstring: latch and SUCCEED this call (an AVM-level
        # necessity -- a failing call cannot persist the state change that
        # is the whole point of this branch).
        return UInt64(1), result, hi_block, hi_slot, UInt64(0)
    assert outcome != UInt64(RING_WRITE_REGRESSION), "N21"

    if outcome == UInt64(RING_WRITE_OK):
        new_block = a_block_number(result)
        new_slot = op.btoi(op.extract(result, UInt64(10), UInt64(8)))  # a_beacon_slot
        if new_block > hi_block:
            assert new_slot > hi_slot, "N-ADMIT-monotonic"
            return conflict, result, new_block, new_slot, UInt64(1)
        return conflict, result, hi_block, hi_slot, UInt64(1)

    # RING_WRITE_IDEMPOTENT
    return conflict, result, hi_block, hi_slot, UInt64(0)


@subroutine
def read_ring_slot(ring_n: UInt64, block_number: UInt64) -> Bytes:
    residue = ring_residue(block_number, ring_n)
    return op.Box.extract(ring_box_name(residue), UInt64(0), UInt64(RECORD_LEN))


@subroutine
def pin_write(block_number: UInt64, record: Bytes, payer: Bytes) -> None:
    """§7.5: create `p:<block_number>`, `A || payer` (186 B). Caller has
    already verified the funding Payment (`N24`) before calling this."""
    assert payer.length == UInt64(32), "N24"
    name = pin_box_name(block_number)
    _created = op.Box.create(name, UInt64(PINNED_RECORD_LEN))
    op.Box.replace(name, UInt64(0), record + payer)


@subroutine
def pin_read_maybe(block_number: UInt64) -> tuple[bool, Bytes, Bytes]:
    """Returns `(exists, record, payer)`. `exists=False` means no pinned
    box for this block number (caller falls back to the ring, or to `N12`
    if neither has it)."""
    name = pin_box_name(block_number)
    length, exists = op.Box.length(name)
    if not exists:
        return False, Bytes(), Bytes()
    raw = op.Box.extract(name, UInt64(0), UInt64(PINNED_RECORD_LEN))
    return True, raw[0:RECORD_LEN], raw[OFF_PIN_PAYER : OFF_PIN_PAYER + 32]


@subroutine
def pin_delete(block_number: UInt64) -> None:
    name = pin_box_name(block_number)
    _deleted = op.Box.delete(name)
