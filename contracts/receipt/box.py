"""
contracts/receipt/box.py -- T2's box-staging mechanics (design doc §3.4):
assembling a leaf that does not fit one transaction's arguments
(1,942 B < leaf <= 4,096 B) across sibling transactions of the same atomic
group, entirely inside that one group (no persistent state, no cross-group
session -- §3.5(d)'s objection, answered the same way §3.4 answers it).

TP-M7-4 (§3.4/§3.5): the staging box needs no integrity guarantee of its
own. Its contents are validated by the EXACT SAME check that validates an
argument-delivered node -- `keccak256(box_extract(...)) == W.expected`
inside `mpt_walk_node`, called by the driver immediately after
`mpt7_stage_walk_node` extracts the box's contents. A relayer that writes
wrong bytes into its own box produces a wrong hash and mpt_walk_node's own
"W11" rejects it -- nothing in this module re-checks the box's contents,
by design.

Box naming: the caller picks an 8-byte session name (design doc's own
pseudocode: `box_create(name, leaf_len)`) -- this reference driver does not
impose a naming policy (that is M9/M10's job, same scoping M5/M6's own
bench-app drivers use for their own out-of-scope production concerns).
"""
from algopy import Bytes, UInt64, subroutine, op

MIN_STAGED_LEAF = 1943  # T1/T2 boundary, exclusive (design doc §3.1)
MAX_STAGED_LEAF = 4096  # the AVM value cap (design doc §2.2)


@subroutine
def mpt7_stage_open(name: Bytes, leaf_len: UInt64) -> None:
    """MODE_STAGE_OPEN (§3.4 txn i): box_create(name, leaf_len).

    assert MIN_STAGED_LEAF <= leaf_len <= MAX_STAGED_LEAF -> "L7"
        (wrong tier for this mode -- a leaf this small belongs in T1's
        plain argument-delivered path, one this large is T3's problem, not
        T2's; §3.1's boundary, enforced here rather than left implicit)
    """
    assert leaf_len >= UInt64(MIN_STAGED_LEAF), "L7"
    assert leaf_len <= UInt64(MAX_STAGED_LEAF), "L7"
    _created = op.Box.create(name, leaf_len)


@subroutine
def mpt7_stage_write(name: Bytes, offset: UInt64, chunk: Bytes) -> None:
    """MODE_STAGE_WRITE (§3.4 txn i+1/i+2): box_replace(name, offset, chunk).

    No separate "L8" bound check here: the declared box size (`leaf_len`,
    fixed at MODE_STAGE_OPEN) is not re-supplied at write time (the design
    doc's own pseudocode passes only `off`/`chunk` to this step), and
    `op.Box.replace` already fails closed -- natively, at the AVM level --
    on any write that would run past the box's actual allocated size. A
    caller wanting a named M7 code instead of that raw panic would need to
    thread `leaf_len` through as well; not done here since the underlying
    safety property (a write cannot silently run past the box) holds
    either way.
    """
    op.Box.replace(name, offset, chunk)


@subroutine
def mpt7_stage_read(name: Bytes, leaf_len: UInt64) -> Bytes:
    """MODE_STAGE_WALK (§3.4 txn i+3), the read half: box_extract(name, 0,
    leaf_len). The caller feeds this straight into `mpt_walk_node` -- the
    keccak check happens there (TP-M7-4), not here."""
    return op.Box.extract(name, UInt64(0), leaf_len)


@subroutine
def mpt7_stage_close(name: Bytes) -> None:
    """MODE_STAGE_WALK (§3.4 txn i+3), the close half: box_del(name), run
    AFTER the walk/decode has consumed the box's contents (§3.4's diagram
    orders this last)."""
    _deleted = op.Box.delete(name)
