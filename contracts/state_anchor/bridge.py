"""§3 (beacon -> execution bridge) and §4 (historical mode). The composed,
fork-gated deep folds (Candidate B, §3.1), N-CHUNK (§3.5), N-INDEX (§4.3),
and N-FORK's two-lookup discipline (§3.4).

Imports M4's header code VERBATIM (§3.6, implementer checklist item 1) and
M3's asserting Merkle-branch wrapper (§12.6, item 12) -- this module
reimplements neither.
"""

from algopy import Application, Bytes, UInt64, subroutine, op

from contracts.primitives.ssz.merkle import assert_valid_merkle_branch
from contracts.sync_committee.constants import epoch_at_slot
from contracts.sync_committee.header import hash_tree_root_beacon_block_header, header_slot, le64

BEACON_HEADER_BYTES = 112
SLOTS_PER_HISTORICAL_ROOT = 8192


@subroutine
def assert_header_shape(header: Bytes) -> None:
    assert header.length == UInt64(BEACON_HEADER_BYTES), "N8"


@subroutine
def assert_fin_header_matches(header: Bytes, fin_root: Bytes) -> Bytes:
    """§4.4 step 3: `hash_tree_root(fin_header) == fin_root` (`N6`). Returns
    `fin_header`'s own `state_root` slice [48:80] for the caller's
    subsequent cross-check against M4's `fin_state_root` global (§4.4 step
    4)."""
    assert_header_shape(header)
    root = hash_tree_root_beacon_block_header(header)
    assert root == fin_root, "N6"
    return header[48:80]


@subroutine
def assert_fin_state_root_cross_check(header_state_root: Bytes, m4_fin_state_root: Bytes) -> None:
    """§4.4 step 4's redundant cross-check (`N7`): `fin_header.state_root`
    (already bound by the htr check) must agree with M4's own
    `fin_state_root` global -- catches "the relayer supplied a header from
    the wrong M4 epoch" as a named error rather than a mysterious branch
    failure four steps later."""
    assert header_state_root == m4_fin_state_root, "N7"


@subroutine
def block_number_leaf(block_number: UInt64) -> Bytes:
    """N-CHUNK (§3.5): the 32-byte SSZ chunk for `execution_payload.
    block_number` is ALWAYS derived on-chain from a native `uint64`
    argument, never accepted as a 32-byte blob directly -- `le64` is M4's
    own, already-tested byte-reversal (`contracts/sync_committee/
    header.py`), imported verbatim (§3.6)."""
    return le64(block_number) + op.bzero(UInt64(24))


@subroutine
def assert_branch_depth(branch: Bytes, gindex: UInt64) -> None:
    """`N9`: branch length must be an exact multiple of 32 AND equal to
    `depth(gindex) * 32` -- checked explicitly, ahead of M3's own identical
    (but differently-worded) assertion inside `compute_merkle_branch_root`,
    so this specific failure mode is independently observable under M8's
    own error code (G9-M8)."""
    assert gindex >= UInt64(1), "N9"
    depth = op.bitlen(gindex) - UInt64(1)
    assert branch.length == depth * UInt64(32), "N9"


@subroutine
def fold_execution_fields(
    body_root: Bytes,
    g_state_root: UInt64,
    g_receipts_root: UInt64,
    g_block_number: UInt64,
    el_state_root: Bytes,
    el_receipts_root: Bytes,
    el_block_number: UInt64,
    state_branch: Bytes,
    receipts_branch: Bytes,
    number_branch: Bytes,
) -> None:
    """§3: three independent depth-9 (or depth-8 pre-Deneb) folds from
    `body_root` to the caller-supplied `state_root`/`receipts_root`/
    `block_number` leaves. `N19` on any fold failure (via M3's own
    assertion message, propagated -- `N9` already isolates the
    depth-mismatch case ahead of this)."""
    assert el_state_root.length == UInt64(32), "N20-shape"
    assert el_receipts_root.length == UInt64(32), "N20-shape"
    assert_branch_depth(state_branch, g_state_root)
    assert_branch_depth(receipts_branch, g_receipts_root)
    number_leaf = block_number_leaf(el_block_number)
    assert_branch_depth(number_branch, g_block_number)
    assert_valid_merkle_branch(el_state_root, state_branch, g_state_root, body_root)
    assert_valid_merkle_branch(el_receipts_root, receipts_branch, g_receipts_root, body_root)
    assert_valid_merkle_branch(number_leaf, number_branch, g_block_number, body_root)


@subroutine
def assert_target_header_matches(header: Bytes, expected_root: Bytes) -> None:
    """HISTORICAL mode's target-header htr check -- distinct call site from
    `assert_fin_header_matches` (different failure semantics: a bad target
    header fails via the `block_roots` fold itself, `N18`, not `N6`, since
    the target header's root is what is BEING PROVEN into `block_roots`,
    not asserted against a pre-known value the way `fin_header` is). This
    helper exists to keep the header-shape check (`N8`) uniform; `header`'s
    hash_tree_root is computed by the caller for the fold, not re-verified
    against a pre-known root here -- see `bridge.py`'s HISTORICAL callers.
    """
    assert_header_shape(header)


@subroutine
def block_roots_gindex(g_block_roots_base: UInt64, t_slot: UInt64) -> UInt64:
    """N-INDEX (§4.3): `g = g_block_roots_base * 8192 + (t_slot mod 8192)`,
    composed ENTIRELY on-chain from `g_block_roots_base` (a governance-
    controlled fork-table value) and `t_slot` (derived from the target
    header's own `slot` field, never a caller-supplied index -- §11 S9,
    implementer checklist item 3: "any implementation that accepts an index
    parameter is a critical defect"). There is deliberately no parameter
    here through which a caller could inject an index directly."""
    residue = t_slot % UInt64(SLOTS_PER_HISTORICAL_ROOT)
    return g_block_roots_base * UInt64(SLOTS_PER_HISTORICAL_ROOT) + residue


@subroutine
def assert_window(t_slot: UInt64, fin_slot: UInt64) -> None:
    """N-WINDOW (§4.2): `t_slot < fin_slot` AND `fin_slot - t_slot <= 8192`.
    Belt-and-braces ahead of the `block_roots` fold itself (`N18`) -- named
    as `N16` so an out-of-window attempt is a legible error rather than an
    obscure fold failure."""
    assert t_slot < fin_slot, "N16"
    assert fin_slot - t_slot <= UInt64(SLOTS_PER_HISTORICAL_ROOT), "N16"


@subroutine
def fold_block_roots(
    fin_state_root: Bytes,
    g_block_roots_base: UInt64,
    t_slot: UInt64,
    target_root: Bytes,
    block_roots_branch: Bytes,
) -> None:
    """§4: prove `target_root` sits at `block_roots[t_slot mod 8192]` in the
    beacon state whose root is `fin_state_root`. `N18` on fold failure."""
    g = block_roots_gindex(g_block_roots_base, t_slot)
    assert_branch_depth(block_roots_branch, g)
    assert_valid_merkle_branch(target_root, block_roots_branch, g, fin_state_root)


@subroutine
def read_m4_finalized(m4_app: Application, expected_m4_id: UInt64) -> tuple[UInt64, Bytes, Bytes]:
    """§8.2/TP-M8-7: read `(fin_slot, fin_root, fin_state_root)` from the app
    whose id equals the immutable `m4` global, asserting the match (`N4`).
    A FREE subroutine (not an ARC4Contract instance method) deliberately --
    this codebase's own convention (M4's `forks.py`, this module's own
    other functions) keeps cross-cutting logic as module-level subroutines
    that take/return plain values rather than touching `self`, and a real,
    measured Puya limitation confirmed while building this module is that
    `@subroutine`-decorated INSTANCE methods on an `ARC4Contract` that
    reference `self.<global-state>` fail to compile ("unrecognised member")
    -- every other module in this codebase already avoided the pattern,
    this is the first to have hit it directly, and it is worth recording
    here rather than silently working around it with no note."""
    assert m4_app.id == expected_m4_id, "N4"
    fin_slot, ok1 = op.AppGlobal.get_ex_uint64(m4_app, Bytes(b"fin_slot"))
    assert ok1, "N4"
    fin_root, ok2 = op.AppGlobal.get_ex_bytes(m4_app, Bytes(b"fin_root"))
    assert ok2, "N4"
    fin_state_root, ok3 = op.AppGlobal.get_ex_bytes(m4_app, Bytes(b"fin_state_root"))
    assert ok3, "N4"
    return fin_slot, fin_root, fin_state_root


@subroutine
def epoch_of(slot: UInt64) -> UInt64:
    """Re-exported for callers that only need `bridge.py`'s own surface
    (N-FORK's two epoch lookups both key off this)."""
    return epoch_at_slot(slot)
