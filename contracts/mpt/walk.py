"""
contracts/mpt/walk.py -- the verified descent (docs/design/005-mpt-walker.md
§5): branch (§5.2), extension (§5.3) and leaf (§5.4) node handlers, the
pure-core single-node walker `mpt_walk_node` (§7.1), and embedded/inline
child handling (§5.5).

This is M5's security content. The load-bearing lines, restated from the
design doc so a reviewer can find them without cross-referencing:

  - branch (mpt_branch_hop): the terminal check (`depth == key_nibs`) runs
    BEFORE `nibble_at` is called -- calling it at depth == key_nibs would
    read past the key. The descent index `nib` is a function of `key` and
    `depth` ONLY; there is no parameter, argument, or caller-settable field
    that selects a different child. This is the module's whole reason to
    exist (§0).
  - extension (mpt_extension_hop): the bounds check
    (`depth + n_path > key_nibs`) runs BEFORE `nibbles_equal`, which would
    otherwise read past the end of `key`.
  - leaf (mpt_leaf_hop): the length check is EXACT equality
    (`depth + n_path != key_nibs`), never `<=`/`>=`. A leaf whose path is a
    strict prefix of the key remainder is a leaf for a different, shorter
    key -- accepting it relocates the original defect to the terminal hop.
    This is the single line the module's security case rests on most
    directly (§5.4).

--- §16 (post-approval fix) ---
`mpt_branch_hop` used to take `(node, start, w)` and re-run the full
list-header + item-0 + item-1 decode itself (via `mpt_descend`) on every
call, DUPLICATING the decode `mpt_walk_node` had just run to learn `arity`
in the first place. It now takes the already-decoded item spans
(`o0,l0,k0,o1,l1,k1,payload_end`) from `mpt_walk_node`'s single
`mpt_arity_discriminate` call and only ever does NEW work (the item-2-
onward skip loop, via `mpt_branch_item_at`). This is a real, measured fix
(see design doc §16.2), not a change to what gets checked: `depth`,
`key_nibs`, `key`, `nib = nibble_at(key, depth)`, and every classification
of the fetched child reference are byte-for-byte the same computation as
before. The one thing that changed is the OLD internal `assert arity ==
17, "W5"` inside this function is gone -- see §16.2 for why that was
already dead code on every real (mpt_walk_node-routed) call path, and
docs/design/005-mpt-walker.md §16.2 / this module's docstring on
`mpt_branch_hop` for the precondition that replaces it.
"""
from algopy import Bytes, UInt64, subroutine, op

from contracts.mpt.descend import mpt_arity_discriminate, mpt_branch_item_at
from contracts.mpt.state import (
    WALK_ABSENT_BRANCH_TERM,
    WALK_ABSENT_EMPTY_SLOT,
    WALK_ABSENT_EXT_DIVERGE,
    WALK_ABSENT_LEAF_DIVERGE,
    WALK_CONTINUE,
    WALK_INCLUDED,
    w_depth,
    w_expected,
    w_key,
    w_key_nibs,
    w_status,
    w_with_continue,
    w_with_continue_depth_only,
    w_with_terminal,
)
from contracts.primitives.rlp.core import KIND_LIST, KIND_STR, rlp_bytes
from contracts.primitives.rlp.nibbles import hp_decode, nibble_at, nibbles_equal

INLINE_STEPS_MAX = 8

# hop-kind discriminators (internal to this module -- NOT the W status
# byte): 0 = terminal, 1 = continue via a new supplied node, 2 = continue
# via an embedded/inline child in the SAME buffer (§5.5).
_HOP_TERMINAL = 0
_HOP_NEXT_NODE = 1
_HOP_INLINE = 2


@subroutine
def mpt_branch_hop(node: Bytes, o0: UInt64, l0: UInt64, k0: UInt64,
                    o1: UInt64, l1: UInt64, k1: UInt64, payload_end: UInt64,
                    w: Bytes) -> tuple[UInt64, Bytes, UInt64, UInt64, UInt64]:
    """One branch-node hop (§5.2). Returns
    (hop_kind, w_out, value_off, value_len, child_off).

    PRECONDITION (§16.2): `(o0,l0,k0,o1,l1,k1,payload_end)` must be the
    result of `mpt_arity_discriminate(node, start)` for the SAME `node` and
    `start` this call is walking, with that discrimination having already
    returned `arity == 17`. `mpt_walk_node` -- the only production caller
    -- always satisfies this by construction (it discriminates once, then
    routes here only on arity == 17). This function no longer re-derives
    or re-checks arity itself (that used to be a second, fully redundant
    list-header + item-0 + item-1 decode on every branch hop, "W5" --
    §16.2 measured this as real, avoidable duplicated work). A caller that
    invokes `mpt_branch_hop` directly, bypassing `mpt_arity_discriminate`,
    is responsible for supplying values that actually came from decoding
    `node`; nothing here re-verifies that."""
    depth = w_depth(w)
    key_nibs = w_key_nibs(w)
    key = w_key(w)

    # 1. TERMINAL CHECK, FIRST -- ordering is load-bearing (§5.2).
    assert depth <= key_nibs, "W4"
    if depth == key_nibs:
        ov, lv, _kv = mpt_branch_item_at(node, o0, l0, k0, o1, l1, k1, payload_end, UInt64(16))
        if lv == UInt64(0):
            return (UInt64(_HOP_TERMINAL), w_with_terminal(w, UInt64(WALK_ABSENT_BRANCH_TERM)),
                    UInt64(0), UInt64(0), UInt64(0))
        return UInt64(_HOP_TERMINAL), w_with_terminal(w, UInt64(WALK_INCLUDED)), ov, lv, UInt64(0)

    # 2. DERIVE THE INDEX FROM THE KEY -- never from an argument.
    nib = nibble_at(key, depth)

    # 3. FETCH THAT CHILD, AND ONLY THAT CHILD.
    oc, lc, kc = mpt_branch_item_at(node, o0, l0, k0, o1, l1, k1, payload_end, nib)

    # 4. CLASSIFY THE CHILD REFERENCE.
    if kc == UInt64(KIND_LIST):
        return (UInt64(_HOP_INLINE), w_with_continue_depth_only(w, depth + UInt64(1)),
                UInt64(0), UInt64(0), oc)
    assert kc == UInt64(KIND_STR), "W6"
    if lc == UInt64(0):
        return (UInt64(_HOP_TERMINAL), w_with_terminal(w, UInt64(WALK_ABSENT_EMPTY_SLOT)),
                UInt64(0), UInt64(0), UInt64(0))
    assert lc == UInt64(32), "W6"
    next_expected = rlp_bytes(node, oc, UInt64(32))
    return (UInt64(_HOP_NEXT_NODE), w_with_continue(w, next_expected, depth + UInt64(1)),
            UInt64(0), UInt64(0), UInt64(0))


@subroutine
def mpt_extension_hop(node: Bytes, o0: UInt64, l0: UInt64,
                       o1: UInt64, l1: UInt64, k1: UInt64, w: Bytes
                       ) -> tuple[UInt64, Bytes, UInt64, UInt64, UInt64]:
    """One extension-node hop (§5.3): arity==2, hex-prefix non-terminating.
    `(o0,l0)` is item 0 (the compact path), `(o1,l1,k1)` is item 1 (the
    child reference) -- both already decoded by the caller's arity-
    discriminating mpt_descend call, per §5.1's "item 0 is returned even in
    the branch case, costs nothing" reuse principle applied here too."""
    depth = w_depth(w)
    key_nibs = w_key_nibs(w)
    key = w_key(w)
    _is_leaf, n_path, nib_index = hp_decode(node, o0, l0)

    # BOUNDS FIRST -- an extension can only match if the key has room for
    # it; without this, nibbles_equal would read past the end of `key`.
    if depth + n_path > key_nibs:
        return (UInt64(_HOP_TERMINAL), w_with_terminal(w, UInt64(WALK_ABSENT_EXT_DIVERGE)),
                UInt64(0), UInt64(0), UInt64(0))

    # THE COMPARISON -- the security check.
    if not nibbles_equal(node, nib_index, key, depth, n_path):
        return (UInt64(_HOP_TERMINAL), w_with_terminal(w, UInt64(WALK_ABSENT_EXT_DIVERGE)),
                UInt64(0), UInt64(0), UInt64(0))

    new_depth = depth + n_path
    if k1 == UInt64(KIND_LIST):
        return UInt64(_HOP_INLINE), w_with_continue_depth_only(w, new_depth), UInt64(0), UInt64(0), o1
    assert k1 == UInt64(KIND_STR), "W6"
    assert l1 != UInt64(0), "W7"  # an extension's child is never empty (well-formed trie)
    assert l1 == UInt64(32), "W6"
    next_expected = rlp_bytes(node, o1, UInt64(32))
    return UInt64(_HOP_NEXT_NODE), w_with_continue(w, next_expected, new_depth), UInt64(0), UInt64(0), UInt64(0)


@subroutine
def mpt_leaf_hop(node: Bytes, o0: UInt64, l0: UInt64, o1: UInt64, l1: UInt64, w: Bytes
                  ) -> tuple[UInt64, Bytes, UInt64, UInt64, UInt64]:
    """One leaf-node hop (§5.4): arity==2, hex-prefix terminating. Always
    terminal (a leaf has no child to continue into)."""
    depth = w_depth(w)
    key_nibs = w_key_nibs(w)
    key = w_key(w)
    _is_leaf, n_path, nib_index = hp_decode(node, o0, l0)

    # EXACT LENGTH -- not >=, not <=. The module's central security check
    # (§5.4): rejects a leaf whose path is a strict prefix of the key
    # remainder, and (the converse, same test) a key remainder longer than
    # the leaf path -- a sound exclusion proof.
    if depth + n_path != key_nibs:
        return (UInt64(_HOP_TERMINAL), w_with_terminal(w, UInt64(WALK_ABSENT_LEAF_DIVERGE)),
                UInt64(0), UInt64(0), UInt64(0))

    # EXACT CONTENT over the whole remainder.
    if not nibbles_equal(node, nib_index, key, depth, n_path):
        return (UInt64(_HOP_TERMINAL), w_with_terminal(w, UInt64(WALK_ABSENT_LEAF_DIVERGE)),
                UInt64(0), UInt64(0), UInt64(0))

    return UInt64(_HOP_TERMINAL), w_with_terminal(w, UInt64(WALK_INCLUDED)), o1, l1, UInt64(0)


@subroutine
def mpt_walk_node(node: Bytes, w: Bytes) -> tuple[Bytes, UInt64, UInt64]:
    """Verify keccak256(node) == w.expected, then walk as far as possible
    INSIDE this one buffer (following inline/embedded children, §5.5).
    Returns (w_out, value_off, value_len); value_* are meaningful only when
    w_out's status == WALK_INCLUDED, and index into `node`.

    This subroutine, mpt_descend, the three node-type handlers above, and
    the key derivations in state.py are the whole of M5's security content,
    and none of them touch Txn -- they are unit-testable offline against
    the Python reference walker with no transaction context at all
    (design doc §7.1).

    assert keccak256(node) == w[33:65]  -> "W11"
    assert w[0] == WALK_CONTINUE         -> "W12" (cannot extend a terminal walk)
    assert inline_steps <= 8             -> "W8"
    """
    assert op.keccak256(node) == w_expected(w), "W11"
    assert w_status(w) == UInt64(WALK_CONTINUE), "W12"

    start = UInt64(0)
    steps = UInt64(0)
    cur_w = w
    value_off = UInt64(0)
    value_len = UInt64(0)
    done = False
    while not done:
        assert steps <= UInt64(INLINE_STEPS_MAX), "W8"
        # §16.2: discriminate ONCE per hop. The old code called mpt_descend
        # here (want=0) purely to learn `arity`, discarding everything but
        # that value for the arity==17 case, then mpt_branch_hop called
        # mpt_descend AGAIN from scratch -- a full second list-header +
        # item-0 + item-1 decode on every single branch hop. This single
        # mpt_arity_discriminate call is now the only decode of node/start;
        # its results are threaded into whichever handler is dispatched.
        arity, payload_end, o0, l0, k0, o1, l1, k1 = mpt_arity_discriminate(node, start)
        if arity == UInt64(17):
            hop_kind, cur_w, value_off, value_len, child_off = mpt_branch_hop(
                node, o0, l0, k0, o1, l1, k1, payload_end, cur_w)
        else:
            is_leaf, _n_path, _nib_index = hp_decode(node, o0, l0)
            if is_leaf:
                hop_kind, cur_w, value_off, value_len, child_off = mpt_leaf_hop(
                    node, o0, l0, o1, l1, cur_w)
            else:
                hop_kind, cur_w, value_off, value_len, child_off = mpt_extension_hop(
                    node, o0, l0, o1, l1, k1, cur_w)

        if hop_kind == _HOP_INLINE:
            start = child_off
            steps += UInt64(1)
        else:
            done = True
    return cur_w, value_off, value_len


@subroutine
def mpt_verify_inclusion(w: Bytes, value_off: UInt64, value_len: UInt64
                          ) -> tuple[UInt64, UInt64]:
    """Convenience wrapper for M6/M7 callers (design doc §6): assert the
    final walk state is WALK_INCLUDED and return its value span. Exclusion
    callers use mpt_walk_node's raw status directly and handle
    WALK_ABSENT_* themselves (mpt_walk, in the design doc's terminology,
    IS mpt_walk_node -- there is no separate exclusion entry point, per
    §6's "one walk producing a status discriminator").

    NOTE: §10's error-code table (W1-W16) does not enumerate a code for
    this assertion -- it is a convenience this implementation adds on top
    of the design doc's §6 description, not itself part of §5's security
    content. "W17" is used here and documented as an M5-implementation
    addition beyond the doc's own table (see the implementation report).
    """
    assert w_status(w) == UInt64(WALK_INCLUDED), "W17"
    return value_off, value_len
