"""
contracts/mpt/descend.py -- mpt_descend: unconditional node-arity
discrimination, spelled out in docs/design/005-mpt-walker.md §5.1.

Discriminates branch (17 items) vs. extension/leaf (2 items) by asking
"does item 1 end exactly at payload_end" -- NOT by sniffing item 0's shape,
which has an ambiguous row (a branch child's 0xa0-prefixed 32-byte hash
reference and a leaf's 63/64-nibble compact path both encode identically).
See the design doc for the full rationale on why this is unconditional and
not the cheaper shape-based test (deferred as O-M5-1, §11.3).

For arity == 17, `mpt_descend` walks from item 2 duplicating M2's
per-item stride arithmetic (`rlp_scan_n`'s hot-loop body,
contracts/primitives/rlp/core.py) rather than calling `rlp_item_header` per
skipped item -- the design doc's §2 table records this as M5's one
permitted duplication of M2's logic, gated on the differential test D1
(tests/unit/test_mpt_descend.py) asserting the duplicate agrees with the
canonical path on every item of every fixture node.

--- §16 (post-approval fix, see docs/design/005-mpt-walker.md §16.2) ---
This module used to have exactly one entry point, `mpt_descend(node, start,
want)`, which internally re-ran `rlp_list_header` + 2x `rlp_item_header`
(the arity-discriminating prefix decode) on EVERY call. `contracts/mpt/
walk.py`'s `mpt_walk_node` called it once per hop just to learn `arity`
(discarding the item data for anything but the `want == 0` case), then --
for every branch hop -- `mpt_branch_hop` called it AGAIN with the real
`want` (16 or the derived nibble), which silently re-ran the identical
prefix decode a second time before continuing the skip loop. That is a
real, measured, avoidable duplication (not something the design doc's
§5.1 pseudocode specifies -- the design's own per-hop pseudocode assumes
ONE `mpt_descend` call per branch hop, which is what motivated writing
`mpt_descend` as a single function in the first place).

The fix splits the prefix decode out into `mpt_arity_discriminate` (run
EXACTLY ONCE per hop, by `mpt_walk_node`) and the item-2-onward skip loop
into `mpt_branch_item_at` (which takes the already-decoded item 0/1 spans
and `payload_end` and does no re-decoding). `mpt_descend` itself is now a
thin composition of the two, kept unchanged in signature and behaviour so
every existing caller/test that calls it directly (it remains part of
`contracts/mpt/__init__.py`'s public surface, and is still the right
one-shot API for a caller that doesn't already have a discriminated node)
continues to work byte-for-byte identically. Only the internal hot path
(`mpt_walk_node` -> `mpt_branch_hop`) was changed to call the split
primitives instead of `mpt_descend` twice.
"""
from algopy import Bytes, UInt64, subroutine, op

from contracts.primitives.rlp.core import rlp_item_header, rlp_list_header


@subroutine
def mpt_arity_discriminate(node: Bytes, start: UInt64
                            ) -> tuple[UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64]:
    """Run the arity-discriminating prefix decode EXACTLY ONCE: list header
    + item 0 + item 1. Returns (arity, payload_end, o0, l0, k0, o1, l1, k1).
    `arity == 2` means (o1, l1, k1) IS item 1 (the ext/leaf child/nothing
    further to walk); `arity == 17` means item 2 onward must still be
    walked via `mpt_branch_item_at` to reach any item other than 0 or 1."""
    payload_off, payload_end = rlp_list_header(node, start)
    o0, l0, k0 = rlp_item_header(node, payload_off)
    o1, l1, k1 = rlp_item_header(node, o0 + l0)
    if o1 + l1 == payload_end:
        return UInt64(2), payload_end, o0, l0, k0, o1, l1, k1
    return UInt64(17), payload_end, o0, l0, k0, o1, l1, k1


@subroutine
def mpt_branch_item_at(node: Bytes, o0: UInt64, l0: UInt64, k0: UInt64,
                        o1: UInt64, l1: UInt64, k1: UInt64,
                        payload_end: UInt64, want: UInt64
                        ) -> tuple[UInt64, UInt64, UInt64]:
    """Given a branch node's ALREADY-DECODED item 0 / item 1 spans (from
    `mpt_arity_discriminate` on the SAME `node`/`start` -- caller's
    responsibility, not re-verified here, since this is the internal hot
    path and TP-M5-3 already licenses trusting `node`'s own bytes once
    hashed), return item `want`'s (offset, length, kind). want 0/1 are
    free (already decoded); want >= 2 continues the skip loop from item 1's
    end -- the same duplicated-per-item stride arithmetic `mpt_descend`
    used to run from scratch on every call (still D1-gated, see the module
    docstring and tests/unit/test_mpt_descend.py)."""
    if want == UInt64(0):
        return o0, l0, k0
    if want == UInt64(1):
        return o1, l1, k1

    pos = o1 + l1
    n = UInt64(2)
    while n < want:
        assert pos < payload_end, "W9"
        # Duplicated per-item stride arithmetic (D1-gated) -- mirrors
        # rlp_scan_n's hot loop exactly, including its branch ordering
        # (p < 0xb8 tested before p < 0x80: real branch-node data is 100%
        # 0x80/0xa0, both landing in the p < 0xb8 arm).
        p = op.getbyte(node, pos)
        if p < 0xB8:
            if p < 0x80:
                pos += 1
            else:
                pos += 1 + p - 0x80
        elif p < 0xC0:
            ll = p - 0xB7
            pos += 1 + ll + op.btoi(op.extract(node, pos + 1, ll))
        elif p < 0xF8:
            pos += 1 + p - 0xC0
        else:
            ll = p - 0xF7
            pos += 1 + ll + op.btoi(op.extract(node, pos + 1, ll))
        n += 1
    assert pos < payload_end, "W9"
    return rlp_item_header(node, pos)


@subroutine
def mpt_descend(node: Bytes, start: UInt64, want: UInt64
                 ) -> tuple[UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64]:
    """Returns (arity, o0, l0, k0, ow, lw, kw).
       arity == 2  -> (o0,l0,k0) is item 0 (the compact path), (ow,lw,kw) is
                      item 1; `want` is ignored.
       arity == 17 -> (o0,l0,k0) is item 0, (ow,lw,kw) is item `want`.

    Unchanged public one-shot API (composed from mpt_arity_discriminate +
    mpt_branch_item_at, §16.2) -- a caller with no prior discrimination for
    this node/start still gets the same single-call convenience and the
    same result as before this pass. contracts/mpt/walk.py's hot path
    (mpt_walk_node -> mpt_branch_hop) no longer goes through this function
    -- it calls the two primitives directly, once each per hop, to avoid
    re-running the list-header + item-0 + item-1 decode a second time.

    Does NOT verify the node has exactly 17 items for arity == 17 (early-
    exits at `want`, the same trade rlp_scan_upto documents, M2 §16.3) --
    under TP-M5-3 the bytes are already hash-committed, so arity is
    corroborated by the root; the one case that DOES reach payload_end
    (want == 16, §5.2's branch-terminal case) gets the arity check for
    free via mpt_walk.py's own assert arity == 17.
    """
    arity, payload_end, o0, l0, k0, o1, l1, k1 = mpt_arity_discriminate(node, start)
    if arity == UInt64(2):
        return UInt64(2), o0, l0, k0, o1, l1, k1
    ow, lw, kw = mpt_branch_item_at(node, o0, l0, k0, o1, l1, k1, payload_end, want)
    return UInt64(17), o0, l0, k0, ow, lw, kw
