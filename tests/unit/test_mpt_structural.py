"""
docs/design/005-mpt-walker.md §9.3 test S2 (structural): M5's public
surface must contain no caller-supplied step list, child index, or path
parameter of any kind -- that absence is the design invariant the whole
module rests on (§0).

Scoping note (read before "fixing" this test): `mpt_descend`'s own `want`
parameter IS an item index -- but `mpt_descend` is an internal decode
helper, never itself an entry point a relayer calls; every caller that
supplies `want` (`mpt_branch_hop`) computes it internally from `key` and
`depth` (`nibble_at(key, depth)` or the constant 16), never from a free
argument. What S2 actually constrains is the WALK entry points: the thing
a segment driver (or a future ARC4 production app, M6/M8) calls to feed in
node bytes and get a walk state out. Those are checked here by name and by
introspecting their signatures for anything index/path/step-shaped.
"""
import inspect

from contracts.mpt import handoff, state, walk

# Every parameter name across the checked signatures must NOT match these
# (case-insensitive substrings) -- a step list, a child/branch index, or a
# raw nibble/path argument.
FORBIDDEN_SUBSTRINGS = ("step", "child_index", "childindex", "nib_arg", "path_arg")

# The WALK entry points: what a segment driver actually calls to progress
# a walk. `mpt_descend` and the three *_hop handlers are internal decode
# machinery (see module docstring) and are deliberately excluded here --
# they are exercised directly by tests/unit/test_mpt_descend.py and
# test_mpt_derived.py/test_mpt_real_walks.py instead, which is where their
# actual behaviour (not their signature) is what matters.
PUBLIC_WALK_ENTRY_POINTS = [
    state.mpt_init_state,
    state.mpt_key_from_address,
    state.mpt_key_from_slot,
    state.mpt_key_from_tx_index,
    walk.mpt_walk_node,
    walk.mpt_verify_inclusion,
    handoff.mpt_state_from_prev,
    handoff.mpt_log_state,
]


def test_s2_no_step_list_or_child_index_parameter_on_walk_entry_points():
    for fn in PUBLIC_WALK_ENTRY_POINTS:
        sig = inspect.signature(fn)
        for name in sig.parameters:
            lowered = name.lower()
            for forbidden in FORBIDDEN_SUBSTRINGS:
                assert forbidden not in lowered, (
                    f"{fn.__qualname__}({sig}) has a forbidden parameter "
                    f"'{name}' -- a walk entry point must never accept a "
                    f"step list, child index, or raw path/nibble argument")


def test_s2_mpt_walk_node_signature_is_exactly_node_and_state():
    """The one function a segment driver calls per supplied node --
    mpt_walk_node(node, w) -- takes NOTHING else. No index, no path, no
    depth override."""
    sig = inspect.signature(walk.mpt_walk_node)
    assert list(sig.parameters) == ["node", "w"]


def test_s2_key_derivation_takes_only_a_preimage():
    """TP-M5-2's structural half: the key derivers take a PREIMAGE (and,
    for the receipt convention, a UInt64 index -- not bytes), never a
    pre-derived key or an explicit nibble/path argument."""
    assert list(inspect.signature(state.mpt_key_from_address).parameters) == ["addr"]
    assert list(inspect.signature(state.mpt_key_from_slot).parameters) == ["slot"]
    assert list(inspect.signature(state.mpt_key_from_tx_index).parameters) == ["index"]


def test_s2_descend_want_is_internal_and_never_reaches_a_walk_entry_point():
    """Documents (does not merely assert) the scoping decision above:
    `mpt_descend`'s `want` parameter exists, but no function in
    PUBLIC_WALK_ENTRY_POINTS forwards a caller-supplied value into it --
    every call site that supplies `want` is inside contracts/mpt/walk.py's
    hop handlers, computed from `nibble_at(key, depth)` or the constant 16
    (§5.2 steps 1-2), never taken as a parameter of an entry point."""
    from contracts.mpt.descend import mpt_descend
    assert "want" in inspect.signature(mpt_descend).parameters
    for fn in PUBLIC_WALK_ENTRY_POINTS:
        assert "want" not in inspect.signature(fn).parameters
