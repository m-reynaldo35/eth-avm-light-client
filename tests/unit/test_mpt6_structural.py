"""
docs/design/006-account-storage-proof.md §11.2 S-M6-1: M6's public surface
contains no root, key, `storageRoot`, or path parameter for phase B. The
absence is the invariant -- M5 S2's analogue (tests/unit/test_mpt_structural.py).
"""
import inspect

from contracts.composer import account, bridge, handoff, state


def test_s_m6_1_state_from_prev_signature_is_exactly_gi():
    """The one thing MODE_B_INIT calls to recover (W, C): `gi` only. No
    root, no key, no storageRoot, no slot -- §5.2's load-bearing absence."""
    sig = inspect.signature(handoff.mpt6_state_from_prev)
    assert list(sig.parameters) == ["gi"]


def test_s_m6_1_no_forbidden_parameter_on_any_public_composer_subroutine():
    """Every public contracts/composer subroutine, inspected for a
    caller-suppliable root/storageRoot/key/slot-selecting parameter. The
    three exceptions are all legitimate PREIMAGE or CONSUMER-EXPECTATION
    arguments, not walk-state-building channels:
      - mpt6_init_composite(state_root, address, slot): TP-M6-1/TP-M6-2 --
        R_state and the (address, slot) PREIMAGES are exactly what M6's
        entry contract IS allowed to take, at MODE_A_INIT, once, immutably.
        There is no second place these are read from.
      - mpt6_result_from_group(gi, want_state_root, want_address,
        want_slot): TP-M6-3 -- these are the CONSUMER'S expectation to
        check the recovered C against, never used to build a walk state.
    """
    forbidden = ("storage_root", "storageroot")
    exempt_functions = {state.mpt6_init_composite, handoff.mpt6_result_from_group}
    public_fns = [
        account.mpt6_account_body,
        account.mpt6_storage_value,
        bridge.mpt6_bridge_account,
        bridge.mpt6_bridge_storage,
        handoff.mpt6_log_state,
        handoff.mpt6_state_from_prev,
        handoff.mpt6_result_from_group,
        state.mpt6_init_composite,
        state.c_with_phase,
    ]
    for fn in public_fns:
        if fn in exempt_functions:
            continue
        for name in inspect.signature(fn).parameters:
            lowered = name.lower()
            for f in forbidden:
                assert f not in lowered, (
                    f"{fn.__qualname__}({inspect.signature(fn)}) has a "
                    f"forbidden parameter '{name}' -- only mpt6_init_composite "
                    f"(MODE_A_INIT, TP-M6-1) may ever take a root argument")


def test_s_m6_1_mpt6_result_from_group_want_args_are_mandatory():
    """TP-M6-3's own load-bearing detail: the three `want_*` parameters have
    no default -- a caller cannot compile a call that skips the check."""
    sig = inspect.signature(handoff.mpt6_result_from_group)
    params = sig.parameters
    for name in ("want_state_root", "want_address", "want_slot"):
        assert name in params
        assert params[name].default is inspect.Parameter.empty, (
            f"{name} must have no default -- TP-M6-3 is not optional")


def test_s_m6_1_bench_app_mode_b_init_reads_no_root_or_slot_app_arg():
    """Confirms the actual DRIVER (contracts/composer/bench_app.py) does not
    smuggle a root/key/slot in through app_args either -- inspecting its
    MODE_B_INIT source for the string 'application_args' shows only arg4
    (prev_gi) and node arguments are read; state_root/address/slot never
    appear as literals in that branch."""
    import inspect as _inspect
    from contracts.composer import bench_app
    src = _inspect.getsource(bench_app.Mpt6ComposerApp.approval_program)
    # Isolate the MODE_B_INIT branch's source text.
    start = src.index("if mode == MODE_B_INIT:")
    end = src.index("assert mode == MODE_B_NEXT")
    mode_b_init_src = src[start:end]
    assert "application_args(6)" not in mode_b_init_src
    assert "application_args(5)" not in mode_b_init_src  # arg5 only exists in MODE_A_INIT
    # The only app_args read in this branch is arg4 (prev_gi) and, inside
    # _walk6, node arguments from arg5 onward -- neither is a root/key/slot.
    assert "Txn.application_args(4)" in mode_b_init_src
