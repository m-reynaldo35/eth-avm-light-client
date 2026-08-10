"""Suite P (design doc §13.1): the planner, entirely offline -- no network,
no algod. This is the reason §7.6 makes planning pure. Runs under
`ci-offline.yml`.
"""
from __future__ import annotations

import pytest

from relayer.group.boxes import (
    m4_install_open_box_sizes,
    m4_submit_update_box_sizes,
    plan_box_refs,
)
from relayer.group.budget import size_donors
from relayer.group.planner import BoxRef, GroupPlan, PlannedTxn
from relayer.group.budget import BudgetConvention
from relayer.proofs.classify import T1_MAX_LEAF_BYTES, T2_MAX_LEAF_BYTES, classify


# ---------------------------------------------------------------------------
# P-1: M8 ring_init_chunk, N=128 -- reproduces G5-M8's shipped shape.
# ---------------------------------------------------------------------------
def test_p1_ring_init_chunk_n128_reproduces_g5_m8():
    record_len = 154
    sizes = {f"h:{i}".encode(): record_len for i in range(128)}
    plan = plan_box_refs(sizes)
    assert plan.refs_required == 128
    assert plan.txns_required == 16


# ---------------------------------------------------------------------------
# P-2: plan_box_refs on submit_update, k = 1..8. 013 §6.2: with `forks`
# gone (the fork table moved to global state, which costs no box-reference
# budget at all), direct mode loses exactly one reference at every
# participation level -- `ceil((6144k + 576)/2048) == 3k+1` (with `forks`)
# becomes `ceil(6144k/2048) == 3k` exactly (measured, §6.2's table).
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "k,expected_refs",
    [(1, 3), (2, 6), (3, 9), (4, 12), (5, 15), (6, 18), (7, 21), (8, 24)],
)
def test_p2_submit_update_box_refs_by_participation(k, expected_refs):
    sizes = m4_submit_update_box_sizes(gen=1, key_box_indices=set(range(k)))
    plan = plan_box_refs(sizes)
    assert plan.refs_required == expected_refs
    if k == 8:
        assert plan.txns_required >= 3


# ---------------------------------------------------------------------------
# P-3: plan_box_refs on the box-opening group.
# ---------------------------------------------------------------------------
def test_p3_install_open_group_matches_min_box_refs_for_install_open():
    from contracts.sync_committee.constants import MIN_BOX_REFS_FOR_INSTALL_OPEN

    sizes = m4_install_open_box_sizes(gen=1)
    plan = plan_box_refs(sizes)
    assert plan.refs_required == MIN_BOX_REFS_FOR_INSTALL_OPEN == 25


# ---------------------------------------------------------------------------
# P-4: replay the two OBSERVED live failures -- the planner's own correct
# number must exceed what the old, buggy `_choose_mode_and_boxes` code
# actually declared in each case (3 refs at k=2 -> "(6144)"; 9 refs at k=8
# -> "(18432)"), proving the old declared amount was genuinely insufficient
# before any group is ever built.
# ---------------------------------------------------------------------------
def test_p4_replay_observed_live_failures_are_rejected_before_building():
    old_declared_k2 = 3  # test_live_e2e.py's real "box read budget (6144) exceeded"
    plan_k2 = plan_box_refs(m4_submit_update_box_sizes(gen=1, key_box_indices={0, 1}))
    assert plan_k2.refs_required > old_declared_k2
    assert plan_k2.refs_required * 2048 > 6144  # the real failing budget number

    old_declared_k8 = 9  # test_live_historical.py's real "box read budget (18432) exceeded"
    plan_k8 = plan_box_refs(m4_submit_update_box_sizes(gen=1, key_box_indices=set(range(8))))
    assert plan_k8.refs_required > old_declared_k8
    assert plan_k8.refs_required * 2048 > 18432

    # And: a group built with the OLD (insufficient) ref count must fail
    # `check_fits` once the real requirement is known to need more
    # transactions than a naive 2-txn `[DonorIssuer, submit_update]` group
    # provides. 013 §6.2/§6.3(b): with `forks` gone, k=8 direct mode's
    # minimum drops from 25 refs/4 txns to 24 refs/3 txns exactly
    # (`ceil(8*6144/2048) == 24` -> `ceil(24/8) == 3`) -- still far more
    # than the 2 the old code shipped.
    assert plan_k8.txns_required == 3
    with pytest.raises(ValueError):
        plan_k8.check_fits(other_real_txns=14)  # 3 + 14 = 17 > 16-txn cap, must reject


# ---------------------------------------------------------------------------
# P-8: GroupPlan.check() negatives -- each rejected with its own error,
# BEFORE any network call (G7-M9).
# ---------------------------------------------------------------------------
def _one_call_plan(**overrides) -> GroupPlan:
    defaults = dict(kind="app_call", app_id=1, args=[b"x"], box_refs=[], fee=1000, inner_call_count=0)
    defaults.update(overrides)
    txn = PlannedTxn(**defaults)
    return GroupPlan(txns=[txn], result_index=0, donor_count=0, convention=BudgetConvention.SELF_ISSUED,
                      total_fee_microalgo=txn.fee)


def test_p8_too_many_transactions_rejected():
    txns = [PlannedTxn(kind="app_call", app_id=1, args=[b"x"]) for _ in range(17)]
    plan = GroupPlan(txns=txns, result_index=0, donor_count=0, convention=BudgetConvention.SELF_ISSUED,
                      total_fee_microalgo=17000)
    with pytest.raises(ValueError, match="17 transactions"):
        plan.check()


def test_p8_too_many_box_refs_on_one_txn_rejected():
    plan = _one_call_plan(box_refs=[BoxRef(0, f"b{i}".encode()) for i in range(9)])
    with pytest.raises(ValueError, match="box reference"):
        plan.check()


def test_p8_too_many_arg_bytes_rejected():
    plan = _one_call_plan(args=[b"x" * 2049])
    with pytest.raises(ValueError, match="app args"):
        plan.check()


def test_p8_too_many_args_rejected():
    plan = _one_call_plan(args=[b"x"] * 17)
    with pytest.raises(ValueError, match="app args"):
        plan.check()


def test_p8_too_many_inner_calls_rejected():
    plan = _one_call_plan(inner_call_count=257, fee=1000 * 258)
    with pytest.raises(ValueError, match="inner-call"):
        plan.check()


def test_p8_underpaid_fee_for_inner_calls_rejected():
    plan = _one_call_plan(inner_call_count=5, fee=1000)  # needs >= 6000
    with pytest.raises(ValueError, match="fee"):
        plan.check()


def test_p8_valid_plan_passes():
    plan = _one_call_plan()
    plan.check()  # must not raise


# ---------------------------------------------------------------------------
# P-9: tier classifier at the exact boundary values.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "leaf_len,expected_tier",
    [(T1_MAX_LEAF_BYTES, "T1"), (T1_MAX_LEAF_BYTES + 1, "T2"), (T2_MAX_LEAF_BYTES, "T2"), (T2_MAX_LEAF_BYTES + 1, "T3_UNSUPPORTED")],
)
def test_p9_tier_classifier_boundaries(leaf_len, expected_tier):
    result = classify(b"\x00" * leaf_len)
    assert result.tier == expected_tier


# ---------------------------------------------------------------------------
# P-10: donor sizing arithmetic against 004 §2.4's measured table, matching
# `test_live_historical.py:719`'s real formula:
#   n_donors = max(4, ceil((consumed - base) / 682) + 4)
# ---------------------------------------------------------------------------
def test_p10_donor_sizing_matches_the_real_formula():
    # test_live_historical.py's own real numbers: 4 app calls already in
    # the group (base = 2800), a real measured `consumed` figure.
    consumed = 8000
    sizing = size_donors(consumed, n_app_calls_in_group=4, margin=4)
    expected = max(4, -(-(consumed - 2800) // 682) + 4)
    assert sizing.n_donors == expected


def test_p10_donor_sizing_never_below_margin_floor():
    sizing = size_donors(measured_consumed=0, n_app_calls_in_group=10, margin=4)
    assert sizing.n_donors == 4
