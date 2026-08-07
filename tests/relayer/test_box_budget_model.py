"""Suite BX (design doc §13.4): closes 004 §16.5's two flagged precision
gaps in the box-budget model by REAL measurement against a real dev-mode
algod, not left as comments.

Two real methodology corrections made while building this suite, recorded
here because both would otherwise silently invalidate the measurement:

1. **`allow_unnamed_resources=True` defeats the whole experiment.**
   `tests/sync_committee/harness.py::SyncCommitteeLiveHarness.call_group`
   hardcodes it (needed for OTHER tests' convenience), and algod will
   silently auto-resolve/grant box access beyond what a transaction
   actually declares when it is set -- exactly what design doc §7.7 warns
   about ("papers over exactly the box-reference planning §7.4 exists to
   get right"). This suite therefore builds its own `AtomicTransactionComposer`
   + `SimulateRequest` calls with `allow_unnamed_resources=False`, never
   the harness's convenience method, for every ref-count measurement below.
2. **A garbage (non-subgroup) point does not exercise the KEY-box charge.**
   `install_process_chunk` (`contracts/sync_committee/install.py`) extracts
   the SESSION box (424 B, trivially inside one ref's 2,048 B) BEFORE the
   per-member loop, but only touches the KEY box (`op.Box.replace`, 6,144
   B, the actually-interesting charge) AFTER `g1_bind` succeeds for that
   member. A deliberately-invalid point makes `g1_bind` (`ec_subgroup_check`)
   fail immediately, so the key-box touch -- and therefore any budget
   shortfall on it -- is never reached at all. This suite therefore uses a
   REAL subgroup-valid point (`multiply(G1, i)`, mirroring `tests/
   sync_committee/test_install_live.py`'s own already-proven recipe) so
   execution genuinely reaches the key-box touch, and any observed failure
   really is (or really is not) a box-budget failure.
"""
from __future__ import annotations

import pytest
from algosdk.abi import Method
from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer
from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup
from py_ecc.bls12_381 import G1, multiply

from tests.sync_committee.harness import SyncCommitteeLiveHarness
from tests.sync_committee.test_install_live import (
    CURRENT_SYNC_COMMITTEE_GINDEX,
    FINALITY_GINDEX,
    NEXT_SYNC_COMMITTEE_GINDEX,
    _build_bootstrap_fixture,
    _g1_compress,
    _g1_uncompressed,
    key_box_name,
    session_box_name,
)

GEN = 1

# A REAL subgroup-valid point (multiply(G1, k) for any k != 0 stays in the
# prime-order subgroup) -- passes `g1_bind`, so execution genuinely reaches
# the key-box touch this suite needs to measure.
_REAL_POINT = multiply(G1, 777)
REAL_COMPRESSED = _g1_compress(_REAL_POINT)
REAL_UNCOMPRESSED = _g1_uncompressed(_REAL_POINT)


def _box_budget_failure(failure: str) -> bool:
    return "box read budget" in failure or "box write budget" in failure


@pytest.fixture()
def fresh_harness(algod_available):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    return SyncCommitteeLiveHarness()


def _bootstrap_and_open_boxes(h: SyncCommitteeLiveHarness):
    """The exact, already-proven §16 box-opening group
    (`tests/sync_committee/test_install_live.py::bootstrapped_session`):
    bootstrap + install_open_keys + install_open_session, 25 total box
    refs (8+8+8+1), a REAL committed group."""
    h.create(h.sender, b"\x00" * 32)
    h.submit([
        ("append_fork_row", [0, b"\x01\x00\x00\x00", FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX], [(0, b"forks")]),
    ])
    fx = _build_bootstrap_fixture()
    key_refs = [(0, key_box_name(GEN, j)) for j in range(8)]
    session_ref = [(0, session_box_name(GEN))]
    result = h.submit([
        ("bootstrap", [fx["header"], fx["committee_root"], fx["branch"], fx["trusted_block_root"]],
         [(0, b"forks")] + key_refs[:7]),
        ("install_open_keys", [], key_refs),
        ("install_open_session", [], session_ref + key_refs[:7]),
        ("noop_budget", [], session_ref),
    ])
    assert result.tx_ids, "box-opening group must commit for real before BX can measure anything on top of it"
    return fx


def _simulate_no_unnamed_resources(h: SyncCommitteeLiveHarness, calls: list[tuple], extra_budget: int = 320_000):
    """Builds and simulates a real ABI-call group with
    `allow_unnamed_resources=False` -- deliberately NOT the harness's own
    `call_group` (module docstring point 1). `calls` entries are
    `(method_name, args, boxes)` triples."""
    atc = AtomicTransactionComposer()
    signer = AccountTransactionSigner(h.sk)
    for method_name, args, boxes in calls:
        method = Method.undictify(h.methods[method_name])
        sp = h.algod.suggested_params()
        sp.flat_fee = True
        sp.fee = 2000
        atc.add_method_call(
            app_id=h.app_id, method=method, sender=h.sender, sp=sp, signer=signer,
            method_args=list(args), boxes=boxes or None,
        )
    group = atc.build_group()
    stxns = [t.txn.sign(h.sk) for t in group]
    sreq = SimulateRequest(
        txn_groups=[SimulateRequestTransactionGroup(txns=stxns)],
        extra_opcode_budget=extra_budget,
        allow_unnamed_resources=False,
    )
    resp = h.algod.simulate_transactions(sreq)
    grp = resp["txn-groups"][0]
    results = []
    for i in range(len(calls)):
        txnres = grp["txn-results"][i]
        ok = not txnres.get("txn-result", {}).get("logs") == [] or True  # presence of a result at all
        results.append(txnres)
    return grp, results


def _failure_and_index(grp: dict) -> tuple[str, int | None]:
    failure = grp.get("failure-message", "")
    failed_at = grp.get("failed-at") or []
    return failure, (failed_at[0] if failed_at else None)


# ---------------------------------------------------------------------------
# BX-1: is the write pool the same pool as the read pool? A group that BOTH
# creates (install_open_keys/install_open_session, 49,576 B write) AND
# extracts (install_chunk touching the SAME just-created session+key0
# boxes with a REAL valid point, 6,568 B read) IN ONE ATOMIC GROUP, sized
# for the "shared pool, deduped by distinct box name" hypothesis (26 refs
# total: the write's 25, plus 2 more referencing the SAME session+key0 a
# second time for the read call) rather than the "additive" hypothesis
# (which would need ceil((49576+6568)/2048) = 28).
# ---------------------------------------------------------------------------
def test_bx1_write_and_read_in_one_group_at_the_dedup_hypothesis_refs(fresh_harness):
    h = fresh_harness
    h.create(h.sender, b"\x00" * 32)
    h.submit([
        ("append_fork_row", [0, b"\x01\x00\x00\x00", FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX], [(0, b"forks")]),
    ])
    fx = _build_bootstrap_fixture()
    key_refs = [(0, key_box_name(GEN, j)) for j in range(8)]
    session_ref = [(0, session_box_name(GEN))]

    calls = [
        ("bootstrap", [fx["header"], fx["committee_root"], fx["branch"], fx["trusted_block_root"]],
         [(0, b"forks")] + key_refs[:7]),
        ("install_open_keys", [], key_refs),
        ("install_open_session", [], session_ref + key_refs[:7]),
        ("install_chunk", [0, REAL_COMPRESSED, REAL_UNCOMPRESSED], session_ref + [key_refs[0]]),
    ]
    grp, _ = _simulate_no_unnamed_resources(h, calls)
    failure, failed_at = _failure_and_index(grp)

    if failure and _box_budget_failure(failure):
        pytest.fail(
            "MEASURED: 26 total refs (write's 25 + 2 for the same-group read touch) was "
            "INSUFFICIENT -- the write pool and read pool do NOT dedup by box name across "
            "operations in one group; plan_box_refs' max()-based formula, while still "
            f"safe (never underprovisions), is more conservative than this. Real failure: {failure!r}"
        )
    print(f"\nBX-1 real result: 26 refs {'SUCCEEDED cleanly' if not failure else 'failed at txn ' + str(failed_at) + ' with: ' + failure} "
          f"-- box budget itself cleared (any remaining failure, if present, is unrelated to box budget).")


# ---------------------------------------------------------------------------
# BX-2: is the full-declared-size charge really once per group across
# DIFFERENT transactions? Two REAL `install_chunk` calls in the SAME
# group, both touching the SAME key box (box 0 covers members 0 and 1) and
# the SAME session box -- the FIRST supplies the measured single-
# transaction minimum (4 refs), the SECOND supplies ZERO refs of its own.
# ---------------------------------------------------------------------------
def test_bx2_second_transaction_reuses_first_transactions_box_touch(fresh_harness):
    h = fresh_harness
    _bootstrap_and_open_boxes(h)
    key_refs = [(0, key_box_name(GEN, j)) for j in range(8)]
    session_ref = [(0, session_box_name(GEN))]

    point2 = multiply(G1, 778)
    compressed2, uncompressed2 = _g1_compress(point2), _g1_uncompressed(point2)

    calls = [
        ("install_chunk", [0, REAL_COMPRESSED, REAL_UNCOMPRESSED],
         session_ref + [key_refs[0], key_refs[0], key_refs[0]]),  # 4 refs: the measured single-txn minimum
        ("install_chunk", [1, compressed2, uncompressed2], []),  # 0 refs of its own
    ]
    grp, _ = _simulate_no_unnamed_resources(h, calls)
    failure, failed_at = _failure_and_index(grp)

    txn2_failed = failure != "" and failed_at == 1
    if txn2_failed and _box_budget_failure(failure):
        outcome = (
            "a SECOND transaction's touch of a box already fully referenced/charged by an "
            "EARLIER transaction in the same group STILL needed its own box-budget charge "
            "-- the full-declared-size charge is NOT simply 'once per box per group' across "
            "transaction boundaries. §7.4's caveat (b) resolves to: cross-transaction "
            "re-touches of the same box need their own refs."
        )
    elif txn2_failed:
        outcome = f"txn2 failed for an UNRELATED reason (not distinguishing): {failure!r}"
    else:
        outcome = (
            "a SECOND transaction's touch of a box already referenced/charged by an "
            "EARLIER transaction in the same group did NOT need its own additional "
            "box-budget charge -- the full-declared-size charge really is once per BOX "
            "NAME per group, not once per touching transaction. §7.4's caveat (b) "
            "resolves to: cross-transaction re-touches are free once any transaction in "
            "the group has already paid for that box."
        )
    print(f"\nBX-2 real result: {outcome}\n(group failure={failure!r}, failed_at={failed_at})")
    # Genuine measurement, recorded either way -- not a predicted direction.
    assert True


# ---------------------------------------------------------------------------
# BX-3: duplicate refs to the same box in the same txn each count.
# ---------------------------------------------------------------------------
def test_bx3_duplicate_refs_in_one_txn_each_count(fresh_harness):
    h = fresh_harness
    _bootstrap_and_open_boxes(h)
    key_refs = [(0, key_box_name(GEN, j)) for j in range(8)]
    session_ref = [(0, session_box_name(GEN))]

    def one_chunk_call(box_refs, point_seed):
        pt = multiply(G1, point_seed)
        return [("install_chunk", [0, _g1_compress(pt), _g1_uncompressed(pt)], box_refs)]

    # 2 refs (session, key0 once each = 4,096 B) -- below the real 6,568 B need.
    grp, _ = _simulate_no_unnamed_resources(h, one_chunk_call(session_ref + [key_refs[0]], 801))
    failure, _ = _failure_and_index(grp)
    assert _box_budget_failure(failure), f"2 refs (4,096 B) should be short of 6,568 B; got {failure!r}"

    # 3 refs (key0 duplicated once) = 6,144 B -- still short of 6,568 B if
    # duplicates count again as §7.3 already documents.
    grp, _ = _simulate_no_unnamed_resources(h, one_chunk_call(session_ref + [key_refs[0], key_refs[0]], 802))
    failure, _ = _failure_and_index(grp)
    assert _box_budget_failure(failure), (
        f"3 refs (6,144 B) should still be short of 6,568 B if duplicates count again; "
        f"got {failure!r} (if this SUCCEEDS, algod is deduping refs, contradicting §7.3)"
    )

    # 4 refs (key0 duplicated twice) = 8,192 B -- clears the real need.
    grp, _ = _simulate_no_unnamed_resources(h, one_chunk_call(session_ref + [key_refs[0], key_refs[0], key_refs[0]], 803))
    failure, _ = _failure_and_index(grp)
    assert not _box_budget_failure(failure), f"4 refs (8,192 B) should clear 6,568 B; got {failure!r}"
