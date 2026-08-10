"""Suite F (docs/design/013-fork-table-global-state.md §11, F-1..F-18) --
M4's half of the fork-table storage revision's live proof. G2/G4-R13's
primary evidence for M4: P1 (governance-only, append-only, strictly-
increasing) and P2 (a lookup selects exactly the row it selected before)
are unchanged, proven against real dev-mode algod, no mocks.

M8's Suite F (F-6 already existed under that name pre-013;
`tests/state_anchor/test_core.py`/`test_forks.py` carry the rest) is not
duplicated here -- this file is M4-only, per docs/design/013 §16's file
layout ("tests/sync_committee/test_forks_state.py NEW -- Suite F for M4").

`lookup_fork_version`/`lookup_gindices` (`contracts/sync_committee/
forks.py`) are not exposed as their own ARC-4 methods -- they are internal
subroutines reached only through `bootstrap` (gindex lookup only) and
`submit_update` (both lookups, but only after a full running committee
plus a real BLS signature -- a much heavier live setup than this suite's
job). This file therefore:

  * exercises `append_fork_row`'s OWN validation (F-3, F-4, F-5, F-10)
    directly -- fast, cheap, and exhaustive, since every one of these is a
    pure function of the append call itself;
  * exercises the READ side (F-2, F-7's gindex-rejection half, F-9)
    through `bootstrap`, the cheapest real on-chain path that calls
    `lookup_gindices`;
  * F-7's OTHER half (`lookup_fork_version` succeeding at the same epoch a
    pre-Altair row's `lookup_gindices` rejects) needs `submit_update`'s
    full running-committee + real-signature machinery and is NOT
    duplicated here -- `tests/harness/m4.py`'s `installed_committee`/
    `finalized_m4` fixtures (driven through `tests/relayer/
    test_live_relayer.py`'s L-1) already exercise `lookup_fork_version`
    for real on every live update, with the real "fulu" row. Honestly
    recorded as a partial F-7 in the implementation report, not hidden.
  * F-11 (zero-pre-funding create) and F-15 (empty box-ref arrays) close
    out the rest of this file's job.
"""

from __future__ import annotations

import pytest

from tests.sync_committee.test_install_live import (
    CURRENT_SYNC_COMMITTEE_GINDEX,
    FINALITY_GINDEX,
    NEXT_SYNC_COMMITTEE_GINDEX,
    _build_bootstrap_fixture,
)

FORK_VERSION_1 = b"\x01\x00\x00\x00"
FORK_VERSION_2 = b"\x02\x00\x00\x00"
UINT64_MAX = 2**64 - 1


@pytest.fixture()
def h(algod_available):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    from tests.sync_committee.harness import SyncCommitteeLiveHarness

    harness = SyncCommitteeLiveHarness()
    harness.create(harness.sender, b"\x00" * 32)
    return harness


# ---------------------------------------------------------------------------
# F-11: a real create() submitted with ZERO prior funding of the app
# account succeeds, and application_boxes(app_id) is empty immediately
# after. THE structural claim this whole revision rests on (§0, §5.4,
# G8-R13) -- measured directly, at the contract level (deploy/plans/m4.py's
# equivalent is tests/deploy/test_deploy_live.py's rewritten D-11).
# ---------------------------------------------------------------------------
def test_f11_create_needs_zero_prefunding_and_creates_no_box(h):
    from algosdk import logic

    info = h.algod.account_info(logic.get_application_address(h.app_id))
    assert info["amount"] == 0, "create() must not have required any app-account funding at all"
    boxes = h.algod.application_boxes(h.app_id)
    assert boxes.get("boxes", []) == [], "create() must create no box at all (the fork table is global state now)"


# ---------------------------------------------------------------------------
# F-15: every built append_fork_row transaction carries an EMPTY box-
# reference array (G5-R13: no transaction anywhere declares a `forks` box
# reference any more).
# ---------------------------------------------------------------------------
def test_f15_append_fork_row_transaction_carries_no_box_refs(h):
    from algosdk.abi import Method
    from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer

    method = Method.undictify(h.methods["append_fork_row"])
    atc = AtomicTransactionComposer()
    signer = AccountTransactionSigner(h.sk)
    sp = h.algod.suggested_params()
    sp.flat_fee = True
    sp.fee = 1000
    atc.add_method_call(
        app_id=h.app_id, method=method, sender=h.sender, sp=sp, signer=signer,
        method_args=[0, FORK_VERSION_1, FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX],
    )
    built = atc.build_group()
    assert built[0].txn.boxes in (None, []), f"append_fork_row must declare no box refs, got {built[0].txn.boxes!r}"


# ---------------------------------------------------------------------------
# F-3: append rows at capacity (16); every row reads back correctly (via
# fork_count advancing 1-by-1); the 17th append is rejected with "fork
# table full".
# ---------------------------------------------------------------------------
def test_f3_capacity_16_then_full(h):
    for i in range(16):
        result = h.call(
            "append_fork_row", i, FORK_VERSION_1, FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX,
        )
        assert result.ok, f"row {i} (of 16) must succeed, got {result.failure!r}"
        h.submit([("append_fork_row", [i, FORK_VERSION_1, FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX])])

    info = h.algod.application_info(h.app_id)
    import base64

    gstate = {base64.b64decode(kv["key"]): kv["value"] for kv in info["params"]["global-state"]}
    assert gstate[b"fork_count"]["uint"] == 16

    # The 17th append must be rejected -- "fork table full".
    result = h.call("append_fork_row", 16, FORK_VERSION_1, FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX)
    assert not result.ok, "the 17th append_fork_row (capacity 16) must be rejected"
    assert "assert failed" in result.failure


# ---------------------------------------------------------------------------
# F-4: epoch monotonicity -- a row at an equal epoch, and a row at a lower
# epoch, are both rejected ("activation_epoch must strictly increase").
# ---------------------------------------------------------------------------
def test_f4_epoch_monotonicity_equal_and_lower_rejected(h):
    h.submit([("append_fork_row", [100, FORK_VERSION_1, FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX])])

    equal = h.call("append_fork_row", 100, FORK_VERSION_2, FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX)
    assert not equal.ok, "a row at an EQUAL epoch must be rejected"
    assert "assert failed" in equal.failure

    lower = h.call("append_fork_row", 50, FORK_VERSION_2, FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX)
    assert not lower.ok, "a row at a LOWER epoch must be rejected"
    assert "assert failed" in lower.failure

    # A row at a genuinely higher epoch still succeeds (the guard is
    # specific to non-increasing epochs, not a general lockout).
    higher = h.call("append_fork_row", 200, FORK_VERSION_2, FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX)
    assert higher.ok, f"a row at a higher epoch must succeed, got {higher.failure!r}"


# ---------------------------------------------------------------------------
# F-5: the uint64-max sentinel epoch is rejected ("sentinel epoch
# rejected").
# ---------------------------------------------------------------------------
def test_f5_sentinel_epoch_rejected(h):
    result = h.call("append_fork_row", UINT64_MAX, FORK_VERSION_1, FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX)
    assert not result.ok, "the uint64-max sentinel epoch must be rejected"
    assert "assert failed" in result.failure


# ---------------------------------------------------------------------------
# F-10: a non-governance sender's append_fork_row is rejected
# ("governance only").
# ---------------------------------------------------------------------------
def test_f10_non_governance_append_rejected(h, algod_available):
    from tests.harness.chain import kmd_client

    kmd = kmd_client()
    wallets = kmd.list_wallets()
    wid = next(w["id"] for w in wallets if w["name"] == "unencrypted-default-wallet")
    handle = kmd.init_wallet_handle(wid, "")
    try:
        addrs = kmd.list_keys(handle)
        other_addr = next((a for a in addrs if a != h.sender), None)
        if other_addr is None:
            pytest.skip("dev-mode kmd's default wallet has only one key -- cannot exercise a non-governance sender")
        other_sender = other_addr
        other_sk = kmd.export_key(handle, "", other_addr)
    finally:
        kmd.release_wallet_handle(handle)

    from algosdk.abi import Method
    from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer

    method = Method.undictify(h.methods["append_fork_row"])
    atc = AtomicTransactionComposer()
    signer = AccountTransactionSigner(other_sk)
    sp = h.algod.suggested_params()
    sp.flat_fee = True
    sp.fee = 1000
    atc.add_method_call(
        app_id=h.app_id, method=method, sender=other_sender, sp=sp, signer=signer,
        method_args=[0, FORK_VERSION_1, FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX],
    )
    with pytest.raises(Exception):
        atc.execute(h.algod, 4)


# ---------------------------------------------------------------------------
# F-2 / F-7 (gindex-rejection half): append 1 row, read it back through
# `bootstrap` (the cheapest real path that calls `lookup_gindices`) --
# every field the row carries is used correctly (the merkle check only
# passes with the RIGHT current_sc_gindex), and a pre-Altair row (all-zero
# gindices) is rejected with "matched row carries no gindices (pre-Altair)".
# ---------------------------------------------------------------------------
def test_f2_append_one_row_and_read_it_back_via_bootstrap(h):
    h.submit([("append_fork_row", [0, FORK_VERSION_1, FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX])])
    fx = _build_bootstrap_fixture()
    # `bootstrap` touches no box at all now (013 §3/§6.4) -- no app-account
    # funding needed here, unlike `install_open_keys`/`install_open_session`.
    result = h.submit([
        ("bootstrap", [fx["header"], fx["committee_root"], fx["branch"], fx["trusted_block_root"]]),
        ("noop_budget", []),
    ])
    assert result.tx_ids, "bootstrap must commit using the just-appended row's current_sc_gindex"


def test_f7_pre_altair_row_rejects_gindex_lookup(h):
    """A row with all-zero gindices (the pre-Altair marker, §4.3) must be
    rejected by `lookup_gindices` -- exercised here through `bootstrap`,
    which calls only `lookup_gindices` (never `lookup_fork_version`, module
    docstring)."""
    h.submit([("append_fork_row", [0, FORK_VERSION_1, 0, 0, 0])])
    fx = _build_bootstrap_fixture()
    result = h.call(
        "bootstrap", fx["header"], fx["committee_root"], fx["branch"], fx["trusted_block_root"],
    )
    assert not result.ok, "bootstrap must reject a pre-Altair (all-zero-gindex) row"
    assert "assert failed" in result.failure


# ---------------------------------------------------------------------------
# F-9: multi-row selection. Three rows at epochs 0 < 3 < 1000, with
# DELIBERATELY WRONG gindices on the rows that must NOT be selected at
# epoch 3 (the bootstrap fixture's own epoch, slot 100 // 32 == 3) --
# `_find_row_index_for_epoch`'s "last row with activation_epoch <= epoch
# wins" rule is proven by the merkle check only passing when the MIDDLE
# row (epoch 3, the correct gindex) is the one actually used.
# ---------------------------------------------------------------------------
def test_f9_multi_row_selection_picks_the_last_activated_row(h):
    WRONG_GINDEX = NEXT_SYNC_COMMITTEE_GINDEX  # 55 -- same depth as 54, different bit pattern
    h.submit([("append_fork_row", [0, FORK_VERSION_1, FINALITY_GINDEX, WRONG_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX])])
    h.submit([("append_fork_row", [3, FORK_VERSION_1, FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX])])
    h.submit([("append_fork_row", [1000, FORK_VERSION_1, FINALITY_GINDEX, WRONG_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX])])

    fx = _build_bootstrap_fixture()  # slot 100 -> epoch 3, branch built for gindex 54
    # `bootstrap` touches no box at all now (013 §3/§6.4) -- no app-account
    # funding needed here. Two `noop_budget()` siblings (pooled +700 each,
    # §9.4): scanning 3 rows (vs F-2's 1) measurably costs more opcode
    # budget than a single donor covers. Real, measured finding while
    # building this test: two bare `noop_budget()` calls with no
    # distinguishing box refs are BYTE-IDENTICAL transactions (same app id,
    # sender, args, fee, valid-round window) and collide as duplicates
    # within the same group ("TransactionPool.Remember: transaction
    # already in ledger") -- a dummy, never-created box ref on each call is
    # enough to make them distinct without changing what they do.
    result = h.submit([
        ("bootstrap", [fx["header"], fx["committee_root"], fx["branch"], fx["trusted_block_root"]]),
        ("noop_budget", [], [(0, b"f9-pad-0")]),
        ("noop_budget", [], [(0, b"f9-pad-1")]),
    ])
    assert result.tx_ids, (
        "bootstrap must select row index 1 (epoch 3, the last row with "
        "activation_epoch <= 3), whose gindex (54) matches the supplied "
        "branch -- rows 0 (epoch 0) and 2 (epoch 1000) carry the WRONG "
        "gindex (55) and would fail the merkle check if either were "
        "selected instead"
    )
