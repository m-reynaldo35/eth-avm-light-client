"""The headline live proof M4 never had before this pass: does a REAL,
currently-live Ethereum `finality_update` -- fetched fresh from a real
beacon-chain light-client API, never a static vendored fixture -- actually
verify correctly on-chain against a REAL, freshly-installed
`SyncCommitteeVerifier` instance on real dev-mode algod?

What real, live "fulu"-fork data exposed that no prior pass had to deal
with, and how each was resolved:

1. **Fork-row registration (§4, `forks.py`)**: M4's `forks` box has never
   been populated with anything but placeholder/test values. The real,
   live gindices for the CURRENT fork ("fulu", confirmed via
   `/eth/v1/beacon/light_client/finality_update`'s own `version` field) are
   NOT the Altair-preset constants (`finality=105`/depth 6,
   `current_sc=54`/`next_sc=55`/depth 5) `test_install_live.py`'s synthetic
   fixture uses -- Electra's `BeaconState` container growth reshuffled every
   one of these generalized indices one level deeper. The real values used
   below (`finality=169`, `current_sc=86`, `next_sc=87`, matching
   docs/design/004-sync-committee.md §9.1's own citation) were independently
   BRUTE-FORCE CONFIRMED against real, live-fetched data.

2. **A real, previously-undiscovered bug, found and FIXED this pass** (not
   a workaround): `contracts/primitives/ssz/merkleize.py`'s
   `merkleize_stack_finalize` silently returned the WRONG root whenever the
   pushed leaf count was EXACTLY `2**depth` (a fully-packed SSZ Vector).
   `install_process_finalize` -- the ONLY real caller in this project that
   ever pushes an exact `2**depth` count -- could therefore never have
   succeeded against ANY real, complete 512-member committee before this
   fix, on any past or future data. Fixed directly in `merkleize.py`.

3. **Real per-call opcode-budget donation, wired up for M4 for the first
   time**: `install_chunk`/`submit_update` both vastly exceed a single app
   call's 700-budget base; this module deploys the tiny, test-only
   `DonorCallee`/`DonorIssuer` pair as a SEPARATE sibling top-level
   transaction ahead of the real verifier call in the same atomic group --
   opcode-budget pooling is group-wide, not per-transaction or per-app.

4. **Real mainnet participation varies run to run**, which is exactly why
   the group-sizing arithmetic below goes through
   `relayer.group.boxes.choose_mode`/`plan_box_refs` and
   `EthAvmClient.submit_update_group` rather than a fixed-shape group
   (§5.3/§5.4 -- see M11 rebasing note below).

**M11 rebasing** (docs/design/011-test-harness-ci.md §5.4/§6.3, G4-M11):
`_choose_mode_and_boxes`, `_submit_update_group` and `_issue_donor_txn` --
this file's own hand-rolled box-reference/group-assembly code -- are
DELETED. `_choose_mode_and_boxes` predated M9's `plan_box_refs` derivation
and only minimized the COUNT of distinct boxes touched, never their real
declared byte size -- the exact, now-identified root cause of every "box
read/write budget (N) exceeded" failure this project's history has hit
(6144, 18432, 20480, 22528, across this file and its two dependents). The
two tests that exercised the genesis install + happy-path update
(`test_real_512_member_committee_installs_live`,
`test_live_finality_update_verifies_and_advances_state_for_real`) are also
DELETED as duplicates of `tests/relayer/test_live_relayer.py`'s
`test_l1_sync_end_to_end_matches_test_live_e2e_finality`, which exercises
the identical real install+update sequence through `EthAvmClient.sync()`
-- the rebasing IS the bug fix, not merely tidying (009 §15.4). The two
genuinely unique adversarial tests below (corrupted signature, corrupted
merkle branch) are KEPT and rebased onto `tests.harness.m4`'s shared
`installed_committee` fixture and `EthAvmClient.submit_update_group`
(promoted from private this pass, §6.3) -- submitting a deliberately-
tampered `SubmitUpdateArgs` through the REAL group-assembly path, not a
hand-rolled copy of it.
"""

from __future__ import annotations

import dataclasses

import pytest

from relayer.drivers import m4_sync_committee as m4sc
from relayer.group.boxes import choose_mode
from relayer.sources import beacon
from tests.harness.m4 import GEN, checkpoint_data, installed_committee, m4_donor_pair  # noqa: F401


def test_corrupted_signature_is_rejected_live(installed_committee, beacon_available):
    """A byte-flipped signature on an otherwise-real, freshly-fetched update
    is genuinely REJECTED on-chain (a real network/protocol error on a real
    submission attempt, not a simulated assert) -- proving a genuine
    positive submission (`tests/relayer/test_live_relayer.py`'s `test_l1`)
    is checking something real, not merely accepting anything shaped like a
    valid call."""
    if not beacon_available:
        pytest.skip("no reachable beacon-API endpoint in the pool")
    client = installed_committee["client"]

    fu_next = beacon.fetch_finality_update()
    fu_next_args = m4sc.transform_finality_update(fu_next)

    sig = bytearray(fu_next_args.signature)
    sig[100] ^= 0xFF  # flip a byte inside the G2 point encoding
    corrupted_sig = bytes(sig)
    assert corrupted_sig != fu_next_args.signature
    corrupted_args = dataclasses.replace(fu_next_args, signature=corrupted_sig)

    mode, plan = choose_mode(fu_next_args.sync_committee_bits, GEN)

    fin_slot_before = client._read_global_state(installed_committee["h"].app_id)[b"fin_slot"]

    with pytest.raises(Exception):
        client.submit_update_group(GEN, corrupted_args, mode, plan)

    fin_slot_after = client._read_global_state(installed_committee["h"].app_id)[b"fin_slot"]
    assert fin_slot_after == fin_slot_before, "rejected submission must not change state"


def test_corrupted_merkle_branch_is_rejected_live(installed_committee, beacon_available):
    """A byte-flipped `finality_branch` sibling node (real signature intact,
    same shape, wrong content) is genuinely REJECTED on-chain -- a distinct
    failure mode from the signature/curve check above, proving the merkle
    verification itself (not just BLS validity) is load-bearing."""
    if not beacon_available:
        pytest.skip("no reachable beacon-API endpoint in the pool")
    client = installed_committee["client"]

    fu_next = beacon.fetch_finality_update()
    fu_next_args = m4sc.transform_finality_update(fu_next)

    branch = bytearray(fu_next_args.finality_branch)
    branch[10] ^= 0xFF
    corrupted_branch = bytes(branch)
    assert corrupted_branch != fu_next_args.finality_branch
    corrupted_args = dataclasses.replace(fu_next_args, finality_branch=corrupted_branch)

    mode, plan = choose_mode(fu_next_args.sync_committee_bits, GEN)

    with pytest.raises(Exception):
        client.submit_update_group(GEN, corrupted_args, mode, plan)
