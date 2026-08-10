"""`installed_committee` / `finalized_m4` fixtures, driven entirely through
`relayer.client.EthAvmClient` (docs/design/011-test-harness-ci.md §5.4,
§6.1, §6.3). This is the §5 fix made structural: every live M4 update in
`tests/` now goes through `EthAvmClient.sync()` /
`EthAvmClient.submit_update_group()`, which sizes its real transaction
count from `relayer.group.boxes.plan_box_refs` -- never a hand-rolled
`_choose_mode_and_boxes`/`_submit_update_group`/`_issue_donor_txn` copy
(009 §18 item 2, 011 §18 item 2: a fixed/under-counted box-reference plan
has been wrong four times in this codebase's own history: 6144, 18432,
20480, 22528).

Generalises `tests/relayer/test_live_relayer.py`'s own
`_deploy_m4`/`_client_for`/`env_a` pattern (the first place this project
drove a full real M4 install purely through the client, G2-M9) into a
shared fixture so `tests/sync_committee/test_live_e2e_finality.py`'s
surviving adversarial tests and `tests/state_anchor/test_live_e2e.py`/
`test_live_historical.py`'s M8 suites no longer need their own hand-rolled
bootstrap/box-open/install_chunk/install_finalize copies.
"""
from __future__ import annotations

import pytest

from relayer.client import EthAvmClient
from relayer.config import RelayerConfig
from relayer.drivers import m4_sync_committee as m4sc
from tests.harness.chain import algod_client
from tests.harness.deployment import deploy_donor_pair

GENESIS_VALIDATORS_ROOT_HEX = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"

# Real, live-confirmed "fulu" fork row (docs/design/004-sync-committee.md
# §9.1's own citation; independently brute-force-verified against real
# fetched data during M11's design pass, 011 §3 module docstring point 1).
FULU_FORK_EPOCH = 411392
FULU_FORK_VERSION = bytes.fromhex("06000000")
FINALITY_GINDEX = 169
CURRENT_SC_GINDEX = 86
NEXT_SC_GINDEX = 87
GEN = 1  # first bootstrap on a fresh app always assigns gen_counter -> 1


def deploy_fresh_committee():
    """A fresh `SyncCommitteeVerifier` with the real live "fulu" fork row
    registered -- the one real (non-simulated) setup step that happens
    OUTSIDE `EthAvmClient` (creating the app and registering its fork
    table is a deployment concern, not a sync concern; `deploy/` itself
    does this for a real deploy via `deploy apply` -- test code uses the
    lighter-weight `SyncCommitteeLiveHarness` for the same effect)."""
    from tests.sync_committee.harness import SyncCommitteeLiveHarness

    h = SyncCommitteeLiveHarness()
    h.create(h.sender, bytes.fromhex(GENESIS_VALIDATORS_ROOT_HEX))
    # 013 §0/§5.4: create() no longer pre-funds the app account (the fork
    # table moved to global state, whose MBR the CREATOR pays at create
    # time) -- but M4's OTHER box families (k:/s:/a:, untouched by 013)
    # still need the app account funded before the install flow creates
    # them, so that happens here instead, as an ordinary post-create
    # payment to the now-known address (no prediction, no race).
    h.fund_app()
    h.submit([(
        "append_fork_row",
        [FULU_FORK_EPOCH, FULU_FORK_VERSION, FINALITY_GINDEX, CURRENT_SC_GINDEX, NEXT_SC_GINDEX],
    )])
    return h


def client_for(h, donor_issuer_id: int, donor_callee_id: int, *,
                m8_app_id: int | None = None, m7_app_id: int | None = None) -> EthAvmClient:
    from algosdk import mnemonic

    cfg = RelayerConfig(
        m4_app_id=h.app_id, m7_app_id=m7_app_id, m8_app_id=m8_app_id,
        donor_issuer_id=donor_issuer_id, donor_callee_id=donor_callee_id,
        signer_mnemonic=mnemonic.from_private_key(h.sk),
    )
    return EthAvmClient(cfg)


@pytest.fixture(scope="module")
def checkpoint_data(beacon_available):
    if not beacon_available:
        pytest.skip("no reachable beacon-API endpoint in the pool")
    return m4sc.fetch_checkpoint_and_update()


@pytest.fixture(scope="module")
def m4_donor_pair(algod_available, account):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    sender, sk = account
    callee_id, issuer_id = deploy_donor_pair(algod_client(), sender, sk)
    return {"sender": sender, "sk": sk, "callee_id": callee_id, "issuer_id": issuer_id}


@pytest.fixture(scope="module")
def installed_committee(algod_available, checkpoint_data, m4_donor_pair):
    """A real, complete 512-member genesis install, driven end to end
    through `EthAvmClient.sync(install=True)` (`relayer/client.py`'s
    `_drive_m4_install`) -- real bootstrap, real box-opening, 64 real
    `install_chunk` groups, real `install_finalize`, against real dev-mode
    algod. Returns a dict (`h`, `client`, `callee_id`, `issuer_id`,
    `checkpoint_data`, `install_result`) covering every field the old
    per-file hand-rolled fixtures exposed."""
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    h = deploy_fresh_committee()
    client = client_for(h, m4_donor_pair["issuer_id"], m4_donor_pair["callee_id"])
    install_result = client.sync(install=True, update=False, bootstrap_root=checkpoint_data["checkpoint_root"])
    return {
        "h": h, "client": client, "checkpoint_data": checkpoint_data,
        "callee_id": m4_donor_pair["callee_id"], "issuer_id": m4_donor_pair["issuer_id"],
        "install_result": install_result,
    }


@pytest.fixture(scope="module")
def finalized_m4(installed_committee):
    """Advances the real M4 instance with the SAME live `finality_update`
    `installed_committee`'s checkpoint was fetched alongside, through
    `EthAvmClient.sync(update=True)` (`_drive_m4_update` ->
    `submit_update_group`, sized from `relayer.group.boxes.plan_box_refs`
    -- never a hand-rolled padding hack). Returns the harness object `h`
    directly (matching every prior `finalized_m4` fixture's own return
    shape) so downstream M8 test code needs no further changes beyond the
    import path."""
    client = installed_committee["client"]
    result = client.sync(install=False, update=True)
    assert "skipped" not in result.detail.get("update", {}), (
        f"finalized_m4: the one real update this fixture performs must not "
        f"have been skipped: {result.detail.get('update')}"
    )
    return installed_committee["h"]
