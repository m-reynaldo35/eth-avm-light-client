"""Suite E (design doc §13.5), G1-M10 -- the module's reason to exist: a
from-scratch `deploy apply`, then a `RelayerConfig` built FROM THE MANIFEST
ALONE (no hand-edited field), driving M9's full real-mainnet-data pipeline:
`sync(install=True)` -> `sync(update=True)` -> `anchor()` ->
`prove_receipt(against_anchor=True)`.

Wall-clock note (§13.5, restated honestly): a fresh 512-member M4 install is
genuinely ~15-25 minutes of real, non-simulated on-chain work (64 real
`install_chunk` groups). This is the same cost `tests/relayer/
test_live_relayer.py`'s own `env_a` fixture already pays -- this suite adds
nothing new on top of that except that the DEPLOYMENT step is `deploy
apply` instead of a hand-rolled test harness.
"""
from __future__ import annotations

import uuid

import pytest

from tests.harness.env import ALGOD_ADDRESS, TOKEN, _algod_reachable, _beacon_reachable

ALGOD_AVAILABLE = _algod_reachable()
BEACON_AVAILABLE = _beacon_reachable()
GENESIS_VALIDATORS_ROOT_HEX = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
ACTIVATION_EPOCHS = {"deneb": 269568, "electra": 364032, "fulu": 411392}


# 011 §4.1: skipif-at-import-time case with no fixture to infer from --
# explicit needs_algod/needs_network alongside the skipif, so --offline
# deselects this test rather than letting it run and skip (which
# --forbid-skips would then treat as a build failure).
@pytest.mark.needs_algod
@pytest.mark.needs_network
@pytest.mark.skipif(not ALGOD_AVAILABLE, reason="no dev-mode algod reachable")
@pytest.mark.skipif(not BEACON_AVAILABLE, reason="no reachable beacon-API endpoint in the pool")
def test_e1_g1_m10_manifest_driven_deploy_feeds_m9_end_to_end(tmp_path, monkeypatch):
    import base64

    from algosdk import kmd as kmd_mod, mnemonic
    from algosdk.v2client import algod as algod_mod

    import deploy.manifest as manifest_mod
    from deploy.config import ContractTarget, DeployTarget, NetworkConfig
    from deploy.diff import apply
    from relayer.client import EthAvmClient
    from relayer.config import RelayerConfig
    from relayer.drivers import m4_sync_committee as m4

    monkeypatch.setattr(manifest_mod, "MANIFEST_DIR", tmp_path)

    algod_client = algod_mod.AlgodClient(TOKEN, ALGOD_ADDRESS)
    kmd = kmd_mod.KMDClient(TOKEN, "http://localhost:4052")
    wallets = kmd.list_wallets()
    wid = next(w["id"] for w in wallets if w["name"] == "unencrypted-default-wallet")
    handle = kmd.init_wallet_handle(wid, "")
    addrs = kmd.list_keys(handle)
    best, best_bal = None, -1
    for a in addrs:
        bal = algod_client.account_info(a)["amount"]
        if bal > best_bal:
            best, best_bal = a, bal
    sender, sk = best, kmd.export_key(handle, "", best)
    kmd.release_wallet_handle(handle)

    sp = algod_client.suggested_params()
    gh = sp.gh if isinstance(sp.gh, str) else base64.b64encode(sp.gh).decode()
    genesis_id = f"e2e-{uuid.uuid4().hex[:12]}"
    target = DeployTarget(
        network=NetworkConfig(ALGOD_ADDRESS, TOKEN, genesis_id, gh),
        governance=sender,
        contracts={
            "m4": ContractTarget(deploy=True, genesis_validators_root="0x" + GENESIS_VALIDATORS_ROOT_HEX),
            "m8": ContractTarget(deploy=True, ring_n=8),
            # 014 §4.1's deferred T1 migration, closed this pass:
            # `prove_receipt(against_anchor=True)` now needs
            # `m7_anchored_app_id` for T1 too, not just T2 -- `deploy.diff.
            # apply` orders this after m8 (its own compile-time
            # ANCHOR_APP_ID dependency, TP-M8-4) and before m7 below.
            "m7_anchored": ContractTarget(deploy=True, t2_float=True),
            "m7": ContractTarget(deploy=True, t2_float=True),
            "m6": ContractTarget(deploy=True),
        },
        forks=["deneb", "electra", "fulu"],
    )

    # -- G1-M10: the from-scratch deploy, driven entirely by `deploy apply` --
    manifest = apply(target, algod_client, sender, sk, yes=True, activation_epochs=ACTIVATION_EPOCHS)

    from deploy.plans.m4 import fund_for_install

    fund_for_install(algod_client, sender, sk, manifest.apps["m4"]["app_id"], stage="install")

    # -- RelayerConfig built FROM THE MANIFEST ALONE, no hand-edited field --
    cfg = RelayerConfig(
        m4_app_id=manifest.apps["m4"]["app_id"],
        m7_app_id=manifest.apps["m7"]["app_id"],
        m8_app_id=manifest.apps["m8"]["app_id"],
        m7_anchored_app_id=manifest.apps["m7_anchored"]["app_id"],
        donor_issuer_id=manifest.apps["donor_issuer"]["app_id"],
        donor_callee_id=manifest.apps["donor_callee"]["app_id"],
        signer_mnemonic=mnemonic.from_private_key(sk),
    )
    client = EthAvmClient(cfg)

    checkpoint_data = m4.fetch_checkpoint_and_update()
    client.sync(install=True, update=False, bootstrap_root=checkpoint_data["checkpoint_root"])
    update_result = client.sync(install=False, update=True)
    assert update_result.ok

    status_after_sync = client.status()
    assert status_after_sync.m4_finalized is not None
    assert status_after_sync.m4_finalized.get(b"fin_slot", 0) != 0, "M4 has no finalized slot after sync(update=True)"

    anchor_result = client.anchor("latest")
    assert anchor_result.ok, f"anchor() did not succeed: {anchor_result}"

    anchored_block = anchor_result.record["el_block_number"]

    # FIXED (real bug found live): this used to hardcode tx_index=0,
    # log_index=0, which fails whenever tx 0's own leaf happens to need T3
    # (ZK, out of v1 scope). `Mpt7AnchoredReceiptApp` implements BOTH T1
    # (raw-arg) and T2 (box-staged) against-anchor walks (014 §4.1's
    # deferred T1 migration is closed as of this pass -- the old
    # `AnchorReceiptProbe`-based restriction to T1-only no longer applies),
    # so this only needs to avoid T3, not pick T1 specifically. Mirrors
    # tests/state_anchor/test_live_historical.py's own dynamic-selection
    # discipline: scan the real, currently-anchored block's own receipts
    # for a transaction with at least one real log whose leaf classifies as
    # T1 or T2, instead of assuming index 0 qualifies.
    from relayer.proofs import classify as classify_mod
    from relayer.proofs.receipts_trie import build_receipts_trie_and_path
    from relayer.sources.eth_rpc import get_block_receipts

    receipts = get_block_receipts(int(anchored_block))
    tx_index = log_index = None
    for r in receipts:
        idx = int(r.get("transactionIndex", "0x0"), 16)
        if not r.get("logs"):
            continue
        try:
            _root, nodes = build_receipts_trie_and_path(receipts, idx)
        except KeyError:
            continue
        if classify_mod.classify(nodes[-1]).tier in ("T1", "T2"):
            tx_index, log_index = idx, 0
            break
    assert tx_index is not None, (
        f"no transaction in real EL block {anchored_block} has a real log and a T1/T2-sized "
        "receipt leaf (only T3/ZK leaves, out of v1 scope, §1.2)"
    )

    receipt_result = client.prove_receipt(int(anchored_block), tx_index, log_index, against_anchor=True)
    assert receipt_result.rstatus_name in ("R_INCLUDED", "R_ABSENT", "R_NO_SUCH_LOG", "R_ZERO_LOGS"), (
        f"unexpected rstatus: {receipt_result.rstatus_name}"
    )
