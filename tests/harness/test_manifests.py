"""Suite M (design doc 012 §12.4): manifests and live verification. M-1/M-2
are offline (parse + cross-check against versions.json/target files); M-3
through M-6 are live, against REAL Algorand mainnet, and need no signer --
every read here is public (application_info), exactly like `deploy verify`/
`deploy resolve` themselves.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MAINNET_MANIFEST = REPO_ROOT / "deploy" / "manifests" / "mainnet-v1.0.json"


def _mainnet_reachable() -> bool:
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen("https://mainnet-api.algonode.cloud/v2/status", timeout=5) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


MAINNET_REACHABLE = _mainnet_reachable()


# ---------------------------------------------------------------------------
# M-1 (offline): the manifest parses, and every approval_sha256 matches a
# code_id in versions.json.
# ---------------------------------------------------------------------------
def test_m1_mainnet_manifest_parses_and_hashes_match_versions_json():
    assert MAINNET_MANIFEST.exists(), "deploy/manifests/mainnet-v1.0.json is missing (§17 item 3)"
    manifest = json.loads(MAINNET_MANIFEST.read_text())
    assert manifest["manifest_version"] == 1
    assert manifest["network"]["genesis_id"] == "mainnet-v1.0"

    versions = json.loads((REPO_ROOT / "deploy" / "versions.json").read_text())
    code_ids = {v.get("code_id") for v in versions["contracts"].values()}

    key_to_contract = {"m7": "Mpt7ReceiptApp", "donor_issuer": "DonorIssuer", "donor_callee": "DonorCallee"}
    for key, contract_name in key_to_contract.items():
        entry = manifest["apps"][key]
        assert entry["approval_sha256"] in code_ids, f"{key}'s approval_sha256 not found in versions.json"
        assert entry["approval_sha256"] == versions["contracts"][contract_name]["code_id"]


# ---------------------------------------------------------------------------
# M-2 (offline): the manifest's genesis_hash matches the target file of the
# same network (G7-M10's data, asserted statically here).
# ---------------------------------------------------------------------------
def test_m2_manifest_genesis_hash_matches_its_target_file():
    manifest = json.loads(MAINNET_MANIFEST.read_text())
    target = json.loads((REPO_ROOT / "deploy" / "targets" / "mainnet.json").read_text())
    assert manifest["network"]["genesis_hash"] == target["network"]["genesis_hash"]
    assert manifest["network"]["genesis_id"] == target["network"]["genesis_id"]


# ---------------------------------------------------------------------------
# M-3 (live, G4-M12): `deploy verify --target mainnet` passes against the
# real live mainnet apps, with no signer.
# ---------------------------------------------------------------------------
@pytest.mark.needs_network
@pytest.mark.skipif(not MAINNET_REACHABLE, reason="mainnet-api.algonode.cloud unreachable")
def test_m3_deploy_verify_passes_against_real_mainnet():
    from algosdk.v2client import algod as algod_mod

    from deploy.config import DeployTarget
    from deploy.diff import verify

    target = DeployTarget.from_file(REPO_ROOT / "deploy" / "targets" / "mainnet.json")
    algod_client = algod_mod.AlgodClient(target.network.algod_token, target.network.algod_url)
    results = verify(target, algod_client)
    assert "m7" in results
    assert results["m7"].ok, f"m7 verify failed: {results['m7'].issues}"


# ---------------------------------------------------------------------------
# M-4 (live): `deploy resolve --network mainnet --fork fulu` -- m7: USABLE;
# m4/m8: NOT_DEPLOYED.
# ---------------------------------------------------------------------------
@pytest.mark.needs_network
@pytest.mark.skipif(not MAINNET_REACHABLE, reason="mainnet-api.algonode.cloud unreachable")
def test_m4_resolve_fulu_reports_m7_usable_m4_m8_not_deployed():
    from algosdk.v2client import algod as algod_mod

    from deploy.config import DeployTarget
    from deploy.manifest import Manifest
    from deploy.resolve import VERDICT_NOT_DEPLOYED, VERDICT_USABLE, resolve

    target = DeployTarget.from_file(REPO_ROOT / "deploy" / "targets" / "mainnet.json")
    algod_client = algod_mod.AlgodClient(target.network.algod_token, target.network.algod_url)
    manifest = Manifest.load(target.network.genesis_id)
    versions = json.loads((REPO_ROOT / "deploy" / "versions.json").read_text())

    result = resolve(target, manifest, versions, "fulu", algod_client)
    assert result["apps"]["m7"]["verdict"] == VERDICT_USABLE
    assert result["apps"]["m4"]["verdict"] == VERDICT_NOT_DEPLOYED
    assert result["apps"]["m8"]["verdict"] == VERDICT_NOT_DEPLOYED
    assert result["donors"]["issuer"] == 3666047636
    assert result["donors"]["callee"] == 3666047587


# ---------------------------------------------------------------------------
# M-5 (live): resolve_one against a real app id whose program does NOT
# match its pin -- CODE_MISMATCH, non-zero-exit-worthy verdict.
# ---------------------------------------------------------------------------
@pytest.mark.needs_network
@pytest.mark.skipif(not MAINNET_REACHABLE, reason="mainnet-api.algonode.cloud unreachable")
def test_m5_resolve_one_reports_code_mismatch_for_a_wrong_pin():
    from algosdk.v2client import algod as algod_mod

    from deploy.resolve import VERDICT_CODE_MISMATCH, resolve_one

    algod_client = algod_mod.AlgodClient("", "https://mainnet-api.algonode.cloud")
    out = resolve_one(
        algod_client, app_id=3665914633,  # real m7 app id
        pinned_code_id="0" * 64,  # deliberately wrong pin
        fork_axis="none", code_window=None, fork="fulu",
    )
    assert out["verdict"] == VERDICT_CODE_MISMATCH
    assert out["code_id_matches_chain"] is False


# ---------------------------------------------------------------------------
# M-6 (live): resolve --fork gloas -- FORK_UNSUPPORTED, with the cited
# reason, for m4/m8; m7 (fork_axis "none") unaffected.
# ---------------------------------------------------------------------------
@pytest.mark.needs_network
@pytest.mark.skipif(not MAINNET_REACHABLE, reason="mainnet-api.algonode.cloud unreachable")
def test_m6_resolve_gloas_reports_fork_unsupported_for_m4_m8():
    from algosdk.v2client import algod as algod_mod

    from deploy.config import DeployTarget
    from deploy.manifest import Manifest
    from deploy.resolve import VERDICT_FORK_UNSUPPORTED, VERDICT_USABLE, resolve

    target = DeployTarget.from_file(REPO_ROOT / "deploy" / "targets" / "mainnet.json")
    algod_client = algod_mod.AlgodClient(target.network.algod_token, target.network.algod_url)
    manifest = Manifest.load(target.network.genesis_id)
    versions = json.loads((REPO_ROOT / "deploy" / "versions.json").read_text())

    result = resolve(target, manifest, versions, "gloas", algod_client)
    assert result["apps"]["m4"]["verdict"] == VERDICT_FORK_UNSUPPORTED
    assert result["apps"]["m4"]["detail"]
    assert result["apps"]["m8"]["verdict"] == VERDICT_FORK_UNSUPPORTED
    assert result["apps"]["m8"]["detail"]
    assert result["apps"]["m7"]["verdict"] == VERDICT_USABLE  # fork_axis "none" -- unaffected
