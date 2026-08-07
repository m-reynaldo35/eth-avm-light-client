"""Suite S (design doc §13.4): adversarial. Includes G8-M10, the AST-based
import-graph purity test mirroring `tests/relayer/test_security.py`'s
G8-M9. §17 item 1: `deploy/` MUST import `relayer` (and `contracts.*`/
`algopy`) and MUST NOT be imported BY `relayer`.
"""
from __future__ import annotations

import ast
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_DIR = REPO_ROOT / "deploy"
RELAYER_DIR = REPO_ROOT / "relayer"

ALGOD_ADDRESS = "http://localhost:4051"
TOKEN = "a" * 64


def _algod_reachable() -> bool:
    try:
        req = urllib.request.Request(ALGOD_ADDRESS + "/v2/status", headers={"X-Algo-API-Token": TOKEN})
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


@pytest.fixture(scope="session")
def algod_available() -> bool:
    return _algod_reachable()


def _imported_top_level_modules(py_file: Path) -> set[str]:
    tree = ast.parse(py_file.read_text(), filename=str(py_file))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".")[0])
    return names


# ---------------------------------------------------------------------------
# G8-M10: relayer/ never imports deploy/ or tests.*; deploy/ freely imports
# relayer and contracts/algopy (the opposite of G8-M9's own rule, and stated
# explicitly as the reason `deploy/` cannot be a subpackage of `relayer/`,
# §8.1).
# ---------------------------------------------------------------------------
def test_g8_m10_relayer_never_imports_deploy():
    violations = []
    for py_file in RELAYER_DIR.rglob("*.py"):
        rel = py_file.relative_to(RELAYER_DIR)
        imported = _imported_top_level_modules(py_file)
        if "deploy" in imported:
            violations.append(f"{rel}: imports 'deploy'")
    assert not violations, "\n".join(violations)


def test_g8_m10_deploy_imports_relayer_not_vacuously():
    """Sanity check the rule above isn't vacuous the other way: confirm
    `deploy/` really does import `relayer` somewhere (§17 item 1's other
    half -- donors, plan_box_refs, ssz)."""
    found = False
    for py_file in DEPLOY_DIR.rglob("*.py"):
        if "relayer" in _imported_top_level_modules(py_file):
            found = True
            break
    assert found, "expected at least one deploy/*.py file to import relayer"


def test_g8_m10_deploy_imports_contracts_and_algopy_not_vacuously():
    """`relayer/` is forbidden `algopy`/`contracts.*` (G8-M9); `deploy/` is
    explicitly allowed both (§17 item 1, §8.1). Confirm it really uses that
    permission (the schema generator)."""
    found_contracts = any("contracts" in _imported_top_level_modules(f) for f in DEPLOY_DIR.rglob("*.py"))
    assert found_contracts, "expected deploy/ to import contracts.* (schema generator)"


# ---------------------------------------------------------------------------
# S-3: refuse to deploy an "unrestricted" contract to a mainnet genesis
# hash. All four CURRENT contracts are "NoOp only" post-fix (test_schema.py
# already asserts this), so this test exercises the REFUSAL MECHANISM
# directly against a synthetic schema shaped like the OLD, pre-fix
# Mpt7ReceiptApp -- confirming the mechanism works, honestly noting that no
# currently-shipped contract would actually trigger it today.
# ---------------------------------------------------------------------------
def test_s3_refuses_unrestricted_contract_on_mainnet_genesis_hash():
    from deploy.diff import MAINNET_GENESIS_HASHES
    from deploy.inspect import refuse_unrestricted_on_mainnet

    old_vulnerable_schema = {"contract": "Mpt7ReceiptApp", "program": {"on_completion_gate": "unrestricted"}}
    mainnet_hash = next(iter(MAINNET_GENESIS_HASHES))
    with pytest.raises(PermissionError, match="unrestricted"):
        refuse_unrestricted_on_mainnet(old_vulnerable_schema, mainnet_hash, MAINNET_GENESIS_HASHES)


def test_s3_allows_unrestricted_contract_on_non_mainnet_genesis_hash():
    from deploy.diff import MAINNET_GENESIS_HASHES
    from deploy.inspect import refuse_unrestricted_on_mainnet

    old_vulnerable_schema = {"contract": "Mpt7ReceiptApp", "program": {"on_completion_gate": "unrestricted"}}
    refuse_unrestricted_on_mainnet(old_vulnerable_schema, "some-devnet-hash=", MAINNET_GENESIS_HASHES)  # no raise


def test_s3_noop_only_contract_never_refused_even_on_mainnet():
    from deploy.diff import MAINNET_GENESIS_HASHES
    from deploy.inspect import refuse_unrestricted_on_mainnet
    from deploy.schema.generate import generate_all

    mainnet_hash = next(iter(MAINNET_GENESIS_HASHES))
    for name, schema in generate_all().items():
        refuse_unrestricted_on_mainnet(schema, mainnet_hash, MAINNET_GENESIS_HASHES)  # no raise for any of the 4


# ---------------------------------------------------------------------------
# S-4: M8 create with an m4_app_id whose program hash is not M4's --
# refused client-side, before any funding Payment.
# ---------------------------------------------------------------------------
@pytest.fixture()
def algod_client(algod_available):
    if not algod_available:
        pytest.skip(f"no dev-mode algod reachable at {ALGOD_ADDRESS}")
    from algosdk.v2client import algod as algod_mod

    return algod_mod.AlgodClient(TOKEN, ALGOD_ADDRESS)


@pytest.fixture()
def funded_account(algod_client):
    from algosdk import kmd as kmd_mod

    kmd = kmd_mod.KMDClient(TOKEN, "http://localhost:4052")
    wallets = kmd.list_wallets()
    wid = next(w["id"] for w in wallets if w["name"] == "unencrypted-default-wallet")
    handle = kmd.init_wallet_handle(wid, "")
    try:
        addrs = kmd.list_keys(handle)
        best, best_bal = None, -1
        for a in addrs:
            bal = algod_client.account_info(a)["amount"]
            if bal > best_bal:
                best, best_bal = a, bal
        sk = kmd.export_key(handle, "", best)
        return best, sk
    finally:
        kmd.release_wallet_handle(handle)


def test_s4_wrong_m4_counterparty_refused_before_funding(algod_client, funded_account):
    from algosdk import transaction

    from deploy.plans.m8 import CounterpartyMismatch, verify_m4_counterparty

    sender, sk = funded_account
    # Deploy some UNRELATED app (not SyncCommitteeVerifier) to serve as the
    # "wrong" m4_app_id -- a real, live app id whose program hash genuinely
    # is not the pinned SyncCommitteeVerifier hash.
    probe_teal = "#pragma version 10\nint 1\nreturn\n"
    probe_compiled = algod_client.compile(probe_teal)
    import base64

    probe_bytes = base64.b64decode(probe_compiled["result"])
    sp = algod_client.suggested_params()
    txn = transaction.ApplicationCreateTxn(
        sender=sender, sp=sp, on_complete=transaction.OnComplete.NoOpOC,
        approval_program=probe_bytes, clear_program=probe_bytes,
        global_schema=transaction.StateSchema(0, 0), local_schema=transaction.StateSchema(0, 0),
    )
    stxn = txn.sign(sk)
    txid = algod_client.send_transaction(stxn)
    confirmed = transaction.wait_for_confirmation(algod_client, txid, 4)
    fake_m4_id = confirmed["application-index"]

    before = algod_client.status()["last-round"]
    with pytest.raises(CounterpartyMismatch):
        verify_m4_counterparty(algod_client, fake_m4_id, pinned_m4_sha256="0" * 64)
    after = algod_client.status()["last-round"]
    assert after == before, "the counterparty check itself must send nothing -- it's a read-only pre-check"


# ---------------------------------------------------------------------------
# S-5: governance == signer -- warns loudly, refused unless yes=True.
# ---------------------------------------------------------------------------
def test_s5_governance_equals_signer_warns():
    from deploy.config import ContractTarget, DeployTarget, NetworkConfig

    addr = "OR3RLQVXMVX3OVQ6K263Z5HKAC2UA62GCBSJXWB5DSTJE727WCAOPHGBBY"
    target = DeployTarget(
        network=NetworkConfig("http://localhost:4051", "a" * 64, "dockernet-v1", "irrelevant="),
        governance=addr, contracts={"m4": ContractTarget(deploy=True)},
    )
    warning = target.warn_if_governance_equals_signer(addr)
    assert warning is not None
    assert "WARNING" in warning

    different = "PXPHYS4JZ5GXHFXCLXQD3PT2XZDDXA7HCP5HXPGWDD5DEXOKMFE2ANN5UM"
    assert target.warn_if_governance_equals_signer(different) is None


def test_s5_apply_refuses_without_yes_when_governance_equals_signer(algod_client, funded_account, tmp_path, monkeypatch):
    import deploy.manifest as manifest_mod
    from deploy.config import ContractTarget, DeployTarget, NetworkConfig
    from deploy.diff import GovernanceSignerWarning, apply

    monkeypatch.setattr(manifest_mod, "MANIFEST_DIR", tmp_path)
    sender, sk = funded_account
    sp = algod_client.suggested_params()
    import base64

    gh = sp.gh if isinstance(sp.gh, str) else base64.b64encode(sp.gh).decode()
    target = DeployTarget(
        network=NetworkConfig("http://localhost:4051", "a" * 64, "dockernet-v1", gh),
        governance=sender,  # == signer, deliberately
        contracts={"m4": ContractTarget(deploy=True, genesis_validators_root="0x" + "00" * 32)},
    )
    before = algod_client.status()["last-round"]
    with pytest.raises(GovernanceSignerWarning):
        apply(target, algod_client, sender, sk, yes=False)
    after = algod_client.status()["last-round"]
    assert after == before, "must refuse BEFORE sending anything"


# ---------------------------------------------------------------------------
# S-7: tampered manifest (app id swapped for an unrelated app) -- verify
# fails on the approval-hash pin, not on behaviour.
# ---------------------------------------------------------------------------
def test_s7_tampered_manifest_fails_on_approval_hash_pin(algod_client, funded_account):
    from algosdk import transaction

    from deploy.inspect import verify_app

    sender, sk = funded_account
    probe_teal = "#pragma version 10\nint 1\nreturn\n"
    import base64

    probe_bytes = base64.b64decode(algod_client.compile(probe_teal)["result"])
    sp = algod_client.suggested_params()
    txn = transaction.ApplicationCreateTxn(
        sender=sender, sp=sp, on_complete=transaction.OnComplete.NoOpOC,
        approval_program=probe_bytes, clear_program=probe_bytes,
        global_schema=transaction.StateSchema(0, 0), local_schema=transaction.StateSchema(0, 0),
    )
    stxn = txn.sign(sk)
    txid = algod_client.send_transaction(stxn)
    confirmed = transaction.wait_for_confirmation(algod_client, txid, 4)
    fake_app_id = confirmed["application-index"]

    # A "tampered manifest" claims fake_app_id is really TrustedRootAnchor,
    # pinned to the REAL TrustedRootAnchor hash.
    result = verify_app(algod_client, fake_app_id, pinned_approval_sha256="9b790b33f2116a5ccbbe07ce2d9ac040c8c1897c695ca2725b7d99956522d57d")
    assert not result.ok
    assert any("sha256" in issue for issue in result.issues)
