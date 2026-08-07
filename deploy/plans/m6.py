"""§5.1/§4.4: `Mpt6ComposerApp` deployment -- a single `ApplicationCreateTxn`,
no global state, no boxes, no governance. §4.4's honest note: nothing in
this repo currently submits real transactions against a deployed
`Mpt6ComposerApp` (`EthAvmClient.prove_account` never sends a transaction);
M10 deploys it anyway because M11/`bench/composer_bench.py` need it (§15
gap 4 -- restated here, not hidden).
"""
from __future__ import annotations

from pathlib import Path

from algosdk import transaction

from deploy.compile import compile_teal_via_algod, puya_compile, sha256_hex
from deploy.mbr import min_extra_pages

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "contracts" / "composer" / "bench_app.py"


def compile_m6(algod_client) -> dict:
    contracts = puya_compile(SRC)["Mpt6ComposerApp"]
    approval = compile_teal_via_algod(algod_client, contracts["approval"])
    clear = compile_teal_via_algod(algod_client, contracts["clear"])
    return {"approval": approval, "clear": clear,
            "approval_sha256": sha256_hex(approval), "clear_sha256": sha256_hex(clear)}


def apply(algod_client, sender: str, sk: str, target, manifest) -> int:
    app_id = manifest.app_id("m6")
    if app_id is not None:
        return app_id
    compiled = compile_m6(algod_client)
    extra_pages = min_extra_pages(len(compiled["approval"]), len(compiled["clear"]))
    sp = algod_client.suggested_params()
    txn = transaction.ApplicationCreateTxn(
        sender=sender, sp=sp, on_complete=transaction.OnComplete.NoOpOC,
        approval_program=compiled["approval"], clear_program=compiled["clear"],
        global_schema=transaction.StateSchema(0, 0), local_schema=transaction.StateSchema(0, 0),
        extra_pages=extra_pages,
    )
    stxn = txn.sign(sk)
    txid = algod_client.send_transaction(stxn)
    confirmed = transaction.wait_for_confirmation(algod_client, txid, 4)
    app_id = confirmed["application-index"]
    manifest.set_app("m6", app_id=app_id, approval_sha256=compiled["approval_sha256"],
                      clear_sha256=compiled["clear_sha256"], schema_version=1, creator=sender)
    return app_id
