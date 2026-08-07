"""§5.4: `Mpt7ReceiptApp` deployment -- the trivial one. No create-time
boxes, so NO pre-funding and NO id prediction is needed (this contract has
no ARC-56 either -- it is a bare `Contract`, so `create()` is a plain
`ApplicationCreateTxn` with no ABI args).
"""
from __future__ import annotations

from pathlib import Path

from algosdk import transaction

from deploy.compile import compile_teal_via_algod, puya_compile, sha256_hex
from deploy.mbr import box_mbr, min_extra_pages

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "contracts" / "receipt" / "bench_app.py"

MIN_STAGED_LEAF = 1943
MAX_STAGED_LEAF = 4096
T2_FLOAT_MICROALGO = 100_000 + box_mbr(8, MAX_STAGED_LEAF)  # 1,744,100 (base + worst-case staging box)


def compile_m7(algod_client) -> dict:
    contracts = puya_compile(SRC)["Mpt7ReceiptApp"]
    approval = compile_teal_via_algod(algod_client, contracts["approval"])
    clear = compile_teal_via_algod(algod_client, contracts["clear"])
    return {"approval": approval, "clear": clear,
            "approval_sha256": sha256_hex(approval), "clear_sha256": sha256_hex(clear)}


def apply(algod_client, sender: str, sk: str, target, manifest) -> int:
    app_id = manifest.app_id("m7")
    if app_id is None:
        compiled = compile_m7(algod_client)
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
        manifest.set_app("m7", app_id=app_id, approval_sha256=compiled["approval_sha256"],
                          clear_sha256=compiled["clear_sha256"], schema_version=1, creator=sender)

    m7_cfg = target.contracts.get("m7")
    if m7_cfg and m7_cfg.t2_float:
        from deploy.create import top_up

        top_up(algod_client, sender, sk, app_id, T2_FLOAT_MICROALGO)
        manifest.set_app("m7", t2_float_microalgo=T2_FLOAT_MICROALGO)

    return app_id
