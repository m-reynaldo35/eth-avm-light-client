"""014 §4.1/§9: `Mpt7AnchoredReceiptApp` deployment -- the permanent,
manifest-pinned combination of M7's T1+T2 walk with M8's anchor check,
replacing the test-only, compiled-per-call `AnchorReceiptProbe` for the T2
path (§4.1's cost table: ~1.74 ALGO abandoned per T2 proof under the old
per-call-deploy model, vs. 0.014 ALGO of fees once deployed once and
reused).

Mirrors `deploy/plans/m7.py`'s own trivial shape (no create-time boxes, no
ARC-56, `create()` is a plain `ApplicationCreateTxn`) with ONE addition:
`handoff.ANCHOR_APP_ID` must be patched to the real, already-deployed M8 app
id BEFORE compiling (TP-M8-4's compile-time-binding requirement, §4.1),
exactly the same `deploy.compile.patched_repo_copy` mechanism
`relayer/drivers/m7_receipt.py::patched_probe_source` already uses for the
per-call probe -- this is why `Mpt7AnchoredReceiptApp`'s compiled bytecode
(and therefore its `approval_sha256` pin) is genuinely different per network:
it differs whenever the bound M8 app id differs, unlike every other bare
`Contract` in this repo's `deploy/plans/`.

014 §14 item 3 (normative): a real network's manifest entry for this
contract MUST be produced by actually running `apply()` below against a
reachable algod -- never hand-written -- and this module's own `apply()`
refuses to proceed if `m8` is not already in the manifest (mirrors
`deploy/plans/m8.py`'s own m4-counterparty precondition).
"""
from __future__ import annotations

from pathlib import Path

from algosdk import transaction

from deploy.compile import compile_teal_via_algod, patched_repo_copy, puya_compile, sha256_hex
from deploy.mbr import box_mbr, min_extra_pages

REPO_ROOT = Path(__file__).resolve().parents[2]

MIN_STAGED_LEAF = 1943
MAX_STAGED_LEAF = 4096
# Identical formula to deploy/plans/m7.py's own T2_FLOAT_MICROALGO -- the
# same worst-case 4,096 B staging box, funded once, reused indefinitely
# (014 §3.6/§6). `Mpt7AnchoredReceiptApp` stages exactly the same box shape
# `Mpt7ReceiptApp` does; there is no second box family here.
T2_FLOAT_MICROALGO = 100_000 + box_mbr(8, MAX_STAGED_LEAF)  # 1,744,100


class MissingM8Dependency(RuntimeError):
    """014 §4.1: `Mpt7AnchoredReceiptApp` compile-time-binds M8's app id
    (TP-M8-4) -- it cannot be compiled, let alone deployed, before M8
    already exists in the manifest."""


def compile_m7_anchored(algod_client, m8_app_id: int) -> dict:
    """Stages a patched `contracts/` copy with `handoff.ANCHOR_APP_ID` set
    to `m8_app_id`, compiles `contracts/receipt/anchored_app.py` from
    INSIDE that copy (so the patched constant is the one actually
    imported -- `patched_repo_copy`'s own docstring / `test_live_historical.
    py`'s established discipline), then resolves the real assembled
    bytecode via algod (bare-`Contract`, no offline TEAL assembler, same
    honest asymmetry `deploy/compile.py`'s module docstring documents)."""
    patched_root = patched_repo_copy(m8_app_id)
    src = patched_root / "contracts" / "receipt" / "anchored_app.py"
    contracts = puya_compile(src, extra_pythonpath=patched_root)["Mpt7AnchoredReceiptApp"]
    approval = compile_teal_via_algod(algod_client, contracts["approval"])
    clear = compile_teal_via_algod(algod_client, contracts["clear"])
    return {"approval": approval, "clear": clear,
            "approval_sha256": sha256_hex(approval), "clear_sha256": sha256_hex(clear)}


def apply(algod_client, sender: str, sk: str, target, manifest) -> int:
    m8_entry = manifest.apps.get("m8")
    if m8_entry is None or m8_entry.get("app_id") is None:
        raise MissingM8Dependency(
            "m7_anchored depends on m8 already existing in the manifest (014 §4.1's compile-time "
            "ANCHOR_APP_ID binding, TP-M8-4) -- deploy m8 first"
        )
    m8_app_id = m8_entry["app_id"]

    app_id = manifest.app_id("m7_anchored")
    if app_id is None:
        compiled = compile_m7_anchored(algod_client, m8_app_id)
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
        manifest.set_app(
            "m7_anchored", app_id=app_id, approval_sha256=compiled["approval_sha256"],
            clear_sha256=compiled["clear_sha256"], schema_version=1, creator=sender,
            bound_to={"m8_app_id": m8_app_id},
        )

    m7a_cfg = target.contracts.get("m7_anchored")
    if m7a_cfg and m7a_cfg.t2_float:
        from deploy.create import top_up

        top_up(algod_client, sender, sk, app_id, T2_FLOAT_MICROALGO)
        manifest.set_app("m7_anchored", t2_float_microalgo=T2_FLOAT_MICROALGO)

    return app_id
