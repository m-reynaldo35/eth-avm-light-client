"""Locate/deploy the `DonorIssuer`/`DonorCallee` pair (design doc §1.2,
§7.1). M9 does not compile or rewrite these -- they are infrastructure, not
verification logic, imported verbatim from `contracts/sync_committee/
bench_app.py` exactly as `tests/state_anchor/conftest.py::deploy_donor_pair`
already establishes. This module only differs from that conftest helper by
living outside `tests/` so `relayer.group.submit`/`relayer.drivers.*` can
import it without a `tests.*` dependency (§4.3 rule 1).
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from algosdk import transaction
from algosdk.atomic_transaction_composer import AccountTransactionSigner, TransactionWithSigner


def compile_teal(algod_client, src: str) -> bytes:
    import base64

    compiled = algod_client.compile(src)
    return base64.b64decode(compiled["result"])


def puya_compile_contracts(src_path: Path, *, extra_pythonpath: Path | None = None) -> dict[str, dict[str, str]]:
    """Runs `puyapy` against `src_path`; returns `{class_name: {"approval":
    teal_str, "clear": teal_str}}` for every contract defined in that
    file. `extra_pythonpath` (needed by `EthAvmClient.prove_receipt(
    against_anchor=True)`'s `AnchorReceiptProbe` compile, TP-M8-4): puyapy
    resolves `contracts.state_anchor.handoff` via ordinary Python import
    rules, so a PATCHED copy of `contracts/` (see `relayer.drivers.
    m7_receipt.patched_probe_source`) must be the one actually imported --
    compiling the original repo path would silently compile against the
    unpatched placeholder again."""
    out_dir = Path(tempfile.mkdtemp(prefix="relayer_puya_"))
    env = None
    if extra_pythonpath is not None:
        import os

        env = dict(os.environ)
        env["PYTHONPATH"] = str(extra_pythonpath) + ":" + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-m", "puyapy", str(src_path), "--out-dir", str(out_dir)],
        capture_output=True, text=True, env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"puyapy failed for {src_path}:\n{result.stdout}\n{result.stderr}")
    contracts: dict[str, dict[str, str]] = {}
    for approval_file in out_dir.glob("*.approval.teal"):
        name = approval_file.name[: -len(".approval.teal")]
        clear_file = out_dir / f"{name}.clear.teal"
        contracts[name] = {"approval": approval_file.read_text(), "clear": clear_file.read_text()}
    return contracts


def deploy_donor_pair(algod_client, sender: str, sk: str, *, repo_root: Path) -> tuple[int, int]:
    """Compiles and deploys `contracts/sync_committee/bench_app.py`'s
    `DonorCallee`/`DonorIssuer` pair. Returns `(callee_id, issuer_id)`. Per
    009 §1.2: M9 *may* deploy this pair on a network where it is absent,
    because it is infrastructure -- source imported, never rewritten."""
    src = repo_root / "contracts" / "sync_committee" / "bench_app.py"
    contracts = puya_compile_contracts(src)

    def deploy(name: str) -> int:
        approval = compile_teal(algod_client, contracts[name]["approval"])
        clear = compile_teal(algod_client, contracts[name]["clear"])
        sp = algod_client.suggested_params()
        txn = transaction.ApplicationCreateTxn(
            sender=sender, sp=sp, on_complete=transaction.OnComplete.NoOpOC,
            approval_program=approval, clear_program=clear,
            global_schema=transaction.StateSchema(0, 0), local_schema=transaction.StateSchema(0, 0),
        )
        stxn = txn.sign(sk)
        txid = algod_client.send_transaction(stxn)
        confirmed = transaction.wait_for_confirmation(algod_client, txid, 4)
        return confirmed["application-index"]

    return deploy("DonorCallee"), deploy("DonorIssuer")


def donor_transaction_with_signer(algod_client, sender: str, sk: str, issuer_id: int, callee_id: int,
                                   n: int, *, extra_boxes: list[tuple[int, bytes]] | None = None
                                   ) -> TransactionWithSigner:
    """§7.1's DONOR_SIBLING convention: one `DonorIssuer` transaction
    issuing `n` no-op inner calls to `DonorCallee`, raising the group's
    shared opcode-budget pool by ~682/call net (004 §2.4). Fee must cover
    every inner call (§7.6's `GroupPlan.check()` asserts this).

    `extra_boxes` (§7.4/§9.1's overflow-box-references trick, mirroring
    `test_live_e2e_finality.py::_issue_donor_txn`): box references are a
    TRANSACTION-level field, not tied to which app actually touches the
    box, so a worst-case `plan_box_refs` group can pad this SAME donor
    transaction with overflow references its own logic never touches --
    pure padding that still counts toward the pooled box-write budget
    (§7.3)."""
    signer = AccountTransactionSigner(sk)
    sp = algod_client.suggested_params()
    sp.flat_fee = True
    sp.fee = (n + 1) * 1000
    kwargs = {}
    if extra_boxes:
        kwargs["boxes"] = extra_boxes
    txn = transaction.ApplicationNoOpTxn(
        sender=sender, sp=sp, index=issuer_id,
        app_args=[n.to_bytes(8, "big"), callee_id.to_bytes(8, "big")],
        foreign_apps=[callee_id], **kwargs,
    )
    return TransactionWithSigner(txn, signer)
