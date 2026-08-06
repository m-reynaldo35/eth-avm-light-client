"""Shared pytest infrastructure for M8's `algod`-backed test tiers. Mirrors
`tests/sync_committee/conftest.py`'s pattern (compile-via-puyapy /
simulate-with-extra-budget), generalised into free helper functions since
M8's tests need to compile and deploy SEVERAL different contracts (the real
`TrustedRootAnchor`, the settable `M4Probe`, the adversarial `FakeAnchor`,
and `AnchorReceiptProbe` -- the last of which must be compiled with
`handoff.ANCHOR_APP_ID` patched to `TrustedRootAnchor`'s REAL, just-deployed
app id, exactly the compile-time-binding TP-M8-4 requires of every real
consumer).

Tests marked to need `algod` are automatically skipped if no dev-mode algod
is reachable, matching `ARCHITECTURE.md`'s two-CI policy.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ALGOD_ADDRESS = "http://localhost:4051"
KMD_ADDRESS = "http://localhost:4052"
TOKEN = "a" * 64

REPO_ROOT = Path(__file__).resolve().parents[2]
SIM_EXTRA_BUDGET_CAP = 320_000


def _algod_reachable() -> bool:
    try:
        req = urllib.request.Request(
            ALGOD_ADDRESS + "/v2/status", headers={"X-Algo-API-Token": TOKEN}
        )
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


@pytest.fixture(scope="session")
def algod_available() -> bool:
    return _algod_reachable()


def algod_client():
    from algosdk.v2client import algod as algod_mod

    return algod_mod.AlgodClient(TOKEN, ALGOD_ADDRESS)


def kmd_client():
    from algosdk import kmd as kmd_mod

    return kmd_mod.KMDClient(TOKEN, KMD_ADDRESS)


def compile_teal(algod, src: str) -> bytes:
    req = urllib.request.Request(
        ALGOD_ADDRESS + "/v2/teal/compile",
        data=src.encode(),
        headers={"X-Algo-API-Token": TOKEN, "Content-Type": "text/plain"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        body = json.load(r)
    return base64.b64decode(body["result"])


def funded_account(algod, kmd, min_balance: int = 200_000_000):
    wallets = kmd.list_wallets()
    wid = next(w["id"] for w in wallets if w["name"] == "unencrypted-default-wallet")
    handle = kmd.init_wallet_handle(wid, "")
    try:
        addrs = kmd.list_keys(handle)
        best, best_bal = None, -1
        for a in addrs:
            bal = algod.account_info(a)["amount"]
            if bal > best_bal:
                best, best_bal = a, bal
        sk = kmd.export_key(handle, "", best)
        return best, sk
    finally:
        kmd.release_wallet_handle(handle)


def puya_compile(src_path: Path, extra_pythonpath: Path | None = None) -> dict:
    """Runs `puyapy` against `src_path`, returns
    `{class_name: {"approval": str, "clear": str, "arc56": dict|None}}` for
    every contract defined directly in that file."""
    out_dir = Path(tempfile.mkdtemp(prefix="m8_puya_"))
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
    contracts = {}
    for approval_file in out_dir.glob("*.approval.teal"):
        name = approval_file.name[: -len(".approval.teal")]
        clear_file = out_dir / f"{name}.clear.teal"
        arc56_file = out_dir / f"{name}.arc56.json"
        contracts[name] = {
            "approval": approval_file.read_text(),
            "clear": clear_file.read_text(),
            "arc56": json.loads(arc56_file.read_text()) if arc56_file.exists() else None,
        }
    return contracts


def patched_repo_copy(anchor_app_id: int) -> Path:
    """Stages a full temp copy of `contracts/` (and nothing else needed for
    import resolution) with `contracts/state_anchor/handoff.py`'s
    `ANCHOR_APP_ID` placeholder replaced by the REAL, already-deployed
    `TrustedRootAnchor` app id -- exactly the compile-time binding TP-M8-4
    requires every real consumer to perform. Returns the temp root (to be
    used as `PYTHONPATH`)."""
    tmp_root = Path(tempfile.mkdtemp(prefix="m8_patched_"))
    shutil.copytree(REPO_ROOT / "contracts", tmp_root / "contracts")
    handoff_path = tmp_root / "contracts" / "state_anchor" / "handoff.py"
    text = handoff_path.read_text()
    needle = "ANCHOR_APP_ID: int = 0"
    assert needle in text, "handoff.py's ANCHOR_APP_ID placeholder line changed shape"
    handoff_path.write_text(text.replace(needle, f"ANCHOR_APP_ID: int = {anchor_app_id}"))
    return tmp_root


@dataclass
class SimResult:
    ok: bool
    app_budget_consumed: int = 0
    logs: list = field(default_factory=list)
    return_value: bytes | None = None
    failure: str = ""
    raw: dict = field(default_factory=dict)


class Arc4Harness:
    """Deploys ONE compiled ARC4Contract (from a `puya_compile` result entry)
    and exposes `create`/`submit`/`call`/`call_group`, mirroring
    `tests/sync_committee/conftest.py`'s `SyncCommitteeLiveHarness` but
    generalised to any contract/method set via the ARC-56 `methods` table.
    """

    def __init__(self, compiled: dict, sender: str, sk: str):
        self.algod = algod_client()
        self.approval_teal = compiled["approval"]
        self.clear_teal = compiled["clear"]
        self.arc56 = compiled["arc56"]
        self.methods = {m["name"]: m for m in self.arc56["methods"]}
        self.global_schema_ints = self.arc56["state"]["schema"]["global"]["ints"]
        self.global_schema_bytes = self.arc56["state"]["schema"]["global"]["bytes"]
        self.approval_compiled = compile_teal(self.algod, self.approval_teal)
        self.clear_compiled = compile_teal(self.algod, self.clear_teal)
        self.sender = sender
        self.sk = sk
        self.app_id = None
        self.ring_n: int | None = None  # set by test fixtures for M8's Arc4Harness, enables auto box refs

    def _auto_boxes_for(self, method_name: str, args: list):
        """M8-specific convenience: `TrustedRootAnchor`'s ring/pin box names
        are a pure function of `block_number` (and the immutable `ring_n`),
        so tests do not have to hand-compute `h:<residue>`/`p:<block>`/
        `forks8` box references at every call site -- this mirrors what a
        real ARC-56-aware client library would derive automatically."""
        if self.ring_n is None or method_name not in self.methods:
            return None
        m = self.methods[method_name]
        arg_names = [a["name"] for a in m.get("args", [])]
        boxes = []
        if method_name in ("anchor_direct", "anchor_historical"):
            boxes.append((0, b"forks8"))
        bn_name = "block_number" if "block_number" in arg_names else (
            "el_block_number" if "el_block_number" in arg_names else None
        )
        if bn_name is not None:
            idx = arg_names.index(bn_name)
            bn = args[idx]
            residue = bn & (self.ring_n - 1)
            boxes.append((0, b"h:" + residue.to_bytes(8, "big")))
            if method_name in ("pin", "unpin"):
                boxes.append((0, b"p:" + bn.to_bytes(8, "big")))
        return boxes or None

    def create(self, method_args: list, *, boxes=None, extra_pages: int = 0, fund_app: int = 0) -> int:
        """`fund_app` (µALGO): if nonzero, predicts the about-to-be-created
        app's address (mirrors `tests/sync_committee/conftest.py`'s
        `SyncCommitteeLiveHarness.create` probe-fund-create recipe exactly
        -- same reasoning: `create()` may create boxes whose MBR is charged
        to the APP account, which needs funds before `create()` executes,
        but an app's address is only knowable once its id is)."""
        from algosdk import logic, transaction
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
        )

        last_error = None
        attempts = 5 if fund_app else 1
        for _attempt in range(attempts):
            if fund_app:
                probe_teal = "#pragma version 10\nint 1\nreturn\n"
                probe_compiled = compile_teal(self.algod, probe_teal)
                sp0 = self.algod.suggested_params()
                probe_txn = transaction.ApplicationCreateTxn(
                    sender=self.sender, sp=sp0, on_complete=transaction.OnComplete.NoOpOC,
                    approval_program=probe_compiled, clear_program=probe_compiled,
                    global_schema=transaction.StateSchema(0, 0), local_schema=transaction.StateSchema(0, 0),
                )
                probe_stxn = probe_txn.sign(self.sk)
                probe_txid = self.algod.send_transaction(probe_stxn)
                probe_confirmed = transaction.wait_for_confirmation(self.algod, probe_txid, 4)
                predicted_id = probe_confirmed["application-index"] + 2
                predicted_address = logic.get_application_address(predicted_id)
                sp1 = self.algod.suggested_params()
                fund_txn = transaction.PaymentTxn(self.sender, sp1, predicted_address, fund_app)
                fund_stxn = fund_txn.sign(self.sk)
                fund_txid = self.algod.send_transaction(fund_stxn)
                transaction.wait_for_confirmation(self.algod, fund_txid, 4)

            atc = AtomicTransactionComposer()
            signer = AccountTransactionSigner(self.sk)
            method = Method.undictify(self.methods["create"])
            sp = self.algod.suggested_params()
            sp.flat_fee = True
            sp.fee = 1000
            kwargs = {}
            if boxes:
                kwargs["boxes"] = boxes
            atc.add_method_call(
                app_id=0, method=method, sender=self.sender, sp=sp, signer=signer,
                method_args=method_args, on_complete=transaction.OnComplete.NoOpOC,
                approval_program=self.approval_compiled, clear_program=self.clear_compiled,
                global_schema=transaction.StateSchema(self.global_schema_ints, self.global_schema_bytes),
                local_schema=transaction.StateSchema(0, 0), extra_pages=extra_pages, **kwargs,
            )
            try:
                result = atc.execute(self.algod, 4)
            except Exception as exc:  # noqa: BLE001 -- raced funding target, retry
                last_error = exc
                continue
            confirmed = self.algod.pending_transaction_info(result.tx_ids[0])
            self.app_id = confirmed["application-index"]
            if fund_app and self.app_id != predicted_id:
                last_error = AssertionError(f"app id prediction raced: predicted {predicted_id}, got {self.app_id}")
                continue
            return self.app_id
        raise RuntimeError(f"create() failed after retries, last error: {last_error}")

    def _build_atc(self, calls: list, default_boxes=None, default_apps=None, fee=1000):
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
        )

        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(self.sk)
        for call in calls:
            method_name = call["method"]
            args = call.get("args", [])
            call_boxes = call.get("boxes", default_boxes)
            if call_boxes is None:
                call_boxes = self._auto_boxes_for(method_name, args)
            call_apps = call.get("apps", default_apps)
            call_app_id = call.get("app_id", self.app_id)
            method = Method.undictify(self.methods[method_name])
            sp = self.algod.suggested_params()
            sp.flat_fee = True
            sp.fee = call.get("fee", fee)
            kwargs = {}
            if call_boxes:
                kwargs["boxes"] = call_boxes
            if call_apps:
                kwargs["foreign_apps"] = call_apps
            atc.add_method_call(
                app_id=call_app_id, method=method, sender=self.sender, sp=sp, signer=signer,
                method_args=args, **kwargs,
            )
        return atc

    def submit(self, calls: list, **kwargs) -> object:
        atc = self._build_atc(calls, **kwargs)
        return atc.execute(self.algod, 4)

    def submit_with_donor(self, method_name: str, args: list, *, donor_issuer_id: int, donor_callee_id: int,
                           n_donors: int = 12, apps=None, boxes=None):
        """A REAL, non-simulated `[DonorIssuer(n), method(...)]` atomic
        group -- for method calls whose real opcode cost exceeds a single
        top-level call's 700 budget (§10.2/§10.3's DIRECT/HISTORICAL
        anchoring groups)."""
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer

        if boxes is None:
            boxes = self._auto_boxes_for(method_name, args)
        atc = AtomicTransactionComposer()
        atc.add_transaction(donor_txn(self.algod, self.sender, self.sk, donor_issuer_id, donor_callee_id, n_donors))
        signer = AccountTransactionSigner(self.sk)
        method = Method.undictify(self.methods[method_name])
        sp = self.algod.suggested_params()
        sp.flat_fee = True
        sp.fee = 1000
        kwargs = {}
        if boxes:
            kwargs["boxes"] = boxes
        if apps:
            kwargs["foreign_apps"] = apps
        atc.add_method_call(
            app_id=self.app_id, method=method, sender=self.sender, sp=sp, signer=signer,
            method_args=args, **kwargs,
        )
        return atc.execute(self.algod, 4)

    def call_group(self, calls: list, extra_budget: int = SIM_EXTRA_BUDGET_CAP, **kwargs) -> list:
        from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup

        atc = self._build_atc(calls, **kwargs)
        group = atc.build_group()
        stxns = [t.txn.sign(self.sk) for t in group]
        sreq = SimulateRequest(
            txn_groups=[SimulateRequestTransactionGroup(txns=stxns)],
            extra_opcode_budget=extra_budget, allow_unnamed_resources=True,
        )
        resp = self.algod.simulate_transactions(sreq)
        return self._parse_group(resp, n=len(calls))

    def call(self, method_name: str, args: list, **kwargs) -> SimResult:
        return self.call_group([{"method": method_name, "args": args, **kwargs}])[0]

    def _parse_group(self, resp: dict, n: int) -> list:
        grp = resp["txn-groups"][0]
        group_ok = True
        group_failure = ""
        failed_at_index = None
        if grp.get("failure-message"):
            group_ok = False
            group_failure = grp["failure-message"]
            failed_at = grp.get("failed-at") or []
            failed_at_index = failed_at[0] if failed_at else None
        results = []
        for i in range(n):
            res = SimResult(ok=True, raw=resp)
            res.app_budget_consumed = grp.get("app-budget-consumed", 0)
            if not group_ok and (failed_at_index is None or i >= failed_at_index):
                res.ok = False
                res.failure = group_failure
            txnres = grp["txn-results"][i]
            tr = txnres.get("txn-result", {})
            logs = tr.get("logs") or []
            res.logs = [base64.b64decode(x) for x in logs]
            if res.logs and res.logs[-1][:4] == bytes.fromhex("151f7c75"):
                res.return_value = res.logs[-1][4:]
            results.append(res)
        return results


def deploy_donor_pair(algod, sender, sk) -> tuple[int, int]:
    """Compiles and deploys `contracts/sync_committee/bench_app.py`'s
    `DonorCallee`/`DonorIssuer` pair (reused verbatim, not redefined --
    `contracts/state_anchor/bench_app.py` re-exports them for exactly this
    reason). Returns `(callee_id, issuer_id)`."""
    from algosdk import transaction

    src = REPO_ROOT / "contracts" / "sync_committee" / "bench_app.py"
    contracts = puya_compile(src)

    def deploy(name):
        approval = compile_teal(algod, contracts[name]["approval"])
        clear = compile_teal(algod, contracts[name]["clear"])
        sp = algod.suggested_params()
        txn = transaction.ApplicationCreateTxn(
            sender=sender, sp=sp, on_complete=transaction.OnComplete.NoOpOC,
            approval_program=approval, clear_program=clear,
            global_schema=transaction.StateSchema(0, 0), local_schema=transaction.StateSchema(0, 0),
        )
        stxn = txn.sign(sk)
        txid = algod.send_transaction(stxn)
        confirmed = transaction.wait_for_confirmation(algod, txid, 4)
        return confirmed["application-index"]

    return deploy("DonorCallee"), deploy("DonorIssuer")


def donor_txn(algod, sender, sk, issuer_id: int, callee_id: int, n: int, extra_boxes=None):
    """One `DonorIssuer` sibling transaction issuing `n` no-op inner calls
    to `DonorCallee`, raising the atomic group's shared opcode-budget pool
    by ~682/call net (measured, 004 §2.4) -- mirrors
    `tests/sync_committee/test_live_e2e_finality.py`'s `_issue_donor_txn`
    exactly."""
    from algosdk import transaction
    from algosdk.atomic_transaction_composer import AccountTransactionSigner, TransactionWithSigner

    signer = AccountTransactionSigner(sk)
    sp = algod.suggested_params()
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


@pytest.fixture(scope="module")
def anchor_src():
    return REPO_ROOT / "contracts" / "state_anchor" / "anchor_app.py"


@pytest.fixture(scope="module")
def bench_src():
    return REPO_ROOT / "contracts" / "state_anchor" / "bench_app.py"
