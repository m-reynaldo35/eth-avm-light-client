"""`LiveHarness` -- M1's live-deploy/call ergonomics (docs/design/
011-test-harness-ci.md §6.3). Lives in its own module, not `conftest.py`,
so test files can import it without a `from tests.*.conftest import ...`
dotted import (§6.1/H-4).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path

from tests.harness.chain import algod_client, funded_account, kmd_client
from tests.harness.deployment import compile_teal

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS_SRC = REPO_ROOT / "contracts" / "primitives" / "bls" / "harness.py"

SIM_EXTRA_BUDGET_CAP = 320_000


@dataclass
class SimResult:
    ok: bool
    app_budget_consumed: int = 0
    logs: list = field(default_factory=list)
    return_value: bytes | None = None
    failure: str = ""
    raw: dict = field(default_factory=dict)


class LiveHarness:
    """Compiles + deploys BlsHarness once, exposes `call(method_name, *args)`."""

    def __init__(self):
        import subprocess
        import sys
        import tempfile

        self.algod = algod_client()

        out_dir = Path(tempfile.mkdtemp(prefix="bls_harness_"))
        subprocess.run(
            [sys.executable, "-m", "puyapy", str(HARNESS_SRC), "--out-dir", str(out_dir)],
            check=True,
            capture_output=True,
        )
        self.approval_teal = (out_dir / "BlsHarness.approval.teal").read_text()
        self.clear_teal = (out_dir / "BlsHarness.clear.teal").read_text()
        import json as _json

        arc56 = _json.loads((out_dir / "BlsHarness.arc56.json").read_text())
        self.arc56 = arc56
        self.methods = {m["name"]: m for m in arc56["methods"]}

        self.approval_compiled = compile_teal(self.algod, self.approval_teal)
        self.clear_compiled = compile_teal(self.algod, self.clear_teal)
        self.sender, self.sk = funded_account(self.algod, kmd_client())
        self.app_id = self._create_app()

    def _create_app(self) -> int:
        from algosdk import logic, transaction

        sp = self.algod.suggested_params()
        txn = transaction.ApplicationCreateTxn(
            sender=self.sender,
            sp=sp,
            on_complete=transaction.OnComplete.NoOpOC,
            approval_program=self.approval_compiled,
            clear_program=self.clear_compiled,
            global_schema=transaction.StateSchema(0, 0),
            local_schema=transaction.StateSchema(0, 0),
            extra_pages=3,
        )
        stxn = txn.sign(self.sk)
        txid = self.algod.send_transaction(stxn)
        result = transaction.wait_for_confirmation(self.algod, txid, 4)
        app_id = result["application-index"]

        # Fund the app account for real (a committed, not simulated, txn):
        # box storage MBR (400 uA/byte + 2500 base per box, §10.2) is paid
        # from the APP's own balance, not the caller's -- box-staging tests
        # (T5/T7 at the true 42-point value-cap width) need this.
        app_address = logic.get_application_address(app_id)
        sp2 = self.algod.suggested_params()
        fund_txn = transaction.PaymentTxn(
            sender=self.sender,
            sp=sp2,
            receiver=app_address,
            amt=10_000_000,  # 10 ALGO -- comfortably covers a few 4096B boxes
        )
        fund_stxn = fund_txn.sign(self.sk)
        fund_txid = self.algod.send_transaction(fund_stxn)
        transaction.wait_for_confirmation(self.algod, fund_txid, 4)

        return app_id

    def call(self, method_name: str, *args, extra_budget: int = SIM_EXTRA_BUDGET_CAP) -> SimResult:
        """Call a single ABI method on the deployed harness via simulate.
        `args` are native Python values matching the method's ABI arg types
        (e.g. `bytes` for `byte[]`, `int` for `uint64`) --
        `AtomicTransactionComposer` does the ABI encoding and 4-byte
        method-selector prefixing.
        """
        return self.call_group([(method_name, list(args))], extra_budget=extra_budget)[0]

    def call_group(
        self, calls: list, extra_budget: int = SIM_EXTRA_BUDGET_CAP
    ) -> list:
        """Call several ABI methods as ONE atomic transaction group via
        simulate. `calls` is a list of `(method_name, args)` pairs, in
        group order. State changes (e.g. box writes) from an earlier txn in
        the group ARE visible to a later txn in the same simulated group --
        this is what lets `box_stage_write` + a box-reading primitive call
        be tested together without a real (non-simulated) multi-round-trip
        submission. Returns one `SimResult` per call, in the same order.
        """
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
        )

        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(self.sk)
        for method_name, args in calls:
            method = Method.undictify(self.methods[method_name])
            sp = self.algod.suggested_params()
            sp.flat_fee = True
            sp.fee = 1000
            atc.add_method_call(
                app_id=self.app_id,
                method=method,
                sender=self.sender,
                sp=sp,
                signer=signer,
                method_args=list(args),
            )
        group = atc.build_group()

        from algosdk.v2client.models import (
            SimulateRequest,
            SimulateRequestTransactionGroup,
        )

        stxns = [t.txn.sign(self.sk) for t in group]
        sreq = SimulateRequest(
            txn_groups=[SimulateRequestTransactionGroup(txns=stxns)],
            extra_opcode_budget=extra_budget,
            allow_unnamed_resources=True,
        )
        resp = self.algod.simulate_transactions(sreq)
        return self._parse_group(resp, n=len(calls))

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

    def _parse(self, resp: dict) -> SimResult:
        return self._parse_group(resp, n=1)[0]
