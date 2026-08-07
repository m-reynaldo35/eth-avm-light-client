"""`SyncCommitteeLiveHarness` -- M4's live-deploy/call ergonomics
(docs/design/011-test-harness-ci.md §6.3: "keeps its ABI-call
ergonomics"). Lives in its own module, not `conftest.py`, so test files can
import the class directly (`from tests.sync_committee.harness import
SyncCommitteeLiveHarness`) without a `from tests.*.conftest import ...`
dotted import (§6.1/H-4).
"""

from __future__ import annotations

import base64
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from tests.harness.chain import algod_client, funded_account, kmd_client
from tests.harness.deployment import compile_teal

REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER_SRC = REPO_ROOT / "contracts" / "sync_committee" / "verifier.py"

SIM_EXTRA_BUDGET_CAP = 320_000
# 8 key boxes (6,144 B) + 1 session box (424 B) per generation, x2 (bootstrap
# opens gen 1; some tests open a second session) + the `forks` box (576 B) +
# headroom. Comfortably covers the ~19.7 ALGO/generation the design doc
# measures (§8.2) twice over.
APP_FUNDING_MICROALGO = 45_000_000


@dataclass
class SimResult:
    ok: bool
    app_budget_consumed: int = 0
    logs: list = field(default_factory=list)
    return_value: bytes | None = None
    failure: str = ""
    raw: dict = field(default_factory=dict)


class SyncCommitteeLiveHarness:
    """Compiles + deploys `SyncCommitteeVerifier` once, exposes `call`/
    `call_group` (simulate, for assert-fails-cleanly checks) and `submit`
    (a real committed group, for state-machine setup steps)."""

    def __init__(self):
        self.algod = algod_client()
        self.kmd = kmd_client()

        out_dir = Path(tempfile.mkdtemp(prefix="m4_verifier_"))
        subprocess.run(
            [sys.executable, "-m", "puyapy", str(VERIFIER_SRC), "--out-dir", str(out_dir)],
            check=True,
            capture_output=True,
        )
        self.approval_teal = (out_dir / "SyncCommitteeVerifier.approval.teal").read_text()
        self.clear_teal = (out_dir / "SyncCommitteeVerifier.clear.teal").read_text()
        import json as _json

        arc56 = _json.loads((out_dir / "SyncCommitteeVerifier.arc56.json").read_text())
        self.arc56 = arc56
        self.methods = {m["name"]: m for m in arc56["methods"]}
        self.global_schema_ints = arc56["state"]["schema"]["global"]["ints"]
        self.global_schema_bytes = arc56["state"]["schema"]["global"]["bytes"]

        self.approval_compiled = compile_teal(self.algod, self.approval_teal)
        self.clear_compiled = compile_teal(self.algod, self.clear_teal)
        self.sender, self.sk = funded_account(self.algod, self.kmd)
        self.app_id = None  # set by create()

    def create(self, governance_addr: str, genesis_validators_root: bytes) -> int:
        """Real, committed `create()` call. `create()`'s body calls
        `forks.forks_box_create()` unconditionally, and box MBR is charged
        against the APP's own account -- so the app account must already
        hold funds by the moment `create()` executes, before its address is
        knowable. Resolved the same way any Algorand tool does: deploy a
        trivial throwaway app first to learn the network's next-app-id
        counter, fund `predicted_id + 1`'s address in an ordinary preceding
        transaction, then submit the real create.

        The predicted id is `probe_id + 2`, not `probe_id + 1`: Algorand's
        `TxnCounter` advances by one per CONFIRMED TRANSACTION OF ANY KIND,
        not merely per creation (confirmed empirically). The probe-fund-
        create sequence is wrapped in a bounded retry loop for the same
        reason `tests/state_anchor/harness.py::Arc4Harness.create` is."""
        from algosdk import transaction, logic
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
        )

        probe_teal = "#pragma version 10\nint 1\nreturn\n"
        probe_compiled = compile_teal(self.algod, probe_teal)

        last_error = None
        for _attempt in range(5):
            sp0 = self.algod.suggested_params()
            probe_txn = transaction.ApplicationCreateTxn(
                sender=self.sender,
                sp=sp0,
                on_complete=transaction.OnComplete.NoOpOC,
                approval_program=probe_compiled,
                clear_program=probe_compiled,
                global_schema=transaction.StateSchema(0, 0),
                local_schema=transaction.StateSchema(0, 0),
            )
            probe_stxn = probe_txn.sign(self.sk)
            probe_txid = self.algod.send_transaction(probe_stxn)
            probe_confirmed = transaction.wait_for_confirmation(self.algod, probe_txid, 4)
            predicted_id = probe_confirmed["application-index"] + 2

            predicted_address = logic.get_application_address(predicted_id)
            sp1 = self.algod.suggested_params()
            fund_txn = transaction.PaymentTxn(
                sender=self.sender, sp=sp1, receiver=predicted_address, amt=APP_FUNDING_MICROALGO
            )
            fund_stxn = fund_txn.sign(self.sk)
            fund_txid = self.algod.send_transaction(fund_stxn)
            transaction.wait_for_confirmation(self.algod, fund_txid, 4)

            atc = AtomicTransactionComposer()
            signer = AccountTransactionSigner(self.sk)
            method = Method.undictify(self.methods["create"])
            sp2 = self.algod.suggested_params()
            sp2.flat_fee = True
            sp2.fee = 1000
            atc.add_method_call(
                app_id=0,
                method=method,
                sender=self.sender,
                sp=sp2,
                signer=signer,
                method_args=[governance_addr, genesis_validators_root],
                on_complete=transaction.OnComplete.NoOpOC,
                approval_program=self.approval_compiled,
                clear_program=self.clear_compiled,
                global_schema=transaction.StateSchema(self.global_schema_ints, self.global_schema_bytes),
                local_schema=transaction.StateSchema(0, 0),
                extra_pages=3,
                boxes=[(0, b"forks")],  # create() calls forks_box_create() (§4.3)
            )
            try:
                result = atc.execute(self.algod, 4)
            except Exception as exc:  # noqa: BLE001 -- raced funding target, retry
                last_error = exc
                continue
            confirmed = self.algod.pending_transaction_info(result.tx_ids[0])
            self.app_id = confirmed["application-index"]
            if self.app_id != predicted_id:
                last_error = AssertionError(
                    f"app id prediction raced: predicted {predicted_id}, got {self.app_id}"
                )
                continue
            return self.app_id

        raise RuntimeError(f"create() failed after retries, last error: {last_error}")

    def submit(self, calls: list, *, boxes: list[tuple[int, bytes]] | None = None) -> list:
        """Real, COMMITTED atomic group of ABI method calls. `calls` is a
        list of either `(method_name, args)` pairs (uses the shared `boxes`
        param) or `(method_name, args, per_call_boxes)` triples (overrides
        `boxes` for that one call only)."""
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
        )

        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(self.sk)
        for call in calls:
            if len(call) == 3:
                method_name, args, call_boxes = call
            else:
                method_name, args = call
                call_boxes = boxes
            method = Method.undictify(self.methods[method_name])
            sp = self.algod.suggested_params()
            sp.flat_fee = True
            sp.fee = 2000
            kwargs = {}
            if call_boxes:
                kwargs["boxes"] = call_boxes
            atc.add_method_call(
                app_id=self.app_id,
                method=method,
                sender=self.sender,
                sp=sp,
                signer=signer,
                method_args=list(args),
                **kwargs,
            )
        result = atc.execute(self.algod, 4)
        return result

    def call(self, method_name: str, *args, extra_budget: int = SIM_EXTRA_BUDGET_CAP, boxes=None) -> SimResult:
        call = (method_name, list(args), boxes) if boxes else (method_name, list(args))
        return self.call_group([call], extra_budget=extra_budget)[0]

    def call_group(self, calls: list, extra_budget: int = SIM_EXTRA_BUDGET_CAP) -> list:
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
        )

        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(self.sk)
        for call in calls:
            if len(call) == 3:
                method_name, args, call_boxes = call
            else:
                method_name, args = call
                call_boxes = None
            method = Method.undictify(self.methods[method_name])
            sp = self.algod.suggested_params()
            sp.flat_fee = True
            sp.fee = 1000
            kwargs = {}
            if call_boxes:
                kwargs["boxes"] = call_boxes
            atc.add_method_call(
                app_id=self.app_id,
                method=method,
                sender=self.sender,
                sp=sp,
                signer=signer,
                method_args=list(args),
                **kwargs,
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
