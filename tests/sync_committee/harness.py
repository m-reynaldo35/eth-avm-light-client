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
# opens gen 1; some tests open a second session) + headroom. Comfortably
# covers the ~19.7 ALGO/generation the design doc measures (§8.2) twice
# over. 013 §4: no `forks` box term any more -- the fork table's MBR is
# creator-side global-state MBR, paid at create time, not app-account box
# MBR funded here.
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
        """Real, committed `create()` call.

        013 §0/§3/§5.4: `create()` used to call `forks.forks_box_create()`
        unconditionally, and box MBR is charged against the APP's own
        account -- so the app account had to already hold funds by the
        moment `create()` executed, before its address was knowable
        (`get_application_address` is a deterministic function of the app
        id, but the id itself is assigned only on confirmation). That forced
        a probe-fund-create dance: deploy a throwaway app first to learn the
        network's next-app-id counter, fund the PREDICTED address in an
        ordinary preceding transaction, then submit the real create and
        retry if the id moved (`docs/design/013-fork-table-global-state.md`
        §0 -- this exact race is what failed 40+ consecutive times on real
        mainnet and is the reason 013 exists at all).

        This revision moves the fork table into global state, whose MBR is
        charged to the CREATOR -- an account that already exists. `create()`
        now creates no box at all, needs no pre-funding of the app account,
        and there is no id to predict and no race to lose: a single,
        ordinary, unfunded `add_method_call(app_id=0, ...)` is the whole
        thing (§17 item 13: this docstring must describe the mechanism that
        exists now, not the defect that used to require the dance above)."""
        from algosdk import transaction
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
        )

        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(self.sk)
        method = Method.undictify(self.methods["create"])
        sp = self.algod.suggested_params()
        sp.flat_fee = True
        sp.fee = 1000
        atc.add_method_call(
            app_id=0,
            method=method,
            sender=self.sender,
            sp=sp,
            signer=signer,
            method_args=[governance_addr, genesis_validators_root],
            on_complete=transaction.OnComplete.NoOpOC,
            approval_program=self.approval_compiled,
            clear_program=self.clear_compiled,
            global_schema=transaction.StateSchema(self.global_schema_ints, self.global_schema_bytes),
            local_schema=transaction.StateSchema(0, 0),
            extra_pages=3,
        )
        result = atc.execute(self.algod, 4)
        confirmed = self.algod.pending_transaction_info(result.tx_ids[0])
        self.app_id = confirmed["application-index"]
        return self.app_id

    def fund_app(self, amount: int = APP_FUNDING_MICROALGO) -> None:
        """An ordinary, POST-create funding payment to the app account --
        013 §0/§5.4: M4's OTHER box families (`k:`/`s:`/`a:`, install/
        session/aggregate) are untouched by this revision and still need
        the app account funded before `install_open_keys`/
        `install_open_session`/`install_finalize` create them. Before 013,
        this same payment had to race the create transaction (fund a
        PREDICTED address before the app existed); now `self.app_id` is
        already a real, confirmed id, so this is just a plain `PaymentTxn`
        to a known address -- no prediction, no race, no retry loop."""
        from algosdk import logic, transaction

        address = logic.get_application_address(self.app_id)
        sp = self.algod.suggested_params()
        pay_txn = transaction.PaymentTxn(sender=self.sender, sp=sp, receiver=address, amt=amount)
        txid = self.algod.send_transaction(pay_txn.sign(self.sk))
        transaction.wait_for_confirmation(self.algod, txid, 4)

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
