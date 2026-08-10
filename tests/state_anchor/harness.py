"""`Arc4Harness` -- M8's live-deploy/call ergonomics (docs/design/
011-test-harness-ci.md §6.3: "keeps its ABI-call ergonomics"). Lives in its
own module, not `conftest.py`, so test files can import the class directly
(`from tests.state_anchor.harness import Arc4Harness`) without a
`from tests.*.conftest import ...` dotted import (§6.1/H-4) -- `conftest.py`
itself now only registers fixtures.

Every compile/deploy primitive `Arc4Harness` used to define locally now
delegates to `tests.harness.chain`/`tests.harness.deployment`, which
themselves delegate to `deploy.compile`/`relayer.group.donors` -- no
`puyapy` invocation and no `/v2/teal/compile` literal live in `tests/`
outside `deploy/`/`relayer/` any more (§6.2).
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field

from tests.harness.chain import algod_client
from tests.harness.deployment import compile_teal

SIM_EXTRA_BUDGET_CAP = 320_000


@dataclass
class SimResult:
    ok: bool
    app_budget_consumed: int = 0
    logs: list = field(default_factory=list)
    return_value: bytes | None = None
    failure: str = ""
    raw: dict = field(default_factory=dict)


class Arc4Harness:
    """Deploys ONE compiled ARC4Contract (from a `puya_compile` result
    entry) and exposes `create`/`submit`/`call`/`call_group`/
    `submit_with_donor`."""

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
        self.ring_n: int | None = None  # set by test fixtures, enables auto box refs

    def _auto_boxes_for(self, method_name: str, args: list):
        """M8-specific convenience: `TrustedRootAnchor`'s ring/pin box
        names are a pure function of `block_number` (and the immutable
        `ring_n`), so tests do not have to hand-compute
        `h:<residue>`/`p:<block>` box references at every call site -- this
        mirrors what a real ARC-56-aware client library would derive
        automatically. 013 §6.4: `anchor_direct`/`anchor_historical` no
        longer add a `forks8` reference -- the fork table moved to global
        state, which costs no box-reference budget at all."""
        if self.ring_n is None or method_name not in self.methods:
            return None
        m = self.methods[method_name]
        arg_names = [a["name"] for a in m.get("args", [])]
        boxes = []
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
        """013 §0/§3/§5.4: `create()` creates no box at all any more (the
        fork table -- the only box `create()` ever created -- moved to
        global state, whose MBR the CREATOR pays at create time), so this
        is now a single, ordinary, unfunded `add_method_call(app_id=0,
        ...)` -- no probe-fund-create dance, no id prediction, no race, no
        retry loop.

        `fund_app` (µALGO) stays as a parameter (M8 still needs app-account
        funds for its `ring`/`pin` box families, untouched by 013) but is
        now a plain POST-create payment to the app's own, already-known,
        already-confirmed address -- there is nothing left to predict."""
        from algosdk import logic, transaction
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
        result = atc.execute(self.algod, 4)
        confirmed = self.algod.pending_transaction_info(result.tx_ids[0])
        self.app_id = confirmed["application-index"]

        if fund_app:
            address = logic.get_application_address(self.app_id)
            sp1 = self.algod.suggested_params()
            fund_txn = transaction.PaymentTxn(self.sender, sp1, address, fund_app)
            fund_txid = self.algod.send_transaction(fund_txn.sign(self.sk))
            transaction.wait_for_confirmation(self.algod, fund_txid, 4)

        return self.app_id

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
        top-level call's 700 budget."""
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer

        from tests.harness.deployment import donor_txn

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
