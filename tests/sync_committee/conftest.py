"""Shared pytest infrastructure for the live (`algod`-backed) tier of the M4
sync-committee test suite (docs/design/004-sync-committee.md §11).

Mirrors `tests/bls/conftest.py`'s pattern (compile-via-puyapy /
simulate-with-extra-budget), extended for `SyncCommitteeVerifier`'s two
differences from `BlsHarness`: (1) it is a real deployed ARC-4 contract with
a `create="require"` constructor that takes arguments, so the create
transaction itself must carry ABI-encoded args (`AtomicTransactionComposer`
handles this via `add_method_call(app_id=0, ...)`); (2) an install session's
boxes (§8.2) cost ~19.7 ALGO MBR per committee generation, so the app
account needs materially more funding than the BLS harness's 10 ALGO.

Tests marked to need `algod` are automatically skipped if no dev-mode algod
is reachable, matching `ARCHITECTURE.md`'s two-CI policy. Bring-up recipe:
`tests/fixtures/spike-reference/README.md`.
"""

from __future__ import annotations

import base64
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
VERIFIER_SRC = REPO_ROOT / "contracts" / "sync_committee" / "verifier.py"

SIM_EXTRA_BUDGET_CAP = 320_000
# 8 key boxes (6,144 B) + 1 session box (424 B) per generation, x2 (bootstrap
# opens gen 1; some tests open a second session) + the `forks` box (576 B) +
# headroom. Comfortably covers the ~19.7 ALGO/generation the design doc
# measures (§8.2) twice over.
APP_FUNDING_MICROALGO = 45_000_000


def _algod_reachable() -> bool:
    try:
        req = urllib.request.Request(
            ALGOD_ADDRESS + "/v2/status",
            headers={"X-Algo-API-Token": TOKEN},
        )
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


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
    `call_group` (simulate, for assert-fails-cleanly-without-committing
    checks) and `submit` (a real committed group, for state-machine setup
    steps that later calls must see)."""

    def __init__(self):
        from algosdk.v2client import algod as algod_mod
        from algosdk import kmd as kmd_mod

        self.algod = algod_mod.AlgodClient(TOKEN, ALGOD_ADDRESS)
        self.kmd = kmd_mod.KMDClient(TOKEN, KMD_ADDRESS)

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

        self.approval_compiled = self._compile(self.approval_teal)
        self.clear_compiled = self._compile(self.clear_teal)
        self.sender, self.sk = self._funded_account()
        self.app_id = None  # set by create()

    def _compile(self, src: str) -> bytes:
        req = urllib.request.Request(
            ALGOD_ADDRESS + "/v2/teal/compile",
            data=src.encode(),
            headers={"X-Algo-API-Token": TOKEN, "Content-Type": "text/plain"},
            method="POST",
        )
        with urllib.request.urlopen(req) as r:
            import json as _json

            body = _json.load(r)
        return base64.b64decode(body["result"])

    def _funded_account(self):
        wallets = self.kmd.list_wallets()
        wid = next(w["id"] for w in wallets if w["name"] == "unencrypted-default-wallet")
        handle = self.kmd.init_wallet_handle(wid, "")
        try:
            addrs = self.kmd.list_keys(handle)
            best, best_bal = None, -1
            for a in addrs:
                bal = self.algod.account_info(a)["amount"]
                if bal > best_bal:
                    best, best_bal = a, bal
            sk = self.kmd.export_key(handle, "", best)
            return best, sk
        finally:
            self.kmd.release_wallet_handle(handle)

    def create(self, governance_addr: str, genesis_validators_root: bytes) -> int:
        """Real, committed `create()` call -- the create txn's own app args
        carry the ABI-encoded constructor arguments (§7.3).

        `create()`'s body calls `forks.forks_box_create()` unconditionally
        (§4.3), and box MBR is charged against the APP's own account (unlike
        global-state MBR, which is charged to the creator) -- so the app
        account must already hold funds by the moment `create()` executes,
        before its address is knowable (Algorand assigns application IDs,
        and therefore addresses, only once a create txn is confirmed). We
        resolve this the same way any Algorand tool does: deploy a trivial
        throwaway app first (no boxes, so it needs no pre-funding) to learn
        the network's next-app-id counter, fund `predicted_id + 1`'s address
        in an ordinary preceding transaction, then submit the real create
        (which -- on a quiet, single-actor dev-mode network -- lands at
        exactly that predicted id).

        The predicted id is `probe_id + 2`, not `probe_id + 1`: Algorand's
        `TxnCounter` (block header `tc`, what `application-index` is
        actually assigned from) advances by one per CONFIRMED TRANSACTION OF
        ANY KIND, not merely per creation -- confirmed empirically while
        writing this harness (a plain `PaymentTxn` submitted between the
        probe and the real create shifts the real create's assigned id by
        one more than a naive "next creation" count would suggest). The
        probe-fund-create sequence is also wrapped in a bounded retry loop:
        even with the correct offset, this is a devnet potentially shared
        with other concurrent activity, and a raced attempt just wastes a
        little dev-mode ALGO and a probe app id -- not a correctness problem
        for the eventual deployed contract this harness tests.
        """
        from algosdk import transaction, logic
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
        )

        probe_teal = "#pragma version 10\nint 1\nreturn\n"
        probe_compiled = self._compile(probe_teal)

        last_error = None
        for _attempt in range(5):
            # -- throwaway probe app: learns the next app id, needs no funding --
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
            # +2, not +1: the funding PaymentTxn submitted next also consumes
            # one TxnCounter slot even though it creates nothing (see
            # docstring above).
            predicted_id = probe_confirmed["application-index"] + 2

            # -- fund the predicted address BEFORE the real create executes --
            predicted_address = logic.get_application_address(predicted_id)
            sp1 = self.algod.suggested_params()
            fund_txn = transaction.PaymentTxn(
                sender=self.sender, sp=sp1, receiver=predicted_address, amt=APP_FUNDING_MICROALGO
            )
            fund_stxn = fund_txn.sign(self.sk)
            fund_txid = self.algod.send_transaction(fund_stxn)
            transaction.wait_for_confirmation(self.algod, fund_txid, 4)

            # -- the real create() call, immediately after (minimize the race window) --
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
                # Funded the wrong address (a race consumed the predicted id
                # before we got there) -- retry from scratch.
                last_error = AssertionError(
                    f"app id prediction raced: predicted {predicted_id}, got {self.app_id}"
                )
                continue
            return self.app_id

        raise RuntimeError(f"create() failed after retries, last error: {last_error}")

    def submit(self, calls: list, *, boxes: list[tuple[int, bytes]] | None = None) -> list:
        """Real, COMMITTED atomic group of ABI method calls (state changes
        persist for later `submit`/`call`/`call_group` calls to see) --
        needed for multi-step state-machine setup (open a session, then
        separately probe a rejection against it). `calls` is a list of
        either `(method_name, args)` pairs (uses the shared `boxes` param
        below on every call) or `(method_name, args, per_call_boxes)`
        triples (overrides `boxes` for that one call only) -- the latter is
        what §16's split box-opening group needs, since
        `bootstrap`/`install_begin`, `install_open_session`, and any padding
        `noop_budget()` calls in the SAME group each carry a DIFFERENT
        `boxes` array (§16: the per-transaction box-reference cap means the
        9 real box names plus write-budget padding cannot all sit in one
        transaction's reference array). `boxes`/`per_call_boxes` are lists
        of `(app_id, box_name_bytes)` box references (app_id 0 means "this
        app")."""
        from algosdk import transaction
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
        """Simulate (non-committing) ABI calls, one atomic group -- used for
        assert-fails-cleanly checks where we do NOT want a doomed txn's
        (partial) effects to matter, and for budget measurement. `calls`
        entries are `(method_name, args)` or `(method_name, args,
        per_call_boxes)` triples, mirroring `submit`'s convention (§16:
        needed to isolate a real, protocol-enforced box-mechanics check --
        reference cap, pooled write/read budget, all still enforced under
        simulate -- from opcode-budget donation, a separate mechanism this
        harness's `extra_budget`/`extra_opcode_budget` substitutes for so a
        single simulated call can carry a budget-heavy op like `g1_bind`
        without needing the real inner-call donor chain §9 describes)."""
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


@pytest.fixture(scope="session")
def algod_available() -> bool:
    return _algod_reachable()


@pytest.fixture(scope="session")
def m4_live_harness(algod_available):
    if not algod_available:
        pytest.skip(
            "no dev-mode algod reachable at "
            f"{ALGOD_ADDRESS} -- see tests/fixtures/spike-reference/README.md"
        )
    return SyncCommitteeLiveHarness()
