"""§7.1's simulate-predict-fund-create recipe -- THE fix for D1 (§2.3): the
repo's existing probe-fund-create recipe (`tests/sync_committee/conftest.py`,
`tests/state_anchor/conftest.py`) deploys a throwaway app and funds the FULL
lifecycle requirement before the real create, an unbounded exposure on any
public network. This module funds ONLY the real, protocol-reported
create-time MBR, learned from a `simulate` response, with NO throwaway app
and NO signer required for the prediction step itself (§17 item 5, item 16).

Recipe (measured end to end against real dev-mode algod, design doc §7.1):

    1. simulate the create txn, UNFUNDED, allow_empty_signatures=True.
       The response carries the id it would assign AND (if underfunded) the
       exact required min-balance in the failure message.
    2. fund `get_application_address(predicted_id)` with EXACTLY that amount
       (a real signed Payment -- this is the one step that needs a signer).
    3. send the real create; assert the assigned id == predicted_id.
    4. caller tops up to the full lifecycle requirement separately (§5.3
       step 5 / §9.4) -- safe now that the id is confirmed.

If the create needs no box MBR at all (M6/M7, §5.4: "NO pre-funding, NO id
prediction needed"), step 1's simulate simply succeeds outright and steps 2
are skipped -- there is no race to bound because there is nothing to fund
before the id is known.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from algosdk import logic, transaction
from algosdk.abi import Method
from algosdk.atomic_transaction_composer import (
    AccountTransactionSigner,
    AtomicTransactionComposer,
    EmptySigner,
)
from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup

_MIN_BALANCE_RE = re.compile(r"below min (\d+)")


class CreateRaced(RuntimeError):
    """§17 item 5: the assigned app id did not match the prediction. MUST
    NOT retry automatically -- the funding Payment already spent real ALGO
    on a predicted address that is now a stranger's application account
    (§10.4: unrecoverable). Bounded at 0.2329-0.3349 ALGO by construction
    (the funded amount is exactly the create-time MBR, never more)."""

    def __init__(self, predicted_id: int, actual_id: int, funded_microalgo: int):
        self.predicted_id = predicted_id
        self.actual_id = actual_id
        self.funded_microalgo = funded_microalgo
        super().__init__(
            f"app id prediction raced: funded {predicted_id}'s address with "
            f"{funded_microalgo} microalgo, but the real create assigned id "
            f"{actual_id} instead. Funding is NOT recoverable (§10.4) -- "
            "refusing to proceed with the wrongly-funded app."
        )


@dataclass
class SimulatedCreate:
    predicted_app_id: int
    required_microalgo: int  # 0 if the create needs no pre-funding at all
    ok_unfunded: bool  # True if the create would succeed with zero funding
    raw: dict


def _build_create_atc(algod_client, sender: str, signer, *, method: Method, method_args: list,
                       approval_bytes: bytes, clear_bytes: bytes, global_schema: transaction.StateSchema,
                       local_schema: transaction.StateSchema, extra_pages: int,
                       boxes: list[tuple[int, bytes]] | None, fee_microalgo: int) -> AtomicTransactionComposer:
    atc = AtomicTransactionComposer()
    sp = algod_client.suggested_params()
    sp.flat_fee = True
    sp.fee = fee_microalgo
    kwargs = {}
    if boxes:
        kwargs["boxes"] = boxes
    atc.add_method_call(
        app_id=0, method=method, sender=sender, sp=sp, signer=signer,
        method_args=method_args, on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval_bytes, clear_program=clear_bytes,
        global_schema=global_schema, local_schema=local_schema, extra_pages=extra_pages,
        **kwargs,
    )
    return atc


def simulate_create(algod_client, sender: str, *, method: Method, method_args: list,
                     approval_bytes: bytes, clear_bytes: bytes, global_schema: transaction.StateSchema,
                     local_schema: transaction.StateSchema, extra_pages: int = 0,
                     boxes: list[tuple[int, bytes]] | None = None) -> SimulatedCreate:
    """Step 1: no signer needed at all (§17 item 16) -- `EmptySigner` plus
    `allow_empty_signatures=True`."""
    atc = _build_create_atc(
        algod_client, sender, EmptySigner(), method=method, method_args=method_args,
        approval_bytes=approval_bytes, clear_bytes=clear_bytes, global_schema=global_schema,
        local_schema=local_schema, extra_pages=extra_pages, boxes=boxes, fee_microalgo=1000,
    )
    group = atc.build_group()
    stxns = [t.txn for t in group]  # unsigned; allow_empty_signatures carries them
    sreq = SimulateRequest(
        txn_groups=[SimulateRequestTransactionGroup(txns=[transaction.SignedTransaction(t, signature=b"")
                                                            for t in stxns])],
        allow_empty_signatures=True, allow_unnamed_resources=True,
    )
    resp = algod_client.simulate_transactions(sreq)
    grp = resp["txn-groups"][0]
    txres = grp["txn-results"][0].get("txn-result", {})
    predicted_id = txres.get("application-index")
    failure = grp.get("failure-message", "")
    if not failure:
        return SimulatedCreate(predicted_app_id=predicted_id, required_microalgo=0, ok_unfunded=True, raw=resp)
    m = _MIN_BALANCE_RE.search(failure)
    if not m:
        raise RuntimeError(f"simulate failed for a reason that is not an MBR shortfall: {failure!r}")
    required = int(m.group(1))
    if predicted_id is None:
        raise RuntimeError(f"simulate reported an MBR shortfall but no application-index: {failure!r}")
    return SimulatedCreate(predicted_app_id=predicted_id, required_microalgo=required, ok_unfunded=False, raw=resp)


def predict_fund_and_create(algod_client, sender: str, sk: str, *, method: Method, method_args: list,
                             approval_bytes: bytes, clear_bytes: bytes, global_schema: transaction.StateSchema,
                             local_schema: transaction.StateSchema, extra_pages: int = 0,
                             boxes: list[tuple[int, bytes]] | None = None) -> tuple[int, int]:
    """The full recipe. Returns `(app_id, funded_microalgo)`. Raises
    `CreateRaced` (never retries -- §17 item 5) if the assigned id does not
    match the prediction."""
    sim = simulate_create(
        algod_client, sender, method=method, method_args=method_args,
        approval_bytes=approval_bytes, clear_bytes=clear_bytes, global_schema=global_schema,
        local_schema=local_schema, extra_pages=extra_pages, boxes=boxes,
    )
    signer = AccountTransactionSigner(sk)
    # §7.1: fund `get_application_address(I0 + n)`, where `n` is the number
    # of REAL transactions submitted between the simulate and the real
    # create -- here always exactly 1 (the funding Payment itself, which
    # consumes a TxnCounter slot despite creating nothing). Confirmed this
    # pass (a first attempt that funded `I0` rather than `I0 + 1` failed
    # with this exact same "balance 0 below min" error against the
    # off-by-one address, reproducing the design doc's own footnote about
    # the conftest's historical `+2`/probe-vs-no-probe offset).
    predicted_id = sim.predicted_app_id + 1 if sim.required_microalgo > 0 else sim.predicted_app_id
    if sim.required_microalgo > 0:
        predicted_address = logic.get_application_address(predicted_id)
        sp = algod_client.suggested_params()
        sp.flat_fee = True
        sp.fee = 1000
        fund_txn = transaction.PaymentTxn(sender, sp, predicted_address, sim.required_microalgo)
        fund_stxn = fund_txn.sign(sk)
        fund_txid = algod_client.send_transaction(fund_stxn)
        transaction.wait_for_confirmation(algod_client, fund_txid, 4)

    atc = _build_create_atc(
        algod_client, sender, signer, method=method, method_args=method_args,
        approval_bytes=approval_bytes, clear_bytes=clear_bytes, global_schema=global_schema,
        local_schema=local_schema, extra_pages=extra_pages, boxes=boxes, fee_microalgo=1000,
    )
    result = atc.execute(algod_client, 4)
    confirmed = algod_client.pending_transaction_info(result.tx_ids[0])
    app_id = confirmed["application-index"]
    if sim.required_microalgo > 0 and app_id != predicted_id:
        raise CreateRaced(predicted_id, app_id, sim.required_microalgo)
    return app_id, sim.required_microalgo


def top_up(algod_client, sender: str, sk: str, app_id: int, target_microalgo: int) -> int:
    """§7.3/§9.4: tops up `app_id`'s account to (at least) `target_microalgo`,
    computed as a LEVEL (idempotent by construction, §7.5), never a fixed
    payment -- a second call with the same target sends 0. Returns the
    amount actually paid (0 if already at/above target)."""
    from algosdk import transaction as txn_mod

    addr = logic.get_application_address(app_id)
    current = algod_client.account_info(addr)["amount"]
    shortfall = target_microalgo - current
    if shortfall <= 0:
        return 0
    sp = algod_client.suggested_params()
    sp.flat_fee = True
    sp.fee = 1000
    pay = txn_mod.PaymentTxn(sender, sp, addr, shortfall)
    stxn = pay.sign(sk)
    txid = algod_client.send_transaction(stxn)
    txn_mod.wait_for_confirmation(algod_client, txid, 4)
    return shortfall
