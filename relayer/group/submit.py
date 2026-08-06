"""The one submission loop for every driver (design doc §7.7):

    plan -> simulate(n_donors=1) -> size (§7.2) -> re-plan -> simulate (assert clean)
         -> send_transactions -> wait_for_confirmation -> parse logs -> typed result

`--dry-run` (§8.4, §18 item 16) stops after the second simulate -- this
module must work with `signer=None` up to and including that point (§18
item 16), which is why `dry_run` is a first-class parameter here rather
than something only the CLI understands.

§18 item 6 (normative): `allow_unnamed_resources` is deliberately NEVER
passed on the real (non-simulate) submission path -- it papers over
exactly the box-reference planning `relayer.group.boxes` exists to get
right, and a group that only works with it will fail against a node that
does not permit it. It IS acceptable on the FIRST (sizing) simulate, since
that call's only purpose is measuring a real consumed-budget number, not
proving the plan works unaided.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup

from relayer.group.budget import size_donors

SIM_EXTRA_BUDGET = 320_000


@dataclass(frozen=True)
class SubmitResult:
    dry_run: bool
    n_donors: int
    measured_consumed: int
    confirmed_round: int | None
    tx_ids: list[str]
    logs: list[bytes]
    simulate_response: dict


def simulate_group(algod_client, atc, *, extra_budget: int = SIM_EXTRA_BUDGET,
                    allow_unnamed_resources: bool = True) -> dict:
    group = atc.build_group()
    stxns = [t.signer.sign_transactions([t.txn], [0])[0] for t in group]
    sreq = SimulateRequest(
        txn_groups=[SimulateRequestTransactionGroup(txns=stxns)],
        extra_opcode_budget=extra_budget,
        allow_unnamed_resources=allow_unnamed_resources,
    )
    return algod_client.simulate_transactions(sreq)


def run(
    algod_client,
    build_group: Callable[[int], "object"],
    *,
    n_app_calls_in_group: int,
    dry_run: bool,
    margin: int = 4,
    confirm_rounds: int = 6,
) -> SubmitResult:
    """`build_group(n_donors)` returns a fresh, unsigned/unsent
    `AtomicTransactionComposer` (or equivalent with `.build_group()`/
    `.execute()`) for the given donor count -- the caller (a driver) owns
    the ABI-specific construction; this function owns the generic
    simulate-size-simulate-send loop (§7.7), identically for every driver.

    §18 item 4: `n_donors=1` for the FIRST simulate, real consumed figure
    read, THEN a real send -- simulate alone is never trusted for the
    final count."""
    probe_atc = build_group(1)
    probe_resp = simulate_group(algod_client, probe_atc, allow_unnamed_resources=True)
    probe_group = probe_resp["txn-groups"][0]
    if probe_group.get("failure-message"):
        raise RuntimeError(f"sizing simulate failed (a logic bug, not a budget one): {probe_group['failure-message']}")
    consumed = probe_group.get("app-budget-consumed", 0)  # NEVER app-budget-added (§18 item 4)

    sizing = size_donors(consumed, n_app_calls_in_group=n_app_calls_in_group, margin=margin)

    sized_atc = build_group(sizing.n_donors)
    confirm_resp = simulate_group(algod_client, sized_atc, allow_unnamed_resources=True)
    confirm_group = confirm_resp["txn-groups"][0]
    if confirm_group.get("failure-message"):
        raise RuntimeError(
            f"sized simulate still failed with n_donors={sizing.n_donors}: {confirm_group['failure-message']}"
        )

    if dry_run:
        return SubmitResult(
            dry_run=True, n_donors=sizing.n_donors, measured_consumed=consumed,
            confirmed_round=None, tx_ids=[], logs=[], simulate_response=confirm_resp,
        )

    # Real send -- §18 item 6: no allow_unnamed_resources on this path.
    real_atc = build_group(sizing.n_donors)
    result = real_atc.execute(algod_client, confirm_rounds)
    info = algod_client.pending_transaction_info(result.tx_ids[-1])
    import base64

    logs = [base64.b64decode(x) if isinstance(x, str) else x for x in info.get("logs", [])]
    return SubmitResult(
        dry_run=False, n_donors=sizing.n_donors, measured_consumed=consumed,
        confirmed_round=info.get("confirmed-round"), tx_ids=list(result.tx_ids),
        logs=logs, simulate_response=confirm_resp,
    )
