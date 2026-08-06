"""`PlannedTxn`/`GroupPlan` (design doc §7.6) -- building a plan is PURE, no
network, which is what makes the whole planner unit-testable offline
against pinned fixtures (`tests/relayer/test_plan_boxes.py`, Suite P,
`ci-offline.yml`). `GroupPlan.check()` is the single place every real cap
from §3's table is asserted, never warned (§18 item 2's spirit extended to
every cap, not just box refs).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from relayer.group.boxes import BOX_WRITE_BUDGET_BYTES_PER_REF, MAX_BOX_REFS_PER_TXN, MAX_TXNS_PER_GROUP
from relayer.group.budget import BudgetConvention, INNER_CALL_CEILING_PER_GROUP

# §3's table (real, measured values -- NOT the plan's stale "42-point MSM
# boundary" premise, corrected by 009 §3).
MAX_ARG_BYTES_PER_TXN = 2048
MAX_ARGS_PER_TXN = 16
MIN_FEE_MICROALGO = 1000


@dataclass(frozen=True)
class BoxRef:
    app_id: int  # 0 means "this/the target app"
    name: bytes


@dataclass(frozen=True)
class PlannedTxn:
    kind: Literal["app_call", "payment", "donor_issuer", "filler"]
    app_id: int
    args: list[bytes] | None = None  # raw-arg contracts (M5/M6/M7)
    method: str | None = None  # ARC-4 contracts (M4/M8)
    method_args: list | None = None
    box_refs: list[BoxRef] = field(default_factory=list)
    foreign_apps: list[int] = field(default_factory=list)
    fee: int = MIN_FEE_MICROALGO
    inner_call_count: int = 0  # this transaction's own contribution to the group's shared 256 ceiling
    produces_log: bool = False
    note: bytes = b""


@dataclass(frozen=True)
class GroupPlan:
    txns: list[PlannedTxn]
    result_index: int  # whose log carries the answer
    donor_count: int
    convention: BudgetConvention
    total_fee_microalgo: int
    prev_gi_refs: dict[int, int] = field(default_factory=dict)  # txn index -> the producing txn's real index it points at

    def check(self, *, max_group_txns: int = MAX_TXNS_PER_GROUP) -> None:
        """Asserts every real cap from §3's table. Raises (never warns) on
        the first violation, per §18 item 2/§7.6's own framing -- this is
        the ONE place every cap is enforced, and G7-M9 (§14) requires every
        negative case in Suite P's P-8 to be rejected here, before any
        network call."""
        n = len(self.txns)
        if n > max_group_txns:
            raise ValueError(f"group has {n} transactions, exceeding the {max_group_txns}-transaction cap")
        if n == 0:
            raise ValueError("an empty group is never valid")
        if not (0 <= self.result_index < n):
            raise ValueError(f"result_index {self.result_index} out of range for a {n}-transaction group")

        total_inner = 0
        distinct_box_bytes: dict[bytes, int] = {}
        for i, t in enumerate(self.txns):
            if len(t.box_refs) > MAX_BOX_REFS_PER_TXN:
                raise ValueError(
                    f"transaction {i} carries {len(t.box_refs)} box references, "
                    f"exceeding the {MAX_BOX_REFS_PER_TXN}-per-transaction cap"
                )
            if t.args is not None:
                arg_bytes = sum(len(a) for a in t.args)
                if arg_bytes > MAX_ARG_BYTES_PER_TXN:
                    raise ValueError(
                        f"transaction {i} carries {arg_bytes} bytes of app args, "
                        f"exceeding the {MAX_ARG_BYTES_PER_TXN}-byte cap"
                    )
                if len(t.args) > MAX_ARGS_PER_TXN:
                    raise ValueError(
                        f"transaction {i} carries {len(t.args)} app args, "
                        f"exceeding the {MAX_ARGS_PER_TXN}-argument cap"
                    )
            if t.fee < MIN_FEE_MICROALGO * (1 + t.inner_call_count):
                raise ValueError(
                    f"transaction {i}'s fee {t.fee} is below the minimum "
                    f"{MIN_FEE_MICROALGO * (1 + t.inner_call_count)} for {t.inner_call_count} inner call(s)"
                )
            total_inner += t.inner_call_count

        if total_inner > INNER_CALL_CEILING_PER_GROUP:
            raise ValueError(
                f"group's total inner-call count {total_inner} exceeds the shared "
                f"{INNER_CALL_CEILING_PER_GROUP}-per-group ceiling"
            )

        for i, gi in self.prev_gi_refs.items():
            if not (0 <= gi < i):
                raise ValueError(f"transaction {i}'s prev_gi={gi} does not point at an earlier, real transaction")
            if not self.txns[gi].produces_log:
                raise ValueError(f"transaction {i}'s prev_gi={gi} points at a transaction that produces no log")

        # Pooled box-write/read budget (§7.3/§7.4): every reference across
        # the whole group counts, including duplicate references to the
        # same box in the same or a sibling transaction.
        total_refs = sum(len(t.box_refs) for t in self.txns)
        # (distinct_box_bytes is intentionally unused for a hard assert
        # here -- §7.4's caveat (a): whether the write pool and the read
        # pool are truly one pool is not confirmed, Suite BX closes it by
        # measurement, not by this offline check. `plan_box_refs` is what
        # callers use BEFORE building a GroupPlan to size refs correctly;
        # `check()` only asserts the STRUCTURAL per-txn/per-group caps that
        # are true regardless of that open question.)
        del distinct_box_bytes, total_refs
