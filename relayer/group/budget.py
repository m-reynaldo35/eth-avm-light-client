"""Donor sizing (design doc §7.1-§7.2) -- the identical procedure M5 §16.3,
M6 §7.6 and 008 §9.4/§15.3 each independently implemented; here, once.

§18 item 4 (normative): size donors by `simulate` with `n_donors=1`, read
the REAL consumed figure, then verify with a real `send_transactions` --
never conclude from `simulate` alone (M5 §16.3 records a segment that
simulated fine and failed outright with `dynamic cost budget exceeded` on
real submission). And: NEVER read `app-budget-added` -- under
`extra-opcode-budget` each app call is credited 320,700 and the field
reports a number reflecting that credit, not real consumption (004 §2.4).
Consumed-side differencing is the only honest read.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from math import ceil

# 004 §2.4: measured net yield per DonorIssuer inner call (issuing 18,
# +700 pooled -> net +682).
DONOR_NET_YIELD_PER_CALL = 682
BASE_BUDGET_PER_APP_CALL = 700
DEFAULT_MARGIN = 4  # matches test_live_historical.py:719's real formula
INNER_CALL_CEILING_PER_GROUP = 256  # shared, global to the group (§7.2)


class BudgetConvention(Enum):
    """§7.1: exactly two values, both live-proven, no third. The planner
    reads the driver's convention and does the right thing; no caller ever
    branches on it."""

    SELF_ISSUED = auto()  # M5, M6: planner writes donor_count/donor_app_id into raw args
    DONOR_SIBLING = auto()  # M4, M7, M8: planner prepends a DonorIssuer transaction


@dataclass(frozen=True)
class DonorSizing:
    n_donors: int
    base_budget: int
    measured_consumed: int
    margin: int


def size_donors(measured_consumed: int, *, n_app_calls_in_group: int, margin: int = DEFAULT_MARGIN) -> DonorSizing:
    """Step 3 of §7.2's procedure:

        n_donors = ceil((consumed - base) / 682) + margin
        base     = 700 * (number of application calls already in the group)

    `measured_consumed` MUST come from a real simulate response's
    `app-budget-consumed` field with `n_donors=1` already in the group
    (§18 item 4) -- never `app-budget-added`."""
    base = BASE_BUDGET_PER_APP_CALL * n_app_calls_in_group
    needed = max(0, measured_consumed - base)
    n_donors = max(margin, ceil(needed / DONOR_NET_YIELD_PER_CALL) + margin)
    return DonorSizing(n_donors=n_donors, base_budget=base, measured_consumed=measured_consumed, margin=margin)


def assert_inner_call_budget_ok(n_donors: int, *, other_inner_calls: int = 0,
                                 ceiling: int = INNER_CALL_CEILING_PER_GROUP) -> None:
    """§7.2: "the inner-call ceiling is shared and is 256 per group." A
    150-donor `submit_update` group has 106 inner slots left, not 256 --
    this must be tracked, since it is the one budget cap that is global to
    the GROUP rather than per-transaction."""
    total = n_donors + other_inner_calls
    if total > ceiling:
        raise ValueError(
            f"{n_donors} donor inner call(s) + {other_inner_calls} other inner call(s) = {total} "
            f"exceeds the shared {ceiling}-inner-call-per-group ceiling"
        )
