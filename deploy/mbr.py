"""The MBR model (design doc §4, §10). Two formulas, both protocol constants
confirmed against real `account_info` responses in §4.1/§4.2/§10.2 of the
design doc and re-confirmed live by this pass (`tests/deploy/test_schema.py`
Suite X, `tests/deploy/test_deploy_live.py` Suite D's `D-8`/G5-M10):

    box MBR           = 2,500 + 400 * (len(name) + len(value))
    global-state MBR  = 100,000 + 28,500 * n_ints + 50,000 * n_bytes

Per §17 item 2/19: every number this module returns is a *formula* applied
to real, imported sizes -- nothing here is a retyped constant, and every
number this module has ever been used to justify in the implementation
report is cross-checked against a real `account_info`/`simulate` response
(see the implementation report / ROADMAP.md's M10 row).
"""
from __future__ import annotations

APP_ACCOUNT_BASE_MICROALGO = 100_000
GLOBAL_STATE_BASE_MICROALGO = 100_000
GLOBAL_STATE_PER_INT_MICROALGO = 28_500
GLOBAL_STATE_PER_BYTES_MICROALGO = 50_000

BOX_BASE_MICROALGO = 2_500
BOX_PER_BYTE_MICROALGO = 400


def box_mbr(name_bytes: int, value_bytes: int) -> int:
    """The real Algorand box-MBR formula, charged to the box's *app account*
    (never the creator/sender), §7's whole reason the two-stage funding
    recipe (`deploy.create`) exists."""
    return BOX_BASE_MICROALGO + BOX_PER_BYTE_MICROALGO * (name_bytes + value_bytes)


def global_state_mbr(n_ints: int, n_bytes: int) -> int:
    """The real Algorand creator-account global-state MBR formula (charged
    to the *creator*, not the app account -- §3.3 drift 3, §4.1/§4.2)."""
    return GLOBAL_STATE_BASE_MICROALGO + GLOBAL_STATE_PER_INT_MICROALGO * n_ints + GLOBAL_STATE_PER_BYTES_MICROALGO * n_bytes


def min_extra_pages(approval_bytes: int, clear_bytes: int) -> int:
    """§4.6/§17 item 6: `extra_pages` computed from the real compiled size,
    never a shipped constant. `ceil((approval+clear)/2048) - 1`, floored at 0
    (a program under 2,048 B combined needs no extra pages at all)."""
    import math

    pages = math.ceil((approval_bytes + clear_bytes) / 2048) - 1
    return max(pages, 0)
