"""M7 tier classifier (design doc §6.3). v1 (§1.2) does not prove T3 -- it
classifies a receipt correctly and refuses cleanly, per 007 §8.2's "must
never swallow `R_INCOMPLETE`".

007 §8.2 / revision 3's ZK-B9 is explicit that a T3 *tier* is a pair
`(N, LOGMAX)`, not just a leaf-length bucket: `max(len(encoded log_i))`
matters as much as `leaf_len` (two real receipts, tx 73 and tx 6, sit
inside a tier's leaf bound and outside its log bound). Since v1 does not
prove T3 at all, `classify()` still records both dimensions on the result
so that adding T3 later is a change of verdict, not a change of interface.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Tier = Literal["T1", "T2", "T3_UNSUPPORTED"]

# 007 §3.1's ARG_BUDGET: the T1/T2 boundary a real leaf either fits under
# (as plain app args) or does not (needs box-staging, still AVM-representable).
T1_MAX_LEAF_BYTES = 1942
# The AVM box/value cap: above this, a leaf cannot be represented at all
# without T3/ZK.
T2_MAX_LEAF_BYTES = 4096


@dataclass(frozen=True)
class ClassificationResult:
    tier: Tier
    leaf_len: int
    max_log_len: int


def classify(leaf: bytes, logs: list[bytes] | None = None) -> ClassificationResult:
    leaf_len = len(leaf)
    max_log_len = max((len(x) for x in logs), default=0) if logs else 0
    if leaf_len <= T1_MAX_LEAF_BYTES:
        tier: Tier = "T1"
    elif leaf_len <= T2_MAX_LEAF_BYTES:
        tier = "T2"
    else:
        tier = "T3_UNSUPPORTED"
    return ClassificationResult(tier=tier, leaf_len=leaf_len, max_log_len=max_log_len)
