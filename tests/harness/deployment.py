"""Thin wrappers over `deploy.compile`/`relayer.group.donors` (docs/design/
011-test-harness-ci.md §6.1/§6.2). Every real compile/deploy operation
already exists, live-proven, in `deploy/` or `relayer/`; this module
adapts their call signatures to what the test suite's pre-existing
call sites expect (mostly a `repo_root=` default), and does NOTHING else.

`tests/harness/` MUST NOT itself invoke `puyapy`, MUST NOT contain the
string `/v2/teal/compile`, and MUST NOT import `algopy` (§6.2, Suite H,
G7-M11) -- every function below is a re-export or a default-supplying
wrapper around an already-existing `deploy.*`/`relayer.*` function, never a
new implementation.
"""
from __future__ import annotations

from pathlib import Path

from deploy.compile import compile_teal_via_algod as compile_teal
from deploy.compile import patched_repo_copy
from deploy.compile import puya_compile as puya_compile
from relayer.group.donors import deploy_donor_pair as _deploy_donor_pair
from relayer.group.donors import donor_transaction_with_signer

REPO_ROOT = Path(__file__).resolve().parents[2]

__all__ = [
    "puya_compile",
    "compile_teal",
    "patched_repo_copy",
    "deploy_donor_pair",
    "donor_txn",
]


def deploy_donor_pair(algod_client, sender: str, sk: str) -> tuple[int, int]:
    """`relayer.group.donors.deploy_donor_pair` needs an explicit
    `repo_root=`; every test call site pre-dates that parameter and calls
    with 3 positional args, so this wrapper supplies the repo's own root
    (§6.3's promised "one-line re-export")."""
    return _deploy_donor_pair(algod_client, sender, sk, repo_root=REPO_ROOT)


def donor_txn(algod_client, sender: str, sk: str, issuer_id: int, callee_id: int, n: int, extra_boxes=None):
    return donor_transaction_with_signer(
        algod_client, sender, sk, issuer_id, callee_id, n, extra_boxes=extra_boxes
    )
