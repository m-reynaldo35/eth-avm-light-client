"""§5.6: the `DonorIssuer`/`DonorCallee` pair. §17 item 12 -- MUST reuse
`relayer.group.donors.deploy_donor_pair` verbatim, MUST NOT reimplement or
copy it. §11.7: reuse from the manifest if already deployed; recover by
program hash if the manifest is absent (this module's `find_existing`).
"""
from __future__ import annotations

from pathlib import Path

from relayer.group.donors import deploy_donor_pair, puya_compile_contracts

REPO_ROOT = Path(__file__).resolve().parents[2]


def ensure_donor_pair(algod_client, sender: str, sk: str, manifest) -> tuple[int, int]:
    """Returns `(callee_id, issuer_id)`. Reuses the manifest's recorded pair
    if present; otherwise deploys a fresh one via
    `relayer.group.donors.deploy_donor_pair` and records it."""
    callee = manifest.app_id("donor_callee")
    issuer = manifest.app_id("donor_issuer")
    if callee is not None and issuer is not None:
        return callee, issuer
    callee, issuer = deploy_donor_pair(algod_client, sender, sk, repo_root=REPO_ROOT)
    manifest.set_app("donor_callee", app_id=callee)
    manifest.set_app("donor_issuer", app_id=issuer)
    return callee, issuer


def pinned_hashes() -> dict[str, str]:
    """§7.4 recovery key: the donor pair's compiled program hashes, for
    `deploy recover`'s approval-hash scan (§11.7)."""
    import hashlib

    contracts = puya_compile_contracts(REPO_ROOT / "contracts" / "sync_committee" / "bench_app.py")
    # NOTE: this returns TEAL, not assembled bytecode -- callers that need
    # the real on-chain sha256 must compile through algod first (mirrors
    # `deploy.compile`'s own honest asymmetry for bare Contracts).
    return {name: hashlib.sha256(entry["approval"].encode()).hexdigest() for name, entry in contracts.items()}
