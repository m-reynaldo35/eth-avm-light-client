"""`algod_client`/`kmd_client`/`funded_account`/`account` -- one copy,
replacing 3 independent `funded_account()` definitions under `tests/`
(`tests/state_anchor/conftest.py`, `tests/deploy/test_deploy_live.py`,
`tests/deploy/test_security_matrix.py`) and fixing §3.3's 8 setup errors in
one place: `account` is now guarded by `algod_available` ONCE, here, rather
than being redefined per-file (some copies of which forgot the guard).
"""
from __future__ import annotations

import pytest

from tests.harness.env import ALGOD_ADDRESS, KMD_ADDRESS, TOKEN


def algod_client():
    from algosdk.v2client import algod as algod_mod

    return algod_mod.AlgodClient(TOKEN, ALGOD_ADDRESS)


def kmd_client():
    from algosdk import kmd as kmd_mod

    return kmd_mod.KMDClient(TOKEN, KMD_ADDRESS)


def funded_account(algod, kmd, min_balance: int = 200_000_000):
    """Returns `(address, private_key)` for whichever key in the dev-mode
    KMD default wallet currently holds the highest balance. `min_balance`
    is documentary only (dev-mode's default wallet always vastly exceeds
    it) -- kept as a parameter for call-site clarity, matching every prior
    copy of this helper."""
    wallets = kmd.list_wallets()
    wid = next(w["id"] for w in wallets if w["name"] == "unencrypted-default-wallet")
    handle = kmd.init_wallet_handle(wid, "")
    try:
        addrs = kmd.list_keys(handle)
        best, best_bal = None, -1
        for a in addrs:
            bal = algod.account_info(a)["amount"]
            if bal > best_bal:
                best, best_bal = a, bal
        sk = kmd.export_key(handle, "", best)
        return best, sk
    finally:
        kmd.release_wallet_handle(handle)


@pytest.fixture(scope="session")
def account(algod_available):
    """The §3.3 fix, made structural: a SINGLE shared `account` fixture,
    guarded by `algod_available` once, here -- no test package needs to
    redefine (and risk forgetting to guard) its own copy any more. Session
    scope: this is a signing keypair, not on-chain state a test mutates, so
    sharing it across every live test in the run is safe and mirrors the
    session scope `algod_available` already has."""
    if not algod_available:
        pytest.skip(
            f"no dev-mode algod reachable at {ALGOD_ADDRESS} -- see "
            "tests/fixtures/spike-reference/README.md"
        )
    algod = algod_client()
    kmd = kmd_client()
    return funded_account(algod, kmd)
