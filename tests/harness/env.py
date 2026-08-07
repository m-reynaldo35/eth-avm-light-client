"""One copy of the network constants and the four availability probes
(docs/design/011-test-harness-ci.md §6.1) -- replaces 7 independent
`_algod_reachable()` definitions, 6 `_beacon_reachable()` definitions, and 9
hardcoded `ALGOD_ADDRESS = "http://localhost:4051"` literals measured across
`tests/` at design time (§2.2).

`ALGOD_ADDRESS`/`KMD_ADDRESS`/`TOKEN` are env-overridable (matching
`relayer.config.RelayerConfig.from_env`'s own `ALGOD_URL`/`ALGOD_TOKEN`
convention) so a contributor whose localnet differs from this repo's
`:4051`/`:4052` convention is not stuck -- but default to the values every
existing probe, fixture and CI workflow in this repo already assumes.
"""
from __future__ import annotations

import os
import urllib.error
import urllib.request

import pytest

ALGOD_ADDRESS = os.environ.get("ALGOD_URL", "http://localhost:4051")
KMD_ADDRESS = os.environ.get("KMD_URL", "http://localhost:4052")
TOKEN = os.environ.get("ALGOD_TOKEN", "a" * 64)


def _algod_reachable() -> bool:
    """§4.2's load-bearing equivalence: this MUST catch exactly
    `(urllib.error.URLError, OSError)` so that `--offline`'s socket guard
    (which raises a plain `ConnectionRefusedError`, an `OSError`) degrades
    identically to a real refused connection (T-5)."""
    try:
        req = urllib.request.Request(
            ALGOD_ADDRESS + "/v2/status",
            headers={"X-Algo-API-Token": TOKEN},
        )
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


def _kmd_reachable() -> bool:
    try:
        req = urllib.request.Request(
            KMD_ADDRESS + "/versions",
            headers={"X-KMD-API-Token": TOKEN},
        )
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


def _beacon_reachable() -> bool:
    from relayer.sources import beacon

    for base in beacon.BEACON_APIS:
        try:
            req = urllib.request.Request(
                base.rstrip("/") + "/eth/v1/beacon/light_client/finality_update",
                headers=beacon.HEADERS,
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:  # noqa: BLE001 -- an EndpointPool-style "try the next one"
            continue
    return False


def _eth_rpc_reachable() -> bool:
    try:
        from relayer.sources.eth_rpc import get_block_header

        get_block_header("latest")
        return True
    except Exception:  # noqa: BLE001
        return False


@pytest.fixture(scope="session")
def algod_available() -> bool:
    return _algod_reachable()


@pytest.fixture(scope="session")
def kmd_available() -> bool:
    return _kmd_reachable()


@pytest.fixture(scope="session")
def beacon_available() -> bool:
    return _beacon_reachable()


@pytest.fixture(scope="session")
def eth_rpc_available() -> bool:
    return _eth_rpc_reachable()
