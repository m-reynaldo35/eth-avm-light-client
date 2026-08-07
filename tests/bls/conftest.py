"""Shared pytest infrastructure for the live (`algod`-backed) tier of the M1
BLS test suite (docs/design/001-bls-primitives.md §11). `algod_available` is
no longer defined here -- it is the single shared fixture re-exported from
`tests/conftest.py` (docs/design/011-test-harness-ci.md §6.3). `LiveHarness`
itself lives in `tests/bls/harness.py` (not here) so test files can import
it without a `from tests.*.conftest import ...` dotted import (§6.1/H-4).
"""

from __future__ import annotations

import pytest

from tests.bls.harness import LiveHarness


@pytest.fixture(scope="session")
def live_harness(algod_available):
    if not algod_available:
        pytest.skip(
            "no dev-mode algod reachable -- see tests/fixtures/spike-reference/README.md"
        )
    return LiveHarness()
