"""Shared pytest infrastructure for the live (`algod`-backed) tier of the M4
sync-committee test suite (docs/design/011-test-harness-ci.md §6.3).
`algod_available` is no longer defined here -- it is the single shared
fixture re-exported from `tests/conftest.py`. `SyncCommitteeLiveHarness`
itself lives in `tests/sync_committee/harness.py` (not here) so test files
can import it without a `from tests.*.conftest import ...` dotted import
(§6.1/H-4); this file now only registers the one fixture that wraps it.
"""

from __future__ import annotations

import pytest

from tests.sync_committee.harness import SyncCommitteeLiveHarness


@pytest.fixture(scope="session")
def m4_live_harness(algod_available):
    if not algod_available:
        pytest.skip(
            "no dev-mode algod reachable -- see tests/fixtures/spike-reference/README.md"
        )
    return SyncCommitteeLiveHarness()
