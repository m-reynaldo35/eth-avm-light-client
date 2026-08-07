"""Shared pytest infrastructure for M8's `algod`-backed test tiers
(docs/design/011-test-harness-ci.md §6.3). `algod_available`/`account` are
no longer defined here -- they are the single shared fixtures re-exported
from `tests/conftest.py` (`tests.harness.env`/`tests.harness.chain`), which
is the §3.3 fix made structural. `puya_compile`/`compile_teal`/
`patched_repo_copy`/`deploy_donor_pair` are one-line re-exports of
`deploy.compile.*`/`relayer.group.donors.*` via `tests.harness.deployment`.
`Arc4Harness` itself lives in `tests/state_anchor/harness.py` (not here) so
test files can import it without a `from tests.*.conftest import ...`
dotted import (§6.1/H-4).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.harness.deployment import deploy_donor_pair, puya_compile

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def anchor_src():
    return REPO_ROOT / "contracts" / "state_anchor" / "anchor_app.py"


@pytest.fixture(scope="module")
def bench_src():
    return REPO_ROOT / "contracts" / "state_anchor" / "bench_app.py"


@pytest.fixture(scope="module")
def compiled(algod_available, anchor_src, bench_src):
    """Shared across `test_core.py`/`test_forks.py` (both previously
    defined this identically) -- module scope means each test MODULE that
    requests it still gets its own instance, so per-file isolation is
    unaffected by hoisting the definition here."""
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    return puya_compile(anchor_src), puya_compile(bench_src)


@pytest.fixture(scope="module")
def donors(algod_available, account):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    from tests.harness.chain import algod_client

    sender, sk = account
    return deploy_donor_pair(algod_client(), sender, sk)
