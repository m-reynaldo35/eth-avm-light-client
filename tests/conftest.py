"""Root conftest (docs/design/011-test-harness-ci.md §6.1). The tier/
variance plugins are actually wired in via `pyproject.toml`'s
`addopts = "-p tests.harness.tiers -p tests.harness.variance"`, not here;
this file's job is narrower and more important: it RE-EXPORTS the shared
fixtures (`algod_available`, `kmd_available`, `beacon_available`,
`eth_rpc_available`, `account`) so no test package needs to import a
sibling's `conftest.py` by dotted path any more (§2.2's cross-package
`from tests.sync_committee.conftest import _algod_reachable` bug class).

Importing a `@pytest.fixture`-decorated function into this module's
namespace is enough for pytest to discover it as a fixture available to
every test under `tests/` -- the function object, not its file of origin,
is what pytest's fixture machinery keys on.
"""
from __future__ import annotations

import pytest

from tests.harness.chain import account  # noqa: F401
from tests.harness.env import (  # noqa: F401
    algod_available,
    beacon_available,
    eth_rpc_available,
    kmd_available,
)


@pytest.fixture()
def algod_client(algod_available):
    """A fixture-shaped wrapper around `tests.harness.chain.algod_client`
    (a plain factory function, used as such everywhere ELSE in the
    harness) -- some `tests/deploy/` files pre-date the harness and request
    `algod_client` as a fixture PARAMETER rather than calling the factory
    directly. This is plumbing, not a probe: no reachability logic of its
    own, so it does not re-introduce §2.2's duplication."""
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    from tests.harness.chain import algod_client as _factory

    return _factory()
