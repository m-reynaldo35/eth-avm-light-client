"""Markers, the `--offline` socket guard, `--live`, and the committed,
CI-diffed tier manifest (docs/design/011-test-harness-ci.md §4). Registered
from `pyproject.toml`'s `addopts` as `-p tests.harness.tiers`.

Two markers are applied automatically wherever the intent is already
expressed (§4.1): a test whose fixture closure contains `algod_available`
or `account` gets `needs_algod`; one whose closure contains
`beacon_available` or `eth_rpc_available` gets `needs_network`. Explicit
`@pytest.mark.needs_algod`/`needs_network` remain available for the
module-level `pytestmark`/`skipif`-at-import-time cases that have no
fixture to infer from (`tests/ssz/test_budget.py`,
`tests/deploy/test_deploy_live.py`, `tests/deploy/test_end_to_end.py`).
"""
from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
# `PYTEST_TIER_MANIFEST_PATH` lets test_tiers.py (T-1/T-3) exercise
# --write-tier-manifest/--check-tier-manifest against a scratch file instead
# of mutating the real committed manifest as a side effect of running the
# test suite that tests it.
TIERS_JSON = Path(os.environ.get("PYTEST_TIER_MANIFEST_PATH") or (Path(__file__).resolve().parent / "tiers.json"))

MARKER_DOCS = {
    "needs_algod": "requires a reachable dev-mode algod (ci-live.yml)",
    "needs_network": "requires reachable public Ethereum RPC and/or beacon API (ci-live.yml)",
    "live_heavy": ">1 GB of real beacon data and multi-GB RSS (ci-live.yml, weekly job)",
}

# §4.3/T-1: an absolute floor, independent of the committed manifest, so a
# manifest edited down to match a shrunken run cannot make a shrunken run
# pass.
MIN_OFFLINE_FLOOR = 400

_ALGOD_FIXTURES = {"algod_available", "account"}
_NETWORK_FIXTURES = {"beacon_available", "eth_rpc_available"}


# ---------------------------------------------------------------------------
# CLI options
# ---------------------------------------------------------------------------
def pytest_addoption(parser):
    group = parser.getgroup("tiers")
    group.addoption("--offline", action="store_true", default=False,
                     help="011 §4.2: deselect needs_algod/needs_network, install the "
                          "socket guard, forbid skips among what remains")
    group.addoption("--live", action="store_true", default=False,
                     help="011 §8.5: select everything except live_heavy")
    group.addoption("--write-tier-manifest", action="store_true", default=False,
                     help="(re)generate tests/harness/tiers.json from the current collection")
    group.addoption("--check-tier-manifest", action="store_true", default=False,
                     help="fail (with a diff) if tests/harness/tiers.json differs "
                          "from the current collection")


def pytest_configure(config):
    for name, doc in MARKER_DOCS.items():
        config.addinivalue_line("markers", f"{name}: {doc}")
    if config.getoption("--offline"):
        _install_socket_guard()


# ---------------------------------------------------------------------------
# §4.2: the socket guard. A plain ConnectionRefusedError (an OSError) so
# every existing probe's `except (URLError, OSError)`/`except Exception`
# degrades exactly as it would against a real refused connection (T-5) --
# the equivalence the §3.1 experiment measured.
# ---------------------------------------------------------------------------
_REAL_CONNECT = socket.socket.connect
_GUARD_INSTALLED = False


def _guarded_connect(self, address):  # noqa: ARG001
    raise ConnectionRefusedError("blocked by --offline")


def _install_socket_guard():
    global _GUARD_INSTALLED
    if not _GUARD_INSTALLED:
        socket.socket.connect = _guarded_connect
        _GUARD_INSTALLED = True


def _uninstall_socket_guard():
    global _GUARD_INSTALLED
    if _GUARD_INSTALLED:
        socket.socket.connect = _REAL_CONNECT
        _GUARD_INSTALLED = False


# ---------------------------------------------------------------------------
# §4.1: automatic marking from the fixture closure.
# ---------------------------------------------------------------------------
def pytest_collection_modifyitems(config, items):
    for item in items:
        fixtures = set(getattr(item, "fixturenames", None) or ())
        if fixtures & _ALGOD_FIXTURES:
            item.add_marker(pytest.mark.needs_algod)
        if fixtures & _NETWORK_FIXTURES:
            item.add_marker(pytest.mark.needs_network)

    write_manifest = config.getoption("--write-tier-manifest")
    check_manifest = config.getoption("--check-tier-manifest")
    if write_manifest or check_manifest:
        manifest = build_manifest(items)
        if write_manifest:
            TIERS_JSON.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        if check_manifest:
            _check_manifest(manifest)

    if config.getoption("--offline"):
        _apply_offline_selection(config, items)
    elif config.getoption("--live"):
        _apply_live_selection(config, items)


def _apply_offline_selection(config, items):
    """§4.2's deselection. The §4.3/T-1 absolute-floor check lives in
    `_check_manifest` (below), gated on `--check-tier-manifest` -- the real
    `ci-offline.yml` invocation always passes both flags together (§7.4),
    and gating the floor there (rather than unconditionally here) is what
    lets `tests/harness/test_tiers.py`'s own meta-tests (T-6, T-7) exercise
    `--offline` in isolation against a tiny synthetic file without tripping
    a floor meant to catch a shrunken REAL run."""
    selected, deselected = [], []
    for item in items:
        marks = {m.name for m in item.iter_markers()}
        if "needs_algod" in marks or "needs_network" in marks or "live_heavy" in marks:
            deselected.append(item)
        else:
            selected.append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
    items[:] = selected


def _apply_live_selection(config, items):
    """§8.5: `--live` selects everything except `live_heavy` (the nightly
    `live` job's own scope). The `live-heavy` job runs the SAME `--live`
    flag PLUS `-m live_heavy` (§8.5's real workflow YAML) to select ONLY
    the heavy tier -- so this must not blanket-deselect `live_heavy` when
    the caller has explicitly asked for it via `-m`; pytest's own `-k`/`-m`
    keyword/mark filtering already runs as a separate, later hook and would
    otherwise be fighting this deselection to a permanent 0-item result."""
    from tests.harness.quarantine import quarantined_nodeids

    markexpr = (config.option.markexpr or "").strip()
    caller_wants_live_heavy = "live_heavy" in markexpr

    quarantined = quarantined_nodeids()
    selected, deselected = [], []
    for item in items:
        marks = {m.name for m in item.iter_markers()}
        if "live_heavy" in marks and not caller_wants_live_heavy:
            deselected.append(item)
        elif item.nodeid in quarantined:
            item.add_marker(pytest.mark.skip(reason=f"quarantined (tests/harness/quarantine.toml): {item.nodeid}"))
            selected.append(item)
        else:
            selected.append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
    items[:] = selected


# ---------------------------------------------------------------------------
# §4.3: the manifest itself.
# ---------------------------------------------------------------------------
def _relpath(item) -> str:
    return str(Path(item.location[0]).as_posix())


def build_manifest(items) -> dict:
    files: dict[str, dict] = {}
    totals = {"collected": 0, "offline": 0, "live": 0, "live_heavy": 0}
    for item in items:
        totals["collected"] += 1
        path = _relpath(item)
        marks = {m.name for m in item.iter_markers()}
        rec = files.setdefault(path, {"offline": 0, "needs_algod": 0, "needs_network": 0})
        if "live_heavy" in marks:
            rec["live_heavy"] = rec.get("live_heavy", 0) + 1
            totals["live_heavy"] += 1
            continue
        needs_algod = "needs_algod" in marks
        needs_network = "needs_network" in marks
        if needs_algod or needs_network:
            if needs_algod:
                rec["needs_algod"] += 1
            if needs_network:
                rec["needs_network"] += 1
            totals["live"] += 1
        else:
            rec["offline"] += 1
            totals["offline"] += 1
    return {"generated_by": "pytest --write-tier-manifest", "totals": totals, "files": files}


def _diff_manifests(committed: dict, fresh: dict) -> str:
    lines = []
    if committed.get("totals") != fresh.get("totals"):
        lines.append(f"totals: committed={committed.get('totals')} fresh={fresh.get('totals')}")
    c_files = committed.get("files", {})
    f_files = fresh.get("files", {})
    for path in sorted(set(c_files) | set(f_files)):
        if c_files.get(path) != f_files.get(path):
            lines.append(f"{path}: committed={c_files.get(path)} fresh={f_files.get(path)}")
    return "\n".join(lines) if lines else "(no diff found, but top-level dicts compared unequal)"


def _check_manifest(fresh: dict) -> None:
    if not TIERS_JSON.exists():
        pytest.exit(f"--check-tier-manifest: {TIERS_JSON} does not exist", returncode=1)
    committed = json.loads(TIERS_JSON.read_text())
    if committed != fresh:
        diff = _diff_manifests(committed, fresh)
        pytest.exit(f"tier manifest drift ({TIERS_JSON}):\n{diff}", returncode=1)
    if fresh["totals"]["offline"] < MIN_OFFLINE_FLOOR:
        pytest.exit(
            f"tier manifest's own offline total ({fresh['totals']['offline']}) is below the "
            f"{MIN_OFFLINE_FLOOR}-test absolute floor (011 §4.3/T-1)",
            returncode=1,
        )


# ---------------------------------------------------------------------------
# §4.4: no silent skips under --offline. Any skip among what --offline
# selected is a failure -- every remaining skip mechanism in the offline
# tier guards a COMMITTED resource (a fixture file, a declared dependency),
# so a skip there means a genuine packaging/fixture regression, not a
# legitimate tier boundary (§4.4).
# ---------------------------------------------------------------------------
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    if not item.config.getoption("--offline"):
        return
    report = outcome.get_result()
    if report.skipped:
        original = report.longrepr
        report.outcome = "failed"
        report.longrepr = (
            f"FORBIDDEN SKIP under --offline (011 §4.4): a skip is not a pass. "
            f"Original skip reason: {original}"
        )
