"""Suite T (docs/design/011-test-harness-ci.md §13.1) -- the tier mechanism
itself, offline. Real subprocess invocations of the repo's own pytest
configuration (not mocks) for the CLI-flag-shaped behaviors (T-1, T-3, T-6,
T-7), and direct in-process calls for the pure-function/socket-guard
behaviors (T-2, T-4, T-5, T-8) -- the harness's own correctness must not
depend on the thing it is deciding whether to run.
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TIERS_JSON = REPO_ROOT / "tests" / "harness" / "tiers.json"


def _run(*args, timeout=120, env=None, cwd=REPO_ROOT):
    full_env = None
    if env is not None:
        import os

        full_env = dict(os.environ)
        full_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "pytest", *args],
        cwd=cwd, capture_output=True, text=True, timeout=timeout, env=full_env,
    )


# ---------------------------------------------------------------------------
# T-1: collect with --offline; count equals tiers.json's totals.offline;
# >= 400 as an absolute floor (011 §4.3/§18 item 6).
# ---------------------------------------------------------------------------
def test_t1_offline_collect_count_matches_manifest_and_floor():
    result = _run("tests/", "--offline", "--collect-only", "-q")
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    # pytest's own summary line is either "N tests collected in Xs" (nothing
    # deselected) or "N/M tests collected (K deselected) in Xs" -- the
    # SELECTED count (what will actually run) is the FIRST number, M (the
    # pre-deselection total) is the second, when present.
    m = re.search(r"(\d+)(?:/\d+)? tests? collected", result.stdout)
    assert m, result.stdout
    collected = int(m.group(1))

    manifest = json.loads(TIERS_JSON.read_text())
    offline_total = manifest["totals"]["offline"]
    assert offline_total >= 400, f"offline total {offline_total} below the 400-test floor"
    assert collected == offline_total, (
        f"real --offline collection count ({collected}) does not match "
        f"tests/harness/tiers.json's totals.offline ({offline_total})"
    )


# ---------------------------------------------------------------------------
# T-2: every collected item carries exactly one tier classification -- the
# partition is total and disjoint.
# ---------------------------------------------------------------------------
def test_t2_tier_partition_is_total_and_disjoint(tmp_path):
    scratch = tmp_path / "tiers.json"
    result = _run(
        "tests/", "--collect-only", "-q", "--write-tier-manifest",
        env={"PYTEST_TIER_MANIFEST_PATH": str(scratch)},
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    manifest = json.loads(scratch.read_text())
    totals = manifest["totals"]
    assert totals["offline"] + totals["live"] + totals["live_heavy"] == totals["collected"], (
        f"partition is not total/disjoint: {totals}"
    )
    m = re.search(r"(\d+) tests? collected", result.stdout)
    assert m and int(m.group(1)) == totals["collected"]


# ---------------------------------------------------------------------------
# T-3: --check-tier-manifest against a deliberately edited manifest fails,
# and prints a per-file diff.
# ---------------------------------------------------------------------------
def test_t3_check_tier_manifest_fails_on_drift(tmp_path):
    scratch = tmp_path / "tiers.json"
    scratch.write_text(json.dumps({
        "generated_by": "pytest --write-tier-manifest",
        "totals": {"collected": 1, "offline": 1, "live": 0, "live_heavy": 0},
        "files": {"deliberately/wrong.py": {"offline": 1, "needs_algod": 0, "needs_network": 0}},
    }))
    result = _run(
        "tests/", "--collect-only", "-q", "--check-tier-manifest",
        env={"PYTEST_TIER_MANIFEST_PATH": str(scratch)},
    )
    assert result.returncode != 0
    assert "tier manifest drift" in (result.stdout + result.stderr)


# ---------------------------------------------------------------------------
# T-4 / T-5: the socket guard is installed under --offline and NOT under
# plain collection; its exception is a plain ConnectionRefusedError (an
# OSError), so every existing probe's `except (URLError, OSError)` degrades
# identically to a real refused connection (§4.2's load-bearing equivalence).
# ---------------------------------------------------------------------------
def test_t4_t5_socket_guard_installed_only_under_offline_and_raises_oserror():
    """Restores whatever guard state was ambient BEFORE this test (rather
    than assuming "not installed") -- this suite's own meta-tests run
    under the real `pytest tests/ --offline` invocation in CI (§7.4), where
    the guard genuinely IS already installed by the outer run itself; T-4/
    T-5's job is to confirm the guard's on/off TOGGLE and exception shape
    are correct, not to assume which state the ambient process started in."""
    from tests.harness import tiers as tiers_mod

    was_installed = tiers_mod._GUARD_INSTALLED
    try:
        tiers_mod._uninstall_socket_guard()
        assert socket.socket.connect is not tiers_mod._guarded_connect

        tiers_mod._install_socket_guard()
        assert socket.socket.connect is tiers_mod._guarded_connect
        with pytest.raises(ConnectionRefusedError) as excinfo:
            socket.socket().connect(("127.0.0.1", 80))
        assert isinstance(excinfo.value, OSError)  # T-5

        tiers_mod._uninstall_socket_guard()
        assert socket.socket.connect is not tiers_mod._guarded_connect
    finally:
        if was_installed:
            tiers_mod._install_socket_guard()
        else:
            tiers_mod._uninstall_socket_guard()


# ---------------------------------------------------------------------------
# T-6: a test that skips inside the --offline selection makes the RUN fail,
# naming the node id and the skip reason (§4.4, G5-M11).
# ---------------------------------------------------------------------------
def test_t6_a_skip_under_offline_fails_the_build(tmp_path):
    scratch_test = tmp_path / "test_forbidden_skip.py"
    scratch_test.write_text(textwrap.dedent("""
        import pytest

        def test_that_skips():
            pytest.skip("this must not be allowed to pass silently under --offline")
    """))
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(scratch_test), "-q", "--offline",
         "-p", "tests.harness.tiers", "--no-header"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode != 0, result.stdout + result.stderr
    combined = result.stdout + result.stderr
    assert "test_that_skips" in combined
    assert "FORBIDDEN SKIP" in combined


# ---------------------------------------------------------------------------
# T-7: a marker typo is a --strict-markers collection error, not a silently
# never-selected test.
# ---------------------------------------------------------------------------
def test_t7_marker_typo_is_a_collection_error(tmp_path):
    scratch_test = tmp_path / "test_marker_typo.py"
    scratch_test.write_text(textwrap.dedent("""
        import pytest

        @pytest.mark.needs_algoddd
        def test_whatever():
            assert True
    """))
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(scratch_test), "-q", "--strict-markers"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode != 0
    assert "not found in `markers`" in (result.stdout + result.stderr) or "needs_algoddd" in (result.stdout + result.stderr)


# ---------------------------------------------------------------------------
# T-8: plan_box_refs at 512/512 participation (empty absentee set) -- a
# zero-box plan, `forks` still referenced (§10 item 7, never exercised live).
# ---------------------------------------------------------------------------
def test_t8_plan_box_refs_at_full_participation_never_exercised_live():
    from relayer.group.boxes import m4_submit_update_box_sizes, plan_box_refs

    # complement mode with an empty absentee set (real 512/512 participation)
    sizes = m4_submit_update_box_sizes(1, set(), include_forks=True, include_total=True)
    plan = plan_box_refs(sizes)
    assert b"forks" in plan.distinct_boxes
    assert plan.refs_required >= 1  # forks + total, never a truly empty plan
    assert plan.txns_required == 1

    # direct mode with an empty participant set (0/512, the dual edge case)
    sizes_direct = m4_submit_update_box_sizes(1, set(), include_forks=True, include_total=False)
    plan_direct = plan_box_refs(sizes_direct)
    assert plan_direct.distinct_boxes == (b"forks",)
