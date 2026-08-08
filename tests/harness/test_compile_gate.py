"""Suite C (docs/design/011-test-harness-ci.md §13.5, §3.5, G3-M11) -- the
compile-and-artifact-diff gate. C-1..C-5 are offline (pinned `puyapy`
alone, no algod, no network); C-6 (bare-contract ASSEMBLED byte
length/sha256 via `/v2/teal/compile`) is `needs_algod`, defined in
`tests/deploy/test_deploy_live.py`-style live suites, not here (§3.5's own
honest asymmetry: puyapy emits no ARC-56 for a non-ARC4Contract, so its
assembled size can only be learned from algod).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from deploy.compile import BARE_CONTRACT_SOURCES, load_bare_contract_cache, puya_compile, sha256_hex
from tests.harness.compile_check import ARC56_TARGETS, ENTRY_POINTS, compile_all, diff_artifacts

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# C-1: all 10 contract entry points compile with the pinned puyapy.
# ---------------------------------------------------------------------------
def test_c1_all_ten_entry_points_compile():
    assert len(ENTRY_POINTS) == 10
    lines = compile_all()
    assert len(lines) == 10
    for src in ENTRY_POINTS:
        assert src.exists(), src


# ---------------------------------------------------------------------------
# C-2: the two ARC-56 artifacts reproduce byte-identically (whole JSON).
# ---------------------------------------------------------------------------
def test_c2_arc56_artifacts_reproduce_byte_identically():
    assert set(ARC56_TARGETS) == {
        REPO_ROOT / "contracts" / "sync_committee" / "verifier.py",
        REPO_ROOT / "contracts" / "state_anchor" / "anchor_app.py",
    }
    lines = diff_artifacts()
    assert any("SyncCommitteeVerifier" in line for line in lines)
    assert any("TrustedRootAnchor" in line for line in lines)


# ---------------------------------------------------------------------------
# C-3: the bare-contract TEAL sha256 (both approval and clear, every bare
# contract with a cached artifact -- "all four bare-contract TEAL hashes",
# §18 item 16) match `deploy/schema/_compiled/`.
#
# 012 §3.4/§15 gap 5: `BARE_CONTRACT_SOURCES` grew from 2 to 5 entries this
# pass (`MptSegmentApp`, `DonorIssuer`, `DonorCallee` added, and their
# compiled-artifact cache filled by running `refresh_bare_contract_cache`
# against a real, reachable algod) -- closing the "3 of 7 code_ids
# unfillable offline" gap `deploy/versions.json` used to have to record.
# ---------------------------------------------------------------------------
def test_c3_bare_contract_teal_hashes_match_cache():
    assert set(BARE_CONTRACT_SOURCES) == {
        "Mpt6ComposerApp", "Mpt7ReceiptApp", "MptSegmentApp", "DonorIssuer", "DonorCallee",
    }
    checked = 0
    for name, src in BARE_CONTRACT_SOURCES.items():
        contracts = puya_compile(src)
        entry = contracts[name]
        cache = load_bare_contract_cache(name)
        assert sha256_hex(entry["approval"].encode()) == cache["approval_teal_sha256"]
        assert sha256_hex(entry["clear"].encode()) == cache["clear_teal_sha256"]
        checked += 2
    assert checked == 10, "expected all ten bare-contract TEAL hashes (5 contracts x 2 programs)"


# ---------------------------------------------------------------------------
# C-4: `deploy schema --check` regenerates byte-identically (G3-M10, now
# actually wired into CI).
# ---------------------------------------------------------------------------
def test_c4_deploy_schema_check_passes():
    """MUST invoke `python -m deploy` (the package's real `__main__.py`,
    which calls `deploy.cli.main()`), NOT `python -m deploy.cli` -- a real
    bug found this pass: `deploy/cli.py` has no `if __name__ ==
    "__main__":` guard, so `-m deploy.cli` silently imports the module,
    calls nothing, and exits 0 without checking anything at all. The
    design doc's own §7.4 example workflow YAML had this exact typo."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "deploy", "schema", "--check"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "schema is up to date" in result.stdout, (
        f"expected the real 'schema is up to date' confirmation, got: {result.stdout!r} -- "
        f"an empty/silent success here is exactly the -m deploy.cli no-op bug"
    )


# ---------------------------------------------------------------------------
# C-5: a deliberately edited contract constant makes C-2/C-3 go red with a
# byte count and a hash, not a bare traceback.
# ---------------------------------------------------------------------------
def test_c5_a_drifted_arc56_artifact_fails_with_a_diff_not_a_traceback(tmp_path, monkeypatch):
    from tests.harness import compile_check

    real_target_src = REPO_ROOT / "contracts" / "sync_committee" / "verifier.py"
    fake_committed = tmp_path / "SyncCommitteeVerifier.arc56.json"
    fake_committed.write_text('{"byteCode": {"approval": "not-the-real-bytecode"}}')

    monkeypatch.setitem(
        compile_check.ARC56_TARGETS, real_target_src, ("SyncCommitteeVerifier", fake_committed)
    )
    with pytest.raises(AssertionError, match=r"drift.*fresh.*sha256"):
        compile_check.diff_artifacts()
