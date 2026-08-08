"""Suite V (design doc 012 §12.1): the versioning artifact, offline.
`deploy/versions.json` is generated, never hand-typed (§17 item 4) -- every
test here either regenerates it in memory and diffs, or asserts a specific
generated field against an independent source of truth.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from deploy.schema import generate

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# V-1 (G3-M12): byte-identical regeneration.
# ---------------------------------------------------------------------------
def test_v1_versions_json_check_is_clean():
    assert generate.check_versions() is True, (
        "deploy/versions.json drifted from a fresh regeneration -- run `python -m deploy schema`"
    )


def test_v1_versions_json_matches_generate_versions_byte_for_byte():
    assert generate.VERSIONS_PATH.exists(), "deploy/versions.json is missing -- run `python -m deploy schema`"
    assert generate.VERSIONS_PATH.read_text() == generate._dump(generate.generate_versions())


# ---------------------------------------------------------------------------
# V-2: every code_id equals the approval_sha256 in the corresponding
# schema/compiled-cache artifact.
# ---------------------------------------------------------------------------
def test_v2_code_ids_match_pinned_approval_hashes():
    versions = generate.generate_versions()
    schemas = generate.generate_all()
    for name in ("TrustedRootAnchor", "SyncCommitteeVerifier", "Mpt7ReceiptApp", "Mpt6ComposerApp"):
        assert versions["contracts"][name]["code_id"] == schemas[name]["program"]["approval_sha256"]

    for name in ("MptSegmentApp", "DonorIssuer", "DonorCallee"):
        cache = generate.load_bare_contract_cache(name)
        assert versions["contracts"][name]["code_id"] == cache["approval_sha256"]


# ---------------------------------------------------------------------------
# V-3: every contract marked fork_axis "none" contains no fork box name and
# no fork-table constant in its own SOURCE FILE (not its whole package
# directory -- DonorIssuer/DonorCallee share a directory with
# SyncCommitteeVerifier's own fork table, so the source file is the right
# granularity, not the subtree).
# ---------------------------------------------------------------------------
def test_v3_fork_axis_none_contracts_have_no_fork_constant_in_their_source():
    versions = generate.generate_versions()
    for name, entry in versions["contracts"].items():
        if entry.get("fork_axis") != "none":
            continue
        source = entry.get("source")
        assert source, f"{name}: fork_axis 'none' but no source recorded to check"
        text = (REPO_ROOT / source).read_text()
        for marker in ("FORKS_BOX_NAME", "FORK_TABLE_CAPACITY", "append_fork_row"):
            assert marker not in text, f"{name}'s source {source} claims fork_axis 'none' but contains {marker!r}"


# ---------------------------------------------------------------------------
# V-4: code_window.supported vs deploy/forks.py::FORK_FIELD_COUNTS.
# ---------------------------------------------------------------------------
def test_v4_supported_forks_match_forks_module():
    from deploy.forks import FORK_FIELD_COUNTS

    versions = generate.generate_versions()
    for name in ("TrustedRootAnchor", "SyncCommitteeVerifier"):
        supported = set(versions["contracts"][name]["code_window"]["supported"])
        assert supported == set(FORK_FIELD_COUNTS), f"{name}'s code_window.supported disagrees with FORK_FIELD_COUNTS"


# ---------------------------------------------------------------------------
# V-5: gloas is unsupported on both M4 and M8, each with a non-empty,
# section-citing reason.
# ---------------------------------------------------------------------------
def test_v5_gloas_unsupported_on_both_table_axis_contracts_with_a_cited_reason():
    versions = generate.generate_versions()
    for name in ("TrustedRootAnchor", "SyncCommitteeVerifier"):
        window = versions["contracts"][name]["code_window"]
        assert "gloas" in window["unsupported"]
        reason = window["reason"]
        assert reason, f"{name}: empty code_window.reason"
        assert re.search(r"§|O-M\d+-\d+", reason), f"{name}'s reason does not cite a real section: {reason!r}"


# ---------------------------------------------------------------------------
# V-6 / V-7: the client-side refusal, both ways (§3.7, §17 item 5).
# ---------------------------------------------------------------------------
def test_v6_deploy_refuses_to_append_a_fork_row_for_an_unsupported_fork():
    from deploy.plans.m4 import desired_fork_rows as m4_rows
    from deploy.plans.m8 import desired_fork_rows as m8_rows
    from deploy.versions_guard import UnsupportedForkError

    with pytest.raises(UnsupportedForkError, match="gloas"):
        m4_rows(["gloas"], {"gloas": 1})
    with pytest.raises(UnsupportedForkError, match="gloas"):
        m8_rows(["gloas"], {"gloas": 1})


def test_v6b_assert_fork_appendable_names_the_cited_reason():
    from deploy.versions_guard import UnsupportedForkError, assert_fork_appendable

    with pytest.raises(UnsupportedForkError) as exc_info:
        assert_fork_appendable("gloas", "TrustedRootAnchor")
    assert "2,048" in str(exc_info.value) or "§10.5" in str(exc_info.value)


def test_v7_the_same_call_for_a_supported_fork_succeeds():
    from deploy.plans.m4 import desired_fork_rows as m4_rows
    from deploy.plans.m8 import desired_fork_rows as m8_rows
    from deploy.versions_guard import assert_fork_appendable

    assert_fork_appendable("fulu", "TrustedRootAnchor")  # no raise
    assert_fork_appendable("fulu", "SyncCommitteeVerifier")  # no raise

    m4_out = m4_rows(["fulu"], {"fulu": 411392})
    assert len(m4_out) == 1
    m8_out = m8_rows(["fulu"], {"fulu": 411392})
    assert len(m8_out) == 1


# ---------------------------------------------------------------------------
# V-8: avm.version vs every *.schema.json's program.avm_version.
# ---------------------------------------------------------------------------
def test_v8_avm_version_matches_every_schema():
    versions = generate.generate_versions()
    schemas = generate.generate_all()
    assert versions["avm"]["version"] == 10
    for name, schema in schemas.items():
        assert schema["program"]["avm_version"] == versions["avm"]["version"]


# ---------------------------------------------------------------------------
# V-9: bytecode_cap_headroom_bytes vs 8192 - approval_bytes.
# ---------------------------------------------------------------------------
def test_v9_bytecode_cap_headroom_is_derived_not_typed():
    versions = generate.generate_versions()
    m4 = versions["contracts"]["SyncCommitteeVerifier"]
    assert m4["approval_bytes"] == 6980
    assert m4["bytecode_cap_headroom_bytes"] == 8192 - m4["approval_bytes"] == 1212


# ---------------------------------------------------------------------------
# The refusal is a real client-side guard, not vacuous -- confirm it is
# actually wired into both plan modules' desired_fork_rows (source-level
# check, so a future refactor that silently drops the call is caught even
# if no test happens to exercise every fork string).
# ---------------------------------------------------------------------------
def test_guard_is_wired_into_both_plan_modules_source():
    for path in (REPO_ROOT / "deploy" / "plans" / "m4.py", REPO_ROOT / "deploy" / "plans" / "m8.py"):
        text = path.read_text()
        assert "assert_fork_appendable" in text, f"{path} no longer calls the §3.7 client-side refusal"
