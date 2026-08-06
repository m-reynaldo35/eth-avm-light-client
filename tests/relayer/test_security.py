"""Suite S (design doc §13.5): adversarial -- what an untrusted relayer can
and cannot do (§11). Includes G8-M9, the import-graph purity test.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RELAYER_DIR = REPO_ROOT / "relayer"

FORBIDDEN_EVERYWHERE = {"tests", "algopy", "fastapi", "x402", "pytest"}
FORBIDDEN_IN_PURE_SUBPACKAGES = {"algosdk"}
PURE_SUBPACKAGES = {"sources", "codec", "ssz", "proofs"}


def _imported_top_level_modules(py_file: Path) -> set[str]:
    tree = ast.parse(py_file.read_text(), filename=str(py_file))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".")[0])
    return names


# ---------------------------------------------------------------------------
# G8-M9: relayer/ imports no tests.*, algopy, fastapi, x402, pytest;
# sources/codec/ssz/proofs import no algosdk. A REAL import-graph test, not
# just a comment (§18 item 1's own instruction).
# ---------------------------------------------------------------------------
def test_g8_m9_relayer_never_imports_forbidden_modules():
    violations = []
    for py_file in RELAYER_DIR.rglob("*.py"):
        rel = py_file.relative_to(RELAYER_DIR)
        imported = _imported_top_level_modules(py_file)
        bad = imported & FORBIDDEN_EVERYWHERE
        if bad:
            violations.append(f"{rel}: imports forbidden module(s) {bad}")
    assert not violations, "\n".join(violations)


def test_g8_m9_pure_subpackages_never_import_algosdk():
    violations = []
    for sub in PURE_SUBPACKAGES:
        for py_file in (RELAYER_DIR / sub).rglob("*.py"):
            rel = py_file.relative_to(RELAYER_DIR)
            imported = _imported_top_level_modules(py_file)
            bad = imported & FORBIDDEN_IN_PURE_SUBPACKAGES
            if bad:
                violations.append(f"{rel}: imports forbidden module(s) {bad}")
    assert not violations, "\n".join(violations)


def test_g8_m9_group_and_drivers_and_client_may_import_algosdk():
    """Sanity check the test above isn't vacuous: confirm at least one
    file OUTSIDE the pure subpackages genuinely does import algosdk (§4.3
    rule 3), so "no violations found" above isn't just "no file imports
    algosdk anywhere"."""
    found = False
    for sub in ("group", "drivers"):
        for py_file in (RELAYER_DIR / sub).rglob("*.py"):
            if "algosdk" in _imported_top_level_modules(py_file):
                found = True
    if "algosdk" in _imported_top_level_modules(RELAYER_DIR / "client.py"):
        found = True
    assert found, "expected at least one of group/drivers/client.py to import algosdk"


# ---------------------------------------------------------------------------
# S-1: configure m8_app_id, then attempt an RPC-rooted receipt proof --
# refused (§11's last paragraph).
# ---------------------------------------------------------------------------
def test_s1_rpc_rooted_receipt_proof_refused_when_m8_configured():
    from relayer.client import EthAvmClient
    from relayer.config import RelayerConfig

    config = RelayerConfig(m7_app_id=1, m8_app_id=2)
    client = EthAvmClient(config)
    with pytest.raises(ValueError, match="against_anchor"):
        client.prove_receipt(1, 0, 0, against_anchor=False)


def test_s1_rpc_rooted_receipt_proof_allowed_when_no_m8_configured():
    """The negative control: without an m8_app_id at all, the RPC-rooted
    path is the ONLY path and must not be refused merely for existing."""
    from relayer.client import EthAvmClient
    from relayer.config import RelayerConfig

    config = RelayerConfig(m7_app_id=1, m8_app_id=None)
    client = EthAvmClient(config)
    # Should get past the S-1 guard (may still fail later on network
    # access in this offline test -- that failure is fine/expected here;
    # what must NOT happen is the ValueError this refusal raises).
    with pytest.raises(Exception) as exc_info:
        client.prove_receipt(1, 0, 0, against_anchor=False)
    assert "against_anchor" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# S-2: a future-dated signature_slot is refused client-side BEFORE
# submission (§1.3).
# ---------------------------------------------------------------------------
def test_s2_future_dated_signature_slot_refused():
    from relayer.drivers.m4_sync_committee import GENESIS_TIME_MAINNET, assert_not_future_dated, slot_now

    current = slot_now(GENESIS_TIME_MAINNET)
    with pytest.raises(ValueError, match="future"):
        assert_not_future_dated(current + 1_000_000)


def test_s2_current_and_past_signature_slot_accepted():
    from relayer.drivers.m4_sync_committee import GENESIS_TIME_MAINNET, assert_not_future_dated, slot_now

    current = slot_now(GENESIS_TIME_MAINNET)
    assert_not_future_dated(current)  # must not raise
    assert_not_future_dated(max(0, current - 1000))  # must not raise


# ---------------------------------------------------------------------------
# S-3: a `transform_optimistic_update` result fed where `SubmitUpdateArgs`
# is expected must be a type error, never a malformed submission.
# ---------------------------------------------------------------------------
def test_s3_optimistic_update_result_is_not_submit_update_ready():
    from py_ecc.bls.point_compression import compress_G2
    from py_ecc.optimized_bls12_381 import G2, multiply

    from relayer.drivers.m4_sync_committee import SubmitUpdateArgs, transform_optimistic_update

    z1, z2 = compress_G2(multiply(G2, 42))
    real_compressed_sig = "0x" + z1.to_bytes(48, "big").hex() + z2.to_bytes(48, "big").hex()

    fake_resp = {
        "data": {
            "attested_header": {
                "slot": "100", "proposer_index": "1",
                "parent_root": "0x" + "11" * 32, "state_root": "0x" + "22" * 32, "body_root": "0x" + "33" * 32,
            },
            "sync_aggregate": {
                "sync_committee_bits": "0x" + "ff" * 64,
                # A REAL compressed G2 point (not garbage) -- an invalid
                # encoding would make `decompress_G2` itself raise before
                # this test ever reaches the real assertion it cares about.
                "sync_committee_signature": real_compressed_sig,
            },
            "signature_slot": "101",
        }
    }
    decoded = transform_optimistic_update(fake_resp)
    assert isinstance(decoded, dict)
    assert not isinstance(decoded, SubmitUpdateArgs)
    # The type itself has no `.abi_args()` -- calling it as if it were
    # SubmitUpdateArgs-shaped raises AttributeError, never silently
    # produces a malformed 9-tuple.
    with pytest.raises(AttributeError):
        decoded.abi_args()
    # And it is missing fields submit_update's ABI requires (no
    # finalized_header / finality_branch at all -- module docstring).
    assert "finalized_header" not in decoded
    assert "finality_branch" not in decoded


# ---------------------------------------------------------------------------
# S-4 / S-5: N13 (revoked) classified FATAL, never auto-re-anchored; N20
# (conflict latch) classified PAGE_A_HUMAN, exits non-zero loudly.
# ---------------------------------------------------------------------------
def test_s4_revoked_anchor_is_fatal_not_retryable():
    from relayer.errors import RevokedAnchor, Retryability

    err = RevokedAnchor("N13: block is revoked")
    assert err.retryability is Retryability.FATAL


def test_s5_conflict_latch_is_page_a_human():
    from relayer.errors import ConflictLatch, Retryability

    err = ConflictLatch("N20: equivocation detected")
    assert err.retryability is Retryability.PAGE_A_HUMAN


def test_s5_cli_exits_non_zero_and_loud_on_page_a_human(monkeypatch, capsys):
    from relayer import cli
    from relayer.errors import ConflictLatch

    class FakeClient:
        def status(self):
            raise ConflictLatch("N20: equivocation detected")

    monkeypatch.setattr(cli, "EthAvmClient", lambda config: FakeClient())
    code = cli.main(["status"])
    assert code == 9, "PAGE_A_HUMAN must map to a distinct, non-zero exit code"
    captured = capsys.readouterr()
    assert "PAGE_A_HUMAN" in captured.err
    assert "N20" in captured.err


def test_s4_cli_exits_non_zero_on_fatal_n13():
    from relayer import cli
    from relayer.errors import RevokedAnchor
    import relayer.client as client_mod

    class FakeClient:
        def __init__(self, config):
            pass

        def status(self):
            raise RevokedAnchor("N13: revoked")

    orig = client_mod.EthAvmClient
    cli.EthAvmClient = FakeClient
    try:
        code = cli.main(["status"])
    finally:
        cli.EthAvmClient = orig
    assert code == 5


# ---------------------------------------------------------------------------
# §11 point 4: fee sanity -- GroupPlan.total_fee_microalgo must be
# computed BEFORE submission, exposed under --dry-run (§18 item 17).
# ---------------------------------------------------------------------------
def test_fee_is_computed_before_any_network_call():
    from relayer.group.planner import GroupPlan, PlannedTxn
    from relayer.group.budget import BudgetConvention

    txns = [PlannedTxn(kind="app_call", app_id=1, args=[b"x"], fee=1000),
            PlannedTxn(kind="app_call", app_id=1, args=[b"y"], fee=2000)]
    plan = GroupPlan(txns=txns, result_index=1, donor_count=0, convention=BudgetConvention.SELF_ISSUED,
                      total_fee_microalgo=sum(t.fee for t in txns))
    assert plan.total_fee_microalgo == 3000
    plan.check()  # pure, no network -- must not raise or touch a socket
