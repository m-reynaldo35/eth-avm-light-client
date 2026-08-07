"""Suite Q (docs/design/011-test-harness-ci.md §13.3) -- quarantine and the
flake-vs-regression variance policy, offline. The single most important
negative in this suite is Q-8: a real algod box-budget-exceeded string must
NEVER be retried -- that is the exact failure mode §5 exists to stop being
treated as background noise.
"""
from __future__ import annotations

import datetime as _dt
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests.harness.quarantine import QuarantineError, load_quarantine
from tests.harness.variance import _is_retryable

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Q-1/Q-2/Q-3: the real committed quarantine.toml is well-formed, every
# nodeid resolves against the real collection, and no entry has expired.
# ---------------------------------------------------------------------------
def test_q1_committed_quarantine_is_well_formed_and_resolves():
    entries = load_quarantine()
    for entry in entries:
        for field in ("nodeid", "reason", "opened", "expires", "owner"):
            assert entry.get(field), f"{entry.get('nodeid')}: missing {field}"
        path_part = entry["nodeid"].split("::", 1)[0]
        assert (REPO_ROOT / path_part).exists(), (
            f"quarantine entry {entry['nodeid']!r}: {path_part} does not exist -- "
            f"a quarantine entry for a test that no longer exists is a failure, not a no-op"
        )


def test_q2_expired_entry_fails_at_load(tmp_path):
    toml_path = tmp_path / "quarantine.toml"
    toml_path.write_text(textwrap.dedent("""
        [[test]]
        nodeid = "tests/does/not/matter.py::test_x"
        reason = "synthetic, for Q-2"
        opened = "2020-01-01"
        expires = "2020-02-01"
        owner = "test"
    """))
    with pytest.raises(QuarantineError, match="EXPIRED"):
        load_quarantine(toml_path, today=_dt.date(2026, 8, 7))


def test_q3_expires_more_than_90_days_after_opened_rejected(tmp_path):
    toml_path = tmp_path / "quarantine.toml"
    toml_path.write_text(textwrap.dedent("""
        [[test]]
        nodeid = "tests/does/not/matter.py::test_x"
        reason = "synthetic, for Q-3"
        opened = "2026-01-01"
        expires = "2026-06-01"
        owner = "test"
    """))
    with pytest.raises(QuarantineError, match="90 days"):
        load_quarantine(toml_path, today=_dt.date(2026, 1, 2))


def test_q1_missing_field_is_a_failure(tmp_path):
    toml_path = tmp_path / "quarantine.toml"
    toml_path.write_text(textwrap.dedent("""
        [[test]]
        nodeid = "tests/does/not/matter.py::test_x"
        reason = "synthetic, missing fields"
    """))
    with pytest.raises(QuarantineError, match="missing field"):
        load_quarantine(toml_path)


# ---------------------------------------------------------------------------
# Q-4: live_variance without reason= is a collection error.
# ---------------------------------------------------------------------------
def test_q4_live_variance_without_reason_is_a_collection_error(tmp_path):
    scratch = tmp_path / "test_q4.py"
    scratch.write_text(textwrap.dedent("""
        import pytest

        @pytest.mark.live_variance(max_attempts=2)
        def test_needs_a_reason():
            assert True
    """))
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(scratch), "-q", "-p", "tests.harness.variance"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode != 0
    assert "requires reason=" in (result.stdout + result.stderr)


# ---------------------------------------------------------------------------
# Q-5/Q-7/Q-8: NEVER retried, regardless of marker, because the exception
# chain does not contain a retryable RelayerError.
# ---------------------------------------------------------------------------
def test_q5_bare_assertion_error_is_not_retryable():
    assert _is_retryable(AssertionError("box read budget (18432) exceeded")) is False


def test_q7_fatal_and_page_a_human_are_not_retryable():
    from relayer.errors import ConflictLatch, RevokedAnchor

    assert _is_retryable(RevokedAnchor("N13")) is False
    assert _is_retryable(ConflictLatch("N20")) is False


def test_q8_box_budget_exceeded_string_is_never_retried():
    """The single most important negative in this suite (§5.4): a REAL
    algod box-budget rejection must never be retried, no matter how it is
    wrapped, because a retry decorator on this exact failure mode is what
    masked a genuine structural defect for this project's entire history
    before M11 (six committee cycles, four different observed byte counts)."""
    exc = RuntimeError("TransactionPool.Remember: transaction ABCD: box read budget (18432) exceeded")
    assert _is_retryable(exc) is False
    # even wrapped inside another exception's __cause__/__context__ chain
    try:
        try:
            raise exc
        except RuntimeError as inner:
            raise AssertionError("submit_update group did not commit") from inner
    except AssertionError as wrapped:
        assert _is_retryable(wrapped) is False


def test_q_other_non_relayer_exceptions_are_not_retryable():
    assert _is_retryable(ValueError("logic eval error")) is False
    assert _is_retryable(None) is False


# ---------------------------------------------------------------------------
# Q-6: a RETRY_NOW-tagged RelayerError IS retried, and the retry is
# reported even though it eventually passed (never a silent green).
# ---------------------------------------------------------------------------
def test_q6_pool_exhausted_is_retryable():
    from relayer.errors import PoolExhaustedError

    assert _is_retryable(PoolExhaustedError("endpoint 503")) is True


def test_q6_retry_replanned_is_retryable():
    from relayer.errors import RetryReplanned

    assert _is_retryable(RetryReplanned("fin_slot advanced")) is True


def test_q6_retry_actually_happens_and_is_reported(tmp_path):
    scratch = tmp_path / "test_q6_live.py"
    scratch.write_text(textwrap.dedent("""
        import pytest
        from relayer.errors import PoolExhaustedError

        ATTEMPTS = []

        @pytest.mark.live_variance(reason="synthetic Q-6 check", max_attempts=2)
        def test_flaky_then_passes():
            ATTEMPTS.append(1)
            if len(ATTEMPTS) < 2:
                raise PoolExhaustedError("synthetic transient endpoint failure")
            assert True
    """))
    junit = tmp_path / "q6.xml"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(scratch), "-q",
         "-p", "tests.harness.variance", f"--junitxml={junit}"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert junit.exists()
    xml_text = junit.read_text()
    assert "live_variance_attempts" in xml_text


# ---------------------------------------------------------------------------
# Q-9: max_attempts is capped at 3 by the plugin, regardless of what a test
# asks for.
# ---------------------------------------------------------------------------
def test_q9_max_attempts_capped_at_3(tmp_path):
    scratch = tmp_path / "test_q9.py"
    scratch.write_text(textwrap.dedent("""
        import pytest
        from relayer.errors import PoolExhaustedError

        ATTEMPTS = []

        @pytest.mark.live_variance(reason="synthetic Q-9 check", max_attempts=9)
        def test_always_retryable_failure():
            ATTEMPTS.append(1)
            raise PoolExhaustedError("synthetic, always fails")
    """))
    junit = tmp_path / "q9.xml"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(scratch), "-q",
         "-p", "tests.harness.variance", f"--junitxml={junit}"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode != 0
    xml_text = junit.read_text()
    assert 'name="live_variance_attempts" value="3"' in xml_text, xml_text


# ---------------------------------------------------------------------------
# Q-10: 4+ distinct tests retrying in one run -> LIVE-VARIANCE-BUDGET-EXCEEDED.
# ---------------------------------------------------------------------------
def test_q10_budget_exceeded_when_more_than_3_distinct_tests_retry(tmp_path):
    body = "\n".join(
        textwrap.dedent(f"""
        import pytest
        from relayer.errors import PoolExhaustedError

        ATTEMPTS_{i} = []

        @pytest.mark.live_variance(reason="synthetic Q-10 check {i}", max_attempts=2)
        def test_flaky_{i}():
            ATTEMPTS_{i}.append(1)
            if len(ATTEMPTS_{i}) < 2:
                raise PoolExhaustedError("synthetic transient failure {i}")
            assert True
        """)
        for i in range(4)
    )
    scratch = tmp_path / "test_q10.py"
    scratch.write_text(body)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(scratch), "-q", "-p", "tests.harness.variance"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert "LIVE-VARIANCE-BUDGET-EXCEEDED" in (result.stdout + result.stderr)
