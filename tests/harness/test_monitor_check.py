"""`scripts/monitor_check.py` is the check logic `.github/workflows/monitor.yml`
runs on a schedule (docs/security.md's "Nothing is monitored" section,
closed by that workflow -- see CHANGELOG.md [Unreleased]). A green
scheduled run only ever exercises the happy path; everything here proves
the FAILURE branch fires correctly, entirely offline (no network, no
subprocess, no algod) by injecting fakes for the two things that talk to
the outside world (`fetch` for the HTTP call, `runner` for the `deploy
verify` subprocess) -- `parse_verify_output` itself takes a plain string,
so the M4-slack-vs-genuine-failure distinction is tested directly against
real captured `deploy verify` output, not a guess at its shape.
"""
from __future__ import annotations

from scripts.monitor_check import check_health, check_mainnet, parse_verify_output

# Real output, captured live this pass via `python3 -m deploy verify
# --target deploy/targets/mainnet.json` against real mainnet -- exactly the
# shape docs/security.md's "`deploy verify`'s M4 slack-balance finding
# (expected, not a bug)" section describes: `m4` always fails with only the
# permanent 366,100 microALGO slack finding.
REAL_HEALTHY_OUTPUT = """\
m4: FAIL
  - app account has 366100 microalgo above its own min-balance (unexpected slack, §10.4/G8-M10)
m6: OK
m7: OK
m7_anchored: OK
m8: OK
"""


def test_m1_all_ok_is_healthy():
    ok, failures = parse_verify_output("m4: OK\nm6: OK\nm7: OK\nm8: OK\n")
    assert ok is True
    assert failures == []


def test_m2_real_m4_slack_only_is_healthy_not_flagged():
    ok, failures = parse_verify_output(REAL_HEALTHY_OUTPUT)
    assert ok is True, f"the documented, expected M4 slack finding must not page anyone: {failures}"
    assert failures == []


def test_m3_m4_with_a_different_or_additional_issue_is_a_genuine_failure():
    output = "m4: FAIL\n  - CODE_MISMATCH: on-chain program does not match the pinned approval hash\nm6: OK\n"
    ok, failures = parse_verify_output(output)
    assert ok is False
    assert any("CODE_MISMATCH" in f for f in failures)


def test_m4_a_non_m4_app_failing_is_always_a_genuine_failure():
    output = "m4: FAIL\n  - app account has 366100 microalgo above its own min-balance (unexpected slack)\nm7: FAIL\n  - unreachable: connection refused\n"
    ok, failures = parse_verify_output(output)
    assert ok is False
    assert any(f.startswith("m7:") for f in failures)
    assert not any(f.startswith("m4:") for f in failures), "m4's known slack finding must stay excluded even when another app also fails"


def test_m5_unparseable_output_is_a_genuine_failure_not_a_silent_pass():
    ok, failures = parse_verify_output("Traceback (most recent call last):\n  ...\nConnectionError: could not reach mainnet-api.algonode.cloud\n")
    assert ok is False
    assert failures


def test_m6_health_check_happy_path():
    body = '{"algod_round": 1, "m7_app_id": 2, "m4_app_id": 3, "m8_app_id": 4, "trustless_configured": true, "keeper_configured": true}'
    ok, msg = check_health("https://example.invalid/health", fetch=lambda url, timeout: (200, body))
    assert ok is True
    assert "algod_round=1" in msg


def test_m7_health_check_missing_key_is_a_failure():
    body = '{"algod_round": 1}'
    ok, msg = check_health("https://example.invalid/health", fetch=lambda url, timeout: (200, body))
    assert ok is False
    assert "missing key" in msg


def test_m8_health_check_non_200_is_a_failure():
    ok, msg = check_health("https://example.invalid/health", fetch=lambda url, timeout: (500, "internal error"))
    assert ok is False
    assert "500" in msg


def test_m9_health_check_transport_error_is_a_failure_not_an_exception():
    def _raise(url, timeout):
        raise ConnectionError("real network calls are exactly what this test must not make")

    ok, msg = check_health("https://example.invalid/health", fetch=_raise)
    assert ok is False
    assert "unreachable" in msg


def test_m10_health_check_non_json_body_is_a_failure():
    ok, msg = check_health("https://example.invalid/health", fetch=lambda url, timeout: (200, "not json"))
    assert ok is False
    assert "non-JSON" in msg


def test_m11_check_mainnet_wraps_the_runner_and_reuses_the_same_parser():
    ok, failures = check_mainnet("deploy/targets/mainnet.json", runner=lambda target: REAL_HEALTHY_OUTPUT)
    assert ok is True
    assert failures == []


def test_m12_check_mainnet_runner_exception_is_a_failure_not_a_crash():
    def _boom(target):
        raise TimeoutError("deploy verify did not return within the subprocess timeout")

    ok, failures = check_mainnet("deploy/targets/mainnet.json", runner=_boom)
    assert ok is False
    assert failures
