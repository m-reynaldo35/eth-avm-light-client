"""`@pytest.mark.live_variance` -- the flake-vs-regression retry policy
(docs/design/011-test-harness-ci.md §5.6). Deliberately NOT
`pytest-rerunfailures` (§5.6, last paragraph): that plugin retries on ANY
failure, which is the exact opposite of the property this module exists to
enforce -- a retry happens ONLY if the failure's exception chain contains a
`relayer.errors.RelayerError` whose `retryability` is `RETRY_NOW` or
`RETRY_REPLANNED`. Every other failure (a bare `AssertionError`, an algod
`assert failed`/`logic eval error`, a `box ... budget ... exceeded`
rejection, `RevokedAnchor` (FATAL), `ConflictLatch` (PAGE_A_HUMAN),
`TierUnsupported`, `RelayerBug`) fails on the first attempt, immediately
(§18 item 3, G6-M11) -- this is what stops a retry decorator from ever
being able to paper over the exact box-budget defect §5 diagnoses.
"""
from __future__ import annotations

import os
import time

import pytest
from _pytest.runner import runtestprotocol

MAX_ATTEMPTS_CAP = 3  # §5.6 rule 3: capped regardless of what a test asks for
BUDGET_MAX_DISTINCT_RETRIES = 3  # §5.6 rule 5

# Populated during a session; read by tests/harness/report.py and by
# test_quarantine.py's own Suite Q assertions.
RETRY_EVENTS: list[dict] = []
RETRIED_NODEIDS: set[str] = set()


def pytest_addoption(parser):
    group = parser.getgroup("variance")
    group.addoption(
        "--live-retries", type=int, default=0,
        help="caps every @pytest.mark.live_variance test's max_attempts at "
             "(this value + 1); 0 (the default) means 'use each marker's own "
             "max_attempts, still capped at 3'",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live_variance(reason, max_attempts=2): retryable ONLY when the "
        "exception chain contains a relayer.errors.RelayerError whose "
        "retryability is RETRY_NOW or RETRY_REPLANNED (011 §5.6). "
        "reason= is mandatory.",
    )


def _is_retryable(exc: BaseException | None) -> bool:
    if exc is None:
        return False
    from relayer.errors import RelayerError, Retryability

    seen: set[int] = set()
    stack = [exc]
    while stack:
        e = stack.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        if isinstance(e, RelayerError) and e.retryability in (
            Retryability.RETRY_NOW, Retryability.RETRY_REPLANNED,
        ):
            return True
        if e.__cause__ is not None:
            stack.append(e.__cause__)
        if e.__context__ is not None:
            stack.append(e.__context__)
    return False


def pytest_runtest_makereport(item, call):
    """Stashes the real exception object (`call.excinfo.value`) for the
    `pytest_runtest_protocol` override below to inspect -- a `TestReport`'s
    `longrepr` is a rendered traceback, not the live exception, so this is
    the one hook that sees the actual object `_is_retryable` needs."""
    if call.when == "call":
        item._live_variance_excinfo = call.excinfo


def _marker_reason_and_attempts(item) -> tuple[str, int]:
    marker = item.get_closest_marker("live_variance")
    reason = marker.kwargs.get("reason") if marker.kwargs else None
    if not reason:
        raise pytest.UsageError(
            f"{item.nodeid}: @pytest.mark.live_variance requires reason= "
            f"(011 §5.6 rule 2) -- a marker with no reason is a collection error"
        )
    requested = int(marker.kwargs.get("max_attempts", 1))
    cli_cap = item.config.getoption("--live-retries", 0)
    cap = MAX_ATTEMPTS_CAP if not cli_cap else min(MAX_ATTEMPTS_CAP, cli_cap + 1)
    return reason, max(1, min(requested, cap))


def _github_step_summary(line: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_protocol(item, nextitem):
    if item.get_closest_marker("live_variance") is None:
        return None  # let the default protocol run this item

    reason, max_attempts = _marker_reason_and_attempts(item)

    item.ihook.pytest_runtest_logstart(nodeid=item.nodeid, location=item.location)
    attempt = 0
    reports: list = []
    while True:
        attempt += 1
        item._live_variance_excinfo = None
        reports = runtestprotocol(item, nextitem=nextitem, log=False)
        call_report = next((r for r in reports if r.when == "call"), None)
        excinfo = getattr(item, "_live_variance_excinfo", None)
        failed = call_report is not None and call_report.failed
        exc = excinfo.value if excinfo is not None else None
        retryable = failed and _is_retryable(exc)
        if not failed or not retryable or attempt >= max_attempts:
            break
        event = {
            "nodeid": item.nodeid, "attempt": attempt, "reason": reason,
            "exception_type": type(exc).__name__ if exc is not None else None,
            "retried_at": time.time(),
        }
        RETRY_EVENTS.append(event)
        RETRIED_NODEIDS.add(item.nodeid)
        _github_step_summary(
            f"- RETRY {item.nodeid} (attempt {attempt}/{max_attempts}): "
            f"{type(exc).__name__ if exc is not None else '?'} -- {reason}"
        )

    if attempt > 1:
        final_ok = call_report is not None and call_report.passed
        RETRY_EVENTS.append({
            "nodeid": item.nodeid, "attempt": attempt, "reason": reason,
            "final_outcome": "passed" if final_ok else "failed", "summary": True,
        })
        RETRIED_NODEIDS.add(item.nodeid)
        _github_step_summary(
            f"- RETRY-SUMMARY {item.nodeid}: {attempt} attempt(s), "
            f"final={'passed' if final_ok else 'failed'} (never a silent green)"
        )

    for report in reports:
        if attempt > 1:
            report.user_properties = list(report.user_properties) + [
                ("live_variance_attempts", attempt),
                ("live_variance_reason", reason),
            ]
        item.ihook.pytest_runtest_logreport(report=report)
    item.ihook.pytest_runtest_logfinish(
        nodeid=item.nodeid, location=item.location,
    )
    return True


def pytest_sessionfinish(session, exitstatus):
    if len(RETRIED_NODEIDS) > BUDGET_MAX_DISTINCT_RETRIES:
        session.exitstatus = 1
        msg = (
            f"LIVE-VARIANCE-BUDGET-EXCEEDED: {len(RETRIED_NODEIDS)} distinct tests "
            f"retried this run (cap: {BUDGET_MAX_DISTINCT_RETRIES}) -- "
            f"{sorted(RETRIED_NODEIDS)}"
        )
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(msg, red=True, bold=True)
        _github_step_summary(f"**{msg}**")
