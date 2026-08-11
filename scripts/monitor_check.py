"""docs/security.md's "Nothing is monitored" section (now closed, see
CHANGELOG.md [Unreleased]): the two things this project has that can go
dark with nobody noticing are the live Vercel service and the live mainnet
apps. This is the actual check logic `.github/workflows/monitor.yml` runs
on a schedule -- kept in its own stdlib-only script, not inlined in the
workflow YAML, so the failure branch (the part a green scheduled run never
exercises) can be unit-tested offline in `tests/harness/test_monitor_check.py`
without touching the real service or the real chain.

Stdlib only (`urllib.request`, `subprocess`, `json`, `re`) -- this repo's
own G8-M9 import-purity test forbids exactly the class of dependency
(sentry-sdk, requests, ...) a naive monitoring script reaches for first,
and `deploy verify` itself needs nothing beyond the four core deps already
in `pyproject.toml` (`py-algorand-sdk`/`rlp`/`pycryptodome`/`py_ecc`).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request

DEFAULT_HEALTH_URL = "https://x402endpoint-nu.vercel.app/health"
DEFAULT_TARGET = "deploy/targets/mainnet.json"

# service/x402_endpoint/main.py's real `/health` handler, read directly
# rather than guessed -- a key renamed there and not here should fail loud,
# not silently stop being checked.
EXPECTED_HEALTH_KEYS = (
    "algod_round",
    "m7_app_id",
    "m4_app_id",
    "m8_app_id",
    "trustless_configured",
    "keeper_configured",
)

# docs/security.md "`deploy verify`'s M4 slack-balance finding (expected,
# not a bug)": M4's real, permanent 366,100 microALGO of install-vs-
# steady-state slack always makes `deploy verify` report `m4: FAIL`. That
# finding, and only that finding, must not page anyone -- anything else
# (CODE_MISMATCH, unreachable, a different app failing) must.
_APP_LINE = re.compile(r"^(\S+): (OK|FAIL)$")
_ISSUE_LINE = re.compile(r"^  - (.+)$")
_KNOWN_M4_ISSUE = "unexpected slack"


def _http_get(url: str, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "eth-avm-light-client-monitor"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https URL, not user input)
        return resp.status, resp.read().decode("utf-8", errors="replace")


def check_health(url: str = DEFAULT_HEALTH_URL, *, timeout: float = 10.0, fetch=_http_get) -> tuple[bool, str]:
    try:
        status, body = fetch(url, timeout)
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code} from {url}"
    except Exception as exc:  # urllib.error.URLError, socket.timeout, etc.
        return False, f"unreachable ({exc.__class__.__name__}): {exc}"

    if status != 200:
        return False, f"HTTP {status} from {url}"

    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        return False, f"non-JSON body from {url}: {exc}"

    missing = [k for k in EXPECTED_HEALTH_KEYS if k not in data]
    if missing:
        return False, f"response missing key(s) {missing}: {body[:200]}"

    return True, f"OK algod_round={data['algod_round']} m7={data['m7_app_id']} m4={data['m4_app_id']} m8={data['m8_app_id']}"


def parse_verify_output(output: str) -> tuple[bool, list[str]]:
    """Pure parsing, no subprocess -- the part unit-tested directly against
    canned `deploy verify` stdout in tests/harness/test_monitor_check.py."""
    apps: dict[str, dict] = {}
    current = None
    for line in output.splitlines():
        m = _APP_LINE.match(line)
        if m:
            current = m.group(1)
            apps[current] = {"status": m.group(2), "issues": []}
            continue
        m = _ISSUE_LINE.match(line)
        if m and current is not None:
            apps[current]["issues"].append(m.group(1))

    if not apps:
        return False, ["deploy verify produced no parseable 'app: OK/FAIL' lines -- treat as a genuine failure: " + output[:300]]

    genuine_failures = []
    for name, info in apps.items():
        if info["status"] != "FAIL":
            continue
        is_known_m4_slack = (
            name == "m4"
            and info["issues"]
            and all(_KNOWN_M4_ISSUE in issue.lower() for issue in info["issues"])
        )
        if is_known_m4_slack:
            continue
        genuine_failures.append(f"{name}: {'; '.join(info['issues']) or 'FAIL (no issue reported)'}")

    return (not genuine_failures), genuine_failures


def _run_deploy_verify(target: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-m", "deploy", "verify", "--target", target],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return proc.stdout + proc.stderr


def check_mainnet(target: str = DEFAULT_TARGET, *, runner=_run_deploy_verify) -> tuple[bool, list[str]]:
    try:
        output = runner(target)
    except Exception as exc:
        return False, [f"failed to invoke 'python -m deploy verify': {exc}"]
    return parse_verify_output(output)


def _parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--health-url", default=DEFAULT_HEALTH_URL)
    p.add_argument("--target", default=DEFAULT_TARGET)
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    lines = []
    overall_ok = True

    health_ok, health_msg = check_health(args.health_url)
    lines.append(f"[service /health] {'OK' if health_ok else 'FAIL'}: {health_msg}")
    overall_ok = overall_ok and health_ok

    mainnet_ok, mainnet_failures = check_mainnet(args.target)
    if mainnet_ok:
        lines.append("[mainnet apps] OK: every app usable (M4's documented slack finding, docs/security.md, is not a failure)")
    else:
        lines.append("[mainnet apps] FAIL:")
        lines.extend(f"  - {f}" for f in mainnet_failures)
    overall_ok = overall_ok and mainnet_ok

    print("\n".join(lines))
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
