"""`python -m tests.harness.report <junit.xml>` -- JUnit XML ->
`$GITHUB_STEP_SUMMARY` (docs/design/011-test-harness-ci.md §8.5/§8.6, §18
item 14). Records, per `ci-live` run: the real algod build under test, the
real current participation count and `k` (key boxes touched per mode) for
the day's real bitfield, every skip with its reason, every
`live_variance` retry with its exception type, and the quarantine list --
the mechanism that turns nightly runs into real evidence about whether
G1-M9's k=8 window ever opens (§15.4), rather than a bare pass/fail tick.
"""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from tests.harness.quarantine import QUARANTINE_TOML, load_quarantine


def _parse_junit(path: Path) -> dict:
    tree = ET.parse(path)
    root = tree.getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    skips: list[tuple[str, str]] = []
    retries: list[tuple[str, str, str]] = []
    for suite in suites:
        for key in totals:
            totals[key] += int(suite.get(key, 0) or 0)
        for case in suite.iter("testcase"):
            nodeid = f"{case.get('classname', '')}::{case.get('name', '')}"
            skip_el = case.find("skipped")
            if skip_el is not None:
                skips.append((nodeid, skip_el.get("message", "") or ""))
            attempts = None
            reason = None
            for prop in case.iter("property"):
                if prop.get("name") == "live_variance_attempts":
                    attempts = prop.get("value")
                if prop.get("name") == "live_variance_reason":
                    reason = prop.get("value")
            if attempts:
                retries.append((nodeid, attempts, reason or ""))
    return {"totals": totals, "skips": skips, "retries": retries}


def _real_participation_line() -> str:
    """A fresh, cheap (one HTTP call) real fetch at REPORT time -- not
    dependent on which live test files actually ran -- so this line is
    always available whenever a beacon endpoint is reachable, independent
    of test selection (`--live -k ...`, a quarantine, an outage during the
    test phase but not now, etc.)."""
    try:
        from relayer.drivers import m4_sync_committee as m4sc
        from relayer.group.boxes import key_box_indices_for_mode
        from relayer.sources import beacon

        fu = beacon.fetch_finality_update()
        args = m4sc.transform_finality_update(fu)
        bits = args.sync_committee_bits
        popcount = sum(bin(b).count("1") for b in bits)
        direct_k = len(key_box_indices_for_mode(bits, 0))
        complement_k = len(key_box_indices_for_mode(bits, 1))
        return (
            f"Real participation (fresh fetch at report time): {popcount}/512 -- "
            f"direct mode touches {direct_k} key box(es), complement touches {complement_k} "
            f"(G1-M9's k=8 window: {'OPEN today' if direct_k == 8 or complement_k == 8 else 'closed today'})"
        )
    except Exception as exc:  # noqa: BLE001
        return f"Real participation: unavailable this run ({type(exc).__name__}: {exc})"


def _algod_build_line(versions_path: Path | None) -> str:
    if versions_path and versions_path.exists():
        try:
            data = json.loads(versions_path.read_text())
            build = data.get("build", {})
            return (
                f"algod build under test: {build.get('branch', '?')}/{build.get('channel', '?')} "
                f"{build.get('major', '?')}.{build.get('minor', '?')}.{build.get('build_number', '?')} "
                f"({build.get('commit_hash', '?')})"
            )
        except Exception as exc:  # noqa: BLE001
            return f"algod build under test: unreadable ({exc})"
    return "algod build under test: not recorded this run (no algod-versions.json artifact)"


def render(junit_path: Path, versions_path: Path | None) -> str:
    parsed = _parse_junit(junit_path)
    lines = ["## ci-live report (docs/design/011-test-harness-ci.md §8.6, §18 item 14)", ""]
    lines.append(_algod_build_line(versions_path))
    lines.append(_real_participation_line())
    lines.append("")

    t = parsed["totals"]
    lines.append(
        f"**Totals**: {t['tests']} tests, {t['failures']} failed, "
        f"{t['errors']} errored, {t['skipped']} skipped"
    )
    total = t["tests"] or 1
    skip_pct = 100.0 * t["skipped"] / total
    if skip_pct > 50:
        lines.append(
            f"**LIVE-TIER-DEGRADED**: {skip_pct:.1f}% of the live tier skipped this run "
            f"(011 §10 edge case 5 -- an endpoint outage, not this repo's bug, but must not "
            f"read as a plain pass either)"
        )
    lines.append("")

    if parsed["skips"]:
        lines.append(f"### Skips ({len(parsed['skips'])})")
        for nodeid, reason in parsed["skips"]:
            lines.append(f"- `{nodeid}`: {reason}")
        lines.append("")

    if parsed["retries"]:
        lines.append(f"### Retries ({len(parsed['retries'])}) -- never a silent green")
        for nodeid, attempts, reason in parsed["retries"]:
            lines.append(f"- `{nodeid}`: {attempts} attempt(s) -- {reason}")
        lines.append("")
    else:
        lines.append("### Retries: none this run")
        lines.append("")

    try:
        entries = load_quarantine(QUARANTINE_TOML)
        if entries:
            lines.append(f"### Quarantine list ({len(entries)}) -- known-unproven claims (011 §5.7)")
            for e in entries:
                lines.append(
                    f"- `{e['nodeid']}` (opened {e['opened']}, expires {e['expires']}, "
                    f"owner {e['owner']}): {e['reason']}"
                )
            lines.append("")
        else:
            lines.append("### Quarantine list: empty")
            lines.append("")
    except Exception as exc:  # noqa: BLE001
        lines.append(f"### Quarantine list -- ERROR loading {QUARANTINE_TOML}: {exc}")
        lines.append("")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("junit_xml")
    parser.add_argument("--algod-versions", default="algod-versions.json")
    args = parser.parse_args(argv)
    versions_path = Path(args.algod_versions)
    print(render(Path(args.junit_xml), versions_path if versions_path.exists() else None))
    return 0


if __name__ == "__main__":
    sys.exit(main())
