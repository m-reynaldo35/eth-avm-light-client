"""`quarantine.toml` loader + validity assertions (docs/design/
011-test-harness-ci.md §5.7). Replaces the tribal-knowledge `--deselect`
convention this repo used before M11 -- three ROADMAP rows (M8, M9, M10)
document a human carrying "deselect test_live_e2e_finality.py" in their
head across sessions, which is exactly the failure mode a committed, dated,
expiring file exists to end.

Every entry needs all five fields (`nodeid`, `reason`, `opened`, `expires`,
`owner`); `expires` is capped at 90 days from `opened`; and an expired
entry fails the BUILD (not merely the quarantined test), so the decision
comes back to a human on a real date rather than silently persisting.
"""
from __future__ import annotations

import datetime as _dt
import tomllib
from pathlib import Path

QUARANTINE_TOML = Path(__file__).resolve().parent / "quarantine.toml"
REQUIRED_FIELDS = ("nodeid", "reason", "opened", "expires", "owner")
MAX_LIFETIME_DAYS = 90


class QuarantineError(ValueError):
    pass


def _parse_date(value: str, *, field: str, nodeid: str) -> _dt.date:
    try:
        return _dt.date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise QuarantineError(f"quarantine entry {nodeid!r}: {field}={value!r} is not an ISO date") from exc


def load_quarantine(path: Path = QUARANTINE_TOML, *, today: _dt.date | None = None) -> list[dict]:
    """Loads and validates every entry. Raises `QuarantineError` (naming
    the offending entry) on: a missing field, `expires` more than 90 days
    after `opened`, or an entry whose `expires` date is in the past
    (§5.7's "the quarantine fails the build, not the test").
    `nodeid`-resolves-against-the-real-collection is checked separately by
    `test_quarantine.py` (it needs a live pytest `Config`/collection, which
    this module -- deliberately dependency-light -- does not import)."""
    today = today or _dt.date.today()
    if not path.exists():
        return []
    data = tomllib.loads(path.read_text())
    entries = data.get("test", [])
    out = []
    for entry in entries:
        nodeid = entry.get("nodeid", "<unknown>")
        missing = [f for f in REQUIRED_FIELDS if f not in entry or not entry[f]]
        if missing:
            raise QuarantineError(f"quarantine entry {nodeid!r} is missing field(s): {missing}")
        opened = _parse_date(entry["opened"], field="opened", nodeid=nodeid)
        expires = _parse_date(entry["expires"], field="expires", nodeid=nodeid)
        if (expires - opened).days > MAX_LIFETIME_DAYS:
            raise QuarantineError(
                f"quarantine entry {nodeid!r}: expires ({expires}) is more than "
                f"{MAX_LIFETIME_DAYS} days after opened ({opened}) -- 011 §5.7 caps this"
            )
        if expires < today:
            raise QuarantineError(
                f"quarantine entry {nodeid!r} EXPIRED on {expires} (owner: {entry['owner']}) -- "
                f"011 §5.7: an expired quarantine fails the BUILD, not just the test. "
                f"Reason it was opened: {entry['reason']}"
            )
        out.append(entry)
    return out


def quarantined_nodeids(path: Path = QUARANTINE_TOML) -> set[str]:
    return {e["nodeid"] for e in load_quarantine(path)}
