"""Client-side fork-row refusal (design doc 012 §3.7, §17 item 5).

`contracts/sync_committee/forks.py::append_fork_row` and its M8 sibling
validate epoch monotonicity, the sentinel and table capacity -- **not the
gindices at all** (012 §3.7, measured by reading both appenders in full). A
Gloas row is therefore appendable on chain today and would fail at
`submit_update`/`anchor_historical` time (a budget or argument-size
rejection), not at governance time when a human is watching.

`deploy` closes the gap it CAN close: before ever building an
`append_fork_row` call, it refuses if the target fork is listed in
`deploy/versions.json`'s `code_window.unsupported` for that contract. This is
tool-side only, and MUST stay described that way (012 §17 item 6): a
governance key holder submitting `append_fork_row` directly (via `goal` or
any other client) bypasses this refusal entirely. Closing it properly needs a
chain-side depth/gindex bound, which is a contract change and out of scope
here (`O-M12-1`, 012 §3.7/§14.4).
"""
from __future__ import annotations

import json
from pathlib import Path

VERSIONS_PATH = Path(__file__).resolve().parent / "versions.json"


class UnsupportedForkError(ValueError):
    """Raised instead of ever building an `append_fork_row` call for a fork
    outside a contract's `code_window.supported` set (012 §3.7)."""


def load_versions(versions_path: Path | None = None) -> dict:
    path = versions_path or VERSIONS_PATH
    return json.loads(path.read_text())


def assert_fork_appendable(fork: str, contract_key: str, *, versions: dict | None = None) -> None:
    """`contract_key` is the `versions.json` contract name
    (`"SyncCommitteeVerifier"`/`"TrustedRootAnchor"`), not the deploy-target
    short name (`"m4"`/`"m8"`). No-op (never raises) for a contract with no
    `code_window` entry (e.g. `fork_axis: "none"`) or for a fork that is not
    in that contract's `unsupported` list -- including a fork the contract
    has never heard of, which is `deploy/forks.py`'s own job to reject."""
    versions = versions if versions is not None else load_versions()
    entry = versions.get("contracts", {}).get(contract_key) or {}
    code_window = entry.get("code_window") or {}
    unsupported = code_window.get("unsupported") or []
    if fork.lower() in {f.lower() for f in unsupported}:
        raise UnsupportedForkError(
            f"{contract_key}: fork {fork!r} is in code_window.unsupported -- refusing to build "
            f"an append_fork_row call for it (this is a tool-side refusal only; a governance "
            f"key holder using a raw client bypasses it, 012 §3.7). Reason: "
            f"{code_window.get('reason')!r}"
        )
