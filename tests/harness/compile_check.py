"""`python -m tests.harness.compile_check` -- the compile-and-artifact-diff
gate (docs/design/011-test-harness-ci.md §3.5, §7.4, §16 item 16, G3-M11).
A build step, not a pytest file: its failure message is a byte count and a
hash, not a traceback (§7.4's own reasoning for keeping this out of
`tests/harness/test_compile_gate.py`, which instead calls these same
functions and asserts on their results for Suite C's offline half, C-1..C-5).

Three offline-safe entry points plus one that needs algod:

  --compile-all      every one of the 10 real contract entry points
                      compiles with the pinned `puyapy` (no network).
  --diff-artifacts    the 2 ARC-56 artifacts and the 2 bare-contract TEAL
                      hashes reproduce byte-identically from source (no
                      network -- `puyapy` alone, §3.5).
  --diff-assembled    (needs algod) the 2 bare contracts' ASSEMBLED byte
                      lengths and `approval_sha256`/`clear_sha256` match the
                      committed cache, via one `/v2/teal/compile` per
                      contract -- the one thing §3.5 says cannot be done
                      offline. Deliberately does NOT call
                      `deploy.compile.refresh_bare_contract_cache` (which
                      overwrites the committed cache file): this is a
                      CHECK, not a regeneration, so it computes the fresh
                      values and compares them without ever touching the
                      committed `deploy/schema/_compiled/*.compiled.json`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from deploy.compile import (
    BARE_CONTRACT_SOURCES,
    compile_teal_via_algod,
    load_bare_contract_cache,
    puya_compile,
    sha256_hex,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

# The 10 real contract entry points (§3.5) -- every `puyapy` compile unit in
# `contracts/`, one file per real deployable surface.
ENTRY_POINTS = [
    REPO_ROOT / "contracts" / "composer" / "bench_app.py",
    REPO_ROOT / "contracts" / "mpt" / "bench_app.py",
    REPO_ROOT / "contracts" / "primitives" / "bls" / "harness.py",
    REPO_ROOT / "contracts" / "primitives" / "rlp" / "bench_app.py",
    REPO_ROOT / "contracts" / "primitives" / "ssz" / "harness.py",
    REPO_ROOT / "contracts" / "receipt" / "bench_app.py",
    REPO_ROOT / "contracts" / "state_anchor" / "anchor_app.py",
    REPO_ROOT / "contracts" / "state_anchor" / "bench_app.py",
    REPO_ROOT / "contracts" / "sync_committee" / "bench_app.py",
    REPO_ROOT / "contracts" / "sync_committee" / "verifier.py",
]

# The 2 ARC4Contract sources whose whole compiled ARC-56 artifact is
# committed and must reproduce byte-identically (§3.5).
ARC56_TARGETS = {
    REPO_ROOT / "contracts" / "sync_committee" / "verifier.py": (
        "SyncCommitteeVerifier",
        REPO_ROOT / "contracts" / "sync_committee" / "SyncCommitteeVerifier.arc56.json",
    ),
    REPO_ROOT / "contracts" / "state_anchor" / "anchor_app.py": (
        "TrustedRootAnchor",
        REPO_ROOT / "contracts" / "state_anchor" / "TrustedRootAnchor.arc56.json",
    ),
}


def _relpath(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def compile_all() -> list[str]:
    """Returns a list of human-readable OK lines; raises on any failure
    (a `puyapy` failure already raises `RuntimeError` from `puya_compile`,
    carrying its own stdout/stderr)."""
    lines = []
    for src in ENTRY_POINTS:
        puya_compile(src)  # raises RuntimeError on failure
        lines.append(f"OK {src.relative_to(REPO_ROOT)}")
    return lines


def diff_artifacts() -> list[str]:
    """Offline: ARC-56 whole-JSON diff + bare-contract TEAL-hash diff.
    Returns a list of OK lines; raises `AssertionError` (naming the byte
    count/hash on both sides) on any mismatch."""
    lines = []

    for src, (class_name, committed_path) in ARC56_TARGETS.items():
        contracts = puya_compile(src)
        fresh_arc56 = contracts[class_name]["arc56"]
        committed_arc56 = json.loads(committed_path.read_text())
        fresh_norm = json.dumps(fresh_arc56, sort_keys=True)
        committed_norm = json.dumps(committed_arc56, sort_keys=True)
        approval_b64 = fresh_arc56.get("byteCode", {}).get("approval", "")
        committed_b64 = committed_arc56.get("byteCode", {}).get("approval", "")
        assert fresh_norm == committed_norm, (
            f"{class_name}.arc56.json drift ({_relpath(committed_path)}): "
            f"fresh byteCode.approval b64 len={len(approval_b64)}, "
            f"committed len={len(committed_b64)}, sha256 fresh="
            f"{sha256_hex(approval_b64.encode())}, committed={sha256_hex(committed_b64.encode())}"
        )
        lines.append(
            f"OK {class_name}.arc56.json byte-identical "
            f"({len(approval_b64)} B approval, sha256 {sha256_hex(approval_b64.encode())[:16]}...)"
        )

    for name, src in BARE_CONTRACT_SOURCES.items():
        contracts = puya_compile(src)
        entry = contracts[name]
        fresh_appr_sha = sha256_hex(entry["approval"].encode())
        fresh_clear_sha = sha256_hex(entry["clear"].encode())
        cache = load_bare_contract_cache(name)
        assert fresh_appr_sha == cache["approval_teal_sha256"], (
            f"{name} approval TEAL drift: fresh sha256={fresh_appr_sha}, "
            f"cached={cache['approval_teal_sha256']}"
        )
        assert fresh_clear_sha == cache["clear_teal_sha256"], (
            f"{name} clear TEAL drift: fresh sha256={fresh_clear_sha}, "
            f"cached={cache['clear_teal_sha256']}"
        )
        lines.append(
            f"OK {name} TEAL byte-identical (approval sha256 {fresh_appr_sha[:16]}..., "
            f"clear sha256 {fresh_clear_sha[:16]}...)"
        )
    return lines


def diff_assembled(algod_client=None) -> list[str]:
    """Live (needs algod): the bare contracts' ASSEMBLED byte length and
    `approval_sha256`/`clear_sha256` match the committed cache, via one
    `/v2/teal/compile` per contract. Deliberately reimplements the compare
    (rather than calling `deploy.compile.refresh_bare_contract_cache`,
    which OVERWRITES the committed cache file) so this is a pure check."""
    if algod_client is None:
        from tests.harness.chain import algod_client as _algod_client_factory

        algod_client = _algod_client_factory()

    lines = []
    for name, src in BARE_CONTRACT_SOURCES.items():
        contracts = puya_compile(src)
        entry = contracts[name]
        appr_bytes = compile_teal_via_algod(algod_client, entry["approval"])
        clear_bytes = compile_teal_via_algod(algod_client, entry["clear"])
        cache = load_bare_contract_cache(name)
        fresh_appr_sha = sha256_hex(appr_bytes)
        fresh_clear_sha = sha256_hex(clear_bytes)
        assert len(appr_bytes) == cache["approval_bytes"], (
            f"{name} approval assembled-size drift: fresh={len(appr_bytes)} B, "
            f"cached={cache['approval_bytes']} B"
        )
        assert fresh_appr_sha == cache["approval_sha256"], (
            f"{name} approval assembled sha256 drift: fresh={fresh_appr_sha}, "
            f"cached={cache['approval_sha256']}"
        )
        assert len(clear_bytes) == cache["clear_bytes"], (
            f"{name} clear assembled-size drift: fresh={len(clear_bytes)} B, "
            f"cached={cache['clear_bytes']} B"
        )
        assert fresh_clear_sha == cache["clear_sha256"], (
            f"{name} clear assembled sha256 drift: fresh={fresh_clear_sha}, "
            f"cached={cache['clear_sha256']}"
        )
        lines.append(
            f"OK {name} assembled bytes match cache (approval {len(appr_bytes)} B, "
            f"clear {len(clear_bytes)} B)"
        )
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compile-all", action="store_true")
    parser.add_argument("--diff-artifacts", action="store_true")
    parser.add_argument("--diff-assembled", action="store_true")
    args = parser.parse_args(argv)

    if not (args.compile_all or args.diff_artifacts or args.diff_assembled):
        parser.error("one of --compile-all / --diff-artifacts / --diff-assembled is required")

    try:
        if args.compile_all:
            for line in compile_all():
                print(line)
        if args.diff_artifacts:
            for line in diff_artifacts():
                print(line)
        if args.diff_assembled:
            for line in diff_assembled():
                print(line)
    except (AssertionError, RuntimeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
