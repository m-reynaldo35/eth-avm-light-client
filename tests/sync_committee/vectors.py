"""Loaders for the vendored `light_client/sync` (minimal preset, Altair) and
`eth_fast_aggregate_verify` (general) consensus-spec-test suites (design doc
§3.3, §11; `tests/fixtures/sync_committee/consensus-spec-tests/RELEASE.txt`).

Two facts pinned by `RELEASE.txt`, load-bearing here:
  * `.ssz_snappy` files are RAW snappy blocks -- `cramjam.snappy.decompress_raw`,
    NOT `.decompress` (the framed format).
  * Altair's `LightClientUpdate`/`LightClientBootstrap` are FULLY FIXED-SIZE
    for the MINIMAL preset (SYNC_COMMITTEE_SIZE=32): every field is either a
    fixed-size basic type or a `Vector`/`Bitvector` of one, so the wire
    encoding is a flat concatenation with no SSZ offset table. This module
    hand-slices those fixed byte ranges rather than pulling in a full
    `remerkleable` container definition -- verified empirically (this
    module's own `_selftest_layout`) against the real vendored files' exact
    byte lengths (2268 B updates, 1856 B bootstrap) before being trusted.

    Capella+ headers are variable-size once `LightClientHeader` gains an
    `execution: ExecutionPayloadHeader` field (whose `extra_data` is a
    `List`); this loader does NOT attempt to parse those forks' updates --
    matching design doc T1's own admission ("remaining forks need a
    LightClientHeader parser... use remerkleable containers"). Only Altair's
    `light_client_sync` vectors are parsed here.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass

import cramjam
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTORS_DIR = REPO_ROOT / "tests/fixtures/sync_committee/consensus-spec-tests"
MINIMAL_DIR = VECTORS_DIR / "minimal"
GENERAL_DIR = VECTORS_DIR / "general"

MINIMAL_SYNC_COMMITTEE_SIZE = 32
FINALIZED_ROOT_DEPTH = 6  # floorlog2(105) -- preset-independent (§4.2)
NEXT_SYNC_COMMITTEE_DEPTH = 5  # floorlog2(55) / floorlog2(54) -- preset-independent
CURRENT_SYNC_COMMITTEE_DEPTH = 5

G1_COMPRESSED_BYTES = 48
BEACON_HEADER_BYTES = 112


def decompress_raw(path: pathlib.Path) -> bytes:
    return bytes(cramjam.snappy.decompress_raw(path.read_bytes()))


def _strip0x(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


@dataclass
class ParsedBootstrap:
    header: bytes  # 112 B
    current_sync_committee_pubkeys: list[bytes]  # 48 B each
    current_sync_committee_aggregate: bytes  # 48 B
    current_sync_committee_branch: list[bytes]  # 32 B each, 5 entries


@dataclass
class ParsedUpdate:
    attested_header: bytes  # 112 B
    next_sync_committee_pubkeys: list[bytes]
    next_sync_committee_aggregate: bytes
    next_sync_committee_branch: list[bytes]
    finalized_header: bytes
    finality_branch: list[bytes]
    sync_committee_bits: bytes  # SYNC_COMMITTEE_SIZE // 8 bytes
    signature: bytes  # 96 B, compressed (this is the wire/SSZ form)
    signature_slot: int


def parse_bootstrap(raw: bytes, sync_committee_size: int = MINIMAL_SYNC_COMMITTEE_SIZE) -> ParsedBootstrap:
    off = 0
    header = raw[off : off + BEACON_HEADER_BYTES]
    off += BEACON_HEADER_BYTES

    pubkeys = []
    for _ in range(sync_committee_size):
        pubkeys.append(raw[off : off + G1_COMPRESSED_BYTES])
        off += G1_COMPRESSED_BYTES
    aggregate = raw[off : off + G1_COMPRESSED_BYTES]
    off += G1_COMPRESSED_BYTES

    branch = []
    for _ in range(CURRENT_SYNC_COMMITTEE_DEPTH):
        branch.append(raw[off : off + 32])
        off += 32

    assert off == len(raw), f"bootstrap length mismatch: consumed {off}, total {len(raw)}"
    return ParsedBootstrap(header, pubkeys, aggregate, branch)


def parse_update(raw: bytes, sync_committee_size: int = MINIMAL_SYNC_COMMITTEE_SIZE) -> ParsedUpdate:
    off = 0
    attested_header = raw[off : off + BEACON_HEADER_BYTES]
    off += BEACON_HEADER_BYTES

    pubkeys = []
    for _ in range(sync_committee_size):
        pubkeys.append(raw[off : off + G1_COMPRESSED_BYTES])
        off += G1_COMPRESSED_BYTES
    aggregate = raw[off : off + G1_COMPRESSED_BYTES]
    off += G1_COMPRESSED_BYTES

    next_branch = []
    for _ in range(NEXT_SYNC_COMMITTEE_DEPTH):
        next_branch.append(raw[off : off + 32])
        off += 32

    finalized_header = raw[off : off + BEACON_HEADER_BYTES]
    off += BEACON_HEADER_BYTES

    finality_branch = []
    for _ in range(FINALIZED_ROOT_DEPTH):
        finality_branch.append(raw[off : off + 32])
        off += 32

    bits_bytes = sync_committee_size // 8
    sync_committee_bits = raw[off : off + bits_bytes]
    off += bits_bytes
    signature = raw[off : off + 96]
    off += 96

    signature_slot = int.from_bytes(raw[off : off + 8], "little")
    off += 8

    assert off == len(raw), f"update length mismatch: consumed {off}, total {len(raw)}"
    return ParsedUpdate(
        attested_header,
        pubkeys,
        aggregate,
        next_branch,
        finalized_header,
        finality_branch,
        sync_committee_bits,
        signature,
        signature_slot,
    )


def altair_sync_case_dir(case_name: str = "light_client_sync") -> pathlib.Path:
    return MINIMAL_DIR / "altair/light_client/sync/pyspec_tests" / case_name


def load_altair_sync_case(case_name: str = "light_client_sync") -> dict:
    """Loads bootstrap + every `process_update` step's parsed update, plus
    `meta.yaml`/`steps.yaml`/`config.yaml`, for the Altair `light_client_sync`
    scenario (design doc §3.4's own walk). Update files are matched to
    `steps.yaml` entries by filename stem.
    """
    d = altair_sync_case_dir(case_name)
    meta = yaml.safe_load((d / "meta.yaml").read_text())
    steps = yaml.safe_load((d / "steps.yaml").read_text())
    config = yaml.safe_load((d / "config.yaml").read_text())

    bootstrap_raw = decompress_raw(d / "bootstrap.ssz_snappy")
    bootstrap = parse_bootstrap(bootstrap_raw)

    # `all_steps` preserves the FULL `steps.yaml` order, including
    # `force_update` entries -- dropping those (as an earlier version of
    # this loader did) silently discards the store mutations that
    # `process_light_client_store_force_update` performs via
    # `store.best_valid_update`, which several of this scenario's later
    # `process_update` steps depend on for correct committee/period
    # tracking (see `test_signing_root.py`'s `_walk`). `process_update_steps`
    # is kept as a process-update-only filtered view for callers that only
    # need per-update data.
    process_update_steps = []
    all_steps = []
    for step in steps:
        if "process_update" in step:
            pu = step["process_update"]
            update_name = pu["update"]
            if isinstance(update_name, dict):
                # yaml quirk: sometimes parsed as a mapping with one key
                update_name = next(iter(update_name))
            update_raw = decompress_raw(d / f"{update_name}.ssz_snappy")
            parsed = parse_update(update_raw)
            entry = {
                "kind": "process_update",
                "update_name": update_name,
                "current_slot": pu["current_slot"],
                "checks": pu["checks"],
                "parsed": parsed,
                "raw": update_raw,
            }
            process_update_steps.append(entry)
            all_steps.append(entry)
        elif "force_update" in step:
            fu = step["force_update"]
            all_steps.append(
                {
                    "kind": "force_update",
                    "current_slot": fu["current_slot"],
                    "checks": fu["checks"],
                }
            )
        # else: other step kinds (e.g. `upgrade_to_*`) do not occur in this
        # scenario; ignored defensively rather than asserted against, since
        # this loader is Altair-only (module docstring).

    return {
        "dir": d,
        "meta": meta,
        "steps": steps,
        "config": config,
        "bootstrap": bootstrap,
        "bootstrap_raw": bootstrap_raw,
        "genesis_validators_root": _strip0x(meta["genesis_validators_root"]),
        "trusted_block_root": _strip0x(meta["trusted_block_root"]),
        "bootstrap_fork_digest": _strip0x(meta["bootstrap_fork_digest"]),
        "process_update_steps": process_update_steps,
        "all_steps": all_steps,
    }


# ---------------------------------------------------------------------------
# eth_fast_aggregate_verify (general/altair/bls) -- T4, T7 (§3.6, §11)
# ---------------------------------------------------------------------------

FAST_AGG_VERIFY_DIR = GENERAL_DIR / "altair/bls/eth_fast_aggregate_verify/bls"


def load_fast_aggregate_verify_cases() -> list[dict]:
    cases = []
    for case_dir in sorted(FAST_AGG_VERIFY_DIR.iterdir()):
        data_path = case_dir / "data.yaml"
        if not data_path.exists():
            continue
        data = yaml.safe_load(data_path.read_text())
        inp = data["input"]
        pubkeys = [_strip0x(p) for p in inp["pubkeys"]]
        message = _strip0x(inp["message"])
        signature = _strip0x(inp["signature"])
        output = data["output"]
        cases.append(
            {
                "name": case_dir.name,
                "pubkeys": pubkeys,
                "message": message,
                "signature": signature,
                "output": bool(output),
            }
        )
    return cases
