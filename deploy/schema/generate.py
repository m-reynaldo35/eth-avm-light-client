"""The schema generator (design doc §3). Produces
`deploy/schema/<Contract>.schema.json`, one per deployable contract, by
IMPORTING the contracts' own `constants.py`/`forks.py` modules and reading
their compiled-artifact caches -- never by hand-typing a byte count, offset,
box name or MBR figure (§17 item 2).

Runs as ordinary Python: no `puyapy`, no algod, no network (§3.1, §3.4) --
`deploy/compile.py`'s module docstring records the one honest asymmetry
(bare-`Contract` compiled sizes need algod to *regenerate the cache*, not to
*read the committed cache*, which is all this module does).
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from deploy.compile import COMPILED_CACHE_DIR, load_bare_contract_cache
from deploy.mbr import box_mbr, global_state_mbr, min_extra_pages

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = Path(__file__).resolve().parent


def _method_signature(method: dict) -> str:
    args = ",".join(a["type"] for a in method.get("args", []))
    ret = method.get("returns", {}).get("type", "void")
    return f"{method['name']}({args}){ret}"


def _arc56_program_info(arc56: dict) -> dict:
    approval = base64.b64decode(arc56["byteCode"]["approval"])
    clear = base64.b64decode(arc56["byteCode"]["clear"])
    approval_teal = ""  # not needed once byteCode exists; kept for symmetry
    on_completion_gate = _on_completion_gate_from_bytecode(arc56)
    return {
        "approval_bytes": len(approval),
        "clear_bytes": len(clear),
        "approval_sha256": hashlib.sha256(approval).hexdigest(),
        "clear_sha256": hashlib.sha256(clear).hexdigest(),
        "min_extra_pages": min_extra_pages(len(approval), len(clear)),
        "avm_version": 10,
        "on_completion_gate": on_completion_gate,
    }


def _on_completion_gate_from_bytecode(arc56: dict) -> str:
    """M4/M8 are `ARC4Contract`s: Puya's own router unconditionally emits
    `txn OnCompletion; !; assert` (rejecting every on-completion but NoOp)
    UNLESS the contract declares an explicit update/delete ARC-4 method --
    neither `SyncCommitteeVerifier` nor `TrustedRootAnchor` does (§9.1,
    confirmed by direct TEAL inspection in the design doc). So for an
    ARC4Contract with no declared bare `update_application`/
    `delete_application` action, the gate is always "NoOp only". This
    mirrors the design doc's own TEAL-prologue check without needing the
    TEAL text (already discarded once byteCode exists) -- `bareActions` is
    the ARC-56-native way to ask the same question."""
    bare = arc56.get("bareActions", {}) or {}
    call_actions = set(bare.get("call", []) or [])
    if "UpdateApplication" in call_actions or "DeleteApplication" in call_actions:
        return "unrestricted"
    for m in arc56.get("methods", []):
        actions = set(m.get("actions", {}).get("call", []) or [])
        if "UpdateApplication" in actions or "DeleteApplication" in actions:
            return "unrestricted"
    return "NoOp only"


def _bare_program_info(cache: dict) -> dict:
    return {
        "approval_bytes": cache["approval_bytes"],
        "clear_bytes": cache["clear_bytes"],
        "approval_sha256": cache["approval_sha256"],
        "clear_sha256": cache["clear_sha256"],
        "min_extra_pages": min_extra_pages(cache["approval_bytes"], cache["clear_bytes"]),
        "avm_version": cache["avm_version"],
        "on_completion_gate": cache["on_completion_gate"],
    }


# ---------------------------------------------------------------------------
# M4 -- SyncCommitteeVerifier
# ---------------------------------------------------------------------------
def generate_m4() -> dict:
    from contracts.sync_committee import forks as m4_forks
    from contracts.sync_committee import install as m4_install
    from contracts.sync_committee.constants import (
        BOXES_PER_COMMITTEE,
        G1_UNCOMPRESSED_BYTES,
        KEY_BOX_BYTES,
        KEYS_PER_BOX,
        MIN_BOX_REFS_FOR_INSTALL_OPEN,
        SESSION_BOX_BYTES,
    )

    arc56 = json.loads((REPO_ROOT / "contracts" / "sync_committee" / "SyncCommitteeVerifier.arc56.json").read_text())
    program = _arc56_program_info(arc56)
    program["source"] = None  # filled below, kept out of the compare payload

    global_keys_raw = arc56["state"]["keys"]["global"]
    keys = []
    for name, meta in global_keys_raw.items():
        vt = meta["valueType"]
        keys.append({"key": name, "type": "uint64" if vt == "AVMUint64" else vt})
    n_ints = arc56["state"]["schema"]["global"]["ints"]
    n_bytes = arc56["state"]["schema"]["global"]["bytes"]

    forks_box_name = m4_forks.FORKS_BOX_NAME
    forks_box_bytes = m4_forks.FORKS_BOX_BYTES
    key_box_name_bytes = len(m4_install.KEY_BOX_PREFIX) + 8 + 1  # "k:" + itob(gen) + itob(j)[7:8]
    session_box_name_bytes = len(m4_install.SESSION_BOX_PREFIX) + 8  # "s:" + itob(gen)
    total_box_name_bytes = len(m4_install.TOTAL_BOX_PREFIX) + 8  # "a:" + itob(gen)

    methods = {m["name"]: m for m in arc56["methods"]}

    return {
        "schema_version": 1,
        "contract": "SyncCommitteeVerifier",
        "source": "contracts/sync_committee/verifier.py",
        "design_doc": "docs/design/004-sync-committee.md",
        "program": {k: v for k, v in program.items() if k != "source"},
        "global_state": {
            "schema": {"ints": n_ints, "bytes": n_bytes},
            "creator_mbr_microalgo": global_state_mbr(n_ints, n_bytes),
            "keys": keys,
        },
        "boxes": [
            {
                "family": "fork_table",
                "name": {"literal": forks_box_name.decode(), "name_bytes": len(forks_box_name)},
                "value_bytes": forks_box_bytes,
                "mbr_microalgo": box_mbr(len(forks_box_name), forks_box_bytes),
                "count": 1,
                "created_by": "create",
                "deleted_by": None,
                "lifetime": "permanent -- no deleter exists (§10.4)",
            },
            {
                "family": "committee_keys",
                "name": {"prefix": m4_install.KEY_BOX_PREFIX.decode(),
                          "key": "itob(gen) || itob(j)[7:8]", "name_bytes": key_box_name_bytes},
                "value_bytes": KEY_BOX_BYTES,
                "mbr_microalgo": box_mbr(key_box_name_bytes, KEY_BOX_BYTES),
                "count": f"{BOXES_PER_COMMITTEE} per generation ({KEYS_PER_BOX} keys/box)",
                "created_by": "install_open_keys",
                "deleted_by": "install_abort, retire",
                "lifetime": "permanent while the generation is installed (§10.4)",
            },
            {
                "family": "install_session",
                "name": {"prefix": m4_install.SESSION_BOX_PREFIX.decode(), "key": "itob(gen)",
                          "name_bytes": session_box_name_bytes},
                "value_bytes": SESSION_BOX_BYTES,
                "mbr_microalgo": box_mbr(session_box_name_bytes, SESSION_BOX_BYTES),
                "count": "1 per in-flight session",
                "created_by": "install_open_session",
                "deleted_by": "install_finalize, install_abort",
                "lifetime": "transient -- deleted at session end",
            },
            {
                "family": "aggregate",
                "name": {"prefix": m4_install.TOTAL_BOX_PREFIX.decode(), "key": "itob(gen)",
                          "name_bytes": total_box_name_bytes},
                "value_bytes": G1_UNCOMPRESSED_BYTES,
                "mbr_microalgo": box_mbr(total_box_name_bytes, G1_UNCOMPRESSED_BYTES),
                "count": "1 per installed generation",
                "created_by": "install_finalize",
                "deleted_by": "retire",
                "lifetime": "permanent while the generation is installed (§10.4)",
            },
        ],
        "deploy": {
            "create_signature": _method_signature(methods["create"]),
            "create_creates_boxes": [forks_box_name.decode()],
            "mbr_at_create_microalgo": 100_000 + box_mbr(len(forks_box_name), forks_box_bytes),
            "ordering": [],
            "init_calls": [
                {"method": "append_fork_row", "repeat": "len(fork_rows)", "cursor": "global:fork_count",
                 "append_only": True, "boxes": [forks_box_name.decode()]},
            ],
            "min_box_refs_for_install_open": MIN_BOX_REFS_FOR_INSTALL_OPEN,
        },
        "invariants": [
            "fork table capacity is 16 rows (FORK_TABLE_CAPACITY)",
            "genesis_validators_root is write-once at create, no setter",
        ],
    }


# ---------------------------------------------------------------------------
# M8 -- TrustedRootAnchor
# ---------------------------------------------------------------------------
def generate_m8() -> dict:
    from contracts.state_anchor import constants as m8c
    from contracts.state_anchor import forks as m8_forks

    arc56 = json.loads((REPO_ROOT / "contracts" / "state_anchor" / "TrustedRootAnchor.arc56.json").read_text())
    program = _arc56_program_info(arc56)

    global_keys_raw = arc56["state"]["keys"]["global"]
    keys = []
    for name, meta in global_keys_raw.items():
        vt = meta["valueType"]
        keys.append({"key": name, "type": "uint64" if vt == "AVMUint64" else vt})
    n_ints = arc56["state"]["schema"]["global"]["ints"]
    n_bytes = arc56["state"]["schema"]["global"]["bytes"]

    ring_name_bytes = len(m8c.RING_BOX_PREFIX) + 8  # "h:" + itob(residue)
    pin_name_bytes = len(m8c.PIN_BOX_PREFIX) + 8  # "p:" + itob(block_number)

    methods = {m["name"]: m for m in arc56["methods"]}

    return {
        "schema_version": 1,
        "contract": "TrustedRootAnchor",
        "source": "contracts/state_anchor/anchor_app.py",
        "design_doc": "docs/design/008-trusted-root-anchor.md",
        "program": program,
        "global_state": {
            "schema": {"ints": n_ints, "bytes": n_bytes},
            "creator_mbr_microalgo": global_state_mbr(n_ints, n_bytes),
            "keys": keys,
        },
        "boxes": [
            {
                "family": "fork_table",
                "name": {"literal": m8_forks.FORKS_BOX_NAME.decode(), "name_bytes": len(m8_forks.FORKS_BOX_NAME)},
                "value_bytes": m8c.FORKS_BOX_BYTES,
                "mbr_microalgo": box_mbr(len(m8_forks.FORKS_BOX_NAME), m8c.FORKS_BOX_BYTES),
                "count": 1,
                "created_by": "create",
                "deleted_by": None,
                "lifetime": "permanent -- no deleter exists (§10.4)",
            },
            {
                "family": "ring",
                "name": {"prefix": m8c.RING_BOX_PREFIX.decode(), "key": "itob(el_block_number & (ring_size-1))",
                          "name_bytes": ring_name_bytes},
                "value_bytes": m8c.RECORD_LEN,
                "mbr_microalgo": box_mbr(ring_name_bytes, m8c.RECORD_LEN),
                "count": "ring_size",
                "created_by": "ring_init_chunk",
                "deleted_by": None,
                "lifetime": "permanent -- no deleter exists (§10.4)",
                "record": {
                    "length": m8c.RECORD_LEN,
                    "fields": [
                        {"offset": m8c.OFF_VERSION, "length": m8c.OFF_FLAGS - m8c.OFF_VERSION, "name": "version"},
                        {"offset": m8c.OFF_FLAGS, "length": m8c.OFF_BLOCK_NUMBER - m8c.OFF_FLAGS, "name": "flags",
                         "bits": {"0": "FLAG_REVOKED", "1": "FLAG_HISTORICAL", "2": "FLAG_PINNED"}},
                        {"offset": m8c.OFF_BLOCK_NUMBER, "length": m8c.OFF_BEACON_SLOT - m8c.OFF_BLOCK_NUMBER,
                         "name": "el_block_number", "encoding": "uint64-be"},
                        {"offset": m8c.OFF_BEACON_SLOT, "length": m8c.OFF_STATE_ROOT - m8c.OFF_BEACON_SLOT,
                         "name": "beacon_slot", "encoding": "uint64-be"},
                        {"offset": m8c.OFF_STATE_ROOT, "length": m8c.OFF_RECEIPTS_ROOT - m8c.OFF_STATE_ROOT,
                         "name": "el_state_root"},
                        {"offset": m8c.OFF_RECEIPTS_ROOT, "length": m8c.OFF_BEACON_BLOCK_ROOT - m8c.OFF_RECEIPTS_ROOT,
                         "name": "el_receipts_root"},
                        {"offset": m8c.OFF_BEACON_BLOCK_ROOT, "length": m8c.OFF_FINALITY_ROOT - m8c.OFF_BEACON_BLOCK_ROOT,
                         "name": "beacon_block_root"},
                        {"offset": m8c.OFF_FINALITY_ROOT, "length": m8c.OFF_ANCHORED_ROUND - m8c.OFF_FINALITY_ROOT,
                         "name": "finality_root"},
                        {"offset": m8c.OFF_ANCHORED_ROUND, "length": m8c.RECORD_LEN - m8c.OFF_ANCHORED_ROUND,
                         "name": "anchored_round", "encoding": "uint64-be"},
                    ],
                },
            },
            {
                "family": "pinned",
                "name": {"prefix": m8c.PIN_BOX_PREFIX.decode(), "key": "itob(block_number)",
                          "name_bytes": pin_name_bytes},
                "value_bytes": m8c.PINNED_RECORD_LEN,
                "mbr_microalgo": box_mbr(pin_name_bytes, m8c.PINNED_RECORD_LEN),
                "count": "unbounded",
                "created_by": "pin (self-funded)",
                "deleted_by": "unpin (refunds the payer)",
                "lifetime": "until unpin",
            },
        ],
        "deploy": {
            "create_signature": _method_signature(methods["create"]),
            "create_creates_boxes": [m8_forks.FORKS_BOX_NAME.decode()],
            "mbr_at_create_microalgo": 100_000 + box_mbr(len(m8_forks.FORKS_BOX_NAME), m8c.FORKS_BOX_BYTES),
            "ordering": ["m4 must already exist (m4_app_id is write-once)"],
            "init_calls": [
                {"method": "ring_init_chunk", "repeat": "ceil(ring_size/8)", "max_boxes_per_call": 8,
                 "cursor": "global:ring_cursor", "completion": "ring_cursor == ring_size => frozen := 0"},
                {"method": "append_fork_row", "repeat": "len(fork_rows)", "cursor": "global:fork_count",
                 "append_only": True, "boxes": [m8_forks.FORKS_BOX_NAME.decode()]},
            ],
        },
        "invariants": [
            "ring_size is a nonzero power of two (asserted at create)",
            "no method takes a ring_size/resize argument (asserted against the ARC-56 method list)",
        ],
    }


def _assert_no_resize_method(arc56: dict) -> None:
    names = {m["name"] for m in arc56["methods"]}
    resize_like = {n for n in names if "resize" in n.lower() or "ring_n" in n.lower()}
    assert not resize_like, f"unexpected resize-like method(s) found: {resize_like}"


# ---------------------------------------------------------------------------
# M7 -- Mpt7ReceiptApp (bare Contract; no global state, no permanent boxes)
# ---------------------------------------------------------------------------
def generate_m7() -> dict:
    from contracts.receipt.box import MAX_STAGED_LEAF, MIN_STAGED_LEAF

    cache = load_bare_contract_cache("Mpt7ReceiptApp")
    program = _bare_program_info(cache)
    max_value_bytes = MAX_STAGED_LEAF
    min_value_bytes = MIN_STAGED_LEAF
    t2_name_bytes = 8

    return {
        "schema_version": 1,
        "contract": "Mpt7ReceiptApp",
        "source": "contracts/receipt/bench_app.py",
        "design_doc": "docs/design/007-receipt-log-proof.md",
        "program": program,
        "global_state": {"schema": {"ints": 0, "bytes": 0}, "creator_mbr_microalgo": global_state_mbr(0, 0), "keys": []},
        "boxes": [
            {
                "family": "t2_staging",
                "name": {"caller_chosen": True, "name_bytes": t2_name_bytes},
                "value_bytes": f"[{min_value_bytes + 1}, {max_value_bytes}]",
                "mbr_microalgo_max": box_mbr(t2_name_bytes, max_value_bytes),
                "count": "0 or 1, transient, per T2 proof",
                "created_by": "MODE_STAGE_OPEN",
                "deleted_by": "mpt7_stage_close (same atomic group)",
                "lifetime": "transient -- opened and closed inside one atomic group (§11.6)",
            },
        ],
        "deploy": {
            "create_signature": None,
            "create_creates_boxes": [],
            "mbr_at_create_microalgo": 100_000,
            "ordering": [],
            "init_calls": [],
            "t2_float_microalgo": 100_000 + box_mbr(t2_name_bytes, max_value_bytes),
        },
        "invariants": [
            "no permanent boxes, no global state, no governance surface",
            f"T2 staged leaf length is in [{min_value_bytes + 1}, {max_value_bytes}] bytes",
        ],
    }


# ---------------------------------------------------------------------------
# M6 -- Mpt6ComposerApp (bare Contract; no global state, no boxes at all)
# ---------------------------------------------------------------------------
def generate_m6() -> dict:
    cache = load_bare_contract_cache("Mpt6ComposerApp")
    program = _bare_program_info(cache)
    return {
        "schema_version": 1,
        "contract": "Mpt6ComposerApp",
        "source": "contracts/composer/bench_app.py",
        "design_doc": "docs/design/006-account-storage-proof.md",
        "program": program,
        "global_state": {"schema": {"ints": 0, "bytes": 0}, "creator_mbr_microalgo": global_state_mbr(0, 0), "keys": []},
        "boxes": [],
        "deploy": {
            "create_signature": None,
            "create_creates_boxes": [],
            "mbr_at_create_microalgo": 100_000,
            "ordering": [],
            "init_calls": [],
        },
        "invariants": [
            "no global state, no boxes, no governance surface",
            "budget donors are self-issued (donor_count/donor_app_id passed per call, 009 §7.1)",
        ],
    }


GENERATORS = {
    "SyncCommitteeVerifier": generate_m4,
    "TrustedRootAnchor": generate_m8,
    "Mpt7ReceiptApp": generate_m7,
    "Mpt6ComposerApp": generate_m6,
}


def generate_all() -> dict[str, dict]:
    return {name: fn() for name, fn in GENERATORS.items()}


def _dump(schema: dict) -> str:
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


# ---------------------------------------------------------------------------
# `deploy/versions.json` (design doc 012 §3.4-§3.6): the contract-versioning
# artifact. Generated from the same schemas/caches above -- never hand-typed
# (§17 item 4) -- and diffed by the same `deploy schema --check` gate.
#
# `versions.json` lives at `deploy/versions.json`, one level up from this
# file's own `deploy/schema/` directory (012 §16's file layout).
# ---------------------------------------------------------------------------
VERSIONS_PATH = SCHEMA_DIR.parent / "versions.json"

# Real mainnet fork range (deploy/forks.py::FORK_FIELD_COUNTS), 012 §14.2's
# correction of ARCHITECTURE.md's original "Altair/Capella/Deneb" guess.
FORK_SUPPORTED = ["deneb", "electra", "fulu"]
FORK_UNSUPPORTED = ["gloas"]

# Cited reasons (012 §3.4's own example, verbatim) -- each names a real
# section, not a shrug (§3.4 property 2).
M8_GLOAS_REASON = (
    "008 NG3 / §10.5: a depth-11 EL branch pushes HISTORICAL's argument payload over "
    "the 2,048 B cap. O-M8-4, not approved."
)
M4_GLOAS_REASON = (
    "004 §4.5 normative: the Gloas row MUST NOT be appended until its gindices are "
    "confirmed against vendored Gloas vectors; 003 §2.6 measures a depth-11 branch at "
    "738 > the 700 single-call limit, so group sizing must change too."
)

# 012 §0: the first real, green `ci-live.yml` run in this project's history
# (G1-M12) -- cited here as the AVM axis's evidence, alongside the pinned
# ALGOD_IMAGE digest comment in the workflow file itself.
CI_LIVE_G1_M12_RUN_ID = "31229821639"


def _existing_release() -> str | None:
    """`release` is the ONE hand-set field in versions.json (012 §3.4
    property 3) -- set once, at tag time, by the release runbook
    (docs/release.md). Regenerating the file must carry it forward
    unchanged; every other field is derived fresh below."""
    if not VERSIONS_PATH.exists():
        return None
    try:
        return json.loads(VERSIONS_PATH.read_text()).get("release")
    except (json.JSONDecodeError, OSError):
        return None


def generate_versions() -> dict:
    schemas = generate_all()
    m4, m8 = schemas["SyncCommitteeVerifier"], schemas["TrustedRootAnchor"]
    m7, m6 = schemas["Mpt7ReceiptApp"], schemas["Mpt6ComposerApp"]

    contracts = {
        "TrustedRootAnchor": {
            "code_id": m8["program"]["approval_sha256"],
            "approval_bytes": m8["program"]["approval_bytes"],
            "source": m8["source"],
            "design_doc": m8["design_doc"],
            "fork_axis": "table",
            "code_window": {
                "supported": list(FORK_SUPPORTED),
                "unsupported": list(FORK_UNSUPPORTED),
                "reason": M8_GLOAS_REASON,
                "table_capacity_rows": 8,
            },
            "consumers_bound_at_compile_time": True,  # TP-M8-4
            "redeploy_cascades_to": ["every M8 consumer"],
        },
        "SyncCommitteeVerifier": {
            "code_id": m4["program"]["approval_sha256"],
            "approval_bytes": m4["program"]["approval_bytes"],
            # 010 §4.6/010:577, promoted to a standing versioning constraint
            # by 012 §3.3: how much room a future fork's CODE change has
            # before it fits nowhere and cascades into M8 and every consumer.
            "bytecode_cap_headroom_bytes": 8192 - m4["program"]["approval_bytes"],
            "source": m4["source"],
            "design_doc": m4["design_doc"],
            "fork_axis": "table",
            "code_window": {
                "supported": list(FORK_SUPPORTED),
                "unsupported": list(FORK_UNSUPPORTED),
                "reason": M4_GLOAS_REASON,
                "table_capacity_rows": 16,
            },
        },
        "Mpt7ReceiptApp": {
            "code_id": m7["program"]["approval_sha256"],
            "approval_bytes": m7["program"]["approval_bytes"],
            "source": m7["source"],
            "design_doc": m7["design_doc"],
            # M2/M5/M6/M7 version on AVM only (003 §9, adopted+extended by
            # 012 §3.2): execution-layer RLP/MPT encodings move with no
            # consensus fork.
            "fork_axis": "none",
            "tiers": ["T1", "T2"],
            "proof_system": None,  # axis C, empty in v1 -- no T3 prover ships (§1.2 item 3)
        },
        "Mpt6ComposerApp": {
            "code_id": m6["program"]["approval_sha256"],
            "approval_bytes": m6["program"]["approval_bytes"],
            "source": m6["source"],
            "design_doc": m6["design_doc"],
            "fork_axis": "none",
        },
    }

    # 012 §3.4's "two gaps": MptSegmentApp and the donor pair have no
    # ARC-56 artifact (bare `Contract`s) and previously had no compiled-
    # artifact cache either, so their code_id could not be filled offline
    # (§15 gap 5). Closed this pass by running
    # `deploy.compile.refresh_bare_contract_cache` against a real, reachable
    # algod (mainnet-api.algonode.cloud's public /v2/teal/compile) -- no
    # signer, no deployment, just a real compile of already-public source.
    for name in ("MptSegmentApp", "DonorIssuer", "DonorCallee"):
        try:
            cache = load_bare_contract_cache(name)
        except FileNotFoundError:
            contracts[name] = {
                "code_id": None,
                "fork_axis": "none",
                "note": (
                    "no compiled-artifact cache -- run "
                    "deploy.compile.refresh_bare_contract_cache against a live algod "
                    "(012 §3.4/§15 gap 5)"
                ),
            }
            continue
        contracts[name] = {
            "code_id": cache["approval_sha256"],
            "approval_bytes": cache["approval_bytes"],
            "source": cache["source"],
            "fork_axis": "none",
        }

    return {
        "versions_version": 1,
        "release": _existing_release(),
        "generated_by": "python -m deploy schema",
        "avm": {
            "version": m4["program"]["avm_version"],
            "measured_against": "go-algorand 4.7.4 (91cbddcd, rel/stable)",
            "evidence": (
                ".github/workflows/ci-live.yml ALGOD_IMAGE digest comment; "
                f"ci-live run {CI_LIVE_G1_M12_RUN_ID} (first real green run, G1-M12, "
                "docs/design/012-docs-packaging-release.md §0)"
            ),
        },
        "contracts": contracts,
    }


def write_versions() -> Path:
    VERSIONS_PATH.write_text(_dump(generate_versions()))
    return VERSIONS_PATH


def check_versions() -> bool:
    """True if `deploy/versions.json` is byte-identical to a fresh
    regeneration (G3-M12)."""
    if not VERSIONS_PATH.exists():
        return False
    return VERSIONS_PATH.read_text() == _dump(generate_versions())


def write_all(out_dir: Path | None = None) -> list[Path]:
    out_dir = out_dir or SCHEMA_DIR
    written = []
    for name, schema in generate_all().items():
        path = out_dir / f"{name}.schema.json"
        path.write_text(_dump(schema))
        written.append(path)
    written.append(write_versions())
    return written


def check(out_dir: Path | None = None) -> list[str]:
    """§3.4's CI gate (G3-M10, extended by G3-M12): regenerate every
    artifact in memory and diff against the committed files, including
    `deploy/versions.json`. Returns a list of mismatching contract names
    (empty = clean)."""
    out_dir = out_dir or SCHEMA_DIR
    mismatches = []
    for name, schema in generate_all().items():
        path = out_dir / f"{name}.schema.json"
        expected = _dump(schema)
        if not path.exists() or path.read_text() != expected:
            mismatches.append(name)
    if not check_versions():
        mismatches.append("versions.json")
    return mismatches


if __name__ == "__main__":
    written = write_all()
    for p in written:
        print(f"wrote {p}")
