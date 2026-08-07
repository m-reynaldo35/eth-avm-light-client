"""Suite X (design doc §13.1): the schema artifact, offline. Pure imports --
no algod, no network, no `puyapy` (the bare-`Contract` compiled sizes are
read from the committed `deploy/schema/_compiled/*.compiled.json` cache,
`deploy/compile.py`'s module docstring explains why that cache -- not a
live `puyapy`/algod call -- is what keeps this suite genuinely offline).
"""
from __future__ import annotations

import json
from pathlib import Path

from deploy.schema import generate

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# X-1 (G3-M10): regenerates byte-identically.
# ---------------------------------------------------------------------------
def test_x1_schema_check_is_clean():
    mismatches = generate.check()
    assert mismatches == [], f"schema drift detected for: {mismatches} -- run `python -m deploy schema` to regenerate"


def test_x1_generated_files_match_committed_files_byte_for_byte():
    for name, schema in generate.generate_all().items():
        path = generate.SCHEMA_DIR / f"{name}.schema.json"
        assert path.exists(), f"{path} missing -- run `python -m deploy schema`"
        assert path.read_text() == generate._dump(schema)


# ---------------------------------------------------------------------------
# X-2: every box value_bytes vs the contract's own constant.
# ---------------------------------------------------------------------------
def test_x2_box_value_bytes_match_contract_constants():
    m4 = generate.generate_m4()
    by_family = {b["family"]: b for b in m4["boxes"]}
    assert by_family["fork_table"]["value_bytes"] == 576
    assert by_family["committee_keys"]["value_bytes"] == 6144
    assert by_family["install_session"]["value_bytes"] == 424
    assert by_family["aggregate"]["value_bytes"] == 96

    m8 = generate.generate_m8()
    by_family8 = {b["family"]: b for b in m8["boxes"]}
    assert by_family8["fork_table"]["value_bytes"] == 320
    assert by_family8["ring"]["value_bytes"] == 154
    assert by_family8["pinned"]["value_bytes"] == 186


# ---------------------------------------------------------------------------
# X-3: record-offset table vs `contracts/state_anchor/constants.py`.
# ---------------------------------------------------------------------------
def test_x3_record_offsets_match_constants_py():
    from contracts.state_anchor import constants as m8c

    m8 = generate.generate_m8()
    ring = next(b for b in m8["boxes"] if b["family"] == "ring")
    offs = {f["name"]: f["offset"] for f in ring["record"]["fields"]}
    assert offs["version"] == m8c.OFF_VERSION
    assert offs["flags"] == m8c.OFF_FLAGS
    assert offs["el_block_number"] == m8c.OFF_BLOCK_NUMBER
    assert offs["beacon_slot"] == m8c.OFF_BEACON_SLOT
    assert offs["el_state_root"] == m8c.OFF_STATE_ROOT
    assert offs["el_receipts_root"] == m8c.OFF_RECEIPTS_ROOT
    assert offs["beacon_block_root"] == m8c.OFF_BEACON_BLOCK_ROOT
    assert offs["finality_root"] == m8c.OFF_FINALITY_ROOT
    assert offs["anchored_round"] == m8c.OFF_ANCHORED_ROUND
    assert ring["record"]["length"] == m8c.RECORD_LEN == 154


# ---------------------------------------------------------------------------
# X-4: MBR model vs the protocol formula, for every family.
# ---------------------------------------------------------------------------
def test_x4_mbr_model_matches_every_box_family():
    m4 = generate.generate_m4()
    by_family = {b["family"]: b for b in m4["boxes"]}
    assert by_family["fork_table"]["mbr_microalgo"] == 234_900
    assert by_family["committee_keys"]["mbr_microalgo"] == 2_464_500
    assert by_family["install_session"]["mbr_microalgo"] == 176_100
    assert by_family["aggregate"]["mbr_microalgo"] == 44_900

    m8 = generate.generate_m8()
    by_family8 = {b["family"]: b for b in m8["boxes"]}
    assert by_family8["fork_table"]["mbr_microalgo"] == 132_900
    assert by_family8["ring"]["mbr_microalgo"] == 68_100
    assert by_family8["pinned"]["mbr_microalgo"] == 80_900


# ---------------------------------------------------------------------------
# X-5: min_extra_pages vs the compiled sizes (§4.6).
# ---------------------------------------------------------------------------
def test_x5_min_extra_pages():
    schemas = generate.generate_all()
    assert schemas["SyncCommitteeVerifier"]["program"]["min_extra_pages"] == 3
    assert schemas["TrustedRootAnchor"]["program"]["min_extra_pages"] == 1
    assert schemas["Mpt7ReceiptApp"]["program"]["min_extra_pages"] == 1
    assert schemas["Mpt6ComposerApp"]["program"]["min_extra_pages"] == 1


# ---------------------------------------------------------------------------
# X-6: global-state schema vs the ARC-56 artifacts.
# ---------------------------------------------------------------------------
def test_x6_global_state_schema_and_mbr():
    m4 = generate.generate_m4()
    assert m4["global_state"]["schema"] == {"ints": 13, "bytes": 7}
    assert m4["global_state"]["creator_mbr_microalgo"] == 820_500

    m8 = generate.generate_m8()
    assert m8["global_state"]["schema"] == {"ints": 9, "bytes": 1}
    assert m8["global_state"]["creator_mbr_microalgo"] == 406_500


# ---------------------------------------------------------------------------
# X-7: both fork-row shapes round-trip.
# ---------------------------------------------------------------------------
def test_x7_fork_row_shapes_are_declared_distinctly():
    from contracts.sync_committee.forks import FORK_ROW_BYTES as M4_ROW_BYTES
    from contracts.state_anchor.constants import FORK_ROW_BYTES as M8_ROW_BYTES

    assert M4_ROW_BYTES == 36  # activation_epoch(8) + fork_version(4) + 3*uint64(8)
    assert M8_ROW_BYTES == 40  # 5 * uint64(8)

    from deploy.forks import m4_fork_row, m8_fork_row

    m4_row = m4_fork_row("fulu", 364032, b"\x05\x00\x00\x00")
    assert len(m4_row.fork_version) == 4
    m8_row = m8_fork_row("fulu", 364032)
    assert isinstance(m8_row.g_state_root, int)


# ---------------------------------------------------------------------------
# The three real drifts §3.3 says the artifact would have caught.
# ---------------------------------------------------------------------------
def test_drift_1_ring_size_not_ring_n():
    m8 = generate.generate_m8()
    keys = {k["key"] for k in m8["global_state"]["keys"]}
    assert "ring_size" in keys
    assert "ring_n" not in keys


def test_drift_2_forks8_is_320_bytes_not_321():
    m8 = generate.generate_m8()
    fork_table = next(b for b in m8["boxes"] if b["family"] == "fork_table")
    assert fork_table["value_bytes"] == 320
    assert fork_table["mbr_microalgo"] == 132_900


def test_drift_3_creator_mbr_is_406500_not_378000():
    m8 = generate.generate_m8()
    assert m8["global_state"]["creator_mbr_microalgo"] == 406_500
    assert m8["global_state"]["schema"] == {"ints": 9, "bytes": 1}


# ---------------------------------------------------------------------------
# The M6/M7 compiled-size drift this pass itself introduced (honest note):
# the design doc's own §4.6 measurement (2,676 / 3,104 B) predates the
# OnCompletion security fix (a separate same-day pass, ROADMAP.md's M5/M6/M7
# rows) that added a 4-byte `assert Txn.on_completion == NoOp` check to each
# bare-`Contract` driver. The schema now correctly reflects the CURRENT,
# fixed bytecode -- 4 bytes larger each -- not the design doc's stale
# pre-fix citation.
# ---------------------------------------------------------------------------
def test_m6_m7_sizes_reflect_the_oncompletion_fix_not_the_stale_design_doc_number():
    schemas = generate.generate_all()
    assert schemas["Mpt6ComposerApp"]["program"]["approval_bytes"] == 2680  # design doc cited 2,676 pre-fix
    assert schemas["Mpt7ReceiptApp"]["program"]["approval_bytes"] == 3108  # design doc cited 3,104 pre-fix


def test_on_completion_gate_is_noop_only_for_all_four_current_contracts():
    """§9.1's finding is about the OLD, vulnerable bytecode. The security
    fix already landed (ROADMAP.md's M5/M6/M7 rows, same day as this
    design doc's approval) -- so ALL FOUR deployable contracts' schemas
    must now report "NoOp only", not "unrestricted". Suite S
    (test_security_matrix.py) asserts the live on-chain behaviour matches."""
    schemas = generate.generate_all()
    for name, schema in schemas.items():
        assert schema["program"]["on_completion_gate"] == "NoOp only", (
            f"{name} reports {schema['program']['on_completion_gate']!r} -- "
            "expected the post-fix state"
        )
