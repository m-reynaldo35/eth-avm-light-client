"""Suite G (design doc §13.2): gindex generation, offline. G4-M10's whole
claim -- every fork-row gindex is GENERATED and reproduces all seven
independently-confirmed real values this project's own live testing already
established (169/86/87/802/803/806/69, plus Deneb's 37).
"""
from __future__ import annotations

import pytest

from deploy.forks import (
    EXECUTION_BLOCK_HASH_GINDEX_DENEB,
    ForkGindexError,
    m4_fork_row,
    m8_fork_row,
)
from relayer.ssz.beacon_state import FULU_FIELDS
from relayer.ssz.execution_payload import FIELD_INDEX


# ---------------------------------------------------------------------------
# G-1: m4_fork_row("fulu") reproduces the exact values
# tests/sync_committee/test_live_e2e_finality.py hand-entered.
# ---------------------------------------------------------------------------
def test_g1_m4_fulu_gindices():
    row = m4_fork_row("fulu", 364032, b"\x06\x00\x00\x00")
    assert row.finality_gindex == 169
    assert row.current_sc_gindex == 86
    assert row.next_sc_gindex == 87
    assert row.activation_epoch == 364032
    assert row.fork_version == b"\x06\x00\x00\x00"


# ---------------------------------------------------------------------------
# G-2 / G-3: m8_fork_row for fulu and deneb.
# ---------------------------------------------------------------------------
def test_g2_m8_fulu_gindices():
    row = m8_fork_row("fulu", 364032)
    assert (row.g_state_root, row.g_receipts_root, row.g_block_number, row.g_block_roots_base) == (802, 803, 806, 69)


def test_g3_m8_deneb_gindices_the_two_row_trap():
    row = m8_fork_row("deneb", 269568)
    # Same execution gindices (ExecutionPayload shape unchanged across
    # Deneb/Electra/Fulu) but a DIFFERENT g_block_roots_base (37, not 69) --
    # 008 §3.4's "two-row trap", the single most important fact this table
    # encodes.
    assert (row.g_state_root, row.g_receipts_root, row.g_block_number) == (802, 803, 806)
    assert row.g_block_roots_base == 37


def test_g2_g3_electra_matches_fulu_at_depth_6():
    # Electra (37 fields) rounds to the same 64-leaf/depth-6 tree as Fulu
    # (38 fields) -- both give g_block_roots_base = 69, the design doc's own
    # "IDENTICAL to Electra's own value, for the same reason" note.
    row = m8_fork_row("electra", 364032)
    assert row.g_block_roots_base == 69


# ---------------------------------------------------------------------------
# G-4: block_hash cross-check reproduces the spec-published value; refuses
# to emit a row otherwise.
# ---------------------------------------------------------------------------
def test_g4_block_hash_cross_check_reproduces_published_gindex():
    from relayer.ssz.execution_payload import EXECUTION_PAYLOAD_DEPTH, EXECUTION_PAYLOAD_GINDEX

    composed = EXECUTION_PAYLOAD_GINDEX * (1 << EXECUTION_PAYLOAD_DEPTH) + FIELD_INDEX["block_hash"]
    assert composed == EXECUTION_BLOCK_HASH_GINDEX_DENEB == 812


def test_g4_refuses_to_emit_when_cross_check_fails():
    corrupted_field_index = dict(FIELD_INDEX)
    corrupted_field_index["block_hash"] = 11  # wrong on purpose
    with pytest.raises(ForkGindexError, match="block_hash cross-check failed"):
        m8_fork_row("fulu", 364032, field_index=corrupted_field_index)


# ---------------------------------------------------------------------------
# G-5: field-list sanity -- Fulu's list really is 38 entries (the base this
# module slices for Deneb/Electra), and a live spec fetch (best-effort,
# skips if unreachable, mirroring tests/state_anchor/test_forks.py) confirms
# the real activation epochs.
# ---------------------------------------------------------------------------
def test_g5_fulu_field_list_is_38_entries():
    assert len(FULU_FIELDS) == 38
    assert FULU_FIELDS.index("block_roots") == 5


@pytest.mark.needs_network
def test_g5_live_spec_fetch_confirms_activation_epochs_or_skips():
    from deploy.forks import KNOWN_ACTIVATION_EPOCHS, fetch_fork_activation_epochs

    fetched = fetch_fork_activation_epochs()
    if fetched is None:
        pytest.skip("no beacon API reachable for a live /eth/v1/config/spec fetch")
    assert fetched["deneb"] == KNOWN_ACTIVATION_EPOCHS["deneb"] == 269568
    assert fetched["electra"] == KNOWN_ACTIVATION_EPOCHS["electra"] == 364032


# ---------------------------------------------------------------------------
# G-6: a deliberately corrupted field list -- generator refuses, does not
# emit a plausible-looking wrong gindex.
# ---------------------------------------------------------------------------
def test_g6_corrupted_field_list_is_refused_not_silently_wrong():
    truncated = FULU_FIELDS[:10]  # too short for "fulu"'s declared 38-field count
    with pytest.raises(ForkGindexError, match="exceeds the available field list"):
        m4_fork_row("fulu", 364032, b"\x06\x00\x00\x00", field_list=truncated)
    with pytest.raises(ForkGindexError, match="exceeds the available field list"):
        m8_fork_row("fulu", 364032, field_list=truncated)


def test_g6_unknown_fork_name_is_refused():
    with pytest.raises(ForkGindexError, match="unknown fork"):
        m4_fork_row("shanghai", 0, b"\x00\x00\x00\x00")
