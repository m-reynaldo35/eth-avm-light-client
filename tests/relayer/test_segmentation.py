"""Suite P (design doc §13.1), continued: segmentation-specific tests
(M6's account/storage packer, M7's MODE_INIT/MODE_NEXT splitter). Pure,
offline, no network/algod.
"""
from __future__ import annotations

import json
from pathlib import Path

from relayer.drivers.m7_receipt import plan_receipt_calls
from relayer.proofs.account import (
    MODE_A_INIT_MAX_NODE_ARGS,
    MODE_A_INIT_NODE_BUDGET_BYTES,
    OTHER_MODE_MAX_NODE_ARGS,
    OTHER_MODE_NODE_BUDGET_BYTES,
    _segment_nodes,
    segment_account_proof,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ETH_DATA_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "spike-reference" / "eth_data.json"


def _load_fixture() -> dict:
    with open(ETH_DATA_FIXTURE) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# P-5: M6 segmentation of the pinned real USDT/Binance-8 proof -- must
# reproduce 006 §6.5's exact 5-segment split byte-for-byte. This is G3-M9.
# ---------------------------------------------------------------------------
def test_p5_g3_m9_usdt_binance8_segmentation_matches_006_section_6_5():
    d = _load_fixture()
    proof = d["proof"]
    assert len(proof["accountProof"]) == 8
    assert len(proof["storageProof"][0]["proof"]) == 9

    segs = segment_account_proof(proof, declared_state_root=bytes.fromhex(d["stateRoot"][2:]))
    assert segs.account_included is True
    assert segs.storage_included is True

    modes_and_bytes = [(s.mode, sum(len(n) for n in s.nodes)) for s in segs.segments]
    # 006 §6.5's own citation: 1,596 / 1,596 / 540 node bytes across three
    # phase-A segments, then phase B (2 more segments) -- 5 total.
    assert len(segs.segments) == 5
    phase_a = [b for m, b in modes_and_bytes if m in ("A_INIT", "A_NEXT")]
    assert phase_a == [1596, 1596, 540]
    assert modes_and_bytes[0][0] == "A_INIT"
    assert all(m == "A_NEXT" for m, _ in modes_and_bytes[1:3])
    assert modes_and_bytes[3][0] == "B_INIT"
    assert modes_and_bytes[4][0] == "B_NEXT"


# ---------------------------------------------------------------------------
# P-6: MODE_A_INIT's 1,943 B cap vs other modes' 2,019 B cap -- a node set
# sized to fit under 2,019 but NOT under 1,943 must split differently
# depending on which cap the FIRST segment uses (proves the 006 §7.1
# "13-byte finding": never "2,048 minus a round number").
# ---------------------------------------------------------------------------
def test_p6_mode_a_init_and_other_mode_caps_differ():
    # Two synthetic nodes whose combined size sits strictly between the two
    # caps: fits OTHER_MODE's budget (2,019) in one call, but NOT
    # MODE_A_INIT's smaller budget (1,943) -- so the SAME node list must
    # split into 1 call under the "other" cap and 2 calls under the
    # MODE_A_INIT cap.
    target_total = MODE_A_INIT_NODE_BUDGET_BYTES + 30  # > 1943, < 2019
    assert target_total < OTHER_MODE_NODE_BUDGET_BYTES
    nodes = [b"\x11" * (target_total // 2), b"\x22" * (target_total - target_total // 2)]

    as_first_group = _segment_nodes(
        nodes, MODE_A_INIT_NODE_BUDGET_BYTES, MODE_A_INIT_MAX_NODE_ARGS,
        OTHER_MODE_NODE_BUDGET_BYTES, OTHER_MODE_MAX_NODE_ARGS,
    )
    as_other_group = _segment_nodes(
        nodes, OTHER_MODE_NODE_BUDGET_BYTES, OTHER_MODE_MAX_NODE_ARGS,
        OTHER_MODE_NODE_BUDGET_BYTES, OTHER_MODE_MAX_NODE_ARGS,
    )
    assert len(as_first_group) == 2, "must split under MODE_A_INIT's smaller 1,943 B budget"
    assert len(as_other_group) == 1, "must fit in one call under the other modes' 2,019 B budget"


def test_p6_max_node_args_per_call_also_differs():
    # 10 tiny nodes: fits MODE_A_INIT's 9-node-arg cap only across 2 calls,
    # but a single OTHER-mode call (11-node-arg cap) fits it in one.
    nodes = [b"\x01"] * 10
    as_first_group = _segment_nodes(
        nodes, MODE_A_INIT_NODE_BUDGET_BYTES, MODE_A_INIT_MAX_NODE_ARGS,
        OTHER_MODE_NODE_BUDGET_BYTES, OTHER_MODE_MAX_NODE_ARGS,
    )
    as_other_group = _segment_nodes(
        nodes, OTHER_MODE_NODE_BUDGET_BYTES, OTHER_MODE_MAX_NODE_ARGS,
        OTHER_MODE_NODE_BUDGET_BYTES, OTHER_MODE_MAX_NODE_ARGS,
    )
    assert len(as_first_group) == 2
    assert len(as_other_group) == 1


# ---------------------------------------------------------------------------
# P-7: M7 T1 splitting across MODE_INIT + MODE_NEXT (fixes D2 -- the old
# `m7_relayer.py` raised rather than splitting above 2,000 argument bytes).
# `prev_gi` must chain to the REAL producing index, not a fixed offset.
# ---------------------------------------------------------------------------
def test_p7_m7_t1_splits_oversized_node_set_across_mode_next():
    # Real T1 leaf boundary is 1,942 B; construct several nodes whose SUM
    # exceeds one call's real byte budget but whose leaf individually
    # stays under ARG_BUDGET, forcing a MODE_INIT + MODE_NEXT split (D2).
    nodes = [b"\xaa" * 900, b"\xbb" * 900, b"\xcc" * 900, b"\xdd" * 500]  # leaf = last, 500 B < 1942
    tier, calls = plan_receipt_calls(receipts_root=b"\x01" * 32, tx_index=5, log_index=0, nodes=nodes)
    assert tier == "T1"
    assert len(calls) >= 2, "D2's whole point: an oversized T1 node set must split, not raise"
    assert calls[0].args[0] == b"RCP1" and calls[0].args[1] == bytes([0])  # MODE_INIT
    for i, call in enumerate(calls[1:], start=1):
        assert call.args[1] == bytes([1]), "every call after the first must be MODE_NEXT"
        prev = call.args[2][0]
        assert prev == i - 1, "prev_gi must chain to the REAL producing call index, not a fixed offset"
    assert calls[-1].produces_log is True
    assert all(not c.produces_log for c in calls[:-1])


def test_p7_m7_t1_single_call_when_it_fits():
    nodes = [b"\x01" * 100, b"\x02" * 200]
    tier, calls = plan_receipt_calls(receipts_root=b"\x02" * 32, tx_index=1, log_index=0, nodes=nodes)
    assert tier == "T1"
    assert len(calls) == 1
    assert calls[0].produces_log is True
