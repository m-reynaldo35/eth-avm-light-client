"""`plan_box_refs` -- design doc §7.4, THE fix. Derives the closed-form box-
reference rule that exactly explains both live box-budget failures hit in
this project's own history (6144 and 18432, k=2 and k=8 key boxes touched)
and shows the shipped 2-transaction `submit_update` group is structurally
incapable of a worst-case real committee update.

Per §18 item 2: no fixed box-reference constant ships anywhere in this
module. A fixed constant has been wrong twice already in this codebase's
own history (`test_live_e2e.py`'s `(6144)` failure, `test_live_historical.
py`'s `(18432)` failure) -- `plan_box_refs` computes `refs`/`txns_min` from
the real, declared box sizes every time, never a hardcoded number.

The two independent caps this reasons about (§7.3, `contracts/
sync_committee/constants.py:110-153`, MEASURED against real dev-mode
algod, not read off documentation):
  * `MAX_BOX_REFS_PER_TXN = 8` -- structural per-TRANSACTION cap
    ("tx.Boxes too long, max number of box references is 8").
  * `BOX_WRITE_BUDGET_BYTES_PER_REF = 2048` -- a byte budget POOLED ACROSS
    THE WHOLE ATOMIC GROUP, charged at a box's FULL DECLARED SIZE once per
    box per group, regardless of how few bytes are actually touched.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from math import ceil

MAX_BOX_REFS_PER_TXN = 8
BOX_WRITE_BUDGET_BYTES_PER_REF = 2048
MAX_TXNS_PER_GROUP = 16


@dataclass(frozen=True)
class BoxRefPlan:
    distinct_boxes: tuple[str, ...]  # box names as opaque strings (hex or raw), for the caller to map to real refs
    total_declared_bytes: int
    refs_required: int
    txns_required: int
    fits_in_group: bool  # False if txns_required + other_real_txns > 16 (see .check_fits)

    def check_fits(self, other_real_txns: int, *, max_group_txns: int = MAX_TXNS_PER_GROUP) -> None:
        total = self.txns_required + other_real_txns
        if total > max_group_txns:
            raise ValueError(
                f"box-reference plan needs {self.txns_required} filler/padding transaction(s) "
                f"(refs_required={self.refs_required}) on top of {other_real_txns} real transaction(s) "
                f"= {total}, exceeding the {max_group_txns}-transaction group cap"
            )


def plan_box_refs(box_sizes: dict[str, int]) -> BoxRefPlan:
    """§7.4's exact closed form:

        distinct  = set of boxes any transaction in the group will touch
        bytes     = sum(declared_size(b) for b in distinct)   # FULL size, once per box
        refs      = max(len(distinct), ceil(bytes / 2048))
        txns_min  = ceil(refs / 8)

    `box_sizes` maps each DISTINCT box name this group will touch to its
    real declared size in bytes (duplicate touches of the same box within
    a group do not add a second entry here -- term 1 counts each box once;
    §9.3's "resumed install_chunk re-touches a key box, needs 4 refs not
    2" case is expressed by the CALLER choosing to list that box's name
    twice under two different opaque keys if it wants two references
    costed, matching §13.5 BX-3's "duplicate refs to the same box each
    count" finding -- `plan_box_refs` itself computes the MINIMUM refs a
    correct plan needs; a caller may always spend more."""
    if not box_sizes:
        return BoxRefPlan(distinct_boxes=(), total_declared_bytes=0, refs_required=0,
                           txns_required=0, fits_in_group=True)
    distinct = tuple(sorted(box_sizes.keys()))
    total_bytes = sum(box_sizes.values())
    refs = max(len(distinct), ceil(total_bytes / BOX_WRITE_BUDGET_BYTES_PER_REF))
    txns_min = ceil(refs / MAX_BOX_REFS_PER_TXN)
    return BoxRefPlan(
        distinct_boxes=distinct, total_declared_bytes=total_bytes,
        refs_required=refs, txns_required=txns_min, fits_in_group=True,
    )


# ---------------------------------------------------------------------------
# M4-specific box-name/size helpers (§7.4's worked example, §9.3's box-name
# construction) -- kept here rather than in `relayer.drivers.m4_sync_committee`
# because they are pure box-accounting, not ABI/network concerns.
# ---------------------------------------------------------------------------
FORKS_BOX_BYTES = 576
KEY_BOX_BYTES = 6144
TOTAL_BOX_BYTES = 96
SESSION_BOX_BYTES = 424
KEYS_PER_BOX = 64
BOXES_PER_COMMITTEE = 8


def key_box_name(gen: int, j: int) -> bytes:
    return b"k:" + gen.to_bytes(8, "big") + j.to_bytes(8, "big")[7:8]


def total_box_name(gen: int) -> bytes:
    return b"a:" + gen.to_bytes(8, "big")


def session_box_name(gen: int) -> bytes:
    return b"s:" + gen.to_bytes(8, "big")


def m4_submit_update_box_sizes(gen: int, key_box_indices: set[int], *, include_forks: bool = True,
                                include_total: bool = False) -> dict[bytes, int]:
    """§7.4 example B: the real box set `submit_update` touches for a given
    mode -- `forks` (always, for the fork-row lookup) plus every key box
    the bitfield walk visits (direct mode: participant-holding boxes;
    complement mode: absentee-holding boxes plus `a:<gen>`)."""
    sizes: dict[bytes, int] = {}
    if include_forks:
        sizes[b"forks"] = FORKS_BOX_BYTES
    for j in sorted(key_box_indices):
        sizes[key_box_name(gen, j)] = KEY_BOX_BYTES
    if include_total:
        sizes[total_box_name(gen)] = TOTAL_BOX_BYTES
    return sizes


def m4_install_open_box_sizes(gen: int) -> dict[bytes, int]:
    """§7.4's consistency check: reproduces `MIN_BOX_REFS_FOR_INSTALL_OPEN`
    (`contracts/sync_committee/constants.py`) exactly -- 8 key boxes
    (6,144 B each) + 1 session box (424 B) = 49,576 B -> ceil(49576/2048)
    = 25 refs."""
    sizes: dict[bytes, int] = {key_box_name(gen, j): KEY_BOX_BYTES for j in range(BOXES_PER_COMMITTEE)}
    sizes[session_box_name(gen)] = SESSION_BOX_BYTES
    return sizes


def bit_set(sync_committee_bits: bytes, i: int) -> bool:
    """True SSZ `Bitvector[512]` semantics: bit i lives in byte i//8,
    MSB-first within the byte on the WIRE (this matches
    `tests/sync_committee/test_live_e2e_finality.py`'s own
    `_choose_mode_and_boxes.bit_set`, kept identical so the two
    implementations can be cross-checked directly)."""
    byte = sync_committee_bits[i // 8]
    return (byte >> (7 - (i % 8))) & 1 == 1


def key_box_indices_for_mode(sync_committee_bits: bytes, mode: int, *, keys_per_box: int = KEYS_PER_BOX,
                              committee_size: int = 512) -> set[int]:
    """Direct mode (0) touches every box holding a SET (participating) bit;
    complement mode (1) touches every box holding a CLEAR (absent) bit."""
    if mode == 0:
        return {i // keys_per_box for i in range(committee_size) if bit_set(sync_committee_bits, i)}
    return {i // keys_per_box for i in range(committee_size) if not bit_set(sync_committee_bits, i)}


def choose_mode(sync_committee_bits: bytes, gen: int) -> tuple[int, BoxRefPlan]:
    """§7.5's corrected mode-selection rule: pick the mode with the LOWER
    real pooled box-reference cost (`plan_box_refs`, not `_choose_mode_and_
    boxes`'s box-COUNT heuristic). Ties broken in favour of direct mode
    (0) when participation is the majority, complement (1) otherwise --
    §7.5's own reasoning: at a tie, box count cannot distinguish them, but
    `bitfield.py`'s real per-point opcode cost (217/point, 004 §2.3) can,
    and the mode touching fewer real participants/absentees is cheaper on
    THAT axis."""
    direct_idx = key_box_indices_for_mode(sync_committee_bits, 0)
    complement_idx = key_box_indices_for_mode(sync_committee_bits, 1)
    direct_sizes = m4_submit_update_box_sizes(gen, direct_idx, include_forks=True, include_total=False)
    complement_sizes = m4_submit_update_box_sizes(gen, complement_idx, include_forks=True, include_total=True)
    direct_plan = plan_box_refs(direct_sizes)
    complement_plan = plan_box_refs(complement_sizes)
    if direct_plan.refs_required == complement_plan.refs_required:
        popcount = sum(1 for i in range(512) if bit_set(sync_committee_bits, i))
        return (0, direct_plan) if popcount > 256 else (1, complement_plan)
    return (0, direct_plan) if direct_plan.refs_required < complement_plan.refs_required else (1, complement_plan)
