"""M8 driver (design doc §6.5, §8.3): `TrustedRootAnchor` -- ARC-4
encoding, `DonorIssuer` sibling budget convention, stateless per-call (the
ring is on-chain state, but M9 never holds a client-side cursor for it).

§6.5's decision rule (§18 item 8, normative -- HISTORICAL is the DEFAULT
for anything but the newest finalized block, inverting the naive instinct):

    if target_block is the newest finalized EL block:      DIRECT
    elif fin_slot - t_slot < 8192:                          HISTORICAL
    else:                                                   NotAnchorable(outside_window)

DIRECT is valid against exactly one finalized header, so if M4 advances
between `simulate` and `send` the group fails N6 (008 §12.4: "normal, not
exceptional"). HISTORICAL is valid against any newer finalized header --
the entire reason 008's own live sessions record the chain moving forward
three times mid-session.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from algosdk.abi import Method

from relayer.errors import NotAnchorable

WINDOW_SLOTS = 8192

# ---------------------------------------------------------------------------
# `TrustedRootAnchor`'s real ARC-4 method signatures -- same rationale as
# `relayer.drivers.m4_sync_committee.METHODS` (built from the real
# signature, cross-checked against a real `puyapy` compile of `contracts/
# state_anchor/anchor_app.py`'s own `arc56.json` before being trusted; note
# `m4_app`'s `Application` ABI parameter compiles to a plain `uint64`, not a
# reference type -- 009 §15.1 point 3, confirmed by that same compile).
# ---------------------------------------------------------------------------
_SIGNATURES = {
    "ring_init_chunk": "ring_init_chunk(uint64)void",
    "append_fork_row": "append_fork_row(uint64,uint64,uint64,uint64,uint64)void",
    "anchor_direct": "anchor_direct(uint64,byte[112],byte[32],byte[32],uint64,byte[],byte[],byte[])byte[154]",
    "anchor_historical": (
        "anchor_historical(uint64,byte[112],byte[112],byte[],byte[32],byte[32],uint64,byte[],byte[],byte[])byte[154]"
    ),
    "attest": "attest(uint64)byte[154]",
    "get_anchor": "get_anchor(uint64)byte[154]",
}
METHODS: dict[str, Method] = {name: Method.from_signature(sig) for name, sig in _SIGNATURES.items()}


class AnchorMode(Enum):
    DIRECT = auto()
    HISTORICAL = auto()


@dataclass(frozen=True)
class AnchorPlanHint:
    mode: AnchorMode
    t_slot: int


def choose_anchor_mode(*, target_is_newest_finalized: bool, fin_slot: int, t_slot: int) -> AnchorPlanHint:
    """§6.5's exact rule, §18 item 8. Raises `NotAnchorable` (a first-class
    result, per §6.5/§8.5 -- "a permanent property of a block, not a
    transient failure") rather than returning a sentinel a caller might
    silently ignore."""
    if target_is_newest_finalized:
        return AnchorPlanHint(mode=AnchorMode.DIRECT, t_slot=t_slot)
    if fin_slot - t_slot < WINDOW_SLOTS:
        return AnchorPlanHint(mode=AnchorMode.HISTORICAL, t_slot=t_slot)
    raise NotAnchorable(
        f"t_slot={t_slot} is {fin_slot - t_slot} slots behind fin_slot={fin_slot}, "
        f"outside the {WINDOW_SLOTS}-slot (~27.3h) HISTORICAL window"
    )


def build_anchor_direct_method_args(m4_app_id: int, fin_header: bytes, el_state_root: bytes,
                                     el_receipts_root: bytes, el_block_number: int,
                                     state_branch: bytes, receipts_branch: bytes, number_branch: bytes) -> list:
    """Positional ABI args for `TrustedRootAnchor.anchor_direct`, in the
    exact declared order (`contracts/state_anchor/anchor_app.py`)."""
    return [
        m4_app_id, fin_header, el_state_root, el_receipts_root, el_block_number,
        state_branch, receipts_branch, number_branch,
    ]


def build_anchor_historical_method_args(m4_app_id: int, fin_header: bytes, target_header: bytes,
                                         block_roots_branch: bytes, el_state_root: bytes,
                                         el_receipts_root: bytes, el_block_number: int,
                                         state_branch: bytes, receipts_branch: bytes,
                                         number_branch: bytes) -> list:
    """Positional ABI args for `TrustedRootAnchor.anchor_historical`."""
    return [
        m4_app_id, fin_header, target_header, block_roots_branch,
        el_state_root, el_receipts_root, el_block_number, state_branch, receipts_branch, number_branch,
    ]


def ring_box_name(residue: int) -> bytes:
    return b"h:" + residue.to_bytes(8, "big")


def pin_box_name(block_number: int) -> bytes:
    return b"p:" + block_number.to_bytes(8, "big")


def build_direct_fixture(fu_now: dict, fu_now_args) -> dict:
    """§6.5 DIRECT mode's real fixture: the target header IS the finalized
    header, so the depth-9 EL branches come straight out of the LIGHT-CLIENT
    response's own already-decoded `execution`/`execution_branch` fields --
    no full-state fetch needed. Promoted from `test_live_e2e.py::
    TestG1M8RealDirectAnchor`'s own fixture-building steps, generalised out
    of the test body (§4.3: pure, no `algosdk`)."""
    from relayer.ssz import execution_payload as real_ssz

    finalized_json = fu_now["data"]["finalized_header"]
    payload = finalized_json["execution"]
    execution_branch = finalized_json["execution_branch"]
    fin_header = fu_now_args.finalized_header

    state_branch, g_state = real_ssz.deep_branch(payload, execution_branch, "state_root")
    receipts_branch, g_receipts = real_ssz.deep_branch(payload, execution_branch, "receipts_root")
    number_branch, g_number = real_ssz.deep_branch(payload, execution_branch, "block_number")
    el_state_root = bytes.fromhex(payload["state_root"][2:])
    el_receipts_root = bytes.fromhex(payload["receipts_root"][2:])
    el_block_number = int(payload["block_number"])
    fin_slot = int.from_bytes(fin_header[0:8], "little")

    return {
        "mode": AnchorMode.DIRECT, "fin_slot": fin_slot, "t_slot": fin_slot,
        "fin_header": fin_header,
        "el_state_root": el_state_root, "el_receipts_root": el_receipts_root, "el_block_number": el_block_number,
        "state_branch": state_branch, "receipts_branch": receipts_branch, "number_branch": number_branch,
        "g_state_root": g_state, "g_receipts_root": g_receipts, "g_block_number": g_number,
    }


def build_historical_fixture(fu_now_args, t_slot_offset: int, *, cache) -> dict:
    """§6.5 HISTORICAL mode's real fixture: no light-client response covers
    an arbitrary historical slot (§5.4), so this fetches the REAL full
    `BeaconState` at `fin_slot` (via `cache`, a `relayer.sources.cache.
    DiskCache` -- §5.5, the ~956 MB response is cached, never refetched),
    independently re-derives its state root (cross-checked against the real
    finalized header's own `state_root` BEFORE anything else is trusted,
    §3.4's "derive, don't copy" discipline), then builds the real depth-19
    `block_roots` branch plus the depth-9 EL branches for `t_slot`'s own
    block. Promoted from `test_live_historical.py::historical_fixture`."""
    from relayer.sources import beacon
    from relayer.ssz import beacon_state as rbs_state
    from relayer.ssz import block_body as rbs_body
    from relayer.ssz import execution_payload as real_ssz
    from relayer.codec.header import hash_tree_root_beacon_block_header

    fin_header = fu_now_args.finalized_header
    fin_slot = int.from_bytes(fin_header[0:8], "little")
    live_fin_state_root = fin_header[48:80]
    fin_root = hash_tree_root_beacon_block_header(fin_header)
    t_slot = fin_slot - t_slot_offset

    resp = cache.get_or_fetch(f"debug_state_{fin_slot}", lambda: beacon.fetch_debug_state(fin_slot))
    data = resp["data"]
    assert int(data["slot"]) == fin_slot, "fetched full-state slot must match the header being anchored against"

    state_root, field_roots, block_roots_raw = rbs_state.build_beacon_state_tree(data, verbose=False)
    assert state_root == live_fin_state_root, (
        "independently-computed BeaconState root must equal the real finalized header's own state_root"
    )

    branch19 = rbs_state.block_roots_fold_branch(field_roots, block_roots_raw, t_slot)

    hresp = beacon._get_json(f"/eth/v1/beacon/headers/{t_slot}")
    hm = hresp["data"]["header"]["message"]
    t_header_bytes = (
        int(hm["slot"]).to_bytes(8, "little") + int(hm["proposer_index"]).to_bytes(8, "little")
        + bytes.fromhex(hm["parent_root"][2:]) + bytes.fromhex(hm["state_root"][2:])
        + bytes.fromhex(hm["body_root"][2:])
    )
    t_root = hash_tree_root_beacon_block_header(t_header_bytes)
    assert "0x" + t_root.hex() == hresp["data"]["root"]
    assert block_roots_raw[t_slot % 8192] == t_root, (
        "block_roots[t_slot % 8192] must equal T_SLOT's own independently-fetched header root"
    )

    tblk = beacon._get_json(f"/eth/v2/beacon/blocks/{t_slot}")
    tbody = tblk["data"]["message"]["body"]
    tpayload = tbody["execution_payload"]
    payload_root, branch_for = rbs_body.build_full_execution_payload_tree(tpayload)
    body_root, branch4 = rbs_body.build_beacon_block_body_tree(tbody, payload_root)
    assert body_root == t_header_bytes[80:112]

    el_state_root = bytes.fromhex(tpayload["state_root"][2:])
    el_receipts_root = bytes.fromhex(tpayload["receipts_root"][2:])
    el_block_number = int(tpayload["block_number"])

    state_branch = branch_for(real_ssz.FIELD_INDEX["state_root"]) + branch4
    receipts_branch = branch_for(real_ssz.FIELD_INDEX["receipts_root"]) + branch4
    number_branch = branch_for(real_ssz.FIELD_INDEX["block_number"]) + branch4

    return {
        "mode": AnchorMode.HISTORICAL, "fin_slot": fin_slot, "t_slot": t_slot,
        "fin_header": fin_header, "fin_root": fin_root, "target_header": t_header_bytes,
        "block_roots_branch": branch19, "g_block_roots_base_fulu": rbs_state.G_BLOCK_ROOTS_BASE_FULU,
        "el_state_root": el_state_root, "el_receipts_root": el_receipts_root, "el_block_number": el_block_number,
        "state_branch": state_branch, "receipts_branch": receipts_branch, "number_branch": number_branch,
    }


def auto_boxes_for(method_name: str, block_number: int, ring_n: int) -> list[tuple[int, bytes]]:
    """Mirrors `tests/state_anchor/conftest.py::Arc4Harness._auto_boxes_for`
    -- the ring/pin box names are a pure function of `block_number` and the
    immutable `ring_n`, so a caller never hand-computes them.

    013 §6.4: `forks8` is no longer a box (the fork table moved to global
    state, which costs no box-reference budget at all), so
    `anchor_direct`/`anchor_historical` no longer add a reference for it --
    unlike M4's bootstrap group (§6.4), M8's anchor group is nowhere near
    any reference cap (008 §18/§19: 2 boxes, 475 B, 12% of two
    references), so this is a straight deletion, not a replacement."""
    boxes = []
    residue = block_number & (ring_n - 1)
    boxes.append((0, ring_box_name(residue)))
    if method_name in ("pin", "unpin"):
        boxes.append((0, pin_box_name(block_number)))
    return boxes
