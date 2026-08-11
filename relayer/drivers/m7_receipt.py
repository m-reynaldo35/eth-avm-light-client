"""M7 driver (design doc §6.3, §7.1, §8.3) -- rewrite of `service/
x402_endpoint/m7_relayer.py` against the generic group planner (§2.2: "the
value IS the code and the code is wrong in shape"). Two real defects fixed
(§2.4 D2, §7.1):

  1. **A `DonorIssuer` sibling, never 8 filler NoOps** (§18 item 5). This
     needs NO change to `Mpt7ReceiptApp` -- opcode budget pools across
     every application call in a group regardless of which app it targets
     (proven live in this repo, M4's `DonorIssuer` donating to
     `TrustedRootAnchor` in `test_live_e2e.py`). Frees 7 of 16 transaction
     slots versus the old 8-filler convention.
  2. **Real `MODE_NEXT` splitting for an oversized T1 node set** (D2): the
     old `m7_relayer.py::prove_receipt` raised `M7Error("MODE_NEXT
     splitting not implemented")` above 2,000 argument bytes even though
     `Mpt7ReceiptApp` implements `MODE_NEXT` and it was proven live at
     round 10 (`test_live_e2e.py`'s own T2 proof). This module splits.

Raw wire format (unchanged from the proven `m7_relayer.py`, `contracts/
receipt/bench_app.py`'s own dispatch): `[b"RCP1", mode(1B), prev_or_zero(1B),
fixed_args, node_args...]`. `fixed_init = receipts_root(32) || tx_index(8,
BE) || log_index(2, BE)`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ARG_BUDGET = 1942  # T1/T2 boundary, 007 §3.1 / M5 §7.2's measured argument budget
MAX_LEAF = 4096
SINGLE_CALL_ARG_BYTE_CAP = 2000  # real per-call safety margin under the 2,048 B hard cap

RSTATUS_NAMES = {0: "R_INCOMPLETE", 1: "R_INCLUDED", 2: "R_ABSENT", 3: "R_NO_SUCH_LOG", 4: "R_ZERO_LOGS"}


class M7Error(Exception):
    pass


@dataclass(frozen=True)
class RawCall:
    """One `Mpt7ReceiptApp` application call's raw args (no box refs
    unless `boxes` is set) -- the driver-neutral shape `relayer.group.
    planner.PlannedTxn.args` wants."""

    args: list[bytes]
    boxes: list[bytes] | None = None
    produces_log: bool = False


def _fixed_init(receipts_root: bytes, tx_index: int, log_index: int) -> bytes:
    return receipts_root + tx_index.to_bytes(8, "big") + log_index.to_bytes(2, "big")


def _pack_nodes(nodes: list[bytes], mode0_extra: int, mode1_prefix_len: int) -> list[list[bytes]]:
    """Greedy packing of a flat node list into MODE_INIT + MODE_NEXT
    argument groups under `SINGLE_CALL_ARG_BYTE_CAP` (D2's fix). Returns a
    list of raw node-arg lists (the caller assembles the fixed prefix args
    per call)."""
    groups: list[list[bytes]] = []
    cur: list[bytes] = []
    cur_bytes = mode0_extra
    for node in nodes:
        if cur and (cur_bytes + len(node) > SINGLE_CALL_ARG_BYTE_CAP):
            groups.append(cur)
            cur, cur_bytes = [], mode1_prefix_len
        cur.append(node)
        cur_bytes += len(node)
    if cur:
        groups.append(cur)
    return groups


def plan_receipt_calls(receipts_root: bytes, tx_index: int, log_index: int, nodes: list[bytes],
                        *, group_offset: int = 0) -> tuple[str, list[RawCall]]:
    """Builds the raw `Mpt7ReceiptApp` call sequence for a receipt walk
    (T1 only -- box-staged T2 is `plan_receipt_calls_t2` below). Returns
    `(tier, calls)`; the LAST call in `calls` is the one whose log carries
    the result (`produces_log=True`).

    `group_offset` (real fix, this pass): `mpt7_state_from_prev`'s `gi`
    (`contracts/receipt/handoff.py`) is the ABSOLUTE group index of the
    producing transaction, not an index relative to `calls` -- a real bug
    if `calls[0]` does not sit at absolute group index 0, which it never
    does once a `DonorIssuer` sibling (§7.1, MUST #5) precedes it. Callers
    that prepend N non-walk transactions before `calls[0]` MUST pass
    `group_offset=N` so a multi-call MODE_NEXT chain references the real
    producing index. Defaults to 0 (offline Suite P's own assumption,
    unaffected)."""
    if not nodes:
        raise M7Error("a receipts-trie walk needs at least one node")
    leaf = nodes[-1]
    if len(leaf) > ARG_BUDGET:
        raise M7Error(f"leaf {len(leaf)} B is > T1's {ARG_BUDGET} B bound -- use plan_receipt_calls_t2")

    fixed_init = _fixed_init(receipts_root, tx_index, log_index)
    # MODE_INIT's fixed prefix: selector(4) + mode(1) + prev(1) + fixed_init(42) = 48
    groups = _pack_nodes(nodes, 48, 6)  # MODE_NEXT's fixed prefix: selector+mode+prev = 6

    calls: list[RawCall] = []
    for i, grp in enumerate(groups):
        if i == 0:
            calls.append(RawCall(args=[b"RCP1", bytes([0]), bytes([0]), fixed_init] + grp,
                                  produces_log=(i == len(groups) - 1)))
        else:
            calls.append(RawCall(args=[b"RCP1", bytes([1]), bytes([group_offset + i - 1]), b""] + grp,
                                  produces_log=(i == len(groups) - 1)))
    return "T1", calls


def derive_t2_box_name(block_number: int) -> bytes:
    """014 §5.2 mitigation 2: `b"t2" || block_number(4 BE) || nonce(2
    random)` -- 8 bytes, the exact width `MODE_STAGE_OPEN`/`WRITE`/`WALK`
    all assert. The OLD derivation (`b"t2" || tx_index(4) || log_index(2)`)
    was fully deterministic from public block data, so an adversary could
    pre-compute and squat any name before the relayer ever built its group
    (measured: `box size mismatch 2000 4094`, §5.2). A block component
    alone would still be guessable (the relayer's own target block is
    public); the random nonce is what makes the name unpredictable ahead of
    the group's own construction, so squatting requires guessing 16 random
    bits per attempt rather than being free. Paired with `box.py`'s
    delete-before-create fix, a squat costs the attacker MBR and buys them
    nothing even when it lands."""
    return b"t2" + block_number.to_bytes(4, "big") + os.urandom(2)


def plan_receipt_calls_t2(receipts_root: bytes, tx_index: int, log_index: int, nodes: list[bytes],
                           box_name: bytes, *, group_offset: int = 0) -> tuple[str, list[RawCall], bytes, int]:
    """T2: branch nodes as plain args (MODE_INIT [+ MODE_NEXT]), then
    box-stage the oversized leaf. Returns `(tier, calls, box_name,
    fund_amount_microalgo)` -- `fund_amount` is the box MBR the caller must
    pay to the APP ACCOUNT (not the sender, §12's real finding) in the SAME
    group before MODE_STAGE_OPEN. `group_offset`: see `plan_receipt_calls`'s
    docstring -- the SAME absolute-vs-relative `prev_gi` fix, also needed
    by `MODE_STAGE_WALK`'s own `prev_gi` (it recovers the branch walk's
    (W, R) the identical way MODE_NEXT does, §5.1)."""
    leaf = nodes[-1]
    branch_nodes = nodes[:-1]
    if not (ARG_BUDGET < len(leaf) <= MAX_LEAF):
        raise M7Error(f"leaf {len(leaf)} B is outside T1/T2 range (T3/ZK is out of scope for v1, §1.2)")
    if not branch_nodes:
        raise M7Error("T2 with zero branch nodes before the leaf is not a real case this driver handles")

    fixed_init = _fixed_init(receipts_root, tx_index, log_index)
    groups = _pack_nodes(branch_nodes, 48, 6)

    calls: list[RawCall] = []
    for i, grp in enumerate(groups):
        if i == 0:
            calls.append(RawCall(args=[b"RCP1", bytes([0]), bytes([0]), fixed_init] + grp))
        else:
            calls.append(RawCall(args=[b"RCP1", bytes([1]), bytes([group_offset + i - 1]), b""] + grp))
    walk_index_pointer = group_offset + len(calls) - 1

    fund_amount = 2500 + 400 * (8 + len(leaf)) + 200_000  # generous headroom, §12
    open_fixed = box_name + len(leaf).to_bytes(2, "big")
    calls.append(RawCall(args=[b"RCP1", bytes([2]), bytes([0]), open_fixed], boxes=[box_name]))

    offset = 0
    while offset < len(leaf):
        chunk = leaf[offset:offset + 1900]
        write_fixed = box_name + offset.to_bytes(2, "big")
        calls.append(RawCall(args=[b"RCP1", bytes([3]), bytes([0]), write_fixed, chunk], boxes=[box_name]))
        offset += len(chunk)

    walk_fixed = box_name + len(leaf).to_bytes(2, "big")
    calls.append(RawCall(
        args=[b"RCP1", bytes([4]), bytes([walk_index_pointer]), walk_fixed],
        boxes=[box_name], produces_log=True,
    ))
    return "T2", calls, box_name, fund_amount


def t2_box_mbr_requirement(leaf_len: int) -> int:
    """014 §3.6/§5.3: the real app-account balance floor once a T2 box of
    `leaf_len` bytes and the ordinary 100,000 uALGO account minimum are
    both accounted for -- `2,500 + 400 * (8 + leaf_len) + 100,000`, §3.6's
    own measured formula. The caller (`EthAvmClient`) reads the app
    account's REAL balance via `account_info` and pays only the shortfall
    against this figure (§5.3's fix), instead of unconditionally paying it
    in full on every call regardless of whether a prior call's float
    already covers it (§3.6's measured finding: three consecutive T2
    proofs against the same app left 5.53 ALGO stranded in the app
    account, all of it recoverable float that a conditional payment would
    have skipped paying twice)."""
    return 2500 + 400 * (8 + leaf_len) + 100_000


def decode_r(log_bytes: bytes) -> dict:
    from relayer.group.logs import Producer, decode_log

    decoded = decode_log(log_bytes, Producer.M7)
    r = decoded.payload
    result = {
        "rstatus": r[0],
        "receipts_root": r[1:33].hex(),
        "tx_index": int.from_bytes(r[33:41], "big"),
        "log_index": int.from_bytes(r[41:43], "big"),
        "tx_type": r[43],
        "status": r[44],
        "cumulative_gas_used": int.from_bytes(r[45:53], "big"),
        "address": r[53:73].hex(),
        "n_topics": r[73],
        "topics": [r[74 + 32 * i: 74 + 32 * (i + 1)].hex() for i in range(r[73])],
        "data_hash": r[202:234].hex(),
        "data_len": int.from_bytes(r[234:238], "big"),
        "wstatus": r[238],
        "n_logs": r[239],
    }
    result["rstatus_name"] = RSTATUS_NAMES.get(result["rstatus"], f"unknown({result['rstatus']})")
    # §6.3/§8.5: R_ABSENT/R_NO_SUCH_LOG/R_ZERO_LOGS are legitimate verdicts
    # delivered by a SUCCESSFUL transaction, never failures. Only
    # R_INCOMPLETE is this relayer's own bug (never a receipt fact).
    if result["rstatus"] == 0:
        raise M7Error("walk did not reach a terminal node (R_INCOMPLETE) -- relayer bug, not a receipt fact")
    return result


# ---------------------------------------------------------------------------
# The combined M7+M8 chain (design doc's own task instructions for this
# pass: "reusing the exact mechanism already live-proven in tests/
# state_anchor/test_live_historical.py's own TestG3CombinedM7M8ReceiptProof").
# `AnchorReceiptProbe` (`contracts/state_anchor/bench_app.py`) is a
# TEST-ONLY, never-deploy-to-mainnet contract that combines M7's own
# unmodified walk subroutines with M8's `mpt7_result_against_anchor` in one
# app, compiled fresh with `handoff.ANCHOR_APP_ID` patched to the real,
# already-deployed M8 anchor app id (TP-M8-4's compile-time-binding
# requirement) -- there is no general-purpose, always-deployed "M7+M8
# combined" app anywhere in this codebase; a real prove_receipt(
# against_anchor=True) call has to compile+deploy this probe on demand,
# exactly as the live test does, just driven generically instead of
# copy-pasted.
# ---------------------------------------------------------------------------
MODE_AGAINST_ANCHOR = 5


def patched_probe_source(repo_root: Path, anchor_app_id: int) -> Path:
    """Stages a temp copy of `contracts/` with `contracts/state_anchor/
    handoff.py`'s `ANCHOR_APP_ID` placeholder patched to the real,
    already-deployed M8 app id. Promoted from `tests/state_anchor/
    conftest.py::patched_repo_copy`, generalised out of the test tree
    (§4.3: relayer must not import tests.*) -- NEVER edits the real repo
    file, only a throwaway temp copy.

    012 §4.2/§9 item 5/§17 item 19: an installed `eth-avm-relayer` wheel
    ships only `relayer/` (§4.2) -- `contracts/` does not exist next to it.
    Raise a NAMED error here, not a bare `FileNotFoundError` from
    `shutil.copytree` two lines down, so the caller sees the real reason
    (a structural wheel limit, not a bug) and where to read about the
    checkout path that avoids it."""
    import shutil
    import tempfile

    from relayer.errors import MissingContractsSource

    if not (repo_root / "contracts").is_dir():
        raise MissingContractsSource(
            f"{repo_root / 'contracts'} does not exist -- prove_receipt(against_anchor=True) needs "
            "a source checkout with puyapy on PATH, not just an installed 'eth-avm-relayer' wheel "
            "(docs/quickstart.md's checkout path; docs/design/012-docs-packaging-release.md §4.2)."
        )

    tmp_root = Path(tempfile.mkdtemp(prefix="relayer_probe_"))
    shutil.copytree(repo_root / "contracts", tmp_root / "contracts")
    handoff_path = tmp_root / "contracts" / "state_anchor" / "handoff.py"
    text = handoff_path.read_text()
    needle = "ANCHOR_APP_ID: int = 0"
    assert needle in text, "handoff.py's ANCHOR_APP_ID placeholder line changed shape"
    handoff_path.write_text(text.replace(needle, f"ANCHOR_APP_ID: int = {anchor_app_id}"))
    return tmp_root


def build_against_anchor_check_args(prev_gi: int, anchor_gi: int, block_number: int, tx_index: int,
                                     log_index: int) -> list[bytes]:
    """`AnchorReceiptProbe`'s `MODE_AGAINST_ANCHOR` (5) raw args -- mirrors
    `test_live_historical.py::TestG3CombinedM7M8ReceiptProof`'s own
    `fixed_check` byte layout exactly."""
    fixed_check = (
        anchor_gi.to_bytes(8, "big") + block_number.to_bytes(8, "big")
        + tx_index.to_bytes(8, "big") + log_index.to_bytes(2, "big")
    )
    return [b"RCP1", bytes([MODE_AGAINST_ANCHOR]), prev_gi.to_bytes(8, "big"), fixed_check]


def decode_against_anchor(log_bytes: bytes) -> dict:
    """Decodes `MODE_AGAINST_ANCHOR`'s own 220-byte payload (NOT the same
    347-byte `R` envelope `decode_r` expects -- `AnchorReceiptProbe` is a
    different contract with its own, simpler log shape: `0x151f7c75 ||
    rstatus(8) || address(20) || n_topics(8) || topics(128) ||
    data_hash(32) || data_len(8) || status(8) || tx_type(8)`)."""
    assert log_bytes[0:4] == bytes.fromhex("151f7c75"), "bad ARC4 return-log prefix"
    out = log_bytes[4:]
    assert len(out) == 220, f"expected a 220-byte MODE_AGAINST_ANCHOR payload, got {len(out)}"
    result = {
        "rstatus": int.from_bytes(out[0:8], "big"),
        "address": out[8:28].hex(),
        "n_topics": int.from_bytes(out[28:36], "big"),
        "topics128": out[36:164].hex(),
        "data_hash": out[164:196].hex(),
        "data_len": int.from_bytes(out[196:204], "big"),
        "status": int.from_bytes(out[204:212], "big"),
        "tx_type": int.from_bytes(out[212:220], "big"),
    }
    result["rstatus_name"] = RSTATUS_NAMES.get(result["rstatus"], f"unknown({result['rstatus']})")
    if result["rstatus"] == 0:
        raise M7Error("walk did not reach a terminal node (R_INCOMPLETE) -- relayer bug, not a receipt fact")
    return result
