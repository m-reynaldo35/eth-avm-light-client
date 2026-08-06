"""`LightClientHeader`/branch decoding (design doc §5.3), promoted from
`service/x402_endpoint/eth_beacon_rpc.py`'s `_decode_header`/`_decode_branch`.

Two invariants carried forward verbatim because they are correctness
properties, not style (§5.3):
  * Never hardcode a branch depth -- concatenate whatever nodes the
    response actually contains. Live "fulu" `finality_branch` has 7
    entries where the Altair-preset vendored vectors have 6; the deployed
    fork table is what must carry the right gindex/depth (§8's N9 assert).
  * Since Capella, `attested_header`/`finalized_header`/bootstrap's
    `header` are `{"beacon": {...}, "execution": {...},
    "execution_branch": [...]}`, not the flat `BeaconBlockHeader` the
    Altair-only vendored vectors use. Only `"beacon"` is M4's concern; both
    shapes are handled so this works against old vectors and live mainnet
    data alike.
"""
from __future__ import annotations

import hashlib


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_tree_root_beacon_block_header(header: bytes) -> bytes:
    """`hash_tree_root(BeaconBlockHeader)` for the raw 112-byte SSZ encoding
    `decode_header` produces. Promoted from `tests.sync_committee.reference.
    hash_tree_root_beacon_block_header` (itself a verbatim mirror of
    `contracts/sync_committee/header.py`) so `relayer.drivers.
    m4_sync_committee`'s own checkpoint-fetching logic can compute a
    checkpoint's block root without importing a pytest test module (§4.3
    rule 1)."""
    assert len(header) == 112
    slot_chunk = header[0:8] + bytes(24)
    proposer_chunk = header[8:16] + bytes(24)
    parent_root = header[16:48]
    state_root = header[48:80]
    body_root = header[80:112]
    zero_leaf = bytes(32)

    l0 = _sha256(slot_chunk + proposer_chunk)
    l1 = _sha256(parent_root + state_root)
    l2 = _sha256(body_root + zero_leaf)
    l3 = _sha256(zero_leaf + zero_leaf)
    n0 = _sha256(l0 + l1)
    n1 = _sha256(l2 + l3)
    return _sha256(n0 + n1)


def le64(x: int) -> bytes:
    """SSZ `uint64` fields are little-endian -- `op.itob`/plain
    `int.to_bytes(..., "big")` are NOT (004 §3.1 trap 1)."""
    return x.to_bytes(8, "little")


def _strip0x(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def decode_header(h: dict) -> bytes:
    """`LightClientHeader` (or a flat pre-Capella `BeaconBlockHeader`) ->
    the raw 112-byte SSZ encoding `contracts/sync_committee/header.py`
    operates on."""
    beacon = h["beacon"] if "beacon" in h else h
    slot = int(beacon["slot"])
    proposer_index = int(beacon["proposer_index"])
    parent_root = _strip0x(beacon["parent_root"])
    state_root = _strip0x(beacon["state_root"])
    body_root = _strip0x(beacon["body_root"])
    assert len(parent_root) == len(state_root) == len(body_root) == 32
    header = le64(slot) + le64(proposer_index) + parent_root + state_root + body_root
    assert len(header) == 112
    return header


def decode_branch(branch_hex: list[str]) -> bytes:
    """Concatenates a JSON list of 32-byte hex merkle-branch nodes into the
    flat `bytes` blob a `DynamicBytes` branch argument expects. Does NOT
    assert a fixed number of entries -- branch depth is fork-dependent."""
    nodes = [_strip0x(n) for n in branch_hex]
    for n in nodes:
        assert len(n) == 32, f"branch node not 32 bytes: {len(n)}"
    return b"".join(nodes)
