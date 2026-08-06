"""Real SSZ merkleization of `ExecutionPayload` (Deneb/Electra/Fulu shape,
17 fields -> 32 leaves, depth 5), promoted verbatim from `tests/state_anchor/
real_ssz.py` (008's G1-M8 live proof). Built from real field values fetched
from a live beacon API's `/eth/v2/beacon/blocks/{slot}` response's own
`execution` field (the light-client-header shape, which already gives
`transactions_root`/`withdrawals_root` as precomputed roots -- see
`relayer.ssz.block_body` for the full-payload variant HISTORICAL mode's
arbitrary-slot fixture builder needs when no such precomputed header is
available).

No gindex is hand-copied: field positions are the real SSZ field ORDER
(fixed by the consensus spec's container definition), cross-checked
against the two published anchors: `block_hash` at composed gindex 812 for
Deneb+ (docs/design/008-trusted-root-anchor.md §3.2).
"""
from __future__ import annotations

from relayer.ssz.merkleize import extra_data_root, logs_bloom_root, sha256


def le_bytes(x: int, n: int) -> bytes:
    return x.to_bytes(n, "little")


def build_tree(depth: int, leaves: list[bytes]):
    n = 1 << depth
    assert len(leaves) <= n
    padded = leaves + [b"\x00" * 32] * (n - len(leaves))
    layers = [padded]
    cur = padded
    while len(cur) > 1:
        nxt = [sha256(cur[2 * i] + cur[2 * i + 1]) for i in range(len(cur) // 2)]
        layers.append(nxt)
        cur = nxt
    root = cur[0]

    def branch_for(position: int) -> bytes:
        b = b""
        idx = position
        for layer in layers[:-1]:
            b += layer[idx ^ 1]
            idx //= 2
        return b

    return root, branch_for


# Real field order, Deneb/Electra/Fulu ExecutionPayload (17 fields, 0-indexed):
FIELD_INDEX = {
    "parent_hash": 0, "fee_recipient": 1, "state_root": 2, "receipts_root": 3,
    "logs_bloom": 4, "prev_randao": 5, "block_number": 6, "gas_limit": 7,
    "gas_used": 8, "timestamp": 9, "extra_data": 10, "base_fee_per_gas": 11,
    "block_hash": 12, "transactions_root": 13, "withdrawals_root": 14,
    "blob_gas_used": 15, "excess_blob_gas": 16,
}
EXECUTION_PAYLOAD_DEPTH = 5  # 17 fields -> 32 leaves
EXECUTION_PAYLOAD_GINDEX = 25  # BeaconBlockBody.execution_payload, field 9 of 16 leaves: 16+9


def build_execution_payload_tree(payload: dict):
    """`payload` is the real JSON dict from `/eth/v2/beacon/blocks/{slot}`'s
    `execution_payload` (hex strings / decimal strings, as the beacon API
    returns them). Returns `(root, branch_for)`."""
    leaves = [b"\x00" * 32] * 17
    leaves[0] = bytes.fromhex(payload["parent_hash"][2:])
    leaves[1] = bytes.fromhex(payload["fee_recipient"][2:]).ljust(32, b"\x00")
    leaves[2] = bytes.fromhex(payload["state_root"][2:])
    leaves[3] = bytes.fromhex(payload["receipts_root"][2:])
    leaves[4] = logs_bloom_root(bytes.fromhex(payload["logs_bloom"][2:]))
    leaves[5] = bytes.fromhex(payload["prev_randao"][2:])
    leaves[6] = le_bytes(int(payload["block_number"]), 8).ljust(32, b"\x00")
    leaves[7] = le_bytes(int(payload["gas_limit"]), 8).ljust(32, b"\x00")
    leaves[8] = le_bytes(int(payload["gas_used"]), 8).ljust(32, b"\x00")
    leaves[9] = le_bytes(int(payload["timestamp"]), 8).ljust(32, b"\x00")
    leaves[10] = extra_data_root(bytes.fromhex(payload["extra_data"][2:]))
    leaves[11] = le_bytes(int(payload["base_fee_per_gas"]), 32)
    leaves[12] = bytes.fromhex(payload["block_hash"][2:])
    leaves[13] = bytes.fromhex(payload["transactions_root"][2:])
    leaves[14] = bytes.fromhex(payload["withdrawals_root"][2:])
    leaves[15] = le_bytes(int(payload["blob_gas_used"]), 8).ljust(32, b"\x00")
    leaves[16] = le_bytes(int(payload["excess_blob_gas"]), 8).ljust(32, b"\x00")
    return build_tree(EXECUTION_PAYLOAD_DEPTH, leaves)


def compute_branch_root(leaf: bytes, branch: bytes, gindex: int) -> bytes:
    depth = gindex.bit_length() - 1
    assert len(branch) == depth * 32
    node = leaf
    for i in range(depth):
        sib = branch[32 * i: 32 * i + 32]
        if (gindex >> i) & 1:
            node = sha256(sib + node)
        else:
            node = sha256(node + sib)
    return node


def deep_branch(payload: dict, execution_branch_hex: list[str], field: str) -> tuple[bytes, int]:
    """Returns `(composed_branch_bytes, composed_gindex)` for `field`
    (one of "state_root"/"receipts_root"/"block_number") -- the real
    depth-9 branch M8's `anchor_direct`/`anchor_historical` need, built
    entirely from real data: the inner depth-5 siblings from this module's
    own real tree, concatenated with the real depth-4 `execution_branch`
    the beacon API already published."""
    _root, branch_for = build_execution_payload_tree(payload)
    field_index = FIELD_INDEX[field]
    inner_branch = branch_for(field_index)  # depth 5, leaf-to-root order
    outer_branch = b"".join(bytes.fromhex(x[2:]) for x in execution_branch_hex)  # depth 4
    composed_gindex = EXECUTION_PAYLOAD_GINDEX * (1 << EXECUTION_PAYLOAD_DEPTH) + field_index
    return inner_branch + outer_branch, composed_gindex
