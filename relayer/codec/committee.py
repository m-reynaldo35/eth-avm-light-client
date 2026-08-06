"""`hash_tree_root(SyncCommittee{pubkeys, aggregate_pubkey})`, promoted from
`service/x402_endpoint/eth_beacon_rpc.py::_committee_root` (design doc
§5.3), which itself mirrored `tests/sync_committee/test_signing_root.py`'s
`_committee_vector_root`/`_next_committee_root` verbatim. The fold is
leaf-count-agnostic, so it generalizes from the vendored 32-member
minimal-preset vectors to the real mainnet 512-member committee with no
new logic, only more leaves.
"""
from __future__ import annotations

import hashlib


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _strip0x(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def committee_root(pubkeys_hex: list[str], aggregate_hex: str) -> bytes:
    """Each `BLSPubkey` (a `Bytes48` basic-byte-vector) SSZ-merkleizes as
    `sha256(pubkey_bytes || 16 zero bytes)` -- 48 + 16 == 64 == two 32-byte
    chunks concatenated."""
    leaves = [sha256(_strip0x(pk) + bytes(16)) for pk in pubkeys_hex]
    layer = leaves
    while len(layer) > 1:
        layer = [sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    committee_vector_root = layer[0]
    agg_leaf = sha256(_strip0x(aggregate_hex) + bytes(16))
    return sha256(committee_vector_root + agg_leaf)
