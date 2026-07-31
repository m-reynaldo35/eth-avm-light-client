#!/usr/bin/env python3
"""
tests/fixtures/mpt/build_fixtures.py -- design doc §9.2.

`tests/fixtures/spike-reference/eth_data.json` contains no extension node,
no embedded (<32B) child, and no exclusion case -- the three structural
gaps §9.2 names (F1-F5). This script fills them the way M2's
`tests/fixtures/rlp/extract_fixtures.py` did: by DERIVING them from real
key/value pairs run through a real reference MPT builder (here: the `trie`
PyPI package's `HexaryTrie`, cross-checked against `rlp.encode` -- verified
below to reproduce the exact real-mainnet hash-chaining rule: a node's
child is referenced by `keccak256(rlp.encode(child))` when that encoding is
>= 32 bytes, and embedded as the raw encoding itself when it is shorter),
never by hand-writing RLP bytes.

Every fixture here is labelled "derived-real" per §9.2 ("Label all derived
fixtures derived-real in the fixture JSON and never mainnet-observed") --
real keccak256 hash-chaining and a real, general-purpose MPT implementation
throughout; only the KEYS are synthetic (chosen to force the structural
cases eth_data.json's shallow real proofs happen not to contain).

`real_supplied_nodes()` below encodes the on-chain delivery rule M5 itself
implements (§5.5): the ROOT node (index 0) is always separately supplied
and hashed, regardless of its own encoded size (there is no parent to
embed it in -- the published trie root is always `keccak256(rlp(root
node))`); every LATER node in `HexaryTrie.get_proof()`'s raw decoded list
is supplied only if its own RLP encoding is >= 32 bytes, exactly M5's own
"< 32 bytes -> embedded, continue in the same buffer" rule (§5.5). This
was verified against `contracts.mpt.walk.mpt_walk_node` (via
algopy_testing) for every fixture below before being written out --
see the bottom of this file's `main()`.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

import rlp as pyrlp  # noqa: E402
from trie import HexaryTrie  # noqa: E402

from tests.reference import mpt_ref  # noqa: E402
from tests.reference.rlp_ref import keccak256  # noqa: E402

OUT_PATH = Path(__file__).resolve().parent / "nodes.json"


def build_trie(entries: dict[bytes, bytes]) -> HexaryTrie:
    t = HexaryTrie(db={})
    for k, v in entries.items():
        t[k] = v
    return t


def encoded_proof(t: HexaryTrie, key: bytes) -> list[bytes]:
    return [pyrlp.encode(node) for node in t.get_proof(key)]


def real_supplied_nodes(proof: list[bytes]) -> list[bytes]:
    """§5.5's delivery rule: index 0 (the root) is always supplied; a later
    node is supplied only if its RLP encoding is >= 32 bytes (otherwise it
    is embedded in its parent and reached by inline descent, never
    separately supplied)."""
    out = [proof[0]]
    for node in proof[1:]:
        if len(node) >= 32:
            out.append(node)
    return out


def verify_with_puya(root: bytes, key: bytes, key_nibs: int, nodes: list[bytes]):
    """Cross-check a fixture against the REAL Puya subroutines (not just the
    Python oracle) before it is ever written to nodes.json -- run at
    build time so a broken fixture fails loudly here, not silently in a
    downstream test."""
    import algopy_testing
    from algopy import Bytes, UInt64

    from contracts.mpt.state import mpt_init_state, w_status
    from contracts.mpt.walk import mpt_walk_node

    with algopy_testing.algopy_testing_context():
        w = mpt_init_state(Bytes(root), Bytes(key), UInt64(key_nibs))
        last_node = None
        voff = vlen = UInt64(0)
        for node in nodes:
            last_node = node
            w, voff, vlen = mpt_walk_node(Bytes(node), w)
        status = int(w_status(w))
        value = bytes(last_node[int(voff):int(voff) + int(vlen)]) if status == 1 else b""
    return status, value


def node_entry(node: bytes, label: str) -> dict:
    return {
        "label": label,
        "source": "derived-real",
        "hex": node.hex(),
        "keccak256": keccak256(node).hex(),
        "len": len(node),
    }


def main() -> None:
    fixtures: list[dict] = []
    scenarios: list[dict] = []

    # ------------------------------------------------------------------
    # F1: extension node whose nib_index/depth have DIFFERENT parity
    # (§5.3's misaligned nibbles_equal fallback). key_a, key_b share
    # exactly 5 leading nibbles (odd count) -> hex-prefix skip=1 ->
    # nib_index odd, while depth on arrival at the root is 0 (even).
    # ------------------------------------------------------------------
    key_a = bytes([0xAB, 0xC1, 0x20])
    key_b = bytes([0xAB, 0xC1, 0x25])
    t1 = build_trie({key_a: b"\xAA\xBB", key_b: b"\xCC"})
    sup1 = real_supplied_nodes(encoded_proof(t1, key_a))
    for i, n in enumerate(sup1):
        fixtures.append(node_entry(n, f"derived.f1_extension.nodes[{i}]"))
    status, value = verify_with_puya(t1.root_hash, key_a, 6, sup1)
    assert status == mpt_ref.WALK_INCLUDED and value == b"\xAA\xBB", (status, value)
    scenarios.append({
        "name": "F1_extension_parity_mismatch",
        "root": t1.root_hash.hex(),
        "nodes": [f"derived.f1_extension.nodes[{i}]" for i in range(len(sup1))],
        "honest_key": key_a.hex(), "honest_key_nibs": 6,
        "expected_status": mpt_ref.WALK_INCLUDED, "expected_value": value.hex(),
        "note": "root is an extension, path length 5 (odd) -> nib_index odd, "
                "depth-on-arrival 0 (even): parity mismatch, exercises the "
                "misaligned nibbles_equal fallback loop (not the aligned "
                "fast path). Also used as X3 with a wholly-different wrong "
                "key (extension divergence).",
        "wrong_keys": [
            {"key": "111111", "key_nibs": 6, "expected_status": mpt_ref.WALK_ABSENT_EXT_DIVERGE,
             "test": "X3"},
        ],
    })

    # ------------------------------------------------------------------
    # F2/F4: two keys where one (0xabcd) is a byte-for-byte prefix of the
    # other (0xabcdef). Produces, in ONE trie: an extension -> an EMBEDDED
    # branch (§5.5, F2) whose item 16 is a NON-EMPTY value (§5.2's branch-
    # terminal case, F4) and whose item 14 is an EMBEDDED leaf (a second
    # inline hop, further exercising §5.5's inline_steps bound).
    # ------------------------------------------------------------------
    t2 = build_trie({b"\xab\xcd": b"\x01\x02", b"\xab\xcd\xef": b"\x03\x04"})
    sup_short = real_supplied_nodes(encoded_proof(t2, b"\xab\xcd"))
    sup_long = real_supplied_nodes(encoded_proof(t2, b"\xab\xcd\xef"))
    assert sup_short == sup_long  # same single root node supplies both proofs
    for i, n in enumerate(sup_long):
        fixtures.append(node_entry(n, f"derived.f2_f4_prefix_pair.nodes[{i}]"))
    status_short, value_short = verify_with_puya(t2.root_hash, b"\xab\xcd", 4, sup_short)
    status_long, value_long = verify_with_puya(t2.root_hash, b"\xab\xcd\xef", 6, sup_long)
    assert status_short == mpt_ref.WALK_INCLUDED and value_short == b"\x01\x02"
    assert status_long == mpt_ref.WALK_INCLUDED and value_long == b"\x03\x04"
    scenarios.append({
        "name": "F2_F4_prefix_sharing_pair",
        "root": t2.root_hash.hex(),
        "nodes": [f"derived.f2_f4_prefix_pair.nodes[{i}]" for i in range(len(sup_long))],
        "note": "single root node (an extension whose child branch AND that "
                "branch's item-14 leaf are both embedded, <32B) supplies "
                "BOTH proofs below -- E4 (chain of 2 inline steps).",
        "short_key": {"key": "abcd", "key_nibs": 4, "expected_status": mpt_ref.WALK_INCLUDED,
                       "expected_value": value_short.hex(), "test": "F4/E2 (branch-terminal, item16 non-empty)"},
        "long_key": {"key": "abcdef", "key_nibs": 6, "expected_status": mpt_ref.WALK_INCLUDED,
                     "expected_value": value_long.hex(), "test": "F2/E4 (embedded child chain)"},
        "wrong_keys": [
            {"key": "abcdef00", "key_nibs": 7, "expected_status": mpt_ref.WALK_ABSENT_LEAF_DIVERGE,
             "test": "S4 (leaf path strict prefix of presented key -- length check fires)"},
            {"key": "abcde0", "key_nibs": 6, "expected_status": mpt_ref.WALK_ABSENT_LEAF_DIVERGE,
             "test": "X4 (same length, content diverges)"},
        ],
    })

    # ------------------------------------------------------------------
    # S6/X1/X2: two keys sharing EXACTLY 3 nibbles (0xabc0, 0xabc9),
    # diverging at nibble index 3 -- a branch, not a leaf. A THIRD,
    # never-inserted key (0xabc5) shares the same 3-nibble prefix but maps
    # to that branch's EMPTY slot 5.
    # ------------------------------------------------------------------
    t3 = build_trie({b"\xab\xc0": b"\x11", b"\xab\xc9": b"\x22"})
    sup3 = real_supplied_nodes(encoded_proof(t3, b"\xab\xc0"))
    for i, n in enumerate(sup3):
        fixtures.append(node_entry(n, f"derived.s6_branch_divergence.nodes[{i}]"))
    status3, value3 = verify_with_puya(t3.root_hash, b"\xab\xc0", 4, sup3)
    assert status3 == mpt_ref.WALK_INCLUDED and value3 == b"\x11"
    status_s6, _ = verify_with_puya(t3.root_hash, bytes([0xAB, 0xC5]), 4, sup3)
    assert status_s6 == mpt_ref.WALK_ABSENT_EMPTY_SLOT
    status_x2, _ = verify_with_puya(t3.root_hash, bytes([0xAB, 0xC0]), 3, sup3)
    assert status_x2 == mpt_ref.WALK_ABSENT_BRANCH_TERM
    scenarios.append({
        "name": "S6_branch_divergence_shared_prefix",
        "root": t3.root_hash.hex(),
        "nodes": [f"derived.s6_branch_divergence.nodes[{i}]" for i in range(len(sup3))],
        "honest_key": "abc0", "honest_key_nibs": 4,
        "expected_status": mpt_ref.WALK_INCLUDED, "expected_value": value3.hex(),
        "note": "extension covers nibbles a,b,c (3); branch at depth 3 has "
                "slot 0 -> key abc0's leaf, slot 9 -> key abc9's leaf, "
                "every other slot empty.",
        "wrong_keys": [
            {"key": "abc5", "key_nibs": 4, "expected_status": mpt_ref.WALK_ABSENT_EMPTY_SLOT,
             "test": "S6/X1 (genuine honest proof for key A, presented for key B "
                     "sharing exactly 3 nibbles -- rejected at the branch where "
                     "they diverge, not earlier [extension matches] and not at "
                     "a leaf [never reached])"},
            {"key": "abc0", "key_nibs": 3, "expected_status": mpt_ref.WALK_ABSENT_BRANCH_TERM,
             "test": "X2 (key ends exactly at the branch, item 16 empty)"},
        ],
    })

    out = {
        "note": ("derived-real: real keccak256 hash-chaining throughout, "
                 "produced by the `trie` PyPI package's HexaryTrie (a real, "
                 "general-purpose Ethereum-compatible MPT implementation) "
                 "and cross-checked byte-for-byte against contracts/mpt/ "
                 "via algopy_testing before being written here (see "
                 "verify_with_puya() in this script). Keys are synthetic "
                 "(chosen to force the extension/embedded-child/branch-"
                 "terminal/divergence structural cases eth_data.json's real "
                 "but shallow proofs do not contain) -- never "
                 "'mainnet-observed'."),
        "nodes": fixtures,
        "scenarios": scenarios,
    }
    OUT_PATH.write_text(json.dumps(out, indent=2))
    print(f"wrote {OUT_PATH} -- {len(fixtures)} nodes, {len(scenarios)} scenarios")


if __name__ == "__main__":
    main()
