"""
docs/design/005-mpt-walker.md §9.5 suite D2: the Puya walker and
tests/reference/mpt_ref.py must agree -- status, depth, derived index at
every hop, and value span -- on all real and derived fixtures, and on a
property-based corpus of tries built by a real reference MPT builder
(`trie.HexaryTrie`, the same builder tests/fixtures/mpt/build_fixtures.py
uses) over random real-shaped (32-byte, keccak-derived) keys.
"""
import random

import algopy_testing
import rlp as pyrlp
from algopy import Bytes, UInt64
from Crypto.Hash import keccak
from trie import HexaryTrie

from contracts.mpt.state import mpt_init_state, w_depth, w_status
from contracts.mpt.walk import mpt_walk_node
from tests.reference import mpt_ref


def kec(b: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


def _real_supplied_nodes(proof: list[bytes]) -> list[bytes]:
    out = [proof[0]]
    for n in proof[1:]:
        if len(n) >= 32:
            out.append(n)
    return out


def _puya_walk(root: bytes, key: bytes, key_nibs: int, nodes: list[bytes]):
    with algopy_testing.algopy_testing_context():
        w = mpt_init_state(Bytes(root), Bytes(key), UInt64(key_nibs))
        for node in nodes:
            w, voff, vlen = mpt_walk_node(Bytes(node), w)
        return int(w_status(w)), int(w_depth(w)), int(voff), int(vlen)


# ---------------------------------------------------------------------------
# D2 on the real fixtures (Suite A) -- Puya vs oracle, full trace agreement.
# ---------------------------------------------------------------------------
def test_d2_real_account_proof_full_trace_agreement(eth_data):
    proof = eth_data["proof"]
    addr = bytes.fromhex(proof["address"][2:])
    root = bytes.fromhex(eth_data["stateRoot"][2:])
    nodes = [bytes.fromhex(h[2:]) for h in proof["accountProof"]]
    key = mpt_ref.mpt_key_from_address(addr)
    oracle = mpt_ref.mpt_walk_full(root, key, 64, nodes)
    status, depth, voff, vlen = _puya_walk(root, key, 64, nodes)
    assert (status, depth, voff, vlen) == (
        oracle.w.status, oracle.w.depth, oracle.value_off, oracle.value_len)


def test_d2_real_storage_proof_full_trace_agreement(eth_data):
    proof = eth_data["proof"]
    sp = proof["storageProof"][0]
    slot_preimage = bytes.fromhex(eth_data["storage_key"][2:])
    root = bytes.fromhex(proof["storageHash"][2:])
    nodes = [bytes.fromhex(h[2:]) for h in sp["proof"]]
    key = mpt_ref.mpt_key_from_slot(slot_preimage)
    oracle = mpt_ref.mpt_walk_full(root, key, 64, nodes)
    status, depth, voff, vlen = _puya_walk(root, key, 64, nodes)
    assert (status, depth, voff, vlen) == (
        oracle.w.status, oracle.w.depth, oracle.value_off, oracle.value_len)


def test_d2_real_receipt_proof_full_trace_agreement(eth_data):
    rp = eth_data["receipt_proof"]
    root = bytes.fromhex(eth_data["receiptsRoot"][2:])
    nodes = [bytes.fromhex(h[2:]) for h in rp["nodes"]]
    key = mpt_ref.mpt_key_from_tx_index(rp["index"])
    oracle = mpt_ref.mpt_walk_full(root, key, 2 * len(key), nodes)
    status, depth, voff, vlen = _puya_walk(root, key, 2 * len(key), nodes)
    assert (status, depth, voff, vlen) == (
        oracle.w.status, oracle.w.depth, oracle.value_off, oracle.value_len)


# ---------------------------------------------------------------------------
# D2 on the derived-real fixtures.
# ---------------------------------------------------------------------------
def test_d2_derived_fixtures_agreement(mpt_scenarios_by_name, mpt_nodes_by_label):
    for scenario in mpt_scenarios_by_name.values():
        root = bytes.fromhex(scenario["root"])
        nodes = [mpt_nodes_by_label[label] for label in scenario["nodes"]]
        key_value_pairs = []
        for field in ("honest_key", "short_key", "long_key"):
            if field in scenario:
                v = scenario[field]
                if isinstance(v, str):
                    key_value_pairs.append((v, scenario[f"{field}_nibs"]))
                else:
                    key_value_pairs.append((v["key"], v["key_nibs"]))
        for wk in scenario.get("wrong_keys", []):
            key_value_pairs.append((wk["key"], wk["key_nibs"]))
        for key_hex, key_nibs in key_value_pairs:
            key = bytes.fromhex(key_hex)
            oracle = mpt_ref.mpt_walk_full(root, key, key_nibs, nodes)
            status, depth, voff, vlen = _puya_walk(root, key, key_nibs, nodes)
            assert (status, depth, voff, vlen) == (
                oracle.w.status, oracle.w.depth, oracle.value_off, oracle.value_len), (
                scenario["name"], key_hex)


# ---------------------------------------------------------------------------
# D2 property-based corpus: random tries over real-shaped (32-byte,
# keccak-derived) keys, built with a real MPT implementation
# (trie.HexaryTrie), Puya vs oracle on every key inserted plus a handful of
# genuinely absent keys per trie.
# ---------------------------------------------------------------------------
def test_d2_property_based_corpus_random_tries():
    rng = random.Random(20260731)
    n_tries = 12
    keys_per_trie = 6
    checked = 0
    for trial in range(n_tries):
        entries = {}
        for i in range(keys_per_trie):
            k = kec(f"trial-{trial}-key-{i}".encode())
            v = kec(f"trial-{trial}-val-{i}".encode())[:rng.randrange(1, 32)]
            entries[k] = v
        t = HexaryTrie(db={})
        for k, v in entries.items():
            t[k] = v
        root = t.root_hash

        for k, v in entries.items():
            proof = [pyrlp.encode(n) for n in t.get_proof(k)]
            nodes = _real_supplied_nodes(proof)
            oracle = mpt_ref.mpt_walk_full(root, k, 64, nodes)
            status, depth, voff, vlen = _puya_walk(root, k, 64, nodes)
            assert (status, depth, voff, vlen) == (
                oracle.w.status, oracle.w.depth, oracle.value_off, oracle.value_len), (
                trial, k.hex())
            assert oracle.w.status == mpt_ref.WALK_INCLUDED
            assert oracle.value == v
            checked += 1

        # a handful of genuinely absent keys against this same trie/root
        for i in range(3):
            absent_key = kec(f"trial-{trial}-absent-{i}".encode())
            if absent_key in entries:
                continue
            proof = [pyrlp.encode(n) for n in t.get_proof(absent_key)]
            nodes = _real_supplied_nodes(proof)
            oracle = mpt_ref.mpt_walk_full(root, absent_key, 64, nodes)
            status, depth, voff, vlen = _puya_walk(root, absent_key, 64, nodes)
            assert (status, depth, voff, vlen) == (
                oracle.w.status, oracle.w.depth, oracle.value_off, oracle.value_len), (
                trial, absent_key.hex())
            assert oracle.w.status in mpt_ref.WALK_ABSENT_ALL
            checked += 1
    assert checked >= n_tries * (keys_per_trie + 2)
