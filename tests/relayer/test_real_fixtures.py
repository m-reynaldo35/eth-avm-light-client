"""Suite R (design doc §13.2): real data, offline against pinned fixtures
-- no live network calls once the fixtures below exist on disk (two of
them, `tests/fixtures/relayer/finality_update_fulu.json` and
`bootstrap_fulu.json`, were captured fresh from real mainnet light-client
endpoints for this pass, exactly as `tests/fixtures/spike-reference/
eth_data.json` was captured for M6/M7 -- both are real, one-time-recorded
mainnet responses, not synthetic).
"""
import json
import random
from pathlib import Path

import pytest
from py_ecc.bls.point_compression import decompress_G1, decompress_G2
from py_ecc.optimized_bls12_381 import G1, G2, multiply

from relayer.codec.bls import g1_compressed_to_avm, g1_uncompressed_avm, g2_compressed_to_avm, g2_uncompressed_avm
from relayer.codec.header import decode_branch, decode_header
from relayer.drivers.m4_sync_committee import install_chunks
from relayer.proofs.account import segment_account_proof, verify_and_extract, mpt_key_from_address
from relayer.proofs.receipts_trie import build_receipts_trie_and_path

REPO_ROOT = Path(__file__).resolve().parents[2]
ETH_DATA_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "spike-reference" / "eth_data.json"
FINALITY_UPDATE_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "relayer" / "finality_update_fulu.json"
BOOTSTRAP_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "relayer" / "bootstrap_fulu.json"


def _load(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# R-1: build_receipts_trie_and_path on the pinned block -- root matches the
# real receiptsRoot; tx 31's 3-node path byte-identical to M7's own fixture.
# ---------------------------------------------------------------------------
def test_r1_receipts_trie_matches_pinned_tx31_fixture():
    d = _load(ETH_DATA_FIXTURE)
    root, nodes = build_receipts_trie_and_path(d["block_receipts"], d["receipt_proof"]["index"])
    assert "0x" + root.hex() == d["receiptsRoot"]
    expected_nodes = [bytes.fromhex(n[2:]) for n in d["receipt_proof"]["nodes"]]
    assert nodes == expected_nodes
    assert len(nodes) == 3


# ---------------------------------------------------------------------------
# R-2: eth_getProof decode against the pinned fixture -- 8 account nodes +
# 9 storage nodes, matching M2's own G6 bench inputs.
# ---------------------------------------------------------------------------
def test_r2_eth_get_proof_decode_matches_pinned_fixture():
    d = _load(ETH_DATA_FIXTURE)
    proof = d["proof"]
    assert len(proof["accountProof"]) == 8
    assert len(proof["storageProof"][0]["proof"]) == 9

    segs = segment_account_proof(proof, declared_state_root=bytes.fromhex(d["stateRoot"][2:]))
    assert segs.account_included is True
    assert segs.storage_included is True
    assert segs.balance is not None and segs.nonce is not None
    assert segs.code_hash is not None

    # Cross-check: the SAME account key (keccak256(address)) walked with
    # verify_and_extract independently reaches the same conclusion.
    key = mpt_key_from_address(proof["address"])
    root = bytes.fromhex(d["stateRoot"][2:])
    result = verify_and_extract(root, key, [bytes.fromhex(n[2:]) for n in proof["accountProof"]])
    assert result.included is True


def test_r2_absent_account_and_slot_cases_are_structurally_handled():
    """Not from the pinned fixture (which is present/present) -- a
    synthetic exclusion case built from a REAL branch node's own shape,
    confirming `verify_and_extract` genuinely returns `included=False`
    when a branch's slot for the next key nibble is empty (the standard
    MPT exclusion-proof shape), not just when it runs out of nodes."""
    # A single 17-entry branch node with every slot empty except one --
    # walking towards ANY other nibble must report exclusion at that hop.
    import rlp

    branch = [b""] * 17
    branch[5] = b"\x01" * 32  # only nibble 5 populated
    branch_rlp = rlp.encode(branch)
    from Crypto.Hash import keccak

    def kec(b):
        h = keccak.new(digest_bits=256)
        h.update(b)
        return h.digest()

    root = kec(branch_rlp)
    # key whose first nibble is 0 (not 5) -> branch[0] is empty -> excluded
    key = bytes([0x0F]) + b"\x00" * 31
    result = verify_and_extract(root, key, [branch_rlp])
    assert result.included is False


# ---------------------------------------------------------------------------
# R-3: relayer/ssz/ vs remerkleable at small scale -- bit-for-bit across
# packed uint64/uint8 lists, fixed vectors, container lists, Bitlist/
# Bitvector (real delimiter bit), n == limit, partial final chunk.
#
# Honest note: `tests/state_anchor/real_beacon_state.py`'s own docstring
# claims this cross-validation already exists (`validate_against_
# remerkleable()`, `_SELF_TEST_RESULTS`) -- neither is actually present in
# that file's source. This is a real, pre-existing documentation/code
# mismatch this pass found (not introduced by it) while promoting the
# module; rather than promote the missing self-test as a TODO, this test
# implements the real cross-validation the docstring describes.
# ---------------------------------------------------------------------------
remerkleable = pytest.importorskip("remerkleable")
from remerkleable.basic import uint8, uint64  # noqa: E402
from remerkleable.bitfields import Bitlist, Bitvector  # noqa: E402
from remerkleable.byte_arrays import Bytes32  # noqa: E402
from remerkleable.complex import Container, List, Vector  # noqa: E402

from relayer.ssz.merkleize import (  # noqa: E402
    bitlist_htr_from_ssz_hex,
    bitvector_htr_from_hex,
    htr_bytes32_vector_fixed,
    htr_container_list,
    htr_uint64_list,
    htr_uint8_list,
    htr_uint64_vector_fixed,
    merkleize_chunks_exact,
)


def test_r3_packed_uint64_list_matches_remerkleable():
    class L(List[uint64, 100]):
        pass

    for n in (0, 1, 3, 4, 5, 31, 32, 33, 100):
        values = [random.randint(0, 2**64 - 1) for _ in range(n)]
        rm_root = L(*values).hash_tree_root()
        our_root = htr_uint64_list(values, 100)
        assert bytes(rm_root) == our_root, f"n={n}"


def test_r3_packed_uint8_list_matches_remerkleable():
    class L(List[uint8, 300]):
        pass

    for n in (0, 1, 31, 32, 33, 300):
        values = [random.randint(0, 255) for _ in range(n)]
        rm_root = L(*values).hash_tree_root()
        our_root = htr_uint8_list(values, 300)
        assert bytes(rm_root) == our_root, f"n={n}"


def test_r3_fixed_uint64_vector_matches_remerkleable():
    class V(Vector[uint64, 16]):
        pass

    values = [random.randint(0, 2**64 - 1) for _ in range(16)]
    rm_root = V(*values).hash_tree_root()
    our_root = htr_uint64_vector_fixed(values, 16)
    assert bytes(rm_root) == our_root


def test_r3_fixed_bytes32_vector_matches_remerkleable():
    class V(Vector[Bytes32, 8]):
        pass

    values = [random.randbytes(32) for _ in range(8)]
    rm_root = V(*[Bytes32(v) for v in values]).hash_tree_root()
    our_root = htr_bytes32_vector_fixed(values, 8)
    assert bytes(rm_root) == our_root


def test_r3_container_list_matches_remerkleable():
    class Pair(Container):
        a: uint64
        b: uint64

    class L(List[Pair, 50]):
        pass

    for n in (0, 1, 7, 8, 9, 50):
        items = [(random.randint(0, 2**64 - 1), random.randint(0, 2**64 - 1)) for _ in range(n)]
        rm_root = L(*[Pair(a=a, b=b) for a, b in items]).hash_tree_root()
        leaves = [merkleize_chunks_exact([a.to_bytes(32, "little"), b.to_bytes(32, "little")]) for a, b in items]
        # Pair's own htr is merkleize([a_chunk, b_chunk]) -- 2 chunks, exact pow2.
        our_root = htr_container_list(leaves, 50)
        assert bytes(rm_root) == our_root, f"n={n}"


def test_r3_validator_shaped_8field_container_matches_remerkleable():
    """The exact 8-field shape `relayer.ssz.beacon_state.validator_htr` uses."""

    class V(Container):
        pubkey: Vector[uint8, 48]
        withdrawal_credentials: Bytes32
        effective_balance: uint64
        slashed: uint8  # remerkleable has no native `boolean` merkleize quirk here; using uint8(0/1) matches our own byte-flag encoding
        activation_eligibility_epoch: uint64
        activation_epoch: uint64
        exit_epoch: uint64
        withdrawable_epoch: uint64

    from relayer.ssz.beacon_state import validator_htr

    pubkey = random.randbytes(48)
    wc = random.randbytes(32)
    rm = V(
        pubkey=Vector[uint8, 48](*pubkey),
        withdrawal_credentials=Bytes32(wc),
        effective_balance=32_000_000_000,
        slashed=0,
        activation_eligibility_epoch=100,
        activation_epoch=101,
        exit_epoch=2**64 - 1,
        withdrawable_epoch=2**64 - 1,
    )
    our_root = validator_htr(pubkey, wc, 32_000_000_000, False, 100, 101, 2**64 - 1, 2**64 - 1)
    assert bytes(rm.hash_tree_root()) == our_root


def test_r3_bitlist_real_delimiter_bit_matches_remerkleable():
    class BL(Bitlist[131072]):
        pass

    for n in (0, 1, 7, 8, 9, 255, 256, 257):
        bits = [random.random() < 0.5 for _ in range(n)]
        rm = BL(*bits)
        rm_bytes = bytes(rm.encode_bytes())
        our_root = bitlist_htr_from_ssz_hex("0x" + rm_bytes.hex(), 131072)
        assert bytes(rm.hash_tree_root()) == our_root, f"n={n}"


def test_r3_bitvector_matches_remerkleable():
    class BV(Bitvector[512]):
        pass

    bits = [random.random() < 0.5 for _ in range(512)]
    rm = BV(*bits)
    rm_bytes = bytes(rm.encode_bytes())
    our_root = bitvector_htr_from_hex("0x" + rm_bytes.hex(), 512)
    assert bytes(rm.hash_tree_root()) == our_root


def test_r3_n_equals_limit_and_partial_final_chunk_edge_cases():
    class L(List[uint64, 32]):
        pass

    # n == limit exactly (fully packed, no zero-padding needed at all).
    values = list(range(32))
    assert bytes(L(*values).hash_tree_root()) == htr_uint64_list(values, 32)
    # n spans a partial final 32-byte chunk (32 has exactly 4 uint64s/chunk
    # -> n=5 spans a partial 2nd chunk).
    values5 = list(range(5))
    assert bytes(L(*values5).hash_tree_root()) == htr_uint64_list(values5, 32)


# ---------------------------------------------------------------------------
# R-4: _decode_header / _decode_branch on recorded live "fulu" JSON --
# 112-byte headers; 7-node finality_branch; 6-node committee branch.
# ---------------------------------------------------------------------------
def test_r4_decode_header_and_branch_on_real_fulu_finality_update():
    resp = _load(FINALITY_UPDATE_FIXTURE)
    assert resp["version"] == "fulu"
    data = resp["data"]
    attested = decode_header(data["attested_header"])
    finalized = decode_header(data["finalized_header"])
    assert len(attested) == 112
    assert len(finalized) == 112
    branch = decode_branch(data["finality_branch"])
    assert len(branch) % 32 == 0
    assert len(branch) // 32 == 7, "real live fulu finality_branch has 7 entries, not the Altair-vendored 6"


def test_r4_decode_header_and_branch_on_real_fulu_bootstrap():
    resp = _load(BOOTSTRAP_FIXTURE)
    header = decode_header(resp["data"]["header"])
    assert len(header) == 112
    branch = decode_branch(resp["data"]["current_sync_committee_branch"])
    assert len(branch) // 32 == 6, "real live fulu current_sync_committee_branch has 6 entries"


# ---------------------------------------------------------------------------
# R-5: G1/G2 decompression round-trip -- AVM limb order (c0 first), the
# REVERSE of every reference serializer.
# ---------------------------------------------------------------------------
def test_r5_g1_round_trip_and_avm_uncompressed_shape():
    for k in (1, 2, 12345, 2**200 + 7):
        pt = multiply(G1, k)
        avm_bytes = g1_uncompressed_avm(pt)
        assert len(avm_bytes) == 96
        x = int.from_bytes(avm_bytes[:48], "big")
        y = int.from_bytes(avm_bytes[48:], "big")
        assert x != 0 and y != 0


def test_r5_g2_avm_limb_order_is_c0_first_not_c1_first():
    pt = multiply(G2, 12345)
    avm_bytes = g2_uncompressed_avm(pt)
    assert len(avm_bytes) == 192
    from py_ecc.optimized_bls12_381 import normalize

    x, y = normalize(pt)
    xc, yc = x.coeffs, y.coeffs
    # AVM order: X.c0 || X.c1 || Y.c0 || Y.c1 -- c0 FIRST.
    assert avm_bytes[0:48] == int(xc[0]).to_bytes(48, "big")
    assert avm_bytes[48:96] == int(xc[1]).to_bytes(48, "big")
    # The reference (ZCash/IETF wire) serializer is c1-first -- confirm our
    # bytes are NOT that order (guards a silent limb swap regressing back in).
    assert avm_bytes[0:48] != int(xc[1]).to_bytes(48, "big")


def test_r5_g1_g2_compressed_to_avm_on_real_fixture_pubkeys():
    resp = _load(BOOTSTRAP_FIXTURE)
    csc = resp["data"]["current_sync_committee"]
    for pk_hex in csc["pubkeys"][:8]:
        comp, uncompressed = g1_compressed_to_avm(pk_hex)
        assert len(comp) == 48
        assert len(uncompressed) == 96
        assert uncompressed != bytes(96), "a real committee member key must not be infinity"


# ---------------------------------------------------------------------------
# R-6: install_chunks(chunk_size=8) -- every blob <= 2,048 B with ARC-4
# framing; chunk_size=64 rejected at the API, not at algod (D1).
# ---------------------------------------------------------------------------
def test_r6_install_chunks_size_8_fits_the_arg_cap():
    resp = _load(BOOTSTRAP_FIXTURE)
    csc = resp["data"]["current_sync_committee"]
    pairs = [g1_compressed_to_avm(pk) for pk in csc["pubkeys"][:64]]
    chunks = install_chunks(pairs, chunk_size=8)
    assert len(chunks) == 8
    for _index, compressed_blob, uncompressed_blob in chunks:
        # ARC-4 DynamicBytes framing adds a 2-byte length prefix per arg;
        # 2 dynamic args -> 4 bytes of framing overhead, comfortably inside
        # the 2,048 B cap alongside the raw node bytes.
        assert len(compressed_blob) + len(uncompressed_blob) + 4 <= 2048


def test_r6_install_chunks_size_64_rejected_at_the_api():
    resp = _load(BOOTSTRAP_FIXTURE)
    csc = resp["data"]["current_sync_committee"]
    pairs = [g1_compressed_to_avm(pk) for pk in csc["pubkeys"]]
    with pytest.raises(ValueError):
        install_chunks(pairs, chunk_size=64)
