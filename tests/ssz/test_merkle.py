"""Offline tests for contracts/primitives/ssz/merkle.py, per design doc §8's
test plan (T1-T3, T5, T6, T8-T12). Runs against `algopy_testing`'s Python
emulation of the AVM -- no algod/docker dependency, matches `ci-offline.yml`.

Authoritative test data is `tests/fixtures/ssz/consensus-spec-tests/` (38
real `ethereum/consensus-spec-tests` v1.6.0-beta.0 `single_merkle_proof`
vectors across 6 forks), loaded via `tests/ssz/generate_fixtures.py`. Hand-
built trees are used only for the structural negative cases (T6, T8-T11)
the official suite does not cover.
"""
import json

import pytest
from algopy import Bytes, UInt64

from contracts.primitives.ssz.merkle import (
    assert_valid_merkle_branch,
    assert_valid_normalized_merkle_branch,
    compute_merkle_branch_root,
)
from tests.ssz import reference
from tests.ssz.generate_fixtures import VECTORS_JSON, cross_proof_groups

ALL_CASES = json.loads(VECTORS_JSON.read_text())
ZERO32 = b"\x00" * 32


def _bytes_list(case):
    leaf = bytes.fromhex(case["leaf"])
    branch = b"".join(bytes.fromhex(s) for s in case["branch"])
    gindex = case["gindex"]
    root = bytes.fromhex(case["root"])
    return leaf, branch, gindex, root


# --------------------------------------------------------------------------
# T1: official vectors, all forks -- all 38 verify.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("case", ALL_CASES, ids=[c["name"] for c in ALL_CASES])
def test_t1_official_vectors_verify(ctx, case):
    leaf, branch, gindex, root = _bytes_list(case)
    assert_valid_merkle_branch(Bytes(leaf), Bytes(branch), UInt64(gindex), Bytes(root))


# --------------------------------------------------------------------------
# T2: length invariant on real data.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("case", ALL_CASES, ids=[c["name"] for c in ALL_CASES])
def test_t2_length_invariant(case):
    assert len(case["branch"]) == case["depth"] == reference.floorlog2(case["gindex"])


# --------------------------------------------------------------------------
# T3: spec-reference equivalence -- on-chain fold == verbatim Python spec fn.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("case", ALL_CASES, ids=[c["name"] for c in ALL_CASES])
def test_t3_matches_python_spec_reference(ctx, case):
    leaf, branch, gindex, _root = _bytes_list(case)
    onchain_root = compute_merkle_branch_root(Bytes(leaf), Bytes(branch), UInt64(gindex)).value
    branch_list = [bytes.fromhex(s) for s in case["branch"]]
    ref_root = reference.compute_merkle_branch_root_gindex(leaf, branch_list, gindex)
    assert onchain_root == ref_root


# --------------------------------------------------------------------------
# T5: cross-proof convergence -- the 3 BeaconState proofs per fork agree.
# --------------------------------------------------------------------------
def test_t5_cross_proof_convergence(ctx):
    groups = cross_proof_groups(ALL_CASES)
    assert len(groups) == 6, "expected altair, bellatrix, capella, deneb, electra, fulu"
    for fork, cases in groups.items():
        roots = set()
        for case in cases:
            leaf, branch, gindex, _ = _bytes_list(case)
            root = compute_merkle_branch_root(Bytes(leaf), Bytes(branch), UInt64(gindex)).value
            roots.add(root)
        assert len(roots) == 1, f"{fork}: proofs diverge on root: {[r.hex() for r in roots]}"


# --------------------------------------------------------------------------
# T6: ordering-convention regression -- reversed siblings must be rejected.
# This is the single highest-value negative test (design doc §8 table).
# --------------------------------------------------------------------------
def test_t6_reversed_sibling_order_is_rejected(ctx):
    case = next(c for c in ALL_CASES if c["name"] == "electra/BeaconState/finality_root_merkle_proof")
    leaf = bytes.fromhex(case["leaf"])
    branch_items = [bytes.fromhex(s) for s in case["branch"]]
    gindex = case["gindex"]
    root = bytes.fromhex(case["root"])

    reversed_branch = b"".join(reversed(branch_items))
    with pytest.raises(Exception):
        assert_valid_merkle_branch(Bytes(leaf), Bytes(reversed_branch), UInt64(gindex), Bytes(root))


# --------------------------------------------------------------------------
# T8: length-mismatch rejection (strict form: == depth exactly).
# --------------------------------------------------------------------------
def test_t8_branch_shorter_than_depth_rejected(ctx):
    case = next(c for c in ALL_CASES if c["depth"] == 5)
    leaf = bytes.fromhex(case["leaf"])
    branch_items = [bytes.fromhex(s) for s in case["branch"]]
    gindex = case["gindex"]
    root = bytes.fromhex(case["root"])

    too_short = b"".join(branch_items[:-1])  # one sibling short of depth
    with pytest.raises(Exception):
        assert_valid_merkle_branch(Bytes(leaf), Bytes(too_short), UInt64(gindex), Bytes(root))


def test_t8_branch_longer_than_depth_rejected_strict(ctx):
    case = next(c for c in ALL_CASES if c["depth"] == 5)
    leaf = bytes.fromhex(case["leaf"])
    branch_items = [bytes.fromhex(s) for s in case["branch"]]
    gindex = case["gindex"]
    root = bytes.fromhex(case["root"])

    too_long = b"".join(branch_items) + ZERO32  # one sibling too many
    with pytest.raises(Exception):
        assert_valid_merkle_branch(Bytes(leaf), Bytes(too_long), UInt64(gindex), Bytes(root))


def test_t8_branch_not_multiple_of_32_rejected(ctx):
    case = next(c for c in ALL_CASES if c["depth"] == 5)
    leaf = bytes.fromhex(case["leaf"])
    branch_items = [bytes.fromhex(s) for s in case["branch"]]
    gindex = case["gindex"]
    root = bytes.fromhex(case["root"])

    truncated = b"".join(branch_items)[:-3]  # 3 bytes short of a multiple of 32
    with pytest.raises(Exception):
        assert_valid_merkle_branch(Bytes(leaf), Bytes(truncated), UInt64(gindex), Bytes(root))


# --------------------------------------------------------------------------
# T9: degenerate gindex.
# --------------------------------------------------------------------------
def test_t9_gindex_zero_rejected(ctx):
    with pytest.raises(Exception):
        compute_merkle_branch_root(Bytes(ZERO32), Bytes(b""), UInt64(0))


def test_t9_gindex_one_depth_zero_accepted_iff_leaf_equals_root(ctx):
    leaf = bytes.fromhex("aa" * 32)
    # gindex == 1 => depth 0 => leaf IS the root, zero iterations.
    root = compute_merkle_branch_root(Bytes(leaf), Bytes(b""), UInt64(1)).value
    assert root == leaf
    assert_valid_merkle_branch(Bytes(leaf), Bytes(b""), UInt64(1), Bytes(leaf))

    wrong_root = bytes.fromhex("bb" * 32)
    with pytest.raises(Exception):
        assert_valid_merkle_branch(Bytes(leaf), Bytes(b""), UInt64(1), Bytes(wrong_root))


def test_t9_gindex_too_deep_rejected(ctx):
    # bitlen(gindex) > 62 => depth > 61, must be rejected as a clean
    # assertion rather than an arg-length failure (design doc §7.8).
    huge_gindex = 2**62  # bitlen == 63
    with pytest.raises(Exception):
        compute_merkle_branch_root(Bytes(ZERO32), Bytes(b"\x00" * (61 * 32)), UInt64(huge_gindex))


# --------------------------------------------------------------------------
# T10: tampering.
# --------------------------------------------------------------------------
def test_t10_flipped_sibling_byte_rejected(ctx):
    case = next(c for c in ALL_CASES if c["depth"] == 5)
    leaf = bytes.fromhex(case["leaf"])
    branch_items = [bytes.fromhex(s) for s in case["branch"]]
    gindex = case["gindex"]
    root = bytes.fromhex(case["root"])

    tampered = bytearray(branch_items[0])
    tampered[0] ^= 0x01
    branch_items[0] = bytes(tampered)
    branch = b"".join(branch_items)
    with pytest.raises(Exception):
        assert_valid_merkle_branch(Bytes(leaf), Bytes(branch), UInt64(gindex), Bytes(root))


def test_t10_wrong_gindex_same_depth_rejected(ctx):
    # Same leaf/branch/root that verify correctly for the real gindex;
    # flipping one bit of gindex flips a left/right decision partway
    # through the fold and must reject.
    #
    # NOTE: bit 0 specifically is degenerate for several of these "minimal"
    # preset vectors -- e.g. gindex 54/55 (current/next sync committee) are
    # tree siblings whose values happen to be bit-for-bit equal in the
    # minimal test state, so swapping which side of the level-0 hash they
    # land on changes nothing. That is a property of the tiny test fixture,
    # not of the fold -- picking a mid-branch bit (here bit 1 of the
    # depth-7 finality_root proof) avoids it and is confirmed to actually
    # change the result before asserting rejection.
    case = next(c for c in ALL_CASES if c["name"] == "electra/BeaconState/finality_root_merkle_proof")
    assert case["gindex"] == 169 and case["depth"] == 7
    leaf, branch, gindex, root = _bytes_list(case)
    assert_valid_merkle_branch(Bytes(leaf), Bytes(branch), UInt64(gindex), Bytes(root))  # sanity: real one passes

    wrong_gindex = gindex ^ (1 << 1)  # flip bit 1, not bit 0 (see note above)
    with pytest.raises(Exception):
        assert_valid_merkle_branch(Bytes(leaf), Bytes(branch), UInt64(wrong_gindex), Bytes(root))


# --------------------------------------------------------------------------
# T11: normalized branches.
# --------------------------------------------------------------------------
def test_t11_normalized_zero_extra_padding_verifies(ctx):
    case = next(c for c in ALL_CASES if c["depth"] == 5)
    leaf = bytes.fromhex(case["leaf"])
    branch = b"".join(bytes.fromhex(s) for s in case["branch"])
    gindex = case["gindex"]
    root = bytes.fromhex(case["root"])
    assert_valid_normalized_merkle_branch(Bytes(leaf), Bytes(branch), UInt64(gindex), Bytes(root))


def test_t11_normalized_with_zero_padding_verifies(ctx):
    case = next(c for c in ALL_CASES if c["depth"] == 5)
    leaf = bytes.fromhex(case["leaf"])
    branch_items = [bytes.fromhex(s) for s in case["branch"]]
    gindex = case["gindex"]
    root = bytes.fromhex(case["root"])

    padded = ZERO32 * 3 + b"".join(branch_items)  # 3 extra leading zero slots
    assert_valid_normalized_merkle_branch(Bytes(leaf), Bytes(padded), UInt64(gindex), Bytes(root))


def test_t11_normalized_nonzero_padding_rejected(ctx):
    case = next(c for c in ALL_CASES if c["depth"] == 5)
    leaf = bytes.fromhex(case["leaf"])
    branch_items = [bytes.fromhex(s) for s in case["branch"]]
    gindex = case["gindex"]
    root = bytes.fromhex(case["root"])

    bad_pad = bytearray(ZERO32)
    bad_pad[-1] = 0x01  # single non-zero byte in the padding slot
    padded = bytes(bad_pad) + b"".join(branch_items)
    with pytest.raises(Exception):
        assert_valid_normalized_merkle_branch(Bytes(leaf), Bytes(padded), UInt64(gindex), Bytes(root))


# --------------------------------------------------------------------------
# T12: zero leaf / zero sibling -- must be ACCEPTED, not special-cased away.
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "name",
    [
        "electra/BeaconState/finality_root_merkle_proof",
        "fulu/BeaconState/finality_root_merkle_proof",
    ],
)
def test_t12_zero_leaf_and_zero_sibling_accepted(ctx, name):
    case = next(c for c in ALL_CASES if c["name"] == name)
    assert case["leaf"] == "00" * 32, "fixture assumption: this vector's leaf is zero"
    assert case["branch"][0] == "00" * 32, "fixture assumption: branch[0] is also zero"
    leaf, branch, gindex, root = _bytes_list(case)
    assert_valid_merkle_branch(Bytes(leaf), Bytes(branch), UInt64(gindex), Bytes(root))
