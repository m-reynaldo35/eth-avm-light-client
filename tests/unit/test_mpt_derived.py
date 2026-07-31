"""
docs/design/005-mpt-walker.md §9.2/§9.3/§9.4: the derived-real fixtures
(tests/fixtures/mpt/build_fixtures.py) that fill eth_data.json's three
structural gaps -- extension node, embedded/inline child, and the
branch-terminal / branch-divergence exclusion forms -- plus the security
tests (S4, S6) and edge/exclusion tests (X1-X4) that only these fixtures
can exercise (state/storage keys are always exactly 64 nibbles, so §5.2's
own honest note is that these cases are structurally unreachable from real
account/storage data; §5.4's leaf-strict-prefix case likewise needs a
variable-length key that real fixed-length state/storage keys cannot
produce -- see the design doc for why the code must still be correct for
them).
"""
import algopy_testing
from algopy import Bytes, UInt64

from contracts.mpt.state import (
    WALK_ABSENT_BRANCH_TERM,
    WALK_ABSENT_EMPTY_SLOT,
    WALK_ABSENT_EXT_DIVERGE,
    WALK_ABSENT_LEAF_DIVERGE,
    WALK_INCLUDED,
    mpt_init_state,
    w_status,
)
from contracts.mpt.walk import mpt_walk_node


def _walk(root: bytes, key: bytes, key_nibs: int, node_labels: list[str],
          nodes_by_label: dict[str, bytes]):
    with algopy_testing.algopy_testing_context():
        w = mpt_init_state(Bytes(root), Bytes(key), UInt64(key_nibs))
        last_node = None
        voff = vlen = UInt64(0)
        for label in node_labels:
            node = nodes_by_label[label]
            last_node = node
            w, voff, vlen = mpt_walk_node(Bytes(node), w)
        status = int(w_status(w))
        value = bytes(last_node[int(voff):int(voff) + int(vlen)]) if status == WALK_INCLUDED else b""
        return status, value


def _scenario_nodes(scenario, nodes_by_label):
    root = bytes.fromhex(scenario["root"])
    return root, scenario["nodes"]


# ---------------------------------------------------------------------------
# F1: extension node, honest walk (parity-mismatched nibbles_equal path).
# ---------------------------------------------------------------------------
def test_f1_extension_honest_walk_misaligned_parity(mpt_scenarios_by_name, mpt_nodes_by_label):
    sc = mpt_scenarios_by_name["F1_extension_parity_mismatch"]
    root, labels = _scenario_nodes(sc, mpt_nodes_by_label)
    key = bytes.fromhex(sc["honest_key"])
    status, value = _walk(root, key, sc["honest_key_nibs"], labels, mpt_nodes_by_label)
    assert status == WALK_INCLUDED
    assert value.hex() == sc["expected_value"]


def test_x3_extension_divergence(mpt_scenarios_by_name, mpt_nodes_by_label):
    sc = mpt_scenarios_by_name["F1_extension_parity_mismatch"]
    root, labels = _scenario_nodes(sc, mpt_nodes_by_label)
    wrong = sc["wrong_keys"][0]
    status, _value = _walk(root, bytes.fromhex(wrong["key"]), wrong["key_nibs"], labels, mpt_nodes_by_label)
    assert status == wrong["expected_status"] == WALK_ABSENT_EXT_DIVERGE


# ---------------------------------------------------------------------------
# F2 (embedded child chain) / F4 (branch-terminal, non-empty item 16).
# ---------------------------------------------------------------------------
def test_f4_branch_terminal_included(mpt_scenarios_by_name, mpt_nodes_by_label):
    sc = mpt_scenarios_by_name["F2_F4_prefix_sharing_pair"]
    root, labels = _scenario_nodes(sc, mpt_nodes_by_label)
    short = sc["short_key"]
    status, value = _walk(root, bytes.fromhex(short["key"]), short["key_nibs"], labels, mpt_nodes_by_label)
    assert status == WALK_INCLUDED == short["expected_status"]
    assert value.hex() == short["expected_value"]


def test_f2_embedded_child_chain_included(mpt_scenarios_by_name, mpt_nodes_by_label):
    """E4: the walk must consume NO extra supplied node for the two
    embedded hops (the branch and the leaf are both < 32 bytes and never
    separately supplied) -- `labels` here is a single node."""
    sc = mpt_scenarios_by_name["F2_F4_prefix_sharing_pair"]
    root, labels = _scenario_nodes(sc, mpt_nodes_by_label)
    assert len(labels) == 1, "the whole chain (extension+branch+leaf) must be one supplied node"
    long_ = sc["long_key"]
    status, value = _walk(root, bytes.fromhex(long_["key"]), long_["key_nibs"], labels, mpt_nodes_by_label)
    assert status == WALK_INCLUDED == long_["expected_status"]
    assert value.hex() == long_["expected_value"]


def test_s4_leaf_strict_prefix_of_presented_key_rejected(mpt_scenarios_by_name, mpt_nodes_by_label):
    """S4: honest proof for the LONGER key (0xabcdef, whose leaf's own path
    fully covers depth+n_path == 6), presented for a key of which the
    leaf's path is a strict prefix (key_nibs == 7 > 6). Must reject via the
    LENGTH test specifically (§5.4 step 2), not the content test."""
    sc = mpt_scenarios_by_name["F2_F4_prefix_sharing_pair"]
    root, labels = _scenario_nodes(sc, mpt_nodes_by_label)
    wrong = sc["wrong_keys"][0]
    assert wrong["test"].startswith("S4")
    status, _value = _walk(root, bytes.fromhex(wrong["key"]), wrong["key_nibs"], labels, mpt_nodes_by_label)
    assert status == wrong["expected_status"] == WALK_ABSENT_LEAF_DIVERGE


def test_x4_leaf_content_diverge_same_length(mpt_scenarios_by_name, mpt_nodes_by_label):
    sc = mpt_scenarios_by_name["F2_F4_prefix_sharing_pair"]
    root, labels = _scenario_nodes(sc, mpt_nodes_by_label)
    wrong = sc["wrong_keys"][1]
    assert wrong["test"].startswith("X4")
    status, _value = _walk(root, bytes.fromhex(wrong["key"]), wrong["key_nibs"], labels, mpt_nodes_by_label)
    assert status == wrong["expected_status"] == WALK_ABSENT_LEAF_DIVERGE


# ---------------------------------------------------------------------------
# S6 / X1 / X2: branch divergence at a shared-prefix boundary, and the
# branch-terminal-empty exclusion case.
# ---------------------------------------------------------------------------
def test_s6_honest_walk(mpt_scenarios_by_name, mpt_nodes_by_label):
    sc = mpt_scenarios_by_name["S6_branch_divergence_shared_prefix"]
    root, labels = _scenario_nodes(sc, mpt_nodes_by_label)
    key = bytes.fromhex(sc["honest_key"])
    status, value = _walk(root, key, sc["honest_key_nibs"], labels, mpt_nodes_by_label)
    assert status == WALK_INCLUDED
    assert value.hex() == sc["expected_value"]


def test_s6_wrong_key_sharing_3_nibbles_rejected_at_branch(mpt_scenarios_by_name, mpt_nodes_by_label):
    """S6, the strongest form: a genuine, valid, correctly-hashed proof
    (for key 0xabc0) presented for key 0xabc5, which shares exactly 3
    leading nibbles with it. Must reject AT THE BRANCH where they diverge
    -- not earlier (the extension covering those 3 nibbles matches fine)
    and not at a leaf (never reached)."""
    sc = mpt_scenarios_by_name["S6_branch_divergence_shared_prefix"]
    root, labels = _scenario_nodes(sc, mpt_nodes_by_label)
    wrong = sc["wrong_keys"][0]
    status, _value = _walk(root, bytes.fromhex(wrong["key"]), wrong["key_nibs"], labels, mpt_nodes_by_label)
    assert status == wrong["expected_status"] == WALK_ABSENT_EMPTY_SLOT


def test_x1_alias_of_s6_empty_slot(mpt_scenarios_by_name, mpt_nodes_by_label):
    """X1: WALK_ABSENT_EMPTY_SLOT, one of the four required absence forms."""
    test_s6_wrong_key_sharing_3_nibbles_rejected_at_branch(mpt_scenarios_by_name, mpt_nodes_by_label)


def test_x2_branch_terminal_empty(mpt_scenarios_by_name, mpt_nodes_by_label):
    sc = mpt_scenarios_by_name["S6_branch_divergence_shared_prefix"]
    root, labels = _scenario_nodes(sc, mpt_nodes_by_label)
    wrong = sc["wrong_keys"][1]
    status, _value = _walk(root, bytes.fromhex(wrong["key"]), wrong["key_nibs"], labels, mpt_nodes_by_label)
    assert status == wrong["expected_status"] == WALK_ABSENT_BRANCH_TERM
