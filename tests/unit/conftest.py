import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

NODES_JSON = REPO_ROOT / "tests" / "fixtures" / "rlp" / "nodes.json"
ETH_DATA_JSON = REPO_ROOT / "tests" / "fixtures" / "spike-reference" / "eth_data.json"
MPT_NODES_JSON = REPO_ROOT / "tests" / "fixtures" / "mpt" / "nodes.json"


@pytest.fixture(scope="session")
def nodes_fixture():
    if not NODES_JSON.exists():
        pytest.skip(f"{NODES_JSON} missing -- run tests/fixtures/rlp/extract_fixtures.py first")
    return json.loads(NODES_JSON.read_text())


@pytest.fixture(scope="session")
def eth_data():
    return json.loads(ETH_DATA_JSON.read_text())


@pytest.fixture(scope="session")
def all_nodes(nodes_fixture):
    """List of (label, source, node_bytes, expected_dict) for all 24 fixtures."""
    out = []
    for n in nodes_fixture["nodes"]:
        out.append((n["label"], n["source"], bytes.fromhex(n["hex"]), n))
    return out


@pytest.fixture(scope="session")
def mpt_fixtures():
    """docs/design/005-mpt-walker.md §9.2's F1/F2/F4/S6 derived-real
    fixtures: tests/fixtures/mpt/build_fixtures.py's output."""
    if not MPT_NODES_JSON.exists():
        pytest.skip(f"{MPT_NODES_JSON} missing -- run "
                     f"tests/fixtures/mpt/build_fixtures.py first")
    return json.loads(MPT_NODES_JSON.read_text())


@pytest.fixture(scope="session")
def mpt_nodes_by_label(mpt_fixtures):
    return {n["label"]: bytes.fromhex(n["hex"]) for n in mpt_fixtures["nodes"]}


@pytest.fixture(scope="session")
def mpt_scenarios_by_name(mpt_fixtures):
    return {s["name"]: s for s in mpt_fixtures["scenarios"]}
