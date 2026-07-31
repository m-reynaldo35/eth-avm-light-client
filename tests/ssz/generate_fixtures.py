"""Fixture generator for M3 (design doc §8): loads the vendored
`ethereum/consensus-spec-tests` `single_merkle_proof` vectors, builds a
pinned JSON fixture set from them, and (for the live tier only) provides an
app-args `simulate_create_args` variant of
`tests/fixtures/spike-reference/mpt_bench.py`'s harness core, driving the
Puya-compiled contracts under `contracts/primitives/ssz/harness.py` with
real application arguments the way design doc §2.4-§2.6 measure them.

Usage:
    python -m tests.ssz.generate_fixtures      # writes tests/fixtures/ssz/vectors.json

`load_consensus_spec_vectors` and `cross_proof_groups` are imported directly
by `tests/ssz/test_merkle.py` (offline tier); `simulate_create_args` is
imported by `tests/ssz/test_budget.py` (live tier only, requires dev-mode
algod per `tests/fixtures/spike-reference/README.md`).
"""
from __future__ import annotations

import json
import pathlib
import sys

import yaml

from tests.ssz import reference

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTORS_DIR = REPO_ROOT / "tests/fixtures/ssz/consensus-spec-tests"
VECTORS_JSON = REPO_ROOT / "tests/fixtures/ssz/vectors.json"

# Real light-client proofs are named after the leaf they prove; blob/kzg
# proof cases (Deneb+ / eip7805) are named per-index. Both are handled
# generically below by walking every `proof.yaml` under VECTORS_DIR.


def load_consensus_spec_vectors() -> list[dict]:
    """Walk the vendored `single_merkle_proof` subset and return one dict
    per case: {fork, container, method, name, leaf, branch, gindex, root}.

    `root` is the branch's OWN folded root (computed here with the pure-Python
    reference, `reference.compute_merkle_branch_root_gindex`), NOT an
    independently-computed `hash_tree_root` of the accompanying
    `object.ssz_snappy` -- design doc §2.10 flags this gap explicitly (T4,
    blocking for *Tested* status, not for this implementation pass). Every
    vector here is therefore validated as "the on-chain fold reproduces the
    spec reference fold, byte-exact" (T3) and, within a fork, that
    independent proofs of the same underlying object converge on one root
    (T5) -- not yet as "the root is the true SSZ hash_tree_root of the
    canonical test object."
    """
    cases = []
    for proof_path in sorted(VECTORS_DIR.glob("**/proof.yaml")):
        rel = proof_path.relative_to(VECTORS_DIR)
        parts = rel.parts  # (fork, 'light_client'|'merkle_proof', 'single_merkle_proof', container, method, 'proof.yaml')
        fork = parts[0]
        container = parts[3]
        method = parts[4]
        with proof_path.open() as f:
            raw = yaml.safe_load(f)
        leaf = bytes.fromhex(_strip0x(raw["leaf"]))
        branch = [bytes.fromhex(_strip0x(s)) for s in raw["branch"]]
        gindex = int(raw["leaf_index"])
        root = reference.compute_merkle_branch_root_gindex(leaf, branch, gindex)
        cases.append(
            {
                "fork": fork,
                "container": container,
                "method": method,
                "name": f"{fork}/{container}/{method}",
                "leaf": leaf.hex(),
                "branch": [b.hex() for b in branch],
                "gindex": gindex,
                "depth": reference.floorlog2(gindex),
                "root": root.hex(),
            }
        )
    return cases


def _strip0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s


def cross_proof_groups(cases: list[dict]) -> dict[str, list[dict]]:
    """Group BeaconState light_client proofs by fork, for T5's convergence
    check (current_sync_committee / next_sync_committee / finality_root
    within one fork must fold to the SAME root, since they are proofs
    against one `object.ssz_snappy`)."""
    groups: dict[str, list[dict]] = {}
    for case in cases:
        if case["container"] != "BeaconState":
            continue
        groups.setdefault(case["fork"], []).append(case)
    return groups


def build_vectors_json() -> list[dict]:
    cases = load_consensus_spec_vectors()
    VECTORS_JSON.parent.mkdir(parents=True, exist_ok=True)
    with VECTORS_JSON.open("w") as f:
        json.dump(cases, f, indent=2, sort_keys=True)
    return cases


# ---------------------------------------------------------------------------
# Live-tier harness: app-args simulate_create, reusing mpt_bench.py's core.
# ---------------------------------------------------------------------------
_SPIKE_REFERENCE = REPO_ROOT / "tests/fixtures/spike-reference"


def _load_mpt_bench():
    if str(_SPIKE_REFERENCE) not in sys.path:
        sys.path.insert(0, str(_SPIKE_REFERENCE))
    import mpt_bench  # noqa: PLC0415 (deliberate lazy import -- live tier only)

    return mpt_bench


def simulate_create_args(approval: bytes, app_args: list[bytes], extra_budget: int | None = None, extra_pages: int = 3):
    """Like `mpt_bench.simulate_create`, but sets `app_args` on the create
    txn -- the real deployment shape design doc §2.4 measures (proof data
    arriving as application arguments), which the spike's original
    `simulate_create` did not need since its opcode-isolation probes had no
    args. Reuses `mpt_bench`'s algod/kmd clients, `compile_teal`,
    `CLEAR_TEAL`, and `_parse_sim` unmodified.
    """
    mpt_bench = _load_mpt_bench()
    from algosdk import transaction
    from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup

    extra_budget = mpt_bench.SIM_EXTRA_BUDGET_CAP if extra_budget is None else extra_budget
    acl = mpt_bench.algod_client()
    sender, sk = mpt_bench.funded_account()
    txn = transaction.ApplicationCreateTxn(
        sender=sender,
        sp=acl.suggested_params(),
        on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval,
        clear_program=mpt_bench.compile_teal(mpt_bench.CLEAR_TEAL),
        global_schema=transaction.StateSchema(0, 0),
        local_schema=transaction.StateSchema(0, 0),
        extra_pages=extra_pages,
        app_args=app_args,
    )
    sreq = SimulateRequest(
        txn_groups=[SimulateRequestTransactionGroup(txns=[txn.sign(sk)])],
        extra_opcode_budget=extra_budget,
    )
    return mpt_bench._parse_sim(acl.simulate_transactions(sreq))


if __name__ == "__main__":
    cases = build_vectors_json()
    print(f"wrote {len(cases)} cases to {VECTORS_JSON}")
    by_fork: dict[str, int] = {}
    for c in cases:
        by_fork[c["fork"]] = by_fork.get(c["fork"], 0) + 1
    for fork, count in sorted(by_fork.items()):
        print(f"  {fork}: {count}")
