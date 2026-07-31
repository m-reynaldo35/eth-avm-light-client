"""Live-tier tests for M3 (design doc §8: T1's live confirmation, T14's
budget regression, and a small-scale live confirmation of the merkleize
primitives). Requires dev-mode `algod` per
`tests/fixtures/spike-reference/README.md` (ports 4051/4052) -- matches
`ci-live.yml`, run manually/nightly, not on every PR.

T14's real point (design doc §8.1): assert the §2.5 closed-form cost model
`budget = 53 + 61*depth + 2*z` itself, not just a table of constants, so a
Puya-codegen change shows up as one clear failure. This module additionally
records what Puya-compiled code costs vs. Appendix A's hand-written TEAL
that the design doc's own numbers trace to (§11 Q2) -- they are NOT expected
to match, and this module's job is to measure and report the delta
honestly, not to assert equality with Appendix A.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile

import pytest

pytest.importorskip("algosdk")

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tests.ssz.generate_fixtures import VECTORS_JSON, simulate_create_args  # noqa: E402

ALL_CASES = json.loads(VECTORS_JSON.read_text())


def _algod_reachable() -> bool:
    try:
        from algosdk.v2client import algod

        algod.AlgodClient("a" * 64, "http://localhost:4051").status()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _algod_reachable(), reason="dev-mode algod not reachable on :4051")


@pytest.fixture(scope="module")
def compiled_teal():
    """Compile contracts/primitives/ssz/harness.py once for the whole
    module and return {contract_name: approval_teal_source}."""
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            ["algokit", "compile", "py", "contracts/primitives/ssz/harness.py", "--out-dir", tmp],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
        )
        out = pathlib.Path(tmp)
        return {
            "SSZBenchmark": (out / "SSZBenchmark.approval.teal").read_text(),
            "SSZVerifier": (out / "SSZVerifier.approval.teal").read_text(),
            "MerkleizeBenchmark": (out / "MerkleizeBenchmark.approval.teal").read_text(),
        }


def _gindex_bytes(gindex: int) -> bytes:
    return gindex.to_bytes(8, "big")


def _compile(mpt_bench, teal_src: str) -> bytes:
    return mpt_bench.compile_teal(teal_src)


# Representative real gindices spanning design doc §2.4's table, one per
# depth bucket actually in the vendored vector set.
_BUDGET_CASES = [
    ("capella/BeaconBlockBody/execution_merkle_proof", 25, 4),
    ("altair/BeaconState/current_sync_committee_merkle_proof", 54, 5),
    ("altair/BeaconState/finality_root_merkle_proof", 105, 6),
    ("electra/BeaconState/finality_root_merkle_proof", 169, 7),
]

# §2.5's closed-form model, evaluated against Appendix A's hand-written TEAL
# -- NOT expected to hold exactly for Puya-generated code; recorded for
# comparison only.
_APPENDIX_A_MEASURED = {25: 301, 54: 362, 105: 425, 169: 488}


def _z(gindex: int, depth: int) -> int:
    return sum(1 for i in range(depth) if not ((gindex >> i) & 1))


@pytest.mark.parametrize("name,gindex,depth", _BUDGET_CASES, ids=[c[0] for c in _BUDGET_CASES])
def test_t14_budget_raw_args_vs_appendix_a(compiled_teal, name, gindex, depth):
    """Re-measure design doc §2.4/§2.5 against Puya-compiled code (raw
    app-arg layout, matching Appendix A's shape exactly) and report the
    delta -- this is Q2 from §11, and the honest expectation is that Puya's
    generic bounds-checked slicing costs MORE than the hand-tuned
    `extract3`, not that it matches.
    """
    from tests.ssz.generate_fixtures import _load_mpt_bench

    mpt_bench = _load_mpt_bench()
    case = next(c for c in ALL_CASES if c["name"] == name)
    assert case["gindex"] == gindex and case["depth"] == depth

    leaf = bytes.fromhex(case["leaf"])
    branch = b"".join(bytes.fromhex(s) for s in case["branch"])
    root = bytes.fromhex(case["root"])
    app_args = [leaf, branch, _gindex_bytes(gindex), root]

    approval = _compile(mpt_bench, compiled_teal["SSZBenchmark"])
    result = simulate_create_args(approval, app_args)

    assert result.ok, f"{name}: expected acceptance, got failure: {result.failure}"

    predicted_appendix_a = 53 + 61 * depth + 2 * _z(gindex, depth)
    measured_appendix_a = _APPENDIX_A_MEASURED[gindex]
    assert predicted_appendix_a == measured_appendix_a, "sanity: §2.5 model reproduces §2.4's own table"

    puya_cost = result.app_budget_consumed
    delta = puya_cost - measured_appendix_a
    print(
        f"\n[T14] {name}: gindex={gindex} depth={depth} "
        f"Appendix A (hand TEAL)={measured_appendix_a} "
        f"Puya-compiled(SSZBenchmark)={puya_cost} delta={delta:+d} "
        f"({100 * delta / measured_appendix_a:+.1f}%)"
    )
    # Not asserting equality with Appendix A -- see module docstring. Do
    # assert the number is sane (positive, and within a generous multiple
    # of Appendix A's, as a canary against a wildly pathological codegen
    # regression rather than a tight bound).
    assert 0 < puya_cost < 5 * measured_appendix_a


def test_t14_rejects_tampered_proof_live(compiled_teal):
    from tests.ssz.generate_fixtures import _load_mpt_bench

    mpt_bench = _load_mpt_bench()
    case = next(c for c in ALL_CASES if c["name"] == "altair/BeaconState/current_sync_committee_merkle_proof")
    leaf = bytes.fromhex(case["leaf"])
    branch_items = [bytes.fromhex(s) for s in case["branch"]]
    tampered = bytearray(branch_items[0])
    tampered[0] ^= 0x01
    branch_items[0] = bytes(tampered)
    branch = b"".join(branch_items)
    root = bytes.fromhex(case["root"])
    app_args = [leaf, branch, _gindex_bytes(case["gindex"]), root]

    approval = _compile(mpt_bench, compiled_teal["SSZBenchmark"])
    result = simulate_create_args(approval, app_args)
    assert not result.ok, "tampered sibling must be rejected on-chain"


def test_arc4_verify_branch_accepts_real_vector(compiled_teal):
    """Live confirmation of the §5.4 ARC-4 shell (`SSZVerifier.verify_branch`)
    against a real vector, via a raw ABI-encoded app call (not the ARC-4
    SDK client, to keep this dependency-light) -- confirms the ARC-4
    boundary conversion (`_unpack_branch`) is correct on real data, not just
    under algopy_testing's emulation.

    `verify_branch` is not marked to allow on-create, so it cannot be
    exercised via a single create-and-call txn the way `SSZBenchmark` is
    (ARC4Contract's router requires `ApplicationID != 0`, i.e. the app must
    already exist). This deploys the app for real first (dev-mode algod
    confirms instantly) and then simulates the method call against the
    live app id -- also a more faithful reproduction of the real deployment
    shape than a single create+call txn would be.
    """
    from algosdk import abi, transaction

    from tests.ssz.generate_fixtures import _load_mpt_bench

    mpt_bench = _load_mpt_bench()
    case = next(c for c in ALL_CASES if c["name"] == "altair/BeaconState/finality_root_merkle_proof")
    leaf = bytes.fromhex(case["leaf"])
    branch_items = [bytes.fromhex(s) for s in case["branch"]]
    gindex = case["gindex"]
    root = bytes.fromhex(case["root"])

    method = abi.Method.from_signature("verify_branch(byte[32],byte[32][],uint64,byte[32])void")
    selector = method.get_selector()
    leaf_arg = abi.ABIType.from_string("byte[32]").encode(list(leaf))
    branch_arg = abi.ABIType.from_string("byte[32][]").encode([list(b) for b in branch_items])
    gindex_arg = abi.ABIType.from_string("uint64").encode(gindex)
    root_arg = abi.ABIType.from_string("byte[32]").encode(list(root))

    approval = _compile(mpt_bench, compiled_teal["SSZVerifier"])
    clear = mpt_bench.compile_teal(mpt_bench.CLEAR_TEAL)

    acl = mpt_bench.algod_client()
    sender, sk = mpt_bench.funded_account()
    create_txn = transaction.ApplicationCreateTxn(
        sender=sender,
        sp=acl.suggested_params(),
        on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval,
        clear_program=clear,
        global_schema=transaction.StateSchema(0, 0),
        local_schema=transaction.StateSchema(0, 0),
        extra_pages=3,
    )
    signed = create_txn.sign(sk)
    txid = acl.send_transaction(signed)
    confirmed = transaction.wait_for_confirmation(acl, txid, 4)
    app_id = confirmed["application-index"]

    call_txn = transaction.ApplicationCallTxn(
        sender=sender,
        sp=acl.suggested_params(),
        index=app_id,
        on_complete=transaction.OnComplete.NoOpOC,
        app_args=[selector, leaf_arg, branch_arg, gindex_arg, root_arg],
    )
    from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup

    sreq = SimulateRequest(
        txn_groups=[SimulateRequestTransactionGroup(txns=[call_txn.sign(sk)])],
        extra_opcode_budget=mpt_bench.SIM_EXTRA_BUDGET_CAP,
    )
    result = mpt_bench._parse_sim(acl.simulate_transactions(sreq))
    assert result.ok, f"ARC-4 verify_branch rejected a real vector: {result.failure}"
    print(f"\n[ARC4] verify_branch budget (app_id={app_id}): {result.app_budget_consumed}")


def test_merkleize_benchmark_matches_python_reference_live(compiled_teal):
    """Small-scale (n=5, depth=3) live confirmation that
    `merkleize_stack_push`/`finalize`/`mix_in_length` execute correctly on
    real algod, and a real (if small-scale) marginal-sha256-cost data
    point. NOT a reproduction of design doc §2.7's 512-leaf/99-app-call
    figure -- see module docstring and the final report for what T13's
    full committee-merkleization scenario still needs."""
    import hashlib

    from tests.ssz import reference
    from tests.ssz.generate_fixtures import _load_mpt_bench

    mpt_bench = _load_mpt_bench()
    n, depth = 5, 3
    chunks = [hashlib.sha256(i.to_bytes(8, "big")).digest() for i in range(n)]
    app_args = [n.to_bytes(8, "big"), b"".join(chunks), depth.to_bytes(8, "big")]

    approval = _compile(mpt_bench, compiled_teal["MerkleizeBenchmark"])
    result = simulate_create_args(approval, app_args)
    assert result.ok, f"MerkleizeBenchmark rejected valid input: {result.failure}"
    assert len(result.logs) == 2, f"expected 2 logs (vector root, list root), got {result.logs}"

    vector_root, list_root = result.logs
    ref_vector_root = reference.merkleize_chunks(chunks, depth)
    ref_list_root = reference.mix_in_length(ref_vector_root, n)
    assert vector_root == ref_vector_root
    assert list_root == ref_list_root
    print(f"\n[T13-lite] n={n} depth={depth} budget={result.app_budget_consumed}")
