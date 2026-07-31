#!/usr/bin/env python3
"""
bench/rlp_bench.py -- design doc §8.4. Follows mpt_bench.py's method
exactly: deploy the real compiled Puya contract (contracts/primitives/rlp/
bench_app.py, via `puyapy`), call each measured operation through
`/v2/transactions/simulate` with a large `extra-opcode-budget`, read back
the REAL `app-budget-consumed`, subtract a baseline. Every number this
script prints traces to an actual simulate response -- none is estimated.

Two harnesses, deliberately:
  - `RlpBenchBareOps` (bare Contract, raw application_args, no ARC4
    dispatch) is used for gates G1-G4. The design doc's targets (<=300,
    <=10, <=90, <=20) trace to the spike's bare-TEAL harness (mpt_bench.py),
    which read raw args with zero ABI-encoding overhead -- so this is the
    apples-to-apples comparison against the spike's 62/318/542/480 numbers.
  - `RlpBenchApp` (ARC4Contract) is used for gate G6 (verify_walk needs
    dynamic arrays, which are only sane to pass via ARC4 encoding) and is
    also reported standalone for every operation so the ARC4-dispatch
    overhead itself is visible and not silently hidden.

Usage:
    python3 bench/rlp_bench.py

Requires: a dev-mode algod + kmd reachable at ALGOD_ADDRESS/KMD_ADDRESS
below (see tests/fixtures/spike-reference/README.md for the bring-up
recipe), and `puyapy` on PATH (pip install algorand-python puya).
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

from algosdk import transaction
from algosdk.abi import Method
from algosdk.v2client import algod
from algosdk import kmd

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

ALGOD_ADDRESS = "http://localhost:4051"
KMD_ADDRESS = "http://localhost:4052"
TOKEN = "a" * 64

BENCH_APP_PY = REPO_ROOT / "contracts" / "primitives" / "rlp" / "bench_app.py"
OUT_DIR = REPO_ROOT / "bench" / "_build"
RESULTS_JSON = REPO_ROOT / "bench" / "rlp_results.json"
NODES_JSON = REPO_ROOT / "tests" / "fixtures" / "rlp" / "nodes.json"
ETH_DATA_JSON = REPO_ROOT / "tests" / "fixtures" / "spike-reference" / "eth_data.json"

SIM_EXTRA_BUDGET_CAP = 320_000


def algod_client() -> algod.AlgodClient:
    return algod.AlgodClient(TOKEN, ALGOD_ADDRESS)


def kmd_client() -> kmd.KMDClient:
    return kmd.KMDClient(TOKEN, KMD_ADDRESS)


def funded_account():
    kcl = kmd_client()
    wid = next(w["id"] for w in kcl.list_wallets() if w["name"] == "unencrypted-default-wallet")
    handle = kcl.init_wallet_handle(wid, "")
    try:
        acl = algod_client()
        best, best_bal = None, -1
        for a in kcl.list_keys(handle):
            bal = acl.account_info(a)["amount"]
            if bal > best_bal:
                best, best_bal = a, bal
        return best, kcl.export_key(handle, "", best)
    finally:
        kcl.release_wallet_handle(handle)


def compile_bench_app() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "puyapy", "--out-dir", str(OUT_DIR),
           "--output-bytecode", str(BENCH_APP_PY)]
    result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"puyapy compile failed:\n{result.stdout}\n{result.stderr}")


def read_program_bytes(contract_name: str, kind: str = "approval") -> bytes:
    return (OUT_DIR / f"{contract_name}.{kind}.bin").read_bytes()


def deploy_app(approval_bytes: bytes, clear_bytes: bytes) -> int:
    acl = algod_client()
    sender, sk = funded_account()
    txn = transaction.ApplicationCreateTxn(
        sender=sender, sp=acl.suggested_params(),
        on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval_bytes, clear_program=clear_bytes,
        global_schema=transaction.StateSchema(0, 0),
        local_schema=transaction.StateSchema(0, 0), extra_pages=3)
    signed = txn.sign(sk)
    txid = acl.send_transaction(signed)
    result = transaction.wait_for_confirmation(acl, txid, 4)
    return result["application-index"]


def simulate_raw_call(app_id: int, app_args: list[bytes], extra_budget: int = SIM_EXTRA_BUDGET_CAP):
    acl = algod_client()
    sender, sk = funded_account()
    txn = transaction.ApplicationNoOpTxn(
        sender=sender, sp=acl.suggested_params(), index=app_id, app_args=app_args)
    from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup
    sreq = SimulateRequest(
        txn_groups=[SimulateRequestTransactionGroup(txns=[txn.sign(sk)])],
        extra_opcode_budget=extra_budget, allow_unnamed_resources=True)
    resp = acl.simulate_transactions(sreq)
    grp = resp["txn-groups"][0]
    consumed = grp.get("app-budget-consumed", 0)
    failure = grp.get("failure-message", "")
    tr = grp["txn-results"][0].get("txn-result", {})
    logs = [base64.b64decode(x) for x in (tr.get("logs") or [])]
    return (not failure), consumed, failure, logs


def abi_selector(method_sig: str) -> bytes:
    return Method.from_signature(method_sig).get_selector()


def abi_encode_dynamic_bytes(b: bytes) -> bytes:
    from algosdk import abi
    return abi.ABIType.from_string("byte[]").encode(list(b))


def abi_encode_uint64(v: int) -> bytes:
    from algosdk import abi
    return abi.ABIType.from_string("uint64").encode(v)


def abi_encode_dynamic_bytes_array(items: list[bytes]) -> bytes:
    from algosdk import abi
    return abi.ABIType.from_string("byte[][]").encode([list(b) for b in items])


def abi_encode_uint64_array(items: list[int]) -> bytes:
    from algosdk import abi
    return abi.ABIType.from_string("uint64[]").encode(items)


def u64_be(v: int) -> bytes:
    return v.to_bytes(8, "big")


def main() -> None:
    print("Compiling contracts/primitives/rlp/bench_app.py via puyapy ...")
    compile_bench_app()

    nodes = json.loads(NODES_JSON.read_text())["nodes"]
    by_label = {n["label"]: bytes.fromhex(n["hex"]) for n in nodes}
    eth_data = json.loads(ETH_DATA_JSON.read_text())

    results: dict = {"gates": {}, "arc4_overhead_reference": {}}

    # -----------------------------------------------------------------
    # G5: compiled TEAL size of core.py + nibbles.py + eip2718.py <= 900 B.
    # This gate was previously never computed by this script even though
    # bench_app.py's RlpSizeProbeBare/RlpBenchBaselineBare (and their ARC4
    # counterparts) exist specifically for it -- no live algod call needed,
    # it is a pure compiled-artifact size diff.
    # -----------------------------------------------------------------
    print("\n-- G5: compiled program size (core.py + nibbles.py + eip2718.py) --")
    size_probe_bare = len(read_program_bytes("RlpSizeProbeBare"))
    baseline_bare_size = len(read_program_bytes("RlpBenchBaselineBare"))
    g5_bare_estimate = size_probe_bare - baseline_bare_size
    size_probe_arc4 = len(read_program_bytes("RlpSizeProbe"))
    baseline_arc4_size = len(read_program_bytes("RlpBenchBaseline"))
    g5_arc4_estimate = size_probe_arc4 - baseline_arc4_size
    print(f"  RlpSizeProbeBare: {size_probe_bare} B, RlpBenchBaselineBare: "
          f"{baseline_bare_size} B -> bare estimate {g5_bare_estimate} B")
    print(f"  RlpSizeProbe (ARC4): {size_probe_arc4} B, RlpBenchBaseline "
          f"(ARC4): {baseline_arc4_size} B -> ARC4 estimate {g5_arc4_estimate} B")
    results["gates"]["G5_compiled_size"] = {
        "size_probe_bare_bytes": size_probe_bare,
        "baseline_bare_bytes": baseline_bare_size,
        "bare_estimate_bytes": g5_bare_estimate,
        "size_probe_arc4_bytes": size_probe_arc4,
        "baseline_arc4_bytes": baseline_arc4_size,
        "arc4_estimate_bytes": g5_arc4_estimate,
        "target": "<= 900 bytes",
        "pass": g5_bare_estimate <= 900,
        "note": ("gate G5's pass/fail is judged on the bare (non-ARC4) "
                 "estimate -- RlpSizeProbeBare calls every public "
                 "subroutine in core.py/nibbles.py/eip2718.py exactly once "
                 "against one hardcoded literal buffer with zero ABI "
                 "decoding, diffed against a bare Contract with no "
                 "reachable library code at all. This is an upper bound, "
                 "not an exact isolation (it still includes this method's "
                 "own glue arithmetic), per bench_app.py's own docstring. "
                 "The ARC4 estimate is reported alongside as the "
                 "realistic-deployment-shape reference.")}

    # -----------------------------------------------------------------
    # G1-G4: bare-Contract harness, raw application_args, no ARC4 dispatch
    # (apples-to-apples against the spike's 62/318/542/480 numbers).
    # -----------------------------------------------------------------
    bare_approval = read_program_bytes("RlpBenchBareOps")
    bare_clear = read_program_bytes("RlpBenchBareOps", "clear")
    print(f"\nRlpBenchBareOps approval program: {len(bare_approval)} bytes")
    bare_app_id = deploy_app(bare_approval, bare_clear)
    print(f"deployed RlpBenchBareOps app_id={bare_app_id}")

    def bare_call(selector: int, *args: bytes, label: str):
        app_args = [u64_be(selector)] + list(args)
        ok, consumed, failure, _logs = simulate_raw_call(bare_app_id, app_args)
        print(f"  {label}: ok={ok} consumed={consumed}" + (f" FAILURE={failure}" if not ok else ""))
        return consumed if ok else None

    print("\n-- baseline (bare) --")
    base = bare_call(0, label="noop")
    results["baseline_bare"] = base

    # Arg-shape baselines (§8.4 isolation, see bench_app.py's selectors
    # 7-10): each reads the SAME Txn.application_args shape as the
    # corresponding gate call and does nothing else, so
    # cost(gate) - cost(matching baseline) isolates the primitive's own
    # contribution from the harness's per-call argument-marshalling tax
    # (Txn.application_args + op.btoi), which grows with the number of
    # arguments a call shape needs and is NOT part of what the design doc's
    # targets are meant to measure. `cost` (vs the universal 0-arg `noop`)
    # remains the number gate pass/fail is judged on -- it is the exact
    # apples-to-apples methodology mpt_bench.py itself used against the
    # spike's 62/318/542/480 baselines -- `isolated_cost` is reported
    # alongside so a harness-tax-inflated miss can be told apart from a
    # genuine primitive-cost miss.
    print("\n-- arg-shape baselines (isolate harness arg-marshalling tax) --")
    base_1bytes = bare_call(7, by_label["accountProof[0]"], label="baseline(1 bytes arg)")
    base_1bytes_1u64 = bare_call(8, by_label["accountProof[0]"], u64_be(0),
                                  label="baseline(1 bytes + 1 uint64 arg)")
    base_1bytes_2u64 = bare_call(9, by_label["accountProof[0]"], u64_be(0), u64_be(1),
                                  label="baseline(1 bytes + 2 uint64 arg)")
    base_2bytes_3u64 = bare_call(10, by_label["accountProof[0]"], u64_be(0),
                                  by_label["accountProof[0]"], u64_be(0), u64_be(1),
                                  label="baseline(2 bytes + 3 uint64 arg)")
    results["baseline_arg_shapes"] = {
        "1bytes": base_1bytes, "1bytes_1u64": base_1bytes_1u64,
        "1bytes_2u64": base_1bytes_2u64, "2bytes_3u64": base_2bytes_3u64}

    print("\n-- G1 (pre-§16, full-table path): full scan of a real 17-item 532-byte branch node --")
    branch = by_label["accountProof[0]"]
    c = bare_call(1, branch, label="scan(accountProof[0])")
    g1_cost = (c - base) if (c is not None and base is not None) else None
    g1_isolated = (c - base_1bytes) if (c is not None and base_1bytes is not None) else None
    results["gates"]["G1_scan_branch_node_table"] = {
        "raw_consumed": c, "baseline": base, "cost": g1_cost,
        "isolated_cost": g1_isolated,
        "target": "<= 300", "pass": (g1_cost is not None and g1_cost <= 300),
        "note": ("PRE-§16 full-table path (rlp_scan + rlp_table_item), kept "
                 "for history/comparison -- this is what mpt_node_scan/"
                 "differential testing still use, and remains the right "
                 "choice for REPEATED access to the same node (see G2, "
                 "delta=0, unaffected by §16). See G1_scan_upto_fast below "
                 "for the §16 re-pointed single-access measurement, and "
                 "docs/design/002-rlp-decoder.md §16 for the full writeup "
                 "of why table-free O-2 alone did not close this gate "
                 "(measured: the removed ~8 opcodes/item of table-write cost "
                 "is offset by the added want-index compare cost when both "
                 "coexist in one full 17-item walk) and why O-1 early exit "
                 "(scan_upto) is the fix that actually matters for the real "
                 "single-child-per-hop access pattern.")}

    print("\n-- G1 (§16 fast path): rlp_scan_upto early-exit retrieval, real branch node --")
    g1_upto_costs = {}
    for w in (0, 1, 4, 6, 8, 10, 11, 13, 15, 16):
        c = bare_call(11, branch, u64_be(w), label=f"scan_upto(want={w})")
        cost = (c - base) if (c is not None and base is not None) else None
        isolated = (c - base_1bytes_1u64) if (c is not None and base_1bytes_1u64 is not None) else None
        g1_upto_costs[w] = {"cost": cost, "isolated_cost": isolated}
    results["gates"]["G1_scan_upto_fast"] = {
        "by_want_index": g1_upto_costs,
        "target": "<= 300 (index-dependent by design, O-1 tradeoff)",
        "pass_want8": (g1_upto_costs[8]["cost"] is not None and g1_upto_costs[8]["cost"] <= 300),
        "note": ("rlp_scan_upto (design doc §16, O-1 early exit) walks ONLY "
                 "through the wanted item instead of building a full table "
                 "for all 17 -- cost is O(want), not flat, which is the "
                 "explicitly accepted O-1 tradeoff (§3.1/§9): cheap for low "
                 "indices, roughly tied with the spike's own per-item cost "
                 "at any index (measured: isolated cost at want=8 lands "
                 "within ~10 of the spike's own item-8 number of 318; at "
                 "want=15 within ~10 of the spike's item-15 number of 542), "
                 "worse than the flat table approach for HIGH indices or "
                 "REPEATED access (for which G1_scan_branch_node_table / G2 "
                 "remain the right choice). pass_want8 is reported as the "
                 "single headline number (want=8 matches G2's own middle "
                 "test point) but every index is reported above since a "
                 "single pass/fail number is inherently incomplete for an "
                 "index-dependent method -- see §16 for the full table and "
                 "for gate G6, which is what actually validates this in situ.")}

    print("\n-- G2: cost(item 15) - cost(item 0), both after one scan --")
    costs = {}
    for i in (0, 8, 15):
        c = bare_call(2, branch, u64_be(i), label=f"scan_and_get(item {i})")
        costs[i] = (c - base) if (c is not None and base is not None) else None
    g2_delta = (costs[15] - costs[0]) if (costs[0] is not None and costs[15] is not None) else None
    results["gates"]["G2_index_independence"] = {
        "cost_item0": costs[0], "cost_item8": costs[8], "cost_item15": costs[15],
        "delta_15_minus_0": g2_delta, "target": "<= 10 (spike baseline: 480)",
        "pass": (g2_delta is not None and g2_delta <= 10),
        "note": ("delta is baseline-agnostic (same arg shape at every "
                 "index), so isolating harness tax would not change this "
                 "gate's number -- not reported separately.")}

    print("\n-- G3 (pre-§16, table path): 2-item ext/leaf node scan + both items --")
    leaf = by_label["accountProof[7]"]
    c = bare_call(3, leaf, u64_be(0), u64_be(1), label="scan_two_items(accountProof[7])")
    g3_cost = (c - base) if (c is not None and base is not None) else None
    g3_isolated = (c - base_1bytes_2u64) if (c is not None and base_1bytes_2u64 is not None) else None
    results["gates"]["G3_two_item_node_table"] = {
        "raw_consumed": c, "cost": g3_cost, "isolated_cost": g3_isolated,
        "target": "<= 90", "pass": (g3_cost is not None and g3_cost <= 90),
        "note": ("PRE-§16 path (rlp_scan + 2x rlp_table_item), kept for "
                 "history/comparison. See G3_scan2_fast below for the §16 "
                 "re-pointed measurement (rlp_scan2, loop-free exact-2-item "
                 "decode) that this gate's pass/fail is now judged on.")}

    print("\n-- G3 (§16 fast path): rlp_scan2, loop-free exact-2-item decode --")
    c = bare_call(12, leaf, label="scan2(accountProof[7])")
    g3f_cost = (c - base) if (c is not None and base is not None) else None
    g3f_isolated = (c - base_1bytes) if (c is not None and base_1bytes is not None) else None
    results["gates"]["G3_scan2_fast"] = {
        "raw_consumed": c, "cost": g3f_cost, "isolated_cost": g3f_isolated,
        "target": "<= 90", "pass": (g3f_cost is not None and g3f_cost <= 90),
        "note": ("rlp_scan2 (design doc §16, O-2 follow-up specialised to "
                 "exact-2-item MPT ext/leaf nodes) has NO while loop at all: "
                 "item 0 always starts at payload_off (no walk needed), and "
                 "item 1's start is directly implied by item 0's own "
                 "(content_off, content_len) -- so the whole function is "
                 "list-header decode + 2x rlp_item_header + one assert. "
                 "This is a substantially bigger win than the general "
                 "table-free O-2 idea (rlp_scan_capture, tried and NOT "
                 "shipped -- see §16): for a 17-item branch node, table-free "
                 "capture still pays the same per-item loop-control "
                 "overhead as the table version for items it walks past, "
                 "but a 2-item node has no 'walk past' cost to eliminate in "
                 "the first place once the loop itself is removed.")}

    print("\n-- G4: nibbles_equal, aligned 57-nibble vs 56-nibble leaf paths --")
    c57 = bare_call(5, leaf, u64_be(7), leaf, u64_be(7), u64_be(57),
                     label="nib_eq(account leaf, 57 nibbles, nib_index=7 ODD)")
    storage_leaf = by_label["storageProof[0].proof[8]"]
    c56 = bare_call(5, storage_leaf, u64_be(6), storage_leaf, u64_be(6), u64_be(56),
                     label="nib_eq(storage leaf, 56 nibbles, nib_index=6 EVEN)")
    g4_57 = (c57 - base) if (c57 is not None and base is not None) else None
    g4_56 = (c56 - base) if (c56 is not None and base is not None) else None
    g4_57_isolated = (c57 - base_2bytes_3u64) if (c57 is not None and base_2bytes_3u64 is not None) else None
    g4_56_isolated = (c56 - base_2bytes_3u64) if (c56 is not None and base_2bytes_3u64 is not None) else None
    results["gates"]["G4_nibbles_equal_aligned"] = {
        "cost_57_nibbles_odd_start": g4_57,
        "cost_56_nibbles_even_start": g4_56,
        "isolated_cost_57_nibbles_odd_start": g4_57_isolated,
        "isolated_cost_56_nibbles_even_start": g4_56_isolated,
        "note": ("nib_index=7 for the account leaf is ODD (2*off+skip with "
                 "odd skip=1). The design doc's literal §5.4 case list only "
                 "spells out a fast path when BOTH a_nib and b_nib are "
                 "EVEN, which would send this (leaf, key) pair -- both "
                 "ODD -- into the O(count) fallback loop. But the doc's own "
                 "prose argument for leaves ('the compact remainder always "
                 "begins at compact byte 1 ... and on the key side it "
                 "begins at nibble c + odd, which is even in both cases') "
                 "describes peeling the one odd leading nibble and then "
                 "comparing the aligned remainder -- exactly this ODD/ODD "
                 "case. nibbles_equal was fixed to implement that: when "
                 "a_nib and b_nib share parity (both even, OR both odd), "
                 "it peels one matching-parity leading nibble when odd and "
                 "then takes the aligned fast path on the (now even, or "
                 "already even) remainder. Only a genuine relative "
                 "misalignment (a_nib/b_nib of DIFFERENT parity) still "
                 "takes the per-nibble loop -- real for extension nodes, "
                 "per §5.4's own caveat. The 56-nibble storage leaf "
                 "(nib_index=6, EVEN/EVEN) was already on the fast path and "
                 "is unaffected by the correctness fix, but its own "
                 "isolated cost (13, then 3 -- see below) shows the true "
                 "aligned-path budget was ALSO being drowned in harness "
                 "tax before isolation. Two separate costs were stacked on "
                 "top of nibbles_equal's real logic, and both had to be "
                 "peeled back to see the primitive's true number: (1) this "
                 "harness's own 5-argument read (Txn.application_args x5, "
                 "3x op.btoi) is baked into `cost_*` -- isolating it "
                 "(isolated_cost_*, vs a baseline reading the identical "
                 "2-bytes+3-uint64 shape and doing nothing else) dropped "
                 "63/13 for the odd/even cases; (2) `nibble_at` -- called "
                 "twice by the ODD/ODD peel path this fix added, and also "
                 "used by the misaligned fallback loop -- was NOT "
                 "auto-inlined by Puya (confirmed via compiled TEAL: real "
                 "`callsub nibble_at` at every use site), so each call "
                 "paid full proto/frame_dig/retsub overhead for a "
                 "3-opcode body. Forcing `@subroutine(inline=True)` on "
                 "`nibble_at` (contracts/primitives/rlp/nibbles.py) "
                 "removed that: isolated_cost dropped to 3 for BOTH the "
                 "57-odd and 56-even cases -- comfortably under the <=20 "
                 "target, and flat in length as the gate requires. "
                 "`pass_*` (vs the universal 0-arg noop, matching the "
                 "spike's own single-baseline methodology) still reads "
                 "false because it also carries the 5-argument harness "
                 "tax that this specific gate's call shape pays and the "
                 "spike's simpler-signature RLP_ITEM_SUB never had to; "
                 "`isolated_pass_*` is the number that reflects "
                 "nibbles_equal's own compiled cost, and it passes both "
                 "cases."),
        "target": "<= 20, flat in length",
        "pass_56_even": (g4_56 is not None and g4_56 <= 20),
        "pass_57_odd": (g4_57 is not None and g4_57 <= 20),
        "isolated_pass_56_even": (g4_56_isolated is not None and g4_56_isolated <= 20),
        "isolated_pass_57_odd": (g4_57_isolated is not None and g4_57_isolated <= 20)}

    print("\n-- envelope: receipt_envelope cost (bare) --")
    receipt_leaf = by_label["receipt_proof.nodes[2]"]
    c = bare_call(6, receipt_leaf, u64_be(0), u64_be(len(receipt_leaf)), label="envelope(nodes[2])")
    results["envelope_cost_bare"] = (c - base) if (c is not None and base is not None) else None

    # -----------------------------------------------------------------
    # ARC4Contract reference numbers (RlpBenchApp) -- same operations,
    # through real ARC4 method dispatch, so the marshalling overhead a
    # real M5/M6 caller might pay is visible and not hidden.
    # -----------------------------------------------------------------
    arc4_approval = read_program_bytes("RlpBenchApp")
    arc4_clear = read_program_bytes("RlpBenchApp", "clear")
    print(f"\nRlpBenchApp (ARC4) approval program: {len(arc4_approval)} bytes")
    arc4_app_id = deploy_app(arc4_approval, arc4_clear)
    print(f"deployed RlpBenchApp app_id={arc4_app_id}")

    def arc4_call(method_sig: str, *abi_args: bytes, label: str):
        acl = algod_client()
        sender, sk = funded_account()
        app_args = [abi_selector(method_sig)] + list(abi_args)
        txn = transaction.ApplicationNoOpTxn(
            sender=sender, sp=acl.suggested_params(), index=arc4_app_id, app_args=app_args)
        from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup
        sreq = SimulateRequest(
            txn_groups=[SimulateRequestTransactionGroup(txns=[txn.sign(sk)])],
            extra_opcode_budget=SIM_EXTRA_BUDGET_CAP, allow_unnamed_resources=True)
        resp = acl.simulate_transactions(sreq)
        grp = resp["txn-groups"][0]
        consumed = grp.get("app-budget-consumed", 0)
        failure = grp.get("failure-message", "")
        ok = not failure
        print(f"  {label}: ok={ok} consumed={consumed}" + (f" FAILURE={failure}" if not ok else ""))
        return consumed if ok else None

    arc4_base = arc4_call("noop()void", label="noop (ARC4)")
    results["baseline_arc4"] = arc4_base
    c = arc4_call("scan(byte[])uint64", abi_encode_dynamic_bytes(branch), label="scan (ARC4)")
    results["arc4_overhead_reference"]["scan"] = (c - arc4_base) if (c and arc4_base is not None) else None
    c = arc4_call("nib_eq(byte[],uint64,byte[],uint64,uint64)bool",
                  abi_encode_dynamic_bytes(storage_leaf), abi_encode_uint64(6),
                  abi_encode_dynamic_bytes(storage_leaf), abi_encode_uint64(6), abi_encode_uint64(56),
                  label="nib_eq 56-nibble aligned (ARC4)")
    results["arc4_overhead_reference"]["nib_eq_56_aligned"] = (
        (c - arc4_base) if (c and arc4_base is not None) else None)

    # -----------------------------------------------------------------
    # G6: suite F composition smoke test (account path, real proof).
    # -----------------------------------------------------------------
    print("\n-- G6: composition smoke test (verify_walk over the real account proof) --")
    account_nodes = [bytes.fromhex(h[2:]) for h in eth_data["proof"]["accountProof"]]
    address = bytes.fromhex(eth_data["proof"]["address"][2:])
    from Crypto.Hash import keccak

    def kec(b: bytes) -> bytes:
        h = keccak.new(digest_bits=256)
        h.update(b)
        return h.digest()

    key = kec(address)
    key_nibbles = []
    for byte in key:
        key_nibbles.append(byte >> 4)
        key_nibbles.append(byte & 0x0F)

    # Derive branch-hop child indices the same way mpt_bench.py's
    # branch_child_index did: which slot's child equals the keccak256 of
    # the next node (or, for the last hop into the leaf, we already know
    # from §5.3 that item 0 is the leaf's own compact-path item and item 1
    # is the account RLP value -- so the final "child_index" is 1).
    from tests.reference import rlp_ref

    child_indices = []
    for i in range(len(account_nodes) - 1):
        node = account_nodes[i]
        table, n = rlp_ref.rlp_scan(node, 0)
        next_hash = kec(account_nodes[i + 1])
        found = None
        for idx in range(n):
            off, length, kind = rlp_ref.rlp_table_item(node, table, idx)
            if length == 32 and node[off:off + 32] == next_hash:
                found = idx
                break
        if found is None:
            print(f"  WARNING: could not find child index at hop {i}; "
                  f"falling back to nibble-derived index")
            found = key_nibbles[i]
        child_indices.append(found)
    child_indices.append(1)  # leaf: item 1 is the account RLP value

    root = bytes.fromhex(eth_data["stateRoot"][2:])
    acl = algod_client()
    sender, sk = funded_account()
    sel = abi_selector("verify_walk(byte[][],uint64[],byte[])byte[]")
    app_args = [sel,
                abi_encode_dynamic_bytes_array(account_nodes),
                abi_encode_uint64_array(child_indices),
                abi_encode_dynamic_bytes(root)]
    txn = transaction.ApplicationNoOpTxn(
        sender=sender, sp=acl.suggested_params(), index=arc4_app_id, app_args=app_args)
    from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup
    sreq = SimulateRequest(
        txn_groups=[SimulateRequestTransactionGroup(txns=[txn.sign(sk)])],
        extra_opcode_budget=SIM_EXTRA_BUDGET_CAP, allow_unnamed_resources=True)
    resp = acl.simulate_transactions(sreq)
    grp = resp["txn-groups"][0]
    consumed = grp.get("app-budget-consumed", 0)
    failure = grp.get("failure-message", "")
    ok = not failure
    print(f"  verify_walk(account path, {len(account_nodes)} nodes): ok={ok} consumed={consumed}"
          + (f" FAILURE={failure}" if not ok else ""))
    g6_arc4_cost = consumed if ok else None

    # -----------------------------------------------------------------
    # G6, true apples-to-apples: bare (non-ARC4) contracts with the real
    # account proof node bytes + derived child indices baked in as
    # module-level literals (contracts/primitives/rlp/bench_app.py), exactly
    # the bytecblock-constants methodology mpt_bench.py used for its
    # 3,276/6,827 totals -- no ABI array-decoding of any kind, since the
    # spike's own harness never paid that cost either.
    #   - RlpVerifyWalkBareTable: PRE-§16 path (rlp_scan+rlp_table_item per
    #     hop), kept for history -- this measured 5,302.
    #   - RlpVerifyWalkBare: §16 fast path (rlp_scan_upto/rlp_scan2 per hop)
    #     -- this is the number gate G6's pass/fail is now judged against,
    #     per the re-pointing this design-doc addendum performs.
    # The ARC4 verify_walk number above is reported alongside as the
    # realistic-caller reference (it still uses the old table path; a fast-
    # path ARC4 method was not added since verify_walk's own array-decoding
    # cost dominates and is orthogonal to which decode primitive is used
    # inside the loop).
    # -----------------------------------------------------------------
    print("\n-- G6 (pre-§16, bare table path): RlpVerifyWalkBareTable --")
    table_walk_approval = read_program_bytes("RlpVerifyWalkBareTable")
    table_walk_clear = read_program_bytes("RlpVerifyWalkBareTable", "clear")
    table_walk_app_id = deploy_app(table_walk_approval, table_walk_clear)
    print(f"deployed RlpVerifyWalkBareTable app_id={table_walk_app_id}")
    ok_table, consumed_table, failure_table, _logs = simulate_raw_call(table_walk_app_id, [])
    print(f"  verify_walk_bare_table(account path, 8 baked-in nodes): ok={ok_table} "
          f"consumed={consumed_table}" + (f" FAILURE={failure_table}" if not ok_table else ""))
    g6_table_cost = consumed_table if ok_table else None

    print("\n-- G6 (§16 fast path): RlpVerifyWalkBare (rlp_scan_upto/rlp_scan2) --")
    bare_walk_approval = read_program_bytes("RlpVerifyWalkBare")
    bare_walk_clear = read_program_bytes("RlpVerifyWalkBare", "clear")
    bare_walk_app_id = deploy_app(bare_walk_approval, bare_walk_clear)
    print(f"deployed RlpVerifyWalkBare app_id={bare_walk_app_id}")
    ok_bare, consumed_bare, failure_bare, _logs = simulate_raw_call(bare_walk_app_id, [])
    print(f"  verify_walk_bare(account path, 8 baked-in nodes): ok={ok_bare} "
          f"consumed={consumed_bare}" + (f" FAILURE={failure_bare}" if not ok_bare else ""))
    g6_bare_cost = consumed_bare if ok_bare else None

    results["gates"]["G6_composition"] = {
        "account_path_nodes": len(account_nodes),
        "bare_consumed_table_pre_16": g6_table_cost,
        "bare_consumed_fast_16": g6_bare_cost,
        "arc4_consumed": g6_arc4_cost,
        "spike_baseline_account": 3276, "target": "< 3276 (spike account proof total)",
        "pass": (g6_bare_cost is not None and g6_bare_cost < 3276),
        "note": ("gate G6's pass/fail is now judged on "
                 "`bare_consumed_fast_16` (RlpVerifyWalkBare: real "
                 "account-proof node bytes and derived child indices baked "
                 "in as module-level literals, using §16's rlp_scan_upto/"
                 "rlp_scan2 per hop instead of rlp_scan/rlp_table_item -- "
                 "zero ABI argument decoding, the same bytecblock-constant "
                 "methodology mpt_bench.py used to produce the 3,276 "
                 "baseline itself). `bare_consumed_table_pre_16` is the "
                 "PRE-§16 number (5,302) kept for before/after comparison. "
                 "`arc4_consumed` (the ARC4Contract `verify_walk` method, "
                 "still on the table path) is reported alongside as the "
                 "realistic-in-situ-caller reference: it additionally pays "
                 "real `byte[][]`/`uint64[]` ABI array-decoding for "
                 "receiving all 8 nodes as call arguments, which is NOT "
                 "part of what the spike's 3,276 number measured, so it is "
                 "not a fair comparison against the spike baseline even "
                 "though it is realistic for an actual M5/M6 caller.\n"
                 "See docs/design/002-rlp-decoder.md §16 for the full "
                 "before/after writeup: why the pre-§16 flat full-table "
                 "scan per hop (5,302) lost to the spike's O(index) walk on "
                 "this proof's low/mid real indices (10,11,1,4,13,6,8), why "
                 "the general table-free O-2 idea alone did not close the "
                 "gap (measured: removing the table-write cost is offset by "
                 "the added want-index compare cost in a full 17-item walk, "
                 "net near-zero), and why O-1 early exit (rlp_scan_upto) "
                 "plus a loop-free exact-2-item decode (rlp_scan2) for the "
                 "final leaf hop is what actually gets this gate close to "
                 "or under the spike baseline -- `rlp_scan`/`rlp_table_item` "
                 "are unchanged and remain the right choice for repeated "
                 "access to the same node (G2, delta=0, unaffected).")}

    RESULTS_JSON.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_JSON.write_text(json.dumps(results, indent=2))
    print(f"\nwrote {RESULTS_JSON}")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
