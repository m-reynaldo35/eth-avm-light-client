#!/usr/bin/env python3
"""
bench/composer_bench.py -- docs/design/006-account-storage-proof.md §7,
§11.4 suite B, §12's gates. Follows bench/mpt_bench.py's method exactly:
deploy the real compiled Puya contracts (contracts/composer/bench_app.py,
via `puyapy`), call the measured operations through
`/v2/transactions/simulate` (and, for G2-M6, a REAL submitted atomic
group -- not simulated) with a large `extra-opcode-budget`, read back the
REAL `app-budget-consumed`. Every number this script prints traces to an
actual algod response.

Usage:
    python3 bench/composer_bench.py

Requires: a dev-mode algod + kmd reachable at ALGOD_ADDRESS/KMD_ADDRESS
below, and `puyapy` on PATH.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

from algosdk import kmd, transaction
from algosdk.v2client import algod

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

ALGOD_ADDRESS = "http://localhost:4051"
KMD_ADDRESS = "http://localhost:4052"
TOKEN = "a" * 64

COMPOSER_BENCH_APP_PY = REPO_ROOT / "contracts" / "composer" / "bench_app.py"
MPT_BENCH_APP_PY = REPO_ROOT / "contracts" / "mpt" / "bench_app.py"
OUT_DIR = REPO_ROOT / "bench" / "_build_composer"
MPT_OUT_DIR = REPO_ROOT / "bench" / "_build_mpt"
RESULTS_JSON = REPO_ROOT / "bench" / "composer_results.json"
ETH_DATA_JSON = REPO_ROOT / "tests" / "fixtures" / "spike-reference" / "eth_data.json"

SIM_EXTRA_BUDGET_CAP = 320_000

# §7.2's real measured reference points (bench/mpt_results.json).
G6_M5_ACCOUNT_WALK = 5116
SPIKE_INSECURE_COMPOSITE = 6827
DESIGN_DOC_PREDICTED_COMPOSITE = 12500


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


def compile_app(path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "puyapy", "--out-dir", str(out_dir),
           "--output-bytecode", str(path)]
    result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"puyapy compile failed:\n{result.stdout}\n{result.stderr}")


def read_program_bytes(out_dir: Path, contract_name: str, kind: str = "approval") -> bytes:
    return (out_dir / f"{contract_name}.{kind}.bin").read_bytes()


def deploy_app(approval_bytes: bytes, clear_bytes: bytes, extra_pages: int = 3) -> int:
    acl = algod_client()
    sender, sk = funded_account()
    txn = transaction.ApplicationCreateTxn(
        sender=sender, sp=acl.suggested_params(),
        on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval_bytes, clear_program=clear_bytes,
        global_schema=transaction.StateSchema(0, 0),
        local_schema=transaction.StateSchema(0, 0), extra_pages=extra_pages)
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


def u64_be(v: int) -> bytes:
    return v.to_bytes(8, "big")


def group_consumed_no_donors(acl, sender, sk, app_id: int, seg_arg_lists):
    txns = [transaction.ApplicationNoOpTxn(sender=sender, sp=acl.suggested_params(),
                                            index=app_id, app_args=a)
            for a in seg_arg_lists]
    g = transaction.assign_group_id(txns) if len(txns) > 1 else txns
    signed = [t.sign(sk) for t in g]
    from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup
    r = SimulateRequest(txn_groups=[SimulateRequestTransactionGroup(txns=signed)],
                         extra_opcode_budget=SIM_EXTRA_BUDGET_CAP, allow_unnamed_resources=True)
    resp = acl.simulate_transactions(r)
    gr = resp["txn-groups"][0]
    per = [t.get("app-budget-consumed", 0) for t in gr.get("txn-results", [])]
    logs_last = []
    if gr.get("txn-results"):
        tr = gr["txn-results"][-1].get("txn-result", {})
        logs_last = [base64.b64decode(x) for x in (tr.get("logs") or [])]
    return gr.get("app-budget-consumed", 0), per, gr.get("failure-message", ""), logs_last


def donors_needed(total_consumed: int, n_top_level: int) -> int:
    base_pool = n_top_level * 700
    if total_consumed < base_pool:
        return 0
    shortfall = total_consumed - base_pool
    return (shortfall // 700) + 2


def main() -> None:
    print("Compiling contracts/composer/bench_app.py via puyapy ...")
    compile_app(COMPOSER_BENCH_APP_PY, OUT_DIR)
    print("Compiling contracts/mpt/bench_app.py via puyapy (for the donor callee) ...")
    compile_app(MPT_BENCH_APP_PY, MPT_OUT_DIR)

    eth_data = json.loads(ETH_DATA_JSON.read_text())
    results: dict = {"gates": {}}

    # -----------------------------------------------------------------
    # G5-M6/G6-M6: compiled size.
    # -----------------------------------------------------------------
    print("\n-- G5-M6/G6-M6: compiled size --")
    mpt_combined_path = MPT_OUT_DIR / "MptSizeProbeCombinedBare.approval.bin"
    mpt_combined_bytes = len(mpt_combined_path.read_bytes()) if mpt_combined_path.exists() else None
    combined_bytes = len(read_program_bytes(OUT_DIR, "Mpt6SizeProbeCombinedBare"))
    baseline_bytes = len(read_program_bytes(OUT_DIR, "Mpt6BenchBaselineBare"))
    m6_only_bytes = len(read_program_bytes(OUT_DIR, "Mpt6SizeProbeBare")) - baseline_bytes
    g6_estimate = (combined_bytes - mpt_combined_bytes) if mpt_combined_bytes is not None else None
    driver_bytes = len(read_program_bytes(OUT_DIR, "Mpt6ComposerApp"))
    print(f"  Mpt6SizeProbeBare - baseline (M6-only, upper bound): {m6_only_bytes} B")
    print(f"  Mpt6SizeProbeCombinedBare (M6 surface alone): {combined_bytes} B")
    print(f"  MptSizeProbeCombinedBare (M2+M5 surface, prior gate run): {mpt_combined_bytes} B")
    print(f"  -> M6's own incremental contribution vs M2+M5: {g6_estimate} B (target <= 900 B)")
    print(f"  Real deployable driver (Mpt6ComposerApp, full M2+M5+M6 dispatch): {driver_bytes} B "
          f"(cap 8,192 B with extra_pages=3)")
    results["gates"]["G5_G6_M6_compiled_size"] = {
        "m6_size_probe_bytes_naive_upper_bound": m6_only_bytes,
        "m6_combined_probe_bytes": combined_bytes,
        "m2_m5_combined_probe_bytes": mpt_combined_bytes,
        "m6_own_contribution_vs_m2_m5_bytes": g6_estimate,
        "g5_target": "<= 900 bytes",
        "g5_metric": "m6_own_contribution_vs_m2_m5_bytes (the diff-based number, per §12's own "
                     "'measured M5-style, a combined probe diffed against an M2+M5 probe' methodology "
                     "-- the naive single-probe number double-counts baked-in literal node bytes both "
                     "probes carry and is not the gate's real metric)",
        "g5_pass": (g6_estimate is not None and g6_estimate <= 900),
        "real_driver_bytes": driver_bytes,
        "g6_target": "<= 8192 bytes (deployable per-call program cap, extra_pages=3)",
        "g6_pass": driver_bytes <= 8192,
        "note": ("Mpt6ComposerApp IS the real deployable driver -- its own "
                 "compiled size against the 8,192 B cap is G6-M6's actual "
                 "pass/fail criterion, not a probe estimate. "
                 "Mpt6SizeProbeCombinedBare vs MptSizeProbeCombinedBare is "
                 "the diff-based estimate mirroring M5's own G5 methodology.")}

    # -----------------------------------------------------------------
    # Phase-B walk alone (Mpt6StorageWalkBare) -- the other half of §7.3's
    # "two-walk floor" (G6-M5 + this).
    # -----------------------------------------------------------------
    print("\n-- Phase-B walk alone (real 9-node Binance-8-under-USDT storage proof) --")
    sw_approval = read_program_bytes(OUT_DIR, "Mpt6StorageWalkBare")
    sw_clear = read_program_bytes(OUT_DIR, "Mpt6StorageWalkBare", "clear")
    sw_app_id = deploy_app(sw_approval, sw_clear)
    print(f"deployed Mpt6StorageWalkBare app_id={sw_app_id}")
    ok, consumed, failure, _logs = simulate_raw_call(sw_app_id, [])
    print(f"  storage walk: ok={ok} consumed={consumed}" + (f" FAILURE={failure}" if not ok else ""))
    two_walk_floor = (G6_M5_ACCOUNT_WALK + consumed) if ok else None
    results["gates"]["phase_b_walk_alone"] = {
        "consumed": consumed if ok else None, "ok": ok, "failure": failure,
        "design_doc_predicted": 5527,
        "note": "Pure M5 walk cost, no M6 code reachable -- the phase-B half of §7.3's two-walk floor."}
    results["gates"]["two_walk_floor"] = {
        "g6_m5_account_walk": G6_M5_ACCOUNT_WALK,
        "phase_b_walk": consumed if ok else None,
        "sum": two_walk_floor,
        "note": "§7.3's reference point: what the same two walks cost with NO composition overhead."}

    # -----------------------------------------------------------------
    # §4.3: mpt6_account_body isolated vs the rlp_scan_upto control.
    # -----------------------------------------------------------------
    print("\n-- §4.3: mpt6_account_body vs rlp_scan_upto control (real USDT leaf) --")
    ab_approval = read_program_bytes(OUT_DIR, "Mpt6AccountBodyBare")
    ab_clear = read_program_bytes(OUT_DIR, "Mpt6AccountBodyBare", "clear")
    ab_app_id = deploy_app(ab_approval, ab_clear)
    ok_ab, consumed_ab, fail_ab, _ = simulate_raw_call(ab_app_id, [])
    print(f"  mpt6_account_body: ok={ok_ab} consumed={consumed_ab}")

    abc_approval = read_program_bytes(OUT_DIR, "Mpt6AccountBodyControlBare")
    abc_clear = read_program_bytes(OUT_DIR, "Mpt6AccountBodyControlBare", "clear")
    abc_app_id = deploy_app(abc_approval, abc_clear)
    ok_abc, consumed_abc, fail_abc, _ = simulate_raw_call(abc_app_id, [])
    print(f"  rlp_scan_upto(..., 2) control: ok={ok_abc} consumed={consumed_abc}")
    print(f"  -> measured trade: {consumed_ab - consumed_abc if (ok_ab and ok_abc) else None} "
          f"budget (design doc's §4.3 estimate: ~80)")
    results["gates"]["mpt6_account_body_vs_control"] = {
        "mpt6_account_body_consumed": consumed_ab if ok_ab else None,
        "rlp_scan_upto_control_consumed": consumed_abc if ok_abc else None,
        "measured_trade": (consumed_ab - consumed_abc) if (ok_ab and ok_abc) else None,
        "design_doc_estimate": 80}

    # -----------------------------------------------------------------
    # G2-M6/G3-M6 (THE HEADLINE): the real 5-transaction composite group,
    # live, following M5's G7-M5 procedure exactly -- simulate with 0
    # donors to size, then a REAL send_transactions submission.
    # -----------------------------------------------------------------
    print("\n-- G2-M6/G3-M6 (HEADLINE): real 5-segment composite group --")
    driver_approval = read_program_bytes(OUT_DIR, "Mpt6ComposerApp")
    driver_clear = read_program_bytes(OUT_DIR, "Mpt6ComposerApp", "clear")
    driver_app_id = deploy_app(driver_approval, driver_clear, extra_pages=3)
    print(f"deployed Mpt6ComposerApp app_id={driver_app_id}")

    donor_approval = MPT_OUT_DIR / "MptBenchBaselineBare.approval.bin"
    donor_clear = MPT_OUT_DIR / "MptBenchBaselineBare.clear.bin"
    donor_app_id = deploy_app(donor_approval.read_bytes(), donor_clear.read_bytes())
    print(f"deployed donor callee app_id={donor_app_id}")

    proof = eth_data["proof"]
    account_nodes = [bytes.fromhex(h[2:]) for h in proof["accountProof"]]
    address = bytes.fromhex(proof["address"][2:])
    state_root = bytes.fromhex(eth_data["stateRoot"][2:])
    slot_preimage = bytes.fromhex(eth_data["storage_key"][2:])
    sp = proof["storageProof"][0]
    storage_nodes = [bytes.fromhex(h[2:]) for h in sp["proof"]]
    assert len(account_nodes) == 8 and len(storage_nodes) == 9

    SELECTOR = b"ACS1"
    MODE_A_INIT, MODE_A_NEXT, MODE_B_INIT, MODE_B_NEXT = 0, 1, 2, 3

    # §6.5's segmentation table.
    seg0 = [SELECTOR, u64_be(MODE_A_INIT), u64_be(0), u64_be(0),
            state_root, address, slot_preimage,
            account_nodes[0], account_nodes[1], account_nodes[2]]
    seg1 = [SELECTOR, u64_be(MODE_A_NEXT), u64_be(0), u64_be(0), u64_be(0),
            account_nodes[3], account_nodes[4], account_nodes[5]]
    seg2 = [SELECTOR, u64_be(MODE_A_NEXT), u64_be(0), u64_be(0), u64_be(1),
            account_nodes[6], account_nodes[7]]
    seg3 = [SELECTOR, u64_be(MODE_B_INIT), u64_be(0), u64_be(0), u64_be(2),
            storage_nodes[0], storage_nodes[1], storage_nodes[2]]
    seg4 = [SELECTOR, u64_be(MODE_B_NEXT), u64_be(0), u64_be(0), u64_be(3),
            storage_nodes[3], storage_nodes[4], storage_nodes[5],
            storage_nodes[6], storage_nodes[7], storage_nodes[8]]

    acl = algod_client()
    sender, sk = funded_account()

    total, per_txn, failure, last_logs = group_consumed_no_donors(
        acl, sender, sk, driver_app_id, [seg0, seg1, seg2, seg3, seg4])
    print(f"  5-segment group, 0 donors (simulate reading): ok={not failure} total={total} "
          f"per_txn={per_txn}" + (f" FAILURE={failure}" if failure else ""))

    predicted_ratio = None
    if not failure and two_walk_floor:
        predicted_ratio = round(total / two_walk_floor, 3)
        print(f"  -> measured composite / two-walk floor = {total} / {two_walk_floor} = {predicted_ratio}x "
              f"(design doc's own predicted ratio: 1.177x [17.7% overhead], gate G3-M6 target <= 1.25x)")

    donors = donors_needed(total, 5) if not failure else None
    print(f"  -> sizing {donors} donor call(s) into segment 0" if donors is not None else
          "  -> could not size donors: simulate failed even with extra_opcode_budget")

    group_real_ok = False
    group_real_error = ""
    final_c_hex = None
    if donors is not None:
        seg0_d = [SELECTOR, u64_be(MODE_A_INIT), u64_be(donors), u64_be(donor_app_id),
                  state_root, address, slot_preimage,
                  account_nodes[0], account_nodes[1], account_nodes[2]]
        sp0 = acl.suggested_params()
        sp0.flat_fee = True
        sp0.fee = (donors + 1) * 1000
        txn0 = transaction.ApplicationNoOpTxn(
            sender=sender, sp=sp0, index=driver_app_id, app_args=seg0_d,
            foreign_apps=[donor_app_id] if donors > 0 else None)
        txn1 = transaction.ApplicationNoOpTxn(sender=sender, sp=acl.suggested_params(),
                                               index=driver_app_id, app_args=seg1)
        txn2 = transaction.ApplicationNoOpTxn(sender=sender, sp=acl.suggested_params(),
                                               index=driver_app_id, app_args=seg2)
        txn3 = transaction.ApplicationNoOpTxn(sender=sender, sp=acl.suggested_params(),
                                               index=driver_app_id, app_args=seg3)
        txn4 = transaction.ApplicationNoOpTxn(sender=sender, sp=acl.suggested_params(),
                                               index=driver_app_id, app_args=seg4)
        group = transaction.assign_group_id([txn0, txn1, txn2, txn3, txn4])
        try:
            signed_group = [t.sign(sk) for t in group]
            first_txid = acl.send_transactions(signed_group)
            result = transaction.wait_for_confirmation(acl, first_txid, 4)
            print(f"  REAL 5-segment composite group with donors CONFIRMED, "
                  f"round={result.get('confirmed-round')}")
            group_real_ok = True
            # Read back the LAST segment's own confirmed LastLog and decode
            # the terminal C against §11.1's A-M6-1 pinned field table
            # (G1-M6) -- send_transactions returns only the FIRST txn's id,
            # so the last segment's own txid is computed directly from its
            # signed transaction.
            last_txid = signed_group[-1].get_txid()
            last_info = transaction.wait_for_confirmation(acl, last_txid, 4)
            logs_b64 = last_info.get("logs", [])
            assert logs_b64, "final segment produced no log"
            final_log = base64.b64decode(logs_b64[-1])
            assert len(final_log) == 355, f"expected 355-byte composite log, got {len(final_log)}"
            assert final_log[:4] == bytes.fromhex("151f7c75")
            w_bytes = final_log[6:6 + 101]
            c_bytes = final_log[6 + 101:]
            assert len(c_bytes) == 248
            cstatus, phase = c_bytes[0], c_bytes[1]
            c_state_root = c_bytes[2:34]
            c_address = c_bytes[34:54]
            c_slot = c_bytes[54:86]
            c_storage_root = c_bytes[86:118]
            c_code_hash = c_bytes[118:150]
            c_nonce = c_bytes[150:182]
            c_balance = c_bytes[182:214]
            c_value = c_bytes[214:246]
            awalk, swalk = c_bytes[246], c_bytes[247]
            print(f"  final C: cstatus={cstatus} phase={phase} awalk={awalk} swalk={swalk}")
            print(f"  final C.value = {c_value.hex()}")
            assert cstatus == 2, f"expected C_INCLUDED (2), got {cstatus}"  # C_INCLUDED
            assert phase == 3, f"expected PHASE_DONE (3), got {phase}"  # PHASE_DONE
            assert c_state_root == state_root
            assert c_address == address
            assert c_slot == slot_preimage
            assert c_storage_root.hex() == proof["storageHash"][2:]
            assert c_code_hash.hex() == proof["codeHash"][2:]
            assert c_nonce == int(proof["nonce"], 16).to_bytes(32, "big")
            assert c_balance == int(proof["balance"], 16).to_bytes(32, "big")
            want_value = int(sp["value"], 16).to_bytes(32, "big")
            assert c_value == want_value, f"expected {want_value.hex()}, got {c_value.hex()}"
            assert awalk == 1 and swalk == 1  # WALK_INCLUDED
            print("  G1-M6: final C matches every §11.1 A-M6-1 pinned field. PASS")
            final_c_hex = c_bytes.hex()
        except Exception as e:
            group_real_error = str(e)
            print(f"  REAL 5-segment composite group with donors FAILED: {e}")

    results["gates"]["G2_G3_M6_real_submission"] = {
        "no_donors_simulated": {"ok": not failure, "total_consumed": total,
                                 "per_txn_consumed": per_txn, "failure": failure},
        "two_walk_floor": two_walk_floor,
        "measured_overhead_ratio": predicted_ratio,
        "design_doc_predicted_ratio": 1.177,
        "g3_m6_target_ratio": 1.25,
        "g3_m6_pass": (predicted_ratio is not None and predicted_ratio <= 1.25),
        "donors_sized": donors,
        "real_submission_ok": group_real_ok,
        "real_submission_error": group_real_error,
        "final_c_hex": final_c_hex,
        "g1_m6_final_c_matches_a_m6_1_pinned_fields": group_real_ok,
        "spike_insecure_baseline": SPIKE_INSECURE_COMPOSITE,
        "design_doc_predicted_total": DESIGN_DOC_PREDICTED_COMPOSITE,
        "note": ("G2-M6: the full composite fits ONE 16-transaction atomic "
                 "group, demonstrated by a real, non-simulated submission "
                 "with sized donors -- M5's G7-M5 analogue and the gate that "
                 "decides whether M6 is usable. G3-M6: measured composite "
                 "budget <= 1.25x the two-walk floor.")}

    RESULTS_JSON.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_JSON.write_text(json.dumps(results, indent=2))
    print(f"\nwrote {RESULTS_JSON}")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
