"""
Empirically test opcode-budget pooling with extra_opcode_budget=0 (real rules).

Top-level pooling: a group of G app-call txns, ONE of which runs `k` ec_add
ops (~205 each). If budget pools, the heavy txn can consume up to G*700.
"""
import json
from avm_bls_bench import *
from algosdk import transaction, encoding as algo_encoding
from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup

acl = algod_client()
SENDER, SK = funded_account()

P = g1_uncompressed(multiply(G1, 7))
Q = g1_uncompressed(multiply(G1, 9))

def heavy_program(k):
    # do k ec_add ops on constants (each ~205 budget), then return 1
    lines = ["#pragma version 10", f"bytecblock 0x{P.hex()} 0x{Q.hex()}"]
    for _ in range(k):
        lines += ["bytec 0", "bytec 1", "ec_add BLS12_381g1", "pop"]
    lines += ["int 1", "return"]
    return compile_teal("\n".join(lines) + "\n")

TRIVIAL = compile_teal("#pragma version 10\nint 1\nreturn\n")
CLEAR = compile_teal(CLEAR_TEAL)

import os
def make_create(approval, note=None):
    sp = acl.suggested_params()
    return transaction.ApplicationCreateTxn(
        sender=SENDER, sp=sp, on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval, clear_program=CLEAR,
        global_schema=transaction.StateSchema(0, 0),
        local_schema=transaction.StateSchema(0, 0), extra_pages=3,
        note=note or os.urandom(8))  # unique note -> distinct txid

def sim_group(txns, extra=0):
    # assign group id
    gid = transaction.calculate_group_id(txns)
    stxns = []
    for t in txns:
        t.group = gid
        stxns.append(t.sign(SK))
    sreq = SimulateRequest(
        txn_groups=[SimulateRequestTransactionGroup(txns=stxns)],
        extra_opcode_budget=extra)
    resp = acl.simulate_transactions(sreq)
    g = resp["txn-groups"][0]
    return {"consumed": g.get("app-budget-consumed"),
            "added": g.get("app-budget-added"),
            "fail": g.get("failure-message", "")}

print("=== Top-level pooling: group of G app-calls, one runs k ec_adds ===")
print("Each ec_add ~205 budget. Pooled budget should be G*700.")
for G in (1, 2, 4, 8, 16):
    # find how many ec_adds succeed with a group of size G (binary-ish scan)
    lo_fail = None
    # test k values around G*700/205
    kmax = (G * 700) // 205 + 3
    last_ok = 0
    for k in range(1, kmax + 2):
        heavy = make_create(heavy_program(k))
        others = [make_create(TRIVIAL) for _ in range(G - 1)]
        r = sim_group([heavy] + others)
        if r["fail"]:
            lo_fail = k
            break
        last_ok = k
        last_consumed = r["consumed"]
        last_added = r["added"]
    print(f"  G={G:2d}: pooled_budget(added)={last_added:6d}  "
          f"max_ec_adds_ok={last_ok}  (fails at k={lo_fail}, "
          f"consumed@max={last_consumed})")
