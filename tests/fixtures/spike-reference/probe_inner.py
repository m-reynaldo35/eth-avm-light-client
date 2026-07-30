"""
Test whether INNER app calls pool opcode budget with the outer call.

Deploy a trivial callee app. Then simulate an outer app-create whose approval
program issues N inner app-calls to the callee, then does k ec_adds. With
extra_opcode_budget=0, if inner calls pool budget the available pool = (1+N)*700.
"""
from avm_bls_bench import *
from algosdk import transaction
from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup

acl = algod_client()
SENDER, SK = funded_account()
CLEAR = compile_teal(CLEAR_TEAL)
P = g1_uncompressed(multiply(G1, 7)); Q = g1_uncompressed(multiply(G1, 9))

# 1) Deploy a trivial callee app for real (dev mode -> instant block)
callee = compile_teal("#pragma version 10\nint 1\nreturn\n")
sp = acl.suggested_params()
create = transaction.ApplicationCreateTxn(
    sender=SENDER, sp=sp, on_complete=transaction.OnComplete.NoOpOC,
    approval_program=callee, clear_program=CLEAR,
    global_schema=transaction.StateSchema(0, 0),
    local_schema=transaction.StateSchema(0, 0))
txid = acl.send_transaction(create.sign(SK))
res = transaction.wait_for_confirmation(acl, txid, 4)
CALLEE_ID = res["application-index"]
print("deployed callee app id:", CALLEE_ID)

def outer_program(n_inner, k_adds):
    lines = ["#pragma version 10", f"bytecblock 0x{P.hex()} 0x{Q.hex()}"]
    for _ in range(n_inner):
        lines += [
            "itxn_begin",
            "int appl", "itxn_field TypeEnum",
            f"int {CALLEE_ID}", "itxn_field ApplicationID",
            "int 0", "itxn_field Fee",          # fee pooled from outer
            "itxn_submit",
        ]
    for _ in range(k_adds):
        lines += ["bytec 0", "bytec 1", "ec_add BLS12_381g1", "pop"]
    lines += ["int 1", "return"]
    return compile_teal("\n".join(lines) + "\n")

def sim_outer(n_inner, k_adds, extra=0):
    sp = acl.suggested_params()
    sp.flat_fee = True
    sp.fee = (n_inner + 1) * 1000  # outer pays pooled fee for all inner txns
    import os
    t = transaction.ApplicationCreateTxn(
        sender=SENDER, sp=sp, on_complete=transaction.OnComplete.NoOpOC,
        approval_program=outer_program(n_inner, k_adds), clear_program=CLEAR,
        global_schema=transaction.StateSchema(0, 0),
        local_schema=transaction.StateSchema(0, 0), extra_pages=3,
        foreign_apps=[CALLEE_ID], note=os.urandom(8))
    sreq = SimulateRequest(
        txn_groups=[SimulateRequestTransactionGroup(txns=[t.sign(SK)])],
        extra_opcode_budget=extra)
    g = acl.simulate_transactions(sreq)["txn-groups"][0]
    return {"consumed": g.get("app-budget-consumed"),
            "added": g.get("app-budget-added"),
            "fail": g.get("failure-message", "")}

print("\n=== Inner-call budget pooling: N inner calls, then max k ec_adds ===")
for N in (0, 1, 2, 4, 8):
    last_ok, last_added, last_consumed = 0, None, None
    kmax = ((1 + N) * 700) // 205 + 3
    fail_k = None
    for k in range(0, kmax + 2):
        r = sim_outer(N, k)
        if r["fail"]:
            fail_k = k
            break
        last_ok, last_added, last_consumed = k, r["added"], r["consumed"]
    print(f"  N_inner={N}: pooled_budget(added)={last_added}  "
          f"max_ec_adds_ok={last_ok} (fail@k={fail_k}, consumed={last_consumed})")

print("\n=== Max inner txns per outer app call (find the cap) ===")
for N in (250, 255, 256, 257, 300):
    r = sim_outer(N, 0)
    print(f"  N_inner={N}: fail={bool(r['fail'])} added={r['added']} "
          f"msg={r['fail'][:70]}")
