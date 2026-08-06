#!/usr/bin/env python3
"""
onchain.py -- verify a real AlgoPlonk PLONK proof on a real dev-mode algod,
in the group shape design doc 007 §4.8 specifies for M7's MODE_ZK_CLOSE.

Follows tests/fixtures/spike-reference/README.md's recipe: algod :4051,
kmd :4052, token = 64 x 'a'.  Reports the REAL logic-sig-budget-consumed and
app-budget-consumed out of /v2/transactions/simulate, and then does a REAL,
non-simulated submission (design doc 007 §4.11 ZK-B6).
"""
import base64
import json
import os
import subprocess
import sys

from algosdk.v2client import algod
from algosdk import kmd, transaction, encoding
from algosdk.logic import get_application_address  # noqa: F401

ALGOD = "http://localhost:4051"
KMD = "http://localhost:4052"
TOKEN = "a" * 64


def clients():
    return algod.AlgodClient(TOKEN, ALGOD), kmd.KMDClient(TOKEN, KMD)


def funded_account(kcl):
    wallets = kcl.list_wallets()
    wid = next(w["id"] for w in wallets if w["name"] == "unencrypted-default-wallet")
    h = kcl.init_wallet_handle(wid, "")
    ac, _ = clients()
    best, bestbal = None, -1
    for a in kcl.list_keys(h):
        bal = ac.account_info(a)["amount"]
        if bal > bestbal:
            best, bestbal = a, bal
    return best, kcl.export_key(h, "", best)


def arc4_bytes32_array(blob: bytes) -> bytes:
    """ARC-4 DynamicArray[StaticArray[Byte,32]] = 2-byte BE count || raw."""
    assert len(blob) % 32 == 0, len(blob)
    return (len(blob) // 32).to_bytes(2, "big") + blob


def compile_teal(ac, teal: str) -> bytes:
    return base64.b64decode(ac.compile(teal)["result"])


def build_group(ac, sender, sk, lsig_prog, proof, pubins, extra_args, n_fill=15):
    """§4.8's group: one logicsig-signed app call carrying the proof, plus
    filler transactions that exist only to raise the pooled logicsig budget."""
    sp = ac.suggested_params()
    sp.flat_fee = True
    sp.fee = 0   # the logicsig account pays nothing; fillers cover the group

    lsig = transaction.LogicSigAccount(lsig_prog)
    lsig_addr = lsig.address()

    # trivial approval program: the app under test is not the point here; the
    # logicsig signing the call is what proves the PLONK proof verified.
    approval = compile_teal(ac, "#pragma version 10\nint 1\nreturn\n")
    clear = compile_teal(ac, "#pragma version 10\nint 1\nreturn\n")

    args = [b"RCP1", arc4_bytes32_array(proof), arc4_bytes32_array(pubins)] + extra_args

    sp_pay = ac.suggested_params()
    sp_pay.flat_fee = True
    sp_pay.fee = 2000 * (n_fill + 1)

    txns = [
        transaction.ApplicationCreateTxn(
            sender=lsig_addr, sp=sp,
            on_complete=transaction.OnComplete.NoOpOC,
            approval_program=approval, clear_program=clear,
            global_schema=transaction.StateSchema(0, 0),
            local_schema=transaction.StateSchema(0, 0),
            app_args=args,
        )
    ]
    for i in range(n_fill):
        p = ac.suggested_params()
        p.flat_fee = True
        p.fee = 1000 * 17 if i == 0 else 0
        txns.append(transaction.PaymentTxn(sender, p, sender, 0, note=bytes([i])))

    gid = transaction.calculate_group_id(txns)
    for t in txns:
        t.group = gid
    signed = [transaction.LogicSigTransaction(txns[0], lsig)]
    signed += [t.sign(sk) for t in txns[1:]]
    return signed, lsig_addr


def _sim_raw(ac, signed):
    """Simulate via the SDK models, exactly as the spike harness does."""
    from algosdk.v2client.models import (
        SimulateRequest, SimulateRequestTransactionGroup,
    )
    sreq = SimulateRequest(
        txn_groups=[SimulateRequestTransactionGroup(txns=signed)])
    try:
        return ac.simulate_transactions(sreq)
    except Exception as e:
        return {"error": str(e)}


def main():
    gen = sys.argv[1]                 # generated/txNN
    name = sys.argv[2]                # M7VerifierTxNN
    real_submit = "--submit" in sys.argv

    ac, kcl = clients()
    sender, sk = funded_account(kcl)

    # 1. compile the AlgoPlonk-generated Puya logicsig
    py = os.path.join(gen, name + ".py")
    print(f"compiling {py} with puyapy ...")
    out = subprocess.run(["puyapy", "--out-dir", os.path.abspath(gen), py],
                         capture_output=True, text=True)
    if out.returncode != 0:
        print(out.stdout, out.stderr)
        sys.exit(1)
    tealf = None
    for f in os.listdir(gen):
        if f.endswith(".teal") and "clear" not in f and "approval" not in f:
            tealf = os.path.join(gen, f)
    if tealf is None:
        print("no logicsig .teal produced; files:", os.listdir(gen))
        sys.exit(1)
    teal = open(tealf).read()
    prog = compile_teal(ac, teal)
    print(f"logicsig program: {tealf}, compiled size = {len(prog)} bytes")

    proof = open(os.path.join(gen, name + ".proof"), "rb").read()
    pubins = open(os.path.join(gen, name + ".public_inputs"), "rb").read()
    print(f"proof = {len(proof)} B, public inputs = {len(pubins)} B "
          f"({len(pubins)//32} field elements)")

    # §4.8's remaining args: mode, prev group index, log_bytes
    log_bytes = open(os.path.join(gen, name + ".log_bytes"), "rb").read() \
        if os.path.exists(os.path.join(gen, name + ".log_bytes")) else b""
    extra = [bytes([9]), bytes([0]), log_bytes]

    signed, lsig_addr = build_group(ac, sender, sk, prog, proof, pubins, extra)
    total_args = sum(len(a) for a in signed[0].transaction.app_args)
    print(f"logicsig address = {lsig_addr}")
    # the logicsig account is the SENDER of the app call (design doc §4.8 step 1
    # requires Txn.Sender == V_ADDR), so it needs min balance.
    if ac.account_info(str(lsig_addr))["amount"] < 1_000_000:
        sp0 = ac.suggested_params()
        tid = ac.send_transaction(
            transaction.PaymentTxn(sender, sp0, lsig_addr, 5_000_000).sign(sk))
        transaction.wait_for_confirmation(ac, tid, 6)
        print("funded logicsig account")
    print(f"total application-args bytes = {total_args} (AVM cap 2048)")

    res = _sim_raw(ac, signed)
    if "error" in res:
        print("SIMULATE ERROR:", res["error"][:1200])
        sys.exit(1)
    g = res["txn-groups"][0]
    if g.get("failure-message"):
        print("SIMULATE FAILED:", g["failure-message"][:1000])
        sys.exit(1)
    print("---- simulate result ----")
    print("app-budget-added   :", g.get("app-budget-added"))
    print("app-budget-consumed:", g.get("app-budget-consumed"))
    lsb = [t.get("logic-sig-budget-consumed") for t in g["txn-results"]]
    print("logic-sig-budget-consumed per txn:", lsb)
    print("VERIFIED ON-CHAIN (simulate): proof accepted by the logicsig")

    # ---- negative test: tamper one byte of the public inputs ----
    bad = bytearray(pubins)
    bad[31] ^= 0x01           # flip a bit in public input 0 (leaf_hash hi half)
    bad_signed, _ = build_group(ac, sender, sk, prog, proof, bytes(bad), extra)
    bres = _sim_raw(ac, bad_signed)
    if "error" in bres:
        neg = "rejected at submission: " + str(bres["error"])[-400:]
    else:
        bg = bres["txn-groups"][0]
        neg = bg.get("failure-message") or "*** ACCEPTED — SOUNDNESS HOLE ***"
    print("negative (1 bit flipped in public inputs):", neg[:200])

    summary = {
        "lsig_program_bytes": len(prog),
        "proof_bytes": len(proof),
        "public_input_bytes": len(pubins),
        "total_app_args_bytes": total_args,
        "app_budget_consumed": g.get("app-budget-consumed"),
        "logicsig_budget_consumed": lsb[0],
        "lsig_address": str(lsig_addr),
        "tampered_public_inputs_result": neg[:300],
    }

    if real_submit:
        print("---- real submission ----")
        signed, _ = build_group(ac, sender, sk, prog, proof, pubins, extra)
        try:
            txid = ac.send_transactions(signed)
            r = transaction.wait_for_confirmation(ac, txid, 8)
            print("REAL SUBMISSION CONFIRMED in round", r["confirmed-round"],
                  "app id", r.get("application-index"))
            summary["real_submission_round"] = r["confirmed-round"]
            summary["real_submission_appid"] = r.get("application-index")
        except Exception as e:
            print("REAL SUBMISSION FAILED:", str(e)[:1000])
            summary["real_submission_error"] = str(e)[:500]

    json.dump(summary, open(os.path.join(gen, name + ".onchain.json"), "w"), indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
