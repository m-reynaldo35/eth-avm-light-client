#!/usr/bin/env python3
"""Real, live test of M7's T2 path (box-staging) against the real receipt
at tx 7, block 25,639,768 -- leaf 2,453 B, squarely in T2's range
(1,942 < leaf <= 4,096), reconstructed for real in tx7_proof.json.

Group shape: MODE_INIT(node0) -> MODE_NEXT(node1) leaves W pointed at the
leaf's hash (still WALK_CONTINUE, argument budget can't carry a 2,453 B
node) -> MODE_STAGE_OPEN -> MODE_STAGE_WRITE x2 (chunked) -> MODE_STAGE_WALK
(box_extract, walk, decode, box_del), plus filler NoOp calls for opcode
budget pooling.
"""
import base64
import json
import sys

from algosdk import kmd, transaction
from algosdk.logic import get_application_address
from algosdk.v2client import algod
from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup

ALGOD = "http://localhost:4051"
KMD = "http://localhost:4052"
TOKEN = "a" * 64


def main():
    ac = algod.AlgodClient(TOKEN, ALGOD)
    kcl = kmd.KMDClient(TOKEN, KMD)
    wid = next(w["id"] for w in kcl.list_wallets() if w["name"] == "unencrypted-default-wallet")
    h = kcl.init_wallet_handle(wid, "")
    sender = kcl.list_keys(h)[0]
    sk = kcl.export_key(h, "", sender)

    with open("/tmp/puya_m7/Mpt7ReceiptApp.approval.teal") as f:
        approval = base64.b64decode(ac.compile(f.read())["result"])
    with open("/tmp/puya_m7/Mpt7ReceiptApp.clear.teal") as f:
        clear = base64.b64decode(ac.compile(f.read())["result"])

    proof = json.load(open("tx7_proof.json"))
    # saved leaf-first (recursion order) -- reverse to root-to-leaf, the
    # order mpt_walk_node/the driver expects nodes supplied in.
    nodes = [bytes.fromhex(n) for n in reversed(proof["nodes"])]
    assert len(nodes) == 3
    leaf = nodes[2]
    print(f"tx=7 real node sizes: {[len(n) for n in nodes]}")
    assert 1942 < len(leaf) <= 4096, len(leaf)

    eth = json.load(open("/home/mark/eth-avm-verifier/tests/fixtures/spike-reference/eth_data.json"))
    receipts_root = bytes.fromhex(eth["receiptsRoot"][2:])
    tx_index = 7
    log_index = 0

    sp = ac.suggested_params()
    create = transaction.ApplicationCreateTxn(
        sender=sender, sp=sp, on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval, clear_program=clear,
        global_schema=transaction.StateSchema(0, 0), local_schema=transaction.StateSchema(0, 0),
        extra_pages=1,
    )
    txid = ac.send_transaction(create.sign(sk))
    res = transaction.wait_for_confirmation(ac, txid, 8)
    app_id = res["application-index"]
    print("app_id", app_id)

    box_name = b"tx7box01"  # 8 bytes, per bench_app.py's MODE_STAGE_* fixed-field layout
    fixed_init = receipts_root + tx_index.to_bytes(8, "big") + log_index.to_bytes(2, "big")

    def sp_fee():
        p = ac.suggested_params()
        p.flat_fee = True
        p.fee = 1000
        return p

    # box MBR is charged to the APP account, not the sender: 2500 + 400*(name+size)
    # ~= 2500 + 400*(8+2453) ~= 986,900 uAlgo, plus base account minimum -- fund
    # generously so this isn't the thing that fails.
    app_addr = get_application_address(app_id)
    fund_txn = transaction.PaymentTxn(sender, sp_fee(), app_addr, 2_000_000)

    txns = []
    txns.append(fund_txn)
    # 1: MODE_INIT with node0
    txns.append(transaction.ApplicationCallTxn(
        sender=sender, sp=sp_fee(), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
        app_args=[b"RCP1", bytes([0]), bytes([0]), fixed_init, nodes[0]]))
    # 2: MODE_NEXT with node1, prev_gi=1 (MODE_INIT's group index, now that
    # fund_txn shifted everything by one)
    txns.append(transaction.ApplicationCallTxn(
        sender=sender, sp=sp_fee(), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
        app_args=[b"RCP1", bytes([1]), bytes([1]), b"", nodes[1]]))
    # 3: MODE_STAGE_OPEN
    open_fixed = box_name + len(leaf).to_bytes(2, "big")
    txns.append(transaction.ApplicationCallTxn(
        sender=sender, sp=sp_fee(), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
        app_args=[b"RCP1", bytes([2]), bytes([0]), open_fixed],
        boxes=[transaction.BoxReference(0, box_name)]))
    # 4/5: MODE_STAGE_WRITE, chunked (<=1900B/arg per design doc)
    chunk0, chunk1 = leaf[:1900], leaf[1900:]
    write0_fixed = box_name + (0).to_bytes(2, "big")
    txns.append(transaction.ApplicationCallTxn(
        sender=sender, sp=sp_fee(), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
        app_args=[b"RCP1", bytes([3]), bytes([0]), write0_fixed, chunk0],
        boxes=[transaction.BoxReference(0, box_name)]))
    write1_fixed = box_name + (1900).to_bytes(2, "big")
    txns.append(transaction.ApplicationCallTxn(
        sender=sender, sp=sp_fee(), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
        app_args=[b"RCP1", bytes([3]), bytes([0]), write1_fixed, chunk1],
        boxes=[transaction.BoxReference(0, box_name)]))
    # 6: MODE_STAGE_WALK, prev_gi=2 (MODE_NEXT's group index), box_extract+walk+decode+close
    walk_fixed = box_name + len(leaf).to_bytes(2, "big")
    txns.append(transaction.ApplicationCallTxn(
        sender=sender, sp=sp_fee(), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
        app_args=[b"RCP1", bytes([4]), bytes([2]), walk_fixed],
        boxes=[transaction.BoxReference(0, box_name)]))
    # fillers for opcode-budget pooling
    for i in range(8):
        txns.append(transaction.ApplicationCallTxn(
            sender=sender, sp=sp_fee(), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
            app_args=[], note=bytes([200 + i])))

    gid = transaction.calculate_group_id(txns)
    for t in txns:
        t.group = gid
    signed = [t.sign(sk) for t in txns]

    sreq = SimulateRequest(txn_groups=[SimulateRequestTransactionGroup(txns=signed)],
                            allow_more_logs=True, extra_opcode_budget=15000)
    sres = ac.simulate_transactions(sreq)
    g = sres["txn-groups"][0]
    if g.get("failure-message"):
        print("SIMULATE FAILED:", g["failure-message"])
        sys.exit(1)

    walk_result = g["txn-results"][6]["txn-result"]
    logs = walk_result.get("logs", [])
    if not logs:
        print("NO LOG from MODE_STAGE_WALK -- unexpected")
        sys.exit(1)
    log_bytes = base64.b64decode(logs[0])
    r = log_bytes[6 + 101:6 + 101 + 240]
    print("R.rstatus =", r[0], "(expect 1 = R_INCLUDED)")
    print("R.tx_index =", int.from_bytes(r[33:41], "big"))
    print("R.n_topics =", r[73], "R.n_logs =", r[239])
    print("R.data_len =", int.from_bytes(r[234:238], "big"))
    assert r[0] == 1
    assert int.from_bytes(r[33:41], "big") == 7
    assert r[239] == 12  # leaves.json's own recorded n_logs for tx 7
    print("SIMULATE: T2 BOX-STAGING PATH PASSED")

    txid2 = ac.send_transactions(signed)
    result = transaction.wait_for_confirmation(ac, txid2, 8)
    print("T2 REAL SUBMISSION CONFIRMED in round", result["confirmed-round"])
    # `wait_for_confirmation` on a group only returns the LAST txn's own
    # confirmation info; the log we care about is MODE_STAGE_WALK's (group
    # index 6, a filler follows it) -- fetch that txn's real confirmed info
    # directly and check its log matches what simulate already showed.
    walk_txid = signed[6].transaction.get_txid()
    walk_info = ac.pending_transaction_info(walk_txid)
    real_walk_logs = walk_info.get("logs", [])
    assert real_walk_logs, "MODE_STAGE_WALK produced no log in the REAL confirmed txn"
    real_log_bytes = base64.b64decode(real_walk_logs[0]) if isinstance(real_walk_logs[0], str) else real_walk_logs[0]
    assert real_log_bytes == log_bytes, "real on-chain log differs from the simulated one"
    print("REAL ON-CHAIN LOG MATCHES SIMULATED LOG EXACTLY")


if __name__ == "__main__":
    main()
