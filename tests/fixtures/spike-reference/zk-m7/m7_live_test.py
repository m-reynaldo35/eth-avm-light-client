#!/usr/bin/env python3
"""Real, live test of M7's T1 path (MODE_INIT, single transaction) against
the real 3-node receipt-inclusion proof for tx 31, block 25,639,768
(tests/fixtures/spike-reference/eth_data.json's receipt_proof), submitted to
a real (dev-mode, isolated on :4051/:4052) algod -- not simulated.
"""
import base64
import json
import sys

from algosdk import kmd, transaction
from algosdk.v2client import algod

ALGOD = "http://localhost:4051"
KMD = "http://localhost:4052"
TOKEN = "a" * 64
ETH_DATA = "/home/mark/eth-avm-verifier/tests/fixtures/spike-reference/eth_data.json"
APPROVAL_TEAL = "/tmp/puya_m7/Mpt7ReceiptApp.approval.teal"
CLEAR_TEAL = "/tmp/puya_m7/Mpt7ReceiptApp.clear.teal"


def clients():
    return algod.AlgodClient(TOKEN, ALGOD), kmd.KMDClient(TOKEN, KMD)


def funded_account(kcl):
    wallets = kcl.list_wallets()
    wid = next(w["id"] for w in wallets if w["name"] == "unencrypted-default-wallet")
    h = kcl.init_wallet_handle(wid, "")
    for a in kcl.list_keys(h):
        return a, kcl.export_key(h, "", a)
    raise RuntimeError("no funded account in default wallet")


def compile_teal(ac, path):
    with open(path) as f:
        src = f.read()
    return base64.b64decode(ac.compile(src)["result"])


def main():
    ac, kcl = clients()
    sender, sk = funded_account(kcl)
    print("sender:", sender)

    approval = compile_teal(ac, APPROVAL_TEAL)
    clear = compile_teal(ac, CLEAR_TEAL)
    print(f"approval program: {len(approval)} bytes compiled")

    eth = json.load(open(ETH_DATA))
    rp = eth["receipt_proof"]
    receipts_root = bytes.fromhex(eth["receiptsRoot"][2:])
    tx_index = rp["index"]
    nodes = [bytes.fromhex(n[2:] if n.startswith("0x") else n) for n in rp["nodes"]]
    log_index = 0
    print(f"tx_index={tx_index} log_index={log_index} nodes={[len(n) for n in nodes]} "
          f"receiptsRoot={receipts_root.hex()}")

    fixed = receipts_root + tx_index.to_bytes(8, "big") + log_index.to_bytes(2, "big")
    assert len(fixed) == 42
    app_args = [b"RCP1", bytes([0]), bytes([0]), fixed] + nodes
    total_args = sum(len(a) for a in app_args)
    print(f"total app-args bytes = {total_args} (AVM cap 2048)")

    # step 1: create the app (M5/M6/M7's own convention: the create call
    # itself is a cheap no-op guard, `if Txn.application_id.id == 0: return
    # True` -- the real logic only runs on a follow-up call).
    sp = ac.suggested_params()
    create_txn = transaction.ApplicationCreateTxn(
        sender=sender, sp=sp, on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval, clear_program=clear,
        global_schema=transaction.StateSchema(0, 0), local_schema=transaction.StateSchema(0, 0),
        extra_pages=1,
    )
    signed_create = create_txn.sign(sk)
    create_txid = ac.send_transaction(signed_create)
    create_result = transaction.wait_for_confirmation(ac, create_txid, 8)
    app_id = create_result["application-index"]
    print(f"app created: id={app_id}")

    # step 2: the real MODE_INIT call, carrying tx 31's real 3-node proof.
    sp2 = ac.suggested_params()
    sp2.flat_fee = True
    sp2.fee = 2000
    call_txn = transaction.ApplicationCallTxn(
        sender=sender, sp=sp2, index=app_id,
        on_complete=transaction.OnComplete.NoOpOC, app_args=app_args,
    )
    signed = call_txn.sign(sk)

    # simulate first for a clean opcode-budget/log read before a real submit
    from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup
    sreq = SimulateRequest(txn_groups=[SimulateRequestTransactionGroup(txns=[signed])],
                            allow_more_logs=True, extra_opcode_budget=15000)
    sres = ac.simulate_transactions(sreq)
    g = sres["txn-groups"][0]
    if g.get("failure-message"):
        print("SIMULATE FAILED:", g["failure-message"])
        sys.exit(1)
    txres = g["txn-results"][0]
    print("simulate app-budget-consumed:", txres.get("app-budget-consumed"))
    logs = txres["txn-result"].get("logs", [])
    if not logs:
        print("NO LOGS PRODUCED -- unexpected")
        sys.exit(1)
    log_bytes = base64.b64decode(logs[0])
    print(f"log length = {len(log_bytes)} (expect 347)")

    # decode (W, R) per §5.1/§5.2's fixed layout
    assert log_bytes[0:4] == bytes.fromhex("151f7c75")
    payload_len = int.from_bytes(log_bytes[4:6], "big")
    assert payload_len == 101 + 240, payload_len
    w = log_bytes[6:6 + 101]
    r = log_bytes[6 + 101:6 + 101 + 240]

    w_status = w[0]
    r_rstatus = r[0]
    r_receipts_root = r[1:33]
    r_tx_index = int.from_bytes(r[33:41], "big")
    r_log_index = int.from_bytes(r[41:43], "big")
    r_tx_type = r[43]
    r_status = r[44]
    r_cum_gas = int.from_bytes(r[45:53], "big")
    r_address = r[53:73]
    r_n_topics = r[73]
    r_topics = r[74:74 + 128]
    r_data_hash = r[202:234]
    r_data_len = int.from_bytes(r[234:238], "big")
    r_wstatus = r[238]
    r_n_logs = r[239]

    print(f"W.status={w_status}  R.rstatus={r_rstatus} (1=R_INCLUDED)")
    print(f"R.receipts_root={r_receipts_root.hex()}")
    print(f"R.tx_index={r_tx_index} R.log_index={r_log_index} R.tx_type={r_tx_type} "
          f"R.status={r_status} R.cum_gas={r_cum_gas}")
    print(f"R.address={r_address.hex()} R.n_topics={r_n_topics} R.n_logs={r_n_logs}")
    print(f"R.data_hash={r_data_hash.hex()} R.data_len={r_data_len} R.wstatus={r_wstatus}")

    assert r_rstatus == 1, f"expected R_INCLUDED, got {r_rstatus}"
    assert r_receipts_root == receipts_root
    assert r_tx_index == tx_index
    assert r_log_index == log_index
    assert r_tx_type == 2  # EIP-1559, design doc's own pinned fact for tx 31
    assert r_n_topics == 4  # design doc's own pinned fact for log 0
    assert r_n_logs == 2
    assert r_data_len == 0
    print("SIMULATE: ALL ASSERTIONS PASSED")

    # REAL, non-simulated submission. §5.1's arg layout has no donor slot
    # (unlike M6's), but real measurement above (3,790 budget) exceeds a
    # single top-level call's ~700 base. Opcode budget pools +700 per
    # APPLICATION call in the group (NOT plain Payments, confirmed live
    # below after a first attempt using Payment fillers still failed at
    # the same point) -- so fillers here are zero-arg NoOp calls to the
    # SAME app, hitting bench_app.py's own cheap early-return guard
    # (`if Txn.num_app_args == 0: return True`).
    n_fill = 5  # 6 group members x 700 = 4200 pooled, > 3790 needed
    sp_group = ac.suggested_params()
    sp_group.flat_fee = True
    sp_group.fee = 1000
    call_txn2 = transaction.ApplicationCallTxn(
        sender=sender, sp=sp_group, index=app_id,
        on_complete=transaction.OnComplete.NoOpOC, app_args=app_args,
        note=b"real-submit",  # distinguish from the identical simulated txn above (same txid otherwise)
    )
    fillers = []
    for i in range(n_fill):
        fp = ac.suggested_params()
        fp.flat_fee = True
        fp.fee = 1000
        fillers.append(transaction.ApplicationCallTxn(
            sender=sender, sp=fp, index=app_id, on_complete=transaction.OnComplete.NoOpOC,
            app_args=[], note=bytes([i]),  # each must be unique or the group has duplicate txids
        ))
    group = [call_txn2] + fillers
    gid = transaction.calculate_group_id(group)
    for t in group:
        t.group = gid
    signed_group = [t.sign(sk) for t in group]

    txid = ac.send_transactions(signed_group)
    result = transaction.wait_for_confirmation(ac, txid, 8)
    print(f"REAL SUBMISSION CONFIRMED in round {result['confirmed-round']}, "
          f"app id {result.get('application-index')}")
    real_logs = result.get("logs", [])
    assert real_logs, "no logs in real confirmed txn"
    real_log_bytes = base64.b64decode(real_logs[0]) if isinstance(real_logs[0], str) else real_logs[0]
    assert real_log_bytes == log_bytes, "real submission log differs from simulated log"
    print("REAL SUBMISSION LOG MATCHES SIMULATED LOG EXACTLY")


if __name__ == "__main__":
    main()
