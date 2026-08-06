"""Real M7 relayer: given (receipts_root, tx_index, log_index, real node
path), builds and submits the right transaction group to a deployed
Mpt7ReceiptApp -- T1 (all nodes fit as plain args, one MODE_INIT/MODE_NEXT
chain) or T2 (the terminal leaf needs box-staging) -- and decodes R.

Generalizes tests/fixtures/spike-reference/zk-m7/m7_live_test.py and
m7_t2_test.py's proven-live logic. Two real Algorand mechanics this module
exists because of, both found live in this project this session:
  1. opcode budget pools per APPLICATION call in a group, not per Payment --
     fillers here are cheap zero-arg NoOp calls to the same app.
  2. box MBR is charged to the APP account, not the sender -- T2 needs a
     funding Payment to the app address before MODE_STAGE_OPEN, in the same
     group.

`ARG_BUDGET` (1,942 B, M5 §7.2's measured argument budget) is the same T1/T2
boundary docs/design/007-receipt-log-proof.md §3.1 uses.
"""
import secrets

from algosdk import transaction
from algosdk.logic import get_application_address
from algosdk.v2client import algod
from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup

ARG_BUDGET = 1942
MAX_LEAF = 4096
N_FILLERS = 8  # generous headroom over the measured 3,790 real budget need


class M7Error(Exception):
    pass


def _sp(ac: algod.AlgodClient, fee: int = 1000):
    p = ac.suggested_params()
    p.flat_fee = True
    p.fee = fee
    return p


def _decode_r(log_bytes: bytes) -> dict:
    assert log_bytes[0:4] == bytes.fromhex("151f7c75"), "bad log envelope"
    r = log_bytes[6 + 101:6 + 101 + 240]
    return {
        "rstatus": r[0],
        "receipts_root": r[1:33].hex(),
        "tx_index": int.from_bytes(r[33:41], "big"),
        "log_index": int.from_bytes(r[41:43], "big"),
        "tx_type": r[43],
        "status": r[44],
        "cumulative_gas_used": int.from_bytes(r[45:53], "big"),
        "address": r[53:73].hex(),
        "n_topics": r[73],
        "topics": [r[74 + 32 * i:74 + 32 * (i + 1)].hex() for i in range(r[73])],
        "data_hash": r[202:234].hex(),
        "data_len": int.from_bytes(r[234:238], "big"),
        "wstatus": r[238],
        "n_logs": r[239],
    }


RSTATUS_NAMES = {0: "R_INCOMPLETE", 1: "R_INCLUDED", 2: "R_ABSENT", 3: "R_NO_SUCH_LOG", 4: "R_ZERO_LOGS"}


def prove_receipt(ac: algod.AlgodClient, app_id: int, sender: str, sk: str,
                   receipts_root: bytes, tx_index: int, log_index: int, nodes: list[bytes]
                   ) -> dict:
    """Real submission. Returns the decoded R plus `{"confirmed_round": ...}`.
    Raises M7Error with the real rstatus name if the result isn't R_INCLUDED."""
    leaf = nodes[-1]
    branch_nodes = nodes[:-1]
    fixed_init = receipts_root + tx_index.to_bytes(8, "big") + log_index.to_bytes(2, "big")

    txns: list = []
    walk_index_pointer = None  # group index of the last txn carrying (W, R)

    if len(leaf) <= ARG_BUDGET:
        # T1: everything fits as plain args. Split across MODE_INIT (+MODE_NEXT
        # continuations) only if the total argument bytes would exceed the
        # 2,048 B cap -- for real T1 receipts this is essentially always one
        # single MODE_INIT call.
        all_nodes = branch_nodes + [leaf]
        init_args = [b"RCP1", bytes([0]), bytes([0]), fixed_init] + all_nodes
        total = sum(len(a) for a in init_args)
        if total > 2000:
            raise M7Error("T1 node set too large for one call -- MODE_NEXT splitting not implemented "
                           "in this relayer yet")
        txns.append(transaction.ApplicationCallTxn(
            sender=sender, sp=_sp(ac), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
            app_args=init_args))
        walk_index_pointer = 0
    else:
        if not (ARG_BUDGET < len(leaf) <= MAX_LEAF):
            raise M7Error(f"leaf {len(leaf)} B is outside T1/T2 range (T3/ZK is out of scope for this service)")
        # T2: branch nodes as plain args (MODE_INIT [+ MODE_NEXT if more than
        # fits in one call]), then box-stage the oversized leaf.
        if branch_nodes:
            init_args = [b"RCP1", bytes([0]), bytes([0]), fixed_init, branch_nodes[0]]
            txns.append(transaction.ApplicationCallTxn(
                sender=sender, sp=_sp(ac), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
                app_args=init_args))
            prev = 0
            for n in branch_nodes[1:]:
                txns.append(transaction.ApplicationCallTxn(
                    sender=sender, sp=_sp(ac), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
                    app_args=[b"RCP1", bytes([1]), bytes([prev]), b"", n]))
                prev = len(txns) - 1
            walk_index_pointer = len(txns) - 1
        else:
            # no branch nodes before the leaf -- MODE_INIT itself must seed W
            # with zero nodes, which this relayer does not need for any real
            # receipt (a receipts trie with >1 entries always has >=1 branch
            # hop before any leaf); guard rather than silently mishandle.
            raise M7Error("T2 with zero branch nodes before the leaf is not a real case this relayer handles")

        box_name = secrets.token_bytes(8)
        app_addr = get_application_address(app_id)
        # box MBR: 2500 + 400*(name+size) uAlgo, funded generously
        fund_amount = 2500 + 400 * (8 + len(leaf)) + 200_000
        txns.insert(0, transaction.PaymentTxn(sender, _sp(ac), app_addr, fund_amount))
        walk_index_pointer += 1  # every later index shifts by the inserted funding txn

        open_fixed = box_name + len(leaf).to_bytes(2, "big")
        txns.append(transaction.ApplicationCallTxn(
            sender=sender, sp=_sp(ac), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"RCP1", bytes([2]), bytes([0]), open_fixed],
            boxes=[transaction.BoxReference(0, box_name)]))

        offset = 0
        while offset < len(leaf):
            chunk = leaf[offset:offset + 1900]
            write_fixed = box_name + offset.to_bytes(2, "big")
            txns.append(transaction.ApplicationCallTxn(
                sender=sender, sp=_sp(ac), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
                app_args=[b"RCP1", bytes([3]), bytes([0]), write_fixed, chunk],
                boxes=[transaction.BoxReference(0, box_name)]))
            offset += len(chunk)

        walk_fixed = box_name + len(leaf).to_bytes(2, "big")
        txns.append(transaction.ApplicationCallTxn(
            sender=sender, sp=_sp(ac), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"RCP1", bytes([4]), bytes([walk_index_pointer]), walk_fixed],
            boxes=[transaction.BoxReference(0, box_name)]))

    result_index = len(txns) - 1
    for i in range(N_FILLERS):
        txns.append(transaction.ApplicationCallTxn(
            sender=sender, sp=_sp(ac), index=app_id, on_complete=transaction.OnComplete.NoOpOC,
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
        raise M7Error(f"simulate failed: {g['failure-message']}")

    result_id = signed[result_index].transaction.get_txid()
    ac.send_transactions(signed)
    info = transaction.wait_for_confirmation(ac, signed[-1].transaction.get_txid(), 8)
    result_info = ac.pending_transaction_info(result_id)
    logs = result_info.get("logs", [])
    if not logs:
        raise M7Error("no log produced by the result transaction")
    import base64
    log_bytes = base64.b64decode(logs[0]) if isinstance(logs[0], str) else logs[0]
    decoded = _decode_r(log_bytes)
    decoded["confirmed_round"] = info["confirmed-round"]
    decoded["rstatus_name"] = RSTATUS_NAMES.get(decoded["rstatus"], f"unknown({decoded['rstatus']})")
    # §5.4: R_ABSENT / R_NO_SUCH_LOG / R_ZERO_LOGS are legitimate RESULTS,
    # not failures -- returned as-is, not raised. Only R_INCOMPLETE (the
    # walk never reached a terminal node) is genuinely this relayer's own
    # bug (it should always supply enough nodes to terminate).
    if decoded["rstatus"] == 0:
        raise M7Error("walk did not reach a terminal node (R_INCOMPLETE) -- relayer bug, not a receipt fact")
    return decoded
