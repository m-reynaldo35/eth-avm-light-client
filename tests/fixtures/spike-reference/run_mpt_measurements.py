#!/usr/bin/env python3
"""
run_mpt_measurements.py -- drives mpt_bench.py over REAL mainnet proof data
(eth_data.json: block 25,639,768, USDT account+storage proof, receipts trie
proof) and prints every measured app-budget-consumed. Nothing here is estimated;
each number is read back from a real /v2/transactions/simulate response.
"""
import json
import mpt_bench as M

d = json.load(open("eth_data.json"))
ACC = [bytes.fromhex(n[2:]) for n in d["proof"]["accountProof"]]
STO = [bytes.fromhex(n[2:]) for n in d["proof"]["storageProof"][0]["proof"]]
RCPT = [bytes.fromhex(n[2:]) for n in d["receipt_proof"]["nodes"]]
STATE_ROOT = d["stateRoot"][2:]
RECEIPTS_ROOT = d["receiptsRoot"][2:]

def sim(src):
    return M.simulate_create(M.compile_teal(src))

def prog_size(src):
    return len(M.compile_teal(src))

RESULTS = {}

# ---------------------------------------------------------------------------
# 0. baseline
# ---------------------------------------------------------------------------
base = sim("#pragma version 10\nint 1\nreturn\n")
RESULTS["baseline_consumed"] = base.app_budget_consumed
RESULTS["budget_added"] = base.app_budget_added
print(f"[baseline] consumed={base.app_budget_consumed} added={base.app_budget_added}")

# ---------------------------------------------------------------------------
# 1. keccak256 cost curve: 32, 128, 532, 1024 bytes
# ---------------------------------------------------------------------------
print("\n== keccak256 cost curve ==")
RESULTS["keccak"] = {}
for n in (32, 128, 532, 1024):
    blob = (b"\xab" * n)
    push = "#pragma version 10\nbytecblock 0x%s\nbytec 0\npop\nint 1\nreturn\n" % blob.hex()
    kec  = "#pragma version 10\nbytecblock 0x%s\nbytec 0\nkeccak256\npop\nint 1\nreturn\n" % blob.hex()
    rp = sim(push); rk = sim(kec)
    cost = rk.app_budget_consumed - rp.app_budget_consumed
    RESULTS["keccak"][n] = {"push": rp.app_budget_consumed,
                            "keccak": rk.app_budget_consumed, "cost": cost}
    print(f"  {n:>4}B: push={rp.app_budget_consumed:>3} keccak={rk.app_budget_consumed:>3} keccak_cost={cost}")

# ---------------------------------------------------------------------------
# 2. RLP branch-node decode cost in TEAL (extract one child, no keccak)
#    measured across all real branch nodes / a range of child indices
# ---------------------------------------------------------------------------
print("\n== RLP branch decode cost (extract item, on-chain parse) ==")
RESULTS["rlp_branch"] = {}
branch_node = ACC[0]  # a real 532B branch node
for idx in (0, 8, 15):
    src = ("#pragma version 10\nbytecblock 0x%s\nbytec 0\nint %d\ncallsub rlp_item\npop\nint 1\nreturn\n%s"
           % (branch_node.hex(), idx, M.RLP_ITEM_SUB))
    r = sim(src)
    # subtract push+call overhead baseline (extract index 0 is cheapest skip loop)
    RESULTS["rlp_branch"][idx] = r.app_budget_consumed
    print(f"  branch extract item[{idx:>2}]: consumed={r.app_budget_consumed}")

# ---------------------------------------------------------------------------
# helpers to derive descent steps from real data
# ---------------------------------------------------------------------------
def derive_steps(nodes, terminal_value_idx=1):
    steps = []
    for i, n in enumerate(nodes):
        kind, _ = M.node_kind(n)
        if i < len(nodes) - 1:
            nxt = M.keccak256(nodes[i+1])
            steps.append({"extract": M.branch_child_index(n, nxt)} if kind == "branch"
                         else {"extract": 1})
        else:
            steps.append({"value": terminal_value_idx})
    return steps

# ---------------------------------------------------------------------------
# 3. full account proof (root = stateRoot), total + per node
# ---------------------------------------------------------------------------
print("\n== full account proof ==")
acc_steps = derive_steps(ACC)
acc_src = M.build_verifier(ACC, acc_steps, STATE_ROOT)
racc = sim(acc_src)
RESULTS["account_proof"] = {"nodes": len(ACC), "consumed": racc.app_budget_consumed,
                            "per_node": racc.app_budget_consumed/len(ACC),
                            "prog_bytes": prog_size(acc_src), "ok": racc.ok,
                            "kinds": [M.node_kind(n)[0] for n in ACC],
                            "sizes": [len(n) for n in ACC]}
print(f"  ok={racc.ok} nodes={len(ACC)} consumed={racc.app_budget_consumed} "
      f"per_node={racc.app_budget_consumed/len(ACC):.1f} prog_bytes={prog_size(acc_src)}")

# keccak-only vs rlp-only split, over the same real account path
def keccak_only_walk(nodes, root_hex):
    # embed expected hashes as constants, chain via python-precomputed values
    exp = [bytes.fromhex(root_hex)]
    for i in range(len(nodes)-1):
        # expected for node i+1 is keccak of node i+1 (that IS what parent points to)
        exp.append(M.keccak256(nodes[i+1]))
    consts = list(nodes) + exp
    off = len(nodes)
    L = ["#pragma version 10", "bytecblock " + " ".join("0x"+c.hex() for c in consts)]
    for i in range(len(nodes)):
        L += [f"bytec {i}", "keccak256", f"bytec {off+i}", "==", "assert"]
    L += ["int 1", "return"]
    return "\n".join(L)+"\n"

def rlp_only_walk(nodes, steps):
    consts = list(nodes)
    L = ["#pragma version 10", "bytecblock " + " ".join("0x"+c.hex() for c in consts)]
    for i, st in enumerate(steps):
        idx = st.get("extract", st.get("value"))
        L += [f"bytec {i}", f"int {idx}", "callsub rlp_item", "pop"]
    L += ["int 1", "return", M.RLP_ITEM_SUB]
    return "\n".join(L)+"\n"

rk = sim(keccak_only_walk(ACC, STATE_ROOT))
rr = sim(rlp_only_walk(ACC, acc_steps))
RESULTS["account_split"] = {"keccak_only": rk.app_budget_consumed,
                            "rlp_only": rr.app_budget_consumed,
                            "keccak_ok": rk.ok, "rlp_ok": rr.ok}
print(f"  split: keccak_only={rk.app_budget_consumed} (ok={rk.ok}) "
      f"rlp_only={rr.app_budget_consumed} (ok={rr.ok}) "
      f"sum={rk.app_budget_consumed+rr.app_budget_consumed} full={racc.app_budget_consumed}")

# ---------------------------------------------------------------------------
# 4. full storage proof: stateRoot -> account leaf -> storageRoot -> storage slot
# ---------------------------------------------------------------------------
print("\n== full storage proof (composite: account walk + storage walk) ==")
def build_storage_composite(acc_nodes, sto_nodes, state_root_hex):
    acc_steps = derive_steps(acc_nodes)          # ends with value:1 (account rlp)
    sto_steps = derive_steps(sto_nodes)          # ends with value:1 (slot value)
    consts = list(acc_nodes) + list(sto_nodes) + [bytes.fromhex(state_root_hex)]
    a0 = 0; s0 = len(acc_nodes); root_idx = len(acc_nodes)+len(sto_nodes)
    L = ["#pragma version 10", "bytecblock " + " ".join("0x"+c.hex() for c in consts)]
    L += [f"bytec {root_idx}", "store 0"]
    # account walk
    for i, st in enumerate(acc_steps):
        L += [f"bytec {a0+i}", "keccak256", "load 0", "==", "assert"]
        if "extract" in st:
            L += [f"bytec {a0+i}", f"int {st['extract']}", "callsub rlp_item", "store 0"]
        else:
            # account value rlp -> extract storageRoot (item 2) -> new expected
            L += [f"bytec {a0+i}", "int 1", "callsub rlp_item", "store 2",   # account rlp
                  "load 2", "int 2", "callsub rlp_item", "store 0"]          # storageRoot
    # storage walk
    for i, st in enumerate(sto_steps):
        L += [f"bytec {s0+i}", "keccak256", "load 0", "==", "assert"]
        if "extract" in st:
            L += [f"bytec {s0+i}", f"int {st['extract']}", "callsub rlp_item", "store 0"]
        else:
            L += [f"bytec {s0+i}", "int 1", "callsub rlp_item", "store 3"]   # slot value
    L += ["int 1", "return", M.RLP_ITEM_SUB]
    return "\n".join(L)+"\n"

sto_src = build_storage_composite(ACC, STO, STATE_ROOT)
rsto = sim(sto_src)
RESULTS["storage_proof"] = {"acc_nodes": len(ACC), "sto_nodes": len(STO),
                            "total_nodes": len(ACC)+len(STO),
                            "consumed": rsto.app_budget_consumed,
                            "per_node": rsto.app_budget_consumed/(len(ACC)+len(STO)),
                            "prog_bytes": prog_size(sto_src), "ok": rsto.ok,
                            "failure": rsto.failure,
                            "sto_sizes": [len(n) for n in STO]}
print(f"  ok={rsto.ok} acc={len(ACC)}+sto={len(STO)}={len(ACC)+len(STO)} nodes "
      f"consumed={rsto.app_budget_consumed} prog_bytes={prog_size(sto_src)} fail={rsto.failure!r}")

# ---------------------------------------------------------------------------
# 5. receipt/log proof: verify a log entry against receiptsRoot
# ---------------------------------------------------------------------------
print("\n== receipt/log proof ==")
rcpt_steps = derive_steps(RCPT)
rcpt_src = M.build_verifier(RCPT, rcpt_steps, RECEIPTS_ROOT)
rrc = sim(rcpt_src)
RESULTS["receipt_proof"] = {"nodes": len(RCPT), "consumed": rrc.app_budget_consumed,
                            "per_node": rrc.app_budget_consumed/len(RCPT),
                            "prog_bytes": prog_size(rcpt_src), "ok": rrc.ok,
                            "failure": rrc.failure,
                            "value_len": d["receipt_proof"]["value_len"],
                            "sizes": [len(n) for n in RCPT]}
print(f"  ok={rrc.ok} nodes={len(RCPT)} consumed={rrc.app_budget_consumed} "
      f"leaf_value_len={d['receipt_proof']['value_len']} fail={rrc.failure!r}")

json.dump(RESULTS, open("results.json", "w"), indent=2)
print("\nsaved results.json")
