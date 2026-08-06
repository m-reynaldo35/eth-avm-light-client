"""Pull a real, larger sample of Ethereum blocks and compute the real T1/T2/T3-tier
coverage distribution, replacing the 2-block sample docs/design/007's §3.1 flags as thin.

Uses eth_getBlockReceipts (one RPC call per block, all receipts) against the same
public RPC pool pull_eth_data.py uses. For each receipt, computes the RLP-encoded
receipt body size (the same encoding build_trie.py uses) and each log's RLP size,
then classifies into T1 (<=1942B)/T2(<=4096B)/tier-A/tier-B/tier-C/unprovable per
docs/design/007-receipt-log-proof.md's real tier bounds:
  T1: leaf <= 1942
  T2: 1942 < leaf <= 4096
  tier A: leaf <= 8567 and max_log <= 640
  tier B: leaf <= 8567 and max_log <= 2560  (excludes A only on log size)
  tier C: leaf <= 16384 and max_log <= 8192
  unprovable: exceeds tier C

Leaf size is approximated as encoded receipt body size + 9 bytes (the doc's own
stated upper bound for hex-prefix path + RLP-list overhead) -- conservative, i.e.
never UNDERcounts which tier a receipt needs.
"""
import json, urllib.request, time, sys, random
import rlp

RPCS = ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org", "https://eth.merkle.io",
        "https://1rpc.io/eth", "https://eth-mainnet.public.blastapi.io"]
HEADERS = {"content-type": "application/json", "User-Agent": "curl/8.0"}
LEAF_OVERHEAD = 9  # conservative upper bound per design doc §3.1

def rpc(method, params, tries=4):
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    last = None
    for attempt in range(tries):
        for u in RPCS:
            try:
                req = urllib.request.Request(u, data=payload, headers=HEADERS)
                with urllib.request.urlopen(req, timeout=20) as r:
                    d = json.load(r)
                if "result" in d and d["result"] is not None:
                    return d["result"]
                last = d
            except Exception as e:
                last = str(e)
            time.sleep(0.15)
        time.sleep(1.0)
    raise RuntimeError(f"all rpc failed for {method}: {last}")

def hx(s):
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)

def qi(s):
    if isinstance(s, int):
        return s
    return int(s, 16) if s else 0

def encode_receipt_and_logs(r):
    logs = [[hx(l["address"]), [hx(t) for t in l["topics"]], hx(l["data"])] for l in r["logs"]]
    log_lens = [len(rlp.encode(l)) for l in logs]
    status = qi(r.get("status", "0x1"))
    body = [b"" if status == 0 else bytes([1]), qi(r["cumulativeGasUsed"]), hx(r["logsBloom"]), logs]
    enc = rlp.encode(body)
    ty = qi(r.get("type", "0x0"))
    final = (bytes([ty]) + enc) if ty else enc
    return len(final), (max(log_lens) if log_lens else 0), len(logs)

def classify(leaf_len, max_log, n_logs):
    if leaf_len <= 1942:
        return "T1"
    if leaf_len <= 4096:
        return "T2"
    if leaf_len <= 8567 and max_log <= 640:
        return "tierA"
    if leaf_len <= 8567 and max_log <= 2560:
        return "tierB"
    if leaf_len <= 16384 and max_log <= 8192:
        return "tierC"
    return "unprovable"

def main():
    n_blocks = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    head = int(rpc("eth_blockNumber", []), 16)
    random.seed(42)
    # spread across the last ~14 days (~100,800 blocks @ 12s/block), avoid the tip (reorg risk)
    span = min(100_800, head - 1000)
    candidates = sorted(random.sample(range(head - span, head - 100), n_blocks))

    counts = {"T1": 0, "T2": 0, "tierA": 0, "tierB": 0, "tierC": 0, "unprovable": 0}
    total_receipts = 0
    blocks_done = 0
    errors = 0
    leaf_sizes = []

    for i, bn in enumerate(candidates):
        bhex = hex(bn)
        try:
            receipts = rpc("eth_getBlockReceipts", [bhex])
        except Exception as e:
            errors += 1
            print(f"  block {bn}: FAILED ({e})", file=sys.stderr)
            continue
        for r in receipts:
            enc_len, max_log, n_logs = encode_receipt_and_logs(r)
            leaf_len = enc_len + LEAF_OVERHEAD
            leaf_sizes.append(leaf_len)
            counts[classify(leaf_len, max_log, n_logs)] += 1
            total_receipts += 1
        blocks_done += 1
        if (i + 1) % 25 == 0:
            print(f"  ...{i+1}/{n_blocks} blocks, {total_receipts} receipts so far", file=sys.stderr)
        time.sleep(0.05)

    print(json.dumps({
        "blocks_requested": n_blocks, "blocks_succeeded": blocks_done, "blocks_failed": errors,
        "total_receipts": total_receipts, "counts": counts,
        "pct": {k: round(100*v/total_receipts, 3) for k, v in counts.items()} if total_receipts else {},
        "leaf_size_p50": sorted(leaf_sizes)[len(leaf_sizes)//2] if leaf_sizes else None,
        "leaf_size_p90": sorted(leaf_sizes)[int(len(leaf_sizes)*0.9)] if leaf_sizes else None,
        "leaf_size_p99": sorted(leaf_sizes)[int(len(leaf_sizes)*0.99)] if leaf_sizes else None,
        "leaf_size_max": max(leaf_sizes) if leaf_sizes else None,
        "block_range": [candidates[0], candidates[-1]],
    }, indent=2))

if __name__ == "__main__":
    main()
