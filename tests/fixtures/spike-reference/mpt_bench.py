#!/usr/bin/env python3
"""
mpt_bench.py -- Empirical AVM opcode-budget measurement harness for Ethereum
Merkle-Patricia-Trie proof verification.

Follows the same method as the prior BLS12-381 spike: compile a minimal AVM
program, run it through /v2/transactions/simulate with a large
extra-opcode-budget, and read the REAL `app-budget-consumed` back. Every number
in MPT_RESULTS.md traces to an actual simulate response produced by this module.

This module keeps the reusable core from avm_bls_bench.py (algod/kmd clients,
funded_account, build_program, compile_teal, simulate_create, SimResult) and
adds keccak/RLP/MPT helpers instead of the BLS point encoders.
"""
import base64, json, urllib.request
from dataclasses import dataclass, field
from Crypto.Hash import keccak
from algosdk.v2client import algod
from algosdk import kmd
from algosdk import transaction

ALGOD_ADDRESS = "http://localhost:4051"
KMD_ADDRESS   = "http://localhost:4052"
TOKEN = "a" * 64  # dev-mode token (also admin token)

def algod_client(): return algod.AlgodClient(TOKEN, ALGOD_ADDRESS)
def kmd_client():   return kmd.KMDClient(TOKEN, KMD_ADDRESS)

def funded_account():
    """Pull a funded account (address, private key) from the KMD default wallet."""
    kcl = kmd_client()
    wid = next(w["id"] for w in kcl.list_wallets()
               if w["name"] == "unencrypted-default-wallet")
    handle = kcl.init_wallet_handle(wid, "")
    try:
        acl = algod_client(); best, best_bal = None, -1
        for a in kcl.list_keys(handle):
            bal = acl.account_info(a)["amount"]
            if bal > best_bal: best, best_bal = a, bal
        return best, kcl.export_key(handle, "", best)
    finally:
        kcl.release_wallet_handle(handle)

def compile_teal(src):
    req = urllib.request.Request(
        ALGOD_ADDRESS + "/v2/teal/compile", data=src.encode(),
        headers={"X-Algo-API-Token": TOKEN, "Content-Type": "text/plain"},
        method="POST")
    with urllib.request.urlopen(req) as r:
        return base64.b64decode(json.load(r)["result"])

CLEAR_TEAL = "#pragma version 10\nint 1\nreturn\n"

@dataclass
class SimResult:
    ok: bool
    app_budget_added: int = 0
    app_budget_consumed: int = 0
    logs: list = field(default_factory=list)
    failure: str = ""
    raw: dict = field(default_factory=dict)

SIM_EXTRA_BUDGET_CAP = 320_000  # algod caps simulate extra-opcode-budget here

def simulate_create(approval, extra_budget=SIM_EXTRA_BUDGET_CAP, extra_pages=3):
    acl = algod_client(); sender, sk = funded_account()
    txn = transaction.ApplicationCreateTxn(
        sender=sender, sp=acl.suggested_params(),
        on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval, clear_program=compile_teal(CLEAR_TEAL),
        global_schema=transaction.StateSchema(0, 0),
        local_schema=transaction.StateSchema(0, 0), extra_pages=extra_pages)
    from algosdk.v2client.models import (SimulateRequest,
                                         SimulateRequestTransactionGroup)
    sreq = SimulateRequest(
        txn_groups=[SimulateRequestTransactionGroup(txns=[txn.sign(sk)])],
        extra_opcode_budget=extra_budget)
    return _parse_sim(acl.simulate_transactions(sreq))

def _parse_sim(resp):
    grp = resp["txn-groups"][0]
    res = SimResult(ok=True, raw=resp)
    res.app_budget_added    = grp.get("app-budget-added", 0)
    res.app_budget_consumed = grp.get("app-budget-consumed", 0)
    if grp.get("failure-message"):
        res.ok = False; res.failure = grp["failure-message"]
    tr = grp["txn-results"][0].get("txn-result", {})
    res.logs = [base64.b64decode(x) for x in (tr.get("logs") or [])]
    return res

# ---------------------------------------------------------------------------
# keccak / RLP / MPT helpers (Python side, for driving/validating the TEAL)
# ---------------------------------------------------------------------------
def keccak256(b: bytes) -> bytes:
    h = keccak.new(digest_bits=256); h.update(b); return h.digest()

def rlp_split(node: bytes):
    """Decode one RLP list into a list of (offset, length) content spans of its
    top-level items (Python reference for the on-chain skip loop). Returns
    (payload_start, [(off,len),...])."""
    fb = node[0]
    if fb >= 0xf8:            # long list
        numlen = fb - 0xf7
        pos = 1 + numlen
    elif fb >= 0xc0:          # short list
        pos = 1
    else:
        raise ValueError("not a list")
    spans = []
    while pos < len(node):
        p = node[pos]
        if p < 0x80:                 # single byte
            spans.append((pos, 1)); pos += 1
        elif p <= 0xb7:              # short string
            ln = p - 0x80; spans.append((pos + 1, ln)); pos += 1 + ln
        else:                        # long string
            lenlen = p - 0xb7
            ln = int.from_bytes(node[pos+1:pos+1+lenlen], "big")
            spans.append((pos + 1 + lenlen, ln)); pos += 1 + lenlen + ln
    return spans

def rlp_item(node: bytes, idx: int) -> bytes:
    off, ln = rlp_split(node)[idx]
    return node[off:off+ln]

def node_kind(node: bytes):
    """Return ('branch'|'extension'|'leaf', items)."""
    spans = rlp_split(node)
    if len(spans) == 17:
        return "branch", spans
    # 2-item: inspect hex-prefix nibble of the path (item 0)
    off, ln = spans[0]
    first = node[off]
    return ("leaf" if (first & 0x20) else "extension"), spans

def branch_child_index(node: bytes, next_node_hash: bytes):
    """Which branch slot (0..15) points at next_node_hash."""
    for i in range(16):
        if rlp_item(node, i) == next_node_hash:
            return i
    raise ValueError("child hash not found in branch")

# ---------------------------------------------------------------------------
# TEAL generation for MPT verification
# ---------------------------------------------------------------------------
# rlp_item subroutine: (node[]byte, idx uint) -> content[]byte, parsing the RLP
# list header + item skip loop entirely on-chain. Scratch slots 100..108 are
# scratch temporaries (single-threaded, non-recursive use only).
RLP_ITEM_SUB = """
rlp_item:
proto 2 1
frame_dig -2
store 100
frame_dig -1
store 101
load 100
int 0
getbyte
store 102
load 102
int 247
>
bnz rli_long
int 1
store 103
b rli_hdrdone
rli_long:
load 102
int 247
-
store 104
int 1
load 104
+
store 103
rli_hdrdone:
int 0
store 105
rli_loop:
load 105
load 101
==
bnz rli_found
load 100
load 103
getbyte
store 106
load 106
int 128
<
bnz rli_single
load 106
int 183
<=
bnz rli_short
load 106
int 183
-
store 107
load 100
load 103
int 1
+
load 107
extract3
btoi
store 108
load 103
int 1
+
load 107
+
load 108
+
store 103
b rli_adv
rli_short:
load 106
int 128
-
store 108
load 103
int 1
+
load 108
+
store 103
b rli_adv
rli_single:
load 103
int 1
+
store 103
rli_adv:
load 105
int 1
+
store 105
b rli_loop
rli_found:
load 100
load 103
getbyte
store 106
load 106
int 128
<
bnz rlf_single
load 106
int 183
<=
bnz rlf_short
load 106
int 183
-
store 107
load 100
load 103
int 1
+
load 107
extract3
btoi
store 108
load 100
load 103
int 1
load 107
+
+
load 108
extract3
retsub
rlf_short:
load 106
int 128
-
store 108
load 108
int 0
==
bnz rlf_empty
load 100
load 103
int 1
+
load 108
extract3
retsub
rlf_empty:
byte 0x
retsub
rlf_single:
load 100
load 103
int 1
extract3
retsub
"""

def build_verifier(nodes, steps, root_hex, trailer_ok=True):
    """Generate a TEAL v10 program that verifies an MPT path.

    nodes  : list of node byte strings (embedded as bytecblock constants).
    steps  : list of dicts describing how to descend at each node:
             {'extract': idx}  -> expected = rlp_item(node, idx)   (branch/ext)
             {'value':   idx}  -> stop; leave rlp_item(node, idx) (leaf value)
    root_hex : hex root (no 0x) the first node must hash to.
    Returns TEAL source string. Each node i: assert keccak256(node_i)==expected;
    then set expected = extracted child (or leave value on stack at a leaf)."""
    consts = list(nodes) + [bytes.fromhex(root_hex)]
    root_idx = len(nodes)
    lines = ["#pragma version 10"]
    lines.append("bytecblock " + " ".join("0x" + c.hex() for c in consts))
    # expected := root
    lines += [f"bytec {root_idx}", "store 0"]
    for i, st in enumerate(steps):
        # assert keccak256(node_i) == expected
        lines += [f"bytec {i}", "keccak256", "load 0", "==", "assert"]
        if "extract" in st:
            lines += [f"bytec {i}", f"int {st['extract']}", "callsub rlp_item",
                      "store 0"]
        else:  # value: leave it on stack, keep for optional logging
            lines += [f"bytec {i}", f"int {st['value']}", "callsub rlp_item",
                      "store 1"]
    if trailer_ok:
        lines += ["int 1", "return"]
    lines.append(RLP_ITEM_SUB)
    return "\n".join(lines) + "\n"
