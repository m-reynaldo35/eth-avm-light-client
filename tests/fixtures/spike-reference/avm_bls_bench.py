#!/usr/bin/env python3
"""
avm_bls_bench.py  -- Empirical AVM opcode-budget measurement harness.

Measures the REAL `app-budget-consumed` for AVM opcodes (focused on the
BLS12-381 `ec_*` family) by:

  1. Building a minimal AVM approval program that runs *one* opcode.
  2. Compiling it with algod's /v2/teal/compile (developer API).
  3. Simulating an app-CREATE transaction via /v2/transactions/simulate with a
     large `extra-opcode-budget` (subsumes the old allow-more-opcode-budget
     flag in this algod; empirically capped at 320000).
  4. Reading `app-budget-consumed` straight out of the simulate response.

The harness is generic: `measure(op_teal, operands=...)` will bench any opcode,
not just BLS.  BLS-specific point construction lives in the `bls` section and
uses py_ecc to build REAL, subgroup-valid curve points (no hand-waved bytes).

Run against a fresh localnet:  see run_all() / __main__ and README notes.
"""
import base64
import json
import urllib.request
from dataclasses import dataclass, field

from algosdk.v2client import algod
from algosdk import kmd
from algosdk import transaction

# py_ecc: real BLS12-381 curve arithmetic (subgroup-valid points)
from py_ecc.bls12_381 import (
    G1, G2, add, neg, multiply, curve_order, field_modulus, is_on_curve, b,
)

# --------------------------------------------------------------------------
# Connection config  (dedicated dev-mode algod started for this experiment)
# --------------------------------------------------------------------------
ALGOD_ADDRESS = "http://localhost:4051"
KMD_ADDRESS = "http://localhost:4052"
TOKEN = "a" * 64  # dev-mode token (also the admin token)


def algod_client() -> algod.AlgodClient:
    return algod.AlgodClient(TOKEN, ALGOD_ADDRESS)


def kmd_client() -> kmd.KMDClient:
    return kmd.KMDClient(TOKEN, KMD_ADDRESS)


def funded_account():
    """Pull a funded account (address, private key) from the KMD default wallet."""
    kcl = kmd_client()
    wallets = kcl.list_wallets()
    wid = next(w["id"] for w in wallets if w["name"] == "unencrypted-default-wallet")
    handle = kcl.init_wallet_handle(wid, "")
    try:
        addrs = kcl.list_keys(handle)
        # pick the account with the largest balance
        acl = algod_client()
        best, best_bal = None, -1
        for a in addrs:
            bal = acl.account_info(a)["amount"]
            if bal > best_bal:
                best, best_bal = a, bal
        sk = kcl.export_key(handle, "", best)
        return best, sk
    finally:
        kcl.release_wallet_handle(handle)


# --------------------------------------------------------------------------
# TEAL program assembly
# --------------------------------------------------------------------------
def build_program(operands: list[bytes], op_lines: list[str],
                  trailer: list[str] | None = None) -> str:
    """
    Assemble a minimal approval program:
        #pragma version 10
        bytecblock <operand0> <operand1> ...
        bytec_0 ; bytec_1 ; ...        # push every operand
        <op_lines>                     # the opcode(s) under test
        <trailer or default: pop; int 1; return>
    Operands are embedded as program constants (bytecblock), pushed in order.
    """
    lines = ["#pragma version 10"]
    if operands:
        consts = " ".join("0x" + o.hex() for o in operands)
        lines.append("bytecblock " + consts)
        for i in range(len(operands)):
            lines.append(f"bytec {i}")
    lines.extend(op_lines)
    if trailer is None:
        trailer = ["pop", "int 1", "return"]
    lines.extend(trailer)
    return "\n".join(lines) + "\n"


def compile_teal(src: str) -> bytes:
    """Compile TEAL source to bytecode via algod developer API."""
    req = urllib.request.Request(
        ALGOD_ADDRESS + "/v2/teal/compile",
        data=src.encode(),
        headers={"X-Algo-API-Token": TOKEN, "Content-Type": "text/plain"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        body = json.load(r)
    return base64.b64decode(body["result"])


# clear program: just `int 1; return`
CLEAR_TEAL = "#pragma version 10\nint 1\nreturn\n"


# --------------------------------------------------------------------------
# Simulation
# --------------------------------------------------------------------------
@dataclass
class SimResult:
    ok: bool
    app_budget_added: int = 0
    app_budget_consumed: int = 0
    logs: list[bytes] = field(default_factory=list)
    failure: str = ""
    raw: dict = field(default_factory=dict)


# algod caps simulate's extra-opcode-budget at 320000 (measured empirically).
SIM_EXTRA_BUDGET_CAP = 320_000


def simulate_create(approval: bytes, extra_budget: int = SIM_EXTRA_BUDGET_CAP,
                    extra_pages: int = 3) -> SimResult:
    """
    Simulate an app-CREATE txn whose approval program is `approval`.
    Uses allow-more-opcode-budget + extra-opcode-budget so expensive ops don't
    blow the 700 default. Returns parsed budget + logs + raw response.
    """
    acl = algod_client()
    sender, sk = funded_account()
    sp = acl.suggested_params()
    clear = compile_teal(CLEAR_TEAL)

    txn = transaction.ApplicationCreateTxn(
        sender=sender,
        sp=sp,
        on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval,
        clear_program=clear,
        global_schema=transaction.StateSchema(0, 0),
        local_schema=transaction.StateSchema(0, 0),
        extra_pages=extra_pages,
    )
    stxn = txn.sign(sk)

    from algosdk.v2client.models import (
        SimulateRequest, SimulateRequestTransactionGroup,
    )
    # NOTE: in this algod/algosdk, a non-zero `extra_opcode_budget` is what
    # grants "more opcode budget" -- it subsumes the older
    # allow-more-opcode-budget flag. The extra budget is added to the group pool.
    sreq = SimulateRequest(
        txn_groups=[SimulateRequestTransactionGroup(txns=[stxn])],
        extra_opcode_budget=extra_budget,
    )
    resp = acl.simulate_transactions(sreq)
    return _parse_sim(resp)


def _parse_sim(resp: dict) -> SimResult:
    grp = resp["txn-groups"][0]
    res = SimResult(ok=True, raw=resp)
    res.app_budget_added = grp.get("app-budget-added", 0)
    res.app_budget_consumed = grp.get("app-budget-consumed", 0)
    if "failure-message" in grp and grp["failure-message"]:
        res.ok = False
        res.failure = grp["failure-message"]
    txnres = grp["txn-results"][0]
    # per-txn failure
    tr = txnres.get("txn-result", {})
    logs = tr.get("logs") or []
    res.logs = [base64.b64decode(x) for x in logs]
    return res


# --------------------------------------------------------------------------
# BLS12-381 point construction + encoding (REAL points via py_ecc)
# --------------------------------------------------------------------------
def _i2b(x: int, n: int = 48) -> bytes:
    return int(x).to_bytes(n, "big")


def g1_uncompressed(P) -> bytes:
    """G1 point -> 96-byte uncompressed X||Y big-endian (0-fill for infinity)."""
    if P is None:
        return b"\x00" * 96
    x, y = P
    return _i2b(x.n) + _i2b(y.n)


def g2_uncompressed(P, order="a0a1") -> bytes:
    """
    G2 point -> 192-byte uncompressed.  FQ2 = c0 + c1*u.
    `order` controls per-coordinate limb order:
      'a0a1' -> X.c0||X.c1||Y.c0||Y.c1
      'a1a0' -> X.c1||X.c0||Y.c1||Y.c0
    We test empirically which one the AVM accepts.
    """
    if P is None:
        return b"\x00" * 192
    x, y = P
    xc = x.coeffs  # (c0, c1)
    yc = y.coeffs
    if order == "a0a1":
        return _i2b(xc[0].n) + _i2b(xc[1].n) + _i2b(yc[0].n) + _i2b(yc[1].n)
    else:
        return _i2b(xc[1].n) + _i2b(xc[0].n) + _i2b(yc[1].n) + _i2b(yc[0].n)


def scalar_be(k: int) -> bytes:
    """32-byte big-endian scalar."""
    return int(k % curve_order).to_bytes(32, "big")


if __name__ == "__main__":
    # quick self-test of point encoding
    P = multiply(G1, 12345)
    Q = multiply(G1, 67890)
    R = add(P, Q)
    print("G1 P =", g1_uncompressed(P).hex()[:32], "...")
    print("expected P+Q =", g1_uncompressed(R).hex())
    print("on curve:", is_on_curve(R, b))
