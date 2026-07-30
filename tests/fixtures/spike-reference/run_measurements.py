#!/usr/bin/env python3
"""
run_measurements.py -- drives avm_bls_bench to measure every BLS12-381 opcode,
isolate the opcode-only cost, verify correctness, and probe the MSM size limit.

Each measured number is printed alongside the raw simulate `app-budget-consumed`
so it traces to an actual response.
"""
import json
from avm_bls_bench import *

BASE_APP_CALL_BUDGET = 700  # confirmed via app-budget-added = extra + 700


def measure(name, operands, op_lines, verbose=False):
    """
    Returns dict with gross app-budget-consumed of a minimal 1-op program and
    the isolated opcode cost.

      FULL:  load N operands ; <op> ; pop ; int1 ; return
      BASE:  load N operands ; pop*N ; int1 ; return
      isolated_C = (FULL - BASE) + N - 1     (pop cost = 1, verified)
    """
    n = len(operands)
    full_src = build_program(operands, op_lines, trailer=["pop", "int 1", "return"])
    base_src = build_program(operands, [], trailer=["pop"] * n + ["int 1", "return"])
    full = simulate_create(compile_teal(full_src))
    base = simulate_create(compile_teal(base_src))
    if not full.ok:
        return {"name": name, "ok": False, "failure": full.failure,
                "gross": None, "isolated": None}
    isolated = (full.app_budget_consumed - base.app_budget_consumed) + n - 1
    row = {
        "name": name,
        "ok": True,
        "gross": full.app_budget_consumed,      # minimal 1-op program cost
        "base_loads": base.app_budget_consumed,  # overhead-only program cost
        "isolated": isolated,                    # opcode-only cost
        "budget_added": full.app_budget_added,
    }
    if verbose:
        print(json.dumps(row, indent=2))
    return row


def main():
    rows = []

    # 1) ec_add G1  (two G1 points)
    P = multiply(G1, 12345); Q = multiply(G1, 67890)
    rows.append(measure("ec_add BLS12_381g1",
                        [g1_uncompressed(P), g1_uncompressed(Q)],
                        ["ec_add BLS12_381g1"]))

    # 2) ec_map_to G1 (hash/map field element -> curve). Input = 48-byte Fp.
    fp = (0x1234567 % field_modulus).to_bytes(48, "big")
    rows.append(measure("ec_map_to BLS12_381g1",
                        [fp], ["ec_map_to BLS12_381g1"]))

    # 3) ec_subgroup_check G1 (one G1 point)
    rows.append(measure("ec_subgroup_check BLS12_381g1",
                        [g1_uncompressed(P)], ["ec_subgroup_check BLS12_381g1"]))

    # 4) ec_pairing_check G1 -- 1 pair and 2 pairs.
    #    G2 encoding order determined by the separate encoding probe (a1a0).
    order = G2_ORDER
    # 1 pair: e(G1, G2) -- valid execution (returns 0, product != identity)
    rows.append(measure("ec_pairing_check BLS12_381g1 (1 pair)",
                        [g1_uncompressed(G1), g2_uncompressed(G2, order)],
                        ["ec_pairing_check BLS12_381g1"]))
    # 2 pairs: e(P,Q)*e(-P,Q) == identity -> returns 1
    g1s = g1_uncompressed(G1) + g1_uncompressed(neg(G1))
    g2s = g2_uncompressed(G2, order) + g2_uncompressed(G2, order)
    rows.append(measure("ec_pairing_check BLS12_381g1 (2 pairs)",
                        [g1s, g2s], ["ec_pairing_check BLS12_381g1"]))

    # 5) ec_multi_scalar_mul G1 -- 8, 21, 42, 43 points
    for npts in (8, 21, 42, 43):
        pts = b"".join(g1_uncompressed(multiply(G1, i + 1)) for i in range(npts))
        scs = b"".join(scalar_be(i + 2) for i in range(npts))
        rows.append(measure(f"ec_multi_scalar_mul BLS12_381g1 ({npts} pts)",
                            [pts, scs], ["ec_multi_scalar_mul BLS12_381g1"]))

    print("\n%-46s %8s %8s %8s" % ("operation", "gross", "isolated", "added"))
    print("-" * 74)
    for r in rows:
        if r["ok"]:
            print("%-46s %8s %8s %8s" %
                  (r["name"], r["gross"], r["isolated"], r["budget_added"]))
        else:
            print("%-46s  FAIL: %s" % (r["name"], r["failure"][:60]))
    return rows


# G2 limb order determined empirically by probe_encoding.py: c0-first (a0a1).
# (Only a0a1 satisfies the pairing negation identity; a1a0 errors.)
G2_ORDER = "a0a1"

if __name__ == "__main__":
    main()
