import json
from avm_bls_bench import *

def run(src):
    return simulate_create(compile_teal(src))

print("=== G2 encoding order probe via pairing identity e(P,Q)*e(-P,Q)==1 ===")
for order in ("a0a1", "a1a0"):
    g1s = g1_uncompressed(G1) + g1_uncompressed(neg(G1))
    g2s = g2_uncompressed(G2, order) + g2_uncompressed(G2, order)
    src = ("#pragma version 10\n"
           f"bytecblock 0x{g1s.hex()} 0x{g2s.hex()}\n"
           "bytec 0\nbytec 1\nec_pairing_check BLS12_381g1\n"
           "return\n")  # leave pairing result as program return value
    r = run(src)
    print(f"  order={order}: ok={r.ok} consumed={r.app_budget_consumed} "
          f"approval_returns_true(=identity)={r.ok} failure={r.failure[:70]}")

print("\n=== also confirm a wrong-subgroup/garbage G2 is rejected ===")
# feed 192 bytes of a non-curve point -> expect failure (proves it validates)
bad = b"\x01" + b"\x00" * 191
src = ("#pragma version 10\n"
       f"bytecblock 0x{g1_uncompressed(G1).hex()} 0x{bad.hex()}\n"
       "bytec 0\nbytec 1\nec_pairing_check BLS12_381g1\nreturn\n")
r = run(src)
print(f"  garbage G2: ok={r.ok} failure={r.failure[:90]}")

print("\n=== MSM correctness / argument order (n=3): 2*P1+3*P2+4*P3 ===")
P1, P2, P3 = multiply(G1, 10), multiply(G1, 20), multiply(G1, 30)
expected = add(add(multiply(P1, 2), multiply(P2, 3)), multiply(P3, 4))
exp = g1_uncompressed(expected)
pts = g1_uncompressed(P1) + g1_uncompressed(P2) + g1_uncompressed(P3)
scs = scalar_be(2) + scalar_be(3) + scalar_be(4)
# try order: push points then scalars
for label, a, bb in (("points,scalars", pts, scs), ("scalars,points", scs, pts)):
    src = ("#pragma version 10\n"
           f"bytecblock 0x{a.hex()} 0x{bb.hex()} 0x{exp.hex()}\n"
           "bytec 0\nbytec 1\nec_multi_scalar_mul BLS12_381g1\n"
           "dup\nlog\nbytec 2\n==\nreturn\n")
    r = run(src)
    match = (r.logs and r.logs[0] == exp)
    print(f"  {label}: ok={r.ok} consumed={r.app_budget_consumed} "
          f"result_matches_expected={match} failure={r.failure[:60]}")

print("\n=== ec_map_to G1 input size probe (48-byte Fp) ===")
for sz in (48,):
    fp = (0x99 % field_modulus).to_bytes(sz, "big")
    src = ("#pragma version 10\n"
           f"bytecblock 0x{fp.hex()}\n"
           "bytec 0\nec_map_to BLS12_381g1\n"
           "ec_subgroup_check BLS12_381g1\nreturn\n")  # result must be in subgroup
    r = run(src)
    print(f"  fp size={sz}: ok={r.ok} consumed={r.app_budget_consumed} "
          f"maps_into_subgroup(returns_true)={r.ok} failure={r.failure[:60]}")
