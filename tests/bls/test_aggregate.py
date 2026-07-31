"""Tests T5, T6, T7 (docs/design/001-bls-primitives.md §11).

T6's core (aggregation vs py_ecc, N in {0,1,2,41,42,43,64,100,512}) runs
offline against `reference.g1_sum`. T5 (42/43 boundary) and T7 (MSM) need
real `ec_*` opcodes / real AVM value-cap enforcement and so are live-tier,
using `conftest.live_harness`.
"""

from __future__ import annotations

import random

import pytest
from py_ecc.bls12_381 import curve_order
from py_ecc.optimized_bls12_381 import G1, add, multiply

from . import reference as ref
from .test_codec import _g1_uncompressed


def _random_points(n: int, seed: int):
    rng = random.Random(seed)
    return [multiply(G1, rng.randrange(1, curve_order)) for _ in range(n)]


# ---------------------------------------------------------------------------
# T6 -- aggregation vs py_ecc, offline.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n", [0, 1, 2, 41, 42, 43, 64, 100, 512])
def test_t6_offline_aggregation_matches_py_ecc(n):
    points = _random_points(n, seed=n)
    avm_points = [_g1_uncompressed(p) for p in points]
    got = ref.g1_sum(avm_points)

    expected = None
    for p in points:
        expected = p if expected is None else add(expected, p)
    want = _g1_uncompressed(expected)

    assert got == want


def test_t6_offline_n0_is_infinity():
    assert ref.g1_sum([]) == ref.G1_INFINITY


def test_t6_offline_n1_is_identity():
    p = multiply(G1, 42)
    avm = _g1_uncompressed(p)
    assert ref.g1_sum([avm]) == avm


# ---------------------------------------------------------------------------
# T5 -- 42/43-point boundary, live.
# ---------------------------------------------------------------------------


def _blob(n: int, seed: int) -> bytes:
    return b"".join(_g1_uncompressed(p) for p in _random_points(n, seed))


def _stage_and_run(live_harness, box_name: bytes, blob: bytes, final_call):
    """Write `blob` into a fresh box across as many `box_stage_write` calls
    as the 2048B-per-txn app-arg cap requires, then run `final_call`
    (a `(method_name, args)` pair referencing the box) in the SAME atomic
    group (§10.1/§10.2's real delivery mechanism -- see harness.py's box
    staging methods docstring). Returns the final call's `SimResult`.
    """
    CHUNK = 2000  # comfortably under the ~2016B a single txn can carry
    calls = [("box_stage_create", [box_name, len(blob)])]
    for i in range(0, len(blob), CHUNK):
        calls.append(("box_stage_write", [box_name, i, blob[i : i + CHUNK]]))
    calls.append(final_call)
    calls.append(("box_stage_delete", [box_name]))
    results = live_harness.call_group(calls)
    return results[-2]  # final_call's result (before the trailing delete)


def test_t5_live_41_and_42_points_ok(live_harness):
    for n in (41, 42):
        blob = _blob(n, seed=n)
        r = _stage_and_run(
            live_harness,
            f"t5-box-{n}".encode(),
            blob,
            ("g1_sum_blob_from_box", [f"t5-box-{n}".encode(), len(blob)]),
        )
        assert r.ok, f"n={n}: {r.failure}"


def test_t5_live_43_points_rejected_at_the_value_cap(live_harness):
    """43*96 = 4128 > 4096 -- the AVM value cap rejects this before the
    contract's own length assertion ever runs (§7.3): the failure happens
    constructing the 4128-byte argument value itself, not inside
    `assert_g1_blob`. We build the arg via ABI byte[] encoding, which the
    node will reject at decode/value-construction time.
    """
    blob = _blob(43, seed=43)
    assert len(blob) == 43 * 96 == 4128
    r = live_harness.call("g1_sum_blob", blob)
    assert not r.ok, "a 4128-byte value must be rejected (43-point blob > 4096B cap)"


def test_t5_live_4032_ok_4033_rejected(live_harness):
    # 42 infinities is a valid (if degenerate) blob shape at exactly the
    # value cap; staged into a box (see `_stage_and_run`) since a single
    # ABI call cannot carry 4032B of argument data (§7.3).
    ok_blob = b"\x00" * 4032
    r_ok = _stage_and_run(
        live_harness,
        b"t5-box-4032",
        ok_blob,
        ("assert_g1_blob_from_box", [b"t5-box-4032", len(ok_blob)]),
    )
    assert r_ok.ok, r_ok.failure

    too_big = b"\x00" * 4033
    r_bad = _stage_and_run(
        live_harness,
        b"t5-box-4033",
        too_big,
        ("assert_g1_blob_from_box", [b"t5-box-4033", len(too_big)]),
    )
    assert not r_bad.ok


def test_t5_live_non_multiple_of_96_rejected(live_harness):
    bad = b"\x00" * 100  # not a multiple of 96
    r = live_harness.call("assert_g1_blob", bad)
    assert not r.ok


def test_t5_live_21_point_app_arg_limit(live_harness):
    """App args cap total arg length at 2048 B -> 21 points max delivered
    per txn (§7.3). Exercise via a real ABI call at exactly 21 points;
    the 22-point case is expected to fail purely on the app-arg
    encoding/size limit, independent of anything `assert_g1_blob` checks.
    """
    blob_21 = _blob(21, seed=21)
    assert len(blob_21) == 21 * 96 == 2016
    r = live_harness.call("g1_sum_blob", blob_21)
    assert r.ok, r.failure


# ---------------------------------------------------------------------------
# T7 -- MSM, live.
# ---------------------------------------------------------------------------


def test_t7_live_spike_exact_vector_2p1_3p2_4p3(live_harness):
    """The spike's exact vector: 2*P1 + 3*P2 + 4*P3."""
    P1, P2, P3 = multiply(G1, 10), multiply(G1, 20), multiply(G1, 30)
    expected = add(add(multiply(P1, 2), multiply(P2, 3)), multiply(P3, 4))

    points = _g1_uncompressed(P1) + _g1_uncompressed(P2) + _g1_uncompressed(P3)
    scalars = (
        (2).to_bytes(32, "big") + (3).to_bytes(32, "big") + (4).to_bytes(32, "big")
    )
    r = live_harness.call("g1_msm_chunk", points, scalars)
    assert r.ok, r.failure
    got = r.return_value[2:]
    assert got == _g1_uncompressed(expected)


def test_t7_live_chunked_n100_random_scalars_vs_py_ecc(live_harness):
    """N=100 needs ceil(100/42) = 3 chunks; verify chunked
    `g1_msm_accumulate` matches py_ecc's own MSM (computed as a plain
    weighted sum)."""
    rng = random.Random(100)
    n = 100
    points = _random_points(n, seed=n)
    scalars = [rng.randrange(1, curve_order) for _ in range(n)]

    expected = None
    for p, k in zip(points, scalars):
        term = multiply(p, k)
        expected = term if expected is None else add(expected, term)

    chunk_size = 42
    acc = ref.G1_INFINITY
    idx = 0
    chunk_num = 0
    while idx < n:
        chunk_pts = points[idx : idx + chunk_size]
        chunk_sc = scalars[idx : idx + chunk_size]
        points_blob = b"".join(_g1_uncompressed(p) for p in chunk_pts)
        scalars_blob = b"".join(k.to_bytes(32, "big") for k in chunk_sc)
        # A full 42-point chunk's points blob (4032 B) exceeds the 2048B
        # total-app-args cap in a single ABI call (§7.3) even though it is
        # a legal single AVM value -- stage it into a box (§10.1/§10.2's
        # real delivery mechanism) and read it back inside the program.
        box_name = f"t7-box-{chunk_num}".encode()
        r = _stage_and_run(
            live_harness,
            box_name,
            points_blob,
            (
                "g1_msm_accumulate_points_from_box",
                [acc, box_name, len(points_blob), scalars_blob],
            ),
        )
        assert r.ok, r.failure
        acc = r.return_value[2:]
        idx += chunk_size
        chunk_num += 1

    assert acc == _g1_uncompressed(expected)


def test_t7_live_mismatched_points_scalars_length_rejected(live_harness):
    points = _g1_uncompressed(multiply(G1, 5)) + _g1_uncompressed(multiply(G1, 6))
    scalars = (1).to_bytes(32, "big")  # only one scalar for two points
    r = live_harness.call("g1_msm_chunk", points, scalars)
    assert not r.ok
