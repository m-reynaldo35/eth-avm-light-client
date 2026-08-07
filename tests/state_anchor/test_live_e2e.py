"""M8's live/real-data suites: G1-M8 (the headline proof), G5-M8 (real
16-transaction ring-init group), and Suite B budget measurements.

G1-M8, as actually delivered this pass (2026-08-06): the design doc's own
pinned example (mainnet block 25,639,768) is now ~11 days / far more than
8,192 slots behind the CURRENT live finalized head, so it is unreachable by
either DIRECT or HISTORICAL mode any more -- the 27.3-hour anchorable window
that made it a good example when 008 was written has since closed. This
test substitutes the CURRENT live finalized block (whatever it is at run
time) for the same property under test: a REAL M4 install against REAL
live data, REAL execution-payload SSZ merkleization (`real_ssz.py`,
independently cross-checked against the two spec-published anchors in
§3.2's own style before this file trusts it), a REAL `anchor_direct`
submission, and a REAL `attest` read whose `el_receipts_root` is
byte-identical to the real chain's `receiptsRoot` for that exact block --
the actual claim TP-M7-2/G1-M8 exist to prove, on real, current data rather
than a historical fixture.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from relayer.sources import beacon  # noqa: E402
from relayer.sources import eth_rpc  # noqa: E402
from relayer.proofs.receipts_trie import build_receipts_trie_and_path  # noqa: E402
from relayer.ssz import execution_payload as real_ssz  # noqa: E402
from tests.state_anchor.conftest import (  # noqa: E402
    Arc4Harness,
    algod_client,
    compile_teal,
    deploy_donor_pair,
    funded_account,
    kmd_client,
    patched_repo_copy,
    puya_compile,
)
from tests.sync_committee import reference as ref  # noqa: E402
from tests.sync_committee.test_live_e2e_finality import (  # noqa: E402
    CURRENT_SC_GINDEX,
    FINALITY_GINDEX,
    FULU_FORK_EPOCH,
    FULU_FORK_VERSION,
    GEN,
    NEXT_SC_GINDEX,
    _choose_mode_and_boxes,
    _deploy_bench_apps,
    _fetch_live_checkpoint_and_update,
    _issue_donor_txn,
    _submit_update_group,
)
from tests.sync_committee.conftest import SyncCommitteeLiveHarness

RING_N = 8

# Electra/Fulu `g_block_roots_base` (§3.3): design-doc-CITED value, used
# ONLY as a placeholder fork-table column DIRECT mode never reads (that
# column is exercised solely by HISTORICAL mode's block_roots fold, which
# this pass's live test does not reach -- see this file's own honest-gap
# note near `test_g1_m8_real_direct_anchor_and_attest`).
G_BLOCK_ROOTS_BASE_PLACEHOLDER = 69


def _beacon_reachable() -> bool:
    for base in beacon.BEACON_APIS:
        try:
            req = urllib.request.Request(
                base.rstrip("/") + "/eth/v1/beacon/light_client/finality_update", headers=beacon.HEADERS
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:  # noqa: BLE001
            continue
    return False


@pytest.fixture(scope="module")
def beacon_available() -> bool:
    return _beacon_reachable()


@pytest.fixture(scope="module")
def genesis_validators_root() -> bytes:
    return bytes.fromhex("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")


@pytest.fixture(scope="module")
def live_data(beacon_available):
    if not beacon_available:
        pytest.skip("no reachable beacon-API endpoint in the pool")
    return _fetch_live_checkpoint_and_update()


@pytest.fixture(scope="module")
def compiled_m4_bench(algod_available):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    import subprocess

    bench_src = REPO_ROOT / "contracts" / "sync_committee" / "bench_app.py"
    out_dir = Path("/tmp/m8_m4bench_out")
    out_dir.mkdir(exist_ok=True)
    subprocess.run([sys.executable, "-m", "puyapy", str(bench_src), "--out-dir", str(out_dir)], check=True, capture_output=True)

    def compile_name(name, kind="approval"):
        return (out_dir / f"{name}.{kind}.teal").read_text()

    algod = algod_client()
    return {
        "callee_approval": compile_teal(algod, compile_name("DonorCallee")),
        "callee_clear": compile_teal(algod, compile_name("DonorCallee", "clear")),
        "issuer_approval": compile_teal(algod, compile_name("DonorIssuer")),
        "issuer_clear": compile_teal(algod, compile_name("DonorIssuer", "clear")),
    }


@pytest.fixture(scope="module")
def installed_committee(algod_available, live_data, compiled_m4_bench, genesis_validators_root):
    """REAL M4: fresh `SyncCommitteeVerifier`, real live "fulu" fork row,
    real bootstrap, real 64-chunk 512-member install. Identical procedure
    to `tests/sync_committee/test_live_e2e_finality.py`'s own fixture --
    this module needs its OWN real M4 instance (not a shared one) so that
    tests in the two files never race on the same on-chain state."""
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    boot_args = live_data["boot_args"]
    checkpoint_root = live_data["checkpoint_root"]

    h = SyncCommitteeLiveHarness()
    h.create(h.sender, genesis_validators_root)
    callee_id, issuer_id = _deploy_bench_apps(h, compiled_m4_bench)

    h.submit([(
        "append_fork_row",
        [FULU_FORK_EPOCH, FULU_FORK_VERSION, FINALITY_GINDEX, CURRENT_SC_GINDEX, NEXT_SC_GINDEX],
        [(0, b"forks")],
    )])

    def key_box_name(gen, j):
        return b"k:" + gen.to_bytes(8, "big") + j.to_bytes(8, "big")[7:8]

    def session_box_name(gen):
        return b"s:" + gen.to_bytes(8, "big")

    def total_box_name(gen):
        return b"a:" + gen.to_bytes(8, "big")

    key_refs = [(0, key_box_name(GEN, j)) for j in range(8)]
    session_ref = [(0, session_box_name(GEN))]
    h.submit([
        ("bootstrap", [boot_args.header, boot_args.committee_root, boot_args.current_sc_branch, checkpoint_root],
         [(0, b"forks")] + key_refs[:7]),
        ("install_open_keys", [], key_refs),
        ("install_open_session", [], session_ref + key_refs[:7]),
        ("noop_budget", [], session_ref),
    ])

    method = __import__("algosdk.abi", fromlist=["Method"]).Method.undictify(h.methods["install_chunk"])
    from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer

    for cursor in range(0, 512, 8):
        chunk = boot_args.pubkey_pairs[cursor : cursor + 8]
        compressed_blob = b"".join(c for c, _u in chunk)
        uncompressed_blob = b"".join(u for _c, u in chunk)
        box_j = cursor // 64
        kb = key_box_name(GEN, box_j)
        sb = session_box_name(GEN)
        signer = AccountTransactionSigner(h.sk)
        atc = AtomicTransactionComposer()
        atc.add_transaction(_issue_donor_txn(h, issuer_id, callee_id, 40))
        sp = h.algod.suggested_params()
        sp.flat_fee = True
        sp.fee = 1000
        atc.add_method_call(
            app_id=h.app_id, method=method, sender=h.sender, sp=sp, signer=signer,
            method_args=[cursor, compressed_blob, uncompressed_blob], boxes=[(0, kb), (0, sb), (0, kb), (0, sb)],
        )
        atc.execute(h.algod, 4)

    signer = AccountTransactionSigner(h.sk)
    atc = AtomicTransactionComposer()
    atc.add_transaction(_issue_donor_txn(h, issuer_id, callee_id, 15))
    from algosdk.abi import Method
    finalize_method = Method.undictify(h.methods["install_finalize"])
    sp = h.algod.suggested_params()
    sp.flat_fee = True
    sp.fee = 1000
    atc.add_method_call(
        app_id=h.app_id, method=finalize_method, sender=h.sender, sp=sp, signer=signer,
        method_args=[boot_args.aggregate_compressed, boot_args.aggregate_uncompressed],
        boxes=[(0, session_box_name(GEN)), (0, total_box_name(GEN))],
    )
    atc.execute(h.algod, 4)

    return {"h": h, "callee_id": callee_id, "issuer_id": issuer_id}


@pytest.fixture(scope="module")
def finalized_m4(installed_committee, live_data):
    """Advances the real M4 instance with the SAME live `finality_update`
    used to derive the anchor fixtures below, so M8's `anchor_direct` reads
    a `fin_root` M4 genuinely just finalized."""
    h = installed_committee["h"]
    issuer_id = installed_committee["issuer_id"]
    callee_id = installed_committee["callee_id"]
    fu_now_args = live_data["fu_now_args"]
    mode, box_refs, plan = _choose_mode_and_boxes(fu_now_args.sync_committee_bits, GEN)
    # FIXED (this pass): the ad hoc `box_refs + box_refs[:4]` padding below
    # this comment used to compensate for `_choose_mode_and_boxes` only
    # counting distinct boxes, not their real declared byte size -- the
    # exact root cause of the "box read budget (6144) exceeded" failure
    # this comment used to describe as unexplained live-data fragility.
    # `_choose_mode_and_boxes` now returns a real `plan` (relayer.group.
    # boxes.plan_box_refs), and `_submit_update_group` sizes the real
    # transaction count from it directly -- no hand-picked padding needed.
    result = _submit_update_group(h, issuer_id, callee_id, fu_now_args, fu_now_args.signature, mode, box_refs, plan=plan)
    assert result.tx_ids, "real submit_update did not commit"
    return h


class TestG5M8RealRingInit:
    def test_ring_init_128_in_one_atomic_group(self, algod_available, compiled_anchor, account):
        """G5-M8: the real 16-transaction `ring_init_chunk` group at
        `N = 128`, committed for real (not `simulate`) -- 004 §16 is a
        first-hand account of why box-reference arithmetic must be
        confirmed live, not merely reasoned about."""
        if not algod_available:
            pytest.skip("no dev-mode algod reachable")
        sender, sk = account
        h = Arc4Harness(compiled_anchor["TrustedRootAnchor"], sender, sk)
        # m4_app_id is irrelevant to ring-init; use 1 (never dereferenced
        # until an anchor_* call touches it).
        h.create([sender, 1, 128], extra_pages=1, boxes=[(0, b"forks8")], fund_app=140_000_000)

        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer

        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(sk)
        method = Method.undictify(h.methods["ring_init_chunk"])
        for chunk_start in range(0, 128, 8):
            boxes = [(0, b"h:" + i.to_bytes(8, "big")) for i in range(chunk_start, chunk_start + 8)]
            sp = h.algod.suggested_params()
            sp.flat_fee = True
            sp.fee = 1000
            atc.add_method_call(
                app_id=h.app_id, method=method, sender=sender, sp=sp, signer=signer,
                method_args=[8], boxes=boxes,
            )
        result = atc.execute(h.algod, 4)
        assert len(result.tx_ids) == 16
        info = h.algod.application_info(h.app_id)
        import base64
        gstate = {base64.b64decode(kv["key"]): kv["value"] for kv in info["params"]["global-state"]}
        assert gstate[b"ring_cursor"]["uint"] == 128
        assert gstate[b"frozen"]["uint"] == 0


@pytest.fixture(scope="module")
def compiled_anchor(algod_available):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    return puya_compile(REPO_ROOT / "contracts" / "state_anchor" / "anchor_app.py")


@pytest.fixture(scope="module")
def account(algod_available):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    algod = algod_client()
    kmd = kmd_client()
    return funded_account(algod, kmd)


@pytest.fixture(scope="module")
def donors(algod_available, account):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    algod = algod_client()
    sender, sk = account
    return deploy_donor_pair(algod, sender, sk)


class TestG1M8RealDirectAnchor:
    """The headline proof, run against CURRENT real data (see module
    docstring for why the design doc's own pinned example is no longer
    reachable)."""

    def test_g1_m8_real_direct_anchor_and_attest(self, finalized_m4, live_data, compiled_anchor, account, donors):
        h = finalized_m4  # real M4, real finalized state
        sender, sk = account

        fu_args = live_data["fu_now_args"]
        fu_now = live_data["fu_now"]
        finalized_json = fu_now["data"]["finalized_header"]
        beacon_fields = finalized_json["beacon"]
        payload = finalized_json["execution"]
        execution_branch = finalized_json["execution_branch"]

        fin_header = fu_args.finalized_header
        real_fin_root = ref.hash_tree_root_beacon_block_header(fin_header)

        # Independent cross-check (§3.2's own discipline), against real
        # data, before this fixture is trusted for the on-chain call:
        body_root_real = bytes.fromhex(beacon_fields["body_root"][2:])
        for field, expected_gindex in (
            ("state_root", 802), ("receipts_root", 803), ("block_number", 806),
        ):
            branch, gindex = real_ssz.deep_branch(payload, execution_branch, field)
            assert gindex == expected_gindex
            leaf = (
                int(payload["block_number"]).to_bytes(8, "little") + b"\x00" * 24
                if field == "block_number" else bytes.fromhex(payload[field][2:])
            )
            assert real_ssz.compute_branch_root(leaf, branch, gindex) == body_root_real

        state_branch, g_state = real_ssz.deep_branch(payload, execution_branch, "state_root")
        receipts_branch, g_receipts = real_ssz.deep_branch(payload, execution_branch, "receipts_root")
        number_branch, g_number = real_ssz.deep_branch(payload, execution_branch, "block_number")
        el_state_root = bytes.fromhex(payload["state_root"][2:])
        el_receipts_root = bytes.fromhex(payload["receipts_root"][2:])
        el_block_number = int(payload["block_number"])

        anchor = Arc4Harness(compiled_anchor["TrustedRootAnchor"], sender, sk)
        anchor.create([sender, h.app_id, RING_N], extra_pages=1, boxes=[(0, b"forks8")], fund_app=15_000_000)
        anchor.ring_n = RING_N
        anchor.submit([{
            "method": "ring_init_chunk", "args": [RING_N],
            "boxes": [(0, b"h:" + i.to_bytes(8, "big")) for i in range(RING_N)],
        }])
        anchor.submit([{
            "method": "append_fork_row",
            "args": [0, g_state, g_receipts, g_number, G_BLOCK_ROOTS_BASE_PLACEHOLDER],
            "boxes": [(0, b"forks8")],
        }])

        callee_id, issuer_id = donors
        result = anchor.submit_with_donor(
            "anchor_direct",
            [h.app_id, fin_header, el_state_root, el_receipts_root, el_block_number,
             state_branch, receipts_branch, number_branch],
            donor_issuer_id=issuer_id, donor_callee_id=callee_id, n_donors=12, apps=[h.app_id],
        )
        assert result.tx_ids, "real anchor_direct submission against real live consensus data did not commit"

        att = anchor.call("attest", [el_block_number])
        assert att.ok, att.failure
        record = att.return_value
        assert record[50:82] == el_receipts_root, (
            "G1-M8: the anchored receipts_root must be byte-identical to the real "
            "execution-layer receiptsRoot for this real, currently-finalized block"
        )
        assert record[18:50] == el_state_root

        print(
            f"\nG1-M8 REAL LIVE PROOF: EL block {el_block_number}, beacon slot "
            f"{int.from_bytes(fin_header[0:8], 'little')}, anchored receipts_root = "
            f"0x{el_receipts_root.hex()}, anchor app {anchor.app_id}, M4 app {h.app_id}"
        )
