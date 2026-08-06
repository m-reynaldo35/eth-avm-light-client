"""M8's HISTORICAL-mode live suite: closes ROADMAP.md's M8 row honest gap
(2) ("HISTORICAL mode (`anchor_historical`, the `block_roots` fold) compiles
and is code-reviewable but was exercised only implicitly ... DIRECT mode
carries the entire live and structural test burden") and the human's
explicit follow-on ask for this session: a REAL Ethereum transaction
receipt verified against an M8-anchored `receipts_root` -- the combined
M7+M8 chain, not M8 tested in isolation.

Both halves use REAL, currently-live chain data end-to-end. Mirrors
`tests/state_anchor/test_live_e2e.py`'s own module docstring discipline
(fetch live, cross-check before trusting, never fall back to synthetic
without first exhausting real options) -- this file is the HISTORICAL-mode
sibling of that file's DIRECT-mode headline proof.

**Part A -- the real `block_roots` branch (previously missing).** Building
this required a full real Fulu `BeaconState` hash_tree_root, computed
field-by-field in `tests/state_anchor/real_beacon_state.py` (see that
module's own extensive docstring for the derivation discipline: three-way
field-count/gindex re-derivation, a hand-rolled-but-`remerkleable`-validated
merkleization algorithm, and the real numbers this pass measured). Real,
confirmed results from this pass (2026-08-06):

  - Real current finalized slot at build time: 14,933,056 (epoch 466,658 --
    Fulu, `FULU_FORK_EPOCH = 411,392`, has been active for tens of thousands
    of epochs; this file always re-fetches "current" at test-run time, this
    number will already be stale by the time anyone re-runs it, which is
    exactly the point -- see `historical_fixture` below).
  - Real Fulu `BeaconState` field count: **38** (Electra's 37, per
    `tests/state_anchor/test_forks.py`'s own count, plus exactly one new
    field, `proposer_lookahead`, EIP-7917 -- confirmed by fetching the real
    `specs/fulu/beacon-chain.md` source directly, AND cross-checked against
    the real fetched state's own `len(data.keys())`). 38 still rounds up to
    64 leaves (depth 6, same as Electra's 37) -> **`g_block_roots_base =
    69`, IDENTICAL to `test_live_e2e.py`'s own
    `G_BLOCK_ROOTS_BASE_PLACEHOLDER`** -- that placeholder is now SHOWN
    correct for Fulu, not merely assumed (see `real_beacon_state.py`'s
    module docstring for the full derivation).
  - The full real Fulu `BeaconState` htr -- including all ~2.33M REAL
    mainnet validators, balances, and participation entries, both real
    sync committees, the real `latest_execution_payload_header`, etc. --
    was computed in ~24s wall-clock (pure Python, no `remerkleable` View
    construction at scale; see that module's docstring for why) and matched
    the real beacon node's own reported `state_root` for that slot
    BYTE-FOR-BYTE on the first attempt that had all 38 fields' packing
    rules correct (earlier attempts during development mismatched before
    the `BeaconBlockBody`/`ExecutionPayload` full-list handling below was
    added -- see git history of this pass's own scratch work, not
    preserved in this file, only the final working version is committed
    here).
  - A REAL depth-4 `BeaconBlockBody` -> `execution_payload` branch for an
    arbitrary HISTORICAL slot (T_SLOT) turned out to need MORE than the
    task brief's own suggested `GET /eth/v2/beacon/blocks/{T_SLOT}` call
    alone: that endpoint does NOT carry a precomputed `execution_branch`
    the way a light-client `finality_update`/`bootstrap` response does (only
    DIRECT mode gets that for free). Tried, in order: (1)
    `GET /eth/v1/beacon/light_client/bootstrap/{T_SLOT's real header root}`
    -- REAL, confirmed 404 on both reachable Nimbus endpoints,
    `{"code":404,"message":"LC bootstrap unavailable"}` (bootstrap only
    serves a small set of retained checkpoints, not an arbitrary historical
    block root); (2) therefore this file computes the real depth-4 fold
    itself, from the block's own real 13 `BeaconBlockBody` fields (Electra's
    `execution_requests` addition included; Fulu does not modify
    `BeaconBlockBody`, confirmed against the real fetched spec source).
    T_SLOT's real block (2026-08-06) had every list field empty except
    `attestations` (4 real entries, real `Bitlist`-packed `aggregation_bits`
    decoded from their real SSZ delimiter-bit encoding) and
    `blob_kzg_commitments` (8 real entries) -- both handled for real, not
    assumed empty. This depth-4 branch, concatenated with the real depth-5
    `ExecutionPayload` branch (`real_beacon_state.build_full_execution_payload_tree`,
    needed because a plain block-endpoint response's `execution_payload`
    carries full `transactions`/`withdrawals` LISTS rather than the
    precomputed roots a `LightClientHeader`'s `execution` field already
    gives DIRECT mode), gave the real composed depth-9 branches
    `fold_execution_fields` needs -- independently cross-checked against
    the real header's own `body_root` before being trusted (see
    `historical_fixture` below).

**Part B -- the real on-chain `anchor_historical` call.** Mirrors
`test_live_e2e.py`'s `TestG1M8RealDirectAnchor` fixture chain
(`installed_committee`/`finalized_m4`/`submit_with_donor`) against the SAME
live checkpoint Part A's fixture is built from -- this file keeps its OWN
copies of those fixtures (not imported from `test_live_e2e.py`) for the
same reason that file gives for keeping its own copies of
`test_live_e2e_finality.py`'s: two live-chain test files must never race on
shared on-chain state.

**Part C -- the combined M7+M8 chain.** Once Part B's `anchor_historical`
commits, the anchor genuinely holds T_SLOT's block's real `receipts_root`.
This suite fetches a REAL transaction from that same block (via
`service/x402_endpoint/eth_rpc.py`/`trie_proof.py`, exactly as
`test_live_e2e.py`'s own docstring anticipated this task would), and
verifies its real inclusion proof through `AnchorReceiptProbe`
(`contracts/state_anchor/bench_app.py`) -- M7's own unmodified receipt-walk
subroutines PLUS M8's `mpt7_result_against_anchor`
(`contracts/state_anchor/handoff.py`) -- against the SAME on-chain anchor
from Part B, not a freshly-trusted root. `contracts/receipt/*.py` and
`contracts/state_anchor/anchor_app.py`/`handoff.py` are read-only imports
here, never modified (same scope boundary as the rest of M8's own pass).
"""
from __future__ import annotations

import base64
import json
import sys
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from service.x402_endpoint import eth_beacon_rpc as beacon  # noqa: E402
from service.x402_endpoint import eth_rpc  # noqa: E402
from service.x402_endpoint.trie_proof import build_receipts_trie_and_path, kec  # noqa: E402
from tests.state_anchor import real_beacon_state as rbs  # noqa: E402
from tests.state_anchor import real_ssz  # noqa: E402
from tests.state_anchor.conftest import (  # noqa: E402
    Arc4Harness,
    algod_client,
    compile_teal,
    deploy_donor_pair,
    donor_txn,
    funded_account,
    kmd_client,
    patched_repo_copy,
    puya_compile,
)
from tests.sync_committee import reference as ref  # noqa: E402
from tests.sync_committee.conftest import SyncCommitteeLiveHarness  # noqa: E402
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

RING_N = 8

# ~20h back (12s/slot), comfortably inside HISTORICAL mode's 8,192-slot
# (~27.3h) window on both edges (008 §4.2's N-WINDOW).
T_SLOT_OFFSET = 6000

# EL fold gindices (802/803/806): UNCHANGED since Deneb (test_forks.py's own
# docstring, `real_ssz.py`'s live-cross-checked constants) -- reused, not
# rederived a third time in this file.
G_STATE_ROOT = 802
G_RECEIPTS_ROOT = 803
G_BLOCK_NUMBER = 806

CACHE_DIR = REPO_ROOT / "tests" / "state_anchor" / ".cache"


# ---------------------------------------------------------------------------
# Reachability / live checkpoint / M4 fixtures -- this file's OWN copies
# (mirrors test_live_e2e.py's own reasoning: two live-chain test files must
# never race on the same on-chain state).
# ---------------------------------------------------------------------------


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
    out_dir = Path("/tmp/m8_hist_m4bench_out")
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
def account():
    algod = algod_client()
    kmd = kmd_client()
    return funded_account(algod, kmd)


@pytest.fixture(scope="module")
def installed_committee(algod_available, live_data, compiled_m4_bench, genesis_validators_root, account):
    """REAL M4: fresh `SyncCommitteeVerifier`, real live "fulu" fork row,
    real bootstrap, real 64-chunk 512-member install. This file's OWN
    instance (not shared with `test_live_e2e.py`/`test_live_e2e_finality.py`)."""
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
        chunk = boot_args.pubkey_pairs[cursor: cursor + 8]
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
    """Advances THIS file's own real M4 instance with the SAME live
    `finality_update` Part A's `historical_fixture` builds its `block_roots`
    proof from, so `fin_root`/`fin_state_root` genuinely agree between the
    on-chain M4 read and the off-chain-computed HISTORICAL fixture."""
    h = installed_committee["h"]
    issuer_id = installed_committee["issuer_id"]
    callee_id = installed_committee["callee_id"]
    fu_now_args = live_data["fu_now_args"]
    mode, box_refs = _choose_mode_and_boxes(fu_now_args.sync_committee_bits, GEN)
    # Same real, reproducible live-participation budget fragility
    # test_live_e2e.py's own docstring documents in `_choose_mode_and_boxes`
    # (there: "box read budget (6144) exceeded"; this run, on a DIFFERENT
    # day's real participation bitfield: "box read budget (18432)
    # exceeded" -- a bigger number, confirming this really is live-data-
    # dependent, not a fixed constant to hardcode a fix for). Pad up to the
    # structural 16-total-box-refs-per-2-txn-group cap (8 on `submit_update`
    # itself + 8 on the donor sibling, M4's own §16.2 measured limit) --
    # maximal available headroom within that structural cap, not a
    # hand-tuned guess.
    padded_box_refs = (box_refs + box_refs)[:16]
    result = _submit_update_group(h, issuer_id, callee_id, fu_now_args, fu_now_args.signature, mode, padded_box_refs)
    assert result.tx_ids, "real submit_update did not commit"
    return h


@pytest.fixture(scope="module")
def compiled_anchor(algod_available):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    return puya_compile(REPO_ROOT / "contracts" / "state_anchor" / "anchor_app.py")


@pytest.fixture(scope="module")
def donors(algod_available, account):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    algod = algod_client()
    sender, sk = account
    return deploy_donor_pair(algod, sender, sk)


# ---------------------------------------------------------------------------
# Part A: the real block_roots + EL branches for a real, current T_SLOT.
# ---------------------------------------------------------------------------


def _fetch_full_state_cached(slot: int) -> dict:
    """Downloads (or reuses a disk cache keyed by slot -- see .gitignore)
    the real full BeaconState JSON at `slot`. Real size observed this pass:
    ~956MB (bigger than the ~150-300MB estimate the task brief gave --
    real mainnet state at ~2.33M validators is simply that big now).
    Cached to disk, never held as a second in-memory copy beyond what
    `json.load` itself needs (confirmed tractable on this machine: ~5s to
    parse, ~24s to merkleize -- see `real_beacon_state.py`)."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / f"state_{slot}.json"
    if not path.exists():
        last = None
        for base in beacon.BEACON_APIS:
            url = base.rstrip("/") + f"/eth/v2/debug/beacon/states/{slot}"
            try:
                req = urllib.request.Request(url, headers=beacon.HEADERS)
                with urllib.request.urlopen(req, timeout=600) as resp:
                    data = resp.read()
                path.write_bytes(data)
                break
            except Exception as e:  # noqa: BLE001
                last = e
                continue
        else:
            raise RuntimeError(f"all beacon-API endpoints failed fetching full state at slot {slot}: {last}")
    with open(path) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def historical_fixture(beacon_available, live_data):
    """Part A, step by step (module docstring): fetch the real full state at
    the SAME finalized slot `finalized_m4` advances M4 to, independently
    re-derive its real top-level state root and cross-check against the
    real header's own `state_root` BEFORE trusting anything else (§3.4's own
    "derive, don't copy" discipline, applied here to a brand-new fork's
    field count), pick a real T_SLOT ~20h back, confirm it against
    `block_roots` directly, then build the real EL branches for T_SLOT's own
    block."""
    if not beacon_available:
        pytest.skip("no reachable beacon-API endpoint in the pool")
    fu_args = live_data["fu_now_args"]
    fin_slot = int.from_bytes(fu_args.finalized_header[0:8], "little")
    live_fin_state_root = fu_args.finalized_header[48:80]
    fin_root = ref.hash_tree_root_beacon_block_header(fu_args.finalized_header)
    t_slot = fin_slot - T_SLOT_OFFSET

    resp = _fetch_full_state_cached(fin_slot)
    data = resp["data"]
    assert int(data["slot"]) == fin_slot, (
        "fetched full-state slot must match the header we're anchoring against "
        "(guards against the numeric-slot-vs-'finalized'-keyword race the task brief names)"
    )

    state_root, field_roots, block_roots_raw = rbs.build_beacon_state_tree(data, verbose=False)
    assert state_root == live_fin_state_root, (
        "real, independently-computed Fulu BeaconState root must equal the real "
        "finalized header's own state_root -- if this fails, there is a real bug "
        "in real_beacon_state.py's field packing/order, not a data problem"
    )

    branch19 = rbs.block_roots_fold_branch(field_roots, block_roots_raw, t_slot)

    hresp = beacon._get_json(f"/eth/v1/beacon/headers/{t_slot}")
    hm = hresp["data"]["header"]["message"]
    t_header_bytes = (
        ref.le64(int(hm["slot"])) + ref.le64(int(hm["proposer_index"]))
        + bytes.fromhex(hm["parent_root"][2:]) + bytes.fromhex(hm["state_root"][2:])
        + bytes.fromhex(hm["body_root"][2:])
    )
    t_root = ref.hash_tree_root_beacon_block_header(t_header_bytes)
    assert "0x" + t_root.hex() == hresp["data"]["root"], "computed T_SLOT header root must match the API's own reported root"
    assert block_roots_raw[t_slot % 8192] == t_root, (
        "block_roots[t_slot % 8192] in the fetched finalized state must equal "
        "T_SLOT's own real, independently-fetched header root (step 6 of the task brief)"
    )

    tblk = beacon._get_json(f"/eth/v2/beacon/blocks/{t_slot}")
    tbody = tblk["data"]["message"]["body"]
    tpayload = tbody["execution_payload"]
    payload_root, branch_for = rbs.build_full_execution_payload_tree(tpayload)
    body_root, branch4 = rbs.build_beacon_block_body_tree(tbody, payload_root)
    assert body_root == t_header_bytes[80:112], "real BeaconBlockBody htr must equal T_SLOT header's own body_root slice"

    el_state_root = bytes.fromhex(tpayload["state_root"][2:])
    el_receipts_root = bytes.fromhex(tpayload["receipts_root"][2:])
    el_block_number = int(tpayload["block_number"])

    state_branch = branch_for(real_ssz.FIELD_INDEX["state_root"]) + branch4
    receipts_branch = branch_for(real_ssz.FIELD_INDEX["receipts_root"]) + branch4
    number_branch = branch_for(real_ssz.FIELD_INDEX["block_number"]) + branch4

    for leaf, branch, gindex in (
        (el_state_root, state_branch, G_STATE_ROOT),
        (el_receipts_root, receipts_branch, G_RECEIPTS_ROOT),
        (el_block_number.to_bytes(8, "little") + b"\x00" * 24, number_branch, G_BLOCK_NUMBER),
    ):
        assert real_ssz.compute_branch_root(leaf, branch, gindex) == body_root, "composed EL branch must fold to body_root"

    return {
        "fin_slot": fin_slot, "t_slot": t_slot,
        "fin_header": fu_args.finalized_header, "fin_root": fin_root, "fin_state_root": state_root,
        "target_header": t_header_bytes, "t_root": t_root,
        "block_roots_branch": branch19,
        "g_block_roots_base_fulu": rbs.G_BLOCK_ROOTS_BASE_FULU,
        "el_state_root": el_state_root, "el_receipts_root": el_receipts_root, "el_block_number": el_block_number,
        "state_branch": state_branch, "receipts_branch": receipts_branch, "number_branch": number_branch,
    }


# ---------------------------------------------------------------------------
# Part B: the real, non-simulated anchor_historical submission.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def real_historical_anchor(finalized_m4, historical_fixture, compiled_anchor, account, donors):
    h = finalized_m4
    fx = historical_fixture
    sender, sk = account

    anchor = Arc4Harness(compiled_anchor["TrustedRootAnchor"], sender, sk)
    anchor.create([sender, h.app_id, RING_N], extra_pages=1, boxes=[(0, b"forks8")], fund_app=15_000_000)
    anchor.ring_n = RING_N
    anchor.submit([{
        "method": "ring_init_chunk", "args": [RING_N],
        "boxes": [(0, b"h:" + i.to_bytes(8, "big")) for i in range(RING_N)],
    }])
    # Real fork row: g_state_root/g_receipts_root/g_block_number are the
    # already-live-proven-unchanged-since-Deneb values (test_live_e2e.py's
    # own G1-M8); g_block_roots_base is real_beacon_state.py's independently
    # derived, shown-not-assumed Fulu value (module docstring).
    anchor.submit([{
        "method": "append_fork_row",
        "args": [0, G_STATE_ROOT, G_RECEIPTS_ROOT, G_BLOCK_NUMBER, fx["g_block_roots_base_fulu"]],
        "boxes": [(0, b"forks8")],
    }])

    callee_id, issuer_id = donors

    # Real measured budget (this project's own locked decision: "no
    # cost/budget claim ships without a real simulate response behind it"),
    # via `simulate` with a generous extra budget, BEFORE the real
    # non-simulated submission below -- closes ROADMAP M8 gap (4)'s
    # "anchor_historical's real budget ... not separately measured" for
    # HISTORICAL mode specifically (DIRECT mode's own number was already
    # measured by `test_live_e2e.py`).
    sim_res = anchor.call(
        "anchor_historical",
        [h.app_id, fx["fin_header"], fx["target_header"], fx["block_roots_branch"],
         fx["el_state_root"], fx["el_receipts_root"], fx["el_block_number"],
         fx["state_branch"], fx["receipts_branch"], fx["number_branch"]],
        apps=[h.app_id],  # call_group's own extra_budget default (320,000) is already generous
    )
    assert sim_res.ok, f"simulate (generous budget) failed -- a real logic bug, not a budget one: {sim_res.failure}"
    print(f"\nG2-M8 real anchor_historical app-budget-consumed (simulate, generous budget): {sim_res.app_budget_consumed}")

    result = anchor.submit_with_donor(
        "anchor_historical",
        [h.app_id, fx["fin_header"], fx["target_header"], fx["block_roots_branch"],
         fx["el_state_root"], fx["el_receipts_root"], fx["el_block_number"],
         fx["state_branch"], fx["receipts_branch"], fx["number_branch"]],
        donor_issuer_id=issuer_id, donor_callee_id=callee_id, n_donors=20, apps=[h.app_id],
    )
    assert result.tx_ids, "real anchor_historical submission against real live consensus data did not commit"

    return {"anchor": anchor, "fx": fx, "m4": h}


class TestG2M8RealHistoricalAnchor:
    """Closes ROADMAP M8 gap (2): `anchor_historical` exercised for the
    first time, live, non-simulated, end-to-end, against a real
    `block_roots` branch built from a real Fulu `BeaconState`."""

    def test_anchor_historical_real_submission_and_attest(self, real_historical_anchor):
        anchor = real_historical_anchor["anchor"]
        fx = real_historical_anchor["fx"]

        att = anchor.call("attest", [fx["el_block_number"]])
        assert att.ok, att.failure
        record = att.return_value
        assert record is not None and len(record) == 154
        assert record[18:50] == fx["el_state_root"], "record.state_root must be byte-identical to the real EL state_root"
        assert record[50:82] == fx["el_receipts_root"], "record.receipts_root must be byte-identical to the real EL receipts_root"
        beacon_slot = int.from_bytes(record[10:18], "big")
        assert beacon_slot == fx["t_slot"], "record must carry T_SLOT (not fin_slot) as beacon_slot, per §6.1"
        flags = record[1]
        assert flags & 0b10 != 0, "FLAG_HISTORICAL must be set"

        print(
            f"\nG2-M8 REAL HISTORICAL PROOF: fin_slot={fx['fin_slot']} t_slot={fx['t_slot']} "
            f"EL block {fx['el_block_number']}, anchored receipts_root=0x{fx['el_receipts_root'].hex()}, "
            f"anchor app {anchor.app_id}, M4 app {real_historical_anchor['m4'].app_id}"
        )


# ---------------------------------------------------------------------------
# Part C: the combined M7+M8 chain -- a real receipt verified against the
# SAME on-chain M8 anchor from Part B.
# ---------------------------------------------------------------------------


def _deploy_bare_contract(algod, sender, sk, compiled_entry) -> int:
    from algosdk import transaction

    approval = compile_teal(algod, compiled_entry["approval"])
    clear = compile_teal(algod, compiled_entry["clear"])
    sp = algod.suggested_params()
    txn = transaction.ApplicationCreateTxn(
        sender=sender, sp=sp, on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval, clear_program=clear,
        global_schema=transaction.StateSchema(0, 0), local_schema=transaction.StateSchema(0, 0),
        extra_pages=1,
    )
    stxn = txn.sign(sk)
    txid = algod.send_transaction(stxn)
    confirmed = transaction.wait_for_confirmation(algod, txid, 4)
    return confirmed["application-index"]


class TestG3CombinedM7M8ReceiptProof:
    """The human's explicit follow-on ask: a REAL Ethereum transaction
    receipt, verified against an M8-anchored `receipts_root` -- the
    combined M7+M8 chain, not M8 tested in isolation. `AnchorReceiptProbe`
    (`contracts/state_anchor/bench_app.py`) is compiled fresh with
    `handoff.ANCHOR_APP_ID` patched to Part B's REAL, just-deployed
    `TrustedRootAnchor` app id (TP-M8-4's own compile-time-binding
    discipline, `conftest.patched_repo_copy`)."""

    def test_real_receipt_verified_against_m8_anchor(self, real_historical_anchor, donors, account):
        from algosdk import transaction
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
            TransactionWithSigner,
        )
        from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup

        anchor = real_historical_anchor["anchor"]
        fx = real_historical_anchor["fx"]
        algod = anchor.algod
        sender, sk = account
        callee_id, issuer_id = donors

        el_block_number = fx["el_block_number"]
        receipts = eth_rpc.get_block_receipts(el_block_number)
        header = eth_rpc.get_block_header(el_block_number)
        assert header["receiptsRoot"] == "0x" + fx["el_receipts_root"].hex(), (
            "the real EL block's own receiptsRoot must match what Part B anchored"
        )

        # Pick a real transaction from THIS real, currently-anchored block
        # whose trie proof nodes all fit under the 2048B/app-arg cap and
        # has 1-3 real logs -- AnchorReceiptProbe (unlike Mpt7ReceiptApp's
        # own T2 box-staging path) only implements the MODE_INIT/MODE_NEXT
        # raw-app-arg path (§9.2's own scope), so a receipt needing box-
        # staging is out of scope for this probe by design, not oversight.
        # Which real tx_index qualifies varies block to block (this fixture
        # re-anchors a NEW real EL block every run, since `historical_fixture`
        # always follows the CURRENT live finalized checkpoint) -- so this
        # is a real, dynamic selection over the block's own real receipts,
        # not a hardcoded index that happened to work once.
        LOG_INDEX = 0
        TX_INDEX = None
        nodes = None
        for r in receipts:
            idx = int(r.get("transactionIndex", "0x0"), 16)
            n_logs = len(r.get("logs", []))
            if not (1 <= n_logs <= 3):
                continue
            try:
                root_hash, candidate_nodes = build_receipts_trie_and_path(receipts, idx)
            except KeyError:
                continue
            if root_hash != fx["el_receipts_root"]:
                continue
            if not (1 <= len(candidate_nodes) <= 12) or not all(len(n) <= 2048 for n in candidate_nodes):
                continue
            TX_INDEX, nodes = idx, candidate_nodes
            break
        assert TX_INDEX is not None, (
            f"no transaction in real EL block {el_block_number} has a small-enough "
            "(<=2048B/node, <=12 nodes) trie proof with 1-3 logs -- would need the "
            "box-staging path this probe intentionally does not implement (§9.2 scope)"
        )

        real_receipt = next(r for r in receipts if int(r.get("transactionIndex", "0x0"), 16) == TX_INDEX)
        real_log = real_receipt["logs"][LOG_INDEX]
        expected_data_hash = kec(bytes.fromhex(real_log["data"][2:]))
        expected_address = bytes.fromhex(real_log["address"][2:])
        expected_n_topics = len(real_log["topics"])
        expected_status = int(real_receipt.get("status", "0x1"), 16)
        expected_tx_type = int(real_receipt.get("type", "0x0"), 16)

        # Compile from INSIDE the patched copy (not the original repo path)
        # -- matches `tests/state_anchor/test_core.py`'s own already-proven
        # `TestForgedAppId`/`test_compiled_teal_embeds_constant_immediate`
        # invocation exactly: `puyapy` resolves `contracts.state_anchor.handoff`
        # via ordinary Python import rules, so the source file compiled must
        # itself live under `patched_root` for the patched `ANCHOR_APP_ID` to
        # actually be the one that gets imported (compiling the ORIGINAL repo
        # path here would silently compile against the placeholder `0` again).
        patched_root = patched_repo_copy(anchor.app_id)
        probe_src = patched_root / "contracts" / "state_anchor" / "bench_app.py"
        compiled = puya_compile(probe_src, extra_pythonpath=patched_root)
        probe_id = _deploy_bare_contract(algod, sender, sk, compiled["AnchorReceiptProbe"])

        fixed_init = fx["el_receipts_root"] + TX_INDEX.to_bytes(8, "big") + LOG_INDEX.to_bytes(2, "big")
        # anchor_gi=1 (attest's own group index, fixed by this group's layout below)
        fixed_check = (1).to_bytes(8, "big") + el_block_number.to_bytes(8, "big") + TX_INDEX.to_bytes(8, "big") + LOG_INDEX.to_bytes(2, "big")

        def build_group(n_donors: int):
            signer = AccountTransactionSigner(sk)
            atc = AtomicTransactionComposer()
            atc.add_transaction(donor_txn(algod, sender, sk, issuer_id, callee_id, n_donors))
            attest_method = Method.undictify(anchor.methods["attest"])
            sp1 = algod.suggested_params()
            sp1.flat_fee = True
            sp1.fee = 1000
            atc.add_method_call(
                app_id=anchor.app_id, method=attest_method, sender=sender, sp=sp1, signer=signer,
                method_args=[el_block_number],
                boxes=anchor._auto_boxes_for("attest", [el_block_number]),
            )
            sp2 = algod.suggested_params()
            sp2.flat_fee = True
            sp2.fee = 1000
            init_txn = transaction.ApplicationCallTxn(
                sender=sender, sp=sp2, index=probe_id, on_complete=transaction.OnComplete.NoOpOC,
                app_args=[b"RCP1", bytes([0]), bytes([0]), fixed_init] + nodes,
            )
            atc.add_transaction(TransactionWithSigner(init_txn, signer))
            sp3 = algod.suggested_params()
            sp3.flat_fee = True
            sp3.fee = 1000
            check_txn = transaction.ApplicationCallTxn(
                sender=sender, sp=sp3, index=probe_id, on_complete=transaction.OnComplete.NoOpOC,
                app_args=[b"RCP1", bytes([5]), (2).to_bytes(8, "big"), fixed_check],
            )
            atc.add_transaction(TransactionWithSigner(check_txn, signer))
            return atc

        # Measure real cost via simulate first (this project's own locked
        # decision: "no cost/budget claim ships without a real simulate
        # response behind it"), THEN submit for real with an adequately
        # sized donor pool -- mirrors M4/M5/M8's own established two-phase
        # live-test pattern.
        probe_atc = build_group(n_donors=1)
        probe_group = probe_atc.build_group()
        probe_stxns = [t.txn.sign(sk) for t in probe_group]
        sreq = SimulateRequest(
            txn_groups=[SimulateRequestTransactionGroup(txns=probe_stxns)],
            extra_opcode_budget=320_000, allow_unnamed_resources=True,
        )
        sim_resp = algod.simulate_transactions(sreq)
        consumed = sim_resp["txn-groups"][0].get("app-budget-consumed", 0)
        failure = sim_resp["txn-groups"][0].get("failure-message", "")
        assert not failure, f"simulate (generous budget) failed -- a real logic bug, not a budget one: {failure}"
        print(f"\nG3 combined-chain real app-budget-consumed (simulate, generous budget): {consumed}")

        # Real per-donor-call yield ~682 (004 §2.4); size with real margin.
        n_donors = max(4, -(-((consumed - 2800) // 682)) + 4)

        real_atc = build_group(n_donors=n_donors)
        result = real_atc.execute(algod, 4)
        assert result.tx_ids and len(result.tx_ids) == 4, "real combined M7+M8 group did not commit"

        check_txid = result.tx_ids[3]
        info = algod.pending_transaction_info(check_txid)
        logs = [base64.b64decode(x) for x in info.get("logs", [])]
        assert logs and logs[-1][:4] == bytes.fromhex("151f7c75"), "MODE_AGAINST_ANCHOR must log a valid ARC4 envelope"
        out = logs[-1][4:]
        assert len(out) == 220
        rstatus = int.from_bytes(out[0:8], "big")
        address = out[8:28]
        n_topics = int.from_bytes(out[28:36], "big")
        data_hash = out[164:196]
        status = int.from_bytes(out[204:212], "big")
        tx_type = int.from_bytes(out[212:220], "big")

        assert rstatus == 1, "expected R_INCLUDED for a real, present receipt/log"
        assert address == expected_address, "recovered log address must match the real receipt's log"
        assert n_topics == expected_n_topics
        assert data_hash == expected_data_hash, "recovered data_hash must equal real keccak256(log.data)"
        assert status == expected_status
        assert tx_type == expected_tx_type

        print(
            f"\nG3-M8 COMBINED M7+M8 REAL PROOF: EL block {el_block_number} tx_index {TX_INDEX} "
            f"log_index {LOG_INDEX}: verified against the SAME on-chain M8 anchor from Part B "
            f"(anchor app {anchor.app_id}), address=0x{address.hex()}, status={status}, tx_type={tx_type}, "
            f"probe app {probe_id}"
        )
