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
module's own extensive docstring for the derivation discipline). Real,
confirmed results from this pass (2026-08-06): real Fulu `BeaconState`
field count 38 (Electra's 37 + `proposer_lookahead`, EIP-7917) still rounds
up to 64 leaves (depth 6) -> `g_block_roots_base = 69`, identical to
`test_live_e2e.py`'s own placeholder -- shown correct for Fulu here, not
merely assumed.

**Part B -- the real on-chain `anchor_historical` call.** M11 rebasing
(docs/design/011-test-harness-ci.md §6.3): `installed_committee`/
`finalized_m4` are now `tests.harness.m4`'s shared fixtures, driven through
`EthAvmClient.sync()` -- this file no longer keeps its own hand-rolled copy
of the bootstrap/box-open/install_chunk sequence, and the
`_choose_mode_and_boxes` import plus its `(box_refs + box_refs)[:16]`
padding workaround are gone with it (§5.3/§5.4).

**Part C -- the combined M7+M8 chain.** Once Part B's `anchor_historical`
commits, the anchor genuinely holds T_SLOT's block's real `receipts_root`.
This suite fetches a REAL transaction from that same block and verifies its
real inclusion proof through `AnchorReceiptProbe`
(`contracts/state_anchor/bench_app.py`) against the SAME on-chain anchor
from Part B, not a freshly-trusted root.
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

from relayer.sources import beacon  # noqa: E402
from relayer.sources import eth_rpc  # noqa: E402
from relayer.proofs.receipts_trie import build_receipts_trie_and_path, kec  # noqa: E402
from relayer.ssz import beacon_state as rbs_state  # noqa: E402
from relayer.ssz import block_body as rbs_body  # noqa: E402
from relayer.ssz import execution_payload as real_ssz  # noqa: E402
from tests.harness.deployment import compile_teal, donor_txn, patched_repo_copy, puya_compile  # noqa: E402
from tests.harness.m4 import checkpoint_data, finalized_m4, installed_committee, m4_donor_pair  # noqa: E402,F401
from tests.state_anchor.harness import Arc4Harness  # noqa: E402
from tests.sync_committee import reference as ref  # noqa: E402

# 011 §3.2/§8.2: every test in this file transitively depends on
# `historical_fixture`, which downloads a real, ~1 GB full `BeaconState`
# (measured 1,003,300,280 B) via `_fetch_full_state_cached` -- the
# `live_heavy` tier (weekly cron / on-demand, not nightly): running it
# nightly would be both an OOM risk on a hosted runner and an unreasonable
# draw on the volunteer public beacon endpoint's bandwidth.
pytestmark = pytest.mark.live_heavy

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


@pytest.fixture(scope="module")
def compiled_anchor(algod_available):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    return puya_compile(REPO_ROOT / "contracts" / "state_anchor" / "anchor_app.py")


# ---------------------------------------------------------------------------
# Part A: the real block_roots + EL branches for a real, current T_SLOT.
# ---------------------------------------------------------------------------


def _fetch_full_state_cached(slot: int) -> dict:
    """Downloads (or reuses a disk cache keyed by slot -- see .gitignore)
    the real full BeaconState JSON at `slot`. Real size observed this pass:
    ~956MB. Cached to disk, never held as a second in-memory copy beyond
    what `json.load` itself needs (~5s to parse, ~24s to merkleize -- see
    `real_beacon_state.py`)."""
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
def historical_fixture(beacon_available, checkpoint_data):
    """Part A, step by step (module docstring): fetch the real full state at
    the SAME finalized slot `finalized_m4` advances M4 to, independently
    re-derive its real top-level state root and cross-check against the
    real header's own `state_root` BEFORE trusting anything else, pick a
    real T_SLOT ~20h back, confirm it against `block_roots` directly, then
    build the real EL branches for T_SLOT's own block."""
    if not beacon_available:
        pytest.skip("no reachable beacon-API endpoint in the pool")
    fu_args = checkpoint_data["fu_now_args"]
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

    state_root, field_roots, block_roots_raw = rbs_state.build_beacon_state_tree(data, verbose=False)
    assert state_root == live_fin_state_root, (
        "real, independently-computed Fulu BeaconState root must equal the real "
        "finalized header's own state_root -- if this fails, there is a real bug "
        "in real_beacon_state.py's field packing/order, not a data problem"
    )

    branch19 = rbs_state.block_roots_fold_branch(field_roots, block_roots_raw, t_slot)

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
    payload_root, branch_for = rbs_body.build_full_execution_payload_tree(tpayload)
    body_root, branch4 = rbs_body.build_beacon_block_body_tree(tbody, payload_root)
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
        "g_block_roots_base_fulu": rbs_state.G_BLOCK_ROOTS_BASE_FULU,
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
    discipline, `tests.harness.deployment.patched_repo_copy`)."""

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
