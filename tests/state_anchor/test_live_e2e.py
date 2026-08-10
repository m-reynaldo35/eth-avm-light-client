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

M11 rebasing (docs/design/011-test-harness-ci.md §6.3): `installed_committee`/
`finalized_m4` are now `tests.harness.m4`'s shared fixtures, driven through
`EthAvmClient.sync()` rather than this file's own hand-rolled bootstrap/
box-open/install_chunk copy -- the `_choose_mode_and_boxes` import and its
`box_refs + box_refs[:4]` padding workaround are gone with it (§5.3/§5.4).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from relayer.proofs.receipts_trie import build_receipts_trie_and_path  # noqa: E402,F401
from relayer.ssz import execution_payload as real_ssz  # noqa: E402
from tests.harness.deployment import puya_compile  # noqa: E402
from tests.harness.m4 import checkpoint_data, finalized_m4, installed_committee, m4_donor_pair  # noqa: E402,F401
from tests.state_anchor.harness import Arc4Harness  # noqa: E402
from tests.sync_committee import reference as ref  # noqa: E402

RING_N = 8

# Electra/Fulu `g_block_roots_base` (§3.3): design-doc-CITED value, used
# ONLY as a placeholder fork-table column DIRECT mode never reads (that
# column is exercised solely by HISTORICAL mode's block_roots fold, which
# this pass's live test does not reach -- see this file's own honest-gap
# note near `test_g1_m8_real_direct_anchor_and_attest`).
G_BLOCK_ROOTS_BASE_PLACEHOLDER = 69


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
        h.create([sender, 1, 128], extra_pages=1, fund_app=140_000_000)

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


class TestG1M8RealDirectAnchor:
    """The headline proof, run against CURRENT real data (see module
    docstring for why the design doc's own pinned example is no longer
    reachable)."""

    def test_g1_m8_real_direct_anchor_and_attest(self, finalized_m4, checkpoint_data, compiled_anchor, account, donors):
        h = finalized_m4  # real M4, real finalized state
        sender, sk = account

        fu_args = checkpoint_data["fu_now_args"]
        fu_now = checkpoint_data["fu_now"]
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
        anchor.create([sender, h.app_id, RING_N], extra_pages=1, fund_app=15_000_000)
        anchor.ring_n = RING_N
        anchor.submit([{
            "method": "ring_init_chunk", "args": [RING_N],
            "boxes": [(0, b"h:" + i.to_bytes(8, "big")) for i in range(RING_N)],
        }])
        anchor.submit([{
            "method": "append_fork_row",
            "args": [0, g_state, g_receipts, g_number, G_BLOCK_ROOTS_BASE_PLACEHOLDER],
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
