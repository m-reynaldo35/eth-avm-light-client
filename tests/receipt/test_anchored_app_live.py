"""tests/receipt/test_anchored_app_live.py -- 014's live verification for
`Mpt7AnchoredReceiptApp` (docs/design/014-t2-against-anchor.md SS10's A-4..
A-13-style checks), against a synthetic-but-real M8 anchor (`contracts/
state_anchor/bench_app.py::M4Probe` + a real `TrustedRootAnchor`,
`tests/state_anchor/synth.py`'s fixture generator -- the same "real sha256
folds, arbitrary leaf values" discipline that module's own docstring
documents) and a synthetic-but-real receipts trie (real RLP + real keccak,
`relayer/proofs/receipts_trie.py` unmodified), run against real dev-mode
algod.

This is NOT A-14 (a real mainnet receipt against a real M8 anchor) -- that
needs a real, currently-anchored mainnet EL block whose receipts trie
happens to contain a T2-tier leaf, which this implementation pass does not
have on hand (014 SS10 itself flags A-14 as the one gate that stayed open
after the design pass too, still open here). Everything below IS real: real
dev-mode algod, real transactions, real box mechanics, real on-chain
rejections -- only the receipt content and the M8 anchor's own EL/beacon
data are synthetic.
"""
from __future__ import annotations

import base64

import pytest
from algosdk import logic, mnemonic, transaction

from tests.harness.chain import algod_client
from tests.harness.deployment import deploy_donor_pair, puya_compile
from tests.state_anchor import synth
from tests.state_anchor.harness import Arc4Harness

RING_N = 8
FIN_SLOT = 5_000_032
EL_BLOCK_NUMBER = 19_000_000

# T2-range leaf, measured this pass: DATA_LEN=1800 -> leaf 2,171 B (inside
# the (1943, 4096] T2 window, 007 SS3.1), branch node 83 B. Not the 014
# design pass's own worst case (4,094 B, SS3.2) -- large enough to force 2
# MODE_STAGE_WRITE calls (1,900 B chunks), small enough to keep this
# suite's wall-clock reasonable.
DATA_LEN = 1800


def _make_receipts(data_len: int) -> list[dict]:
    """Two synthetic-but-real receipts (real address/topic/data bytes, fed
    through `relayer/proofs/receipts_trie.py`'s real RLP+keccak, unmodified):
    tx 0 small, tx 1's log `data` padded to `data_len` so ITS leaf lands in
    T2 range once RLP-encoded. `rlp(0)` and `rlp(1)` diverge at the first
    nibble, so the real trie has exactly one small branch node above the
    leaf -- never zero, matching 014 SS4.4's own group layout, which always
    has a MODE_INIT branch-node call before staging (`plan_receipt_calls_t2`
    refuses a zero-branch-node T2 case outright)."""
    logs0 = [{"address": "0x" + "11" * 20, "topics": ["0x" + "22" * 32], "data": "0x" + "33" * 4}]
    r0 = {"transactionIndex": "0x0", "status": "0x1", "cumulativeGasUsed": "0x5208",
          "logsBloom": "0x" + "00" * 256, "type": "0x0", "logs": logs0}
    logs1 = [{"address": "0x" + "44" * 20, "topics": ["0x" + "55" * 32, "0x" + "66" * 32],
              "data": "0x" + "77" * data_len}]
    r1 = {"transactionIndex": "0x1", "status": "0x1", "cumulativeGasUsed": "0x9c40",
          "logsBloom": "0x" + "00" * 256, "type": "0x0", "logs": logs1}
    return [r0, r1]


@pytest.fixture(scope="module")
def probe_env(account):
    """Builds ONE real, shared environment for this module: a synthetic M4
    stand-in + a real `TrustedRootAnchor` anchoring a real synthetic
    receipts trie whose tx-1 leaf is T2-tier, plus a real, permanently
    deployed `Mpt7AnchoredReceiptApp` bound to that anchor -- via
    `deploy.plans.m7_anchored`, exercising the actual deploy-tooling path
    (014 SS9), not a hand-rolled substitute."""
    from deploy.config import ContractTarget, DeployTarget, NetworkConfig
    from deploy.manifest import Manifest
    from deploy.plans import m7_anchored
    from relayer.proofs.receipts_trie import build_receipts_trie_and_path

    sender, sk = account
    algod = algod_client()

    bench_compiled = puya_compile("contracts/state_anchor/bench_app.py")
    m4probe = Arc4Harness(bench_compiled["M4Probe"], sender, sk)
    m4probe.create([])

    def _set_m4(fin_slot, fin_root, fin_state_root):
        m4probe.submit([{"method": "set_finalized", "args": [fin_slot, fin_root, fin_state_root]}])

    _set_m4(FIN_SLOT, synth.random32(), synth.random32())

    anchor_compiled = puya_compile("contracts/state_anchor/anchor_app.py")
    anchor = Arc4Harness(anchor_compiled["TrustedRootAnchor"], sender, sk)
    anchor.create([sender, m4probe.app_id, RING_N], extra_pages=1, fund_app=5_000_000)
    anchor.ring_n = RING_N
    anchor.submit([{
        "method": "ring_init_chunk", "args": [RING_N],
        "boxes": [(0, b"h:" + i.to_bytes(8, "big")) for i in range(RING_N)],
    }])
    anchor.submit([{
        "method": "append_fork_row",
        "args": [0, synth.G_STATE_ROOT, synth.G_RECEIPTS_ROOT, synth.G_BLOCK_NUMBER, synth.G_BLOCK_ROOTS_BASE],
    }])

    callee_id, issuer_id = deploy_donor_pair(algod, sender, sk)

    receipts = _make_receipts(DATA_LEN)
    receipts_root, nodes = build_receipts_trie_and_path(receipts, 1)
    assert len(nodes) == 2, "expected exactly one branch node above the T2 leaf"
    assert 1943 < len(nodes[-1]) <= 4096, f"leaf {len(nodes[-1])} B drifted out of T2 range"

    el_state_root = synth.random32()
    body_root, sb, rb, nb = synth.build_execution_tree(el_state_root, receipts_root, EL_BLOCK_NUMBER)
    parent_root = synth.random32()
    fin_header, fin_root = synth.make_header(FIN_SLOT, 0, parent_root, synth.random32(), body_root)
    fin_state_root = fin_header[48:80]
    _set_m4(FIN_SLOT, fin_root, fin_state_root)

    direct_args = [m4probe.app_id, fin_header, el_state_root, receipts_root, EL_BLOCK_NUMBER, sb, rb, nb]
    anchor.submit_with_donor(
        "anchor_direct", direct_args, donor_issuer_id=issuer_id, donor_callee_id=callee_id,
        n_donors=8, apps=[m4probe.app_id],
    )
    att = anchor.call("attest", [EL_BLOCK_NUMBER])
    assert att.ok, att.failure
    assert att.return_value[50:82] == receipts_root, "attest() must echo back the SAME receipts_root we anchored"

    sp = algod.suggested_params()
    gh = sp.gh if isinstance(sp.gh, str) else base64.b64encode(sp.gh).decode()
    manifest = Manifest(genesis_id="test-probe-014", genesis_hash=gh)
    manifest.set_app("m8", app_id=anchor.app_id, approval_sha256="unused-by-this-plan")
    target = DeployTarget(
        network=NetworkConfig("http://localhost:4051", "a" * 64, "test-probe-014", gh),
        governance=sender,
        contracts={"m7_anchored": ContractTarget(deploy=True, t2_float=True)},
    )
    anchored_app_id = m7_anchored.apply(algod, sender, sk, target, manifest)

    return {
        "sender": sender, "sk": sk, "algod": algod,
        "m4probe_id": m4probe.app_id, "anchor_id": anchor.app_id,
        "issuer_id": issuer_id, "callee_id": callee_id,
        "anchored_app_id": anchored_app_id, "manifest_entry": manifest.apps["m7_anchored"],
        "receipts": receipts, "receipts_root": receipts_root, "nodes": nodes,
    }


class TestT2AgainstAnchorLive:
    """G2-014/G3-014/G6-014/G7-014, real: the whole `prove_receipt(
    against_anchor=True)` T2 path, driven exactly as production code would
    drive it (`EthAvmClient`, a real `RelayerConfig`, with ONLY the EL data
    source monkeypatched to serve the synthetic block -- the Algorand side
    is never faked)."""

    def test_t2_against_anchor_real_group(self, probe_env, monkeypatch):
        import relayer.client as client_mod
        from relayer.client import EthAvmClient
        from relayer.config import RelayerConfig

        env = probe_env
        header = {"receiptsRoot": "0x" + env["receipts_root"].hex(), "number": hex(EL_BLOCK_NUMBER)}
        monkeypatch.setattr(client_mod, "get_block_header", lambda block: header)
        monkeypatch.setattr(client_mod, "get_block_receipts", lambda block: env["receipts"])

        cfg = RelayerConfig(
            m4_app_id=env["m4probe_id"], m8_app_id=env["anchor_id"],
            m7_anchored_app_id=env["anchored_app_id"],
            donor_issuer_id=env["issuer_id"], donor_callee_id=env["callee_id"],
            signer_mnemonic=mnemonic.from_private_key(env["sk"]),
        )
        client = EthAvmClient(cfg)

        app_addr = logic.get_application_address(env["anchored_app_id"])
        balance_before = env["algod"].account_info(app_addr)["amount"]

        result = client.prove_receipt(EL_BLOCK_NUMBER, 1, 0, against_anchor=True)

        assert result.rstatus_name == "R_INCLUDED"
        assert result.fields["address"] == "44" * 20
        assert result.fields["n_topics"] == 2
        assert result.fields["data_len"] == DATA_LEN
        # G3-014: one atomic group -- donor + payment + attest + MODE_INIT
        # + STAGE_OPEN + 2x STAGE_WRITE (2,171 B leaf / 1,900 B chunks) +
        # STAGE_WALK + MODE_AGAINST_ANCHOR = 9 real transactions.
        assert len(result.tx_ids) == 9
        assert result.fields["n_transactions"] == 9
        # G7-014: measured_consumed persisted into ReceiptResult.fields,
        # not discarded (014 SS6's own real finding about the T1 path).
        assert result.fields["measured_consumed"] > 0

        balance_after = env["algod"].account_info(app_addr)["amount"]
        # G6-014: the t2_float funded at deploy time (deploy.plans.
        # m7_anchored.apply's own top_up, mirroring m7.py's) already covers
        # this leaf's box MBR -- the conditional PaymentTxn sent exactly 0.
        assert balance_after == balance_before, "the deploy-time float should have made this call's payment 0"


class TestOnCompletionGuard:
    """G1-014/A-10: the guard 014 SS5.1 requires on the promoted contract,
    proven live against the REAL deployed app -- not merely present in
    source."""

    def test_update_and_delete_are_rejected(self, probe_env):
        env = probe_env
        algod = env["algod"]
        # version 11, matching Mpt7AnchoredReceiptApp's own compiled
        # version (puyapy 5.9.0's current default for a bare `Contract`) --
        # otherwise algod's OWN version-downgrade guard rejects the call
        # first and this test would pass for the wrong reason.
        always_approve = "#pragma version 11\nint 1\nreturn\n"
        program = base64.b64decode(algod.compile(always_approve)["result"])

        sp = algod.suggested_params()
        sp.flat_fee = True
        sp.fee = 1000
        upd = transaction.ApplicationUpdateTxn(env["sender"], sp, env["anchored_app_id"], program, program)
        with pytest.raises(Exception, match="OnCompletion"):
            algod.send_transaction(upd.sign(env["sk"]))

        sp2 = algod.suggested_params()
        sp2.flat_fee = True
        sp2.fee = 1000
        delt = transaction.ApplicationDeleteTxn(env["sender"], sp2, env["anchored_app_id"])
        with pytest.raises(Exception, match="OnCompletion"):
            algod.send_transaction(delt.sign(env["sk"]))


class TestBoxSquattingMitigation:
    """SS5.2/A-11: `mpt7_stage_open` deletes a pre-existing box (any size)
    before creating, so a name squatted at the wrong size does not break a
    later, honest re-open at the real size -- proven against the REAL
    deployed app, not a throwaway."""

    def test_stage_open_survives_a_squatted_box(self, probe_env):
        env = probe_env
        algod = env["algod"]
        app_id = env["anchored_app_id"]
        name = b"SQUAT001"

        sp = algod.suggested_params()
        sp.flat_fee = True
        sp.fee = 1000
        squat = transaction.ApplicationCallTxn(
            sender=env["sender"], sp=sp, index=app_id, on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"RCP1", bytes([2]), bytes([0]), name + (2000).to_bytes(2, "big")],
            boxes=[transaction.BoxReference(0, name)],
        )
        txid = algod.send_transaction(squat.sign(env["sk"]))
        transaction.wait_for_confirmation(algod, txid, 4)
        squatted = algod.application_box_by_name(app_id, name)
        assert len(base64.b64decode(squatted["value"])) == 2000

        sp2 = algod.suggested_params()
        sp2.flat_fee = True
        sp2.fee = 1000
        reopen = transaction.ApplicationCallTxn(
            sender=env["sender"], sp=sp2, index=app_id, on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"RCP1", bytes([2]), bytes([0]), name + (4094).to_bytes(2, "big")],
            # Two references to the SAME box: a standalone call outside a
            # group only carries 2,048 B of write budget per reference
            # (014 SS3.3) -- a lone box_create(name, 4094) needs 4,096. A
            # real T2 group gets this pooled for free from its OTHER
            # box-touching transactions (STAGE_WRITE/STAGE_WALK), as
            # TestT2AgainstAnchorLive demonstrates with a single reference
            # per call above; this is a standalone-call artefact of THIS
            # test, not a contract requirement.
            boxes=[transaction.BoxReference(0, name), transaction.BoxReference(0, name)],
        )
        txid2 = algod.send_transaction(reopen.sign(env["sk"]))
        transaction.wait_for_confirmation(algod, txid2, 4)
        reopened = algod.application_box_by_name(app_id, name)
        assert len(base64.b64decode(reopened["value"])) == 4094, (
            "re-open at a different size must succeed (delete-before-create) -- "
            "pre-fix this failed with 'box size mismatch 2000 4094'"
        )
