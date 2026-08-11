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


def _assert_box_absent(algod, app_id, name):
    with pytest.raises(Exception, match="box not found"):
        algod.application_box_by_name(app_id, name)


def _t2_against_anchor_atc(env, *, tx_index=1, log_index=0, want_tx_index=None, want_log_index=None,
                            corrupt_write_index=None, attest_app_id=None, attest_method=None,
                            attest_method_args=None, attest_boxes=None, n_donors=4):
    """Hand-builds the real `[DonorIssuer, PaymentTxn, attest, MODE_INIT,
    MODE_STAGE_OPEN, MODE_STAGE_WRITE..., MODE_STAGE_WALK,
    MODE_AGAINST_ANCHOR]` group -- the same shape `relayer/client.py::
    _submit_t2_receipt_against_anchor` builds, replicated by hand (not
    driven through `EthAvmClient`) because that method's `relayer.group.
    submit.run` raises out of its OWN sizing `simulate` on a genuinely
    failing group and never sends a real transaction -- every A-6..A-9
    scenario needs a REAL rejected send, box-absence/balance checks
    included. Returns `(atc, box_name)`; the caller signs nothing here,
    `atc.execute(algod, 4)` does both build and send."""
    from algosdk import transaction
    from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer, TransactionWithSigner
    from relayer.drivers import m7_receipt as m7
    from relayer.drivers import m8_anchor as m8
    from relayer.group.donors import donor_transaction_with_signer

    algod = env["algod"]
    sender, sk = env["sender"], env["sk"]
    signer = AccountTransactionSigner(sk)
    anchored_app_id = env["anchored_app_id"]
    app_address = logic.get_application_address(anchored_app_id)

    want_tx_index = tx_index if want_tx_index is None else want_tx_index
    want_log_index = log_index if want_log_index is None else want_log_index

    box_name = m7.derive_t2_box_name(EL_BLOCK_NUMBER)
    GROUP_OFFSET = 3  # donor(0) + payment(1) + attest(2), matching 014 SS4.4's table
    _tier, calls, box_name, _fund = m7.plan_receipt_calls_t2(
        env["receipts_root"], tx_index, log_index, env["nodes"], box_name, group_offset=GROUP_OFFSET
    )
    if corrupt_write_index is not None:
        write_indices = [i for i, c in enumerate(calls) if c.args[1] == bytes([3])]
        i = write_indices[corrupt_write_index]
        corrupted_chunk = bytearray(calls[i].args[4])
        corrupted_chunk[0] ^= 0xFF
        calls[i] = m7.RawCall(args=[*calls[i].args[:4], bytes(corrupted_chunk)], boxes=calls[i].boxes)

    prev_gi = GROUP_OFFSET + len(calls) - 1  # MODE_STAGE_WALK's own absolute group index
    anchor_gi = GROUP_OFFSET - 1  # attest's (or the fake's) own absolute group index
    check_args = m7.build_against_anchor_check_args(
        prev_gi, anchor_gi, EL_BLOCK_NUMBER, want_tx_index, want_log_index
    )

    # Real interaction found while building this: `m7.t2_box_mbr_requirement`
    # (mirroring `relayer/client.py::_t2_payment_amount` exactly) assumes
    # the ONLY min-balance obligation on the app account is THIS leaf's own
    # box plus the bare 100,000 uALGO account floor -- true in production
    # (a T2 box is always opened and closed inside its own atomic group),
    # false in THIS suite once `TestBoxSquattingMitigation` runs first and
    # leaves its own "SQUAT001" box (4,094 B) permanently open on the SAME
    # shared `probe_env` app account. Funding off the account's REAL,
    # currently-reported `min-balance` (whatever it already reflects) is
    # robust to that, where the production formula is not.
    leaf_len = len(env["nodes"][-1])
    info = algod.account_info(app_address)
    required_min_balance = info["min-balance"] + 2500 + 400 * (8 + leaf_len)
    pay_amount = max(0, required_min_balance - info["amount"])

    atc = AtomicTransactionComposer()
    atc.add_transaction(donor_transaction_with_signer(
        algod, sender, sk, env["issuer_id"], env["callee_id"], n_donors,
    ))
    sp_pay = algod.suggested_params()
    pay_txn = transaction.PaymentTxn(sender, sp_pay, app_address, pay_amount)
    atc.add_transaction(TransactionWithSigner(pay_txn, signer))

    sp1 = algod.suggested_params()
    sp1.flat_fee = True
    sp1.fee = 1000
    if attest_app_id is None:
        attest_app_id = env["anchor_id"]
        attest_method = m8.METHODS["attest"]
        attest_method_args = [EL_BLOCK_NUMBER]
        attest_boxes = m8.auto_boxes_for("attest", EL_BLOCK_NUMBER, RING_N)
    atc.add_method_call(
        app_id=attest_app_id, method=attest_method, sender=sender, sp=sp1, signer=signer,
        method_args=attest_method_args, boxes=attest_boxes,
    )

    for call in calls:
        sp = algod.suggested_params()
        sp.flat_fee = True
        sp.fee = 1000
        kwargs = {}
        if call.boxes:
            kwargs["boxes"] = [transaction.BoxReference(0, b) for b in call.boxes]
        txn = transaction.ApplicationCallTxn(
            sender=sender, sp=sp, index=anchored_app_id,
            on_complete=transaction.OnComplete.NoOpOC, app_args=call.args, **kwargs,
        )
        atc.add_transaction(TransactionWithSigner(txn, signer))

    sp_check = algod.suggested_params()
    sp_check.flat_fee = True
    sp_check.fee = 1000
    check_txn = transaction.ApplicationCallTxn(
        sender=sender, sp=sp_check, index=anchored_app_id,
        on_complete=transaction.OnComplete.NoOpOC, app_args=check_args,
    )
    atc.add_transaction(TransactionWithSigner(check_txn, signer))
    return atc, box_name


class TestNegativePaths014:
    """A-6..A-9 (SS10): the four negative live rows the implementation pass
    disclosed as an explicit gap, not silently skipped. All four build a
    REAL group by hand (`_t2_against_anchor_atc`, not `EthAvmClient`, since
    the client's `submit_run` aborts a genuinely-failing group at its own
    sizing `simulate` and never sends) and confirm rejection via a real
    `atc.execute()`.

    Real, live finding (this pass, not assumed): a Puya `assert cond,
    "CODE"` string is a TEAL COMMENT, stripped from what real algod
    returns even on a real send -- confirmed directly against dev-mode
    algod (`logic eval error: assert failed pc=2636. Details: ...
    opcodes=pop; swap; assert`, no "N12" anywhere in the string), matching
    `tests/state_anchor/test_core.py::TestSecurityErrorCodes`'s own
    documented finding. Every test below therefore matches the generic
    `"assert failed"` real algod gives, the same discipline that suite
    already established, and instead proves it is the RIGHT assert by
    making every other input honest -- documented per test which SS10 code
    that isolation targets.

    A-6 evicts `EL_BLOCK_NUMBER` from the shared `probe_env` ring for
    real and MUST run last in this class (`probe_env` is module-scoped and
    shared with the other three classes above, which all need
    `EL_BLOCK_NUMBER` to stay attestable; nothing after this class's own
    A-6 test needs it again, and pytest's default, non-randomized run
    order is definition order, confirmed against this repo's own
    `pyproject.toml` addopts, which loads no order-randomizing plugin)."""

    def test_a7_corrupted_write_chunk_rejects(self, probe_env):
        """A-7: one byte flipped in one `MODE_STAGE_WRITE` chunk -- the
        staged leaf's own `keccak256` no longer chains to the branch
        node's reference, so `mpt_walk_node`'s FIRST check (`contracts/
        mpt/walk.py`'s own "W11", asserted before any RLP parsing of the
        node even starts) rejects it. Nothing else about this group is
        dishonest, so W11 is the only assert this scenario can trip."""
        env = probe_env
        algod = env["algod"]
        app_address = logic.get_application_address(env["anchored_app_id"])
        balance_before = algod.account_info(app_address)["amount"]

        atc, box_name = _t2_against_anchor_atc(env, corrupt_write_index=0)
        with pytest.raises(Exception, match="assert failed"):
            atc.execute(algod, 4)

        _assert_box_absent(algod, env["anchored_app_id"], box_name)
        balance_after = algod.account_info(app_address)["amount"]
        assert balance_after == balance_before, "a rejected group must strand nothing (SS3.6)"

    def test_a8_fake_anchor_rejects(self, probe_env):
        """A-8: `MODE_AGAINST_ANCHOR`'s `anchor_gi` pointed at a
        `FakeAnchor.attest` call (`contracts/state_anchor/bench_app.py`)
        instead of the real, compile-time-bound M8 `attest` -- proves
        TP-M8-4's compile-time-binding guarantee still holds through the
        box-staged tier, not just T1 (`AnchorReceiptProbe`'s own existing
        proof, `tests/state_anchor/test_core.py::
        TestTPM84CompileTimeConstant::test_forged_app_id_is_rejected`).
        The walk itself (MODE_INIT..MODE_STAGE_WALK) never touches M8 at
        all -- it reaches a genuine R_INCLUDED using the receipts_root
        supplied directly in MODE_INIT's own args -- so `anchor_from_group`'s
        `assert prev.app_id == ANCHOR_APP_ID, "N2"` is the only thing this
        scenario can trip; `Mpt7AnchoredReceiptApp` was compiled against the
        REAL M8 app id (`deploy.plans.m7_anchored.apply`, same as
        production), so a compile-time constant, not a runtime check, is
        what fails here."""
        env = probe_env
        algod = env["algod"]
        sender, sk = env["sender"], env["sk"]

        from algosdk.abi import Method

        bench_compiled = puya_compile("contracts/state_anchor/bench_app.py")
        fake = Arc4Harness(bench_compiled["FakeAnchor"], sender, sk)
        fake.create([])

        app_address = logic.get_application_address(env["anchored_app_id"])
        balance_before = algod.account_info(app_address)["amount"]

        atc, box_name = _t2_against_anchor_atc(
            env,
            attest_app_id=fake.app_id,
            attest_method=Method.undictify(fake.methods["attest"]),
            attest_method_args=[EL_BLOCK_NUMBER, b"\x01" * 154],
            attest_boxes=None,
        )
        with pytest.raises(Exception, match="assert failed"):
            atc.execute(algod, 4)

        _assert_box_absent(algod, env["anchored_app_id"], box_name)
        balance_after = algod.account_info(app_address)["amount"]
        assert balance_after == balance_before, "a rejected group must strand nothing (SS3.6)"

    def test_a9_wrong_want_tx_index_rejects(self, probe_env):
        """A-9: `MODE_AGAINST_ANCHOR`'s `want_tx_index` (26-byte fixed arg,
        `contracts/receipt/anchored_app.py`'s own docstring:
        `anchor_gi(8) || want_block_number(8) || want_tx_index(8) ||
        want_log_index(2)`) does not match the tx index the walk actually
        walked (1). The walk itself is 100% honest -- same receipts_root,
        same real M8 attest -- so `mpt7_result_from_group`'s `assert
        r_tx_index(r) == want_tx_index, "L11"` (`contracts/receipt/
        handoff.py`) is the only assert this scenario can trip; the
        preceding `r_receipts_root(r) == want_receipts_root` check (also
        "L11") passes because the anchor's root is genuinely the one this
        leaf was walked against."""
        env = probe_env
        algod = env["algod"]
        app_address = logic.get_application_address(env["anchored_app_id"])
        balance_before = algod.account_info(app_address)["amount"]

        atc, box_name = _t2_against_anchor_atc(env, want_tx_index=2)
        with pytest.raises(Exception, match="assert failed"):
            atc.execute(algod, 4)

        _assert_box_absent(algod, env["anchored_app_id"], box_name)
        balance_after = algod.account_info(app_address)["amount"]
        assert balance_after == balance_before, "a rejected group must strand nothing (SS3.6)"

    def test_a6_evicted_block_rejects_and_strands_nothing(self, probe_env):
        """A-6/SS3.5's own measured claim, reproduced for real: `attest`
        on an evicted block fails the whole group closed, before
        MODE_STAGE_OPEN (transaction index 3) ever runs -- box absent,
        app balance unchanged.

        Eviction, the real rule (`contracts/state_anchor/box.py::
        ring_admit_and_write`): a ring slot is keyed by `block_number &
        (ring_n - 1)`, and ANY later block at the SAME residue overwrites
        it outright (`ex_block < new_block` -> unconditional replace) --
        not a FIFO cursor. `RING_N` (8) consecutive blocks anchored from
        `EL_BLOCK_NUMBER + 1` cycle through every residue exactly once and
        the LAST one (`EL_BLOCK_NUMBER + RING_N`) lands back on
        `EL_BLOCK_NUMBER`'s own residue, matching `tests/state_anchor/
        test_core.py::test_ring_eviction_and_admission_rule`'s own
        `RING_N + 1`-consecutive-blocks-total recipe (`RING_N` here plus
        the block `probe_env` already anchored) and 014 SS3.5's own
        measured note ("ring_n = 8 in the test fixture, then 8 further
        blocks anchored to force eviction")."""
        env = probe_env
        algod = env["algod"]
        sender, sk = env["sender"], env["sk"]

        from relayer.drivers import m8_anchor as m8

        bench_compiled = puya_compile("contracts/state_anchor/bench_app.py")
        anchor_compiled = puya_compile("contracts/state_anchor/anchor_app.py")
        m4probe = Arc4Harness(bench_compiled["M4Probe"], sender, sk)
        m4probe.app_id = env["m4probe_id"]
        anchor = Arc4Harness(anchor_compiled["TrustedRootAnchor"], sender, sk)
        anchor.app_id = env["anchor_id"]
        anchor.ring_n = RING_N

        slot = FIN_SLOT
        for i in range(1, RING_N + 1):
            bn = EL_BLOCK_NUMBER + i
            slot += 32
            state_root = synth.random32()
            receipts_root = synth.random32()
            body_root, sb, rb, nb = synth.build_execution_tree(state_root, receipts_root, bn)
            parent_root = synth.random32()
            fin_header, fin_root = synth.make_header(slot, 0, parent_root, synth.random32(), body_root)
            fin_state_root = fin_header[48:80]
            m4probe.submit([{"method": "set_finalized", "args": [slot, fin_root, fin_state_root]}])
            res = anchor.submit_with_donor(
                "anchor_direct", [env["m4probe_id"], fin_header, state_root, receipts_root, bn, sb, rb, nb],
                donor_issuer_id=env["issuer_id"], donor_callee_id=env["callee_id"],
                n_donors=8, apps=[env["m4probe_id"]],
            )
            assert res.tx_ids, f"setup anchor of block {bn} (needed to evict {EL_BLOCK_NUMBER}) failed"

        # Confirm the eviction really happened via `simulate` BEFORE
        # attempting the real T2-against-anchor send below, so a rejection
        # there is unambiguously the ring's own N12, not a setup bug.
        evicted = anchor.call("attest", [EL_BLOCK_NUMBER])
        assert not evicted.ok and "assert failed" in evicted.failure

        app_address = logic.get_application_address(env["anchored_app_id"])
        balance_before = algod.account_info(app_address)["amount"]

        # `m8.auto_boxes_for("attest", ...)` only names the ring box -- the
        # happy path never needs the pinned-tier box because it never falls
        # through to it. An evicted block DOES fall through to
        # `pin_read_maybe` (never pinned here), so this scenario needs the
        # `p:<block>` reference too or it fails on "invalid Box reference"
        # instead of the real N12 this test targets.
        residue = EL_BLOCK_NUMBER & (RING_N - 1)
        attest_boxes = [(0, m8.ring_box_name(residue)), (0, m8.pin_box_name(EL_BLOCK_NUMBER))]

        atc, box_name = _t2_against_anchor_atc(
            env, attest_app_id=env["anchor_id"], attest_method=m8.METHODS["attest"],
            attest_method_args=[EL_BLOCK_NUMBER], attest_boxes=attest_boxes,
        )
        with pytest.raises(Exception, match="assert failed"):
            atc.execute(algod, 4)

        _assert_box_absent(algod, env["anchored_app_id"], box_name)
        balance_after = algod.account_info(app_address)["amount"]
        assert balance_after == balance_before, (
            "SS3.5's own claim: an evicted attest() aborts before MODE_STAGE_OPEN "
            "ever runs, so nothing is stranded"
        )
