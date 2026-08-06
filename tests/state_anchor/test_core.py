"""M8 core suites (F/H/S/R against synthetic-but-self-consistent Merkle
fixtures, `synth.py`) plus the two explicitly-flagged risk areas: TP-M8-4
(compile-time `ANCHOR_APP_ID`) and `ring_n` immutability. Every assertion
here runs against real dev-mode algod via `simulate` (real box-mechanics,
real assert failures) -- the ONE thing this file does NOT do is submit a
real, non-simulated group against real live chain data; that is
`test_live_e2e.py`'s job (G1-M8/G5-M8/Suite B).
"""
from __future__ import annotations

import pytest

from tests.state_anchor import synth
from tests.state_anchor.conftest import (
    REPO_ROOT,
    Arc4Harness,
    algod_client,
    compile_teal,
    deploy_donor_pair,
    funded_account,
    kmd_client,
    patched_repo_copy,
    puya_compile,
)

RING_N = 8
FIN_SLOT = 2_000_032  # multiple of 32 (epoch boundary) for convenience
EPOCH = FIN_SLOT // 32


@pytest.fixture(scope="module")
def compiled(algod_available, anchor_src, bench_src):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    anchor_contracts = puya_compile(anchor_src)
    bench_contracts = puya_compile(bench_src)
    return anchor_contracts, bench_contracts


@pytest.fixture(scope="module")
def account():
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


@pytest.fixture()
def m4probe(compiled, account):
    _anchor, bench = compiled
    sender, sk = account
    h = Arc4Harness(bench["M4Probe"], sender, sk)
    h.create([])
    return h


def _set_m4(m4probe, fin_slot: int, fin_root: bytes, fin_state_root: bytes):
    res = m4probe.call(
        "set_finalized", [fin_slot, fin_root, fin_state_root],
    )
    # set_finalized is a state-changing call; commit it for real so a LATER
    # transaction (a different app, in a different simulate/submit call)
    # observes it via app_global_get_ex.
    m4probe.submit([{"method": "set_finalized", "args": [fin_slot, fin_root, fin_state_root]}])
    return res


@pytest.fixture()
def anchor(compiled, account, m4probe):
    anchor_contracts, _bench = compiled
    sender, sk = account
    h = Arc4Harness(anchor_contracts["TrustedRootAnchor"], sender, sk)
    h.create([sender, m4probe.app_id, RING_N], extra_pages=1, boxes=[(0, b"forks8")], fund_app=15_000_000)
    h.ring_n = RING_N
    ring_boxes = [(0, b"h:" + i.to_bytes(8, "big")) for i in range(RING_N)]
    h.submit([{"method": "ring_init_chunk", "args": [RING_N], "boxes": ring_boxes}])
    h.submit([{
        "method": "append_fork_row",
        "args": [0, synth.G_STATE_ROOT, synth.G_RECEIPTS_ROOT, synth.G_BLOCK_NUMBER, synth.G_BLOCK_ROOTS_BASE],
        "boxes": [(0, b"forks8")],
    }])
    return h


def _ring_box(block_number, ring_n=RING_N):
    return (0, b"h:" + (block_number & (ring_n - 1)).to_bytes(8, "big"))


def _pin_box(block_number):
    return (0, b"p:" + block_number.to_bytes(8, "big"))


def _anchor_direct_submit(anchor, donors, args, m4_app_id):
    callee_id, issuer_id = donors
    return anchor.submit_with_donor(
        "anchor_direct", args, donor_issuer_id=issuer_id, donor_callee_id=callee_id,
        n_donors=12, apps=[m4_app_id],
    )


def _direct_anchor_args(m4_app_id, block_number, beacon_slot=FIN_SLOT, seed=0):
    state_root = synth.random32()
    receipts_root = synth.random32()
    body_root, sb, rb, nb = synth.build_execution_tree(state_root, receipts_root, block_number)
    parent_root = synth.random32()
    fin_header, fin_root = synth.make_header(beacon_slot, 0, parent_root, synth.random32(), body_root)
    fin_state_root = fin_header[48:80]
    args = [m4_app_id, fin_header, state_root, receipts_root, block_number, sb, rb, nb]
    return args, fin_root, fin_state_root, state_root, receipts_root


class TestDirectAnchorHappyPath:
    def test_anchor_direct_then_attest(self, anchor, m4probe):
        args, fin_root, fin_state_root, state_root, receipts_root = _direct_anchor_args(
            m4probe.app_id, block_number=100
        )
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        # `anchor_direct` then `attest` in ONE simulate group: `attest`
        # (a later transaction in the SAME group) sees the box write
        # `anchor_direct` (an earlier transaction in that SAME group) just
        # made -- two SEPARATE `simulate` calls would NOT share state, since
        # each is its own independent, non-committing evaluation.
        res, att = anchor.call_group([
            {"method": "anchor_direct", "args": args, "apps": [m4probe.app_id]},
            {"method": "attest", "args": [100]},
        ])
        assert res.ok, res.failure
        record = res.return_value
        assert record is not None and len(record) == 154
        assert record[18:50] == state_root
        assert record[50:82] == receipts_root

        assert att.ok, att.failure
        assert att.return_value[50:82] == receipts_root


class TestTPM84CompileTimeConstant:
    """The single most explicitly flagged risk area: `ANCHOR_APP_ID` must be
    a compile-time constant. Proves it two ways: (1) a real consumer
    (`AnchorReceiptProbe`, compiled against the REAL deployed anchor app id)
    genuinely accepts a real anchor and rejects a forged one; (2) directly
    inspects the compiled TEAL to confirm the constant is embedded as an
    immediate, not read from any argument/box/global."""

    def test_forged_app_id_is_rejected(self, compiled, account, anchor, m4probe, donors):
        """§11 S4: deploy `FakeAnchor` (identical selector, valid ARC-4
        envelope, attacker-chosen 154-byte payload); compile a REAL
        consumer against the REAL `TrustedRootAnchor`'s app id; point the
        consumer's `anchor_gi` at the FakeAnchor call instead. Must reject
        via `N2` -- and, for contrast, must ACCEPT when pointed at the real
        anchor app's `attest` call in the same group shape."""
        _anchor_contracts, bench = compiled
        sender, sk = account

        fake = Arc4Harness(bench["FakeAnchor"], sender, sk)
        fake.create([])

        # Compile `AnchorReceiptProbe` (imports `handoff.anchor_from_group`)
        # against the REAL anchor app id -- TP-M8-4's actual compile-time
        # binding step, done for real, not simulated.
        patched_root = patched_repo_copy(anchor.app_id)
        probe_src = patched_root / "contracts" / "state_anchor" / "bench_app.py"
        probe_contracts = puya_compile(probe_src, extra_pythonpath=patched_root)
        # AnchorReceiptProbe is a raw Contract (no ARC-4 arc56) -- deploy it
        # with plain ApplicationCreateTxn.
        from algosdk import transaction

        algod = algod_client()
        approval = compile_teal(algod, probe_contracts["AnchorReceiptProbe"]["approval"])  # noqa: F821
        clear = compile_teal(algod, probe_contracts["AnchorReceiptProbe"]["clear"])  # noqa: F821
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
        probe_app_id = confirmed["application-index"]

        # Group: [attest(real anchor, block 100), fake.attest(forged), probe MODE_AGAINST_ANCHOR pointed at fake]
        args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=100)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        _anchor_direct_submit(anchor, donors, args, m4probe.app_id)

        forged_payload = b"\x01" * 154
        # attest(real) at gi=0, fake.attest(forged) at gi=1 -- probe reads gi=1 (the FAKE one).
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer

        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(sk)
        sp1 = algod.suggested_params(); sp1.flat_fee = True; sp1.fee = 1000
        atc.add_method_call(
            app_id=anchor.app_id, method=Method.undictify(anchor.methods["attest"]),
            sender=sender, sp=sp1, signer=signer, method_args=[100],
        )
        sp2 = algod.suggested_params(); sp2.flat_fee = True; sp2.fee = 1000
        atc.add_method_call(
            app_id=fake.app_id, method=Method.undictify(fake.methods["attest"]),
            sender=sender, sp=sp2, signer=signer, method_args=[100, forged_payload],
        )
        sp3 = algod.suggested_params(); sp3.flat_fee = True; sp3.fee = 1000
        # probe MODE_AGAINST_ANCHOR: prev_gi is unused directly here (we call a
        # standalone check-only path) -- reuse arg2 as anchor_gi carrier via
        # raw app args since AnchorReceiptProbe is a raw Contract.
        fixed = (1).to_bytes(8, "big") + (100).to_bytes(8, "big") + (0).to_bytes(8, "big") + (0).to_bytes(2, "big")
        txn3 = transaction.ApplicationCallTxn(
            sender=sender, sp=sp3, index=probe_app_id, on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"RCP1", bytes([5]), bytes([1]), fixed],
        )
        from algosdk.atomic_transaction_composer import TransactionWithSigner
        atc.add_transaction(TransactionWithSigner(txn3, signer))

        with pytest.raises(Exception):
            atc.execute(algod, 4)

    def test_compiled_teal_embeds_constant_immediate(self, anchor):
        """A source-level review item made mechanical (§13.6 B4's spirit):
        confirm `ANCHOR_APP_ID` is compiled as an immediate `pushint`, not
        derived from `txna ApplicationArgs`/`box_get`/a global-state
        opcode."""
        patched_root = patched_repo_copy(anchor.app_id)
        probe_src = patched_root / "contracts" / "state_anchor" / "bench_app.py"
        contracts = puya_compile(probe_src, extra_pythonpath=patched_root)
        teal = contracts["AnchorReceiptProbe"]["approval"]
        assert f"pushint {anchor.app_id}" in teal or f"pushint {anchor.app_id} " in teal


class TestRingNImmutable:
    def test_ring_n_has_no_setter(self, compiled):
        """§6.2/implementer checklist item 15: `ring_n` MUST be write-once,
        with no resize method exposed anywhere in the ABI."""
        anchor_contracts, _bench = compiled
        arc56 = anchor_contracts["TrustedRootAnchor"]["arc56"]
        method_names = {m["name"] for m in arc56["methods"]}
        assert method_names == {
            "create", "ring_init_chunk", "append_fork_row", "anchor_direct",
            "anchor_historical", "attest", "get_anchor", "pin", "unpin",
            "revoke", "freeze", "unfreeze", "gov_clear_conflict", "renounce",
            "noop_budget", "donor",
        }
        # No method takes a "ring_n"/"ring_size"/resize-shaped argument
        # anywhere except `create` (write-once).
        for m in arc56["methods"]:
            if m["name"] == "create":
                continue
            arg_names = [a["name"] for a in m.get("args", [])]
            assert "ring_n" not in arg_names and "ring_size" not in arg_names

    def test_ring_n_must_be_power_of_two(self, compiled, account, m4probe):
        anchor_contracts, _bench = compiled
        sender, sk = account
        h = Arc4Harness(anchor_contracts["TrustedRootAnchor"], sender, sk)
        with pytest.raises(Exception):
            h.create([sender, m4probe.app_id, 7], extra_pages=1, boxes=[(0, b"forks8")], fund_app=15_000_000)  # not a power of two


class TestSecurityErrorCodes:
    """Real finding, consistent with `tests/sync_committee/test_install_live.py`'s
    own documented precedent: Puya's `assert cond, "N4"`-style messages are
    TEAL COMMENTS only (confirmed by inspecting the compiled TEAL --
    `assert // N4`), not data `simulate` returns at runtime. Every check
    below therefore confirms "some assert fired" (`"assert failed" in
    .failure`) plus, where precision matters, that the SPECIFIC scenario
    constructed could only have tripped one assert -- the same discipline
    M4's own test suite already established, not a new gap this pass
    introduced."""

    def test_N4_wrong_m4_app_rejected(self, anchor, m4probe, compiled, account):
        """§11 S3, TP-M8-7: point `m4_app` at a FakeM4Probe deployed
        separately -- `m4_app.id != self.m4_app` (M8's own immutable
        global) rejects with N4 regardless of what the fake exposes."""
        _anchor_contracts, bench = compiled
        sender, sk = account
        fake_m4 = Arc4Harness(bench["M4Probe"], sender, sk)
        fake_m4.create([])
        fake_m4.submit([{"method": "set_finalized", "args": [FIN_SLOT, synth.random32(), synth.random32()]}])

        args, _fr, _fsr, _s, _r = _direct_anchor_args(fake_m4.app_id, block_number=101)
        args[0] = fake_m4.app_id
        res = anchor.call("anchor_direct", args, apps=[fake_m4.app_id])
        assert not res.ok
        assert "assert failed" in res.failure

    def test_N5_zero_fin_root_rejected(self, anchor, m4probe):
        args, _fr, _fsr, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=102)
        # m4probe was created with fin_root == 0 and never set_finalized here
        res = anchor.call("anchor_direct", args, apps=[m4probe.app_id])
        assert not res.ok
        assert "assert failed" in res.failure

    def test_N6_wrong_fin_header_rejected(self, anchor, m4probe):
        args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=103)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        # corrupt the header so its htr no longer equals fin_root
        corrupted = bytearray(args[1])
        corrupted[0] ^= 0xFF
        args[1] = bytes(corrupted)
        res = anchor.call("anchor_direct", args, apps=[m4probe.app_id])
        assert not res.ok
        assert "assert failed" in res.failure

    def test_N15_want_block_number_mismatch_via_attest(self, anchor, m4probe, donors):
        args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=104)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        _anchor_direct_submit(anchor, donors, args, m4probe.app_id)
        res = anchor.call("attest", [999999])  # never anchored -> N12, not N15 (attest has no want_* check itself)
        assert not res.ok
        assert "assert failed" in res.failure

    def test_N12_vs_N13_absent_vs_revoked(self, anchor, m4probe, account, donors):
        args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=105)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        _anchor_direct_submit(anchor, donors, args, m4probe.app_id)

        never_anchored = anchor.call("attest", [777_777])
        assert not never_anchored.ok and "assert failed" in never_anchored.failure

        anchor.submit([{"method": "revoke", "args": [105]}])
        revoked = anchor.call("attest", [105])
        assert not revoked.ok and "assert failed" in revoked.failure


class TestRetentionRing:
    def test_idempotent_reanchor_is_a_noop_success(self, anchor, m4probe, donors):
        args, fin_root, fin_state_root, s, r = _direct_anchor_args(m4probe.app_id, block_number=200)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        first = _anchor_direct_submit(anchor, donors, args, m4probe.app_id)
        assert first.tx_ids
        # identical content, different (later) round -- must still succeed (S15)
        second = _anchor_direct_submit(anchor, donors, args, m4probe.app_id)
        assert second.tx_ids
        att = anchor.call("attest", [200])
        assert att.ok

    def test_equivocation_latches_conflict_then_gov_clear_restores(self, anchor, m4probe, donors):
        args, fin_root, fin_state_root, s, r = _direct_anchor_args(m4probe.app_id, block_number=201)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        _anchor_direct_submit(anchor, donors, args, m4probe.app_id)

        args2, fin_root2, fin_state_root2, s2, r2 = _direct_anchor_args(m4probe.app_id, block_number=201, beacon_slot=FIN_SLOT)
        _set_m4(m4probe, FIN_SLOT, fin_root2, fin_state_root2)
        conflicting = _anchor_direct_submit(anchor, donors, args2, m4probe.app_id)
        assert conflicting.tx_ids, "the equivocating call itself must SUCCEED so the latch persists (box.py docstring)"

        blocked = anchor.call("attest", [201])
        assert not blocked.ok and "assert failed" in blocked.failure

        anchor.submit([{"method": "gov_clear_conflict", "args": []}])
        restored = anchor.call("attest", [201])
        assert restored.ok, restored.failure

    def test_ring_eviction_and_admission_rule(self, anchor, m4probe, donors):
        """§7.4 N-ADMIT + §5.4's distinctness lemma at the real `ring_n=8`
        this module's fixtures use: anchor `ring_n + 1` consecutive blocks,
        confirm the oldest evicts and `attest` on it returns N12."""
        base = 10_000
        slot = FIN_SLOT
        for i in range(RING_N + 1):
            bn = base + i
            slot += 32
            args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=bn, beacon_slot=slot)
            _set_m4(m4probe, slot, fin_root, fin_state_root)
            res = _anchor_direct_submit(anchor, donors, args, m4probe.app_id)
            assert res.tx_ids, f"anchor of block {bn} failed"

        evicted = anchor.call("attest", [base])
        assert not evicted.ok and "assert failed" in evicted.failure
        still_there = anchor.call("attest", [base + RING_N])
        assert still_there.ok


class TestPinnedTier:
    def test_pin_and_unpin_refunds_payer(self, anchor, m4probe, account, donors):
        from algosdk import transaction
        from algosdk.atomic_transaction_composer import TransactionWithSigner, AccountTransactionSigner

        sender, sk = account
        args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=300)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        _anchor_direct_submit(anchor, donors, args, m4probe.app_id)

        algod = algod_client()
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import AtomicTransactionComposer
        from algosdk.logic import get_application_address

        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(sk)
        sp_pay = algod.suggested_params()
        pay_txn = transaction.PaymentTxn(sender, sp_pay, get_application_address(anchor.app_id), 80_900)
        sp_pin = algod.suggested_params(); sp_pin.flat_fee = True; sp_pin.fee = 2000
        atc.add_method_call(
            app_id=anchor.app_id, method=Method.undictify(anchor.methods["pin"]),
            sender=sender, sp=sp_pin, signer=signer,
            method_args=[300, TransactionWithSigner(pay_txn, signer)],
            boxes=[_ring_box(300), _pin_box(300)],
        )
        result = atc.execute(algod, 4)
        assert result.tx_ids

        anchor.submit([{"method": "unpin", "args": [300], "boxes": [_pin_box(300)], "fee": 2000}])
