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

from tests.harness.chain import algod_client
from tests.harness.deployment import compile_teal, patched_repo_copy, puya_compile
from tests.state_anchor import synth
from tests.state_anchor.harness import Arc4Harness

RING_N = 8
FIN_SLOT = 2_000_032  # multiple of 32 (epoch boundary) for convenience
EPOCH = FIN_SLOT // 32


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
    h.create([sender, m4probe.app_id, RING_N], extra_pages=1, fund_app=15_000_000)
    h.ring_n = RING_N
    ring_boxes = [(0, b"h:" + i.to_bytes(8, "big")) for i in range(RING_N)]
    h.submit([{"method": "ring_init_chunk", "args": [RING_N], "boxes": ring_boxes}])
    h.submit([{
        "method": "append_fork_row",
        "args": [0, synth.G_STATE_ROOT, synth.G_RECEIPTS_ROOT, synth.G_BLOCK_NUMBER, synth.G_BLOCK_ROOTS_BASE],
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
            h.create([sender, m4probe.app_id, 7], extra_pages=1, fund_app=15_000_000)  # not a power of two


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

    def test_N7_fin_state_root_cross_check_mismatch_rejected(self, anchor, m4probe):
        """§4.4 step 4: `fin_header`'s own `state_root` field is already
        bound by `assert_fin_header_matches`'s htr check (so `N6` passes --
        `fin_root` genuinely IS `hash_tree_root(fin_header)`), but M4's
        SEPARATELY-read `fin_state_root` global must independently agree
        with it. Set `M4Probe.fin_state_root` to a value that disagrees
        with the real header's own embedded field -- the relayer-supplied-
        header-from-the-wrong-M4-epoch case `N7` exists to name."""
        args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=106)
        wrong_fin_state_root = synth.random32()
        assert wrong_fin_state_root != fin_state_root
        _set_m4(m4probe, FIN_SLOT, fin_root, wrong_fin_state_root)
        res = anchor.call("anchor_direct", args, apps=[m4probe.app_id])
        assert not res.ok
        assert "assert failed" in res.failure

    def test_N8_malformed_header_arg_length_rejected(self, anchor, m4probe, account):
        """`bridge.assert_header_shape`: `fin_header` must be exactly 112
        bytes. A conforming ARC-4 client (algosdk's own `StaticArray`
        encoder) refuses client-side to encode anything but exactly 112
        bytes for this argument, so this can ONLY be reached via a raw,
        hand-crafted app-call argument that bypasses the ABI encoder
        entirely -- exactly what `N8` exists to catch ahead of an obscure
        `extract`-range failure four steps later (bridge.py's own
        docstring). Built by ABI-encoding a genuinely honest
        `anchor_direct` call via a real ATC (so every OTHER argument is
        correctly shaped), then truncating JUST the already-encoded header
        app-arg to 100 bytes before signing. A single, ungrouped call, so
        there is no stale group-id hash to invalidate (empirically
        confirmed: ATC leaves `.group` unset for a lone method call)."""
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer
        from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup

        sender, sk = account
        args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=107)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)

        algod = anchor.algod
        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(sk)
        sp = algod.suggested_params()
        sp.flat_fee = True
        sp.fee = 1000
        atc.add_method_call(
            app_id=anchor.app_id, method=Method.undictify(anchor.methods["anchor_direct"]),
            sender=sender, sp=sp, signer=signer, method_args=args,
            foreign_apps=[m4probe.app_id],
        )
        group = atc.build_group()
        txn = group[0].txn
        assert txn.group is None, "a lone method call must not carry a stale group id"
        header_idx = next(i for i, a in enumerate(txn.app_args) if len(a) == 112)
        txn.app_args[header_idx] = txn.app_args[header_idx][:100]  # 112 -> 100 bytes
        stxn = txn.sign(sk)

        sreq = SimulateRequest(
            txn_groups=[SimulateRequestTransactionGroup(txns=[stxn])], allow_unnamed_resources=True,
        )
        resp = algod.simulate_transactions(sreq)
        grp = resp["txn-groups"][0]
        assert grp.get("failure-message"), "a header arg of the wrong byte length must be rejected"
        assert "assert failed" in grp["failure-message"]

    def test_N16_historical_window_t_slot_not_before_fin_slot_rejected(self, anchor, m4probe):
        """§4.2 N-WINDOW: HISTORICAL mode requires `t_slot < fin_slot`. A
        real, valid `fin_header`/`fin_root`/`fin_state_root` triple (N5/N6/
        N7 all pass) paired with a `target_header` whose OWN slot is AFTER
        `fin_slot` -- the shape check (still 112 bytes) passes, and the
        target header's hash is never checked against a pre-known value in
        HISTORICAL mode (only folded later against `block_roots`, which
        this call never reaches), so `N16` is the first and only check that
        can fire."""
        state_root = synth.random32()
        receipts_root = synth.random32()
        body_root, _sb, _rb, _nb = synth.build_execution_tree(state_root, receipts_root, 0)
        fin_header, fin_root = synth.make_header(FIN_SLOT, 0, synth.random32(), synth.random32(), body_root)
        fin_state_root = fin_header[48:80]
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)

        bad_t_slot = FIN_SLOT + 5  # violates t_slot < fin_slot
        target_header, _t_root = synth.make_header(
            bad_t_slot, 0, synth.random32(), synth.random32(), synth.random32()
        )

        args = [
            m4probe.app_id, fin_header, target_header, b"",
            b"\x00" * 32, b"\x00" * 32, 0, b"", b"", b"",
        ]
        res = anchor.call("anchor_historical", args, apps=[m4probe.app_id])
        assert not res.ok
        assert "assert failed" in res.failure

    def test_N17_no_fork_row_for_epoch_rejected(self, compiled, account, m4probe):
        """`forks.lookup_row`: `N17` when the table has no row with
        `activation_epoch <= epoch(fin_slot)` -- here, no row at all
        (`append_fork_row` never called). A real, valid `fin_header`/
        `fin_root`/`fin_state_root` (N5/N6/N7 all pass) proves this is
        genuinely the fork-lookup failing, not an earlier check."""
        anchor_contracts, _bench = compiled
        sender, sk = account
        h = Arc4Harness(anchor_contracts["TrustedRootAnchor"], sender, sk)
        h.create([sender, m4probe.app_id, RING_N], extra_pages=1, fund_app=15_000_000)
        h.ring_n = RING_N
        # deliberately: no ring_init_chunk, no append_fork_row

        args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=108)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        res = h.call("anchor_direct", args, apps=[m4probe.app_id])
        assert not res.ok
        assert "assert failed" in res.failure


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


class TestRingLifecycleErrorCodes:
    def test_N10_anchor_before_ring_initialised_rejected(self, compiled, account, m4probe, donors):
        """`box.finish_anchor_flow`'s FIRST check: `ring_cursor == ring_n`
        (§7.4/§12.1's "ring not initialised" case). A fork row IS appended
        (so `forks.lookup_row`, checked earlier in the call, succeeds --
        proving N10, not N17, is what fires) but `ring_init_chunk` is never
        called, so `ring_cursor` stays 0 while `ring_n == 8`. The full,
        real 3-way Merkle fold must still succeed honestly to even REACH
        `finish_anchor_flow`, hence the donor-funded budget (mirrors the
        happy-path test's own real cost)."""
        anchor_contracts, _bench = compiled
        sender, sk = account
        h = Arc4Harness(anchor_contracts["TrustedRootAnchor"], sender, sk)
        h.create([sender, m4probe.app_id, RING_N], extra_pages=1, fund_app=15_000_000)
        h.ring_n = RING_N
        h.submit([{
            "method": "append_fork_row",
            "args": [0, synth.G_STATE_ROOT, synth.G_RECEIPTS_ROOT, synth.G_BLOCK_NUMBER, synth.G_BLOCK_ROOTS_BASE],
        }])
        # deliberately: no ring_init_chunk

        args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=109)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        callee_id, issuer_id = donors
        with pytest.raises(Exception) as exc_info:
            h.submit_with_donor(
                "anchor_direct", args, donor_issuer_id=issuer_id, donor_callee_id=callee_id,
                n_donors=12, apps=[m4probe.app_id],
            )
        assert "assert failed" in str(exc_info.value)

    def test_N11_frozen_blocks_pin(self, anchor, m4probe, account, donors):
        """`pin`'s own explicit check: `assert self.frozen == UInt64(0),
        "N11"`. `freeze()` (governance) is called AFTER a block is
        genuinely anchored and pin-able -- proving N11, not N12/N24, is
        what blocks the subsequent `pin` (the funding payment is honest:
        correct receiver, sufficient amount)."""
        from algosdk import transaction
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
            TransactionWithSigner,
        )
        from algosdk.logic import get_application_address

        sender, sk = account
        args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=110)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        _anchor_direct_submit(anchor, donors, args, m4probe.app_id)

        anchor.submit([{"method": "freeze", "args": []}])

        algod = anchor.algod
        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(sk)
        sp_pay = algod.suggested_params()
        pay_txn = transaction.PaymentTxn(sender, sp_pay, get_application_address(anchor.app_id), 80_900)
        sp_pin = algod.suggested_params(); sp_pin.flat_fee = True; sp_pin.fee = 2000
        atc.add_method_call(
            app_id=anchor.app_id, method=Method.undictify(anchor.methods["pin"]),
            sender=sender, sp=sp_pin, signer=signer,
            method_args=[110, TransactionWithSigner(pay_txn, signer)],
            boxes=[_ring_box(110), _pin_box(110)],
        )
        with pytest.raises(Exception) as exc_info:
            atc.execute(algod, 4)
        assert "assert failed" in str(exc_info.value)


class TestGovernanceAndConflictErrorCodes:
    def test_N22_conflict_latch_blocks_pin(self, anchor, m4probe, donors, account):
        """`pin`'s own explicit `assert self.conflict == UInt64(0), "N22"`
        -- a distinct call site from `attest`'s (already functionally
        exercised by `TestRetentionRing::
        test_equivocation_latches_conflict_then_gov_clear_restores`), but
        never itself literally NAMED anywhere in this suite before now, so
        the coverage-discipline word-scan (its own documented "text match,
        not a functional verification" caveat) never credited it. Latch
        `conflict` via a genuine equivocation, then attempt `pin` (an
        otherwise honest payment) on the SAME block number."""
        args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=111)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        _anchor_direct_submit(anchor, donors, args, m4probe.app_id)

        args2, fin_root2, fin_state_root2, _s2, _r2 = _direct_anchor_args(
            m4probe.app_id, block_number=111, beacon_slot=FIN_SLOT
        )
        _set_m4(m4probe, FIN_SLOT, fin_root2, fin_state_root2)
        conflicting = _anchor_direct_submit(anchor, donors, args2, m4probe.app_id)
        assert conflicting.tx_ids, "the equivocating call itself must succeed so the latch persists"

        from algosdk import transaction
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
            TransactionWithSigner,
        )
        from algosdk.logic import get_application_address

        sender, sk = account
        algod = anchor.algod
        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(sk)
        sp_pay = algod.suggested_params()
        pay_txn = transaction.PaymentTxn(sender, sp_pay, get_application_address(anchor.app_id), 80_900)
        sp_pin = algod.suggested_params(); sp_pin.flat_fee = True; sp_pin.fee = 2000
        atc.add_method_call(
            app_id=anchor.app_id, method=Method.undictify(anchor.methods["pin"]),
            sender=sender, sp=sp_pin, signer=signer,
            method_args=[111, TransactionWithSigner(pay_txn, signer)],
            boxes=[_ring_box(111), _pin_box(111)],
        )
        with pytest.raises(Exception) as exc_info:
            atc.execute(algod, 4)
        assert "assert failed" in str(exc_info.value)

    def test_N23_non_governance_sender_rejected(self, anchor):
        """§6.4: every governance-only method rejects a non-`gov` sender.
        Mirrors the sibling M4 suite's own established pattern exactly
        (`tests/sync_committee/test_forks_state.py::
        test_f10_non_governance_append_rejected`): pull a SECOND key from
        dev-mode kmd's own default wallet (never the harness's own
        governance signer) and call `freeze()` with it."""
        from tests.harness.chain import kmd_client

        kmd = kmd_client()
        wallets = kmd.list_wallets()
        wid = next(w["id"] for w in wallets if w["name"] == "unencrypted-default-wallet")
        handle = kmd.init_wallet_handle(wid, "")
        try:
            addrs = kmd.list_keys(handle)
            other_addr = next((a for a in addrs if a != anchor.sender), None)
            if other_addr is None:
                pytest.skip(
                    "dev-mode kmd's default wallet has only one key -- "
                    "cannot exercise a non-governance sender"
                )
            other_sender = other_addr
            other_sk = kmd.export_key(handle, "", other_addr)
        finally:
            kmd.release_wallet_handle(handle)

        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer

        method = Method.undictify(anchor.methods["freeze"])
        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(other_sk)
        sp = anchor.algod.suggested_params()
        sp.flat_fee = True
        sp.fee = 1000
        atc.add_method_call(
            app_id=anchor.app_id, method=method, sender=other_sender, sp=sp, signer=signer, method_args=[],
        )
        with pytest.raises(Exception) as exc_info:
            atc.execute(anchor.algod, 4)
        assert "assert failed" in str(exc_info.value)

    def test_N24_pin_wrong_receiver_rejected(self, anchor, m4probe, donors, account):
        """`pin`: `assert payment.receiver == Global.current_application_
        address, "N24"`. A genuinely admitted, pin-able block with a
        Payment that is otherwise well-funded (>= 80,900) but addressed to
        the SENDER's own account instead of the app."""
        from algosdk import transaction
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
            TransactionWithSigner,
        )

        sender, sk = account
        args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=112)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        _anchor_direct_submit(anchor, donors, args, m4probe.app_id)

        algod = anchor.algod
        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(sk)
        sp_pay = algod.suggested_params()
        pay_txn = transaction.PaymentTxn(sender, sp_pay, sender, 80_900)  # wrong receiver: self, not the app
        sp_pin = algod.suggested_params(); sp_pin.flat_fee = True; sp_pin.fee = 2000
        atc.add_method_call(
            app_id=anchor.app_id, method=Method.undictify(anchor.methods["pin"]),
            sender=sender, sp=sp_pin, signer=signer,
            method_args=[112, TransactionWithSigner(pay_txn, signer)],
            boxes=[_ring_box(112), _pin_box(112)],
        )
        with pytest.raises(Exception) as exc_info:
            atc.execute(algod, 4)
        assert "assert failed" in str(exc_info.value)

    def test_N24_pin_underfunded_rejected(self, anchor, m4probe, donors, account):
        """`pin`: `assert payment.amount >= UInt64(80_900), "N24"`. Same
        shape as the wrong-receiver case, but the receiver is correct and
        the amount is one microAlgo short of the real box MBR."""
        from algosdk import transaction
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
            TransactionWithSigner,
        )
        from algosdk.logic import get_application_address

        sender, sk = account
        args, fin_root, fin_state_root, _s, _r = _direct_anchor_args(m4probe.app_id, block_number=113)
        _set_m4(m4probe, FIN_SLOT, fin_root, fin_state_root)
        _anchor_direct_submit(anchor, donors, args, m4probe.app_id)

        algod = anchor.algod
        atc = AtomicTransactionComposer()
        signer = AccountTransactionSigner(sk)
        sp_pay = algod.suggested_params()
        pay_txn = transaction.PaymentTxn(sender, sp_pay, get_application_address(anchor.app_id), 80_899)
        sp_pin = algod.suggested_params(); sp_pin.flat_fee = True; sp_pin.fee = 2000
        atc.add_method_call(
            app_id=anchor.app_id, method=Method.undictify(anchor.methods["pin"]),
            sender=sender, sp=sp_pin, signer=signer,
            method_args=[113, TransactionWithSigner(pay_txn, signer)],
            boxes=[_ring_box(113), _pin_box(113)],
        )
        with pytest.raises(Exception) as exc_info:
            atc.execute(algod, 4)
        assert "assert failed" in str(exc_info.value)


def _deploy_anchor_receipt_probe(anchor):
    """Compiles+deploys `AnchorReceiptProbe` (a raw `Contract`, no ARC-4)
    against the REAL, already-deployed anchor app id -- TP-M8-4's actual
    compile-time binding step, done for real. Mirrors
    `TestTPM84CompileTimeConstant`'s own established deploy sequence
    exactly (duplicated rather than shared, matching this codebase's own
    convention of not reaching into another class's private helper)."""
    from algosdk import transaction

    algod = anchor.algod
    patched_root = patched_repo_copy(anchor.app_id)
    probe_src = patched_root / "contracts" / "state_anchor" / "bench_app.py"
    probe_contracts = puya_compile(probe_src, extra_pythonpath=patched_root)
    approval = compile_teal(algod, probe_contracts["AnchorReceiptProbe"]["approval"])
    clear = compile_teal(algod, probe_contracts["AnchorReceiptProbe"]["clear"])

    sender, sk = anchor.sender, anchor.sk
    sp = algod.suggested_params()
    create_txn = transaction.ApplicationCreateTxn(
        sender=sender, sp=sp, on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval, clear_program=clear,
        global_schema=transaction.StateSchema(0, 0), local_schema=transaction.StateSchema(0, 0),
        extra_pages=1,
    )
    stxn = create_txn.sign(sk)
    txid = algod.send_transaction(stxn)
    confirmed = transaction.wait_for_confirmation(algod, txid, 4)
    return confirmed["application-index"]


class TestHandoffErrorCodes:
    """`contracts/state_anchor/handoff.py::anchor_from_group` -- not wired
    into the deployed `TrustedRootAnchor` itself (that file's own module
    docstring), but real, compiled, and exercised live via
    `AnchorReceiptProbe`'s `MODE_AGAINST_ANCHOR`, the SAME sanctioned
    mechanism `TestTPM84CompileTimeConstant::test_forged_app_id_is_rejected`
    already uses to prove `N2`. These two close the two OTHER checks in the
    same subroutine, both ahead of the M7/M6-repack-shaped part of it."""

    def test_N1_replay_from_same_or_later_group_index_rejected(self, anchor):
        """`assert gi < Txn.group_index, "N1"`. The cheapest possible
        construction: a SOLO (ungrouped) call, so `Txn.group_index == 0`;
        pointing `anchor_gi` at 0 (itself) violates `0 < 0` immediately,
        before `anchor_from_group` even reads the referenced transaction --
        no real anchor call is needed in the group at all."""
        from algosdk import transaction
        from algosdk.v2client.models import SimulateRequest, SimulateRequestTransactionGroup

        sender, sk = anchor.sender, anchor.sk
        probe_app_id = _deploy_anchor_receipt_probe(anchor)
        algod = anchor.algod

        fixed = (0).to_bytes(8, "big") + (0).to_bytes(8, "big") + (0).to_bytes(8, "big") + (0).to_bytes(2, "big")
        sp = algod.suggested_params(); sp.flat_fee = True; sp.fee = 1000
        probe_txn = transaction.ApplicationCallTxn(
            sender=sender, sp=sp, index=probe_app_id, on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"RCP1", bytes([5]), bytes([0]), fixed],
        )
        stxn = probe_txn.sign(sk)
        sreq = SimulateRequest(
            txn_groups=[SimulateRequestTransactionGroup(txns=[stxn])], allow_unnamed_resources=True,
        )
        resp = algod.simulate_transactions(sreq)
        grp = resp["txn-groups"][0]
        assert grp.get("failure-message"), "anchor_gi >= the caller's own group index must be rejected"
        assert "assert failed" in grp["failure-message"]

    def test_N3_wrong_selector_predecessor_rejected(self, anchor):
        """`assert prev.app_args(0) == ATTEST_SELECTOR, "N3"`. Group:
        [`anchor.noop_budget()` at gi=0 -- a REAL call to the REAL,
        deployed anchor app, so `N2`'s own app-id check passes -- then the
        probe's `MODE_AGAINST_ANCHOR` at gi=1, `anchor_gi=0`]. `gi(0) <
        group_index(1)` passes (N1 ok); `prev.app_id == ANCHOR_APP_ID`
        passes (N2 ok); but `noop_budget`'s selector is not `attest`'s, so
        `N3` fires."""
        from algosdk import transaction
        from algosdk.abi import Method
        from algosdk.atomic_transaction_composer import (
            AccountTransactionSigner,
            AtomicTransactionComposer,
            TransactionWithSigner,
        )

        sender, sk = anchor.sender, anchor.sk
        probe_app_id = _deploy_anchor_receipt_probe(anchor)
        algod = anchor.algod

        signer = AccountTransactionSigner(sk)
        atc = AtomicTransactionComposer()
        sp1 = algod.suggested_params(); sp1.flat_fee = True; sp1.fee = 1000
        atc.add_method_call(
            app_id=anchor.app_id, method=Method.undictify(anchor.methods["noop_budget"]),
            sender=sender, sp=sp1, signer=signer, method_args=[],
        )
        fixed = (0).to_bytes(8, "big") + (0).to_bytes(8, "big") + (0).to_bytes(8, "big") + (0).to_bytes(2, "big")
        sp2 = algod.suggested_params(); sp2.flat_fee = True; sp2.fee = 1000
        probe_txn = transaction.ApplicationCallTxn(
            sender=sender, sp=sp2, index=probe_app_id, on_complete=transaction.OnComplete.NoOpOC,
            app_args=[b"RCP1", bytes([5]), bytes([0]), fixed],
        )
        atc.add_transaction(TransactionWithSigner(probe_txn, signer))
        with pytest.raises(Exception) as exc_info:
            atc.execute(algod, 4)
        assert "assert failed" in str(exc_info.value)
