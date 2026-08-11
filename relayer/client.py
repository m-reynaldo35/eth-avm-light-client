"""`EthAvmClient` (design doc §8.2) -- the facade. Five verbs: `sync`
(M4), `anchor` (M8), `prove_account` (M6), `prove_receipt` (M7, +M8),
`status` (read-only, free). This is the ONLY class M10/M11/the x402
service are meant to import from `relayer` directly (§8.1: "the CLI never
reaches past `EthAvmClient`").
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Literal

from algosdk import logic, mnemonic, transaction
from algosdk.account import address_from_private_key
from algosdk.atomic_transaction_composer import (
    AccountTransactionSigner,
    AtomicTransactionComposer,
    TransactionWithSigner,
)
from algosdk.v2client import algod

from relayer.config import RelayerConfig
from relayer.drivers import m4_sync_committee as m4
from relayer.drivers import m6_account_storage as m6  # noqa: F401 -- re-exported for callers building M6 groups
from relayer.drivers import m7_receipt as m7
from relayer.drivers import m8_anchor as m8
from relayer.errors import RetryReplanned, TierUnsupported
from relayer.group.boxes import key_box_name, m4_retire_box_sizes, plan_box_refs, session_box_name, total_box_name
from relayer.group.donors import donor_transaction_with_signer
from relayer.group.submit import run as submit_run
from relayer.proofs import account as account_proof
from relayer.proofs import classify
from relayer.proofs.receipts_trie import build_receipts_trie_and_path
from relayer.sources import beacon
from relayer.sources.eth_rpc import get_block_header, get_block_receipts, get_proof


@dataclass
class Status:
    m4_finalized: dict | None
    m8_anchor: dict | None


@dataclass
class SyncResult:
    ok: bool
    detail: dict


@dataclass
class AnchorResult:
    ok: bool
    mode: str
    record: dict


@dataclass
class AccountResult:
    status: str
    balance: int | None
    slot_value: bytes | None
    fields: dict | None = None
    confirmed_round: int | None = None
    tx_ids: list | None = None


@dataclass
class ReceiptResult:
    rstatus_name: str
    fields: dict
    confirmed_round: int | None = None
    tx_ids: list | None = None


class EthAvmClient:
    def __init__(self, config: RelayerConfig) -> None:
        self.config = config
        self.algod = algod.AlgodClient(config.algod_token, config.algod_url)
        self._sender = None
        self._sk = None
        if config.has_signer:
            self._sk = mnemonic.to_private_key(config.signer_mnemonic)
            self._sender = address_from_private_key(self._sk)

    # ------------------------------------------------------------------
    # status() -- readonly, free (§8.2: "get_anchor before planning")
    # ------------------------------------------------------------------
    def status(self) -> Status:
        m4_state = None
        if self.config.m4_app_id:
            try:
                m4_state = self._read_global_state(self.config.m4_app_id)
            except Exception:  # noqa: BLE001
                m4_state = None
        m8_state = None
        if self.config.m8_app_id:
            try:
                m8_state = self._read_global_state(self.config.m8_app_id)
            except Exception:  # noqa: BLE001
                m8_state = None
        return Status(m4_finalized=m4_state, m8_anchor=m8_state)

    def _read_global_state(self, app_id: int) -> dict:
        """`{decoded_key_bytes: int | bytes}` -- uint fields decoded as
        `int`, byte-slice fields decoded (from base64) as `bytes`. Used by
        every driver below to read M4's `inst_state`/`inst_cursor`/
        `inst_gen`/`cur_gen`/`fin_slot` (§9.1's "the on-chain state machine
        IS the checkpoint") and M8's `ring_size` -- never a local file."""
        app = self.algod.application_info(app_id)
        out: dict = {}
        for kv in app["params"].get("global-state", []):
            key = base64.b64decode(kv["key"])
            v = kv["value"]
            out[key] = v["uint"] if v.get("type") == 2 else base64.b64decode(v.get("bytes", ""))
        return out

    def _signer(self) -> AccountTransactionSigner:
        return AccountTransactionSigner(self._sk)

    def _require_signer_and_donors(self, verb: str) -> None:
        if not self.config.has_signer:
            raise ValueError(f"{verb} needs a signer configured to submit a real group")
        if self.config.donor_issuer_id is None or self.config.donor_callee_id is None:
            raise ValueError(f"{verb} needs donor_issuer_id/donor_callee_id configured (§7.1 DonorIssuer sibling)")

    # ------------------------------------------------------------------
    # anchor() -- M8
    # ------------------------------------------------------------------
    def anchor(self, block: int | Literal["latest"] = "latest", *, mode: str = "auto",
               t_slot_offset: int = 6000, dry_run: bool = False) -> AnchorResult:
        """§6.5's DIRECT/HISTORICAL decision, then a real
        `[DonorIssuer, anchor_direct|anchor_historical]` group, reusing the
        exact real branch-building logic promoted into `relayer.ssz`/
        `relayer.drivers.m8_anchor` (§6.4/§6.5).

        `block`: `"latest"` anchors the CURRENT finalized EL block (DIRECT,
        unless `mode="historical"` is forced). Any other value is treated
        as a target BEACON SLOT for the HISTORICAL `block_roots` fold --
        this project has no EL-block-number -> beacon-slot resolver
        anywhere (not even in the live test suite HISTORICAL mode's own
        fixture builder, which always picks T_SLOT directly, §6.5's own
        `t_slot = fin_slot - T_SLOT_OFFSET` convention); building one is
        real, additional scope this pass does not add, stated here rather
        than silently assumed away."""
        self._require_signer_and_donors("anchor()")
        if self.config.m4_app_id is None or self.config.m8_app_id is None:
            raise ValueError("anchor() needs both m4_app_id and m8_app_id configured")

        fu_now = beacon.fetch_finality_update()
        fu_now_args = m4.transform_finality_update(fu_now)

        want_direct = block == "latest" and mode != "historical"
        if want_direct:
            fixture = m8.build_direct_fixture(fu_now, fu_now_args)
        else:
            from relayer.sources.cache import DiskCache

            cache = DiskCache(self.config.cache_dir) if self.config.cache_dir else DiskCache()
            fin_slot = int.from_bytes(fu_now_args.finalized_header[0:8], "little")
            offset = t_slot_offset if block == "latest" else max(0, fin_slot - int(block))
            fixture = m8.build_historical_fixture(fu_now_args, offset, cache=cache)

        record = self._submit_anchor(fixture, dry_run=dry_run)
        return AnchorResult(ok=True, mode=fixture["mode"].name, record=record)

    def _m8_ring_n(self) -> int:
        gs = self._read_global_state(self.config.m8_app_id)
        return gs[b"ring_size"]

    def _submit_anchor(self, fixture: dict, *, dry_run: bool) -> dict:
        signer = self._signer()
        m4_app_id = self.config.m4_app_id
        m8_app_id = self.config.m8_app_id
        anchor_mode = fixture["mode"]
        ring_n = self._m8_ring_n()

        if anchor_mode is m8.AnchorMode.DIRECT:
            method_name = "anchor_direct"
            method_args = [
                m4_app_id, fixture["fin_header"], fixture["el_state_root"], fixture["el_receipts_root"],
                fixture["el_block_number"], fixture["state_branch"], fixture["receipts_branch"],
                fixture["number_branch"],
            ]
        else:
            method_name = "anchor_historical"
            method_args = [
                m4_app_id, fixture["fin_header"], fixture["target_header"], fixture["block_roots_branch"],
                fixture["el_state_root"], fixture["el_receipts_root"], fixture["el_block_number"],
                fixture["state_branch"], fixture["receipts_branch"], fixture["number_branch"],
            ]
        boxes = m8.auto_boxes_for(method_name, fixture["el_block_number"], ring_n)

        def build_group(n_donors: int):
            atc = AtomicTransactionComposer()
            atc.add_transaction(donor_transaction_with_signer(
                self.algod, self._sender, self._sk, self.config.donor_issuer_id, self.config.donor_callee_id,
                n_donors,
            ))
            sp = self.algod.suggested_params()
            sp.flat_fee = True
            sp.fee = 1000
            atc.add_method_call(
                app_id=m8_app_id, method=m8.METHODS[method_name], sender=self._sender, sp=sp, signer=signer,
                method_args=method_args, foreign_apps=[m4_app_id], boxes=boxes,
            )
            return atc

        try:
            result = submit_run(self.algod, build_group, n_app_calls_in_group=2, dry_run=dry_run)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            # §18 item 8 / §8.5: M8's N6 (fin header changed between plan and
            # submit) is "normal, not exceptional" (008 §12.4) -- classified
            # RETRY_REPLANNED, never a bare exception, so a caller's retry
            # loop can tell "the chain moved, replan" apart from a real bug.
            if "N6" in msg or method_name == "anchor_direct":
                raise RetryReplanned(
                    f"{method_name} rejected (fin header likely advanced since plan time, N6-shaped): {exc}"
                ) from exc
            raise
        if dry_run:
            return {"dry_run": True, "n_donors": result.n_donors, "measured_consumed": result.measured_consumed}
        if not result.logs:
            raise RuntimeError("no log produced by the anchor call")
        payload = result.logs[-1][4:]  # M8_ATTEST envelope: 0x151f7c75 || A(154), no length field (§7.8)
        assert len(payload) == 154
        return {
            "el_block_number": fixture["el_block_number"], "t_slot": fixture["t_slot"],
            "el_state_root": fixture["el_state_root"].hex(), "el_receipts_root": fixture["el_receipts_root"].hex(),
            "record_hex": payload.hex(), "tx_ids": result.tx_ids, "confirmed_round": result.confirmed_round,
            "n_donors": result.n_donors, "measured_consumed": result.measured_consumed,
        }

    # ------------------------------------------------------------------
    # prove_account() -- M6
    # ------------------------------------------------------------------
    def prove_account(self, address: str, slot_hex: str, block: int | Literal["latest"] = "latest") -> AccountResult:
        """Real, non-simulated submission against `Mpt6ComposerApp`
        (design doc §6/§7): fetches the block header (for `R_state`, TP-
        M6-1 -- the caller must not blindly trust a root derived from the
        proof's own first node, §1.3's own honest caveat about
        `segment_account_proof`'s fallback) and the real `eth_getProof`
        response, segments it into M6's raw wire calls
        (`relayer.proofs.account.segment_account_proof` /
        `relayer.drivers.m6_account_storage.plan_composer_calls`), submits
        the ONE atomic group via the shared `relayer.group.submit.run`
        loop, and validates the terminal result against TP-M6-3 before
        returning it (`m6.verify_terminal_result`, the off-chain analogue
        of `mpt6_result_from_group`'s A17/A18 asserts -- this client is
        exactly the "M9 off-chain client" §6.6/§13.3 say must perform that
        check, since nothing on-chain does it here in v1 without an M8
        anchor)."""
        if self.config.m6_app_id is None:
            raise ValueError("prove_account() needs m6_app_id configured")
        if not self.config.has_signer:
            raise ValueError("prove_account() needs a signer configured to submit a real group")
        # §7.1/§6.2: M6's contract is SELF_ISSUED (BudgetConvention.
        # SELF_ISSUED, relayer/group/budget.py) -- every segment's OWN
        # `_issue_donors` call raises the group's shared pool, so unlike
        # M4/M7/M8's DONOR_SIBLING convention this needs only a bare
        # callee app (`donor_callee_id`), never a `DonorIssuer` sibling
        # transaction (`donor_issuer_id` is not read below).
        if self.config.donor_callee_id is None:
            raise ValueError(
                "prove_account() needs donor_callee_id configured (M6's SELF_ISSUED donor "
                "convention, design doc §7.1 -- no DonorIssuer sibling needed, unlike M4/M7/M8)"
            )

        header = get_block_header(block)
        state_root = bytes.fromhex(header["stateRoot"][2:])
        resp = get_proof(address, [slot_hex], block)
        return self._submit_account_proof(resp, state_root)

    def _submit_account_proof(self, resp: dict, declared_state_root: bytes) -> AccountResult:
        """Builds and submits the real, one-atomic-group `Mpt6ComposerApp`
        call sequence for one `eth_getProof` response (§6.5's real
        5-transaction USDT/Binance-8 shape when both phases run; fewer
        segments -- and NO phase-B segments at all -- for the account-
        absent/empty-storage-trie cases, §8.1/§9.1, exactly matching what
        `segment_account_proof` already decided offline).

        §6.5's own finding ("All donors are issued in transaction 0,
        before any walk work") is followed literally: `plan_composer_calls`
        bakes the SAME scalar `donor_count` into every segment's own args
        (each mode's `_issue_donors` call would otherwise fire on every
        segment independently), so this method plans with `donor_count=0`
        and then patches ONLY segment 0's `donor_count` arg once sizing is
        known -- concentrating every donor call in the one transaction
        that runs before any node-walking work, rather than redundantly
        re-donating on every later segment."""
        signer = self._signer()
        segs = account_proof.segment_account_proof(resp, declared_state_root=declared_state_root)
        donor_app_id = self.config.donor_callee_id
        calls = m6.resolve_prev_gi(
            m6.plan_composer_calls(segs, donor_app_id=donor_app_id, donor_count=0), group_offset=0
        )

        def build_group(n_donors: int):
            atc = AtomicTransactionComposer()
            for i, call in enumerate(calls):
                sp = self.algod.suggested_params()
                sp.flat_fee = True
                args = list(call.args)
                kwargs = {}
                if i == 0:
                    sp.fee = (n_donors + 1) * 1000
                    if n_donors > 0:
                        args[2] = n_donors.to_bytes(8, "big")
                        kwargs["foreign_apps"] = [donor_app_id]
                else:
                    sp.fee = 1000
                txn = transaction.ApplicationCallTxn(
                    sender=self._sender, sp=sp, index=self.config.m6_app_id,
                    on_complete=transaction.OnComplete.NoOpOC, app_args=args, **kwargs,
                )
                atc.add_transaction(TransactionWithSigner(txn, signer))
            return atc

        result = submit_run(self.algod, build_group, n_app_calls_in_group=len(calls), dry_run=False)
        if not result.logs:
            raise m6.M6Error("no log produced by the M6 composite result")
        decoded = m6.decode_result_from_log(result.logs[-1])
        # TP-M6-3, load-bearing (§5.4's substitution attack, §6.6): refuse
        # to believe `decoded["value"]` until the terminal result's own
        # self-described (state_root, address, slot) header is checked
        # against what THIS call actually asked for.
        m6.verify_terminal_result(decoded, declared_state_root, segs.address, segs.slot)
        decoded["confirmed_round"] = result.confirmed_round
        decoded["measured_consumed"] = result.measured_consumed
        status = m6.CSTATUS_NAMES.get(decoded["cstatus"], f"unknown({decoded['cstatus']})")
        # §8.1: C_ABSENT_ACCOUNT has no storage trie to speak of at all
        # (§1.2's non-goal, no phase-B segment was ever issued) -- every
        # OTHER terminal code (C_INCLUDED/C_ABSENT_SLOT/
        # C_ABSENT_SLOT_EMPTY_TRIE/C_ZERO_ENTRY) carries a real, meaningful
        # 32-byte value per §6.4's table, even when that value is zero.
        slot_value = None if status == "C_ABSENT_ACCOUNT" else bytes.fromhex(decoded["value"])
        return AccountResult(
            status=status, balance=decoded["balance"], slot_value=slot_value, fields=decoded,
            confirmed_round=result.confirmed_round, tx_ids=result.tx_ids,
        )

    # ------------------------------------------------------------------
    # prove_receipt() -- M7 (+M8)
    # ------------------------------------------------------------------
    def prove_receipt(self, block: int, tx_index: int, log_index: int, *, against_anchor: bool = False) -> ReceiptResult:
        # `against_anchor=True` drives `Mpt7AnchoredReceiptApp` (permanent,
        # manifest-pinned, both T1 and T2 since this pass -- 014 §4.1's
        # deferred T1 migration, closed), never the configured `m7_app_id`
        # -- so m7_app_id is only required on the RPC-rooted path below.
        if not against_anchor and self.config.m7_app_id is None:
            raise ValueError("prove_receipt() needs m7_app_id configured")
        if against_anchor and self.config.m8_app_id is None:
            raise ValueError("against_anchor=True needs m8_app_id configured")
        if against_anchor and self.config.m7_anchored_app_id is None:
            raise ValueError(
                "against_anchor=True needs m7_anchored_app_id configured (the deployed "
                "Mpt7AnchoredReceiptApp -- docs/design/014-t2-against-anchor.md §4.1/§9; "
                "this pass migrated the T1 path onto it too)"
            )
        # §11's last paragraph, §18 item 11 (normative, security-adjacent):
        # "never re-derive receipts_root from RPC and pass it to M7 when an
        # M8 anchor is available... if M9 is configured with an m8_app_id,
        # prove_receipt MUST use the anchored path; falling back to the
        # RPC-supplied root silently would reintroduce exactly the gap
        # 83b4fb8 closed." An operator who configured m8_app_id but calls
        # prove_receipt without against_anchor=True is refused loudly here,
        # not silently downgraded to the untrusted RPC-rooted path (S-1).
        if self.config.m8_app_id is not None and not against_anchor:
            raise ValueError(
                "m8_app_id is configured but against_anchor=False -- refusing to build an "
                "RPC-rooted receipt proof when a trustless anchored path is available "
                "(§11, S-1). Pass against_anchor=True explicitly."
            )

        header = get_block_header(block)
        receipts = get_block_receipts(block)
        receipts_root_hex = header["receiptsRoot"]
        root_hash, nodes = build_receipts_trie_and_path(receipts, tx_index)
        assert "0x" + root_hash.hex() == receipts_root_hex, (
            "reconstructed receiptsRoot does not match the RPC block header -- a real integrity problem"
        )
        leaf = nodes[-1]
        cls_result = classify.classify(leaf)
        if cls_result.tier == "T3_UNSUPPORTED":
            raise TierUnsupported(
                f"leaf {cls_result.leaf_len} B needs T3/ZK proving, out of v1 scope (§1.2)"
            )

        if against_anchor:
            self._require_signer_and_donors("prove_receipt(against_anchor=True)")
            el_block_number = int(header["number"], 16)
            if cls_result.tier == "T2":
                return self._submit_t2_receipt_against_anchor(root_hash, tx_index, log_index, nodes, el_block_number)
            return self._submit_receipt_against_anchor(root_hash, tx_index, log_index, nodes, el_block_number)

        if cls_result.tier == "T2":
            self._require_signer_and_donors("prove_receipt() T2")
            el_block_number = int(header["number"], 16)
            return self._submit_t2_receipt(root_hash, tx_index, log_index, nodes, el_block_number)

        if not self.config.has_signer:
            raise ValueError("prove_receipt() needs a signer configured to submit a real T1 group")
        if self.config.donor_issuer_id is None or self.config.donor_callee_id is None:
            raise ValueError("prove_receipt() needs donor_issuer_id/donor_callee_id configured (§7.1 DonorIssuer sibling)")

        return self._submit_t1_receipt(root_hash, tx_index, log_index, nodes)

    def _submit_t1_receipt(self, receipts_root: bytes, tx_index: int, log_index: int, nodes: list[bytes]) -> ReceiptResult:
        """§18 item 5: a `DonorIssuer` sibling, never 8 filler NoOps.
        Real `simulate(n_donors=1) -> size -> simulate -> send` loop
        (§7.7), reusing `relayer.group.submit.run` -- the SAME loop every
        other driver uses, not a bespoke one for M7."""
        signer = self._signer()

        _tier, calls = m7.plan_receipt_calls(receipts_root, tx_index, log_index, nodes, group_offset=1)

        def build_group(n_donors: int):
            atc = AtomicTransactionComposer()
            atc.add_transaction(donor_transaction_with_signer(
                self.algod, self._sender, self._sk, self.config.donor_issuer_id, self.config.donor_callee_id, n_donors
            ))
            for call in calls:
                sp = self.algod.suggested_params()
                sp.flat_fee = True
                sp.fee = 1000
                kwargs = {}
                if call.boxes:
                    kwargs["boxes"] = [transaction.BoxReference(0, b) for b in call.boxes]
                txn = transaction.ApplicationCallTxn(
                    sender=self._sender, sp=sp, index=self.config.m7_app_id,
                    on_complete=transaction.OnComplete.NoOpOC, app_args=call.args, **kwargs,
                )
                atc.add_transaction(TransactionWithSigner(txn, signer))
            return atc

        # +1: the DonorIssuer transaction is itself an application call and
        # contributes its own 700 base budget (matches
        # `test_live_historical.py:719`'s own real formula, base = 700 *
        # ALL app calls in the group including the donor).
        result = submit_run(self.algod, build_group, n_app_calls_in_group=len(calls) + 1, dry_run=False)
        if not result.logs:
            raise m7.M7Error("no log produced by the result transaction")
        decoded = m7.decode_r(result.logs[-1])
        decoded["confirmed_round"] = result.confirmed_round
        decoded["measured_consumed"] = result.measured_consumed
        return ReceiptResult(
            rstatus_name=decoded["rstatus_name"], fields=decoded,
            confirmed_round=result.confirmed_round, tx_ids=result.tx_ids,
        )

    def _t2_payment_amount(self, app_address: str, leaf_len: int) -> int:
        """014 §3.6/§5.3: pay only the REAL shortfall against a live
        `account_info` read, never the full box-MBR figure unconditionally
        -- §3.6's own measured finding was that the old unconditional
        payment stranded 5.53 ALGO of recoverable float in the app account
        across three consecutive proofs. Returns 0 once a prior call's
        float already covers `m7.t2_box_mbr_requirement(leaf_len)`."""
        info = self.algod.account_info(app_address)
        required = m7.t2_box_mbr_requirement(leaf_len)
        return max(0, required - info["amount"])

    def _submit_t2_receipt(self, receipts_root: bytes, tx_index: int, log_index: int, nodes: list[bytes],
                            el_block_number: int) -> ReceiptResult:
        """T2 (box-staged) real submission (§12, G5-M9): a `DonorIssuer`
        sibling (§18 item 5, MUST #5 -- never 8 filler NoOps here either),
        a `PaymentTxn` funding the oversized leaf's box MBR to the APP
        ACCOUNT (not the sender, §12's real finding) in the SAME group
        before `MODE_STAGE_OPEN`, then the real
        `relayer.group.submit.run` loop. Targets the design doc's own
        §7.1 finding: with a donor sibling instead of 8 fillers, T2 cache-
        miss drops from 17 txns to <=10.

        014 §5.2/§5.3: the box name now carries a block component and a
        random nonce (`m7.derive_t2_box_name`, not a deterministic function
        of `(tx_index, log_index)` alone -- squattable ahead of time,
        measured), and the `PaymentTxn` amount is conditional on a real
        `account_info` read (`_t2_payment_amount`), not unconditional."""
        signer = self._signer()
        box_name = m7.derive_t2_box_name(el_block_number)
        _tier, calls, box_name, _static_fund_amount = m7.plan_receipt_calls_t2(
            receipts_root, tx_index, log_index, nodes, box_name, group_offset=2
        )
        app_address = logic.get_application_address(self.config.m7_app_id)
        leaf_len = len(nodes[-1])

        def build_group(n_donors: int):
            atc = AtomicTransactionComposer()
            atc.add_transaction(donor_transaction_with_signer(
                self.algod, self._sender, self._sk, self.config.donor_issuer_id, self.config.donor_callee_id, n_donors
            ))
            sp_pay = self.algod.suggested_params()
            pay_amount = self._t2_payment_amount(app_address, leaf_len)
            pay_txn = transaction.PaymentTxn(self._sender, sp_pay, app_address, pay_amount)
            atc.add_transaction(TransactionWithSigner(pay_txn, signer))
            for call in calls:
                sp = self.algod.suggested_params()
                sp.flat_fee = True
                sp.fee = 1000
                kwargs = {}
                if call.boxes:
                    kwargs["boxes"] = [transaction.BoxReference(0, b) for b in call.boxes]
                txn = transaction.ApplicationCallTxn(
                    sender=self._sender, sp=sp, index=self.config.m7_app_id,
                    on_complete=transaction.OnComplete.NoOpOC, app_args=call.args, **kwargs,
                )
                atc.add_transaction(TransactionWithSigner(txn, signer))
            return atc

        n_total_txns = 2 + len(calls)  # donor + payment + every RCP1 call
        if n_total_txns > 16:
            raise ValueError(f"T2 group needs {n_total_txns} transactions, over the 16-txn group cap")

        result = submit_run(self.algod, build_group, n_app_calls_in_group=len(calls) + 1, dry_run=False)
        if not result.logs:
            raise m7.M7Error("no log produced by the result transaction")
        decoded = m7.decode_r(result.logs[-1])
        decoded["confirmed_round"] = result.confirmed_round
        decoded["n_transactions"] = n_total_txns
        decoded["measured_consumed"] = result.measured_consumed
        return ReceiptResult(
            rstatus_name=decoded["rstatus_name"], fields=decoded,
            confirmed_round=result.confirmed_round, tx_ids=result.tx_ids,
        )

    def _submit_receipt_against_anchor(self, receipts_root: bytes, tx_index: int, log_index: int,
                                        nodes: list[bytes], el_block_number: int) -> ReceiptResult:
        """T1-against-anchor, migrated onto the same permanent
        `Mpt7AnchoredReceiptApp` §4.4 uses for T2 (this pass closes the gap
        014 §4.1 deliberately deferred). Group: `[DonorIssuer, attest,
        MODE_INIT(+MODE_NEXT), MODE_AGAINST_ANCHOR]` -- no payment, no
        staging calls, since T1's raw-arg walk needs neither; only the
        target app id changed from a freshly compiled+deployed
        `AnchorReceiptProbe` (§4.1's own table: ~0.1-1.74 ALGO abandoned
        MBR plus a ~3.4s `puyapy` compile, PER CALL, and unreachable from
        the packaged Vercel deployment entirely -- `MissingContractsSource`)
        to `self.config.m7_anchored_app_id`, the same already-deployed,
        already-proven app `_submit_t2_receipt_against_anchor` drives."""
        signer = self._signer()
        ring_n = self._m8_ring_n()
        anchored_app_id = self.config.m7_anchored_app_id
        _tier, walk_calls = m7.plan_receipt_calls(receipts_root, tx_index, log_index, nodes, group_offset=2)

        def build_group(n_donors: int):
            atc = AtomicTransactionComposer()
            atc.add_transaction(donor_transaction_with_signer(
                self.algod, self._sender, self._sk, self.config.donor_issuer_id, self.config.donor_callee_id, n_donors
            ))
            sp1 = self.algod.suggested_params()
            sp1.flat_fee = True
            sp1.fee = 1000
            atc.add_method_call(
                app_id=self.config.m8_app_id, method=m8.METHODS["attest"], sender=self._sender, sp=sp1,
                signer=signer, method_args=[el_block_number],
                boxes=m8.auto_boxes_for("attest", el_block_number, ring_n),
            )
            for call in walk_calls:
                sp = self.algod.suggested_params()
                sp.flat_fee = True
                sp.fee = 1000
                txn = transaction.ApplicationCallTxn(
                    sender=self._sender, sp=sp, index=anchored_app_id,
                    on_complete=transaction.OnComplete.NoOpOC, app_args=call.args,
                )
                atc.add_transaction(TransactionWithSigner(txn, signer))
            # group layout: 0=donor, 1=attest, 2..(1+len(walk_calls))=walk
            prev_gi = 1 + len(walk_calls)
            anchor_gi = 1  # attest's own group index, fixed by this layout
            check_args = m7.build_against_anchor_check_args(prev_gi, anchor_gi, el_block_number, tx_index, log_index)
            sp2 = self.algod.suggested_params()
            sp2.flat_fee = True
            sp2.fee = 1000
            check_txn = transaction.ApplicationCallTxn(
                sender=self._sender, sp=sp2, index=anchored_app_id,
                on_complete=transaction.OnComplete.NoOpOC, app_args=check_args,
            )
            atc.add_transaction(TransactionWithSigner(check_txn, signer))
            return atc

        n_calls = 1 + len(walk_calls) + 1  # attest + walk calls + the check call
        result = submit_run(self.algod, build_group, n_app_calls_in_group=n_calls, dry_run=False)
        if not result.logs:
            raise m7.M7Error("no log produced by the against-anchor check")
        decoded = m7.decode_against_anchor(result.logs[-1])
        decoded["confirmed_round"] = result.confirmed_round
        decoded["anchored_app_id"] = anchored_app_id
        decoded["measured_consumed"] = result.measured_consumed
        return ReceiptResult(
            rstatus_name=decoded["rstatus_name"], fields=decoded,
            confirmed_round=result.confirmed_round, tx_ids=result.tx_ids,
        )

    def _submit_t2_receipt_against_anchor(self, receipts_root: bytes, tx_index: int, log_index: int,
                                           nodes: list[bytes], el_block_number: int) -> ReceiptResult:
        """014 §4.4's group layout, closing the T2-against-anchor
        `TierUnsupported` gap: `[DonorIssuer, PaymentTxn(conditional),
        attest, MODE_INIT(+MODE_NEXT), MODE_STAGE_OPEN, MODE_STAGE_WRITE...,
        MODE_STAGE_WALK, MODE_AGAINST_ANCHOR]`, ALL nine app calls plus the
        donor and the payment in ONE atomic group (§14 item 2: MUST NOT
        split), driven against the PERMANENT `Mpt7AnchoredReceiptApp`
        (`self.config.m7_anchored_app_id`, §14 item 3: MUST NOT
        compile-and-deploy per call) rather than a freshly compiled probe.

        `group_offset=3`: donor(0) + payment(1) + attest(2) precede the
        walk calls, matching §4.4's table exactly -- `anchor_gi` is
        therefore always 2 in this layout, and `prev_gi` for
        MODE_AGAINST_ANCHOR is the walk's own last (STAGE_WALK) absolute
        index, `3 + len(calls) - 1`."""
        signer = self._signer()
        ring_n = self._m8_ring_n()
        anchored_app_id = self.config.m7_anchored_app_id
        app_address = logic.get_application_address(anchored_app_id)
        leaf_len = len(nodes[-1])

        box_name = m7.derive_t2_box_name(el_block_number)
        GROUP_OFFSET = 3  # donor(0) + payment(1) + attest(2)
        _tier, calls, box_name, _static_fund_amount = m7.plan_receipt_calls_t2(
            receipts_root, tx_index, log_index, nodes, box_name, group_offset=GROUP_OFFSET
        )
        prev_gi = GROUP_OFFSET + len(calls) - 1  # MODE_STAGE_WALK's own absolute group index
        anchor_gi = GROUP_OFFSET - 1  # attest's own absolute group index, fixed by this layout
        check_args = m7.build_against_anchor_check_args(prev_gi, anchor_gi, el_block_number, tx_index, log_index)

        def build_group(n_donors: int):
            atc = AtomicTransactionComposer()
            atc.add_transaction(donor_transaction_with_signer(
                self.algod, self._sender, self._sk, self.config.donor_issuer_id, self.config.donor_callee_id, n_donors
            ))
            sp_pay = self.algod.suggested_params()
            pay_amount = self._t2_payment_amount(app_address, leaf_len)
            pay_txn = transaction.PaymentTxn(self._sender, sp_pay, app_address, pay_amount)
            atc.add_transaction(TransactionWithSigner(pay_txn, signer))
            sp1 = self.algod.suggested_params()
            sp1.flat_fee = True
            sp1.fee = 1000
            atc.add_method_call(
                app_id=self.config.m8_app_id, method=m8.METHODS["attest"], sender=self._sender, sp=sp1,
                signer=signer, method_args=[el_block_number],
                boxes=m8.auto_boxes_for("attest", el_block_number, ring_n),
            )
            for call in calls:
                sp = self.algod.suggested_params()
                sp.flat_fee = True
                sp.fee = 1000
                kwargs = {}
                if call.boxes:
                    kwargs["boxes"] = [transaction.BoxReference(0, b) for b in call.boxes]
                txn = transaction.ApplicationCallTxn(
                    sender=self._sender, sp=sp, index=anchored_app_id,
                    on_complete=transaction.OnComplete.NoOpOC, app_args=call.args, **kwargs,
                )
                atc.add_transaction(TransactionWithSigner(txn, signer))
            check_txn = transaction.ApplicationCallTxn(
                sender=self._sender, sp=self.algod.suggested_params(), index=anchored_app_id,
                on_complete=transaction.OnComplete.NoOpOC, app_args=check_args,
            )
            check_txn.fee = 1000
            check_txn.flat_fee = True
            atc.add_transaction(TransactionWithSigner(check_txn, signer))
            return atc

        n_calls = 1 + len(calls) + 1  # attest + walk/stage calls + the check call
        n_total_txns = 2 + n_calls  # donor + payment + every app call
        if n_total_txns > 16:
            raise ValueError(f"T2-against-anchor group needs {n_total_txns} transactions, over the 16-txn group cap")

        result = submit_run(self.algod, build_group, n_app_calls_in_group=n_calls, dry_run=False)
        if not result.logs:
            raise m7.M7Error("no log produced by the against-anchor check")
        decoded = m7.decode_against_anchor(result.logs[-1])
        decoded["confirmed_round"] = result.confirmed_round
        decoded["anchored_app_id"] = anchored_app_id
        decoded["n_transactions"] = n_total_txns
        decoded["measured_consumed"] = result.measured_consumed
        return ReceiptResult(
            rstatus_name=decoded["rstatus_name"], fields=decoded,
            confirmed_round=result.confirmed_round, tx_ids=result.tx_ids,
        )

    # ------------------------------------------------------------------
    # sync() -- M4
    # ------------------------------------------------------------------
    def sync(self, *, install: bool = False, update: bool = True, bootstrap_root: bytes | None = None,
              auto_retire: bool = True) -> SyncResult:
        """§9.1: resumes purely from on-chain `inst_state`/`inst_cursor`,
        never a local progress file (§18 item 14). Drives the real,
        non-simulated multi-transaction M4 sequence (bootstrap -> box-open
        -> 64x `install_chunk` -> `install_finalize` -> `submit_update`)
        via `relayer.group.submit.run`, matching `test_live_e2e_finality.
        py`'s own real fixture procedure but generically, through this
        facade, instead of hand-rolled test code.

        **Retirement gap closed this pass**: `retire(gen)` (§8.4) -- a real,
        permissionless, deployed contract method that refunds a superseded
        generation's ~19.76 ALGO of key-box MBR back to the app account --
        had no caller anywhere in this codebase before this pass; every
        real committee rollover just permanently locked another
        generation's worth of box MBR with no automatic reclamation, even
        though the contract itself has always supported reclaiming it.
        `auto_retire=True` (the default) calls `retire_old_generations()`
        after `update`'s own submission, on every `sync(update=True)`, so
        this now self-heals automatically rather than needing a caller to
        remember a separate manual step. It is gated on `update` (not
        `install`) because only a `submit_update` rollover can ever create
        a newly-retireable generation, and on `self.config.has_signer`
        (retiring submits real transactions, so a read-only/no-signer
        client silently skips it rather than raising -- matching every
        other write path's own has_signer convention)."""
        if self.config.m4_app_id is None:
            raise ValueError("sync() needs m4_app_id configured")
        detail: dict = {}
        if install:
            detail["install"] = self._drive_m4_install(bootstrap_root)
        if update:
            detail["update"] = self._drive_m4_update()
            if auto_retire and self.config.has_signer:
                detail["retire"] = self.retire_old_generations()
        return SyncResult(ok=True, detail=detail)

    # ------------------------------------------------------------------
    # retire() -- M4 §8.4, wired to a real caller for the first time this
    # pass (grep for "retire" anywhere in `relayer/` before this pass
    # returned nothing -- every real committee rotation permanently locked
    # ~19.76 ALGO of box MBR with no automatic reclamation, even though the
    # contract itself has always supported reclaiming it).
    # ------------------------------------------------------------------
    def retire_old_generations(self) -> dict:
        """Scans every generation id ever allocated (`1..gen_counter`,
        `gen_counter` itself is on-chain global state, §9.1's "the on-chain
        state machine IS the checkpoint" -- no local bookkeeping of which
        gens exist or were already retired) and retires whichever ones are
        BOTH safe (not `cur_gen`/`next_gen`/`inst_gen`, exactly `retire`'s
        own asserts) AND still real (its `a:<gen>` total box -- created only
        at `install_finalize`, deleted only by `retire` -- still exists).

        The `a:<gen>` existence check is a free, local `application_box_by_
        name` read (no transaction, no fee) done BEFORE spending any real
        transaction fees -- without it, a long-lived relayer would re-submit
        a real (harmless but wasteful) no-op retire group for every already-
        retired historical generation on every single sync() call forever,
        since `gen_counter` only grows. This also cleans up any backlog a
        pre-this-pass relayer left behind, not just the generation this
        exact sync() call may have just superseded.

        Per-generation failures (already retired by a concurrent/previous
        run, a race where the generation became `next_gen`/`inst_gen`
        again, or a real network hiccup) are caught individually and
        reported in the returned dict's `failed` list -- one bad generation
        must never abort the whole sync() call or the retirement of OTHER,
        unrelated generations."""
        if self.config.m4_app_id is None:
            raise ValueError("retire_old_generations() needs m4_app_id configured")
        if not self.config.has_signer:
            raise ValueError("retire_old_generations() needs a signer configured to submit real transactions")

        gs = self._read_global_state(self.config.m4_app_id)
        cur_gen = gs.get(b"cur_gen", 0)
        next_gen = gs.get(b"next_gen", 0)
        inst_gen = gs.get(b"inst_gen", 0)
        gen_counter = gs.get(b"gen_counter", 0)
        protected = {0, cur_gen, next_gen, inst_gen}

        retired: list[dict] = []
        skipped_already_retired: list[int] = []
        failed: list[dict] = []
        for gen in range(1, gen_counter + 1):
            if gen in protected:
                continue
            try:
                self.algod.application_box_by_name(self.config.m4_app_id, total_box_name(gen))
            except Exception as exc:  # noqa: BLE001
                if getattr(exc, "code", None) == 404:
                    skipped_already_retired.append(gen)
                    continue
                failed.append({"gen": gen, "error": f"could not check a:{gen} existence: {exc}"})
                continue
            try:
                retired.append(self._retire_generation(gen))
            except Exception as exc:  # noqa: BLE001 -- a real, legitimate retire failure (e.g. a race that
                # made `gen` become next_gen/inst_gen again between the read above and this submission, or a
                # concurrent relayer already retired it) must not corrupt state or abort the rest of this scan.
                failed.append({"gen": gen, "error": str(exc)})

        return {"retired": retired, "skipped_already_retired": skipped_already_retired, "failed": failed}

    def _retire_generation(self, gen: int) -> dict:
        """A real, non-simulated `[retire, noop_budget*]` atomic group.
        `retire(gen)` deletes ALL 8 key boxes (6,144 B each) plus `a:<gen>`
        (96 B) -- 49,248 B of real declared box content, `plan_box_refs`'s
        same closed form already proven for `submit_update`'s k=8 worst
        case (§7.4): 25 refs, 4 transactions, since a DELETE is charged the
        pooled per-ref write budget at the box's full declared size exactly
        like a read/write is (measured live this pass -- retire's own
        Box.delete calls are the first real caller of this box-reference
        math for a delete rather than a create/read). `retire`'s own
        transaction claims the first 8 refs; the rest ride on `noop_budget`
        filler transactions in the same group, the same convention
        `submit_update_group` already uses."""
        signer = self._signer()
        sizes = m4_retire_box_sizes(gen)
        plan = plan_box_refs(sizes)
        refs = list(plan.distinct_boxes)
        base = list(refs)
        while len(refs) < plan.refs_required:
            refs.append(base[len(refs) % len(base)])

        retire_boxes, remaining = refs[:8], refs[8:]
        filler_chunks = [remaining[i:i + 8] for i in range(0, len(remaining), 8)]

        atc = AtomicTransactionComposer()
        self._add_m4_call(atc, signer, "retire", [gen], boxes=[(0, b) for b in retire_boxes])
        for fb in filler_chunks:
            self._add_m4_call(atc, signer, "noop_budget", [], boxes=[(0, b) for b in fb])
        result = atc.execute(self.algod, 4)
        return {
            "gen": gen, "tx_ids": result.tx_ids, "confirmed_round": result.confirmed_round,
            "refs_required": plan.refs_required, "txns_required": plan.txns_required,
        }

    def _add_m4_call(self, atc, signer, name: str, args: list, boxes=None) -> None:
        sp = self.algod.suggested_params()
        sp.flat_fee = True
        sp.fee = 1000
        kwargs = {}
        if boxes:
            kwargs["boxes"] = boxes
        atc.add_method_call(
            app_id=self.config.m4_app_id, method=m4.METHODS[name], sender=self._sender, sp=sp, signer=signer,
            method_args=args, **kwargs,
        )

    def _drive_m4_install(self, bootstrap_root: bytes | None) -> dict:
        self._require_signer_and_donors("sync(install=True)")
        signer = self._signer()

        gs = self._read_global_state(self.config.m4_app_id)
        inst_state = gs.get(b"inst_state", 0)
        cur_gen = gs.get(b"cur_gen", 0)
        gen_counter = gs.get(b"gen_counter", 0)
        boot_args = None

        if inst_state == 0:  # INST_STATE_IDLE
            if cur_gen != 0:
                return {"skipped": "already installed (cur_gen != 0), no fresh bootstrap needed", "gen": cur_gen}
            if bootstrap_root is None:
                raise ValueError(
                    "a fresh install needs bootstrap_root -- §6.1: M9 fails loudly rather than "
                    "silently substituting a different, fetchable root"
                )
            boot_resp = beacon.fetch_bootstrap(bootstrap_root.hex())
            boot_args = m4.transform_bootstrap(boot_resp)
            from relayer.codec.header import hash_tree_root_beacon_block_header

            assert hash_tree_root_beacon_block_header(boot_args.header) == bootstrap_root, (
                "fetched bootstrap header does not hash to the trusted bootstrap_root"
            )
            gen = gen_counter + 1
            key_refs = [(0, key_box_name(gen, j)) for j in range(8)]
            session_ref = [(0, session_box_name(gen))]
            atc = AtomicTransactionComposer()
            # 013 §6.4 / §17 item 7: `forks` is no longer a box (the fork
            # table moved to global state), so the slot it occupied here
            # MUST be REPLACED, not deleted, by an 8th key-box reference --
            # this group needs 25 references total (measured, unchanged by
            # 013: the box-opening group's own total was and is 49,576 B),
            # and dropping to 7 refs here would silently under-budget it,
            # reintroducing the exact class of shortfall 009's history
            # records four times.
            self._add_m4_call(
                atc, signer, "bootstrap",
                [boot_args.header, boot_args.committee_root, boot_args.current_sc_branch, bootstrap_root],
                boxes=key_refs[:8],
            )
            self._add_m4_call(atc, signer, "install_open_keys", [], boxes=key_refs)
            self._add_m4_call(atc, signer, "install_open_session", [], boxes=session_ref + key_refs[:7])
            self._add_m4_call(atc, signer, "noop_budget", [], boxes=session_ref)
            atc.execute(self.algod, 4)
            gs = self._read_global_state(self.config.m4_app_id)
            inst_state = gs.get(b"inst_state", 0)

        if inst_state in (1, 2):  # VALIDATED / OPENING_BOXES
            raise NotImplementedError(
                "resuming mid-box-opening (VALIDATED/OPENING_BOXES) is not reachable via this "
                "driver's own bootstrap+box-opening atomic grouping (both phases commit together, "
                "§9.1) -- only reachable via the separate install_begin rollover flow, a real, named "
                "gap this pass's remaining time did not add, not a silently-assumed one"
            )

        if inst_state != 3:  # not INSTALLING -- nothing left to do
            return {"gen": gs.get(b"inst_gen", 0), "inst_state": inst_state}

        gen = gs[b"inst_gen"]
        if boot_args is None:
            if bootstrap_root is None:
                raise ValueError(
                    "resuming an INSTALLING session needs the same bootstrap_root to refetch the real "
                    "committee data -- §18 item 14: no local progress file is kept, so the committee's "
                    "own key material is re-derived from the trusted root every time, never cached client-side"
                )
            boot_resp = beacon.fetch_bootstrap(bootstrap_root.hex())
            boot_args = m4.transform_bootstrap(boot_resp)
        assert boot_args.committee_root == gs[b"inst_root"], (
            "refetched committee root does not match the on-chain in-flight inst_root -- wrong bootstrap_root?"
        )

        cursor = gs[b"inst_cursor"]
        n_resumed = 0
        for start in range(cursor, len(boot_args.pubkey_pairs), m4.INSTALL_CHUNK_SIZE):
            chunk = boot_args.pubkey_pairs[start:start + m4.INSTALL_CHUNK_SIZE]
            compressed_blob = b"".join(c for c, _u in chunk)
            uncompressed_blob = b"".join(u for _c, u in chunk)
            box_j = start // 64
            kb = key_box_name(gen, box_j)
            sb = session_box_name(gen)

            def build_group(n_donors: int, start=start, compressed_blob=compressed_blob,
                             uncompressed_blob=uncompressed_blob, kb=kb, sb=sb):
                atc = AtomicTransactionComposer()
                atc.add_transaction(donor_transaction_with_signer(
                    self.algod, self._sender, self._sk, self.config.donor_issuer_id,
                    self.config.donor_callee_id, n_donors,
                ))
                self._add_m4_call(
                    atc, signer, "install_chunk", [start, compressed_blob, uncompressed_blob],
                    boxes=[(0, kb), (0, sb), (0, kb), (0, sb)],
                )
                return atc

            submit_run(self.algod, build_group, n_app_calls_in_group=2, dry_run=False)
            n_resumed += 1

        def build_finalize(n_donors: int):
            atc = AtomicTransactionComposer()
            atc.add_transaction(donor_transaction_with_signer(
                self.algod, self._sender, self._sk, self.config.donor_issuer_id, self.config.donor_callee_id, n_donors
            ))
            self._add_m4_call(
                atc, signer, "install_finalize", [boot_args.aggregate_compressed, boot_args.aggregate_uncompressed],
                boxes=[(0, session_box_name(gen)), (0, total_box_name(gen))],
            )
            return atc

        submit_run(self.algod, build_finalize, n_app_calls_in_group=2, dry_run=False)
        return {"gen": gen, "installed": True, "chunks_submitted_this_call": n_resumed, "resumed_from_cursor": cursor}

    def _drive_m4_update(self) -> dict:
        gs = self._read_global_state(self.config.m4_app_id)
        fin_slot_onchain = gs.get(b"fin_slot", 0)
        cur_gen = gs.get(b"cur_gen", 0)
        if cur_gen == 0:
            return {"skipped": "no installed committee yet -- run sync(install=True) first"}

        finality = beacon.fetch_finality_update()
        args = m4.transform_finality_update(finality)
        m4.assert_not_future_dated(args.signature_slot)
        new_finalized_slot = int.from_bytes(args.finalized_header[0:8], "little")
        if new_finalized_slot <= fin_slot_onchain:
            return {"skipped": "not newer than on-chain fin_slot", "fin_slot_onchain": fin_slot_onchain}

        if not self.config.has_signer or self.config.donor_issuer_id is None:
            raise ValueError("sync(update=True) needs a signer and donor_issuer_id/donor_callee_id configured")

        # §6.4/step 5 of `submit_update`: a signature signed in `store_period
        # + 1` is verified against `next_gen`'s installed committee, NOT
        # `cur_gen`'s -- a real bug found and fixed THIS pass (retire()
        # needed a genuine rollover to prove itself against, and driving one
        # surfaced this): this call used to hardcode `cur_gen` into both the
        # box-reference plan and the submitted group's box names regardless
        # of which committee the contract would actually use, which is only
        # ever correct for the `using_next == False` case. A real
        # `using_next == True` submission would have referenced `cur_gen`'s
        # key boxes while the contract read `next_gen`'s, a structural
        # box-reference mismatch that could never have committed on-chain --
        # meaning `sync(update=True)` could never have driven a real
        # rollover at all before this fix, independent of `retire()`.
        store_period = fin_slot_onchain // 8192
        update_signature_period = args.signature_slot // 8192
        using_next = update_signature_period == store_period + 1
        if using_next:
            next_gen_onchain = gs.get(b"next_gen", 0)
            if next_gen_onchain == 0:
                return {
                    "skipped": "signature period is store_period + 1 but next_gen is not yet installed",
                    "store_period": store_period, "update_signature_period": update_signature_period,
                }
            committee_gen = next_gen_onchain
        else:
            committee_gen = cur_gen

        mode, plan = m4.plan_submit_update_boxes(args.sync_committee_bits, committee_gen)
        result = self.submit_update_group(committee_gen, args, mode, plan)
        from relayer.codec.header import hash_tree_root_beacon_block_header

        return {
            "fin_slot": new_finalized_slot,
            "fin_root": hash_tree_root_beacon_block_header(args.finalized_header).hex(),
            "fin_state_root": args.finalized_header[48:80].hex(),
            "mode": mode, "committee_gen": committee_gen, "using_next": using_next,
            "refs_required": plan.refs_required,
            "txns_required_for_boxes": plan.txns_required, "n_donors": result.n_donors,
            "measured_consumed": result.measured_consumed, "tx_ids": result.tx_ids,
            "confirmed_round": result.confirmed_round,
        }

    def submit_update_group(self, gen: int, args, mode: int, plan):
        """Promoted from a private `_submit_update_group` to a public
        method (docs/design/011-test-harness-ci.md §6.3): the M11 rebasing
        of `tests/sync_committee/test_live_e2e_finality.py`'s adversarial
        corrupted-signature/corrupted-branch tests needs to submit a
        deliberately-tampered `SubmitUpdateArgs` through the REAL group
        path, and reaching into a private method from a test would leave
        those two tests coupled to an underscore. This is a genuine
        operator-usable seam (submit a specific, already-planned update
        group directly); no behaviour changed by the rename.

        §7.4/§18 item 3: sizes the group's TRANSACTION COUNT from the
        real bitfield's box-reference plan, never assumes 2 transactions
        suffice. At k=8 key boxes (worst case), 25 refs -> 4 transactions:
        `[DonorIssuer, noop_budget, noop_budget, submit_update]`, exactly
        the shape §7.4's own closed form predicts (G1-M9).

        Real, measured finding this pass (not in the design doc, found
        live): the donor transaction's own `foreign_apps=[callee_id]`
        reference COUNTS against the same per-transaction reference
        budget as its box refs -- real algod rejects an 8-box + 1-app
        donor transaction structurally with `"tx references exceed
        MaxAppTotalTxnReferences = 8"`, not merely the box-specific `"max
        number of box references is 8"` §7.3 cites. So the donor's own
        padding capacity is 7 boxes, not 8; `submit_update` (no foreign
        app refs of its own) and each `noop_budget` filler still get the
        full 8."""
        signer = self._signer()

        refs = list(plan.distinct_boxes)
        if refs:
            base = list(refs)
            while len(refs) < plan.refs_required:
                refs.append(base[len(refs) % len(base)])

        # submit_update gets first claim on up to 8 refs (it is the call
        # that structurally needs some of these boxes named); everything
        # left over is pure padding, spread across the donor (cap 7, see
        # docstring) then as many plain noop_budget fillers (cap 8 each)
        # as needed.
        submit_boxes, remaining = refs[:8], refs[8:]
        donor_boxes, remaining = remaining[:7], remaining[7:]
        filler_chunks = [remaining[i:i + 8] for i in range(0, len(remaining), 8)]

        def build_group(n_donors: int):
            atc = AtomicTransactionComposer()
            atc.add_transaction(donor_transaction_with_signer(
                self.algod, self._sender, self._sk, self.config.donor_issuer_id, self.config.donor_callee_id,
                n_donors, extra_boxes=[(0, b) for b in donor_boxes] or None,
            ))
            for fb in filler_chunks:
                self._add_m4_call(atc, signer, "noop_budget", [], boxes=[(0, b) for b in fb])
            self._add_m4_call(
                atc, signer, "submit_update",
                [
                    args.attested_header, args.finalized_header, args.finality_branch,
                    args.next_committee_root, args.next_committee_branch,
                    args.sync_committee_bits, args.signature, args.signature_slot, mode,
                ],
                boxes=[(0, b) for b in submit_boxes],
            )
            return atc

        n_app_calls = 1 + len(filler_chunks) + 1  # donor + fillers + submit_update
        return submit_run(self.algod, build_group, n_app_calls_in_group=n_app_calls, dry_run=False)
