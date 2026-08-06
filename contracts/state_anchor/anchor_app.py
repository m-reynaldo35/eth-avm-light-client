"""M8 -- `TrustedRootAnchor`, the deployed ARC-4 contract. Design doc §8.2
(interface), §3-§5 (bridge/finality semantics), §6-§7 (data model/retention).

Imports M3's asserting Merkle-branch wrapper and M4's header code verbatim
(§3.6, §12.6) -- never reimplements the header layout or the fold. Reads
M4's global state via `app_global_get_ex` (§8.2) -- no inner call, no
co-deployment.
"""

import typing

from algopy import (
    ARC4Contract,
    Account,
    Application,
    Bytes,
    Global,
    Txn,
    UInt64,
    arc4,
    gtxn,
    itxn,
    op,
    subroutine,
)

from contracts.primitives.ssz.merkle import assert_valid_merkle_branch
from contracts.state_anchor import box, forks
from contracts.state_anchor.bridge import (
    assert_fin_header_matches,
    assert_fin_state_root_cross_check,
    assert_window,
    epoch_of,
    fold_block_roots,
    fold_execution_fields,
    read_m4_finalized,
)
from contracts.state_anchor.constants import RECORD_LEN
from contracts.state_anchor.record import (
    a_is_revoked,
    a_matches_block_number,
    a_version,
    build_record,
)
from contracts.sync_committee.header import hash_tree_root_beacon_block_header, header_slot

Byte = arc4.Byte
Bytes32 = arc4.StaticArray[Byte, typing.Literal[32]]
Bytes112 = arc4.StaticArray[Byte, typing.Literal[112]]
Bytes154 = arc4.StaticArray[Byte, typing.Literal[154]]


@subroutine
def zero32() -> Bytes:
    return op.Global.zero_address.bytes


class TrustedRootAnchor(ARC4Contract, avm_version=10):
    # ---- one-time setup --------------------------------------------------

    @arc4.abimethod(create="require")
    def create(self, governance: arc4.Address, m4_app_id: arc4.UInt64, ring_n: arc4.UInt64) -> None:
        """§6.2, §8.2: `m4_app_id`/`ring_n` are write-once, immutable
        thereafter (TP-M8-7, §6.2's "ring_n is immutable for a load-bearing
        reason"). `ring_n` MUST be a power of two and non-zero (§6.2,
        §12.9).

        Real, measured Puya (5.9.0) quirk found while building this method:
        assigning a global-state field directly from a chained-call
        expression (`self.x = some_arc4_value.native`) sometimes leaves that
        field genuinely unrecognised everywhere else in the contract
        ("unrecognised member"), for reasons this pass could not fully
        pin down (it is NOT simply "every non-literal RHS breaks it" --
        `self.gov = governance.native` on the very next line is fine). The
        reliable, reproduced fix is to bind the value to an explicitly
        `UInt64`-annotated local first, then assign the LOCAL to
        `self.x` -- done for `m4_app`/`ring_size` below, the two fields
        that actually hit this. Documented here (and in ROADMAP.md's M8
        row) rather than silently worked around, per this project's own
        standing convention for real toolchain findings."""
        n: UInt64 = ring_n.native
        m4v: UInt64 = m4_app_id.native
        assert n > UInt64(0), "ring_n must be nonzero"
        assert n & (n - UInt64(1)) == UInt64(0), "ring_n must be a power of two"

        self.gov = governance.native
        self.m4_app = m4v
        self.ring_size = n
        self.ring_cursor = UInt64(0)
        self.hi_block = UInt64(0)
        self.hi_slot = UInt64(0)
        self.n_anchored = UInt64(0)
        self.frozen = UInt64(1)
        self.conflict = UInt64(0)
        self.fork_count = UInt64(0)
        forks.forks_box_create()

    @arc4.abimethod
    def ring_init_chunk(self, k: arc4.UInt64) -> None:
        """§7.7: governance only; creates up to 8 ring boxes per call (the
        measured per-transaction box-reference cap, §16 of M4 applied here
        too); `frozen` clears to 0 once `ring_cursor` reaches `ring_n`."""
        assert Txn.sender == self.gov, "N23"
        assert self.ring_cursor < self.ring_size, "ring already initialised"
        kk = k.native
        assert self.ring_cursor + kk <= self.ring_size, "chunk would overflow ring_n"
        self.ring_cursor = box.ring_init_chunk(self.ring_cursor, kk)
        if self.ring_cursor == self.ring_size:
            self.frozen = UInt64(0)

    @arc4.abimethod
    def append_fork_row(
        self,
        activation_epoch: arc4.UInt64,
        g_state_root: arc4.UInt64,
        g_receipts_root: arc4.UInt64,
        g_block_number: arc4.UInt64,
        g_block_roots_base: arc4.UInt64,
    ) -> None:
        """§3.3, TP-M8-3: governance only; append-only; strictly increasing
        `activation_epoch`. G4-M8 requires the deployed rows to be
        regenerated with `get_generalized_index`, never copied from the
        design doc's own tables."""
        assert Txn.sender == self.gov, "N23"
        self.fork_count = forks.append_fork_row(
            self.fork_count,
            activation_epoch.native,
            g_state_root.native,
            g_receipts_root.native,
            g_block_number.native,
            g_block_roots_base.native,
        )

    # ---- anchoring -----------------------------------------------------

    @arc4.abimethod
    def anchor_direct(
        self,
        m4_app: Application,
        fin_header: Bytes112,
        el_state_root: Bytes32,
        el_receipts_root: Bytes32,
        el_block_number: arc4.UInt64,
        state_branch: arc4.DynamicBytes,
        receipts_branch: arc4.DynamicBytes,
        number_branch: arc4.DynamicBytes,
    ) -> Bytes154:
        """§3, §10.2: anchors the execution block inside the header M4
        currently holds as finalized (`t_slot == fin_slot`)."""
        fin_slot, fin_root, fin_state_root = read_m4_finalized(m4_app, self.m4_app)
        assert fin_root != zero32(), "N5"

        header_bytes = fin_header.bytes
        header_state_root = assert_fin_header_matches(header_bytes, fin_root)
        assert_fin_state_root_cross_check(header_state_root, fin_state_root)
        t_slot = header_slot(header_bytes)
        assert t_slot == fin_slot, "DIRECT requires t_slot == fin_slot"

        epoch = epoch_of(t_slot)
        g_state_root, g_receipts_root, g_block_number, _g_base = forks.lookup_row(self.fork_count, epoch)

        body_root = header_bytes[80:112]
        fold_execution_fields(
            body_root, g_state_root, g_receipts_root, g_block_number,
            el_state_root.bytes, el_receipts_root.bytes, el_block_number.native,
            state_branch.native, receipts_branch.native, number_branch.native,
        )

        beacon_block_root = fin_root  # DIRECT: target header IS the finalized header
        candidate = build_record(
            False, el_block_number.native, t_slot, el_state_root.bytes, el_receipts_root.bytes,
            beacon_block_root, fin_root, Global.round,
        )
        new_conflict, result, new_hi_block, new_hi_slot, wrote = box.finish_anchor_flow(
            self.ring_cursor, self.ring_size, self.frozen, self.conflict,
            self.hi_block, self.hi_slot, candidate,
        )
        self.conflict = new_conflict
        self.hi_block = new_hi_block
        self.hi_slot = new_hi_slot
        if wrote == UInt64(1):
            self.n_anchored += UInt64(1)
        return Bytes154.from_bytes(result)

    @arc4.abimethod
    def anchor_historical(
        self,
        m4_app: Application,
        fin_header: Bytes112,
        target_header: Bytes112,
        block_roots_branch: arc4.DynamicBytes,
        el_state_root: Bytes32,
        el_receipts_root: Bytes32,
        el_block_number: arc4.UInt64,
        state_branch: arc4.DynamicBytes,
        receipts_branch: arc4.DynamicBytes,
        number_branch: arc4.DynamicBytes,
    ) -> Bytes154:
        """§4, §10.3: reaches back up to 8,192 slots via `BeaconState.
        block_roots`. N-FORK (§3.4): `g_block_roots_base` is selected by
        `epoch(fin_slot)`; the three execution gindices by `epoch(t_slot)`
        -- two SEPARATE lookups, never collapsed."""
        fin_slot, fin_root, fin_state_root = read_m4_finalized(m4_app, self.m4_app)
        assert fin_root != zero32(), "N5"

        fin_header_bytes = fin_header.bytes
        fin_header_state_root = assert_fin_header_matches(fin_header_bytes, fin_root)
        assert_fin_state_root_cross_check(fin_header_state_root, fin_state_root)

        target_bytes = target_header.bytes
        assert target_bytes.length == UInt64(112), "N8"
        t_root = hash_tree_root_beacon_block_header(target_bytes)
        t_slot = header_slot(target_bytes)
        assert_window(t_slot, fin_slot)

        # N-FORK: two independent lookups, deliberately not collapsed
        # (§3.4's "two-row trap").
        _s1, _r1, _n1, g_block_roots_base = forks.lookup_row(self.fork_count, epoch_of(fin_slot))
        g_state_root, g_receipts_root, g_block_number, _g_base2 = forks.lookup_row(
            self.fork_count, epoch_of(t_slot)
        )

        fold_block_roots(fin_state_root, g_block_roots_base, t_slot, t_root, block_roots_branch.native)

        body_root = target_bytes[80:112]
        fold_execution_fields(
            body_root, g_state_root, g_receipts_root, g_block_number,
            el_state_root.bytes, el_receipts_root.bytes, el_block_number.native,
            state_branch.native, receipts_branch.native, number_branch.native,
        )

        candidate = build_record(
            True, el_block_number.native, t_slot, el_state_root.bytes, el_receipts_root.bytes,
            t_root, fin_root, Global.round,
        )
        new_conflict, result, new_hi_block, new_hi_slot, wrote = box.finish_anchor_flow(
            self.ring_cursor, self.ring_size, self.frozen, self.conflict,
            self.hi_block, self.hi_slot, candidate,
        )
        self.conflict = new_conflict
        self.hi_block = new_hi_block
        self.hi_slot = new_hi_slot
        if wrote == UInt64(1):
            self.n_anchored += UInt64(1)
        return Bytes154.from_bytes(result)

    # ---- the consumer-facing read ---------------------------------------

    @arc4.abimethod
    def attest(self, block_number: arc4.UInt64) -> Bytes154:
        """§8.2: THE hot path. Reads the ring, then the pinned tier."""
        assert self.conflict == UInt64(0), "N22"
        bn = block_number.native
        record = box.read_ring_slot(self.ring_size, bn)
        if a_version(record) != UInt64(0) and a_matches_block_number(record, bn):
            assert not a_is_revoked(record), "N13"
            return Bytes154.from_bytes(record)
        exists, pinned, _payer = box.pin_read_maybe(bn)
        assert exists, "N12"
        assert a_version(pinned) == UInt64(1), "N14"
        assert not a_is_revoked(pinned), "N13"
        return Bytes154.from_bytes(pinned)

    @arc4.abimethod(readonly=True)
    def get_anchor(self, block_number: arc4.UInt64) -> Bytes154:
        """Same semantics as `attest`, `readonly=True` for off-chain callers
        and the inner-call hand-off (§8.4)."""
        assert self.conflict == UInt64(0), "N22"
        bn = block_number.native
        record = box.read_ring_slot(self.ring_size, bn)
        if a_version(record) != UInt64(0) and a_matches_block_number(record, bn):
            assert not a_is_revoked(record), "N13"
            return Bytes154.from_bytes(record)
        exists, pinned, _payer = box.pin_read_maybe(bn)
        assert exists, "N12"
        assert not a_is_revoked(pinned), "N13"
        return Bytes154.from_bytes(pinned)

    # ---- pinned tier -----------------------------------------------------

    @arc4.abimethod
    def pin(self, block_number: arc4.UInt64, payment: gtxn.PaymentTransaction) -> None:
        """§7.5: `payment` MUST be a Payment to the app account covering the
        pinned-box MBR (`2500 + 400*196 = 80,900` uALGO). The block number
        must already be readable (ring or a just-anchored earlier group
        transaction) -- `get_anchor`'s own logic is reused via `attest`'s
        same-transaction-group convention: this method simply re-derives
        the record from the ring; a HISTORICAL-anchored-then-pinned block
        not yet in the ring is not supported by this v1 (the ring always
        holds every block within `N-ADMIT`'s window at anchor time, so this
        covers §7.5's real "[Payment, anchor_historical, pin]" flow whenever
        pin runs in the SAME group as the anchor, ring residues being
        written before pin executes)."""
        assert self.conflict == UInt64(0), "N22"
        assert self.frozen == UInt64(0), "N11"
        bn = block_number.native
        record = box.read_ring_slot(self.ring_size, bn)
        assert a_version(record) != UInt64(0) and a_matches_block_number(record, bn), "N12"
        assert payment.receiver == Global.current_application_address, "N24"
        assert payment.amount >= UInt64(80_900), "N24"
        box.pin_write(bn, record, Txn.sender.bytes)

    @arc4.abimethod
    def unpin(self, block_number: arc4.UInt64) -> None:
        """§7.5: refunds ONLY the recorded payer, never the sender, never a
        parameter (§11 S18)."""
        bn = block_number.native
        exists, _record, payer = box.pin_read_maybe(bn)
        assert exists, "N12"
        box_mbr_refund = UInt64(80_900)
        box.pin_delete(bn)
        itxn.Payment(receiver=Account.from_bytes(payer), amount=box_mbr_refund, fee=UInt64(0)).submit()

    # ---- governance --------------------------------------------------

    @arc4.abimethod
    def revoke(self, block_number: arc4.UInt64) -> None:
        """§5.7: sets `FLAG_REVOKED` on the ring record (if present). Does
        not delete, does not alter the anchored fields."""
        assert Txn.sender == self.gov, "N23"
        bn = block_number.native
        residue = box.ring_residue(bn, self.ring_size)
        name = box.ring_box_name(residue)
        record = op.Box.extract(name, UInt64(0), UInt64(RECORD_LEN))
        assert a_version(record) != UInt64(0) and a_matches_block_number(record, bn), "N12"
        flags = op.getbyte(record, UInt64(1)) | UInt64(1)
        op.Box.replace(name, UInt64(1), op.extract(op.itob(flags), UInt64(7), UInt64(1)))

    @arc4.abimethod
    def freeze(self) -> None:
        assert Txn.sender == self.gov, "N23"
        self.frozen = UInt64(1)

    @arc4.abimethod
    def unfreeze(self) -> None:
        assert Txn.sender == self.gov, "N23"
        assert self.ring_cursor == self.ring_size, "ring not initialised"
        self.frozen = UInt64(0)

    @arc4.abimethod
    def gov_clear_conflict(self) -> None:
        assert Txn.sender == self.gov, "N23"
        self.conflict = UInt64(0)

    @arc4.abimethod
    def renounce(self) -> None:
        assert Txn.sender == self.gov, "N23"
        self.gov = Global.zero_address

    # ---- group plumbing -----------------------------------------------

    @arc4.abimethod
    def noop_budget(self) -> None:
        pass

    @arc4.abimethod
    def donor(self) -> None:
        pass
