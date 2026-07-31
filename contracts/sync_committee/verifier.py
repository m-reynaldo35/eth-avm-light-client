"""M4 -- `SyncCommitteeVerifier`, the deployed ARC-4 contract. Design doc
§7 (interface), §6 (protocol semantics), §8 (install/session/rollover).

Unlike M1/M3 (compile-time subroutine libraries), this module IS the
deployed application: it imports `contracts.primitives.bls` and
`contracts.primitives.ssz` as ordinary Puya subroutines, never as inner app
calls (001 §5, 003 §5.4) -- an inner call into a library primitive would
burn one of the 256 inner-call slots §9 already spends entirely on budget
donation.

Two elaborations of the design doc's pseudocode, called out explicitly
because a design doc cannot be literally executed and these are the
judgment calls made to turn §8.3's prose into code (both documented again
at their point of use below):

  1. **Genesis generation placement.** §8.3's `install_finalize` pseudocode
     unconditionally writes `next_gen`. But `bootstrap` has no prior "current"
     committee to roll over from, so the very first install must become
     `cur_gen` directly (mirroring the light-client spec's
     `initialize_light_client_store`, which seeds `store.current_sync_committee`
     directly from the bootstrap, not via `apply_light_client_update`'s
     rollover path). `install_finalize` here special-cases `cur_gen == 0`
     (true genesis) to write `cur_gen`/`cur_period` instead of
     `next_gen`/`next_period`. This does not weaken §8.3's security
     properties: the merkle-root check gates BOTH destinations identically.
  2. **`next_committee_root_trusted` / `next_committee_root_period`.** §8.2's
     state table does not name the global slot that carries "the trusted
     root for `period`, established by a verified update" that §8.3's
     `install_begin` precondition refers to. This module adds those two
     globals explicitly; `submit_update` writes them (subject to §10.3's
     divergence check) whenever it proves a `next_committee_branch` for the
     store's current period, mirroring the spec's "supply the next sync
     committee from a past update" behaviour -- this does not require the
     2/3 supermajority that gates finality advancement (§6.3's threshold
     gates finalized-state advancement and rollover; committee *discovery*
     is a strictly weaker, MIN_SYNC_COMMITTEE_PARTICIPANTS-gated fact, per
     the vendored `supply_sync_committee_from_past_update` scenario).

Known, deliberate scope reduction beyond §6.6's own list (flagged in the
implementation report, not hidden here): the spec's
`update_has_finalized_next_sync_committee` early-finality special case (an
edge condition letting a store advance on a same-slot finality update the
very first time the next committee becomes known) is NOT implemented; this
module advances finalized state only on the mainline rule, strict
`finalized_slot` increase plus the 2/3 supermajority (§6.3).
"""

import typing

from algopy import ARC4Contract, Bytes, Txn, UInt64, arc4, op, subroutine

from contracts.primitives.bls.hash_to_curve import hash_to_g2
from contracts.primitives.bls.pairing import verify_aggregate_signature
from contracts.primitives.ssz.merkle import assert_valid_normalized_merkle_branch
from contracts.sync_committee import forks
from contracts.sync_committee.bitfield import aggregate_participants
from contracts.sync_committee.constants import (
    G1_UNCOMPRESSED_BYTES,
    INST_STATE_IDLE,
    INST_STATE_INSTALLING,
    INST_STATE_OPENING_BOXES,
    INST_STATE_VALIDATED,
    MIN_SYNC_COMMITTEE_PARTICIPANTS,
    SYNC_COMMITTEE_SIZE,
    TWO_THIRDS_DENOMINATOR,
    TWO_THIRDS_NUMERATOR,
    domain_sync_committee,
    epoch_at_slot,
    eth_dst,
    fork_version_epoch_for_signature_slot,
    period_at_slot,
)
from contracts.sync_committee.header import (
    compute_domain,
    compute_signing_root,
    hash_tree_root_beacon_block_header,
    header_slot,
)
from contracts.sync_committee.install import (
    install_abort_boxes,
    install_abort_key_boxes,
    install_delete_committee_boxes,
    install_open_key_boxes,
    install_open_session_box,
    install_process_chunk,
    install_process_finalize,
    total_box_name,
)

# ---------------------------------------------------------------------------
# §16: box-opening is validate-then-create, split across `bootstrap`/
# `install_begin` (validate + reserve a generation, `INST_STATE_VALIDATED`,
# touching at most the `forks` box) -> `install_open_keys` (create the 8 key
# boxes, `INST_STATE_OPENING_BOXES`, exactly the measured per-txn
# box-reference cap) -> `install_open_session` (create the session box,
# `INST_STATE_INSTALLING`). See install.py's module docstring and
# docs/design/004-sync-committee.md §16 for the measured constraints this
# split satisfies and why bootstrap specifically needed a THREE-way split
# (its `forks`-box read plus 8 key-box creates was a second, independent hit
# of the same reference cap).
# ---------------------------------------------------------------------------

Byte = arc4.Byte
Bytes4 = arc4.StaticArray[Byte, typing.Literal[4]]
Bytes32 = arc4.StaticArray[Byte, typing.Literal[32]]
Bytes48 = arc4.StaticArray[Byte, typing.Literal[48]]
Bytes64 = arc4.StaticArray[Byte, typing.Literal[64]]
Bytes96 = arc4.StaticArray[Byte, typing.Literal[96]]
Bytes112 = arc4.StaticArray[Byte, typing.Literal[112]]
Bytes192 = arc4.StaticArray[Byte, typing.Literal[192]]

@subroutine
def zero32() -> Bytes:
    return op.Global.zero_address.bytes


class LightClientUpdateVerified(arc4.Struct):
    """§7.4 -- what M8 consumes. Emitted only on a successful, 2/3-finalized,
    state-advancing update."""

    finalized_slot: arc4.UInt64
    finalized_beacon_root: Bytes32
    finalized_state_root: Bytes32
    attested_slot: arc4.UInt64
    attested_state_root: Bytes32
    participation: arc4.UInt64
    signature_slot: arc4.UInt64


class SyncCommitteeVerifier(ARC4Contract, avm_version=10):
    # ---- one-time setup --------------------------------------------------

    @arc4.abimethod(create="require")
    def create(self, governance: arc4.Address, genesis_validators_root: Bytes32) -> None:
        """§7.3, §10.7: `genesis_validators_root` is write-once, no setter
        anywhere in this contract (§15 item 13)."""
        self.gov = governance.native
        self.gvr = genesis_validators_root.bytes

        self.fin_slot = UInt64(0)
        self.fin_root = zero32()
        self.fin_state_root = zero32()
        self.att_slot = UInt64(0)
        self.att_state_root = zero32()

        self.cur_gen = UInt64(0)
        self.cur_period = UInt64(0)
        self.next_gen = UInt64(0)
        self.next_period = UInt64(0)
        self.next_committee_root_trusted = zero32()
        self.next_committee_root_period = UInt64(0)

        self.inst_state = UInt64(INST_STATE_IDLE)
        self.inst_gen = UInt64(0)
        self.inst_period = UInt64(0)
        self.inst_root = zero32()
        self.inst_cursor = UInt64(0)

        self.fork_count = UInt64(0)
        self.gen_counter = UInt64(0)
        forks.forks_box_create()

    @arc4.abimethod
    def append_fork_row(
        self,
        activation_epoch: arc4.UInt64,
        fork_version: Bytes4,
        finality_gindex: arc4.UInt64,
        current_sc_gindex: arc4.UInt64,
        next_sc_gindex: arc4.UInt64,
    ) -> None:
        """§4.3, §7.3: governance only; append-only; strictly increasing
        `activation_epoch`; rejects the `uint64` max sentinel epoch."""
        assert Txn.sender == self.gov, "governance only"
        self.fork_count = forks.append_fork_row(
            self.fork_count,
            activation_epoch.native,
            fork_version.bytes,
            finality_gindex.native,
            current_sc_gindex.native,
            next_sc_gindex.native,
        )

    @arc4.abimethod
    def bootstrap(
        self,
        header: Bytes112,
        committee_root: Bytes32,
        current_sc_branch: arc4.DynamicBytes,
        trusted_block_root: Bytes32,
    ) -> None:
        """§7.3, §8.3: governance only, once. Verifies
        `hash_tree_root(header) == trusted_block_root` and the
        current-committee branch at `current_sc_gindex(epoch(header.slot))`
        against `header.state_root`, then reserves a generation id and
        moves to `INST_STATE_VALIDATED` -- box creation happens in the
        LATER `install_open_keys`/`install_open_session` calls (§16), not
        here. This call touches at most the `forks` box (the gindex
        lookup): §16 found that reading `forks` in the SAME call that used
        to create the 8 key boxes was a second, independent way to exceed
        the measured 8-box-reference-per-transaction cap, distinct from the
        9-boxes-in-`install_open_boxes` bug -- decoupling validation from
        box creation entirely fixes both at once. `install_open_keys` then
        `install_open_session` MUST follow in the SAME atomic group; the
        eventual `install_finalize` lands this generation in `cur_gen`
        directly, per this module's genesis elaboration (module docstring).
        """
        assert Txn.sender == self.gov, "governance only"
        assert self.cur_gen == UInt64(0), "already bootstrapped"
        assert self.inst_state == UInt64(INST_STATE_IDLE), "install session in progress"

        header_bytes = header.bytes
        root = hash_tree_root_beacon_block_header(header_bytes)
        assert root == trusted_block_root.bytes, "header != trusted_block_root"

        slot = header_slot(header_bytes)
        epoch = epoch_at_slot(slot)
        _finality_gindex, current_sc_gindex, _next_sc_gindex = forks.lookup_gindices(
            self.fork_count, epoch
        )
        state_root = header_bytes[48:80]
        assert_valid_normalized_merkle_branch(
            committee_root.bytes, current_sc_branch.native, current_sc_gindex, state_root
        )

        period = period_at_slot(slot)
        self.gen_counter += UInt64(1)
        gen = self.gen_counter
        self.inst_gen = gen
        self.inst_period = period
        self.inst_root = committee_root.bytes
        self.inst_cursor = UInt64(0)
        self.inst_state = UInt64(INST_STATE_VALIDATED)

        # Seed the store's initial finalized/attested state from the
        # bootstrap header (mirrors `initialize_light_client_store`) so
        # `submit_update`'s period/monotonicity checks have a real base.
        self.fin_slot = slot
        self.fin_root = root
        self.fin_state_root = state_root
        self.att_slot = slot
        self.att_state_root = state_root

    # ---- committee install session (§8) -----------------------------------

    @arc4.abimethod
    def install_begin(self, period: arc4.UInt64) -> None:
        """§8.3. Permissionless (any relayer may drive/resume a session,
        mirroring `retire`'s permissionless design, §12.4 item 5) --
        correctness rests entirely on `g1_bind` + the merkle-root check in
        `install_finalize`, not on who calls this.

        Validates and reserves a generation id ONLY (`INST_STATE_VALIDATED`,
        §16) -- touches no box references at all. `install_open_keys` then
        `install_open_session` MUST follow, in the SAME atomic group, to
        create the boxes and complete the install session -- see those
        methods and `install.py`'s module docstring for why atomicity (not
        just the `inst_state` guard below) is what keeps a partially-open
        box set from ever being observable on-chain.
        """
        assert self.inst_state == UInt64(INST_STATE_IDLE), "a session is already in flight"
        p = period.native
        assert p == self.cur_period + UInt64(1), "period must be exactly cur_period + 1"
        assert self.next_committee_root_period == p, "no trusted root established for this period"
        root = self.next_committee_root_trusted
        assert root != zero32(), "next-committee root not yet established"

        self.gen_counter += UInt64(1)
        gen = self.gen_counter
        self.inst_gen = gen
        self.inst_period = p
        self.inst_root = root
        self.inst_cursor = UInt64(0)
        self.inst_state = UInt64(INST_STATE_VALIDATED)

    @arc4.abimethod
    def install_open_keys(self) -> None:
        """§8.3, §16: box-opening PHASE 1, shared by both the `bootstrap`
        and `install_begin` flows (either may have set `INST_STATE_VALIDATED`
        for the in-flight `inst_gen`). Creates `k:<inst_gen>:0..7` -- exactly
        `BOXES_PER_COMMITTEE` (8) box references, the measured per-transaction
        cap, so this call's OWN box-reference array has no room for anything
        else. Flips `inst_state` to `OPENING_BOXES`. Permissionless, matching
        `install_begin`/`retire`'s design.

        MUST run in the same atomic group as the preceding
        `bootstrap`/`install_begin` call: if this call fails or is omitted,
        Algorand rolls back the whole group, including whatever that
        preceding call did, so `INST_STATE_VALIDATED` can never persist
        on-chain past a single (failed, fully-reverted) group either.
        """
        assert self.inst_state == UInt64(INST_STATE_VALIDATED), "no validated install session in flight"
        install_open_key_boxes(self.inst_gen)  # phase 1 of 2 box-creating calls (§16)
        self.inst_state = UInt64(INST_STATE_OPENING_BOXES)

    @arc4.abimethod
    def install_open_session(self) -> None:
        """§8.3, §16: box-opening PHASE 2. Creates `s:<inst_gen>` and flips
        `inst_state` from `OPENING_BOXES` to `INSTALLING`, unblocking
        `install_chunk`/`install_finalize`. Permissionless, matching
        `install_begin`/`retire`'s design -- correctness rests on the
        `inst_state` guard plus the atomic-group all-or-nothing property,
        not on who calls this.

        MUST run in the same atomic group as `install_open_keys` (§16): if
        this call is omitted or fails, Algorand rolls back the WHOLE group,
        including phase 1's box creates -- so `inst_state == OPENING_BOXES`
        can never persist on-chain past a single (failed, fully-reverted)
        group.
        """
        assert self.inst_state == UInt64(INST_STATE_OPENING_BOXES), "no box-opening phase in flight"
        install_open_session_box(self.inst_gen)  # phase 2 of 2 box-creating calls (§16)
        self.inst_state = UInt64(INST_STATE_INSTALLING)

    @arc4.abimethod
    def install_chunk(
        self, index: arc4.UInt64, compressed: arc4.DynamicBytes, uncompressed: arc4.DynamicBytes
    ) -> None:
        """§8.3, §12.4 item 4: `index` must match the session cursor
        EXACTLY -- resumption after a failed group is a retry from
        `inst_cursor`, never a restart (§12.4 item 5)."""
        assert self.inst_state == UInt64(INST_STATE_INSTALLING), "no install session in flight"
        assert index.native == self.inst_cursor, "index must equal the session cursor"
        self.inst_cursor = install_process_chunk(
            self.inst_gen, self.inst_cursor, compressed.native, uncompressed.native
        )

    @arc4.abimethod
    def install_finalize(
        self, aggregate_compressed: Bytes48, aggregate_uncompressed: Bytes96
    ) -> None:
        """§8.3. THE check: the merkleized root of the 512 bound keys plus
        the bound aggregate key must equal `inst_root`. Only after that
        passes does this generation become reachable from `submit_update`
        (§15 item 8) -- via `cur_gen` if this is the genesis install, else
        `next_gen` (module docstring elaboration 1)."""
        assert self.inst_state == UInt64(INST_STATE_INSTALLING), "no install session in flight"
        gen = self.inst_gen
        a_total = install_process_finalize(
            gen,
            self.inst_cursor,
            self.inst_root,
            aggregate_compressed.bytes,
            aggregate_uncompressed.bytes,
        )
        _created = op.Box.create(total_box_name(gen), UInt64(G1_UNCOMPRESSED_BYTES))
        op.Box.replace(total_box_name(gen), UInt64(0), a_total)

        if self.cur_gen == UInt64(0):
            self.cur_gen = gen
            self.cur_period = self.inst_period
        else:
            self.next_gen = gen
            self.next_period = self.inst_period

        self.inst_state = UInt64(INST_STATE_IDLE)
        self.inst_gen = UInt64(0)
        self.inst_period = UInt64(0)
        self.inst_root = zero32()
        self.inst_cursor = UInt64(0)

    @arc4.abimethod
    def install_abort(self) -> None:
        """§8.3, §10.3: governance-only manual recovery -- e.g. the
        pathological divergent-`next_committee_root` case, a stop-the-bridge
        event, not a retry.

        §16: handles all THREE non-idle states, since box creation now has
        three checkpoints, not one. `VALIDATED` -- `bootstrap`/`install_begin`
        ran but neither `install_open_keys` nor `install_open_session` has,
        so NO boxes exist yet; nothing to delete. `OPENING_BOXES` --
        `install_open_keys` ran but `install_open_session` has not, so only
        `k:<gen>:*` exist. `INSTALLING` -- box-opening completed and
        `s:<gen>` exists too."""
        assert Txn.sender == self.gov, "governance only"
        assert (
            self.inst_state == UInt64(INST_STATE_VALIDATED)
            or self.inst_state == UInt64(INST_STATE_OPENING_BOXES)
            or self.inst_state == UInt64(INST_STATE_INSTALLING)
        ), "no install session in flight"
        if self.inst_state == UInt64(INST_STATE_OPENING_BOXES):
            install_abort_key_boxes(self.inst_gen)
        elif self.inst_state == UInt64(INST_STATE_INSTALLING):
            install_abort_boxes(self.inst_gen)
        # else INST_STATE_VALIDATED: no boxes exist yet, nothing to delete.
        self.inst_state = UInt64(INST_STATE_IDLE)
        self.inst_gen = UInt64(0)
        self.inst_period = UInt64(0)
        self.inst_root = zero32()
        self.inst_cursor = UInt64(0)

    @arc4.abimethod
    def retire(self, gen: arc4.UInt64) -> None:
        """§8.4: permissionless, refunds MBR to the app account. Asserts
        the generation is not `cur_gen`/`next_gen`/`inst_gen`."""
        g = gen.native
        assert g != UInt64(0), "generation 0 is never a real committee"
        assert g != self.cur_gen, "generation is the active committee"
        assert g != self.next_gen, "generation is the staged next committee"
        assert g != self.inst_gen, "generation has an install session in flight"
        install_delete_committee_boxes(g)

    # ---- the per-update entry point ---------------------------------------

    @arc4.abimethod
    def submit_update(
        self,
        attested_header: Bytes112,
        finalized_header: Bytes112,
        finality_branch: arc4.DynamicBytes,
        next_committee_root: Bytes32,
        next_committee_branch: arc4.DynamicBytes,
        sync_committee_bits: Bytes64,
        signature: Bytes192,
        signature_slot: arc4.UInt64,
        mode: arc4.UInt8,
    ) -> None:
        """§6.1's 16-step ordering, cheap rejections before the
        55,474-budget pairing (§6.1)."""
        sig_slot = signature_slot.native
        attested_bytes = attested_header.bytes
        finalized_bytes = finalized_header.bytes

        attested_slot = header_slot(attested_bytes)
        finalized_slot = header_slot(finalized_bytes)  # 0 (GENESIS_SLOT) if absent (§10.4)

        # -- steps 3-4: slot ordering -----------------------------------
        assert sig_slot > attested_slot, "signature_slot must exceed attested_slot"
        assert attested_slot >= finalized_slot, "attested_slot must be >= finalized_slot"

        # -- step 5: period-skip rule + committee selection (§6.4) ------
        store_period = period_at_slot(self.fin_slot)
        update_signature_period = period_at_slot(sig_slot)
        assert (
            update_signature_period == store_period
            or update_signature_period == store_period + UInt64(1)
        ), "signature period skips a sync-committee period"

        using_next = update_signature_period == store_period + UInt64(1)
        if using_next:
            assert self.next_gen != UInt64(0), "next committee is not known"
            committee_gen = self.next_gen
        else:
            assert self.cur_gen != UInt64(0), "no committee installed"
            committee_gen = self.cur_gen

        # -- steps 6-7: two independent slot-keyed table lookups (§4.4,
        #    §15 item 2 -- never collapse these into one lookup) ----------
        fork_version = forks.lookup_fork_version(
            self.fork_count, fork_version_epoch_for_signature_slot(sig_slot)
        )
        finality_gindex, _current_sc_gindex, next_sc_gindex = forks.lookup_gindices(
            self.fork_count, epoch_at_slot(attested_slot)
        )

        # -- steps 8-9: SSZ branches, BEFORE the signature check (§6.1: a
        #    branch failure is a rejection either way; this makes a
        #    malformed update cheap to reject). `attested_state_root` is
        #    the header's own claimed state_root -- untrusted until step 15
        #    confirms the signature over this exact header. --------------
        attested_state_root = attested_bytes[48:80]

        if finalized_slot == UInt64(0):
            finalized_leaf = zero32()  # §10.4: unknown finality -> Bytes32() leaf, not htr(zero header)
        else:
            finalized_leaf = hash_tree_root_beacon_block_header(finalized_bytes)
        assert_valid_normalized_merkle_branch(
            finalized_leaf, finality_branch.native, finality_gindex, attested_state_root
        )

        next_branch_bytes = next_committee_branch.native
        has_next_proof = next_branch_bytes.length > UInt64(0)
        if has_next_proof:
            assert_valid_normalized_merkle_branch(
                next_committee_root.bytes, next_branch_bytes, next_sc_gindex, attested_state_root
            )

        # -- step 10: fused bitfield walk + adaptive aggregation (§5) ----
        agg_pubkey, popcount = aggregate_participants(
            sync_committee_bits.bytes, committee_gen, mode.native
        )

        # -- step 11: participation floor --------------------------------
        assert popcount >= UInt64(MIN_SYNC_COMMITTEE_PARTICIPANTS), "insufficient participation"

        # -- steps 12-15: domain, signing root, hash_to_g2, pairing ------
        domain = compute_domain(domain_sync_committee(), fork_version, self.gvr)
        signing_root = compute_signing_root(attested_bytes, domain)
        msg_point = hash_to_g2(signing_root, eth_dst())
        # `agg_pubkey` came only from the fused walk over `k:<gen>:*` /
        # `a:<gen>` (§10.2's T12-analogue property) -- never from calldata.
        assert verify_aggregate_signature(
            agg_pubkey, msg_point, signature.bytes
        ), "aggregate signature verification failed"

        # -- step 16: apply -----------------------------------------------
        # §10.3: reject a next-committee proof that diverges from an
        # in-flight install session's already-trusted root for the same
        # period -- a reorg-deeper-than-finality stop-the-bridge event.
        if has_next_proof:
            next_period = period_at_slot(attested_slot) + UInt64(1)
            if self.inst_state == UInt64(INST_STATE_INSTALLING) and self.inst_period == next_period:
                assert next_committee_root.bytes == self.inst_root, "next-committee root diverges from in-flight install"
            # Discover the next committee's root opportunistically (mirrors
            # the spec's "supply sync committee from a past update"): only
            # meaningful while it is genuinely the *next* period relative
            # to the store, and only from an update signed in the CURRENT
            # period (module docstring elaboration 2).
            if not using_next and next_period == store_period + UInt64(1):
                if self.next_committee_root_period == next_period:
                    assert (
                        next_committee_root.bytes == self.next_committee_root_trusted
                    ), "next-committee root diverges from a previously trusted root"
                else:
                    self.next_committee_root_trusted = next_committee_root.bytes
                    self.next_committee_root_period = next_period

        has_supermajority = (
            popcount * UInt64(TWO_THIRDS_DENOMINATOR)
            >= UInt64(SYNC_COMMITTEE_SIZE) * UInt64(TWO_THIRDS_NUMERATOR)
        )
        advances = has_supermajority and finalized_slot > self.fin_slot
        if advances:
            if using_next:
                # Rollover: the committee that just proved 2/3 finality was
                # `next_gen` -- promote it (§8.4).
                self.cur_gen = self.next_gen
                self.cur_period = self.next_period
                self.next_gen = UInt64(0)
                self.next_period = UInt64(0)

            self.fin_slot = finalized_slot
            self.fin_root = finalized_leaf
            self.fin_state_root = finalized_bytes[48:80] if finalized_slot != UInt64(0) else zero32()
            self.att_slot = attested_slot
            self.att_state_root = attested_state_root

            arc4.emit(
                LightClientUpdateVerified(
                    arc4.UInt64(finalized_slot),
                    Bytes32.from_bytes(finalized_leaf),
                    Bytes32.from_bytes(self.fin_state_root),
                    arc4.UInt64(attested_slot),
                    Bytes32.from_bytes(attested_state_root),
                    arc4.UInt64(popcount),
                    arc4.UInt64(sig_slot),
                )
            )

    @arc4.abimethod
    def noop_budget(self) -> None:
        """§7.3, §9.4: group filler that carries extra box references and
        pools +700 budget. Asserts nothing, writes nothing.

        §16: this is also the natural vehicle for the extra (real or
        never-touched "padding") box references the
        `bootstrap`/`install_begin` -> `install_open_keys` ->
        `install_open_session` box-opening group needs to clear the pooled
        write-budget floor (`constants.MIN_BOX_REFS_FOR_INSTALL_OPEN`,
        measured at 25) -- the relayer attaches spare box refs to one or
        more `noop_budget()` calls in that same atomic group. No contract
        change was needed for this: box references are a transaction-level
        field the caller sets, not an ABI argument."""
        pass

    @arc4.abimethod
    def donor(self) -> None:
        """§7.3, §2.4: inner-call target for budget donation (18 to issue,
        +700 pooled -> net +682, §2.4)."""
        pass

    # ---- output for M8 ------------------------------------------------

    @arc4.abimethod(readonly=True)
    def get_finalized(
        self,
    ) -> arc4.Tuple[
        arc4.UInt64, Bytes32, Bytes32, arc4.UInt64, Bytes32, arc4.UInt64
    ]:
        """§7.4: the latest verified, 2/3-finalized tuple. A zero
        `finalized_beacon_root` means "no finality yet" (§10.4) -- M8 must
        refuse to anchor it. Not an inner call from `submit_update`: §9.4
        requires M8 to read this via a LATER transaction in the same
        group, since `submit_update` uses all 256 inner-call slots."""
        return arc4.Tuple(
            (
                arc4.UInt64(self.fin_slot),
                Bytes32.from_bytes(self.fin_root),
                Bytes32.from_bytes(self.fin_state_root),
                arc4.UInt64(self.att_slot),
                Bytes32.from_bytes(self.att_state_root),
                arc4.UInt64(self.cur_period),
            )
        )
