"""
contracts/composer -- Puya library implementing M6: the account & storage
proof composer. See docs/design/006-account-storage-proof.md for the full
design.

The one new security property M6 owns (§0): `storage_root` is read out of a
transaction the AVM itself executed (the account walk's own terminal hop,
via the bridge, §5.1), never out of a caller argument. `MODE_B_INIT` (§5.2,
contracts/composer/bench_app.py) takes no root argument, no key argument and
no slot argument -- it derives everything it needs from `C`, which itself
came from the group's own execution record (`mpt6_state_from_prev`, §5.2).
This is what makes a relayer's honest, fully hash-chained storage proof for
a DIFFERENT contract fail at M5's own `W11` hash-chain check (§5.4) instead
of silently succeeding against a forged root.

This is a library of module-level `@subroutine`s -- no class, no global
state -- plus a driver app (`bench_app.py`) that is NOT a production app
(mirroring M5 §1.2's own caveat: M6 makes no root-anchoring claims; that is
M8's job, §13.2).

Trust preconditions (design doc §1.3), inherited/extended from M5:
  TP-M6-1 (state root)     -- R_state must already be a root the caller
                               trusts (M5's TP-M5-1, unchanged).
  TP-M6-2 (preimages)      -- M6 takes the 20-byte address and 32-byte slot,
                               never a pre-derived key.
  TP-M6-3 (consumer check) -- a terminal C must be checked by its consumer
                               against the (state_root, address, slot) it
                               actually asked about. `mpt6_result_from_group`
                               (§6.6, handoff.py) makes this unforgettable.
  TP-M6-4 (account bodies) -- the account leaf's body was hash-committed by
                               M5 before any of its bytes were parsed.

Data model (§3.3): the 248-byte composite state C is defined in state.py,
mirroring M5's W layout convention (fixed width, constant-offset access,
`op.replace` splice-only updates).

Error codes (§10), mirrored here, two-character, prefix `A`:
  A1   account body decode ran past the value span M5 returned
  A2   account body is not exactly 4 items (item3 does not end at payload_end)
  A3   storageRoot / codeHash is not a 32-byte RLP string
  A4   nonce / balance item longer than 32 bytes
  A5   storage value longer than 32 bytes after RLP decode
  A6   storage value span is not exactly one RLP item filling the span
  A7   phase A: recovered W.root != C.state_root
  A8   MODE_B_INIT against EMPTY_TRIE_ROOT (§9.1 already terminated the composite)
  A9   phase B: recovered W.root != C.storage_root
  A10  attempted to extend a composite whose phase is not the one this mode continues
  A11  hand-off: referenced group index does not precede this transaction
  A12  hand-off: referenced transaction is not a call to this application
  A13  hand-off: referenced transaction did not use SEGMENT_SELECTOR
  A14  hand-off: referenced transaction's last log is not a well-formed 355-byte composite log
  A15  MODE_B_INIT from a predecessor whose phase != PHASE_A_OK
  A16  MODE_B_INIT from a predecessor whose phase-A walk did not reach WALK_INCLUDED
  A17  mpt6_result_from_group: composite is not PHASE_DONE -- no verdict (§8.3)
  A18  mpt6_result_from_group: state_root / address / slot does not match what
       the consumer asked (TP-M6-3)
  A19  unknown mode byte
  --- implementation additions beyond the design doc's own A1-A19 table
      (documented here, not silently invented -- same convention M5's
      W17-W19 established):
  A20  internal: a fixed-width C field (state_root/address/slot) supplied to
       mpt6_init_composite was not exactly its declared width

M5's W1-W19 and M2's R1-R9 remain reachable through M6 unchanged; a W11 from
phase B specifically means "the first storage node does not hash to the
extracted storageRoot" -- §5.4's attack being caught. The driver app
(bench_app.py) additionally uses local, driver-only dispatch codes ("D1")
for concerns that are not part of this library's own security content,
exactly mirroring M5 bench_app.py's V2/V3 precedent.
"""
from contracts.composer.account import mpt6_account_body, mpt6_storage_value
from contracts.composer.bridge import (
    EMPTY_CODE_HASH,
    EMPTY_TRIE_ROOT,
    mpt6_bridge_account,
    mpt6_bridge_storage,
)
from contracts.composer.handoff import (
    ARC4_RETURN_PREFIX,
    LOG_LEN_M6,
    SEGMENT_SELECTOR,
    mpt6_log_state,
    mpt6_result_from_group,
    mpt6_state_from_prev,
)
from contracts.composer.state import (
    C_ABSENT_ACCOUNT,
    C_ABSENT_SLOT,
    C_ABSENT_SLOT_EMPTY_TRIE,
    C_INCLUDED,
    C_LEN,
    C_PENDING_ACCOUNT,
    C_PENDING_STORAGE,
    C_ZERO_ENTRY,
    PHASE_A,
    PHASE_A_OK,
    PHASE_B,
    PHASE_DONE,
    c_address,
    c_awalk,
    c_balance,
    c_code_hash,
    c_cstatus,
    c_nonce,
    c_phase,
    c_slot,
    c_state_root,
    c_storage_root,
    c_swalk,
    c_value,
    c_with_phase,
    mpt6_init_composite,
)

__all__ = [
    "C_LEN",
    "C_PENDING_ACCOUNT",
    "C_PENDING_STORAGE",
    "C_INCLUDED",
    "C_ABSENT_ACCOUNT",
    "C_ABSENT_SLOT",
    "C_ABSENT_SLOT_EMPTY_TRIE",
    "C_ZERO_ENTRY",
    "PHASE_A",
    "PHASE_A_OK",
    "PHASE_B",
    "PHASE_DONE",
    "c_cstatus",
    "c_phase",
    "c_state_root",
    "c_address",
    "c_slot",
    "c_storage_root",
    "c_code_hash",
    "c_nonce",
    "c_balance",
    "c_value",
    "c_awalk",
    "c_swalk",
    "c_with_phase",
    "mpt6_init_composite",
    "mpt6_account_body",
    "mpt6_storage_value",
    "EMPTY_TRIE_ROOT",
    "EMPTY_CODE_HASH",
    "mpt6_bridge_account",
    "mpt6_bridge_storage",
    "ARC4_RETURN_PREFIX",
    "LOG_LEN_M6",
    "SEGMENT_SELECTOR",
    "mpt6_log_state",
    "mpt6_state_from_prev",
    "mpt6_result_from_group",
]
