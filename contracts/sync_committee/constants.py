"""M4 constants: domain separation, DST, presets, and the fields M4 owns
that M1 deliberately does not hard-code.

Design doc: docs/design/004-sync-committee.md §3.1-§3.2, §4.1, §6.2, §7.2.

Implementation note on module "constants" (same pattern `codec.py` (M1)
established, see that module's docstring): Puya only allows plain-Python
literals (`int`, `str`, `bytes`) at module scope -- not constructed
`algopy`-typed values. Every typed constant here is therefore a plain
literal plus a zero-argument `@subroutine` accessor. Callers use the
accessor functions, never the raw literals.
"""

from algopy import Bytes, UInt64, subroutine

# ---------------------------------------------------------------------------
# Domain separation (§3.1, §3.2). DOMAIN_SYNC_COMMITTEE and ETH_DST are
# declared ONCE, here, and passed explicitly at the single hash_to_g2 call
# site in header.py. Never hard-code either inside contracts/primitives/bls
# (implementer checklist §15 item 1; M1's hash_to_curve.py module docstring).
# ---------------------------------------------------------------------------
DOMAIN_SYNC_COMMITTEE_HEX = "07000000"  # 4 bytes

# BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ -- 43 bytes, the Ethereum
# consensus-layer signature DST (NOT RFC 9380's own QUUX-... DST, and NOT
# the proof-of-possession suite's DST used for validator registration).
ETH_DST_HEX = (
    "424c535f5349475f424c53313233383147325f584d443a534841"
    "2d3235365f535357555f524f5f504f505f"
)

# ---------------------------------------------------------------------------
# Presets (§4.1: `presets/mainnet/altair.yaml`, v1.6.0-beta.0). These are
# PRESET values (fixed at contract-compile-time, not config values), so they
# are ordinary Python ints -- never runtime parameters. A runtime committee
# size would let a caller resize the box layout (§5.1).
# ---------------------------------------------------------------------------
SYNC_COMMITTEE_SIZE = 512
SYNC_COMMITTEE_BITS_BYTES = SYNC_COMMITTEE_SIZE // 8  # 64
MIN_SYNC_COMMITTEE_PARTICIPANTS = 1

# `configs/mainnet.yaml`, v1.6.0-beta.0.
SLOTS_PER_EPOCH = 32
EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256

# 2/3 rule (§6.3): 3 * popcount >= 2 * SYNC_COMMITTEE_SIZE.
TWO_THIRDS_NUMERATOR = 2
TWO_THIRDS_DENOMINATOR = 3

# ---------------------------------------------------------------------------
# Wire shapes (§7.2, §7.3).
# ---------------------------------------------------------------------------
BEACON_HEADER_BYTES = 112
G1_COMPRESSED_BYTES = 48
G1_UNCOMPRESSED_BYTES = 96

# ---------------------------------------------------------------------------
# Box layout (§8.2). 8 boxes of 64 keys each -> finer box-reference
# granularity than 2 boxes of 256 (§8.2's rationale).
# ---------------------------------------------------------------------------
KEYS_PER_BOX = 64
BOXES_PER_COMMITTEE = SYNC_COMMITTEE_SIZE // KEYS_PER_BOX  # 8
KEY_BOX_BYTES = KEYS_PER_BOX * G1_UNCOMPRESSED_BYTES  # 6,144 B

# merkleize_stack_push/_finalize target depth for a 512-leaf Vector:
# ceil(log2(512)) = 9. Session-scratch stack needs depth+1 = 10 slots.
COMMITTEE_MERKLE_DEPTH = 9
SESSION_STACK_SLOTS = COMMITTEE_MERKLE_DEPTH + 1  # 10
SESSION_STACK_BYTES = SESSION_STACK_SLOTS * 32  # 320 B
# session scratch box `s:<gen>` (§8.2): merkle stack + filled mask (8 B,
# native itob) + running G1 sum (96 B, AVM-uncompressed).
SESSION_FILLED_BYTES = 8
SESSION_BOX_BYTES = SESSION_STACK_BYTES + SESSION_FILLED_BYTES + G1_UNCOMPRESSED_BYTES  # 424 B

# `inst_state` values (§8.2, revised §16). Three non-idle states, not one,
# because live testing found TWO independent instances of the same
# box-reference-cap bug (§16): the original 9-refs-in-one-call
# `install_open_boxes`, AND `bootstrap` itself needing the `forks` box (a
# READ, for the gindex lookup) plus 8 key-box CREATEs in what used to be one
# call -- 9 references either way. The fix decouples validation (which may
# need to read `forks`) from box creation entirely, so `VALIDATED` and
# `OPENING_BOXES` are genuinely different sub-states, not just a stylistic
# split of one:
#
#   VALIDATED       -- `bootstrap`/`install_begin` has validated its inputs
#                      and reserved a generation id (`inst_gen` etc.), but
#                      created NO boxes yet. 0 or 1 box refs needed (only
#                      `forks`, for `bootstrap`'s gindex lookup).
#   OPENING_BOXES   -- `install_open_keys` has created `k:<gen>:0..7` (8
#                      refs, exactly the measured per-txn cap). Session box
#                      does not exist yet.
#   INSTALLING      -- `install_open_session` has created `s:<gen>` too.
#                      `install_chunk`/`install_finalize` may now run.
#
# None of the three is observable on-chain outside of a single in-flight
# atomic group: the group's all-or-nothing guarantee means either every
# phase commits (state ends at INSTALLING) or none do (the whole group,
# including any box creates already run, rolls back together).
INST_STATE_IDLE = 0
INST_STATE_VALIDATED = 1
INST_STATE_OPENING_BOXES = 2
INST_STATE_INSTALLING = 3

# ---------------------------------------------------------------------------
# Box reference / write-budget constants (§16). MEASURED against a real
# dev-mode algod (go-algorand, `docker` recipe in
# tests/fixtures/spike-reference/README.md), not read off documentation --
# see docs/design/004-sync-committee.md §16 for the full experiment log.
# ---------------------------------------------------------------------------
# Hard per-TRANSACTION cap on the `boxes` array length. Structural txn-field
# validation, enforced before the AVM program even runs (error observed
# verbatim: "tx.Boxes too long, max number of box references is 8") --
# not an opcode-budget or simulate artifact.
MAX_BOX_REFS_PER_TXN = 8

# Per-box-reference budget, in bytes, POOLED ACROSS THE WHOLE ATOMIC GROUP
# (confirmed empirically: a transaction can write/touch MORE than its own
# refs would allow alone, as long as a sibling transaction in the same group
# carries additional box references -- real or "padding" refs to box names
# that are never touched -- to cover the shortfall; duplicate refs to an
# already-real box name, in the same txn or a sibling one, count again too).
# Measured at 2048 B/ref via TWO separate error families that algod reports
# distinctly (NOT confirmed to share one pool -- §16.5 flags this precision
# gap explicitly):
#   * `box_create` on a brand-new box -> "write budget (N) exceeded M".
#     1 ref -> 2048, 8 refs -> 16384: exactly 2048 B/ref, linear.
#   * `box_extract`/`box_replace` on an EXISTING box -> "box read budget (N)
#     exceeded M", charged at the box's FULL DECLARED SIZE regardless of the
#     touched slice, once per box per group regardless of operation count.
#     1 ref -> 2048 (a 6,144 B box's full-size touch fails at 1 ref, exactly
#     the 6,144 B a 3-ref/6,144-budget touch clears).
# `install_open_key_boxes`/`install_open_session_box` (pure `box_create`,
# §8.3 box-opening) draw on the write pool; `install_process_chunk`/
# `install_process_finalize` (which `box_extract`/`box_replace` existing
# boxes) draw on the read pool -- see `MIN_BOX_REFS_FOR_INSTALL_OPEN` below
# for the former; the latter is NOT similarly precomputed here because it
# was only spot-checked for a single small chunk (§16.5), not re-derived for
# every chunk size across a full 512-member install.
BOX_WRITE_BUDGET_BYTES_PER_REF = 2048

# Total bytes `install_open_key_boxes` + `install_open_session_box` WRITE
# (via `box_create`) per generation: BOXES_PER_COMMITTEE key boxes
# (KEY_BOX_BYTES each) + one session box (SESSION_BOX_BYTES).
# 8*6144 + 424 = 49,576 B.
INSTALL_BOX_WRITE_BYTES = 8 * 6144 + 424

# Minimum total box references (real + padding) the CALLER must spread
# across the box-opening atomic group to clear the pooled write budget:
# ceil(49576 / 2048) = 25. This is a client/relayer-side concern (which
# transactions carry which box refs), not something the contract enforces
# -- documented here so the number has one source of truth instead of being
# re-derived at each call site.
MIN_BOX_REFS_FOR_INSTALL_OPEN = 25


@subroutine
def domain_sync_committee() -> Bytes:
    """`DOMAIN_SYNC_COMMITTEE = 0x07000000` (§3.1)."""
    return Bytes.from_hex(DOMAIN_SYNC_COMMITTEE_HEX)


@subroutine
def eth_dst() -> Bytes:
    """`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, 43 bytes (§3.1)."""
    return Bytes.from_hex(ETH_DST_HEX)


@subroutine
def sync_committee_size() -> UInt64:
    return UInt64(SYNC_COMMITTEE_SIZE)


@subroutine
def min_sync_committee_participants() -> UInt64:
    return UInt64(MIN_SYNC_COMMITTEE_PARTICIPANTS)


@subroutine
def slots_per_epoch() -> UInt64:
    return UInt64(SLOTS_PER_EPOCH)


@subroutine
def epochs_per_sync_committee_period() -> UInt64:
    return UInt64(EPOCHS_PER_SYNC_COMMITTEE_PERIOD)


@subroutine
def epoch_at_slot(slot: UInt64) -> UInt64:
    """`epoch(slot) = slot // SLOTS_PER_EPOCH` (§4.4)."""
    return slot // UInt64(SLOTS_PER_EPOCH)


@subroutine
def period_at_epoch(epoch: UInt64) -> UInt64:
    """`period(epoch) = epoch // EPOCHS_PER_SYNC_COMMITTEE_PERIOD` (§4.4)."""
    return epoch // UInt64(EPOCHS_PER_SYNC_COMMITTEE_PERIOD)


@subroutine
def period_at_slot(slot: UInt64) -> UInt64:
    """`period(slot) = epoch(slot) // EPOCHS_PER_SYNC_COMMITTEE_PERIOD`."""
    return period_at_epoch(epoch_at_slot(slot))


@subroutine
def fork_version_epoch_for_signature_slot(signature_slot: UInt64) -> UInt64:
    """`epoch(max(signature_slot, 1) - 1)` -- §3.1 trap 3 / §4.4 / §15 item 2.

    THE off-by-one the design doc's whole §3.1/§10.5 discussion is about:
    the fork version is resolved one slot BEFORE the signature slot, never
    at the signature slot itself. Getting this right breaks exactly one
    update per fork if wrong -- the hardest possible failure to catch in
    testing (§3.1).
    """
    fork_version_slot = signature_slot - UInt64(1) if signature_slot >= UInt64(1) else UInt64(0)
    return epoch_at_slot(fork_version_slot)
