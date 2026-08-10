"""M8 constants: record layout offsets, flags, error codes, box-name
prefixes, and the two-dimensional fork table's row shape.

Design doc: docs/design/008-trusted-root-anchor.md §3.3, §6.1, §6.2, §6.3,
§6.4.

Same module-scope-literal-plus-accessor pattern M4's `constants.py`
established (Puya only allows plain-Python literals at module scope, not
constructed `algopy`-typed values): every typed constant here is a plain
literal; call sites wrap it in `UInt64(...)`/`Bytes(...)` themselves, or use
a thin accessor where a value is used from more than one module.
"""

from algopy import UInt64, subroutine

# ---------------------------------------------------------------------------
# Record `A` layout (§6.1) -- fixed 154 bytes.
# ---------------------------------------------------------------------------
RECORD_LEN = 154

OFF_VERSION = 0
OFF_FLAGS = 1
OFF_BLOCK_NUMBER = 2
OFF_BEACON_SLOT = 10
OFF_STATE_ROOT = 18
OFF_RECEIPTS_ROOT = 50
OFF_BEACON_BLOCK_ROOT = 82
OFF_FINALITY_ROOT = 114
OFF_ANCHORED_ROUND = 146

VERSION_1 = 1

FLAG_REVOKED = 1  # bit0
FLAG_HISTORICAL = 2  # bit1
FLAG_PINNED = 4  # bit2

# ---------------------------------------------------------------------------
# Pinned-record layout: A (154 B) || payer address (32 B) = 186 B (§6.3).
# ---------------------------------------------------------------------------
PINNED_RECORD_LEN = RECORD_LEN + 32
OFF_PIN_PAYER = RECORD_LEN

# ---------------------------------------------------------------------------
# Box naming (§6.3). `itob` big-endian, mirroring M4's `forks.py`/`install.py`
# box-key convention -- these are OUR OWN box-key bytes, not SSZ chunks, so
# no endianness trap applies here (unlike header.py's SSZ fields).
# ---------------------------------------------------------------------------
RING_BOX_PREFIX = b"h:"  # h:<itob(residue)>  -- 10 B
PIN_BOX_PREFIX = b"p:"  # p:<itob(block_number)> -- 10 B

# ---------------------------------------------------------------------------
# Fork table row shape (§3.3). 40 bytes/row, 8-row capacity. Rows live in
# GLOBAL STATE, keyed by `FORK_ROW_KEY_PREFIX + itob(index)[7:8]` (docs/
# design/013 §3.1/§3.3 -- moved off box storage so create()'s MBR is charged
# to the creator, not the app's own not-yet-existent account):
#   activation_epoch      uint64 (8B)
#   g_state_root          uint64 (8B)
#   g_receipts_root       uint64 (8B)
#   g_block_number        uint64 (8B)
#   g_block_roots_base    uint64 (8B)
# `fork_count` lives in its own GLOBAL STATE slot (mirrors M4's own
# `forks.py` pattern, named in this module's file-layout comment as the
# module to mirror).
# ---------------------------------------------------------------------------
FORK_ROW_BYTES = 40
FORK_TABLE_CAPACITY = 8
if FORK_TABLE_CAPACITY > 256:
    # Row keys are FORK_ROW_KEY_PREFIX + itob(index)[7:8] -- a single index
    # byte -- so capacity above 256 would alias row i with row i + 256
    # (docs/design/013 §3.1, §9.1). A bare module-scope `assert` is REJECTED
    # unconditionally by puyapy 5.9.0 (`visit_assert_stmt` always raises
    # "unsupported statement type at module level" -- measured, not what
    # 013 §17 item 3 assumed); puyapy's `if` DOES constant-fold its
    # condition and skips an unreached branch entirely (`visit_if_stmt`),
    # so this raises a real compile error only if capacity is ever bumped
    # past the safe range, and compiles away to nothing otherwise.
    assert False, "FORK_TABLE_CAPACITY must be <= 256 for the single-index-byte row key"
FORK_ROW_KEY_PREFIX = b"g"

UINT64_MAX = 2**64 - 1

BLOCK_ROOTS_VECTOR_LOG2 = 13  # SLOTS_PER_HISTORICAL_ROOT = 8192 = 2**13
SLOTS_PER_HISTORICAL_ROOT = 8192

# ---------------------------------------------------------------------------
# ARC-4 return/log envelope (M5 §7.4, reused verbatim by every module's
# handoff.py in this codebase).
# ---------------------------------------------------------------------------
ARC4_RETURN_PREFIX = b"\x15\x1f\x7c\x75"
ATTEST_SELECTOR_METHOD = "attest(uint64)154"  # ARC-4 method signature attest is defined with


@subroutine
def record_len() -> UInt64:
    return UInt64(RECORD_LEN)
