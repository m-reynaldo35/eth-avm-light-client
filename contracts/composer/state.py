"""
contracts/composer/state.py -- the composite state C (design doc §3.3) and
its status/phase discriminators (§3.1, §3.2).

C is a fixed 248-byte buffer, never variable width -- the same "fixed
width, not variable" design note M5's W makes (contracts/mpt/state.py).
Every accessor here is a constant-offset extract3/getbyte; every update
elsewhere in this package (bridge.py) is an `op.replace` splice of only the
field that changes (§3.3's design note, M5 §16.2's measured lesson applied
from line one).

Layout (§3.3):
    offset  size  field           mutability
       0      1   cstatus         per-step
       1      1   phase           per-step
       2     32   state_root      IMMUTABLE (set at A_INIT)
      34     20   address         IMMUTABLE (set at A_INIT)
      54     32   slot            IMMUTABLE (set at A_INIT)
      86     32   storage_root    write-once (bridge, §5.1)
     118     32   code_hash       write-once (bridge)
     150     32   nonce           write-once (bridge)
     182     32   balance         write-once (bridge)
     214     32   value           write-once (terminal)
     246      1   awalk           write-once (bridge/absent)
     247      1   swalk           write-once (terminal)
"""
from algopy import Bytes, UInt64, subroutine, op

# --- §3.1 composite status discriminator ------------------------------------
C_PENDING_ACCOUNT = 0  # phase A in progress; NOT a verdict
C_PENDING_STORAGE = 1  # account proven present, phase B in progress; NOT a verdict
C_INCLUDED = 2  # slot present; C.value is its 32-byte value
C_ABSENT_ACCOUNT = 3  # no state-trie entry for the address (§8.1)
C_ABSENT_SLOT = 4  # account present, no storage-trie entry for the slot (§8.2)
C_ABSENT_SLOT_EMPTY_TRIE = 5  # account present with an EMPTY storage trie (§9.1)
C_ZERO_ENTRY = 6  # slot present but its RLP value is the empty string (§9.2)

# --- §3.2 phase ---------------------------------------------------------
PHASE_A = 0  # walking the state trie
PHASE_A_OK = 1  # account leaf proven and decoded; storage_root extracted
PHASE_B = 2  # walking the storage trie
PHASE_DONE = 3  # terminal

C_LEN = 248

_OFF_CSTATUS = 0
_OFF_PHASE = 1
_OFF_STATE_ROOT = 2
_OFF_ADDRESS = 34
_OFF_SLOT = 54
_OFF_STORAGE_ROOT = 86
_OFF_CODE_HASH = 118
_OFF_NONCE = 150
_OFF_BALANCE = 182
_OFF_VALUE = 214
_OFF_AWALK = 246
_OFF_SWALK = 247


@subroutine(inline=True)
def byte1(v: UInt64) -> Bytes:
    """The single low byte of `v` as a 1-byte Bytes -- shared by every
    1-byte field splice in this package (mirrors M5's inline itob/extract
    idiom for status bytes)."""
    return op.extract(op.itob(v), UInt64(7), UInt64(1))


@subroutine(inline=True)
def c_cstatus(c: Bytes) -> UInt64:
    return op.getbyte(c, UInt64(_OFF_CSTATUS))


@subroutine(inline=True)
def c_phase(c: Bytes) -> UInt64:
    return op.getbyte(c, UInt64(_OFF_PHASE))


@subroutine(inline=True)
def c_state_root(c: Bytes) -> Bytes:
    return op.extract(c, UInt64(_OFF_STATE_ROOT), UInt64(32))


@subroutine(inline=True)
def c_address(c: Bytes) -> Bytes:
    return op.extract(c, UInt64(_OFF_ADDRESS), UInt64(20))


@subroutine(inline=True)
def c_slot(c: Bytes) -> Bytes:
    return op.extract(c, UInt64(_OFF_SLOT), UInt64(32))


@subroutine(inline=True)
def c_storage_root(c: Bytes) -> Bytes:
    return op.extract(c, UInt64(_OFF_STORAGE_ROOT), UInt64(32))


@subroutine(inline=True)
def c_code_hash(c: Bytes) -> Bytes:
    return op.extract(c, UInt64(_OFF_CODE_HASH), UInt64(32))


@subroutine(inline=True)
def c_nonce(c: Bytes) -> Bytes:
    return op.extract(c, UInt64(_OFF_NONCE), UInt64(32))


@subroutine(inline=True)
def c_balance(c: Bytes) -> Bytes:
    return op.extract(c, UInt64(_OFF_BALANCE), UInt64(32))


@subroutine(inline=True)
def c_value(c: Bytes) -> Bytes:
    return op.extract(c, UInt64(_OFF_VALUE), UInt64(32))


@subroutine(inline=True)
def c_awalk(c: Bytes) -> UInt64:
    return op.getbyte(c, UInt64(_OFF_AWALK))


@subroutine(inline=True)
def c_swalk(c: Bytes) -> UInt64:
    return op.getbyte(c, UInt64(_OFF_SWALK))


@subroutine
def c_with_phase(c: Bytes, phase: UInt64) -> Bytes:
    """Splice only the 1-byte phase field (§3.3's `op.replace`-only rule)."""
    return op.replace(c, UInt64(_OFF_PHASE), byte1(phase))


@subroutine
def mpt6_init_composite(state_root: Bytes, address: Bytes, slot: Bytes) -> Bytes:
    """Build C0 (§3.3): cstatus := C_PENDING_ACCOUNT, phase := PHASE_A,
    `state_root`/`address`/`slot` fixed for the composite's whole lifetime
    (IMMUTABLE, TP-M6-3's basis), every write-once field zeroed.

    assert state_root.length == 32 -> "A20"
    assert address.length == 20    -> "A20"
    assert slot.length == 32       -> "A20"

    (A20 is an implementation addition beyond the design doc's own A1-A19
    table, documented here -- same convention M5's W17-W19 established.
    `address`'s width is also independently enforced by
    `mpt_key_from_address`'s W1 when MODE_A_INIT derives the account trie
    key from the same argument; this assert additionally protects the
    fixed-width splice into C itself, and is the only guard for `slot`,
    whose own length check (`mpt_key_from_slot`'s W2) does not run until
    phase B starts, §5.2 step 6 -- by which point `slot` is long since
    baked immutably into C.)
    """
    assert state_root.length == UInt64(32), "A20"
    assert address.length == UInt64(20), "A20"
    assert slot.length == UInt64(32), "A20"
    zero32 = op.bzero(UInt64(32))
    cstatus_b = byte1(UInt64(C_PENDING_ACCOUNT))
    phase_b = byte1(UInt64(PHASE_A))
    awalk_b = byte1(UInt64(0))
    swalk_b = byte1(UInt64(0))
    return (
        cstatus_b + phase_b + state_root + address + slot
        + zero32 + zero32 + zero32 + zero32 + zero32
        + awalk_b + swalk_b
    )
