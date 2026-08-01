"""
contracts/composer/bridge.py -- design doc §5.1: the bridge from a
terminated phase-A (or phase-B) M5 walk into the composite state C. This is
the module's security core, restated here so a reviewer does not have to
cross-reference: `mpt6_bridge_account` MUST be called in the SAME
transaction as the account walk's terminal `mpt_walk_node` call, on the
SAME `node` buffer that call was given, using the `value_off`/`value_len`
THAT SAME CALL returned. `storage_root` never exists as a value outside
that one call frame until it is written into `C` -- it is never an
argument, never staged in a box, never read back from anywhere but this
one, same-transaction extraction (§5's whole point, §5.5's rejected
alternatives).

`contracts/composer/bench_app.py`'s driver enforces the "same transaction"
half of this contract structurally: it calls `mpt6_bridge_account` from
inside the very node-argument loop that produced the terminal walk status,
never from a value recovered out of a log.
"""
from algopy import Bytes, UInt64, subroutine, op

from contracts.composer.account import mpt6_account_body, mpt6_storage_value
from contracts.composer.state import (
    C_ABSENT_ACCOUNT,
    C_ABSENT_SLOT,
    C_ABSENT_SLOT_EMPTY_TRIE,
    C_INCLUDED,
    C_PENDING_STORAGE,
    C_ZERO_ENTRY,
    PHASE_A_OK,
    PHASE_DONE,
    byte1,
)
from contracts.mpt.state import WALK_INCLUDED

# §9.1: keccak256(rlp("")) == keccak256(0x80) -- the empty-trie root.
EMPTY_TRIE_ROOT = (
    b"\x56\xe8\x1f\x17\x1b\xcc\x55\xa6\xff\x83\x45\xe6\x92\xc0\xf8\x6e"
    b"\x5b\x48\xe0\x1b\x99\x6c\xad\xc0\x01\x62\x2f\xb5\xe3\x63\xb4\x21"
)
# §8.1: keccak256("") -- the EOA code-hash constant.
EMPTY_CODE_HASH = (
    b"\xc5\xd2\x46\x01\x86\xf7\x23\x3c\x92\x7e\x7d\xb2\xdc\xc7\x03\xc0"
    b"\xe5\x00\xb6\x53\xca\x82\x27\x3b\x7b\xfa\xd8\x04\x5d\x85\xa4\x70"
)


@subroutine
def mpt6_bridge_account(c: Bytes, walk_status: UInt64, node: Bytes,
                         value_off: UInt64, value_len: UInt64) -> Bytes:
    """§5.1: fires in whichever segment the phase-A walk reaches a terminal
    M5 status (`WALK_INCLUDED` or any `WALK_ABSENT_*`). `walk_status`,
    `node`, `value_off`, `value_len` must all come from the SAME
    `mpt_walk_node` call, in the SAME transaction as this call -- carrying
    a span or a raw node byte string across a transaction boundary would be
    meaningless/insecure (§5.1's own reasoning).

    §8.1 (WALK_ABSENT_* -- no state-trie entry): C terminates immediately.
    No phase B is issued or accepted. `storage_root`/`code_hash` are filled
    with the consensus-defined non-existent-account constants;
    `nonce`/`balance` stay zero (already zero from `mpt6_init_composite`).

    §5.1 step 3 / §9.1 (WALK_INCLUDED): decode the account body from the
    SAME node buffer (`mpt6_account_body`, §4.2), write `storage_root`,
    `code_hash`, `nonce`, `balance` into C. If the extracted `storage_root`
    equals `EMPTY_TRIE_ROOT`, terminate immediately with
    `C_ABSENT_SLOT_EMPTY_TRIE` (§9.1's genuine finding: walking an empty
    trie aborts inside M2 with "R1" rather than returning an M5 absence
    code, so this must be special-cased here, before phase B ever starts).
    Otherwise `C.cstatus = C_PENDING_STORAGE`, `C.phase = PHASE_A_OK` --
    the ONLY place `PHASE_A_OK` is ever written, and therefore the only way
    `MODE_B_INIT`'s `A15` check (handoff.py) can ever pass.
    """
    if walk_status != UInt64(WALK_INCLUDED):
        c2 = op.replace(c, UInt64(0), byte1(UInt64(C_ABSENT_ACCOUNT)))
        c2 = op.replace(c2, UInt64(1), byte1(UInt64(PHASE_DONE)))
        c2 = op.replace(c2, UInt64(86), Bytes(EMPTY_TRIE_ROOT))
        c2 = op.replace(c2, UInt64(118), Bytes(EMPTY_CODE_HASH))
        c2 = op.replace(c2, UInt64(246), byte1(walk_status))
        return c2

    storage_root, code_hash, nonce32, balance32 = mpt6_account_body(node, value_off, value_len)
    c2 = op.replace(c, UInt64(86), storage_root)
    c2 = op.replace(c2, UInt64(118), code_hash)
    c2 = op.replace(c2, UInt64(150), nonce32)
    c2 = op.replace(c2, UInt64(182), balance32)
    c2 = op.replace(c2, UInt64(246), byte1(UInt64(WALK_INCLUDED)))
    if storage_root == Bytes(EMPTY_TRIE_ROOT):
        c2 = op.replace(c2, UInt64(0), byte1(UInt64(C_ABSENT_SLOT_EMPTY_TRIE)))
        c2 = op.replace(c2, UInt64(1), byte1(UInt64(PHASE_DONE)))
        return c2
    c2 = op.replace(c2, UInt64(0), byte1(UInt64(C_PENDING_STORAGE)))
    c2 = op.replace(c2, UInt64(1), byte1(UInt64(PHASE_A_OK)))
    return c2


@subroutine
def mpt6_bridge_storage(c: Bytes, walk_status: UInt64, node: Bytes,
                         value_off: UInt64, value_len: UInt64) -> Bytes:
    """Phase-B terminal handling: fires in whichever segment the phase-B
    walk reaches a terminal M5 status, on the SAME node buffer (same
    same-transaction discipline as `mpt6_bridge_account`, though this half
    carries no root-forging risk -- phase B's root was already bound at
    `MODE_B_INIT`, handoff.py's A7/A8/A15/A16).

    §8.2 (any WALK_ABSENT_* -- no storage-trie entry): `C_ABSENT_SLOT`,
    value stays 32 zero bytes (already zero). `swalk` records which M5
    absence form was reached.

    §4.4/§9.2 (WALK_INCLUDED): decode the RLP-encoded value
    (`mpt6_storage_value`) and write the normalised 32-byte word.
    `content_len == 0` (the RLP empty string `0x80` actually present in the
    trie) is `C_ZERO_ENTRY`, distinguished from `C_ABSENT_SLOT` even though
    both carry a zero `C.value` (§8.2's "absent <=> zero" claim stays
    auditable rather than assumed away).

    `C.phase = PHASE_DONE` unconditionally -- this IS the composite's
    terminal step whichever branch is taken.
    """
    c2 = op.replace(c, UInt64(1), byte1(UInt64(PHASE_DONE)))
    c2 = op.replace(c2, UInt64(247), byte1(walk_status))
    if walk_status != UInt64(WALK_INCLUDED):
        c2 = op.replace(c2, UInt64(0), byte1(UInt64(C_ABSENT_SLOT)))
        return c2
    value32, is_zero = mpt6_storage_value(node, value_off, value_len)
    c2 = op.replace(c2, UInt64(214), value32)
    if is_zero:
        c2 = op.replace(c2, UInt64(0), byte1(UInt64(C_ZERO_ENTRY)))
    else:
        c2 = op.replace(c2, UInt64(0), byte1(UInt64(C_INCLUDED)))
    return c2
