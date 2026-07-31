"""§8.3's install/session state machine, box-mechanics half. Box naming,
box lifecycle (create/delete), and the two heavy per-chunk / finalize
subroutines `verifier.py`'s ARC4 methods call. The `inst_*` control-flow
state (which generation is in flight, what period, what root, the cursor)
lives in `verifier.py`'s global state, per §8.2 -- this module owns only the
boxes and the security-critical checks that run against them.

Box naming (§8.2): `gen` is encoded as the native 8-byte big-endian `itob`
(this is our own box-key format, not an SSZ chunk -- no endianness trap
applies here, unlike header.py).

    k:<gen>:<j>   j in 0..7   -- 64 uncompressed G1 keys each (§8.2)
    a:<gen>                    -- A_total, the full-committee aggregate
    s:<gen>                    -- session scratch (stack + filled + running Σ)

THE trust boundary (§8.3, §10.2, §15 items 7-10) is enforced entirely in
`install_process_chunk`/`install_process_finalize`:

  * every stored key passes `g1_bind` against its committed compressed form
    BEFORE it is written to `k:<gen>:*` (§8.3 property 2);
  * `install_process_finalize` is the ONLY place `a:<gen>` is computed, and
    only after the merkleized root of every bound key equals the
    already-trusted `inst_root` (§8.3 property 1, §15 item 8) -- callers in
    `verifier.py` must write `a:<gen>` from this function's return value and
    must not accept any other source for it (§15 item 10);
  * storage is per member INDEX, never per key (§10.6, §15 item 11) -- a
    committee that samples the same validator twice must count it twice.

Box-opening is split across THREE phases (§16, post-approval fix): live
testing against a real dev-mode algod found creating all 9 boxes (8 key
boxes + 1 session box) in a single call/transaction impossible for TWO
independent reasons, both measured, not assumed (§16 has the full
experiment log) -- plus a third instance of the same underlying constraint
in `bootstrap` specifically:

  1. Algorand caps the `boxes` reference array at exactly 8 entries PER
     TRANSACTION (a structural txn-field limit, not an opcode-budget or
     simulate artifact) -- 9 distinct box names cannot fit in one txn's
     reference array regardless of what the program does.
  2. Box writes (including the zero-fill `box_create` performs) draw against
     a write-BUDGET of 2,048 bytes per box reference, POOLED ACROSS THE
     WHOLE ATOMIC GROUP -- not the read-budget's 1,024 B/ref this module's
     original docstring cited (§8.2), and not per-transaction: a txn can
     write more than its own references would allow alone, as long as a
     sibling transaction in the same group carries the shortfall in
     (possibly unused) box references. 49,576 total install-open bytes needs
     >= 25 pooled references (`constants.MIN_BOX_REFS_FOR_INSTALL_OPEN`);
     at 8 refs/txn that is itself enough to force >= 4 transactions in the
     group, independent of the 8-vs-9-name reference-cap argument above.
  3. `bootstrap` ALSO reads the `forks` box (for its gindex lookup) in the
     same call that used to create the 8 key boxes -- 8 + 1 = 9 references
     again, the identical cap hit for a different reason. Fixed by moving
     ALL box creation out of `bootstrap`/`install_begin` entirely: those two
     methods now only validate and reserve a generation id
     (`INST_STATE_VALIDATED`), touching at most the `forks` box.

`install_open_key_boxes` (8 real refs, exactly at the per-txn cap) and
`install_open_session_box` (1 real ref, room for padding) are called from
two dedicated ARC4 methods (`install_open_keys`, then `install_open_session`)
shared by BOTH the `bootstrap` and `install_begin` flows, that MUST be
submitted as sibling transactions in the SAME atomic group as whichever
validation call preceded them -- see `verifier.py`'s
`INST_STATE_OPENING_BOXES`/`INST_STATE_VALIDATED` handling for why
atomicity, not just the state guard, is what keeps a partially-open box set
from ever being observable on-chain. The extra pooled-budget references
needed to clear (2) are supplied by the caller as ordinary box refs on ANY
sibling transaction in the group -- e.g. the existing `noop_budget()`
filler, whose docstring already anticipated carrying "extra box
references" -- and are a client/relayer concern, not something this
module's code needs to know about (it only ever creates the 9 real boxes
it owns).
"""

from algopy import Bytes, UInt64, subroutine, urange, op
from algopy.op import EC, EllipticCurve

from contracts.primitives.bls.codec import g1_bind
from contracts.primitives.ssz.merkleize import merkleize_stack_finalize, merkleize_stack_push
from contracts.sync_committee.constants import (
    BOXES_PER_COMMITTEE,
    COMMITTEE_MERKLE_DEPTH,
    G1_COMPRESSED_BYTES,
    G1_UNCOMPRESSED_BYTES,
    KEYS_PER_BOX,
    SESSION_BOX_BYTES,
    SESSION_FILLED_BYTES,
    SESSION_STACK_BYTES,
    SYNC_COMMITTEE_SIZE,
)

KEY_BOX_PREFIX = b"k:"
TOTAL_BOX_PREFIX = b"a:"
SESSION_BOX_PREFIX = b"s:"


@subroutine
def key_box_name(gen: UInt64, box_index: UInt64) -> Bytes:
    """`k:<gen>:<j>` -- box_index j in 0..7 (§8.2)."""
    return Bytes(KEY_BOX_PREFIX) + op.itob(gen) + op.itob(box_index)[7:8]


@subroutine
def total_box_name(gen: UInt64) -> Bytes:
    """`a:<gen>` -- `A_total`, the contract-computed full-committee sum."""
    return Bytes(TOTAL_BOX_PREFIX) + op.itob(gen)


@subroutine
def session_box_name(gen: UInt64) -> Bytes:
    """`s:<gen>` -- install-session scratch, deleted at finalize/abort."""
    return Bytes(SESSION_BOX_PREFIX) + op.itob(gen)


@subroutine
def install_open_key_boxes(gen: UInt64) -> None:
    """Box-opening phase 1 (§8.3, §16): create `k:<gen>:0..7` -- exactly
    `BOXES_PER_COMMITTEE` (8) box references, the measured per-transaction
    cap (§16), so this must be the ONLY box-referencing work in whatever
    transaction calls it. Box creation zero-fills, so the session's `filled`
    mask (written in phase 2) starts at 0 and its running sum starts as 96
    zero bytes -- the AVM G1-infinity encoding, the correct additive
    identity to begin accumulating into.
    """
    for j in urange(UInt64(BOXES_PER_COMMITTEE)):
        _created = op.Box.create(key_box_name(gen, j), UInt64(KEYS_PER_BOX * G1_UNCOMPRESSED_BYTES))


@subroutine
def install_open_session_box(gen: UInt64) -> None:
    """Box-opening phase 2 (§8.3, §16): create `s:<gen>` alone. Must run in
    the SAME atomic group as the phase-1 call that opened `k:<gen>:*`
    (`verifier.py`'s `install_open_session` enforces
    `INST_STATE_OPENING_BOXES`) -- Algorand's atomic-group all-or-nothing
    guarantee is what prevents an on-chain state where key boxes exist
    without a session box: if this call fails or the group omits it
    entirely, phase 1's box creates roll back too.
    """
    _created = op.Box.create(session_box_name(gen), UInt64(SESSION_BOX_BYTES))


@subroutine
def install_abort_key_boxes(gen: UInt64) -> None:
    """`install_abort` during `INST_STATE_OPENING_BOXES` (§16): only
    `k:<gen>:*` exist yet (phase 2 never ran), so only those are deleted.
    """
    for j in urange(UInt64(BOXES_PER_COMMITTEE)):
        _deleted = op.Box.delete(key_box_name(gen, j))


@subroutine
def install_abort_boxes(gen: UInt64) -> None:
    """`install_abort` during `INST_STATE_INSTALLING` (§8.3 property 1,
    §16): delete every box the session opened -- both key boxes and the
    session box, since box-opening has fully completed by this state --
    refunding MBR (an abandoned session's boxes are orphaned under a
    generation id nothing references; this reclaims them explicitly rather
    than leaving them orphaned forever).
    """
    for j in urange(UInt64(BOXES_PER_COMMITTEE)):
        _deleted = op.Box.delete(key_box_name(gen, j))
    _deleted = op.Box.delete(session_box_name(gen))


@subroutine
def install_delete_committee_boxes(gen: UInt64) -> None:
    """`retire(gen)` (§8.4): delete a retired generation's key boxes and
    its `A_total` box. Caller (`verifier.py`) must already have asserted
    `gen != cur_gen and gen != next_gen and gen != inst_gen`.
    """
    for j in urange(UInt64(BOXES_PER_COMMITTEE)):
        _deleted = op.Box.delete(key_box_name(gen, j))
    _deleted = op.Box.delete(total_box_name(gen))


@subroutine
def install_process_chunk(gen: UInt64, cursor: UInt64, compressed_blob: Bytes, uncompressed_blob: Bytes) -> UInt64:
    """`install_chunk` (§8.3): bind, store, merkle-push, and sum `k` members
    starting at `cursor`. Returns the new cursor (`cursor + k`).

    `g1_bind` runs BEFORE anything is written or folded (§8.3 property 2):
    binding an unconfirmed key is safe because the compressed 48 bytes are
    tied to the trusted committee root only later, at `install_process_finalize`
    -- composed, every stored key is the one the beacon chain committed to.
    """
    assert compressed_blob.length % G1_COMPRESSED_BYTES == 0, "compressed blob not a multiple of 48"
    k = compressed_blob.length // G1_COMPRESSED_BYTES
    assert uncompressed_blob.length == k * G1_UNCOMPRESSED_BYTES, "uncompressed blob length mismatch"
    assert cursor + k <= UInt64(SYNC_COMMITTEE_SIZE), "chunk would overflow the committee"

    sbox = session_box_name(gen)
    session = op.Box.extract(sbox, UInt64(0), UInt64(SESSION_BOX_BYTES))
    stack = session[0:SESSION_STACK_BYTES]
    filled = op.btoi(session[SESSION_STACK_BYTES : SESSION_STACK_BYTES + SESSION_FILLED_BYTES])
    running_sum = session[SESSION_STACK_BYTES + SESSION_FILLED_BYTES : SESSION_BOX_BYTES]

    for m in urange(k):
        i = cursor + m
        comp = compressed_blob[m * G1_COMPRESSED_BYTES : m * G1_COMPRESSED_BYTES + G1_COMPRESSED_BYTES]
        uncomp = uncompressed_blob[m * G1_UNCOMPRESSED_BYTES : m * G1_UNCOMPRESSED_BYTES + G1_UNCOMPRESSED_BYTES]

        g1_bind(uncomp, comp)  # THE trust boundary (§8.3, §10.2)

        kbox = key_box_name(gen, i // UInt64(KEYS_PER_BOX))
        op.Box.replace(kbox, (i % UInt64(KEYS_PER_BOX)) * G1_UNCOMPRESSED_BYTES, uncomp)

        # hash_tree_root(BLSPubkey) == sha256(compressed[0:32] || compressed[32:48] || 0*16)
        # == sha256(comp || 16 zero bytes), since comp[0:32]||comp[32:48] == comp.
        leaf = op.sha256(comp + op.bzero(UInt64(16)))
        stack, filled = merkleize_stack_push(stack, filled, leaf)

        running_sum = EllipticCurve.add(EC.BLS12_381g1, running_sum, uncomp)

    new_session = stack + op.itob(filled) + running_sum
    op.Box.replace(sbox, UInt64(0), new_session)
    return cursor + k


@subroutine
def install_process_finalize(
    gen: UInt64,
    cursor: UInt64,
    inst_root: Bytes,
    aggregate_compressed: Bytes,
    aggregate_uncompressed: Bytes,
) -> Bytes:
    """`install_finalize` (§8.3). Returns `A_total` (== `running_sum`) once
    every check passes; the caller writes it to `a:<gen>` and must not
    accept `A_total` from any other source (§15 item 10).

    THE check: the merkleized root of the 512 bound keys' compressed forms,
    combined with the bound aggregate key's leaf, must equal `inst_root` --
    the trusted committee root a prior verified update proved (§8.3 "THE
    check"). `aggregate_uncompressed == running_sum` is a free 512-`ec_add`
    integrity cross-check that also confirms `A_total` equals the
    committed `aggregate_pubkey` (with multiplicity, §10.6).
    """
    assert cursor == UInt64(SYNC_COMMITTEE_SIZE), "install session incomplete"
    assert inst_root.length == 32
    assert aggregate_compressed.length == G1_COMPRESSED_BYTES
    assert aggregate_uncompressed.length == G1_UNCOMPRESSED_BYTES

    sbox = session_box_name(gen)
    session = op.Box.extract(sbox, UInt64(0), UInt64(SESSION_BOX_BYTES))
    stack = session[0:SESSION_STACK_BYTES]
    filled = op.btoi(session[SESSION_STACK_BYTES : SESSION_STACK_BYTES + SESSION_FILLED_BYTES])
    running_sum = session[SESSION_STACK_BYTES + SESSION_FILLED_BYTES : SESSION_BOX_BYTES]

    vector_root = merkleize_stack_finalize(stack, filled, UInt64(COMMITTEE_MERKLE_DEPTH))
    agg_leaf = op.sha256(aggregate_compressed + op.bzero(UInt64(16)))
    assert op.sha256(vector_root + agg_leaf) == inst_root, "committee does not fold to the trusted root"

    g1_bind(aggregate_uncompressed, aggregate_compressed)  # THE trust boundary, aggregate key
    assert aggregate_uncompressed == running_sum, "aggregate_pubkey != sum of installed keys"

    _deleted = op.Box.delete(sbox)
    return running_sum
