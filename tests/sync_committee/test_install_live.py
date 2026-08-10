"""§16 live-execution test: the install-flow box-opening fix, run end-to-end
against a real dev-mode algod (docs/design/004-sync-committee.md §16).

This is the test that originally surfaced the bugs this fix addresses: a
single-call `install_open_boxes` (9 box references: 8 key boxes + 1 session
box) exceeds Algorand's real per-transaction box-reference cap, confirmed
via a direct protocol error during live testing -- and, found while building
THIS test, `bootstrap` independently hit the same cap a second way: AT THE
TIME, it read the `forks` box for its gindex lookup in the same call that
used to create the 8 key boxes, a second, independent way to exceed the
cap. §16 measured the exact constraints and split box-opening into three
phases -- `bootstrap`/`install_begin` (validate + reserve,
`INST_STATE_VALIDATED`) -> `install_open_keys` (`INST_STATE_OPENING_BOXES`)
-> `install_open_session` (`INST_STATE_INSTALLING`) -- submitted as sibling
transactions in one atomic group, padded with `noop_budget()` calls
carrying the extra box references the pooled write-budget needs. (013
moved the fork table into global state, so `bootstrap`'s gindex lookup no
longer touches a box at all -- but the three-phase split this file tests
stands regardless, since it was ALSO fixing the independent 9-refs-in-
one-call `install_open_boxes` problem, untouched by 013.)

This file proves that fix actually works against a real network:

  * `test_bootstrap_box_opening_completes_live` -- the exact call sequence
    that used to fail with a protocol error now commits cleanly: all 9
    boxes exist afterward, with the right sizes, and `inst_state` reads
    back as `INSTALLING` (3), not stuck at `VALIDATED` (1) or
    `OPENING_BOXES` (2).
  * `test_install_chunk_proceeds_after_box_opening_fix` -- continues the
    SAME session with one `install_chunk` call (real BLS12-381
    subgroup-valid points, real `g1_bind`-passing compressed/uncompressed
    pairs) to confirm the state-machine guard correctly unblocks
    `install_chunk` once box-opening completes. Run via simulate (extra
    opcode budget), NOT a real committed transaction: `g1_bind` alone costs
    ~1,966 opcode budget against a bare transaction's 700, and supplying
    that for real needs the inner-call donor chain §9 already designs for
    -- a separate, pre-existing mechanism this test does not need to
    re-exercise to prove the box-mechanics fix. Simulate still enforces the
    REAL box-reference cap and pooled read/write budget (confirmed
    empirically, §16), so this remains a genuine test of the box-mechanics
    fix, just not of budget donation. It also surfaced a THIRD real finding
    (§16): touching an EXISTING box via `box_extract`/`box_replace` charges
    the pooled budget the box's FULL DECLARED SIZE, not the touched slice
    -- so a single `install_chunk` call needs >= 4 box refs (one 6,144 B
    key box + the 424 B session box = 6,568 B >= 3*2048, needs a 4th ref
    for margin), not the 2 a naive one-ref-per-box-name count would
    suggest, REGARDLESS of chunk size.
  * `test_install_chunk_rejected_while_validated` /
    `test_install_open_session_rejected_before_keys_opened` -- the negative
    half of the state-machine guard the task asked for explicitly: on a
    SEPARATE fresh app that has run only `bootstrap` (state `VALIDATED`,
    zero boxes created), `install_chunk` and `install_open_session` both
    genuinely fail on-chain rather than silently proceeding against a
    box set that doesn't exist yet.

Deliberately NOT covered here (out of scope for the box-opening fix this
file targets, and expensive to run live): a full 512-member
`install_chunk`/`install_finalize` sequence, or a re-derivation of §8.5's
per-group chunk-count estimate now that per-chunk box-touch cost is known
to need real box-reference headroom too (§16 flags this as still open).

The synthetic header/committee-root/branch data below is self-consistent
(computed with the exact same sha256-folding algorithm the contract
implements, mirrored in `tests/sync_committee/reference.py` and already
validated bit-exact against real consensus-spec vectors in
`test_signing_root.py`'s T1/T2) but is NOT drawn from an official vector
file: `bootstrap()` never touches individual committee-member key material,
so no BLS data is needed to exercise the box-opening fix, and inventing a
minimal self-consistent fixture is standard practice for testing box/state
mechanics in isolation from the (already independently vector-tested)
signing-root machinery.
"""

from __future__ import annotations

import hashlib

import pytest

from tests.sync_committee import reference as ref

# real Ethereum consensus-spec generalized indices (Altair, preset-
# independent -- container field position, not committee size):
CURRENT_SYNC_COMMITTEE_GINDEX = 54
CURRENT_SYNC_COMMITTEE_DEPTH = 5  # bit_length(54) - 1
FINALITY_GINDEX = 105
NEXT_SYNC_COMMITTEE_GINDEX = 55

GEN = 1  # first bootstrap on a fresh app always assigns gen_counter -> 1


def key_box_name(gen: int, j: int) -> bytes:
    """Mirrors `contracts/sync_committee/install.py`'s `key_box_name`:
    `b"k:" + itob(gen)[8B] + itob(j)[7:8][1B]`."""
    return b"k:" + gen.to_bytes(8, "big") + j.to_bytes(8, "big")[7:8]


def session_box_name(gen: int) -> bytes:
    """Mirrors `session_box_name`: `b"s:" + itob(gen)[8B]`."""
    return b"s:" + gen.to_bytes(8, "big")


def _fold_branch(leaf: bytes, branch: list[bytes], gindex: int) -> bytes:
    """`compute_merkle_branch_root`, mirrored (same algorithm as
    `contracts/primitives/ssz/merkle.py` / `test_signing_root.py`'s
    `_compute_branch_root`)."""
    depth = gindex.bit_length() - 1
    assert len(branch) == depth
    node = leaf
    for i in range(depth):
        sibling = branch[i]
        if (gindex >> i) & 1:
            node = ref.sha256(sibling + node)
        else:
            node = ref.sha256(node + sibling)
    return node


def _build_bootstrap_fixture():
    """Self-consistent (not officially-vectored, see module docstring)
    header + committee_root + branch such that:
      * hash_tree_root(header) == trusted_block_root
      * committee_root folds through `branch` at gindex 54 to
        header.state_root
    """
    committee_root = hashlib.sha256(b"m4-section-16-fix-test-committee-root").digest()
    branch = [hashlib.sha256(f"m4-16-sibling-{i}".encode()).digest() for i in range(CURRENT_SYNC_COMMITTEE_DEPTH)]
    state_root = _fold_branch(committee_root, branch, CURRENT_SYNC_COMMITTEE_GINDEX)

    slot = 100
    proposer_index = 0
    parent_root = hashlib.sha256(b"m4-16-parent-root").digest()
    body_root = hashlib.sha256(b"m4-16-body-root").digest()

    header = (
        slot.to_bytes(8, "little")
        + proposer_index.to_bytes(8, "little")
        + parent_root
        + state_root
        + body_root
    )
    assert len(header) == 112
    trusted_block_root = ref.hash_tree_root_beacon_block_header(header)

    return {
        "header": header,
        "committee_root": committee_root,
        "branch": b"".join(branch),
        "trusted_block_root": trusted_block_root,
        "slot": slot,
    }


def _g1_compress(point) -> bytes:
    """Mirrors `contracts/primitives/bls/codec.py`'s `g1_compress` exactly
    (standard ZCash/IETF BLS12-381 compressed encoding): 0x80 compression
    flag OR'd into X's top byte, plus 0x20 sign flag iff Y > (p-1)/2."""
    FIELD_MODULUS = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
    HALF_P = (FIELD_MODULUS - 1) // 2
    x, y = point
    xb = bytearray(x.n.to_bytes(48, "big"))
    sign_flag = 0x20 if y.n > HALF_P else 0x00
    xb[0] = xb[0] | 0x80 | sign_flag
    return bytes(xb)


def _g1_uncompressed(point) -> bytes:
    x, y = point
    return x.n.to_bytes(48, "big") + y.n.to_bytes(48, "big")


@pytest.fixture(scope="module")
def validated_only_session(algod_available):
    """A SEPARATE, freshly-deployed app (not `m4_live_harness`'s shared
    instance) that has run ONLY `bootstrap` -- stopping at
    `INST_STATE_VALIDATED`, before either box-creating call. Used to prove
    the state-machine guard genuinely rejects premature calls (§16's "think
    through what state tracks box-creation-complete" requirement), not just
    to prove the happy path works."""
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    from tests.sync_committee.harness import SyncCommitteeLiveHarness

    h = SyncCommitteeLiveHarness()
    h.create(h.sender, b"\x00" * 32)
    # 013 §0/§5.4: create() no longer pre-funds the app account -- fund it
    # here, as an ordinary post-create payment, for the box-creating calls
    # below (M4's k:/s:/a: box families are untouched by 013).
    h.fund_app()
    h.submit([("append_fork_row", [0, b"\x01\x00\x00\x00", FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX])])
    fx = _build_bootstrap_fixture()
    # `noop_budget()` sibling call pools +700 opcode budget (§9.4) -- bootstrap
    # alone (hash_tree_root + forks-row lookup + a depth-5 merkle branch check)
    # exceeds a bare transaction's 700, confirmed empirically here. 013 §3:
    # the forks-row lookup is now a global-state read, so `bootstrap` needs
    # no box references of its own any more.
    h.submit(
        [
            (
                "bootstrap",
                [fx["header"], fx["committee_root"], fx["branch"], fx["trusted_block_root"]],
            ),
            ("noop_budget", []),
        ]
    )
    return h, fx


def test_install_chunk_rejected_while_validated(validated_only_session):
    """`install_chunk` must reject while `inst_state == VALIDATED` (no boxes
    exist yet at all) -- the guard `install_process_chunk`/`install_chunk`
    were already asserting `inst_state == INSTALLING` unconditionally, this
    just confirms it still holds against the new intermediate state."""
    h, _fx = validated_only_session
    result = h.call("install_chunk", 0, b"\x00" * 48, b"\x00" * 96, boxes=[(0, key_box_name(GEN, 0)), (0, session_box_name(GEN))])
    # Puya-compiled asserts don't surface their custom message text through
    # simulate's failure-message (just "assert failed pc=..."), so the
    # meaningful check is that the call genuinely fails, not the message
    # text -- the `assert self.inst_state == UInt64(INST_STATE_INSTALLING)`
    # guard in `install_chunk` is what's firing here.
    assert not result.ok, "install_chunk must reject before box-opening completes"
    assert "assert failed" in result.failure


def test_install_open_session_rejected_before_keys_opened(validated_only_session):
    """`install_open_session` must reject while `inst_state == VALIDATED`
    (i.e. before `install_open_keys` has run) -- the exact guard §16 added
    to keep box-opening's phases strictly ordered."""
    h, _fx = validated_only_session
    result = h.call("install_open_session", boxes=[(0, session_box_name(GEN))])
    # Same caveat as the sibling test above re: Puya assert message text.
    assert not result.ok, "install_open_session must reject before install_open_keys has run"
    assert "assert failed" in result.failure


@pytest.fixture(scope="module")
def bootstrapped_session(m4_live_harness):
    """Runs the fixed box-opening group (bootstrap + install_open_session +
    2 padding noop_budget calls, one atomic group) against live algod, once
    per test-module run, and returns the harness plus the fixture data so
    both tests in this file can build on the same committed session."""
    h = m4_live_harness
    h.create(h.sender, b"\x00" * 32)
    # 013 §0/§5.4: create() no longer pre-funds the app account -- fund it
    # here instead, as an ordinary post-create payment (no prediction, no
    # race: `h.app_id` is already a real, confirmed id).
    h.fund_app()

    h.submit(
        [
            (
                "append_fork_row",
                [0, b"\x01\x00\x00\x00", FINALITY_GINDEX, CURRENT_SYNC_COMMITTEE_GINDEX, NEXT_SYNC_COMMITTEE_GINDEX],
            ),
        ]
    )

    fx = _build_bootstrap_fixture()

    key_refs = [(0, key_box_name(GEN, j)) for j in range(8)]
    session_ref = [(0, session_box_name(GEN))]

    # §16: the exact split that fixes both bugs -- 4 sibling transactions in
    # ONE atomic group.
    #   1. bootstrap(): validates + reserves gen (INST_STATE_VALIDATED).
    #      013 §3/§6.4: its forks-row lookup is a global-state read now, so
    #      it touches NO box references of its own -- the 8 references
    #      below are pure padding toward the group's pooled write budget,
    #      REPLACING (not deleting) the slot the `forks` box reference used
    #      to occupy here (013 §6.4/§17 item 7: dropping to 7 would
    #      silently under-budget the group by one reference).
    #   2. install_open_keys(): creates k:<gen>:0..7 -- exactly 8 real refs,
    #      the measured per-txn cap, no room for padding.
    #   3. install_open_session(): creates s:<gen> -- 1 real ref + 7 padding.
    #   4. noop_budget(): 1 more padding ref.
    # Total group refs: 8 + 8 + 8 + 1 = 25, matching
    # MIN_BOX_REFS_FOR_INSTALL_OPEN (pool = 25*2048 = 51,200 B >=
    # the 49,576 B actually written) -- unchanged by 013 (measured, §6.4).
    result = h.submit(
        [
            (
                "bootstrap",
                [fx["header"], fx["committee_root"], fx["branch"], fx["trusted_block_root"]],
                key_refs[:8],
            ),
            ("install_open_keys", [], key_refs),
            ("install_open_session", [], session_ref + key_refs[:7]),
            ("noop_budget", [], session_ref),
        ]
    )
    return h, fx, result


def test_bootstrap_box_opening_completes_live(bootstrapped_session):
    """THE regression test: the call sequence that used to fail with
    "tx.Boxes too long, max number of box references is 8" (single-call
    `install_open_boxes`) now commits with no protocol error, and all 9
    boxes genuinely exist afterward with the right sizes."""
    h, fx, result = bootstrapped_session
    assert result.tx_ids, "atomic group did not commit"

    # All 8 key boxes exist, each exactly KEY_BOX_BYTES (6,144 B).
    for j in range(8):
        box = h.algod.application_box_by_name(h.app_id, key_box_name(GEN, j))
        raw = box["value"]
        import base64

        assert len(base64.b64decode(raw)) == 64 * 96, f"key box {j} wrong size"

    # The session box exists, SESSION_BOX_BYTES (424 B).
    import base64

    sbox = h.algod.application_box_by_name(h.app_id, session_box_name(GEN))
    assert len(base64.b64decode(sbox["value"])) == 320 + 8 + 96

    # inst_state reads back as INSTALLING (3), not stuck at VALIDATED (1)
    # or OPENING_BOXES (2) -- all three phases committed together, per the
    # atomic group's all-or-nothing guarantee.
    info = h.algod.application_info(h.app_id)
    gstate = {
        base64.b64decode(kv["key"]): kv["value"]
        for kv in info["params"]["global-state"]
    }
    inst_state_val = gstate[b"inst_state"]["uint"]
    assert inst_state_val == 3, f"expected INSTALLING (3), got {inst_state_val}"


def test_install_chunk_proceeds_after_box_opening_fix(bootstrapped_session):
    """Continues the SAME session (via simulate, see module docstring for
    why: isolates the box-mechanics fix from opcode-budget donation, a
    separate mechanism) with one `install_chunk` call using genuinely
    subgroup-valid BLS12-381 G1 points and their real compressed forms (so
    `g1_bind` -- the trust boundary -- actually runs and passes, not a
    stub). Confirms the `inst_state == INSTALLING` guard correctly unblocks
    `install_chunk` once §16's box-opening fix has run, and measures the
    real box-reference floor a chunk call needs (>= 4, not the naive 2 --
    see the module docstring's third finding)."""
    from py_ecc.bls12_381 import G1, multiply

    h, fx, _result = bootstrapped_session

    points = [multiply(G1, i) for i in (11, 12, 13, 14)]
    compressed = b"".join(_g1_compress(p) for p in points)
    uncompressed = b"".join(_g1_uncompressed(p) for p in points)

    # §16 follow-on finding: touching an EXISTING box via box_extract/
    # box_replace charges the pooled budget the box's FULL DECLARED SIZE,
    # not the touched slice, and only ONCE per box regardless of how many
    # ops touch it within the group (measured separately, same experiment
    # family as the box-creation fix). `install_chunk` touches one 6,144 B
    # key box + the 424 B session box = 6,568 B minimum, REGARDLESS of
    # chunk size -- needing >= 4 box refs (4*2048=8192), not the 2 a naive
    # "one ref per box name" count would suggest. 2 real + 2 padding here.
    boxes = [
        (0, key_box_name(GEN, 0)),
        (0, session_box_name(GEN)),
        (0, key_box_name(GEN, 0)),
        (0, session_box_name(GEN)),
    ]
    result = h.call("install_chunk", 0, compressed, uncompressed, boxes=boxes)
    assert result.ok, f"install_chunk failed after box-opening fix: {result.failure}"
