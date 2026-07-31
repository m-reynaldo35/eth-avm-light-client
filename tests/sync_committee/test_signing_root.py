"""T1-T3 (design doc §11): signing-root construction vs real consensus-spec
vectors. Fully offline -- pure Python + `py_ecc`, no algod dependency
(matches `ci-offline.yml`). Reproduces design doc §3.4's own walk of the
Altair `light_client_sync` scenario: bootstrap -> apply every update in
`steps.yaml` order, tracking current/next committee across period rollover,
and asserting `py_ecc.bls.G2ProofOfPossession.FastAggregateVerify` succeeds
for every one of the 8 updates across 5 sync-committee periods.

T1: signing root construction (§3.1) reproduces a genuinely valid signature
    for all 8 real updates.
T2: `hash_tree_root(attested_header)` equals the block root embedded in the
    update's own filename (an independent oracle for our header
    merkleization, per §3.4), and the finalized-header leaf matches
    `steps.yaml`'s expected `finalized_header.beacon_root`.
T3: `compute_fork_data_root(fork_version, gvr)[0:4]` equals `meta.yaml`'s
    `bootstrap_fork_digest` -- catches a wrong fork version or a wrong
    `gvr` independently of BLS (§3.1 trap 2).
"""

from __future__ import annotations

from py_ecc.bls import G2ProofOfPossession as bls

from tests.sync_committee import reference as ref
from tests.sync_committee import vectors

CASE = vectors.load_altair_sync_case("light_client_sync")

# minimal preset (presets/minimal/{phase0,altair}.yaml @ v1.6.0-beta.0):
# SLOTS_PER_EPOCH=8, EPOCHS_PER_SYNC_COMMITTEE_PERIOD=8, SYNC_COMMITTEE_SIZE=32.
SLOTS_PER_EPOCH = 8
EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 8
SYNC_COMMITTEE_SIZE = 32
# UPDATE_TIMEOUT = SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD (sync-protocol.md).
UPDATE_TIMEOUT = SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD


def _period(slot: int) -> int:
    return ref.period_at_slot(slot, SLOTS_PER_EPOCH, EPOCHS_PER_SYNC_COMMITTEE_PERIOD)


def _fork_version(config: dict) -> bytes:
    """`config.yaml` values that look like hex (`0x01000001`) are parsed by
    PyYAML's default resolver as plain ints, not strings -- normalize both
    representations to 4 canonical big-endian bytes."""
    value = config["ALTAIR_FORK_VERSION"]
    if isinstance(value, int):
        return value.to_bytes(4, "big")
    return bytes.fromhex(value.removeprefix("0x"))


def _committee_vector_root(pubkeys: list[bytes]) -> bytes:
    leaves = [ref.sha256(pk + bytes(16)) for pk in pubkeys]
    # merkleize 32 leaves -> depth 5 (2**5 == 32, matches minimal preset)
    layer = leaves
    while len(layer) > 1:
        layer = [ref.sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def _next_committee_root(u) -> bytes:
    vector_root = _committee_vector_root(u.next_sync_committee_pubkeys)
    agg_leaf = ref.sha256(u.next_sync_committee_aggregate + bytes(16))
    return ref.sha256(vector_root + agg_leaf)


def _compute_branch_root(leaf: bytes, branch: list[bytes], gindex: int) -> bytes:
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


def _verify_next_committee_branch(u) -> bool:
    leaf = _next_committee_root(u)
    attested_state_root = u.attested_header[48:80]
    root = _compute_branch_root(leaf, u.next_sync_committee_branch, 55)
    return root == attested_state_root


def _is_sync_committee_update(u) -> bool:
    """`is_sync_committee_update`: the update genuinely carries a
    `next_sync_committee` proof iff its branch is non-default (§3.3's
    vendored vectors zero out pubkeys/aggregate/branch together whenever
    the update omits this proof -- verified empirically against this exact
    fixture)."""
    return any(b != bytes(32) for b in u.next_sync_committee_branch)


def _is_finality_update(u) -> bool:
    """`is_finality_update`: the update's `finality_branch` is non-default."""
    return any(b != bytes(32) for b in u.finality_branch)


def _is_better_update(new_meta: dict, old_meta: dict) -> bool:
    """Verbatim port of `is_better_update`
    (specs/altair/light-client/sync-protocol.md @ v1.6.0-beta.0), restricted
    to the fields this offline walk tracks. Needed because
    `process_light_client_store_force_update` (exercised by this scenario's
    two `force_update` steps) applies `store.best_valid_update`, and which
    update is "best" depends on this exact ranking -- getting it wrong
    silently changes which committee a later update is checked against."""
    size = SYNC_COMMITTEE_SIZE
    new_super = new_meta["popcount"] * 3 >= size * 2
    old_super = old_meta["popcount"] * 3 >= size * 2
    if new_super != old_super:
        return new_super
    if not new_super and new_meta["popcount"] != old_meta["popcount"]:
        return new_meta["popcount"] > old_meta["popcount"]

    new_rel = new_meta["is_sc_update"] and (
        _period(new_meta["attested_slot"]) == _period(new_meta["sig_slot"])
    )
    old_rel = old_meta["is_sc_update"] and (
        _period(old_meta["attested_slot"]) == _period(old_meta["sig_slot"])
    )
    if new_rel != old_rel:
        return new_rel

    if new_meta["is_fin_update"] != old_meta["is_fin_update"]:
        return new_meta["is_fin_update"]

    if new_meta["is_fin_update"]:
        new_scf = _period(new_meta["finalized_slot"]) == _period(new_meta["attested_slot"])
        old_scf = _period(old_meta["finalized_slot"]) == _period(old_meta["attested_slot"])
        if new_scf != old_scf:
            return new_scf

    if new_meta["popcount"] != old_meta["popcount"]:
        return new_meta["popcount"] > old_meta["popcount"]
    if new_meta["attested_slot"] != old_meta["attested_slot"]:
        return new_meta["attested_slot"] < old_meta["attested_slot"]
    return new_meta["sig_slot"] < old_meta["sig_slot"]


def _apply_light_client_update(store, finalized_slot: int, finalized_root: bytes, next_pubkeys: list[bytes]):
    """Verbatim port of `apply_light_client_update`'s committee-rollover and
    finality-write halves. THE point this test's original `_walk()` got
    wrong (root cause of the collection-time failure): the real spec's two
    branches are keyed on `period(update.finalized_header.slot)` vs
    `period(store.finalized_header.slot)` -- NEVER on the signature/attested
    period used for *selecting* which committee verifies a signature
    (`validate_light_client_update`'s separate, correct concern). Collapsing
    these two into one period comparison (what the original code did, via
    `using_next`) desyncs committee learning from what the real store does,
    and this fixture's `light_client_sync` scenario walks 5 periods across 2
    `force_update` boundaries -- enough for the two notions to diverge and
    hit "next committee used before it was known".
    """
    store_period = _period(store["finalized_slot"])
    update_finalized_period = _period(finalized_slot)
    if store["next_pubkeys"] is None:
        assert update_finalized_period == store_period, "learn: finalized period must equal store period"
        store["next_pubkeys"] = next_pubkeys
    elif update_finalized_period == store_period + 1:
        store["current_pubkeys"] = store["next_pubkeys"]
        store["next_pubkeys"] = next_pubkeys

    if finalized_slot > store["finalized_slot"]:
        store["finalized_slot"] = finalized_slot
        store["finalized_root"] = finalized_root


def _walk():
    """Replicates the design doc §3.4 walk -- and, unlike the original
    version of this function, replicates it against the REAL light-client
    store state machine (`validate_light_client_update` /
    `apply_light_client_update` / `process_light_client_update` /
    `process_light_client_store_force_update` / `is_better_update`, all
    fetched verbatim from `ethereum/consensus-specs` tag `v1.6.0-beta.0`),
    including this scenario's two `force_update` steps -- not a hand-rolled
    approximation. Returns a list of per-step result dicts: one per
    `process_update` step (`kind="process_update"`, with signing-root/BLS
    data for T1/T2) and one per `force_update` step (`kind="force_update"`,
    carrying only the store's finalized root/slot for T2's cross-check).
    """
    gvr = CASE["genesis_validators_root"]
    fork_version = _fork_version(CASE["config"])
    domain = ref.compute_domain(ref.DOMAIN_SYNC_COMMITTEE, fork_version, gvr)

    bootstrap = CASE["bootstrap"]
    store = {
        "current_pubkeys": bootstrap.current_sync_committee_pubkeys,
        "next_pubkeys": None,  # is_next_sync_committee_known(store) == False at genesis
        "finalized_slot": ref.be64_from_le(bootstrap.header[0:8]),
        "finalized_root": ref.hash_tree_root_beacon_block_header(bootstrap.header),
    }
    best_valid_update: dict | None = None

    results = []
    for step in CASE["all_steps"]:
        if step["kind"] == "force_update":
            current_slot = step["current_slot"]
            if current_slot > store["finalized_slot"] + UPDATE_TIMEOUT and best_valid_update is not None:
                bvu = dict(best_valid_update)
                if bvu["finalized_slot"] <= store["finalized_slot"]:
                    # "because the apply logic waits for finalized_header.slot
                    # to indicate sync committee finality, the attested_header
                    # may be treated as finalized_header ... to guarantee
                    # progression" (process_light_client_store_force_update)
                    bvu["finalized_slot"] = bvu["attested_slot"]
                    bvu["finalized_root"] = bvu["attested_root"]
                _apply_light_client_update(
                    store, bvu["finalized_slot"], bvu["finalized_root"], bvu["next_sync_committee_pubkeys"]
                )
                best_valid_update = None
            results.append(
                {
                    "kind": "force_update",
                    "checks": step["checks"],
                    "finalized_header_root": store["finalized_root"],
                }
            )
            continue

        u = step["parsed"]
        sig_slot = u.signature_slot
        attested_slot = ref.be64_from_le(u.attested_header[0:8])
        finalized_slot = ref.be64_from_le(u.finalized_header[0:8])

        store_period = _period(store["finalized_slot"])
        sig_period = _period(sig_slot)
        known = store["next_pubkeys"] is not None
        allowed_periods = (store_period, store_period + 1) if known else (store_period,)
        assert sig_period in allowed_periods, f"{step['update_name']}: signature period skips a sync-committee period"

        using_next = sig_period == store_period + 1
        committee_pubkeys = store["next_pubkeys"] if using_next else store["current_pubkeys"]
        assert committee_pubkeys is not None, "next committee used before it was known"

        signing_root = ref.compute_signing_root(u.attested_header, domain)

        popcount = 0
        participants = []
        for i, pk in enumerate(committee_pubkeys):
            if ref.ssz_bitvector_get(u.sync_committee_bits, i):
                popcount += 1
                participants.append(pk)

        ok = bls.FastAggregateVerify(participants, signing_root, u.signature)

        is_sc_update = _is_sync_committee_update(u)
        is_fin_update = _is_finality_update(u)
        if is_sc_update:
            # Cross-check: the committee this update claims for period+1
            # really does fold to the proven root under `attested_state_root`
            # (strengthens T1 beyond signature-only verification).
            assert _verify_next_committee_branch(u), f"{step['update_name']}: next_sync_committee branch does not fold"

        attested_root = ref.hash_tree_root_beacon_block_header(u.attested_header)
        finalized_root = (
            ref.hash_tree_root_beacon_block_header(u.finalized_header) if finalized_slot != 0 else bytes(32)
        )

        meta = {
            "popcount": popcount,
            "attested_slot": attested_slot,
            "sig_slot": sig_slot,
            "finalized_slot": finalized_slot,
            "finalized_root": finalized_root,
            "attested_root": attested_root,
            "is_sc_update": is_sc_update,
            "is_fin_update": is_fin_update,
            "next_sync_committee_pubkeys": u.next_sync_committee_pubkeys,
        }

        if best_valid_update is None or _is_better_update(meta, best_valid_update):
            best_valid_update = meta

        has_supermajority = popcount * 3 >= SYNC_COMMITTEE_SIZE * 2  # §6.3's 2/3 rule
        update_has_finalized_next_sync_committee = (
            store["next_pubkeys"] is None
            and is_sc_update
            and is_fin_update
            and _period(finalized_slot) == _period(attested_slot)
        )
        if has_supermajority and (finalized_slot > store["finalized_slot"] or update_has_finalized_next_sync_committee):
            _apply_light_client_update(store, finalized_slot, finalized_root, u.next_sync_committee_pubkeys)
            best_valid_update = None

        results.append(
            {
                "kind": "process_update",
                "update_name": step["update_name"],
                "signature_slot": sig_slot,
                "attested_slot": attested_slot,
                "period": sig_period,
                "committee": "next" if using_next else "current",
                "popcount": popcount,
                "signing_root": signing_root,
                "attested_header_root": attested_root,
                # The STORE's finalized root after this step (what T2 / the
                # vendored `checks.finalized_header` actually describes) --
                # NOT this update's own raw `finalized_header` field, which
                # is legitimately empty/zero on non-finality-carrying updates
                # (e.g. the "_sx"/"_xx" steps) even while the store's real
                # finalized root is unchanged from an earlier step.
                "finalized_header_root": store["finalized_root"],
                "bls_ok": ok,
                "checks": step["checks"],
            }
        )

    return results


_ALL_RESULTS = _walk()
_RESULTS = [r for r in _ALL_RESULTS if r["kind"] == "process_update"]


def test_t1_signing_root_verifies_all_8_updates():
    assert len(_RESULTS) == 8
    for r in _RESULTS:
        assert r["bls_ok"] is True, f"{r['update_name']}: signature failed to verify"


def test_t1_matches_design_doc_table():
    """Cross-check against docs/design/004-sync-committee.md §3.4's own
    table: sig slot, period, committee used, popcount for all 8 updates.

    KNOWN DOCUMENTATION ERRATUM (found while fixing the collection-time
    failure this file used to have): the design doc's own table labels
    updates 4, 5, and 7 "current". A verbatim, spec-driven replay of this
    exact scenario -- including its two `force_update` steps, cross-checked
    twice against `steps.yaml`'s own expected post-force-update
    `finalized_header` (slot+root, both matched exactly) -- shows the
    committee used for those three updates is genuinely `next` at the
    moment each is verified: `store.next_sync_committee` (period 2, then
    period 3) is not promoted to `store.current_sync_committee` until the
    LATER `force_update` step rolls it over, and updates 4/5/7 are each
    processed strictly before the `force_update` that promotes the
    committee they used. This does not change which physical committee
    verifies which update (still exactly as the design doc's own §3.4
    prose describes), nor any popcount/signing-root/BLS-result cell in the
    table -- only this one column's label for these three rows.
    """
    expected = [
        (41, 0, "current", 32),
        (89, 1, "next", 32),
        (129, 2, "next", 32),
        (130, 2, "next", 32),  # doc says "current"; see docstring erratum note
        (131, 2, "next", 32),  # doc says "current"; see docstring erratum note
        (195, 3, "next", 32),
        (196, 3, "next", 32),  # doc says "current"; see docstring erratum note
        (281, 4, "next", 32),
    ]
    got = [(r["signature_slot"], r["period"], r["committee"], r["popcount"]) for r in _RESULTS]
    assert got == expected


def test_t2_attested_header_root_matches_filename():
    """`hash_tree_root(attested_header)` equals the block root embedded in
    the update's own filename -- an oracle independent of our own code."""
    for r in _RESULTS:
        # filenames look like update_0x<hash>_sf.ssz_snappy
        name = r["update_name"]
        hex_root = name.split("update_0x", 1)[1].rsplit("_", 1)[0]
        expected = bytes.fromhex(hex_root)
        assert r["attested_header_root"] == expected, r["update_name"]


def test_t2_finalized_header_root_matches_steps_yaml():
    """Checked across EVERY step, `process_update` and `force_update` alike
    -- `checks.finalized_header` describes the STORE's finalized header
    after the step, which for several steps here differs from that step's
    own raw update payload (e.g. a "_sx"/"_xx" update carries an empty
    `finalized_header` while the store's real finalized root is carried
    over unchanged from an earlier step; both `force_update` steps change
    the store's finalized root without any update payload at all)."""
    for r in _ALL_RESULTS:
        expected_hex = r["checks"]["finalized_header"]["beacon_root"]
        expected = bytes.fromhex(expected_hex.removeprefix("0x"))
        label = r.get("update_name", r["kind"])
        assert r["finalized_header_root"] == expected, label


def test_t3_fork_digest_cross_check():
    """§3.1 trap 2 / T3: `compute_fork_data_root(...)[0:4]` equals
    `meta.yaml`'s `bootstrap_fork_digest`."""
    fork_version = _fork_version(CASE["config"])
    gvr = CASE["genesis_validators_root"]
    fork_data_root = ref.compute_fork_data_root(fork_version, gvr)
    assert fork_data_root[0:4] == CASE["bootstrap_fork_digest"]


def test_t3_domain_matches_design_doc():
    """Cross-check against the literal domain the design doc records in §3.4."""
    fork_version = _fork_version(CASE["config"])
    gvr = CASE["genesis_validators_root"]
    domain = ref.compute_domain(ref.DOMAIN_SYNC_COMMITTEE, fork_version, gvr)
    assert domain.hex() == "0700000015cfa0a7e842ca383b78d60efba16c294ec206ac937d1cb432fdc29e"
