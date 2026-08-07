"""Suite F6 -- the Deneb->Electra two-row trap (docs/design/008 §3.4, "the
single most important test in Suite F"), closing ROADMAP.md's M8 row honest
gap (1).

**What was tried, in order, before this file's fixture was built (2026-08-06):**

1. Independently confirmed the REAL mainnet Electra activation epoch, THREE
   ways, none of them a hardcoded guess:
     - `GET /eth/v1/config/spec` against `unstable.mainnet.beacon-api.nimbus.team`
       -> `ELECTRA_FORK_EPOCH: 364032`, `DENEB_FORK_EPOCH: 269568`.
     - The SAME endpoint on `testing.mainnet.beacon-api.nimbus.team` (a
       DIFFERENT node) -> identical values.
     - `eth-clients/mainnet`'s own published `metadata/config.yaml`
       (https://raw.githubusercontent.com/eth-clients/mainnet/main/metadata/config.yaml)
       -> `ELECTRA_FORK_EPOCH: 364032  # May 7, 2025, 10:05:11am UTC`,
       `DENEB_FORK_EPOCH: 269568  # March 13, 2024, 01:55:35pm UTC`.
   Three independent sources agree. `ELECTRA_ACTIVATION_EPOCH`/
   `DENEB_ACTIVATION_EPOCH` below are these confirmed values, not copied
   from the design doc's prose.

2. Looked for a REAL archive-capable beacon endpoint that still retains data
   from around that transition (May 2025 -- ~15 months before this pass
   ran, so it is FAR outside HISTORICAL mode's own 8,192-slot/~27.3h window
   and cannot be fetched via `finality_update`/`light_client/updates`
   "current" endpoints the way `test_live_e2e.py` fetches live data):
     - `GET /eth/v1/beacon/light_client/updates?start_period=1421&count=2`
       (period 1421 = the sync-committee period containing the Electra
       activation slot, `364032*32 // 8192 == 1422`, so 1421/1422 straddle
       it) -- `unstable.mainnet.beacon-api.nimbus.team` returned an EMPTY
       list (pruned), but `testing.mainnet.beacon-api.nimbus.team` returned
       REAL data: a `"deneb"`-version update for period 1421 (finalized
       slot 11,640,928) and a REAL `"electra"`-version update for period
       1422 (finalized slot 11,651,008). So real archived LIGHT-CLIENT
       HEADER data spanning the boundary DOES exist and IS reachable --
       better retention than the task brief expected from "light-client"
       infra, confirmed rather than assumed.
     - That is not sufficient by itself, though: proving the `block_roots`
       fold (the actual thing F6 tests) needs the FULL `BeaconState` at a
       slot near the boundary, to compute the real sibling hashes of the
       other ~36 top-level `BeaconState` fields (validators, balances, ...)
       and the other ~8,191 `block_roots` vector entries -- header/update
       endpoints do not carry this. Checked for it directly:
       `GET /eth/v2/debug/beacon/states/11651008` -> HTTP 404 on BOTH
       reachable Nimbus endpoints (light-client-serving nodes prune full
       state history, as the task brief predicted but did not assume).
       The other two pool members (`lodestar-mainnet.chainsafe.io`,
       `www.lightclientdata.org`) were unreachable entirely on this run
       (503 / connection failure) -- consistent with `eth_beacon_rpc.py`'s
       own module docstring, which already flags them as flaky/untested.
   Conclusion, checked rather than presumed: a REAL `block_roots` multiproof
   spanning this boundary is NOT obtainable from any endpoint this project's
   pool can reach. A full Electra `BeaconState` SSZ dump is hundreds of MB
   even where archive nodes exist; no such node was reachable here.

3. Therefore: this file builds a SYNTHETIC fixture, following this
   project's own established precedent for exactly this situation
   (ROADMAP.md's M6 row: "absent-slot test uses derived, not real
   eth_getProof, fixtures", and `synth.py`'s own docstring/`build_tree`
   helper, already used by every OTHER Suite-style M8 test in
   `test_core.py`) -- but every constant that CAN be real, IS real and
   independently re-derived, not copied from the design doc:
     - `ELECTRA_ACTIVATION_EPOCH = 364032` / `DENEB_ACTIVATION_EPOCH =
       269568` (confirmed three ways, above).
     - `ELECTRA_ACTIVATION_SLOT = 364032 * 32 = 11649024` (`SLOTS_PER_EPOCH
       = 32` is `contracts/sync_committee/constants.py`'s own, already-
       tested constant, re-derived here, not re-typed).
     - `G_BLOCK_ROOTS_BASE_DENEB = 37` / `G_BLOCK_ROOTS_BASE_ELECTRA = 69`:
       independently RE-DERIVED in this pass (not copied from 008 §3.3)
       by fetching the actual `consensus-specs` `master` branch container
       definitions directly (`specs/deneb/beacon-chain.md`,
       `specs/electra/beacon-chain.md`) and counting fields: `BeaconState`
       has 28 fields in Deneb, 37 in Electra (9 new Electra fields
       appended AFTER `historical_summaries`; `block_roots` stays at field
       index 5 in both -- position 6 in program order,
       0-indexed = 5: genesis_time(0), genesis_validators_root(1), slot(2),
       fork(3), latest_block_header(4), block_roots(5)). 28 fields round up
       to 32 leaves (depth 5) -> gindex `32+5=37`; 37 fields round up to 64
       leaves (depth 6) -> gindex `64+5=69`. Matches 008 §3.3's own table
       exactly, via an independent derivation against a freshly-fetched
       spec source -- not merely trusting the document under test.
     - `G_STATE_ROOT=802`/`G_RECEIPTS_ROOT=803`/`G_BLOCK_NUMBER=806`: reused
       from `real_ssz.py`/`test_live_e2e.py`, which already independently
       derived and live-cross-checked these against real mainnet data in
       this same pass (008 §3.2's two-published-anchor check). Not
       rederived a third time here -- these are UNCHANGED across the
       Deneb->Electra boundary, which is exactly what makes it a trap
       (008 §3.4).
   Only the beacon headers' OTHER fields (`proposer_index`, `parent_root`),
   the EL leaves' exact byte values, and the full `block_roots` vector's
   ~8,191 other entries are synthetic placeholders -- clearly labelled as
   such, per this project's own convention, never presented as live data.

**What this file proves:** `anchor_historical`'s two independent
`forks.lookup_row` calls (one at `epoch(fin_slot)`, one at `epoch(t_slot)`)
genuinely select DIFFERENT `g_block_roots_base` rows when `fin_slot` is
Electra and `t_slot` is Deneb, and a `block_roots` branch shaped for the
WRONG row (the one N-FORK forbids) is rejected -- the two things ROADMAP's
gap (1) named as unverified.
"""
from __future__ import annotations

import pytest

from tests.state_anchor import synth
from tests.state_anchor.conftest import (
    Arc4Harness,
    algod_client,
    deploy_donor_pair,
    funded_account,
    kmd_client,
    puya_compile,
)

RING_N = 8

# ---------------------------------------------------------------------------
# Real, independently confirmed/re-derived constants (see module docstring).
# ---------------------------------------------------------------------------
DENEB_ACTIVATION_EPOCH = 269568
ELECTRA_ACTIVATION_EPOCH = 364032
SLOTS_PER_EPOCH = 32
ELECTRA_ACTIVATION_SLOT = ELECTRA_ACTIVATION_EPOCH * SLOTS_PER_EPOCH  # 11,649,024

G_BLOCK_ROOTS_BASE_DENEB = 37
G_BLOCK_ROOTS_BASE_ELECTRA = 69

# Unchanged across this boundary -- reused from real_ssz.py's live-verified
# values, not rederived (see module docstring point 3, third bullet).
G_STATE_ROOT = 802
G_RECEIPTS_ROOT = 803
G_BLOCK_NUMBER = 806

# t_slot: 1,024 slots (~12.3 min) before the Electra activation slot -- real
# slot ARITHMETIC (12s/slot is a real, unchanging Ethereum constant), well
# inside Deneb (epoch 364000 < 364032) and well inside the 8,192-slot
# HISTORICAL window measured from `ELECTRA_ACTIVATION_SLOT`.
T_SLOT = ELECTRA_ACTIVATION_SLOT - 1024  # 11,648,000, epoch 364,000 (Deneb)
FIN_SLOT = ELECTRA_ACTIVATION_SLOT  # 11,649,024, epoch 364,032 (Electra, exactly the first Electra epoch)

EL_BLOCK_NUMBER = 22_000_000  # arbitrary EL block number for the ring key


@pytest.fixture(scope="module")
def compiled(algod_available, anchor_src, bench_src):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    return puya_compile(anchor_src), puya_compile(bench_src)


@pytest.fixture(scope="module")
def account(algod_available):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    algod = algod_client()
    kmd = kmd_client()
    return funded_account(algod, kmd)


@pytest.fixture(scope="module")
def donors(algod_available, account):
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    algod = algod_client()
    sender, sk = account
    return deploy_donor_pair(algod, sender, sk)


@pytest.fixture()
def m4probe(compiled, account):
    _anchor, bench = compiled
    sender, sk = account
    h = Arc4Harness(bench["M4Probe"], sender, sk)
    h.create([])
    return h


def _set_m4(m4probe, fin_slot: int, fin_root: bytes, fin_state_root: bytes):
    m4probe.submit([{"method": "set_finalized", "args": [fin_slot, fin_root, fin_state_root]}])


@pytest.fixture()
def anchor_two_rows(compiled, account, m4probe):
    """A `TrustedRootAnchor` with BOTH the real Deneb row and the real
    Electra row appended -- the honest, correctly-maintained fork table
    008 §3.3 describes, never collapsed to one row."""
    anchor_contracts, _bench = compiled
    sender, sk = account
    h = Arc4Harness(anchor_contracts["TrustedRootAnchor"], sender, sk)
    h.create([sender, m4probe.app_id, RING_N], extra_pages=1, boxes=[(0, b"forks8")], fund_app=15_000_000)
    h.ring_n = RING_N
    ring_boxes = [(0, b"h:" + i.to_bytes(8, "big")) for i in range(RING_N)]
    h.submit([{"method": "ring_init_chunk", "args": [RING_N], "boxes": ring_boxes}])
    h.submit([{
        "method": "append_fork_row",
        "args": [DENEB_ACTIVATION_EPOCH, G_STATE_ROOT, G_RECEIPTS_ROOT, G_BLOCK_NUMBER, G_BLOCK_ROOTS_BASE_DENEB],
        "boxes": [(0, b"forks8")],
    }])
    h.submit([{
        "method": "append_fork_row",
        "args": [ELECTRA_ACTIVATION_EPOCH, G_STATE_ROOT, G_RECEIPTS_ROOT, G_BLOCK_NUMBER, G_BLOCK_ROOTS_BASE_ELECTRA],
        "boxes": [(0, b"forks8")],
    }])
    return h


def _build_f6_fixture():
    """Builds the synthetic-but-self-consistent F6 fixture (module
    docstring point 3). Returns a dict of everything a test needs:
    `fin_header`/`fin_root`/`fin_state_root` (Electra, at
    `ELECTRA_ACTIVATION_SLOT`), `target_header`/`t_root` (Deneb, at
    `T_SLOT`), the three EL branches (802/803/806, depth 9 -- IDENTICAL
    row on both sides of the boundary, per 008 §3.4's own note that this is
    what makes the trap silent), and TWO `block_roots` branches for the
    SAME `(fin_state_root, t_root)` pair: `branch_correct` (composed with
    the ELECTRA base, 69, depth 19 -- the one N-FORK says MUST be used,
    keyed by `epoch(fin_slot)`) and `branch_wrong` (composed with the
    DENEB base, 37, depth 18 -- what a buggy single-lookup implementation,
    or a stale/forged fork-table row, would produce instead)."""
    # --- the target (Deneb) header and its execution-payload EL fields ---
    el_state_root = synth.random32()
    el_receipts_root = synth.random32()
    body_root, state_branch, receipts_branch, number_branch = synth.build_execution_tree(
        el_state_root, el_receipts_root, EL_BLOCK_NUMBER
    )
    t_parent_root = synth.random32()
    t_state_root_field = synth.random32()  # target header's OWN state_root field -- unused by the fold (only its htr matters)
    target_header, t_root = synth.make_header(T_SLOT, 0, t_parent_root, t_state_root_field, body_root)

    # --- the two candidate block_roots folds for the SAME (t_root) leaf ---
    g_correct = synth.compose_block_roots_gindex(G_BLOCK_ROOTS_BASE_ELECTRA, T_SLOT)
    g_wrong = synth.compose_block_roots_gindex(G_BLOCK_ROOTS_BASE_DENEB, T_SLOT)
    fin_state_root_correct, branch_correct = synth.build_tree_at_gindex(g_correct, t_root)
    _fin_state_root_wrong, branch_wrong = synth.build_tree_at_gindex(g_wrong, t_root)
    assert len(branch_correct) == 19 * 32, "Electra-base fold must be depth 19"
    assert len(branch_wrong) == 18 * 32, "Deneb-base fold must be depth 18"
    assert branch_correct != branch_wrong

    # --- the finalized (Electra) header, whose state_root IS the real
    # root of the block_roots tree the CORRECT branch folds into ---
    fin_parent_root = synth.random32()
    fin_body_root = synth.random32()  # unused by HISTORICAL mode (only fin_header.state_root/slot matter)
    fin_header, fin_root = synth.make_header(FIN_SLOT, 0, fin_parent_root, fin_state_root_correct, fin_body_root)

    return {
        "fin_header": fin_header, "fin_root": fin_root, "fin_state_root": fin_state_root_correct,
        "target_header": target_header, "t_root": t_root,
        "el_state_root": el_state_root, "el_receipts_root": el_receipts_root,
        "state_branch": state_branch, "receipts_branch": receipts_branch, "number_branch": number_branch,
        "branch_correct": branch_correct, "branch_wrong": branch_wrong,
    }


class TestF6DenebElectraTwoRowTrap:
    """008 §3.4 / §13.2 F6, ROADMAP M8 gap (1)."""

    def test_two_row_lookup_uses_electra_base_for_fin_slot_epoch(
        self, anchor_two_rows, m4probe, donors,
    ):
        """The honest, correct call: `epoch(FIN_SLOT) == 364032` selects the
        Electra row (base 69, depth-19 fold) for `block_roots`; `epoch(T_SLOT)
        == 364000` selects the Deneb row for the EL fields (802/803/806 --
        same values as Electra's row here, which is 008 §3.4's own point:
        the EL columns do not change at this boundary, only
        `g_block_roots_base` does). Must SUCCEED, and the record must carry
        `T_SLOT` (not `FIN_SLOT`) as `beacon_slot` with `FLAG_HISTORICAL`
        set."""
        fx = _build_f6_fixture()
        _set_m4(m4probe, FIN_SLOT, fx["fin_root"], fx["fin_state_root"])

        args = [
            m4probe.app_id, fx["fin_header"], fx["target_header"], fx["branch_correct"],
            fx["el_state_root"], fx["el_receipts_root"], EL_BLOCK_NUMBER,
            fx["state_branch"], fx["receipts_branch"], fx["number_branch"],
        ]
        res = anchor_two_rows.call(
            "anchor_historical", args, apps=[m4probe.app_id], extra_budget=320_000,
        )
        assert res.ok, res.failure
        record = res.return_value
        assert record is not None and len(record) == 154
        assert record[18:50] == fx["el_state_root"]
        assert record[50:82] == fx["el_receipts_root"]
        beacon_slot = int.from_bytes(record[10:18], "big")
        assert beacon_slot == T_SLOT, "record must carry t_slot, not fin_slot (§6.1)"
        flags = record[1]
        assert flags & 0b10 != 0, "FLAG_HISTORICAL must be set"

    def test_wrong_row_branch_is_rejected(self, anchor_two_rows, m4probe, donors):
        """The adversarial half of F6: SAME table (both real rows present,
        correctly distinguishing epoch(fin_slot) from epoch(t_slot)), SAME
        `fin_header`/`target_header`/EL fields -- but the `block_roots`
        branch supplied is the one composed with the DENEB base (37, depth
        18), i.e. exactly what a buggy implementation that collapsed
        N-FORK's two lookups into one (or a stale/forged fork-table row
        that never got the Electra base appended) would hand the contract.
        On-chain, `epoch(fin_slot)` still correctly resolves to the REAL
        Electra row (base 69, depth 19) -- so a depth-18 branch is a length
        mismatch against what the contract actually asks for, and must be
        REJECTED. This is the genuinely observable, on-chain proof that the
        two-row lookup is not decorative: swapping in the row N-FORK
        forbids breaks the call."""
        fx = _build_f6_fixture()
        _set_m4(m4probe, FIN_SLOT, fx["fin_root"], fx["fin_state_root"])

        args = [
            m4probe.app_id, fx["fin_header"], fx["target_header"], fx["branch_wrong"],
            fx["el_state_root"], fx["el_receipts_root"], EL_BLOCK_NUMBER,
            fx["state_branch"], fx["receipts_branch"], fx["number_branch"],
        ]
        res = anchor_two_rows.call(
            "anchor_historical", args, apps=[m4probe.app_id], extra_budget=320_000,
        )
        assert not res.ok, "a block_roots branch shaped for the WRONG fork row must be rejected"
        assert "assert failed" in res.failure

    def test_missing_electra_row_falls_back_to_stale_deneb_row_and_rejects(
        self, compiled, account, m4probe, donors,
    ):
        """A second, complementary shape of 'forged/mismatched row': the
        Electra row is simply never appended (a stale/lagging governance
        table -- 008 §3.3's own real soundness surface, TP-M8-3). Then
        `lookup_row(epoch(FIN_SLOT))` legitimately finds no row with
        `activation_epoch > 364032` and returns the LAST one, i.e. the
        Deneb row (base 37) -- for a genuinely Electra-shaped
        `fin_state_root`. Proves the on-chain code really does depend on
        the table being current, not on some other implicit correctness
        source: a truthful depth-19 branch against a table that only knows
        about Deneb's depth-18 shape is rejected the same way."""
        anchor_contracts, _bench = compiled
        sender, sk = account
        h = Arc4Harness(anchor_contracts["TrustedRootAnchor"], sender, sk)
        h.create([sender, m4probe.app_id, RING_N], extra_pages=1, boxes=[(0, b"forks8")], fund_app=15_000_000)
        h.ring_n = RING_N
        ring_boxes = [(0, b"h:" + i.to_bytes(8, "big")) for i in range(RING_N)]
        h.submit([{"method": "ring_init_chunk", "args": [RING_N], "boxes": ring_boxes}])
        # ONLY the Deneb row -- Electra's row was never appended.
        h.submit([{
            "method": "append_fork_row",
            "args": [DENEB_ACTIVATION_EPOCH, G_STATE_ROOT, G_RECEIPTS_ROOT, G_BLOCK_NUMBER, G_BLOCK_ROOTS_BASE_DENEB],
            "boxes": [(0, b"forks8")],
        }])

        fx = _build_f6_fixture()
        _set_m4(m4probe, FIN_SLOT, fx["fin_root"], fx["fin_state_root"])

        # The RELAYER honestly supplies the CORRECT (Electra-base, depth 19)
        # branch for the real fin_state_root -- but the on-chain table can
        # only offer the stale Deneb row (depth 18) for epoch(fin_slot).
        args = [
            m4probe.app_id, fx["fin_header"], fx["target_header"], fx["branch_correct"],
            fx["el_state_root"], fx["el_receipts_root"], EL_BLOCK_NUMBER,
            fx["state_branch"], fx["receipts_branch"], fx["number_branch"],
        ]
        res = h.call("anchor_historical", args, apps=[m4probe.app_id], extra_budget=320_000)
        assert not res.ok, "a stale fork table missing the Electra row must reject a genuinely Electra-shaped anchor"
        assert "assert failed" in res.failure


@pytest.fixture(scope="module")
def beacon_available() -> bool:
    import urllib.request

    from relayer.sources import beacon

    for base in beacon.BEACON_APIS:
        try:
            req = urllib.request.Request(base.rstrip("/") + "/eth/v1/config/spec", headers=beacon.HEADERS)
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:  # noqa: BLE001
            continue
    return False


class TestElectraEpochLiveCrossCheck:
    """Best-effort, network-dependent re-confirmation of this file's
    hardcoded `ELECTRA_ACTIVATION_EPOCH`/`DENEB_ACTIVATION_EPOCH` against a
    LIVE beacon node's own `/eth/v1/config/spec`, at test-run time --
    independent from, and in addition to, the three-way check already
    performed and recorded in this module's own docstring. Skipped (not
    failed) if no beacon endpoint is reachable, since the synthetic F6
    tests above do not themselves need the network."""

    def test_live_spec_matches_hardcoded_epochs(self, beacon_available):
        if not beacon_available:
            pytest.skip("no reachable beacon-API endpoint in the pool")
        import urllib.request

        from relayer.sources import beacon

        last = None
        for base in beacon.BEACON_APIS:
            try:
                req = urllib.request.Request(base.rstrip("/") + "/eth/v1/config/spec", headers=beacon.HEADERS)
                with urllib.request.urlopen(req, timeout=10) as r:
                    import json
                    data = json.load(r)["data"]
                assert int(data["ELECTRA_FORK_EPOCH"]) == ELECTRA_ACTIVATION_EPOCH
                assert int(data["DENEB_FORK_EPOCH"]) == DENEB_ACTIVATION_EPOCH
                return
            except Exception as e:  # noqa: BLE001
                last = e
                continue
        pytest.skip(f"no beacon endpoint answered /eth/v1/config/spec: {last}")
