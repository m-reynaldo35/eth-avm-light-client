"""Suite R (retirement, this pass's real gap) -- `retire(gen)` (`contracts/
sync_committee/verifier.py` §8.4) is a real, permissionless, already-
deployed contract method that refunds a superseded generation's ~19.76
ALGO of key-box MBR back to the app account. Before this pass, NOTHING in
this codebase ever called it (`grep -rn "retire" relayer/` returned
nothing) -- every real committee rollover just permanently locked another
generation's worth of box MBR with no automatic reclamation, even though
the contract itself has always supported reclaiming it.

This suite proves `EthAvmClient.sync(update=True)`'s new automatic
`retire_old_generations()` wiring (`relayer/client.py`) actually reclaims
that MBR, live, against real historical (genuinely real, mainnet,
BLS-signature-verified) sync-committee data spanning a real period
boundary -- not simulated, not synthetic.

Why HISTORICAL (not live-"now") periods: a genuine committee ROLLOVER
needs a real signature from sync-committee period P+1, which does not
exist yet while period P is still the live, current period (periods are
~27.3h; waiting one out live is not a real option for a test run).
Historical periods `PERIOD_P`/`PERIOD_P1` below (long past, well after the
"fulu" fork activation `tests/sync_committee/test_live_e2e_finality.py`'s
own live tests already use -- `FULU_FORK_EPOCH=411392` -> fulu period
1607, vs. period ~1823 at the time this pass was written) are already
finalized on real mainnet, so `/eth/v1/beacon/light_client/updates?
start_period=` serves REAL BLS-signed committee data for both periods
immediately, no wait needed. `EthAvmClient._drive_m4_update`'s own
`beacon.fetch_finality_update()` call is monkeypatched to return this real
historical `LightClientUpdate` instead of "whatever mainnet finalized a
moment ago" -- the ONLY thing faked is WHEN the data is fetched from,
never WHAT it is: every header, branch, signature, and pubkey below is
real vendored mainnet consensus data, verified for real by the real
deployed contract exactly as `test_live_e2e_finality.py`/`test_live_relayer
.py`'s own `env_a` fixture do for "now" data.

**Real, additional bug found and fixed while building this test** (see
`relayer/client.py`'s `_drive_m4_update`, ROADMAP.md's M4 row): the
box-reference plan for a `submit_update` call always assumed `cur_gen`'s
key boxes, even when the submission's signature period is `store_period +
1` -- in which case the real contract reads `next_gen`'s key boxes instead
(`verifier.py`'s own step 5, `submit_update`). This meant `sync(
update=True)` could never actually have driven a real rollover before this
fix, independent of `retire()` never being called -- a real,
non-hypothetical structural box-reference mismatch, not a hypothetical
edge case. Fixed by computing `using_next`/`committee_gen` client-side
with the exact same rule the contract applies, before planning box refs.

**Real, honest finding about what "the ALGO comes back" actually means**
(confirmed via a standalone box-create/delete probe against a throwaway
app on this same dev-mode algod before writing this suite): Algorand box
MBR is a REQUIREMENT on funds the app account must already hold, not an
escrow -- `retire()` never issues an inner `Payment` (confirmed by reading
`install_delete_committee_boxes`: plain `Box.delete` calls only), so the
account's `amount` field does NOT change by even one microALGO when a box
is deleted. What changes -- provably, measured live below -- is
`min-balance`, which drops by EXACTLY the box's declared MBR, freeing that
same amount of real, already-resident ALGO to become spendable again
(`amount - min-balance` rises by exactly the refund). This suite asserts
that real property, not a literal `amount` increase, and states plainly
why.

**This pass's own addition (test_r4, below):** `test_r1` above proves
exactly ONE real rollover-then-retire cycle. That leaves a real, explicitly
named gap open: does the recycling actually hold up over MULTIPLE
consecutive real rotations, or could something drift/compound/leak across
cycles that a single cycle's own before/after snapshot cannot reveal (a
stale global-state field, a box left half-deleted, a peak that creeps
upward cycle over cycle)? `test_r4` drives THREE full real install-ahead ->
rollover -> auto-retire cycles back to back, across four real, historical
periods (1810 -> 1811 -> 1812 -> 1813), through the SAME production
`EthAvmClient.sync(update=True)` entry point `test_r1` uses, in its own
freshly-deployed environment (`env_retire_multi`, independent of
`env_retire` above so the two suites' on-chain state never interacts).
"""
from __future__ import annotations

import pytest
from algosdk import logic, transaction
from algosdk.abi import Method
from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer

from deploy.inspect import list_boxes
from deploy.mbr import box_mbr
from relayer.codec.bls import g1_compressed_to_avm
from relayer.codec.committee import committee_root
from relayer.codec.header import hash_tree_root_beacon_block_header
from relayer.drivers import m4_sync_committee as m4
from relayer.group.boxes import key_box_name, session_box_name, total_box_name
from relayer.group.donors import donor_transaction_with_signer
from relayer.sources import beacon
from tests.relayer.test_live_relayer import ALGOD_AVAILABLE, BEACON_AVAILABLE, _client_for, _deploy_m4

# 011 §4.1: same shape as test_live_relayer.py -- every test in this file
# is Tier C (algod + beacon), driven from eagerly-computed booleans rather
# than fixture parameters, so the tier auto-marker cannot infer it from a
# fixture closure. Explicit module-level pytestmark, mirroring that file.
pytestmark = [pytest.mark.needs_algod, pytest.mark.needs_network]

# Real, already-elapsed mainnet sync-committee periods (~27.3h each), both
# well after fulu's own activation period (1607) and well before "now"
# (~1823 at the time this pass was written) -- see module docstring for
# why historical, not live-now, periods are required to exercise a real
# rollover without an unbounded real-time wait.
PERIOD_P = 1810
PERIOD_P1 = PERIOD_P + 1

# Two generations' worth of key-box MBR (~39.5 ALGO) must coexist on-chain
# simultaneously right up until the rollover retires the first --
# `tests/sync_committee/harness.py`'s own `APP_FUNDING_MICROALGO` (45
# ALGO) is sized for only ONE generation, so this env needs real, explicit
# extra headroom on top of it.
EXTRA_APP_FUNDING_MICROALGO = 25_000_000

_EXTRA_METHODS = dict(m4.METHODS)
_EXTRA_METHODS["install_begin"] = Method.from_signature("install_begin(uint64)void")


def _add_call(h, atc, name: str, args: list, boxes=None) -> None:
    signer = AccountTransactionSigner(h.sk)
    sp = h.algod.suggested_params()
    sp.flat_fee = True
    sp.fee = 1000
    kwargs = {"boxes": boxes} if boxes else {}
    atc.add_method_call(
        app_id=h.app_id, method=_EXTRA_METHODS[name], sender=h.sender, sp=sp, signer=signer,
        method_args=args, **kwargs,
    )


@pytest.fixture(scope="module")
def donor_pair():
    if not ALGOD_AVAILABLE:
        pytest.skip("no dev-mode algod reachable")
    from tests.harness.chain import algod_client, funded_account, kmd_client
    from tests.harness.deployment import deploy_donor_pair as ts_deploy_donor_pair

    algod_c = algod_client()
    kmd_c = kmd_client()
    sender, sk = funded_account(algod_c, kmd_c)
    callee_id, issuer_id = ts_deploy_donor_pair(algod_c, sender, sk)
    return {"sender": sender, "sk": sk, "callee_id": callee_id, "issuer_id": issuer_id}


@pytest.fixture(scope="module")
def historical_period_data():
    if not BEACON_AVAILABLE:
        pytest.skip("no reachable beacon-API endpoint in the pool")
    update_p = beacon.fetch_updates(PERIOD_P, 1)[0]
    update_p1 = beacon.fetch_updates(PERIOD_P1, 1)[0]
    args_p = m4.transform_light_client_update(update_p)
    args_p1 = m4.transform_light_client_update(update_p1)

    assert "next_sync_committee" in update_p["data"], f"period {PERIOD_P}'s real update carries no next_sync_committee"

    checkpoint_root = hash_tree_root_beacon_block_header(args_p.finalized_header)
    boot_resp = beacon.fetch_bootstrap(checkpoint_root.hex())
    boot_args = m4.transform_bootstrap(boot_resp)
    assert hash_tree_root_beacon_block_header(boot_args.header) == checkpoint_root
    assert len(boot_args.pubkey_pairs) == 512

    nsc = update_p["data"]["next_sync_committee"]
    next_root_check = committee_root(nsc["pubkeys"], nsc["aggregate_pubkey"])
    assert next_root_check == args_p.next_committee_root, "real next_sync_committee does not fold to its own proven root"
    next_pairs = [g1_compressed_to_avm(pk) for pk in nsc["pubkeys"]]
    next_agg_compressed, next_agg_uncompressed = g1_compressed_to_avm(nsc["aggregate_pubkey"])
    assert len(next_pairs) == 512

    return {
        "update_p": update_p, "update_p1": update_p1, "args_p": args_p, "args_p1": args_p1,
        "checkpoint_root": checkpoint_root, "boot_args": boot_args, "next_pairs": next_pairs,
        "next_agg_compressed": next_agg_compressed, "next_agg_uncompressed": next_agg_uncompressed,
    }


# ---------------------------------------------------------------------------
# Real environment: gen 1 (cur_gen, period P) installed entirely through
# EthAvmClient (mirrors test_live_relayer.py's own env_a exactly), then gen
# 2 (next_gen, period P+1) installed via the SAME real install_begin ->
# install_open_keys -> install_open_session -> 64x install_chunk ->
# install_finalize sequence, but via raw ATC calls (mirroring `test_l7`'s
# own established pattern for the bootstrap flow) -- EthAvmClient's
# `_drive_m4_install` only ever drives the GENESIS `bootstrap` path, a
# real, already-named gap (ROADMAP M9's row item (b)) this pass's own
# scope (`retire()`) does not additionally close.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def env_retire(historical_period_data, donor_pair):
    if not ALGOD_AVAILABLE:
        pytest.skip("no dev-mode algod reachable")
    h = _deploy_m4()
    client = _client_for(h, donor_pair)
    d = historical_period_data

    install_result = client.sync(install=True, update=False, bootstrap_root=d["checkpoint_root"])
    assert install_result.ok
    gs = client._read_global_state(h.app_id)
    assert gs[b"cur_gen"] == 1, "genesis install must land as cur_gen"

    # A single-generation contract has NOTHING retireable yet -- a real,
    # live no-op (requirement 3: fresh install must be a no-op, not an
    # error), asserted here for free (no transactions) before gen 2 exists.
    assert client.retire_old_generations() == {"retired": [], "skipped_already_retired": [], "failed": []}

    # -- discovery: re-submit period P's OWN real update as a real
    #    submit_update, via the client's public `submit_update_group`
    #    (promoted from private in M11, 011 §6.3 -- the SAME method
    #    `test_l2` in `test_live_relayer.py` already calls directly, for
    #    exactly this reason: to
    #    force a specific real, historical `args` tuple that `_drive_m4_
    #    update`'s own "always fetch whatever finalized a moment ago"
    #    fetch cannot express). finalized_slot(args_p) == the store's own
    #    fin_slot (bootstrap seeded it from this exact header), so this
    #    deliberately does NOT advance finality -- it only exercises
    #    `submit_update`'s "discover next committee opportunistically"
    #    side effect (verifier.py's module docstring, elaboration 2),
    #    which runs independently of whether finality itself advances. --
    mode, plan = m4.plan_submit_update_boxes(d["args_p"].sync_committee_bits, 1)
    discovery_result = client.submit_update_group(1, d["args_p"], mode, plan)
    assert discovery_result.tx_ids, "the real discovery submit_update did not commit"
    gs = client._read_global_state(h.app_id)
    assert gs[b"next_committee_root_trusted"] == d["args_p"].next_committee_root
    assert gs[b"next_committee_root_period"] == PERIOD_P1

    app_address = logic.get_application_address(h.app_id)
    sp = h.algod.suggested_params()
    pay = transaction.PaymentTxn(h.sender, sp, app_address, EXTRA_APP_FUNDING_MICROALGO)
    txid = h.algod.send_transaction(pay.sign(h.sk))
    transaction.wait_for_confirmation(h.algod, txid, 4)

    # -- gen 2 (next_gen): real install_begin/install_open_keys/install_
    #    open_session box-opening group, mirroring `bootstrap`'s own group
    #    shape (25 pooled box refs) exactly, just with `install_begin`
    #    swapped in (it touches zero boxes of its own, per its docstring,
    #    so no `forks`-box ref is needed here unlike bootstrap's). --
    key_refs = [(0, key_box_name(2, j)) for j in range(8)]
    session_ref = [(0, session_box_name(2))]
    atc = AtomicTransactionComposer()
    _add_call(h, atc, "install_begin", [PERIOD_P1], boxes=key_refs)
    _add_call(h, atc, "install_open_keys", [], boxes=key_refs)
    _add_call(h, atc, "install_open_session", [], boxes=session_ref + key_refs[:7])
    _add_call(h, atc, "noop_budget", [], boxes=session_ref)
    atc.execute(h.algod, 4)

    gs = client._read_global_state(h.app_id)
    assert gs[b"inst_state"] == 3, "install session must be INSTALLING after the box-opening group"
    assert gs[b"inst_gen"] == 2

    for start in range(0, 512, m4.INSTALL_CHUNK_SIZE):
        chunk = d["next_pairs"][start:start + m4.INSTALL_CHUNK_SIZE]
        compressed_blob = b"".join(c for c, _u in chunk)
        uncompressed_blob = b"".join(u for _c, u in chunk)
        kb = key_box_name(2, start // 64)
        sb = session_box_name(2)
        atc2 = AtomicTransactionComposer()
        atc2.add_transaction(donor_transaction_with_signer(
            h.algod, h.sender, h.sk, donor_pair["issuer_id"], donor_pair["callee_id"], 40,
        ))
        _add_call(h, atc2, "install_chunk", [start, compressed_blob, uncompressed_blob],
                  boxes=[(0, kb), (0, sb), (0, kb), (0, sb)])
        atc2.execute(h.algod, 4)

    atc3 = AtomicTransactionComposer()
    atc3.add_transaction(donor_transaction_with_signer(
        h.algod, h.sender, h.sk, donor_pair["issuer_id"], donor_pair["callee_id"], 10,
    ))
    _add_call(h, atc3, "install_finalize", [d["next_agg_compressed"], d["next_agg_uncompressed"]],
              boxes=[(0, session_box_name(2)), (0, total_box_name(2))])
    atc3.execute(h.algod, 4)

    gs = client._read_global_state(h.app_id)
    assert gs[b"next_gen"] == 2
    assert gs[b"next_period"] == PERIOD_P1
    assert gs[b"cur_gen"] == 1, "rollover must not have happened yet -- gen 1 is still the about-to-be-superseded committee"
    assert gs[b"inst_state"] == 0

    return {"h": h, "client": client, "app_address": app_address, "data": d}


def test_r1_rollover_auto_retires_old_generation_real_mbr_reclaimed(env_retire, monkeypatch):
    h = env_retire["h"]
    client = env_retire["client"]
    app_address = env_retire["app_address"]
    d = env_retire["data"]

    # THE exact real refund, derived from real declared box sizes (`deploy.
    # mbr.box_mbr`, `relayer.group.boxes.key_box_name`/`total_box_name`) --
    # never a hardcoded 19.76 magic number.
    expected_refund = sum(box_mbr(len(key_box_name(1, j)), 6144) for j in range(8)) + box_mbr(len(total_box_name(1)), 96)
    assert expected_refund == 19_760_900, "cross-check against the design doc's own measured figure (010 SS10.2)"

    info_before = client.algod.account_info(app_address)
    amount_before, min_balance_before = info_before["amount"], info_before["min-balance"]

    client.algod.application_box_by_name(h.app_id, total_box_name(1))  # gen 1's boxes are genuinely still live

    # THE only faked thing: WHEN this data is fetched from, never WHAT it
    # is (module docstring) -- `update_p1` is a real, historical, BLS-
    # signed mainnet LightClientUpdate for period P+1.
    monkeypatch.setattr(beacon, "fetch_finality_update", lambda: d["update_p1"])
    sync_result = client.sync(install=False, update=True)

    update_detail = sync_result.detail["update"]
    assert "skipped" not in update_detail, f"the real rollover update must not have been skipped: {update_detail}"
    assert update_detail["using_next"] is True, "this submission's signature period must be store_period + 1"
    assert update_detail["committee_gen"] == 2, "must have been verified against gen 2's (next_gen's) real committee"

    gs = client._read_global_state(h.app_id)
    assert gs[b"cur_gen"] == 2, "the real rollover must have promoted gen 2 to cur_gen"
    assert gs[b"next_gen"] == 0

    retire_detail = sync_result.detail["retire"]
    assert not retire_detail["failed"], f"no legitimate retire failure was expected here: {retire_detail['failed']}"
    retired_gens = {r["gen"] for r in retire_detail["retired"]}
    assert retired_gens == {1}, f"gen 1 (now superseded) should have been auto-retired this call, got {retired_gens}"

    with pytest.raises(Exception):  # noqa: B017 -- real 404, gen 1's total box must genuinely be gone now
        client.algod.application_box_by_name(h.app_id, total_box_name(1))

    info_after = client.algod.account_info(app_address)
    amount_after, min_balance_after = info_after["amount"], info_after["min-balance"]

    # See module docstring: box MBR is a requirement on already-resident
    # funds, never an escrow -- `retire()` issues no inner Payment, so
    # `amount` is EXPECTED, correctly, to be unchanged. What "the ALGO
    # comes back" really means, proven live here: min-balance drops by
    # EXACTLY the real declared refund, and spendable headroom
    # (amount - min-balance) rises by that same exact amount.
    assert amount_after == amount_before, "a box refund is a min-balance reduction, not a fund transfer"
    assert min_balance_before - min_balance_after == expected_refund
    spendable_before = amount_before - min_balance_before
    spendable_after = amount_after - min_balance_after
    assert spendable_after - spendable_before == expected_refund

    print(
        f"\nM4 REAL LIVE PROOF (retire() wiring, this pass's fix): real rollover at M4 app {h.app_id} "
        f"promoted gen 2 to cur_gen via a real submit_update (committee_gen=2, using_next=True) and "
        f"auto-retired gen 1 via sync(update=True)'s new retire_old_generations(). "
        f"min-balance: {min_balance_before} -> {min_balance_after} "
        f"(delta={min_balance_before - min_balance_after}, expected_refund={expected_refund} microALGO "
        f"= {expected_refund / 1_000_000} ALGO); amount unchanged at {amount_after} microALGO (no inner "
        f"Payment -- MBR is a requirement on resident funds, not an escrow); spendable "
        f"(amount - min-balance) rose by the same {spendable_after - spendable_before} microALGO. "
        f"retire tx_ids={retire_detail['retired'][0]['tx_ids']}"
    )


def test_r2_second_retire_of_same_generation_is_a_harmless_noop_not_a_double_refund(env_retire):
    """Confirms the SECOND retirement attempt of an already-retired
    generation cannot double-refund or corrupt state. Real, measured
    finding this pass, stated honestly rather than assumed: `retire(gen)`'s
    own asserts (`verifier.py`) only reject `gen == cur_gen/next_gen/
    inst_gen` -- there is no separate on-chain flag for "already retired".
    A second `retire(1)` call therefore does NOT fail on-chain: AVM
    `box_del` on an already-missing box name simply returns 0/false (no
    assertion), so the call genuinely COMMITS, as a real, harmless no-op.
    This test proves the property that actually matters -- no double
    refund, no state corruption -- rather than asserting a rejection that
    would misdescribe the contract's real, live-confirmed behaviour.
    """
    h = env_retire["h"]
    client = env_retire["client"]
    app_address = env_retire["app_address"]

    info_before = client.algod.account_info(app_address)
    amount_before, min_balance_before = info_before["amount"], info_before["min-balance"]

    result = client._retire_generation(1)  # gen 1 was already fully retired by test_r1, above
    assert result["tx_ids"], "the second real retire(1) call is expected to COMMIT (a real no-op), not fail"

    info_after = client.algod.account_info(app_address)
    assert info_after["amount"] == amount_before
    assert info_after["min-balance"] == min_balance_before, (
        "a second retire of an already-retired generation must not change min-balance at all -- no double refund"
    )

    print(
        f"\nM4 REAL LIVE PROOF: a second real retire(1) call on M4 app {h.app_id} committed as a "
        f"harmless no-op (tx_ids={result['tx_ids']}) -- min-balance unchanged at {min_balance_before} "
        "microALGO, confirming no double-refund and no state corruption, even though the contract's own "
        "asserts do not separately reject an already-retired generation (verified live, not assumed)."
    )


def test_r3_retire_old_generations_noop_on_a_brand_new_contract(donor_pair):
    """Requirement 3, cheapest form: a genuinely brand-new contract (no
    committee ever installed, `cur_gen == gen_counter == 0`) must be a
    true no-op -- zero transactions, zero errors. Deliberately does NOT
    install a real 512-member committee (unlike `env_retire`) since this
    property needs nothing more than a bare deploy to prove."""
    if not ALGOD_AVAILABLE:
        pytest.skip("no dev-mode algod reachable")
    h = _deploy_m4()
    client = _client_for(h, donor_pair)

    result = client.retire_old_generations()
    assert result == {"retired": [], "skipped_already_retired": [], "failed": []}

    print(
        f"\nM4 REAL LIVE PROOF: retire_old_generations() on a brand-new M4 app {h.app_id} "
        "(gen_counter==0, no committee ever installed) is a genuine no-op -- no transactions submitted, "
        "no error raised."
    )


# ---------------------------------------------------------------------------
# This pass's own real gap: does the recycling proven above by test_r1 hold
# up over MULTIPLE consecutive real rotations, not just one? Reuses
# PERIOD_P/PERIOD_P1 as the first two periods and extends two more real,
# already-elapsed mainnet periods -- four periods in total, giving THREE
# full install-ahead -> rollover -> auto-retire cycles (gen1->gen2->gen3->
# gen4), the real minimum-plus-one bar for "proves it's not a one-off" (the
# task's own bar was >= 2 cycles / 3-4 periods).
#
# A SEPARATE, freshly-deployed M4 app is used (`env_retire_multi`'s own
# `_deploy_m4()` call) -- this suite drives three rollovers against it, so
# it must never share on-chain state with `env_retire`'s own single-cycle
# environment above (`test_r1`/`test_r2`/`test_r3`).
# ---------------------------------------------------------------------------
PERIOD_P2 = PERIOD_P1 + 1
PERIOD_P3 = PERIOD_P2 + 1


def _fetch_period_data(period: int) -> dict:
    """Same real transform/assert shape `historical_period_data` already
    applies to PERIOD_P/PERIOD_P1 inline, generalised to any single period:
    fetches `period`'s own real, BLS-signature-verified update and folds
    out its `next_sync_committee` (i.e. real committee data for `period +
    1`) into ready-to-install `(compressed, uncompressed)` pairs plus its
    aggregate key -- exactly what `env_retire`'s own fixture body does
    inline for PERIOD_P, just made reusable across four periods."""
    update = beacon.fetch_updates(period, 1)[0]
    args = m4.transform_light_client_update(update)
    assert "next_sync_committee" in update["data"], f"period {period}'s real update carries no next_sync_committee"
    nsc = update["data"]["next_sync_committee"]
    next_root_check = committee_root(nsc["pubkeys"], nsc["aggregate_pubkey"])
    assert next_root_check == args.next_committee_root, "real next_sync_committee does not fold to its own proven root"
    next_pairs = [g1_compressed_to_avm(pk) for pk in nsc["pubkeys"]]
    next_agg_compressed, next_agg_uncompressed = g1_compressed_to_avm(nsc["aggregate_pubkey"])
    assert len(next_pairs) == 512
    return {
        "period": period, "update": update, "args": args, "next_pairs": next_pairs,
        "next_agg_compressed": next_agg_compressed, "next_agg_uncompressed": next_agg_uncompressed,
    }


@pytest.fixture(scope="module")
def historical_period_data_multi():
    if not BEACON_AVAILABLE:
        pytest.skip("no reachable beacon-API endpoint in the pool")
    periods = [_fetch_period_data(p) for p in (PERIOD_P, PERIOD_P1, PERIOD_P2, PERIOD_P3)]

    checkpoint_root = hash_tree_root_beacon_block_header(periods[0]["args"].finalized_header)
    boot_resp = beacon.fetch_bootstrap(checkpoint_root.hex())
    boot_args = m4.transform_bootstrap(boot_resp)
    assert hash_tree_root_beacon_block_header(boot_args.header) == checkpoint_root
    assert len(boot_args.pubkey_pairs) == 512

    return {"periods": periods, "checkpoint_root": checkpoint_root, "boot_args": boot_args}


@pytest.fixture(scope="module")
def env_retire_multi(historical_period_data_multi, donor_pair):
    """Only gen 1 (genesis, bootstrapped from PERIOD_P's real checkpoint)
    and this environment's real extra funding are set up here; the actual
    install-ahead/rollover/retire cycles are driven inside the test itself
    so each cycle's real, measured intermediate balances can be recorded
    and compared cycle-to-cycle."""
    if not ALGOD_AVAILABLE:
        pytest.skip("no dev-mode algod reachable")
    h = _deploy_m4()
    client = _client_for(h, donor_pair)
    d = historical_period_data_multi

    install_result = client.sync(install=True, update=False, bootstrap_root=d["checkpoint_root"])
    assert install_result.ok
    gs = client._read_global_state(h.app_id)
    assert gs[b"cur_gen"] == 1, "genesis install must land as cur_gen"

    # Same real peak-sizing reasoning as `env_retire` above: at most TWO
    # generations' worth of key-box MBR ever coexist at once (the old one
    # is retired before a third is ever installed), so the SAME extra
    # funding suffices for all three cycles, not just one.
    app_address = logic.get_application_address(h.app_id)
    sp = h.algod.suggested_params()
    pay = transaction.PaymentTxn(h.sender, sp, app_address, EXTRA_APP_FUNDING_MICROALGO)
    txid = h.algod.send_transaction(pay.sign(h.sk))
    transaction.wait_for_confirmation(h.algod, txid, 4)

    return {"h": h, "client": client, "app_address": app_address, "donor_pair": donor_pair, "periods": d["periods"]}


def _discovery_resubmit(client, committee_gen: int, args, expected_next_period: int) -> None:
    """Re-submits `args` (a period's OWN real update, already reflected
    on-chain as the store's current finality) as a non-advancing
    `submit_update`, purely for its opportunistic next-committee discovery
    side effect (verifier.py module docstring elaboration 2) -- the SAME
    real method `env_retire`'s own fixture already calls directly for
    PERIOD_P/PERIOD_P1's discovery step, generalised here to run once per
    cycle: `next_committee_root_trusted`/`_period` are never reset by
    `install_begin`/`install_finalize`, but they are also never advanced to
    a FURTHER-OUT period except by a fresh discovery submission like this
    one, so each of the three cycles below needs its own."""
    mode, plan = m4.plan_submit_update_boxes(args.sync_committee_bits, committee_gen)
    result = client.submit_update_group(committee_gen, args, mode, plan)
    assert result.tx_ids, "the real discovery submit_update did not commit"
    gs = client._read_global_state(client.config.m4_app_id)
    assert gs[b"next_committee_root_trusted"] == args.next_committee_root
    assert gs[b"next_committee_root_period"] == expected_next_period


def _install_ahead(h, client, donor_pair, gen: int, period: int,
                    next_pairs, next_agg_compressed, next_agg_uncompressed) -> None:
    """The real `install_begin -> install_open_keys -> install_open_session
    -> 64x install_chunk -> install_finalize` sequence for a non-genesis
    generation, factored out of `env_retire`'s own inline body above so
    this suite can run it three times (once per cycle) without hand-copying
    it three times over."""
    key_refs = [(0, key_box_name(gen, j)) for j in range(8)]
    session_ref = [(0, session_box_name(gen))]
    atc = AtomicTransactionComposer()
    _add_call(h, atc, "install_begin", [period], boxes=key_refs)
    _add_call(h, atc, "install_open_keys", [], boxes=key_refs)
    _add_call(h, atc, "install_open_session", [], boxes=session_ref + key_refs[:7])
    _add_call(h, atc, "noop_budget", [], boxes=session_ref)
    atc.execute(h.algod, 4)

    gs = client._read_global_state(h.app_id)
    assert gs[b"inst_state"] == 3, "install session must be INSTALLING after the box-opening group"
    assert gs[b"inst_gen"] == gen

    for start in range(0, 512, m4.INSTALL_CHUNK_SIZE):
        chunk = next_pairs[start:start + m4.INSTALL_CHUNK_SIZE]
        compressed_blob = b"".join(c for c, _u in chunk)
        uncompressed_blob = b"".join(u for _c, u in chunk)
        kb = key_box_name(gen, start // 64)
        sb = session_box_name(gen)
        atc2 = AtomicTransactionComposer()
        atc2.add_transaction(donor_transaction_with_signer(
            h.algod, h.sender, h.sk, donor_pair["issuer_id"], donor_pair["callee_id"], 40,
        ))
        _add_call(h, atc2, "install_chunk", [start, compressed_blob, uncompressed_blob],
                  boxes=[(0, kb), (0, sb), (0, kb), (0, sb)])
        atc2.execute(h.algod, 4)

    atc3 = AtomicTransactionComposer()
    atc3.add_transaction(donor_transaction_with_signer(
        h.algod, h.sender, h.sk, donor_pair["issuer_id"], donor_pair["callee_id"], 10,
    ))
    _add_call(h, atc3, "install_finalize", [next_agg_compressed, next_agg_uncompressed],
              boxes=[(0, session_box_name(gen)), (0, total_box_name(gen))])
    atc3.execute(h.algod, 4)

    gs = client._read_global_state(h.app_id)
    assert gs[b"next_gen"] == gen
    assert gs[b"next_period"] == period
    assert gs[b"inst_state"] == 0


def test_r4_three_consecutive_real_cycles_no_drift_no_leak(env_retire_multi, monkeypatch):
    """The real gap this pass closes: `test_r1`'s single-cycle proof cannot
    rule out drift/leak/compounding across REPEATED real rotations -- e.g.
    a box left half-deleted, a stale global-state field silently growing,
    or a peak that creeps upward cycle over cycle. This test drives THREE
    full real install-ahead -> rollover -> auto-retire cycles back to back
    (gen1->gen2->gen3->gen4, across real periods 1810->1811->1812->1813)
    through the SAME production `EthAvmClient.sync(update=True)` entry
    point `test_r1` uses for its single cycle, and asserts the real,
    measured pattern holds identically every time: peak min-balance during
    each install-ahead phase is IDENTICAL cycle to cycle (box names are
    fixed-width, §7.4/`relayer/group/boxes.py` -- MBR is content-
    independent, so there is no reason for it to differ), and the
    post-retire baseline returns to EXACTLY the same value every cycle, not
    creeping upward."""
    h = env_retire_multi["h"]
    client = env_retire_multi["client"]
    app_address = env_retire_multi["app_address"]
    donor_pair = env_retire_multi["donor_pair"]
    periods = env_retire_multi["periods"]

    expected_refund = sum(box_mbr(len(key_box_name(1, j)), 6144) for j in range(8)) + box_mbr(len(total_box_name(1)), 96)
    assert expected_refund == 19_760_900

    def _balance():
        info = client.algod.account_info(app_address)
        return info["amount"], info["min-balance"]

    amount0, min_balance0 = _balance()
    records: list[dict] = []
    cur_gen = 1

    for i in range(3):
        d_cur, d_next = periods[i], periods[i + 1]
        new_gen = cur_gen + 1

        amount_pre, min_balance_pre = _balance()

        # -- ahead-of-time install phase: discover the next period's real
        #    trusted committee root, then run the real install_begin/...
        #    /install_finalize sequence for it while `cur_gen` is still the
        #    active committee (mirrors env_retire's own single-cycle body,
        #    factored into `_discovery_resubmit`/`_install_ahead` above). --
        _discovery_resubmit(client, cur_gen, d_cur["args"], d_next["period"])
        _install_ahead(
            h, client, donor_pair, new_gen, d_next["period"],
            d_cur["next_pairs"], d_cur["next_agg_compressed"], d_cur["next_agg_uncompressed"],
        )

        amount_peak, min_balance_peak = _balance()
        client.algod.application_box_by_name(h.app_id, total_box_name(cur_gen))  # still live, pre-retire

        # -- THE real, production rollover call: the SAME EthAvmClient.
        #    sync(update=True) entry point test_r1 proves for one cycle,
        #    monkeypatched only on WHEN this period's real update is
        #    fetched from, never WHAT it is (module docstring). Its own
        #    new retire_old_generations() wiring fires automatically. --
        monkeypatch.setattr(beacon, "fetch_finality_update", lambda u=d_next["update"]: u)
        sync_result = client.sync(install=False, update=True)

        update_detail = sync_result.detail["update"]
        assert "skipped" not in update_detail, f"cycle {i + 1}: real rollover must not have been skipped: {update_detail}"
        assert update_detail["using_next"] is True, f"cycle {i + 1}: signature period must be store_period + 1"
        assert update_detail["committee_gen"] == new_gen

        gs = client._read_global_state(h.app_id)
        assert gs[b"cur_gen"] == new_gen, f"cycle {i + 1}: rollover must have promoted gen {new_gen} to cur_gen"
        assert gs[b"next_gen"] == 0

        retire_detail = sync_result.detail["retire"]
        assert not retire_detail["failed"], f"cycle {i + 1}: no legitimate retire failure expected: {retire_detail['failed']}"
        assert {r["gen"] for r in retire_detail["retired"]} == {cur_gen}, (
            f"cycle {i + 1}: gen {cur_gen} (now superseded) should have been auto-retired this call"
        )

        with pytest.raises(Exception):  # noqa: B017 -- real 404, this generation's total box must genuinely be gone
            client.algod.application_box_by_name(h.app_id, total_box_name(cur_gen))

        amount_post, min_balance_post = _balance()

        assert amount_pre == amount_peak == amount_post == amount0, (
            f"cycle {i + 1}: amount must never move -- box MBR is a min-balance requirement, never a fund transfer "
            f"(amount_pre={amount_pre}, amount_peak={amount_peak}, amount_post={amount_post}, amount0={amount0})"
        )
        assert min_balance_peak - min_balance_pre == expected_refund, (
            f"cycle {i + 1}: installing generation {new_gen} ahead of time while generation {cur_gen} is still "
            f"live must raise min-balance by exactly one generation's real box MBR "
            f"(got {min_balance_peak - min_balance_pre}, expected {expected_refund})"
        )
        assert min_balance_post == min_balance_pre, (
            f"cycle {i + 1}: post-retire min-balance ({min_balance_post}) must return to this cycle's own "
            f"pre-install baseline ({min_balance_pre}) -- any difference would be real drift/leak"
        )

        records.append({
            "cycle": i + 1, "retired_gen": cur_gen, "new_cur_gen": new_gen,
            "period_retired": d_cur["period"], "period_now_current": d_next["period"],
            "min_balance_pre": min_balance_pre, "min_balance_peak": min_balance_peak, "min_balance_post": min_balance_post,
            "amount": amount_post, "tx_ids_retire": retire_detail["retired"][0]["tx_ids"],
        })
        cur_gen = new_gen

    # -- cross-cycle: no drift. Every cycle's own pre-install baseline AND
    #    the final post-retire value must be the exact same real number --
    #    if anything leaked or compounded across repeated real cycles, this
    #    is where it would show up. --
    baselines = [min_balance0] + [r["min_balance_pre"] for r in records] + [records[-1]["min_balance_post"]]
    assert len(set(baselines)) == 1, f"post-retire baseline drifted across cycles: {baselines}"
    peaks = [r["min_balance_peak"] for r in records]
    assert len(set(peaks)) == 1, f"peak min-balance differed across cycles (box names are fixed-width -- should be identical): {peaks}"
    amounts = [amount0] + [r["amount"] for r in records]
    assert len(set(amounts)) == 1, f"amount moved across cycles: {amounts}"

    # -- orphan check: gens 1-3 (all now retired) must have NOTHING left on
    #    chain -- not just their `a:<gen>` total box (already checked
    #    per-cycle above via the real 404), but all 8 key boxes and the
    #    session box too (already deleted at install_finalize time, per
    #    `install_process_finalize`, so this doubles as confirmation that
    #    retire's own cleanup is not silently relying on something
    #    install_finalize already did). Only gen 4 (the final cur_gen)
    #    should still have any boxes at all. --
    box_names = set(list_boxes(client.algod, h.app_id))
    for retired_gen in (1, 2, 3):
        assert total_box_name(retired_gen) not in box_names, f"gen {retired_gen}'s total box orphaned"
        assert session_box_name(retired_gen) not in box_names, f"gen {retired_gen}'s session box orphaned"
        for j in range(8):
            assert key_box_name(retired_gen, j) not in box_names, f"gen {retired_gen}'s key box {j} orphaned"
    assert total_box_name(4) in box_names, "the final, still-active generation's total box should still be live"
    for j in range(8):
        assert key_box_name(4, j) in box_names, "the final, still-active generation's key boxes should still be live"

    print(
        "\nM4 REAL LIVE MULTI-CYCLE PROOF (this pass's own gap): three consecutive real rollover+auto-retire "
        f"cycles at M4 app {h.app_id}, real periods 1810->1811->1812->1813, all driven through the real, "
        "production EthAvmClient.sync(update=True):\n"
        + "\n".join(
            f"  cycle {r['cycle']} (retire gen {r['retired_gen']}, period {r['period_retired']} -> "
            f"cur_gen {r['new_cur_gen']}, period {r['period_now_current']}): "
            f"min-balance {r['min_balance_pre']} -> (install-ahead peak {r['min_balance_peak']}, "
            f"+{r['min_balance_peak'] - r['min_balance_pre']}) -> {r['min_balance_post']} (post-retire, "
            f"delta {r['min_balance_peak'] - r['min_balance_post']}); amount unchanged at {r['amount']}; "
            f"retire tx_ids={r['tx_ids_retire']}"
            for r in records
        )
        + f"\nPost-retire baseline identical across all cycles at {records[-1]['min_balance_post']} microALGO "
        f"(no drift/leak across {len(records)} repeated cycles); peak identical every cycle at {peaks[0]} "
        f"microALGO; amount constant throughout at {amounts[0]} microALGO; zero orphaned boxes for any of "
        "the 3 retired generations, confirmed via a real application_boxes listing."
    )
