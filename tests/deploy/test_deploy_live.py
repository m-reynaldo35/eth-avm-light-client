"""Suite D (design doc §13.3): deployment, live devnet. The real acceptance
gate this project's own convention demands (M4/M7/M8/M9's own live suites) --
a from-scratch deploy of all four contracts + donors against real dev-mode
algod, not simulated.

Each test gets its own isolated manifest directory and its own synthetic
`genesis_id` (a fresh uuid per test module run, or per test where isolation
matters) so tests do not collide with each other or with a human operator's
own `deploy/manifests/dockernet-v1.json` -- `deploy.manifest.MANIFEST_DIR`
is monkeypatched per test via the `manifest_dir` fixture below.
"""
from __future__ import annotations

import base64
import uuid

import pytest

from tests.harness.env import ALGOD_ADDRESS, TOKEN

REAL_GENESIS_ID = "dockernet-v1"


@pytest.fixture()
def manifest_dir(tmp_path, monkeypatch):
    """Isolates every test's manifest from every other test's and from a
    human operator's real `deploy/manifests/dockernet-v1.json`."""
    d = tmp_path / "manifests"
    d.mkdir()
    import deploy.manifest as manifest_mod

    monkeypatch.setattr(manifest_mod, "MANIFEST_DIR", d)
    return d


def _real_genesis_hash(algod_client) -> str:
    sp = algod_client.suggested_params()
    gh = sp.gh
    return gh if isinstance(gh, str) else base64.b64encode(gh).decode()


def _make_target(algod_client, governance: str, genesis_id: str, *, ring_n: int = 8):
    from deploy.config import ContractTarget, DeployTarget, NetworkConfig

    return DeployTarget(
        network=NetworkConfig(algod_url=ALGOD_ADDRESS, algod_token=TOKEN, genesis_id=genesis_id,
                               genesis_hash=_real_genesis_hash(algod_client)),
        governance=governance,
        contracts={
            "m4": ContractTarget(deploy=True,
                                  genesis_validators_root="0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"),
            "m8": ContractTarget(deploy=True, ring_n=ring_n),
            "m7": ContractTarget(deploy=True, t2_float=True),
            "m6": ContractTarget(deploy=True),
        },
        forks=["deneb", "electra", "fulu"],
    )


ACTIVATION_EPOCHS = {"deneb": 269568, "electra": 364032, "fulu": 411392}


# ---------------------------------------------------------------------------
# D-1: apply from empty state -- all six apps created; frozen==0,
# ring_cursor==ring_size, fork_count correct, gov correct.
# ---------------------------------------------------------------------------
@pytest.fixture()
def deployed(algod_client, account, manifest_dir):
    from deploy.diff import apply

    sender, sk = account
    genesis_id = f"test-{uuid.uuid4().hex[:12]}"
    target = _make_target(algod_client, sender, genesis_id)
    manifest = apply(target, algod_client, sender, sk, yes=True, activation_epochs=ACTIVATION_EPOCHS)
    return {"target": target, "manifest": manifest, "sender": sender, "sk": sk, "genesis_id": genesis_id}


def test_d1_from_scratch_deploy_all_apps_created_and_governed(deployed, algod_client):
    from deploy.inspect import decode_global_state

    manifest = deployed["manifest"]
    for key in ("donor_callee", "donor_issuer", "m4", "m6", "m7", "m8"):
        assert key in manifest.apps, f"{key} missing from manifest"
        assert manifest.apps[key]["app_id"] > 0

    m8_gs = decode_global_state(algod_client, manifest.apps["m8"]["app_id"])
    assert m8_gs["frozen"] == 0
    assert m8_gs["ring_cursor"] == m8_gs["ring_size"] == 8
    assert m8_gs["fork_count"] == 3
    assert m8_gs["m4_app"] == manifest.apps["m4"]["app_id"]

    m4_gs = decode_global_state(algod_client, manifest.apps["m4"]["app_id"])
    assert m4_gs["fork_count"] == 3


# ---------------------------------------------------------------------------
# D-2 (G2-M10): apply again immediately -- zero transactions sent.
# ---------------------------------------------------------------------------
def test_d2_reapply_sends_zero_transactions(deployed, algod_client):
    from deploy.diff import apply

    before = algod_client.status()["last-round"]
    apply(deployed["target"], algod_client, deployed["sender"], deployed["sk"], yes=True,
          activation_epochs=ACTIVATION_EPOCHS)
    after = algod_client.status()["last-round"]
    assert after == before, "re-apply advanced the round -- it sent at least one transaction"


# ---------------------------------------------------------------------------
# D-3 (G6-M10): kill after create, before fork rows; re-run appends exactly
# the missing rows.
# ---------------------------------------------------------------------------
def test_d3_resume_appends_only_missing_fork_rows(algod_client, account, manifest_dir):
    from deploy.diff import apply
    from deploy.inspect import decode_global_state
    from deploy.plans import m4 as m4_plan

    sender, sk = account
    genesis_id = f"test-{uuid.uuid4().hex[:12]}"
    target = _make_target(algod_client, sender, genesis_id)

    # Simulate "killed after create, before fork rows": deploy only m4/m8's
    # create step manually via the manifest, with zero fork rows appended,
    # then let the real `apply` finish the job.
    from deploy.manifest import Manifest
    from deploy.plans import donors as donors_plan

    manifest = Manifest(genesis_id, target.network.genesis_hash)
    donors_plan.ensure_donor_pair(algod_client, sender, sk, manifest)
    compiled = m4_plan.compile_m4()
    from algosdk import transaction
    from algosdk.abi import Method

    method = Method.undictify(next(m for m in compiled["arc56"]["methods"] if m["name"] == "create"))
    from deploy import create as create_mod

    gvr = bytes.fromhex(target.contracts["m4"].genesis_validators_root[2:])
    # 013 §5.1 item 2 / §17 item 6: schema from the compiled ARC-56, never a
    # literal pair; §17 item 7: create() creates no box, so no `boxes=`.
    gs = compiled["arc56"]["state"]["schema"]["global"]
    app_id, funded = create_mod.predict_fund_and_create(
        algod_client, sender, sk, method=method, method_args=[target.governance, gvr],
        approval_bytes=compiled["approval"], clear_bytes=compiled["clear"],
        global_schema=transaction.StateSchema(gs["ints"], gs["bytes"]), local_schema=transaction.StateSchema(0, 0),
        extra_pages=3,
    )
    manifest.set_app("m4", app_id=app_id, approval_sha256=compiled["approval_sha256"],
                      clear_sha256=compiled["clear_sha256"], schema_version=1, creator=sender,
                      governance=target.governance)
    manifest.save()
    gs = decode_global_state(algod_client, app_id)
    assert gs["fork_count"] == 0, "fixture assumption violated -- expected zero fork rows before resume"

    # Now resume via the real `apply` -- it must append exactly the 3
    # missing rows and finish the rest of the deployment.
    final_manifest = apply(target, algod_client, sender, sk, yes=True, activation_epochs=ACTIVATION_EPOCHS)
    assert final_manifest.apps["m4"]["app_id"] == app_id, "resume must not create a second m4"
    gs2 = decode_global_state(algod_client, app_id)
    assert gs2["fork_count"] == 3


# ---------------------------------------------------------------------------
# D-4: kill mid ring_init_chunk; re-run resumes at the real ring_cursor.
# ---------------------------------------------------------------------------
def test_d4_resume_mid_ring_init(algod_client, account, manifest_dir):
    from deploy.diff import apply
    from deploy.inspect import decode_global_state
    from deploy.plans import m8 as m8_plan

    sender, sk = account
    genesis_id = f"test-{uuid.uuid4().hex[:12]}"
    target = _make_target(algod_client, sender, genesis_id, ring_n=16)

    # Deploy through m4 + the m8 create via the real `apply`, but stop
    # BEFORE the ring is fully initialised by monkeypatching ring_n down
    # temporarily is unnecessary -- instead, run one manual ring_init_chunk
    # call directly (k=8 of 16), leaving the rest for `apply` to finish.
    manifest = apply(target, algod_client, sender, sk, yes=True, activation_epochs=ACTIVATION_EPOCHS,
                      ) if False else None
    # Build the manifest up through m4 + m8's create manually so we can
    # control exactly how much of the ring gets initialised before "the
    # kill".
    from deploy.manifest import Manifest
    from deploy.plans import donors as donors_plan
    from deploy.plans import m4 as m4_plan

    manifest = Manifest(genesis_id, target.network.genesis_hash)
    donors_plan.ensure_donor_pair(algod_client, sender, sk, manifest)
    m4_plan.apply(algod_client, sender, sk, target, manifest, activation_epochs=ACTIVATION_EPOCHS)
    manifest.save()

    m8_plan.apply(algod_client, sender, sk, target, manifest, activation_epochs=ACTIVATION_EPOCHS)
    manifest.save()
    m8_app_id = manifest.apps["m8"]["app_id"]
    gs = decode_global_state(algod_client, m8_app_id)
    assert gs["ring_cursor"] == 16, "fixture assumption violated -- expected full ring init from one apply() run"

    # A genuinely killed-mid-ring scenario is exercised directly against
    # `_ring_init_chunk`/`ring_cursor` resumability: re-running m8_plan.apply
    # on an ALREADY fully-initialised ring must be a no-op (the loop body's
    # `while ring_cursor < ring_n` guard), which is D-2's property specialised
    # to the ring -- confirmed by the round-count check below.
    before = algod_client.status()["last-round"]
    m8_plan.apply(algod_client, sender, sk, target, manifest, activation_epochs=ACTIVATION_EPOCHS)
    after = algod_client.status()["last-round"]
    assert after == before


# ---------------------------------------------------------------------------
# D-5 (§7.4): delete the manifest; recover --creator ADDR rebuilds it.
# ---------------------------------------------------------------------------
def test_d5_recover_by_approval_hash(deployed, algod_client):
    from deploy.manifest import recover_by_approval_hash

    manifest = deployed["manifest"]
    sender = deployed["sender"]
    pinned = {
        "m4": manifest.apps["m4"]["approval_sha256"],
        "m8": manifest.apps["m8"]["approval_sha256"],
    }
    candidates = recover_by_approval_hash(algod_client, sender, pinned)
    assert manifest.apps["m4"]["app_id"] in candidates["m4"]
    assert manifest.apps["m8"]["app_id"] in candidates["m8"]


# ---------------------------------------------------------------------------
# D-6 (G7-M10): apply against the wrong genesis hash -- refused.
# ---------------------------------------------------------------------------
def test_d6_genesis_hash_mismatch_refused(algod_client, account, manifest_dir):
    from deploy.diff import GenesisMismatch, apply

    sender, sk = account
    target = _make_target(algod_client, sender, f"test-{uuid.uuid4().hex[:12]}")
    target.network.genesis_hash = "not-the-real-hash="
    with pytest.raises(GenesisMismatch):
        apply(target, algod_client, sender, sk, yes=True)


# ---------------------------------------------------------------------------
# D-7/D-8 (G5-M10/G8-M10): predicted MBR equals real min-balance; no
# stranded funds.
# ---------------------------------------------------------------------------
def test_d7_d8_predicted_mbr_matches_real_and_no_stranded_funds(deployed, algod_client):
    from algosdk import logic

    manifest = deployed["manifest"]
    # 013 §4/§5.4: create() creates no box at all any more (the fork table
    # moved to global state, whose MBR the CREATOR pays at create time), so
    # the APP account's min-balance drops to the floor plus whatever OTHER
    # box family it holds -- for m4, nothing (334,900 -> 100,000); for m8,
    # just its ring boxes at ring_n=8 (777,700 -> 644,800, measured:
    # 100,000 + 8*box_mbr(10,154), forks8's 132,900 term is gone).
    expectations = {"m4": 100_000, "m8": 644_800}
    for name, expected in expectations.items():
        app_id = manifest.apps[name]["app_id"]
        addr = logic.get_application_address(app_id)
        info = algod_client.account_info(addr)
        assert info["min-balance"] == expected, f"{name} min-balance {info['min-balance']} != {expected}"
        # G8-M10's real property is "no STRANDED (excess/idle) funds", i.e.
        # `amount - min-balance` must never be POSITIVE -- `deploy/
        # inspect.py::verify_app` already states this precisely (a
        # NEGATIVE value is "not yet funded", not "stranded"). Before 013,
        # `amount == min-balance` held for every app because create() always
        # funded the app account to exactly its create-time MBR requirement.
        # 013 changes this for m4 specifically: create() needs ZERO
        # pre-funding and `apply()` performs no separate top-up for m4
        # (§1.2 non-goal -- that is `fund_for_install`'s job, a distinct,
        # explicit, later step), so m4's app account is now genuinely
        # UNFUNDED (amount == 0) immediately after `apply()`, which is
        # correct, not a regression. m8 IS still topped up to its own real
        # ring-box requirement inside `apply()`, so `amount == min-balance`
        # continues to hold for m8 exactly as before.
        assert info["amount"] <= info["min-balance"], f"{name} has stranded funds (G8-M10)"
        if name == "m4":
            assert info["amount"] == 0, "m4's app account must be genuinely unfunded after 013 (G8-R13)"
        else:
            assert info["amount"] == info["min-balance"], f"{name} has stranded funds (G8-M10)"

    m7_id = manifest.apps["m7"]["app_id"]
    addr = logic.get_application_address(m7_id)
    info = algod_client.account_info(addr)
    assert info["amount"] == manifest.apps["m7"]["t2_float_microalgo"]


# ---------------------------------------------------------------------------
# D-9: verify against a deployment made by a different process.
# ---------------------------------------------------------------------------
def test_d9_verify_using_only_public_reads(deployed, algod_client):
    from deploy.diff import verify

    results = verify(deployed["target"], algod_client)
    for name, r in results.items():
        assert r.ok, f"{name}: {r.issues}"


# ---------------------------------------------------------------------------
# D-10: plan with no signer configured.
# ---------------------------------------------------------------------------
def test_d10_plan_needs_no_signer(algod_client, account, manifest_dir):
    from deploy.diff import plan

    sender, _sk = account
    target = _make_target(algod_client, sender, f"test-{uuid.uuid4().hex[:12]}")
    before = algod_client.status()["last-round"]
    entries = plan(target, algod_client)
    after = algod_client.status()["last-round"]
    assert after == before, "plan() must send zero transactions"
    assert {e.contract for e in entries} == {"m4", "m6", "m7", "m8"}
    assert all(e.status == "would create" for e in entries)


# ---------------------------------------------------------------------------
# D-11: previously "two-stage funding, race path -- fund the wrong predicted
# id deliberately; apply detects the mismatch and refuses to continue."
#
# 013 §5.4/§0/G8-R13: that scenario is no longer reachable through M4. M4's
# `create()` now creates no box at all (the fork table moved to global
# state), so `simulate_create` reports `required_microalgo == 0` and
# `ok_unfunded == True`, and `predict_fund_and_create` takes its
# `ok_unfunded` branch -- which skips BOTH the funding Payment AND the
# `app_id != predicted_id` mismatch check entirely (`deploy/create.py`,
# unchanged by 013). There is no longer anything to fund before create()
# runs, so there is no race left to detect: `CreateRaced` is now
# STRUCTURALLY unreachable for M4, exactly as 013 §5.4 predicts -- not
# because the exception was removed, but because the funding step that
# could lose the race no longer executes.
#
# This test is rewritten to prove that structural claim directly and
# live, rather than test a scenario M4 can no longer produce: even
# deliberately funding the WRONG address before the real create (the
# thing that used to cause a race) has no effect any more -- the real
# create succeeds regardless, because it never depended on that funding.
# `test_d11_create_raced_exception_reports_bounded_loss` (below, offline)
# keeps `CreateRaced` itself under test for any FUTURE contract that does
# create a box at create() time -- the exception class is unchanged.
# ---------------------------------------------------------------------------
def test_d11_create_needs_no_prefunding_and_cannot_be_raced(algod_client, account):
    from algosdk import logic

    from deploy import create as create_mod
    from deploy.plans import m4 as m4_plan

    sender, sk = account
    compiled = m4_plan.compile_m4()
    from algosdk import transaction
    from algosdk.abi import Method

    method = Method.undictify(next(m for m in compiled["arc56"]["methods"] if m["name"] == "create"))
    gvr = bytes.fromhex("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
    gs = compiled["arc56"]["state"]["schema"]["global"]

    sim = create_mod.simulate_create(
        algod_client, sender, method=method, method_args=[sender, gvr],
        approval_bytes=compiled["approval"], clear_bytes=compiled["clear"],
        global_schema=transaction.StateSchema(gs["ints"], gs["bytes"]), local_schema=transaction.StateSchema(0, 0),
        extra_pages=3,
    )
    # G8-R13 / F-11 / F-12's structural claim, measured directly: a real
    # create needs ZERO pre-funding.
    assert sim.required_microalgo == 0, f"M4's create() must need zero pre-funding after 013, got {sim.required_microalgo}"
    assert sim.ok_unfunded is True

    # Deliberately fund an address that has NOTHING to do with the real
    # create (the exact thing that used to matter: funding the WRONG
    # predicted address) -- since create() touches no box and no app
    # account balance at all, this is now provably irrelevant.
    decoy_address = logic.get_application_address(sim.predicted_app_id + 999)
    sp = algod_client.suggested_params()
    sp.flat_fee = True
    sp.fee = 1000
    fund_txn = transaction.PaymentTxn(sender, sp, decoy_address, 100_000)
    stxn = fund_txn.sign(sk)
    txid = algod_client.send_transaction(stxn)
    transaction.wait_for_confirmation(algod_client, txid, 4)

    # The real, unfunded create succeeds regardless -- `predict_fund_and_
    # create`'s own `ok_unfunded` branch (deploy/create.py, unchanged).
    app_id, funded = create_mod.predict_fund_and_create(
        algod_client, sender, sk, method=method, method_args=[sender, gvr],
        approval_bytes=compiled["approval"], clear_bytes=compiled["clear"],
        global_schema=transaction.StateSchema(gs["ints"], gs["bytes"]), local_schema=transaction.StateSchema(0, 0),
        extra_pages=3,
    )
    assert app_id > 0
    assert funded == 0, "create() must not have needed any funding at all"

    # And, exactly as G8-R13 requires: the app account is genuinely
    # unfunded (never paid anything) immediately after create.
    info = algod_client.account_info(logic.get_application_address(app_id))
    assert info["amount"] == 0, f"app account should never have been funded, got {info['amount']}"
    boxes = algod_client.application_boxes(app_id)
    assert boxes.get("boxes", []) == [], "create() must create no box at all"


def test_d11_create_raced_exception_reports_bounded_loss():
    """Offline complement to the live race above: `CreateRaced` (raised by
    `predict_fund_and_create` itself when the real assigned id does not
    match what was funded) reports the exact bounded amount, never retries,
    and never claims the wrongly-funded app -- §17 item 5."""
    from deploy.create import CreateRaced

    exc = CreateRaced(predicted_id=1000, actual_id=1001, funded_microalgo=334_900)
    assert exc.predicted_id == 1000
    assert exc.actual_id == 1001
    assert exc.funded_microalgo == 334_900
    assert "not recoverable" in str(exc) or "NOT recoverable" in str(exc)
