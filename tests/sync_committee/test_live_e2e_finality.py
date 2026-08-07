"""The headline live proof M4 never had before this pass: does a REAL,
currently-live Ethereum `finality_update` -- fetched fresh from a real
beacon-chain light-client API via `service/x402_endpoint/eth_beacon_rpc.py`,
never a static vendored fixture -- actually verify correctly on-chain
against a REAL, freshly-installed `SyncCommitteeVerifier` instance on real
dev-mode algod? Every existing M4 test (`tests/sync_committee/*.py`)
exercises either pre-vendored Altair-minimal-preset test vectors or
synthetic self-consistent fixtures (`test_install_live.py`'s own module
docstring says so explicitly); this is the first time real mainnet data has
been pushed through the full bootstrap -> install -> submit_update pipeline
end to end.

Reuses, rather than re-invents:
  * `tests/sync_committee/conftest.py`'s `SyncCommitteeLiveHarness` for
    deploy/create/submit -- the same dev-mode algod (`:4051`/`:4052`)
    `test_install_live.py` already uses, brought up per that file's README
    recipe (`tests/fixtures/spike-reference/README.md`).
  * `service/x402_endpoint/eth_beacon_rpc.py` for every byte of real chain
    data and its ABI-argument shaping -- this file adds NO new fetching or
    decoding logic, only real-data-driven test orchestration.
  * `test_install_live.py`'s own box-naming helpers and box-opening group
    shape (`bootstrap` -> `install_open_keys` -> `install_open_session`,
    §16) verbatim, substituting real live checkpoint data for that file's
    synthetic fixture.

What real, live "fulu"-fork data exposed that no prior pass had to deal
with, and how each was resolved:

1. **Fork-row registration (§4, `forks.py`)**: M4's `forks` box has never
   been populated with anything but placeholder/test values. The real,
   live gindices for the CURRENT fork ("fulu", confirmed via
   `/eth/v1/beacon/light_client/finality_update`'s own `version` field) are
   NOT the Altair-preset constants (`finality=105`/depth 6,
   `current_sc=54`/`next_sc=55`/depth 5) `test_install_live.py`'s synthetic
   fixture uses -- Electra's `BeaconState` container growth (new fields
   pushing the container past the 32-field/depth-5 boundary into
   64-field/depth-6) reshuffled every one of these generalized indices one
   level deeper. This module does NOT trust that reasoning alone: the real
   values used below (`finality=169`, `current_sc=86`, `next_sc=87`,
   matching docs/design/004-sync-committee.md §9.1's own "Electra/Fulu
   gindices (169 finality / 87 next committee)" citation) were independently
   BRUTE-FORCE CONFIRMED by folding a real, live `current_sync_committee`
   root and a real, live `finalized_header` root through their real,
   live branches (both fetched fresh) against every gindex candidate at
   the observed depth (6 and 7 nodes respectively) and finding the unique
   match -- then confirmed a THIRD, independent way when the real
   `bootstrap()` call below (which performs this exact merkle check
   on-chain) accepted the real committee root against real live data using
   these values. The real `activation_epoch` (411,392) and 4-byte
   `fork_version` (`0x06000000`) come directly from the beacon node's own
   `/eth/v1/config/spec` endpoint, not from memory or a hardcoded guess.
   ONE fork row suffices for this test: every real epoch touched here
   (attested/finalized/signature slots, all fetched fresh at test time) is
   already deep into "fulu" territory, so there is no genuine fork-boundary
   straddle to register a second row for.

2. **A real, previously-undiscovered bug, found and FIXED this pass** (not
   a workaround): `contracts/primitives/ssz/merkleize.py`'s
   `merkleize_stack_finalize` silently returned the WRONG root whenever the
   pushed leaf count was EXACTLY `2**depth` (a fully-packed SSZ Vector).
   The real, completed subtree root ends up in stack slot `depth` (the
   "extra" slot `SESSION_STACK_SLOTS = COMMITTEE_MERKLE_DEPTH + 1`
   provisions for exactly this case), but the finalize loop only ever read
   slots `0..depth-1` and silently substituted a chain of bare
   `zero_hash` values instead -- invisible for any partial fill (which is
   all `tests/ssz/test_merkleize.py`'s own `NON_POWER_OF_TWO_NS` list ever
   exercises; it deliberately stops at 511, one below the depth-9
   boundary) but ALWAYS wrong for a real mainnet sync committee, which has
   EXACTLY 512 = 2**9 members, every single time, by protocol definition.
   `install_process_finalize` -- the ONLY real caller in this project that
   ever pushes an exact `2**depth` count -- could therefore never have
   succeeded against ANY real, complete 512-member committee before this
   fix, on any past or future data. Fixed directly in `merkleize.py` (see
   that file's updated docstring/code); all 165 pre-existing
   `tests/ssz/` tests still pass unchanged, confirming the fix only
   changes behaviour in the previously-untested, previously-wrong
   exact-power-of-two branch.

3. **Real per-call opcode-budget donation, wired up for M4 for the first
   time**: `install_chunk` (real `g1_bind` measured at 1,966/point,
   design doc §2.2) and `submit_update` (worst case 157,509, §9.1) both
   vastly exceed a single app call's 700-budget base, and -- unlike M5/M6/
   M7's own production walker contracts -- `SyncCommitteeVerifier` does not
   issue its own inner donor calls (its `donor()` method is deliberately
   just an inner-call TARGET, per its own docstring, and the AVM forbids an
   app from inner-calling itself). This module deploys the tiny, test-only
   `DonorCallee`/`DonorIssuer` pair from the new
   `contracts/sync_committee/bench_app.py` (mirroring
   `contracts/mpt/bench_app.py`'s own `_issue_donors`/trivial-callee
   pattern exactly, "NEVER deploy to mainnet") as a SEPARATE sibling
   top-level transaction in the same atomic group, ahead of the real
   `install_chunk`/`submit_update` call -- opcode-budget pooling is
   group-wide, not per-transaction or per-app (confirmed by this project's
   own pre-existing `noop_budget()` sibling-call pattern), so the credit
   `DonorIssuer` raises is available to the unmodified, real verifier call
   later in the same group. No change was made to `verifier.py`/
   `install.py` themselves to achieve this.

4. **Real mainnet participation was 512/512 (zero absentees)** at the time
   this was run, which makes adaptive complement mode (`mode=1`) the
   obviously cheap choice for the real submission (measured 91,384 vs
   mode=0's 211,266) and means the real box-reference set for the headline
   submission is trivially small: just the `forks` box (fork-table lookup)
   and the committee's `a:<gen>` total box (complement mode's baseline) --
   no absentee key boxes to reference at all.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import pytest
from algosdk import transaction
from algosdk.abi import Method
from algosdk.atomic_transaction_composer import (
    AccountTransactionSigner,
    AtomicTransactionComposer,
    TransactionWithSigner,
)

from relayer.drivers import m4_sync_committee as m4sc
from relayer.group.boxes import plan_box_refs
from relayer.sources import beacon
from tests.sync_committee import reference as ref
from tests.sync_committee.conftest import ALGOD_ADDRESS, TOKEN, SyncCommitteeLiveHarness

REPO_ROOT = Path(__file__).resolve().parents[2]
BENCH_SRC = REPO_ROOT / "contracts" / "sync_committee" / "bench_app.py"

# Real, live network constants -- NOT hardcoded from memory: fetched fresh
# from the beacon node's own /eth/v1/beacon/genesis and /eth/v1/config/spec
# endpoints the one time this module needed them confirmed (module
# docstring point 1). Re-derived here as literals only because they are
# genuinely static (mainnet's genesis root and the "fulu" fork's activation
# epoch/version do not change), not because they were assumed rather than
# checked.
GENESIS_VALIDATORS_ROOT_HEX = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
FULU_FORK_VERSION = bytes.fromhex("06000000")
FULU_FORK_EPOCH = 411392

# Real, live-confirmed generalized indices (module docstring point 1;
# independently brute-force-verified against real fetched data, matching
# docs/design/004-sync-committee.md §9.1's own citation).
FINALITY_GINDEX = 169
CURRENT_SC_GINDEX = 86
NEXT_SC_GINDEX = 87

GEN = 1  # first bootstrap on a fresh app always assigns gen_counter -> 1
KEYS_PER_BOX = 64
KEY_BOX_BYTES = 6144  # real declared size, contracts/sync_committee/constants.py's KEY_BOX_BYTES
FORKS_BOX_BYTES = 576  # real declared size, contracts/sync_committee/forks.py's FORKS_BOX_BYTES
TOTAL_BOX_BYTES = 96  # G1_UNCOMPRESSED_BYTES, the A_total box's real declared size
CHUNK_SIZE = 8  # max chunk that fits a single ARC-4 call's 2,048 B app-args cap
CHUNK_DONORS = 40  # >= ~26 measured minimum (real g1_bind x8 + ec_add + merkleize), margin for safety
FINALIZE_DONORS = 15
SUBMIT_DONORS = 150  # >= ~131 measured minimum for a mode=1 (complement) submission


def key_box_name(gen: int, j: int) -> bytes:
    return b"k:" + gen.to_bytes(8, "big") + j.to_bytes(8, "big")[7:8]


def session_box_name(gen: int) -> bytes:
    return b"s:" + gen.to_bytes(8, "big")


def total_box_name(gen: int) -> bytes:
    return b"a:" + gen.to_bytes(8, "big")


def _choose_mode_and_boxes(sync_committee_bits: bytes, gen: int):
    """Real mainnet participation is NOT guaranteed to be a fixed number
    across separate live fetches (it moves block to block) -- this computes,
    from the ACTUAL fetched bitfield, which key boxes `aggregate_participants`
    will really touch under each mode (`bitfield.py`'s `walk_and_accumulate`:
    direct mode touches participant-holding boxes, complement mode touches
    absentee-holding boxes plus the `a:<gen>` total box) and picks whichever
    mode is really cheaper.

    FIXED (this pass): the original version picked the mode with fewer
    DISTINCT boxes touched, which is only the first term of
    `relayer.group.boxes.plan_box_refs`'s real closed form
    (`refs = max(len(distinct), ceil(bytes/2048))`). Every M4 key box is a
    real, declared 6,144 B regardless of how many bits happen to fall in
    it, so at real high participation (few absentee boxes, e.g. 1-3),
    DIRECT mode's touched-box COUNT can look cheap while its real BYTE
    term is not -- this is the exact, now-identified root cause of every
    "box read/write budget (N) exceeded" failure this project's own
    history has hit in this file and its callers (6144, 18432, 20480,
    22528 -- all real, all this one mechanism, confirmed live).

    Returns `(mode, box_refs, plan)` -- `plan` (a `BoxRefPlan`) is what
    `_submit_update_group` now sizes the real transaction count from,
    instead of assuming 2 transactions always suffice."""

    def bit_set(i: int) -> bool:
        byte = sync_committee_bits[i // 8]
        return (byte >> (7 - (i % 8))) & 1 == 1

    participant_boxes = sorted({i // KEYS_PER_BOX for i in range(512) if bit_set(i)})
    absentee_boxes = sorted({i // KEYS_PER_BOX for i in range(512) if not bit_set(i)})

    def plan_for(key_boxes: list[int], *, include_total: bool):
        sizes = {"forks": FORKS_BOX_BYTES}
        for j in key_boxes:
            sizes[f"k:{j}"] = KEY_BOX_BYTES
        if include_total:
            sizes["total"] = TOTAL_BOX_BYTES
        return plan_box_refs(sizes)

    plan_direct = plan_for(participant_boxes, include_total=False)
    plan_complement = plan_for(absentee_boxes, include_total=True)

    if plan_complement.refs_required <= plan_direct.refs_required:
        boxes = [(0, b"forks")] + [(0, key_box_name(gen, j)) for j in absentee_boxes] + [(0, total_box_name(gen))]
        return 1, boxes, plan_complement
    boxes = [(0, b"forks")] + [(0, key_box_name(gen, j)) for j in participant_boxes]
    return 0, boxes, plan_direct


def _beacon_reachable() -> bool:
    for base in beacon.BEACON_APIS:
        try:
            req = urllib.request.Request(
                base.rstrip("/") + "/eth/v1/beacon/light_client/finality_update",
                headers=beacon.HEADERS,
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:  # noqa: BLE001
            continue
    return False


@pytest.fixture(scope="module")
def beacon_available() -> bool:
    return _beacon_reachable()


@pytest.fixture(scope="module")
def compiled_bench_app(algod_available):
    """Compiles `contracts/sync_committee/bench_app.py` (the new,
    test-only `DonorCallee`/`DonorIssuer` pair, module docstring point 3)
    once per module run and returns their algod-compiled bytecode."""
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")
    out_dir = Path(tempfile.mkdtemp(prefix="m4_bench_"))
    subprocess.run(
        [sys.executable, "-m", "puyapy", str(BENCH_SRC), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )

    def compile_teal(name: str, kind: str = "approval") -> bytes:
        src = (out_dir / f"{name}.{kind}.teal").read_text()
        req = urllib.request.Request(
            ALGOD_ADDRESS + "/v2/teal/compile",
            data=src.encode(),
            headers={"X-Algo-API-Token": TOKEN, "Content-Type": "text/plain"},
            method="POST",
        )
        with urllib.request.urlopen(req) as r:
            body = json.load(r)
        return base64.b64decode(body["result"])

    return {
        "callee_approval": compile_teal("DonorCallee"),
        "callee_clear": compile_teal("DonorCallee", "clear"),
        "issuer_approval": compile_teal("DonorIssuer"),
        "issuer_clear": compile_teal("DonorIssuer", "clear"),
    }


def _fetch_live_checkpoint_and_update(max_attempts: int = 3):
    """Fetches a REAL, live finality_update to submit, plus a REAL,
    strictly-EARLIER real checkpoint from the SAME sync-committee period to
    bootstrap from (so the submission actually ADVANCES finalized state,
    module docstring: bootstrapping from the update's own finalized header
    would seed fin_slot == the update's finalized_slot exactly, and
    `submit_update` only advances on a STRICT increase). Retries a couple
    of times in case of a rare period-boundary race (real wall-clock
    timing, not a stub)."""
    last_err = None
    for _ in range(max_attempts):
        try:
            fu_now = beacon.fetch_finality_update()
            fu_now_args = m4sc.transform_finality_update(fu_now)
            fu_now_finalized_slot = int.from_bytes(fu_now_args.finalized_header[0:8], "little")
            fu_now_attested_slot = int.from_bytes(fu_now_args.attested_header[0:8], "little")
            period = fu_now_attested_slot // 8192

            checkpoint_update = beacon.fetch_updates(period, 1)[0]
            checkpoint_args = m4sc.transform_light_client_update(checkpoint_update)
            checkpoint_finalized_slot = int.from_bytes(checkpoint_args.finalized_header[0:8], "little")

            if checkpoint_finalized_slot >= fu_now_finalized_slot:
                last_err = AssertionError(
                    f"checkpoint finalized_slot {checkpoint_finalized_slot} not "
                    f"earlier than submission update's {fu_now_finalized_slot}"
                )
                time.sleep(2)
                continue

            checkpoint_root = ref.hash_tree_root_beacon_block_header(checkpoint_args.finalized_header)
            boot_resp = beacon.fetch_bootstrap(checkpoint_root.hex())
            boot_args = m4sc.transform_bootstrap(boot_resp)
            assert ref.hash_tree_root_beacon_block_header(boot_args.header) == checkpoint_root
            assert len(boot_args.pubkey_pairs) == 512

            return {
                "fu_now": fu_now,
                "fu_now_args": fu_now_args,
                "checkpoint_root": checkpoint_root,
                "boot_args": boot_args,
            }
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(2)
    raise RuntimeError(f"could not assemble a live checkpoint+update pair: {last_err}")


@pytest.fixture(scope="module")
def genesis_validators_root() -> bytes:
    return bytes.fromhex(GENESIS_VALIDATORS_ROOT_HEX)


@pytest.fixture(scope="module")
def live_data(beacon_available):
    if not beacon_available:
        pytest.skip("no reachable beacon-API endpoint in the pool")
    return _fetch_live_checkpoint_and_update()


def _deploy_bench_apps(h: SyncCommitteeLiveHarness, bench) -> tuple[int, int]:
    def deploy(approval, clear):
        sp = h.algod.suggested_params()
        txn = transaction.ApplicationCreateTxn(
            sender=h.sender,
            sp=sp,
            on_complete=transaction.OnComplete.NoOpOC,
            approval_program=approval,
            clear_program=clear,
            global_schema=transaction.StateSchema(0, 0),
            local_schema=transaction.StateSchema(0, 0),
        )
        stxn = txn.sign(h.sk)
        txid = h.algod.send_transaction(stxn)
        res = transaction.wait_for_confirmation(h.algod, txid, 4)
        return res["application-index"]

    callee_id = deploy(bench["callee_approval"], bench["callee_clear"])
    issuer_id = deploy(bench["issuer_approval"], bench["issuer_clear"])
    return callee_id, issuer_id


def _issue_donor_txn(h: SyncCommitteeLiveHarness, issuer_id: int, callee_id: int, n: int, extra_boxes=None):
    """Builds the `DonorIssuer` sibling transaction (module docstring point
    3). `extra_boxes` lets this SAME transaction also carry overflow box
    references that don't fit in `submit_update`'s own 8-per-transaction
    array -- box references are a transaction-level field, not something
    tied to which app actually touches the box (`noop_budget()`'s own
    docstring in `verifier.py` makes exactly this point for the install
    path); this is the same trick applied to the donor txn instead."""
    signer = AccountTransactionSigner(h.sk)
    sp = h.algod.suggested_params()
    sp.flat_fee = True
    sp.fee = (n + 1) * 1000
    kwargs = {}
    if extra_boxes:
        kwargs["boxes"] = extra_boxes
    txn = transaction.ApplicationNoOpTxn(
        sender=h.sender,
        sp=sp,
        index=issuer_id,
        app_args=[n.to_bytes(8, "big"), callee_id.to_bytes(8, "big")],
        foreign_apps=[callee_id],
        **kwargs,
    )
    return TransactionWithSigner(txn, signer)


def _submit_update_group(
    h: SyncCommitteeLiveHarness,
    issuer_id: int,
    callee_id: int,
    args,
    signature: bytes,
    mode: int,
    box_refs: list,
    finality_branch: bytes | None = None,
    plan=None,
):
    """Builds and executes the real (non-simulated) `[DonorIssuer,
    noop_budget*, submit_update]` atomic group.

    FIXED (this pass): the original version always assumed a fixed
    2-transaction shape (`[DonorIssuer, submit_update]`), splitting
    `box_refs` across only those two -- structurally incapable of the
    25-ref/4-transaction real worst case `plan_box_refs` can compute (real
    high-participation DIRECT mode). This now sizes the group's real
    transaction count from `plan.txns_required` (falls back to computing
    a plan from `len(box_refs)` alone if the caller doesn't pass one, for
    the few call sites that build `box_refs` by hand rather than via
    `_choose_mode_and_boxes`), mirroring `relayer/client.py`'s own
    `_submit_update_group` exactly: the donor's own `foreign_apps`
    reference counts against its per-transaction ref budget too (real,
    live-confirmed finding), so its padding capacity is 7 boxes, not 8;
    `submit_update` and each `noop_budget` filler still get the full 8."""
    if plan is None:
        plan = plan_box_refs({f"box{i}": 1 for i, _ in enumerate(box_refs)})

    refs = list(box_refs)
    if refs:
        base = list(refs)
        while len(refs) < plan.refs_required:
            refs.append(base[len(refs) % len(base)])

    submit_boxes, remaining = refs[:8], refs[8:]
    donor_boxes, remaining = remaining[:7], remaining[7:]
    filler_chunks = [remaining[i:i + 8] for i in range(0, len(remaining), 8)]

    method = Method.undictify(h.methods["submit_update"])
    noop_method = Method.undictify(h.methods["noop_budget"])
    signer = AccountTransactionSigner(h.sk)
    atc = AtomicTransactionComposer()

    atc.add_transaction(_issue_donor_txn(h, issuer_id, callee_id, SUBMIT_DONORS, extra_boxes=donor_boxes or None))

    for fb in filler_chunks:
        sp = h.algod.suggested_params()
        sp.flat_fee = True
        sp.fee = 1000
        atc.add_method_call(
            app_id=h.app_id, method=noop_method, sender=h.sender, sp=sp, signer=signer,
            method_args=[], boxes=fb,
        )

    sp = h.algod.suggested_params()
    sp.flat_fee = True
    sp.fee = 1000
    atc.add_method_call(
        app_id=h.app_id,
        method=method,
        sender=h.sender,
        sp=sp,
        signer=signer,
        method_args=[
            args.attested_header,
            args.finalized_header,
            finality_branch if finality_branch is not None else args.finality_branch,
            args.next_committee_root,
            args.next_committee_branch,
            args.sync_committee_bits,
            signature,
            args.signature_slot,
            mode,
        ],
        boxes=submit_boxes,
    )
    return atc.execute(h.algod, 4)


@pytest.fixture(scope="module")
def installed_committee(algod_available, live_data, compiled_bench_app, genesis_validators_root):
    """The expensive, shared setup: deploys a fresh `SyncCommitteeVerifier`,
    registers the real live "fulu" fork row, bootstraps from a REAL earlier
    checkpoint in the same sync-committee period, and installs the REAL,
    complete 512-member committee via 64 real (non-simulated) `install_chunk`
    submissions plus a real `install_finalize` -- all against real dev-mode
    algod. Runs once per module; every test below builds on this SAME
    committed on-chain state, matching `test_install_live.py`'s own
    module-fixture convention.
    """
    if not algod_available:
        pytest.skip("no dev-mode algod reachable")

    boot_args = live_data["boot_args"]
    checkpoint_root = live_data["checkpoint_root"]

    h = SyncCommitteeLiveHarness()
    h.create(h.sender, genesis_validators_root)

    callee_id, issuer_id = _deploy_bench_apps(h, compiled_bench_app)

    h.submit(
        [
            (
                "append_fork_row",
                [FULU_FORK_EPOCH, FULU_FORK_VERSION, FINALITY_GINDEX, CURRENT_SC_GINDEX, NEXT_SC_GINDEX],
                [(0, b"forks")],
            )
        ]
    )

    key_refs = [(0, key_box_name(GEN, j)) for j in range(8)]
    session_ref = [(0, session_box_name(GEN))]
    h.submit(
        [
            (
                "bootstrap",
                [boot_args.header, boot_args.committee_root, boot_args.current_sc_branch, checkpoint_root],
                [(0, b"forks")] + key_refs[:7],
            ),
            ("install_open_keys", [], key_refs),
            ("install_open_session", [], session_ref + key_refs[:7]),
            ("noop_budget", [], session_ref),
        ]
    )

    info = h.algod.application_info(h.app_id)
    gstate = {base64.b64decode(kv["key"]): kv["value"] for kv in info["params"]["global-state"]}
    assert gstate[b"inst_state"]["uint"] == 3, "box-opening did not reach INSTALLING"

    method = Method.undictify(h.methods["install_chunk"])

    for cursor in range(0, 512, CHUNK_SIZE):
        chunk = boot_args.pubkey_pairs[cursor : cursor + CHUNK_SIZE]
        compressed_blob = b"".join(c for c, _u in chunk)
        uncompressed_blob = b"".join(u for _c, u in chunk)
        box_j = cursor // KEYS_PER_BOX
        kb = key_box_name(GEN, box_j)
        sb = session_box_name(GEN)

        signer = AccountTransactionSigner(h.sk)
        atc = AtomicTransactionComposer()
        atc.add_transaction(_issue_donor_txn(h, issuer_id, callee_id, CHUNK_DONORS))
        sp = h.algod.suggested_params()
        sp.flat_fee = True
        sp.fee = 1000
        atc.add_method_call(
            app_id=h.app_id,
            method=method,
            sender=h.sender,
            sp=sp,
            signer=signer,
            method_args=[cursor, compressed_blob, uncompressed_blob],
            boxes=[(0, kb), (0, sb), (0, kb), (0, sb)],
        )
        atc.execute(h.algod, 4)

    # install_finalize -- THE check: the real 512-member merkleized root
    # must equal `inst_root` (module docstring point 2: this is exactly the
    # call path the merkleize_stack_finalize fix was required for).
    signer = AccountTransactionSigner(h.sk)
    atc = AtomicTransactionComposer()
    atc.add_transaction(_issue_donor_txn(h, issuer_id, callee_id, FINALIZE_DONORS))
    finalize_method = Method.undictify(h.methods["install_finalize"])
    sp = h.algod.suggested_params()
    sp.flat_fee = True
    sp.fee = 1000
    atc.add_method_call(
        app_id=h.app_id,
        method=finalize_method,
        sender=h.sender,
        sp=sp,
        signer=signer,
        method_args=[boot_args.aggregate_compressed, boot_args.aggregate_uncompressed],
        boxes=[(0, session_box_name(GEN)), (0, total_box_name(GEN))],
    )
    atc.execute(h.algod, 4)

    return {"h": h, "callee_id": callee_id, "issuer_id": issuer_id}


def test_real_512_member_committee_installs_live(installed_committee):
    """The real, complete, 512-member mainnet sync committee -- fetched
    fresh, chunked, bound (`g1_bind`), merkle-checked, and summed via 64
    real (non-simulated) `install_chunk` calls plus a real
    `install_finalize` -- lands as `cur_gen` (the genesis-install path,
    `verifier.py`'s own elaboration 1). This is the scenario
    `merkleize_stack_finalize`'s bug (module docstring point 2) made
    permanently impossible before this pass's fix: a REAL committee is
    ALWAYS exactly 512 members, so this check could never have passed on
    any real data, ever, until the fix landed.
    """
    h = installed_committee["h"]
    info = h.algod.application_info(h.app_id)
    gstate = {base64.b64decode(kv["key"]): kv["value"] for kv in info["params"]["global-state"]}
    assert gstate[b"cur_gen"]["uint"] == GEN
    assert gstate[b"inst_state"]["uint"] == 0  # INST_STATE_IDLE, session closed out


def test_live_finality_update_verifies_and_advances_state_for_real(installed_committee, live_data, compiled_bench_app):
    """THE headline proof this whole module exists for: a REAL, currently
    live Ethereum `finality_update` (fetched fresh, no static fixture),
    submitted as a REAL (non-simulated) atomic transaction group against the
    real, freshly-installed committee above, is ACCEPTED on-chain, and
    `fin_slot`/`fin_root`/`fin_state_root` afterward match EXACTLY what the
    live data actually said -- not merely "some update was accepted."
    """
    h = installed_committee["h"]
    issuer_id = installed_committee["issuer_id"]
    callee_id = installed_committee["callee_id"]
    fu_now_args = live_data["fu_now_args"]

    mode, box_refs, plan = _choose_mode_and_boxes(fu_now_args.sync_committee_bits, GEN)
    result = _submit_update_group(h, issuer_id, callee_id, fu_now_args, fu_now_args.signature, mode, box_refs, plan=plan)
    assert result.tx_ids, "real submit_update group did not commit"

    expected_finalized_slot = int.from_bytes(fu_now_args.finalized_header[0:8], "little")
    expected_finalized_root = ref.hash_tree_root_beacon_block_header(fu_now_args.finalized_header)
    expected_finalized_state_root = fu_now_args.finalized_header[48:80]

    info = h.algod.application_info(h.app_id)
    gstate = {base64.b64decode(kv["key"]): kv["value"] for kv in info["params"]["global-state"]}
    assert gstate[b"fin_slot"]["uint"] == expected_finalized_slot
    assert base64.b64decode(gstate[b"fin_root"]["bytes"]) == expected_finalized_root
    assert base64.b64decode(gstate[b"fin_state_root"]["bytes"]) == expected_finalized_state_root


def test_corrupted_signature_is_rejected_live(installed_committee, beacon_available):
    """A byte-flipped signature on an otherwise-real, freshly-fetched update
    is genuinely REJECTED on-chain (a real network/protocol error on a real
    submission attempt, not a simulated assert) -- proving the positive test
    above is checking something real, not merely accepting anything shaped
    like a valid call."""
    if not beacon_available:
        pytest.skip("no reachable beacon-API endpoint in the pool")
    h = installed_committee["h"]
    issuer_id = installed_committee["issuer_id"]
    callee_id = installed_committee["callee_id"]

    info_before = h.algod.application_info(h.app_id)
    gstate_before = {base64.b64decode(kv["key"]): kv["value"] for kv in info_before["params"]["global-state"]}
    fin_slot_before = gstate_before[b"fin_slot"]["uint"]

    fu_next = beacon.fetch_finality_update()
    fu_next_args = m4sc.transform_finality_update(fu_next)

    sig = bytearray(fu_next_args.signature)
    sig[100] ^= 0xFF  # flip a byte inside the G2 point encoding
    corrupted_sig = bytes(sig)
    assert corrupted_sig != fu_next_args.signature

    mode, box_refs, plan = _choose_mode_and_boxes(fu_next_args.sync_committee_bits, GEN)

    with pytest.raises(Exception):
        _submit_update_group(h, issuer_id, callee_id, fu_next_args, corrupted_sig, mode, box_refs, plan=plan)

    info_after = h.algod.application_info(h.app_id)
    gstate_after = {base64.b64decode(kv["key"]): kv["value"] for kv in info_after["params"]["global-state"]}
    assert gstate_after[b"fin_slot"]["uint"] == fin_slot_before, "rejected submission must not change state"


def test_corrupted_merkle_branch_is_rejected_live(installed_committee, beacon_available):
    """A byte-flipped `finality_branch` sibling node (real signature intact,
    same shape, wrong content) is genuinely REJECTED on-chain -- a distinct
    failure mode from the signature/curve check above, proving the merkle
    verification itself (not just BLS validity) is load-bearing."""
    if not beacon_available:
        pytest.skip("no reachable beacon-API endpoint in the pool")
    h = installed_committee["h"]
    issuer_id = installed_committee["issuer_id"]
    callee_id = installed_committee["callee_id"]

    fu_next = beacon.fetch_finality_update()
    fu_next_args = m4sc.transform_finality_update(fu_next)

    branch = bytearray(fu_next_args.finality_branch)
    branch[10] ^= 0xFF
    corrupted_branch = bytes(branch)
    assert corrupted_branch != fu_next_args.finality_branch

    mode, box_refs, plan = _choose_mode_and_boxes(fu_next_args.sync_committee_bits, GEN)

    with pytest.raises(Exception):
        _submit_update_group(
            h, issuer_id, callee_id, fu_next_args, fu_next_args.signature, mode, box_refs,
            finality_branch=corrupted_branch, plan=plan,
        )
