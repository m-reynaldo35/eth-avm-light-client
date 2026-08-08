"""§5.2: `SyncCommitteeVerifier` deployment sequence -- compile, predict+fund
+create, top up, append the fork rows. Stops there (§1.2 non-goal: the
committee install session is M9's).
"""
from __future__ import annotations

import base64
from pathlib import Path

from algosdk import transaction
from algosdk.abi import Method

from deploy import create as create_mod
from deploy import forks as forks_mod
from deploy.compile import puya_compile, sha256_hex
from deploy.mbr import min_extra_pages

REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER_SRC = REPO_ROOT / "contracts" / "sync_committee" / "verifier.py"

FORKS_BOX_NAME = b"forks"
FORK_ROW_BYTES = 36

# §5.2 step 4 / §8.2's SEPARATE `deploy fund --app m4 --stage install`
# subcommand -- deliberately NOT part of `apply`'s own automatic sequence.
# G8-M10/D-7 requires `amount - min-balance == 0` for m4 right after
# `apply` (create + fork rows only, no boxes beyond `forks` yet) --
# eagerly pre-funding to the install level here would strand exactly the
# same idle-until-M9-installs ALGO §2.3/§10.3 call out as the over-funding
# defect this design fixes (D1). So `apply` stops at "funded, governed" per
# §1.2's own non-goal, and the install-level top-up is a distinct, explicit,
# operator-invoked step run immediately before M9's `sync(install=True)` --
# not something `apply` guesses is coming.
FUND_STAGE_MICROALGO = {
    "install": 20_227_000,  # one generation installing (§4.1's MBR table)
    "rollover": 40_119_100,  # two generations, one installing (period rollover)
}


class ForkRowConflict(RuntimeError):
    """§11.4 / §17 item 10: an already-appended on-chain fork row disagrees
    with the target. FATAL -- never append a "corrected" row on top."""


def compile_m4() -> dict:
    compiled = puya_compile(VERIFIER_SRC)["SyncCommitteeVerifier"]
    arc56 = compiled["arc56"]
    approval = base64.b64decode(arc56["byteCode"]["approval"])
    clear = base64.b64decode(arc56["byteCode"]["clear"])
    return {"arc56": arc56, "approval": approval, "clear": clear,
            "approval_sha256": sha256_hex(approval), "clear_sha256": sha256_hex(clear)}


def _read_fork_rows(algod_client, app_id: int) -> list[tuple]:
    from deploy.inspect import read_box

    try:
        raw = read_box(algod_client, app_id, FORKS_BOX_NAME)
    except Exception:
        return []
    from deploy.inspect import decode_global_state

    gs = decode_global_state(algod_client, app_id)
    fork_count = gs.get("fork_count", 0)
    rows = []
    for i in range(fork_count):
        chunk = raw[i * FORK_ROW_BYTES:(i + 1) * FORK_ROW_BYTES]
        activation_epoch = int.from_bytes(chunk[0:8], "big")
        fork_version = chunk[8:12]
        finality_gindex = int.from_bytes(chunk[12:20], "big")
        current_sc = int.from_bytes(chunk[20:28], "big")
        next_sc = int.from_bytes(chunk[28:36], "big")
        rows.append((activation_epoch, fork_version, finality_gindex, current_sc, next_sc))
    return rows


def desired_fork_rows(forks: list[str], activation_epochs: dict[str, int]) -> list[tuple]:
    from deploy.versions_guard import assert_fork_appendable

    rows = []
    for fork in forks:
        # 012 §3.7/§17 item 5: client-side refusal, BEFORE ever building the
        # row, for a fork listed in versions.json's code_window.unsupported.
        assert_fork_appendable(fork, "SyncCommitteeVerifier")
        row = forks_mod.m4_fork_row(fork, activation_epochs[fork], forks_mod.fork_version_bytes(fork))
        rows.append(row.as_tuple())
    return sorted(rows, key=lambda r: r[0])


def apply(algod_client, sender: str, sk: str, target, manifest, *,
          activation_epochs: dict[str, int] | None = None) -> int:
    """Idempotent (§7.3/G2-M10): re-run sends the missing subset only.
    Returns the app id."""
    activation_epochs = activation_epochs or forks_mod.KNOWN_ACTIVATION_EPOCHS
    m4_cfg = target.contracts.get("m4")
    app_id = manifest.app_id("m4")

    if app_id is None:
        compiled = compile_m4()
        gvr_hex = (m4_cfg.genesis_validators_root if m4_cfg else None) or "00" * 32
        gvr = bytes.fromhex(gvr_hex[2:] if gvr_hex.startswith("0x") else gvr_hex)
        method = Method.undictify(next(m for m in compiled["arc56"]["methods"] if m["name"] == "create"))
        # §17 item 6: computed from the real compiled size, never a shipped
        # constant (D3's finding -- a hand-picked `extra_pages` has already
        # been wrong once in this project's own history, for M6).
        extra_pages = min_extra_pages(len(compiled["approval"]), len(compiled["clear"]))
        app_id, funded = create_mod.predict_fund_and_create(
            algod_client, sender, sk, method=method, method_args=[target.governance, gvr],
            approval_bytes=compiled["approval"], clear_bytes=compiled["clear"],
            global_schema=transaction.StateSchema(13, 7), local_schema=transaction.StateSchema(0, 0),
            extra_pages=extra_pages, boxes=[(0, FORKS_BOX_NAME)],
        )
        manifest.set_app(
            "m4", app_id=app_id, approval_sha256=compiled["approval_sha256"],
            clear_sha256=compiled["clear_sha256"], schema_version=1, creator=sender,
            governance=target.governance, genesis_validators_root=gvr_hex, funded_at_create=funded,
        )

    forks_list = target.forks
    desired = desired_fork_rows(forks_list, activation_epochs)
    on_chain = _read_fork_rows(algod_client, app_id)

    n_common = min(len(on_chain), len(desired))
    for i in range(n_common):
        if on_chain[i] != desired[i]:
            raise ForkRowConflict(
                f"m4 fork row {i} on-chain {on_chain[i]} != desired {desired[i]} -- "
                "append-only table, cannot be corrected in place (§6.5, §11.4)"
            )

    for row in desired[len(on_chain):]:
        _append_m4_fork_row(algod_client, sender, sk, app_id, row)

    return app_id


def fund_for_install(algod_client, sender: str, sk: str, app_id: int, *, stage: str = "install") -> int:
    """§8.2's `deploy fund --app m4 --stage install|rollover` -- a separate,
    explicit, operator-invoked top-up run immediately before M9's
    `sync(install=True)`. Not part of `apply` (module docstring above,
    G8-M10/D-7). Returns the amount actually paid (0 if already funded)."""
    target_microalgo = FUND_STAGE_MICROALGO[stage]
    return create_mod.top_up(algod_client, sender, sk, app_id, target_microalgo)


def _append_m4_fork_row(algod_client, sender: str, sk: str, app_id: int, row: tuple) -> None:
    from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer

    compiled = compile_m4()
    method = Method.undictify(next(m for m in compiled["arc56"]["methods"] if m["name"] == "append_fork_row"))
    atc = AtomicTransactionComposer()
    signer = AccountTransactionSigner(sk)
    sp = algod_client.suggested_params()
    sp.flat_fee = True
    sp.fee = 1000
    activation_epoch, fork_version, finality_gindex, current_sc, next_sc = row
    atc.add_method_call(
        app_id=app_id, method=method, sender=sender, sp=sp, signer=signer,
        method_args=[activation_epoch, fork_version, finality_gindex, current_sc, next_sc],
        boxes=[(0, FORKS_BOX_NAME)],
    )
    atc.execute(algod_client, 4)
