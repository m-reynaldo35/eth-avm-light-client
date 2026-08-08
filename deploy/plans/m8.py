"""§5.3: `TrustedRootAnchor` deployment sequence -- verify the M4
counterparty by program hash, compile, predict+fund+create, top up, init
the ring, append the fork rows.
"""
from __future__ import annotations

import base64
from pathlib import Path

from algosdk import transaction
from algosdk.abi import Method
from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer

from deploy import create as create_mod
from deploy import forks as forks_mod
from deploy.compile import puya_compile, sha256_hex
from deploy.inspect import approval_sha256, decode_global_state, read_box
from deploy.mbr import box_mbr, min_extra_pages

REPO_ROOT = Path(__file__).resolve().parents[2]
ANCHOR_SRC = REPO_ROOT / "contracts" / "state_anchor" / "anchor_app.py"

FORKS_BOX_NAME = b"forks8"
FORK_ROW_BYTES = 40
RING_BOX_PREFIX = b"h:"


class CounterpartyMismatch(RuntimeError):
    """§1.3 mitigation 2 / §17 item 7: refuses to bind `m4_app_id` into a
    write-once field without first confirming its approval-program hash
    matches the pinned `SyncCommitteeVerifier` hash."""


class ForkRowConflict(RuntimeError):
    pass


def compile_m8() -> dict:
    compiled = puya_compile(ANCHOR_SRC)["TrustedRootAnchor"]
    arc56 = compiled["arc56"]
    approval = base64.b64decode(arc56["byteCode"]["approval"])
    clear = base64.b64decode(arc56["byteCode"]["clear"])
    return {"arc56": arc56, "approval": approval, "clear": clear,
            "approval_sha256": sha256_hex(approval), "clear_sha256": sha256_hex(clear)}


def verify_m4_counterparty(algod_client, m4_app_id: int, pinned_m4_sha256: str) -> None:
    real = approval_sha256(algod_client, m4_app_id)
    if real != pinned_m4_sha256:
        raise CounterpartyMismatch(
            f"m4_app_id {m4_app_id}'s approval program sha256 {real} != pinned SyncCommitteeVerifier "
            f"hash {pinned_m4_sha256} -- refusing to bind this id into m8's write-once m4_app_id (§5.3 step 2)"
        )


def _read_fork_rows(algod_client, app_id: int) -> list[tuple]:
    try:
        raw = read_box(algod_client, app_id, FORKS_BOX_NAME)
    except Exception:
        return []
    gs = decode_global_state(algod_client, app_id)
    fork_count = gs.get("fork_count", 0)
    rows = []
    for i in range(fork_count):
        chunk = raw[i * FORK_ROW_BYTES:(i + 1) * FORK_ROW_BYTES]
        vals = [int.from_bytes(chunk[j:j + 8], "big") for j in range(0, 40, 8)]
        rows.append(tuple(vals))
    return rows


def desired_fork_rows(forks: list[str], activation_epochs: dict[str, int]) -> list[tuple]:
    from deploy.versions_guard import assert_fork_appendable

    rows = []
    for fork in forks:
        # 012 §3.7/§17 item 5: client-side refusal, BEFORE ever building the
        # row, for a fork listed in versions.json's code_window.unsupported.
        assert_fork_appendable(fork, "TrustedRootAnchor")
        row = forks_mod.m8_fork_row(fork, activation_epochs[fork])
        rows.append(row.as_tuple())
    return sorted(rows, key=lambda r: r[0])


def apply(algod_client, sender: str, sk: str, target, manifest, *,
          activation_epochs: dict[str, int] | None = None) -> int:
    activation_epochs = activation_epochs or forks_mod.KNOWN_ACTIVATION_EPOCHS
    m8_cfg = target.contracts.get("m8")
    ring_n = (m8_cfg.ring_n if m8_cfg else 128)
    app_id = manifest.app_id("m8")

    m4_entry = manifest.apps.get("m4")
    if m4_entry is None:
        raise RuntimeError("m8 depends on m4 already existing in the manifest (§5.1's one hard edge)")
    m4_app_id = m4_entry["app_id"]
    pinned_m4_sha256 = m4_entry["approval_sha256"]
    verify_m4_counterparty(algod_client, m4_app_id, pinned_m4_sha256)

    if app_id is None:
        compiled = compile_m8()
        method = Method.undictify(next(m for m in compiled["arc56"]["methods"] if m["name"] == "create"))
        # §17 item 6: computed from the real compiled size, never a shipped
        # constant.
        extra_pages = min_extra_pages(len(compiled["approval"]), len(compiled["clear"]))
        app_id, funded = create_mod.predict_fund_and_create(
            algod_client, sender, sk, method=method,
            method_args=[target.governance, m4_app_id, ring_n],
            approval_bytes=compiled["approval"], clear_bytes=compiled["clear"],
            global_schema=transaction.StateSchema(9, 1), local_schema=transaction.StateSchema(0, 0),
            extra_pages=extra_pages, boxes=[(0, FORKS_BOX_NAME)],
        )
        manifest.set_app(
            "m8", app_id=app_id, approval_sha256=compiled["approval_sha256"],
            clear_sha256=compiled["clear_sha256"], schema_version=1, creator=sender,
            governance=target.governance, bound_to={"m4_app_id": m4_app_id}, ring_n=ring_n,
            funded_at_create=funded,
        )

    target_balance = 100_000 + box_mbr(len(FORKS_BOX_NAME), 40 * 8) + ring_n * box_mbr(10, 154)
    create_mod.top_up(algod_client, sender, sk, app_id, target_balance)

    gs = decode_global_state(algod_client, app_id)
    ring_cursor = gs.get("ring_cursor", 0)
    while ring_cursor < ring_n:
        k = min(8, ring_n - ring_cursor)
        _ring_init_chunk(algod_client, sender, sk, app_id, k)
        gs = decode_global_state(algod_client, app_id)
        new_cursor = gs.get("ring_cursor", 0)
        if new_cursor == ring_cursor:
            raise RuntimeError(f"ring_init_chunk({k}) did not advance ring_cursor past {ring_cursor}")
        ring_cursor = new_cursor

    desired = desired_fork_rows(target.forks, activation_epochs)
    on_chain = _read_fork_rows(algod_client, app_id)
    n_common = min(len(on_chain), len(desired))
    for i in range(n_common):
        if on_chain[i] != desired[i]:
            raise ForkRowConflict(
                f"m8 fork row {i} on-chain {on_chain[i]} != desired {desired[i]} -- "
                "append-only table, cannot be corrected in place (§6.5, §11.4)"
            )
    for row in desired[len(on_chain):]:
        _append_m8_fork_row(algod_client, sender, sk, app_id, row)

    return app_id


def _ring_boxes_for_chunk(ring_cursor: int, k: int, ring_n: int) -> list[tuple[int, bytes]]:
    # ring_init_chunk fills residues [ring_cursor, ring_cursor+k) directly
    # (box.py's `ring_init_chunk` mirrors the cursor 1:1 for the first
    # ring_n calls -- no residue wraparound occurs during initial fill).
    return [(0, RING_BOX_PREFIX + i.to_bytes(8, "big")) for i in range(ring_cursor, ring_cursor + k)]


def _ring_init_chunk(algod_client, sender: str, sk: str, app_id: int, k: int) -> None:
    compiled = compile_m8()
    method = Method.undictify(next(m for m in compiled["arc56"]["methods"] if m["name"] == "ring_init_chunk"))
    gs = decode_global_state(algod_client, app_id)
    ring_cursor = gs.get("ring_cursor", 0)
    ring_n = gs.get("ring_size", 0)
    atc = AtomicTransactionComposer()
    signer = AccountTransactionSigner(sk)
    sp = algod_client.suggested_params()
    sp.flat_fee = True
    sp.fee = 1000
    # `ring_init_chunk` (contracts/state_anchor/anchor_app.py) touches only
    # global state (`ring_cursor`/`ring_size`/`frozen`) and the k new ring
    # boxes -- it never reads `forks8`, so the box-reference array carries
    # only the k ring boxes (<= 8, exactly the measured per-txn cap at
    # k=8, same constant M4's install-open phase hits, §16 of the M4 doc).
    boxes = _ring_boxes_for_chunk(ring_cursor, k, ring_n)
    atc.add_method_call(
        app_id=app_id, method=method, sender=sender, sp=sp, signer=signer,
        method_args=[k], boxes=boxes,
    )
    atc.execute(algod_client, 4)


def _append_m8_fork_row(algod_client, sender: str, sk: str, app_id: int, row: tuple) -> None:
    compiled = compile_m8()
    method = Method.undictify(next(m for m in compiled["arc56"]["methods"] if m["name"] == "append_fork_row"))
    atc = AtomicTransactionComposer()
    signer = AccountTransactionSigner(sk)
    sp = algod_client.suggested_params()
    sp.flat_fee = True
    sp.fee = 1000
    atc.add_method_call(
        app_id=app_id, method=method, sender=sender, sp=sp, signer=signer,
        method_args=list(row), boxes=[(0, FORKS_BOX_NAME)],
    )
    atc.execute(algod_client, 4)
