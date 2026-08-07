"""Decode a deployed app's real global state and real boxes through the
schema (design doc §8.3). What makes a deployment auditable by someone who
did not perform it (§1.3 mitigation 3) -- every read here is public
(`account_info`/`application_info`/`application_boxes`), no signer needed
(§17 item 16).
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field


def approval_sha256(algod_client, app_id: int) -> str:
    info = algod_client.application_info(app_id)
    approval = base64.b64decode(info["params"]["approval-program"])
    return hashlib.sha256(approval).hexdigest()


def decode_global_state(algod_client, app_id: int) -> dict:
    """Puya stores each global-state field under the literal Python
    attribute name as the on-chain key (confirmed against the real ARC-56
    artifacts' `state.keys.global.<name>.key` base64 fields, which all
    decode to plain ASCII attribute names -- e.g. `Z292` -> `gov`)."""
    info = algod_client.application_info(app_id)
    gs = info["params"].get("global-state", [])
    decoded = {}
    for entry in gs:
        key = base64.b64decode(entry["key"]).decode("utf-8", errors="replace")
        v = entry["value"]
        if v.get("type") == 1:  # bytes
            decoded[key] = base64.b64decode(v.get("bytes", ""))
        else:
            decoded[key] = v.get("uint", 0)
    return decoded


def account_balance(algod_client, app_id: int) -> dict:
    from algosdk import logic

    addr = logic.get_application_address(app_id)
    info = algod_client.account_info(addr)
    return {"address": addr, "amount": info["amount"], "min-balance": info["min-balance"]}


def list_boxes(algod_client, app_id: int) -> list[bytes]:
    resp = algod_client.application_boxes(app_id)
    return [base64.b64decode(b["name"]) for b in resp.get("boxes", [])]


def read_box(algod_client, app_id: int, name: bytes) -> bytes:
    resp = algod_client.application_box_by_name(app_id, name)
    return base64.b64decode(resp["value"])


def decode_ring_record(raw: bytes, schema: dict) -> dict:
    ring = next(b for b in schema["boxes"] if b["family"] == "ring")
    out = {}
    for f in ring["record"]["fields"]:
        chunk = raw[f["offset"]: f["offset"] + f["length"]]
        if f.get("encoding") == "uint64-be":
            out[f["name"]] = int.from_bytes(chunk, "big")
        elif f["name"] == "flags":
            out[f["name"]] = chunk[0] if chunk else 0
        elif f["name"] == "version":
            out[f["name"]] = chunk[0] if chunk else 0
        else:
            out[f["name"]] = chunk
    return out


@dataclass
class VerifyResult:
    ok: bool
    issues: list[str] = field(default_factory=list)

    def add(self, msg: str) -> None:
        self.ok = False
        self.issues.append(msg)


def verify_app(algod_client, app_id: int, *, pinned_approval_sha256: str,
                expected_governance: str | None = None, expected_m4_app_id: int | None = None,
                expect_t2_float: bool = False) -> VerifyResult:
    """§1.3 mitigation 3 / §9.5: the manifest is not a trust anchor -- this
    re-derives everything it can from chain state and the pinned hash, so a
    tampered manifest produces a verify FAILURE, not a silent redirection.
    """
    result = VerifyResult(ok=True)
    real_hash = approval_sha256(algod_client, app_id)
    if real_hash != pinned_approval_sha256:
        result.add(f"approval program sha256 {real_hash} != pinned {pinned_approval_sha256}")

    gs = decode_global_state(algod_client, app_id)
    if expected_governance is not None and "gov" in gs:
        from algosdk import encoding

        gov_addr = encoding.encode_address(gs["gov"]) if isinstance(gs["gov"], (bytes, bytearray)) else gs["gov"]
        if gov_addr != expected_governance:
            result.add(f"gov {gov_addr} != expected {expected_governance}")

    if expected_m4_app_id is not None and "m4_app" in gs:
        if gs["m4_app"] != expected_m4_app_id:
            result.add(f"m4_app {gs['m4_app']} != expected {expected_m4_app_id}")

    # G8-M10: no stranded funds -- amount - min-balance must be zero (never
    # POSITIVE, i.e. no idle excess) for every app but the declared T2
    # float. A NEGATIVE value (e.g. Mpt6ComposerApp's own base min-balance
    # requirement with a zero balance, since it has never been funded at
    # all -- §5.1: "no funding" for M6) is not "stranded funds", just
    # "not yet funded"; §10.4 is about excess sitting idle, not shortfall.
    bal = account_balance(algod_client, app_id)
    slack = bal["amount"] - bal["min-balance"]
    if slack > 0 and not expect_t2_float:
        result.add(f"app account has {slack} microalgo above its own min-balance (unexpected slack, §10.4/G8-M10)")

    return result


def refuse_unrestricted_on_mainnet(schema: dict, genesis_hash: str, mainnet_genesis_hashes: set[str]) -> None:
    """§6.4 item 3 / §17 item 14: `apply` MUST refuse to deploy a contract
    whose schema declares `"on_completion_gate": "unrestricted"` to a
    mainnet genesis hash."""
    if genesis_hash in mainnet_genesis_hashes and schema["program"]["on_completion_gate"] == "unrestricted":
        raise PermissionError(
            f"{schema['contract']} has on_completion_gate == 'unrestricted' (§9.1: any account can "
            "UpdateApplication/DeleteApplication it) -- refusing to deploy it to a mainnet genesis hash. "
            "See docs/design/010-deployment-tooling.md §6.4 item 3."
        )
