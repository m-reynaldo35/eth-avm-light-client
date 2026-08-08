"""`deploy resolve` (design doc 012 §3.5): the verb that ties the three
discovery layers together -- the chain (table window, `inspect --forks`),
the pinned `code_id` (code window, `versions.json`), and the manifest (which
app id is ours, `deploy/manifests/*.json`).

Read-only, needs no signer, and refuses rather than guesses. Four verdicts:

  * `USABLE`            -- deployed, and its live approval hash matches the pin.
  * `NOT_DEPLOYED`       -- not present in this network's manifest.
  * `FORK_UNSUPPORTED`   -- the requested fork is outside this contract's
                            `code_window` (a property of the BYTECODE,
                            checked even for an undeployed contract).
  * `CODE_MISMATCH`      -- deployed, but the live approval hash is not the
                            pinned one (010 §9.1's "reprogrammed out from
                            under us" failure mode). MUST exit non-zero
                            (012 §10 adversarial note 5) -- never a warning.
"""
from __future__ import annotations

VERDICT_USABLE = "USABLE"
VERDICT_NOT_DEPLOYED = "NOT_DEPLOYED"
VERDICT_FORK_UNSUPPORTED = "FORK_UNSUPPORTED"
VERDICT_CODE_MISMATCH = "CODE_MISMATCH"

# deploy-target short name -> versions.json contract name.
VERSIONS_KEY_FOR_APP = {
    "m4": "SyncCommitteeVerifier",
    "m8": "TrustedRootAnchor",
    "m7": "Mpt7ReceiptApp",
    "m6": "Mpt6ComposerApp",
}
RESOLVABLE_APPS = ("m4", "m8", "m7", "m6")


def resolve_one(algod_client, *, app_id: int | None, pinned_code_id: str | None,
                 fork_axis: str, code_window: dict | None, fork: str,
                 deploy_flag: bool | None = None) -> dict:
    """One contract's verdict. No signer -- every read here is public
    (`application_info`)."""
    # The code window is a property of the BYTECODE (versions.json), not the
    # deployment -- checked first, even for a contract that is not deployed
    # anywhere on this network (012 §9 edge case 8/9).
    if fork_axis == "table" and code_window and fork.lower() in {f.lower() for f in code_window.get("unsupported", [])}:
        return {"verdict": VERDICT_FORK_UNSUPPORTED, "fork_axis": fork_axis, "detail": code_window.get("reason")}

    if app_id is None:
        detail = "not present in this network's manifest"
        if deploy_flag is False:
            detail += " (target file declares deploy=false)"
        return {"verdict": VERDICT_NOT_DEPLOYED, "fork_axis": fork_axis, "detail": detail}

    from deploy.inspect import approval_sha256

    real_hash = approval_sha256(algod_client, app_id)
    matches = pinned_code_id is not None and real_hash == pinned_code_id
    out = {
        "app_id": app_id,
        "code_id": pinned_code_id,
        "code_id_matches_chain": matches,
        "fork_axis": fork_axis,
    }
    if matches:
        out["verdict"] = VERDICT_USABLE
    else:
        out["verdict"] = VERDICT_CODE_MISMATCH
        out["detail"] = f"live approval sha256 {real_hash} != pinned {pinned_code_id!r}"
    return out


def resolve(target, manifest, versions: dict, fork: str, algod_client) -> dict:
    """`target` is a `deploy.config.DeployTarget`; `manifest` is a
    `deploy.manifest.Manifest` or `None` (no manifest yet -- every contract
    resolves `NOT_DEPLOYED` unless its code window already excludes the
    fork); `versions` is a parsed `deploy/versions.json`."""
    apps = {}
    for app_key in RESOLVABLE_APPS:
        vkey = VERSIONS_KEY_FOR_APP[app_key]
        centry = versions.get("contracts", {}).get(vkey) or {}
        code_window = centry.get("code_window")
        fork_axis = centry.get("fork_axis", "none")
        pinned_code_id = centry.get("code_id")

        manifest_entry = manifest.apps.get(app_key) if manifest is not None else None
        app_id = manifest_entry["app_id"] if manifest_entry else None
        cfg = target.contracts.get(app_key)
        deploy_flag = cfg.deploy if cfg else None

        apps[app_key] = resolve_one(
            algod_client, app_id=app_id, pinned_code_id=pinned_code_id,
            fork_axis=fork_axis, code_window=code_window, fork=fork, deploy_flag=deploy_flag,
        )

    donor_issuer = (manifest.apps.get("donor_issuer") or {}).get("app_id") if manifest is not None else None
    donor_callee = (manifest.apps.get("donor_callee") or {}).get("app_id") if manifest is not None else None

    return {
        "network": target.network.genesis_id,
        "fork": fork,
        "apps": apps,
        "donors": {"issuer": donor_issuer, "callee": donor_callee},
    }
