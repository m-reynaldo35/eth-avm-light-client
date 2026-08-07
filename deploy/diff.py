"""§7.3: converge-by-diff, the top-level `plan`/`apply`/`verify` library
functions design doc §8.1 calls "the product" (`deploy.apply(target, algod,
signer) -> Manifest`; the CLI is a thin shell over these). §17 item 8/9:
every call here checks the genesis hash first and computes its plan as a
diff against on-chain state -- no local progress file beyond the identity
manifest.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field

from deploy import inspect as inspect_mod
from deploy.manifest import Manifest
from deploy.plans import donors, m4, m6, m7, m8

# Real Algorand MainNet genesis hash (§6.4 item 3 / §17 item 14's mainnet
# refusal check). Cited value, not derived -- this is a network identity
# constant, the same kind of real, external fact `genesis_id`/`genesis_hash`
# already are in every target file (§6.1).
MAINNET_GENESIS_HASHES = {"wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="}


class GenesisMismatch(RuntimeError):
    """§6.1/§17 item 8, G7-M10: `apply`/`verify` refuse to act if the
    connected algod's genesis hash differs from the target's."""


class GovernanceSignerWarning(RuntimeError):
    """§9.3/§17 item 13: raised when `governance == signer` and the caller
    has not explicitly acknowledged it (`yes=True`)."""


def genesis_hash_b64(algod_client) -> str:
    sp = algod_client.suggested_params()
    gh = sp.gh
    if isinstance(gh, str):
        return gh
    return base64.b64encode(gh).decode()


def assert_genesis_matches(algod_client, target) -> None:
    real = genesis_hash_b64(algod_client)
    if real != target.network.genesis_hash:
        raise GenesisMismatch(
            f"connected algod genesis hash {real} != target {target.path}'s genesis hash "
            f"{target.network.genesis_hash} -- refusing to act (§6.1, G7-M10)"
        )


@dataclass
class PlanEntry:
    contract: str
    status: str  # "already deployed" | "would create" | "no signer -- predicted only"
    app_id: int | None = None
    predicted_app_id: int | None = None
    required_microalgo: int = 0
    warnings: list[str] = field(default_factory=list)


def plan(target, algod_client) -> list[PlanEntry]:
    """§8.2: no signer needed -- every number here comes from a real
    `simulate`/manifest/chain read (§17 item 16)."""
    assert_genesis_matches(algod_client, target)
    manifest = Manifest.load(target.network.genesis_id) or Manifest(target.network.genesis_id, target.network.genesis_hash)
    entries = []
    for name, cfg in target.contracts.items():
        if not cfg.deploy:
            continue
        app_id = manifest.app_id(name)
        if app_id is not None:
            entries.append(PlanEntry(contract=name, status="already deployed", app_id=app_id))
            continue
        entries.append(PlanEntry(contract=name, status="would create"))
    return entries


def apply(target, algod_client, sender: str, sk: str, *, yes: bool = False,
          activation_epochs: dict[str, int] | None = None) -> Manifest:
    """§17 items 8/9/13/14: genesis check, diff-against-chain (delegated to
    each `deploy.plans.*` module, which is itself idempotent), governance
    warning, and mainnet-unrestricted refusal, all before any state-changing
    call for the contract in question."""
    assert_genesis_matches(algod_client, target)

    gov_warning = target.warn_if_governance_equals_signer(sender)
    if gov_warning and not yes:
        raise GovernanceSignerWarning(gov_warning)

    manifest = Manifest.load(target.network.genesis_id) or Manifest(target.network.genesis_id, target.network.genesis_hash)

    donors.ensure_donor_pair(algod_client, sender, sk, manifest)

    m4_cfg = target.contracts.get("m4")
    if m4_cfg and m4_cfg.deploy:
        m4.apply(algod_client, sender, sk, target, manifest, activation_epochs=activation_epochs)
        manifest.save()

    m8_cfg = target.contracts.get("m8")
    if m8_cfg and m8_cfg.deploy:
        m8.apply(algod_client, sender, sk, target, manifest, activation_epochs=activation_epochs)
        manifest.save()

    m7_cfg = target.contracts.get("m7")
    if m7_cfg and m7_cfg.deploy:
        from deploy.schema.generate import generate_m7

        inspect_mod.refuse_unrestricted_on_mainnet(generate_m7(), target.network.genesis_hash, MAINNET_GENESIS_HASHES)
        m7.apply(algod_client, sender, sk, target, manifest)
        manifest.save()

    m6_cfg = target.contracts.get("m6")
    if m6_cfg and m6_cfg.deploy:
        from deploy.schema.generate import generate_m6

        inspect_mod.refuse_unrestricted_on_mainnet(generate_m6(), target.network.genesis_hash, MAINNET_GENESIS_HASHES)
        m6.apply(algod_client, sender, sk, target, manifest)
        manifest.save()

    return manifest


def verify(target, algod_client) -> dict[str, inspect_mod.VerifyResult]:
    """§8.2/§17 item 16: no signer needed. Re-derives everything from chain
    state and the manifest's pinned hashes (§9.5: the manifest itself is
    untrusted input here)."""
    assert_genesis_matches(algod_client, target)
    manifest = Manifest.load(target.network.genesis_id)
    if manifest is None:
        raise FileNotFoundError(f"no manifest for genesis_id={target.network.genesis_id!r} -- nothing to verify")

    results = {}
    for name in ("m4", "m6", "m7", "m8"):
        entry = manifest.apps.get(name)
        if entry is None:
            continue
        expected_m4 = manifest.apps.get("m4", {}).get("app_id") if name == "m8" else None
        results[name] = inspect_mod.verify_app(
            algod_client, entry["app_id"],
            pinned_approval_sha256=entry["approval_sha256"],
            expected_governance=entry.get("governance"),
            expected_m4_app_id=expected_m4,
            expect_t2_float=bool(entry.get("t2_float_microalgo")),
        )
    return results
