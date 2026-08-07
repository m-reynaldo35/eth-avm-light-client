"""`DeployTarget` -- network, governance, per-contract flags (design doc §6,
§8.2, §17 item 13). Loaded from `deploy/targets/*.json`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


class TargetConfigError(ValueError):
    """§9.3/§17 item 13: raised when a target file is missing something
    `apply`/`plan` MUST refuse to proceed without (e.g. no `governance`)."""


@dataclass
class NetworkConfig:
    algod_url: str
    algod_token: str
    genesis_id: str
    genesis_hash: str


@dataclass
class ContractTarget:
    deploy: bool = False
    genesis_validators_root: str | None = None  # M4 only, 0x-hex
    m4_app_id: int | None = None  # M8 only -- if unset, taken from the manifest
    ring_n: int = 128  # M8 only, 008 §7.8's recommendation
    t2_float: bool = False  # M7 only


@dataclass
class DeployTarget:
    network: NetworkConfig
    governance: str  # REQUIRED (§17 item 13) -- TargetConfigError if missing
    contracts: dict[str, ContractTarget] = field(default_factory=dict)
    forks: list[str] = field(default_factory=lambda: ["deneb", "electra", "fulu"])
    path: Path | None = None

    @classmethod
    def from_file(cls, path: Path) -> "DeployTarget":
        data = json.loads(Path(path).read_text())
        net = data.get("network")
        if not net:
            raise TargetConfigError(f"{path}: missing 'network'")
        for required in ("algod_url", "algod_token", "genesis_id", "genesis_hash"):
            if required not in net:
                raise TargetConfigError(f"{path}: network missing {required!r}")
        governance = data.get("governance")
        if not governance:
            # §17 item 13 / §9.3: MUST require governance explicitly.
            raise TargetConfigError(
                f"{path}: 'governance' is required and must be an explicit address -- "
                "deploy tooling never defaults it to the deployer's own key (§9.3)"
            )
        contracts = {
            name: ContractTarget(**cfg) for name, cfg in (data.get("contracts") or {}).items()
        }
        return cls(
            network=NetworkConfig(**net),
            governance=governance,
            contracts=contracts,
            forks=data.get("forks", ["deneb", "electra", "fulu"]),
            path=Path(path),
        )

    def warn_if_governance_equals_signer(self, signer_address: str) -> str | None:
        """§9.3/§17 item 13: MUST warn (never silently accept) when
        `governance == signer`. Returns the warning string, or None."""
        if self.governance == signer_address:
            return (
                f"WARNING: target governance ({self.governance}) equals the configured "
                "signer address. A compromised signer key can freeze/revoke/renounce "
                "governance outright (§9.3). This is accepted only with --yes."
            )
        return None
