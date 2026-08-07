"""The deployment manifest (design doc §7.2): identity ONLY, keyed by
genesis hash. No progress is recorded -- §7.3's converge-by-diff engine
re-derives progress from on-chain state every time (009 §9.1's "the on-chain
state machine IS the checkpoint" principle, one level up).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

MANIFEST_DIR = Path(__file__).resolve().parent / "manifests"
MANIFEST_VERSION = 1


@dataclass
class Manifest:
    genesis_id: str
    genesis_hash: str
    apps: dict[str, dict] = field(default_factory=dict)  # "m4"/"m6"/"m7"/"m8"/"donor_issuer"/"donor_callee"

    @classmethod
    def path_for(cls, genesis_id: str) -> Path:
        return MANIFEST_DIR / f"{genesis_id}.json"

    @classmethod
    def load(cls, genesis_id: str) -> "Manifest | None":
        path = cls.path_for(genesis_id)
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        return cls(genesis_id=data["network"]["genesis_id"], genesis_hash=data["network"]["genesis_hash"],
                    apps=data.get("apps", {}))

    def save(self) -> Path:
        MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
        path = self.path_for(self.genesis_id)
        data = {
            "manifest_version": MANIFEST_VERSION,
            "network": {"genesis_id": self.genesis_id, "genesis_hash": self.genesis_hash},
            "apps": self.apps,
        }
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        return path

    def set_app(self, key: str, **fields) -> None:
        self.apps[key] = {**self.apps.get(key, {}), **fields}

    def app_id(self, key: str) -> int | None:
        entry = self.apps.get(key)
        return entry.get("app_id") if entry else None


def recover_by_approval_hash(algod_client, creator: str, pinned_sha256: dict[str, str]) -> dict[str, list[int]]:
    """§7.4: rebuild a lost manifest with NO local state, using the pinned
    approval-program hashes. `pinned_sha256` maps contract name ->
    hex sha256 of its approval program. Returns
    `{contract_name: [candidate_app_id, ...]}` -- ambiguity (more than one
    match) is resolved by the CALLER (§7.4: "the right M8 is the one whose
    `m4_app` points at the right M4 and whose `gov` is the configured
    address" -- `deploy.inspect`'s job, not this function's)."""
    import base64
    import hashlib

    info = algod_client.account_info(creator)
    candidates: dict[str, list[int]] = {name: [] for name in pinned_sha256}
    for app in info.get("created-apps", []):
        approval_b64 = app["params"]["approval-program"]
        approval = base64.b64decode(approval_b64)
        digest = hashlib.sha256(approval).hexdigest()
        for name, pinned in pinned_sha256.items():
            if digest == pinned:
                candidates[name].append(app["id"])
    return candidates
