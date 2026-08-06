"""`RelayerConfig` (design doc §8.2) -- env + file loading. `signer=None`
means dry-run only (§18 item 16): every verb must work up to and including
the second `simulate` with no signer configured at all."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_ETH_RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://eth.merkle.io",
    "https://1rpc.io/eth",
    "https://eth-mainnet.public.blastapi.io",
]
DEFAULT_BEACON_APIS = [
    "http://unstable.mainnet.beacon-api.nimbus.team",
    "http://testing.mainnet.beacon-api.nimbus.team",
    "https://lodestar-mainnet.chainsafe.io",
    "https://www.lightclientdata.org",
]


@dataclass
class RelayerConfig:
    algod_url: str = "http://localhost:4051"
    algod_token: str = "a" * 64
    m4_app_id: int | None = None
    m6_app_id: int | None = None
    m7_app_id: int | None = None
    m8_app_id: int | None = None
    donor_issuer_id: int | None = None
    donor_callee_id: int | None = None
    eth_rpcs: list[str] = field(default_factory=lambda: list(DEFAULT_ETH_RPCS))
    beacon_apis: list[str] = field(default_factory=lambda: list(DEFAULT_BEACON_APIS))
    signer_mnemonic: str | None = None  # None => dry-run only (§18 item 16)
    cache_dir: Path | None = None
    max_group_txns: int = 16

    @property
    def has_signer(self) -> bool:
        return self.signer_mnemonic is not None

    @classmethod
    def from_env(cls) -> "RelayerConfig":
        def _int_or_none(name: str) -> int | None:
            v = os.environ.get(name)
            return int(v) if v else None

        return cls(
            algod_url=os.environ.get("ALGOD_URL", "http://localhost:4051"),
            algod_token=os.environ.get("ALGOD_TOKEN", "a" * 64),
            m4_app_id=_int_or_none("M4_APP_ID"),
            m6_app_id=_int_or_none("M6_APP_ID"),
            m7_app_id=_int_or_none("M7_APP_ID"),
            m8_app_id=_int_or_none("M8_APP_ID"),
            donor_issuer_id=_int_or_none("DONOR_ISSUER_ID"),
            donor_callee_id=_int_or_none("DONOR_CALLEE_ID"),
            eth_rpcs=os.environ.get("ETH_RPCS", "").split(",") if os.environ.get("ETH_RPCS") else list(DEFAULT_ETH_RPCS),
            beacon_apis=os.environ.get("BEACON_APIS", "").split(",") if os.environ.get("BEACON_APIS") else list(DEFAULT_BEACON_APIS),
            signer_mnemonic=os.environ.get("RELAYER_MNEMONIC"),
            cache_dir=Path(os.environ["RELAYER_CACHE_DIR"]) if os.environ.get("RELAYER_CACHE_DIR") else None,
        )

    @classmethod
    def from_file(cls, path: Path) -> "RelayerConfig":
        with open(path) as f:
            data = json.load(f)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
