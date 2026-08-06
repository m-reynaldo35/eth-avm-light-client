"""Real Ethereum beacon-chain light-client REST API access (design doc
§5.3). Promoted from `service/x402_endpoint/eth_beacon_rpc.py`, split
three ways per §4.3's dependency rule: this module keeps only the
`fetch_*` HTTP calls (fetchers only -- no ABI-argument transforms, no BLS
decompression, no `algosdk`). Argument-shape transforms live in
`relayer.drivers.m4_sync_committee`; byte-decoding helpers live in
`relayer.codec.*`.

JSON vs SSZ: this module requests plain JSON (the default `Accept`), not
`application/octet-stream` SSZ -- every field M4's contract needs is
already the raw hex of a fixed-size SSZ chunk/vector, decoding it is a
`bytes.fromhex` + concatenation, exactly as cheap as parsing SSZ would be,
with no offset-table/variable-length bookkeeping (see
`relayer.codec.header` for the one real exception, Capella+'s nested
`{"beacon":...}` shape, which is still simpler to pick apart by key than to
generically SSZ-decode).

Real gotchas recorded here because a client cannot recover from assuming
otherwise (module history, confirmed live 2026-08-06, fork "fulu"):
  * Merkle branch DEPTHS are fork-dependent, not preset-dependent -- see
    `relayer.codec.header.decode_branch`'s docstring.
  * `optimistic_update` carries NO `finalized_header`/`finality_branch` at
    all -- it cannot be turned into `submit_update`-ready args the way
    `finality_update` can. `relayer.drivers.m4_sync_committee.
    transform_optimistic_update` returns decoded fields only, never an
    ABI-args tuple, for exactly this reason.
"""
from __future__ import annotations

from relayer.sources.pool import EndpointPool

# ---------------------------------------------------------------------------
# Endpoint pool (§5.1): community-maintained light-client endpoint list
# (https://s1na.github.io/light-sync-endpoints/, mainnet section). Confirmed
# live 2026-08-06: Nimbus's two endpoints answered every request used to
# build/verify M4's and M8's live tests. `lodestar-mainnet.chainsafe.io`
# 503'd at least once during that session -- kept in the pool ("a 503 today
# is not a 503 tomorrow") but never relied on alone. `lightclientdata.org`
# (Helios) untested here; included per the design doc's own endpoint list.
# ---------------------------------------------------------------------------
BEACON_APIS = [
    "http://unstable.mainnet.beacon-api.nimbus.team",
    "http://testing.mainnet.beacon-api.nimbus.team",
    "https://lodestar-mainnet.chainsafe.io",
    "https://www.lightclientdata.org",
]
HEADERS = {"accept": "application/json", "User-Agent": "curl/8.0"}

_default_pool: EndpointPool | None = None


def default_pool() -> EndpointPool:
    global _default_pool
    if _default_pool is None:
        _default_pool = EndpointPool(BEACON_APIS, headers=HEADERS)
    return _default_pool


def _get_json(path: str, tries: int = 4, timeout: int = 20, pool: EndpointPool | None = None) -> dict | list:
    """Kept as a named function (not inlined into each fetcher) because
    `relayer.drivers.m8_anchor`'s HISTORICAL-mode fixture builder and
    several tests reach for it directly -- same retry/fallback shape as
    `relayer.sources.eth_rpc`'s JSON-RPC pool, walking the whole pool once
    per attempt, real errors accumulated for `PoolExhausted` rather than
    swallowed."""
    p = pool or default_pool()
    if tries != p.tries or timeout != p.timeout:
        p = EndpointPool(p.urls, headers=p.headers, tries=tries, timeout=timeout)
    return p.get_json(lambda base: base.rstrip("/") + path, path_for_errors=path)


def fetch_bootstrap(block_root: str, pool: EndpointPool | None = None) -> dict:
    """`GET /eth/v1/beacon/light_client/bootstrap/{block_root}` -- the
    initial trusted sync-committee snapshot for a checkpoint root.
    `block_root` may be given with or without the `0x` prefix. Per §5.4/
    §6.1: this endpoint 404s ("LC bootstrap unavailable") for an arbitrary
    root outside the small retained checkpoint set -- callers must not
    treat a 404 here as "try a different root", only as "this root isn't
    bootstrappable right now"."""
    if not block_root.startswith("0x"):
        block_root = "0x" + block_root
    return _get_json(f"/eth/v1/beacon/light_client/bootstrap/{block_root}", pool=pool)


def fetch_updates(start_period: int, count: int, pool: EndpointPool | None = None) -> list[dict]:
    """`GET /eth/v1/beacon/light_client/updates?start_period=&count=` --
    one `LightClientUpdate` per sync-committee period."""
    return _get_json(
        f"/eth/v1/beacon/light_client/updates?start_period={start_period}&count={count}", pool=pool
    )


def fetch_finality_update(pool: EndpointPool | None = None) -> dict:
    """`GET /eth/v1/beacon/light_client/finality_update` -- the latest
    finalized-header update; what M8 anchors a finalized beacon header +
    execution payload from."""
    return _get_json("/eth/v1/beacon/light_client/finality_update", pool=pool)


def fetch_optimistic_update(pool: EndpointPool | None = None) -> dict:
    """`GET /eth/v1/beacon/light_client/optimistic_update` -- no
    `finalized_header` at all (module docstring)."""
    return _get_json("/eth/v1/beacon/light_client/optimistic_update", pool=pool)


def fetch_spec(pool: EndpointPool | None = None) -> dict:
    """`GET /eth/v1/config/spec` -- fork activation epochs/versions, used
    by M9 to cross-check hardcoded fork constants at run time rather than
    trust memory (§5.3's derive-don't-copy discipline)."""
    return _get_json("/eth/v1/config/spec", pool=pool)


def fetch_genesis(pool: EndpointPool | None = None) -> dict:
    """`GET /eth/v1/beacon/genesis` -- `genesis_time`/`genesis_validators_root`."""
    return _get_json("/eth/v1/beacon/genesis", pool=pool)


def fetch_block(slot: int | str, pool: EndpointPool | None = None) -> dict:
    """`GET /eth/v2/beacon/blocks/{slot}` -- the full `BeaconBlockBody`,
    no precomputed `execution_branch` for an arbitrary slot (§5.4). What
    HISTORICAL mode's fixture builder (`relayer.ssz.block_body`) needs when
    no light-client response is available for the target slot."""
    return _get_json(f"/eth/v2/beacon/blocks/{slot}", pool=pool)


def fetch_debug_state(slot: int | str, pool: EndpointPool | None = None) -> dict:
    """`GET /eth/v2/debug/beacon/states/{slot}` -- the full `BeaconState`
    (§5.4: ~956 MB for a current slot, 404s near the ~15-month-old
    Deneb->Electra boundary). Callers should route through
    `relayer.sources.cache` rather than call this directly on a hot path."""
    return _get_json(f"/eth/v2/debug/beacon/states/{slot}", pool=pool, timeout=120)
