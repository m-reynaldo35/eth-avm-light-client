"""Live smoke test for `service/x402_endpoint/eth_beacon_rpc.py`: fetches a
REAL, currently-live `finality_update` from a real beacon-node light-client
API (no static vendored fixture, no mock), decodes it into the exact
`submit_update` argument shape (contracts/sync_committee/verifier.py), and
asserts the decoded fields are sane -- non-zero, correctly sized, and
plausible against real wall-clock time.

Deliberately does NOT touch algod or any contract -- that is a separate,
later task (this module's own docstring / the task brief that produced it
are explicit about this). Skipped outright if no beacon-API endpoint in the
pool is reachable, matching this repo's existing live-tier skip convention
(`tests/sync_committee/conftest.py`'s `algod_available`).
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request

import pytest

from service.x402_endpoint import eth_beacon_rpc as beacon

# Genesis timestamp for Ethereum mainnet (2020-12-01T12:00:23Z), used only to
# sanity-check that a fetched slot's implied wall-clock time is plausible --
# NOT a consensus-critical constant anywhere in this module.
MAINNET_GENESIS_TIME = 1606824023
SECONDS_PER_SLOT = 12


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
        except (urllib.error.URLError, OSError, TimeoutError):
            continue
    return False


@pytest.fixture(scope="module")
def beacon_available() -> bool:
    return _beacon_reachable()


def test_live_finality_update_decodes_sanely(beacon_available):
    if not beacon_available:
        pytest.skip("no reachable beacon-API endpoint in the pool")

    resp = beacon.fetch_finality_update()
    assert resp["version"], "missing fork version"

    args = beacon.transform_finality_update(resp)

    # -- byte-length shape checks (the exact shapes submit_update expects) --
    assert len(args.attested_header) == 112
    assert len(args.finalized_header) == 112
    assert len(args.finality_branch) % 32 == 0 and len(args.finality_branch) > 0
    assert args.next_committee_root == bytes(32)  # finality_update never proves this
    assert args.next_committee_branch == b""
    assert len(args.sync_committee_bits) == 64  # mainnet Bitvector[512]
    assert len(args.signature) == 192  # AVM-uncompressed G2

    # -- sanity: slots are real, non-zero, and correctly ordered --
    attested_slot = int.from_bytes(args.attested_header[0:8], "little")
    finalized_slot = int.from_bytes(args.finalized_header[0:8], "little")
    assert attested_slot > 0
    assert finalized_slot > 0
    assert args.signature_slot > attested_slot  # §6.1 step 3, mirrored here as a live sanity check
    assert attested_slot >= finalized_slot  # §6.1 step 4

    # -- sanity: a real, non-default aggregate signature and bitfield --
    assert args.signature != bytes(192), "signature must not be the zero/infinity point"
    assert any(b != 0 for b in args.sync_committee_bits), "at least one participant must be set"
    popcount = sum(bin(b).count("1") for b in args.sync_committee_bits)
    assert popcount > 0

    # -- sanity: the attested slot's implied wall-clock time is close to
    #    "now" (within an hour) -- proves this is genuinely LIVE data, not
    #    a stale cached response or a replayed static fixture. --
    implied_time = MAINNET_GENESIS_TIME + attested_slot * SECONDS_PER_SLOT
    assert abs(time.time() - implied_time) < 3600, (
        f"attested slot {attested_slot}'s implied time {implied_time} is not "
        f"within an hour of wall-clock now ({time.time()}) -- stale data?"
    )

    # -- sanity: header fields are real 32-byte roots, not all-zero --
    parent_root = args.attested_header[16:48]
    state_root = args.attested_header[48:80]
    body_root = args.attested_header[80:112]
    assert parent_root != bytes(32)
    assert state_root != bytes(32)
    assert body_root != bytes(32)

    print(
        f"fork={resp['version']} signature_slot={args.signature_slot} "
        f"attested_slot={attested_slot} finalized_slot={finalized_slot} "
        f"popcount={popcount}/512 finality_branch_depth={len(args.finality_branch) // 32}"
    )


def test_live_optimistic_update_has_no_finality_fields(beacon_available):
    """Documents/pins the real, live-confirmed shape difference this module's
    docstring calls out: `optimistic_update` genuinely carries no
    finalized-header/finality-branch data, so it cannot alone produce a
    `submit_update`-ready argument set."""
    if not beacon_available:
        pytest.skip("no reachable beacon-API endpoint in the pool")

    resp = beacon.fetch_optimistic_update()
    assert set(resp["data"].keys()) == {"attested_header", "sync_aggregate", "signature_slot"}

    decoded = beacon.transform_optimistic_update(resp)
    assert len(decoded["attested_header"]) == 112
    assert len(decoded["signature"]) == 192
    assert decoded["signature_slot"] > 0


def test_live_bootstrap_round_trips_against_a_real_checkpoint(beacon_available):
    """Fetches a real finality_update, computes the finalized header's own
    `hash_tree_root` (reusing `tests/sync_committee/reference.py`'s proven
    implementation -- the same one T1/T2 pin against vendored vectors), then
    fetches a REAL bootstrap for that exact, independently-derived root --
    proving the header decode + hash_tree_root reuse is correct end to end
    against live data, not just against static fixtures."""
    if not beacon_available:
        pytest.skip("no reachable beacon-API endpoint in the pool")

    from tests.sync_committee import reference as ref

    resp = beacon.fetch_finality_update()
    args = beacon.transform_finality_update(resp)
    trusted_block_root = ref.hash_tree_root_beacon_block_header(args.finalized_header)

    boot_resp = beacon.fetch_bootstrap(trusted_block_root.hex())
    boot_args = beacon.transform_bootstrap(boot_resp)

    # The bootstrap's own header must hash back to the exact root we asked
    # for -- an independent oracle (the beacon node's own state) confirming
    # our header decode + hash_tree_root reuse is correct on live data.
    assert ref.hash_tree_root_beacon_block_header(boot_args.header) == trusted_block_root

    assert len(boot_args.pubkey_pairs) == 512
    for compressed, uncompressed in boot_args.pubkey_pairs[:4]:
        assert len(compressed) == 48
        assert len(uncompressed) == 96
        assert uncompressed != bytes(96), "a real committee member key must not be infinity"
    assert len(boot_args.aggregate_compressed) == 48
    assert len(boot_args.aggregate_uncompressed) == 96

    chunks = beacon.install_chunks(boot_args.pubkey_pairs, chunk_size=64)
    assert len(chunks) == 8  # 512 / 64, matches BOXES_PER_COMMITTEE
    assert chunks[0][0] == 0
    assert chunks[-1][0] == 448
    for _index, compressed_blob, uncompressed_blob in chunks:
        assert len(compressed_blob) == 64 * 48
        assert len(uncompressed_blob) == 64 * 96
