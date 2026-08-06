"""Real Ethereum Beacon Chain light-client API access + M4 argument encoding.

Co-located with `eth_rpc.py` (same kind of client-side relayer code, same
retried-endpoint-pool pattern) even though this talks to the *consensus*
layer (a beacon node's REST API) rather than the execution layer (an
`eth_*` JSON-RPC endpoint) -- both exist purely to turn real, live chain
data into the exact byte shapes `service/x402_endpoint`'s relayers (and,
here, M4's `SyncCommitteeVerifier`) need, and neither touches algod.

Fetches from the Ethereum beacon-APIs light-client endpoints (spec:
https://github.com/ethereum/beacon-APIs, "light client" section):

    GET /eth/v1/beacon/light_client/bootstrap/{block_root}
    GET /eth/v1/beacon/light_client/updates?start_period=&count=
    GET /eth/v1/beacon/light_client/finality_update
    GET /eth/v1/beacon/light_client/optimistic_update

JSON vs SSZ: this module requests plain JSON (the default `Accept`), not
`application/octet-stream` SSZ. Every JSON field M4's contract needs is
already the raw hex of a fixed-size SSZ chunk or vector (headers, branch
nodes, `sync_committee_bits`, compressed BLS points) -- decoding it is a
`bytes.fromhex` and a concatenation, exactly as cheap as parsing SSZ would
be, with no offset-table/variable-length bookkeeping to get wrong (Capella+
`LightClientHeader.execution` IS variable-size via `extra_data`, but this
module never touches `execution` at all -- that's M8's field, per the
`_decode_header` docstring below). SSZ would only pay off if a whole
`LightClientUpdate` needed decoding uniformly; picking fields out of a JSON
dict by name is simpler and less error-prone here, and the existing static
test-vector loader (`tests/sync_committee/vectors.py`) already had to
hand-roll fixed-offset SSZ slicing for the *minimal* preset only -- doing
the same generically for real mainnet variable-size Capella+ headers would
be strictly more parsing code for zero benefit.

Real gotchas hit building this, confirmed against live mainnet data
(2026-08-06, fork "fulu"), that the static Altair-minimal-preset vendored
test vectors (`tests/fixtures/sync_committee/consensus-spec-tests/`) never
exercise:

  * Since Capella, `attested_header`/`finalized_header`/bootstrap's `header`
    are NOT the flat `BeaconBlockHeader` the Altair-only vendored vectors
    use -- they are `{"beacon": {...}, "execution": {...},
    "execution_branch": [...]}`. Only `"beacon"` is M4's concern (see
    `_decode_header`).
  * Merkle branch DEPTHS are one level deeper on live "fulu" data than the
    Altair-preset vectors' hardcoded assumption: `finality_branch` has 7
    entries live (not 6), and `next_sync_committee_branch` has 6 (not 5) --
    `current_sync_committee_branch` similarly has 6, not 5. This is the
    real, on-chain consequence of `consensus-specs`' Electra-era
    `BeaconState` container growth reshuffling generalized indices one
    level deeper (`tests/sync_committee/vectors.py`'s
    `FINALIZED_ROOT_DEPTH = 6` comment "preset-independent" is true across
    *presets* but not across *forks* -- a distinction the Altair-only
    vectors can't surface). This module does not hardcode any branch depth
    -- it just concatenates whatever nodes the response actually contains,
    which is the only client-side-correct behaviour (the deployed
    contract's `forks` box is what must carry the right fork-specific
    gindex/depth via `append_fork_row`, a separate governance action, not
    this module's job).
  * `optimistic_update` carries NO `finalized_header`/`finality_branch` at
    all (confirmed live: its `data` keys are exactly `attested_header`,
    `sync_aggregate`, `signature_slot`) -- it cannot be turned into a
    `submit_update`-ready argument tuple the way `finality_update` can
    (`submit_update` always merkle-checks a finality leaf, even the "no
    finality" zero-leaf case, against a real branch this response never
    provides). `transform_optimistic_update` below returns only the
    decoded fields for informational/fast-path use, not ABI args.
"""

from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass, field

from py_ecc.bls.point_compression import decompress_G1, decompress_G2

# Reused verbatim, not re-derived (per this module's design brief): pure,
# non-pytest-dependent helpers already proven against real consensus-spec
# vectors (T1-T3, T5, `tests/sync_committee/test_signing_root.py` /
# `test_bitfield.py`) and against real py_ecc-generated signatures (M1's
# T11, `tests/bls/test_pairing.py`).
from tests.bls.test_codec import _g1_uncompressed, _g2_uncompressed
from tests.sync_committee import reference as ref

# ---------------------------------------------------------------------------
# Endpoint pool (community-maintained list for light-client use:
# https://s1na.github.io/light-sync-endpoints/, mainnet section).
# Confirmed live 2026-08-06: Nimbus's two endpoints answered every request
# used to build/verify this module. `lodestar-mainnet.chainsafe.io` 503'd
# at least once during that session -- kept in the pool (a 503 today is not
# a 503 tomorrow) but never relied on alone. `lightclientdata.org` (Helios)
# untested here; included per the task brief's endpoint list.
# ---------------------------------------------------------------------------
BEACON_APIS = [
    "http://unstable.mainnet.beacon-api.nimbus.team",
    "http://testing.mainnet.beacon-api.nimbus.team",
    "https://lodestar-mainnet.chainsafe.io",
    "https://www.lightclientdata.org",
]
HEADERS = {"accept": "application/json", "User-Agent": "curl/8.0"}


def _get_json(path: str, tries: int = 4, timeout: int = 20) -> dict:
    """Same retry/fallback shape as `eth_rpc.py`'s `rpc()`: walk the whole
    pool once per attempt, short sleep between endpoints, longer sleep
    between full-pool passes, real errors accumulated for the final
    exception rather than swallowed silently."""
    last = None
    for _attempt in range(tries):
        for base in BEACON_APIS:
            url = base.rstrip("/") + path
            try:
                req = urllib.request.Request(url, headers=HEADERS)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return json.load(resp)
            except Exception as e:  # noqa: BLE001 -- real network call, real fallback
                last = f"{url}: {e}"
            time.sleep(0.15)
        time.sleep(1.0)
    raise RuntimeError(f"all beacon-API endpoints failed for {path}: {last}")


# ---------------------------------------------------------------------------
# Raw fetchers -- one per light-client REST endpoint.
# ---------------------------------------------------------------------------


def fetch_bootstrap(block_root: str) -> dict:
    """GET /eth/v1/beacon/light_client/bootstrap/{block_root} -- the initial
    trusted sync-committee snapshot for a checkpoint root. `block_root` may
    be given with or without the `0x` prefix."""
    if not block_root.startswith("0x"):
        block_root = "0x" + block_root
    return _get_json(f"/eth/v1/beacon/light_client/bootstrap/{block_root}")


def fetch_updates(start_period: int, count: int) -> list[dict]:
    """GET /eth/v1/beacon/light_client/updates?start_period=&count= -- one
    `LightClientUpdate` per sync-committee period, used to walk a client
    forward from a bootstrap to the current committee. Returns the raw list
    of `{"version": ..., "data": {...}}` entries (may be shorter than
    `count` near the chain head)."""
    return _get_json(f"/eth/v1/beacon/light_client/updates?start_period={start_period}&count={count}")


def fetch_finality_update() -> dict:
    """GET /eth/v1/beacon/light_client/finality_update -- the latest
    finalized-header update. This is what M8's design doc anchors a
    finalized beacon header + execution payload from."""
    return _get_json("/eth/v1/beacon/light_client/finality_update")


def fetch_optimistic_update() -> dict:
    """GET /eth/v1/beacon/light_client/optimistic_update -- the latest
    attested/optimistic-header update. No `finalized_header` at all (see
    module docstring) -- fetched for completeness/a future fast-path, not
    consumed by M4's `submit_update` or M8."""
    return _get_json("/eth/v1/beacon/light_client/optimistic_update")


# ---------------------------------------------------------------------------
# Byte-decoding helpers.
# ---------------------------------------------------------------------------


def _strip0x(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def _decode_header(h: dict) -> bytes:
    """`LightClientHeader` -> the raw 112-byte `BeaconBlockHeader` SSZ
    encoding `contracts/sync_committee/header.py` operates on.

    Since Capella, `h` is `{"beacon": {...}, "execution": {...},
    "execution_branch": [...]}` -- confirmed live (module docstring); only
    `"beacon"` is M4's concern. Pre-Capella (Altair/Bellatrix, and every one
    of the vendored Altair-minimal test vectors) `h` IS the flat
    `BeaconBlockHeader` dict directly -- both shapes are handled here so
    this function works against old vectors and live mainnet data alike.
    """
    beacon = h["beacon"] if "beacon" in h else h
    slot = int(beacon["slot"])
    proposer_index = int(beacon["proposer_index"])
    parent_root = _strip0x(beacon["parent_root"])
    state_root = _strip0x(beacon["state_root"])
    body_root = _strip0x(beacon["body_root"])
    assert len(parent_root) == len(state_root) == len(body_root) == 32
    # `ref.le64` (tests/sync_committee/reference.py) is the exact mirror of
    # `contracts/sync_committee/header.py`'s own `le64` -- SSZ `uint64`
    # fields are little-endian, `op.itob`/plain `int.to_bytes(..., "big")`
    # are NOT (§3.1 trap 1) -- reused here rather than re-derived.
    header = ref.le64(slot) + ref.le64(proposer_index) + parent_root + state_root + body_root
    assert len(header) == 112
    return header


def _decode_branch(branch_hex: list[str]) -> bytes:
    """Concatenates a JSON list of 32-byte hex merkle-branch nodes into the
    flat `bytes` blob `arc4.DynamicBytes` branch arguments expect (no
    length prefix needed here -- an ABI caller's DynamicBytes wrapper adds
    that; mirrors `tests/sync_committee/test_install_live.py`'s
    `b"".join(branch)` usage of the same shape). Deliberately does NOT
    assert a fixed number of entries -- branch depth is fork-dependent, not
    a client-side constant (module docstring)."""
    nodes = [_strip0x(n) for n in branch_hex]
    for n in nodes:
        assert len(n) == 32, f"branch node not 32 bytes: {len(n)}"
    return b"".join(nodes)


def _g1_compressed_to_avm(hex_compressed: str) -> tuple[bytes, bytes]:
    """48-byte compressed (ZCash/IETF) G1 hex -> `(compressed_48B,
    uncompressed_96B_AVM)`. Mirrors `tests/bls/test_pairing.py`'s
    `_pk_bytes_to_g1_point` exactly (`py_ecc.bls.point_compression.
    decompress_G1` + `tests/bls/test_codec.py`'s `_g1_uncompressed`, which
    is itself the proven inverse of `contracts/primitives/bls/codec.py`'s
    `g1_compress`, pinned by that module's own T1/T8) -- reused verbatim
    rather than re-derived."""
    comp = _strip0x(hex_compressed)
    assert len(comp) == 48
    pt = decompress_G1(int.from_bytes(comp, "big"))
    uncompressed = _g1_uncompressed(pt)
    assert len(uncompressed) == 96
    return comp, uncompressed


def _g2_compressed_to_avm(hex_compressed: str) -> bytes:
    """96-byte compressed G2 signature hex -> 192-byte AVM-uncompressed G2
    (`X.c0 || X.c1 || Y.c0 || Y.c1`), the exact format `submit_update`'s
    `signature: Bytes192` argument expects. Mirrors `tests/bls/
    test_pairing.py`'s `_sig_bytes_to_g2_avm` exactly: `py_ecc.bls.
    point_compression.decompress_G2` on the `(z1, z2)` big-endian-int pair,
    then `tests/bls/test_codec.py`'s `_g2_uncompressed` -- which performs
    the c0/c1 AVM ordering that is the *inverse* of `contracts/primitives/
    bls/codec.py`'s `g2_compress` (that module's own docstring calls this
    limb swap out as THE trap: AVM G2 order is c0-first, Ethereum/ZCash wire
    order is c1-first). This is the one place in this module a compressed
    BLS value turns into the exact bytes M4 verifies against a live
    pairing check -- deliberately not re-derived by hand here.
    """
    sig = _strip0x(hex_compressed)
    assert len(sig) == 96
    z1 = int.from_bytes(sig[:48], "big")
    z2 = int.from_bytes(sig[48:], "big")
    pt = decompress_G2((z1, z2))
    out = _g2_uncompressed(pt)
    assert len(out) == 192
    return out


def _committee_root(pubkeys_hex: list[str], aggregate_hex: str) -> bytes:
    """`hash_tree_root(SyncCommittee{pubkeys: Vector[BLSPubkey, N],
    aggregate_pubkey: BLSPubkey})`. Mirrors `tests/sync_committee/
    test_signing_root.py`'s `_committee_vector_root`/`_next_committee_root`
    verbatim (same sha256 leaf-then-pair-fold algorithm those functions use
    against the vendored 32-member minimal-preset vectors) -- the fold is
    leaf-count-agnostic (`while len(layer) > 1`), so it generalizes to the
    real mainnet 512-member committee with no new logic, only more leaves.
    Each `BLSPubkey` (a `Bytes48` basic-byte-vector) SSZ-merkleizes as
    `sha256(pubkey_bytes || 16 zero bytes)` -- 48 + 16 == 64 == two 32-byte
    chunks concatenated, exactly what a single `sha256` call over that
    64-byte string reproduces (same identity `install.py`'s own
    `install_process_chunk` comment calls out for the on-chain leaf).
    """
    leaves = [ref.sha256(_strip0x(pk) + bytes(16)) for pk in pubkeys_hex]
    layer = leaves
    while len(layer) > 1:
        layer = [ref.sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    committee_vector_root = layer[0]
    agg_leaf = ref.sha256(_strip0x(aggregate_hex) + bytes(16))
    return ref.sha256(committee_vector_root + agg_leaf)


# ---------------------------------------------------------------------------
# Argument-shape transforms -- fetched JSON -> exact `SyncCommitteeVerifier`
# ABI argument shapes (contracts/sync_committee/verifier.py).
# ---------------------------------------------------------------------------


@dataclass
class SubmitUpdateArgs:
    """Positional shape of `SyncCommitteeVerifier.submit_update`
    (contracts/sync_committee/verifier.py). `mode` is a pure relayer hint
    (`bitfield.py`'s `aggregate_participants` docstring: "not a
    security-relevant input") -- default 0 (direct-mode: walk and sum
    exactly the SET bits) is always correct; callers may pass 1
    (complement mode) as a budget optimisation for near-full-participation
    updates, never for correctness.
    """

    attested_header: bytes
    finalized_header: bytes
    finality_branch: bytes
    next_committee_root: bytes
    next_committee_branch: bytes
    sync_committee_bits: bytes
    signature: bytes
    signature_slot: int
    mode: int = 0

    def abi_args(self) -> tuple:
        """Positional argument tuple in `submit_update`'s exact declared
        order -- pass straight to an ARC4 method-call builder (e.g.
        algosdk's `AtomicTransactionComposer.add_method_call(..., method_args=
        list(args.abi_args()))`)."""
        return (
            self.attested_header,
            self.finalized_header,
            self.finality_branch,
            self.next_committee_root,
            self.next_committee_branch,
            self.sync_committee_bits,
            self.signature,
            self.signature_slot,
            self.mode,
        )


def transform_finality_update(resp: dict) -> SubmitUpdateArgs:
    """`fetch_finality_update()`'s response -> `submit_update` args.

    `finality_update` carries NO `next_sync_committee` data at all (only
    `/light_client/updates` period-update responses do) -- so
    `next_committee_root`/`next_committee_branch` are the §10.4
    "no next-committee proof this update" sentinel (zero root, empty
    branch; the contract's `has_next_proof` check on branch length being
    zero takes the no-proof path)."""
    data = resp["data"]
    attested_header = _decode_header(data["attested_header"])
    finalized_header = _decode_header(data["finalized_header"])
    finality_branch = _decode_branch(data["finality_branch"])
    sync_committee_bits = _strip0x(data["sync_aggregate"]["sync_committee_bits"])
    assert len(sync_committee_bits) == 64, (
        f"expected a 64-byte Bitvector[512] (mainnet SYNC_COMMITTEE_SIZE), "
        f"got {len(sync_committee_bits)}"
    )
    signature = _g2_compressed_to_avm(data["sync_aggregate"]["sync_committee_signature"])
    signature_slot = int(data["signature_slot"])

    return SubmitUpdateArgs(
        attested_header=attested_header,
        finalized_header=finalized_header,
        finality_branch=finality_branch,
        next_committee_root=bytes(32),
        next_committee_branch=b"",
        sync_committee_bits=sync_committee_bits,
        signature=signature,
        signature_slot=signature_slot,
    )


def transform_light_client_update(update_entry: dict) -> SubmitUpdateArgs:
    """One entry of `fetch_updates()`'s response list (a
    `{"version": ..., "data": {...}}` `LightClientUpdate`) -> `submit_update`
    args. Unlike `finality_update`, this DOES carry `next_sync_committee` +
    `next_sync_committee_branch` when the update proves one -- used to walk
    a client's `next_gen`/`next_committee_root_trusted` state forward."""
    args = transform_finality_update(update_entry)
    data = update_entry["data"]
    if "next_sync_committee" in data:
        nsc = data["next_sync_committee"]
        args.next_committee_root = _committee_root(nsc["pubkeys"], nsc["aggregate_pubkey"])
        args.next_committee_branch = _decode_branch(data["next_sync_committee_branch"])
    return args


def transform_optimistic_update(resp: dict) -> dict:
    """`fetch_optimistic_update()`'s response -> decoded fields ONLY, not a
    `submit_update`-ready tuple (module docstring: no `finalized_header`/
    `finality_branch` exists in this response to satisfy `submit_update`'s
    always-checked finality merkle branch). Useful for an optimistic
    fast-path display, not for any on-chain call today."""
    data = resp["data"]
    return {
        "attested_header": _decode_header(data["attested_header"]),
        "sync_committee_bits": _strip0x(data["sync_aggregate"]["sync_committee_bits"]),
        "signature": _g2_compressed_to_avm(data["sync_aggregate"]["sync_committee_signature"]),
        "signature_slot": int(data["signature_slot"]),
    }


@dataclass
class BootstrapArgs:
    """`bootstrap()`'s 4 declared args, plus the decoded committee key
    material a subsequent `install_open_keys`/`install_chunk`/
    `install_finalize` sequence needs (that sequence is a SEPARATE set of
    ABI calls from `bootstrap` itself -- see `install_chunks` below)."""

    header: bytes
    committee_root: bytes
    current_sc_branch: bytes
    pubkey_pairs: list[tuple[bytes, bytes]] = field(repr=False)  # (compressed_48B, uncompressed_96B)
    aggregate_compressed: bytes = b""
    aggregate_uncompressed: bytes = b""

    def bootstrap_abi_args(self, trusted_block_root: bytes) -> tuple:
        """`trusted_block_root` is the caller's already-trusted checkpoint
        root (the same one `fetch_bootstrap` was called with) -- it is not
        part of the bootstrap response, so it cannot be filled in here; the
        caller must supply the value it already trusted before fetching."""
        assert len(trusted_block_root) == 32
        return (self.header, self.committee_root, self.current_sc_branch, trusted_block_root)


def transform_bootstrap(resp: dict) -> BootstrapArgs:
    """`fetch_bootstrap()`'s response -> `BootstrapArgs`."""
    data = resp["data"]
    header = _decode_header(data["header"])
    csc = data["current_sync_committee"]
    committee_root = _committee_root(csc["pubkeys"], csc["aggregate_pubkey"])
    branch = _decode_branch(data["current_sync_committee_branch"])
    pairs = [_g1_compressed_to_avm(pk) for pk in csc["pubkeys"]]
    agg_compressed, agg_uncompressed = _g1_compressed_to_avm(csc["aggregate_pubkey"])
    return BootstrapArgs(
        header=header,
        committee_root=committee_root,
        current_sc_branch=branch,
        pubkey_pairs=pairs,
        aggregate_compressed=agg_compressed,
        aggregate_uncompressed=agg_uncompressed,
    )


def install_chunks(
    pairs: list[tuple[bytes, bytes]], chunk_size: int = 64
) -> list[tuple[int, bytes, bytes]]:
    """Splits a committee's `(compressed, uncompressed)` pairs (from
    `BootstrapArgs.pubkey_pairs`, or a `LightClientUpdate`'s
    `next_sync_committee` decoded the same way) into `install_chunk`-sized
    `(index, compressed_blob, uncompressed_blob)` triples -- mirrors
    `install_process_chunk`'s accepted shapes exactly (contracts/
    sync_committee/install.py): `compressed_blob` a multiple of 48 bytes,
    `uncompressed_blob` the matching multiple of 96, `index` the running
    member cursor `install_chunk`'s own `index` argument must equal
    exactly. Default `chunk_size=64` matches `KEYS_PER_BOX` so a chunk never
    straddles a key-box boundary -- a convenience, not a contract
    requirement.
    """
    out = []
    for start in range(0, len(pairs), chunk_size):
        chunk = pairs[start : start + chunk_size]
        compressed_blob = b"".join(c for c, _u in chunk)
        uncompressed_blob = b"".join(u for _c, u in chunk)
        out.append((start, compressed_blob, uncompressed_blob))
    return out


if __name__ == "__main__":
    # Minimal manual smoke run (the real assertions live in
    # tests/sync_committee/test_live_beacon_fetch.py): fetch and decode one
    # real, live finality_update, print the sane fields.
    resp = fetch_finality_update()
    args = transform_finality_update(resp)
    print("fork:", resp["version"])
    print("signature_slot:", args.signature_slot)
    print("attested slot:", int.from_bytes(args.attested_header[0:8], "little"))
    print("finalized slot:", int.from_bytes(args.finalized_header[0:8], "little"))
    print("finality_branch bytes:", len(args.finality_branch))
    print("sync_committee_bits bytes:", len(args.sync_committee_bits))
    print("signature bytes:", len(args.signature))
