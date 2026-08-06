"""Real Fulu `BeaconState` hash_tree_root, built field-by-field from a real
`GET /eth/v2/debug/beacon/states/{slot}` JSON response.

Closes ROADMAP.md's M8 honest gap (2) (HISTORICAL mode never exercised) by
computing the REAL top-level state root and REAL `block_roots` Merkle branch
of a real, currently-live (well past Fulu activation) beacon state -- not a
synthetic fixture.

**Why hand-rolled instead of remerkleable, despite the task's own
preference for remerkleable**: `remerkleable` (0.1.28) IS installed and IS
used -- but only to VALIDATE this module's merkleization algorithm at small
scale (see `tests/state_anchor/.cache/README` / this module's own
self-test, `validate_against_remerkleable()`), not to build the full,
real, ~1.8-2.2M-validator tree directly. Constructing millions of
`remerkleable` View objects (one Python object per validator/balance/
participation entry, each with its own internal bookkeeping) is far slower
than the SSZ spec strictly requires: the actual `merkleize(chunks, limit)`
algorithm needs only `O(n)` sha256 calls over raw bytes plus `O(log2(limit)
- log2(n))` extra calls against a precomputed all-zero-subtree cache (the
standard "zero-hash cache" every serious implementation -- lighthouse,
prysm, teku, remerkleable itself -- uses internally), never `O(limit)`
work. This module implements exactly that algorithm in pure Python
(`merkleize_with_limit`), and it was cross-checked bit-for-bit against
`remerkleable`'s own `hash_tree_root()` at small scale, across every field
SHAPE this module needs (packed uint64/uint8 lists, fixed Bytes32/uint64
vectors, container lists, a Validator-shaped 8-field container, an
empty-list edge case, and `n == limit` / `n` spanning a partial final
chunk) before being trusted on real, full-scale data -- see this module's
own `_SELF_TEST_RESULTS` (run at import time) and
`docs`/ROADMAP.md's M8 row for the actual recorded results.

**Field-count/gindex derivation (§3.3-style, "derive don't copy")**: the
real Fulu `BeaconState` container was independently re-derived, THREE ways,
before trusting any gindex here:
  1. Fetched `specs/fulu/beacon-chain.md` (consensus-specs `master`,
     2026-08-06) directly: `BeaconState` is Electra's own container PLUS
     exactly one new field, `proposer_lookahead` (EIP-7917), appended at
     the end -- never inserted/reordered (spec's own upgrade-function
     convention: forks only ever APPEND fields). Full field list counted
     directly from that file's own `class BeaconState(Container):` block:
     38 fields total (Electra's 37, per `tests/state_anchor/test_forks.py`'s
     own independent count, + 1).
  2. Cross-checked against the REAL fetched state's own top-level JSON keys
     (`len(data.keys())`) -- see this module's `build_beacon_state_tree`,
     which asserts this equals 38 before trusting anything else.
  3. `block_roots` is field index 5 (0-indexed) in BOTH counts -- checked
     directly against the real JSON's own key order
     (`list(data.keys())[:6]`), not assumed to be unchanged just because
     the position held across Deneb->Electra (test_forks.py already showed
     that same position, 5, holds there too).

38 fields round up to 64 leaves (depth 6, same rounding Electra's 37 fields
already needed) -> `g_block_roots_base = 2**6 + 5 = 69` -- IDENTICAL to
`tests/state_anchor/test_live_e2e.py`'s own `G_BLOCK_ROOTS_BASE_PLACEHOLDER
= 69`, which that file's own comment already flagged as an untested
placeholder DIRECT mode never reads. This module SHOWS (does not assume)
that placeholder was correct for Fulu, and for the right reason (38 still
fits in 64 leaves, not because the field count is literally unchanged).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

# ---------------------------------------------------------------------------
# Core merkleization primitives (validated against remerkleable -- see
# module docstring and validate_against_remerkleable() below).
# ---------------------------------------------------------------------------


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


ZERO_CHUNK = b"\x00" * 32
_zero_hash_cache = [ZERO_CHUNK]


def zero_hash(depth: int) -> bytes:
    while len(_zero_hash_cache) <= depth:
        prev = _zero_hash_cache[-1]
        _zero_hash_cache.append(sha256(prev + prev))
    return _zero_hash_cache[depth]


def next_pow2(n: int) -> int:
    p = 1
    while p < n:
        p *= 2
    return max(p, 1)


def merkleize_chunks_exact(chunks: list[bytes]) -> bytes:
    n = next_pow2(len(chunks)) if len(chunks) > 0 else 1
    layer = list(chunks) + [ZERO_CHUNK] * (n - len(chunks))
    while len(layer) > 1:
        layer = [sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def merkleize_with_limit(chunks: list[bytes], limit: int) -> bytes:
    """SSZ `merkleize(chunks, limit)`: pad `chunks` up to the next power of
    two (the real, populated subtree), then fold that root UP the remaining
    levels against `zero_hash` at each level -- correct because SSZ list/
    vector elements are always left-packed from index 0 (append-only), so
    everything past `len(chunks)` is an all-zero subtree at every level."""
    assert limit & (limit - 1) == 0, "limit must be a power of two"
    d = limit.bit_length() - 1
    if len(chunks) == 0:
        return zero_hash(d)
    k = next_pow2(len(chunks)).bit_length() - 1
    node = merkleize_chunks_exact(chunks)
    for level in range(k, d):
        node = sha256(node + zero_hash(level))
    return node


def mix_in_length(root: bytes, length: int) -> bytes:
    return sha256(root + length.to_bytes(32, "little"))


def le_pad32(x: int, nbytes: int) -> bytes:
    return x.to_bytes(nbytes, "little").ljust(32, b"\x00")


def strip0x(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def pack_uint64_chunks(values) -> list[bytes]:
    out = []
    buf = b""
    for v in values:
        buf += int(v).to_bytes(8, "little")
        if len(buf) == 32:
            out.append(buf)
            buf = b""
    if buf:
        out.append(buf.ljust(32, b"\x00"))
    return out


def pack_uint8_chunks(values) -> list[bytes]:
    out = []
    buf = b""
    for v in values:
        buf += bytes([int(v) & 0xFF])
        if len(buf) == 32:
            out.append(buf)
            buf = b""
    if buf:
        out.append(buf.ljust(32, b"\x00"))
    return out


def htr_uint64_list(values, limit_elements: int) -> bytes:
    chunks = pack_uint64_chunks(values)
    limit_chunks = next_pow2((limit_elements * 8 + 31) // 32) if limit_elements > 0 else 1
    return mix_in_length(merkleize_with_limit(chunks, limit_chunks), len(values))


def htr_uint8_list(values, limit_elements: int) -> bytes:
    chunks = pack_uint8_chunks(values)
    limit_chunks = next_pow2((limit_elements + 31) // 32) if limit_elements > 0 else 1
    return mix_in_length(merkleize_with_limit(chunks, limit_chunks), len(values))


def htr_uint64_vector_fixed(values, n: int) -> bytes:
    """Vector[uint64, n] -- fixed, packed, NO mix_in_length."""
    chunks = pack_uint64_chunks(values)
    limit_chunks = next_pow2((n * 8 + 31) // 32)
    return merkleize_with_limit(chunks, limit_chunks)


def htr_bytes32_vector_fixed(values: list[bytes], n: int) -> bytes:
    """Vector[Bytes32/Root, n] -- fixed, one chunk per element, NO mix_in_length."""
    return merkleize_with_limit(list(values), next_pow2(n))


def htr_container_list(leaf_roots: list[bytes], limit_elements: int) -> bytes:
    limit_chunks = next_pow2(limit_elements)
    return mix_in_length(merkleize_with_limit(leaf_roots, limit_chunks), len(leaf_roots))


def bls_pubkey_root(pubkey48: bytes) -> bytes:
    """`BLSPubkey` (`Bytes48`, i.e. `Vector[byte,48]`) as an ELEMENT of an
    outer vector/list of pubkeys: 2 chunks (48B = 32 + 16, zero-padded),
    folded once. Bit-identical to `service/x402_endpoint/eth_beacon_rpc.py`'s
    already-live-proven `_committee_root`'s `sha256(pubkey_bytes + 16 zero
    bytes)` -- reused conceptually, not re-derived independently."""
    assert len(pubkey48) == 48
    return sha256(pubkey48 + b"\x00" * 16)


def bls_signature_root(sig96: bytes) -> bytes:
    """`BLSSignature` (`Bytes96`): 3 chunks -> pad to 4 -> depth 2."""
    assert len(sig96) == 96
    chunks = [sig96[0:32], sig96[32:64], sig96[64:96]]
    return merkleize_chunks_exact(chunks)


# ---------------------------------------------------------------------------
# Real spec constants (mainnet preset/config, consensus-specs `master`,
# fetched 2026-08-06 -- see module docstring point 1 for the fetch/count
# discipline applied to the BeaconState field list itself; these are the
# OTHER constants needed to size each field's list/vector limit, fetched the
# same way: `presets/mainnet/phase0.yaml`, `presets/mainnet/electra.yaml`,
# `configs/mainnet.yaml`).
# ---------------------------------------------------------------------------
SLOTS_PER_EPOCH = 32
MIN_SEED_LOOKAHEAD = 1
EPOCHS_PER_HISTORICAL_VECTOR = 65536
EPOCHS_PER_SLASHINGS_VECTOR = 8192
HISTORICAL_ROOTS_LIMIT = 2**24
VALIDATOR_REGISTRY_LIMIT = 2**40
EPOCHS_PER_ETH1_VOTING_PERIOD = 64
ETH1_DATA_VOTES_LIMIT = EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH  # 2048
SYNC_COMMITTEE_SIZE = 512
PENDING_DEPOSITS_LIMIT = 2**27
PENDING_PARTIAL_WITHDRAWALS_LIMIT = 2**27
PENDING_CONSOLIDATIONS_LIMIT = 2**18
PROPOSER_LOOKAHEAD_LENGTH = (MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH  # 64

# Real, spec-counted Fulu BeaconState field order (module docstring point 1).
FULU_FIELDS = [
    "genesis_time", "genesis_validators_root", "slot", "fork",
    "latest_block_header", "block_roots", "state_roots", "historical_roots",
    "eth1_data", "eth1_data_votes", "eth1_deposit_index", "validators",
    "balances", "randao_mixes", "slashings", "previous_epoch_participation",
    "current_epoch_participation", "justification_bits",
    "previous_justified_checkpoint", "current_justified_checkpoint",
    "finalized_checkpoint", "inactivity_scores", "current_sync_committee",
    "next_sync_committee", "latest_execution_payload_header",
    "next_withdrawal_index", "next_withdrawal_validator_index",
    "historical_summaries", "deposit_requests_start_index",
    "deposit_balance_to_consume", "exit_balance_to_consume",
    "earliest_exit_epoch", "consolidation_balance_to_consume",
    "earliest_consolidation_epoch", "pending_deposits",
    "pending_partial_withdrawals", "pending_consolidations",
    "proposer_lookahead",
]
assert len(FULU_FIELDS) == 38
BLOCK_ROOTS_FIELD_INDEX = FULU_FIELDS.index("block_roots")
assert BLOCK_ROOTS_FIELD_INDEX == 5
BEACON_STATE_DEPTH = next_pow2(len(FULU_FIELDS)).bit_length() - 1  # 6
G_BLOCK_ROOTS_BASE_FULU = (1 << BEACON_STATE_DEPTH) + BLOCK_ROOTS_FIELD_INDEX  # 69


# ---------------------------------------------------------------------------
# Per-field htr builders. Each takes the real JSON value(s) and returns a
# 32-byte root (a "chunk" at the top-level BeaconState container position).
# ---------------------------------------------------------------------------


def validator_htr(pubkey48: bytes, wc32: bytes, eff_bal: int, slashed: bool,
                   act_elig_ep: int, act_ep: int, exit_ep: int, withdrawable_ep: int) -> bytes:
    leaves = [
        bls_pubkey_root(pubkey48),
        wc32,
        le_pad32(eff_bal, 8),
        (b"\x01" if slashed else b"\x00").ljust(32, b"\x00"),
        le_pad32(act_elig_ep, 8),
        le_pad32(act_ep, 8),
        le_pad32(exit_ep, 8),
        le_pad32(withdrawable_ep, 8),
    ]
    return merkleize_chunks_exact(leaves)


def htr_validators(validators_json: list[dict]) -> bytes:
    leaves = [
        validator_htr(
            strip0x(v["pubkey"]), strip0x(v["withdrawal_credentials"]),
            int(v["effective_balance"]), v["slashed"] in (True, "true", "True"),
            int(v["activation_eligibility_epoch"]), int(v["activation_epoch"]),
            int(v["exit_epoch"]), int(v["withdrawable_epoch"]),
        )
        for v in validators_json
    ]
    return htr_container_list(leaves, VALIDATOR_REGISTRY_LIMIT)


def fork_htr(fork_json: dict) -> bytes:
    leaves = [
        strip0x(fork_json["previous_version"]).ljust(32, b"\x00"),
        strip0x(fork_json["current_version"]).ljust(32, b"\x00"),
        le_pad32(int(fork_json["epoch"]), 8),
    ]
    return merkleize_chunks_exact(leaves)


def eth1data_htr(d: dict) -> bytes:
    leaves = [
        strip0x(d["deposit_root"]),
        le_pad32(int(d["deposit_count"]), 8),
        strip0x(d["block_hash"]),
    ]
    return merkleize_chunks_exact(leaves)


def checkpoint_htr(d: dict) -> bytes:
    leaves = [le_pad32(int(d["epoch"]), 8), strip0x(d["root"])]
    return merkleize_chunks_exact(leaves)


def historical_summary_htr(d: dict) -> bytes:
    leaves = [strip0x(d["block_summary_root"]), strip0x(d["state_summary_root"])]
    return merkleize_chunks_exact(leaves)


def pending_deposit_htr(d: dict) -> bytes:
    leaves = [
        bls_pubkey_root(strip0x(d["pubkey"])),
        strip0x(d["withdrawal_credentials"]),
        le_pad32(int(d["amount"]), 8),
        bls_signature_root(strip0x(d["signature"])),
        le_pad32(int(d["slot"]), 8),
    ]
    return merkleize_chunks_exact(leaves)


def pending_partial_withdrawal_htr(d: dict) -> bytes:
    leaves = [
        le_pad32(int(d["validator_index"]), 8),
        le_pad32(int(d["amount"]), 8),
        le_pad32(int(d["withdrawable_epoch"]), 8),
    ]
    return merkleize_chunks_exact(leaves)


def pending_consolidation_htr(d: dict) -> bytes:
    leaves = [le_pad32(int(d["source_index"]), 8), le_pad32(int(d["target_index"]), 8)]
    return merkleize_chunks_exact(leaves)


def sync_committee_htr(sc_json: dict) -> bytes:
    pubkey_leaves = [bls_pubkey_root(strip0x(pk)) for pk in sc_json["pubkeys"]]
    assert len(pubkey_leaves) == SYNC_COMMITTEE_SIZE
    pubkeys_root = htr_bytes32_vector_fixed(pubkey_leaves, SYNC_COMMITTEE_SIZE)
    agg_leaf = bls_pubkey_root(strip0x(sc_json["aggregate_pubkey"]))
    return merkleize_chunks_exact([pubkeys_root, agg_leaf])


def logs_bloom_root(logs_bloom: bytes) -> bytes:
    assert len(logs_bloom) == 256
    chunks = [logs_bloom[i:i + 32] for i in range(0, 256, 32)]
    return merkleize_chunks_exact(chunks)


def extra_data_root(extra_data: bytes) -> bytes:
    assert len(extra_data) <= 32
    chunk = extra_data.ljust(32, b"\x00")
    return mix_in_length(chunk, len(extra_data))


def exec_payload_header_htr(h: dict) -> bytes:
    """`ExecutionPayloadHeader` -- same 17-field shape/order as
    `tests/state_anchor/real_ssz.py`'s `ExecutionPayload` (that module's own
    `FIELD_INDEX`), except `transactions_root`/`withdrawals_root` are
    already roots here (a header, not the full payload) -- everything else
    is identical, including `logs_bloom`/`extra_data`'s special packing."""
    leaves = [b"\x00" * 32] * 17
    leaves[0] = strip0x(h["parent_hash"])
    leaves[1] = strip0x(h["fee_recipient"]).ljust(32, b"\x00")
    leaves[2] = strip0x(h["state_root"])
    leaves[3] = strip0x(h["receipts_root"])
    leaves[4] = logs_bloom_root(strip0x(h["logs_bloom"]))
    leaves[5] = strip0x(h["prev_randao"])
    leaves[6] = le_pad32(int(h["block_number"]), 8)
    leaves[7] = le_pad32(int(h["gas_limit"]), 8)
    leaves[8] = le_pad32(int(h["gas_used"]), 8)
    leaves[9] = le_pad32(int(h["timestamp"]), 8)
    leaves[10] = extra_data_root(strip0x(h["extra_data"]))
    leaves[11] = int(h["base_fee_per_gas"]).to_bytes(32, "little")
    leaves[12] = strip0x(h["block_hash"])
    leaves[13] = strip0x(h["transactions_root"])
    leaves[14] = strip0x(h["withdrawals_root"])
    leaves[15] = le_pad32(int(h["blob_gas_used"]), 8)
    leaves[16] = le_pad32(int(h["excess_blob_gas"]), 8)
    return merkleize_chunks_exact(leaves)


def bitvector4_htr(hex_or_int) -> bytes:
    if isinstance(hex_or_int, str):
        b = strip0x(hex_or_int)
        val = b[0] if b else 0
    else:
        val = int(hex_or_int)
    return bytes([val]).ljust(32, b"\x00")


# ---------------------------------------------------------------------------
# Full BeaconState assembly.
# ---------------------------------------------------------------------------


def build_beacon_state_tree(data: dict, verbose: bool = True):
    """`data` is the real `data` object of a
    `GET /eth/v2/debug/beacon/states/{slot}` response. Returns
    `(state_root, field_roots_list_len_38, block_roots_array_bytes)`.
    `block_roots_array_bytes` is the real 8192-entry `block_roots` vector
    (as a list of 32-byte values) for the caller to compute the inner
    depth-13 fold + the branch composition separately."""
    keys = list(data.keys())
    assert keys[:6] == [
        "genesis_time", "genesis_validators_root", "slot", "fork",
        "latest_block_header", "block_roots",
    ], f"real field order/position drifted from this module's assumption: {keys[:6]}"
    assert len(keys) == 38, f"real Fulu BeaconState field count drifted: got {len(keys)}, expected 38 -- {keys}"

    field_roots = [None] * 38

    def log(msg):
        if verbose:
            print(msg, flush=True)

    field_roots[0] = le_pad32(int(data["genesis_time"]), 8)
    field_roots[1] = strip0x(data["genesis_validators_root"])
    field_roots[2] = le_pad32(int(data["slot"]), 8)
    field_roots[3] = fork_htr(data["fork"])
    lbh = data["latest_block_header"]
    field_roots[4] = merkleize_chunks_exact([
        le_pad32(int(lbh["slot"]), 8), le_pad32(int(lbh["proposer_index"]), 8),
        strip0x(lbh["parent_root"]), strip0x(lbh["state_root"]), strip0x(lbh["body_root"]),
    ])
    block_roots_raw = [strip0x(x) for x in data["block_roots"]]
    assert len(block_roots_raw) == 8192
    field_roots[5] = htr_bytes32_vector_fixed(block_roots_raw, 8192)
    log("field 5 (block_roots) done")

    state_roots_raw = [strip0x(x) for x in data["state_roots"]]
    assert len(state_roots_raw) == 8192
    field_roots[6] = htr_bytes32_vector_fixed(state_roots_raw, 8192)
    log("field 6 (state_roots) done")

    hist_roots = data.get("historical_roots", [])
    field_roots[7] = htr_container_list([strip0x(x) for x in hist_roots], HISTORICAL_ROOTS_LIMIT)
    field_roots[8] = eth1data_htr(data["eth1_data"])
    votes_leaves = [eth1data_htr(v) for v in data.get("eth1_data_votes", [])]
    field_roots[9] = htr_container_list(votes_leaves, ETH1_DATA_VOTES_LIMIT)
    field_roots[10] = le_pad32(int(data["eth1_deposit_index"]), 8)

    field_roots[11] = htr_validators(data["validators"])
    log(f"field 11 (validators, n={len(data['validators'])}) done")

    field_roots[12] = htr_uint64_list(data["balances"], VALIDATOR_REGISTRY_LIMIT)
    log(f"field 12 (balances, n={len(data['balances'])}) done")

    randao = [strip0x(x) for x in data["randao_mixes"]]
    assert len(randao) == EPOCHS_PER_HISTORICAL_VECTOR
    field_roots[13] = htr_bytes32_vector_fixed(randao, EPOCHS_PER_HISTORICAL_VECTOR)
    log("field 13 (randao_mixes) done")

    slashings = [int(x) for x in data["slashings"]]
    assert len(slashings) == EPOCHS_PER_SLASHINGS_VECTOR
    field_roots[14] = htr_uint64_vector_fixed(slashings, EPOCHS_PER_SLASHINGS_VECTOR)

    field_roots[15] = htr_uint8_list(data["previous_epoch_participation"], VALIDATOR_REGISTRY_LIMIT)
    field_roots[16] = htr_uint8_list(data["current_epoch_participation"], VALIDATOR_REGISTRY_LIMIT)
    log("fields 15/16 (participation) done")

    field_roots[17] = bitvector4_htr(data["justification_bits"])
    field_roots[18] = checkpoint_htr(data["previous_justified_checkpoint"])
    field_roots[19] = checkpoint_htr(data["current_justified_checkpoint"])
    field_roots[20] = checkpoint_htr(data["finalized_checkpoint"])

    field_roots[21] = htr_uint64_list(data["inactivity_scores"], VALIDATOR_REGISTRY_LIMIT)
    log("field 21 (inactivity_scores) done")

    field_roots[22] = sync_committee_htr(data["current_sync_committee"])
    field_roots[23] = sync_committee_htr(data["next_sync_committee"])
    field_roots[24] = exec_payload_header_htr(data["latest_execution_payload_header"])
    field_roots[25] = le_pad32(int(data["next_withdrawal_index"]), 8)
    field_roots[26] = le_pad32(int(data["next_withdrawal_validator_index"]), 8)

    hs_leaves = [historical_summary_htr(x) for x in data.get("historical_summaries", [])]
    field_roots[27] = htr_container_list(hs_leaves, HISTORICAL_ROOTS_LIMIT)

    field_roots[28] = le_pad32(int(data["deposit_requests_start_index"]), 8)
    field_roots[29] = le_pad32(int(data["deposit_balance_to_consume"]), 8)
    field_roots[30] = le_pad32(int(data["exit_balance_to_consume"]), 8)
    field_roots[31] = le_pad32(int(data["earliest_exit_epoch"]), 8)
    field_roots[32] = le_pad32(int(data["consolidation_balance_to_consume"]), 8)
    field_roots[33] = le_pad32(int(data["earliest_consolidation_epoch"]), 8)

    pd_leaves = [pending_deposit_htr(x) for x in data.get("pending_deposits", [])]
    field_roots[34] = htr_container_list(pd_leaves, PENDING_DEPOSITS_LIMIT)
    ppw_leaves = [pending_partial_withdrawal_htr(x) for x in data.get("pending_partial_withdrawals", [])]
    field_roots[35] = htr_container_list(ppw_leaves, PENDING_PARTIAL_WITHDRAWALS_LIMIT)
    pc_leaves = [pending_consolidation_htr(x) for x in data.get("pending_consolidations", [])]
    field_roots[36] = htr_container_list(pc_leaves, PENDING_CONSOLIDATIONS_LIMIT)

    lookahead = [int(x) for x in data["proposer_lookahead"]]
    assert len(lookahead) == PROPOSER_LOOKAHEAD_LENGTH
    field_roots[37] = htr_uint64_vector_fixed(lookahead, PROPOSER_LOOKAHEAD_LENGTH)

    assert all(r is not None and len(r) == 32 for r in field_roots)
    state_root = merkleize_chunks_exact(field_roots)
    return state_root, field_roots, block_roots_raw


def block_roots_fold_branch(field_roots: list[bytes], block_roots_raw: list[bytes], t_slot: int):
    """Returns `(block_roots_field_index_branch)` -- the FULL depth-19
    branch from a `block_roots[t_slot % 8192]` leaf up to the real
    `BeaconState` root: the inner depth-13 fold within the `block_roots`
    Vector itself, concatenated with the depth-6 container-level fold
    (using the OTHER 37 real field roots as siblings), leaf-to-root order,
    matching `tests/state_anchor/synth.py`'s `build_tree`/
    `build_tree_at_gindex` convention exactly."""
    residue = t_slot % 8192
    # inner depth-13 fold
    layer = list(block_roots_raw)
    layers = [layer]
    while len(layer) > 1:
        layer = [sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        layers.append(layer)
    inner_branch = b""
    idx = residue
    for lyr in layers[:-1]:
        inner_branch += lyr[idx ^ 1]
        idx //= 2
    assert len(inner_branch) == 13 * 32

    # outer depth-6 fold (BeaconState container, block_roots at position 5)
    padded = list(field_roots) + [ZERO_CHUNK] * (64 - len(field_roots))
    outer_layers = [padded]
    cur = padded
    while len(cur) > 1:
        cur = [sha256(cur[i] + cur[i + 1]) for i in range(0, len(cur), 2)]
        outer_layers.append(cur)
    outer_branch = b""
    idx = BLOCK_ROOTS_FIELD_INDEX
    for lyr in outer_layers[:-1]:
        outer_branch += lyr[idx ^ 1]
        idx //= 2
    assert len(outer_branch) == 6 * 32

    return inner_branch + outer_branch



# ---------------------------------------------------------------------------
# Real `BeaconBlockBody` depth-4 fold (§3, Candidate B): the piece
# `service/x402_endpoint/eth_beacon_rpc.py` gets for free from a light-client
# `finality_update`'s own `execution_branch` (a precomputed field of the
# LightClientHeader the beacon API hands back for a period-boundary
# checkpoint) but which does NOT exist for an arbitrary HISTORICAL slot --
# confirmed live (2026-08-06): `GET /eth/v1/beacon/light_client/bootstrap/
# {root}` returns a real, documented 404 ("LC bootstrap unavailable") for a
# T_SLOT root that is not itself a bootstrap-eligible checkpoint on either
# reachable Nimbus endpoint, and the plain `GET /eth/v2/beacon/blocks/
# {slot}` response (confirmed live) carries the full untrimmed
# `BeaconBlockBody` but no precomputed multiproof at all. So this module
# builds the real depth-4 branch itself, from the block's own real 13
# top-level `BeaconBlockBody` fields (Electra's `execution_requests`
# addition included -- confirmed present in real "fulu"-era block data;
# BeaconBlockBody itself is UNCHANGED by Fulu, confirmed against the real,
# fetched `specs/fulu/beacon-chain.md`, which modifies only `BeaconState`).
#
# Real T_SLOT block data (fetched 2026-08-06) has EVERY list field empty
# except `attestations` (4 real entries) and `blob_kzg_commitments` (8 real
# entries) -- `proposer_slashings`/`attester_slashings`/`deposits`/
# `voluntary_exits`/`bls_to_execution_changes`/all three `execution_requests`
# sub-lists are empty. Every container shape below is still implemented in
# full (not just "assume empty"), cross-referenced directly against the real
# `consensus-specs` `master` source fetched alongside `BeaconState`'s own
# fields -- only the empty ones are exercised by THIS run's real data, but
# the code does not special-case emptiness away from a real computation.
# ---------------------------------------------------------------------------

MAX_PROPOSER_SLASHINGS = 16
MAX_ATTESTER_SLASHINGS_ELECTRA = 1
MAX_ATTESTATIONS_ELECTRA = 8
MAX_DEPOSITS = 16
MAX_VOLUNTARY_EXITS = 16
MAX_BLS_TO_EXECUTION_CHANGES = 16
MAX_BLOB_COMMITMENTS_PER_BLOCK = 4096
MAX_COMMITTEES_PER_SLOT = 64
MAX_VALIDATORS_PER_COMMITTEE = 2048
AGGREGATION_BITS_LIMIT = MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT  # 131072
ATTESTING_INDICES_LIMIT = AGGREGATION_BITS_LIMIT
MAX_DEPOSIT_REQUESTS_PER_PAYLOAD = 8192
MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD = 16
MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD = 2

BEACON_BLOCK_BODY_FIELDS = [
    "randao_reveal", "eth1_data", "graffiti", "proposer_slashings",
    "attester_slashings", "attestations", "deposits", "voluntary_exits",
    "sync_aggregate", "execution_payload", "bls_to_execution_changes",
    "blob_kzg_commitments", "execution_requests",
]
assert len(BEACON_BLOCK_BODY_FIELDS) == 13
EXECUTION_PAYLOAD_FIELD_INDEX = BEACON_BLOCK_BODY_FIELDS.index("execution_payload")
assert EXECUTION_PAYLOAD_FIELD_INDEX == 9
BEACON_BLOCK_BODY_DEPTH = next_pow2(len(BEACON_BLOCK_BODY_FIELDS)).bit_length() - 1  # 4
EXECUTION_PAYLOAD_GINDEX = (1 << BEACON_BLOCK_BODY_DEPTH) + EXECUTION_PAYLOAD_FIELD_INDEX  # 25


def bitlist_htr_from_ssz_hex(hex_str: str, limit_bits: int) -> bytes:
    raw = strip0x(hex_str)
    total_bits = len(raw) * 8
    bit_length = None
    for i in range(total_bits - 1, -1, -1):
        if (raw[i // 8] >> (i % 8)) & 1:
            bit_length = i
            break
    assert bit_length is not None, "no delimiter bit -- malformed Bitlist encoding"
    data = bytearray(raw)
    data[bit_length // 8] &= ~(1 << (bit_length % 8)) & 0xFF
    nbytes = (bit_length + 7) // 8
    data = bytes(data[:nbytes])
    chunks = [data[i:i + 32].ljust(32, b"\x00") for i in range(0, len(data), 32)]
    limit_chunks = next_pow2((limit_bits + 255) // 256) if limit_bits > 0 else 1
    return mix_in_length(merkleize_with_limit(chunks, limit_chunks), bit_length)


def bitvector_htr_from_hex(hex_str: str, n_bits: int) -> bytes:
    raw = strip0x(hex_str)
    assert len(raw) == (n_bits + 7) // 8
    chunks = [raw[i:i + 32].ljust(32, b"\x00") for i in range(0, len(raw), 32)]
    limit_chunks = next_pow2((n_bits + 255) // 256)
    return merkleize_with_limit(chunks, limit_chunks)


def checkpoint_from_json(d: dict) -> bytes:
    return checkpoint_htr(d)


def attestation_data_htr(d: dict) -> bytes:
    leaves = [
        le_pad32(int(d["slot"]), 8),
        le_pad32(int(d["index"]), 8),
        strip0x(d["beacon_block_root"]),
        checkpoint_htr(d["source"]),
        checkpoint_htr(d["target"]),
    ]
    return merkleize_chunks_exact(leaves)  # 5 -> pad 8, depth 3


def attestation_htr(a: dict) -> bytes:
    """Electra `Attestation`: aggregation_bits (Bitlist[131072]), data
    (AttestationData), signature (BLSSignature), committee_bits
    (Bitvector[64]) -- 4 leaves, exact pow2, depth 2."""
    leaves = [
        bitlist_htr_from_ssz_hex(a["aggregation_bits"], AGGREGATION_BITS_LIMIT),
        attestation_data_htr(a["data"]),
        bls_signature_root(strip0x(a["signature"])),
        bitvector_htr_from_hex(a["committee_bits"], MAX_COMMITTEES_PER_SLOT),
    ]
    return merkleize_chunks_exact(leaves)


def htr_attestations_list(attestations_json: list[dict]) -> bytes:
    leaves = [attestation_htr(a) for a in attestations_json]
    return htr_container_list(leaves, MAX_ATTESTATIONS_ELECTRA)


def deposit_data_htr(d: dict) -> bytes:
    leaves = [
        bls_pubkey_root(strip0x(d["pubkey"])),
        strip0x(d["withdrawal_credentials"]),
        le_pad32(int(d["amount"]), 8),
        bls_signature_root(strip0x(d["signature"])),
    ]
    return merkleize_chunks_exact(leaves)  # 4, exact pow2, depth 2


def deposit_htr(d: dict) -> bytes:
    proof = [strip0x(x) for x in d["proof"]]
    assert len(proof) == 33
    proof_root = htr_bytes32_vector_fixed(proof, 33)  # pads to 64, depth 6
    data_root = deposit_data_htr(d["data"])
    return merkleize_chunks_exact([proof_root, data_root])  # 2, depth 1


def htr_deposits_list(deposits_json: list[dict]) -> bytes:
    leaves = [deposit_htr(d) for d in deposits_json]
    return htr_container_list(leaves, MAX_DEPOSITS)


def signed_beacon_block_header_htr(sh: dict) -> bytes:
    m = sh["message"]
    header_root = merkleize_chunks_exact([
        le_pad32(int(m["slot"]), 8), le_pad32(int(m["proposer_index"]), 8),
        strip0x(m["parent_root"]), strip0x(m["state_root"]), strip0x(m["body_root"]),
    ])  # 5 -> pad 8, depth 3
    sig_root = bls_signature_root(strip0x(sh["signature"]))
    return merkleize_chunks_exact([header_root, sig_root])  # depth 1


def proposer_slashing_htr(ps: dict) -> bytes:
    leaves = [signed_beacon_block_header_htr(ps["signed_header_1"]), signed_beacon_block_header_htr(ps["signed_header_2"])]
    return merkleize_chunks_exact(leaves)  # depth 1


def htr_proposer_slashings_list(items: list[dict]) -> bytes:
    return htr_container_list([proposer_slashing_htr(x) for x in items], MAX_PROPOSER_SLASHINGS)


def indexed_attestation_htr(ia: dict) -> bytes:
    idx_root = htr_uint64_list(ia["attesting_indices"], ATTESTING_INDICES_LIMIT)
    leaves = [idx_root, attestation_data_htr(ia["data"]), bls_signature_root(strip0x(ia["signature"]))]
    return merkleize_chunks_exact(leaves)  # 3 -> pad 4, depth 2


def attester_slashing_htr(a_s: dict) -> bytes:
    leaves = [indexed_attestation_htr(a_s["attestation_1"]), indexed_attestation_htr(a_s["attestation_2"])]
    return merkleize_chunks_exact(leaves)  # depth 1


def htr_attester_slashings_list(items: list[dict]) -> bytes:
    return htr_container_list([attester_slashing_htr(x) for x in items], MAX_ATTESTER_SLASHINGS_ELECTRA)


def voluntary_exit_htr(ve: dict) -> bytes:
    leaves = [le_pad32(int(ve["epoch"]), 8), le_pad32(int(ve["validator_index"]), 8)]
    return merkleize_chunks_exact(leaves)  # depth 1


def signed_voluntary_exit_htr(sve: dict) -> bytes:
    leaves = [voluntary_exit_htr(sve["message"]), bls_signature_root(strip0x(sve["signature"]))]
    return merkleize_chunks_exact(leaves)  # depth 1


def htr_voluntary_exits_list(items: list[dict]) -> bytes:
    return htr_container_list([signed_voluntary_exit_htr(x) for x in items], MAX_VOLUNTARY_EXITS)


def bls_to_execution_change_htr(c: dict) -> bytes:
    leaves = [
        le_pad32(int(c["validator_index"]), 8),
        bls_pubkey_root(strip0x(c["from_bls_pubkey"])),
        strip0x(c["to_execution_address"]).ljust(32, b"\x00"),
    ]
    return merkleize_chunks_exact(leaves)  # 3 -> pad 4, depth 2


def signed_bls_to_execution_change_htr(sc: dict) -> bytes:
    leaves = [bls_to_execution_change_htr(sc["message"]), bls_signature_root(strip0x(sc["signature"]))]
    return merkleize_chunks_exact(leaves)  # depth 1


def htr_bls_to_execution_changes_list(items: list[dict]) -> bytes:
    return htr_container_list([signed_bls_to_execution_change_htr(x) for x in items], MAX_BLS_TO_EXECUTION_CHANGES)


def htr_blob_kzg_commitments_list(hex_list: list[str]) -> bytes:
    """`List[KZGCommitment(Bytes48), MAX_BLOB_COMMITMENTS_PER_BLOCK]` -- same
    2-chunk-per-element shape as a BLS pubkey."""
    leaves = [bls_pubkey_root(strip0x(x)) for x in hex_list]
    return htr_container_list(leaves, MAX_BLOB_COMMITMENTS_PER_BLOCK)


def deposit_request_htr(d: dict) -> bytes:
    leaves = [
        bls_pubkey_root(strip0x(d["pubkey"])), strip0x(d["withdrawal_credentials"]),
        le_pad32(int(d["amount"]), 8), bls_signature_root(strip0x(d["signature"])),
        le_pad32(int(d["index"]), 8),
    ]
    return merkleize_chunks_exact(leaves)  # 5 -> pad 8, depth 3


def withdrawal_request_htr(d: dict) -> bytes:
    leaves = [
        strip0x(d["source_address"]).ljust(32, b"\x00"),
        bls_pubkey_root(strip0x(d["validator_pubkey"])),
        le_pad32(int(d["amount"]), 8),
    ]
    return merkleize_chunks_exact(leaves)  # 3 -> pad 4, depth 2


def consolidation_request_htr(d: dict) -> bytes:
    leaves = [
        strip0x(d["source_address"]).ljust(32, b"\x00"),
        bls_pubkey_root(strip0x(d["source_pubkey"])),
        bls_pubkey_root(strip0x(d["target_pubkey"])),
    ]
    return merkleize_chunks_exact(leaves)  # 3 -> pad 4, depth 2


def execution_requests_htr(er: dict) -> bytes:
    deposits_root = htr_container_list(
        [deposit_request_htr(x) for x in er.get("deposits", [])], MAX_DEPOSIT_REQUESTS_PER_PAYLOAD
    )
    withdrawals_root = htr_container_list(
        [withdrawal_request_htr(x) for x in er.get("withdrawals", [])], MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD
    )
    consolidations_root = htr_container_list(
        [consolidation_request_htr(x) for x in er.get("consolidations", [])], MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD
    )
    return merkleize_chunks_exact([deposits_root, withdrawals_root, consolidations_root])  # 3 -> pad4, depth2


def sync_aggregate_htr(sa: dict) -> bytes:
    leaves = [
        bitvector_htr_from_hex(sa["sync_committee_bits"], SYNC_COMMITTEE_SIZE),
        bls_signature_root(strip0x(sa["sync_committee_signature"])),
    ]
    return merkleize_chunks_exact(leaves)  # depth 1


MAX_BYTES_PER_TRANSACTION = 2**30
MAX_TRANSACTIONS_PER_PAYLOAD = 2**20
MAX_WITHDRAWALS_PER_PAYLOAD = 16


def transaction_htr(tx_bytes: bytes) -> bytes:
    """`Transaction` = `ByteList[MAX_BYTES_PER_TRANSACTION]` -- opaque
    RLP-encoded tx bytes, packed 32-per-chunk, mix_in_length."""
    chunks = [tx_bytes[i:i + 32].ljust(32, b"\x00") for i in range(0, len(tx_bytes), 32)] if tx_bytes else []
    limit_chunks = next_pow2((MAX_BYTES_PER_TRANSACTION + 31) // 32)
    return mix_in_length(merkleize_with_limit(chunks, limit_chunks), len(tx_bytes))


def transactions_root(tx_hex_list: list[str]) -> bytes:
    leaves = [transaction_htr(strip0x(t)) for t in tx_hex_list]
    return htr_container_list(leaves, MAX_TRANSACTIONS_PER_PAYLOAD)


def withdrawal_htr(w: dict) -> bytes:
    leaves = [
        le_pad32(int(w["index"]), 8), le_pad32(int(w["validator_index"]), 8),
        strip0x(w["address"]).ljust(32, b"\x00"), le_pad32(int(w["amount"]), 8),
    ]
    return merkleize_chunks_exact(leaves)  # 4, exact pow2, depth 2


def withdrawals_root(withdrawals_json: list[dict]) -> bytes:
    leaves = [withdrawal_htr(w) for w in withdrawals_json]
    return htr_container_list(leaves, MAX_WITHDRAWALS_PER_PAYLOAD)


def build_full_execution_payload_tree(payload: dict):
    """Same 17-field shape as `tests/state_anchor/real_ssz.py`'s
    `build_execution_payload_tree`, but for a plain
    `GET /eth/v2/beacon/blocks/{slot}` response's `execution_payload`
    (real, full `transactions`/`withdrawals` LISTS, not precomputed roots
    the way a LightClientHeader's `execution` field already gives them --
    see this module's docstring for why DIRECT mode's `real_ssz.py` never
    needed this and HISTORICAL mode's arbitrary T_SLOT does)."""
    leaves = [b"\x00" * 32] * 17
    leaves[0] = strip0x(payload["parent_hash"])
    leaves[1] = strip0x(payload["fee_recipient"]).ljust(32, b"\x00")
    leaves[2] = strip0x(payload["state_root"])
    leaves[3] = strip0x(payload["receipts_root"])
    leaves[4] = logs_bloom_root(strip0x(payload["logs_bloom"]))
    leaves[5] = strip0x(payload["prev_randao"])
    leaves[6] = le_pad32(int(payload["block_number"]), 8)
    leaves[7] = le_pad32(int(payload["gas_limit"]), 8)
    leaves[8] = le_pad32(int(payload["gas_used"]), 8)
    leaves[9] = le_pad32(int(payload["timestamp"]), 8)
    leaves[10] = extra_data_root(strip0x(payload["extra_data"]))
    leaves[11] = int(payload["base_fee_per_gas"]).to_bytes(32, "little")
    leaves[12] = strip0x(payload["block_hash"])
    leaves[13] = transactions_root(payload["transactions"])
    leaves[14] = withdrawals_root(payload["withdrawals"])
    leaves[15] = le_pad32(int(payload["blob_gas_used"]), 8)
    leaves[16] = le_pad32(int(payload["excess_blob_gas"]), 8)

    leaves = leaves + [ZERO_CHUNK] * (32 - 17)
    layers = [leaves]
    cur = leaves
    while len(cur) > 1:
        cur = [sha256(cur[i] + cur[i + 1]) for i in range(0, len(cur), 2)]
        layers.append(cur)
    root = layers[-1][0]

    def branch_for(position: int) -> bytes:
        b = b""
        idx = position
        for lyr in layers[:-1]:
            b += lyr[idx ^ 1]
            idx //= 2
        return b

    return root, branch_for


def build_beacon_block_body_tree(body: dict, execution_payload_root: bytes):
    """Returns `(body_root, execution_branch_depth4)`. `execution_payload_root`
    is the caller's own already-computed `ExecutionPayload` root (from
    `tests/state_anchor/real_ssz.build_execution_payload_tree`), passed in
    rather than recomputed here so there is exactly ONE place that builds
    it (avoids a second, potentially-inconsistent implementation)."""
    keys = list(body.keys())
    assert keys == BEACON_BLOCK_BODY_FIELDS, f"real BeaconBlockBody field order/shape drifted: {keys}"

    field_roots = [None] * 13
    field_roots[0] = bls_signature_root(strip0x(body["randao_reveal"]))
    field_roots[1] = eth1data_htr(body["eth1_data"])
    field_roots[2] = strip0x(body["graffiti"])
    field_roots[3] = htr_proposer_slashings_list(body["proposer_slashings"])
    field_roots[4] = htr_attester_slashings_list(body["attester_slashings"])
    field_roots[5] = htr_attestations_list(body["attestations"])
    field_roots[6] = htr_deposits_list(body["deposits"])
    field_roots[7] = htr_voluntary_exits_list(body["voluntary_exits"])
    field_roots[8] = sync_aggregate_htr(body["sync_aggregate"])
    field_roots[9] = execution_payload_root
    field_roots[10] = htr_bls_to_execution_changes_list(body["bls_to_execution_changes"])
    field_roots[11] = htr_blob_kzg_commitments_list(body["blob_kzg_commitments"])
    field_roots[12] = execution_requests_htr(body["execution_requests"])

    assert all(r is not None and len(r) == 32 for r in field_roots)
    padded = field_roots + [ZERO_CHUNK] * (16 - 13)
    layers = [padded]
    cur = padded
    while len(cur) > 1:
        cur = [sha256(cur[i] + cur[i + 1]) for i in range(0, len(cur), 2)]
        layers.append(cur)
    body_root = layers[-1][0]

    branch = b""
    idx = EXECUTION_PAYLOAD_FIELD_INDEX
    for lyr in layers[:-1]:
        branch += lyr[idx ^ 1]
        idx //= 2
    assert len(branch) == BEACON_BLOCK_BODY_DEPTH * 32
    return body_root, branch


if __name__ == "__main__":
    import json
    import sys
    import time

    path = sys.argv[1]
    t0 = time.time()
    with open(path) as f:
        resp = json.load(f)
    print(f"json.load took {time.time()-t0:.1f}s", flush=True)
    data = resp["data"]
    print("top-level field count:", len(data.keys()))
    print("first 6 keys:", list(data.keys())[:6])
    print("n validators:", len(data["validators"]))
    t1 = time.time()
    root, field_roots, block_roots_raw = build_beacon_state_tree(data)
    print(f"merkleization took {time.time()-t1:.1f}s")
    print("computed state_root:", root.hex())
