"""The real 38-field Fulu `BeaconState` tree and the `block_roots` fold
(design doc §6.4/§17), promoted from `tests/state_anchor/real_beacon_state.py`
(that module's docstring records the full field-count/gindex derivation
discipline this file inherits verbatim: three independent ways of
confirming 38 fields before trusting any gindex here).

38 fields round up to 64 leaves (depth 6, same rounding Electra's 37
fields already needed) -> `g_block_roots_base = 2**6 + 5 = 69` --
IDENTICAL to Electra's own value, for the same reason (38 still fits in 64
leaves). Real, on-chain use MUST still read this from the fork table at
call time (§6.4 normative rule) -- the constant here is what a fixture
builder / offline test cross-checks the fork table's row against, never a
value forwarded straight to a contract call.
"""
from __future__ import annotations

from relayer.ssz.merkleize import (
    bls_pubkey_root,
    bls_signature_root,
    htr_container_list,
    htr_uint8_list,
    htr_uint64_list,
    htr_uint64_vector_fixed,
    htr_bytes32_vector_fixed,
    le_pad32,
    logs_bloom_root,
    extra_data_root,
    merkleize_chunks_exact,
    next_pow2,
    sha256,
    strip0x,
    ZERO_CHUNK,
)

# ---------------------------------------------------------------------------
# Real spec constants (mainnet preset/config, consensus-specs `master`).
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

# Real, spec-counted Fulu BeaconState field order.
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
# Per-field htr builders.
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


def exec_payload_header_htr(h: dict) -> bytes:
    """`ExecutionPayloadHeader` -- same 17-field shape/order as
    `relayer.ssz.execution_payload`'s `ExecutionPayload` (`FIELD_INDEX`),
    except `transactions_root`/`withdrawals_root` are already roots here (a
    header, not the full payload)."""
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
    `(state_root, field_roots_list_len_38, block_roots_array_bytes)`."""
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
    """Returns the FULL depth-19 branch from a `block_roots[t_slot % 8192]`
    leaf up to the real `BeaconState` root: the inner depth-13 fold within
    the `block_roots` Vector itself, concatenated with the depth-6
    container-level fold (using the OTHER 37 real field roots as
    siblings), leaf-to-root order."""
    residue = t_slot % 8192
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
