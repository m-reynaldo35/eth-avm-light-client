"""Real `BeaconBlockBody` depth-4 fold (design doc §5.4/§6.4), promoted
from `tests/state_anchor/real_beacon_state.py`'s bottom half.

Why this exists at all: a light-client `finality_update`/`bootstrap`
response carries a precomputed `execution_branch` for free (a period-
boundary checkpoint), but an arbitrary HISTORICAL target slot does not --
confirmed live: `GET /eth/v1/beacon/light_client/bootstrap/{root}` 404s
("LC bootstrap unavailable") for a non-checkpoint root, and the plain
`GET /eth/v2/beacon/blocks/{slot}` response carries the full untrimmed
`BeaconBlockBody` but no precomputed multiproof at all. So this module
builds the real depth-4 branch itself, from the block's own real 13
top-level `BeaconBlockBody` fields (Electra's `execution_requests`
included; Fulu does not modify `BeaconBlockBody`).
"""
from __future__ import annotations

from relayer.ssz.merkleize import (
    bitlist_htr_from_ssz_hex,
    bitvector_htr_from_hex,
    bls_pubkey_root,
    bls_signature_root,
    extra_data_root,
    htr_container_list,
    htr_uint64_list,
    le_pad32,
    logs_bloom_root,
    merkleize_chunks_exact,
    merkleize_with_limit,
    mix_in_length,
    next_pow2,
    sha256,
    strip0x,
    ZERO_CHUNK,
)
from relayer.ssz.beacon_state import checkpoint_htr, eth1data_htr, SYNC_COMMITTEE_SIZE

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
MAX_BYTES_PER_TRANSACTION = 2**30
MAX_TRANSACTIONS_PER_PAYLOAD = 2**20
MAX_WITHDRAWALS_PER_PAYLOAD = 16

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


def attestation_data_htr(d: dict) -> bytes:
    leaves = [
        le_pad32(int(d["slot"]), 8),
        le_pad32(int(d["index"]), 8),
        strip0x(d["beacon_block_root"]),
        checkpoint_htr(d["source"]),
        checkpoint_htr(d["target"]),
    ]
    return merkleize_chunks_exact(leaves)


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
    return merkleize_chunks_exact(leaves)


def deposit_htr(d: dict) -> bytes:
    proof = [strip0x(x) for x in d["proof"]]
    assert len(proof) == 33
    from relayer.ssz.merkleize import htr_bytes32_vector_fixed
    proof_root = htr_bytes32_vector_fixed(proof, 33)
    data_root = deposit_data_htr(d["data"])
    return merkleize_chunks_exact([proof_root, data_root])


def htr_deposits_list(deposits_json: list[dict]) -> bytes:
    leaves = [deposit_htr(d) for d in deposits_json]
    return htr_container_list(leaves, MAX_DEPOSITS)


def signed_beacon_block_header_htr(sh: dict) -> bytes:
    m = sh["message"]
    header_root = merkleize_chunks_exact([
        le_pad32(int(m["slot"]), 8), le_pad32(int(m["proposer_index"]), 8),
        strip0x(m["parent_root"]), strip0x(m["state_root"]), strip0x(m["body_root"]),
    ])
    sig_root = bls_signature_root(strip0x(sh["signature"]))
    return merkleize_chunks_exact([header_root, sig_root])


def proposer_slashing_htr(ps: dict) -> bytes:
    leaves = [signed_beacon_block_header_htr(ps["signed_header_1"]), signed_beacon_block_header_htr(ps["signed_header_2"])]
    return merkleize_chunks_exact(leaves)


def htr_proposer_slashings_list(items: list[dict]) -> bytes:
    return htr_container_list([proposer_slashing_htr(x) for x in items], MAX_PROPOSER_SLASHINGS)


def indexed_attestation_htr(ia: dict) -> bytes:
    idx_root = htr_uint64_list(ia["attesting_indices"], ATTESTING_INDICES_LIMIT)
    leaves = [idx_root, attestation_data_htr(ia["data"]), bls_signature_root(strip0x(ia["signature"]))]
    return merkleize_chunks_exact(leaves)


def attester_slashing_htr(a_s: dict) -> bytes:
    leaves = [indexed_attestation_htr(a_s["attestation_1"]), indexed_attestation_htr(a_s["attestation_2"])]
    return merkleize_chunks_exact(leaves)


def htr_attester_slashings_list(items: list[dict]) -> bytes:
    return htr_container_list([attester_slashing_htr(x) for x in items], MAX_ATTESTER_SLASHINGS_ELECTRA)


def voluntary_exit_htr(ve: dict) -> bytes:
    leaves = [le_pad32(int(ve["epoch"]), 8), le_pad32(int(ve["validator_index"]), 8)]
    return merkleize_chunks_exact(leaves)


def signed_voluntary_exit_htr(sve: dict) -> bytes:
    leaves = [voluntary_exit_htr(sve["message"]), bls_signature_root(strip0x(sve["signature"]))]
    return merkleize_chunks_exact(leaves)


def htr_voluntary_exits_list(items: list[dict]) -> bytes:
    return htr_container_list([signed_voluntary_exit_htr(x) for x in items], MAX_VOLUNTARY_EXITS)


def bls_to_execution_change_htr(c: dict) -> bytes:
    leaves = [
        le_pad32(int(c["validator_index"]), 8),
        bls_pubkey_root(strip0x(c["from_bls_pubkey"])),
        strip0x(c["to_execution_address"]).ljust(32, b"\x00"),
    ]
    return merkleize_chunks_exact(leaves)


def signed_bls_to_execution_change_htr(sc: dict) -> bytes:
    leaves = [bls_to_execution_change_htr(sc["message"]), bls_signature_root(strip0x(sc["signature"]))]
    return merkleize_chunks_exact(leaves)


def htr_bls_to_execution_changes_list(items: list[dict]) -> bytes:
    return htr_container_list([signed_bls_to_execution_change_htr(x) for x in items], MAX_BLS_TO_EXECUTION_CHANGES)


def htr_blob_kzg_commitments_list(hex_list: list[str]) -> bytes:
    leaves = [bls_pubkey_root(strip0x(x)) for x in hex_list]
    return htr_container_list(leaves, MAX_BLOB_COMMITMENTS_PER_BLOCK)


def deposit_request_htr(d: dict) -> bytes:
    leaves = [
        bls_pubkey_root(strip0x(d["pubkey"])), strip0x(d["withdrawal_credentials"]),
        le_pad32(int(d["amount"]), 8), bls_signature_root(strip0x(d["signature"])),
        le_pad32(int(d["index"]), 8),
    ]
    return merkleize_chunks_exact(leaves)


def withdrawal_request_htr(d: dict) -> bytes:
    leaves = [
        strip0x(d["source_address"]).ljust(32, b"\x00"),
        bls_pubkey_root(strip0x(d["validator_pubkey"])),
        le_pad32(int(d["amount"]), 8),
    ]
    return merkleize_chunks_exact(leaves)


def consolidation_request_htr(d: dict) -> bytes:
    leaves = [
        strip0x(d["source_address"]).ljust(32, b"\x00"),
        bls_pubkey_root(strip0x(d["source_pubkey"])),
        bls_pubkey_root(strip0x(d["target_pubkey"])),
    ]
    return merkleize_chunks_exact(leaves)


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
    return merkleize_chunks_exact([deposits_root, withdrawals_root, consolidations_root])


def sync_aggregate_htr(sa: dict) -> bytes:
    leaves = [
        bitvector_htr_from_hex(sa["sync_committee_bits"], SYNC_COMMITTEE_SIZE),
        bls_signature_root(strip0x(sa["sync_committee_signature"])),
    ]
    return merkleize_chunks_exact(leaves)


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
    return merkleize_chunks_exact(leaves)


def withdrawals_root(withdrawals_json: list[dict]) -> bytes:
    leaves = [withdrawal_htr(w) for w in withdrawals_json]
    return htr_container_list(leaves, MAX_WITHDRAWALS_PER_PAYLOAD)


def build_full_execution_payload_tree(payload: dict):
    """Same 17-field shape as `relayer.ssz.execution_payload`'s
    `build_execution_payload_tree`, but for a plain
    `GET /eth/v2/beacon/blocks/{slot}` response's `execution_payload`
    (real, full `transactions`/`withdrawals` LISTS, not precomputed roots)."""
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
    is the caller's own already-computed `ExecutionPayload` root, passed in
    rather than recomputed here so there is exactly ONE place that builds it."""
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
