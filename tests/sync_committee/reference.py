"""Pure-Python mirror of contracts/sync_committee/header.py + bitfield.py's
bit-order remap, checked against `py_ecc` and real consensus-spec vectors.

This is NOT the on-chain implementation -- it is a bit-for-bit re-expression
in plain Python, used so T1-T3 (design doc §11) can pin the signing-root
construction against `py_ecc.bls.G2ProofOfPossession.FastAggregateVerify`
before ever touching the compiled Puya contract. Keep this file's logic in
lockstep with `header.py`/`bitfield.py`: any change to the domain/signing-
root/bit-order rules there must be mirrored here.
"""

from __future__ import annotations

import hashlib

DOMAIN_SYNC_COMMITTEE = bytes.fromhex("07000000")
ETH_DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

SLOTS_PER_EPOCH_MAINNET = 32
EPOCHS_PER_SYNC_COMMITTEE_PERIOD_MAINNET = 256


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def le64(x: int) -> bytes:
    return x.to_bytes(8, "little")


def be64_from_le(chunk8: bytes) -> int:
    assert len(chunk8) == 8
    return int.from_bytes(chunk8, "little")


def zero_hash(depth: int) -> bytes:
    h = bytes(32)
    for _ in range(depth):
        h = sha256(h + h)
    return h


def hash_tree_root_beacon_block_header(header: bytes) -> bytes:
    """Verbatim mirror of `header.hash_tree_root_beacon_block_header`.
    `header` is the raw 112-byte SSZ encoding (§7.2)."""
    assert len(header) == 112
    slot_chunk = header[0:8] + bytes(24)
    proposer_chunk = header[8:16] + bytes(24)
    parent_root = header[16:48]
    state_root = header[48:80]
    body_root = header[80:112]
    zero_leaf = zero_hash(0)

    l0 = sha256(slot_chunk + proposer_chunk)
    l1 = sha256(parent_root + state_root)
    l2 = sha256(body_root + zero_leaf)
    l3 = sha256(zero_leaf + zero_leaf)
    n0 = sha256(l0 + l1)
    n1 = sha256(l2 + l3)
    return sha256(n0 + n1)


def compute_fork_data_root(current_version: bytes, genesis_validators_root: bytes) -> bytes:
    assert len(current_version) == 4
    assert len(genesis_validators_root) == 32
    return sha256(current_version + bytes(28) + genesis_validators_root)


def compute_domain(domain_type: bytes, fork_version: bytes, genesis_validators_root: bytes) -> bytes:
    assert len(domain_type) == 4
    fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root)
    return domain_type + fork_data_root[0:28]


def compute_signing_root(header: bytes, domain: bytes) -> bytes:
    assert len(domain) == 32
    object_root = hash_tree_root_beacon_block_header(header)
    return sha256(object_root + domain)


def epoch_at_slot(slot: int, slots_per_epoch: int = SLOTS_PER_EPOCH_MAINNET) -> int:
    return slot // slots_per_epoch


def period_at_epoch(
    epoch: int, epochs_per_period: int = EPOCHS_PER_SYNC_COMMITTEE_PERIOD_MAINNET
) -> int:
    return epoch // epochs_per_period


def period_at_slot(
    slot: int,
    slots_per_epoch: int = SLOTS_PER_EPOCH_MAINNET,
    epochs_per_period: int = EPOCHS_PER_SYNC_COMMITTEE_PERIOD_MAINNET,
) -> int:
    return period_at_epoch(epoch_at_slot(slot, slots_per_epoch), epochs_per_period)


def fork_version_epoch_for_signature_slot(
    signature_slot: int, slots_per_epoch: int = SLOTS_PER_EPOCH_MAINNET
) -> int:
    """§3.1 trap 3: `epoch(max(signature_slot, 1) - 1)`."""
    fork_version_slot = max(signature_slot, 1) - 1
    return epoch_at_slot(fork_version_slot, slots_per_epoch)


def avm_bit_index(i: int) -> int:
    """§5.1's SSZ-bit -> AVM-`getbit`-index remap, mirrored for the offline
    T5 negative test (a pure-arithmetic check the on-chain formula matches
    the intended semantics, independent of any AVM opcode)."""
    return (i // 8) * 8 + 7 - (i % 8)


def ssz_bitvector_get(bits: bytes, i: int) -> bool:
    """The TRUE SSZ Bitvector semantics: bit i lives in byte i//8, LSB-first
    within that byte. Reference oracle T5 checks the AVM remap against."""
    byte = bits[i // 8]
    return bool((byte >> (i % 8)) & 1)


def naive_msb_first_get(bits: bytes, i: int) -> bool:
    """The WRONG mapping T5 must show diverges: byte-order-only, MSB-first
    within the byte, i.e. `getbit(bits, i)` with no remap at all."""
    byte = bits[i // 8]
    return bool((byte >> (7 - (i % 8))) & 1)
