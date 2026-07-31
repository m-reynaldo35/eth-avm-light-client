"""SSZ `BeaconBlockHeader` chunking, domain separation, and the signing
root. Design doc §3.1 (normative construction), §3.2, §7.2.

This is the part of M4 that a self-consistent test suite could get wrong
without ever noticing (§3, quoting `ARCHITECTURE.md`): every construction
below is validated against real consensus-spec vectors in
`tests/sync_committee/test_signing_root.py` (T1-T3), not merely internally
consistent with this module's own inverse.
"""

from algopy import Bytes, UInt64, subroutine, op

from contracts.primitives.bls.hash_to_curve import hash_to_g2
from contracts.primitives.ssz.merkleize import zero_hash
from contracts.sync_committee.constants import (
    BEACON_HEADER_BYTES,
    domain_sync_committee,
    eth_dst,
)


@subroutine
def le64(x: UInt64) -> Bytes:
    """8-byte LITTLE-endian encoding of a uint64 SSZ basic-type chunk.

    `op.itob` is big-endian (§3.1 trap 1 / §15 item 3); every SSZ `uint64`
    field (`slot`, `proposer_index`, and any `List`/`Bitlist` length mixed
    in elsewhere) must be byte-reversed before it is safe to concatenate
    into a chunk. Same endianness trap M3 §2.11 flagged for
    `mix_in_length`, in a second place (§3.1 item 1).
    """
    be = op.itob(x)
    out = Bytes()
    for one_byte in reversed(be):
        out += one_byte
    return out


@subroutine
def be64_from_le(chunk_bytes8: Bytes) -> UInt64:
    """Inverse of `le64` for the 8-byte little-endian slots this module
    reads back out of a raw 112-byte header (e.g. to compare `slot`
    against a `UInt64` bound). `chunk_bytes8` must be exactly 8 bytes.
    """
    assert chunk_bytes8.length == 8
    be = Bytes()
    for one_byte in reversed(chunk_bytes8):
        be += one_byte
    return op.btoi(be)


@subroutine
def header_slot(header: Bytes) -> UInt64:
    """`header[0:8]`, little-endian -> native `UInt64` (§7.2)."""
    assert header.length == BEACON_HEADER_BYTES
    return be64_from_le(header[0:8])


@subroutine
def hash_tree_root_beacon_block_header(header: Bytes) -> Bytes:
    """`hash_tree_root(BeaconBlockHeader)` (§3.1).

    `header` is the raw 112-byte SSZ encoding (§7.2):
        slot            uint64 LE   [  0: 8]
        proposer_index  uint64 LE   [  8:16]
        parent_root     Bytes32     [ 16:48]
        state_root      Bytes32     [ 48:80]
        body_root       Bytes32     [ 80:112]

    5 fields -> 5 chunks, padded to 8 leaves (the next power of two) with
    zero chunks, folded bottom-up. `slot`/`proposer_index` are ALREADY
    little-endian in the wire encoding (§7.2), so the first two chunks are
    the raw 32-byte-padded field bytes verbatim -- no re-encoding needed;
    `le64`/`be64_from_le` exist for the *other* direction (constructing a
    header from a native slot, and reading a slot back out), not for this
    hash.
    """
    assert header.length == BEACON_HEADER_BYTES
    slot_chunk = header[0:8] + op.bzero(UInt64(24))
    proposer_chunk = header[8:16] + op.bzero(UInt64(24))
    parent_root = header[16:48]
    state_root = header[48:80]
    body_root = header[80:112]

    zero_leaf = zero_hash(UInt64(0))

    # Depth-3 merkleization of 8 leaves (5 real + 3 zero-padding), folded
    # bottom-up in a fixed 3-level tree -- cheaper and more direct than the
    # generic incremental-stack accumulator for a small, fixed leaf count.
    l0 = op.sha256(slot_chunk + proposer_chunk)
    l1 = op.sha256(parent_root + state_root)
    l2 = op.sha256(body_root + zero_leaf)
    l3 = op.sha256(zero_leaf + zero_leaf)

    n0 = op.sha256(l0 + l1)
    n1 = op.sha256(l2 + l3)

    return op.sha256(n0 + n1)


@subroutine
def compute_fork_data_root(current_version: Bytes, genesis_validators_root: Bytes) -> Bytes:
    """`hash_tree_root(ForkData{current_version, genesis_validators_root})`
    (§3.1). `ForkData` is exactly 2 chunks -> a single `sha256`, no padding
    tree: `sha256(current_version || 0x00*28 || genesis_validators_root)`.
    """
    assert current_version.length == 4
    assert genesis_validators_root.length == 32
    return op.sha256(current_version + op.bzero(UInt64(28)) + genesis_validators_root)


@subroutine
def compute_domain(
    domain_type: Bytes, fork_version: Bytes, genesis_validators_root: Bytes
) -> Bytes:
    """`domain_type || compute_fork_data_root(fork_version, gvr)[0:28]`
    (§3.1 trap 2 / §15 item 4). Truncates the fork-data root to 28 bytes,
    NOT 32 -- the first 4 bytes of that root are, separately, the
    network's fork DIGEST (a different, unrelated quantity); truncating to
    32 instead of 28 silently produces a 36-byte, not 32-byte, domain.
    """
    assert domain_type.length == 4
    fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root)
    return domain_type + fork_data_root[0:28]


@subroutine
def compute_signing_root(header: Bytes, domain: Bytes) -> Bytes:
    """`hash_tree_root(SigningData{object_root, domain})` (§3.1) --
    `SigningData` is 2 chunks -> one `sha256`:
    `sha256(hash_tree_root(header) || domain)`.
    """
    assert domain.length == 32
    object_root = hash_tree_root_beacon_block_header(header)
    return op.sha256(object_root + domain)


@subroutine
def signing_root_msg_point(
    header: Bytes, fork_version: Bytes, genesis_validators_root: Bytes
) -> Bytes:
    """The full §3.1 pipeline: header -> signing root -> `hash_to_g2` under
    the real Ethereum DST. `domain_sync_committee()`/`eth_dst()` are the
    ONLY call site for these two constants (§3.2) -- never hard-code either
    inside `contracts/primitives/bls`.
    """
    domain = compute_domain(domain_sync_committee(), fork_version, genesis_validators_root)
    signing_root = compute_signing_root(header, domain)
    return hash_to_g2(signing_root, eth_dst())
