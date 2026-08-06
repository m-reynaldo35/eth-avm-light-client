"""Generic SSZ merkleization core (design doc §6.4/§17), promoted from
`tests/state_anchor/real_beacon_state.py`'s own core primitives (that
module's docstring explains the "why hand-rolled instead of remerkleable"
choice in full -- `remerkleable` was used only to cross-validate this exact
algorithm bit-for-bit at small scale before it was trusted on real,
full-scale data).

The whole point of `merkleize_with_limit`: SSZ list/vector elements are
always left-packed from index 0 (append-only), so everything past
`len(chunks)` is an all-zero subtree at every level -- the standard
"zero-hash cache" every serious SSZ implementation (lighthouse, prysm,
teku, remerkleable itself) uses internally to avoid `O(limit)` work.
"""
from __future__ import annotations

import hashlib


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
    two (the real, populated subtree), then fold that root UP the
    remaining levels against `zero_hash` at each level."""
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
    """`BLSPubkey` (`Bytes48`) as an element of an outer vector/list: 2
    chunks (48B = 32 + 16, zero-padded), folded once."""
    assert len(pubkey48) == 48
    return sha256(pubkey48 + b"\x00" * 16)


def bls_signature_root(sig96: bytes) -> bytes:
    """`BLSSignature` (`Bytes96`): 3 chunks -> pad to 4 -> depth 2."""
    assert len(sig96) == 96
    chunks = [sig96[0:32], sig96[32:64], sig96[64:96]]
    return merkleize_chunks_exact(chunks)


def logs_bloom_root(logs_bloom: bytes) -> bytes:
    """`Vector[byte, 256]` -> 8 chunks, depth 3, no length mix-in (fixed vector)."""
    assert len(logs_bloom) == 256
    chunks = [logs_bloom[i:i + 32] for i in range(0, 256, 32)]
    return merkleize_chunks_exact(chunks)


def extra_data_root(extra_data: bytes) -> bytes:
    """`List[byte, MAX_EXTRA_DATA_BYTES=32]`: pack, merkleize with the
    32-byte (1-chunk) limit, mix in length."""
    assert len(extra_data) <= 32
    chunk = extra_data.ljust(32, b"\x00")
    return mix_in_length(chunk, len(extra_data))


def bitlist_htr_from_ssz_hex(hex_str: str, limit_bits: int) -> bytes:
    """`Bitlist[N]`, decoded from its real SSZ delimiter-bit encoding (the
    highest set bit marks the boundary, not a length prefix)."""
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
