"""`eth_getProof` -> M6 account/storage proof segments (design doc §6.2).

Confirmed by 009 §2.1 to be the largest single gap in this project's real
usability before M9: M6 ("the only module with a fully implemented,
live-submitted, under-budget on-chain composite") had no off-chain client
at all. `grep -rn "eth_getProof"` found exactly one prior hit outside docs,
a frozen one-shot spike script.

Pure, no `algosdk` import (§4.3): this module decides HOW to segment a real
`eth_getProof` response into M6's raw-arg wire shapes; it never builds or
signs a transaction. `relayer.drivers.m6_account_storage` turns the
`AccountSegments` this module returns into a `GroupPlan`.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import rlp

# 006 §6.3's real fixed-overhead figures -- NOT "2,048 minus a round
# number" (007 §7.1's own 13-byte finding about why that produces a
# different, sometimes invalid, split). MODE_A_INIT carries the extra
# state_root(32)/address(20)/slot(32) fixed args a *_NEXT call does not.
MODE_A_INIT_NODE_BUDGET_BYTES = 1943
MODE_A_INIT_MAX_NODE_ARGS = 9
OTHER_MODE_NODE_BUDGET_BYTES = 2019
OTHER_MODE_MAX_NODE_ARGS = 11

EMPTY_TRIE_ROOT = bytes.fromhex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
EMPTY_CODE_HASH = bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")


def keccak256(b: bytes) -> bytes:
    from Crypto.Hash import keccak

    h = keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


def _strip0x(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def _nibbles(b: bytes) -> list[int]:
    out = []
    for x in b:
        out += [x >> 4, x & 0xF]
    return out


def mpt_key_from_address(address_hex: str) -> bytes:
    """Ethereum's state trie key is `keccak256(address)`, not the address
    itself (006's own `mpt_key_from_address` on-chain does the same)."""
    return keccak256(_strip0x(address_hex))


def mpt_key_from_slot(slot32: bytes) -> bytes:
    """The storage trie key is `keccak256(slot)`."""
    assert len(slot32) == 32
    return keccak256(slot32)


def mapping_slot(holder_address_hex: str, declaration_slot: int) -> bytes:
    """§6.2 step 5: Solidity's `mapping(address => uint256) balances`
    layout -- `slot = keccak256(pad32(holder) || pad32(declaration_slot))`.

    This repo's own pinned example (`tests/fixtures/spike-reference/
    eth_data.json`, 006 §6.5): USDT's `balances` mapping is declared at
    slot 2; Binance-8's holder address hashes to exactly the storage slot
    that fixture's own `storage_key` pins.

    >>> mapping_slot("0xF977814e90dA44bFA03b6295A0616a897441aceC", 2).hex()
    '0be16d71963429204d70543701f859c43526c316ac005c10114f4694ca405f36'
    """
    holder = _strip0x(holder_address_hex).rjust(32, b"\x00")
    decl = declaration_slot.to_bytes(32, "big")
    return keccak256(holder + decl)


@dataclass(frozen=True)
class MptProofResult:
    included: bool
    value_rlp: bytes | None  # raw RLP-encoded value at the leaf, if included


def verify_and_extract(root32: bytes, key: bytes, proof_nodes_rlp: list[bytes]) -> MptProofResult:
    """Standard Merkle-Patricia-proof walk-and-extract: verifies
    `proof_nodes_rlp` really chains from `root32` down to (or provably away
    from) `key`, and returns the raw RLP value at the leaf if included.

    This is a real off-chain cross-check (§1.3: "M9 uses balance/nonce/
    codeHash/storageHash only to cross-check its own understanding, never
    as an input the contract trusts") -- the on-chain walk (M2/M5) is the
    one that actually matters for soundness; this is what lets M9 decide,
    BEFORE spending a transaction, whether phase B is needed at all (§6.2
    point 4), a liveness/fee optimisation only.

    Known simplification: assumes every internal node is >=32 bytes RLP
    (always hash-referenced by a parent), which is true for essentially
    every real mainnet account/storage node. The rare short-node-embedded-
    by-value case is not handled -- if hit, this raises rather than
    silently mis-classifying (safe: falls back to FATAL / "ask a human",
    never a wrong C_* classification)."""
    key_nibbles = _nibbles(key)
    expected_ref = root32
    for node_rlp in proof_nodes_rlp:
        computed_hash = keccak256(node_rlp) if len(node_rlp) >= 32 else node_rlp
        if len(expected_ref) == 32:
            assert computed_hash == expected_ref, "proof node does not hash to the expected reference"
        node = rlp.decode(node_rlp)
        if len(node) == 17:
            if not key_nibbles:
                val = node[16]
                return MptProofResult(included=bool(val), value_rlp=val or None)
            nib = key_nibbles[0]
            key_nibbles = key_nibbles[1:]
            child = node[nib]
            if child == b"":
                return MptProofResult(included=False, value_rlp=None)
            expected_ref = child
        elif len(node) == 2:
            path_hp, value_or_ref = node
            flag_nib = path_hp[0] >> 4
            is_leaf = flag_nib in (2, 3)
            odd = flag_nib in (1, 3)
            nibs = []
            if odd:
                nibs.append(path_hp[0] & 0xF)
            for b in path_hp[1:]:
                nibs += [b >> 4, b & 0xF]
            if is_leaf:
                if nibs == key_nibbles:
                    return MptProofResult(included=True, value_rlp=value_or_ref)
                return MptProofResult(included=False, value_rlp=None)
            if key_nibbles[: len(nibs)] != nibs:
                return MptProofResult(included=False, value_rlp=None)
            key_nibbles = key_nibbles[len(nibs):]
            expected_ref = value_or_ref
        else:
            raise ValueError(f"unrecognised MPT node shape (len={len(node)})")
    raise ValueError("proof ran out of nodes before reaching a terminal node")


@dataclass(frozen=True)
class Segment:
    mode: str  # "A_INIT" | "A_NEXT" | "B_INIT" | "B_NEXT"
    nodes: list[bytes] = field(default_factory=list)


@dataclass(frozen=True)
class AccountSegments:
    """The result of segmenting one real `eth_getProof` response (§6.2).
    `segments` is `[A_INIT, A_NEXT..., B_INIT, B_NEXT...]` in submission
    order -- phase B is empty when the account is absent, or present but
    the storage trie is genuinely empty (§6.2 point 4, 006 §6.4)."""

    state_root: bytes
    address: bytes
    slot: bytes
    segments: list[Segment]
    account_included: bool
    storage_included: bool | None  # None when phase B legitimately does not run
    storage_root: bytes | None
    balance: int | None
    nonce: int | None
    code_hash: bytes | None


def _segment_nodes(nodes: list[bytes], first_budget: int, first_max_args: int,
                    other_budget: int, other_max_args: int) -> list[list[bytes]]:
    """Greedy path-order packing under the two per-mode caps (§6.2 point
    2): the FIRST call in a walk (A_INIT or B_INIT) has a smaller node
    budget than later _NEXT calls in the SAME walk, because it also
    carries state_root/address/slot (A_INIT) or prev_gi (B_INIT, same as
    _NEXT -- B_INIT's budget is the "other" 2,019/11 figure, only A_INIT is
    special, per contracts/composer/bench_app.py's real arg layout)."""
    groups: list[list[bytes]] = []
    cur: list[bytes] = []
    cur_bytes = 0
    budget, max_args = first_budget, first_max_args
    for node in nodes:
        would_bytes = cur_bytes + len(node)
        if cur and (would_bytes > budget or len(cur) >= max_args):
            groups.append(cur)
            cur, cur_bytes = [], 0
            budget, max_args = other_budget, other_max_args
        cur.append(node)
        cur_bytes += len(node)
    if cur:
        groups.append(cur)
    return groups


def segment_account_proof(get_proof_response: dict, *, declared_state_root: bytes | None = None) -> AccountSegments:
    """Given a raw `eth_getProof` JSON-RPC result, produce the M6 wire-
    format segmentation (§6.2). `declared_state_root` is the block header's
    own `stateRoot` (what M9 will pass to `MODE_A_INIT`'s `state_root` arg)
    -- if given, this function cross-checks the proof actually walks from
    it (a liveness check, §1.3; the on-chain walk re-derives the real
    security property regardless)."""
    address = _strip0x(get_proof_response["address"])
    account_proof = [_strip0x(n) for n in get_proof_response["accountProof"]]
    key = mpt_key_from_address(get_proof_response["address"])

    root = declared_state_root if declared_state_root is not None else keccak256(account_proof[0]) if account_proof and len(account_proof[0]) < 32 else None
    if root is None:
        # Root not supplied and the first node is too large to BE the root
        # (i.e. it's hash-referenced by a parent that isn't in this proof,
        # which is the normal case) -- verify_and_extract only needs
        # SOME expected root to start the chain; when unknown, use the
        # (already-hash-checked-internally) first node's own hash as a
        # a bootstrap value so extraction can still proceed, deferring the
        # real security check to whoever calls with declared_state_root.
        root = keccak256(account_proof[0])
    acct_result = verify_and_extract(root, key, account_proof)

    balance = nonce = None
    storage_root = None
    code_hash = None
    account_included = acct_result.included
    if account_included:
        acct_fields = rlp.decode(acct_result.value_rlp)
        nonce = int.from_bytes(acct_fields[0], "big") if acct_fields[0] else 0
        balance = int.from_bytes(acct_fields[1], "big") if acct_fields[1] else 0
        storage_root = acct_fields[2] if len(acct_fields[2]) == 32 else acct_fields[2]
        code_hash = acct_fields[3]

    slot_hex = None
    storage_proof_nodes: list[bytes] = []
    storage_included: bool | None = None
    slot_key_bytes = b""
    if get_proof_response.get("storageProof"):
        sp = get_proof_response["storageProof"][0]
        slot_hex = sp["key"]
        storage_proof_nodes = [_strip0x(n) for n in sp["proof"]]
        slot_key_bytes = _strip0x(slot_hex).rjust(32, b"\x00")

    need_phase_b = account_included and storage_root not in (None, EMPTY_TRIE_ROOT) and storage_proof_nodes
    if need_phase_b:
        skey = mpt_key_from_slot(slot_key_bytes)
        storage_included = verify_and_extract(storage_root, skey, storage_proof_nodes).included

    segments: list[Segment] = []
    a_groups = _segment_nodes(
        account_proof, MODE_A_INIT_NODE_BUDGET_BYTES, MODE_A_INIT_MAX_NODE_ARGS,
        OTHER_MODE_NODE_BUDGET_BYTES, OTHER_MODE_MAX_NODE_ARGS,
    )
    for i, grp in enumerate(a_groups):
        segments.append(Segment(mode="A_INIT" if i == 0 else "A_NEXT", nodes=grp))

    if need_phase_b:
        b_groups = _segment_nodes(
            storage_proof_nodes, OTHER_MODE_NODE_BUDGET_BYTES, OTHER_MODE_MAX_NODE_ARGS,
            OTHER_MODE_NODE_BUDGET_BYTES, OTHER_MODE_MAX_NODE_ARGS,
        )
        for i, grp in enumerate(b_groups):
            segments.append(Segment(mode="B_INIT" if i == 0 else "B_NEXT", nodes=grp))
    # §6.2 point 4: C_ABSENT_ACCOUNT and C_ABSENT_SLOT_EMPTY_TRIE need ZERO
    # phase-B segments -- emitting them anyway would fail against a
    # correct chain state. `need_phase_b` above already encodes this: it
    # is False whenever the account is absent OR its storage trie is
    # genuinely empty, so no B_INIT/B_NEXT segment is ever appended in
    # either case.

    return AccountSegments(
        state_root=root,
        address=address,
        slot=slot_key_bytes,
        segments=segments,
        account_included=account_included,
        storage_included=storage_included,
        storage_root=storage_root,
        balance=balance,
        nonce=nonce,
        code_hash=code_hash,
    )
