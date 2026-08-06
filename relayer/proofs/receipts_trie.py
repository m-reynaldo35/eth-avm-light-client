"""Real receipts-trie reconstruction for an arbitrary block/tx_index.
Promoted verbatim (design doc §2.1/§17: "Promote verbatim") from
`service/x402_endpoint/trie_proof.py` -- live-proven against M7's real
mainnet app `3664247481`.

There is no `eth_getProof`-equivalent for the receipts trie on real
Ethereum JSON-RPC (`eth_getProof` only covers the state/storage tries) --
this is exactly the gap M7 as a whole exists to work around, and why a real
relayer has to reconstruct it itself.
"""
import rlp
from Crypto.Hash import keccak


def kec(b: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


def _hx(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def _qi(s) -> int:
    if isinstance(s, int):
        return s
    return int(s, 16) if s else 0


def _encode_receipt(r: dict) -> bytes:
    logs = [[_hx(l["address"]), [_hx(t) for t in l["topics"]], _hx(l["data"])] for l in r["logs"]]
    status = _qi(r.get("status", "0x1"))
    body = [b"" if status == 0 else bytes([1]), _qi(r["cumulativeGasUsed"]), _hx(r["logsBloom"]), logs]
    enc = rlp.encode(body)
    ty = _qi(r.get("type", "0x0"))
    return (bytes([ty]) + enc) if ty else enc


def _nib(b: bytes) -> list[int]:
    out = []
    for x in b:
        out += [x >> 4, x & 15]
    return out


def _hp(nibbles: list[int], leaf: bool) -> bytes:
    flag = 2 if leaf else 0
    if len(nibbles) % 2:
        first = (flag + 1) * 16 + nibbles[0]
        rest = nibbles[1:]
    else:
        first = flag * 16
        rest = nibbles
    out = bytes([first])
    for i in range(0, len(rest), 2):
        out += bytes([rest[i] * 16 + rest[i + 1]])
    return out


def build_receipts_trie_and_path(receipts: list[dict], target_tx_index: int
                                  ) -> tuple[bytes, list[bytes]]:
    """Rebuild the real receipts trie from a block's real `eth_getBlockReceipts`
    result, and return `(receipts_root, nodes)` where `nodes` is the real
    root-to-leaf node path for `target_tx_index` (RLP-encoded bytes, in the
    order `mpt_walk_node` expects: root first, leaf last)."""
    items: dict[tuple, bytes] = {}
    for i, r in enumerate(receipts):
        idx = _qi(r.get("transactionIndex", i))
        items[tuple(_nib(rlp.encode(idx)))] = _encode_receipt(r)

    target_key = tuple(_nib(rlp.encode(target_tx_index)))
    if target_key not in items:
        raise KeyError(f"tx_index {target_tx_index} not found in this block's receipts")

    path_nodes_reverse: list[bytes] = []

    def ref(node):
        enc = rlp.encode(node)
        return kec(enc) if len(enc) >= 32 else node

    def build(keys, depth, on_path):
        if len(keys) == 1:
            k = keys[0]
            path = list(k[depth:])
            node = [_hp(path, True), items[k]]
            if on_path:
                path_nodes_reverse.append(rlp.encode(node))
            return node
        pref = 0
        while all(len(k) > depth + pref for k in keys) and len({k[depth + pref] for k in keys}) == 1:
            pref += 1
        if pref > 0:
            child_on_path = on_path and target_key[depth:depth + pref] == tuple(keys[0][depth:depth + pref])
            node = [_hp(list(keys[0][depth:depth + pref]), False), ref(build(keys, depth + pref, child_on_path))]
            if on_path:
                path_nodes_reverse.append(rlp.encode(node))
            return node
        branch = [b""] * 17
        chosen_nib = target_key[depth] if (on_path and depth < len(target_key)) else None
        for n in range(16):
            sub = [k for k in keys if len(k) > depth and k[depth] == n]
            if sub:
                branch[n] = ref(build(sub, depth + 1, on_path and n == chosen_nib))
        exact = [k for k in keys if len(k) == depth]
        if exact:
            branch[16] = items[exact[0]]
        if on_path:
            path_nodes_reverse.append(rlp.encode(branch))
        return branch

    keys = sorted(items.keys())
    root_node = build(keys, 0, True)
    root_hash = kec(rlp.encode(root_node))
    nodes = list(reversed(path_nodes_reverse))
    return root_hash, nodes
