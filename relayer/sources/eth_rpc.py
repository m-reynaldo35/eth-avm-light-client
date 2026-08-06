"""§5.2: real Ethereum execution-layer JSON-RPC access. Promoted from
`service/x402_endpoint/eth_rpc.py` (43 lines, live-proven through the real
mainnet USDC x402 flow, `86a5e87`), extended with the methods M9 needs that
did not exist anywhere in this codebase before this pass: `eth_getProof`
(M6's account/storage proof -- confirmed by 009 §2.1 to have exactly one
prior hit in the whole repo, a frozen one-shot spike script) and
`eth_getTransactionReceipt` (a `tx_index` fast-path helper, §5.2's table).

Uses `relayer.sources.pool.EndpointPool` rather than a private retry loop
(§5.1) -- the default URL list is exactly the live-proven pool `eth_rpc.py`
shipped with.
"""
from __future__ import annotations

from relayer.sources.pool import EndpointPool

DEFAULT_RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://eth.merkle.io",
    "https://1rpc.io/eth",
    "https://eth-mainnet.public.blastapi.io",
]


def default_pool(urls: list[str] | None = None) -> EndpointPool:
    return EndpointPool(urls or DEFAULT_RPCS, headers={"User-Agent": "curl/8.0"})


def get_block_receipts(block_number: int, pool: EndpointPool | None = None) -> list[dict]:
    pool = pool or default_pool()
    return pool.post_json_rpc("eth_getBlockReceipts", [hex(block_number)])


def get_block_header(block_number: int | str, pool: EndpointPool | None = None) -> dict:
    """`block_number` may be an int block number or the string "latest"."""
    pool = pool or default_pool()
    tag = block_number if isinstance(block_number, str) else hex(block_number)
    return pool.post_json_rpc("eth_getBlockByNumber", [tag, False])


def get_transaction_receipt(tx_hash: str, pool: EndpointPool | None = None) -> dict:
    """New, trivial (§5.2 table) -- a `tx_index` fast path when a caller
    already has the transaction hash rather than only `(block, tx_index)`."""
    pool = pool or default_pool()
    return pool.post_json_rpc("eth_getTransactionReceipt", [tx_hash])


def get_proof(address: str, storage_keys: list[str], block_number: int | str,
              pool: EndpointPool | None = None) -> dict:
    """`eth_getProof(address, [storageKeys...], block)` -- §5.2, §6.2: the
    ONLY execution-layer RPC that produces a Merkle-Patricia account+
    storage proof. Returns the raw JSON-RPC result: `{"address":...,
    "accountProof":[...], "balance":..., "codeHash":..., "nonce":...,
    "storageHash":..., "storageProof":[{"key":...,"value":...,"proof":[...]}]}`.

    `storage_keys` should contain at most one 32-byte hex slot for M6's v1
    scope (§6.2 step 5's mapping-key helper produces exactly one). Passing
    zero keys is valid (an account-only proof)."""
    pool = pool or default_pool()
    tag = block_number if isinstance(block_number, str) else hex(block_number)
    return pool.post_json_rpc("eth_getProof", [address, list(storage_keys), tag])
