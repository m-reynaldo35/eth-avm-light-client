"""Real Ethereum RPC access -- reused pattern from
tests/fixtures/spike-reference/pull_eth_data.py and sample_coverage.py: a
small pool of public endpoints, retried, with a User-Agent header (several
public endpoints 403 the default urllib UA)."""
import json
import time
import urllib.request

RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://eth.merkle.io",
    "https://1rpc.io/eth",
    "https://eth-mainnet.public.blastapi.io",
]
HEADERS = {"content-type": "application/json", "User-Agent": "curl/8.0"}


def rpc(method: str, params: list, tries: int = 4):
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    last = None
    for _attempt in range(tries):
        for url in RPCS:
            try:
                req = urllib.request.Request(url, data=payload, headers=HEADERS)
                with urllib.request.urlopen(req, timeout=20) as resp:
                    d = json.load(resp)
                if "result" in d and d["result"] is not None:
                    return d["result"]
                last = d
            except Exception as e:  # noqa: BLE001 -- real network call, real fallback
                last = str(e)
            time.sleep(0.15)
        time.sleep(1.0)
    raise RuntimeError(f"all Ethereum RPC endpoints failed for {method}: {last}")


def get_block_receipts(block_number: int) -> list[dict]:
    return rpc("eth_getBlockReceipts", [hex(block_number)])


def get_block_header(block_number: int) -> dict:
    return rpc("eth_getBlockByNumber", [hex(block_number), False])
