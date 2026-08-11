#!/usr/bin/env python3
"""Real end-to-end x402 payment test: the funded client wallet pays for
GET /verify-receipt against the mainnet-deployed M7 service, via GoPlausible's
real facilitator -- not simulated, not mocked.
"""
import re

import msgpack
from algosdk import encoding, mnemonic
from algosdk.transaction import Transaction
from x402 import x402ClientSync
from x402.http.clients.requests import x402_requests
from x402.mechanisms.avm.exact.register import register_exact_avm_client

with open("/home/mark/eth-avm-verifier/service/x402_endpoint/.secrets/relayer_wallet.txt") as f:
    content = f.read()
CLIENT_ADDR = re.search(r"ADDRESS=(.+)", content).group(1).strip()
CLIENT_MN = re.search(r"MNEMONIC=(.+)", content).group(1).strip()
CLIENT_SK = mnemonic.to_private_key(CLIENT_MN)


class AlgorandSigner:
    def __init__(self, secret_key: bytes, address: str):
        self._secret_key = secret_key
        self._address = address

    @property
    def address(self) -> str:
        return self._address

    def sign_transactions(self, unsigned_txns: list[bytes], indexes_to_sign: list[int]):
        # `unsigned_txns[i]` are RAW msgpack bytes (confirmed live: algosdk's
        # own `encoding.msgpack_decode` expects a base64 STRING and fails
        # with "unpack received extra data" when handed raw bytes directly)
        # -- unpack with `msgpack` directly, reconstruct via `Transaction.
        # undictify`, sign, then re-pack as raw msgpack (algosdk's own
        # canonical rules: sorted keys, use_bin_type), no base64 wrapping.
        out = [None] * len(unsigned_txns)
        for i in indexes_to_sign:
            raw = unsigned_txns[i]
            decoded_dict = msgpack.unpackb(raw, raw=False)
            txn = Transaction.undictify(decoded_dict)
            signed = txn.sign(self._secret_key)
            sorted_dict = encoding._sort_dict(signed.dictify())
            out[i] = msgpack.packb(sorted_dict, use_bin_type=True)
        return out


signer = AlgorandSigner(CLIENT_SK, CLIENT_ADDR)
x402 = x402ClientSync()
register_exact_avm_client(x402, signer)
session = x402_requests(x402)

url = "https://eth-avm-light-client.vercel.app/verify-receipt/25691209/0/0"
print(f"paying client address: {CLIENT_ADDR}")
print(f"requesting: {url}")
resp = session.get(url, timeout=60)
print("status:", resp.status_code)
print("body:", resp.text[:2000])
