"""M7 receipt-proof-as-a-service: a real x402-gated FastAPI endpoint.

GET /verify-receipt/{block_number}/{tx_index}/{log_index} -- pay, and get
back a real, on-chain-verified answer to "is log `log_index` of the receipt
at `tx_index` in block `block_number` really in Ethereum's receipts trie,
and what does it say" -- verified by a live Algorand transaction against
the deployed Mpt7ReceiptApp, not just trusted from the RPC response.

Configuration is environment-variable driven (see .env.example in this
directory) -- nothing here is hardcoded to one network, matching how this
project moved from local dev-mode algod to real AWS-hosted proving earlier:
the same code path should run against local devnet, testnet, or mainnet by
changing config, not code.

Honest, documented gap (TP-M7-2, unchanged from the design doc): M8
("Trusted-root anchor contract") does not exist yet, so this service trusts
the `receiptsRoot` it reads out of the RPC's own block header response --
it is NOT yet anchored on-chain via a trustless consensus proof. This is the
same gap the design doc has always named, not a new one this service
introduces.
"""
import os

from algosdk import account, mnemonic
from algosdk.v2client import algod
from fastapi import FastAPI, HTTPException, Request

from x402.http import FacilitatorConfig, HTTPFacilitatorClient, PaymentOption
from x402.http.middleware.fastapi import PaymentMiddlewareASGI
from x402.http.types import RouteConfig
from x402.mechanisms.avm import ALGORAND_MAINNET_CAIP2, USDC_MAINNET_ASA_ID, USDC_TESTNET_ASA_ID
from x402.mechanisms.avm.exact import ExactAvmServerScheme
from x402.schemas import AssetAmount
from x402.server import x402ResourceServer

from eth_rpc import get_block_header, get_block_receipts
from m7_relayer import M7Error, prove_receipt
from trie_proof import build_receipts_trie_and_path

# ---- config (env-driven, see the module docstring) ----
ALGOD_URL = os.environ.get("ALGOD_URL", "http://localhost:4051")
ALGOD_TOKEN = os.environ.get("ALGOD_TOKEN", "a" * 64)
M7_APP_ID = int(os.environ["M7_APP_ID"])
RELAYER_MNEMONIC = os.environ["RELAYER_MNEMONIC"]
PAY_TO_ADDRESS = os.environ["PAY_TO_ADDRESS"]
FACILITATOR_URL = os.environ.get("FACILITATOR_URL", "https://facilitator.goplausible.xyz")
NETWORK = os.environ.get("X402_NETWORK", "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=")  # testnet default
PRICE_MICRO_USDC = int(os.environ.get("PRICE_MICRO_USDC", "10000"))  # $0.01

ac = algod.AlgodClient(ALGOD_TOKEN, ALGOD_URL)
relayer_sk = mnemonic.to_private_key(RELAYER_MNEMONIC)
relayer_addr = account.address_from_private_key(relayer_sk)

usdc_asset = USDC_MAINNET_ASA_ID if "wGHE2Pwd" in NETWORK else USDC_TESTNET_ASA_ID

facilitator = HTTPFacilitatorClient(FacilitatorConfig(url=FACILITATOR_URL))
server = x402ResourceServer(facilitator)
server.register(NETWORK, ExactAvmServerScheme())

routes = {
    "GET /verify-receipt/*": RouteConfig(
        accepts=PaymentOption(
            scheme="exact",
            pay_to=PAY_TO_ADDRESS,
            price=AssetAmount(amount=str(PRICE_MICRO_USDC), asset=str(usdc_asset),
                               extra={"name": "USDC", "decimals": 6}),
            network=NETWORK,
        ),
        mime_type="application/json",
        description="Verify an Ethereum receipt/log's inclusion via a real Algorand transaction "
                     "against M7 (docs/design/007-receipt-log-proof.md), T1/T2 direct-AVM path.",
    ),
}

app = FastAPI(title="ETH-AVM Receipt Proof Service")
app.add_middleware(PaymentMiddlewareASGI, routes=routes, server=server)


@app.get("/verify-receipt/{block_number}/{tx_index}/{log_index}")
async def verify_receipt(block_number: int, tx_index: int, log_index: int, request: Request):
    try:
        header = get_block_header(block_number)
        receipts = get_block_receipts(block_number)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Ethereum RPC error: {e}")

    receipts_root_hex = header["receiptsRoot"]
    try:
        root_hash, nodes = build_receipts_trie_and_path(receipts, tx_index)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"tx_index {tx_index} not in block {block_number}")

    if "0x" + root_hash.hex() != receipts_root_hex:
        # would mean OUR reconstruction disagrees with the RPC's own header --
        # a real integrity problem, not a normal error path.
        raise HTTPException(status_code=500,
                             detail="reconstructed receiptsRoot does not match the RPC block header")

    try:
        result = prove_receipt(ac, M7_APP_ID, relayer_addr, relayer_sk,
                                root_hash, tx_index, log_index, nodes)
    except M7Error as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "block_number": block_number,
        "receipts_root": receipts_root_hex,
        "verified_by": f"Algorand app {M7_APP_ID}, round {result['confirmed_round']}",
        "result": result,
    }


@app.get("/health")
async def health():
    status = ac.status()
    return {"algod_round": status.get("last-round"), "m7_app_id": M7_APP_ID}
