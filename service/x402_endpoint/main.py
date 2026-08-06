"""M7 receipt-proof-as-a-service: a real x402-gated FastAPI endpoint.

GET /verify-receipt/{block_number}/{tx_index}/{log_index} -- pay, and get
back a real, on-chain-verified answer to "is log `log_index` of the receipt
at `tx_index` in block `block_number` really in Ethereum's receipts trie,
and what does it say" -- verified by a live Algorand transaction against
the deployed Mpt7ReceiptApp, not just trusted from the RPC response.

Post-M9 (docs/design/009-relayer-client.md §2.3, §17): this is the ONLY
`.py` module left in this directory besides config -- `eth_rpc.py`,
`eth_beacon_rpc.py`, `trie_proof.py` and `m7_relayer.py` all moved to
`relayer/`. The dependency is INVERTED, not merged: this service is a
separately-deployed artifact (Vercel, its own `requirements.txt` pulling
`fastapi`/`x402-avm`) that now IMPORTS `relayer` as a library, exactly as
M10/M11/an operator's own script would -- it does not hand-roll its own
RPC/trie/group-assembly logic any more.

Configuration is environment-variable driven (see .env.example in this
directory) -- nothing here is hardcoded to one network.

Honest, documented gap (TP-M7-2, unchanged from the design doc, and from
`EthAvmClient.prove_receipt`'s own docstring): this route calls
`against_anchor=False` (an m8_app_id is not configured here), so it still
trusts the `receiptsRoot` it reads out of the RPC's own block header
response -- not yet anchored on-chain via a trustless consensus proof. Once
an `M8_APP_ID` is configured, `EthAvmClient.prove_receipt`'s own §11/S-1
refusal (docs/design/009 §11) means this route would need
`against_anchor=True`, whose real submission wiring is itself a named,
open gap this pass leaves (ROADMAP.md's M9 row) -- not silently patched
around here.
"""
import os

from fastapi import FastAPI, HTTPException, Request

from x402.http import FacilitatorConfig, HTTPFacilitatorClient, PaymentOption
from x402.http.middleware.fastapi import PaymentMiddlewareASGI
from x402.http.types import RouteConfig
from x402.mechanisms.avm import USDC_MAINNET_ASA_ID, USDC_TESTNET_ASA_ID
from x402.mechanisms.avm.exact import ExactAvmServerScheme
from x402.schemas import AssetAmount
from x402.server import x402ResourceServer

from relayer.client import EthAvmClient
from relayer.config import RelayerConfig
from relayer.drivers.m7_receipt import M7Error
from relayer.errors import RelayerError, TierUnsupported

# ---- config (env-driven, see the module docstring) ----
M7_APP_ID = int(os.environ["M7_APP_ID"])
PAY_TO_ADDRESS = os.environ["PAY_TO_ADDRESS"]
FACILITATOR_URL = os.environ.get("FACILITATOR_URL", "https://facilitator.goplausible.xyz")
NETWORK = os.environ.get("X402_NETWORK", "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=")  # testnet default
PRICE_MICRO_USDC = int(os.environ.get("PRICE_MICRO_USDC", "10000"))  # $0.01

relayer_config = RelayerConfig.from_env()
relayer_config.m7_app_id = M7_APP_ID
client = EthAvmClient(relayer_config)

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
                     "against M7 (docs/design/007-receipt-log-proof.md), T1 direct-AVM path.",
    ),
}

app = FastAPI(title="ETH-AVM Receipt Proof Service")
app.add_middleware(PaymentMiddlewareASGI, routes=routes, server=server)


@app.get("/verify-receipt/{block_number}/{tx_index}/{log_index}")
async def verify_receipt(block_number: int, tx_index: int, log_index: int, request: Request):
    try:
        result = client.prove_receipt(block_number, tx_index, log_index, against_anchor=False)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"tx_index {tx_index} not in block {block_number}")
    except TierUnsupported as e:
        raise HTTPException(status_code=501, detail=str(e))
    except (M7Error, RelayerError) as e:
        raise HTTPException(status_code=500, detail=str(e))
    except AssertionError as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "block_number": block_number,
        "verified_by": f"Algorand app {M7_APP_ID}, round {result.confirmed_round}",
        "result": result.fields,
    }


@app.get("/health")
async def health():
    status = client.algod.status()
    return {"algod_round": status.get("last-round"), "m7_app_id": M7_APP_ID}
