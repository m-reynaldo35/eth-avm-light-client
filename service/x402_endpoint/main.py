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

Two verification routes, two different trust models, offered as an
explicit real choice rather than one silently swapped for the other
(EthAvmClient.prove_receipt's own S-1 rule refuses to let a SINGLE client
configured with m8_app_id ever fall back to the RPC-rooted path -- so this
module uses TWO SEPARATE client instances, one per route, rather than
fight that rule):

  * `/verify-receipt/...` -- the original T1+T2 path (against_anchor=False),
    `receipts_client` (no m8_app_id configured). Trusts the RPC's own
    receiptsRoot. 97.5% real receipt coverage (007's own measured figure).
  * `/verify-receipt-trustless/...` -- the M7+M8 combined path
    (against_anchor=True), `trustless_client` (m8_app_id AND
    m7_anchored_app_id configured). Verifies the receiptsRoot itself
    against a real, sync-committee-signed Algorand anchor -- zero RPC
    trust. Both T1 and T2 leaves (97.5% real receipt coverage, same as the
    RPC-trusted route -- 93.7% was T1-only, before this migration folded T2
    in), driven against the permanent, deployed `Mpt7AnchoredReceiptApp`
    (docs/design/014-t2-against-anchor.md, this migration closing §4.1's
    deferred T1 case) rather than a per-call compiled probe -- and only
    for a block ALREADY anchored in M8's ring
    (this route does not anchor on demand -- `/keeper/run` below is what
    keeps the ring fresh).

`/keeper/run` -- a Vercel Cron-triggered route (see vercel.json's `crons`)
that periodically calls `sync(update=True)` then `anchor("latest")` with a
dedicated, minimal-privilege signer (`KEEPER_MNEMONIC`) -- never the
governance key, since neither call is governance-gated (both are
cryptographically self-verifying; a compromised keeper key can waste its
own ALGO on rejected calls but cannot move funds, corrupt the fork table,
or touch governance). Guarded by Vercel's own `CRON_SECRET` convention
(a Bearer token Vercel injects automatically on real cron-triggered
requests) so arbitrary internet traffic cannot trigger it and burn the
keeper's balance on RPC/beacon calls.
"""
import hmac
import os

from fastapi import FastAPI, Header, HTTPException, Request

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
M4_APP_ID = int(os.environ["M4_APP_ID"]) if os.environ.get("M4_APP_ID") else None
M8_APP_ID = int(os.environ["M8_APP_ID"]) if os.environ.get("M8_APP_ID") else None
PAY_TO_ADDRESS = os.environ["PAY_TO_ADDRESS"]
FACILITATOR_URL = os.environ.get("FACILITATOR_URL", "https://facilitator.goplausible.xyz")
NETWORK = os.environ.get("X402_NETWORK", "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=")  # testnet default
PRICE_MICRO_USDC = int(os.environ.get("PRICE_MICRO_USDC", "10000"))  # $0.01
CRON_SECRET = os.environ.get("CRON_SECRET")  # unset => /keeper/run always refuses (fail closed)
KEEPER_MNEMONIC = os.environ.get("KEEPER_MNEMONIC")  # unset => /keeper/run always refuses

# `receipts_client`: the original route's client -- m8_app_id deliberately
# NEVER set here, even though M8_APP_ID may be configured for the OTHER
# route, so this client keeps taking the against_anchor=False path (S-1
# only fires per-client, and this client's own config simply doesn't
# mention m8 at all).
_base_config = RelayerConfig.from_env()
_base_config.m7_app_id = M7_APP_ID
_base_config.m8_app_id = None
receipts_client = EthAvmClient(_base_config)

# `trustless_client`: same signer and donor pair, m8_app_id configured --
# every call through this client MUST pass against_anchor=True (S-1
# enforces this). m7_anchored_app_id comes from `RelayerConfig.from_env()`
# above (M7_ANCHORED_APP_ID env var) and is never cleared here, unlike
# m8_app_id on `receipts_client` -- both T1 and T2 against_anchor calls
# need it (prove_receipt's own m7_anchored_app_id-required check).
trustless_client = None
if M8_APP_ID is not None:
    _trustless_config = RelayerConfig.from_env()
    _trustless_config.m7_app_id = M7_APP_ID
    _trustless_config.m4_app_id = M4_APP_ID
    _trustless_config.m8_app_id = M8_APP_ID
    trustless_client = EthAvmClient(_trustless_config)

usdc_asset = USDC_MAINNET_ASA_ID if "wGHE2Pwd" in NETWORK else USDC_TESTNET_ASA_ID

facilitator = HTTPFacilitatorClient(FacilitatorConfig(url=FACILITATOR_URL))
server = x402ResourceServer(facilitator)
server.register(NETWORK, ExactAvmServerScheme())

_price = PaymentOption(
    scheme="exact",
    pay_to=PAY_TO_ADDRESS,
    price=AssetAmount(amount=str(PRICE_MICRO_USDC), asset=str(usdc_asset), extra={"name": "USDC", "decimals": 6}),
    network=NETWORK,
)

routes = {
    "GET /verify-receipt/*": RouteConfig(
        accepts=_price,
        mime_type="application/json",
        description="Verify an Ethereum receipt/log's inclusion via a real Algorand transaction "
                     "against M7 (docs/design/007-receipt-log-proof.md), T1+T2, RPC-trusted receiptsRoot.",
    ),
    "GET /verify-receipt-trustless/*": RouteConfig(
        accepts=_price,
        mime_type="application/json",
        description="Verify an Ethereum receipt/log's inclusion AND the receiptsRoot itself, against a "
                     "real sync-committee-signed Algorand anchor (docs/design/008-trusted-root-anchor.md) "
                     "-- zero RPC trust. T1-only; the block must already be anchored (see /keeper/run).",
    ),
}

app = FastAPI(title="ETH-AVM Receipt Proof Service")
app.add_middleware(PaymentMiddlewareASGI, routes=routes, server=server)


@app.get("/verify-receipt/{block_number}/{tx_index}/{log_index}")
async def verify_receipt(block_number: int, tx_index: int, log_index: int, request: Request):
    try:
        result = receipts_client.prove_receipt(block_number, tx_index, log_index, against_anchor=False)
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
        "trust_model": "rpc-trusted-receiptsRoot",
        "verified_by": f"Algorand app {M7_APP_ID}, round {result.confirmed_round}",
        "result": result.fields,
    }


@app.get("/verify-receipt-trustless/{block_number}/{tx_index}/{log_index}")
async def verify_receipt_trustless(block_number: int, tx_index: int, log_index: int, request: Request):
    if trustless_client is None:
        raise HTTPException(status_code=503, detail="trustless verification not configured (M8_APP_ID unset)")
    try:
        result = trustless_client.prove_receipt(block_number, tx_index, log_index, against_anchor=True)
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
        "trust_model": "sync-committee-anchored",
        "verified_by": f"Algorand apps m7={M7_APP_ID} m8={M8_APP_ID}, round {result.confirmed_round}",
        "result": result.fields,
    }


@app.get("/keeper/run")
async def keeper_run(authorization: str = Header(default="")):
    if not CRON_SECRET or not KEEPER_MNEMONIC:
        raise HTTPException(status_code=503, detail="keeper not configured (CRON_SECRET/KEEPER_MNEMONIC unset)")
    expected = f"Bearer {CRON_SECRET}"
    if not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="unauthorized")
    if M4_APP_ID is None or M8_APP_ID is None:
        raise HTTPException(status_code=503, detail="keeper needs M4_APP_ID and M8_APP_ID configured")

    keeper_config = RelayerConfig.from_env()
    keeper_config.m4_app_id = M4_APP_ID
    keeper_config.m8_app_id = M8_APP_ID
    keeper_config.m7_app_id = M7_APP_ID
    keeper_config.signer_mnemonic = KEEPER_MNEMONIC
    keeper_client = EthAvmClient(keeper_config)

    out = {}
    try:
        out["sync"] = keeper_client.sync(install=False, update=True).detail
    except Exception as e:  # noqa: BLE001 -- a keeper tick failing must not 500-crash the cron; report it
        out["sync_error"] = str(e)
    try:
        anchor_result = keeper_client.anchor("latest")
        out["anchor"] = {"ok": anchor_result.ok, "mode": anchor_result.mode, "record": anchor_result.record}
    except Exception as e:  # noqa: BLE001
        out["anchor_error"] = str(e)
    return out


@app.get("/health")
async def health():
    status = receipts_client.algod.status()
    return {
        "algod_round": status.get("last-round"),
        "m7_app_id": M7_APP_ID,
        "m4_app_id": M4_APP_ID,
        "m8_app_id": M8_APP_ID,
        "trustless_configured": trustless_client is not None,
        "keeper_configured": bool(CRON_SECRET and KEEPER_MNEMONIC),
    }
