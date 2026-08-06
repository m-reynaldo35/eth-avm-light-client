"""ETH-AVM off-chain relayer/client (M9, docs/design/009-relayer-client.md).

A library (`EthAvmClient`, `relayer/client.py`) with a thin CLI shell
(`python -m relayer ...`, `relayer/cli.py`) over it. Fetches real Ethereum
execution/consensus-layer data, assembles the exact proof shapes M4/M6/M7/M8
verify, plans real Algorand atomic groups against the real, measured AVM
caps (§7), and submits/decodes results.

Dependency rules (§4.3, enforced by `tests/relayer/test_security.py`'s
G8-M9 import-graph test):
  * `relayer/` as a whole MUST NOT import `tests.*`, `algopy`, `fastapi`,
    `x402`, or `pytest`.
  * `relayer/sources/`, `relayer/codec/`, `relayer/ssz/`, `relayer/proofs/`
    MUST NOT import `algosdk` -- they are pure, bytes-in/bytes-out, and
    therefore testable fully offline.
  * Only `relayer/group/`, `relayer/drivers/`, `relayer/client.py` and
    `relayer/cli.py` touch `algosdk` or a live algod.
"""

from __future__ import annotations

__all__ = ["__version__"]
__version__ = "0.1.0"
