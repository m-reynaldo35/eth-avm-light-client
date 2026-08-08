# Quickstart

Two install paths, because they genuinely give you different capabilities
(see [`docs/security.md`](./security.md) and
[`docs/design/012-docs-packaging-release.md`](./design/012-docs-packaging-release.md)
§4.2 for why).

## Path 1 — the wheel (client only)

```
pip install eth-avm-relayer
eth-avm-relayer status
# equivalently, if you prefer:
python -m relayer status
```

Both invocations work identically — `eth-avm-relayer` is a console-script
entry point (`relayer.cli:main`) and `python -m relayer` is
`relayer/__main__.py`, a two-line mirror of `deploy/__main__.py`. `status`
needs no signer and reads M4/M8's currently-anchored state from whichever
deployment `RelayerConfig` points at (by default, the environment-variable
convention `RelayerConfig.from_env()` reads; see `relayer/config.py`).

**What works from a wheel**: `status`, `sync`, `anchor`,
`prove receipt` (without `--against-anchor`), `prove account`. None of
these touch `contracts/`.

**What does not work from a wheel, and why**: `prove receipt --against-anchor`
and deploying the donor pair (`relayer.group.donors.deploy_donor_pair`)
both need to compile a small on-demand probe contract against
`contracts/state_anchor/bench_app.py` / `contracts/sync_committee/bench_app.py`,
which are not in the wheel (only `relayer/` ships — 35 `.py` files, zero
data files, measured). Reaching either of these from a wheel-only install
raises a named `relayer.errors.MissingContractsSource` — never a bare
`FileNotFoundError` — pointing back at this page.

## Path 2 — a checkout (contracts, `deploy/`, and the two verbs above)

```
git clone https://github.com/m-reynaldo35/eth-avm-light-client
cd eth-avm-light-client
pip install -e ".[test,contracts]"
```

The `contracts` extra pins `puyapy==5.9.0` **exactly**. Do not run
`pip install puya` — it is a real trap this project hit once (007 §14.6):
that fetches a **different, incompatible** package with a similar name,
not the Puya compiler. If `python -m puyapy --version` doesn't print
`5.9.0`, you have the wrong thing installed.

From a checkout, both CLIs are real and documented:

```
python -m relayer --help
python -m deploy --help
```

Every verb printed in `relayer/cli.py`'s and `relayer/__init__.py`'s own
module docstrings actually parses and runs — this is asserted mechanically
(`tests/harness/test_packaging.py`, Suite W, W-7).

## The `service` extra

`pip install -e ".[service]"` installs `fastapi`, `uvicorn[standard]`, and
`x402-avm[fastapi,avm]` — `service/x402_endpoint/`'s own dependencies, not
`relayer/`'s. `relayer/` imports none of them, and an AST-based test
(`tests/relayer/test_security.py`) enforces that. You need this extra only
if you are running `service/x402_endpoint/` yourself, not to use the
relayer or the deploy tool.

## What "quickstart" does not mean here

This is **not** a deployment quickstart. Deploying M4/M8/M6/M7 from
scratch needs a checkout, `puyapy`, a funded signer, and (for a public
network) a faucet or real ALGO — see [`docs/operating.md`](./operating.md)
for that walkthrough. "Quickstart" here means the first command a new
reader can run against an **existing** deployment, per 009 §15.4's own
framing, with no signer and no risk.
