"""Thin `argparse` shell over `EthAvmClient` (design doc §8.1/§8.4). Adds
no logic of its own -- anything the CLI can do, the library can do; the
CLI never reaches past `EthAvmClient`.

    python -m relayer status
    python -m relayer sync [--install] [--update]
    python -m relayer anchor --block latest|N [--mode auto|direct|historical]
    python -m relayer prove account --address 0x... --slot 0x... [--block N]
    python -m relayer prove receipt --block N --tx-index I --log-index L [--against-anchor]

Global flags: `--dry-run`, `--json`, `--config`. §18 item 16: every verb
must work with no signer configured (`RelayerConfig(signer_mnemonic=None)`),
up to and including the second `simulate` -- this is the CI/audit path.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from relayer.client import EthAvmClient
from relayer.config import RelayerConfig
from relayer.errors import RelayerError, Retryability


def _as_dict(obj) -> dict:
    if dataclasses.is_dataclass(obj):
        return {k: _as_dict(v) for k, v in dataclasses.asdict(obj).items()}
    return obj


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="relayer")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--config", type=Path, default=None)
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--verbose", action="store_true")

    sub = p.add_subparsers(dest="verb", required=True)
    sub.add_parser("status")

    sync_p = sub.add_parser("sync")
    sync_p.add_argument("--bootstrap-root")
    sync_p.add_argument("--install", action="store_true")
    sync_p.add_argument("--update", action="store_true")

    anchor_p = sub.add_parser("anchor")
    anchor_p.add_argument("--block", default="latest")
    anchor_p.add_argument("--mode", default="auto", choices=["auto", "direct", "historical"])

    prove_p = sub.add_parser("prove")
    prove_sub = prove_p.add_subparsers(dest="prove_kind", required=True)
    acc_p = prove_sub.add_parser("account")
    acc_p.add_argument("--address", required=True)
    acc_p.add_argument("--slot", required=True)
    acc_p.add_argument("--block", default="latest")
    rcpt_p = prove_sub.add_parser("receipt")
    rcpt_p.add_argument("--block", type=int, required=True)
    rcpt_p.add_argument("--tx-index", type=int, required=True)
    rcpt_p.add_argument("--log-index", type=int, required=True)
    rcpt_p.add_argument("--against-anchor", action="store_true")

    sub.add_parser("plan")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = RelayerConfig.from_file(args.config) if args.config else RelayerConfig.from_env()
    client = EthAvmClient(config)

    try:
        return _dispatch(client, args)
    except RelayerError as e:
        # §8.5's taxonomy, §18 item 10: PAGE_A_HUMAN (M8's N20 equivocation
        # latch) must exit non-zero and LOUDLY -- never silently retried.
        # FATAL conditions (outside window, T3 tier, N13 revoked) are also
        # surfaced here rather than swallowed. Exit code encodes the class
        # so a calling script (M10/M11) can branch without parsing text.
        code = {
            Retryability.RETRY_NOW: 3,
            Retryability.RETRY_REPLANNED: 4,
            Retryability.FATAL: 5,
            Retryability.PAGE_A_HUMAN: 9,
        }[e.retryability]
        print(f"[{e.retryability.name}] {e}", file=sys.stderr)
        return code


def _dispatch(client: EthAvmClient, args) -> int:
    if args.verb == "status":
        result = client.status()
    elif args.verb == "sync":
        result = client.sync(install=args.install, update=args.update)
    elif args.verb == "anchor":
        block = args.block if args.block == "latest" else int(args.block)
        result = client.anchor(block, mode=args.mode, dry_run=args.dry_run)
    elif args.verb == "prove" and args.prove_kind == "account":
        block = args.block if args.block == "latest" else int(args.block)
        result = client.prove_account(args.address, args.slot, block)
    elif args.verb == "prove" and args.prove_kind == "receipt":
        result = client.prove_receipt(args.block, args.tx_index, args.log_index, against_anchor=args.against_anchor)
    else:  # pragma: no cover - argparse already enforces valid verbs
        raise SystemExit(2)

    if args.json:
        print(json.dumps(_as_dict(result), default=str, indent=2))
    else:
        print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
