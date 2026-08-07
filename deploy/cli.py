"""§8.2: the `argparse` shell. Adds no logic of its own -- every verb calls
straight into `deploy.diff`/`deploy.schema.generate`/`deploy.manifest`/
`deploy.inspect` (§8.1: "the CLI is an argparse shell that adds no logic").
"""
from __future__ import annotations

import argparse
import json
import sys


def _algod_client(target):
    from algosdk.v2client import algod as algod_mod

    return algod_mod.AlgodClient(target.network.algod_token, target.network.algod_url)


def _load_target(path: str):
    from deploy.config import DeployTarget

    return DeployTarget.from_file(path)


def _funded_kmd_account():
    """localnet convenience only -- pulls the best-funded key out of
    dev-mode kmd's default wallet, mirroring every existing conftest in this
    repo. NOT used on testnet/mainnet (§6.3: signer comes from a mnemonic or
    external signer there)."""
    from algosdk import kmd as kmd_mod

    client = kmd_mod.KMDClient("a" * 64, "http://localhost:4052")
    wallets = client.list_wallets()
    wid = next(w["id"] for w in wallets if w["name"] == "unencrypted-default-wallet")
    handle = client.init_wallet_handle(wid, "")
    try:
        addrs = client.list_keys(handle)
        return addrs[0], client.export_key(handle, "", addrs[0])
    finally:
        client.release_wallet_handle(handle)


def cmd_plan(args):
    from deploy.diff import plan

    target = _load_target(args.target)
    algod_client = _algod_client(target)
    entries = plan(target, algod_client)
    for e in entries:
        print(f"{e.contract}: {e.status}" + (f" (app_id={e.app_id})" if e.app_id else ""))
    return 0


def cmd_apply(args):
    from deploy.diff import apply

    target = _load_target(args.target)
    algod_client = _algod_client(target)
    sender, sk = _funded_kmd_account()
    manifest = apply(target, algod_client, sender, sk, yes=args.yes)
    print(json.dumps(manifest.apps, indent=2, sort_keys=True))
    return 0


def cmd_verify(args):
    from deploy.diff import verify

    target = _load_target(args.target)
    algod_client = _algod_client(target)
    results = verify(target, algod_client)
    ok = True
    for name, r in results.items():
        print(f"{name}: {'OK' if r.ok else 'FAIL'}")
        for issue in r.issues:
            print(f"  - {issue}")
        ok = ok and r.ok
    return 0 if ok else 1


def cmd_inspect(args):
    from deploy import inspect as inspect_mod
    from deploy.manifest import Manifest

    target = _load_target(args.target)
    algod_client = _algod_client(target)
    manifest = Manifest.load(target.network.genesis_id)
    if manifest is None:
        print("no manifest found", file=sys.stderr)
        return 1
    entry = manifest.apps.get(args.app)
    if entry is None:
        print(f"no {args.app!r} entry in manifest", file=sys.stderr)
        return 1
    app_id = entry["app_id"]
    gs = inspect_mod.decode_global_state(algod_client, app_id)
    bal = inspect_mod.account_balance(algod_client, app_id)
    out = {"app_id": app_id, "global_state": {k: (v.hex() if isinstance(v, bytes) else v) for k, v in gs.items()},
           "balance": bal}
    if args.boxes:
        boxes = inspect_mod.list_boxes(algod_client, app_id)
        out["boxes"] = [b.hex() for b in boxes]
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def cmd_schema(args):
    from deploy.schema import generate

    if args.check:
        mismatches = generate.check()
        if mismatches:
            print(f"schema drift: {mismatches}", file=sys.stderr)
            return 1
        print("schema is up to date")
        return 0
    written = generate.write_all()
    for p in written:
        print(f"wrote {p}")
    return 0


def cmd_recover(args):
    from deploy.manifest import recover_by_approval_hash

    from algosdk.v2client import algod as algod_mod

    algod_client = algod_mod.AlgodClient("a" * 64, args.algod_url)
    pinned = json.loads(args.pinned_json) if args.pinned_json else {}
    candidates = recover_by_approval_hash(algod_client, args.creator, pinned)
    print(json.dumps(candidates, indent=2, sort_keys=True))
    return 0


def cmd_fund(args):
    from deploy.manifest import Manifest

    target = _load_target(args.target)
    algod_client = _algod_client(target)
    manifest = Manifest.load(target.network.genesis_id)
    sender, sk = _funded_kmd_account()
    entry = manifest.apps[args.app]
    if args.app == "m4" and args.stage:
        from deploy.plans.m4 import fund_for_install

        paid = fund_for_install(algod_client, sender, sk, entry["app_id"], stage=args.stage)
    else:
        from deploy.create import top_up

        if args.target_microalgo is None:
            print("--target-microalgo (or --stage for m4) is required", file=sys.stderr)
            return 1
        paid = top_up(algod_client, sender, sk, entry["app_id"], args.target_microalgo)
    print(f"paid {paid} microalgo")
    return 0


def cmd_renounce(args):
    """§6.5/§17 item 18/`O-M10-4`: interactive, never scripted -- there is no
    `--yes` for this one command, by design, and no other `deploy` verb ever
    calls this code path automatically. Prints the migration table BEFORE
    doing anything, requires a typed confirmation, and only THEN submits the
    real `renounce()` call -- 'interactive' means a human types the
    confirmation every time, not 'unimplemented'."""
    print(
        "renounce() removes governance from TrustedRootAnchor PERMANENTLY.\n"
        "Migration cost table (design doc §6.5):\n"
        "  - new fork              : free (append_fork_row still works... no, it does NOT: "
        "renounce() sets gov to the zero address, and append_fork_row/ring_init_chunk/freeze/"
        "unfreeze/gov_clear_conflict all require Txn.sender == gov, so EVERY governance action "
        "becomes permanently unreachable, including a future correct fork row.\n"
        "  - wrong row appended before renouncing: unfixable -- full redeploy required.\n"
        "This project's recommendation: do NOT renounce on a first deployment (§6.5).\n"
    )
    confirm = input("Type the app id to renounce, to confirm: ")
    if confirm != str(args.app_id):
        print("aborted (confirmation did not match)")
        return 1

    from algosdk.abi import Method
    from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer

    algod_client = _algod_client(_load_target(args.target)) if args.target else None
    if algod_client is None:
        print("--target is required to actually submit renounce()", file=sys.stderr)
        return 1
    sender, sk = _funded_kmd_account()
    method = Method.from_signature("renounce()void")
    atc = AtomicTransactionComposer()
    signer = AccountTransactionSigner(sk)
    sp = algod_client.suggested_params()
    sp.flat_fee = True
    sp.fee = 1000
    atc.add_method_call(app_id=args.app_id, method=method, sender=sender, sp=sp, signer=signer, method_args=[])
    result = atc.execute(algod_client, 4)
    print(f"renounce() submitted: {result.tx_ids}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m deploy")
    sub = p.add_subparsers(dest="command", required=True)

    p_plan = sub.add_parser("plan")
    p_plan.add_argument("--target", required=True)
    p_plan.set_defaults(func=cmd_plan)

    p_apply = sub.add_parser("apply")
    p_apply.add_argument("--target", required=True)
    p_apply.add_argument("--yes", action="store_true")
    p_apply.set_defaults(func=cmd_apply)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--target", required=True)
    p_verify.set_defaults(func=cmd_verify)

    p_inspect = sub.add_parser("inspect")
    p_inspect.add_argument("--target", required=True)
    p_inspect.add_argument("--app", required=True)
    p_inspect.add_argument("--boxes", action="store_true")
    p_inspect.add_argument("--json", action="store_true")
    p_inspect.set_defaults(func=cmd_inspect)

    p_schema = sub.add_parser("schema")
    p_schema.add_argument("--check", action="store_true")
    p_schema.set_defaults(func=cmd_schema)

    p_recover = sub.add_parser("recover")
    p_recover.add_argument("--creator", required=True)
    p_recover.add_argument("--algod-url", default="http://localhost:4051")
    p_recover.add_argument("--pinned-json", default=None)
    p_recover.set_defaults(func=cmd_recover)

    p_fund = sub.add_parser("fund")
    p_fund.add_argument("--target", required=True)
    p_fund.add_argument("--app", required=True)
    p_fund.add_argument("--stage", choices=["install", "rollover"], default=None)
    p_fund.add_argument("--target-microalgo", type=int, default=None)
    p_fund.set_defaults(func=cmd_fund)

    p_renounce = sub.add_parser("renounce")
    p_renounce.add_argument("--app-id", type=int, required=True)
    p_renounce.add_argument("--target", required=False, default=None)
    p_renounce.set_defaults(func=cmd_renounce)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
