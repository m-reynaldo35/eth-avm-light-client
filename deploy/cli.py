"""§8.2: the `argparse` shell. Adds no logic of its own -- every verb calls
straight into `deploy.diff`/`deploy.schema.generate`/`deploy.manifest`/
`deploy.inspect` (§8.1: "the CLI is an argparse shell that adds no logic").
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


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

    if args.forks:
        # 012 §3.5 layer 1: decode the on-chain fork table through the
        # already-existing `_read_fork_rows` (deploy/plans/m4.py,
        # deploy/plans/m8.py) -- this flag is the only thing that was
        # missing to reach them from the CLI.
        if args.app == "m4":
            from deploy.plans.m4 import _read_fork_rows

            rows = _read_fork_rows(algod_client, app_id)
            decoded = [
                {
                    "activation_epoch": r[0], "fork_version": r[1].hex(),
                    "finality_gindex": r[2], "current_sc_gindex": r[3], "next_sc_gindex": r[4],
                }
                for r in rows
            ]
        elif args.app == "m8":
            from deploy.plans.m8 import _read_fork_rows

            rows = _read_fork_rows(algod_client, app_id)
            decoded = [
                {
                    "activation_epoch": r[0], "g_state_root": r[1], "g_receipts_root": r[2],
                    "g_block_number": r[3], "g_block_roots_base": r[4],
                }
                for r in rows
            ]
        else:
            print(f"--forks is only meaningful for m4/m8 (got --app {args.app!r})", file=sys.stderr)
            return 1
        print(json.dumps({"app_id": app_id, "fork_rows": decoded}, indent=2, sort_keys=True))
        return 0

    # §17 item 8 / §15.2 item 6: the default dump is human-facing, so
    # fork-row-family binary keys (2 raw bytes, invisible/unnamed) are
    # filtered out here -- they remain reachable via `--forks`.
    gs_raw = inspect_mod.decode_global_state_raw(algod_client, app_id)
    gs_raw = inspect_mod.filter_named_keys_raw(gs_raw)
    gs = {k.decode("utf-8", errors="replace"): v for k, v in gs_raw.items()}
    bal = inspect_mod.account_balance(algod_client, app_id)
    out = {"app_id": app_id, "global_state": {k: (v.hex() if isinstance(v, bytes) else v) for k, v in gs.items()},
           "balance": bal}
    if args.boxes:
        boxes = inspect_mod.list_boxes(algod_client, app_id)
        out["boxes"] = [b.hex() for b in boxes]
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def cmd_resolve(args):
    """012 §3.5: read-only, no signer. Loads `deploy/targets/<network>.json`
    (never a raw --target path -- `resolve` is the one verb whose whole
    point is that a stranger only needs to know a network NAME, not a file
    path into a checkout they may not have)."""
    from deploy.manifest import Manifest
    from deploy.resolve import VERDICT_CODE_MISMATCH, resolve

    target_path = Path(__file__).resolve().parent / "targets" / f"{args.network}.json"
    if not target_path.exists():
        print(f"no target file for network {args.network!r} ({target_path})", file=sys.stderr)
        return 1
    target = _load_target(target_path)
    algod_client = _algod_client(target)
    manifest = Manifest.load(target.network.genesis_id)

    versions_path = Path(__file__).resolve().parent / "versions.json"
    versions = json.loads(versions_path.read_text()) if versions_path.exists() else {"contracts": {}}

    result = resolve(target, manifest, versions, args.fork, algod_client)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for name, v in result["apps"].items():
            suffix = f" ({v['detail']})" if v.get("detail") else ""
            print(f"{name}: {v['verdict']}{suffix}")
        print(f"donors: issuer={result['donors']['issuer']} callee={result['donors']['callee']}")

    any_mismatch = any(v["verdict"] == VERDICT_CODE_MISMATCH for v in result["apps"].values())
    return 1 if any_mismatch else 0


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
    p = argparse.ArgumentParser(
        prog="python -m deploy",
        description=(
            "Source-checkout deployment tool for the ETH-AVM light client's Algorand "
            "contracts (docs/design/010-deployment-tooling.md). Not published as a wheel "
            "(docs/quickstart.md) -- needs a checkout, puyapy, and the 'contracts' extra."
        ),
        epilog=(
            "Every verb needs a reachable algod except 'resolve' and 'schema', which are "
            "also usable with no signer configured. See docs/operating.md for the full "
            "walkthrough and docs/versioning.md for what 'resolve' answers."
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    p_plan = sub.add_parser(
        "plan", help="show what 'apply' would do against --target, with no signer needed",
        description="Read-only: diffs --target's declared contracts against the manifest. Sends nothing.",
    )
    p_plan.add_argument("--target", required=True, help="path to a deploy/targets/*.json file")
    p_plan.set_defaults(func=cmd_plan)

    p_apply = sub.add_parser(
        "apply", help="deploy/converge the contracts declared in --target (idempotent)",
        description="Creates/updates every contract --target marks deploy=true. Re-running sends only the missing subset.",
    )
    p_apply.add_argument("--target", required=True, help="path to a deploy/targets/*.json file")
    p_apply.add_argument("--yes", action="store_true", help="acknowledge the governance==signer warning (§9.3)")
    p_apply.set_defaults(func=cmd_apply)

    p_verify = sub.add_parser(
        "verify", help="re-derive and check a deployment against its pinned approval hash, no signer",
        description="For each app in the manifest: re-hashes the live approval program and compares it to the pin.",
    )
    p_verify.add_argument("--target", required=True, help="path to a deploy/targets/*.json file")
    p_verify.set_defaults(func=cmd_verify)

    p_inspect = sub.add_parser(
        "inspect", help="decode a deployed app's real global state, boxes, or fork table",
        description="Public reads only (application_info/application_boxes) -- auditable by someone who did not deploy it.",
    )
    p_inspect.add_argument("--target", required=True, help="path to a deploy/targets/*.json file")
    p_inspect.add_argument("--app", required=True, choices=["m4", "m6", "m7", "m8", "donor_issuer", "donor_callee"],
                            help="which manifest entry to inspect")
    p_inspect.add_argument("--boxes", action="store_true", help="also list every box name (hex)")
    p_inspect.add_argument("--forks", action="store_true",
                            help="decode the on-chain fork table instead of global state (m4/m8 only, §3.5 layer 1)")
    p_inspect.add_argument("--json", action="store_true", help="unused -- output is always JSON; kept for symmetry")
    p_inspect.set_defaults(func=cmd_inspect)

    p_resolve = sub.add_parser(
        "resolve", help="which app id is usable for --network/--fork, and why (§3.5's three layers, tied together)",
        description=(
            "Read-only, no signer. Four verdicts: USABLE, NOT_DEPLOYED, FORK_UNSUPPORTED, "
            "CODE_MISMATCH (exits non-zero on any CODE_MISMATCH)."
        ),
    )
    p_resolve.add_argument("--network", required=True, choices=["mainnet", "testnet", "localnet"],
                            help="selects deploy/targets/<network>.json and its manifest")
    p_resolve.add_argument("--fork", required=True, help="e.g. deneb, electra, fulu, gloas")
    p_resolve.add_argument("--json", action="store_true", help="print the full structured result, not just verdicts")
    p_resolve.set_defaults(func=cmd_resolve)

    p_schema = sub.add_parser(
        "schema", help="(re)generate deploy/schema/*.json and deploy/versions.json from the contracts",
        description="Never hand-typed (§17 item 4) -- reads contracts/**/constants.py and the compiled-artifact caches.",
    )
    p_schema.add_argument("--check", action="store_true", help="fail (exit 1) if any generated artifact would differ")
    p_schema.set_defaults(func=cmd_schema)

    p_recover = sub.add_parser(
        "recover", help="rebuild a lost manifest by scanning a creator's apps for a pinned approval hash",
        description="No local state needed -- matches --creator's created-apps against --pinned-json's sha256 map.",
    )
    p_recover.add_argument("--creator", required=True, help="the deployer address to scan created-apps for")
    p_recover.add_argument("--algod-url", default="http://localhost:4051", help="algod to query (default: localnet)")
    p_recover.add_argument("--pinned-json", default=None, help='JSON string: {"contract_name": "sha256hex", ...}')
    p_recover.set_defaults(func=cmd_recover)

    p_fund = sub.add_parser(
        "fund", help="top up an already-deployed app's balance (e.g. before an M9 install session)",
        description="Explicit and separate from 'apply' by design (§5.2) -- funding a stage is an operator decision.",
    )
    p_fund.add_argument("--target", required=True, help="path to a deploy/targets/*.json file")
    p_fund.add_argument("--app", required=True, help="manifest entry to fund")
    p_fund.add_argument("--stage", choices=["install", "rollover"], default=None,
                         help="m4-only: a named funding recipe from §4.1's MBR table")
    p_fund.add_argument("--target-microalgo", type=int, default=None,
                         help="fund to exactly this balance (required unless --stage is given)")
    p_fund.set_defaults(func=cmd_fund)

    p_renounce = sub.add_parser(
        "renounce", help="PERMANENTLY remove governance from a TrustedRootAnchor deployment",
        description=(
            "Interactive only -- no --yes exists for this command. Prints the migration cost table, "
            "requires a typed app-id confirmation, then submits the real renounce() call."
        ),
    )
    p_renounce.add_argument("--app-id", type=int, required=True, help="the TrustedRootAnchor app id to renounce")
    p_renounce.add_argument("--target", required=False, default=None,
                             help="path to a deploy/targets/*.json file (required to actually submit)")
    p_renounce.set_defaults(func=cmd_renounce)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
