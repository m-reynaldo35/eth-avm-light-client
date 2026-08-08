# Operating `deploy/`

`deploy/` is a **source-checkout tool**, deliberately not published as a
wheel (`docs/design/012-docs-packaging-release.md` §4.2) — it shells out to
`puyapy` and imports `contracts/**` at module scope, both of which 010 §8.1
says a relayer running on an operator's laptop must not require. This page
walks it end to end: targets, the five main verbs, the funding recipe's
real numbers, the governance warnings, and the migration table for when a
redeploy is unavoidable.

`deploy/` is this project's **one trusted component** (010 §1.3) — it runs
real governance calls with a real signer. Read
[`docs/security.md`](./security.md) before running anything against a
network that holds value.

## Targets

`deploy/targets/{localnet,testnet,mainnet}.json` declare, per network: the
algod endpoint, the genesis hash (used to refuse acting against the wrong
network, G7-M10), the governance address, which contracts to deploy, and
the Ethereum fork list. **`governance` is required and never defaults to
the deployer's own key** (§9.3) — a missing `governance` field is a hard
`TargetConfigError`, not a silent default.

`deploy/targets/mainnet.json` declares `"deploy": false` for M4, M8, M6,
and M7 — this release deploys nothing new to mainnet (§1.2 non-goal 1). The
only mainnet apps this repository claims anything about are the ones
already recorded in `deploy/manifests/mainnet-v1.0.json` (M7 and the donor
pair).

## The verbs

```
python -m deploy plan     --target <target.json>                  # read-only, no signer needed
python -m deploy apply    --target <target.json> [--yes]          # create/converge, idempotent
python -m deploy verify   --target <target.json>                  # read-only, no signer needed
python -m deploy inspect  --target <target.json> --app m8 [--boxes] [--forks]
python -m deploy resolve  --network mainnet --fork fulu [--json]  # read-only, no signer needed
python -m deploy schema   [--check]                                # regenerate/diff schemas + versions.json
python -m deploy fund     --target <target.json> --app m4 --stage install|rollover
python -m deploy recover  --creator <address> [--pinned-json <json>]
python -m deploy renounce --app-id <id> [--target <target.json>]   # interactive, never scripted
```

`plan`, `verify`, and `resolve` all run with **no signer configured** and
send nothing — this is the audit path anyone can run against a public
deployment, per 010 §1.3 mitigation 3's whole argument that a deployment
nobody can independently check is worse than one whose procedure is
public.

`apply` is **idempotent**: re-running it against an already-deployed stack
sends zero transactions (confirmed live, by an unchanged
`algod.status()['last-round']` before/after). It refuses to proceed — before
sending anything — if the connected algod's genesis hash does not match
the target file's, or if `governance == signer` and `--yes` was not passed
(next section).

`deploy resolve` is the newest verb (§3.5 of the design doc): it ties the
chain (the on-chain fork table), the pinned `code_id` (the code window),
and the manifest (which app id is ours) together into one of four
verdicts — see [`docs/versioning.md`](./versioning.md) for the full
explanation and worked examples against real mainnet.

## Governance warnings (§9.3)

`apply` **warns loudly, and refuses without `--yes`**, if the target's
`governance` address equals the signer's own address:

> `governance == signer` — a compromised signer key can freeze/revoke/
> renounce governance outright. This is accepted only with `--yes`.

This is not a formality: `TrustedRootAnchor`'s governance controls fork-row
appends, ring initialization, freeze/unfreeze, and — if ever
called — permanent renunciation. Use a multisig or hardware signer for
`governance` on any network holding real value; `O-M10-3` names this as a
precondition this project does not waive for a mainnet deployment of M4/M8.

## The funding recipe — real numbers, `ring_n = 128`

| step | txns | µALGO (fees) |
|---|---:|---:|
| M4: fund + create + 3 fork rows | 5 | 5,000 |
| M4: top-up to install level | 1 | 1,000 |
| M8: fund + create + `ring_init_chunk` ×16 + 3 fork rows + top-up | 22 | 22,000 |
| M7: create + optional T2 float payment | 2 | 2,000 |
| M6: create | 1 | 1,000 |
| Donor pair: 2 creates | 2 | 2,000 |
| **Total fees** | **33** | **≈ 0.033 ALGO** |

MBR (the real cost — fees are noise by comparison):

| account | item | µALGO |
|---|---|---:|
| creator | M4 global state (13 ints, 7 bytes) | 820,500 |
| creator | M8 global state (9 ints, 1 byte) | 406,500 |
| M4 app | base + `forks` box | 334,900 |
| M4 app | 8 key boxes + aggregate, one generation | 19,760,900 |
| M8 app | base + `forks8` box | 232,900 |
| M8 app | ring at N=128 | 8,716,800 |
| M7 app | base | 100,000 |
| M7 app | T2 float (worst-case 4,096 B leaf) | 1,644,100 |
| M6 app | base | 100,000 |
| donors | 2 × base | 200,000 |
| | **total locked (N=128)** | **≈ 32.3 ALGO** |
| | **total locked (N=8, test scale)** | **≈ 24.1 ALGO** |

**Box MBR on these contracts is not recoverable.** Every µALGO sent to a
box-holding app account is spent, not lent — there is no deleter for the
`forks`/`forks8`/ring box families. On a test network that is free. **On
mainnet it is real ALGO, permanently locked; treat this line as load-bearing,
not a footnote, before funding a mainnet deployment.**

The app-id-prediction race (the only genuinely non-idempotent step,
`create()`) is bounded, not eliminated: `apply` simulates the create
unfunded first (`allow_empty_signatures=True`), reads the exact MBR
requirement and predicted app id back from the simulation's own error
message, funds precisely that address, and refuses to proceed if the real
create lands at a different id than predicted. Measured worst-case loss on
a lost race: **0.2329–0.3349 ALGO**, permanently — down from an unbounded
~45 ALGO under the old probe-app convention, and it works with no signer
for the prediction step.

## Migration — what a redeploy actually costs

| trigger | what must redeploy | why |
|---|---|---|
| New Ethereum fork (ordinary case) | nothing — `append_fork_row` on the affected table | Both tables are append-only, capacity 16 (M4) / 8 (M8) |
| Fork table full | M8 (or M4) **and every consumer** | No row deleter, no capacity change without a code change |
| A wrong row was appended | M8 (or M4) **and every consumer** | Append-only; a row cannot be edited or removed |
| `ring_n` change | M8 **and every consumer** | Write-once; changing it silently remaps every residue |
| `renounce()` then a later fork | M8 **and every consumer** | Renouncing freezes the fork table permanently |
| M4 contract bugfix | M4, M8 (write-once `m4_app_id`), **and every consumer** | Cascades down the whole dependency graph |
| M7/M6 contract change | just that app | Stateless, unbound |

**Recommendation: do not `renounce()` on a first deployment.** This
project has amended fork-table values more than once while getting them
right, and `renounce()` converts the cheapest possible correction (1,000
µALGO, a new row) into the most expensive (a full redeploy cascade).
`deploy renounce` is deliberately **interactive and never scripted** — no
`--yes` exists for it. It prints the migration table above, requires you
to type the app id back as confirmation, and only then submits the real
`renounce()` call (`O-M10-4`).

## Recovering a lost manifest

`deploy recover --creator <address> --pinned-json '{"Mpt7ReceiptApp": "<sha256>"}'`
scans the creator's `created-apps` for one whose approval program hashes to
a pinned value, with **no local state required**. Ambiguity (more than one
match) is resolved by the caller — cross-check `gov`/`m4_app_id` via
`deploy inspect`, not by this command.

## Mainnet deployment preconditions (not waived by this release)

1. A **multisig or hardware governance signer** (`O-M10-3`) — never a
   single hot key for `governance`.
2. `governance != signer`, confirmed by `apply`'s own warning, not just
   assumed.
3. **Box MBR is not recoverable** (above) — budget for it as spent, not
   lent, before funding.

This release performs no mainnet deployment of M4/M6/M8 — it writes this
runbook. See [`docs/release.md`](./release.md) for the release process
itself.
