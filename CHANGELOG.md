# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). One
additional, non-optional rule for this project
(`docs/design/012-docs-packaging-release.md` §5.5): **every entry that
states a result cites its evidence inline** — a commit hash, a GitHub
Actions run id, an Algorand round, or an app id. An entry with no citation
is exactly the class of claim `ARCHITECTURE.md`'s standing rule forbids.

## [Unreleased]

### Fixed

- **Bazaar catalog listing root-caused and fixed, 2026-08-18.** GoPlausible's
  "x402 Doctor" tool (`facilitator.goplausible.xyz/guide`), run against
  `GET /verify-receipt/25700000/0/0`, returned the real diagnosis:
  `bazaar.schema method enum must match the declared method`. Traced into
  `x402-avm` 2.0.2's own source: for a GET/HEAD/DELETE route,
  `declare_discovery_extension()` (`x402/extensions/bazaar/resource_service.py`)
  unconditionally emits `schema.properties.input.properties.method.enum ==
  ["GET", "HEAD", "DELETE"]`, and `bazaar_resource_server_extension`'s runtime
  enrichment (`server.py`) injects the real method into `info.input.method`
  correctly but never narrows that schema enum to match — a library bug, not
  fixable via any argument to `declare_discovery_extension()`. Both this
  service's routes are GET-only; `service/x402_endpoint/main.py`'s new
  `_get_only_discovery_extension()` narrows the enum to `["GET"]` itself
  after the library builds it (commit `70d5b09`), deployed to production the
  same pass and confirmed live: a fresh 402 response now decodes to
  `schema.properties.input.properties.method.enum == ["GET"]` matching
  `info.input.method == "GET"` exactly. Filed upstream (issues are disabled
  on `x402-avm` itself, so filed against the org's docs/meta repo instead):
  [GoPlausible/.github#7](https://github.com/GoPlausible/.github/issues/7).
  Whether the catalog itself now lists this service still needs a fresh real
  settled payment plus a real re-check of `/discovery/resources` — not yet
  done as of this entry.

### Changed

- **T1-against-anchor migrated off the per-call `AnchorReceiptProbe` deploy
  onto the permanent `Mpt7AnchoredReceiptApp`** — 014 §4.1's own deliberately
  deferred scope, closed. `relayer/client.py::_submit_receipt_against_anchor`
  now drives `self.config.m7_anchored_app_id` (the same app
  `_submit_t2_receipt_against_anchor` already used for T2), instead of
  compiling `contracts/state_anchor/bench_app.py` with `puyapy` and creating
  a fresh app on every call; `_deploy_anchor_receipt_probe` is deleted.
  `prove_receipt(against_anchor=True)` now requires `m7_anchored_app_id` for
  both T1 and T2. Real cost improvement, measured this pass (standalone
  dev-mode live script, same synthetic-but-real harness `tests/receipt/
  test_anchored_app_live.py` uses): the one-time `Mpt7AnchoredReceiptApp`
  deploy took 3.27s wall-clock (funds its own 1.7441 ALGO box-MBR float
  once); the proof call itself then took 0.04s with zero app-balance delta
  (no MBR abandoned) — versus the old path's ~3.4s `puyapy` compile PLUS a
  fresh app create, on EVERY call, abandoning that call's MBR permanently (a
  bare `Contract` has no delete-and-recover path). A real 337 B T1 leaf
  verified `R_INCLUDED` against a real on-chain M8 anchor through the
  migrated path, `measured_consumed=3041`. Also closes the T1 case of the
  live, confirmed `MissingContractsSource` gap: `/verify-receipt-trustless`
  on a T1 leaf no longer needs `contracts/` source + `puyapy` on `PATH` at
  request time, so the packaged Vercel deployment (which ships neither) can
  now serve it — previously a real 500 on every T1 request.
- `tests/relayer/test_live_relayer.py`'s `env_a_anchor` fixture and `tests/
  deploy/test_end_to_end.py`'s E-1 now deploy/configure `m7_anchored_app_id`
  via the real `deploy.plans.m7_anchored.apply` tooling (never hand-written)
  instead of relying on the retired per-call probe deploy; L-4's own dynamic
  tx-selection comment updated to stop citing `AnchorReceiptProbe`, which no
  longer exists in this path. Both files collect cleanly (`pytest
  --collect-only`); their own real-beacon-dependent 15-25-minute live runs
  were not re-executed this pass (see `ROADMAP.md`'s M13 row).
- `service/x402_endpoint/main.py`'s module docstring corrected: the
  `/verify-receipt-trustless` route was already T1-only at 93.7% coverage
  before this pass and is now T1+T2 at 97.5%, matching `/verify-receipt`'s
  coverage under a trustless model instead of a narrower one. No code change
  was needed here — `trustless_client`'s config already picked up
  `M7_ANCHORED_APP_ID` via `RelayerConfig.from_env()` and never cleared it,
  unlike `m8_app_id` on `receipts_client`.
- **M6 (`Mpt6ComposerApp`) now has a real submitting client.**
  `relayer/client.py::prove_account` builds and submits a real transaction
  group (fetches the block header for `R_state`/TP-M6-1, then
  `eth_getProof`, segments via `relayer/proofs/account.py`/
  `relayer/drivers/m6_account_storage.py`, submits through the shared
  `relayer.group.submit.run` loop) instead of never sending a transaction,
  and enforces TP-M6-3 off-chain (`m6.verify_terminal_result`) before
  trusting the result — the check that defeats a real substitution attack
  (design doc §5.4): a relayer pointing an honestly-executed `MODE_B_INIT`
  at the wrong phase-A segment in the same group, producing a
  true-but-irrelevant composite about a different address/slot that no
  on-chain check alone catches. Found and fixed a real, load-bearing bug
  along the way: `resolve_prev_gi` located its `_PENDING_PREV_GI`
  placeholder by scanning for a byte-value match, but `donor_count=0` (the
  ordinary value on every non-donor-carrying segment) encodes to the
  identical 8 zero bytes, false-positiving on `A_INIT` itself and crashing
  every real call — fixed to locate the placeholder structurally instead.
  `tests/relayer/test_m6_live.py` (new): two real, live submissions against
  a freshly-deployed dev-mode `Mpt6ComposerApp` — the design doc's own
  pinned USDT/Binance-8 `C_INCLUDED` case, and a single-transaction
  `C_ABSENT_ACCOUNT` case with zero phase-B segments.
- **11 of M8's 13 untested error codes now have real, live tests**
  (`tests/state_anchor/test_core.py`: N1, N3, N7, N8, N10, N11, N16, N17,
  N22, N23, N24) — each matches generically on `"assert failed"` and
  proves it's the right assert by construction, never the code string
  itself (Puya's `assert cond, "CODE"` strings are stripped TEAL comments,
  never present in algod's real rejection text). The remaining 2 (N14,
  N21) are proven genuinely unreachable rather than force-tested: N14
  (`attest()`'s pinned-version check) can never see a version byte other
  than `VERSION_1`, since the only pinned-box writer always copies an
  already-N12-validated ring record; N21 (`RING_WRITE_REGRESSION`) is
  algebraically excluded once N-ADMIT holds in the same call (a
  same-residue collision needs a full `ring_n`-multiple gap N-ADMIT's own
  bound rules out) — independently re-derived, not just repeating
  `box.py`'s own docstring claim. `tests/harness/error_codes_uncovered.txt`:
  13 → 2, with the reasoning for both remaining entries recorded inline.

**`docs/security.md`'s "Nothing is monitored" is closed.** A new scheduled
GitHub Actions workflow (`.github/workflows/monitor.yml`), not a
third-party service — this repo's own G8-M9 import-purity test forbids the
sentry-sdk/Datadog class of dependency a naive monitor reaches for — checks
the live Vercel service and the real mainnet apps every 30 minutes and
alerts via a real GitHub issue on genuine failure, using only the
workflow's own `GITHUB_TOKEN` (no new secret). Check logic lives in
`scripts/monitor_check.py`, stdlib-only (`urllib`, `subprocess`), kept out
of the YAML specifically so its failure branch is unit-testable offline.

- **Real live evidence, this pass**: `GET
  https://x402endpoint-nu.vercel.app/health` →
  `{"algod_round":63968372,"m7_app_id":3670577356,"m4_app_id":3670310452,"m8_app_id":3670310865,"trustless_configured":true,"keeper_configured":true}`
  (200). `python3 -m deploy verify --target deploy/targets/mainnet.json` →
  `m6`/`m7`/`m7_anchored`/`m8`: `OK`, `m4`: `FAIL` with only the documented,
  expected "unexpected slack" finding (`docs/security.md`). `python3
  scripts/monitor_check.py` correctly classifies that combination healthy
  and exits 0 against both real checks in the same session.
- **Failure path proven offline, not just the happy path**:
  `tests/harness/test_monitor_check.py` (12 tests, no network, no algod) —
  a genuine `CODE_MISMATCH`, an unreachable/failing non-M4 app, a
  non-200/non-JSON/missing-key health response, and a subprocess exception
  are all correctly reported unhealthy; the one case that must NOT page
  anyone (M4's real, captured slack-only `deploy verify` output) is
  correctly reported healthy. Also exercised live and harmlessly:
  `check_health` against a real nonexistent path on the real production
  host (404) and a real nonexistent hostname (DNS failure) both correctly
  report unhealthy, without touching anything the production service
  actually serves.
- **Honest limitation**: this workflow had not, as of when it was written,
  produced a real, live, scheduled/dispatched GitHub Actions run — it was
  built in an isolated git worktree under a no-commit constraint, and
  GitHub does not recognize a `workflow_dispatch`/`schedule` trigger for a
  workflow file that has never been pushed. What was verified there is the
  real check logic run directly against the real live service and real
  live mainnet apps, plus its failure branches under real offline pytest.
  The first real `workflow_dispatch`/scheduled run happens once this lands
  on `main` — see `docs/release.md`/`ROADMAP.md` for its run id once one
  exists.
- `TrustedRootAnchor`'s equivocation latch (`conflict != 0`, 009 §8.5) is
  explicitly NOT covered by this workflow — `deploy verify` does not read
  that piece of on-chain state — see `docs/security.md`.
- **x402 Bazaar discovery wired up** (`server.register_extension(bazaar_resource_server_extension)`
  plus `declare_discovery_extension()` on both routes, using real output
  examples/schemas captured from live production calls). Verified locally:
  a real 402 response's `payment-required` header decodes to a complete,
  correctly-shaped `extensions.bazaar` payload. **Real production outage
  caused deploying this**: `jsonschema` (required by
  `x402.extensions.bazaar`) was present locally only as an incidental
  transitive dependency, never declared — the first deploy took the entire
  live service down (`ModuleNotFoundError`, every route, not just the new
  ones), caught immediately by this session's own health check and fixed
  by adding the `extensions` extra to `x402-avm`'s declared dependency.
  **Resolved 2026-08-18** (was: "not yet diagnosed" — see below, closed).
- **Live service domain renamed**: the Vercel project (and its production
  domain) was `x402_endpoint`/`x402endpoint-nu.vercel.app` since the
  service's first deployment (2026-08-07) — an artifact of that first
  deploy running from `service/x402_endpoint/` rather than the repo root.
  Renamed to match the actual GitHub repo slug:
  **`eth-avm-light-client.vercel.app`**. Real gotcha found doing this:
  Vercel's project-level `ssoProtection` (`all_except_custom_domains`)
  gates any domain added via `vercel alias set` behind a Vercel SSO
  login page — a plain deployment alias isn't a registered project
  domain. Fixed by registering it properly via the `POST /v10/projects/
  {id}/domains` API instead, confirmed publicly reachable (`GET
  /health` returns real data, no redirect) immediately after. The old
  domain is left in place, unremoved, and still serves the same live
  deployment.

## [1.0.0] - 2026-08-11

All nine of the release-readiness checklist's originally-blocking rows are
closed (full citation trail: [`docs/release.md`](./docs/release.md)). The
last one closed the same day the tag was cut: a real mainnet
deploy-verify-drive, twice over — 013's fork-table-to-global-state redesign
(`SyncCommitteeVerifier`/`TrustedRootAnchor`/`Mpt6ComposerApp`, real end-to-
end receipt proof, commit `ee9ef6c`) and 014's T2-against-anchor capability
(`Mpt7AnchoredReceiptApp` plus a redeployed `Mpt7ReceiptApp`, real
end-to-end T2 receipt proof through the live, real-USDC-paid production
service, commits `b7dafdb`/`871f07d`). `ci-offline` run
[31491458151](https://github.com/m-reynaldo35/eth-avm-light-client/actions/runs/31491458151)
(3m46s, the push after every commit below) and `ci-live` run
[31493546100](https://github.com/m-reynaldo35/eth-avm-light-client/actions/runs/31493546100)
(triggered for this release specifically) are both cited as this release's
evidence: `ci-live` — **green**, `live` tier 643 passed/1 skipped/2
deselected in 967.7s (0:16:07), `contracts-live` green.

**Real mainnet apps as of this tag** (`deploy verify --target
deploy/targets/mainnet.json` → every app `OK`):

| app | id | note |
|---|---|---|
| `SyncCommitteeVerifier` (m4) | `3670310452` | 013's fork table, real committee installed and finalized |
| `Mpt6ComposerApp` (m6) | `3670312896` | |
| `Mpt7ReceiptApp` (m7) | `3670577356` | redeployed 2026-08-11; the original `3665914633` is abandoned in place, not deleted (see `docs/security.md`) |
| `Mpt7AnchoredReceiptApp` (m7_anchored) | `3670553866` | new, 014 |
| `TrustedRootAnchor` (m8) | `3670310865` | |
| `DonorIssuer` | `3666047636` | |
| `DonorCallee` | `3666047587` | |

**Requires-python / CI matrix**: `>=3.12` (`pyproject.toml`); `ci-offline`
runs 3.12 and 3.13; `ci-live` runs 3.13 only.

### Added (013 / 014, 2026-08-10 – 2026-08-11)

- `docs/design/013-fork-table-global-state.md` — M4/M8's fork table moved
  from box storage to global state, structurally eliminating the mainnet
  create-race that previously cost two real, non-recoverable losses of
  ~0.335 ALGO each. Implemented, and proven live the same session: a real
  512-member committee installed, finalized, and a full receipt proved
  end-to-end against a real anchor (`ee9ef6c`, ~22.5 ALGO real cost).
- `docs/design/014-t2-against-anchor.md` — T2 (box-staged) receipt proofs
  against an M8 anchor. A design pass that built and submitted a real
  prototype rather than just reasoning about it: one atomic 10-transaction
  group, zero donor transactions needed at the worst case. Implemented as
  `contracts/receipt/anchored_app.py::Mpt7AnchoredReceiptApp` — T1 walk, T2
  box-staged walk, and the M8 anchor check as one permanent, manifest-
  pinned app, replacing the test-only, compiled-per-call `AnchorReceiptProbe`
  for this path. Deployed to real mainnet (`3670553866`) and proven with a
  real T2-tier receipt (block `25731394`, tx index `12`, 2,362 B leaf, a
  real USDC Transfer event): `R_INCLUDED`, confirmed round `63965073`.
- `/verify-receipt-trustless` — a second, explicit route on the live x402
  service (`service/x402_endpoint/main.py`) offering the anchor-verified
  path (zero RPC trust, T1-only, 93.7% coverage) alongside the unchanged
  `/verify-receipt` (RPC-trusted, T1+T2, 97.5% coverage) — two trust models,
  offered as a real choice rather than one silently swapping for the other.
- `/keeper/run` — a Vercel Cron-triggered route that periodically runs
  `sync(update=True)`/`anchor("latest")` with a dedicated, minimal-privilege
  signer, guarded by Vercel's `CRON_SECRET` convention. Verified live
  against production: a real `sync` (137 donors) + `anchor` (8 donors) tick,
  both landed on mainnet.

### Fixed (013 / 014, 2026-08-10 – 2026-08-11)

- **A live, exploitable hijack window on the shipped T1 trustless path.**
  `AnchorReceiptProbe` (`contracts/state_anchor/bench_app.py`) had no
  `on_completion` guard — live-verified `UpdateApplication` with an
  always-approve program was **accepted**. Since the relayer deploys a
  fresh probe and submits the proof group as a separate transaction, this
  was a real mainnet window in which anyone could substitute a fabricated
  result for a real proof. Fixed with the standard one-line guard
  (`bd3f2a7`), re-verified live (`UpdateApplication`/`DeleteApplication`
  both rejected).
- **Permissionless box-name squatting** (`contracts/receipt/box.py::
  mpt7_stage_open`) — anyone could pre-create a T2 staging box at the wrong
  size under a name the driver was about to use, breaking every honest
  proof that picked it. Fixed (delete-before-create) in source and in a
  fresh mainnet redeploy of `Mpt7ReceiptApp` (`3670577356`); the original
  app (`3665914633`) could not be patched in place (its own `on_completion`
  guard) and is abandoned, not deleted.
- **The live Vercel deployment was serving `FUNCTION_INVOCATION_FAILED` on
  every request** — `fastapi` was never actually installed. `pyproject.
  toml`'s own comment had flagged this as an unmeasured question ("whether
  Vercel's builder honours an EXTRA... must be settled by one real
  redeploy"); it doesn't. Fixed with `vercel.json`'s `installCommand`
  override; confirmed live via real, real-USDC-paid requests afterward.
- `deploy/manifests/mainnet-v1.0.json` now correctly records
  `Mpt7AnchoredReceiptApp` and the redeployed `Mpt7ReceiptApp` (see table
  above) — a manifest write that was initially missed in the first commit
  and caught/fixed the same session (`367a151`).
- **014's negative-path tests** (design doc §10's A-6 through A-9 — a
  forged M8 anchor, a corrupted staged chunk, an evicted ring entry, a
  mismatched tx index) were not written by the implementation pass;
  `TestNegativePaths014` (`tests/receipt/test_anchored_app_live.py`) closes
  all four the same day, real and live against dev-mode algod, each
  confirming both the rejection AND §3.5/§3.6's "fails closed, nothing
  stranded" claim (box absent, app balance unchanged) by measurement, not
  assumption. One real correction found while writing them: the design
  doc's own `N12`/`W11`/`N2`/`L11` codes never appear as literal substrings
  in algod's real rejection text (Puya's `assert cond, "CODE"` strings are
  TEAL comments, stripped at runtime — matches `tests/state_anchor/
  test_core.py::TestSecurityErrorCodes`'s own prior finding) — each test
  matches the generic `"assert failed"` and proves it's the *right* assert
  by construction instead.

### Added

- `deploy/versions.json` — the contract-versioning artifact (three axes:
  AVM/protocol, consensus fork, proof system), generated by
  `python -m deploy schema` and diffed by `ci-offline.yml`'s `contracts`
  job. Keyed by approval-program SHA-256 (`code_id`), never hand-typed. All
  seven contracts (`TrustedRootAnchor`, `SyncCommitteeVerifier`,
  `Mpt7ReceiptApp`, `Mpt6ComposerApp`, `MptSegmentApp`, `DonorIssuer`,
  `DonorCallee`) have a filled `code_id`, the last three filled this pass by
  running `deploy.compile.refresh_bare_contract_cache` against a real,
  reachable algod (`mainnet-api.algonode.cloud`'s public
  `/v2/teal/compile`) — no signer, no deployment.
- `deploy resolve --network <net> --fork <fork> [--json]` — read-only,
  no-signer discovery across the chain (table window), the pinned `code_id`
  (code window), and the manifest (which app id is ours). Four verdicts:
  `USABLE`, `NOT_DEPLOYED`, `FORK_UNSUPPORTED`, `CODE_MISMATCH`. Verified
  live against real mainnet: `resolve --network mainnet --fork fulu` reports
  `m7: USABLE` (app `3665914633`, `code_id_matches_chain: true`) and
  `m4`/`m8`/`m6`: `NOT_DEPLOYED`; `resolve --network mainnet --fork gloas`
  reports `m4`/`m8`: `FORK_UNSUPPORTED` with the cited reason, `m7`
  unaffected (`USABLE`, `fork_axis: "none"`).
- `deploy inspect --target <t> --app m4|m8 --forks` — decodes the on-chain
  fork table through the schema, surfacing the two `_read_fork_rows`
  functions in `deploy/plans/m4.py`/`deploy/plans/m8.py` that already
  existed but were unreachable from the CLI.
- `deploy/versions_guard.py` — `deploy` refuses, client-side, to build an
  `append_fork_row` call for any fork listed in a contract's
  `code_window.unsupported`. Tested both ways: it fires for `gloas` on both
  M4 and M8, and does not fire for `fulu`. **Tool-side only** — a governance
  key holder using a raw client bypasses this refusal; closing it properly
  needs a chain-side gindex/depth bound, out of scope for this release
  (`O-M12-1`).
- `deploy/manifests/mainnet-v1.0.json` — the committed mainnet manifest,
  recording the three real live app ids this project can currently make any
  claim about: `Mpt7ReceiptApp` (`3665914633`, created round `63833882`),
  `DonorIssuer` (`3666047636`, round `63837794`), `DonorCallee`
  (`3666047587`, round `63837792`), each with its `code_id`, creator
  (`6XP7MJKMEPSCZ46RPB42FFRQGF7U5ACXLCXNCXWAVJUSP5J7U3ZFWBRIFQ` for all
  three), and confirmed live against real mainnet with no signer:
  `python -m deploy verify --target deploy/targets/mainnet.json` → `m7: OK`.
- `relayer/__main__.py` — `python -m relayer` now works (`RelayerError`'s
  exit-code taxonomy unchanged); previously `python -m relayer status`
  failed with `No module named relayer.__main__`, the exact command 009
  §15.4 nominated as this project's own quickstart.
- `[project.scripts] eth-avm-relayer = "relayer.cli:main"` — a real console
  script; verified in a clean venv (`eth-avm-relayer --help`).
- Real `--help` text (`description=`/`epilog=`/`help=`) on every subcommand
  of both `relayer/cli.py` and `deploy/cli.py`.
- A named `relayer.errors.MissingContractsSource` error, raised (never a
  bare `FileNotFoundError`) when `prove_receipt(against_anchor=True)` or
  `deploy_donor_pair` is reached from an installed wheel with no
  `contracts/` source tree next to it. Verified in a clean venv: raises
  with a message pointing at `docs/quickstart.md`'s checkout path.
- `docs/security.md`, `docs/versioning.md`, `docs/quickstart.md`,
  `docs/operating.md`, `docs/release.md` — new.
- `tests/harness/test_versions.py` (Suite V), `test_packaging.py` (Suite
  W), `test_doc_claims.py` (Suite N), `test_manifests.py` (Suite M — M-1/
  M-2 offline, M-3..M-6 live against real mainnet, no signer needed for any
  of them).

### Changed

- `[project.dependencies]` no longer includes `fastapi`, `uvicorn[standard]`,
  or `x402-avm[fastapi,avm]` — moved to a new `service` extra. Measured in a
  clean venv: 20 packages install (was 59), all four real runtime deps
  (`py-algorand-sdk`, `rlp`, `pycryptodome`, `py_ecc`) plus their real
  transitive closure — none of the ~40 previously-forced packages
  (`sentry-sdk`, `fastapi-cloud-cli`, etc.) that `relayer/`'s own G8-M9
  import-purity test forbids it from importing.
- `README.md` rewritten from its original "Early scaffold stage" status
  line — replaced with a per-module status table citing real run ids,
  rounds, and app ids; a `ci-offline`-only badge; install/quickstart
  sections; the live mainnet deployment table with its `deploy verify`
  command; the supported-fork statement (Deneb/Electra/Fulu, Gloas
  excluded); an honest "what this does not do" section; and the
  sync-committee trust-model sentence in the same paragraph as the first
  use of "verifier" (008 §15.6, normative).
- `ARCHITECTURE.md`'s "Contract versioning" section replaced its original
  guess ("Altair/Capella/Deneb") with the real, measured range
  (Deneb/Electra/Fulu) and a link to `docs/versioning.md`. Its "CI" section
  now states that a "Released" claim must cite the `ci-live` run id it
  passed on, not merely assert one exists.
- `ROADMAP.md`'s M7 row corrected: public HTTPS exposure is done (was
  listed as "not yet done"; `GET https://x402endpoint-nu.vercel.app/health`
  returns real data), and mainnet app `3664247481` no longer exists (was
  described as "still live and still hijackable"; confirmed 404 against
  real mainnet, re-verified this pass).
- `docs/design/002-rlp-decoder.md` §4.2(a) and `docs/design/005-mpt-walker.md`
  §7.5 amended per 007 §10's own correction: "cannot materialise or hash
  that leaf at all" / "cannot be `keccak256`'d (no streaming hash)" replaced
  with "cannot materialise it, and cannot hash it with the `keccak256`
  opcode; software hashing is possible at 109.2 budget/byte (007 §2.4)".
  Neither module's underlying decision changes.

### Fixed

- `pip install eth-avm-relayer` no longer installs `fastapi-cloud-cli`,
  `sentry-sdk`, and ~38 other packages `relayer/` is forbidden by its own
  tests from importing (see "Changed," above).
- `python -m relayer` — a genuinely broken command, confirmed independently
  before this pass (`No module named relayer.__main__; 'relayer' is a
  package and cannot be directly executed`) — now works.

## Known, unproven claims at this snapshot

`tests/harness/quarantine.toml`, in full:

- `tests/relayer/test_live_relayer.py::test_l2_submit_update_all_8_key_boxes_g1_m9`
  — real, measured, structural: at real live participation, the only mode
  touching all 8 key boxes costs 210,381–211,502 opcodes, more than the
  shared 256-inner-call donor ceiling can ever supply (~177,392 max),
  regardless of donor count. Needs a real day with moderate, spread-out
  absenteeism. **Opened 2026-08-06, expires 2026-11-04.**

## Honestly still open (not blocking, tracked)

- M5's three budget-gate targets are open — real measured numbers, not the
  design targets: 5,116 opcode 8-node account walk (target < 3,276), 1,813
  opcode 3-node receipt walk (target < 1,121), 1,969 B (target ≤ 1,400 B).
- M2's G1/G3 gates are open (192 vs. a ≤90 target; G1 is index-dependent by
  design).
- T3 (the ZK tier) is unimplemented; no coverage percentage for it is
  published anywhere in this repository.
- Nothing monitors the live mainnet app or the live Vercel service. **Closed
  post-release, 2026-08-11 — see `[Unreleased]` above for the workflow and
  its evidence.**
- A real, non-reproducing N6-shaped live race surfaced once in
  `tests/state_anchor/test_live_e2e.py::TestG1M8RealDirectAnchor` during
  this pass's own `ci-live` dispatch (run 31228946039; did not reproduce on
  the immediately following green run, 31229821639) — a hand-rolled test
  harness bypassing `EthAvmClient.anchor()`'s own retry/resync handling for
  a finalized-header race 011 already documented as "normal, not
  exceptional." Left as a named gap for a future M8/M9-scope pass, per this
  release's own scope boundary (no new test content for M1–M11).
- AlgoPlonk's swallowed `ReadFrom` error (upstream, in `giuliop/AlgoPlonk`)
  was reported as
  [giuliop/AlgoPlonk#8](https://github.com/giuliop/AlgoPlonk/issues/8),
  drafted at `tests/fixtures/spike-reference/zk-m7/UPSTREAM_ISSUE_ALGOPLONK.md`
  (that file itself unmodified, per this repo's own frozen-fixture policy).
  Not a release blocker — nothing this repository ships depends on
  AlgoPlonk.
- The original mainnet `Mpt7ReceiptApp` (`3665914633`) is abandoned, not
  deleted — still live and squattable in principle, no longer referenced by
  any manifest, service config, or this project's own tooling. `deploy
  resolve`/`deploy verify` correctly report the *current* app (`3670577356`)
  `USABLE`/`OK`; nothing in this repository points at the old one any more.
- `deploy verify` reports mainnet M4 with 366,100 µALGO of "unexpected
  slack" — real, structural, and permanent (a bare `Contract` app account
  has no withdrawal path), not a funding-calculation bug. Full root cause
  in `docs/security.md`.
- Scheduled `ci-live` runs failed for three consecutive days
  (2026-08-09/10/11) before this release — the most recent two traced to a
  test asserting mainnet M4/M8 were `NOT_DEPLOYED`, stale from before this
  session's own real deployments of them; fixed same-day (`871f07d`). A
  fresh `ci-live` run was triggered specifically for this release; see its
  cited result above.
