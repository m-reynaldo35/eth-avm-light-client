# Release process

This page is the release runbook and the release-readiness checklist,
`docs/design/012-docs-packaging-release.md` §6/§7 made into a living
document. It is regenerated — the *table*, not the prose — at each release.

## The checklist

Every "state" cell is measured, not asserted. **Nine rows originally
blocked a `v1.0.0` tag. All nine are now closed** (row 3 closed 2026-08-11
by a real mainnet deploy, exceeding the testnet bar it originally asked
for — see its own row and "What this pass could not close," below, for the
full citation trail).

| # | item | state (this pass) | blocks v1? |
|---|---|---|---|
| 1 | `ci-live.yml`'s real body has run and passed | **CLOSED.** Run [31229821639](https://github.com/m-reynaldo35/eth-avm-light-client/actions/runs/31229821639) — `live` 589 passed/1 skipped/2 deselected in 774.5s, `contracts-live` green. The first real, green `ci-live` run in this project's history. `ci-offline.yml` on M12's own implementation push is likewise fully green as of run [31248277269](https://github.com/m-reynaldo35/eth-avm-light-client/actions/runs/31248277269), after three follow-up fixes to real gaps a clean CI runner (not that pass's own ambient environment) surfaced: a missing `build` package, and two tests (`pip install`ing a wheel into a genuinely clean venv) miscategorized `offline` when they need a real PyPI round trip regardless of local caching — re-marked `needs_network`. Re-confirmed green again 2026-08-11 on the v1.0.0 release push (run [31491458151](https://github.com/m-reynaldo35/eth-avm-light-client/actions/runs/31491458151)) and by a fresh, release-specific `ci-live` dispatch (run [31493546100](https://github.com/m-reynaldo35/eth-avm-light-client/actions/runs/31493546100): `live` 643 passed/1 skipped/2 deselected in 967.7s, `contracts-live` green). | no longer |
| 2 | A `pull_request` event has run CI at least once | **CLOSED.** [PR #1](https://github.com/m-reynaldo35/eth-avm-light-client/pull/1), 3/3 jobs green ([31248827365](https://github.com/m-reynaldo35/eth-avm-light-client/actions/runs/31248827365)) — the first `pull_request`-triggered CI run in this project's history. Left open, unmerged (merging is a human approval step). | no longer |
| 3 | A real testnet (or mainnet) deploy exists in an acceptance gate | **CLOSED, 2026-08-11 — real mainnet, exceeding the testnet bar this row originally asked for.** 013's fork-table-to-global-state redesign deployed M4/M6/M8 to real mainnet and proved a full receipt end-to-end (commit `ee9ef6c`: real app ids, `R_INCLUDED`, ~22.5 ALGO real cost). 014 then deployed `Mpt7AnchoredReceiptApp` (app `3670553866`) and a redeployed `Mpt7ReceiptApp` (app `3670577356`, closing the box-squatting gap `deploy resolve` had been reporting `CODE_MISMATCH` for) and proved a real T2-against-anchor receipt end-to-end through the live, real-USDC-paid `/verify-receipt-trustless` endpoint (commits `b7dafdb`/`871f07d`, `deploy verify` reports every app `OK`). **Caveat, not itself blocking**: every deploy this session used `governance == signer` (the disposable deployer key `RTG5QL...`), accepted only via `apply`'s own `--yes` override — `docs/operating.md`'s O-M10-3 already documents this is not appropriate for a network holding real value long-term; a multisig/hardware governance signer migration remains a separate, still-open human decision, unchanged by this row closing. | no longer |
| 4 | A committed manifest for the live mainnet deployment | **CLOSED.** `deploy/manifests/mainnet-v1.0.json` records M7 + the donor pair, verified live against real mainnet with no signer (`deploy verify`, exit 0). | no longer |
| 5 | `python -m relayer` works | **CLOSED.** `relayer/__main__.py` added; both `python -m relayer --help` and the `eth-avm-relayer` console script work from a clean-venv wheel install. | no longer |
| 6 | `pip install eth-avm-relayer` does not pull forbidden service deps | **CLOSED.** Measured in a clean venv: 20 packages (was 59), all four real runtime deps plus their real transitive closure. `fastapi`/`uvicorn`/`x402-avm` moved to a `service` extra. | no longer |
| 7 | README no longer says "Early scaffold stage" | **CLOSED.** Rewritten per §5.1's table. | no longer |
| 8 | The sync-committee trust sentence (008 §15.6) is present | **CLOSED.** In the same paragraph as `README.md`'s first "verifier". | no longer |
| 9 | 007 §10's four documentation corrections have landed | **CLOSED.** `docs/design/002-rlp-decoder.md` §4.2(a) and `docs/design/005-mpt-walker.md` §7.5 amended; `README.md`'s sentence kept with its citation added; no T3 coverage number published anywhere; the frozen spike file is unmodified by policy. | no longer |
| 10 | `G1-M9` quarantined | Real, measured, structural: at real live participation the only mode touching all 8 key boxes costs 210,381–211,502 opcodes, over the ~177,392 shared donor ceiling. Opened 2026-08-06, **expires 2026-11-04**. | no — release-note item |
| 11 | M5's budget gates open | Real measured numbers, not design targets: 5,116 opcode 8-node account walk (target < 3,276); 1,813 opcode 3-node receipt walk (target < 1,121); 1,969 B (target ≤ 1,400 B) | no — performance, not correctness |
| 12 | M2's G1/G3 open | G3: 192 vs a ≤90 target; G1 is now index-dependent by design | no — same reasoning |
| 13 | M6 has no submitting client (G4-M9) | `prove_account` never sends a transaction; no `test_l5` exists | no — README qualifies it |
| 14 | 13 of M8's 22 error codes untested | Committed baseline (`tests/harness/error_codes_uncovered.txt`); growth is a red build | no — tracked, not blocking |
| 15 | T3 unimplemented | ~2.2% of a real 94,667-receipt sample needs it | no — no T3 coverage number is published anywhere |
| 16 | Nothing monitors the live service/app | Measured up at release time; no alerting of any kind | no — docs must not say "monitored," and don't |
| 17 | AlgoPlonk's swallowed-error bug reported upstream | **CLOSED.** Filed as [giuliop/AlgoPlonk#8](https://github.com/giuliop/AlgoPlonk/issues/8), from the draft at `tests/fixtures/spike-reference/zk-m7/UPSTREAM_ISSUE_ALGOPLONK.md` (that file itself left unmodified, per this repo's frozen-fixture policy). | no longer |
| 18 | Bazaar registration / challenge submission tag | Undone | no — §8 declines Bazaar, sequences the tag; all five of the tag's preconditions are met as of this release |
| 19 | Bare-contract `code_id`s unfillable offline | **CLOSED.** All seven contracts (including `MptSegmentApp`, `DonorIssuer`, `DonorCallee`) now have a `code_id` in `deploy/versions.json`, filled by running `deploy.compile.refresh_bare_contract_cache` against a real, reachable algod. | no longer |
| 20 | MBR is not recoverable | Structural; stated in bold in `docs/operating.md` | no — documented, not a defect |

**As of the `v1.0.0` tag: all nine originally-blocking rows are closed.**
Row 3 (G2-M12, "a real testnet-or-mainnet deploy exists in an acceptance
gate") was the last to close, superseded by a real mainnet
deploy-verify-drive that exceeds the testnet bar it originally asked for
— see row 3 above and `CHANGELOG.md`'s `[1.0.0]` entry for the full
citation trail.

## The release notes' required contents (cite, don't assert)

1. The `ci-offline` run id and its measured job times.
2. **The `ci-live` run id** (G1-M12), with the `go-algorand` build from its
   `algod-versions.json` artifact.
3. The testnet app ids, rounds, and manifest path (G2-M12, once run).
4. The mainnet app ids and `code_id`s, with the `deploy verify` command a
   reader can run themselves, and the sentence that nothing monitors them.
5. **The quarantine list, in full**, with its real numbers and expiry date.
6. **The open-gate list** — the table above, verbatim.
7. `requires-python` and the Python versions CI actually ran.
8. The `versions.json` fork window, and the Gloas exclusion with its reason.
9. Known structural limits of the wheel (§4.2 of the design doc).

## The runbook

```
1.  Close the checklist's blocking rows above (one remaining, needs a human).
2.  gh workflow run ci-live.yml                        -> G1-M12. Record the run id.
                                                           (Already done this pass: 31229821639.)
3.  Open one real PR (docs-only is fine)               -> closes the "PR has run CI" gap.
                                                           (Already done: PR #1, green, left unmerged.)
4.  Testnet apply/verify/drive (docs/operating.md)     -> G2-M12. Commit the manifest.
                                                           (The one item still open -- needs a human
                                                           to fund a testnet account first.)
5.  python -m deploy schema                            -> regenerates versions.json with the real release tag.
6.  Write CHANGELOG's v1.0.0 entry from the nine items above. Every line cites something.
7.  git tag v1.0.0 + a GitHub release whose body IS the changelog entry.
8.  (Human, separately) publish the wheel; (human, separately) any mainnet deployment.
```

Step 8 is deliberate: publishing a name to PyPI is a global, irreversible
claim, and any mainnet deployment of M4/M6/M8 needs a multisig/hardware
governance signer this project does not provide — both are a human
decision, not something a design doc or a release script should press.

## What this pass could not close, and why

- **G1-M12 (real green `ci-live`)**: **closed** — run 31229821639, cited
  above.
- **G2-M12 (real testnet deploy-verify-drive)**: **CLOSED, 2026-08-11 —
  superseded by a real mainnet deploy-verify-drive**, a strictly stronger
  result than the testnet bar this gate originally asked for. 013 deployed
  M4/M6/M8 and proved a full receipt end-to-end on real mainnet (`ee9ef6c`);
  014 deployed `Mpt7AnchoredReceiptApp` and a redeployed `Mpt7ReceiptApp`
  and proved a real T2-against-anchor receipt end-to-end through the live,
  real-USDC-paid service (`b7dafdb`/`871f07d`). `deploy verify --target
  deploy/targets/mainnet.json` reports every app `OK`. See row 3 above for
  the full citation trail and the governance-key caveat.
- **One real pull request**: **CLOSED.**
  [#1](https://github.com/m-reynaldo35/eth-avm-light-client/pull/1), a
  real, docs-only PR against this repository, ran real CI on a
  `pull_request` event for the first time in this project's history — 3/3
  jobs green
  ([31248827365](https://github.com/m-reynaldo35/eth-avm-light-client/actions/runs/31248827365)).
  Left **open, not merged**: merging is a human approval step, consistent
  with this project's standing rule that a delegated pass stops at green
  CI.
- **The AlgoPlonk upstream report**: **CLOSED.** Filed as
  [giuliop/AlgoPlonk#8](https://github.com/giuliop/AlgoPlonk/issues/8)
  after explicit human confirmation to post it — filing a GitHub issue
  against a third-party project under a real identity is exactly the kind
  of external, irreversible action this project's own standing practice
  pauses on before acting, even under a broad "close these out" instruction.
- **The `x402-global-challenge` submission tag**: **not pressed.** All five
  of its preconditions are met (a live paid endpoint, a public repository,
  a readable README, a tagged release process, and a verifiable on-chain
  artifact) — pressing submit has a deadline attached to somebody else's
  calendar and is a human's call.
- **A `v1.0.0` git tag / GitHub release**: **cut, 2026-08-11**, human-
  authorized, once all nine originally-blocking rows were genuinely
  closed (above) — not before. `deploy verify` was re-run immediately
  before tagging and reports every mainnet app `OK`.
