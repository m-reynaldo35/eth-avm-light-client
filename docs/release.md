# Release process

This page is the release runbook and the release-readiness checklist,
`docs/design/012-docs-packaging-release.md` §6/§7 made into a living
document. It is regenerated — the *table*, not the prose — at each release.

## The checklist

Every "state" cell is measured, not asserted. **Nine rows block a `v1.0.0`
tag; two of the nine need a real run this documentation pass could not
perform itself** (see "What this pass could not close," below).

| # | item | state (this pass) | blocks v1? |
|---|---|---|---|
| 1 | `ci-live.yml`'s real body has run and passed | **CLOSED.** Run [31229821639](https://github.com/m-reynaldo35/eth-avm-light-client/actions/runs/31229821639) — `live` 589 passed/1 skipped/2 deselected in 774.5s, `contracts-live` green. The first real, green `ci-live` run in this project's history. | no longer |
| 2 | A `pull_request` event has run CI at least once | **OPEN.** 0 of this project's workflow runs, ever, have been a `pull_request` event. Needs one real PR. | **yes — human action** |
| 3 | A real testnet (or mainnet) deploy exists in an acceptance gate | **OPEN.** No public-network deploy has ever been performed; devnet-with-real-data is the strongest evidence so far. Needs funded testnet ALGO (≈24–32 ALGO) and 15–25 minutes. | **yes — human action, needs funding** |
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
| 17 | AlgoPlonk's swallowed-error bug unreported upstream | A draft report with the two-line diff and an existing reproduction sits at `tests/fixtures/spike-reference/zk-m7/UPSTREAM_ISSUE_ALGOPLONK.md`, marked "not filed — for human review before submitting." **Still not filed.** | no — nothing this repo ships depends on AlgoPlonk; **human action to file it** |
| 18 | Bazaar registration / challenge submission tag | Undone | no — §8 declines Bazaar, sequences the tag; all five of the tag's preconditions are met as of this release |
| 19 | Bare-contract `code_id`s unfillable offline | **CLOSED.** All seven contracts (including `MptSegmentApp`, `DonorIssuer`, `DonorCallee`) now have a `code_id` in `deploy/versions.json`, filled by running `deploy.compile.refresh_bare_contract_cache` against a real, reachable algod. | no longer |
| 20 | MBR is not recoverable | Structural; stated in bold in `docs/operating.md` | no — documented, not a defect |

**As of this pass: seven of the nine originally-blocking rows are closed.
Two remain, and both need a real-world action this documentation pass
cannot perform on its own**: opening one real PR against this repository,
and running the funded testnet deploy-verify-drive (G2-M12). Both are
explicitly scoped to a human/a separate pass with funded testnet ALGO —
see `CHANGELOG.md`'s "Unreleased" section.

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
1.  Close the checklist's blocking rows above (both remaining ones need a human).
2.  gh workflow run ci-live.yml                        -> G1-M12. Record the run id.
                                                           (Already done this pass: 31229821639.)
3.  Open one real PR (docs-only is fine)               -> closes the "PR has run CI" gap.
4.  Testnet apply/verify/drive (docs/operating.md)     -> G2-M12. Commit the manifest.
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
- **G2-M12 (real testnet deploy-verify-drive)**: **not performed.** It
  needs funded testnet ALGO a human may want to provide and is explicitly
  out of scope for this documentation/packaging pass — see `CHANGELOG.md`.
- **One real pull request**: **not opened.** This pass leaves every change
  uncommitted for human review, per this project's standing workflow; a PR
  is the reviewing human's action once they choose to land these changes.
- **The AlgoPlonk upstream report**: **drafted, not filed.** The draft
  exists and is ready (`tests/fixtures/spike-reference/zk-m7/UPSTREAM_ISSUE_ALGOPLONK.md`),
  marked for human review before submission — filing a GitHub issue against
  a third-party project is a human action, consistent with how this
  project treats every other external, irreversible action.
- **The `x402-global-challenge` submission tag**: **not pressed.** All five
  of its preconditions are met (a live paid endpoint, a public repository,
  a readable README, a tagged release process, and a verifiable on-chain
  artifact) — pressing submit has a deadline attached to somebody else's
  calendar and is a human's call.
- **A `v1.0.0` git tag / GitHub release**: **not cut.** Two of the
  checklist's blocking rows are still open (above), and cutting a tag with
  known-blocking rows open would be exactly the kind of claim this whole
  module exists to prevent.
