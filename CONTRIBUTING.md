# Contributing

## Workflow

Every module in this project follows the same gate:

1. A design doc is written under `docs/design/NNN-<module-name>.md` covering
   scope, interface, algorithm, edge cases, and a test plan. It must
   explicitly call out which open question(s) from `ROADMAP.md` it resolves.
2. The design doc is reviewed and approved before any implementation code is
   written against it.
3. Implementation lands as Puya (Algorand Python) contract code plus tests,
   validated against real Ethereum mainnet data wherever the module touches
   real chain data — no synthetic-only test coverage for state-proof or
   signature-verification logic.
4. `ROADMAP.md` is updated with the module's new status.

If you're proposing a change to an already-"Implemented" module, open an
issue describing the gap first — don't skip straight to a PR that changes
approved design assumptions.

## No cost claims without evidence

If your change touches opcode-budget behavior, back it with a real
`/v2/transactions/simulate` response (see `tests/fixtures/spike-reference/`
for the harness pattern this project already validated). Documented
per-opcode costs alone are not sufficient — measured costs have been found to
diverge from documentation in this project's own history.

## Tests

- `ci-offline.yml` (pinned fixtures, no live dependencies) must pass on every
  PR.
- `ci-live.yml` (dev-mode algod + public Ethereum RPC) should be run manually
  before a module is marked "Released," and the release notes must cite the
  run id it passed on (see `ARCHITECTURE.md`'s "CI" section).

## Releases

The release process — the runbook, the release-readiness checklist, and
what a `v1.0.0` tag is and is not allowed to claim — lives in
[`docs/release.md`](./docs/release.md), not here.
