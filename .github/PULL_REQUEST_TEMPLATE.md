## What this changes and why

## Which design doc / ROADMAP row does this relate to?

If this touches an already-"Implemented" module's approved assumptions,
link the design doc and note what's changing.

## Evidence

Per `CONTRIBUTING.md`: no cost/behavior claim without a real measurement
behind it. If this touches opcode budget, contract behavior, or a live
service, cite what you ran and its real output (a `simulate` response, a
real test run, a transaction id) — not just "should work."

## Checklist

- [ ] `ci-offline.yml` passes (pinned fixtures, no live dependencies)
- [ ] `ci-live.yml` run if this touches contract/chain behavior, with the
      run id cited above
- [ ] `ROADMAP.md` / `CHANGELOG.md` updated if this changes a module's status
