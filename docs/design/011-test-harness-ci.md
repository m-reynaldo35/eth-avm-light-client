# 011 — M11: Real-data test harness & CI integration

**Status**: Design drafted, awaiting human review.
**Depends on**: M9 (`relayer/`) and M10 (`deploy/`) — both implemented, live-proven
and committed (`git log`: `6b88acb`, `56781cb`, `0912df8`). M11 targets their
*code*, not their design docs. Transitively depends on every module M1–M8,
because M11's job is to run all of their tests.
**Consumed by**: M12 (docs & release — a release claim rests on what CI proves),
every future module, and every external contributor, for whom `ci-offline.yml` is
the only reviewer that reads every PR.
**Design-time convention, inherited**: every number below is labelled
**measured** (a real command run during this design pass, cited to the command)
or **projected** (an estimate this document owns, which an implementation pass
must replace with a real result). `ARCHITECTURE.md`'s rule applies unchanged, and
this module is the one that finally enforces it mechanically.

---

## 0. The question, stated first

Every prior design doc in this repo opens by naming its own hardest question. M11
is unusual: its hardest question was answered by a two-minute API call at the
start of this pass, and the answer is bad enough that it reframes the whole
module.

**Measured** (`gh api repos/m-reynaldo35/eth-avm-light-client/actions/runs`, this
pass):

> **21 GitHub Actions runs. 21 successes. Zero failures, ever, since
> 2026-07-30.** 13 runs of `ci-offline.yml` (on `push`) and 8 nightly runs of
> `ci-live.yml` (on `schedule`).
>
> **Every single one of them executed nothing but `echo`.**

Both workflows are still the scaffold-commit placeholders from `51dd033`:

```yaml
      - name: Placeholder (no modules implemented yet)
        run: echo "ci-offline skeleton -- populate once M1+ lands"
```

M1 through M10 have all landed. `ci-live.yml`'s nightly cron has fired every
morning for eight days and reported a green tick against a repo whose test suite
it has never once run. The badge is not merely uninformative — it is an active
false claim, and it has been making that claim for the entire life of the
project.

So M11's question is not "should CI be offline or live". Both workflows have
existed since commit 1 and `ARCHITECTURE.md` already ratifies the two-workflow
policy. The question is:

> **What can a workflow that runs in 10 minutes on a hosted runner, with no
> secrets and no Algorand node, actually prove about a project whose entire
> engineering standard is "no number ships without a real `simulate` response
> against real mainnet data" — and what must therefore be true of the *other*
> workflow, and of the boundary between them, for the pair to be honest?**

**The answer, stated up front, defended in §3–§8:**

> **A hard, mechanically-enforced three-tier split, and a `--offline` flag that
> makes the offline tier's independence a property of the test run rather than a
> claim in a comment.**
>
> **Measured this pass**: with every outbound socket dead (algod *and* internet),
> **462 of 555 tests pass in 33.5 seconds**, 85 skip cleanly, and 8 error. Those
> 462 are `ci-offline.yml`'s real body — 83.2% of the suite, at zero external
> dependency, well inside a per-PR budget. Adding a `puyapy` compile-and-diff
> job (**measured: all 10 contract entry points compile in 34 s, and every
> committed ARC-56 artifact and TEAL blob reproduces byte-identically**) closes
> the one thing a fixture-only suite structurally cannot see.
>
> **The 8 errors are not a tier boundary. They are a bug** (§3.3), and the
> ~15-minute live suite's single most notorious "flake" is not a flake either
> (§5) — it is a deterministic, fully-explained, already-solved box-reference
> arithmetic bug in legacy test-helper code, which this pass reproduced **live,
> today, from the current mainnet bitfield**, predicting both of its historically
> observed error numbers exactly.

**Three things this document has to get right**, in order of how much damage
getting them wrong does:

1. **Refusing to retry the box-budget failure** (§5). The tempting design is a
   `@pytest.mark.flaky` with a retry count. That would be the single worst
   decision available: it would paper over a *real*, *deterministic*,
   *reproducible-on-demand* defect that M9 already fixed in `relayer/`, and it
   would train everyone who reads the CI output to treat the one error class
   that has masked a genuine structural insufficiency as background noise.
2. **Making green non-vacuous** (§4). This project has just spent eight days
   proving that a green tick means nothing unless something forces it to. Silent
   skips are how a suite becomes an `echo` again by degrees rather than all at
   once, so `--offline` **deselects** the live tier and then **forbids skips**
   among what is left, and the tier partition itself is a committed, CI-diffed
   artifact — the same generated-and-checked pattern M10 established for the box
   schema (G3-M10).
3. **Not letting the harness become a second relayer** (§6). `tests/harness/`
   consolidates duplicated *scaffolding*; it must delegate every deployment,
   compilation, group-assembly and box-reference decision to `deploy/` and
   `relayer/`, which are already live-proven. The measured duplication is real
   (7 copies of the algod probe, 6 of the beacon probe, 9 hardcoded algod URLs,
   6 `funded_account`s) and the temptation to fix it by writing a *better* copy
   is exactly how this repo grew five copies of group assembly in the first
   place.

---

## 1. Scope, non-goals, trust preconditions

### 1.1 In scope

1. **A real `ci-offline.yml`** — the 462-test offline tier plus a contract
   compile-and-artifact-diff job, on every push and every PR, in a measured
   budget (§7).
2. **A real `ci-live.yml`** — dev-mode algod brought up from the spike's own
   recipe as an actual workflow step, the live tier run against real public
   Ethereum RPC/beacon endpoints, torn down cleanly, on a real trigger, with a
   real report (§8).
3. **A tier mechanism** — two orthogonal markers, an `--offline` socket guard, a
   `--live` selector, and a committed tier manifest that CI diffs (§4).
4. **`tests/harness/`** — one home for the availability probes, the network
   constants, the funded-account helper, and the deployment fixtures, every one
   of which is currently duplicated between 3 and 9 times (§2.2, §6).
5. **Deleting the box-reference flake** — rebasing the three test files that
   import `_choose_mode_and_boxes` onto `relayer.group.boxes.plan_box_refs` and
   `EthAvmClient`, which is 009 §15.4's and 010 §16's explicitly-assigned
   hand-off to this module (§5.4, §6.3).
6. **A live-variance policy** that is keyed on `relayer.errors.Retryability` —
   M9's own already-shipped, already-live-proven error taxonomy — rather than on
   a generic rerun plugin (§5.6).
7. **`pyproject.toml`'s test dependencies and pytest configuration**, neither of
   which currently exists (§7.2).

### 1.2 Non-goals (explicit)

1. **No new test *content* for M1–M10.** M11 moves, deletes, deduplicates and
   schedules tests; it does not write new coverage for modules that already have
   it. The one exception is the coverage-discipline meta-tests of §9, which test
   the *test suite*, not the contracts.
2. **No `bench/` rebasing.** The four bench scripts are standalone
   hand-run CLI tools with their own `funded_account`/`ALGOD_ADDRESS` copies.
   Rebasing them onto `tests/harness` would create a `bench/ → tests/` import
   edge this repo has no precedent for, and they are not, and will not be, CI
   jobs (§6.4, §9.4).
3. **No budget-regression gate in v1** (`O-M11-2`). Only three of the four bench
   result files carry a machine-comparable `gates` key, M8 has no bench file at
   all (008 §15.5 item 3), and M1/M3 never emitted one — unifying them is its own
   module's worth of work, and would let a half-built gate imply a coverage this
   project does not have.
4. **No testnet or mainnet CI.** Same boundary M10 drew (010 §15 gap 3). CI
   deploys to a throwaway dev-mode algod and carries real mainnet *data*.
5. **No secret-bearing jobs.** §8.5 confirms, by inspection of every endpoint
   list and every signer path, that the live tier needs none — and M11 treats
   that as a property to *preserve*, not merely a fact to observe (§11).
6. **No coverage-percentage gate.** `coverage.py` over a repo whose real subject
   is compiled TEAL executing on a chain would measure the Python that drives the
   contracts, not the contracts. It would be a number that looks like evidence
   and is not, which is the specific failure mode §0 exists to end.
7. **No test parallelisation (`pytest-xdist`) in v1** (`O-M11-3`). The live tier
   shares one algod, one KMD default wallet and one funded account; parallelism
   there is a correctness question, not a speed knob. The offline tier is
   already 33.5 s.

### 1.3 Trust preconditions — what a green tick is allowed to mean

M9 is untrusted (009 §1.3); M10 is trusted (010 §1.3). M11 is neither: it is a
**claim-making** module. Its output is not a transaction, it is a belief in a
reviewer's head. So the preconditions are about what that belief may contain.

1. **A green `ci-offline` means**: every pure-computation assertion in this repo
   holds against its committed fixtures, on this Python, with no network of any
   kind reachable; every contract still compiles; and every committed compiled
   artifact and schema still reproduces byte-identically from source. It means
   **nothing whatsoever** about whether a transaction would commit on a real
   chain, what any opcode costs, or whether real mainnet data still has the shape
   this repo assumes.
2. **A green `ci-live` means**: on the day it ran, against the real chain state
   of that day and a specific pinned algod build, the real submissions listed in
   its report committed. It is a statement with a date on it and it expires.
3. **Neither workflow is a security boundary.** They run on public runners, with
   no secrets (§8.5), against a throwaway dev-mode node. A malicious PR cannot
   steal anything because there is nothing to steal — and §11 records the one
   design rule (never `pull_request_target`, never a secret) that keeps that
   true as the repo grows.
4. **A skipped test is not a passed test**, and the mechanism must make that
   structurally impossible to forget (§4.4). This is the entire lesson of §0.
5. **CI is not permitted to be the only place a live claim is made.** The
   project's standing rule is that ROADMAP rows cite real responses.
   `ci-live.yml` uploads its JUnit XML and its algod build identification as
   artifacts precisely so a row can cite a *run*, not a memory.

---

## 2. What already exists — the inventory, measured

### 2.1 The suite

**Measured** (`python3 -m pytest tests/ --collect-only -q`): **555 tests
collected in 5.61 s across 50 test files.** Per-file, measured the same way:

| package | files | tests |
|---|---|---|
| `tests/unit/` | 21 | 174 |
| `tests/ssz/` | 3 | 165 |
| `tests/relayer/` | 7 | 74 |
| `tests/bls/` | 5 | 52 |
| `tests/deploy/` | 5 | 45 |
| `tests/sync_committee/` | 5 | 23 |
| `tests/state_anchor/` | 4 | 22 |
| **total** | **50** | **555** |

Supporting, non-test modules that the suite imports:
`tests/reference/{mpt_ref,rlp_ref}.py`, `tests/ssz/reference.py`,
`tests/sync_committee/{reference,vectors}.py`, `tests/state_anchor/synth.py`,
`tests/bls/reference.py`, and five `conftest.py` files (266 + 431 + 394 + 54 +
12 lines).

Committed fixtures, **measured** (`du -sh tests/fixtures/*`): `sync_committee`
3.0 MB, `ssz` 2.5 MB, `spike-reference` 2.4 MB, `rlp` 88 KB, `relayer` 72 KB,
`mpt` 24 KB. Total under 8.1 MB — a checkout cost CI need not think about.

There is **no** root `tests/conftest.py`, **no** `pytest.ini`, **no**
`[tool.pytest.ini_options]`, **no** registered markers, and **no**
`[project.optional-dependencies]`. Nothing in the repo currently states how to
install what the tests need.

### 2.2 The duplication inventory, measured

Every count below is a real `grep` over `tests/`, `bench/`, `relayer/`,
`deploy/`, excluding `tests/fixtures/spike-reference/` (frozen by policy):

| thing | independent definitions | where |
|---|---|---|
| `_algod_reachable()` | **7** | `tests/bls/conftest.py`, `tests/sync_committee/conftest.py`, `tests/state_anchor/conftest.py`, `tests/ssz/test_budget.py`, `tests/deploy/test_deploy_live.py`, `tests/deploy/test_security_matrix.py`, `tests/deploy/test_end_to_end.py` |
| …plus cross-package imports of one of them | 2 | `tests/relayer/test_live_relayer.py`, `tests/relayer/test_box_budget_model.py` both do `from tests.sync_committee.conftest import _algod_reachable` |
| `_beacon_reachable()` | **6** | `tests/sync_committee/test_live_beacon_fetch.py`, `test_live_e2e_finality.py`, `tests/state_anchor/test_live_e2e.py`, `test_live_historical.py`, `tests/relayer/test_live_relayer.py`, `tests/deploy/test_end_to_end.py` |
| `ALGOD_ADDRESS = "http://localhost:4051"` literal | **9** | 6 under `tests/`, 3 under `bench/` |
| `funded_account()` | **6** | `tests/state_anchor/conftest.py`, `tests/deploy/test_deploy_live.py`, `tests/deploy/test_security_matrix.py`, `bench/{mpt,composer,rlp}_bench.py` |
| `compile_teal()` | **6** | 2 under `tests/`, 1 in `relayer/group/donors.py`, 2 in `deploy/compile.py`, 1 nested inside a fixture |
| `puya_compile()` | **3** | `tests/state_anchor/conftest.py`, `relayer/group/donors.py::puya_compile_contracts`, `deploy/compile.py` |
| `patched_repo_copy()` | **2** | `tests/state_anchor/conftest.py`, `deploy/compile.py` (the promoted one) |
| `deploy_donor_pair()` | **2** | `tests/state_anchor/conftest.py`, `relayer/group/donors.py` (the promoted one) — the test copy is imported by **5** test files, including two in `tests/relayer/` |

Two of these are worse than plain duplication. `tests/state_anchor/conftest.py`'s
`patched_repo_copy` and `deploy_donor_pair` are *stale copies of code that has
since been promoted* into `deploy/compile.py` and `relayer/group/donors.py` —
010 §16 states plainly that these conftest helpers "become thin wrappers over
`deploy.*`… *Rebasing the live test files themselves onto the tool is M11's*".
And the cross-package `from tests.sync_committee.conftest import …` in
`tests/relayer/` imports a `conftest` module by dotted path from a sibling test
package, which works only because `tests/` happens to be importable and is
exactly the kind of accident that breaks the first time someone runs pytest from
a different rootdir.

### 2.3 The verdict, and the scoping call

009 §0 and 010 §0 each answer "refactor, rewrite, or new?" explicitly. M11's
answer, in the same shape:

> **M11 is ~55% consolidation of scaffolding that already works, ~30% genuinely
> new construction (the two workflows and the tier mechanism), and ~15%
> deletion.**
>
> **Consolidate**: the 7 algod probes, 6 beacon probes, 9 URL literals, 3
> `funded_account`s under `tests/`, and the four stale `conftest` copies of
> promoted `deploy`/`relayer` helpers — into `tests/harness/`, which *delegates*
> and does not reimplement (§6).
>
> **Build new**: `ci-offline.yml`, `ci-live.yml`, `tests/harness/tiers.py` (the
> markers, the `--offline` socket guard, the manifest check), `tests/harness/
> variance.py` (the live-retry policy), the `pyproject.toml` test extras and
> pytest config, and the compile-and-diff gate.
>
> **Delete**: `_choose_mode_and_boxes` and every padding workaround built on it
> (§5), the duplicate happy-path live test that `test_l1` already supersedes, and
> the tribal-knowledge `--deselect` convention that currently substitutes for a
> quarantine policy.

---

## 3. The offline/live split — measured, not guessed

### 3.1 The experiment

The split cannot be settled by grepping for `algod_available`, because a file can
reference the fixture and still contain a majority of tests that do not need it
(`tests/bls/test_codec.py`: 10 offline, 5 live), and because a file can need the
network without ever mentioning it. It is settled by running the suite with
nothing reachable.

**Measured, this pass.** The whole tree, with every outbound connection —
including `localhost:4051`/`4052` — routed to a closed port:

```
env http_proxy=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 no_proxy= \
    python3 -m pytest tests/ -q -rs
⇒ 462 passed, 85 skipped, 8 errors in 33.49s
```

462 + 85 + 8 = 555. Every skip carries a real reason string, all four of which
already exist in the codebase and work: `"no dev-mode algod reachable"`,
`"dev-mode algod not reachable on :4051"`, `"no reachable beacon-API endpoint in
the pool"`, `"no reachable Ethereum RPC endpoint in the pool"`.

This is the single most important measurement in this document, and it says
something better than expected: **the auto-skip discipline this project has
maintained since `tests/bls/conftest.py` was written already very nearly
partitions the suite correctly.** M11 is not inventing the split; it is
mechanising, tightening and enforcing one that mostly exists.

The 33.49 s figure includes ~20 s that the live-tier files spend attempting and
failing connections. Selecting only the wholly-offline files removes that:
**measured, three consecutive runs, 418 passed in 12.73 / 12.70 / 12.71 s.**

### 3.2 The three tiers, file by file

**Tier A — wholly offline** (30 files, **418 tests**, measured 12.7 s):

| files | tests |
|---|---|
| `tests/unit/` (all 21 files) | 174 |
| `tests/ssz/test_merkle.py`, `test_merkleize.py` | 129 + 29 |
| `tests/relayer/test_plan_boxes.py`, `test_real_fixtures.py`, `test_security.py`, `test_segmentation.py` | 24 + 19 + 13 + 5 |
| `tests/deploy/test_schema.py` | 13 |
| `tests/sync_committee/test_bitfield.py`, `test_signing_root.py` | 6 + 6 |

**Tier B — mixed, per-test** (6 files, **44 offline / 32 live**):

| file | offline | live | what the offline half is |
|---|---|---|---|
| `tests/bls/test_aggregate.py` | 11 | 8 | `test_t6_offline_*` — `py_ecc` aggregation reference |
| `tests/bls/test_codec.py` | 10 | 5 | T1/T4/T8 compression + negation against `py_ecc` |
| `tests/bls/test_hash_to_curve.py` | 6 | 5 | T9 `expand_message_xmd` vs RFC 9380 App. K.1 |
| `tests/deploy/test_forks_gindex.py` | 9 | 1 | Suite G — **the gindex regeneration 008 §15.5 item 1 demands CI run** |
| `tests/deploy/test_security_matrix.py` | 7 | 3 | G8-M10 import graph + S3/S5 refusals |
| `tests/deploy/test_deploy_live.py` | 1 | 10 | `test_d11_create_raced_exception_reports_bounded_loss` |

**Tier C — wholly live** (14 files, **61 tests**), plus, for completeness, the
one Tier B file whose live half is substantial:

| file | tests | needs |
|---|---|---|
| `tests/bls/test_pairing.py` | 6 | algod |
| `tests/bls/test_trust_boundary.py` | 1 | algod |
| `tests/ssz/test_budget.py` | 7 | algod |
| `tests/relayer/test_box_budget_model.py` | 3 | algod |
| `tests/state_anchor/test_core.py` | 14 | algod |
| `tests/sync_committee/test_install_live.py` | 4 | algod |
| `tests/sync_committee/test_live_beacon_fetch.py` | 3 | beacon |
| `tests/state_anchor/test_forks.py` | 4 | algod + beacon |
| `tests/state_anchor/test_live_e2e.py` | 2 | algod + beacon |
| `tests/state_anchor/test_live_historical.py` | 2 | algod + beacon (**heavy**, §8.3) |
| `tests/sync_committee/test_live_e2e_finality.py` | 4 | algod + beacon |
| `tests/relayer/test_live_relayer.py` | 7 | algod + beacon + eth RPC |
| `tests/relayer/test_retire_live.py` | 3 | algod + beacon |
| `tests/deploy/test_end_to_end.py` | 1 | algod + beacon + eth RPC |
| *(Tier B)* `tests/deploy/test_deploy_live.py`, live half | 10 | algod |

**Tier C (61) + Tier B's live half (32) = 93**, the measured
85-skipped-plus-8-errored figure exactly.

Tier A + Tier B-offline = **462**, which is the measured offline pass count
exactly. **`ci-offline.yml` runs all 462**, not just Tier A's 418: the extra 44
include Suite G, which is the only gate standing between a governance typo and a
silently wrong anchored root (008 §15.5), and the G8-M9/G8-M10 import-graph
tests, which are the only enforcement of the layering the whole architecture
rests on.

**Two orthogonal needs, not one axis** (§4.1): `needs_algod` and
`needs_network` are independent. `test_live_beacon_fetch.py` needs the internet
and no chain; `test_core.py` needs a chain and no internet; `test_end_to_end.py`
needs both. A single `live` marker would force the beacon-only tests to wait for
a container they never touch.

### 3.3 The 8 errors are a bug, not a tier boundary

**Measured**: all 8 errors are `ERROR at setup`, in exactly two files —
`tests/state_anchor/test_core.py` (6) and `tests/state_anchor/test_forks.py`
(2) — and all 8 have the same cause:

```python
@pytest.fixture(scope="module")
def account():
    algod = algod_client()
    kmd = kmd_client()
    return funded_account(algod, kmd)      # <-- never asks for algod_available
```

Both files define this fixture independently (`test_core.py:41`,
`test_forks.py:151`). Tests that request `account` *and* `algod_available` skip
correctly; the 8 that request only `account` blow up with
`ConnectionRefusedError` wrapped in `urllib.error.URLError` before any test body
runs.

This is a two-line fix in each file (make `account` depend on `algod_available`
and skip), and after §6 it is a zero-line fix, because `account` becomes one
shared fixture in `tests/harness/chain.py` that is guarded once. It is recorded
here in its own subsection because it is the exact failure mode `--forbid-skips`
(§4.4) exists to catch in the other direction: a fixture that *errors* instead of
skipping is as much a tier-boundary defect as a test that *skips* instead of
running.

### 3.4 What the offline tier structurally cannot see

`ci-offline` is fixture-driven. **Measured**: not one of the 462 offline tests
invokes `puyapy` (`grep -rn "puyapy\|puya_compile"` over every Tier A/B offline
file returns only `tests/deploy/test_schema.py`'s *docstring*, saying so
explicitly). `tests/unit/` and `tests/ssz/` execute contract logic through
`algopy_testing`'s pure-Python emulation; `tests/deploy/test_schema.py` reads the
committed `contracts/**/*.arc56.json` and `deploy/schema/_compiled/*.json`.

The consequence is sharp and must not be glossed: **a change to any file under
`contracts/` that breaks compilation, or that changes the compiled output without
the committed artifacts being regenerated, is invisible to the entire offline
tier.** `deploy schema --check` re-derives the schema JSON *from the cache*, not
from the contracts — 010 §3.4 and `deploy/compile.py`'s own docstring both say so
plainly. So the artifacts could drift from the source and every one of the 462
tests would still pass.

That is not a reason to weaken the offline tier's independence. It is a reason
for a second offline job.

### 3.5 The compile tier — measured this pass, and it passes today

`puyapy` needs no algod and no network. **Measured, this pass**, all ten contract
entry points, from a clean checkout:

```
OK contracts/composer/bench_app.py          OK contracts/state_anchor/anchor_app.py
OK contracts/mpt/bench_app.py               OK contracts/state_anchor/bench_app.py
OK contracts/primitives/bls/harness.py      OK contracts/sync_committee/bench_app.py
OK contracts/primitives/rlp/bench_app.py    OK contracts/sync_committee/verifier.py
OK contracts/primitives/ssz/harness.py      OK contracts/receipt/bench_app.py
⇒ 10/10 compile, total 34 s (puyapy 5.9.0, ~3.0–3.4 s each)
```

And the artifacts reproduce. **Measured, this pass**, fresh `puyapy` output
against the committed files:

| artifact | fresh | committed | result |
|---|---|---|---|
| `SyncCommitteeVerifier.arc56.json` `byteCode.approval` | 6,980 B, `sha256 7a937250bbff32a2…` | 6,980 B, `7a937250bbff32a2…` | **identical**; whole JSON identical under `sort_keys` |
| `TrustedRootAnchor.arc56.json` `byteCode.approval` | 3,027 B, `9b790b33f2116a5c…` | 3,027 B, `9b790b33f2116a5c…` | **identical**; whole JSON identical |
| `Mpt7ReceiptApp` approval/clear TEAL sha256 | `95f33c13…`/`d1099e1f…` | cache's `approval_teal_sha256`/`clear_teal_sha256` | **identical** |
| `Mpt6ComposerApp` approval/clear TEAL sha256 | `b2b154c7…`/`00dba827…` | cache's | **identical** |

6,980 B and 3,027 B match every prior citation in this repo (010 §4.6). So
**G3-M11 is measured, not projected: the gate passes today**, and its cost is 34 s
plus a handful of hashes.

The one thing this job cannot do offline is the *assembled byte length* of a
bare-`Contract` (`Mpt6ComposerApp`, `Mpt7ReceiptApp`, `MptSegmentApp`, the donor
pair): `puyapy` emits no ARC-56 for a non-`ARC4Contract`, and there is no offline
TEAL assembler anywhere in this toolchain (`deploy/compile.py`'s docstring, and
confirmed here by the shape of `deploy/schema/_compiled/*.compiled.json`, which
stores `approval_bytes: 3108` beside `approval_teal_sha256`). So the split is:

- **offline**: every contract compiles; every ARC-56 artifact reproduces
  byte-identically; every bare-contract **TEAL** hash matches the cache; the
  schema regenerates byte-identically (`deploy schema --check`, G3-M10).
- **live**: the bare contracts' **assembled byte counts** and `approval_sha256`
  match the cache, via one `/v2/teal/compile` per contract against the CI algod
  (`deploy.compile.refresh_bare_contract_cache` in check-only mode).

---

## 4. Tiers as a mechanism

### 4.1 Two markers, registered and strict

```python
# tests/harness/tiers.py, registered from tests/conftest.py
"needs_algod: requires a reachable dev-mode algod (ci-live.yml)"
"needs_network: requires reachable public Ethereum RPC and/or beacon API (ci-live.yml)"
"live_heavy: >1 GB of real beacon data and multi-GB RSS (ci-live.yml, weekly job)"
"live_variance: retryable under §5.6's narrow, exception-typed policy"
```

`--strict-markers` is on, so a typo is an error rather than a silently
never-selected test.

Markers are applied **automatically wherever the intent is already expressed** —
a root `pytest_collection_modifyitems` hook adds `needs_algod` to any item whose
fixture closure contains `algod_available` and `needs_network` to any whose
closure contains `beacon_available` / `eth_rpc_available`. Explicit
`@pytest.mark.needs_algod` is for the module-level `pytestmark` cases
(`tests/ssz/test_budget.py`) and the `skipif`-at-import-time cases
(`tests/deploy/test_deploy_live.py`, `test_end_to_end.py`) which have no fixture
to infer from. Deriving the marker from the fixture closure rather than requiring
a hand-typed decorator on all 93 live tests is what keeps the two mechanisms from
drifting apart, and it is why §6's shared fixtures are a prerequisite for §4
rather than a nicety.

### 4.2 `--offline`: a socket guard, not an honour system

`--offline` does three things, in this order:

1. **Deselects** every item marked `needs_algod` or `needs_network`.
2. **Installs a socket guard**: `socket.socket.connect` is patched to raise
   `ConnectionRefusedError("blocked by --offline")`.
3. **Forbids skips** among what remains (§4.4).

`ConnectionRefusedError` is chosen deliberately: it is an `OSError`, so every
probe already in this repo degrades identically to a real refused connection —
`_algod_reachable` catches `(urllib.error.URLError, OSError)`,
`_beacon_reachable` catches bare `Exception`, `EndpointPool.request` catches bare
`Exception` and accumulates. **This equivalence is what the §3.1 experiment
measured**: routing every connection to a closed port produced exactly the clean
85 skips, so the guard's behaviour is not a projection.

Why an in-process guard rather than only the proxy environment variables that
§3.1 used: proxy honouring is per-library and per-`no_proxy` (a contributor with
`no_proxy=localhost` in their shell gets a silently different run), whereas a
patched `connect` is uniform across `urllib`, `http.client`, `requests` and
`algosdk` alike. `ci-offline.yml` sets the proxy variables **as well**, as a
second, out-of-process line of defence for anything that reaches the network
without going through `socket.socket.connect` (a subprocess, say).

### 4.3 The tier manifest, CI-diffed

M10 established the pattern: generate the artifact, commit it, and have CI
regenerate and diff (`deploy schema --check`, G3-M10). M11 uses the identical
pattern for the tier partition.

`tests/harness/tiers.json` is generated by `pytest --write-tier-manifest` and
records, per test file, the count in each tier plus a total:

**Measured, this pass**, from the §3.1 run's own skip reasons: of the 85 clean
skips, **63 stopped at an algod gate** (four distinct reason strings) and **22 at
a network gate** (20 beacon, 1 Ethereum RPC, 1 `config/spec`). That is a
*first-failing-gate* count, not a marker partition — a test needing both reports
only the gate it checked first — so the real marker counts are
`needs_algod ≥ 63 + 8` (the §3.3 errors, which are mis-guarded algod tests) and
`needs_network ≥ 22`, with the overlap resolved for the first time by the
manifest itself. The illustrative shape:

```json
{
  "generated_by": "pytest --write-tier-manifest",
  "totals": {"collected": 555, "offline": 462, "live": 93, "live_heavy": 2},
  "files": {
    "tests/unit/test_rlp_core.py":            {"offline": 12, "needs_algod": 0,  "needs_network": 0},
    "tests/bls/test_codec.py":                {"offline": 10, "needs_algod": 5,  "needs_network": 0},
    "tests/deploy/test_deploy_live.py":       {"offline": 1,  "needs_algod": 10, "needs_network": 0},
    "tests/state_anchor/test_live_historical.py": {"offline": 0, "needs_algod": 2, "needs_network": 2, "live_heavy": 2}
  }
}
```

`--check-tier-manifest` regenerates it in memory and fails on any difference,
printing the diff. This is not bureaucracy: it is the only thing that makes
"someone added 40 tests to the live tier and the offline job silently got no
bigger" a *failure* rather than an unnoticed drift, and it is the only thing that
makes "someone marked a test `needs_algod` to make a red build green" show up in
a code review as a one-line diff with a reviewer's name on it.

The counts in the manifest are also the answer to "is the offline job still
non-trivial" without hardcoding 462 in a test body.

### 4.4 No silent skips

Under `--offline`, after deselection, **any skip is a failure.** The
justification is concrete rather than doctrinaire: every remaining skip mechanism
in the offline tier guards a *committed* resource —
`nodes_fixture`/`mpt_fixtures` skip when `tests/fixtures/{rlp,mpt}/nodes.json` is
missing, and `tests/relayer/test_real_fixtures.py:111` does
`pytest.importorskip("remerkleable")`. In CI those files are committed and that
dependency is declared, so a skip there means a genuine packaging or fixture
regression, which is exactly what should turn the build red.

`ci-live.yml` does **not** forbid skips, because a live tier legitimately skips
when an endpoint pool is down. Instead it **reports** them: every skip and every
retry lands in the job summary and the uploaded JUnit XML (§8.6, §13 Suite Q).
An unreported skip in a live job is how a suite silently stops testing anything;
a reported one is a weather report.

---

## 5. The flake — named, explained, and deleted

### 5.1 The standing convention this design refuses to ratify

This repo has a documented convention, visible in the M8, M9 and M10 ROADMAP
rows and in two test files' own comments: `tests/sync_committee/
test_live_e2e_finality.py` is `--deselect`ed by hand before a full-suite run,
because real current mainnet sync-committee participation "occasionally" trips a
`box read budget (N) exceeded` error in that file's own `_choose_mode_and_boxes`
helper, with a different N each time — **6144, 18432, 20480 and 22528 have all
been observed for real, across different sessions**. Two other files
(`tests/state_anchor/test_live_e2e.py`, `test_live_historical.py`) import that
same helper and work around it with hand-tuned padding.

The obvious M11 design is a retry marker. **That design is wrong, and the reason
is arithmetic.**

### 5.2 What is actually failing

M9 derived the closed form (009 §7.4) and shipped it as
`relayer/group/boxes.py::plan_box_refs`, then *measured it exactly correct*
against real algod in Suite BX:

```
distinct = the set of boxes any transaction in the group will touch
bytes    = Σ full declared size of each distinct box     (once per box per GROUP)
refs     = max(len(distinct), ceil(bytes / 2048))
txns_min = ceil(refs / 8)
```

`_choose_mode_and_boxes` predates that derivation. It returns **one reference per
distinct box** — i.e. only the first term. For M4's `submit_update`, the boxes
are `forks` (576 B) and up to eight key boxes at **6,144 B each**, so the second
term dominates by a factor of three and the helper is short by construction, on
every real bitfield, in both modes.

### 5.3 Reproduced live, today, from the current mainnet bitfield

**Measured, this pass**, against a freshly fetched real
`/eth/v1/beacon/light_client/finality_update` (signature_slot **14,940,654**,
real participation **511/512**):

| mode | boxes touched | `_choose_mode_and_boxes` gives | budget that grants | `plan_box_refs` needs | short by |
|---|---|---|---|---|---|
| COMPLEMENT | `forks` + 1 absentee key box + `a:` | 3 refs | **6,144 B** | 4 refs (6,816 B declared) | 1 ref |
| DIRECT | `forks` + 8 participant key boxes | 9 refs | **18,432 B** | **25 refs / 4 txns** (49,728 B declared) | 16 refs |

**Those are the error numbers.** `6144` is the M8 row's reported failure verbatim.
`18432` is the M9 row's, verbatim. They are not two samples of a random variable;
they are `2048 × 3` and `2048 × 9`, the pooled read budget the helper's own
reference count buys, printed back by algod. The remaining two are the same
mechanism through the two files' literal padding expressions:
`test_live_e2e.py`'s `padded_box_refs = box_refs + box_refs[:4]` turns a 6-ref
base into 10 (**20,480**) and a 7-ref base into 11 (**22,528**).

**All four observed numbers are exactly accounted for.** There is no residual
randomness to attribute to the chain. What varies between sessions is only *which
mode is cheaper on the day*, which changes the base ref count, which changes the
printed number — the failure itself is certain.

### 5.4 Why it must never be retried, and what the fix is

The DIRECT case is not merely short. It needs **25 references, i.e. at least 4
transactions**, and `_submit_update_group` in that test file builds **2**
(`[DonorIssuer, submit_update]`, `box_refs[:8]` on one and the overflow on the
other). Two transactions cap out at 16 references. Even
`test_live_historical.py`'s maximal workaround — `(box_refs + box_refs)[:16]`,
described in its own comment as "maximal available headroom within that
structural cap" — cannot reach 25. **On any day whose cheapest mode touches all
eight key boxes, that group is structurally incapable of committing, and a
retry decorator would retry it forever.**

A retry policy would also be actively harmful in the other direction: this is
precisely the class of on-chain rejection that a real M4 regression would
produce, and marking it "known variance" trains the next reviewer to ignore the
signal.

**The fix is not new work.** M9 shipped it, and closed G2-M9 with it:
`EthAvmClient._submit_update_group` sizes the transaction count from
`plan_box_refs`, pads across a donor (capped at 7 refs, because a donor's own
`foreign_apps` entry counts against the same `MaxAppTotalTxnReferences = 8`) and
as many `noop_budget` fillers as needed, and has driven four separate fresh
512-member installs end to end on live data. `tests/relayer/test_live_relayer.py`'s
first test is literally named
`test_l1_sync_end_to_end_matches_test_live_e2e_finality`.

So M11's answer to "design a real flake policy for `test_live_e2e_finality.py`"
is: **delete the cause.** §6.3 gives the concrete rebasing.

### 5.5 What genuinely *is* live-data variance

Removing the arithmetic bug leaves a real, irreducible residue. It is small, it
is enumerable, and every member of it already has a name in `relayer/errors.py`:

| what happens | real precedent in this repo | class |
|---|---|---|
| an endpoint 5xx's or times out mid-run | `lodestar-mainnet.chainsafe.io` 503'd during M9's session (`relayer/sources/beacon.py`'s own comment) | `PoolExhaustedError` → `RETRY_NOW` |
| a new finalization lands between fixture build and submit | reproduced by real wall-clock timing during M9's pass (~2 min gap after a 956 MB `BeaconState` fetch) | `RetryReplanned` → `RETRY_REPLANNED` (M8's `N6`) |
| `signature_slot` observed ahead of locally-computed `slot_now()` | 3–4 slots, real, live; fixed by M9's `MARGIN_SLOTS = 12` | not an error any more |
| the ring rejects a candidate on ordering | M9 bug (4): DIRECT before HISTORICAL at `ring_n = 8` | `N-ADMIT`; a **test-ordering** bug, fixed, not variance |
| G1-M9's k=8/DIRECT combination is unreachable at 511/512 participation | measured: 210,381–211,502 opcodes vs a hard ~177,392 ceiling | a documented `pytest.skip` with the real numbers — **not** a retry |

Note what is *not* on that list: nothing about box references, and nothing that
produces a bare `AssertionError`.

### 5.6 The policy: retry on a typed exception, never on a message

```python
@pytest.mark.live_variance(
    reason="a fresh mainnet finalization can land between fixture build and submit "
           "(008 §12.4: normal, not exceptional); driven for real in test_l8",
    max_attempts=2,
)
```

The marker is implemented in `tests/harness/variance.py` and is deliberately
narrow:

1. **A retry happens only if the failure's exception chain contains a
   `relayer.errors.RelayerError` whose `retryability` is `RETRY_NOW` or
   `RETRY_REPLANNED`.** Everything else — `AssertionError`, an algod
   `assert failed`, `logic eval error`, any `box … budget … exceeded`,
   `RevokedAnchor` (FATAL), `ConflictLatch` (PAGE_A_HUMAN), `TierUnsupported`,
   `RelayerBug` — fails on the first attempt, immediately. This reuses M9's
   already-live-proven taxonomy rather than inventing a second one, and it means
   the retry decision is made by the same code that decides it in production.
2. **`reason=` is mandatory** and must be a real sentence citing a real
   precedent. A marker without one is a collection error.
3. **`max_attempts` is capped at 3** by the plugin, regardless of what a test
   asks for.
4. **Every retry is reported**, whether or not it eventually passed: to
   `$GITHUB_STEP_SUMMARY`, to the JUnit XML as a property, and to the uploaded
   artifact. A retried pass is a *yellow* result in the summary, never a silent
   green.
5. **A budget across the run**: if more than 3 distinct tests retry, or if any
   one test retries on 3 consecutive scheduled runs, the job fails with
   `LIVE-VARIANCE-BUDGET-EXCEEDED`. Rising variance is a signal about the
   endpoints or the chain, and the whole point is that it must eventually
   demand attention rather than compound quietly. (The consecutive-run check
   reads the previous runs' uploaded artifacts via the Actions API; if it cannot,
   it reports "unknown" rather than passing.)

`pytest-rerunfailures` is explicitly **not** used: it retries on *any* failure,
which is the exact opposite of the property required here.

### 5.7 Quarantine: committed, dated, expiring

If a test must be excluded, it goes in `tests/harness/quarantine.toml`:

```toml
[[test]]
nodeid  = "tests/relayer/test_live_relayer.py::test_l2_submit_update_all_8_key_boxes_g1_m9"
reason  = "G1-M9: needs a day with moderate spread-out absenteeism; at 511/512 the only \
           k=8 mode is DIRECT at 210,381-211,502 opcodes vs a hard ~177,392 donor ceiling"
opened  = "2026-08-06"
expires = "2026-11-06"
owner   = "ROADMAP.md M9 row"
```

Rules, enforced by an **offline** test (Suite Q):

- Every entry needs all five fields, and `nodeid` must resolve against the real
  collection — a quarantine entry for a test that no longer exists is a failure,
  not a no-op.
- `expires` is at most 90 days from `opened`. Past expiry the *quarantine* fails
  the build, not the test — so the decision comes back to a human on a date.
- `ci-live` reports the quarantine list in its summary on every run.
- **A hand-typed `--deselect` on the command line is not a quarantine.** The
  convention this replaces required a human to carry the knowledge "deselect
  `test_live_e2e_finality.py`" in their head across sessions; three ROADMAP rows
  document that they did, which is three rows' worth of evidence that tribal
  knowledge does not survive contact with a new session.

---

## 6. `tests/harness/` — the reusable fixture library

The plan's own M11 sentence asks for "a reusable fixture/harness" that
generalises the spike's real-data style. §2.2 measured what that means concretely
here.

### 6.1 What moves, and what it becomes

```
tests/conftest.py               NEW. registers markers + the tier/variance plugins,
                                re-exports the shared fixtures so no test package
                                needs to import a sibling's conftest by dotted path.
tests/harness/
  __init__.py
  env.py         ALGOD_ADDRESS / KMD_ADDRESS / TOKEN (one copy, env-overridable);
                 algod_available, kmd_available, beacon_available, eth_rpc_available
                 -- replaces 7 + 6 hand-written probes (§2.2)
  chain.py       algod_client, kmd_client, funded_account, account  -- replaces 3
                 copies under tests/ and fixes §3.3's 8 errors in one place
  deployment.py  THIN wrappers over deploy/ and relayer/: compile_contract ->
                 deploy.compile.puya_compile; assembled_bytes ->
                 deploy.compile.compile_teal_via_algod; patched_anchor_repo ->
                 deploy.compile.patched_repo_copy; donor_pair ->
                 relayer.group.donors.deploy_donor_pair; deployed_stack ->
                 deploy.diff.apply
  m4.py          installed_committee / finalized_m4 fixtures, driven by
                 relayer.client.EthAvmClient -- the §5.4 fix, in one place
  tiers.py       markers, --offline socket guard, --live, manifest write/check
  variance.py    @pytest.mark.live_variance (§5.6), the budget, the report
  quarantine.py  quarantine.toml loader + its own validity assertions
  tiers.json     the committed, CI-diffed manifest (§4.3)
  quarantine.toml
```

### 6.2 What it must not become

`tests/harness/deployment.py` **delegates**. It contains no `puyapy` invocation,
no `/v2/teal/compile` call, no app-id prediction, no box-reference arithmetic and
no group assembly of its own. Every one of those already exists, live-proven, in
`deploy/` or `relayer/`, and this repo's own history is the argument: five
independent copies of group assembly is how the §5 bug survived from M4 to M10.

Concretely, the rule is enforced the same way G8-M9 and G8-M10 are — by a real
AST test, not a comment (Suite H): **`tests/harness/` may import `deploy`,
`relayer`, `pytest`, `algosdk` and the standard library, and must not import
`algopy`, must not `subprocess`-invoke `puyapy`, and must not contain the string
`/v2/teal/compile`.**

### 6.3 The rebasing hand-off, resolved

009 §15.4 assigned M11 "rebasing the four existing live test files onto M9". 010
§16 restated it: "*Rebasing the live test files themselves onto the tool is
M11's*". Both are answered here, concretely, file by file.

| file | what changes | why |
|---|---|---|
| `tests/state_anchor/conftest.py` | `puya_compile`, `compile_teal`, `patched_repo_copy`, `deploy_donor_pair` become one-line re-exports of `deploy.compile.*` / `relayer.group.donors.*`. `algod_available`/`funded_account` are deleted in favour of `tests.harness`. | 010 §16's own instruction; removes 4 stale copies of promoted code |
| `tests/sync_committee/conftest.py` | same; `SyncCommitteeLiveHarness` keeps its ABI-call ergonomics but its `_compile`/deploy path calls `deploy.compile`/`deploy.create` | one deployment recipe, not three |
| `tests/sync_committee/test_live_e2e_finality.py` | **`_choose_mode_and_boxes`, `_submit_update_group` and `_issue_donor_txn` are deleted.** Tests 1–2 (install + happy update) are deleted as duplicates of `test_l1`. Tests 3–4 (corrupted signature, corrupted branch) are **kept** — they are genuinely unique adversarial coverage — and rebased onto `EthAvmClient` | §5.4 |
| `tests/state_anchor/test_live_e2e.py` | drops the `_choose_mode_and_boxes` import and the `+ box_refs[:4]` padding; `finalized_m4` becomes `tests.harness.m4.finalized_m4` | §5.3 rows 3–4 |
| `tests/state_anchor/test_live_historical.py` | same, dropping `(box_refs + box_refs)[:16]` | §5.3 |
| `tests/relayer/test_live_relayer.py`, `test_retire_live.py` | drop `from tests.sync_committee.conftest import …` / `from tests.state_anchor.conftest import deploy_donor_pair`; use `tests.harness` | §2.2's cross-package conftest import |
| `tests/deploy/test_deploy_live.py`, `test_security_matrix.py`, `test_end_to_end.py` | drop their own probes and `funded_account`s | §2.2 |
| `tests/bls/conftest.py`, `tests/ssz/test_budget.py` | drop their own probes | §2.2 |

**One `relayer/` change, and only one**: `EthAvmClient._submit_update_group` is
promoted to a public `submit_update_group(gen, args, mode, plan)`. The corrupted-
signature and corrupted-branch tests need to submit a deliberately-tampered
`SubmitUpdateArgs` through the *real* group path; reaching into a private method
from a test would leave the two adversarial tests coupled to an underscore, and
adding a `tamper=` hook to `sync()` would put test scaffolding into production
code. The method is a genuine operator-usable seam. No behaviour changes.

### 6.4 Explicitly deferred, with reasons

Following M9 §2 and M10 §2's discipline of stating the scoping line rather than
letting it be discovered:

- **`bench/*.py`'s three `funded_account`s and three `ALGOD_ADDRESS` literals stay
  as they are.** They are hand-run CLI scripts, never CI jobs (§9.4), and
  rebasing them onto `tests.harness` would create a `bench/ → tests/` import edge
  with no precedent here. If they are ever consolidated, the right target is
  `deploy/`, not `tests/`. (`O-M11-5`.)
- **`tests/fixtures/spike-reference/` is untouched**, as it has been since the
  scaffold commit. It is a frozen empirical reference, and `ARCHITECTURE.md`
  says so.
- **`tests/reference/`, `tests/ssz/reference.py`, `tests/bls/reference.py`,
  `tests/sync_committee/reference.py` are not merged.** They are independent
  oracles — the entire value of a differential test is that the oracle was
  written separately from the thing it checks. Merging them into a harness would
  be an actively harmful "deduplication".
- **`tests/state_anchor/real_ssz.py`/`real_beacon_state.py`** were already
  promoted into `relayer/ssz/` by M9; whatever shims remain are left alone unless
  they are literally dead.

---

## 7. `ci-offline.yml` — the real workflow

### 7.1 Triggers

`push` to `main`, `pull_request`, and `workflow_dispatch`. The existing file
already has the first two, and both matter: **measured**, all 13 historical
`ci-offline` runs were `push` events and **zero** were `pull_request`, because
this project has never opened a PR — everything has landed directly on `main`.
A workflow that only ran on PRs would, today, run never.

`concurrency: group: offline-${{ github.ref }}, cancel-in-progress: true`.
`permissions: contents: read`.

### 7.2 Dependencies — the gap, stated

`pyproject.toml` today declares only `relayer`'s runtime dependencies plus
`service/x402_endpoint/`'s three Vercel-driven ones. **It does not declare a
single thing the test suite needs.** `pip install -e .` does not get you a
runnable suite. Measured by import-scanning the 462 offline tests, the missing
set is:

| package | installed here | needed by |
|---|---|---|
| `pytest` | 8.3.4 | everything |
| `algorand-python` (`algopy`) | 3.5.0 | `tests/unit/` (18 files), `tests/ssz/` |
| `algorand-python-testing` (`algopy_testing`) | 1.1.0 | `tests/ssz/conftest.py`, `tests/unit/` |
| `remerkleable` | 0.1.28 | `tests/relayer/test_real_fixtures.py` (R-3) |
| `trie` (py-trie) | 3.1.0 | `tests/unit/test_mpt_differential.py` (hard import, not guarded) |
| `PyYAML` | 6.0.2 | `tests/sync_committee/vectors.py` ← `test_signing_root.py` |

So:

```toml
[project.optional-dependencies]
test = [
  "pytest>=8.3",
  "algorand-python==3.5.0",
  "algorand-python-testing==1.1.0",
  "remerkleable==0.1.28",
  "trie>=3.1",
  "PyYAML>=6",
]
contracts = ["puyapy==5.9.0"]

[tool.pytest.ini_options]
testpaths = ["tests"]
norecursedirs = ["tests/fixtures/spike-reference"]
addopts = "--strict-markers -p tests.harness.tiers -p tests.harness.variance"
```

`algorand-python` and `algorand-python-testing` are **pinned exactly**, not
floated: `algopy_testing` is an *emulator*, and 174 of the 462 offline tests are
assertions about emulated AVM semantics. A minor-version drift there changes what
"passing" means. `puyapy` is pinned to **5.9.0** for the same reason and a
stronger one — it is the compiler whose output §3.5's gate diffs byte-for-byte,
and `deploy/schema/_compiled/*.compiled.json` records `"puyapy_version":
"5.9.0"` in the artifact itself. (007 §14.6 also records the real trap that
`pip install puya` fetches a *different, incompatible* package; the extra is
named `contracts` and pins `puyapy` precisely so nobody rediscovers that.)

### 7.3 Python version — a real, unmeasured claim

**Measured**: this repo's every test result, every budget number and every live
submission was produced on **Python 3.13.3**. Both existing workflows pin
**3.12**, which nothing has ever run. `pyproject.toml` declares
`requires-python = ">=3.10"`, which nothing has ever run either.

Decision: `ci-offline` runs a matrix of **3.12 and 3.13** (33 s each — the
cheapest possible way to stop claiming an untested interpreter), and `ci-live`
pins **3.13**, the interpreter every measured number in this repo came from.
Whether `>=3.10` is honest is left to the implementation pass to *measure* and
then either satisfy or narrow (§18 item 4) — this document will not guess.

### 7.4 The workflow

```yaml
name: CI (offline, pinned fixtures)

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: offline-${{ github.ref }}
  cancel-in-progress: true

jobs:
  tests:
    name: offline tier (py${{ matrix.python }})
    runs-on: ubuntu-latest
    timeout-minutes: 10
    strategy:
      fail-fast: false
      matrix:
        python: ["3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
          cache: pip
      - name: Install
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[test]"
      - name: Offline tier
        # --offline: deselect needs_algod/needs_network, install the socket
        # guard, forbid skips (design doc 011 §4.2/§4.4).
        # The proxy vars are a second, out-of-process line of defence for
        # anything that reaches the network without socket.socket.connect.
        env:
          http_proxy: http://127.0.0.1:9
          https_proxy: http://127.0.0.1:9
          no_proxy: ""
        run: |
          python -m pytest tests/ -q --offline --check-tier-manifest \
            --junitxml=offline-py${{ matrix.python }}.xml
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: offline-results-py${{ matrix.python }}
          path: offline-py${{ matrix.python }}.xml

  contracts:
    name: contracts compile + artifact diff
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
          cache: pip
      - name: Install
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[test,contracts]"
      - name: Every contract entry point compiles
        run: python -m tests.harness.compile_check --compile-all
      - name: Committed ARC-56 + TEAL artifacts reproduce byte-identically
        run: python -m tests.harness.compile_check --diff-artifacts
      - name: Box/state schema regenerates byte-identically (G3-M10)
        run: python -m deploy.cli schema --check
```

`tests.harness.compile_check` is a small module, not a pytest file, because it is
a build step with no fixtures and its failure message should be a diff, not a
traceback. `--compile-all` runs `deploy.compile.puya_compile` over the 10 entry
points of §3.5; `--diff-artifacts` compares fresh output against
`contracts/**/*.arc56.json` (full JSON, `sort_keys`) and against every
`approval_teal_sha256`/`clear_teal_sha256` in `deploy/schema/_compiled/`.

### 7.5 Measured runtime budget

| step | measured | source |
|---|---|---|
| collection | 5.6 s | `--collect-only -q` |
| Tier A only | **12.7 s** (3 consecutive runs: 12.73 / 12.70 / 12.71) | this pass |
| whole tree, everything unreachable | **33.5 s** | §3.1 |
| offline tier under `--offline` (deselected, no connect attempts) | ~13–15 s, **projected** — the 20 s delta in the 33.5 s figure is entirely failed connection attempts the deselection removes | this pass |
| 10 contracts compile | **34 s** | §3.5 |
| artifact + schema diff | ~2 s, **projected** | §3.5's hashes ran in well under a second |
| `pip install -e ".[test]"`, warm cache | ~30–60 s, **projected** | hosted-runner norm |

**Projected total wall-clock: ~2 minutes per matrix leg, both jobs in parallel.**
`timeout-minutes: 10` is therefore a genuine circuit-breaker (5× headroom), not
a formality.

---

## 8. `ci-live.yml` — the real workflow

### 8.1 The algod bring-up, as a real step

`ci-live.yml`'s current comment says "*Real job brings up a dev-mode algod
container (see `tests/fixtures/spike-reference/README.md` for the exact
recipe)*". M11's job is to stop pointing at the recipe and run it. Verbatim from
that README, with two deliberate changes:

```bash
TOK=$(printf 'a%.0s' {1..64})
docker create --name ci_algod -p 4051:8080 -p 4052:7833 \
  -e DEV_MODE=1 -e START_KMD=1 \
  -e TOKEN=$TOK -e ADMIN_TOKEN=$TOK -e KMD_TOKEN=$TOK \
  "$ALGOD_IMAGE"
docker start ci_algod
./.github/scripts/wait_for_algod.sh          # change 1
docker exec ci_algod algocfg -d /algod/data set -p EnableDeveloperAPI -v true
docker restart ci_algod
./.github/scripts/wait_for_algod.sh
```

**Change 1: `sleep 12` becomes a real poll** on `GET /v2/status` with the token,
120 s deadline, non-zero exit with the last curl output on timeout. A fixed sleep
on a shared hosted runner is how a workflow becomes intermittently red for
reasons that have nothing to do with the code — the one genuine flake class M11
would otherwise be *introducing*.

**Change 2: `$ALGOD_IMAGE` is a pinned digest**, not `algorand/algod:latest`.
This project's entire currency is opcode budgets and protocol caps measured
against a specific `go-algorand` (the spike README cites 4.7.3; M4/M9 measured
`MAX_BOX_REFS_PER_TXN = 8` and the 2,048 B pooled per-ref budget against a
specific build). A moving tag means a silent budget change reads as a code
regression. The job's first real step after bring-up is therefore:

```bash
curl -sS -H "X-Algo-API-Token: $TOK" http://localhost:4051/versions | tee algod-versions.json
```

uploaded as an artifact, so any live number in a ROADMAP row can name the build
it came from.

Explicitly **not** using GitHub Actions `services:`: the `algocfg
EnableDeveloperAPI` + restart step has no hook there, and `EnableDeveloperAPI` is
non-optional — `/v2/teal/compile` is what §3.5's live half and every deployment
fixture depend on.

### 8.2 Job split

Three jobs, because they have genuinely different shapes:

**`live` (nightly).** Everything in Tier C except `live_heavy`, plus Tier B's
live half. **Measured this pass**, against real dev-mode algod and real public
endpoints:

| slice | tests | wall-clock |
|---|---|---|
| `tests/bls/` + `tests/ssz/test_budget.py` | 59 | **31.0 s** |
| `tests/state_anchor/test_core.py` + `tests/relayer/test_box_budget_model.py` | 17 | **29.1 s** |
| `test_live_beacon_fetch.py` + `test_forks.py` + `test_install_live.py` | 11 | **21.5 s** |
| `tests/deploy/test_deploy_live.py` + `test_security_matrix.py` | 21 | **282.6 s** |
| **subtotal, measured** | **108 collected (73 of them live-tier)** | **364 s (6 m 04 s)** |

Each slice was run as whole files against a live algod, so the 108 includes the
offline halves of the mixed files; the live-tier content is **73 of the 93**, and
the real `--live` selection will be marginally faster than 364 s, not slower.

The remaining **18** nightly live tests are the expensive ones — the four files
that each drive a fresh 512-member M4 install (64 real `install_chunk` groups)
plus `test_end_to_end.py`'s manifest-driven deploy (M10's row measures that one
at 84.6 s). **Projected** at 450–580 s, consistent with the full-suite figures
this project has observed (833–966 s including the offline tier). **Projected
`live` job total: 14–17 minutes.** `timeout-minutes: 45`.

**`live-heavy` (weekly).** `tests/state_anchor/test_live_historical.py` alone, 2
tests. **Measured**: its cached real `BeaconState` dumps are **1,003,300,280 B
and 1,003,315,998 B** — 1.003 GB each — and the local cache holds **28 GB** of
them. That is a 1 GB download from a volunteer-run public beacon endpoint plus a
`json.load` of a 2.33-million-validator object graph, per run. Running it nightly
is both an OOM risk on a 16 GB hosted runner and an unreasonable draw on
`nimbus.team`'s bandwidth. It runs on a **weekly** cron and on demand, in its own
job so its memory is not shared, and it records peak RSS. This is a real
constraint discovered by measurement, not a preference.

**`contracts-live`.** §3.5's live half: one `/v2/teal/compile` per bare
`Contract`, diffing `approval_bytes`/`approval_sha256` against
`deploy/schema/_compiled/`. Under 30 s, **projected**.

### 8.3 Triggers

```yaml
on:
  workflow_dispatch:
    inputs:
      include_heavy: {type: boolean, default: false}
      pytest_args:   {type: string,  default: ""}
  schedule:
    - cron: "0 6 * * *"      # nightly: live + contracts-live
    - cron: "0 4 * * 0"      # Sunday: adds live-heavy
```

Both, not one. The nightly cron is what catches "real mainnet data changed shape"
without anyone asking — the single most valuable thing a live job can do for a
project whose subject is somebody else's chain, and the thing that would have
surfaced M10's placeholder-fork-epoch bug within a day. `workflow_dispatch` with
a `pytest_args` passthrough is what makes it usable as the "must pass manually
before any module is marked Released" gate `ARCHITECTURE.md` and the plan both
require, and what lets a reviewer re-run one file without editing YAML.

Scheduled crons run only on the default branch, so `live` never runs against
untrusted PR code. It is **never** `pull_request` and **never**
`pull_request_target` (§11).

### 8.4 Secrets: none — confirmed, and preserved

**Confirmed by inspection this pass**, against the shipped code rather than
memory:

- `relayer/config.py::DEFAULT_ETH_RPCS` — five endpoints
  (`ethereum-rpc.publicnode.com`, `eth.drpc.org`, `eth.merkle.io`, `1rpc.io/eth`,
  `eth-mainnet.public.blastapi.io`). No key in any URL.
- `relayer/sources/beacon.py::BEACON_APIS` — four
  (`unstable.mainnet.beacon-api.nimbus.team`,
  `testing.mainnet.beacon-api.nimbus.team`, `lodestar-mainnet.chainsafe.io`,
  `www.lightclientdata.org`). No key. **Two are plain `http://`** — worth knowing
  for a hardened runner, and a real (liveness-only, not soundness) note, since
  every fetched value is verified on-chain.
- `relayer/config.py`'s only credential-shaped env var is `RELAYER_MNEMONIC`, and
  no live test reads it: every one obtains its signer from dev-mode algod's own
  KMD default wallet (`tests/deploy/test_end_to_end.py` picks the highest-balance
  key out of `unencrypted-default-wallet`).
- `ALGOD_TOKEN` defaults to 64 `a`s — a dev-mode constant, not a secret.

So `ci-live.yml` needs **zero repository secrets**, and turning it on introduces
no new secret surface. §11 records why that is a property to defend rather than a
happy accident.

### 8.5 The workflow

```yaml
name: CI (live, dev-mode algod + public RPC)

on:
  workflow_dispatch:
    inputs:
      include_heavy: {description: "also run the >1 GB BeaconState tier", type: boolean, default: false}
      pytest_args:   {description: "extra args, e.g. a single file", type: string, default: ""}
  schedule:
    - cron: "0 6 * * *"
    - cron: "0 4 * * 0"

permissions:
  contents: read
# No secrets are used or needed (design doc 011 §8.4). Do not add
# `pull_request_target` and do not add secrets without re-reading §11.

env:
  # Pinned by digest, never `:latest` -- every opcode budget in this repo was
  # measured against a specific go-algorand build (011 §8.1).
  ALGOD_IMAGE: algorand/algod@sha256:<PIN AT IMPLEMENTATION TIME>

jobs:
  live:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.13", cache: pip}
      - run: python -m pip install --upgrade pip && pip install -e ".[test,contracts]"
      - name: Bring up dev-mode algod
        run: .github/scripts/algod_up.sh
      - name: Record the algod build under test
        run: .github/scripts/algod_versions.sh | tee algod-versions.json
      - name: Live tier
        run: |
          python -m pytest tests/ -q --live --live-retries=2 \
            --junitxml=live.xml ${{ inputs.pytest_args }}
      - name: Bare-contract assembled sizes vs the committed cache
        run: python -m tests.harness.compile_check --diff-assembled
      - name: Report (skips, retries, quarantine, budget)
        if: always()
        run: python -m tests.harness.report live.xml >> "$GITHUB_STEP_SUMMARY"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: live-results
          path: |
            live.xml
            algod-versions.json
      - name: Tear down
        if: always()
        run: docker rm -f ci_algod || true

  live-heavy:
    if: github.event.schedule == '0 4 * * 0' || inputs.include_heavy
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.13", cache: pip}
      - run: python -m pip install --upgrade pip && pip install -e ".[test,contracts]"
      - run: .github/scripts/algod_up.sh
      - name: HISTORICAL-mode tier (>1 GB real BeaconState, multi-GB RSS)
        run: |
          /usr/bin/time -v python -m pytest tests/ -q --live -m live_heavy \
            --live-retries=2 --junitxml=live-heavy.xml 2> rss.txt || (cat rss.txt; exit 1)
          grep "Maximum resident set size" rss.txt >> "$GITHUB_STEP_SUMMARY"
      - uses: actions/upload-artifact@v4
        if: always()
        with: {name: live-heavy-results, path: "live-heavy.xml\nrss.txt"}
      - name: Tear down
        if: always()
        run: docker rm -f ci_algod || true
```

`--live` is the inverse of `--offline`: it selects everything, installs no socket
guard, forbids nothing, deselects `live_heavy` (which `live-heavy` selects with
`-m live_heavy`), applies the quarantine list, and enables §5.6's retry policy at
`--live-retries`.

---

## 9. Coverage disciplines M11 inherits and owns

### 9.1 Error-code coverage — 008 §15.5 item 4

> *"G9-M8 (every error code exercised) is a coverage discipline M1–M7 did not
> have; M11 owns keeping it true as codes are added."*

**Measured this pass.** M8's contracts raise **22 distinct numeric error codes**
(`assert …, "Nxx"` string literals under `contracts/`): N1–N17, N20–N24. Of those,
**9** are mentioned anywhere at all in `tests/` or `relayer/` (N2, N4, N5, N6, N9,
N12, N13, N15, N20). **13 are never mentioned anywhere**: N1, N3, N7, N8, N10,
N11, N14, N16, N17, N21, N22, N23, N24.

And "mentioned" is a generous upper bound — a word-boundary text match over test
names, docstrings and string literals, which certainly over-counts "exercised".
The honest reading is: **at most 9 of 22, probably fewer.**

M11 owns the *discipline*, not the coverage. Suite F adds one **offline** test
that extracts every code from `contracts/**` by AST/regex, cross-references
`tests/**` and `relayer/**`, and asserts the uncovered set equals a committed
`tests/harness/error_codes_uncovered.txt`. Adding a code without a test makes the
build red; deliberately deferring one is a one-line, reviewable, blame-able diff.
Closing the 13 is not M11's work — it is M8's, and this is the mechanism that
stops the list growing while nobody notices.

### 9.2 Gindex regeneration in CI — 008 §15.5 item 1: **closed**

> *"G4-M8 must run in CI — the gindex regeneration. It is the only gate standing
> between a governance typo and a silently wrong anchored root."*

**Closed, and better than the item hoped.** M10 built the generator, and
**measured this pass**, `tests/deploy/test_forks_gindex.py` runs **9 of its 10
tests with no network and no algod** — including the `block_hash` cross-check
against the spec-published `EXECUTION_BLOCK_HASH_GINDEX_DENEB = 812` and the
negative test that a corrupted field list is *refused* rather than silently
producing a plausible wrong gindex. All 9 are in §3.2's Tier B offline half, so
they run on **every PR**, not nightly. The 10th (a live `/eth/v1/config/spec`
fetch confirming the real activation epochs) is Tier C and runs nightly. This is
strictly stronger than 008 §15.5 asked for.

That this matters is not theoretical: M10's own pass caught a placeholder
`fulu` activation epoch (500000 vs the real 411392) that would have fed
`submit_update` the wrong BLS signing domain, and it surfaced as an
`ec_pairing_check` rejection — i.e. loudly, but only because someone ran the live
suite. From M11 onward the *generator* half of that check runs per-PR.

### 9.3 Receipt-size sample — 007 §8.4: **already closed, nothing owed**

> *"M11: widen the receipt-size sample. This document rests on two blocks (288
> receipts)…"*

Closed by 007 revision 8 before M11 began: 300 real blocks, 94,667 real receipts,
recording each receipt's largest single log as revision 3 required, and the
artifact is committed at
`tests/fixtures/spike-reference/coverage_sample_300blocks.json`. M11's only
remaining obligation is a Suite F assertion that the committed sample still
re-derives the published 97.5% / 2.2% headline figures — a pure JSON read, and
therefore offline and per-PR. The sample is **not** re-pulled in CI: 300 blocks
of `eth_getBlockReceipts` against volunteer public RPC, nightly, would be
abusive, and the numbers are a one-time population estimate, not a regression
target.

### 9.4 Bench results — decided, and mostly deferred

008 §15.5 item 3 asks for `bench/anchor_results.json` "to join the four existing
bench files". M11's answer is explicit rather than silent: **no, and the bench
scripts do not become CI jobs.**

Reasons, in order: they need algod and take minutes each; only three of the four
existing files carry a machine-comparable `gates` key at all
(`mpt_results.json`, `rlp_results.json`, `composer_results.json` do;
`receipt_zk_results.json` does not, and M1/M3/M4/M8 have no file); and a
budget-regression gate built over an inconsistent half-set would imply a coverage
this project does not have — precisely the failure mode §0 exists to end. The
real budget assertions that *do* exist and *are* machine-checkable already run:
`tests/ssz/test_budget.py`'s 7 tests are in Tier C and run nightly.

A genuine unified budget-regression harness is `O-M11-2`, gated on someone first
making all the bench outputs one shape.

### 9.5 007 §8.4's circuit differential corpus — deferred, with the reason

> *"M11 additionally owns the circuit's differential test corpus (§9.5)."*

T3/ZK is not implemented (009 §16 gap 1: v1 refuses T3 cleanly; 007 §14.8 measures
the real trigger rate at 2.2% of receipts). There is no circuit in this repo to
run a differential corpus against — the gnark work lives outside it and its
generated artifacts are deliberately uncommitted per that directory's own README.
M11 records the obligation and does not pretend to discharge it (`O-M11-4`, gated
on T3 shipping a prover).

---

## 10. Edge cases

1. **A hosted runner with no `/dev/kvm`, no nested virt, but working Docker.**
   Dev-mode algod is a plain container; nothing here needs privileged mode. Fine.
2. **Port 4051/4052 already bound on the runner.** They are not, on a clean
   hosted runner, but `algod_up.sh` checks and fails loudly rather than letting
   pytest talk to something unexpected.
3. **The container starts but `EnableDeveloperAPI` is not applied** (e.g. the
   `algocfg` step silently no-ops on a future image). Every deployment fixture
   fails with a compile 404, which is a confusing error. `algod_up.sh` therefore
   asserts positively: `POST /v2/teal/compile` with `#pragma version 10\nint 1`
   must return 200 before the job proceeds.
4. **A beacon endpoint returns 200 with a stale/short response.** `EndpointPool`
   already treats a value its `accept` predicate rejects exactly like an
   exception and moves on; a full-pool failure is `PoolExhausted` carrying every
   attempt. No new handling; the live report surfaces it.
5. **All four beacon endpoints down at 06:00 UTC.** Every `needs_network` test
   skips with its existing reason string (**measured floor: 22**, §4.3), the
   `live` job goes **green with a quarter of its tier unrun**, and §4.4's
   reporting is the only thing that stops that being
   indistinguishable from success. The summary leads with the skip count, and
   more than 50% of the live tier skipping is reported as `LIVE-TIER-DEGRADED`
   (a warning annotation, not a failure — an endpoint outage is not this repo's
   bug, but it must not read as a pass either).
6. **The chain finalises between a fixture build and a submission.** §5.5 row 2:
   `RETRY_REPLANNED`, retried once by §5.6, reported.
7. **Real participation reaches 512/512.** COMPLEMENT touches zero key boxes and
   the absentee set is empty. `plan_box_refs` handles the empty case (returns a
   zero plan) and `m4_submit_update_box_sizes` still includes `forks`. Worth an
   offline planner test (Suite T) because it has never occurred live.
8. **A PR that only touches `docs/`.** `ci-offline` still runs; 2 minutes is not
   worth a `paths-ignore` rule whose main effect would be to make "did CI run"
   conditional on a glob.
9. **A PR from a fork.** `pull_request` runs `ci-offline` only, with a read-only
   token and no secrets. Nothing to leak (§11).
10. **The 1 GB `BeaconState` download fails halfway.** `live-heavy` fails on that
    test; nothing else is affected, because it is a separate job. `tests/state_anchor/
    .cache/` is `.gitignore`d and is not restored from an Actions cache —
    a partially-written 1 GB JSON restored across runs would be worse than
    re-downloading.
11. **`puyapy` emits a byte-different artifact after a dependency bump.** §3.5's
    diff goes red with a byte count and a hash, which is exactly the intended
    outcome: regenerating the committed artifacts becomes a visible, reviewed
    commit rather than a silent drift.
12. **Someone adds a test that needs the network and forgets the marker.** Under
    `--offline` its connection raises `ConnectionRefusedError` and, unless it
    catches it and skips (which `--forbid-skips` also rejects), the offline job
    fails. This is the mechanism that keeps §4.1's automatic marking honest.
13. **A test marked `needs_algod` that actually does not need it.** Nothing
    catches this, and it is the one direction the design is blind in. Named in
    §16 gap 4.
14. **`git` history rewritten / a workflow file edited in a PR.** Workflow changes
    in a PR run the *PR's* version for `pull_request`, which is why `ci-offline`
    must never hold a secret and why `ci-live` must never be PR-triggered (§11).

---

## 11. Adversarial notes — what a green tick can and cannot claim

1. **The strongest attack on this project is not against a contract; it is
   against belief.** §0 is an existence proof: for eight days this repo displayed
   a green nightly "live" tick over a workflow that ran `echo`. Nobody attacked
   it; it simply drifted into being untrue and nothing noticed. Every
   non-vacuity mechanism in §4 exists for that adversary.
2. **A hostile PR cannot obtain anything from `ci-offline`**: read-only token, no
   secrets, no deployment, no network (§4.2's guard runs in the job itself). The
   worst it can do is burn runner minutes.
3. **A hostile PR must never be able to run `ci-live`.** `ci-live` has a Docker
   daemon and outbound network. It is `workflow_dispatch` + `schedule` only, and
   the workflow file carries an inline comment saying so, because the specific
   mistake — `pull_request_target`, which runs *base-branch* workflow code with
   *PR* content and a writable token — is the standard way repos get compromised.
4. **The "no secrets" property must be defended, not merely observed.** Today it
   is free (§8.4). The moment someone adds a paid RPC key to raise rate limits,
   `ci-live` becomes a target and rule 3 becomes load-bearing rather than
   prophylactic. §18 item 15 makes adding a secret require re-reading this
   section.
5. **A green CI does not make an untrusted relayer trusted.** 009 §11 stands
   unchanged. CI proves the client assembles groups the contracts accept; the
   contracts, not CI, are what make a forged proof fail.
6. **A retry that hides a regression is an attack on the reviewer.** §5.6's
   exception-typed gate exists so that the failure mode which has *actually*
   masked a structural insufficiency in this repo — a box-budget rejection —
   cannot be retried, by construction, no matter how a marker is written.
7. **A quarantine with no expiry is a permanent lie with a polite name.** §5.7's
   90-day cap makes silence expensive.
8. **Pinning the algod image is a security property as well as a reproducibility
   one.** `:latest` on a scheduled job means an arbitrary future image executes
   in this repo's CI context, nightly, unreviewed.
9. **CI cannot verify the mainnet deployments.** `Mpt7ReceiptApp` at
   `3665914633` and the donor pair at `3666047587`/`3666047636` are real mainnet
   apps this CI never touches (010 §15 gap 3's boundary, restated). A green
   nightly says nothing about them, and M12's README must not imply otherwise.

---

## 12. Cost — what M11 actually spends

**Runner minutes** (GitHub-hosted, public repo ⇒ free, but the numbers are the
honest ones):

| workflow | frequency | projected wall-clock | notes |
|---|---|---|---|
| `ci-offline` `tests` × 2 Python versions | every push + PR | ~2 min each, parallel | measured components in §7.5 |
| `ci-offline` `contracts` | every push + PR | ~2 min | 34 s measured compile + install |
| `ci-live` `live` | nightly | **14–17 min** | 6 m 04 s measured + 450–580 s projected |
| `ci-live` `contracts-live` | nightly | ~2 min | |
| `ci-live` `live-heavy` | weekly | 15–35 min | dominated by a 1 GB download + merkleize |

≈ **6 runner-minutes per push**, ≈ **19 per night**, ≈ **35 extra per week**.

**Third-party bandwidth**, which is the cost that lands on someone else:

- nightly: several hundred beacon-API and JSON-RPC requests, ~tens of MB.
- weekly: **~1.0 GB** in one `debug/beacon/states` fetch (measured: 1,003,300,280
  B). This is the entire reason `live-heavy` is weekly and not nightly.

**Real chain cost: zero.** Every live test runs against a throwaway dev-mode
algod whose KMD wallet is pre-funded with play money. No mainnet transaction, no
testnet faucet, no real ALGO.

**Engineering cost**, honestly: the workflows are small; the tier plugin is a few
hundred lines; the rebasing in §6.3 touches 11 files and deletes more than it
adds. The genuinely fiddly part is §5.6's report/budget plumbing, and the
genuinely irreducible part is one full live validation run against the real thing.

---

## 13. Test plan

M11 is unusual: its subject is the test suite, so most of its "tests" are the CI
runs themselves. The meta-tests below are the part that lives in `tests/`, and
they are all **offline** — the harness's own correctness must not depend on the
thing it is deciding whether to run. Suites follow the M5 §9 / M6 §11 / M7 §9 /
M8 §13 / M9 §13 / M10 §13 numbering convention.

### 13.1 Suite T — the tier mechanism, offline

| id | test | expectation |
|---|---|---|
| T-1 | Collect with `--offline`; count | equals `tiers.json`'s `totals.offline`; **≥ 400** as an absolute floor so a mis-selection cannot pass by matching a shrunken manifest |
| T-2 | Every collected item carries exactly one tier classification | the partition is total and disjoint; an unmarked item that touches a probe fixture is a failure |
| T-3 | `--check-tier-manifest` against a deliberately edited `tiers.json` | fails, and prints the per-file diff |
| T-4 | The socket guard is installed under `--offline` and not under `--live` | a direct `socket.socket().connect(("127.0.0.1", 80))` raises `ConnectionRefusedError("blocked by --offline")` in the first case only |
| T-5 | The guard's exception is an `OSError` | so every existing probe's `except (URLError, OSError)` still degrades to "unavailable" — §4.2's load-bearing equivalence, asserted rather than assumed |
| T-6 | A test that skips inside the `--offline` selection | the run **fails** with the node id and the skip reason (§4.4) |
| T-7 | A marker typo | `--strict-markers` collection error, not a silent never-selected test |
| T-8 | `plan_box_refs` at 512/512 participation (empty absentee set) | zero-box plan, `forks` still referenced — §10 item 7, never exercised live |

### 13.2 Suite H — the harness's own layering, offline

| id | test | expectation |
|---|---|---|
| H-1 | AST scan of `tests/harness/**` | imports none of: `algopy`; contains no `subprocess` invocation of `puyapy`; contains no `/v2/teal/compile` literal (§6.2) |
| H-2 | The same scan, non-vacuously | `deploy` **and** `relayer` are both genuinely imported — mirroring `test_security_matrix.py`'s own both-ways discipline |
| H-3 | Grep the whole `tests/` tree for the retired duplicates | zero remaining definitions of `_algod_reachable`, `_beacon_reachable`, `funded_account`, `patched_repo_copy`, `deploy_donor_pair`; zero `ALGOD_ADDRESS = "http://localhost:4051"` literals outside `tests/harness/env.py` |
| H-4 | Grep for cross-package conftest imports | zero `from tests.*.conftest import` anywhere |
| H-5 | **`_choose_mode_and_boxes` does not exist**, anywhere in the repo | the §5 fix, asserted as a permanent property rather than a one-time edit |
| H-6 | Grep for hand-rolled box-reference padding | zero occurrences of `box_refs + box_refs` / `box_refs[:4]`-style expressions in `tests/` |

### 13.3 Suite Q — quarantine and variance, offline

| id | test | expectation |
|---|---|---|
| Q-1 | Every `quarantine.toml` entry has all five fields, and `nodeid` resolves against the real collection | a stale entry is a failure, not a no-op |
| Q-2 | An entry with `expires` in the past | the build fails, naming the entry and its owner (§5.7) |
| Q-3 | `expires - opened > 90 days` | rejected at load |
| Q-4 | `live_variance` without a `reason` | collection error |
| Q-5 | A synthetic failure raising `AssertionError` under `live_variance` | **not** retried |
| Q-6 | A synthetic failure raising `PoolExhaustedError` (`RETRY_NOW`) | retried once, and the retry **is reported** even though it passed |
| Q-7 | A synthetic failure raising `RevokedAnchor` (FATAL) / `ConflictLatch` (PAGE_A_HUMAN) | **not** retried |
| Q-8 | A synthetic algod `box read budget (18432) exceeded` string | **not** retried — the single most important negative in this suite (§5.4) |
| Q-9 | `max_attempts=9` | capped at 3 by the plugin |
| Q-10 | 4 distinct tests retrying in one run | `LIVE-VARIANCE-BUDGET-EXCEEDED` |

### 13.4 Suite F — coverage disciplines, offline

| id | test | expectation |
|---|---|---|
| F-1 | Extract every `"Nxx"` from `contracts/**`; diff the uncovered set against `error_codes_uncovered.txt` | equal. Baseline, measured this pass: **22 codes, ≤9 mentioned, 13 uncovered** (§9.1) |
| F-2 | Adding a new code without a test | red, naming the code |
| F-3 | `coverage_sample_300blocks.json` re-derives 007 §14.8's headline | 97.5% T1+T2, 2.2% needing a ZK tier (§9.3) |
| F-4 | Every design doc referenced by `ROADMAP.md` exists at its stated path | catches a renamed/deleted doc — the cheapest possible defence of this repo's own primary artifact |

### 13.5 Suite C — the compile-and-diff gate, offline

| id | test | expectation |
|---|---|---|
| C-1 | All 10 contract entry points compile with pinned `puyapy` | **measured this pass: 10/10 in 34 s** |
| C-2 | `SyncCommitteeVerifier.arc56.json` / `TrustedRootAnchor.arc56.json` vs fresh output | byte-identical whole JSON. **Measured: identical; 6,980 B / 3,027 B** |
| C-3 | Bare-contract TEAL sha256 vs `deploy/schema/_compiled/` | equal. **Measured: 4/4 identical** |
| C-4 | `deploy schema --check` | regenerates byte-identically (G3-M10, in CI at last) |
| C-5 | A deliberately edited contract constant | C-2/C-3/C-4 go red with a byte count and a hash, not a traceback |
| C-6 (**live**) | Bare-contract **assembled** sizes/sha256 vs the cache, via `/v2/teal/compile` | equal — the half §3.5 proves cannot be done offline |

### 13.6 The two runs that are the real test plan

> **CI-1 (G1-M11).** A real `ci-offline.yml` run, on a real push **and** on a
> real pull request, green, on both matrix legs, in a real measured wall-clock,
> with the run's own JUnit XML showing **≥ 400 tests executed and zero skipped**.
> The PR half matters independently: **measured, zero of the 13 historical
> `ci-offline` runs were `pull_request` events**, so "runs on every PR" has never
> once been observed to be true in this repo.

> **CI-2 (G2-M11).** A real, human-triggered `ci-live.yml` `workflow_dispatch`
> run, green, against a real dev-mode algod brought up by the workflow itself
> from the pinned digest, with the uploaded artifact showing: the real
> `go-algorand` version under test, ≥ 90 of the 93 live tests executed (the
> `live_heavy` pair excepted), the real number of
> skips and retries, and — the specific thing this module exists to prove —
> `tests/sync_committee/test_live_e2e_finality.py` **passing without any
> `--deselect`, on whatever the day's real participation happens to be.**

---

## 14. Acceptance gates

| Gate | Statement | How judged |
|---|---|---|
| **G1-M11** | `ci-offline.yml` runs the real offline tier, green, on a real push **and** a real PR, both Python versions, with **zero** skipped tests | CI-1 |
| **G2-M11** | `ci-live.yml` brings up dev-mode algod from the pinned digest, runs the live tier against real mainnet data, and tears down — green, on a real `workflow_dispatch` | CI-2 |
| **G3-M11** | Every contract compiles and every committed ARC-56/TEAL/schema artifact reproduces byte-identically, per PR | C-1…C-5. **Already measured passing this pass** — the gate must stay passing, not become passing |
| **G4-M11** | `test_live_e2e_finality.py` passes live **with no `--deselect` and no padding hack**, and `_choose_mode_and_boxes` no longer exists anywhere in the repo | CI-2 + H-5. **The gate this module exists for** |
| **G5-M11** | No skip in `ci-offline` is silent, and no tier reclassification can land without a manifest diff | T-1, T-3, T-6 |
| **G6-M11** | A box-budget rejection, an `AssertionError`, and every FATAL/PAGE_A_HUMAN class are **never** retried | Q-5, Q-7, Q-8 |
| **G7-M11** | `tests/harness/` delegates: no `puyapy` invocation, no TEAL compile, no group assembly, no box arithmetic of its own — and it genuinely imports both `deploy` and `relayer` | H-1, H-2 |
| **G8-M11** | Zero duplicate availability probes, network constants, funded-account helpers, donor deployers or cross-package conftest imports remain under `tests/` | H-3, H-4 |
| **G9-M11** | `ci-live.yml` requires **no repository secret**, and is reachable from neither `pull_request` nor `pull_request_target` | inspection of the merged workflow; §8.4, §11 |
| **G10-M11** | Every wall-clock and size figure in M11's implementation report traces to a real run or a real file | `ARCHITECTURE.md`'s standing rule |

---

## 15. Questions resolved, and what is handed on

### 15.1 M11's own ROADMAP row

> *"Live-docker-CI vs. pinned-fixture-CI split (both workflows exist from
> scaffold; this module ratifies the policy)."*

**Resolved, and the framing is corrected.** The row treats this as a *choice*
between two CI styles. It is not: `ARCHITECTURE.md` settled the two-workflow
policy at commit 1 and this document does not overturn it. The open question was
always *where the line falls*, and that has now been **measured** rather than
argued: **462 / 555 offline in 33.5 s with every socket dead**, a per-test tier
table (§3.2), and a third tier (`live_heavy`, 2 tests, 1 GB) that nobody had
noticed was a tier at all.

> *"Grows continuously from scaffold onward — revisit after every module lands."*

**Corrected by observation.** It did not grow. It ran `echo` 21 times (§0). The
"grows continuously" model produced nothing in ten modules, which is why M11
ships a mechanism (the tier manifest, `--forbid-skips`, the quarantine expiry)
rather than a convention.

### 15.2 The plan's own M11 sentence

> *"Generalizes the spike's proven 'real mainnet data, nothing synthetic' style
> into a reusable fixture/harness, wrapping `avm_bls_bench.py`/`mpt_bench.py`'s
> simulate-based measurement pattern. Decides live-docker-CI vs. pinned-fixture
> CI."*

Three clauses; two hold, one is superseded.

- *"reusable fixture/harness"* — holds; §6 makes it concrete, and §2.2 measures
  exactly how much duplication it retires.
- *"decides the CI split"* — holds; §3, §7, §8.
- *"wrapping `avm_bls_bench.py`/`mpt_bench.py`'s simulate-based measurement
  pattern"* — **superseded by events, and this document says so rather than
  pretending to do it.** That pattern was already generalised twice, by modules
  that needed it: `relayer/group/submit.py` (simulate → size from the real
  consumed figure → simulate → send) and `deploy/create.py`'s
  simulate-predict-fund-create recipe. Both are live-proven. A third wrapper in
  `tests/harness/` would be a fifth copy of exactly the thing §6.2 forbids. What
  M11 owes the sentence is that the *rule* it protects — no cost number without a
  real response — becomes mechanical, and §9.4 explains honestly why the
  mechanical form of that (a unified budget-regression gate) is deferred rather
  than half-built.

### 15.3 Inherited questions, answered

**Flagged for M11 across the prior design docs** — every one hunted down and
answered, in the discipline M9 §15.3 and M10 §12 established:

| source | item | resolution |
|---|---|---|
| 008 §15.5 (1) | G4-M8 gindex regeneration must run in CI | **Closed, better than asked**: 9 of `test_forks_gindex.py`'s 10 tests are offline and run **per PR**, not nightly (§9.2) |
| 008 §15.5 (2) | The Deneb→Electra straddle fixture (F6) is a new fixture class | **Closed by M10-era work, but it lands in the live tier**: `test_forks.py` needs algod (its folds are `simulate`d on-chain), so F6 runs nightly, not per-PR. Named as a real limitation in §16 gap 3 |
| 008 §15.5 (3) | `bench/anchor_results.json` joins the four bench files | **Declined, explicitly** (§9.4): bench scripts do not become CI jobs; a unified budget gate is `O-M11-2` |
| 008 §15.5 (4) | G9-M8 error-code coverage discipline | **Owned, and baselined by measurement**: 22 codes, ≤9 mentioned, 13 uncovered; Suite F-1/F-2 freeze the list and make growth red (§9.1) |
| 008 §13 F1 | Regenerate all gindices in CI | same as (1) — closed |
| 009 §15.4 | "Suite P is pure and belongs in `ci-offline.yml` from day one" | **Done**: `test_plan_boxes.py` (24) + `test_segmentation.py` (5) are Tier A, measured |
| 009 §15.4 | "Suite L is the natural body of `ci-live.yml`, and L-2 should gate any claim that M4 works on live data" | **Done, with one correction**: Suite L is `ci-live`'s body. But L-2 (G1-M9) **cannot** gate anything today — M9 measured it structurally unreachable at 511/512 participation (210,381–211,502 opcodes vs a hard ~177,392 ceiling). It goes in `quarantine.toml` with those real numbers and a 90-day expiry (§5.7), not in a gate |
| 009 §15.4 | "M11 should own rebasing the four existing live test files onto M9" | **Done, file by file** (§6.3), and it turns out to be the *same work* as fixing the flake (§5.4) — the rebasing is not tidying, it is the bug fix |
| 010 §16 | "Rebasing the live test files themselves onto the tool is M11's" | **Done** — same table (§6.3); the four stale `conftest` copies of promoted `deploy`/`relayer` code are deleted |
| 010 §15 (3) | No testnet/mainnet run in the acceptance gate | **Inherited unchanged**, and M11 does not close it (§1.2 item 4). Restated for M12 |
| 010 §15 (4) | M6 still has no client that submits | **Not M11's to close.** `Mpt6ComposerApp` is deployed by `deploy apply` and exercised structurally by `tests/unit/test_mpt6_*` (53 offline tests), but no live submission exists to schedule. Recorded, not papered over |
| 007 §8.4 | "M11: widen the receipt-size sample" | **Already closed** by 007 rev 8 (300 blocks / 94,667 receipts, committed). M11 adds only the offline re-derivation assertion (§9.3) |
| 007 §8.4 | "M11 owns the circuit's differential test corpus" | **Deferred with a reason**: no circuit exists in this repo to run it against; `O-M11-4`, gated on T3 shipping (§9.5) |
| 002 §9.2 | O-1/O-2 "(M11)" — RLP early-exit and table-free capture | **Already closed, by M2 itself.** 002 §16 shipped `rlp_scan_upto` and `rlp_scan2` and measured G6 at 2,566. The "(M11)" owner tags are stale; §18 item 20 has M11 correct them, since they are the only two places in the design corpus that still name M11 as owner of work that is done |
| 003 (M3 row) | "ci-live.yml/ci-offline.yml still placeholders (M11's job)" | **This document** |

### 15.4 Handed on

**To M12 (docs & release).**

1. **The README badge is now a claim that can be true.** M12 should add one, and
   it must point at `ci-offline` — the per-PR gate — not at `ci-live`, whose
   green means "on the day it ran". §1.3 is the wording M12 should paraphrase.
2. **A release requires a `ci-live` run, cited by run id.** `ARCHITECTURE.md` and
   the plan both already say `ci-live` must pass before any module is marked
   "Released"; from M11 onward there is a real run and a real uploaded artifact
   to cite, so M12 should require the *citation*, not the assertion.
3. **The quarantine list is release-blocking input.** Anything in
   `quarantine.toml` at release time is, by definition, a known-unproven claim,
   and belongs in the release notes — starting with G1-M9/L-2.
4. **`requires-python`.** §7.3 leaves `>=3.10` unverified; M12 owns the packaging
   story and should not ship a floor CI has not run.
5. **Contract versioning (M12's own open question) now has a mechanism.** §3.5's
   artifact diff means the compiled bytecode of every contract is pinned in-repo
   and CI-enforced; an AVM/fork-gated version string can be tied to those hashes
   rather than to a hand-maintained number.

**To a future M8 revision.** §9.1's `error_codes_uncovered.txt` is a 13-item work
list with a mechanism that stops it growing. It is the cheapest well-defined
coverage work left in this repo.

**To a future M4/M9 revision.** G1-M9 needs either a real day with moderate,
spread-out absenteeism or the two-group fallback (`O-M9-2` / 008 §9.3).
`ci-live`'s nightly run is, incidentally, the cheapest possible way to *find*
such a day: §18 item 14 has the live report record the day's real participation
and k, so that after a few weeks there is real data on whether the k=8 window
ever opens.

---

## 16. Honest gaps and deferred work

**Gaps this design knowingly leaves open:**

1. **`ci-offline` cannot see a real chain, by construction.** 462 of 555 tests is
   83.2% by count, but the 93 it cannot run include every claim this project is
   actually interesting for: every opcode budget, every real submission, every
   box-reference cap, every real-mainnet-data shape assumption. Per-PR CI proves
   the Python is self-consistent. It does not prove the system works. The
   nightly job is not a nice-to-have here; it is where the project's actual
   claims live, and §1.3 exists so nobody reads the badge otherwise.
2. **Nightly is a 24-hour detection window for a live regression**, and a bisect
   across a day's commits costs a 15-minute run each. Accepted: a hosted runner
   cannot carry a 15-minute live suite per PR, and no cheaper honest option was
   found.
3. **The Deneb→Electra straddle (008 §15.5 item 2) is nightly, not per-PR**, and
   its `block_roots` fold is still a synthetic fixture with real constants —
   `/eth/v2/debug/beacon/states/{slot}` 404s near that ~15-month-old boundary on
   every reachable endpoint (008 §17, 009 §16 gap 4). M11 changes nothing about
   that ceiling; it only schedules the test that exists.
4. **Nothing detects an *over*-marked test** (§10 item 13). A test marked
   `needs_algod` that does not need algod silently leaves the per-PR tier
   forever, and the manifest diff shows the move but cannot judge it. The only
   defence designed here is that the move is a reviewable one-line diff. A real
   detector would run the live tier under `--offline` and flag anything that
   passes — cheap, and deliberately **not** in v1 because a test that *passes*
   without algod may still be *asserting* something meaningless without it.
   (`O-M11-6`.)
5. **`live_heavy` is weekly, so HISTORICAL mode's real `block_roots` fold gets
   ~4 real exercises a month.** That is a real reduction in coverage frequency
   versus "run everything nightly", chosen for a real reason (1.003 GB per run,
   measured, from a volunteer endpoint) and stated rather than hidden.
6. **No budget-regression gate** (§9.4, `O-M11-2`). This is the largest gap
   relative to `ARCHITECTURE.md`'s central rule: CI enforces that cost *claims*
   are documented, not that costs have not *changed*. A silent 20% budget
   regression in a contract would pass every gate in this document.
7. **The Python matrix does not cover the declared floor** (§7.3). `>=3.10` stays
   an unverified claim until someone measures or narrows it.
8. **CI never touches the real mainnet deployments** (§11 item 9), including the
   live `Mpt7ReceiptApp` at `3665914633` and the Vercel service at
   `x402endpoint-nu.vercel.app`. Neither has any automated check of any kind.
   That is a genuine operational gap this module does not close, and M12 should
   not describe the service as "monitored".
9. **The variance budget's consecutive-run check depends on the Actions API and
   artifact retention.** If artifacts expire or the API call fails it reports
   "unknown" rather than passing — correct, but it means the check can be
   silently degraded by a retention setting nobody thinks of as a test setting.

**Deferred (`O-M11-*`), each measurement- or event-gated:**

| id | idea | gate |
|---|---|---|
| `O-M11-1` | A self-hosted runner with a long-lived algod, to make the live tier per-PR | only if nightly detection proves too slow in practice |
| `O-M11-2` | Unified budget-regression gate over all bench outputs (subsumes 008 §15.5 item 3) | first make all four bench result files one shape; then a real regression must be caught by it before it is trusted |
| `O-M11-3` | `pytest-xdist` for the live tier | needs per-worker algod isolation, i.e. a container per worker; only if the live job passes ~30 min |
| `O-M11-4` | The T3 circuit differential corpus (007 §8.4) | when T3 ships a prover (009 `O-M9-1`) |
| `O-M11-5` | Rebase `bench/*.py` onto shared helpers | only alongside a real reason to touch them; target `deploy/`, never `tests/` (§6.4) |
| `O-M11-6` | Over-marking detector: run the live tier under `--offline`, flag passes | needs a way to distinguish "passes without algod" from "asserts nothing without algod" (§16 gap 4) |
| `O-M11-7` | Cache the beacon `BeaconState` in an Actions cache for `live-heavy` | only if the 1 GB fetch becomes the job's failure mode; a partial 1 GB restore is worse than a re-download (§10 item 10) |

---

## 17. File layout

```
.github/
  workflows/
    ci-offline.yml            REWRITTEN (§7.4) -- was an echo since 51dd033
    ci-live.yml               REWRITTEN (§8.5) -- was an echo since 51dd033
  scripts/
    algod_up.sh               NEW. the spike README recipe, verbatim, with a real
                              /v2/status poll and a positive /v2/teal/compile
                              assertion (§8.1, §10 item 3)
    algod_versions.sh         NEW. records the go-algorand build under test

tests/
  conftest.py                 NEW (root). markers, plugins, shared fixtures
  harness/                    NEW
    __init__.py
    env.py                    one algod/kmd address + token; the 4 availability fixtures
    chain.py                  algod_client/kmd_client/funded_account/account
    deployment.py             THIN wrappers over deploy.* and relayer.group.donors
    m4.py                     installed_committee / finalized_m4 via EthAvmClient
    tiers.py                  markers, --offline, --live, manifest write/check
    variance.py               @pytest.mark.live_variance, retry policy, budget
    quarantine.py             quarantine.toml loader + validity assertions
    report.py                 JUnit -> $GITHUB_STEP_SUMMARY (skips/retries/quarantine)
    compile_check.py          --compile-all / --diff-artifacts / --diff-assembled
    tiers.json                the committed, CI-diffed tier manifest
    quarantine.toml           the committed, dated, expiring exclusion list
    error_codes_uncovered.txt the committed 13-item baseline (§9.1)
    test_tiers.py             Suite T
    test_harness_layering.py  Suite H
    test_quarantine.py        Suite Q
    test_coverage_discipline.py Suite F
    test_compile_gate.py      Suite C (C-1..C-5; C-6 is live)

pyproject.toml                [project.optional-dependencies] test/contracts;
                              [tool.pytest.ini_options] (§7.2)
```

**Files this module changes elsewhere** (all in §6.3's table): five `conftest.py`
files, and nine test files that shed their duplicated probes, their imported
`_choose_mode_and_boxes`, and their padding workarounds.

**Files deleted**: none outright — but `tests/sync_committee/
test_live_e2e_finality.py` loses `_choose_mode_and_boxes`, `_submit_update_group`,
`_issue_donor_txn` and its two duplicated happy-path tests, and
`tests/state_anchor/conftest.py` loses four helpers to re-export.

**One `relayer/` change**: `EthAvmClient._submit_update_group` →
`submit_update_group` (§6.3). **Nothing under `contracts/` is modified** — the
same scope boundary M8, M9 and M10 all kept.

---

## 18. Implementer checklist (normative MUSTs)

1. **MUST NOT** leave either workflow containing an `echo` as its only real step.
   Both **MUST** run the tests they name, and the implementation report **MUST**
   cite a real run id for each (G1-M11, G2-M11).
2. **MUST** delete `_choose_mode_and_boxes` from the repo and **MUST NOT**
   replace it with any hand-computed box-reference list. Every M4 update group in
   `tests/` **MUST** go through `relayer.group.boxes.plan_box_refs` (009 §18 item
   2 — a fixed box-reference constant has now been wrong **four** times in this
   codebase: 6,144 / 18,432 / 20,480 / 22,528).
3. **MUST NOT** retry, rerun, `xfail` or quarantine any failure whose exception
   chain does not contain a `relayer.errors.RelayerError` with `retryability in
   {RETRY_NOW, RETRY_REPLANNED}`. In particular a `box … budget … exceeded`
   rejection, any `AssertionError`, any `logic eval error` and every FATAL /
   PAGE_A_HUMAN class **MUST** fail on the first attempt (Q-5, Q-7, Q-8).
4. **MUST** run `ci-offline` on a Python matrix that includes 3.13 (the
   interpreter every measured number in this repo came from), and **MUST** either
   add the declared `requires-python` floor to that matrix or raise the floor to
   something CI runs. **MUST NOT** leave `>=3.10` untested and unamended.
5. **MUST** make `--offline` deselect the live tier, install the socket guard,
   **and** forbid skips. **MUST** raise `ConnectionRefusedError` (an `OSError`)
   from the guard, so every existing probe degrades identically (T-5).
6. **MUST** commit `tiers.json` and **MUST** fail CI on any difference. **MUST**
   assert an absolute floor (≥ 400 offline tests) as well as the manifest match,
   so a shrunken manifest cannot make a shrunken run pass (T-1).
7. **MUST** fix the 8 setup errors of §3.3 by giving `account` a single guarded
   definition in `tests/harness/chain.py`, not by adding two `skipif`s.
8. **MUST** keep `tests/harness/` delegating: no `puyapy` invocation, no
   `/v2/teal/compile`, no `algopy` import, no group assembly, no box arithmetic.
   Enforced by an AST test both ways, non-vacuously (H-1, H-2), mirroring G8-M9
   and G8-M10 exactly.
9. **MUST** pin the algod container by **digest**, **MUST NOT** use
   `algorand/algod:latest`, and **MUST** record the real `/versions` response as
   a job artifact.
10. **MUST** replace the spike recipe's `sleep 12` with a real `/v2/status` poll,
    and **MUST** assert `POST /v2/teal/compile` returns 200 before running any
    test (§10 item 3).
11. **MUST** tear the container down under `if: always()`.
12. **MUST** trigger `ci-live` from `workflow_dispatch` and `schedule` only.
    **MUST NOT** add `pull_request` or `pull_request_target` to it, and **MUST**
    carry §11's inline comment saying why.
13. **MUST NOT** introduce any repository secret. If a future endpoint needs a
    key, §11 **MUST** be re-read first and the decision recorded in `ROADMAP.md`.
14. **MUST** have the live report record, per run: the algod build, the real
    participation count and the real `k` (key boxes touched) for the day's
    bitfield, every skip with its reason, every retry with its exception type,
    and the quarantine list. The participation/`k` line is what turns nightly
    runs into evidence about whether G1-M9's window ever opens (§15.4).
15. **MUST** fail the build on an expired quarantine entry, and **MUST** cap
    `expires - opened` at 90 days.
16. **MUST** put the compile-and-artifact-diff job in `ci-offline`, covering all
    10 entry points, both ARC-56 artifacts (whole JSON), all four bare-contract
    TEAL hashes, and `deploy schema --check`. **MUST** pin `puyapy==5.9.0`, and
    **MUST NOT** `pip install puya` (007 §14.6's real trap).
17. **MUST** add `[project.optional-dependencies]` covering `pytest`,
    `algorand-python`, `algorand-python-testing`, `remerkleable`, `trie` and
    `PyYAML`, pinning the two `algorand-python*` packages exactly (§7.2).
    **MUST** keep `requirements.txt` and `pyproject.toml` in step — nothing
    enforces that today (ROADMAP, M7 row), and M11 is where a test for it
    belongs.
18. **MUST NOT** add `coverage.py`, `pytest-rerunfailures`, or `pytest-xdist` in
    v1 (§1.2 items 6/7, §5.6).
19. **MUST** cite a real command output for every wall-clock, size and count
    figure in the implementation report (`ARCHITECTURE.md`, G10-M11).
20. **MUST** update `ROADMAP.md` to record: M11's own results and run ids; the
    §0 finding that 21/21 historical runs were vacuous; §9.1's measured
    error-code baseline; and the correction that 002 §9.2's `O-1 (M11)` /
    `O-2 (M11)` owner tags are **stale** — both were shipped by M2 itself
    (002 §16) and neither is M11's work.
