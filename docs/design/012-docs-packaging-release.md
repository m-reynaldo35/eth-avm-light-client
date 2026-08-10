# 012 — M12: Docs & packaging / release prep

**Status**: Design drafted, awaiting human review.
**Depends on**: M10 (`deploy/`) and M11 (`tests/harness/`, both workflows) — both
implemented, committed and pushed (`git log`: `56781cb`, `325797f`, `8d95cc7`,
`4fb90e2`, `e8bf7b8`). Transitively depends on every module M1–M11, because M12's
subject is *what this repo may claim about all of them*.
**Consumed by**: every person who is not the author. That is the whole module.
**Design-time convention, inherited**: every number below is labelled
**measured** (a real command run, a real HTTP response, or a real file read
during this design pass, cited to the command) or **projected** (an estimate this
document owns, which an implementation pass must replace with a real result).
`ARCHITECTURE.md`'s standing rule applies unchanged and is, in this module,
also the *subject matter*: M12 is the module that decides which of this
project's numbers a stranger is allowed to see, and in what frame.

> **Numbers new to this document.** §2, §3.7, §4.1 and §7 contain measurements
> taken *while writing this design doc*, against the real GitHub Actions API, the
> real Algorand mainnet at `mainnet-api.algonode.cloud`, the real live Vercel
> service, a real `python -m build` wheel, and a real `pip install --dry-run
> --report`. Four of them contradict statements currently in this repo's own
> `ROADMAP.md` or design corpus. Those are §2.4 (`ci-live` has never run its real
> body), §2.5 (the mainnet app `3664247481` no longer exists, and the x402
> service *is* publicly exposed), §4.1 (`pip install eth-avm-relayer` installs 59
> packages), and §2.3 (`python -m relayer` does not work).

---

## 0. The question, stated first

Every prior design doc in this repo opens by naming its own hardest question.
M9's was "refactor or rewrite". M10's was "thin CLI or real engineering". M11's
was answered by a two-minute API call and reframed the module. M12's is answered
the same way, and the answer is the same shape.

**Measured** (`gh api repos/m-reynaldo35/eth-avm-light-client/actions/workflows/ci-live.yml/runs`,
this pass, and `gh api .../actions/runs?per_page=100`):

> **27 workflow runs. 19 `push`, 8 `schedule`, and — still, today —
> `pull_request`: zero.**
>
> **All 8 `schedule` runs of `ci-live.yml` carry `head_sha = 1148ae4`.** That is
> M6's implementation commit, and it is the last commit that was on GitHub's
> `main` between 2026-08-01 and 2026-08-07. Every one of those eight runs
> executed the scaffold-commit placeholder. **M11 replaced that placeholder
> four minutes before this pass began** (`325797f`, pushed 23:21 UTC; the
> current HEAD `e8bf7b8` at 23:34 UTC; measured wall-clock at the start of this
> pass: `2026-08-07 23:38 UTC`), and the next scheduled `ci-live` fires at
> 06:00 UTC.
>
> **So `ci-live.yml`'s real body has never executed. Not once. G2-M11 — "a
> real, human-triggered `workflow_dispatch` run, green" — is open, and
> `ARCHITECTURE.md`'s rule that `ci-live` "must be run manually and pass before
> any module is marked 'Released'" has never once been satisfiable.**

M11 spent its §0 establishing that a green tick over an `echo` is an active
false claim. It fixed that for `ci-offline` — **measured**: run
[31227550081](https://github.com/m-reynaldo35/eth-avm-light-client/actions/runs/31227550081)
on `e8bf7b8`, 3/3 jobs green, `contracts compile + artifact diff` 84 s,
`offline tier (py3.12)` 3 m 21 s, `offline tier (py3.13)` 3 m 05 s. It did not,
and could not within its own pass, fix it for `ci-live`.

So M12's question is not "what should the README say".

> **A v1 release is a set of claims, made once, in public, by someone who will
> not be in the room when they are read. This repo currently contains eleven
> modules' worth of real, measured, live-proven work and a `README.md` whose
> first substantive line is "Early scaffold stage". Which claims can this
> project actually make on the evidence it holds — and what is the smallest set
> of *real runs* that has to happen before it may make them?**

**The answer, stated up front, defended in §3–§8:**

> **Three artifacts and two runs.**
>
> **The artifacts**: (1) a **generated, CI-diffed `deploy/versions.json`** whose
> primary key is the approval-program SHA-256 that already exists, is already
> pinned, and is already byte-diffed per PR — because a hand-maintained version
> number is precisely the drift class 010 §3.3 measured three times in this
> repo's own prose; (2) a **committed mainnet manifest**, which is the only
> thing standing between "a deployed app id mentioned in a ROADMAP paragraph"
> and "a deployment anyone can verify"; (3) a **documentation set whose every
> claim cites a run, a response, or a file** — with a mechanical test that the
> corrections owed since 007 revision 3 have actually landed.
>
> **The two runs**: a real green `ci-live` `workflow_dispatch` (closing
> G2-M11), and a real **testnet** `deploy apply` → `verify` → M9 end-to-end
> (closing 010 §15 gap 3, which 011 §15.3 restated and explicitly handed here).
> Neither is optional and neither is expensive; together they are the entire
> difference between a release and a claim.
>
> **Measured, this pass, and it is the single most encouraging number in this
> document**: the live mainnet `Mpt7ReceiptApp` at app id **`3665914633`** has an
> approval program of **3,108 B** whose SHA-256 is
> `f7a846ff33314d8f9ecc48e85584327f13e9cb808a3650b30e69339c7fcdc9d2` — **byte-
> identical to the pin in `deploy/schema/_compiled/Mpt7ReceiptApp.compiled.json`**,
> as is the 4-byte clear program (`ed90f0d2…0ce7`). The verification primitive a
> release needs already works, against real mainnet, with no signer, today. What
> is missing is a committed manifest telling anyone which app id to check.

**Three things this document has to get right**, in order of how much damage
getting them wrong does:

1. **Not letting the README launder a projection into a claim** (§5, §10). This
   repo's engineering culture is unusually good at labelling `measured` vs
   `projected` *inside* design docs. A README has no such convention and is read
   by people who will never open `docs/design/`. Every number that crosses into
   `README.md` loses its provenance unless something forces it not to, and §12's
   Suite N is that something.
2. **Versioning the thing that actually varies** (§3). The tempting design is a
   semver string in `pyproject.toml`. That number describes the Python client.
   It says nothing about which bytecode is on chain, which AVM it was measured
   against, or which Ethereum forks it can verify — and those three are the only
   things a consumer of this project needs to know. §3 gives them their own
   axes and ties the identity to a hash that CI already enforces.
3. **Being honest that a docs module cannot close an engineering gap** (§7,
   §15). M5's three budget gates are open. M6 has no submitting client. Thirteen
   of M8's twenty-two error codes are untested. T3 does not exist. M12 must
   neither pretend those are closed nor refuse to ship over them — it must put
   each one in a **release-readiness checklist with a real state and a real
   verdict**, which is what §7 is.

---

## 1. Scope, non-goals, trust preconditions

### 1.1 In scope

1. **A contract-versioning scheme** (§3) — the module's own headline open
   question and `ARCHITECTURE.md:56–61`'s explicitly deferred policy. Three
   axes, a generated artifact, a per-contract fork-event decision table, and a
   discovery path a third party can walk with public reads only.
2. **`deploy/versions.json`** — generated by the existing schema generator,
   committed, and diffed by the existing `ci-offline` job (§3.4, §3.6).
3. **A committed mainnet manifest** and the `deploy resolve` verb that makes
   "which app id do I point at" answerable without reading a ROADMAP paragraph
   (§3.5, §3.6).
4. **Packaging** (§4) — what ships, under what name, with which dependencies,
   with which entry points, and what an installed wheel genuinely cannot do.
5. **The documentation set** (§5) — `README.md` rewritten, `CHANGELOG.md`
   created, `docs/security.md`, `docs/versioning.md`, `docs/operating.md`,
   `docs/quickstart.md`, and the discharge of every outstanding
   documentation-correction obligation in the corpus (§5.4).
6. **A release process** (§6) — the runbook, the tag, the release notes'
   required contents, and the two real runs that gate it.
7. **A release-readiness checklist** (§7) — every open gate, quarantine entry
   and honest gap across M1–M11, with a measured state and a blocking/
   non-blocking verdict.
8. **Answering every "flagged for M12" hand-off in the corpus** (§14.3), in the
   discipline 011 §15.3 established: a real decision, a real fix, or an honest
   "still open, here is why, here is the cost of closing it".

### 1.2 Non-goals (explicit)

1. **No mainnet deployment of M4, M6 or M8.** `deploy/targets/mainnet.json` has
   `"deploy": false` for all four contracts and this document does not change
   that. Reasons, all pre-existing: `O-M10-3` (a multisig/hardware governance
   signer, "before any mainnet deployment holding real value") is unmet; 010
   §1.3 establishes M10 as the one trusted component and governance-key custody
   is a human's decision, not a design doc's; and §7's checklist has open rows
   that a mainnet trust root should not carry. **M12 writes the runbook; a
   human performs the deployment.**
2. **No contract changes.** Same boundary M8, M9, M10 and M11 all kept. In
   particular M12 does **not** add the `gov`-only MBR sweep (`O-M10-6`), the
   depth guard §3.7 shows is missing from `append_fork_row`, or a readonly
   fork-row getter — each is named as a future revision's work with its reason.
3. **No T3/ZK.** No prover, no trusted-setup provisioning (`O-M10-1`), no
   circuit differential corpus (`O-M11-4`). §3.2's third version axis is
   *defined* so that T3 has somewhere to land, and is **empty** in v1.
4. **No PyPI publication in this pass.** §4.5 designs the distribution and
   §13's G5-M12 gates it against a clean venv, but pressing "upload" claims a
   name in a global namespace and is a human's decision. The gate proves the
   artifact is publishable; the human publishes it.
5. **No monitoring or alerting for the live service.** 011 §16 gap 8 records
   that nothing watches `x402endpoint-nu.vercel.app` or app `3665914633`. M12
   does **not** build monitoring; it forbids the docs from implying it exists
   (§5.2, G7-M12) and records the gap (`O-M12-3`).
6. **No Bazaar discovery registration** (§8). Declined for v1, with a reason.
7. **No new test *content* for M1–M11.** Same boundary M11 drew. M12's suites
   test artifacts, packaging and *claims*, not contracts.
8. **No budget-regression gate** (`O-M11-2`, still open). M12 inherits 011's
   reasoning unchanged and does not build half of one to make a release look
   better instrumented than it is.

### 1.3 Trust preconditions — what a v1 release is allowed to mean

M9 is untrusted (009 §1.3). M10 is trusted (010 §1.3). M11 is claim-making (011
§1.3). **M12 is claim-*publishing*, which is strictly worse**: its output is a
belief in the head of someone who has no access to this repo's context, cannot
distinguish `measured` from `projected` because the README carries no such
labels, and will not read 19,280 lines of design docs to find the caveat.

1. **A `v1.0.0` tag means**: on the day it was cut, every claim in `README.md`
   and `CHANGELOG.md` traced to a cited run id, a cited on-chain response, or a
   cited file in the tree, and the two runs of §6.3 were green. It means
   **nothing** about any later day, any other network, or any deployment not
   named in the committed manifests.
2. **A published `eth-avm-relayer` wheel means**: this Python assembles the
   proof shapes M4/M6/M7/M8 accept and submits them. It is **untrusted** (009
   §1.3 stands unchanged) and it is **not** the verifier. The verifier is
   bytecode on Algorand, and the wheel does not contain it (§4.2 —
   **measured**: the wheel contains 35 `.py` files and zero data files).
3. **"Verified on Algorand" means the sync-committee light-client trust model,
   not full-node security.** 008 §5.3 and §15.6 are normative here and this is
   the single most important sentence M12 owes anyone: sync-committee messages
   are not slashable, a 2/3 majority of 512 validators can sign a lie at no
   cost, and detection is off-chain. **This sentence must appear in the same
   paragraph as the first use of "verifier", "verified" or "trustless" in
   `README.md`** (G7-M12).
4. **A green badge means what 011 §1.3 says it means, and the badge must point
   at `ci-offline`.** `ci-live`'s green has a date on it and expires. A README
   badge that silently tracked the nightly would be exactly the §0 failure
   mode with a longer fuse.
5. **CI never touches the mainnet deployment** (011 §11 item 9, §16 gap 8).
   `deploy verify` can, and §3.5 makes that a documented, runnable command —
   but it is a command a human runs, not a job that runs itself, and the docs
   must say so in those words.
6. **A quarantined test is a known-unproven claim** (011 §5.7, §15.4 item 3).
   Anything in `tests/harness/quarantine.toml` at tag time belongs in the
   release notes with its real numbers and its real expiry date.

---

## 2. What exists today — the survey, measured

### 2.1 The documentation surface

**Measured** (`ls -la`, `wc -c`, and reading each file in full):

| file | bytes | last touched | state |
|---|---:|---|---|
| `README.md` | 2,277 | **2026-07-30** (`51dd033`, the scaffold commit) | untouched since day 1 |
| `ARCHITECTURE.md` | 3,669 | 2026-07-30 | untouched since day 1 |
| `CONTRIBUTING.md` | 1,499 | 2026-07-30 | untouched since day 1 |
| `ROADMAP.md` | 97,097 | 2026-08-08 | the real state of the project, in 36 very long lines |
| `docs/design/00*.md` | — | continuously | 11 docs, 19,280 lines total |
| `CHANGELOG.md` | — | — | **does not exist** (`find . -iname "CHANGELOG*"` → nothing) |
| per-package README | — | — | **none** (`find . -name "README*"` → root, `.pytest_cache/`, and two frozen files under `tests/fixtures/spike-reference/`) |

`README.md`'s substantive content, read in full:

- **"## Status — Early scaffold stage."** Measured against reality: 11 of 12
  modules implemented, 35 commits, 592 collected tests, a real mainnet
  deployment serving real USDC payments, and a green CI. This is the single
  most wrong sentence in the repo.
- **No badge.** 011 §15.4 item 1 hands M12 the job of adding one, and notes
  that it is now a claim that *can* be true.
- **No install instructions, no quickstart, no CLI documentation, no app ids,
  no fork-support statement, no security/trust-model section.**
- Line 3 reads "An Ethereum → Algorand **light-client verifier**". 008 §15.6 is
  therefore already violated: the word appears with no trust-assumption
  sentence anywhere near it.
- Line 45 carries the ">4096B receipt" text that 007 §10 assessed as "accurate
  as written, but should point at 007 §2.4 for the measured non-naive cost".
- The spike figures it quotes (`~6,827 opcode budget / 0.010 ALGO`, `~27x
  headroom`) are correctly attributed to the spike, but M5 §16 has since
  **measured** the security-fixed 8-node account walk at **5,116** and the
  3-node receipt walk at **1,813** — different numbers for a different thing,
  which is exactly the confusion a README invites if it does not say which.

`ARCHITECTURE.md:56–61`, the "Contract versioning" section, in full:

> Versioning is gated by AVM/consensus-protocol compatibility, not plain
> semver — a contract version implicitly targets a specific AVM version and a
> specific set of supported Ethereum forks (Altair/Capella/Deneb field
> layouts). **This gets a concrete policy in M12's design doc once the supported
> fork range is known from M3/M4.**

The supported fork range is now known and is **not** what that sentence guesses.
**Measured** (`deploy/forks.py::FORK_FIELD_COUNTS`, and all three files under
`deploy/targets/`): the range is `{deneb: 28, electra: 37, fulu: 38}` fields —
**Deneb, Electra, Fulu**, not "Altair/Capella/Deneb". §3 writes the policy and
§5.3 corrects the sentence.

### 2.2 The packaging surface

**Measured**, `python3 -m build --wheel`, this pass:

```
Successfully built eth_avm_relayer-0.1.0-py3-none-any.whl
```

| property | measured |
|---|---|
| wheel size | **84,041 B** |
| entries | **40** — 35 under `relayer/`, 5 under `dist-info/` |
| non-`.py` files | **zero**, other than `LICENSE`/`METADATA`/`WHEEL`/`RECORD`/`top_level.txt` |
| `top_level.txt` | `relayer` |
| `Requires-Python` | `>=3.12` |
| `Description` | **absent** — no `readme` key in `[project]`, so a PyPI page would be blank |
| `Author`, `Project-URL`, `Classifier`, `Keywords` | **all absent** |
| `[project.scripts]` | **absent** — no console script exists |

`[tool.setuptools] packages` lists exactly seven: `relayer`, `relayer.sources`,
`relayer.codec`, `relayer.ssz`, `relayer.proofs`, `relayer.group`,
`relayer.drivers`. **`deploy`, `contracts`, `service`, `tests` and `bench` are
not packaged**, which 009 §17 scoped deliberately and `pyproject.toml:40–43`
hands to M12 verbatim:

> Only `relayer` is a distributable package today (009 §17) … **M12 ("Docs &
> packaging / release prep") owns the full release story**; this file is the
> minimum needed for both `relayer`'s own editable-install consumers and
> Vercel's build to resolve everything they need from one file.

**Two real defects fall out of that last clause**, and both are measured in
§4.1 and §4.2 rather than asserted here.

### 2.3 The CLI surface — one of the two exists

**Measured**, this pass:

```
$ python3 -m relayer status
/usr/bin/python3: No module named relayer.__main__; 'relayer' is a package and
cannot be directly executed

$ python3 -m deploy --help
usage: python -m deploy [-h] {plan,apply,verify,inspect,schema,recover,fund,renounce} ...
```

`find relayer -name "__main__.py"` returns nothing. There is no
`relayer/__main__.py` and no console-script entry point, so **every documented
invocation of the relayer CLI is false today**:

- `relayer/__init__.py`'s own module docstring: *"A library (`EthAvmClient`) with
  a thin CLI shell (`python -m relayer ...`, `relayer/cli.py`) over it."*
- `relayer/cli.py`'s module docstring lists five: `python -m relayer status`,
  `sync`, `anchor`, `prove account`, `prove receipt`.
- 009 §15.4's hand-off to this module, in full: *"**To M12.** The CLI is the
  first user-facing surface this project has; the README's quickstart should be
  `python -m relayer status` against a public deployment."*

The command 009 nominates as the README's quickstart does not run. `relayer/cli.py`
is 117 lines and `build_parser()`/`main()` are complete and correct; what is
missing is a two-line `__main__.py`. That is the whole defect, and it is the
cheapest genuine bug in this document.

`deploy/cli.py` is 250 lines with eight verbs and works. **Measured**:
`python3 -m deploy schema --check` → `schema is up to date`, exit 0.

Neither CLI is documented anywhere a new user could find. `--help` output is
bare (`add_parser("status")` with no `help=`, no `description=`, no `epilog`),
`README.md` mentions neither, and there is no `docs/` page for either.

### 2.4 What CI actually proves, measured against the real API

**Measured** (`gh api`, this pass — the full run list, 27 rows):

| | count | note |
|---|---:|---|
| total workflow runs | **27** | since 2026-07-30 |
| `push` events | **19** | |
| `schedule` events | **8** | all of them `ci-live.yml` |
| `pull_request` events | **0** | this repo has never had a PR (`gh api .../pulls?state=all` → **0**) |
| failures, ever | **2** | `4fb90e2`, `325797f` — both during M11's own pass, both real gaps it then fixed |
| `ci-live.yml` runs at a `head_sha` newer than `1148ae4` | **0** | §0 |

So, precisely:

- **G1-M11 is half-satisfied.** Its statement is "green on a real push **and** a
  real PR, both Python versions, with zero skipped tests". The push half is
  measured green on `e8bf7b8` (run 31227550081, 3/3). The PR half has never been
  observed, because this project has never opened a PR. 011 §7.1 measured the
  same thing about its 13 predecessors and said so; it remains true.
- **G2-M11 is entirely open.** §0.
- **G3-M11 is measured green** (the `contracts compile + artifact diff` job, 84 s
  on the current HEAD).

Locally, **measured this pass**:

```
$ python3 -m pytest tests/ -q --offline --check-tier-manifest
500 passed, 92 deselected in 117.59s (0:01:57)
```

and `tests/harness/tiers.json`'s committed totals are
`{"collected": 592, "offline": 500, "live": 90, "live_heavy": 2}` across 55
files. 500 + 92 = 592: the manifest and the run agree exactly. (011 §3.1's
figures were 555/462/93 at design time; the suite grew by 37 tests during M11's
own implementation, which is the manifest doing its job.)

The 117.59 s local figure is ~9× 011 §7.5's projected 13–15 s, and the reason is
not a regression: `tests/harness/test_compile_gate.py` (Suite C) invokes real
`puyapy` over 10 entry points, which 011 §3.5 itself measured at 34 s. The CI
job splits that into a separate `contracts` job, which is why the hosted
`offline tier` legs are 3 m 05 s / 3 m 21 s including install rather than two
minutes of compiling.

### 2.5 The live surface — three real reads against real mainnet

Everything in this subsection is a real HTTP response taken this pass, not a
recollection from `ROADMAP.md`.

**(a) The x402 service is publicly exposed over HTTPS, right now.**

```
$ curl -sS https://x402endpoint-nu.vercel.app/health
{"algod_round":63855556,"m7_app_id":3665914633}
```

`ROADMAP.md`'s M7 row (last updated 2026-08-04) still lists *"Not yet done:
public HTTPS exposure, Bazaar discovery registration, and the actual
`x402-global-challenge` submission tag"*. The first of those three landed on
2026-08-07 (`4b4ddfe`, `68bd2ce`, and the M9 row's own account of the real
Vercel deployment) and the M7 row was never updated. §14.3 records the
correction; §8 decides the other two.

**(b) The deployed mainnet bytecode matches this repo's pin, exactly.**

`GET https://mainnet-api.algonode.cloud/v2/applications/3665914633`:

| field | live mainnet | `deploy/schema/_compiled/Mpt7ReceiptApp.compiled.json` | |
|---|---|---|---|
| approval bytes | **3,108** | 3,108 | **equal** |
| approval sha256 | `f7a846ff33314d8f9ecc48e85584327f13e9cb808a3650b30e69339c7fcdc9d2` | same | **equal** |
| clear bytes / sha256 | 4 / `ed90f0d2…0ce7` | 4 / `ed90f0d2…0ce7` | **equal** |
| global state schema | `{uint: 0, byte-slice: 0}` | `StateSchema(0,0)` | consistent |
| extra program pages | 1 | `min_extra_pages` 1 | consistent |
| creator | `6XP7MJKMEPSCZ46RPB42FFRQGF7U5ACXLCXNCXWAVJUSP5J7U3ZFWBRIFQ` | — | |

The artifact also records `"on_completion_gate": "NoOp only"` and
`"puyapy_version": "5.9.0"`, so the live app is the **fixed** contract — 010
§9.1's `UpdateApplication`/`DeleteApplication` hole is closed on the deployed
artifact, which `6636c8a` fixed and `4395377` redeployed. Note the size moved
from 010 §4.6's measured 3,104 B to 3,108 B: that is the four bytes of the
`txn OnCompletion; !; assert` prologue, and it is a small, satisfying
confirmation that the pinned artifact tracks the real fix.

**This is the release-verification primitive, and it works today.** Anyone, with
no signer and no repo access beyond a checkout, can confirm the bytecode
executing on mainnet is the bytecode this repo's CI diffs per PR (G3-M11). §3.5
turns it from a thing that is possible into a thing that is documented and
runnable.

**(c) The old, hijackable app is gone.**

`GET .../v2/applications/3664247481` → `{"message": "application does not
exist"}`.

`ROADMAP.md`'s M7 and M10 rows both describe `3664247481` as *"currently 0 ALGO,
still live and still hijackable by anyone"*, and record the disposal decision
("leave it inert or delete it") as *pending*. **Measured: it has been deleted.**
This document does not know by whom — and that is itself the point, because 010
§9.1 established by real experiment that *any* account could have done it. The
correction is owed to `ROADMAP.md` and to 011 §11 item 9, which still names it.

The donor pair is live and matches its expected shapes: **measured**,
`3666047636` has a 48-byte approval program (`DonorIssuer`) and `3666047587` a
4-byte one (`DonorCallee`), both from the same creator as the M7 app. 010 §4.5's
measured 48 B / 4 B reproduce exactly.

**(d) And none of it is verifiable by the tooling, because there is no manifest.**

**Measured**: `git ls-files deploy/manifests` returns **zero files**; the
directory is empty. `deploy/diff.py::verify` opens with
`manifest = Manifest.load(target.network.genesis_id)`, so
`python -m deploy verify --target deploy/targets/mainnet.json` cannot run
against the real deployment. The three live mainnet app ids exist in this repo
**only as prose inside a 97 KB ROADMAP row** — which is, word for word, the
defect 010 §2.2 wrote `deploy/manifest.py` to fix:

> Without the **manifest**, a deployment is a thing that happened in a terminal.
> The live mainnet M7 app id `3664247481` exists in this repo only as prose in
> `ROADMAP.md` and three design docs; there is no machine-readable record of its
> network, creator, governance, program hash, or deployment round anywhere.

M10 built the mechanism. Nobody has written the file. That is a one-file M12
deliverable (§3.5) and it is the highest value-per-byte item in this document.

### 2.6 The verdict, and the scoping call

009 §0, 010 §0 and 011 §2.3 each state their refactor/build split explicitly
rather than letting it be discovered. M12's, in the same shape:

> **M12 is ~50% writing, ~25% two real runs, ~20% four small pieces of
> generated tooling, and ~5% deletion.**
>
> **Write**: `README.md` (rewrite from zero — the current one describes a
> different project), `CHANGELOG.md`, `docs/versioning.md`, `docs/security.md`,
> `docs/quickstart.md`, `docs/operating.md`, the release runbook, and the
> release notes themselves.
>
> **Run**: one green `ci-live` `workflow_dispatch` (G1-M12), and one real
> testnet deploy-and-drive (G2-M12). These are the module's only genuinely
> irreducible cost and they are the two things that convert eleven modules of
> devnet evidence into a public claim.
>
> **Build** (all small, all on top of existing M10/M11 machinery):
> `deploy/versions.json` + its generator hook (§3.4), `deploy resolve` (§3.5),
> `deploy inspect --forks` (surfacing two `_read_fork_rows` functions that
> already exist), `relayer/__main__.py` (2 lines), and `[project.scripts]`.
>
> **Delete**: `README.md`'s "Early scaffold stage" section, the three service
> dependencies from `relayer`'s runtime requirement set (§4.1), and — from the
> corpus — four stale documentation claims that 007 §10 flagged for correction
> in revision 3 and that **measurably never landed** (§5.4).

---

## 3. Contract versioning — the scheme

This is the module's headline open question, inherited from
`ARCHITECTURE.md:56–61` and named in `ROADMAP.md`'s own M12 row as
*"Contract-versioning story (AVM/consensus-fork-gated, not plain semver)"*.

### 3.1 Why semver is the wrong axis, on this repo's own evidence

A semver string answers "did the API change". The four things a consumer of this
project actually needs to know are:

1. **Is the bytecode at app id *X* the bytecode I audited?**
2. **Which Ethereum forks can it verify — and is that the same as which forks
   its operator has *told* it about?**
3. **Which AVM/protocol version were its opcode budgets and its caps measured
   against?**
4. **If I compile against it, what breaks when it is redeployed?**

Semver answers none of them. Worse, a hand-maintained number is precisely the
artifact class this repo has already measured going wrong. **010 §3.3 found
three real doc-vs-code drifts** by generating a schema instead of writing one:
a global key named `ring_n` in prose and `ring_size` on chain; a `forks8` box
documented at 321 B and shipped at 320 B; a creator MBR documented at 378,000
µALGO against a real 406,500. Each was harmless alone. Each survived review.

So the scheme's first rule is the rule M10 already proved:

> **Generate, never type.** The version identity is a value CI already computes
> and already diffs byte-for-byte, not a number a human increments.

### 3.2 The three axes

007 §8.6 named the third one before this module existed:

> Adding or revising a tier is a contract redeployment, and the version story
> `ARCHITECTURE.md` already says is "AVM/consensus-fork-gated, not plain semver"
> **gains a third axis: the proof system.**

| axis | what it pins | mutable after deploy? | where it lives today |
|---|---|---|---|
| **A — AVM / protocol** | `avm_version`, and the `go-algorand` build every budget and cap in this repo was measured against | **no** (bytecode) | `avm_version: 10` in all four `deploy/schema/*.schema.json`; the build is in `.github/workflows/ci-live.yml`'s pinned digest comment (**measured, quoted from the file**: `4.7.4, commit 91cbddcd, rel/stable`) |
| **B — consensus fork** | which Ethereum forks the deployment can verify | **partly** — see below | `contracts/*/forks.py` tables (on chain, mutable) **and** the bytecode's structural limits (immutable) |
| **C — proof system** | for T3 only: `(circuit source, gnark version, curve, setup, verifying key) → logicsig address` (007 §8.6) | **no** — `Mpt7App` hard-codes the address (TP-M7-7) | **nowhere. Empty in v1**, because T3 ships no prover (009 §1.2, `O-M9-1`) |

**Axis B is the one that needs real design, because it is two windows, not one.**

> **The `table window`** is what the deployment's own on-chain fork table says.
> It is mutable, governance-gated, append-only, and per-*deployment*.
>
> **The `code window`** is what the bytecode can structurally execute. It is
> immutable and per-*bytecode*.
>
> **The effective supported range is their intersection**, and nothing on chain
> computes it (§3.7).

003 §4.3's decision is what makes this split exist at all, and it is why M3
needs no fork axis:

> M3 does not target any fork. `gindex` is a runtime `UInt64` parameter and M3
> contains no fork-conditional code, no fork constants, and no SSZ field
> layouts. … It moves a hard-fork event from "redeploy the verifier and
> re-anchor" to "write a new row in a table".

and 003 §9's hand-off to this module, in full:

> **M12's contract-versioning story — informed.** Because M3 is fork-agnostic,
> the fork gate lives entirely in M4/M8 mutable state. A consensus fork that
> moves a gindex requires **a table update, not an M3 redeployment**. M12 should
> therefore version M3 on AVM version only, and version M4/M8 on supported fork
> range.

**Adopted, verbatim, and extended**: M2, M5, M6 and M7 join M3 on the
AVM-version-only side, for a different and equally structural reason — they
verify *execution-layer* RLP and Merkle-Patricia-Trie encodings, which no
consensus fork has moved. Nothing under `contracts/primitives/rlp/`,
`contracts/mpt/`, `contracts/composer/` or `contracts/receipt/` contains a fork
constant or a fork table.

### 3.3 What a new Ethereum fork actually costs, per contract

This is the concrete answer to "redeploy? in-place table update? both, depending
on which contract?". Every row is grounded in a cited measurement or a cited
contract constant.

**Measured from the contracts, this pass:**

| | M4 `SyncCommitteeVerifier` | M8 `TrustedRootAnchor` |
|---|---|---|
| box | `forks`, 576 B | `forks8`, 320 B |
| row size | **36 B** (`FORK_ROW_BYTES`) | **40 B** |
| capacity | **16 rows** (`FORK_TABLE_CAPACITY`) | **8 rows** |
| row shape | `(epoch u64, fork_version byte[4], finality_gindex, current_sc_gindex, next_sc_gindex)` | five `uint64`: `(epoch, g_state_root, g_receipts_root, g_block_number, g_block_roots_base)` |
| appender | `append_fork_row`, `gov` only, append-only, strictly increasing epoch | same |

**The decision table:**

| fork event | M1/M2/M3/M5/M6/M7 | M4 | M8 | consumers compiled against M8 |
|---|---|---|---|---|
| **A fork moves a gindex, depth unchanged** (e.g. Deneb → Electra: `BeaconState` past 32 fields, tree 5 → 6, every gindex moved) | nothing | **one `append_fork_row`, 1,000 µALGO** | **one `append_fork_row`, 1,000 µALGO** | nothing |
| **A fork deepens a branch past a *budget* ceiling** (Gloas: sync-committee gindices 2,945/2,946 at depth 11 ⇒ 003 §2.6 measures **738**, over the 700 single-call limit) | nothing | **table row + a relayer group-sizing change; no redeploy.** 003 §4.3: "one extra donor call per branch, which is 0.001 ALGO, but it must be *planned*" | see next row | nothing |
| **A fork deepens a branch past an *argument-size* cap** (Gloas: 008 §10.5 — a depth-11 execution-layer branch pushes HISTORICAL mode's payload over the hard 2,048 B app-arg cap) | nothing | — | **redeploy.** 008 NG3: "not merely unapproved — it needs a structural change (§17, `O-M8-4`)" | **recompile and redeploy all** (TP-M8-4: `ANCHOR_APP_ID` is a `pushint` immediate) |
| **A fork restructures the proof** (Gloas removes `EXECUTION_PAYLOAD_GINDEX` entirely and replaces it with `signed_execution_payload_bid.message.parent_block_hash`, 003 §4.2) | nothing | table row | **redeploy** | **recompile and redeploy all** |
| **The fork table fills** (M8 at 8 rows; ~4 years at mainnet's ~2 forks/year, 010 §11.12) | nothing | 16 rows ⇒ ~8 years | **redeploy** | **recompile and redeploy all** |
| **A wrong row was appended** | nothing | **redeploy** — append-only, no editor, no deleter (010 §11.4, FATAL) | **redeploy** | **recompile and redeploy all** |

**So the answer to the question, stated plainly:**

> **In-place table update is the ordinary case and covers every fork this
> project has actually seen. The boundary between "table update" and "redeploy"
> is not a spec boundary — it is a *measured budget or protocol-cap boundary*,
> and it is per-contract.** M4's next boundary is a budget ceiling it can buy its
> way past with a donor call; M8's is a hard 2,048-byte argument cap it cannot.
> That asymmetry is not incidental: it is why the two contracts need *different*
> code windows in `versions.json`, and why a single "supported forks" list for
> the project as a whole would be a lie.

One further cost, **measured** and flagged for exactly this document by 010:577 —
`SyncCommitteeVerifier` compiles to **6,980 B**, which is **85.2% of the 8,192 B
per-application bytecode cap**, leaving **1,212 B** of headroom. 010 §4.6 says it
"is worth M12 and any future M4 revision knowing that before someone adds a
method." It is worth more than that: **a fork that requires an M4 *code* change
has 1,212 bytes to fit in**, and if it does not fit, an M4 change cascades into
M8 (write-once `m4_app_id`) and thence into every consumer (010 §6.5). That
number belongs in `docs/versioning.md` as a standing budget, not just in a
design doc's appendix.

### 3.4 The artifact — `deploy/versions.json`, generated and CI-diffed

**Decision: one generated file, keyed by approval-program SHA-256, produced by
the existing `deploy/schema/generate.py` and diffed by the existing
`ci-offline.yml` `contracts` job.**

Why the hash and not a number: it is the one identifier that is (a) already
computed, (b) already committed (`deploy/schema/_compiled/*.compiled.json` and
each `*.schema.json`'s `program.approval_sha256`), (c) already diffed
byte-for-byte per PR by a gate **measured green today** (G3-M11), and (d)
**measured this pass to match the live mainnet deployment exactly** (§2.5b). A
version scheme whose identity is already enforced by CI and already verifiable
against the chain costs nothing to make true.

```jsonc
// deploy/versions.json  -- generated; `deploy schema --check` diffs it
{
  "versions_version": 1,
  "release": "v1.0.0",                       // the git tag this file was cut at
  "generated_by": "python -m deploy schema",
  "avm": {
    "version": 10,                           // from every *.schema.json
    "measured_against": "go-algorand 4.7.4 (91cbddcd, rel/stable)",
    "evidence": ".github/workflows/ci-live.yml ALGOD_IMAGE digest; ci-live run id"
  },
  "contracts": {
    "TrustedRootAnchor": {
      "code_id": "9b790b33f2116a5ccbbe07ce2d9ac040c8c1897c695ca2725b7d99956522d57d",
      "approval_bytes": 3027,
      "source": "contracts/state_anchor/anchor_app.py",
      "design_doc": "docs/design/008-trusted-root-anchor.md",
      "fork_axis": "table",                  // A | table | none
      "code_window": {
        "supported": ["deneb", "electra", "fulu"],
        "unsupported": ["gloas"],
        "reason": "008 NG3 / §10.5: a depth-11 EL branch pushes HISTORICAL's \
                   argument payload over the 2,048 B cap. O-M8-4, not approved.",
        "table_capacity_rows": 8
      },
      "consumers_bound_at_compile_time": true,   // TP-M8-4
      "redeploy_cascades_to": ["every M8 consumer"]
    },
    "SyncCommitteeVerifier": {
      "code_id": "…",
      "approval_bytes": 6980,
      "bytecode_cap_headroom_bytes": 1212,       // 010 §4.6 / 010:577
      "fork_axis": "table",
      "code_window": {
        "supported": ["deneb", "electra", "fulu"],
        "unsupported": ["gloas"],
        "reason": "004 §4.5 normative: the Gloas row MUST NOT be appended until \
                   its gindices are confirmed against vendored Gloas vectors; \
                   003 §2.6 measures a depth-11 branch at 738 > the 700 \
                   single-call limit, so group sizing must change too.",
        "table_capacity_rows": 16
      }
    },
    "Mpt7ReceiptApp":  {"code_id": "f7a846ff…c9d2", "fork_axis": "none",
                        "tiers": ["T1", "T2"], "proof_system": null},
    "Mpt6ComposerApp": {"code_id": "…", "fork_axis": "none"},
    "MptSegmentApp":   {"code_id": "…", "fork_axis": "none"},
    "DonorIssuer":     {"code_id": "…", "fork_axis": "none"},
    "DonorCallee":     {"code_id": "…", "fork_axis": "none"}
  }
}
```

Four properties, each load-bearing:

1. **`code_id` is the primary key and is never typed.** It is read from the same
   place `deploy verify` reads its pin, so a version and a verification can never
   disagree.
2. **`code_window` is per-contract and carries its own *reason*, cited.** A
   reviewer who wants to know why Gloas is excluded gets a section number, not a
   shrug. This is the field that makes §3.3's asymmetry machine-readable.
3. **`release` is the only hand-set field**, and it is set once, at tag time, by
   the release runbook (§6.2). Everything else is derived.
4. **`fork_axis: "none"` is an assertion, not an omission.** Suite V asserts that
   every contract marked `"none"` contains no fork constant and no fork box
   (grep over `contracts/`), so the claim cannot rot silently.

**Two gaps in the generator's current coverage, measured and to be closed here:**
`deploy/schema/_compiled/` contains **two** files (`Mpt6ComposerApp`,
`Mpt7ReceiptApp`) — `MptSegmentApp` and the donor pair have no pinned compiled
artifact, so three of the seven `code_id`s above cannot be filled today. 011
§3.5 named the same four bare contracts. Closing this is a `refresh_bare_contract_cache`
run against a live algod (it needs `/v2/teal/compile` for assembled sizes), i.e.
it belongs in the `ci-live` run of G1-M12, not offline.

### 3.5 Discovery — how a consumer finds the right app id

Three layers, in strict order of authority. This ordering is the design.

**Layer 1 — the chain is authoritative for the table window.**
`deploy inspect --app m8 --forks` decodes the on-chain `forks8` box through the
schema and prints one line per row. **This is nearly free**: `deploy/plans/m8.py::_read_fork_rows`
and `deploy/plans/m4.py::_read_fork_rows` **both already exist and already
decode both row shapes** (measured: `deploy/plans/m8.py:56`,
`deploy/plans/m4.py:54`). What is missing is a flag that surfaces them —
**measured**, `grep -c fork deploy/inspect.py` returns **0**; `inspect.py`
decodes ring records only, and 010 §8.3's illustrative output showing decoded
fork rows was never implemented.

**Layer 2 — the `code_id` is authoritative for the code window.**
`deploy verify` fetches `application_info(app_id)`, hashes the approval program,
and compares against the pin. **Measured working against real mainnet this
pass** (§2.5b). Given a `code_id`, `versions.json` yields the code window, the
design doc, and the redeploy-cascade set.

**Layer 3 — the manifest is a pointer, never a truth** (010 §9.5). It answers
only "which app id is ours", which is the one fact chain state cannot supply.

**The new verb that ties them together:**

```
$ python -m deploy resolve --network mainnet --fork fulu --json
{
  "network": "mainnet-v1.0",
  "fork": "fulu",
  "apps": {
    "m7": {"app_id": 3665914633,
           "code_id": "f7a846ff…c9d2",
           "code_id_matches_chain": true,          // real read, this invocation
           "fork_axis": "none",
           "verdict": "USABLE"},
    "m4": {"verdict": "NOT_DEPLOYED",
           "detail": "deploy/targets/mainnet.json declares m4.deploy=false"},
    "m8": {"verdict": "NOT_DEPLOYED"}
  },
  "donors": {"issuer": 3666047636, "callee": 3666047587}
}
```

`resolve` is **read-only, needs no signer, and refuses rather than guesses**.
Its four verdicts are `USABLE`, `NOT_DEPLOYED`, `FORK_UNSUPPORTED` (the fork is
outside the intersection of table and code windows), and `CODE_MISMATCH` (the
live approval hash is not the pinned one — i.e. the app was updated out from
under us, which 010 §9.1 proved was possible for the *old* M7 and remains
possible for any future unrestricted contract). **`CODE_MISMATCH` must be loud
and must exit non-zero**: it is the only signal a consumer will ever get that
the thing they are calling is no longer the thing they audited.

**And the missing file**: `deploy/manifests/mainnet-v1.0.json`, committed,
recording the three real live app ids, their `code_id`s, their creator, and
their deployment rounds. Without it, layer 3 is empty and `deploy verify
--target mainnet` cannot run at all (§2.5d). With it, every reader of this
repo can independently confirm §2.5b for themselves, which is the entire
argument of 010 §1.3 mitigation 3.

### 3.6 What M10's primitives already give us, and what is new

010 §7.2 asked whether the manifest tooling has the right primitives for this.
Answered, itemised:

| need | exists? | evidence |
|---|---|---|
| pinned approval hash per contract | **yes** | `deploy/schema/*.schema.json` `program.approval_sha256`; `_compiled/*.compiled.json` |
| CI-enforced byte-identity of that pin | **yes** | G3-M11, `contracts` job, measured green on `e8bf7b8` |
| verify a live app against the pin | **yes** | `deploy/inspect.py::verify_app`; measured against mainnet this pass |
| manifest schema and loader | **yes** | `deploy/manifest.py`, `MANIFEST_VERSION = 1` |
| genesis-hash guard against wrong-network action | **yes** | G7-M10 |
| recover a lost manifest by program hash | **yes** | `deploy/manifest.py::recover_by_approval_hash` |
| decode both fork-row shapes | **yes, but unsurfaced** | two `_read_fork_rows`, neither reachable from the CLI |
| **`versions.json` (the code window, the AVM pin, the cascade set)** | **no** | new, §3.4 |
| **`deploy resolve`** | **no** | new, §3.5 |
| **`deploy inspect --forks`** | **no** | new — a flag over existing code |
| **a committed mainnet manifest** | **no** | new — a file, not code |
| **a schema-migration story** (`O-M10-7`) | **no** | still deferred; §15 gap 6 |

So the answer to 010's question is: **the primitives are right and nearly
complete; what is missing is one generated artifact, one read-only verb, one
flag, and one committed file.** No new mechanism, no second source of truth, and
no change to `deploy`'s existing "identity only" manifest principle (010 §7.2) —
`versions.json` describes *bytecode*, the manifest describes *deployments*, and
the two meet only through the hash.

### 3.7 The hazard nothing enforces, stated plainly

**Measured**, reading `contracts/sync_committee/forks.py::append_fork_row` and
`contracts/sync_committee/verifier.py:163–182` in full, the appender validates
exactly four things:

```
assert fork_version.length == 4
assert activation_epoch != UINT64_MAX        # sentinel rejected
assert fork_count < FORK_TABLE_CAPACITY      # table not full
assert activation_epoch > prev_epoch         # strictly increasing
```

**It does not validate the gindices at all** — not their value, not their depth,
not against any bound the bytecode can actually execute. M8's appender has the
same shape.

The consequence is exact:

> **A Gloas row is appendable to both contracts today.** It would produce a
> deployment whose *table window* claims Gloas and whose *code window* cannot
> execute it — M4 at 738 budget against a 700 single-call ceiling (003 §2.6), M8
> with a depth-11 argument payload against a hard 2,048 B cap (008 §10.5). The
> failure would surface at `submit_update`/`anchor_historical` time, as a budget
> or argument rejection, **not** at governance time when a human is watching.

004 §4.5 is already normative about this — *"the Gloas row MUST NOT be appended
until its gindices are confirmed against vendored Gloas vectors"* — and 004 §18
item 15 repeats it. But it is a rule in a design doc, enforced by nothing.

**M12's answer, and its honest limit:**

- `deploy` **refuses client-side**, before sending: `append_fork_row` for any
  fork listed in `versions.json`'s `code_window.unsupported` is rejected with
  the cited reason. This is the same shape as 010 §6.4's refusal to deploy an
  `"unrestricted"` contract to mainnet, and the same shape for the same reason:
  the tool is the only place it *can* be refused.
- Suite V asserts the refusal both ways (it fires for `gloas`, it does not fire
  for `fulu`), mirroring G8-M9/G8-M10's non-vacuity discipline.
- **The honest limit**: this is a tool-side guard, not a chain-side one. A
  governance key holder using `goal` directly can still append the row. Closing
  it properly needs a depth or gindex bound in the contract, which is a contract
  change and therefore an M4/M8 revision's work, not M12's. Recorded as
  `O-M12-1`, and named in §15 gap 2 rather than left implicit.

---

## 4. Packaging

### 4.1 The dependency defect — measured, and it is bigger than it looks

**Measured**, this pass, `pip install --dry-run --report` against the wheel
`python3 -m build` just produced:

```
59 packages would be installed.
```

The full list includes `sentry-sdk`, `fastapi-cloud-cli`, `uvloop`, `typer`,
`rich`, `rich-toolkit`, `email-validator`, `python-multipart`, `watchfiles`,
`websockets`, `httptools`, `Jinja2`, `starlette`, `pydantic-settings`,
`shellingham`, `rignore`, `detect-installer`, `fastar`.

**Measured**, the same command against only the four packages `relayer/`
actually needs (`py-algorand-sdk`, `rlp`, `pycryptodome`, `py_ecc`):

```
19 packages would be installed.
```

> **40 of the 59 packages a consumer of `eth-avm-relayer` is forced to install
> are packages `relayer/` is *forbidden by its own tests* to import.**

That is not rhetoric: `relayer/__init__.py`'s docstring and G8-M9's AST-enforced
test in `tests/relayer/test_security.py` both state that `relayer/` MUST NOT
import `fastapi`, `x402` or `pytest`. The three offending declarations are in
`[project.dependencies]`, and `pyproject.toml`'s own comment explains exactly
why, in a passage worth quoting because it is both correct and the cause:

> fastapi/uvicorn/x402-avm below are service/x402_endpoint's own deps, not
> relayer's … They live in THIS list, not just
> `service/x402_endpoint/requirements.txt`, because Vercel's Python/FastAPI
> builder resolves dependencies from pyproject.toml exclusively once
> `[tool.vercel]` is present — requirements.txt is silently ignored for the
> deployed build (confirmed live, 2026-08-07…).

The finding is real, it was expensive to learn, and it must not be regressed.
`sentry-sdk` arriving transitively in a library install is nonetheless not
acceptable in a published artifact.

**Decision, primary (option A):** move the three into an extra, and prove the
Vercel build still works with a **real redeploy and a real paid request**.

```toml
dependencies = ["py-algorand-sdk", "rlp", "pycryptodome", "py_ecc"]

[project.optional-dependencies]
service = ["fastapi", "uvicorn[standard]", "x402-avm[fastapi,avm]"]
```

**Whether Vercel's builder installs extras is unknown and this document will not
guess it** — the same posture 011 §7.3 took on `requires-python`. It is settled
by one deploy, which is cheap (the service is already deployed and the paid path
is already proven end to end, `ROADMAP.md` M7/M9 rows, round 63,837,827).

**Decision, fallback (option B), recorded now so the implementation pass does
not improvise one:** if the extra is not honoured, add a second, minimal build
configuration (`packaging/library/pyproject.toml`) declaring only the four real
dependencies with `package-dir` pointing at the repo's `relayer/`, and build the
published wheel from that. The root `pyproject.toml` stays exactly as it is, as
Vercel's build manifest. Cost: two places declare dependencies.

**Either way, one normative MUST**: a real offline test asserts that every place
this repo declares dependencies agrees — root `pyproject.toml`,
`service/x402_endpoint/requirements.txt`, and (under option B) the library
config. 011 §18 item 17 already asked for this and named the gap: *"MUST keep
`requirements.txt` and `pyproject.toml` in step — nothing enforces that today
(ROADMAP, M7 row), and M11 is where a test for it belongs."* It did not land.
M12 lands it (Suite W, W-4).

### 4.2 What ships — and what an installed wheel structurally cannot do

**Decision: v1 publishes exactly one distribution, `eth-avm-relayer`. `deploy/`
stays a source-checkout tool and is *documented as such*.**

Reasons, in order of weight:

1. **`deploy/` cannot be packaged without packaging `contracts/`.**
   `deploy/schema/generate.py` imports `contracts.sync_committee.constants` and
   `contracts.state_anchor.constants` at module scope, and 010 §8.1 makes that
   the explicit reason `deploy/` is not a subpackage of `relayer/`. Publishing
   `deploy` means publishing the contract sources and pulling `algopy` into an
   operator's environment.
2. **`deploy/` shells out to `puyapy`**, which 010 §8.1 says a relayer on an
   operator's laptop must not require, and which 007 §14.6 records a real trap
   about (`pip install puya` fetches a *different, incompatible* package).
3. **`deploy/`'s real users are this repo's own operator and CI**, both of which
   have a checkout. The audit use case (010 §1.3 mitigation 3, "runnable by
   anyone") is served by `git clone` + `pip install -e ".[contracts]"`, which
   `docs/operating.md` documents as a first-class path.

**But the wheel's limits must be stated in the wheel's own documentation, because
they are not obvious and they are structural.** **Measured**, reading
`relayer/client.py`:

```python
relayer/client.py:38    REPO_ROOT = Path(__file__).resolve().parents[1]
relayer/client.py:432   patched_root = m7.patched_probe_source(REPO_ROOT, self.config.m8_app_id)
```

In an installed wheel, `parents[1]` resolves to `site-packages/`, and
`contracts/state_anchor/bench_app.py` is not there. The same is true of
`relayer.group.donors.deploy_donor_pair(repo_root=…)`, which reads
`repo_root / "contracts" / "sync_committee" / "bench_app.py"`.

> **So `prove_receipt(against_anchor=True)` and `deploy_donor_pair` require a
> source checkout and a `puyapy` on `PATH`. They do not work from a `pip
> install`.** Every other verb does: `status`, `sync`, `anchor`,
> `prove receipt` (without an anchor), and `prove account` touch no contract
> source.

This is a genuine finding of this pass and it constrains the README. **The
quickstart 009 §15.4 nominates (`python -m relayer status` against a public
deployment) is exactly right and works from a wheel.** The anchored-receipt path
is documented under the checkout instructions, with the reason. `O-M12-2`
records the proper fix (ship the two `bench_app.py` sources as package data, or
accept a `repo_root=` argument on the public API) as a future `relayer`
revision's work, because changing a public signature is not a docs module's job.

**Package data**: none needed. **Measured**: the wheel contains zero non-`.py`
files and `grep -rn "Path(__file__)" relayer/` returns exactly the one line
above. `relayer/` reads no bundled data.

### 4.3 Entry points

```toml
[project.scripts]
eth-avm-relayer = "relayer.cli:main"
```

plus a two-line `relayer/__main__.py` mirroring the one `deploy/__main__.py`
already has, so that **both** documented forms work:

```python
"""`python -m relayer` -- entry point. Mirrors deploy/__main__.py."""
import sys
from relayer.cli import main
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

`main()` already returns an `int` exit code and already handles `RelayerError`
with the PAGE_A_HUMAN/FATAL taxonomy (`relayer/cli.py:75–90`), so nothing else
changes. **No console script for `deploy`**, per §4.2 — `python -m deploy` from a
checkout is the documented form, which is what it already is.

Both CLIs gain real `--help`: `description=` and `epilog=` on the top-level
parser, and `help=` on every subparser and argument. **Measured** today: not one
`add_parser` call in either file passes `help=`, so `--help` lists verb names and
nothing else. G6-M12 asserts that every invocation printed in
`relayer/cli.py`'s and `relayer/__init__.py`'s docstrings actually executes —
which is the mechanical form of "the documentation is not lying".

### 4.4 `requires-python` — closed, with the evidence

011 §15.4 item 4 handed this here:

> **`requires-python`.** §7.3 leaves `>=3.10` unverified; M12 owns the packaging
> story and should not ship a floor CI has not run.

**Closed by M11's own implementation, and verified this pass.** **Measured**:
`pyproject.toml` declares `requires-python = ">=3.12"`; the built wheel's
`METADATA` carries `Requires-Python: >=3.12`; `.github/workflows/ci-offline.yml`
runs a matrix of `["3.12", "3.13"]`; and run 31227550081 shows **both legs
green** (`offline tier (py3.12)` 3 m 21 s, `offline tier (py3.13)` 3 m 05 s).
The `ROADMAP.md` M11 row's own note — *"py3.12 leg of the matrix untested
locally (only 3.13 available in this pass's environment); confirm on first real
push"* — is therefore **confirmed on a real push**. Nothing is owed. M12's only
duty is to record the confirmation in the release notes rather than restate the
question.

### 4.5 Two version numbers, and why they must not be conflated

| number | what it versions | who sets it | today |
|---|---|---|---|
| `[project] version` in `pyproject.toml` | the **Python distribution** — the client library and its CLI | a human, semver, at release time | `0.1.0` |
| `versions.json` `code_id` | the **deployed bytecode** | generated from the compiled artifact | §3.4 |
| `versions.json` `release` | the tag that ties them together | the release runbook | new |

**Decision: the Python distribution uses ordinary semver and says so; the
contracts use §3's scheme and say so; `versions.json.release` is the only thing
that claims they were cut together.** A client at `1.1.0` talking to a
`code_id` cut at `v1.0.0` is a normal, supported, common situation — the ABI is
frozen by the contracts (009 §0's own framing: "their ABIs are frozen by their
*code*"). Pretending one number covers both is how a consumer concludes that
upgrading a pip package changed what is on chain.

**`relayer.__version__`** already exists and reads `"0.1.0"` (**measured**,
`relayer/__init__.py:23`). It must be kept in step with `[project] version` by a
test, not by discipline (Suite W, W-5) — a two-place version string is a
one-line drift waiting to happen and this repo has already measured that class
of drift three times (010 §3.3).

---

## 5. The documentation set

### 5.1 `README.md` — a rewrite, not an edit

The current file describes a scaffold. The replacement is structured around what
a stranger needs, in the order they need it, and every section names its
evidence.

| § | content | normative constraints |
|---|---|---|
| 1 | **What this is**, in three sentences, and **the trust model in the same paragraph as the first "verifier"** | 008 §15.6, §5.3 below. **G7-M12** |
| 2 | **Status**, as a table: module, state, what is proven, what is not. Replaces "Early scaffold stage" | every "proven" cell cites a run id, a round, or a test suite |
| 3 | **Badges**: `ci-offline` only, with one sentence on what green means | 011 §15.4 item 1, §1.3. **MUST NOT** badge `ci-live` |
| 4 | **Install** — `pip install eth-avm-relayer` for the client; `git clone` + `pip install -e ".[test,contracts]"` for the contracts, the deploy tool, and the anchored-receipt path | §4.2's structural limit stated here, not buried |
| 5 | **Quickstart** — `eth-avm-relayer status` / `python -m relayer status` against the committed mainnet manifest | 009 §15.4's own nomination, now runnable (§4.3) |
| 6 | **Live deployment** — the mainnet app ids, their `code_id`s, and the exact `deploy verify` command that checks them | §2.5b/§3.5. **MUST** carry "nothing monitors this" (011 §16 gap 8) |
| 7 | **Supported forks** — Deneb, Electra, Fulu; Gloas explicitly not supported, with the reason | §3.3 |
| 8 | **What this does *not* do** — the honest list, linked to `docs/security.md` and §7's checklist | §5.2 |
| 9 | **Costs** — with `measured`/`projected` preserved | ARCHITECTURE.md's rule, **G10-M12** |
| 10 | Contributing, design docs, licence | unchanged in substance |

**The one thing §2 must not do**: present M5's design-doc targets as achieved.
**Measured** (005 §16's own table, read this pass): G6-M5 measured **5,116**
against a `< 3,276` target; G1-M5 **1,813** against `< 1,121`; G5-M5 **1,969 B**
against `≤ 1,400 B`. All three are open, all three are *performance* rather than
correctness, and all three have a real, non-simulated submission behind them.
The status table says exactly that, in those numbers.

### 5.2 The other documents

> **Superseded by [013 §3.6](013-fork-table-global-state.md#36-the-mechanism-compiled-for-real):**
> the "1,212 B M4 headroom" cited below (`docs/versioning.md`'s row) moved to
> 1,215 B — the fork-table storage revision made the compiled program 3
> bytes smaller. Left as originally written, per this project's convention.

| file | why it exists | key content |
|---|---|---|
| `CHANGELOG.md` | **new.** §5.5 | one entry per release; every claim cites a commit, a run id, or an on-chain round |
| `docs/security.md` | **new.** The trust model, at length, so §1 of the README can be three sentences | TP-M8-1 in full (008 §5.3's table, verbatim); 009 §1.3's "M9 is untrusted" table; 010 §1.3's "M10 is trusted" table; 011 §1.3's "what a green tick means"; the `CODE_MISMATCH` failure mode (§3.5); the fact that **nothing monitors the live service or the live app** |
| `docs/versioning.md` | **new.** §3, written for a consumer rather than a reviewer | the three axes; the fork decision table; how to read `versions.json`; the 1,212 B M4 headroom as a standing budget; §3.7's unenforced hazard, stated |
| `docs/quickstart.md` | **new** | the wheel path and the checkout path, with the §4.2 limit; both CLIs' real verbs |
| `docs/operating.md` | **new** | `deploy` end to end: targets, `plan`/`apply`/`verify`/`inspect`/`resolve`, the funding recipe's real numbers (010 §10.2), the governance warnings (010 §9.3), and 010 §6.5's migration table |
| `docs/release.md` | **new.** §6 | the runbook |

**Decision: no per-package `README.md` files.** `[project] readme = "README.md"`
makes the root file the PyPI long description; a second `relayer/README.md`
would immediately drift from it, and `deploy/` is not published so its README
would have no consumer that `docs/operating.md` does not serve better. This is
the same call 011 §6.4 made about not "deduplicating" the independent reference
oracles: a second copy is not always an improvement.

### 5.3 `ARCHITECTURE.md` — two corrections

1. **§"Contract versioning"** currently defers to this document and guesses the
   fork range as "Altair/Capella/Deneb". Replace with a three-sentence summary
   of §3 and a link to `docs/versioning.md`, naming the real range
   (Deneb/Electra/Fulu) and the real exclusion (Gloas).
2. **§"CI"** says `ci-live.yml` "must be run manually and pass before any module
   is marked 'Released' in `ROADMAP.md`". That rule is correct and has **never
   been satisfiable** (§0). It stays, and G1-M12 makes it satisfiable for the
   first time. Add one sentence: a Released claim cites the run id, per 011
   §15.4 item 2's *"M12 should require the citation, not the assertion"*.

**Not changed: the "Language" section.** 007 §8.7 flagged for the maintainer
that T3 would introduce Go/gnark as a second implementation language. **M12's
verdict: nothing is owed, because nothing ships.** T3 is unimplemented (009 §1.2,
`O-M9-1`), no Go artifact is in the tree, and `ARCHITECTURE.md` must describe
what this project *is*. The obligation is recorded in §14.3 and re-fires the day
T3 ships a prover, not before.

### 5.4 The documentation-correction list — resolved

007 §10 is the "documentation-correction list" 008 §725 and §15.6 both refer to.
**Measured this pass: none of its four in-repo corrections has landed.**

| # | file | claim | measured state | M12 verdict |
|---|---|---|---|---|
| 1 | `docs/design/002-rlp-decoder.md` §4.2(a) | "M7 **cannot materialise or hash that leaf at all**" | **still present**, `002:405` | **Amend** to 007 §10's wording: "cannot materialise it, and cannot hash it with the `keccak256` opcode; software hashing is possible at 109.2 budget/byte (007 §2.4)". M2's decision is unaffected |
| 2 | `docs/design/005-mpt-walker.md` §7.5 | "cannot be `keccak256`'d (no streaming hash)" | **still present**, `005:752` | **Amend**, same wording. M5's args-not-boxes decision is unaffected |
| 3 | `README.md` | "it can't even be pushed to the stack, let alone hashed, with a naive approach" | **still present**, `README:45` | **Keep the sentence** (007 §10 assessed it as accurate as written) and **add the pointer** to 007 §2.4 and §3.1. Survives the §5.1 rewrite |
| 4 | `tests/fixtures/spike-reference/MPT_RESULTS.md` §5.3 | "you cannot even materialize or `keccak256` the leaf node" | **still present, and must stay** | **Not corrected in place** — `ARCHITECTURE.md` freezes that tree and 007 §10 itself says to "record the correction here and in the README instead". The README's §8 records it |
| 5 | `README.md` (007 rev. 3 requirement) | any T3 receipt-coverage number | **absent** — the README quotes no coverage figure | **Correct as-is, and normatively frozen**: 007 §10 says *"do not publish a T3 coverage number in `README.md` until one real proof exists at the deployed tier"*. Suite N asserts no T3 percentage appears in any published doc |
| 6 | `ARCHITECTURE.md` "Language" | Go/gnark as a second language | flagged for the maintainer, not this module | **Nothing owed in v1** — §5.3 |

**Plus the item 008 §15.6 puts at the top of that list, above all six:**

> **`README.md` must state TP-M8-1 in the same breath as the words "trustless"
> or "verified".** Sync-committee messages are not slashable; a 2/3 committee
> majority can lie at no cost; this is Ethereum's light-client model, not a
> defect in this implementation, and it is not full-node security.

**Adopted as normative and gated.** G7-M12 asserts, mechanically, that the
trust-assumption sentence appears in the same paragraph as the first occurrence
of "verifier"/"verified"/"trustless" in `README.md`. 008 §15.6's own reason for
putting it first is the right one: *"it is the only item on that list that
affects what a user should believe."*

**Two further corrections this pass's own measurements require**, both to
`ROADMAP.md`:

7. The **M7 row's** "Not yet done: public HTTPS exposure, …" — public HTTPS
   exposure **is done** (§2.5a, measured live).
8. The **M7 and M10 rows**' description of app `3664247481` as "still live and
   still hijackable" — **it no longer exists** (§2.5c, measured). 011 §11 item 9
   names it too and inherits the correction.

### 5.5 `CHANGELOG.md` — yes, and what shape

**Decision: create one, in Keep-a-Changelog form, with one project-specific
amendment that is not optional here.**

> **Every entry that states a result cites its evidence inline** — a commit
> hash, a GitHub Actions run id, an Algorand round, or an app id. An entry that
> says "verified against real mainnet data" without one is exactly the class of
> claim `ARCHITECTURE.md`'s standing rule exists to forbid, and a changelog is
> read by more people than a design doc.

Why a changelog is genuinely needed rather than ceremonial: `ROADMAP.md` is
97,097 bytes in 36 lines and is a *working* document — it records what the next
session should do, carries corrections mid-row, and is not readable by anyone
outside the project. It is the right artifact for its purpose and the wrong one
for a release note. The changelog is the readable projection of it.

The v1.0.0 entry's required contents are §6.2's list.

---

## 6. Release process, and the testnet question

### 6.1 Is a real testnet run in M12's scope? — decided

010 §15 gap 3, in full:

> **No testnet or mainnet run is in the acceptance gate.** G1-M10 is a devnet
> deployment carrying real mainnet *data*. That matches how M4/M7/M8/M9 were all
> validated, and it is genuinely weaker than a real public-network deployment.
> §6.3 recommends a testnet run before v1; **M12 should require one.**

011 §15.3 restated it as *"Inherited unchanged, and M11 does not close it.
Restated for M12."*

> **Decision: a real testnet run IS in M12's acceptance gate (G2-M12). A
> mainnet deployment of M4/M6/M8 is NOT (§1.2 item 1).**

The reasoning for taking it rather than deferring it a third time:

1. **It is the one open gap in this corpus that a docs-and-release module can
   actually close.** It needs test-token ALGO and an afternoon, not a contract
   change, a ZK prover, or a lucky day on mainnet.
2. **It tests four things devnet structurally cannot**, all named by 010 §6.3
   and §7.1: the app-id prediction race under real contention (010 §15 gap 2 —
   "on a busy network the retry loop is real"); the **no-kmd signing path**, which
   is a genuinely different code path (`deploy/cli.py::_funded_kmd_account` is
   localnet-only by its own docstring); faucet-funded MBR against the measured
   requirement; and `verify` run by a party that did not perform the deploy.
3. **It is the precondition for the mainnet runbook to be honest.** Writing
   "here is how to deploy this to mainnet" on the strength of a devnet-only
   record would be the same category of claim as a green tick over an `echo`.

**The gate, concretely** — this is 010's E-1 re-run on a public network:

> **RL-1 (G2-M12).** From an empty Algorand **testnet**: `deploy apply --target
> deploy/targets/testnet.json` for M4 + M8 + M6 + M7 + the donor pair, with a
> real signer from a mnemonic (no kmd), funded from the faucet. Then `deploy
> verify` from a **second process with no signer**. Then a `RelayerConfig` built
> **from the manifest alone** driving `sync(install=True)` → `sync(update=True)`
> → `anchor()` → `prove_receipt(against_anchor=True)` against **real mainnet
> Ethereum data**. The manifest is committed as
> `deploy/manifests/testnet-v1.0.json`.

**Projected cost**, from 010 §10.2's measured MBR model at `ring_n = 128`:
**≈ 32.3 ALGO** of testnet tokens locked (creator global-state MBR 1.227 +
M4 app 20.096 + M8 app 8.950 + M7 base and float 1.744 + M6 0.100 + donors
0.200), plus **0.033 ALGO** in fees across 33 transactions. At `ring_n = 8` the
total falls to **≈ 24.1 ALGO**. That is one faucet ask, and `deploy plan` prints
the exact figure with no signer configured (010 §8.2), so the ask is one number
rather than a guess. **Projected wall-clock: 15–25 minutes**, dominated by the 64
real `install_chunk` submissions (010 §13.5's own measured expectation).

**A recorded risk, because 010 §10.4 is unambiguous**: box MBR on these contracts
is **not recoverable**. Every µALGO sent to a testnet app account is spent, not
lent. On testnet that is free; the runbook says it in the mainnet section in
bold, because on mainnet it is 32.3 real ALGO.

### 6.2 The release notes' required contents

Not a template — a checklist, each item of which is a citation:

1. The `ci-offline` run id and its measured job times (the per-PR claim).
2. **The `ci-live` run id** (G1-M12) — the first one that has ever existed — with
   the `go-algorand` build from its uploaded `algod-versions.json` artifact, per
   011 §18 item 9.
3. The testnet app ids, rounds and manifest path (G2-M12).
4. The **mainnet** app ids and their `code_id`s, with the `deploy verify`
   command a reader can run themselves, and the sentence that nothing monitors
   them.
5. **The quarantine list, in full** — 011 §15.4 item 3: *"Anything in
   `quarantine.toml` at release time is, by definition, a known-unproven claim,
   and belongs in the release notes."* Today that is exactly one entry, and it
   goes in with its real numbers: `test_l2_submit_update_all_8_key_boxes_g1_m9`,
   210,381–211,502 opcodes against a ~177,392 donor ceiling, opened 2026-08-06,
   **expires 2026-11-04**.
6. **The open-gate list** — §7's table, verbatim.
7. `requires-python` and the Python versions CI actually ran (§4.4).
8. The `versions.json` fork window, and the Gloas exclusion with its reason.
9. Known structural limits of the wheel (§4.2).

### 6.3 The two runs, and the tag

```
1.  Close §7's blocking rows.
2.  `gh workflow run ci-live.yml`         → G1-M12. Record the run id.
3.  Open one real PR (docs-only is fine)  → closes G1-M11's PR half.
4.  Testnet apply/verify/drive            → G2-M12. Commit the manifest.
5.  `python -m deploy schema` regenerates versions.json with `release: v1.0.0`.
6.  Write CHANGELOG's v1.0.0 entry from §6.2. Every line cites something.
7.  `git tag v1.0.0` + a GitHub release whose body IS the changelog entry.
8.  (Human, separately) publish the wheel; (human, separately) any mainnet
    deployment, per §1.2 item 1.
```

Step 3 is not padding. **Measured**: zero of this repo's 27 workflow runs were
`pull_request` events, so "CI runs on every PR" — the thing the badge will
claim — has never once been observed to be true here. One real PR converts it
from a configuration into an observation, at a cost of about four minutes.

---

## 7. The release-readiness checklist

The deliverable this section describes is a real, committed table
(`docs/release.md` §1), regenerated at each release, not prose. Every "state"
cell below is **measured this pass**.

| # | item | source | measured state | blocks v1? |
|---|---|---|---|---|
| 1 | **`ci-live.yml` has never run its real body** | §0, `gh api` | 8 scheduled runs, all at `1148ae4`, all the placeholder. G2-M11 open | **YES** — one `workflow_dispatch`. G1-M12 |
| 2 | **No `pull_request` has ever run CI** | §2.4 | 0 of 27 runs. G1-M11 half-open | **YES** — one PR. §6.3 step 3 |
| 3 | **No testnet or mainnet deploy in any gate** | 010 §15 gap 3, 011 §15.3 | never performed | **YES** — G2-M12 (§6.1) |
| 4 | **No committed manifest for the live mainnet deployment** | §2.5d | `git ls-files deploy/manifests` → 0 files; `deploy verify --target mainnet` cannot run | **YES** — one file. G4-M12 |
| 5 | **`python -m relayer` does not work** | §2.3 | `No module named relayer.__main__`; 009 §15.4's nominated quickstart is false | **YES** — two lines. G6-M12 |
| 6 | **`pip install` pulls 59 packages, 40 forbidden by G8-M9** | §4.1 | measured, incl. `sentry-sdk`, `fastapi-cloud-cli` | **YES** — G5-M12 |
| 7 | **README says "Early scaffold stage"** | §2.1 | untouched since `51dd033` | **YES** — G7-M12 |
| 8 | **008 §15.6's trust sentence absent** | §5.4 | "verifier" appears at `README:3` with no trust statement anywhere | **YES** — G7-M12 |
| 9 | **007 §10's four corrections never landed** | §5.4 | `002:405`, `005:752`, `README:45` all unchanged | **YES** — G8-M12 |
| 10 | **G1-M9 quarantined** | `quarantine.toml` | opened 2026-08-06, **expires 2026-11-04**; 210,381–211,502 vs ~177,392 | **no** — release-note item (§6.2 item 5) |
| 11 | **M5's G1/G5/G6 budget gates open** | 005 §16 | 5,116 vs <3,276; 1,813 vs <1,121; 1,969 B vs ≤1,400 B | **no** — performance, not correctness; a real submission exists. README must print the real numbers |
| 12 | **M2's G1/G3 open** | 002 §16 | G3 192 vs ≤90 target; G1 now index-dependent by design | **no** — same reasoning |
| 13 | **G4-M9 open: M6 has no submitting client** | 010 §4.4, 011 §15.3 | `prove_account` never sends a transaction; no `test_l5` exists | **no** — but README **MUST** qualify account/storage proofs. G7-M12 |
| 14 | **13 of M8's 22 error codes untested** | 011 §9.1, `error_codes_uncovered.txt` | committed baseline; growth is a red build | **no** — named in the release notes |
| 15 | **T3 unimplemented; no ZK tier ships** | 009 §1.2, 007 §14.8 | 2.2% of 94,667 real receipts need it | **no** — but **no T3 coverage number may be published** (007 §10 row 5) |
| 16 | **Nothing monitors the live service or app** | 011 §16 gap 8 | measured up today; no alerting of any kind | **no** — but the docs **MUST NOT** say "monitored". G7-M12 |
| 17 | **AlgoPlonk's swallowed-error bug unreported upstream** | 007 §14.3.1, 007:2938 | two-line fix identified, applied locally in `ptaufast`, never sent | **no** — §8 decides; not a release blocker because nothing in this repo depends on AlgoPlonk |
| 18 | **Bazaar registration / challenge submission tag** | ROADMAP M7 row | undone | **no** — §8 declines one, sequences the other |
| 19 | **3 of 7 `code_id`s unfillable offline** | §3.4 | `_compiled/` holds 2 of 4 bare contracts | **no** — filled by G1-M12's `ci-live` run, which has `/v2/teal/compile` |
| 20 | **MBR is not recoverable on these contracts** | 010 §10.4 | structural; four docs still say otherwise | **no** — but the mainnet runbook **MUST** say it in bold |

**Nine blocking rows. Seven of them are a file, a flag, or two lines of code.
Two of them are a real run.** That is the honest size of M12.

---

## 8. M7's undone x402 items — decided

`ROADMAP.md`'s M7 row names three. §2.5a measured the first as already done.
The other two:

**Bazaar discovery registration — declined for v1, with a reason.**

Registering a paid endpoint in a public discovery directory is a claim about
*availability*, and this project has no basis for one. **Measured**: the service
runs on Vercel's Hobby tier as a single function, with no health check, no
alerting, no uptime target, and no owner on call — 011 §16 gap 8 says exactly
this and adds that M12 "should not describe the service as monitored". A
directory listing is a stronger claim than a README sentence, because the reader
of a directory is *looking to depend on something*. Listing an unwatched paid
endpoint is worse than not listing it. **Gated on a monitoring story
(`O-M12-3`)**, which is genuinely small (a scheduled `GET /health` plus an
approval-hash check against the pin, both of which §3.5's `resolve` already
does) but is a different module's worth of decisions about who gets paged.

**The `x402-global-challenge` submission tag — not M12's to press, but M12
produces every precondition.**

The submission needs: a live paid endpoint (**measured live**, §2.5a; a real
0.01 USDC payment settled at round 63,837,827 per the ROADMAP M9 row), a public
repository (yes), a README a stranger can read (**M12's §5.1**), a tagged
release (**M12's §6.3**), and a verifiable on-chain artifact (**M12's §3.5 +
the committed manifest**). M12 delivers all five and stops. Pressing submit is a
human action with a deadline attached to somebody else's calendar, and a design
doc that scheduled it would be pretending to an authority it does not have.
Recorded in `docs/release.md` as a post-tag step with its prerequisites ticked.

**The AlgoPlonk upstream report (007:2938–2939) — do it, and scope it.**

007 §14.3.1's finding is real and this document does not soften it: AlgoPlonk's
`trustedSetupBN254` calls `srs.Vk.ReadFrom(...)` and **discards the error**,
leaving `vk.Lines` zeroed, which silently voids the off-chain KZG verification
gate. 007 §4.12's earlier, milder note said M12 "should note it if this project
ever pins AlgoPlonk as a dependency"; §14.3 corrects itself — *"the swallowed
error has a demonstrated consequence"* — and assigns the upstream report to M12.

> **Decision: file it upstream, as a one-off action, and do not pin AlgoPlonk.**
> The report costs an issue with a two-line diff and a reproduction that already
> exists in `tests/fixtures/spike-reference/zk-m7/`. It is not a release blocker
> because **nothing this repo ships depends on AlgoPlonk** — T3 is
> unimplemented, no Go toolchain is required to build or test anything here
> (§5.3), and `pyproject.toml` names no such dependency. So it is a good-citizen
> obligation with a demonstrated security consequence for *other* users, which
> is precisely the kind of thing that gets dropped if a document does not name
> an owner and a trigger. Owner: this module. Trigger: before the tag.

For completeness, 007:2597's hand-off — *"M8–M12 should be able to answer such a
question by arithmetic from §13.1 rather than by another spike"* — is
acknowledged and **not exercised**: M12 raises no "should we just ZK this?"
question, and §13.1's table remains where it is. `docs/versioning.md` cites it
as the standing reference so the next module that wants the question answered
knows where to look.

---

## 9. Edge cases

1. **The `ci-live` run at G1-M12 goes red.** Then the release stops, which is the
   correct outcome and the entire reason the gate exists. The likeliest causes
   are enumerable in advance from 011: a beacon endpoint pool outage (011 §10
   item 5 — reported as `LIVE-TIER-DEGRADED`, and a degraded run **must not** be
   cited as G1-M12), a real `RETRY_REPLANNED` finalization race (011 §5.5), or
   the quarantined G1-M9 test. Only the last is expected.
2. **The nightly `ci-live` fires at 06:00 UTC before anyone triggers one
   manually.** Fine, and it counts — the gate asks for a green run of the real
   body, and 011 §8.3 makes the scheduled and dispatched jobs the same body. The
   release notes cite whichever ran, with its event type.
3. **The testnet faucet will not fund 32.3 ALGO.** `ring_n` drops to 8 (010 §5.3
   makes it a target-file value; both are supported and `ring_init_chunk` is
   resumable), and the release notes record which `N` the testnet run used.
   Anything smaller than the mainnet recommendation is a *weaker* test and must
   be labelled as one.
4. **The mainnet app is updated or deleted between the tag and someone reading
   the README.** `deploy verify` and `deploy resolve` return `CODE_MISMATCH` or a
   404, loudly. This is not hypothetical — §2.5c measured a mainnet app in this
   project vanishing between a ROADMAP row's writing and this pass. The README's
   §6 therefore prints a **command**, never just a claim.
5. **A reader `pip install`s the wheel and calls
   `prove_receipt(against_anchor=True)`.** It fails on a missing
   `contracts/state_anchor/bench_app.py` (§4.2). The error must name the reason
   and point at the checkout instructions, not raise a bare `FileNotFoundError`
   from `patched_probe_source`. That is a one-line guard in
   `relayer/drivers/m7_receipt.py` and it is in §17's MUST list.
6. **Vercel's builder ignores the `service` extra** (§4.1). Option B, recorded in
   advance so the implementation pass does not invent a third approach under
   time pressure. The gate is a real paid request, not a successful build.
7. **Someone regenerates `versions.json` on a machine with a different `puyapy`.**
   The `contracts` job goes red with a byte count and a hash, which is 011 §10
   item 11's intended outcome. `puyapy==5.9.0` is pinned exactly and 007 §14.6's
   `pip install puya` trap is documented in `docs/quickstart.md`.
8. **A fork activates between the tag and the next release.** The ordinary path:
   two `append_fork_row` calls, 2,000 µALGO, no redeploy, no new tag (§3.3 row
   1). `versions.json`'s `code_window` does not change, because the code did not.
   The *deployment's* table window changes, and `deploy inspect --forks` shows
   it. This is the scheme working as designed.
9. **A `code_id` appears in `versions.json` for a contract with no deployment
   anywhere.** Normal — `versions.json` describes bytecode, manifests describe
   deployments. `resolve` returns `NOT_DEPLOYED`, which is a verdict, not an
   error.
10. **The quarantine entry expires on 2026-11-04 and nobody has looked.** 011
    §5.7's mechanism fires: the *quarantine* fails the build, not the test. A
    release cut after that date cannot be green without a human decision, which
    is the design. The release notes' expiry date makes it visible before then.
11. **A docs-only PR.** `ci-offline` still runs (011 §10 item 8). Two minutes,
    deliberately no `paths-ignore`.
12. **`README.md` is the PyPI long description and contains a badge pointing at
    a private-looking URL.** The repo is **measured public**
    (`"visibility": "public"`), so the badge renders. If the repo ever goes
    private the badge silently breaks on PyPI — worth one sentence in
    `docs/release.md`, not a mechanism.

---

## 10. Adversarial notes

1. **The adversary is the reader's inference, not an attacker.** 011 §11 item 1
   established that this project's real threat is drift into untruth with nobody
   noticing. M12 raises the stakes: a design doc's wrong sentence misleads a
   reviewer who can check it; a README's wrong sentence misleads someone who
   cannot. Every mechanism in §5 and §12 exists for that reader.
2. **The most dangerous sentence available to this project is "verified on
   Algorand".** It is true in the narrow sense that a BLS aggregate and a Merkle
   path were checked on chain, and false in every sense a reader will supply —
   that a 2/3 sync-committee majority cannot lie, that finality is economically
   secured, that this is full-node security. 008 §5.3 is explicit that it is
   none of those. **G7-M12 is the mechanism and §5.4's item is its content.**
3. **A version scheme that a human maintains is a version scheme that lies.**
   §3.1's argument is not aesthetic: 010 §3.3 measured three prose-vs-code
   drifts in this repo in documents written by careful people. The `code_id` is
   chosen because CI already recomputes and diffs it on every push.
4. **A committed manifest is a target.** 010 §9.5 is unchanged: the manifest is
   not signed and is not authoritative. `verify` re-derives everything it can
   from chain state and the pinned hash, so a tampered manifest produces a
   `verify` **failure**, not a silent redirection. That property is why the
   manifest may be committed at all.
5. **`CODE_MISMATCH` must never be a warning.** It is the only signal that
   distinguishes "the app I audited" from "an app at that id". 010 §9.1 proved by
   real experiment that an unrestricted contract can be reprogrammed by anyone
   for one transaction fee, and §2.5c measured a mainnet app in this very project
   ceasing to exist. Exit non-zero, always.
6. **Publishing a name is irreversible.** `eth-avm-relayer` on PyPI is a global
   claim, and an abandoned package under a plausible name is a supply-chain
   liability for everyone who later types it. §1.2 item 4 keeps the upload a
   human decision precisely because a design doc cannot weigh that.
7. **A badge is a claim with no caveats attached.** It renders next to the
   project title, above the trust-model paragraph, in a context that strips every
   qualifier. That is why it points at `ci-offline` — whose green is a statement
   about pure computation on committed fixtures — and never at `ci-live`, whose
   green is a statement about one day.
8. **The release notes are the only place the quarantine list will ever be
   read.** 011 §5.7 made silence expensive by giving quarantine entries an expiry;
   §6.2 item 5 makes it *visible* by putting the entry in front of everyone who
   reads a release. Those are different mechanisms and both are needed.
9. **Documenting the deploy tool documents an attack surface.**
   `docs/operating.md` describes governance calls, the funding recipe, and
   `renounce`. That is correct — 010 §1.3 mitigation 3's whole argument is that a
   deployment nobody can audit is worse than one whose procedure is public — but
   the governance warnings (010 §9.3: `apply` must warn when `governance ==`
   the signer) belong in the *document*, not only in the tool's stderr.

---

## 11. Cost

**Engineering**, honestly:

| item | scale |
|---|---|
| `README.md` rewrite + 6 new docs | the bulk of the module; ~1,500–2,500 lines of prose, all of it citation work |
| `deploy/versions.json` + generator hook | small — the generator exists and already emits four artifacts |
| `deploy resolve`, `deploy inspect --forks` | small — both decoders already exist (§3.6) |
| `relayer/__main__.py`, `[project.scripts]`, `--help` text | trivial |
| dependency split + drift test | small, but §4.1's Vercel unknown makes it the fiddliest item |
| Suites V/W/N/M | ~300 lines, all offline |
| **the two real runs** | irreducible: ~20 min of `ci-live`, ~25 min of testnet, plus the faucet |

**Runner minutes**: unchanged from 011 §12 except one `ci-live` dispatch
(**projected 14–17 min**, per 011 §8.2) and one PR's `ci-offline`
(**measured ~4 min** wall-clock from run 31227550081's job times).

**Real chain cost**: **testnet only — projected ≈ 32.3 ALGO of test tokens
locked and 0.033 in fees** at `ring_n = 128` (010 §10.2's measured model), or
≈ 24.1 at `ring_n = 8`. **Mainnet: zero**, because §1.2 item 1 deploys nothing.

**Third-party cost**: one `ci-live` run's beacon/RPC traffic (011 §12: "several
hundred requests, ~tens of MB"), plus the testnet faucet. No `live_heavy` run is
required for the release, so no 1 GB `BeaconState` fetch is incurred.

**Ongoing cost this module creates**: `versions.json` joins the set of artifacts
that must be regenerated when contracts change. That is a real, permanent tax,
and it is the same tax G3-M10 and G3-M11 already charge — paid by the same
command (`python -m deploy schema`) and enforced by the same job.

---

## 12. Test plan

Suites follow the M5 §9 / M6 §11 / M7 §9 / M8 §13 / M9 §13 / M10 §13 / M11 §13
numbering convention. **All four suites are offline** and run per-PR: a module
whose subject is truthfulness must not have its own checks gated on a nightly.

### 12.1 Suite V — the versioning artifact, offline

| id | test | expectation |
|---|---|---|
| V-1 | `python -m deploy schema --check` regenerates `versions.json` | byte-identical; **G3-M12**. (Baseline **measured this pass**: the four existing schema artifacts already pass — `schema is up to date`, exit 0) |
| V-2 | Every `code_id` equals the `approval_sha256` in the corresponding `*.schema.json` / `_compiled/*.compiled.json` | equal, for every contract present |
| V-3 | Every contract with `"fork_axis": "none"` | grep of its `contracts/` subtree contains no fork box name and no fork-table constant — the claim is asserted, not omitted |
| V-4 | `code_window.supported` vs `deploy/forks.py::FORK_FIELD_COUNTS` | identical sets: `{deneb, electra, fulu}` |
| V-5 | `code_window.unsupported` contains `gloas` for **both** M4 and M8, each with a non-empty `reason` citing a real section | present; an empty reason is a failure |
| V-6 | `deploy` refuses to build an `append_fork_row` for an `unsupported` fork | raises, naming the reason (§3.7) |
| V-7 | The same call for `fulu` | **succeeds** — the non-vacuity half, mirroring H-2/G8-M10's both-ways discipline |
| V-8 | `avm.version` vs every `*.schema.json`'s `program.avm_version` | all equal (**measured today: 10** in all four) |
| V-9 | `bytecode_cap_headroom_bytes` vs `8192 − approval_bytes` | equal (**measured: 6,980 ⇒ 1,212**) |

### 12.2 Suite W — packaging, offline (plus one build step)

| id | test | expectation |
|---|---|---|
| W-1 | `python -m build --wheel`, then inspect | contains `relayer/**` only; **zero** modules from `deploy`, `contracts`, `service`, `tests` |
| W-2 | Dependency closure of the built wheel | **≤ 20 packages**. Baselines **measured this pass: 59 today, 19 for the four real deps.** **G5-M12** |
| W-3 | `METADATA` | has `Description` (from `readme`), `Requires-Python: >=3.12`, a `Project-URL`, and a licence classifier |
| W-4 | Dependency-declaration drift | the package sets in `pyproject.toml` and `service/x402_endpoint/requirements.txt` agree. **Closes 011 §18 item 17, which did not land** |
| W-5 | `relayer.__version__` vs `[project] version` | equal (**measured: both `0.1.0`**) |
| W-6 | In a clean venv from the wheel: `import relayer`, `eth-avm-relayer --help`, `python -m relayer --help` | all three succeed. **Measured today: the third fails outright** (§2.3) |
| W-7 | Every `python -m relayer …` invocation in `relayer/cli.py`'s and `relayer/__init__.py`'s docstrings | parses under `build_parser()`. **G6-M12** |
| W-8 | `prove_receipt(against_anchor=True)` from an installed wheel | raises a **named** error citing §4.2's checkout requirement, not a bare `FileNotFoundError` |

### 12.3 Suite N — the claims, offline

The suite that makes §10's adversary expensive.

| id | test | expectation |
|---|---|---|
| N-1 | First occurrence of `verifier`/`verified`/`trustless` in `README.md` | the sync-committee trust sentence is in the **same paragraph**. **G7-M12**, 008 §15.6 |
| N-2 | The four stale strings of §5.4 rows 1–3 | **absent** from `002`, `005` and `README.md`; the amended wording present. **G8-M12** |
| N-3 | Any T3 coverage percentage in `README.md` or `docs/**` | **absent** (007 §10 row 5). The T1+T2 figure is permitted **only** with its citation to the committed 300-block sample |
| N-4 | The committed `coverage_sample_300blocks.json` still re-derives its headline | **measured this pass**: 94,667 receipts, T1 93.729% + T2 3.775% = **97.5%**, ZK tiers 1.144+0.429+0.633 = 2.2%, unprovable 0.29%. Duplicates 011's F-3 deliberately: F-3 protects the fixture, N-4 protects the *published* number |
| N-5 | Words `monitored`, `monitoring`, `uptime`, `SLA` near the service or mainnet app | **absent** from README and docs (011 §16 gap 8) |
| N-6 | Every design doc, run id, app id and round cited in `README.md`/`CHANGELOG.md` | resolves: docs exist at their path (extending 011's F-4), run ids are 11-digit, app ids appear in a committed manifest |
| N-7 | `README.md` mentions account/storage proofs | the G4-M9 qualifier is present (§7 row 13) |
| N-8 | Any number in `README.md` matching `\d{3,}` | appears in an allowlist mapping it to a design-doc section or a manifest field. **G10-M12** — the mechanical form of `ARCHITECTURE.md`'s standing rule |
| N-9 | `ROADMAP.md`'s M7/M10 rows | no longer describe `3664247481` as live, nor "public HTTPS exposure" as undone (§5.4 items 7–8) |

### 12.4 Suite M — manifests and live verification

| id | test | expectation |
|---|---|---|
| M-1 (offline) | `deploy/manifests/mainnet-v1.0.json` parses, and every `approval_sha256` matches a `code_id` in `versions.json` | equal |
| M-2 (offline) | Every manifest's `genesis_hash` matches the target file of the same network | equal (G7-M10's data, asserted statically) |
| M-3 (**live**) | `deploy verify --target mainnet` with **no signer** | passes against the real apps. **Measured by hand this pass** for app `3665914633`: approval 3,108 B / `f7a846ff…c9d2`, clear `ed90f0d2…0ce7`, both matching the pin. **G4-M12** |
| M-4 (**live**) | `deploy resolve --network mainnet --fork fulu` | `m7: USABLE`; `m4`/`m8`: `NOT_DEPLOYED` |
| M-5 (**live**) | `resolve` against an app id whose program does not match its pin | `CODE_MISMATCH`, **non-zero exit** |
| M-6 (**live**) | `resolve --fork gloas` | `FORK_UNSUPPORTED`, with the cited reason |

### 12.5 The runs that are the real test plan

> **RL-1 (G2-M12).** §6.1's testnet deploy-verify-drive, committed manifest,
> real app ids and rounds in the release notes.

> **RL-2 (G1-M12).** A real green `ci-live.yml` run — the first in this
> project's history — with its uploaded `algod-versions.json` naming the
> `go-algorand` build, its report listing the day's real participation and `k`
> (011 §18 item 14), the quarantine list, and every skip with its reason.

---

## 13. Acceptance gates

| Gate | Statement | How judged |
|---|---|---|
| **G1-M12** | A **real, green `ci-live.yml` run exists** and is cited by run id in the release notes, with its `algod-versions.json` artifact. Closes 011's G2-M11, which has **never** run (§0) | RL-2 |
| **G2-M12** | A real **testnet** `deploy apply` → `verify` (second process, no signer) → M9 `sync`/`anchor`/`prove_receipt` against real mainnet Ethereum data, from the manifest alone. Closes 010 §15 gap 3 | RL-1 |
| **G3-M12** | `deploy/versions.json` regenerates **byte-identically** in `ci-offline`, and every `code_id` equals the committed compiled pin | V-1, V-2 |
| **G4-M12** | `deploy verify --target mainnet` passes against the **real live mainnet apps**, from a committed manifest, with **no signer**. (Hand-verified this pass; the gate is that it is committed, runnable and in CI-adjacent documentation) | M-1, M-3 |
| **G5-M12** | A clean-venv install of the published wheel pulls **≤ 20** packages and imports `relayer`. Baseline **measured: 59** | W-1, W-2 |
| **G6-M12** | **Every CLI invocation this repo documents actually runs** — `python -m relayer …`, `eth-avm-relayer …`, `python -m deploy …` | W-6, W-7 |
| **G7-M12** | `README.md` carries the sync-committee trust statement in the same paragraph as its first "verifier"/"verified"/"trustless", qualifies G4-M9, and nowhere implies the live deployment is monitored | N-1, N-5, N-7 |
| **G8-M12** | 007 §10's documentation corrections and 008 §15.6's item are **landed**, asserted by a test that greps for the stale strings | N-2, and §5.4's table |
| **G9-M12** | A `v1.0.0` tag and GitHub release exist whose notes contain all nine items of §6.2 — including the **full quarantine list** and the **open-gate table** | inspection of the release body against §6.2 |
| **G10-M12** | **No number published outside `docs/design/` lacks a real run, response or file behind it** | N-8; `ARCHITECTURE.md`'s standing rule |

---

## 14. Questions resolved, and what is handed on

### 14.1 M12's own ROADMAP row

> *"Contract-versioning story (AVM/consensus-fork-gated, not plain semver)"*

**Resolved, §3**, and the row's framing is sharpened in two places. First, the
axis count is **three, not two** — 007 §8.6 added the proof system before this
module existed, and §3.2 gives it a home even though v1 leaves it empty. Second,
and more consequentially, the fork axis is **two windows, not one**: a mutable
per-deployment table window and an immutable per-bytecode code window, whose
intersection is what a consumer can actually rely on. Nothing on chain computes
that intersection, and §3.7 shows nothing prevents them diverging — which is a
finding this row did not anticipate.

> *"Gates public v1 release"*

**Held, and made concrete**: §7's checklist has **nine blocking rows**, seven of
which are a file, a flag or two lines of code, and two of which are real runs.

### 14.2 `ARCHITECTURE.md`'s deferred policy

> *"This gets a concrete policy in M12's design doc once the supported fork
> range is known from M3/M4."*

**Written, §3.** And the sentence's own parenthetical — "(Altair/Capella/Deneb
field layouts)" — is **corrected**: **measured**, the real supported range is
**Deneb, Electra, Fulu** (`deploy/forks.py::FORK_FIELD_COUNTS = {deneb: 28,
electra: 37, fulu: 38}`, and all three `deploy/targets/*.json`). Gloas is
excluded, per contract, for two *different* measured reasons (§3.3). §5.3 lands
the correction.

### 14.3 Inherited questions, answered

**Every "flagged for M12" in the corpus**, found by
`grep -rn "M12" --exclude-dir=.git` (which returns exactly nine files:
`ARCHITECTURE.md`, `pyproject.toml`, `ROADMAP.md`, and design docs 003, 007,
008, 009, 010, 011), and answered in the discipline 011 §15.3 established.

| source | item | resolution |
|---|---|---|
| `ARCHITECTURE.md:56–61` | Concrete versioning policy once the fork range is known | **Written**, §3. Fork range corrected to Deneb/Electra/Fulu (§14.2) |
| `pyproject.toml:40–43` | "M12 owns the full release story"; only `relayer` is distributable | **Decided**, §4.2: one distribution, `deploy/` stays a checkout tool, with the three reasons. And the file's own Vercel workaround is **measured to cost 40 extra packages** (§4.1) — fixed, with a recorded fallback |
| 003 §9 (`003:1132–1135`) | Version M3 on AVM only; M4/M8 on fork range, because a gindex change is a table update not an M3 redeployment | **Adopted verbatim and extended** (§3.2): M2/M5/M6/M7 join M3 on the AVM-only side, because execution-layer RLP/MPT encodings are fork-independent. §3.3 shows *when* a table update is nonetheless insufficient, which 003 could not know |
| 003 §4.3 (Gloas warning) | Depth-11 sync-committee branch = 738 > the 700 single-call limit; "must be *planned*" | **Encoded** as M4's `code_window.unsupported` with the cited reason (§3.4), and enforced client-side (§3.7) |
| 007 §4.8 (`007:1266`) | Adding a T3 tier is a contract redeployment — "a contract-versioning event, and §8.6 hands it to M12" | **Given an axis** (§3.2 axis C) and a field (`versions.json`'s `proof_system`), **empty in v1** because T3 ships no prover. The seam exists so T3 does not have to invent one |
| 007 §4.12 (`007:1479`) | AlgoPlonk's swallowed `ReadFrom` error; "M12 should note it if this project ever pins AlgoPlonk" | **Superseded by 007 §14.3.1's own correction** and resolved as a *report*, not a note — §8. This repo pins no AlgoPlonk dependency (**measured**: `pyproject.toml` names none), so the note's trigger never fires; the report's does |
| 007 §8.6 (`007:2106`) | A tier is a versioned artifact; gnark/AlgoPlonk must be pinned exactly | **Recorded in the scheme** (§3.2 axis C) with the pinning rule attached to the axis. Inert until T3 ships |
| 007 §13 (`007:2597`) | "M8–M12 should be able to answer 'should we just ZK this?' by arithmetic from §13.1" | **Acknowledged, not exercised** — M12 raises no such question. `docs/versioning.md` cites §13.1 as the standing reference (§8) |
| 007 §14.3.1 (`007:2938–2939`) | "**M12 action**: this should be reported upstream to AlgoPlonk"; the swallowed error has a demonstrated consequence | **Accepted, with an owner and a trigger** (§8): file it before the tag; a two-line diff and an existing reproduction. **Not** a release blocker, because nothing here depends on AlgoPlonk (§7 row 17) |
| 007 §10 (the correction list) | Four in-repo documentation corrections | **Measured: none landed.** §5.4 resolves all four with exact wording and **G8-M12** asserts them mechanically |
| 007 §8.7 | Go/gnark as a second language in `ARCHITECTURE.md` | **Nothing owed in v1** (§5.3): nothing Go ships, so the document must not describe one. Re-fires when T3 ships |
| 008 §5.3 (`008:725`) | "007 §8.6 already flags documentation-correction duty to M12; this is a second item for that list" | **Placed at the top of that list** (§5.4), where 008 §15.6 asked for it |
| 008 §15.6 (`008:2207–2212`) | `README.md` must state TP-M8-1 alongside "trustless"/"verified"; this is not full-node security | **Normative and gated** — **G7-M12**, mechanically asserted by N-1. `docs/security.md` carries 008 §5.3's table in full |
| 009 §15.4 (`009:1364`) | "The CLI is the first user-facing surface; the README's quickstart should be `python -m relayer status` against a public deployment" | **Taken, and the blocker found**: **measured**, `python -m relayer` does not work at all (§2.3). §4.3 fixes it in two lines and **G6-M12** asserts every documented invocation runs. It becomes README §5, against the committed mainnet manifest |
| 010 §0 (`010:11`) | "M12 (release: the README's quickstart is a deployment)" | **Partly declined, deliberately.** The quickstart is `status` against an **existing** deployment (009's call), not a deployment — deploying requires `puyapy`, a checkout, a faucet and ~32 ALGO (§6.1), which is a first *page* but not a first *command*. `docs/operating.md` is where a deployment quickstart belongs, and it exists |
| 010 §4.6 (`010:577`) | `SyncCommitteeVerifier` is 6,980 B = 85% of the bytecode cap; "worth M12 and any future M4 revision knowing" | **Promoted from a footnote to a versioning constraint** (§3.3): `bytecode_cap_headroom_bytes: 1212` is a generated field, and `docs/versioning.md` states it as a standing budget — because a fork needing an M4 *code* change has 1,212 bytes to fit in before it cascades into M8 and every consumer |
| 010 §15 gap 3 (`010:1565`) | "§6.3 recommends a testnet run before v1; M12 should require one" | **Required. G2-M12** (§6.1), with the four things it proves that devnet cannot, and a projected cost of ≈32.3 testnet ALGO |
| 011 §15.4 (1) | Add a README badge; it must point at `ci-offline`, not `ci-live` | **Done**, §5.1 row 3, with 011 §1.3's wording paraphrased beside it |
| 011 §15.4 (2) | A release requires a `ci-live` run, cited by run id — "require the *citation*, not the assertion" | **Done, and it turns out to be the module's first blocking row**: **measured**, no such run has ever existed (§0). **G1-M12** |
| 011 §15.4 (3) | The quarantine list is release-blocking input and belongs in the release notes | **Adopted** (§6.2 item 5). Today: one entry, G1-M9, expiring **2026-11-04**, quoted with its real opcode numbers. Verdict: **not blocking**, but published (§7 row 10) |
| 011 §15.4 (4) | `requires-python` — do not ship a floor CI has not run | **Closed with evidence** (§4.4): `>=3.12`, matrix `["3.12","3.13"]`, **both legs measured green** on run 31227550081. The M11 row's "confirm on first real push" is confirmed |
| 011 §15.4 (5) | Contract versioning "now has a mechanism": tie a version to the artifact hashes rather than a hand-maintained number | **This is the scheme** (§3.4). `code_id` *is* the artifact hash, and §2.5b measured it matching live mainnet |
| 011 §11 item 9 / §16 gap 8 (`011:1433`, `011:1717`) | CI cannot verify the mainnet deployments; "M12's README must not imply otherwise"; do not describe the service as "monitored" | **Both gated** — N-5 forbids the vocabulary, and §5.1 row 6 requires the "nothing monitors this" sentence beside the app ids. **Plus a correction owed back**: the app id 011 names, `3664247481`, **no longer exists** (§2.5c) |
| `ROADMAP.md` M11 row | "cite this pass's real `ci-offline`/`ci-live` run ids"; "note `test_l2`/G1-M9 remains a quarantined gap"; "py3.12 leg untested locally" | **All three**: §6.2 items 1–2 (and §0 finds the `ci-live` id does not exist yet), §6.2 item 5, and §4.4 respectively |
| `ROADMAP.md` M7 row | public HTTPS exposure / Bazaar registration / challenge submission tag | **§8**: the first is **measured already done**; Bazaar is **declined** with a reason and a gate; the submission tag is **sequenced** — M12 builds all five preconditions, a human presses submit |

### 14.4 Handed on

**To a future M4/M8 revision.** §3.7's hazard: `append_fork_row` validates
epoch monotonicity, the sentinel, capacity and `fork_version` length, and
**nothing about the gindices**. A chain-side depth or gindex bound would make
the code window enforceable on chain rather than only in `deploy`. `O-M12-1`.

**To a future `relayer` revision.** §4.2's structural limit: `REPO_ROOT =
Path(__file__).resolve().parents[1]` makes `prove_receipt(against_anchor=True)`
and `deploy_donor_pair` unusable from an installed wheel. The fix is either
package data or a `repo_root=` parameter on the public API; both change a public
signature, which is why M12 documents rather than changes it. `O-M12-2`.

**To whoever performs the mainnet v1 deployment.** `docs/operating.md`'s mainnet
section, plus three standing preconditions this document does not waive:
`O-M10-3` (a multisig or hardware governance signer), 010 §9.3's warning that
`governance` must not equal the signer, and 010 §10.4's fact — in bold, on the
page — that **box MBR on these contracts is not recoverable**: at `ring_n = 128`
that is ~32.3 real ALGO spent, not lent.

**To a monitoring module, if one is ever wanted.** `deploy resolve` already
performs the two checks a monitor needs (is the app there; does its program still
hash to the pin), and 010 §8.3 identifies the third (M8's `conflict != 0`
equivocation latch, which 009 §8.5 classifies PAGE_A_HUMAN and which nothing
watches). `O-M12-3`. Until it exists, §8's decision on Bazaar stands.

---

## 15. Honest gaps and deferred work

**Gaps this design knowingly leaves open:**

1. **A version scheme cannot make a deployment trustworthy — it can only make it
   *identifiable*.** `code_id` proves the bytecode on chain is the bytecode in
   this repo. It says nothing about whether that bytecode is correct, and 010
   §1.3's table of things nothing downstream re-checks is unchanged by anything
   in this document.
2. **The code-window guard is tool-side only** (§3.7). A governance key holder
   using `goal` bypasses it entirely. This is the largest correctness gap M12
   surfaces and the one it is least able to close, because closing it is a
   contract change.
3. **Nothing monitors anything** (011 §16 gap 8, §8). The live mainnet app, the
   live Vercel service, and M8's `conflict` latch all have zero automated
   observation. M12's response is to forbid the docs from implying otherwise,
   which is the correct response for a docs module and is not a fix.
4. **The release is a snapshot; the fork window is not.** A deployment's table
   window changes by governance call, with no version bump and no release. That
   is the scheme working as intended (§9 item 8), but it does mean
   `versions.json` at tag time describes *bytecode*, never *current deployment
   state* — `deploy resolve` is the only thing that answers the latter, and it
   requires a live algod.
5. **Three of seven `code_id`s cannot be filled offline** (§3.4).
   `MptSegmentApp` and the donor pair have no entry in
   `deploy/schema/_compiled/`, and producing one needs `/v2/teal/compile`. They
   are filled by G1-M12's `ci-live` run; until it happens the artifact is
   incomplete and must say so rather than omit the contracts silently.
6. **No schema-migration story** (`O-M10-7`, inherited unchanged). A
   `versions.json` at `versions_version: 2` decoding a `v1` deployment works only
   because every layout so far has been append-compatible. M12 adds a second
   versioned artifact to a repo that already had four, and does not solve the
   general problem.
7. **The dependency fix has an unmeasured step** (§4.1). Whether Vercel's builder
   honours an extra is unknown at design time. Option B is recorded, but the
   possibility remains that v1 ships with either two build configurations or a
   documented, deliberate 59-package install.
8. **The testnet run is not a mainnet run.** G2-M12 closes 010 §15 gap 3 as far
   as a public network can, but testnet contention is not mainnet contention,
   test ALGO is not ALGO, and no mainnet M4/M8 exists to be verified. The gap
   narrows; it does not close.
9. **A README cannot be tested for honesty, only for specific dishonesties.**
   Suite N catches the failures this project has actually had or been warned
   about — an unqualified "verified", a stale corrected claim, an unbacked
   number, a "monitored". It cannot catch a *new* misleading sentence, and no
   mechanism can. The design compensates by keeping the README short and making
   every number cite something, so that the surface area for a new one is small.

**Deferred (`O-M12-*`), each measurement- or event-gated:**

| id | idea | gate |
|---|---|---|
| `O-M12-1` | A chain-side gindex/depth bound in `append_fork_row` on M4 and M8 | an M4/M8 revision; §3.7 |
| `O-M12-2` | Make `prove_receipt(against_anchor=True)` and `deploy_donor_pair` work from an installed wheel (package data, or `repo_root=` on the public API) | a `relayer` revision; §4.2 |
| `O-M12-3` | A monitoring job: scheduled `GET /health`, `deploy resolve` against the pin, and an alert on M8's `conflict != 0` | needed **before** Bazaar registration (§8); needs a decision about who is paged |
| `O-M12-4` | Publish `eth-avm-deploy` as a second distribution (implies packaging `contracts/`) | only when a second party needs to deploy without a checkout; `O-M10-8` is its sibling |
| `O-M12-5` | A `docs/` site (rendered, versioned) rather than markdown in-tree | only if the doc set outgrows six files |
| `O-M12-6` | Automated release notes generated from `ROADMAP.md` + the run APIs | only after two releases have been cut by hand, so the format is known rather than guessed |
| `O-M12-7` | A signed manifest, or a manifest anchored on chain | only if a third party ever needs to trust a manifest they did not fetch from this repo (010 §9.5's boundary) |

---

## 16. File layout

```
README.md                     REWRITTEN (§5.1) -- "Early scaffold stage" since 51dd033
CHANGELOG.md                  NEW (§5.5). v1.0.0's entry is §6.2's nine items
ARCHITECTURE.md               two sections corrected (§5.3)
CONTRIBUTING.md               one paragraph: the release process points at docs/release.md

docs/
  security.md                 NEW. the trust model at length; 008 §5.3's table verbatim
  versioning.md               NEW. §3 for consumers; the fork decision table; the
                              1,212 B M4 headroom as a standing budget
  quickstart.md               NEW. wheel path + checkout path, with §4.2's real limit
  operating.md                NEW. deploy end to end; 010 §6.5's migration table;
                              the mainnet runbook, incl. the non-recoverable-MBR warning
  release.md                  NEW. §6's runbook + §7's release-readiness checklist
  design/012-docs-packaging-release.md   this document

deploy/
  versions.json               NEW, GENERATED, CI-diffed (§3.4)
  schema/generate.py          + the versions.json emitter
  inspect.py                  + --forks decoding (surfacing the two existing
                              _read_fork_rows; measured: `grep -c fork` is 0 today)
  cli.py                      + `resolve` (§3.5), + `--forks` on inspect, + real --help
  manifests/
    mainnet-v1.0.json         NEW, COMMITTED -- the three real live app ids (§2.5d)
    testnet-v1.0.json         NEW, COMMITTED -- produced by G2-M12's run

relayer/
  __main__.py                 NEW, 5 lines. `python -m relayer` (§4.3)
  cli.py                      + real help text; no logic change
  drivers/m7_receipt.py       + a named error when contracts/ is absent (§9 item 5)

pyproject.toml                readme, scripts, classifiers, project-urls;
                              the three service deps move to a `service` extra (§4.1)

tests/harness/
  test_versions.py            Suite V
  test_packaging.py           Suite W
  test_doc_claims.py          Suite N
  test_manifests.py           Suite M (M-1/M-2 offline; M-3..M-6 live)
```

**Files this module changes elsewhere**: `ROADMAP.md` (M12's row, plus §5.4's
corrections 7–8 to the M7/M10 rows), `docs/design/002-rlp-decoder.md` §4.2(a),
`docs/design/005-mpt-walker.md` §7.5.

**Nothing under `contracts/` is modified.** The same scope boundary M8, M9, M10
and M11 all kept. **Nothing under `tests/fixtures/spike-reference/` is
modified** — frozen by `ARCHITECTURE.md` and by 007 §10's own instruction.

---

## 17. Implementer checklist (normative MUSTs)

1. **MUST NOT** tag a release before a **real, green `ci-live.yml` run exists**,
   and **MUST** cite its run id and its `algod-versions.json` artifact in the
   release notes (G1-M12). **MUST NOT** cite a run reported as
   `LIVE-TIER-DEGRADED` (011 §10 item 5) as satisfying this.
2. **MUST** perform the testnet run of §6.1 and **MUST** commit its manifest
   (G2-M12). **MUST NOT** substitute another devnet run: every module M4–M11 has
   already done that, and the point of this gate is the difference.
3. **MUST** commit `deploy/manifests/mainnet-v1.0.json` recording the three real
   live app ids (**measured**: `3665914633`, `3666047636`, `3666047587`) with
   their `code_id`s, creator and rounds, and **MUST** verify it against the chain
   before committing (G4-M12).
4. **MUST** generate `deploy/versions.json` from the compiled artifacts and
   **MUST NOT** hand-write any `code_id`, byte count or headroom figure into it
   (G3-M12). **MUST** fail CI on any difference, via the existing `contracts`
   job.
5. **MUST** make `deploy` refuse client-side to append a fork row for any fork in
   `code_window.unsupported`, and **MUST** test the refusal **both ways** (it
   fires for `gloas`, it does not for `fulu`) — the non-vacuity discipline
   G8-M9/G8-M10/H-2 already established.
6. **MUST** state, in `docs/versioning.md` and in the release notes, that the
   §3.7 guard is **tool-side only** and that a governance key holder using
   `goal` bypasses it. **MUST NOT** describe the code window as enforced.
7. **MUST** add `relayer/__main__.py` and `[project.scripts]`, and **MUST**
   assert that **every** CLI invocation printed in `relayer/cli.py`'s and
   `relayer/__init__.py`'s docstrings actually runs (G6-M12).
8. **MUST** move `fastapi`, `uvicorn[standard]` and `x402-avm[fastapi,avm]` out
   of `[project.dependencies]`, and **MUST** prove the Vercel service still works
   with a **real redeploy and a real paid request** — not a successful build.
   **MUST** fall back to §4.1's option B rather than improvising a third
   approach. **MUST NOT** leave `sentry-sdk` and `fastapi-cloud-cli` in a
   library's dependency closure (G5-M12).
9. **MUST** add a test that every place this repo declares dependencies agrees.
   011 §18 item 17 asked for this and it did not land (W-4).
10. **MUST** put the sync-committee trust statement (008 §15.6 / TP-M8-1) in the
    **same paragraph** as `README.md`'s first "verifier"/"verified"/"trustless",
    and **MUST** assert it mechanically (G7-M12). **MUST NOT** treat a link to
    `docs/security.md` as satisfying this.
11. **MUST** land all four of 007 §10's in-repo corrections and **MUST** assert
    the stale strings are gone (G8-M12). **MUST NOT** edit
    `tests/fixtures/spike-reference/` to do it.
12. **MUST NOT** publish any T3 coverage percentage in `README.md` or `docs/**`
    until a real proof exists at the deployed tier (007 §10 row 5). The T1+T2
    figure is publishable **only** with its citation to the committed 300-block
    sample (**measured: 97.5% of 94,667 receipts**).
13. **MUST NOT** use the words "monitored", "monitoring", "uptime" or "SLA" of
    the live service or the mainnet app anywhere in published documentation
    (011 §16 gap 8).
14. **MUST** qualify account/storage proofs wherever the README lists
    capabilities: G4-M9 is open, `prove_account` never submits a transaction, and
    `test_l5` does not exist (010 §4.4).
15. **MUST** point the README badge at `ci-offline` and **MUST NOT** badge
    `ci-live` (011 §15.4 item 1).
16. **MUST** include §7's full open-gate table and the **entire** contents of
    `tests/harness/quarantine.toml` in the release notes (011 §15.4 item 3).
17. **MUST** print the real M5 numbers (5,116 / 1,813 / 1,969 B) rather than the
    design-doc targets wherever the README reports M5's state.
18. **MUST** open at least one real pull request before the tag, so that the
    badge's "runs on every PR" claim has been observed at least once
    (**measured: 0 of 27 runs, ever**).
19. **MUST** raise a **named** error, citing the checkout requirement, when an
    installed wheel reaches `prove_receipt(against_anchor=True)` or
    `deploy_donor_pair` (§4.2, §9 item 5). **MUST NOT** let a bare
    `FileNotFoundError` be the user-facing message.
20. **MUST** file the AlgoPlonk swallowed-error report upstream before the tag,
    with the two-line diff and the existing reproduction (§8, 007 §14.3.1).
    **MUST NOT** add AlgoPlonk as a dependency to do it.
21. **MUST** cite a real run id, on-chain response, or file path for every number
    that appears outside `docs/design/` (G10-M12, `ARCHITECTURE.md`).
22. **MUST** update `ROADMAP.md` to record: M12's own results and the tag; the §0
    finding that **`ci-live.yml`'s real body has never executed and all 8 of its
    scheduled runs were the placeholder at `1148ae4`**; the §2.5 corrections that
    **app `3664247481` no longer exists** and that **public HTTPS exposure is
    done**; §4.1's measured 59-vs-19 dependency figure; and §2.3's finding that
    `python -m relayer` — the quickstart 009 §15.4 nominated — has never worked.
