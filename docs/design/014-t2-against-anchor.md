# 014 — T2 (box-staged) receipt proofs against an M8 anchor

**Status**: Design drafted, awaiting human review.
**Type**: **New capability on two already-implemented, already-live modules**
(M7 `Mpt7ReceiptApp` T2 box-staging, M8 `TrustedRootAnchor.attest`) plus a
**promotion** of one test-only artefact (`AnchorReceiptProbe`) to a real,
deployable contract. Not a new track, not a new primitive.
**Closes**: the `TierUnsupported` raised at `relayer/client.py:299-306` —
`prove_receipt(against_anchor=True)` on a T2 leaf, which today has no contract
anywhere in this codebase to drive.
**Extends**: [007 §3.4/§5.1](007-receipt-log-proof.md) (T2's staging mechanism),
[008 §9.2](008-trusted-root-anchor.md) (`mpt7_result_against_anchor`),
[009 §9.2/§12](009-relayer-client.md) (single-group/stateless claim, the T2 MBR
figure), [010](010-deployment-tooling.md) (the manifest and the declared T2 float).
**Depends on**: nothing new. Every mechanism below already exists, compiled and
live-proven, in this repo.
**Design-time convention, inherited from 013**: every number below is labelled
**measured** (a real command run during this design pass against real dev-mode
algod at `localhost:4051`, cited to its real output) or **projected** (an estimate
this document owns, which the implementation pass must replace with a real
result). No number in this document is copied from another document without being
re-derived or re-measured here.

---

## 0. The answer, stated first

**Question the human asked**: *does a T2 (box-staged) receipt proof, verified
against an M8-anchored `receiptsRoot`, actually work — atomically, trustlessly,
permissionlessly — or not?*

**Answer: yes, it works, and it is smaller than expected — but it is gated behind
one real, live, currently-exploitable security bug that must be fixed first.**

This design pass did not reason about the group; it **built it and submitted it
for real**. A T2-against-anchor proof at the worst-case 4,096-byte leaf runs as
**one atomic 10-transaction group**, confirmed on-chain, returning `R_INCLUDED`
against a real M8 `attest()` in the same group:

| | measured |
|---|---|
| Group shape | **10 transactions, 9 application calls, ONE atomic group** |
| Worst measured opcode consumption | **5,237** (4,094 B leaf, 24 logs) |
| Pooled budget available from the group's own app calls | **6,300** (`700 × 9`) |
| Donor transactions actually required | **zero** — real send with no `DonorIssuer` at all committed (§3.2) |
| Box references required | **1 per box-touching transaction** (5 in the group); the 8-per-transaction cap is never approached (§3.3) |
| Race between staging and the anchor check | **structurally impossible** — the whole thing is one group (§3.5) |
| Aborted group | **leaves nothing** — box absent, app balance unchanged, measured (§3.6) |
| Fees | **14,000 µALGO** with a 4-donor margin; 9,000 µALGO with none (§6) |
| Contract delta | **+3 mode branches, ~35 lines, +103 compiled bytes** (3,208 B → 3,311 B) (§4.3) |

**The informal framing this pass was asked to test — "staging may span several
groups, only the final verification must be atomic" — is technically true but is
the wrong design, and adopting it would be a real regression.** It is unnecessary
(everything fits in one group, measured, at the worst case), and it is expensive:
a staging group that opens a box and then does not close it in the same group
**permanently locks 1,643,300 µALGO of MBR in the app account** — measured, §3.6 —
and creates a **permissionless griefing vector** that today's single-group design
does not have (§5.2, measured: `box size mismatch 2000 4094`). §3.1 corrects the
claim in full.

**The blocker.** `AnchorReceiptProbe` — the only artefact in this codebase that
combines an M7 walk with M8's `attest()`, and the thing this design extends — has
**no `on_completion` guard**. Measured live this pass:

> `AnchorReceiptProbe`: `UpdateApplication` with an always-approve program
> **ACCEPTED** (app 108110). `Mpt7ReceiptApp`: rejected —
> `assert failed pc=38, opcodes=txn OnCompletion; !; assert`.

Every other bench app in this repo (`contracts/mpt/bench_app.py:362`,
`contracts/composer/bench_app.py:422`, `contracts/receipt/bench_app.py:146`) has
this guard. `AnchorReceiptProbe` is the single omission. This is **not** a
hypothetical: `relayer/client.py::_deploy_anchor_receipt_probe` deploys a fresh
probe in one transaction and then submits the proof group in a *separate*
transaction, so on mainnet there is a real inter-transaction window in which any
observer can `UpdateApplication` the probe into a program that logs an arbitrary
220-byte `MODE_AGAINST_ANCHOR` payload — which `m7_receipt.decode_against_anchor`
would accept as a proven Ethereum fact. **This affects the shipped T1
against-anchor path today, on mainnet, not just the T2 path this document
proposes.** §5.1 has the full trace and the one-line fix.

**Implementation size**: comparable to `AnchorReceiptProbe`'s own construction,
which landed as one class inside M8's single implementation commit (`35f64e6`).
Contract: three mode branches copied verbatim from `Mpt7ReceiptApp` plus the
one-line on-completion guard. Relayer: one `if tier == "T2"` branch in
`_submit_receipt_against_anchor`, reusing `plan_receipt_calls_t2` unchanged.
Deploy: one manifest entry and one declared float. The real work is the promotion
decision in §4.1 and the test matrix in §10, not the code.

---

## 1. Scope, non-goals, trust preconditions

### 1.1 In scope

1. A **deployable** contract combining M7's T1 **and T2** receipt walk with M8's
   `mpt7_result_against_anchor`, replacing the test-only, compiled-per-call
   `AnchorReceiptProbe`.
2. The **transaction-group layout** for a T2-against-anchor proof, and the proof
   that it is one atomic group at the worst case.
3. The **budget, box-reference, MBR and fee arithmetic**, measured.
4. The relayer change that removes `TierUnsupported` for
   `against_anchor=True, tier="T2"`.
5. Two **real defects in shipped code** found while verifying the above (§5).

### 1.2 Non-goals (explicit)

* **T3.** Leaves > 4,096 B stay out of scope, for the reason 007 §2.2 already
  closed with literal error strings: `box_extract` caps at 4,096 B and there is
  no way to get a larger object into `keccak256`'s one argument. T1+T2 = 97.5 %
  of real receipts (012 §N-4, 94,667 real receipts). This document does not
  reopen it.
* **A sender allowlist.** Today's T2 staging calls are keyed only by box name and
  have no ownership gate, and this design keeps it that way (§7.1 argues why that
  is *correct*, not merely inherited).
* **A general box sweeper.** 007 §8.4 flags one for M10; §5.2's mitigation makes
  it unnecessary for *this* path, and this document does not build one.
* **Changing M8.** `attest()` is untouched. Measured cost inside the combined
  group: **64 opcodes** (§3.2) — it is not the problem and it is not on the
  critical path.
* **Changing `contracts/receipt/*.py`.** Same discipline `AnchorReceiptProbe`
  already established: M7's subroutines are *imported*, never edited.

### 1.3 Trust preconditions

Unchanged from 008 §1.3 and inherited whole. One addition specific to this
document, which is the whole of §5.1:

> **The consumer must be sure the app that produced the `MODE_AGAINST_ANCHOR`
> log is the program it thinks it is.** M8's `ANCHOR_APP_ID` compile-time
> constant (TP-M8-4) guarantees the *anchor* side of the hand-off. Nothing
> today guarantees the *verifier* side, because the verifier is an app deployed
> minutes ago by the relayer itself and is updatable by anyone.

---

## 2. What exists today — measured

Every row re-derived this pass, not cited.

| Component | File | State today | Measured |
|---|---|---|---|
| T1 raw-arg walk | `contracts/receipt/bench_app.py` `MODE_INIT`/`MODE_NEXT` | live, mainnet | `Mpt7ReceiptApp` = **3,108 B** compiled |
| T2 box staging | `contracts/receipt/box.py` `mpt7_stage_open/write/read/close` | live, mainnet | staging calls cost **44–51** opcodes each — effectively free |
| T2 driver | `relayer/drivers/m7_receipt.py::plan_receipt_calls_t2` | live | 4,096 B leaf ⇒ **3** `MODE_STAGE_WRITE` calls at 1,900 B chunks |
| M8 read | `contracts/state_anchor/anchor_app.py::attest` | live, mainnet app `3670310865`, `ring_n=128` | **64** opcodes inside a real combined group |
| M7↔M8 hand-off | `contracts/state_anchor/handoff.py::mpt7_result_against_anchor` | live | the `MODE_AGAINST_ANCHOR` check costs **205** opcodes |
| Combined app | `contracts/state_anchor/bench_app.py::AnchorReceiptProbe` | **test-only**, compiled+deployed per call | **3,208 B** compiled; `MODE_INIT`/`MODE_NEXT`/`MODE_AGAINST_ANCHOR` only |
| T2 + anchor | — | **does not exist** | `relayer/client.py:299` raises `TierUnsupported` |
| Declared T2 float | `deploy/manifests/mainnet-v1.0.json` | live | `m7.t2_float_microalgo = 1744100` |

Two facts from this table do most of the work below and are worth stating
separately, because both contradict a plausible prior:

* **Box staging is nearly free in opcodes.** `MODE_STAGE_OPEN` = 44–51,
  `MODE_STAGE_WRITE` = 40–47 each. The 4,096 bytes never touch the opcode budget
  on the way in; they only cost box *I/O budget* (§3.3), and `keccak256` is flat
  at 130 regardless of input size (007 §2.2's own measurement, re-confirmed here
  by the leaf-size-independence of the walk cost in §3.2's table).
* **`attest()` is not the expensive part of M8.** The 3,837-opcode figure carried
  into this pass from the live session belongs to `anchor_direct` — the SSZ fold
  that *writes* an anchor. Reading one back via `attest()` is a ring-box read and
  a block-number compare: **64**. Nothing in this design needs to budget for M8.

---

## 3. The claim under test, stress-tested

This pass was asked not to accept the casual framing but to break it. Each
subsection states the claim, then what was actually measured.

### 3.1 Atomicity — the claim is true but is the wrong design. Corrected.

**Claim as floated**: *staging need not be one atomic group; only the final
close+verify must be.*

**Verdict: technically true, practically wrong, and adopting it would be a
regression.** Three independent reasons, two of them measured:

1. **It is unnecessary.** The whole thing fits in one group at the worst case.
   Measured (§3.2): **10 transactions**, of which 5 are the staging sequence, at a
   4,096 B leaf. The 16-transaction group cap is never approached, and 009 §9.2's
   existing claim — "M7's T2 path … creates a staging box and closes it in the
   same group, so an aborted group leaves no box and no MBR stranded" — carries
   over to the anchored path unchanged. The premise that staging is "already
   multi-group today" is simply **false**: `contracts/receipt/box.py`'s own
   docstring says *"entirely inside that one group (no persistent state, no
   cross-group session)"*, and `relayer/client.py::_submit_t2_receipt` builds
   exactly one `AtomicTransactionComposer`.

2. **It strands real money.** Measured this pass: a group that runs
   `MODE_STAGE_OPEN` and stops commits successfully, the box survives, and the
   app account's minimum balance rises by **1,643,300 µALGO** and stays there:

   > `after a stage_open-only group: box persists=True min_balance 100000 ->
   > 1743300 (delta 1643300, real MBR 1643300)`

   A bare `Contract` has no withdrawal path, so that MBR is recoverable only by a
   later group that deletes the same box — which is exactly a box sweeper, i.e.
   new machinery invented to clean up after a design choice that bought nothing.

3. **It opens a griefing vector the single-group design does not have.** With
   boxes that persist between groups, an unrelated party can pre-create a box
   under the deterministically-derived name at the wrong size and every honest
   proof using that name fails hard. Measured (§5.2):
   `box size mismatch 2000 4094`.

**Adopted rule (normative): the entire T2-against-anchor proof — `attest`,
`MODE_INIT[/MODE_NEXT]`, `MODE_STAGE_OPEN`, every `MODE_STAGE_WRITE`,
`MODE_STAGE_WALK`, `MODE_AGAINST_ANCHOR` — is ONE atomic transaction group. The
box is created and deleted inside it. No design in this project may split it
without first exhausting the 16-transaction cap, which §3.2 shows is not close.**

### 3.2 Opcode budget and donors — measured, and cheaper than the T1 path

The AVM pools opcode budget across every *application* call in a group (not
payments — 007's own finding, recorded in `ROADMAP.md`'s M7 row), at 700 per app
call, plus ~682 net per `DonorIssuer` inner call (`relayer/group/budget.py`).

**Method**: a T2-capable copy of `AnchorReceiptProbe` (the three stage modes from
`Mpt7ReceiptApp`, copied verbatim; see §4.3 for the exact diff) compiled with
`puyapy` against a throwaway tree with `handoff.ANCHOR_APP_ID` patched to a real
deployed `TrustedRootAnchor`, deployed to dev-mode algod, and driven with real
RLP/keccak receipt tries whose leaf node lands at exactly the 4,096 B ceiling. The
`receiptsRoot` of each synthetic trie was **really anchored** through
`anchor_direct` first, so `attest()` in the proof group returns a genuinely
on-chain record. Every group below was `simulate`d and then **submitted for
real**.

**Group `app-budget-consumed`, T2 against anchor** (10 txns, 9 app calls, base
budget `700 × 9 = 6,300`):

| leaf node | n_logs | group consumed | headroom on base alone |
|---:|---:|---:|---:|
| 4,096 B | 2 | **4,006** | +2,294 |
| 4,086 B | 16 | **4,776** | +1,524 |
| 4,094 B | 24 | **5,186** | +1,114 |
| 4,094 B | 24 (donor n=4) | **5,237** | +1,063 |

**Per-transaction breakdown** (4,094 B leaf, 24 logs — the worst case):

| # | transaction | consumed |
|---:|---|---:|
| 0 | `DonorIssuer` | 31 |
| 1 | `PaymentTxn` (box MBR) | 0 (not an app call) |
| 2 | **`attest(block_number)`** | **64** |
| 3 | `MODE_INIT` (branch nodes) | 1,278 |
| 4 | `MODE_STAGE_OPEN` | 44 |
| 5–7 | `MODE_STAGE_WRITE` × 3 | 40 each |
| 8 | **`MODE_STAGE_WALK`** (box read + keccak + walk + decode) | **3,444** |
| 9 | **`MODE_AGAINST_ANCHOR`** | **205** |

**Three findings this changes:**

1. **The group needs no donor transaction at all.** Measured, and confirmed by a
   real submission:

   > `with_donor=False n_donors=0: txns=9 appl=8 base=5600 consumed=5155 fail=''`
   > `REAL SEND with NO donor transaction at all: OK round=5073 R_INCLUDED`

   Nine app calls carry 6,300 of pooled budget; the proof consumes ≤ 5,237. The
   T2 staging transactions are not overhead — each one *pays for itself and
   more*, contributing 700 to the pool while consuming ~40. **A T2 proof is
   budget-easier than a T1 proof**, which has fewer app calls to pool from
   (measured T1-against-anchor: 5 txns, 5 app calls, base 3,500, consumed
   **3,846** — genuinely short, and the only one of the two that *needs* donors).

   The implementation should nevertheless keep one `DonorIssuer` with
   `relayer.group.budget.size_donors`' standard `margin=4`, unchanged: at 8 app
   calls the no-donor margin is 445 opcodes (8 %), which is not a margin this
   project's own conventions accept, and `submit_run`'s sizing loop already
   produces `n_donors=4` for free from the floor.

2. **Cost scales with `n_logs`, not with leaf size.** 4,006 → 5,186 across 2 → 24
   logs at a constant ~4,096 B leaf: ≈ **+51 opcodes per log**, consistent with
   M2's measured ~30–35/item RLP scan cost plus the logs-table write. The 4,096
   bytes themselves are free — `keccak256` is flat and `box_extract` is one op.
   **`MAX_LOGS_T1T2 = 64` (`contracts/receipt/decode.py:48`) is therefore the
   real cost ceiling, not the byte cap**: projected at 64 logs,
   `5,186 + 40 × 51 ≈ 7,226`, which exceeds the 6,300 base and *would* need
   donors. A 64-log receipt cannot fit in 4,096 B (measured: 32 zero-data logs
   already encode to 4,270 B > 4,096), so this ceiling is unreachable in T2 —
   but the implementation must not hardcode "no donors needed", and
   `size_donors` already prevents that.

3. **Trie depth does not matter.** Receipts-trie keys are `rlp(tx_index)`, so a
   path is at most 6 branch levels plus the leaf. Measured across blocks of 16,
   300 and 1,500 transactions, the path was 3 nodes each time and the group
   stayed at 10 transactions / 6,300 base / 5,237 consumed. **Projected** absolute
   worst case (a 6-nibble key with six ~532 B branch nodes ⇒ two `MODE_INIT`/
   `MODE_NEXT` calls): 11 transactions, base 7,000. Still not close to 16.

### 3.3 Box references and box I/O budget — never binding

Two independent caps (both measured earlier in this project, both re-confirmed
here):

* **8 box references per transaction** — structural.
* **2,048 bytes of I/O budget per box reference, pooled across the group**,
  charged at a box's **full declared size once per box per group**, with
  **separate pools for reads and writes** (007 §2.3, which measured a 4,096 B box
  at a minimum of **2** references).

Measured this pass, with `allow_unnamed_resources=False` (i.e. the real
submission path, not simulate's auto-fill):

| references per box-touching transaction | result |
|---:|---|
| 0 | `logic eval error: invalid Box reference 0x7432000000070000` |
| 1 | **OK**, consumed 5,237 |
| 2 | OK |
| 3 | OK |

**Conclusion: the byte budget is never the binding constraint here.** Box
references are a *legality* requirement first — every transaction that touches a
box must name it — and this group has 5 box-touching transactions
(`STAGE_OPEN`, 3 × `STAGE_WRITE`, `STAGE_WALK`), so it carries **5 references**
whether or not it wants them. Five references buy 10,240 bytes of pooled budget
against a 4,096-byte charge: 2.5× headroom, arrived at for free. The
8-per-transaction cap is not approached at 1 reference per transaction, and
`plan_box_refs`' minimum of 2 for a 4,096 B box is satisfied 2.5× over.

**M8's own reference cost is separate and additive**: `attest` names `h:<residue>`
(and, on the pinned path, `p:<block>`) on its *own* transaction — 1–2 references
there. No interaction.

**Box-reference legality — the question this pass was asked to settle
explicitly.** The factory-contract wall recorded in `ROADMAP.md`'s M4 row is
*"box references cannot name an app that does not exist yet within the same
execution"*. **This design does not have that shape.** The staging box is owned by
the combined verifier app, which is created in an **earlier, already-confirmed
transaction** — a separate deployment today, and a permanent manifest entry under
§4.1's recommendation. Its app id is known at group-construction time and is
named in the ordinary way (`BoxReference(0, name)` = "the app this transaction
calls"). Measured: every group above committed with explicit, non-unnamed box
references. **The earlier wall is not a precedent that applies here, and this
design must not be read as re-litigating it.**

> **Note for the record**: the factory-contract postmortem is **not committed to
> any design document**. It exists only as prose in `ROADMAP.md`'s M4 row
> (searched: `docs/design/*.md` contains no "factory" discussion; 013 §0
> mentions the wall in two sentences without the reproduction). If that
> postmortem matters — and it cost 40+ failed mainnet creates and ~0.67 ALGO —
> it deserves its own document. Flagged, not fixed here.

### 3.4 What is actually verified, and where the trust boundary sits

Unchanged from the T1 path, and worth restating because the box makes people
nervous:

`mpt7_stage_write` has no integrity check and needs none. The staged bytes are
inert until `MODE_STAGE_WALK` calls `mpt_walk_node(node, w)`, whose `W11` check is
`keccak256(node) == w.expected` — where `w.expected` chains back, hop by hop, to
the `receipts_root` that `MODE_INIT` was initialised with. And under
`MODE_AGAINST_ANCHOR`, that root is not a caller argument at all:
`mpt7_result_against_anchor` derives it from `anchor_receipts_root(a)`, where `a`
comes from `anchor_from_group(anchor_gi, want_block_number)`, which asserts
`prev.app_id == ANCHOR_APP_ID` — a compile-time constant (TP-M8-4). **There is no
parameter anywhere in the chain by which a relayer can substitute a root.**
Writing wrong bytes into your own box produces a wrong keccak and the group
fails. This is exactly 007 TP-M7-4, unchanged; the box tier adds no new trusted
input.

The one link this argument *assumes* — that the app running this logic is the
compiled program you audited — is the one §5.1 shows is currently broken.

### 3.5 The race — structurally impossible, and measured anyway

**Question**: can M8's ring rotate between the start of staging and the
close+verify, leaving a stale root in play?

**Answer: no, twice over.**

1. **There is no window.** Under §3.1's adopted single-group rule, `attest()` and
   `MODE_STAGE_WALK` execute in the same atomic group, microseconds and zero
   rounds apart. The question the T1 path never had to ask, this design never has
   to ask either — deliberately.

2. **Even in a hypothetical split design, it fails closed, never open.** The
   `receiptsRoot` used by the check is read *at check time* from that group's own
   `attest()` log; no earlier-committed value survives. If the anchor has been
   evicted, `attest()` itself aborts and takes the group with it. Measured
   (ring_n = 8 in the test fixture, then 8 further blocks anchored to force
   eviction):

   > simulate: `logic eval error: assert failed pc=2636 … app=<anchor app>`
   > (M8's `N12`)
   > real send: rejected
   > `box exists after aborted group? False`
   > `probe app account after abort: {'amount': 1843300, 'min-balance': 100000}`

   Nothing committed, nothing stranded, no stale root accepted.

**The real, non-security consequence of eviction is liveness, and it is sized**:
mainnet `ring_n = 128` (`deploy/manifests/mainnet-v1.0.json`), so an anchored EL
block stays attestable for 128 subsequent anchored blocks. At Ethereum's ~12 s
slot time that is a floor of ~25 minutes if every block is anchored, and much
longer in practice since anchoring is on demand. A single group is submitted and
confirmed in one Algorand round. **The margin is four orders of magnitude.** For
callers that need more, 008 §7.5's pinned tier already exists and `attest()`
already falls back to it.

### 3.6 MBR and the aborted case — measured, with a real cost finding

Box MBR is `2,500 + 400 × (len(name) + size)`, charged to the **app account**.
Measured exactly, twice:

| leaf | formula | measured `min-balance` delta |
|---:|---|---:|
| 4,094 B | `2500 + 400 × (8 + 4094)` = 1,643,300 | **1,643,300** |
| 4,096 B | `2500 + 400 × (8 + 4096)` = 1,644,100 | — (payment sized to this) |

**In the aborted case, nothing is stranded** — measured in §3.5's eviction run:
the group is rejected whole, the box never exists, and the app account balance is
unchanged. This is 009 §9.2's property, and combining with `attest()` does not
weaken it: `attest()` is *earlier* in the group than `MODE_STAGE_OPEN`, so an
anchor failure aborts before a box is even created; and an `MODE_AGAINST_ANCHOR`
failure *after* the box is closed still reverts the whole group, box creation
included.

**The real finding is on the success path, and it is a live inefficiency in
shipped code.** The box's MBR requirement is released by `mpt7_stage_close`, but
the µALGO paid to the app account **stays there** — a bare `Contract` has no
withdrawal path. Measured across three consecutive successful T2-against-anchor
proofs against the same app:

> `probe app account: amount=1844100 min_balance=100000`
> `probe app account: amount=3684200 min_balance=100000`
> `probe app account: amount=5527500 min_balance=100000`

The app account accumulated 5.53 ALGO across three proofs while its actual
requirement returned to 100,000 µALGO every time.

**This is already solved in the deployment model and simply not used by the
driver.** `deploy/manifests/mainnet-v1.0.json` declares
`m7.t2_float_microalgo = 1744100` — a *one-time* float, sized at the 4,096 B
worst case plus the account minimum. Measured: with the float already in place,
the per-call payment is unnecessary:

> `fund=0 (app account already holds a float): consumed=5237 fail=''`

**Normative for this design**: the combined app carries a declared T2 float in the
manifest, funded once at deploy time, and the group's `PaymentTxn` is
**conditional** — sent only when a real `account_info` read shows the app account
short of `2500 + 400 × (8 + leaf_len) + 100_000`. §5.3 records that
`_submit_t2_receipt` should be fixed the same way; it is the same bug on the
non-anchored path.

---

## 4. The proposed mechanism

### 4.1 One contract, deployed once — not a probe compiled per call

`relayer/client.py::_deploy_anchor_receipt_probe` compiles `AnchorReceiptProbe`
with `puyapy` and deploys a **fresh app on every `prove_receipt(against_anchor=
True)` call**. For T1 that is merely wasteful (0.1 ALGO of app MBR abandoned per
call, plus a ~3.4 s compile). For T2 it is **untenable**: each call would also
abandon the 1.64 ALGO box float in a throwaway app account with no withdrawal
path — **≈ 1.74 ALGO burned per proof**, against 0.014 ALGO of fees.

It is also the mechanism that makes §5.1's hijack window exist at all.

**Recommendation (the one real decision in this document): promote the combined
app to a first-class, deployed, manifest-pinned contract.**

| | per-call probe (today) | deployed contract (proposed) |
|---|---|---|
| `ANCHOR_APP_ID` binding | patched at compile time, per call | patched at build time, pinned by approval-program SHA-256 in the manifest |
| Cost per T2 proof | ≈ 1.74 ALGO abandoned | 0.014 ALGO of fees |
| Latency per proof | + ~3.4 s `puyapy` compile + 1 deploy round | none |
| Hijack window (§5.1) | real, per call | none — deployed once, guarded, hash-verified by `deploy verify` |
| Wheel-only installs | `MissingContractsSource` (needs a source checkout + `puyapy`) | works — no compiler needed at call time |

The new contract is `contracts/receipt/anchored_app.py::Mpt7AnchoredReceiptApp` —
in `contracts/receipt/`, not `contracts/state_anchor/`, because it *is* an M7
verifier that happens to import one M8 helper, and because leaving it inside a
file whose module docstring says **"NEVER deploy to mainnet"** is precisely how a
never-deploy artefact gets deployed.

`AnchorReceiptProbe` stays exactly where it is, unchanged except for §5.1's
guard, and keeps doing its job: proving TP-M8-4 against `FakeAnchor` in
`tests/state_anchor/test_core.py`.

### 4.2 Entrypoints — no new primitives

Six modes, of which **five are copied verbatim** from already-live code and one
already exists in `AnchorReceiptProbe`:

| mode | source | new? |
|---:|---|---|
| 0 `MODE_INIT` | `AnchorReceiptProbe` | no |
| 1 `MODE_NEXT` | `AnchorReceiptProbe` | no |
| 2 `MODE_STAGE_OPEN` | `Mpt7ReceiptApp` | copied |
| 3 `MODE_STAGE_WRITE` | `Mpt7ReceiptApp` | copied |
| 4 `MODE_STAGE_WALK` | `Mpt7ReceiptApp` | copied |
| 5 `MODE_AGAINST_ANCHOR` | `AnchorReceiptProbe` | no |

Mode numbers are deliberately identical to `Mpt7ReceiptApp`'s so the two contracts
never diverge and `relayer/drivers/m7_receipt.py`'s existing arg builders work
against both **unchanged**. The wire format is `Mpt7ReceiptApp`'s exactly:
`[b"RCP1", mode(1B), prev_gi(1B or 8B), fixed, …]`.

`MODE_STAGE_WALK`'s `prev_gi` recovers `(W, R)` from whichever earlier transaction
produced it (`MODE_INIT` or the last `MODE_NEXT`) via `mpt7_state_from_prev`,
whose `prev.app_id == Global.current_application_id` assert is satisfied by
construction because the walk and the anchor check are modes of the same app —
the identical argument `AnchorReceiptProbe`'s own docstring makes for T1.

### 4.3 The contract diff, compiled and measured

Exactly three insertions into `AnchorReceiptProbe`'s structure, plus §5.1's
guard. Measured: compiles clean with `puyapy` in **3.3 s**; **3,208 B → 3,311 B
(+103 B)**; still one extra program page.

```python
# imports
from contracts.receipt.box import (
    mpt7_stage_close, mpt7_stage_open, mpt7_stage_read, mpt7_stage_write,
)

MODE_STAGE_OPEN = 2
MODE_STAGE_WRITE = 3
MODE_STAGE_WALK = 4

# ... inserted between MODE_NEXT and the MODE_AGAINST_ANCHOR tail:
if mode == MODE_STAGE_OPEN:
    fixed = Txn.application_args(3)
    assert fixed.length == UInt64(10), "L20"
    mpt7_stage_open(op.extract(fixed, UInt64(0), UInt64(8)),
                    op.extract_uint16(fixed, UInt64(8)))
    return True

if mode == MODE_STAGE_WRITE:
    fixed = Txn.application_args(3)
    assert fixed.length == UInt64(10), "L20"
    mpt7_stage_write(op.extract(fixed, UInt64(0), UInt64(8)),
                     op.extract_uint16(fixed, UInt64(8)),
                     Txn.application_args(4))
    return True

if mode == MODE_STAGE_WALK:
    fixed = Txn.application_args(3)
    assert fixed.length == UInt64(10), "L20"
    name = op.extract(fixed, UInt64(0), UInt64(8))
    leaf_len = op.extract_uint16(fixed, UInt64(8))
    w, r = mpt7_state_from_prev(prev_gi)
    node = mpt7_stage_read(name, leaf_len)
    w2, voff, vlen = mpt_walk_node(node, w)
    r2 = _finalize_if_terminal_probe(w2, r, node, voff, vlen)
    mpt7_stage_close(name)
    log(mpt7_log_state(w2, r2))
    return True
```

Two deliberate differences from a naive copy, both normative:

* **`assert r_rstatus(r) == R_INCOMPLETE, "L22"` is present in `Mpt7ReceiptApp`'s
  `MODE_STAGE_WALK` and absent from `AnchorReceiptProbe`'s `MODE_NEXT`.** Carry
  it. It costs ~4 opcodes and rejects a group that tries to walk past an
  already-terminal state.
* **`mpt7_stage_open` must tolerate a squatted box** — §5.2.

### 4.4 The group layout

```
gi  txn                                   app          notes
--  ------------------------------------  -----------  ------------------------------
 0  DonorIssuer(n=4)                       donor        margin only; measured unnecessary
 1  PaymentTxn -> app account              —            CONDITIONAL (§3.6); 0 when floated
 2  attest(block_number)                   M8           boxes: h:<residue> [, p:<block>]
 3  MODE_INIT      + branch nodes          verifier
(4) MODE_NEXT      + branch nodes          verifier     only if branch nodes > 2,000 B
 4  MODE_STAGE_OPEN  name || leaf_len      verifier     box: <name>
5-7 MODE_STAGE_WRITE name || off, chunk     verifier     box: <name>; 1,900 B chunks
 8  MODE_STAGE_WALK  name || leaf_len       verifier     box: <name>; prev_gi = 3 (or 4)
 9  MODE_AGAINST_ANCHOR                     verifier     prev_gi = 8, anchor_gi = 2
```

**10 transactions, measured; 11 in the projected deepest-trie case.** Compare
`AnchorReceiptProbe`'s existing T1 layout — `[DonorIssuer, attest, MODE_INIT
(+MODE_NEXT), MODE_AGAINST_ANCHOR]` — which is the same shape with the five
staging transactions spliced in between the walk and the check. `anchor_gi` and
`prev_gi` are absolute group indices, so `plan_receipt_calls_t2`'s existing
`group_offset` parameter (added for exactly this reason) is passed
`3` instead of T1's `2`.

### 4.5 Client change

`relayer/client.py::prove_receipt` loses the `TierUnsupported` raise at line 299;
`_submit_receipt_against_anchor` gains a `tier` branch that calls
`m7.plan_receipt_calls_t2(...)` instead of `plan_receipt_calls(...)`, prepends the
conditional payment, and shifts `group_offset`. `m7.build_against_anchor_check_args`
and `m7.decode_against_anchor` are unchanged. **No new module, no new driver, no
new planner.**

---

## 5. Real defects in shipped code, found while verifying the above

### 5.1 BLOCKER — `AnchorReceiptProbe` is updatable and deletable by anyone

**Measured, live, this pass:**

```
AnchorReceiptProbe: UpdateApplication with an always-approve program ACCEPTED (app 108110)
AnchorReceiptProbe: DeleteApplication ACCEPTED
Mpt7ReceiptApp:     UpdateApplication rejected:
                    logic eval error: assert failed pc=38, opcodes=txn OnCompletion; !; assert
```

**Cause.** `AnchorReceiptProbe.approval_program` opens with

```python
if Txn.application_id.id == UInt64(0):
    return True
if Txn.num_app_args == UInt64(0):
    return True
```

and never checks `Txn.on_completion`. A zero-argument `UpdateApplication` takes
the second branch and returns `True`. Every other bench app in this repo has the
guard — `contracts/mpt/bench_app.py:362` (`"V1"`),
`contracts/composer/bench_app.py:422` (`"D0"`),
`contracts/receipt/bench_app.py:146` (`"L1"`). This is one omission, not a
pattern.

**Why it is live and not theoretical.** `_deploy_anchor_receipt_probe` deploys the
probe in transaction A and `_submit_receipt_against_anchor` submits the proof
group in transaction B, separately. Between A and B — a real, public, observable
window of at least one mainnet round — an attacker can `UpdateApplication` the
probe to a program that emits an arbitrary 220-byte
`0x151f7c75 || rstatus || address || …` log. `m7_receipt.decode_against_anchor`
validates the prefix and the length and nothing else, so the caller receives a
fabricated Ethereum log as a proven fact. **Every protection in the chain — the
BLS verification, the SSZ folds, `ANCHOR_APP_ID`'s compile-time constant, the
keccak hash chain — is bypassed, because none of them is running.**

**Fix, one line**, and it belongs in `AnchorReceiptProbe` *today*, independent of
whether this design is approved:

```python
assert Txn.on_completion == OnCompleteAction.NoOp, "L1"
```

For §4.1's promoted contract the same line is mandatory, and a deployed contract
additionally gets `deploy verify`'s approval-program SHA-256 pin, which is the
structural version of the same guarantee.

**This is a blocker in the sense the human asked about**: not a reason the design
cannot be built, but a defect that must be fixed *before* anything is deployed
under this design, and which should be fixed on the T1 path regardless.

### 5.2 Permissionless box-name squatting

`mpt7_stage_open` calls `op.Box.create(name, leaf_len)` and **discards the return
value**. The AVM's rule is that `box_create` on an existing box of the *same* size
is a no-op returning `False`, and on an existing box of a *different* size it
**fails**. Since `MODE_STAGE_OPEN` has no sender gate (correctly — see §7.1) and
`relayer/drivers/m7_receipt.py` derives the name deterministically as
`b"t2" || tx_index(4) || log_index(2)`, anyone can pre-create that exact box at
the wrong size. Measured:

```
squatted a 2000 B box under the driver's own derived name
honest T2-against-anchor group: logic eval error: box size mismatch 2000 4094
```

**Severity, honestly stated.** Under the single-group rule this is *hard to
exploit and self-limiting*: the squatter must pay ~0.8 ALGO of MBR into the
victim app's account with no way to get it back, and the name space is only 48
bits of `(tx_index, log_index)` with no block component — so the same names recur
across blocks and the grief is durable once paid. Under a multi-group staging
design (§3.1) it becomes cheap and routine. It also already applies to the
deployed mainnet M7 app `3665914633`.

**Two mitigations, both cheap; the design adopts both:**

1. **On-chain**: `mpt7_stage_open` deletes any pre-existing box before creating
   (`op.Box.delete(name)` — a no-op if absent — then `op.Box.create`). This is
   safe precisely because box contents are never trusted (§3.4), and it *reclaims*
   the squatter's MBR to the app account, making the grief self-funding for the
   defender. Under the single-group rule no honest box ever exists between
   groups, so nothing legitimate can be destroyed.
2. **Off-chain**: the driver derives the name with a block component and a random
   nonce (`b"t2" || block(4) || nonce(2)`), which keeps the 8-byte width
   `MODE_STAGE_OPEN` asserts and makes pre-computation impossible.

### 5.3 The T2 payment is unconditional and the float is unused

Covered in §3.6. `_submit_t2_receipt` sends a full `2500 + 400 × (8 + leaf) +
200_000` payment on **every** call to an app that the manifest already declares a
`t2_float_microalgo` for. Measured: with the float in place a `fund=0` group
simulates clean. The fix is a balance check before the payment, on both the
anchored and non-anchored paths.

---

## 6. Cost

Fees at the 1,000 µALGO minimum. All **measured** except where marked.

| Operation | Group | Fee (µALGO) |
|---|---|---:|
| M7 T1 + anchor (today, 009 §12) | `[DonorIssuer(6), attest, MODE_INIT, MODE_AGAINST_ANCHOR]` | 10,000 |
| M7 T1 + anchor (re-measured this pass) | 5 txns, `n_donors=5` | **10,000** |
| **M7 T2 + anchor (this design)** | 10 txns, `n_donors=4` | **14,000** |
| M7 T2 + anchor, no donor | 9 txns | **9,000** |

**One-time, per deployed verifier app:**

| Item | µALGO | Recoverable? |
|---|---:|---|
| App account minimum | 100,000 | on app deletion, no — but the app is permanent |
| T2 float, 4,096 B worst case | 1,644,100 | reusable indefinitely; not withdrawable from a bare `Contract` |
| **Declared total** | **1,744,100** | matches `m7.t2_float_microalgo` exactly |

**The number that should drive the decision**: with §4.1's promotion, a T2
against-anchor proof costs **0.014 ALGO** and reuses a 1.74 ALGO float forever.
Without it — i.e. keeping the compile-and-deploy-a-probe-per-call architecture —
it costs **≈ 1.754 ALGO per proof**, 125× more, all of it abandoned.

**What this document cannot cost, honestly.** The live 2026-08-11 end-to-end run
recorded `prove_receipt(against_anchor=True)` at 15.7 s wall-clock and the whole
chain at ~22.5 ALGO, but **no per-call opcode or µALGO figure for that
`prove_receipt` was recorded anywhere in the repo** — `grep` for `3790`/`3837`
across `*.py` and `*.md` returns only unrelated round numbers, and
`SubmitResult.measured_consumed` is populated by `relayer/group/submit.py` and
then discarded by `_submit_receipt_against_anchor`, which never puts it in the
returned `ReceiptResult.fields`. The T1 figures in this document are therefore
**this pass's own dev-mode measurements** (3,846 consumed, 10,000 µALGO), not a
mainnet reading. **G7-014 requires the implementation pass to persist
`measured_consumed` into `ReceiptResult.fields` so this gap closes permanently
rather than being re-measured by hand every time.**

---

## 7. Adversarial notes

### 7.1 Why permissionless staging is correct, not merely inherited

A sender allowlist on `MODE_STAGE_OPEN`/`WRITE` would buy nothing and cost the
property the project exists for. The box's contents are validated by
`keccak256(node) == w.expected` inside the same group; a hostile writer produces a
wrong hash and the group dies. Gating *who may write* would therefore protect
nothing, while making the verifier permissioned — the opposite of "anyone can
prove an Ethereum fact on Algorand". §5.2's squatting vector is a *denial* attack
on a name, not a soundness attack on a proof, and is answered by name derivation
and delete-before-create rather than by an allowlist.

### 7.2 What an untrusted relayer can still do

Unchanged from 009 §11 and 007 §5.4: it can pick which receipt to prove, refuse to
prove, or produce a group that fails. It cannot make a false receipt fact appear
true, because it controls no input on the trusted path — the root comes from
`attest()` under a compile-time-constant app id, the hash chain is the AVM's, and
`R_ABSENT`/`R_NO_SUCH_LOG`/`R_ZERO_LOGS` are *verdicts delivered by a successful
transaction*, never failures (007 §5.4). Adding the box tier does not add a
trusted input.

### 7.3 Cross-group interference

Two honest relayers proving different receipts concurrently collide only if they
derive the same 8-byte box name. §5.2's nonce removes the collision; even without
it, one of the two groups simply fails and can be retried, since nothing is
committed.

---

## 8. Alternatives considered and rejected

| Alternative | Why rejected |
|---|---|
| **Multi-group staging** (the framing this pass was asked to test) | Unnecessary (10 txns of 16 used), strands 1.64 ALGO per abandoned box (measured), and makes §5.2 cheap. §3.1. |
| **Extend `AnchorReceiptProbe` in place and keep the per-call deploy** | Works — it is literally what was measured — but costs ≈ 1.74 ALGO per proof and keeps §5.1's hijack window open. §4.1. |
| **Add `MODE_AGAINST_ANCHOR` to `Mpt7ReceiptApp` instead** | Would put a compile-time `ANCHOR_APP_ID` into the general-purpose M7 app, coupling every M7 deployment to one M8 instance. 008 §8.6 already rejected co-deployment for this reason. |
| **Inner-call `get_anchor` instead of the group log-chain** | 008 §8.4's secondary path; adds an inner call against the 256-per-group ceiling and buys nothing here, since `attest` in the group costs 64 opcodes and one transaction slot. |
| **Raise `MAX_LOGS_T1T2` above 64** | Not reachable in T2 (measured: 32 zero-data logs already exceed 4,096 B). Nothing to gain. |

---

## 9. Files that change

**Contracts (2)**
* `contracts/receipt/anchored_app.py` — **new**, `Mpt7AnchoredReceiptApp` (§4.2/§4.3).
* `contracts/receipt/box.py` — `mpt7_stage_open` deletes before creating (§5.2).
* `contracts/state_anchor/bench_app.py` — **one line**, §5.1's guard on
  `AnchorReceiptProbe`. No other change; it stays test-only.

**Relayer (2)**
* `relayer/client.py` — remove the T2 `TierUnsupported`; T2 branch in
  `_submit_receipt_against_anchor`; conditional payment on both T2 paths;
  persist `measured_consumed` into `ReceiptResult.fields`.
* `relayer/drivers/m7_receipt.py` — box-name derivation with block + nonce.
  `plan_receipt_calls_t2` itself is **unchanged**.

**Deploy (3)**
* `deploy/plans/` — a plan for the new app.
* `deploy/manifests/mainnet-v1.0.json` — new app entry with its own
  `t2_float_microalgo`.
* `deploy/schema/` — regenerate; the new app has no state and no schema, but the
  compiled cache and the approval-hash pin are what `deploy verify` reads.

**Tests** — §10.

**Docs (3)** — `ROADMAP.md` (§12), `ARCHITECTURE.md` (the app inventory),
`docs/security.md` (§5.1 and §5.2 are both disclosable findings about already-live
mainnet apps).

---

## 10. Test plan

| id | tier | statement |
|---|---|---|
| **A-1** | offline | `Mpt7AnchoredReceiptApp` compiles; committed artefact byte-identical to a fresh compile |
| **A-2** | offline | `plan_receipt_calls_t2(group_offset=3)` produces exactly the §4.4 layout; `prev_gi`/`anchor_gi` are absolute |
| **A-3** | offline | Box names for two different `(block, tx_index, log_index)` never collide across 10⁶ samples |
| **A-4** | live | Full T2-against-anchor group at a 4,096 B leaf: real submission, `R_INCLUDED`, log byte-identical to simulate |
| **A-5** | live | Same at 2, 16 and 24 logs; `app-budget-consumed` recorded for each |
| **A-6** | live | **Negative**: `attest` on an evicted block ⇒ group rejected, box absent, app balance unchanged |
| **A-7** | live | **Negative**: one staged chunk corrupted by one byte ⇒ `W11` rejects; group fails; nothing committed |
| **A-8** | live | **Negative**: `MODE_AGAINST_ANCHOR` pointed at a `FakeAnchor` ⇒ `N2` (TP-M8-4 still holds through the box tier) |
| **A-9** | live | **Negative**: `want_tx_index` ≠ the walked index ⇒ `L11` |
| **A-10** | live | **§5.1**: `UpdateApplication` and `DeleteApplication` against the deployed app are both **rejected** |
| **A-11** | live | **§5.2**: a squatted box at the wrong size does not break an honest proof (delete-before-create) |
| **A-12** | live | **§3.6**: with the float in place, a second proof sends **no** payment and the app balance is unchanged |
| **A-13** | live | `log_index >= n_logs` returns `R_NO_SUCH_LOG` as a **successful** transaction, through the box tier |
| **A-14** | live | A real mainnet T2 receipt (not synthetic) proven against a real M8 anchor, end to end |

A-4 through A-13 all ran in prototype form during this design pass, against
dev-mode algod, and passed. A-14 is the one that has not.

---

## 11. Acceptance gates

| Gate | Statement | How judged |
|---|---|---|
| **G1-014** | §5.1 is fixed: `AnchorReceiptProbe` **and** the new app reject every non-NoOp on-completion, proven by real rejected `UpdateApplication`/`DeleteApplication` transactions | A-10. **The gate everything else is behind.** Must land even if the rest of this design is deferred |
| **G2-014** | A real, non-simulated T2-against-anchor group commits at a 4,096 B leaf and returns `R_INCLUDED` against a genuinely on-chain M8 anchor | A-4. **Already measured passing** against a scratchpad build this pass (§3.2) — the gate is that it stays true for the real tree |
| **G3-014** | The proof is **one atomic group** — no code path anywhere splits staging across groups, and the group is ≤ 12 transactions at the deepest real trie | A-2, A-4 + a source grep for a second `AtomicTransactionComposer` on this path |
| **G4-014** | Every negative case rejects for the **right** reason, with the right code: `W11`, `N2`, `N12`, `L11`, `L22` | A-6…A-9 |
| **G5-014** | Nothing is stranded by a failed group: box absent and app balance unchanged after each negative case | A-6, A-7 |
| **G6-014** | The float model works: proof *n+1* sends no payment, and the app account never exceeds its declared `t2_float_microalgo` | A-12 |
| **G7-014** | Every cost claim traces to a real `app-budget-consumed` and a real fee total, and `measured_consumed` is persisted into `ReceiptResult.fields` so it never has to be re-measured by hand | §6, `ARCHITECTURE.md`'s standing rule |
| **G8-014** | `deploy verify` reports the new app `USABLE` with a hash-matched approval program on the target network | A-1 + `deploy verify` |
| **G9-014** | The pre-existing M7 and M8 live suites pass unchanged, and the T1 against-anchor path still works after §5.1's guard lands | full live re-run |
| **G10-014** | A real mainnet T2 receipt is proven end to end | A-14. **The headline gate.** **CLOSED, 2026-08-11**: `Mpt7AnchoredReceiptApp` deployed to real mainnet (app `3670553866`, bound to real M8 app `3670310865`, `deploy verify` reports `OK`). A real T2-tier receipt (block `25731394`, tx index `12`, `2,362` B leaf, a real USDC Transfer event) proved against a real on-chain M8 anchor in one atomic 9-transaction group: `R_INCLUDED`, confirmed round `63965073`, measured consumed `4,512`. Along the way, hit and root-caused a real staleness gap — `anchor_direct` failed deterministically (not intermittently) because M4's on-chain finalized checkpoint had fallen behind real current beacon finality; `sync(update=True)` before `anchor("latest")` resolved it, confirming the operational need for `/keeper/run` rather than exposing a defect in this design. `Mpt7ReceiptApp` itself remains un-redeployed; see `docs/security.md` and `ROADMAP.md`'s M13 row. |

---

## 12. How `ROADMAP.md` should record this

A new **M13** row (`T2 receipt proofs against an M8 anchor`), depending on M7,
M8, M9, M10, citing this document — plus a correction note on M7's and M9's own
rows recording §5.1 and §5.2 as **defects found in already-live code**, with the
mainnet app ids affected. §5.1 in particular should not be buried inside a new
module's row: it is a live security finding about the shipped T1 path.

---

## 13. Questions resolved, and what is handed on

**Resolved by this pass, with evidence:**

* *Does a T2 leaf plus an M8 anchor check fit in one atomic group?* **Yes** —
  measured, 10 transactions, submitted for real.
* *Does it need extended donor budget?* **No** — measured, a real send with zero
  donor transactions committed. The staging transactions are budget-positive.
* *Are box references or box I/O budget a constraint?* **No** — measured, 1
  reference per touching transaction suffices; the group carries 5 for free.
* *Is this the factory-contract box-reference wall again?* **No** — different
  shape; the box's owning app is created in an earlier confirmed transaction.
* *Can the anchor rotate under a staging window?* **The window does not exist**
  under the single-group rule; and in any split design it fails closed —
  measured (`N12`, nothing committed).
* *Who funds the box MBR, and is it recovered?* App account; the *requirement* is
  released on close but the *µALGO* stays, so it is a one-time float, not a
  per-call cost — measured, and already declared in the manifest.
* *Is `attest()` expensive?* **No** — 64 opcodes. The 3,837 figure is
  `anchor_direct`, a different method.
* *Is `AnchorReceiptProbe` safe to deploy?* **No** — measured hijackable (§5.1).

**Handed on to the implementation pass:**

* **The one number this design could not measure honestly**: the real *mainnet*
  cost of the existing T1 against-anchor proof. It was never recorded, and
  `measured_consumed` is discarded by the client. G7-014 fixes the plumbing;
  the first real mainnet T2 run should record both.
* **Projected, not measured**: the deepest-real-trie case (6-nibble key, two
  `MODE_NEXT` calls, 11 transactions, base 7,000). Every trie measured this pass
  was 3 nodes deep. A-4 should deliberately construct a deep one.
* **Projected, not measured**: the 64-log cost ceiling (≈ 7,226 opcodes). Argued
  unreachable inside 4,096 B; not proven exhaustively.
* **Not this document's to fix**: the factory-contract postmortem has never been
  committed to a design doc (§3.3). It cost 40+ failed mainnet creates and
  ~0.67 ALGO and lives only as prose in a `ROADMAP.md` cell.

---

## 14. Implementer checklist (normative MUSTs)

1. **MUST** land §5.1's `on_completion` guard on `AnchorReceiptProbe` first, as
   its own commit, before anything else in this document. It fixes a live
   mainnet-path defect and is independent of the rest.
2. **MUST NOT** split the proof across groups. One `AtomicTransactionComposer`,
   `attest` through `MODE_AGAINST_ANCHOR`.
3. **MUST** deploy the combined verifier as a permanent, manifest-pinned app —
   never compile-and-deploy per call.
4. **MUST** keep mode numbers identical to `Mpt7ReceiptApp`'s (0–5) so the two
   contracts cannot diverge and the existing arg builders work unchanged.
5. **MUST** carry `Mpt7ReceiptApp`'s `"L22"` (`r_rstatus(r) == R_INCOMPLETE`)
   assert into `MODE_STAGE_WALK`; `AnchorReceiptProbe`'s `MODE_NEXT` omits it.
6. **MUST** make `mpt7_stage_open` delete before creating (§5.2), and derive box
   names with a block component and a nonce.
7. **MUST** make the MBR payment conditional on a real `account_info` read, on
   both the anchored and non-anchored T2 paths.
8. **MUST NOT** add a sender gate to any staging mode (§7.1).
9. **MUST** size donors through `relayer.group.budget.size_donors` from a real
   `simulate` `app-budget-consumed`, never a constant — even though this design
   measured the group self-sufficient without donors.
10. **MUST** record every cost claim from a real response, and persist
    `measured_consumed` into `ReceiptResult.fields` (G7-014).
11. **MUST** re-run the full M7 and M8 live suites after §5.1's guard, since the
    approval hash of `AnchorReceiptProbe` moves.

---

## 15. Measurement appendix

Every number in this document was produced against real dev-mode algod
(`localhost:4051`, `dockernet-v1`, build 4.7.3, `future` protocol) during this
design pass, using the repo's own `tests.harness.chain` / `deploy.compile` /
`relayer.drivers.m7_receipt` / `relayer.group.budget` code paths unmodified.
Receipt tries were built with `relayer.proofs.receipts_trie.
build_receipts_trie_and_path` over synthetic-but-real receipts (real RLP, real
keccak, real MPT node structure), with the leaf **node** length binary-searched to
the 4,096-byte ceiling — note that the T1/T2 boundary and the 4,096 B cap apply to
the RLP-encoded *leaf node*, not the receipt value, a distinction that cost this
pass one failed run (`leaf 4098 B is outside T1/T2 range`). Each trie's
`receiptsRoot` was really anchored through `anchor_direct` on a real
`TrustedRootAnchor` (synthetic-but-self-consistent SSZ trees via
`tests/state_anchor/synth.py`, the same fixtures M8's own core suite uses) before
being proven. **No mainnet transaction was submitted and no mainnet contract was
touched by this pass.**
