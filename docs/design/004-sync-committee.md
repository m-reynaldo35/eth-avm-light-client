# 004 — M4: Sync-committee update verifier

**Module**: M4 · **Status**: Design Drafted · **Depends on**: M1 (implemented), M3 (implemented) ·
**Consumed by**: M8 (trusted-root anchor), M9 (relayer)
**Author**: design pass, 2026-07-31

---

## 0. Executive summary

M4 is the module the whole bridge's trust rests on: it verifies a real Ethereum
Altair-light-client-protocol sync-committee update on-chain — real BLS aggregate
signature, real SSZ branches, real domain separation and signing root — and rolls
the trusted committee forward.

Unlike M1 and M3's design passes, this one had **implemented dependencies to
measure against**, and unlike either of them it had a *semantic* obligation the
AVM cannot check for itself: that we hash the **right bytes** under the **right
domain**. Both are settled here on real spec data, not by assertion.

| Finding | Value | § |
|---|---|---|
| **A real consensus-spec light-client update verifies on the AVM, end to end** | `verify_aggregate_signature` → `0x80` (true) on the official altair `light_client_sync` vector | 3.5 |
| Signing-root construction validated against real vectors | **8/8** real updates across **5 sync-committee periods** verify with py_ecc under our `compute_domain`/`compute_signing_root` | 3.4 |
| Ethereum DST validated against the official BLS suite | **10/12** `eth_fast_aggregate_verify` vectors reproduce on-chain; the 2 misses are two known, documented, unreachable-in-M4 deviations | 3.6, 11 |
| Fork-gindex table | `(105, 54, 55)` Altair…Deneb / `(169, 86, 87)` Electra…Fulu, each **read out of vendored spec vectors**, not copied from prose | 4 |
| `hash_to_g2` under the real Ethereum DST | **17,443** budget, byte-exact vs `py_ecc` | 2.2 |
| `verify_aggregate_signature` (subgroup check + 2-pair pairing) | **55,474** | 2.2 |
| `g1_bind` (per committee key, install-time) | **1,966** | 2.2 |
| **P9 answered at real scale** (M1's open blocker) | 42-point chain **10,182** vs 42-point MSM **10,611** — the `ec_add` chain still wins, by 4% | 2.3 |
| **P11 answered** (M1's other open blocker) | a no-op donor inner app call costs **18** to issue and yields **+700** ⇒ **net +682**, 97.4% efficient | 2.4 |
| Fused bitfield-walk + box-gather + `ec_add` loop | **22.5 per bit walked**, **217 per participant** | 5.3 |
| SSZ branch verify, real Puya | **103 + 83·depth** re-measured exactly (435/518/601/684 at depth 4/5/6/7) | 2.5 |
| **Group-count decision** | **ONE 16-txn atomic group**, worst case 142,890 (+10% allowance = 157,179) against **180,192** net usable | 9 |
| The thing that buys the single group | the adaptive **complement** path — direct-only worst case is 198,559, which does **not** fit | 9.3 |

**Nothing in the group-sizing decision rests on an unmeasured number.** M1's two
flagged blockers (P9 at 42-point scale, P11) were both measured during this pass
and are reported above. The only projected quantities are small glue terms
(§2.6), all absorbed by a stated ±10% allowance that the 13% headroom covers.

---

## 1. Scope and non-goals

### 1.1 In scope

1. **`LightClientUpdate` verification** — the on-chain equivalent of the spec's
   `validate_light_client_update` (`specs/altair/light-client/sync-protocol.md`),
   minus the parts that need a wall clock (§6.5).
2. **Domain separation and signing root** — `compute_fork_data_root`,
   `compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)`,
   `compute_signing_root(BeaconBlockHeader, domain)`, and supplying the real DST
   `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` to M1's `hash_to_g2`.
3. **The fork-gated gindex and fork-version table** that M3 §4.5 requires of this
   module, resolved per-slot in the spec's `*_gindex_at_slot` shape (§4).
4. **Participation bitfield handling** — SSZ `Bitvector[512]` decode, popcount,
   participant selection, and the adaptive direct/complement aggregation
   decision (§5).
5. **Committee lifecycle** — install (resumable, multi-group), activation,
   period rollover, retirement, and the invariant that a partially installed
   committee can never be used (§8).
6. **The values M8 anchors** — verified `(finalized_beacon_root, finalized_slot,
   finalized_state_root, attested_state_root, participation)` (§7.4).

### 1.2 Non-goals

- **Trusted-root anchor storage, history, retention, eviction.** M8. M4
  *produces* the values and exposes them through a readonly getter and an ARC-4
  event; it stores only the single latest verified tuple as the state it needs
  for its own monotonicity checks (§7.4).
- **The execution-layer bridge** — `ExecutionPayload.state_root` /
  `receipts_root`, `get_lc_execution_root`, `execution_branch`. M8 (M3 §4.5).
  M4 never parses `LightClientHeader.execution`; it takes the **beacon** header
  only, and §7.2 explains why that is sufficient and safe.
- **Relayer construction of the payload**, chunk scheduling, fork-digest
  handling on the p2p side, `is_better_update` ranking. M9.
- **Box schema deployment/MBR tooling.** M10 (M4 specifies the schema; M10 owns
  provisioning it).
- **BLS/SSZ mechanics.** M1/M3, both implemented. M4 adds no curve arithmetic
  and no Merkle folding of its own.
- **`process_light_client_store_force_update` / `best_valid_update` /
  optimistic headers.** Deliberately out of v1 — see §6.6, which is a decision
  with a security argument, not an omission.

---

## 2. Empirical baseline

Per `ARCHITECTURE.md`, every number below traces to a real
`/v2/transactions/simulate` response taken during this design pass. Projected
quantities are labelled **projected** and never used without an allowance.

### 2.1 Environment

- Dev-mode Algorand localnet, algod `:4051` / kmd `:4052`, token `64×'a'`,
  protocol `future` — the spike container recipe
  (`tests/fixtures/spike-reference/README.md`), reused unmodified.
- Harness: `contracts/primitives/bls/harness.py` (`BlsHarness`) and
  `contracts/primitives/ssz/harness.py` (`SSZBenchmark`, `MerkleizeBenchmark`,
  `SSZVerifier`) as implemented, driven through `tests/bls/conftest.py`'s
  `LiveHarness` and `tests/ssz/generate_fixtures.py`'s `simulate_create_args`.
  One throwaway probe app (`M4Probe`, Appendix A) was compiled for the two
  measurements no existing harness covers.
- Simulate `extra-opcode-budget = 320,000`. All per-primitive figures are
  **per-transaction** `app-budget-consumed`, read from
  `txn-groups[0].txn-results[i]`, not the group total.
- Baseline: a trivial ARC-4 method (`chunk_count(512,42)`) consumes **44**.
  That 44 is the ARC-4 routing + decode floor and is *included* in every
  per-method figure below unless stated.

### 2.2 M1 primitives, measured with real Ethereum inputs

| primitive | input | **budget** |
|---|---|---:|
| `g1_bind(uncompressed, committed_compressed)` | a real altair committee pubkey | **1,966** |
| `g1_compress` | 96 B G1 | 92 |
| `expand_message_xmd_sha256(32 B, 43 B DST, 256)` | Ethereum DST | 655 |
| **`hash_to_g2(signing_root, ETH_DST)`** | 32 B msg, 43 B Ethereum DST | **17,443** |
| **`verify_aggregate_signature`** | real agg pubkey / msg point / real signature | **55,474** |
| `assert_g1_blob_from_box` (box read + guards only) | 96 B / 2,016 B / 4,032 B | **58, flat** |

Two things worth pinning:

- **`hash_to_g2` under the 43-byte Ethereum DST is byte-exact against
  `py_ecc.bls.hash_to_curve.hash_to_G2(msg, ETH_DST, sha256)`.** M1's T10 only
  ever exercised RFC 9380's own `QUUX-…` DST; this is the first time the
  *Ethereum* DST has been run through the AVM implementation. It works, and the
  DST length (43 vs RFC 9380's 50) does not change the `ell = 8` block count, so
  the cost is the same shape.
- **A box read is flat at 58 regardless of length.** M1 probe P12b and M3 probe
  Q1 are hereby resolved: `box_extract` does not meter by byte. (Box *read
  budget* — 1,024 B per box reference — is a separate, non-opcode accounting;
  see §9.4.)

### 2.3 P9 at real scale — M1's flagged blocker, now closed

M1 §6.4 shipped the `ec_add` chain as the default with a measure-then-branch
rule: *if per-iteration Puya glue ≥ 45, switch to MSM*. M1's implementation only
spot-checked this at small `n`, because a 42-point blob (4,032 B) cannot be
delivered through the 2,048 B app-arg cap. This pass used the box-staging
scaffold already present in `harness.py` (`box_stage_create` / `box_stage_write`
/ `g1_sum_blob_from_box` / `g1_msm_accumulate_points_from_box`) to measure at the
real chunk size.

| n | `ec_add` chain (from box) | MSM, all-ones scalars (from box) |
|---:|---:|---:|
| 1 | 96 | — |
| 2 | 342 | — |
| 11 | 2,556 | — |
| 21 | 5,016 | 8,616 |
| 32 | 7,722 | — |
| **42** | **10,182** | **10,611** |

The chain fits `96 + 246·(n − 1)` **exactly** at every measured `n`. So:

> **Measured per-iteration cost of the Puya `ec_add` accumulation loop = 246,
> of which 205 is the opcode and 41 is glue.** M1's break-even was 45. **41 < 45,
> so the `ec_add` chain stays the default — but the margin is 9%, not the
> comfortable "10–20" M1 expected.**

At the full 42-point chunk the chain beats MSM by 429 budget (4.0%). At 21 points
it beats it by 3,600 (42%). M1's §6.4 decision is confirmed, and its expectation
about the size of the margin is corrected. Correctness was cross-checked: the
42-point MSM result is byte-identical to a `py_ecc` reference sum.

**Implementer note:** M4 does not actually use `g1_sum_blob` on the per-update
path — the fused bitfield loop of §5.3 is cheaper still (217/point, because
`op.Box.extract` of 96 B beats slicing a 4,032 B in-memory value). The chain-vs-MSM
result matters for the *install* path and as the standing answer to P9.

### 2.4 P11 — donor inner-call efficiency, now closed

M1 §9.1 flagged that inner app calls raise the pooled budget by 700 each but cost
something to issue, and that "M4 cannot size its group without this number".
Measured with `M4Probe.issue_donors(donor_app_id, n)` (Appendix A) against a
trivial `int 1` donor app:

| n donors issued | consumed |
|---:|---:|
| 0 | 37 |
| 1 | 55 |
| 2 | 73 |
| 4 | 109 |
| 8 | 181 |

Perfectly linear: **18 budget per donor inner app call issued.**

> **Net budget gain per donor call = 700 − 18 = 682 (97.4% efficient).**
> A 16-txn group's 272-call ceiling therefore yields
> `190,400 − 256·18 = **185,792** net usable opcode budget`, not 190,400.

(The `app-budget-added` field in the simulate response is not usable for this:
under `extra-opcode-budget` each app call is credited 320,700, so it reports
2,886,300 at n=8. The consumed-side differencing above is the honest measurement.)

### 2.5 M3's real Puya branch cost, re-measured

Re-run of `tests/ssz/test_budget.py`'s T14 against the implemented
`contracts/primitives/ssz/`:

| gindex | fork role | depth | **Puya** | hand-TEAL (003 §2.4) |
|---:|---|---:|---:|---:|
| 25 | `EXECUTION_PAYLOAD_GINDEX` | 4 | **435** | 301 |
| 54 | `CURRENT_SYNC_COMMITTEE_GINDEX` | 5 | **518** | 362 |
| 105 | `FINALIZED_ROOT_GINDEX` | 6 | **601** | 425 |
| 169 | `FINALIZED_ROOT_GINDEX_ELECTRA` | 7 | **684** | 488 |

> **`budget = 103 + 83·depth`, exact on all four.** The `2·z` left-child term of
> 003 §2.5 has vanished in Puya codegen — both child cases cost the same. Use the
> flat form. The ARC-4 `SSZVerifier.verify_branch` wrapper measured **644** on the
> same shape (routing + `DynamicArray` unpack on top of the fold).

Single-app-call ceiling is therefore **depth ≤ 7** (684 of 700) with nothing left
for routing, and **depth ≤ 6 comfortably** — the ROADMAP's "~7-8" restated
precisely. M4 pools budget across donors anyway (§9), so this bounds nothing in
practice; it is recorded because Gloas's depth-11 branch (1,016) will silently
need the pool.

### 2.6 Real Puya merkleization scaling (install path)

`MerkleizeBenchmark` (`merkleize_stack_push` → `finalize` → `mix_in_length`):

| n leaves | depth | budget | marginal/leaf |
|---:|---:|---:|---:|
| 4 | 2 | 1,103 | — |
| 8 | 3 | 1,933 | 207.5 |
| 16 | 4 | 3,495 | 195.3 |
| 32 | 5 | 6,521 | 189.1 |
| 63 | 6 | 11,839 | 171.5 |

Marginal cost is ~172–195 per leaf and drifting down; M3's hand-TEAL figure was
67.5. **Projected** cost of `hash_tree_root(Vector[BLSPubkey, 512])` at real Puya
cost: `512 × ~185` (vector tree) `+ 512 × ~100` (per-pubkey
`sha256(pk[0:32] ‖ pk[32:48] ‖ 0×16)` leaf) ≈ **146,000 ± 25,000**, versus M3's
69,078 hand-TEAL figure. This is the **only** projected figure in the document
that is above 1,000 budget, and it lands on the *install* path, which is already
multi-group and dominated by `g1_bind` (§8.5) — a ±25,000 error moves the install
by well under one group. It is **not** load-bearing, and §14 assigns it a probe.

### 2.7 Facts inherited and re-confirmed

From `tests/fixtures/spike-reference/RESULTS.md` §4, unchanged and used in §9:
top-level app calls pool 700 each; inner app calls pool +700 each; **the 256
inner-txn cap is per GROUP**; one 16-txn group therefore tops out at 272 app calls
= 190,400 gross. A *single* app call may itself issue 256 inner calls
(N=256 → 179,900 succeeds, N=257 fails).

---

## 3. Domain separation, DST, and the signing root

This is the part M1 §11.1 explicitly could not validate and
`ARCHITECTURE.md` makes a condition of M4's approval: *"`py_ecc` can generate
real signatures but cannot tell you whether you are hashing the right bytes
under the right domain — a self-consistent M4 could pass its own tests with a
wrong DST."*

### 3.1 The construction (normative)

```
DOMAIN_SYNC_COMMITTEE = 0x07000000                              # 4 bytes
ETH_DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"        # 43 bytes

compute_fork_data_root(current_version, genesis_validators_root):
    # hash_tree_root(ForkData{current_version: Version, genesis_validators_root: Root})
    # ForkData is 2 chunks -> a single sha256, no padding tree.
    return sha256( current_version ‖ 0x00 * 28  ‖  genesis_validators_root )

compute_domain(domain_type, fork_version, genesis_validators_root):
    return domain_type ‖ compute_fork_data_root(fork_version, genesis_validators_root)[0:28]

hash_tree_root(BeaconBlockHeader):
    # 5 fields -> 5 chunks -> padded to 8 leaves with zero chunks
    chunks = [ slot_le64 ‖ 0*24, proposer_index_le64 ‖ 0*24,
               parent_root, state_root, body_root ]
    return merkleize(chunks, limit=8)

compute_signing_root(header, domain):
    # hash_tree_root(SigningData{object_root, domain}) -- 2 chunks, one sha256
    return sha256( hash_tree_root(header) ‖ domain )

msg_point = hash_to_g2(compute_signing_root(attested_header.beacon, domain), ETH_DST)
```

Five traps, each of which produces a plausible-looking wrong answer:

1. **`slot` and `proposer_index` are little-endian** in their SSZ chunks. `itob`
   gives 8-byte big-endian. This is the same endianness trap M3 §2.11 flagged for
   `mix_in_length`, in a second place.
2. **`compute_domain` truncates the fork-data root to 28 bytes**, not 32. The
   first 4 bytes of that root are, separately, the network's **fork digest** —
   our measured domain `0x07000000 15cfa0a7 e842ca38…` has `15cfa0a7` in
   position 4..8, which is exactly the `bootstrap_fork_digest` recorded in the
   vector's `meta.yaml`. That coincidence is a free self-check and the test plan
   uses it (§11, T3).
3. **The fork version is resolved at `signature_slot − 1`, not `signature_slot`.**
   Verbatim from `specs/altair/light-client/sync-protocol.md`:
   ```python
   fork_version_slot = max(update.signature_slot, Slot(1)) - Slot(1)
   fork_version = compute_fork_version(compute_epoch_at_slot(fork_version_slot))
   ```
   An update whose `signature_slot` is the very first slot of a fork is signed
   under the *previous* fork's version. Getting this wrong breaks exactly one
   update per fork — the hardest possible failure to catch in testing.
4. **The gindices are resolved at a different slot from the fork version**: the
   spec passes `update.attested_header.beacon.slot` to
   `finalized_root_gindex_at_slot` / `next_sync_committee_gindex_at_slot`, while
   the domain uses `signature_slot − 1`. They can straddle a fork boundary. §4.4
   handles this.
5. **The signing root is over `attested_header.beacon`, never the finalized
   header**, and never over the `LightClientHeader` wrapper.

### 3.2 Why the DST must not be hard-coded in M1 — and is not

M1's `hash_to_g2(msg, dst)` takes the DST as a runtime parameter and hard-codes
no Ethereum constant (`hash_to_curve.py` module docstring; 001 §1.2, §8, §15
item 6). M4 owns the constant. It is declared once, in
`contracts/sync_committee/constants.py`, as a module-level `bytes` literal with
a subroutine accessor (the pattern `codec.py` established for Puya's
module-scope restriction), and passed explicitly at the single call site.

### 3.3 Vendored evidence

Vendored during this pass into
`tests/fixtures/sync_committee/consensus-spec-tests/`, release-pinned exactly as
M3 did (`RELEASE.txt` records the recipe):

| suite | cases | what it pins |
|---|---:|---|
| `general/altair/bls/eth_fast_aggregate_verify/bls/` | 12 | the **DST** — these signatures were produced under `BLS_SIG_…_POP_`; a wrong DST fails all of them |
| `minimal/{altair,bellatrix,capella,deneb,electra,fulu}/light_client/sync/pyspec_tests/` | 4 each | the **signing root, domain, committee rollover, bitfield order** — full sync scenarios with `bootstrap`, N updates, `steps.yaml`, `meta.yaml`, `config.yaml` |
| `minimal/*/light_client/update_ranking/pyspec_tests/` | — | `is_better_update` ordering; retained but not implemented (§6.6) |

> Two facts an implementer will otherwise lose an afternoon to: (a) the
> `.ssz_snappy` files are **raw** snappy blocks, not the snappy *frame* format —
> `cramjam.snappy.decompress_raw`, not `.decompress`; (b) v1.6.0-beta.0's
> `general` tarball contains only `eth_fast_aggregate_verify` and
> `eth_aggregate_pubkeys`; the older phase0 `verify`/`aggregate`/`hash_to_G2`
> suites M1 §11.1 anticipated **are not in this release**.

### 3.4 Reproduction on real vectors — signing root

The altair `light_client_sync` case was walked exactly as a light client would:
start from `bootstrap.ssz_snappy`, apply every update in `steps.yaml` order,
track current/next committee across period rollover, construct the signing root
with §3.1, and verify the real signature with `py_ecc.bls.G2ProofOfPossession.
FastAggregateVerify`.

```
genesis_validators_root = 0a08c27fe4ece2483f9e581f78c66379a06f96e9c24cd1390594ff939b26f95b
ALTAIR_FORK_VERSION     = 01000001                     (minimal config)
domain                  = 0700000015cfa0a7e842ca383b78d60efba16c294ec206ac937d1cb432fdc29e
```

| update | sig slot | period | committee used | popcount | signing root | BLS |
|---|---:|---:|---|---:|---|:--:|
| `…280701f3…_sf` | 41 | 0 | current | 32 | `74e1d7be6dd92bf2…` | ✅ |
| `…6b92ec5d…_sf` | 89 | 1 | next | 32 | `84fc83adae69da8a…` | ✅ |
| `…c8056e52…_xf` | 129 | 2 | next | 32 | `70766309cc6b58af…` | ✅ |
| `…a955d148…_sx` | 130 | 2 | current | 32 | `48dd7051552896df…` | ✅ |
| `…448c1cb2…_sf` | 131 | 2 | current | 32 | `37d05aadd3d59cbc…` | ✅ |
| `…28faa328…_xx` | 195 | 3 | next | 32 | `88065adb62315e1a…` | ✅ |
| `…343922a9…_sf` | 196 | 3 | current | 32 | `3ba3d8dba4f9292f…` | ✅ |
| `…6b231a0a…_sf` | 281 | 4 | next | 32 | `8b11f198e0ea3c55…` | ✅ |

**8/8 verified, across 5 sync-committee periods and 4 rollovers.** Two
independent corroborations fell out of it:

- `hash_tree_root(attested_header.beacon)` equals the block root embedded in
  each update's **filename** — for all 8. The spec's own test-data naming is an
  oracle for our header merkleization.
- The `finalized_header` leaf we compute, `9001cc7abda67695…`, is byte-identical
  to `steps.yaml`'s expected `finalized_header.beacon_root` for that step.

If the DST, the fork version, the 28-byte domain truncation, the endianness, the
bitfield bit order, or the committee-selection rule were wrong, this table would
be empty.

### 3.5 The same update, verified on the AVM

The first update above (attested slot 40, signature slot 41, 32/32 participants)
was then pushed through the real M1 primitives on live algod: pubkeys staged into
a box, aggregated with the `ec_add` chain, signing root hashed to G2 under the
real Ethereum DST, and the 2-pair pairing run.

| step | budget | result |
|---|---:|---|
| aggregate 32 real committee pubkeys from box | **7,722** | `18b78d0310bc7728…` |
| `g1_bind` a real committee key to its committed compressed form | **1,966** | pass |
| `hash_to_g2(74e1d7be…, ETH_DST)` | **17,443** | matches `py_ecc` |
| **`verify_aggregate_signature`** | **55,474** | **`0x80` = true** |

And the SSZ side of the same update, folded at the fork-gated gindices:

| leaf | gindex | folds to | matches `attested_header.beacon.state_root`? |
|---|---:|---|:--:|
| `hash_tree_root(next_sync_committee)` = `d2efd486…` | **55** | `eddb8ae1865c1cf9…` | ✅ |
| `hash_tree_root(finalized_header.beacon)` = `9001cc7a…` | **105** | `eddb8ae1865c1cf9…` | ✅ |

> **A real Ethereum consensus-spec sync-committee update verifies on the Algorand
> Virtual Machine.** That sentence is the reason this module exists, and it is now
> a measured fact rather than a plan.

### 3.6 The official BLS suite, run through the AVM

All 12 `eth_fast_aggregate_verify` vectors were pushed through
aggregate → `hash_to_g2(msg, ETH_DST)` → `verify_aggregate_signature`:

| outcome | count | cases |
|---|---:|---|
| AVM agrees with the vector | **10** | `valid_0/1/2` (true), `extra_pubkey_0/1/2` (false), `tampered_signature_0/1/2` (false — the tampered G2 is undecodable, so it never becomes uncompressed bytes at all), `na_pubkeys_and_zero_signature` (false, likewise) |
| **deviation 1** | 1 | `infinity_pubkey`: expected false, the bare primitives return **true** |
| **deviation 2** | 1 | `na_pubkeys_and_infinity_signature`: expected true, the primitives **fail closed** (assert) |

Both deviations are real, both are already anticipated by M1 §7.1, and **both are
unreachable in M4** — but only because of things M4 does, so they are stated
normatively:

- **Deviation 1 is closed by `g1_bind`, not by the pairing.** An infinity pubkey
  in the aggregate is invisible to `ec_add` (96 zero bytes is the identity). The
  spec's `eth_fast_aggregate_verify` rejects it via `KeyValidate`. In M4 a
  committee key can only enter the box through `g1_bind`, which asserts
  `not g1_is_infinity` *before* the subgroup check — so an infinity key can never
  be installed. This is the same "the primitive is not the security boundary,
  the binding is" lesson as M1's T12, one layer up. **A test that runs this
  vector against M4's install path, not against `g1_sum_blob`, is mandatory
  (§11, T7).**
- **Deviation 2 is closed by `MIN_SYNC_COMMITTEE_PARTICIPANTS`.** The empty-set /
  infinity-signature case is legal under `eth_fast_aggregate_verify` but excluded
  by the light-client protocol's participation floor, and M1 fails closed
  regardless. M4 asserts the floor before ever reaching the pairing (§6.2).

---

## 4. The fork-gated table

M3 §4.5 requires this module to own it: *"M4 must maintain a fork-gated gindex
table equivalent to `finalized_root_gindex_at_slot` /
`current_sync_committee_gindex_at_slot` / `next_sync_committee_gindex_at_slot`,
keyed on the epoch of the update's slot… the fork epochs are themselves consensus
constants and must come from the same pinned config M4 uses for the BLS
fork-version/DST."* Done, from a pinned config, cross-checked against vendored
vectors.

### 4.1 Sources (pinned)

- `ethereum/consensus-specs` tag **`v1.6.0-beta.0`** —
  `configs/mainnet.yaml` (fork versions and epochs),
  `presets/mainnet/altair.yaml` (`SYNC_COMMITTEE_SIZE: 512`,
  `EPOCHS_PER_SYNC_COMMITTEE_PERIOD: 256`, `MIN_SYNC_COMMITTEE_PARTICIPANTS: 1`),
  `specs/altair/light-client/sync-protocol.md` (gindex constants 105/54/55),
  `specs/electra/light-client/sync-protocol.md` (gindex constants 169/86/87 and
  the three `*_gindex_at_slot` accessors).
- `ethereum/consensus-spec-tests` release **`v1.6.0-beta.0`** — the
  `light_client/single_merkle_proof/BeaconState/*` vectors M3 already vendored
  into `tests/fixtures/ssz/consensus-spec-tests/`.

### 4.2 The gindices are read out of the vectors, not copied from prose

Every value below is the `leaf_index` field of a vendored `proof.yaml`. This is
the check that matters: it is possible to mis-transcribe a constant from a
markdown table; it is not possible to mis-transcribe one out of the file whose
sibling `branch` folds to a real `BeaconState` root.

| fork dir (vendored) | `finality_root` | `current_sync_committee` | `next_sync_committee` |
|---|---:|---:|---:|
| `altair/` | **105** | **54** | **55** |
| `bellatrix/` | 105 | 54 | 55 |
| `capella/` | 105 | 54 | 55 |
| `deneb/` | 105 | 54 | 55 |
| `electra/` | **169** | **86** | **87** |
| `fulu/` | 169 | 86 | 87 |

Depths (`floorlog2`): 105→6, 54/55→5, 169→7, 86/87→6. Real Puya branch cost from
§2.5: **601 / 518 / 684 / 601**.

### 4.3 The deployed table

Row shape, stored in box `forks` (§7.3), append-only, governance-written:

```
(activation_epoch: uint64, fork_version: byte[4],
 finality_gindex: uint64, current_sc_gindex: uint64, next_sc_gindex: uint64)
```

Mainnet rows, from `configs/mainnet.yaml` @ `v1.6.0-beta.0`:

| fork | `fork_version` | `activation_epoch` | finality | current SC | next SC |
|---|---|---:|---:|---:|---:|
| phase0 | `0x00000000` | 0 | — | — | — |
| altair | `0x01000000` | 74240 | 105 | 54 | 55 |
| bellatrix | `0x02000000` | 144896 | 105 | 54 | 55 |
| capella | `0x03000000` | 194048 | 105 | 54 | 55 |
| deneb | `0x04000000` | 269568 | 105 | 54 | 55 |
| electra | `0x05000000` | 364032 | 169 | 86 | 87 |
| fulu | `0x06000000` | **see below** | 169 | 86 | 87 |
| gloas | `0x07000000` | **unset** | 735 | 2945 | 2946 **(unverified — §4.5)** |

> **Honest correction to a number in an earlier design doc.** 003 §4.2 states
> "mainnet is on Fulu, `FULU_FORK_EPOCH = 411392`". At the spec release this
> project pins, `configs/mainnet.yaml` still carries
> `FULU_FORK_EPOCH: 18446744073709551615  # temporary stub`. The two are not
> reconcilable from a single source, and that is precisely the argument for the
> table being **mutable state read from the deployed network's config at
> deployment time**, not a constant baked into a design document or a contract.
> **Normative: fork *epochs* come from the network config in force when the row
> is appended; fork *gindices* come from spec vectors verified before the row is
> appended (§4.5).** A row whose epoch is the `uint64` max sentinel MUST be
> rejected at append time.

Below-Altair rows exist only so that `compute_fork_version` at
`signature_slot − 1` can return `GENESIS_FORK_VERSION` for the single update
whose signature slot is the first slot of the Altair fork. They carry no
gindices and MUST never be selected by a gindex lookup (assert).

### 4.4 Resolution rules (normative, mirroring the spec exactly)

```
epoch(slot)                = slot // SLOTS_PER_EPOCH                 # 32 on mainnet
period(slot)               = epoch(slot) // EPOCHS_PER_SYNC_COMMITTEE_PERIOD   # 256

fork_version               = table_lookup(epoch(max(signature_slot,1) - 1)).fork_version
finality_gindex            = table_lookup(epoch(attested_header.slot)).finality_gindex
next_sc_gindex             = table_lookup(epoch(attested_header.slot)).next_sc_gindex
```

**Two different slots feed two different lookups.** Do not collapse them. A
committee that signs in the last slot of fork F an attestation to a header in
fork F uses F's version; the *following* slot's update uses F+1's version while
the gindices may still be F's. That is not a hypothetical — it is exactly one
update per fork, and §10.6 makes it a test.

`table_lookup(epoch)` is a linear scan of ≤ 10 rows returning the last row with
`activation_epoch <= epoch`; **projected** ~20 budget per row, ~200 total.
Rejects if no row matches (i.e. pre-Altair) or if the matched row has zero
gindices.

### 4.5 The Gloas row is not approved by this document

M3 §4.2 lists Gloas as `(735, 2945, 2946)`. This release contains **no Gloas
`single_merkle_proof` vectors** (M3's own `RELEASE.txt` says so), so unlike every
other row those three numbers are transcribed from prose, not read out of a
vector. **Normative: the Gloas row MUST NOT be appended until its gindices are
confirmed against vendored Gloas vectors.** The table is append-only mutable
state precisely so this can happen later without a redeployment. Note also that
Gloas's depth-11 branch costs `103 + 83·11 = 1,016`, over a single call's 700 —
harmless inside M4's pooled group (§9) but fatal to anyone who assumes "one
branch = one app call".

---

## 5. Participation bitfield and adaptive aggregation

### 5.1 `sync_committee_bits` is a `Bitvector[512]`, and its bit order is not the AVM's

`SyncAggregate.sync_committee_bits` is `Bitvector[SYNC_COMMITTEE_SIZE]` = exactly
**64 bytes** on mainnet, with **no length delimiter** (that is `Bitlist`, a
different type — using `Bitlist` semantics here would consume a nonexistent
terminator bit).

- **SSZ**: bit `i` lives in byte `i // 8`, at bit position `i % 8` counted from
  that byte's **least** significant bit.
- **AVM `getbit` on a byte array**: bit 0 is the **most** significant bit of
  byte 0.

```
avm_bit_index(i) = (i // 8) * 8 + 7 - (i % 8)
```

This mapping is not optional and not cosmetic: getting it wrong selects a
*permuted* subset of the committee, which for a fully-participating committee
(the common case, and every one of the vendored altair vectors) still verifies —
so it passes the obvious test and fails the first time real mainnet participation
is partial. §11 T5 pins it with a deliberately asymmetric bitfield.

`len(sync_committee_bits) == 64` is asserted; `SYNC_COMMITTEE_SIZE` is a
compile-time constant of the contract (512), not a runtime parameter, because it
is a *preset*, not a config value — it cannot change without a new preset, and a
runtime committee size would let a caller resize the box layout.

### 5.2 Popcount comes free from the walk

There is no AVM popcount opcode. Measured cost of a naive 512-bit `getbit` loop
(`M4Probe.popcount`): **6,703**. M4 pays **none** of it, because the count falls
out of the aggregation walk it must do anyway:

- direct mode: `popcount` = the number of iterations that performed an `ec_add`;
- complement mode: `popcount = 512 − (number of iterations that were skipped)`.

A separate popcount pass is therefore forbidden by the implementer checklist
(§15 item 5). (For reference, if one were ever needed, a 256-entry byte-popcount
lookup table walked over 64 bytes should cost ~1,900 rather than 6,703 — recorded
as an option, not built.)

### 5.3 The fused walk — measured

The real per-update inner loop is a single pass that tests a bit, and on a hit
reads that member's 96-byte uncompressed pubkey from box storage and `ec_add`s it.
Measured with `M4Probe.agg_bitfield` (Appendix A) over a 64-bit window against a
box of 64 real G1 points:

| popcount over 64 bits | budget |
|---:|---:|
| 0 | 1,486 |
| 1 | 1,499 |
| 16 | 4,754 |
| 32 | 8,226 |
| 48 | 11,698 |
| 64 | 15,170 |

Exactly linear in both dimensions:

> **`cost = 44 + 22.5·(bits walked) + 217·(participants − 1) + 13`**
>
> **22.5 budget per bit walked** (bit test + the §5.1 index remap + loop glue),
> **217 budget per participant** (`box_extract` 96 B + `ec_add` + branch).

Sanity: predicted at 64 bits / 64 participants = `44 + 1,440 + 13,671 + 13 =
15,168` against a measured 15,170.

Note **217 < 246**: gathering each point with `op.Box.extract` is *cheaper* than
slicing it out of a 4,032-byte in-memory blob (§2.3). The fused loop is both the
correct shape and the fast one. For 512 bits the walk term is `512 × 22.5 =
11,520`.

### 5.4 The adaptive direct/complement decision

M1 §10.3 designed for this and shipped `g1_accumulate_negated`; the full-committee
aggregate `A_total` is cached in a box at install time (§8.3). Because
`Σ_participants = A_total − Σ_absent`:

| `popcount p` | mode | points touched |
|---|---|---:|
| `p ≤ 256` | **direct** — sum the participants | `p` |
| `p > 256` | **complement** — subtract the absentees from `A_total` | `512 − p` |

Points touched is therefore **≤ 256 always**, and on mainnet (typically 95–99%+
participation) it is **≤ 26**.

| scenario | points | aggregation budget |
|---|---:|---:|
| typical mainnet, p = 505 (complement) | 7 | `11,520 + 217·6 + 400 = 13,222` |
| p = 486 / 95% (complement) | 26 | `11,520 + 217·25 + 400 = 17,345` |
| **adaptive worst case, p = 257** (complement) | 255 | `11,520 + 217·254 + 400 = 67,038` |
| adaptive worst case, p = 256 (direct) | 256 | `11,520 + 217·255 = 66,855` |
| *(direct-only, no complement, p = 512)* | 511 | `11,520 + 217·511 = 122,407` |

The 400 is the complement fixup: `g1_negate` on the summed absentees (two
`BigUInt` subtractions plus `pad_fp`) and one `ec_add` against `A_total`
(**projected**; `ec_add` alone is a measured 205).

### 5.5 The mode is a relayer hint, and that is safe

The wire payload carries `mode ∈ {0=direct, 1=complement}`. **A wrong or
malicious `mode` cannot change the result**: both branches compute the same
group element from the same contract-owned inputs (the bitfield, which is covered
by the signature, and the box-resident bound keys plus `A_total`, which the
contract itself wrote). A lying relayer only wastes budget, and only its own.
The contract therefore does **not** validate `mode` against the popcount — doing
so would cost a separate popcount pass to no security benefit. It *does* assert
that the mode taken is consistent with what it counted, purely as a
cheap sanity trap: `assert (mode == 1) == (popcount > 256)` is **not** required;
what *is* required is that `popcount` is computed from the walk actually
performed (§5.2) and checked against the participation floor (§6.2).

---

## 6. Protocol semantics implemented, and the deliberate deviations

### 6.1 What `submit_update` checks, in order

Mirrors `validate_light_client_update`, reordered so that cheap rejections
precede the 55,474-budget pairing:

```
 1  assert len(sync_committee_bits) == 64
 2  assert len(signature) == 192 and len(attested_header) == 112
 3  assert signature_slot > attested_slot >= finalized_slot          # spec ordering
 4  assert attested_slot >= finalized_slot                            #  (finalized may be 0/empty)
 5  resolve store_period, update_signature_period; assert the period-skip rule
 6  resolve fork_version   <- table @ epoch(signature_slot - 1)       # §4.4
 7  resolve gindices       <- table @ epoch(attested_slot)            # §4.4
 8  verify finality branch      (gindex from step 7, root = attested_state_root)
 9  verify next_sc branch, if present (gindex from step 7, same root)
10  walk the bitfield, aggregate adaptively, obtain popcount          # §5
11  assert popcount >= MIN_SYNC_COMMITTEE_PARTICIPANTS                # = 1
12  domain = compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, gvr)
13  signing_root = compute_signing_root(attested_header, domain)
14  msg_point = hash_to_g2(signing_root, ETH_DST)
15  assert verify_aggregate_signature(agg, msg_point, signature)      # 55,474
16  apply: 2/3 rule, monotonicity, committee rollover, emit event     # §6.3, §8
```

Steps 8 and 9 come **before** the signature check even though their root
(`attested_state_root`) is only trusted *after* step 15. That is safe and
deliberate: a branch that fails is a rejection either way, and putting the two
601/684-budget checks ahead of the 73k-budget crypto makes a malformed update
cheap to reject. Nothing between steps 8 and 15 writes state.

### 6.2 `MIN_SYNC_COMMITTEE_PARTICIPANTS`

`presets/mainnet/altair.yaml` @ `v1.6.0-beta.0`: **`MIN_SYNC_COMMITTEE_PARTICIPANTS: 1`.**
It is a *preset*, so it is a contract constant, not a table row. One is a very
weak floor — it exists only to exclude the empty aggregate — and it is **not**
the threshold that gates anchoring; see §6.3.

### 6.3 The 2/3 rule gates state advancement

From `process_light_client_update`:
`if sum(sync_committee_bits) * 3 >= len(sync_committee_bits) * 2 and …`. On
mainnet that is **`3·popcount >= 1024`, i.e. `popcount >= 342`**.

- `popcount >= 1` → the update is *valid* (signature verified) but changes
  nothing.
- `popcount >= 342` **and** `finalized_slot > store.finalized_slot` (or the
  first-next-committee case) → the finalized root advances and the committee
  rollover may occur.

M4 implements only this path. It does **not** implement the optimistic header
(`get_safety_threshold`, `current_max_active_participants`) — see §6.6.

### 6.4 Committee selection

```
if update_signature_period == store_period:   committee = current
else:                                          committee = next        # must be known
```
with the spec's guard `update_signature_period in (store_period, store_period + 1)`
when the next committee is known, and `== store_period` when it is not.
`store_period` is `period(store.finalized_slot)` — the finalized header's slot,
not the attested one.

### 6.5 Deviation: there is no `current_slot` on-chain

The spec asserts `current_slot >= update.signature_slot`. The AVM has no view of
Ethereum's clock, and Algorand's own round timestamps are not a sound proxy (they
would let a stalled or racing Algorand chain reject valid Ethereum updates).

> **Decision: drop the `current_slot` bound; keep every other ordering
> assertion, and add strict monotonicity of `finalized_slot`.**

What this costs: the ability to reject an update whose `signature_slot` is
implausibly far ahead of wall-clock. What it does not cost: any safety property.
An update with a future `signature_slot` still needs a signature from a committee
this contract has installed, and a replayed old update fails the strict
`finalized_slot > store.finalized_slot` monotonicity check. Observing wall-clock
sanity is **M9's** job and is recorded as such in §12.

### 6.6 Deviation: no `best_valid_update`, no force-update, no optimistic header

`process_light_client_store_force_update` exists so a light client can make
progress through extended non-finality by promoting `attested_header` to
`finalized_header` after `UPDATE_TIMEOUT`. Implementing it on-chain would require
storing a whole candidate update (~1 KB) plus `is_better_update`'s six-way
ranking, and it deliberately **weakens** the finality guarantee that Track B's
state proofs are anchored to.

> **Decision: v1 anchors only 2/3-finalized updates. No `best_valid_update`, no
> force-update, no optimistic header tracking.**

Consequence: during an extended Ethereum non-finality event the bridge stalls
rather than advancing on attested-but-unfinalized data. For a *bridge*, stalling
is the correct failure mode. The `update_ranking` vectors are vendored anyway so
this can be revisited with data rather than opinion.

### 6.7 Deviation: `hash_tree_root(next_sync_committee)` arrives as a leaf, not as 512 pubkeys

The spec computes the next-committee branch leaf as
`hash_tree_root(update.next_sync_committee)`. Doing that inside `submit_update`
would mean merkleizing 512 pubkeys (§2.6, ~146,000 **projected**) *and* carrying
24,576 bytes of committee data through a 2,048-byte-per-txn arg cap — inside the
same call that already costs 73k for crypto. Both are impossible in one group.

> **Decision: `submit_update` takes the 32-byte committee root as a leaf and
> verifies the branch against it (601 budget). The 512 pubkeys are delivered
> separately by the install session (§8), which asserts that the keys it
> merkleizes hash to exactly that trusted root.**

This is strictly equivalent to the spec's check and it is what makes the
per-update path uniform and small. It also inverts the dependency pleasantly: the
cheap check establishes the trusted root first, and the expensive session then
proves the bulk data matches it. If the session's merkle root does not match, the
committee is never activated and the trusted root is simply left unfulfilled.

---

## 7. Interface

### 7.1 Shape

`contracts/sync_committee/` is a **deployed ARC-4 contract** (unlike M1/M3, which
are compile-time subroutine libraries imported into it). It imports
`contracts/primitives/bls` and `contracts/primitives/ssz` as subroutines — never
as inner app calls, per 001 §5 and 003 §5.4.

### 7.2 Headers cross the boundary as raw SSZ bytes

`BeaconBlockHeader` serializes to **exactly 112 bytes**, all fields fixed-size:

```
slot            uint64   little-endian   [  0:  8]
proposer_index  uint64   little-endian   [  8: 16]
parent_root     Bytes32                  [ 16: 48]
state_root      Bytes32                  [ 48: 80]
body_root       Bytes32                  [ 80:112]
```

M4 takes `byte[112]` verbatim rather than an ARC-4 tuple: the contract needs the
*chunks* to merkleize, so decoding into typed fields and re-encoding them would be
pure waste. `slot` is read with an 8-byte reverse when a `uint64` comparison is
needed (M3 §2.11's endianness trap, second occurrence).

**Only the `beacon` part of `LightClientHeader` is accepted.** Post-Bellatrix
`LightClientHeader` also carries `execution` + `execution_branch`; M4 does not
look at them, which is exactly right — they are M8's bridge to the execution
layer (M3 §4.5), and the beacon header alone is what the signature covers. Note
for M8: `is_valid_light_client_header` (which checks the execution branch) is
therefore **not** performed by M4, and M8 must not assume it was.

### 7.3 ARC-4 surface

```python
class SyncCommitteeVerifier(ARC4Contract):

    # ---- one-time setup -------------------------------------------------
    @arc4.abimethod(create="require")
    def create(self, governance: arc4.Address,
               genesis_validators_root: arc4.StaticBytes[Literal[32]]) -> None: ...
        # genesis_validators_root is write-once and immutable thereafter (§10.7)

    @arc4.abimethod
    def append_fork_row(self, activation_epoch: arc4.UInt64,
                        fork_version: arc4.StaticBytes[Literal[4]],
                        finality_gindex: arc4.UInt64,
                        current_sc_gindex: arc4.UInt64,
                        next_sc_gindex: arc4.UInt64) -> None: ...
        # governance only; append-only; activation_epoch must strictly exceed the
        # last row's; the uint64-max stub epoch is rejected (§4.3)

    @arc4.abimethod
    def bootstrap(self, header: arc4.StaticBytes[Literal[112]],
                  committee_root: arc4.StaticBytes[Literal[32]],
                  current_sc_branch: arc4.DynamicBytes,   # packed 32*k
                  trusted_block_root: arc4.StaticBytes[Literal[32]]) -> None: ...
        # governance only, once. Verifies hash_tree_root(header) == trusted_block_root
        # and the current-committee branch at current_sc_gindex(epoch(header.slot))
        # against header.state_root, then opens an install session for
        # committee_root at period(header.slot).

    # ---- committee install session (§8) ---------------------------------
    @arc4.abimethod
    def install_begin(self, period: arc4.UInt64) -> None: ...
    @arc4.abimethod
    def install_chunk(self, index: arc4.UInt64,
                      compressed: arc4.DynamicBytes,      # 48*k
                      uncompressed: arc4.DynamicBytes     # 96*k, same k
                      ) -> None: ...
    @arc4.abimethod
    def install_finalize(self, aggregate_compressed: arc4.StaticBytes[Literal[48]],
                         aggregate_uncompressed: arc4.StaticBytes[Literal[96]]
                         ) -> None: ...
    @arc4.abimethod
    def install_abort(self) -> None: ...

    # ---- the per-update entry point -------------------------------------
    @arc4.abimethod
    def submit_update(self,
        attested_header:       arc4.StaticBytes[Literal[112]],   # SSZ, §7.2
        finalized_header:      arc4.StaticBytes[Literal[112]],   # all-zero if absent
        finality_branch:       arc4.DynamicBytes,                # packed 32*k, normalized
        next_committee_root:   arc4.StaticBytes[Literal[32]],    # zero if absent
        next_committee_branch: arc4.DynamicBytes,                # packed 32*k, empty if absent
        sync_committee_bits:   arc4.StaticBytes[Literal[64]],
        signature:             arc4.StaticBytes[Literal[192]],   # UNCOMPRESSED G2
        signature_slot:        arc4.UInt64,
        mode:                  arc4.UInt8,                       # 0 direct, 1 complement
    ) -> None: ...

    @arc4.abimethod
    def noop_budget(self) -> None: ...
        # exists only to be a group filler that carries box references and adds
        # 700 to the pool (§9.4). Asserts nothing, writes nothing.

    @arc4.abimethod
    def donor(self) -> None: ...
        # inner-call target for budget donation (18 to issue, +700 to the pool,
        # §2.4). Separate from noop_budget so the two roles stay legible.

    # ---- output for M8 ---------------------------------------------------
    @arc4.abimethod(readonly=True)
    def get_finalized(self) -> arc4.Tuple[...]: ...
```

**Payload size check.** `112 + 112 + (7·32) + 32 + (6·32) + 64 + 192 + 8 + 1 =
937` bytes plus ARC-4 framing ≈ **~1,000 B**, comfortably inside the 2,048-byte
per-transaction app-arg cap. **A finality update fits in a single transaction's
arguments** — no chunking, no box staging on the per-update path. (M1 §6.1's
chunking rules apply only to the install session, §8.)

### 7.4 What M8 consumes

On a successful 2/3-finalized update, M4 writes to global state and emits:

```
LightClientUpdateVerified(
    finalized_slot:        uint64,
    finalized_beacon_root: bytes32,   # hash_tree_root(finalized_header.beacon)
    finalized_state_root:  bytes32,   # finalized_header.state_root
    attested_slot:         uint64,
    attested_state_root:   bytes32,
    participation:         uint64,
    signature_slot:        uint64,
)
```

M4 keeps only the **latest** tuple (it needs `finalized_slot` for monotonicity
and `period(finalized_slot)` for committee selection). **History, retention and
eviction are M8's** (its ROADMAP open question). Recommended integration: M8
reads via `get_finalized()` in the same group, or M4 is deployed as a component
of M8's app; either way M8 must key its history on `finalized_slot` and must
treat a zero `finalized_beacon_root` as "no finality yet" and refuse to anchor it
(M3 §7.5 asks for exactly this, and §10.4 below implements it).

---

## 8. Install / session / rollover state machine

### 8.1 Why a session is unavoidable

Installing a committee costs (§8.5) **~1,357,000** budget and requires delivering
**73,728 bytes** through a 2,048-byte-per-transaction arg cap. Neither fits one
group under any design. M1 §9.3 predicted this and asked M4 to own it.

### 8.2 State

Global:

| key | type | meaning |
|---|---|---|
| `gov` | address | may append fork rows / bootstrap |
| `gvr` | bytes32 | `genesis_validators_root`, write-once |
| `fin_slot`, `fin_root`, `fin_state_root` | uint64, bytes32, bytes32 | latest anchored finality (§7.4) |
| `att_slot`, `att_state_root` | uint64, bytes32 | latest attested |
| `cur_gen`, `cur_period` | uint64 | active committee generation + its period |
| `next_gen`, `next_period` | uint64 | staged next committee; `next_gen == 0` ⇒ unknown |
| `inst_state` | uint8 | `IDLE` / `INSTALLING` |
| `inst_gen`, `inst_period`, `inst_root`, `inst_cursor` | — | the in-flight session |

Boxes:

| box | size | contents |
|---|---:|---|
| `k:<gen>:<j>` for `j` in 0..7 | 6,144 B | 64 uncompressed G1 pubkeys, member `i` at offset `96·(i mod 64)` in box `i // 64` |
| `a:<gen>` | 96 B | `A_total` = Σ of all 512 installed keys (the complement path's base) |
| `s:<gen>` | ~480 B | session scratch: merkle stack (10×32 B) + `filled` mask + running Σ (96 B) |
| `forks` | ~400 B | the §4.3 table |

8 boxes of 64 keys rather than 2 of 256: box read budget is granted per *box
reference* (1,024 B each, 8 refs per txn), so finer boxes give finer reference
granularity, and 6,144 B is under the 32,768 B box cap with room to spare.
MBR ≈ **19.7 ALGO per committee** (400 µA/byte × 49,152 + 8 × 2,500), locked and
recoverable; holding current + next ≈ 39.4 ALGO. Boxes are deleted on retirement
(§8.6), refunding it.

### 8.3 The session

```
install_begin(period):
    require inst_state == IDLE
    require the trusted root for `period` is known:
        period == cur_period + 1  and  next_committee_root_trusted != 0
      (or the bootstrap case, where bootstrap() supplies it directly)
    inst_gen    := fresh generation id (monotonic counter)
    inst_root   := the trusted committee root established by a verified update
    inst_cursor := 0
    create boxes k:<inst_gen>:0..7 and s:<inst_gen>
    inst_state  := INSTALLING

install_chunk(index, compressed[k], uncompressed[k]):
    require inst_state == INSTALLING and index == inst_cursor
    for each member m in 0..k-1:
        i := index + m
        g1_bind(uncompressed[m], compressed[m])          # 1,966 -- THE trust boundary
        box_replace(k:<inst_gen>:<i//64>, 96*(i%64), uncompressed[m])
        merkleize_stack_push(sha256(compressed[m][0:32] ‖ compressed[m][32:48] ‖ 0*16))
        running_sum := ec_add(running_sum, uncompressed[m])
    inst_cursor += k

install_finalize(aggregate_compressed, aggregate_uncompressed):
    require inst_cursor == 512
    vector_root := merkleize_stack_finalize(depth=9)
    agg_leaf    := sha256(aggregate_compressed[0:32] ‖ aggregate_compressed[32:48] ‖ 0*16)
    require sha256(vector_root ‖ agg_leaf) == inst_root          # <<< THE check
    g1_bind(aggregate_uncompressed, aggregate_compressed)
    require aggregate_uncompressed == running_sum                # free cross-check
    write a:<inst_gen> := running_sum
    next_gen := inst_gen ; next_period := inst_period
    delete s:<inst_gen> ; inst_state := IDLE
```

Three properties this gets right:

1. **A partially installed committee is unusable.** `submit_update` selects a
   committee only from `cur_gen` / `next_gen`. `inst_gen` is written to `next_gen`
   **only** by `install_finalize`, after the root check. If the session is
   abandoned, its boxes are orphaned under a generation id nothing references
   (and `install_abort` deletes them, refunding MBR).
2. **Binding before the root is confirmed is safe.** `g1_bind` runs during
   `install_chunk`, against `compressed[m]` that is not yet proven to be in the
   committed committee. That is fine: the binding's *purpose* is to tie the
   uncompressed point to those 48 bytes, and the 48 bytes are tied to the trusted
   root at `install_finalize`. Composed, every stored key is the one the beacon
   chain committed to. If the final check fails, nothing was activated. **This
   ordering must not be "optimized" by skipping `g1_bind` and trusting the merkle
   root alone** — the root covers the *compressed* keys only, and the AVM cannot
   decompress (001 §4.2). Both halves are required.
3. **`A_total` is contract-computed, never relayer-supplied**, which is what makes
   the complement path (§5.4) as trustworthy as the direct one. The
   `aggregate_uncompressed == running_sum` assertion is a free 512-`ec_add`
   integrity check, and it also confirms the committed `aggregate_pubkey`
   (duplicated committee members are counted with multiplicity, exactly as
   `eth_aggregate_pubkeys` does).

### 8.4 Rollover

```
on a 2/3-finalized update whose signature period == cur_period + 1:
    require next_gen != 0                       # spec: next committee must be known
    retire_gen := cur_gen
    cur_gen    := next_gen ; cur_period := next_period
    next_gen   := 0
    schedule deletion of k:<retire_gen>:*, a:<retire_gen>
```

Box deletion is a separate `retire(gen)` method (permissionless, callable by
anyone, refunds MBR to the app account) rather than inline, because deleting 9
boxes inside an already-busy update transaction wastes budget the update needs.
`retire` asserts `gen != cur_gen and gen != next_gen and gen != inst_gen`.

### 8.5 Install cost

| line | per key | ×512 |
|---|---:|---:|
| `g1_bind` (measured 1,966; −44 routing amortised) | 1,922 | 984,064 |
| `box_replace` 96 B (**projected**, ~2× the measured 58-flat read) | 120 | 61,440 |
| pubkey leaf `sha256(48 B ‖ 16 zero)` + concat (**projected**) | 100 | 51,200 |
| `merkleize_stack_push` (measured marginal §2.6, upper end) | 195 | 99,840 |
| `ec_add` into `running_sum` (measured 246, blob-slice form) | 246 | 125,952 |
| loop + arg-decode glue (**projected**) | 60 | 30,720 |
| **per-key total** | **~2,643** | **1,353,216** |
| finalize (stack finalize, agg leaf, root compare, `g1_bind`, compare) | — | ~4,000 |
| **install total** | | **~1,357,000** |

At **180,192** net usable per group (§9.2): **8 groups**. Delivery is not the
binding constraint: `512 × 144 B = 73,728 B` at ~1,850 usable arg-bytes per txn
= 40 transactions = 2.5 groups' worth of the 16 available slots.

Fee: 8 groups × 272 app calls × 0.001 ALGO = **~2.18 ALGO per committee install**,
once per sync-committee period (`EPOCHS_PER_SYNC_COMMITTEE_PERIOD` 256 × 32 slots
× 12 s ≈ **27.3 hours**).

### 8.6 The alternative that was considered and rejected

**Scheme B — cache only the 512 *compressed* keys plus `A_total`, and `g1_bind`
the absentees on demand each update.** Install collapses to merkleization only
(~165,000, one group, ~0.24 ALGO) and MBR halves to ~9.9 ALGO, because
`512 × 48 = 24,576 B` replaces `512 × 96 = 49,152 B`.

| participation | Scheme A (this design) | Scheme B |
|---|---:|---:|
| install, per period | ~1,357,000 (8 groups) | ~165,000 (1 group) |
| update @ 99% (5 absent) | ~89,000 | ~101,000 |
| update @ 95% (26 absent) | ~93,000 | ~148,000 |
| update @ 90% (51 absent) | ~98,000 | ~205,000 → **2 groups** |
| update, worst case | **142,890 (bounded)** | ~1,160,000 → **7 groups** |

Converting budget to fees at the measured 97.4% donor efficiency
(≈ `budget × 1.466 × 10⁻⁶` ALGO), Scheme A costs `2.18 + 0.131·U` ALGO per period
and Scheme B `0.24 + f(participation)·U`. **Break-even is ~110 updates per
27.3-hour period at 99% participation (one update every ~15 minutes), but only
~23 updates at 95% participation** — the break-even is itself a function of a
variable neither module controls. **Scheme A is chosen anyway**, and that
sensitivity is the reason rather than an aside:

> In Scheme B the *per-update* cost is a function of participation, which is a
> property of the Ethereum network and can be *selected* by whoever chooses which
> update to relay. That turns a cost into a griefing/liveness lever: an adversary
> who influences update selection can push any single update past the one-group
> boundary. Scheme A's per-update cost is bounded at 142,890 for **every**
> participation level, which is the property that makes §9's decision a decision
> rather than an average.

Scheme A is also what M1 §4.5 already made normative ("bind once per committee,
not once per update") and what `g1_accumulate_negated` was built for. Recorded
here with real numbers so a future revisit is an informed one.

---

## 9. The group-sizing decision

### 9.1 Per-update budget

Mainnet, 512-member committee, Electra/Fulu gindices (169 finality / 87 next
committee). Measured lines are cited; **projected** lines are marked and are
2.6% of the worst-case total.

| line | source | typical (p=505) | **adaptive worst (p=257)** |
|---|---|---:|---:|
| ARC-4 routing + payload length guards | measured 44, ×~5 args | 250 | 250 |
| fork-table lookup ×2 | **projected** §4.4 | 200 | 200 |
| slot/period arithmetic, ordering asserts | **projected** | 300 | 300 |
| `hash_tree_root(BeaconBlockHeader)` + fork-data root + domain + signing root | **projected** §3.1 (9 `sha256` + chunking) | 900 | 900 |
| bitfield walk, 512 bits | measured 22.5/bit | 11,520 | 11,520 |
| participant gather + `ec_add` | measured 217/point | 1,302 | 55,118 |
| complement fixup (`g1_negate` + `ec_add`) | **projected**, `ec_add`=205 measured | 400 | 400 |
| **`hash_to_g2(signing_root, ETH_DST)`** | **measured 17,443** | 17,443 | 17,443 |
| **`verify_aggregate_signature`** | **measured 55,474** | 55,474 | 55,474 |
| finality branch, gindex 169 (depth 7) | measured 684 | 684 | 684 |
| next-committee branch, gindex 87 (depth 6) | measured 601 | 601 | 601 |
| state writes + event log | **projected** | 300 | 300 |
| **total** | | **89,374** | **143,190** |
| **+10% assembly allowance** | | 98,311 | **157,509** |

The allowance exists because these are per-primitive measurements from separate
programs, not one compiled M4 program; Puya will add inter-subroutine glue.

### 9.2 Budget available in one group

From §2.4 and §2.7, with `T` top-level app calls and `I ≤ 256` donor inner calls:

```
gross = (T + I) · 700
net   = gross − 18·I
```

| T | I | gross | issuance | **net usable** |
|---:|---:|---:|---:|---:|
| 1 | 256 | 179,900 | 4,608 | 175,292 |
| **8** | **256** | **184,800** | **4,608** | **180,192** |
| 16 | 256 | 190,400 | 4,608 | 185,792 |

### 9.3 The decision

> **A full sync-committee update — adaptive aggregation over 512 members, real
> `hash_to_g2` under the Ethereum DST, the 2-pair pairing, and both SSZ branch
> checks — fits in ONE 16-txn atomic group, at every participation level.**
>
> Worst case **157,509** against **180,192** available at `T=8, I=256`:
> **12.6% headroom**. Typical case 98,311: 45% headroom.
>
> Recommended group: **8 top-level app calls + 256 donor inner calls = 264 app
> calls = 0.264 ALGO** per update. The relayer may size `I` down for
> high-participation updates (`I=140` covers the typical case at 0.148 ALGO).

**The complement path is load-bearing for this result.** Direct-only aggregation
at `p = 512` costs `11,520 + 217·511 = 122,407` for the walk and gather alone,
giving a total of `198,559 × 1.10 = 218,415` — **over** the 185,792 absolute
ceiling. So:

> **Normative: `g1_accumulate_negated` / complement mode is not an optimisation.
> Removing it moves M4 from one atomic group to two.**

This supersedes M1 §9.2's provisional "~177,505 / 254 calls, 18 calls of
headroom, plausibly one group" — which was right in outcome and 10% optimistic in
margin, and did not include the bitfield walk (11,520) at all.

### 9.4 Non-budget group constraints

- **App args**: the payload is ~1,000 B in one transaction (§7.3). ✅
- **Box read budget**: 1,024 B per box reference, 8 references per top-level
  transaction. The adaptive worst case gathers ≤ 256 keys = **24,576 B** → 24
  references → 3 transactions' worth. At `T=8` we have 64 references = 65,536 B.
  ✅ (The `noop_budget` method exists to carry these references, §7.3.)
- **Inner-txn cap**: 256 per group, and we use exactly 256. Note this leaves no
  room for M4 to make *any* other inner call — including an inner call into M8.
  **M8 integration must therefore be by readonly getter in a later transaction of
  the same group, or by co-deployment, not by an inner call from
  `submit_update`.** Flagged for M8 in §12.
- **Fees**: 264 app calls × 1,000 µA; the outer transaction must carry pooled fees
  for its 256 inner calls (set inner `fee=0`, outer `fee=257,000`).

---

## 10. Edge cases

### 10.1 Too few participants

`popcount < MIN_SYNC_COMMITTEE_PARTICIPANTS (=1)` → reject before the pairing
(§6.1 step 11). `popcount == 0` additionally means the aggregate is the point at
infinity, which M1's `verify_aggregate_signature` rejects independently
(001 §7.1) — two independent controls, which is exactly why vector
`eth_fast_aggregate_verify_na_pubkeys_and_infinity_signature` fails closed on our
stack (§3.6). `1 <= popcount < 342` → the update verifies but advances nothing
(§6.3).

### 10.2 Adversarial update — the M1 T12 analogue

M1's T12 builds a fully forged committee, shows it passes
`g1_validate_wellformed_only` and produces a *genuinely valid* signature, and
shows `g1_bind` rejects it. **M4's boxes are the T12 defence made structural**:
the aggregation loop reads pubkeys only from `k:<cur_gen>:*`, which only
`install_chunk` writes, which only writes points that passed `g1_bind` against
compressed bytes that `install_finalize` proved merkleize to a root that
`submit_update` proved sits at a fork-gated gindex under a BLS-verified state
root. There is **no code path by which relayer-supplied bytes become a
committee key.**

The M4-specific attacks and their controls:

| attack | control |
|---|---|
| relayer supplies its own pubkeys inline | no such parameter exists; §7.3 |
| relayer supplies its own `gindex` | never accepted from calldata; gindex comes from the §4.3 table (M3 §6, normative) |
| relayer flips bits in `sync_committee_bits` to match a forged aggregate | the bitfield is covered by the signature; the aggregate is recomputed from it |
| relayer lies about `mode` | both modes compute the same point (§5.5) |
| relayer supplies a substituted `signature` | not committed to anything, so the pairing simply fails (001 §4.6); `ec_subgroup_check` rejects malformed G2 |
| relayer stuffs the normalized-branch padding slots | `assert_valid_normalized_merkle_branch` zero-checks them (003 §3.5) |
| relayer replays an old valid update | strict `finalized_slot > store.finalized_slot` monotonicity (§6.5) |
| relayer picks `signature_slot` in a period we have no committee for | committee selection asserts `period ∈ {store, store+1}` and `next_gen != 0` |
| relayer supplies a `next_committee_root` of its choosing | the branch check at gindex 87 under the BLS-verified `attested_state_root` pins it |

### 10.3 Period boundary crossed mid-session

An install session for period `P+1` is in flight when an update arrives whose
signature period is `P+1` (so the store wants to roll over). Rollover requires
`next_gen != 0`, which only `install_finalize` sets — so the rollover simply does
not happen and the update is verified against `current` (period `P`) or rejected
by the period rule. The session continues and completes normally; the next
qualifying update rolls over.

The pathological direction: an update arrives establishing a **different**
`next_committee_root` for the same period while a session is in flight. That
cannot happen honestly (the committee for a period is unique), so it means one of
the two updates is on a forked beacon chain. Rule: `install_begin` records
`inst_root`, and any subsequent update whose proven `next_committee_root` for the
same period differs from `inst_root` is **rejected** rather than allowed to
silently restart the session — a divergence at this point is a beacon-chain
reorg deeper than finality, which is a stop-the-bridge event, not a retry.
`install_abort` (governance) is the manual recovery.

### 10.4 Zero / empty finalized header

The spec permits `update_finalized_slot == GENESIS_SLOT` with an empty
`finalized_header` and `finalized_root = Bytes32()`; the vendored Electra/Fulu
`finality_root_merkle_proof` vectors genuinely have an all-zero leaf (M3 §7.5).
M3 accepts it and explicitly hands M4 the obligation to reject it as a *state
transition*:

- all-zero `finalized_header` → the branch is verified against a zero leaf (valid
  SSZ), the update may still verify, but **`fin_root`/`fin_slot` are not
  advanced** and no rollover occurs.
- M8 must likewise refuse to anchor a zero root (§7.4).

### 10.5 Fork boundary between the signing committee and the installed committee

`fork_version` is looked up at `epoch(signature_slot − 1)` and the gindices at
`epoch(attested_header.slot)` (§4.4). Around a fork these differ. Three real
cases the implementation must handle without special-casing, because two
independent lookups already do:

1. Both slots pre-fork → old version, old gindices.
2. `attested_slot` pre-fork, `signature_slot` at/after → old gindices, and
   `signature_slot − 1` may still be pre-fork ⇒ old version. The `−1` is what
   makes this land correctly.
3. Both post-fork → new version, new gindices.

A committee that *signs* under fork F may be proving a `next_sync_committee` whose
inclusion gindex belongs to F+1's `BeaconState` layout — perfectly legal, and the
`attested_slot` lookup handles it. The committee's *members* have no fork
affiliation at all; only the tree layout and the domain do.

### 10.6 Sync-committee members appear more than once

`get_next_sync_committee` samples with replacement, so the same pubkey can occupy
several indices. Storage is per **index**, never per key, and `A_total` counts
multiplicity — which is why `A_total == aggregate_pubkey` holds (§8.3). Any
"deduplicate the committee" optimization is a correctness bug.

### 10.7 Immutability of `genesis_validators_root`

`gvr` is the anchor of every domain this contract will ever compute. It is
written once at `create` and there is **no setter**. A wrong `gvr` makes every
update fail (fail-closed) rather than accept a wrong chain, and the fix is a
redeployment. Do not add a governance setter "for convenience": a mutable `gvr`
lets governance re-point the entire bridge at a different Ethereum network, which
is a strictly larger power than appending a fork row.

### 10.8 `signature` is delivered uncompressed and is not committed

Per 001 §4.6 the G2 signature needs only well-formedness, which
`verify_aggregate_signature` provides (`ec_subgroup_check`, infinity rejection).
But note for M9/M8: because the wire form is uncompressed, **two byte-distinct
payloads can carry the same signature** only if one is malformed (the
uncompressed encoding is canonical for a given point). If a canonical update hash
is ever needed for dedup or ranking, compute it over `g2_compress(signature)`
(measured 92 for the G1 form; the G2 form is the same shape) together with the
zero-checked normalized branches (003 §3.5) — those two together make the
encoding canonical.

---

## 11. Test plan

Real consensus-spec vectors are **mandatory** here, not optional — that is the
whole reason this module exists, and `ARCHITECTURE.md` makes it an approval
condition. Vendored set and provenance: §3.3 and
`tests/fixtures/sync_committee/consensus-spec-tests/RELEASE.txt`.

| # | test | tier | asserts | status now |
|---|---|---|---|---|
| **T1** | **Signing root vs real vectors** | offline | For every `minimal/*/light_client/sync/pyspec_tests/*` case, walk `steps.yaml`, construct the signing root per §3.1, and assert `py_ecc.G2ProofOfPossession.FastAggregateVerify` succeeds for **every** update. | **altair `light_client_sync`: 8/8 passing** (§3.4). Remaining forks need a `LightClientHeader` parser (Capella+ headers are variable-size); use `remerkleable` containers. |
| **T2** | **Header root oracle** | offline | `hash_tree_root(attested_header.beacon)` equals the block root in the update's **filename**, and `hash_tree_root(finalized_header.beacon)` equals `steps.yaml`'s `checks.finalized_header.beacon_root`. | **passing, 8/8** (§3.4) |
| **T3** | **Fork digest cross-check** | offline | `compute_fork_data_root(fork_version, gvr)[0:4]` equals `meta.yaml`'s `bootstrap_fork_digest` / `store_fork_digest`. Catches a wrong fork version or a wrong `gvr` independently of BLS. | **passing** (§3.1 trap 2) |
| **T4** | **DST vs the official BLS suite** | live | All 12 `eth_fast_aggregate_verify` cases through aggregate → `hash_to_g2(msg, ETH_DST)` → pairing. | **10/12 agree**; the 2 deviations are T7's subject (§3.6) |
| **T5** | **Bitfield bit order** ⚠️ highest-value negative test | live | An intentionally asymmetric bitfield (e.g. members `{0, 1, 8, 63, 511}`) selects exactly those members. Assert that the **byte-order-only** mapping (`getbit(bits, i)` without the §5.1 remap) selects a *different* set and fails verification. A fully-participating committee cannot catch this. | to write |
| **T6** | **End-to-end on-chain** | live | The §3.5 flow as a contract test: real committee installed, real update submitted, `verify_aggregate_signature` true, both branches verified, state advanced. | **the primitive-level version is passing** (§3.5) |
| **T7** | **Infinity-pubkey rejection at the right layer** | live | `eth_fast_aggregate_verify_infinity_pubkey` run against **`install_chunk`**, not against `g1_sum_blob`: assert `g1_bind` rejects the infinity key so the committee can never install. Documents §3.6 deviation 1 as closed by M4. | to write |
| **T8** | **Fork-gindex table vs vectors** | offline | For each vendored fork dir, `table_lookup(epoch)` returns the `leaf_index` found in that fork's `proof.yaml` (§4.2), and the branch folds to the state root. Fails loudly if a row is ever edited. | table read out of vectors already (§4.2) |
| **T9** | **Fork-boundary resolution** | offline | Synthetic slots either side of `ELECTRA_FORK_EPOCH`: assert `fork_version` uses `signature_slot − 1` and gindices use `attested_slot`, including the single update where the two disagree (§10.5 case 2). |  to write |
| **T10** | **Trust-boundary attack (M4's T12)** | live | Forge a whole committee with attacker keys; show the *update* verifies against the forged committee in isolation, then show `install_finalize`'s merkle-root check rejects installing it, and that `submit_update` never touches any key outside `k:<cur_gen>:*`. Cross-references 001 T12. | to write |
| **T11** | **Rollover & session** | live | Multi-period walk over a vendored `light_client_sync` case: install, activate, roll over, retire; a partially installed generation is unusable; `install_chunk` out of order is rejected; a period boundary crossed mid-session behaves per §10.3. | to write |
| **T12** | **Replay / monotonicity** | live | Re-submitting a previously accepted update is rejected; an update with `finalized_slot <= store.finalized_slot` does not advance state. | to write |
| **T13** | **Zero finalized header** | live | Update with an all-zero `finalized_header` verifies but advances nothing and emits no anchorable root (§10.4). | to write |
| **T14** | **Budget regression** | live | Re-assert every §2 figure with the real simulate response recorded into `tests/fixtures/sync_committee/*.json`, plus the §9.1 assembled total measured on the real contract. **The §9.1 total measured against a real M4 program is the merge gate for the group-count claim.** | to write |
| **T15** | **`is_better_update` non-implementation** | offline | The vendored `update_ranking` vectors are parsed and *skipped* with an explicit reason string, so that §6.6's decision is visible in the test output rather than silently absent. | to write |

---

## 12. Open questions resolved, and raised

### 12.1 M4's own ROADMAP row

**Q1 — "Real BLS domain-separation tag + signing-root vs. consensus-spec test
vectors (spike never tested this)." RESOLVED.** §3. The DST is
`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, validated against the official
`eth_fast_aggregate_verify` suite on-chain (10/12, with two documented,
unreachable deviations). The signing root is
`sha256(hash_tree_root(attested_header.beacon) ‖ compute_domain(0x07000000,
fork_version, genesis_validators_root))` with the fork version taken at
`signature_slot − 1` — validated on 8/8 real updates across 5 sync-committee
periods, with two independent oracles (filename block roots, `steps.yaml`
expectations), and then verified end to end on the AVM.

**Q2 — "Finalize 1-vs-2-group call with real G2 numbers (~282 calls / 2
groups)." RESOLVED: ONE group.** §9. Worst case 157,509 (including a 10%
assembly allowance) against 180,192 net usable at `T=8, I=256`. The spike's
282-call/2-group estimate is beaten by: M1's `ec_add` chain over MSM, the
adaptive complement path (without which it would still be two groups), the
cached-committee design that removes ~1.36 M budget from the per-update path, and
the newly measured 97.4% donor efficiency. All four contributions are quantified
in §9.3.

### 12.2 Questions this pass closed for other modules

- **M1 P9 at real scale — CLOSED.** 42-point `ec_add` chain 10,182 vs 42-point
  MSM 10,611; loop glue **41/iteration** against M1's 45 threshold. Chain stays
  the default; margin is 9%, not the "10–20 glue" M1 expected (§2.3).
- **M1 P11 — CLOSED.** Donor inner call: 18 to issue, +700 pooled, **net +682**
  (§2.4). One group's true net budget is 185,792, not 190,400.
- **M1 P12b / M3 Q1 (box-read budget) — CLOSED.** `box_extract` is **flat at 58**
  including ARC-4 routing, from 96 B to 4,032 B (§2.2). Box *read budget* (bytes
  per reference) remains a separate, non-opcode accounting (§9.4).
- **M3 Q2 (does Puya codegen inflate the §2.5 model?) — CLOSED.** Yes, by ~41%,
  and the `2·z` term disappears: **`103 + 83·depth`, exact** (§2.5).
- **M1 §10.1's merkleization handoff — priced at real Puya cost.** ~172–195 per
  leaf, not M3's hand-TEAL 67.5; `hash_tree_root(Vector[BLSPubkey,512])` is
  **projected** ~146,000, not 69,078 (§2.6). Not load-bearing (§8.5), but M3's
  §2.7 figure should not be quoted as a Puya cost.

### 12.3 Questions raised for M8

1. **No inner call available.** `submit_update` uses all 256 of the group's inner
   transactions for budget donation. M8 cannot be invoked by an inner call from
   it. Integrate by readonly getter in a later group transaction, or co-deploy
   (§9.4).
2. **M4 does not validate `LightClientHeader.execution`.** M4 takes the beacon
   header only; `is_valid_light_client_header` (the execution-branch check) is
   **not** performed. M8 owns it along with the execution gindices (§7.2).
3. **Zero finalized roots reach the boundary.** M8 must refuse to anchor them
   (§10.4).
4. **Anchor key.** M8's history should key on `finalized_slot`, which is strictly
   increasing by construction (§6.5).
5. **M4 keeps only the latest tuple.** All retention/eviction policy is M8's
   (its own ROADMAP open question) — M4 imposes no constraint beyond emitting the
   event on every advancing update.

### 12.4 Questions raised for M9

1. **M9 owns wall-clock sanity.** M4 cannot check `current_slot >= signature_slot`
   (§6.5). A relayer must not forward updates it knows to be from the future.
2. **M9 owns off-chain decompression** of 512 committee pubkeys and the
   signature, and must use the AVM limb order for G2 (`c0` first — 001 §3.3),
   which is the **reverse** of every reference library's serializer.
3. **M9 owns `mode` selection and donor sizing.** Both are pure fee optimizations
   with no safety content (§5.5, §9.3); a relayer that always sends `mode=0` and
   `I=256` is correct, just more expensive.
4. **M9 owns install chunking.** `install_chunk` takes `(index, compressed[k],
   uncompressed[k])` with `index` matching the contract's cursor exactly; the
   relayer must use the same `chunk_count` rule as the contract (001 §5.2).
   ~12 members per transaction at 144 B each within the 2,048 B arg cap.
5. **M9 must handle install-session abandonment** across an 8-group session
   (§8.5) — a failed group leaves the cursor where it was, and resumption is a
   retry from `inst_cursor`, not a restart.

---

## 13. File layout

```
contracts/sync_committee/
    __init__.py
    constants.py       # DOMAIN_SYNC_COMMITTEE, ETH_DST, SYNC_COMMITTEE_SIZE,
                       # SLOTS_PER_EPOCH, EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
                       # MIN_SYNC_COMMITTEE_PARTICIPANTS -- literals + accessors
    forks.py           # §4.3 table encode/decode/lookup, append validation
    header.py          # §7.2 SSZ header chunking, hash_tree_root, signing root
    bitfield.py        # §5.1 bit-order remap, §5.3 fused walk (both modes)
    install.py         # §8.3 session state machine
    verifier.py        # §7.3 SyncCommitteeVerifier ARC4Contract
tests/sync_committee/
    reference.py           # pure-Python mirror: domain, signing root, bitfield,
                           # committee htr -- checked against py_ecc/remerkleable
    vectors.py             # loaders for the vendored suites (raw snappy!)
    test_signing_root.py   # T1-T3
    test_dst.py            # T4
    test_bitfield.py       # T5
    test_end_to_end.py     # T6, T10
    test_install.py        # T7, T11
    test_forks.py          # T8, T9
    test_lifecycle.py      # T12, T13, T15
    test_budget.py         # T14
tests/fixtures/sync_committee/
    consensus-spec-tests/  # vendored, release-pinned (RELEASE.txt)
    *.json                 # pinned inputs, expected roots, measured budgets
```

---

## 14. Measurement backlog

No design decision above rests on an unmeasured number, but these must land with
the implementation.

| # | probe | blocks |
|---|---|---|
| R1 | **The assembled §9.1 total, measured on the real M4 program** | the one-group claim's merge gate (T14) |
| R2 | `hash_tree_root(Vector[BLSPubkey,512])` at real Puya cost — extrapolated at ~146,000 ± 25,000 (§2.6) | install group count (8 → 7 or 9); not the per-update decision |
| R3 | `box_replace` write cost (96 B and ~1,900 B) | §8.5's 120/key projection |
| R4 | `g1_negate` + complement fixup, measured | §9.1's 400 projection |
| R5 | Signing-root construction (header merkleize + fork data + domain), measured | §9.1's 900 projection |
| R6 | Fork-table linear scan, measured at 8 rows | §9.1's 200 projection |
| R7 | Real box **read budget** consumption for 256 × 96 B extracts across 8 boxes | §9.4's reference count |
| R8 | Byte-table popcount (64 iterations) vs the measured 6,703 bit loop | only if a standalone popcount is ever needed (§5.2) |

---

## 15. Implementer checklist (normative MUSTs)

1. **The DST is `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`**, declared once in
   `constants.py` and passed to `hash_to_g2` at the single call site. Never
   hard-code it inside M1 (§3.2).
2. **The fork version comes from `epoch(max(signature_slot,1) − 1)`; the gindices
   come from `epoch(attested_header.slot)`.** Two lookups, two slots (§4.4). Do
   not collapse them.
3. **`slot` and `proposer_index` chunks are little-endian**; `itob` is big-endian
   (§3.1 trap 1).
4. **`compute_domain` truncates the fork-data root to 28 bytes** (§3.1 trap 2).
5. **The bitfield bit-order remap is `(i//8)*8 + 7 − (i%8)`** (§5.1), and the
   popcount comes out of the aggregation walk — **never** a separate pass (§5.2).
6. **`gindex` is never read from calldata.** Always from the §4.3 table. This is
   M3 §6's normative requirement and it is the module's security property.
7. **Committee keys enter box storage only through `g1_bind`**, and the
   aggregation loop reads only from `k:<cur_gen>:*` / `k:<next_gen>:*` (§8.3,
   §10.2).
8. **`install_finalize` is the only writer of `next_gen`.** A generation that has
   not passed the merkle-root check must be unreachable from `submit_update`
   (§8.3).
9. **Keep the complement path.** Removing it costs a second atomic group (§9.3).
10. **`A_total` is contract-computed at install, never relayer-supplied** (§8.3).
11. **Store per index, never per key** — committees contain duplicates (§10.6).
12. **A zero finalized root verifies but never anchors** (§10.4).
13. **`genesis_validators_root` has no setter** (§10.7).
14. **The `.ssz_snappy` fixtures are raw snappy, not framed**
    (`cramjam.snappy.decompress_raw`) (§3.3).
15. **Do not append the Gloas fork row** until its gindices are confirmed against
    vendored Gloas vectors (§4.5).
16. Every budget number in code comments or docs must cite a fixture containing a
    real simulate response (`ARCHITECTURE.md`).

---

## Appendix A — the probe app behind §2.4, §5.2 and §5.3

Compiled with `puyapy 5.9.0`, deployed to dev-mode algod, driven through
`simulate`. Throwaway measurement code, **not** an implementation sketch — the
real `bitfield.py` should read its committee-size bound from `constants.py` and
must not take `count` from calldata.

```python
from algopy import ARC4Contract, Bytes, UInt64, arc4, itxn, op, urange
from algopy.op import EC, EllipticCurve


class M4Probe(ARC4Contract):
    @arc4.abimethod
    def box_create(self, name: arc4.DynamicBytes, size: arc4.UInt64) -> arc4.Bool:
        return arc4.Bool(op.Box.create(name.native, size.native))

    @arc4.abimethod
    def box_write(self, name: arc4.DynamicBytes, offset: arc4.UInt64,
                  chunk: arc4.DynamicBytes) -> arc4.Bool:
        op.Box.replace(name.native, offset.native, chunk.native)
        return arc4.Bool(True)

    @arc4.abimethod
    def agg_bitfield(self, bits: arc4.DynamicBytes, name: arc4.DynamicBytes,
                     start: arc4.UInt64, count: arc4.UInt64) -> arc4.DynamicBytes:
        b = bits.native
        acc = op.bzero(UInt64(96))
        have = False
        for i in urange(start.native, start.native + count.native):
            # SSZ Bitvector: bit i is byte i//8, bit i%8 from that byte's LSB.
            # AVM getbit counts from the MSB of byte 0.
            if op.getbit(b, (i // 8) * 8 + 7 - (i % 8)) != 0:
                pk = op.Box.extract(name.native, i * 96, UInt64(96))
                if have:
                    acc = EllipticCurve.add(EC.BLS12_381g1, acc, pk)
                else:
                    acc = pk
                    have = True
        return arc4.DynamicBytes(acc)

    @arc4.abimethod
    def popcount(self, bits: arc4.DynamicBytes, count: arc4.UInt64) -> arc4.UInt64:
        b = bits.native
        n = UInt64(0)
        for i in urange(count.native):
            n += op.getbit(b, i)
        return arc4.UInt64(n)

    @arc4.abimethod
    def issue_donors(self, app: arc4.UInt64, n: arc4.UInt64) -> arc4.UInt64:
        for _i in urange(n.native):
            itxn.ApplicationCall(app_id=app.native, fee=0).submit()
        return arc4.UInt64(n.native)
```

The donor callee is a two-line app (`#pragma version 10 / int 1 / return`);
`issue_donors` is called with outer `fee = 1000·(n+1)` so the inner `fee=0` calls
are covered by fee pooling.

---

## Appendix B — reproducing everything in §2 and §3

1. Bring up dev-mode `algod` per `tests/fixtures/spike-reference/README.md`
   (ports 4051/4052, token `64×'a'`, `EnableDeveloperAPI=true`, protocol
   `future`).
2. Vendor the vectors (also recorded in
   `tests/fixtures/sync_committee/consensus-spec-tests/RELEASE.txt`):
   ```
   curl -sL https://github.com/ethereum/consensus-spec-tests/releases/download/v1.6.0-beta.0/general.tar.gz \
     | tar -xz --wildcards 'tests/general/*/bls/eth_fast_aggregate_verify/*'
   curl -sL https://github.com/ethereum/consensus-spec-tests/releases/download/v1.6.0-beta.0/minimal.tar.gz \
     | tar -xz --wildcards '*/light_client/sync/*' '*/light_client/update_ranking/*'
   ```
3. Pin the spec constants from `ethereum/consensus-specs` tag `v1.6.0-beta.0`:
   `configs/mainnet.yaml`, `presets/mainnet/altair.yaml`,
   `specs/{altair,electra}/light-client/sync-protocol.md`.
4. M1/M3 primitive costs: `tests/bls/conftest.py`'s `LiveHarness` against
   `contracts/primitives/bls/harness.py`, and
   `python -m pytest tests/ssz/test_budget.py -s` for §2.5/§2.6.
5. §2.3's 42-point figures need the **box-staging** path
   (`box_stage_create` → 3 × `box_stage_write` → `g1_sum_blob_from_box` /
   `g1_msm_accumulate_points_from_box`) in one simulated group — a 4,032-byte
   blob cannot be delivered through the 2,048-byte app-arg cap.
6. §2.4, §5.2, §5.3: compile Appendix A with `puyapy`, deploy alongside a trivial
   donor app, fund the probe app (~8 ALGO) for the 6,144-byte box MBR.
7. Read `app-budget-consumed` **per transaction**
   (`txn-groups[0].txn-results[i]`), not the group total.
8. Decode `arc4.Bool` returns as **`0x80` = true**, not `0x01`. (Reading it as
   `0x01` makes a genuinely passing pairing look like a failure — it cost this
   design pass an hour.)

## Appendix C — raw measured values

```
ARC-4 routing floor (chunk_count)                              44
assert_g1_blob_from_box  (96 B / 2,016 B / 4,032 B)            58 / 58 / 58
g1_sum_blob_from_box     n=1,2,11,21,32,42        96, 342, 2556, 5016, 7722, 10182
g1_msm_accumulate_points_from_box  n=21 / 42                   8,616 / 10,611
g1_compress                                                    92
g1_bind                                                        1,966
expand_message_xmd_sha256(32 B, 43 B DST, 256)                 655
hash_to_g2(32 B, ETH_DST)                                      17,439 / 17,443
verify_aggregate_signature (real signature -> 0x80)            55,474
M4Probe.agg_bitfield, 64 bits, p=0,1,16,32,48,64
                                  1486, 1499, 4754, 8226, 11698, 15170
M4Probe.popcount, 64 / 512 bits                                879 / 6,703
M4Probe.issue_donors, n=0,1,2,4,8                              37, 55, 73, 109, 181
SSZBenchmark verify_branch, gindex 25/54/105/169               435 / 518 / 601 / 684
SSZVerifier.verify_branch (ARC-4 wrapper)                      644
MerkleizeBenchmark, n=4,8,16,32,63          1103, 1933, 3495, 6521, 11839
```
