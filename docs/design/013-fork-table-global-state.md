# 013 — M4/M8 revision: the fork table moves from box storage to global state

**Status**: Design drafted, awaiting human review.
**Type**: **Revision** of two already-implemented, already-live-tested modules
(M4 `SyncCommitteeVerifier`, M8 `TrustedRootAnchor`) — *not* a new module. See
§14 for how this is to be reflected in `ROADMAP.md`.
**Revises**: [004 §4.3/§4.4](004-sync-committee.md) (M4's fork table),
[008 §3.3/§6.3](008-trusted-root-anchor.md) (M8's fork table),
[010 §4/§5.2/§5.3/§7.1](010-deployment-tooling.md) (the create-time MBR model
and the predict-fund-create recipe), [009 §7.4/§7.5](009-relayer-client.md)
(the box-reference planner).
**Depends on**: nothing new. Every mechanism below already exists in the
installed toolchain (`puyapy` 5.9.0) and has been exercised in this pass.
**Consumed by**: the first real mainnet deployment of M4 and M8 — which is
the only reason this document exists.
**Design-time convention, inherited**: every number below is labelled
**measured** (a real command run during this design pass, cited to the command
and its real output) or **projected** (an estimate this document owns, which
the implementation pass must replace with a real result).

---

## 0. The question, stated first

On 2026-08-09 the first real mainnet deployment of M4 and M8 was attempted. It
failed **40+ consecutive times**, and two of those attempts stranded
~0.335 ALGO each in an address that will never become an application account.
Nothing was wrong with the contracts, the deploy tooling, the funding amounts,
or the operator. The failure is structural, and this is the whole of it:

> `create()` creates a box. A box's MBR is charged to the **application's own
> account**. An application has no account until its id is assigned. Its id is
> assigned only when the create transaction is *confirmed*. So the funding must
> be sent to an address that is *predicted*, and on a busy public network the
> prediction races every other app and asset creation on Earth.

`deploy/create.py::predict_fund_and_create` implements the standard mitigation
(simulate → learn the would-be id → fund `id + 1` → submit the real create →
`CreateRaced` if the id moved). It is correct, it is bounded, it refuses to
retry — and on mainnet it still loses the race almost every time, because the
window between the `simulate` and the real `create` spans real rounds.

A factory contract (a helper app creating the child by inner transaction and
funding it atomically in the same execution) was tried and hit a *harder* wall:
Algorand requires every box access to be declared in advance in a box-reference
array naming the box's **owning app id**, and there is no way to name the app id
of an application that does not exist yet within the same execution. That is an
AVM-level limitation on inner transactions, not a tooling gap.

So the real question is not "how do we win the race?" It is:

> **Why is there a race at all?** The *only* thing on M4's and M8's create path
> that needs the app's own account funded before the app exists is a 576-byte /
> 320-byte fork table. Nothing else in either `create()` touches the app
> account.

**The answer this document adopts**: delete the box. Put the fork table in
global state. Global-state MBR is charged to the **creator** — an account that
already exists, whose address is already known, and which needs no prediction.
The mechanism that produces the race is removed, not worked around. `create()`
then needs **zero** pre-funding on the app account, `predict_fund_and_create`'s
`ok_unfunded` branch takes over by itself, and `CreateRaced` becomes structurally
unreachable for M4 and M8.

Neither contract has ever been deployed to mainnet, so there is no
backward-compatibility cost, no migration of live state, and no deployed
counterparty pinning either program hash. This is the cheapest moment this
change will ever be available. It gets more expensive forever after the first
mainnet create lands.

**The price**, computed independently in §4 (**measured**, via
`deploy.mbr.global_state_mbr`): **+832,200 µALGO** total, one-time, paid by the
creator across both contracts. That is 0.83 ALGO to permanently delete a failure
mode that has already cost 0.67 ALGO and an entire evening.

---

## 1. Scope, non-goals, trust preconditions

### 1.1 In scope

1. `contracts/sync_committee/forks.py` and `contracts/state_anchor/forks.py` —
   the storage mechanism of the fork-activation table, and only that.
2. `contracts/sync_committee/verifier.py` / `contracts/state_anchor/anchor_app.py`
   — the removed `forks_box_create()` call in `create()`, and a new
   `state_totals=` class option (§3.4).
3. `contracts/state_anchor/constants.py` — the box-name/box-size constants.
4. `deploy/plans/m4.py`, `deploy/plans/m8.py`, `deploy/schema/generate.py`, and
   the two regenerated `*.schema.json` artifacts.
5. `relayer/group/boxes.py` (the box-reference planner), `relayer/client.py` and
   `relayer/drivers/m8_anchor.py` (their real call sites).
6. Every test that names the `forks`/`forks8` box (§7), and the three
   operator-facing docs that quote its MBR (§7.4).

### 1.2 Non-goals

* **No change to what the table means, or to any validation it performs.** Epoch
  monotonicity, sentinel-epoch rejection, capacity, gindex sanity, the
  pre-Altair "carries no gindices" rejection, and M8's `N17` no-active-row
  rejection are all untouched. §3.3 proves this line by line; G4-R13 tests it.
* **No change to the row encodings.** M4's row stays 36 B in the same field
  order; M8's stays 40 B. A row that is byte-identical today stays byte-identical.
* **No change to `FORK_TABLE_CAPACITY`** (16 for M4, 8 for M8). §3.5.4 records
  that lowering it is a real, available MBR knob and explains why this pass
  declines to pull it.
* **No change to `deploy/create.py`.** §5.4 shows why: it already handles the
  zero-pre-funding case, so the fix lands by making that branch the one M4/M8
  take.
* **No other box family is touched.** M4's `k:`/`s:`/`a:` boxes and M8's
  `h:`/`p:` boxes stay boxes; they are created *after* the app exists, by
  ordinary calls from a funded app account, and have never had this problem.
* **No mainnet deployment in this pass.** This document ends at "the revised
  contracts are re-proven against real dev-mode algod and the schema artifacts
  are regenerated and CI-diffed."

### 1.3 Trust preconditions

The fork table is a trust boundary: it is the *only* source of the
`fork_version` M4 checks a BLS signature against, and the *only* source of the
gindices M4 and M8 check Merkle branches against (004 §15 item 6, 008 §3.4's
`N-FORK`). Two properties must survive this change untouched, and both are
gated in §12:

* **P1 — governance-only, append-only, strictly-increasing.** Only
  `append_fork_row` writes; only `gov` may call it; every write is at index
  `fork_count` and bumps it; `activation_epoch` must strictly exceed the
  previous row's.
* **P2 — a lookup selects exactly the row it selects today.** For any table and
  any epoch, `lookup_fork_version` / `lookup_gindices` / `lookup_row` must return
  exactly what the box-backed implementation returns, including the failure cases.

A third precondition is new to this design and is called out because it did not
exist under box storage:

* **P3 — no key aliasing.** The row key derives from a *single index byte*
  (§3.1). Aliasing would let row `i` and row `i + 256` collide. §9.1 proves it
  cannot arise at capacity 16/8, and §17 requires a compile-time guard so a
  future capacity raise cannot silently break it.

---

## 2. What exists today — measured

**Measured** (`grep -rn` across the repo this pass; `git log` head `dc8a719`):
31 files reference the fork table or its box. The two `forks.py` modules are
structurally identical:

| Subroutine | M4 (`contracts/sync_committee/forks.py`) | M8 (`contracts/state_anchor/forks.py`) | Storage-dependent? |
|---|---|---|---|
| `forks_box_create()` | `op.Box.create(b"forks", 576)` | `op.Box.create(b"forks8", 320)` | **entirely** — deleted |
| `_row_offset(index)` | `index * 36` | `index * 40` | **entirely** — replaced by `_row_key` |
| `_read_row(index)` | `op.Box.extract` + 5 decodes | `op.Box.extract` + 5 decodes | **the fetch only**; decodes unchanged |
| `append_fork_row(...)` | 4 asserts + encode + `op.Box.replace` | 6 asserts + encode + `op.Box.replace` | **the write only**; asserts/encode unchanged |
| `_find_row_index_for_epoch(...)` | linear scan over `_read_row` | linear scan over `_read_row` | **no** |
| `lookup_fork_version` / `lookup_gindices` | asserts + `_read_row` | — | **no** |
| `lookup_row` | — | asserts + `_read_row` | **no** |

Real constants (**measured**, read from the files):

| | M4 | M8 |
|---|---|---|
| `FORK_ROW_BYTES` | 36 | 40 (`constants.py`) |
| `FORK_TABLE_CAPACITY` | 16 | 8 (`constants.py`) |
| box name / size | `b"forks"` / 576 B | `b"forks8"` / 320 B |
| declared global schema (ARC-56) | `{ints: 13, bytes: 7}` | `{ints: 9, bytes: 1}` |
| compiled approval | 6,980 B | 3,027 B |

The existing global keys, **measured** by decoding
`contracts/*/[…].arc56.json`'s `state.keys.global[*].key` base64 this pass:

* M4 (20 keys): `gov`, `gvr`, `fin_slot`, `fin_root`, `fin_state_root`,
  `att_slot`, `att_state_root`, `cur_gen`, `cur_period`, `next_gen`,
  `next_period`, `next_committee_root_trusted`, `next_committee_root_period`,
  `inst_state`, `inst_gen`, `inst_period`, `inst_root`, `inst_cursor`,
  `fork_count`, `gen_counter`.
* M8 (10 keys): `gov`, `m4_app`, `ring_size`, `ring_cursor`, `hi_block`,
  `hi_slot`, `n_anchored`, `frozen`, `conflict`, `fork_count`.

**The shortest key in either contract is 3 bytes (`gov`).** This is the
collision argument in §3.1, and it is a *measured* fact about the real
artifacts, not an inspection of the source by eye.

---

## 3. The replacement mechanism

### 3.1 The key scheme — validated, with one correction

The sketch this pass inherited was `Bytes(b"f") + op.itob(index)[7:8]` for M4 and
`Bytes(b"g") + op.itob(index)[7:8]` for M8. **Adopted unchanged**, for three
reasons that were checked rather than assumed:

1. **It cannot collide.** Every existing global key in both contracts is ≥ 3
   bytes (§2, measured); every row key is exactly 2. No 2-byte string is a
   3-byte string.
2. **It matches the codebase's own existing convention.** `contracts/
   sync_committee/install.py` already names key boxes `b"k:" + itob(gen) +
   itob(j)[7:8]` — a raw low-order index byte. Using the same idiom for row keys
   means one convention in the codebase, not two.
3. **Key length is free.** Unlike box MBR (`2,500 + 400 × (len(name) +
   len(value))`), global-state MBR is charged **purely by declared slot count**
   (`100,000 + 28,500 × n_ints + 50,000 × n_bytes`, `deploy/mbr.py`). A 2-byte
   key and a 62-byte key cost exactly the same. There is therefore no reason to
   optimise the key, and no reason to make it printable at the cost of on-chain
   opcodes.

**One correction to the brief's framing**: the distinct prefixes `f` (M4) and
`g` (M8) are *not* required for correctness — the two tables live in two
different applications and could both use `f`. They are kept distinct anyway
because `deploy inspect` prints both contracts' state through the same code path
and a distinct prefix makes a mis-attributed dump obvious at a glance. This is a
debuggability choice, and the doc should say so rather than implying a
correctness need.

**Aliasing** (P3): `op.itob(index)[7:8]` keeps only the low byte, so index `i`
and `i + 256` would produce the same key. At capacity 16 and 8 this is
unreachable (§9.1), but it is a real cliff for a future capacity raise, so §17
item 3 makes it a compile-time guard.

### 3.2 The API — checked against the real installed stubs

**Measured**, `/home/mark/.local/lib/python3.13/site-packages/algopy-stubs/op.pyi`,
class `AppGlobal`:

```
get_bytes(a: BytesBacked | bytes, /) -> Bytes
get_ex_bytes(a: Application | UInt64 | int, b: BytesBacked | bytes, /) -> tuple[Bytes, bool]
put(a: BytesBacked | bytes, b: Bytes | UInt64 | ..., /) -> None
delete(a: BytesBacked | bytes, /) -> None
```

**Correction to the sketch, and it matters.** The brief proposed reading with
`op.AppGlobal.get_bytes(key)`. The stub's own docstring for `get_bytes` says:

> "The value is zero (of type uint64) if the key does not exist."

That is `app_global_get`'s real behaviour: on a missing key it pushes a **uint64
zero**, not an empty byte string. A `Bytes`-typed read of a missing key therefore
does not return `b""` — it returns a value of the *wrong AVM type*, and the first
`extract`/`btoi` that touches it fails with an opaque type error rather than a
named assertion. Under box storage, an out-of-range read failed cleanly on the
box's own bounds check. Losing that would be a small but real regression in
failure legibility on a trust-boundary read path.

**This design uses `get_ex_bytes(0, key)` instead**, whose second return value is
an explicit `exists` flag (app index `0` = the current application). `_read_row`
asserts on it. Same opcode cost class (`app_global_get_ex`, cost 1, same as
`app_global_get`), strictly better failure behaviour, and it restores a named
assertion in place of the box bounds check that is being removed.

`_read_row` additionally asserts `raw.length == FORK_ROW_BYTES`. This is
defence-in-depth with a specific job: it makes any future divergence between the
declared row size and a stored row a *loud, named* failure at the read, rather
than a silent mis-slice of the trailing gindex fields.

### 3.3 Exactly what changes, and exactly what does not

The change was **applied for real** to a scratchpad copy of the contracts this
pass and compiled (§3.6). The complete diff to `contracts/sync_committee/forks.py`
is:

```diff
 FORK_ROW_BYTES = 36
 FORK_TABLE_CAPACITY = 16
-FORKS_BOX_NAME = b"forks"
-FORKS_BOX_BYTES = FORK_ROW_BYTES * FORK_TABLE_CAPACITY  # 576 B
+FORK_ROW_KEY_PREFIX = b"f"

 @subroutine
-def forks_box_create() -> None:
-    _created = op.Box.create(Bytes(FORKS_BOX_NAME), UInt64(FORKS_BOX_BYTES))
-
-@subroutine
-def _row_offset(index: UInt64) -> UInt64:
-    return index * FORK_ROW_BYTES
+def _row_key(index: UInt64) -> Bytes:
+    return Bytes(FORK_ROW_KEY_PREFIX) + op.itob(index)[7:8]

 @subroutine
 def _read_row(index: UInt64) -> tuple[UInt64, Bytes, UInt64, UInt64, UInt64]:
-    off = _row_offset(index)
-    raw = op.Box.extract(Bytes(FORKS_BOX_NAME), off, UInt64(FORK_ROW_BYTES))
+    raw, exists = op.AppGlobal.get_ex_bytes(0, _row_key(index))
+    assert exists, "fork row missing"
+    assert raw.length == UInt64(FORK_ROW_BYTES), "fork row wrong length"
     activation_epoch = op.btoi(raw[0:8])
     …                                       # unchanged
```

and, inside `append_fork_row`, only:

```diff
-    off = _row_offset(fork_count)
     row = ( … )                             # encode unchanged
-    op.Box.replace(Bytes(FORKS_BOX_NAME), off, row)
+    op.AppGlobal.put(_row_key(fork_count), row)
```

`contracts/state_anchor/forks.py` takes the byte-for-byte analogous diff (prefix
`g`, `FORK_ROW_BYTES` 40, constants imported from `constants.py`).

**Unchanged, verbatim, in both modules** — this is the §1.3 P1/P2 claim, and it
is a claim about a diff that now exists rather than an intention:

* every `assert` in `append_fork_row`: `fork_version.length == 4` (M4);
  `activation_epoch != UINT64_MAX` ("sentinel epoch rejected" / `N17-sentinel`);
  `fork_count < FORK_TABLE_CAPACITY` ("fork table full"); `activation_epoch >
  prev_epoch` ("activation_epoch must strictly increase"); M8's four
  `g_* >= 2` gindex-sanity asserts;
* the row encoding expression, field order and widths;
* `_find_row_index_for_epoch` in full — same `urange(fork_count)` scan, same
  "last row with `activation_epoch <= epoch` wins" rule, same `(found, index)`
  return;
* `lookup_fork_version`'s `assert found`; `lookup_gindices`'s `assert found` and
  its `finality_gindex != 0` pre-Altair rejection; `lookup_row`'s `assert found,
  "N17"`;
* every caller in `verifier.py` / `anchor_app.py` / `bridge.py` — the subroutine
  signatures do not change.

The only behavioural difference visible to a caller is the *message* on an
out-of-range row read: box-bounds failure becomes `"fork row missing"`. No
reachable path produces either, because every read is `index < fork_count` and
every write is capacity-gated (§9.1).

`contracts/state_anchor/constants.py` additionally drops `FORKS_BOX_NAME`,
`FORKS_BOX_BYTES` and the `forks_box_name()` accessor (**measured**: no other
module imports that accessor), gaining `FORK_ROW_KEY_PREFIX = b"g"`. Its
`from algopy import Bytes, UInt64, subroutine` then has an **unused `Bytes`** —
§17 item 5.

### 3.4 The schema declaration — the part the compiler will not do for you, and the fix that makes it do it anyway

Puya infers the global schema from `self.<name>` assignments. It cannot infer
anything about `op.AppGlobal.put` with a computed key. **Measured** (scratchpad
probe `probe.py`, `puyapy 5.9.0`, a contract with one named `fork_count` uint and
16 dynamic byte-slice rows): the emitted ARC-56 reports

```
schema: {'global': {'ints': 1, 'bytes': 0}}
```

— the 16 rows are invisible to it, exactly as the brief warned. Shipping that
would mean a create transaction declaring 7 byte slices for a contract that needs
23, and the 8th `append_fork_row` failing on a live deployment.

**The brief proposed fixing this by hand-widening `global_schema=StateSchema(…)`
in `deploy/plans/m4.py`/`m8.py`. This design rejects that as the primary
mechanism**, because it puts a hand-maintained integer in the deploy tooling,
three files away from the constant it must track, in a project whose own history
records four separate hand-maintained box/reference constants going wrong
(009's `6144`, `18432`, `20480`, `22528`).

Instead, the **contract itself declares its own totals**, using the option
`algopy` provides for exactly this case. From the real stub
(`algopy-stubs/_contract.pyi`, `class StateTotals`, **measured**):

> "This is not required when all state is assigned to `self.`, but **is required
> if a contract dynamically interacts with state via `AppGlobal.get_bytes` etc**,
> or if you want to reserve additional state storage for future contract
> updates, since the Algorand protocol doesn't allow increasing them after
> creation."

```python
class SyncCommitteeVerifier(
    ARC4Contract,
    avm_version=10,
    state_totals=StateTotals(global_uints=13, global_bytes=7 + forks.FORK_TABLE_CAPACITY),
):
```

```python
class TrustedRootAnchor(
    ARC4Contract,
    avm_version=10,
    state_totals=StateTotals(global_uints=9, global_bytes=1 + FORK_TABLE_CAPACITY),
):
```

**Measured**, compiling the real (patched) contracts this pass:

| | ARC-56 `state.schema.global` |
|---|---|
| `SyncCommitteeVerifier` | `{'ints': 13, 'bytes': 23}` |
| `TrustedRootAnchor` | `{'ints': 9, 'bytes': 9}` |

This is the load-bearing consequence: **the declared schema now flows out of the
contract, through the ARC-56 artifact, into `deploy/schema/generate.py` (which
already reads `arc56["state"]["schema"]["global"]`) and into both test harnesses
(which already read `global_schema_ints`/`global_schema_bytes` from the ARC-56)
with no hand-typed number anywhere.** The one remaining hand-typed number is the
hardcoded `StateSchema(13, 7)` / `StateSchema(9, 1)` in the deploy plans, and
§5.1 deletes it in favour of the ARC-56 value. After that, an off-by-one is not
merely unlikely — there is no place left to write one.

Note that `7 + FORK_TABLE_CAPACITY` and `1 + FORK_TABLE_CAPACITY` still restate
the *named*-byte-slice counts (7 and 1) as literals. That is unavoidable — the
compiler will not hand its own inference back to the source — and Puya
compensates: the stub states it "produce[s] a warning if the total specified is
insufficient to accommodate all `self.` state values at once", so an
under-declaration of the *named* half is caught at compile time. The *dynamic*
half is what G6-R13 exists to prove.

### 3.5 Alternatives considered and rejected

**3.5.1 `algopy.GlobalMap`.** The stubs (`_state.pyi`) provide a real
`GlobalMap(key_type, value_type, key_prefix=…)` with `__getitem__`/`__setitem__`/
`maybe()`. **Measured** (scratchpad `probe3.py`): it compiles, and it emits
richer ARC-56 metadata that tooling could consume directly —
`state.maps.global.fork_rows = {'keyType': 'uint64', 'valueType': 'AVMBytes',
'prefix': 'Zg=='}`. It is, in the abstract, the nicer API.

**Rejected**, for a concrete structural reason: `GlobalMap` is a *contract
member* (`self.fork_rows`), and **every subroutine in both `forks.py` modules is
a module-level `@subroutine` with no `self`**. Adopting `GlobalMap` means either
moving the whole fork table into the contract classes (dissolving the two
`forks.py` modules that 004 §4.3 and 008 §3.3 both specify as separate modules,
and that `tests/harness/test_versions.py::V-3` greps as a structural marker), or
threading a map object through six subroutine signatures. Both are far larger
diffs to trust-boundary code than the 12-line diff in §3.3, for a metadata
convenience. The metadata loss is repaid instead by §5.2's explicit
`global_state.row_family` block in the generated schema artifact, which is
strictly more informative than the ARC-56 map entry (it carries capacity, MBR per
slot, and the writer/deleter fields the artifact's box entries already carry).

**3.5.2 Packing several rows per global-state slot.** Would cut MBR
substantially (M4: 9 slots instead of 16). **Not possible.** The AVM caps a
byte-slice global value at 64 bytes (`MaxAppBytesValueLen`; the sum of key and
value is separately capped at 128, `MaxAppSumKeyValueLens`). Two M4 rows are 72 B
and two M8 rows are 80 B — both over. Packing would require rows to *straddle*
64-byte chunks, turning `_read_row` into a two-slot fetch-and-splice and
`append_fork_row` into a read-modify-write of up to two slots, in exactly the code
§1.3 says must stay boringly obvious. Rejected on both counts. *(These two caps
are **projected** here — cited protocol constants, not measured this pass; G3-R13
measures them by round-tripping a real 36/40-byte row.)*

**3.5.3 Keep the box, fund it differently.** Every variant reduces to predicting
the app id (the funding must land before `create()` runs), which is the race
itself. The factory-contract variant additionally cannot declare a box reference
for an app that does not yet exist. Rejected — this is the finding that
motivated the whole document.

**3.5.4 Lower `FORK_TABLE_CAPACITY`.** This is now a *direct* MBR lever: each row
of capacity costs exactly 50,000 µALGO whether or not it is ever used, because
global-state MBR is charged on the declared schema at create time. Dropping M4
from 16 to 10 rows would save 300,000 µALGO; dropping M8 from 8 to 6 would save
100,000. **Declined in this pass**, deliberately: capacity is a
security-relevant bound whose current value carries a documented rationale (004
§4.4's "linear scan of ≤ 10 rows + headroom"), it cannot be raised after create
(the protocol forbids growing schema), and changing it in the same pass that
changes the storage mechanism would muddy the "validation behaviour is provably
unchanged" gate this revision rests on. Recorded here as a known, available knob
with a known price, for a human to pull deliberately if 0.83 ALGO ever matters
more than headroom.

### 3.6 The mechanism, compiled for real

**Measured**, this design pass, `puyapy 5.9.0`, against a scratchpad copy of the
real `contracts/` tree with the §3.3 diff and the §3.4 `state_totals` applied
(no repository file was modified — see §0 of the report accompanying this doc):

| | before (committed artifact) | after (spike) | delta |
|---|---|---|---|
| `SyncCommitteeVerifier` approval | 6,980 B | **6,977 B** | −3 B |
| `SyncCommitteeVerifier` `min_extra_pages` | 3 | **3** | unchanged |
| `SyncCommitteeVerifier` global schema | (13, 7) | **(13, 23)** | +16 byte slices |
| `TrustedRootAnchor` approval | 3,027 B | **3,023 B** | −4 B |
| `TrustedRootAnchor` `min_extra_pages` | 1 | **1** | unchanged |
| `TrustedRootAnchor` global schema | (9, 1) | **(9, 9)** | +8 byte slices |

Both compiled clean, first attempt, no warnings beyond the scratchpad's
package-root notice. Remaining box opcodes in the emitted TEAL: 10 in M4 (the
`k:`/`s:`/`a:` install families) and 12 in M8 (the `h:`/`p:` families) —
i.e. exactly the fork-table box operations disappeared and nothing else did.

The programs get *smaller*, which is worth stating plainly: a box access
(`box_extract` with name, offset and length operands) is more emitted code than
`app_global_get_ex` with a 2-byte key. `extra_pages` is unaffected in both cases,
so no deployment parameter moves.

---

## 4. The MBR arithmetic, verified independently

The two formulas, from `deploy/mbr.py` (already confirmed against real
`account_info` responses in 010 §4.1/§4.2 and again live in M10's own pass):

```
box MBR          = 2,500 + 400 × (len(name) + len(value))     → charged to the APP account
global-state MBR = 100,000 + 28,500 × n_ints + 50,000 × n_bytes → charged to the CREATOR
```

**Measured** this pass by calling `deploy.mbr.global_state_mbr` / `box_mbr`
directly (not by retyping the brief's numbers):

| | M4 today | M4 revised | M8 today | M8 revised |
|---|---|---|---|---|
| creator-side, global state | 820,500 (13, 7) | **1,620,500** (13, 23) | 406,500 (9, 1) | **806,500** (9, 9) |
| app-side, fork box | 234,900 (`forks`, 576 B) | **0** | 132,900 (`forks8`, 320 B) | **0** |
| **combined** | 1,055,400 | **1,620,500** | 539,400 | **806,500** |
| **net delta** | — | **+565,100** | — | **+267,100** |

Combined net across both contracts: **+832,200 µALGO**. Every figure in the
brief is confirmed exactly; none needed correction.

Two consequences that are easy to miss:

* **`mbr_at_create` for the app account goes to the floor.** M4: 334,900 →
  **100,000**; M8: 232,900 → **100,000**. And since nothing else in either
  `create()` touches the app account, the create needs **no funding of that
  account at all** before it runs — the app account's balance requirement is met
  by the protocol's own base minimum, which the app account satisfies at zero
  balance until it is asked to hold something. This is the property G8-R13 tests.
* **`deploy/plans/m8.py`'s `target_balance` drops a term.** `100_000 +
  box_mbr(6, 320) + ring_n × box_mbr(10, 154)` becomes `100_000 + ring_n ×
  box_mbr(10, 154)`; at the default `ring_n = 128` that is **8,949,700 →
  8,816,800 µALGO** (**measured**).

**Schema headroom** (**measured**): the AVM caps total global-state slots at 64.
M4 goes to 13 + 23 = **36**; M8 to 9 + 9 = **18**. Both comfortably inside, with
room for the capacity to be raised later *if* the contract is redeployed — it can
never be raised on a live app.

**Recoverability, stated honestly.** Global-state MBR is released to the creator
when the application is deleted; box MBR is released only when the box is
deleted. Neither table's storage was ever recoverable in practice: no deleter
exists for `forks`/`forks8` (the generated schema says `"deleted_by": null`), and
both contracts are `NoOp`-only gated, so `DeleteApplication` is refused outright.
The change therefore moves ~832,200 µALGO of *permanently* locked value from one
account to another; it does not make it recoverable, and no doc should claim it
does (010 §10.4's standing rule).

---

## 5. Deploy-side changes

### 5.1 `deploy/plans/m4.py` and `deploy/plans/m8.py`

1. **Delete** `FORKS_BOX_NAME` (and M8's unused-after-this `box_mbr` import if it
   becomes so) from both plan modules.
2. **`global_schema=`**: replace the hardcoded `transaction.StateSchema(13, 7)` /
   `StateSchema(9, 1)` with the value read from the freshly compiled ARC-56:

   ```python
   gs = compiled["arc56"]["state"]["schema"]["global"]
   global_schema=transaction.StateSchema(gs["ints"], gs["bytes"]),
   ```

   This is the §3.4 payoff: the number the create transaction declares is
   produced by the compiler from the contract's own `StateTotals`, and can no
   longer disagree with it. §17 item 6 makes it normative that no literal schema
   pair is reintroduced.
3. **Drop `boxes=[(0, FORKS_BOX_NAME)]`** from the `predict_fund_and_create` call
   and from `_append_m4_fork_row` / `_append_m8_fork_row`'s `add_method_call`.
   Both are now dead references: `create()` creates no box, and `append_fork_row`
   touches no box. A stale box reference would not fail — it would silently pay
   the reference and hide the change — which is why §12's G5-R13 asserts the
   built transactions carry an *empty* box array rather than merely working.
4. **`_read_fork_rows`** (both plans, and therefore `deploy inspect --forks`,
   which calls straight into them) is rewritten from
   `read_box(algod, app_id, FORKS_BOX_NAME)` + offset slicing to a global-state
   read:

   ```python
   gs_raw = decode_global_state(algod_client, app_id)      # already exists
   fork_count = gs_raw.get("fork_count", 0)
   rows = []
   for i in range(fork_count):
       key = (PREFIX + i.to_bytes(1, "big")).decode("latin-1")   # see below
       chunk = gs_raw[key]
       …same field slicing as today…
   ```

   **A real trap here, found by reading `deploy/inspect.py`**:
   `decode_global_state` decodes every key with
   `base64.b64decode(entry["key"]).decode("utf-8", errors="replace")`. Row keys
   are binary. Index bytes `0x00`–`0x0F` happen to be valid UTF-8 (they are ASCII
   control characters), so the 16 M4 keys and 8 M8 keys do decode to *distinct*
   strings and nothing collides today — but this is luck, not design, and it
   breaks at index 0x80 if capacity is ever raised past 128. The implementation
   MUST therefore make `decode_global_state` preserve raw `bytes` keys (either by
   returning them alongside the decoded dict or by adding a
   `decode_global_state_raw`), and `_read_fork_rows` MUST key off the raw bytes.
   §17 item 8.
5. **M8's `target_balance`** loses its `box_mbr(len(FORKS_BOX_NAME), 40 * 8)`
   term (§4).
6. `deploy/plans/m8.py`'s `_ring_init_chunk` comment already says
   `ring_init_chunk` "never reads `forks8`" — after this change that sentence is
   trivially true of every method, and should be reworded rather than left
   implying the box still exists.

### 5.2 `deploy/schema/generate.py` and the two `*.schema.json` artifacts

`generate_m4()` / `generate_m8()`:

* **Remove** the `"fork_table"` entry from `boxes[]` in both (M4 keeps
  `committee_keys`/`install_session`/`aggregate`; M8 keeps `ring`/`pinned`).
* **Remove** `forks_box_name` / `forks_box_bytes` / the `m8c.FORKS_BOX_BYTES`
  reads and the `m8_forks.FORKS_BOX_NAME` import.
* `deploy.create_creates_boxes`: `["forks"]` / `["forks8"]` → `[]`.
* `deploy.mbr_at_create_microalgo`: `100_000 + box_mbr(…)` → `100_000`.
* `deploy.init_calls[append_fork_row].boxes`: drop the key entirely.
* `global_state.schema` / `creator_mbr_microalgo` need **no code change** — they
  already read the ARC-56 schema, which now reports (13, 23) / (9, 9), so the
  artifact's `creator_mbr_microalgo` becomes 1,620,500 / 806,500 automatically.
* `program.approval_bytes` / `approval_sha256` / `clear_*` change automatically
  with the recompile (6,980 → 6,977 and 3,027 → 3,023; both hashes move).
  `min_extra_pages` stays 3 / 1.
* **Add** a new `global_state.row_family` block, carrying the information the
  deleted box entry used to carry, so the artifact remains a complete description
  of where every byte of state lives and what it costs:

  ```json
  "row_family": {
    "family": "fork_table",
    "key": {"prefix": "f", "index_encoding": "itob(index)[7:8]", "key_bytes": 2},
    "value_bytes": 36,
    "capacity": 16,
    "slots_reserved": 16,
    "mbr_microalgo_per_slot": 50000,
    "mbr_microalgo_total": 800000,
    "reserved_by": "StateTotals(global_bytes=7 + FORK_TABLE_CAPACITY)",
    "written_by": "append_fork_row",
    "deleted_by": null,
    "lifetime": "permanent -- no deleter exists (010 §10.4)"
  }
  ```

  Every field derives from an imported contract constant or the ARC-56, per 010
  §17 item 2 — no retyped numbers.

The artifacts are regenerated by `python -m deploy schema` and committed;
`tests/deploy/test_schema.py::X-1` diffs them in CI, so a stale artifact fails the
build rather than the deployment.

### 5.3 `deploy/schema/_compiled/`

**Measured**: `_compiled/` holds `DonorCallee`, `DonorIssuer`, `Mpt6ComposerApp`,
`Mpt7ReceiptApp`, `MptSegmentApp` — the bare-`Contract` apps with no ARC-56.
**M4 and M8 are not in it**; their byte code lives inline in their committed
`*.arc56.json`. So `contracts/sync_committee/SyncCommitteeVerifier.arc56.json`
and `contracts/state_anchor/TrustedRootAnchor.arc56.json` are the artifacts that
must be recompiled and committed, and no `_compiled/` refresh (which would need
algod) is required by this change. This corrects the brief's framing, which
implied `_compiled/` pins M4/M8.

### 5.4 `deploy/create.py` — no change, and that is the point

`simulate_create` already returns `ok_unfunded=True, required_microalgo=0` when
the create needs no pre-funding, and `predict_fund_and_create` already skips both
the funding Payment and the `app_id != predicted_id` check in that case (its own
docstring anticipates it for M6/M7: *"If the create needs no box MBR at all …
there is no race to bound because there is nothing to fund before the id is
known"*). After this revision M4 and M8 simply *take that branch*.

`CreateRaced` therefore becomes structurally unreachable for M4 and M8 — not
because the exception was removed or softened, but because the funding step that
could lose the race no longer executes. The exception stays exactly as it is, for
any future contract that does create a box at create time.

---

## 6. The relayer's box-reference plan — the hot-path change, proved

This is the highest-risk part of the change, because `submit_update` is M4's most
frequently invoked method on a real deployment and `relayer/group/boxes.py` sizes
the *real transaction group* that carries it.

### 6.1 The change

`m4_submit_update_box_sizes(gen, key_box_indices, *, include_forks=True,
include_total=False)` currently inserts `sizes[b"forks"] = 576` unconditionally
by default, because `submit_update` reads the fork table on every call to resolve
`fork_version` at `epoch(signature_slot - 1)` and the gindices at
`epoch(attested_slot)`. Global-state reads consume **no** box-reference budget at
all, so the entry — and the `include_forks` parameter with it — is deleted, along
with the module-level `FORKS_BOX_BYTES = 576`.

Every caller drops the keyword: `choose_mode` (two calls),
`tests/harness/test_tiers.py::T-8`, `tests/relayer/test_live_relayer.py:216`.

### 6.2 Why removing it is correct, and what it moves

The project's established closed form (`plan_box_refs`, 009 §7.4):

```
distinct = the set of boxes any transaction in the group touches
bytes    = Σ declared_size(b) for b in distinct        (full size, once per box)
refs     = max(len(distinct), ceil(bytes / 2048))
txns_min = ceil(refs / 8)
```

The term that matters is `ceil(bytes / 2048)`, and the arithmetic is exact rather
than approximate: a key box is 6,144 B = **exactly 3 × 2048**. So for `k` key
boxes in **direct mode**:

* today: `ceil((6144k + 576)/2048) = 3k + 1` (the 576 B of `forks` occupies a
  whole extra 2,048-byte reference, of which it uses 28 %);
* revised: `ceil(6144k/2048) = 3k` exactly.

`len(distinct)` is `k + 1` → `k`, never the binding term for `k ≥ 1`. So **direct
mode loses exactly one reference at every participation level**, and the saving is
a whole reference, not a rounding artifact.

In **complement mode** the group also carries `a:<gen>` (96 B), and the answer is
different — this is the non-obvious part:

* today: `ceil((6144k + 96 + 576)/2048) = 3k + 1`;
* revised: `ceil((6144k + 96)/2048) = 3k + 1` — **unchanged**, because `a:<gen>`'s
  96 bytes already claims the partial reference that `forks` was sharing.

**Measured**, by running the real `plan_box_refs` over the real
`m4_submit_update_box_sizes` with and without the entry, `k = 0…8`:

| k | direct today | direct revised | complement today | complement revised |
|---|---|---|---|---|
| 0 | 1 ref | **0** | 2 | **1** |
| 1 | 4 | **3** | 4 | 4 |
| 2 | 7 | **6** | 7 | 7 |
| 3 | 10 | **9** | 10 | 10 |
| 4 | 13 | **12** | 13 | 13 |
| 5 | 16 | **15** | 16 | 16 |
| 6 | 19 | **18** | 19 | 19 |
| 7 | 22 | **21** | 22 | 22 |
| 8 | 25 | **24** | 25 | 25 |

### 6.3 The three things this could have broken, checked

**(a) Does the real submitted group shrink, and could that starve it of opcode
budget?** `submit_update_group` (`relayer/client.py`) pads by cycling
`plan.distinct_boxes` up to `plan.refs_required`, gives `submit_update` the first
8, the donor the next 7 (its `foreign_apps` entry costs one of its 8 reference
slots — a real measured finding recorded in that method's docstring), and spends
the remainder on `noop_budget` filler transactions at 8 each. **Measured**, by
replaying that exact algorithm for `k = 0…8` both ways: the number of filler
transactions is **identical at every k** (0 fillers for k ≤ 4, 1 for k = 6,7, 2
for k = 8), with a single exception — **k = 5 drops from 1 filler to 0** (refs
16 → 15, i.e. 16 − 15 = 1 remainder → 0). Every filler is also an app call, and
therefore also donates opcode budget, so k = 5 is the one participation level
where this change removes a transaction that was incidentally contributing
budget. The opcode budget is sized separately and explicitly by
`relayer/group/budget.py::size_donors` (donor count, not filler count), and
`submit_update_group` re-sizes donors through its own `build_group(n_donors)`
loop, so the design's expectation is that k = 5 self-corrects with one more
donor if it needs one. **This is the single riskiest line in the change, and
G7-R13 exists to measure it live rather than to argue it.**

**(b) Does `plan.txns_required` change, and does anything trust it as a
contract?** Yes at k = 8 only: `ceil(25/8) = 4` → `ceil(24/8) = 3`. It is a
*lower bound* used for reporting (`_drive_m4_update`'s returned
`txns_required_for_boxes`) and for `check_fits`; the real group shape is built
from `refs_required`, not from it. `tests/relayer/test_plan_boxes.py::P-4`
asserts `plan_k8.txns_required == 4` and must become 3 — a genuine expectation
change, not a test that can be left alone (§7.2).

**(c) Does mode selection change?** Yes, and it becomes *more* correct — this is
the finding a casual "just drop a box" change would have shipped silently.
`choose_mode` compares real reference cost, with a documented tie-break on
popcount. With direct at `3k_d` and complement at `3k_c + 1`:

* direct wins iff `3k_d < 3k_c + 1` ⟺ `k_d ≤ k_c`. Today it wins iff
  `k_d < k_c`.
* **So when both modes touch the same number of key boxes, direct now wins
  outright instead of tying.** That is correct on the merits: at equal `k`,
  direct genuinely costs one fewer reference, because complement additionally
  carries `a:<gen>`. Today's tie is an artifact of `forks` masking that 96-byte
  difference inside a shared partial reference.
* A consequence worth writing down: `3k_d = 3k_c + 1` has no integer solutions,
  so **the tie branch becomes structurally unreachable**. The design keeps the
  branch (deleting live code on a *proof* of unreachability is how the next
  refactor gets a surprise) but requires its comment to say so, and requires
  `test_t8`-adjacent coverage to stop asserting a tie can occur. §17 item 11.

**(d) Anything else that assumed `forks` is in the plan?** **Measured**, by
grepping every caller of `plan_box_refs` / `m4_submit_update_box_sizes` /
`choose_mode`: `relayer/drivers/m4_sync_committee.py::plan_submit_update_boxes`
(pass-through, no change), `relayer/client.py::submit_update_group` (no change —
it is generic over the plan) and `::_retire_generation` (uses
`m4_retire_box_sizes`, which never included `forks`; unchanged, still 25 refs /
4 txns), `m4_install_open_box_sizes` (never included `forks`; still 25 refs,
still equal to `MIN_BOX_REFS_FOR_INSTALL_OPEN`, so `contracts/sync_committee/
constants.py`'s 25 and its `INSTALL_BOX_WRITE_BYTES = 8*6144 + 424` need **no
change**), and the tests in §7.

### 6.4 The other two real box-reference call sites

* **`relayer/client.py:695`, the bootstrap group.** Today it declares
  `boxes=[(0, b"forks")] + key_refs[:7]` — 8 references, of which `forks` is one
  real reference (bootstrap does read the table for its gindex lookup) and the
  other seven are pure budget donation toward the 8 key-box creates in the next
  transaction. The group needs `ceil((8×6144 + 424)/2048) = 25` references
  (**measured**: unchanged before and after, since the fork box's 576 B was
  costed into the *submit_update* plan, not this one — the box-opening group's
  own total is and was 49,576 B). After the change `forks` is not a box, so the
  slot must be **replaced, not deleted**: `boxes=key_refs[:8]` keeps the count at
  8. Deleting it outright would drop the group to 24 references and reintroduce
  the exact class of shortfall 009's history records four times.
  `tests/sync_committee/test_install_live.py:269` and
  `tests/relayer/test_live_relayer.py:579` carry the same pattern and take the
  same fix.
* **`relayer/drivers/m8_anchor.py::auto_boxes_for`** appends `(0, b"forks8")` for
  `anchor_direct`/`anchor_historical`. M8's anchor group is nowhere near any cap
  (008 §1819's own table: 2 boxes, 475 B, 12 % of two references), so this one is
  a straight deletion. `tests/state_anchor/harness.py::_auto_boxes_for` mirrors
  it exactly and takes the same deletion.

---

## 7. Every file that changes

**Measured**, `grep -rln "append_fork_row\|forks8\|b\"forks\"\|FORKS_BOX\|fork_count"`
over `tests/ deploy/ relayer/ service/ bench/ docs/`, plus the contract tree.
The brief's starting list was **not** complete — five test files and three docs
below were not on it.

### 7.1 Contracts (5 files)

| File | Change |
|---|---|
| `contracts/sync_committee/forks.py` | §3.3 diff; `FORKS_BOX_NAME`/`FORKS_BOX_BYTES` → `FORK_ROW_KEY_PREFIX`; `forks_box_create`/`_row_offset` → `_row_key` |
| `contracts/sync_committee/verifier.py` | delete `forks.forks_box_create()` from `create()`; add `state_totals=StateTotals(global_uints=13, global_bytes=7 + forks.FORK_TABLE_CAPACITY)`; import `StateTotals` |
| `contracts/state_anchor/forks.py` | same diff, prefix `g`, imports updated |
| `contracts/state_anchor/constants.py` | drop `FORKS_BOX_NAME`, `FORKS_BOX_BYTES`, `forks_box_name()`; add `FORK_ROW_KEY_PREFIX = b"g"`; drop now-unused `Bytes` import |
| `contracts/state_anchor/anchor_app.py` | delete `forks.forks_box_create()`; add `state_totals=StateTotals(global_uints=9, global_bytes=1 + FORK_TABLE_CAPACITY)`; import `StateTotals` and `FORK_TABLE_CAPACITY` |

Plus the two recompiled, committed ARC-56 artifacts
(`SyncCommitteeVerifier.arc56.json`, `TrustedRootAnchor.arc56.json`).

### 7.2 Relayer and deploy (6 files)

| File | Change |
|---|---|
| `relayer/group/boxes.py` | delete `FORKS_BOX_BYTES`, the `include_forks` parameter and its `sizes[b"forks"]` line; update `choose_mode`'s two calls and its tie-break comment (§6.3c); update the module/function docstrings that cite `forks` as always-referenced |
| `relayer/client.py` | line 695: `[(0, b"forks")] + key_refs[:7]` → `key_refs[:8]` (§6.4) |
| `relayer/drivers/m8_anchor.py` | line 214: delete the `(0, b"forks8")` append |
| `deploy/plans/m4.py` | §5.1 (1,2,3,4) |
| `deploy/plans/m8.py` | §5.1 (1,2,3,4,5,6) |
| `deploy/schema/generate.py` | §5.2 |
| `deploy/inspect.py` | preserve raw byte keys from `decode_global_state` (§5.1 item 4) |

### 7.3 Tests (13 files)

| File | What it asserts today | Update |
|---|---|---|
| `tests/sync_committee/harness.py` | `create()` uses a probe-fund-create loop with `boxes=[(0, b"forks")]` and `APP_FUNDING_MICROALGO`, with a docstring explaining the box-MBR-before-address problem | **The single biggest simplification in the change**: delete the probe app, the funding Payment, the `predicted_id + 2` arithmetic and the 5-attempt retry loop; `create()` becomes a plain `add_method_call(app_id=0, …)` with no `boxes=`. Its schema already comes from the ARC-56, so it needs no schema edit. Rewrite the docstring — it currently *documents the defect* |
| `tests/state_anchor/harness.py` | `_auto_boxes_for` appends `(0, b"forks8")`; `create(..., fund_app=…)` pre-funds the app account | delete the `forks8` append; `fund_app` stays (M8 still needs app-account funds for its *ring* boxes) but the fork-table term comes out of every call site's figure |
| `tests/sync_committee/test_install_live.py` | `append_fork_row` with `[(0, b"forks")]` (181, 240); bootstrap with `[(0, b"forks")] + key_refs[:7]` (269); comments describing the "forks + 8 key-box creates" 9-reference hit | drop the box refs on `append_fork_row`; bootstrap → `key_refs[:8]` (§6.4); the §16 comments become historical and must be reworded, not deleted (they explain why the 3-way install split exists, which is still true) |
| `tests/relayer/test_live_relayer.py` | `append_fork_row` boxes (87, 286); `m4_submit_update_box_sizes(..., include_forks=True, ...)` (216); bootstrap refs (579); M8 create with `boxes=[(0, b"forks8")]` (277) | drop all four box references; drop the `include_forks` kwarg |
| `tests/relayer/test_box_budget_model.py` | Suite BX builds real groups with `[(0, b"forks")]` on `append_fork_row` and on bootstrap, and measures reference budgets with `allow_unnamed_resources=False` | drop the `forks` refs; the *measurements* (2,048 B/ref, 8 refs/txn, shared read/write pool, duplicate refs count) are about key boxes and are unaffected — but this suite is the one that would notice if they were, so it must be **re-run live**, not merely edited |
| `tests/relayer/test_plan_boxes.py` | P-2 expects `(1,4),(2,7),…,(8,25)`; P-4 asserts `plan_k8.txns_required == 4` | P-2 → `(1,3),(2,6),(3,9),(4,12),(5,15),(6,18),(7,21),(8,24)`; P-4's replay of the two historical live failures still holds (`21 > 9`, `6 > 3`) but its `txns_required == 4` becomes 3 |
| `tests/harness/test_tiers.py` | T-8 asserts `b"forks" in plan.distinct_boxes` and, for direct mode at 0 participation, `plan_direct.distinct_boxes == (b"forks",)` | Both assertions become false. Direct mode at k = 0 now yields a **genuinely empty plan** (`distinct_boxes == ()`, `refs_required == 0`, `txns_required == 0`) — T-8's whole point is this never-exercised edge, so it must be rewritten to assert the *new* degenerate shape and to state that an empty plan is safe because `submit_update` at 0/512 participation is rejected on-chain by `MIN_SYNC_COMMITTEE_PARTICIPANTS` long before box references matter |
| `tests/harness/m4.py` | `deploy_fresh_committee()` submits `append_fork_row` with `[(0, b"forks")]` | drop the box ref |
| `tests/harness/test_versions.py` | V-3 greps `fork_axis: "none"` sources for the markers `("FORKS_BOX_NAME", "FORK_TABLE_CAPACITY", "append_fork_row")` | `FORKS_BOX_NAME` no longer exists anywhere, so that marker silently stops discriminating. Replace with `FORK_ROW_KEY_PREFIX` |
| `tests/deploy/test_deploy_live.py` | three creates with `extra_pages=3, boxes=[(0, b"forks")]` (142, 307, 339); `fork_count == 3` assertions | drop the box refs; keep `extra_pages=3` (**measured** unchanged, §3.6); the `fork_count` assertions are unaffected. **Additionally**: this suite is where G8-R13's "create needs zero app-account pre-funding" is proven |
| `tests/deploy/test_schema.py` | X-2 (`fork_table.value_bytes == 576/320`), X-4 (`fork_table.mbr_microalgo == 234,900/132,900`), X-6 (schemas `(13,7)`/`(9,1)`, MBR 820,500/406,500), `drift_2_forks8_is_320_bytes_not_321`, `drift_3_creator_mbr_is_406500_not_378000` | X-2/X-4 lose their `fork_table` lines; X-6 → `(13,23)`/`(9,9)` and 1,620,500/806,500; `drift_2` must be **rewritten, not deleted** — the drift it guards (a doc claiming 321 B) is now expressed as `FORK_ROW_BYTES × FORK_TABLE_CAPACITY == 320` and the new `row_family.value_bytes == 40`; `drift_3`'s creator-MBR number moves. New assertions for the `row_family` block |
| `tests/state_anchor/test_core.py` | `create(..., boxes=[(0, b"forks8")], fund_app=15_000_000)` (48, 233); `append_fork_row` with `boxes` (55); the ABI method-name inventory (215) | drop box refs; method inventory unchanged |
| `tests/state_anchor/test_forks.py` | the M8 fork-table suite proper — creates + `append_fork_row` with `[(0, b"forks8")]` at 157–169, 300–308 | drop box refs. **This is the suite that carries P1/P2 for M8** and is the primary evidence for G4-R13 |
| `tests/state_anchor/test_live_e2e.py`, `tests/state_anchor/test_live_historical.py` | creates and `append_fork_row` calls with `[(0, b"forks8")]` (64, 138–147; 218–231) | drop box refs |

### 7.4 Docs (4 files)

| File | Change |
|---|---|
| `docs/operating.md` | the MBR table's "M4 app — base + `forks` box — 334,900" and "M8 app — base + `forks8` box — 232,900" rows become base-only 100,000; the creator-side figures gain the new schema cost; line 109's "unrecoverable box MBR for the `forks`/`forks8`/ring families" drops the first two (§4's recoverability note) |
| `docs/versioning.md` | line 68's per-fork cost table is unchanged (an `append_fork_row` is still ~1,000 µALGO), but the storage description must stop calling the table a box |
| `docs/security.md` | prose only — `append_fork_row` remains governance-gated; no claim changes |
| `docs/design/004`, `008`, `010`, `012` | **not rewritten.** This project's convention is that a design doc records what was designed *at the time*; 013 supersedes the storage decision. §14 requires 004 §4.3, 008 §3.3/§6.3 and 010 §4/§5.2/§5.3 to each gain a one-line "superseded by 013 §3" pointer at the top of the affected section, and nothing more |

---

## 8. Edge cases

1. **Empty table (`fork_count == 0`).** `_find_row_index_for_epoch` iterates
   `urange(0)` — zero iterations, `found == False`, callers assert. No global read
   is attempted; identical to today, where no box read was attempted either.
2. **Full table (`fork_count == 16` / `8`).** `append_fork_row` asserts before any
   write. Unchanged. Note the difference in *what would happen if the assert were
   removed*: today the write would land outside the box and fail on bounds; now it
   would land on key `f\x10` and fail on the **declared schema** instead. Both
   fail; the messages differ. The assert is what matters, and it is untouched.
3. **A row read before it is written.** Unreachable (every read is
   `index < fork_count`, and `fork_count` only advances after a successful
   write in the same call), but now fails as `"fork row missing"` instead of a
   box-bounds error (§3.2).
4. **Two `append_fork_row` calls in one atomic group.** Each reads
   `self.fork_count` fresh at its own execution, and global-state writes are
   visible to later transactions in the same group. Unchanged semantics; the box
   behaved the same way. `deploy apply`'s idempotent resume (010 G6-M10) submits
   them as separate transactions anyway.
5. **`deploy apply` resuming a partially-populated table.** `_read_fork_rows` now
   reads global state instead of a box; the conflict check (row `i` on-chain vs
   desired) is byte-identical because the row encoding is. The one real change:
   today a *missing box* is caught by `except Exception: return []`; with global
   state a fresh app simply has `fork_count == 0` and no row keys, so the same
   `[]` results — but by the normal path, not by an exception. §17 item 9
   requires the bare `except` to be narrowed rather than inherited, since it can
   no longer be doing the job it was written for.
6. **`deploy inspect --forks` against a pre-revision deployment.** There is none —
   no mainnet deployment exists, and dev-mode deployments are recreated per run.
   The tool does not need a dual-format reader, and must not grow one.
7. **A relayer built before the change talking to a contract built after it (or
   vice versa).** The client would declare a box reference for a box that does not
   exist (harmless, wasted reference) or omit one that is required (fails). The
   real guard already exists and is unchanged: `deploy verify` pins the approval
   program hash, and both hashes move in this revision (§3.6). A mismatched pair
   fails the pin, not a box budget.
8. **Direct mode at 0/512 participation.** Now yields a completely empty box plan
   (§7.3, T-8). Safe, and unreachable in practice, but it is a new degenerate
   shape that did not exist before and it is written down here so the next reader
   does not treat `refs_required == 0` as a bug.
9. **`k = 5` participation loses a filler transaction.** §6.3(a). The one place
   where a group's *shape*, not just its accounting, changes.

---

## 9. Adversarial notes

**9.1 Can an attacker force a key collision (P3)?** No, and the argument is
short enough to check: the *only* writer is `append_fork_row`, which writes at
index `fork_count` after asserting `fork_count < FORK_TABLE_CAPACITY` (16 / 8),
so no write index ever exceeds 15. The *only* readers pass `i < fork_count` (the
`urange` scan) or `fork_count - 1` (the monotonicity check). `itob(i)[7:8]` is
injective on `0…255`. Therefore no two distinct live indices share a key. The
cliff is at capacity > 256, which is why §17 item 3 requires
`assert FORK_TABLE_CAPACITY <= 256` as a module-scope Python assertion (evaluated
at compile time by Puya's own import of the module, costing zero on-chain bytes).

**9.2 Can governance overwrite an existing row?** No more than today.
`op.AppGlobal.put` overwrites unconditionally *at the key it is given*, exactly as
`op.Box.replace` overwrote unconditionally at the offset it was given. The
append-only property has never come from the storage primitive; it comes from
`append_fork_row` writing only at `fork_count` and from `fork_count` only ever
increasing. That logic is untouched. A compromised `gov` key could append a
malicious row today and could append one after this change; it cannot rewrite
history in either case. (010 §11.4's `ForkRowConflict` is the client-side
detector for exactly this, and it still works — it compares decoded rows, not
storage.)

**9.3 Does moving to global state widen read access?** Global state is
world-readable; so was the box (`/v2/applications/{id}/boxes` enumerates them,
and 010 §991 records that being verified live). The fork table was never secret —
it is a published trust parameter. No confidentiality property changes.

**9.4 Could an undersized declared schema be exploited?** The failure mode is a
denial of *governance capability*, not a safety hole: if the schema were declared
too small, `append_fork_row` would begin failing at some row `n`, and — because
schema cannot be grown after create — the fix would be a redeploy. It cannot
corrupt an existing row or cause a wrong row to be selected. It is nonetheless the
single most consequential number in this change, which is why §3.4 removes the
opportunity to type it by hand and G6-R13 tests the boundary directly by filling
the table to capacity.

**9.5 What a green test run will and will not prove.** It will prove the table
round-trips, that validation is unchanged, that the schema accommodates capacity,
and that a create needs no pre-funding — all against **dev-mode algod**. It will
**not** prove the mainnet create succeeds, because dev-mode has no competing
traffic. The honest claim after this work is *"the mechanism that could lose the
race no longer runs"*, which is a structural argument (§5.4), not a measurement.
G8-R13 is deliberately written to be satisfiable by a **`simulate` against real
mainnet with no signer** (`EmptySigner`, `allow_empty_signatures=True` — the same
recipe `deploy.create.simulate_create` already uses), which is the strongest
real-network evidence obtainable without spending anything.

---

## 10. Cost

| Item | Amount | Basis |
|---|---|---|
| M4 creator MBR increase | +800,000 µALGO | **measured**, `global_state_mbr(13,23) − global_state_mbr(13,7)` |
| M4 app-account MBR released | −234,900 µALGO | **measured**, `box_mbr(5, 576)` |
| M8 creator MBR increase | +400,000 µALGO | **measured**, `global_state_mbr(9,9) − global_state_mbr(9,1)` |
| M8 app-account MBR released | −132,900 µALGO | **measured**, `box_mbr(6, 320)` |
| **Net, both contracts, one-time** | **+832,200 µALGO (0.83 ALGO)** | sum |
| Per-`append_fork_row` transaction fee | unchanged (1,000 µALGO flat) | no new transactions |
| Per-`submit_update` cost | **unchanged or slightly lower** | one fewer box reference; at k = 5, one fewer filler transaction (−1,000 µALGO fee) |
| Compiled program size | −3 B (M4), −4 B (M8) | **measured**, §3.6 |
| Implementation effort | ~12 lines of contract diff, ~10 files of tooling, ~13 test files | §7 |
| **Re-verification effort** | **the dominant cost** — see §15.1 | |

Against this: two stranded funding payments already cost ~0.67 ALGO, and a
successful mainnet deployment is currently blocked entirely.

---

## 11. Test plan

Suite **F** (fork-table storage), new or rehomed assertions, on top of the
existing suites listed in §7.3. Everything marked *live* runs against real
dev-mode algod, no mocks, per this project's standing rule.

| ID | Test | Kind |
|---|---|---|
| F-1 | Both contracts compile; the committed ARC-56 artifacts reproduce byte-for-byte; `state.schema.global` is `(13,23)` / `(9,9)` | offline |
| F-2 | Append 1 row, read it back through `lookup_fork_version`/`lookup_gindices` (M4) and `lookup_row` (M8); every field matches the submitted value exactly | live |
| F-3 | Append rows at capacity (16 / 8); every row reads back correctly; the (capacity+1)-th append is rejected with `"fork table full"` | live |
| F-4 | Epoch monotonicity: a row at an equal epoch and a row at a lower epoch are both rejected with `"activation_epoch must strictly increase"` | live |
| F-5 | Sentinel epoch (`2**64 − 1`) rejected (`"sentinel epoch rejected"` / `N17-sentinel`) | live |
| F-6 | M8 gindex sanity: each of the four `g_* >= 2` asserts fires independently | live |
| F-7 | M4 pre-Altair row: `lookup_gindices` at an epoch matching a zero-gindex row is rejected; `lookup_fork_version` at the same epoch succeeds | live |
| F-8 | M8 `N17`: `lookup_row` at an epoch before the first row's activation is rejected with `N17` | live |
| F-9 | Multi-row selection: with rows at epochs `e0 < e1 < e2`, lookups at `e0`, `e1 − 1`, `e1`, `e2 + 10^6` select rows 0, 0, 1, 2 | live |
| F-10 | Non-governance `append_fork_row` rejected | live |
| F-11 | A real `create()` submitted with **zero** prior funding of the app account succeeds, and `application_boxes(app_id)` is empty immediately after | live |
| F-12 | Same create as F-11, simulated against **real mainnet** with `EmptySigner` — no MBR shortfall in the failure message | live, mainnet read-only |
| F-13 | `plan_box_refs` regression table for `k = 0…8`, both modes, against §6.2's measured table | offline |
| F-14 | `choose_mode` picks direct at `k_d == k_c` (the §6.3c behaviour change), and complement at `k_c < k_d` | offline |
| F-15 | Every built `append_fork_row` / `create` transaction (deploy plans and both test harnesses) carries an **empty** box-reference array | offline, by inspecting the built transaction |
| F-16 | The generated schema artifacts contain no `fork_table` box family, contain a `row_family` block, and report `mbr_at_create_microalgo == 100_000` for both contracts | offline |
| F-17 | Full M4 live path unchanged: real bootstrap → 64 real `install_chunk` groups → `install_finalize` → real `submit_update` against real mainnet data, at both a direct-mode and a complement-mode bitfield, plus one at k = 5 if a real bitfield produces it (§6.3a) | live |
| F-18 | Full M8 live path unchanged: `anchor_direct` and `anchor_historical` against a real finalized M4 state | live |

---

## 12. Acceptance gates

Gate naming: this document revises two existing modules rather than adding a new
one, so its gates are numbered against the **document** (`R13` = revision, doc
013) rather than a module number that does not exist. `ROADMAP.md`'s M4 and M8
rows cite them as `G1-R13` … `G9-R13`.

| Gate | Statement | How judged |
|---|---|---|
| **G1-R13** | Both revised contracts compile with `puyapy`, and the committed ARC-56 artifacts are regenerated and reproduce byte-for-byte in CI | F-1. **Already measured passing** against a scratchpad copy this pass (§3.6) — the gate is that it stays true for the real tree |
| **G2-R13** | The fork table round-trips: every field of every appended row reads back exactly, at 1 row, at capacity, and at three rows with distinct epochs | F-2, F-3, F-9 |
| **G3-R13** | The declared schema is exactly right — a table filled to `FORK_TABLE_CAPACITY` writes every row successfully, and no create declares a schema not produced by the compiler | F-3, F-15, F-16, plus a source grep for a literal `StateSchema(` pair |
| **G4-R13** | **Security-critical validation is unchanged in behaviour**: epoch monotonicity, sentinel rejection, capacity limit, M8's gindex sanity, M4's pre-Altair gindex rejection, M8's `N17`, and governance-only writes all reject exactly the inputs they reject today, with the same messages | F-4…F-8, F-10. The gate this revision rests on |
| **G5-R13** | No transaction anywhere in `deploy/`, `relayer/` or `tests/` declares a `forks`/`forks8` box reference, and the string does not appear in any non-historical comment | F-15 + repo-wide grep |
| **G6-R13** | `submit_update`'s box-reference plan is correct and regresses none of the numbers this project has already measured: `MIN_BOX_REFS_FOR_INSTALL_OPEN` stays 25, `m4_retire_box_sizes` stays 25/4, and the direct/complement table matches §6.2 exactly | F-13, F-14, `tests/relayer/test_plan_boxes.py` P-2/P-3/P-4 |
| **G7-R13** | A real `submit_update` lands live at a direct-mode bitfield, a complement-mode bitfield, and — if a real bitfield yields one — at `k = 5`, with no box-budget failure and no opcode-budget failure | F-17. **The riskiest gate**; §6.3(a) |
| **G8-R13** | A real `create()` for each contract needs **zero** pre-funding of the app account: it succeeds on dev-mode algod with an unfunded app account, and a real mainnet `simulate` with no signer reports no MBR shortfall | F-11, F-12 |
| **G9-R13** | The full pre-existing M4 and M8 live suites pass against real dev-mode algod, unchanged in coverage | F-17, F-18 + §15.1's re-run |
| **G10-R13** | Every number in the implementation report traces to a real command, response or file | `ARCHITECTURE.md`'s standing rule |

---

## 13. Questions resolved, and what is handed on

**Resolved by this pass, with evidence:**

* *Does Puya 5.9.0 accept a dynamic-key global read/write?* **Yes** — measured,
  three scratchpad probes plus both real contracts.
* *Does Puya infer schema for dynamic keys?* **No** — measured: a contract with
  16 dynamic rows reports `bytes: 0`.
* *Is there a way to make the compiler carry the number anyway?* **Yes** —
  `StateTotals`, measured to propagate into the ARC-56 schema, which every
  consumer in this repo already reads.
* *Do the brief's MBR figures hold?* **Yes, exactly** — all four recomputed from
  `deploy/mbr.py`.
* *Can a 2-byte row key collide with an existing global key?* **No** — measured:
  the shortest existing key in either contract is 3 bytes.
* *Does removing `forks` from the box plan change `submit_update`'s real group?*
  **Yes, in two places nobody had noticed**: mode selection at equal `k` (§6.3c)
  and the filler count at `k = 5` (§6.3a).
* *Does `deploy/create.py` need changing?* **No** — its `ok_unfunded` branch
  already implements the new behaviour.

**Handed on:**

* The `k = 5` filler-count change is the one behaviour this design could not
  settle offline. G7-R13 must measure it, and the implementation report must say
  what it measured, not that it reasoned about it.
* The AVM's 64-byte global value cap and 128-byte key+value cap are cited, not
  measured (§3.5.2). G3-R13 measures them incidentally by storing a real 40-byte
  row.
* The exact algod error text for an over-schema `app_global_put` is **projected**
  (expected to be of the form `"store bytes count N exceeds schema bytes count
  M"`). The implementation pass should capture the real string once, deliberately,
  by declaring an under-sized schema in a throwaway app, and record it — this
  project has repeatedly benefited from having the real error text written down.

---

## 14. How `ROADMAP.md` should record this

**Recommendation: revision notes on M4's and M8's own rows plus a new
`docs/design/` entry — no new module row.** Reasoning:

1. The roadmap's `#` column is a *module* identifier that other rows depend on
   (`Depends on: M3, M4`). Inventing an `M13` for a change that ships no new
   capability would put a dependency-graph node in the table that nothing
   depends on and that no future module should ever be told to build against.
2. The roadmap's own workflow line says a design doc is written, approved, then
   implemented — it does not say design docs and module numbers are 1:1. Doc 013
   is a design doc for work on M4 and M8.
3. The status legend already accommodates this: M4's and M8's `Status` cells
   become e.g. *"Implemented, live-tested; **fork table revised to global state
   2026-08-10 (013), re-verified live**"*, and their `Last updated` dates move.

Concretely, the implementation pass should:

* update M4's and M8's `Status` and `Last updated` cells as above;
* add `[docs/design/013-fork-table-global-state.md](docs/design/013-fork-table-global-state.md)`
  to the `Design doc` cell of both rows, alongside their existing 004 / 008 links;
* record the real gate outcomes (`G1-R13` … `G10-R13`) in those two rows' notes,
  in the same measured-citation style the M10 and M11 rows use;
* add a one-line supersession pointer at the head of 004 §4.3, 008 §3.3/§6.3 and
  010 §4/§5.2/§5.3 (§7.4) — leaving the original text intact, per this project's
  convention that a design doc records what was designed at the time;
* note in M9's and M10's rows that their box-reference planner and deploy plans
  changed, with a pointer to §6 and §5 — those modules are not being re-gated,
  but their code moved and the roadmap is where that is discoverable.

---

## 15. Honest gaps and deferred work

### 15.1 The re-verification burden — stated plainly

This revises the storage of a trust-boundary table inside two contracts that the
roadmap currently marks *"Implemented, live-tested"*. **That claim does not
survive a bytecode change on its own evidence.** Both approval program hashes
move (§3.6), which means every live result recorded against M4 and M8 was
produced by a program that no longer exists.

**The whole M4 and M8 live suite must be re-run against real dev-mode algod.**
Not a subset. Concretely, that is: `tests/sync_committee/` (including the full
512-member install — 64 real `install_chunk` groups — and the live finality
suite), `tests/state_anchor/` (core, forks, live e2e, live historical),
`tests/relayer/` (live relayer, box-budget model), and `tests/deploy/` (live
deploy, schema). M10's own record puts a full from-scratch deploy plus end-to-end
drive at **84.6 s** wall-clock on dev-mode algod, so the run itself is cheap; the
expense is that it needs a real algod and real beacon/EL endpoints, and that
someone must read the results rather than the exit code.

Modules M1, M2, M3, M5, M6, M7 are untouched — no contract they own changes, and
`plan_box_refs`'s changes do not reach them (§6.3d). Their live results stand.

**A dev-mode algod was not reachable during this design pass** (**measured**:
nothing on `localhost:4051`/`:4052`, and the Docker daemon is not running), which
is why every live claim in this document is a *gate* rather than a result. That
is the honest boundary of what a design pass could establish here, and §3.6's
compile-level evidence is deliberately as far as it was taken.

### 15.2 Gaps this design does not close

1. **No mainnet create is proven.** G8-R13's mainnet evidence is a read-only
   `simulate`. The structural argument (§5.4) is strong — the funding step does
   not execute — but a real mainnet create remains a human action, taken after
   this work, and the roadmap should not claim otherwise.
2. **`k = 5` is unmeasured** (§6.3a, §13).
3. **The over-schema error string is unmeasured** (§13).
4. **The 64-byte value cap is cited, not measured** (§3.5.2).
5. **Capacity is not revisited** (§3.5.4) — a deliberate deferral with a known
   price, not an oversight.
6. **`deploy inspect`'s global-state decoding gets a binary-key seam**
   (§5.1 item 4). The fix keeps raw bytes, but every other consumer of
   `decode_global_state` (the `deploy inspect` JSON dump, `deploy verify`,
   `relayer.client._read_global_state`) will now see 16/8 extra entries with
   unprintable keys in its output. The implementation should filter row keys out
   of the human-facing dump and print them only under `--forks`, or the operator
   experience regresses. This is named here rather than discovered later.
7. **No testnet run.** 010 §15 gap 3 and 012 §6.3 both already recommend one
   before any mainnet action; this change does not alter that recommendation, and
   arguably strengthens it, since a testnet create is now the cheapest possible
   end-to-end proof of the whole point of the change.

---

## 16. File layout

```
docs/design/013-fork-table-global-state.md          NEW (this document)

contracts/sync_committee/forks.py                   MODIFIED  (§3.3)
contracts/sync_committee/verifier.py                MODIFIED  (create(), StateTotals)
contracts/sync_committee/SyncCommitteeVerifier.arc56.json   REGENERATED
contracts/state_anchor/forks.py                     MODIFIED  (§3.3)
contracts/state_anchor/constants.py                 MODIFIED  (§3.3)
contracts/state_anchor/anchor_app.py                MODIFIED  (create(), StateTotals)
contracts/state_anchor/TrustedRootAnchor.arc56.json REGENERATED

relayer/group/boxes.py                              MODIFIED  (§6.1)
relayer/client.py                                   MODIFIED  (§6.4, one line)
relayer/drivers/m8_anchor.py                        MODIFIED  (§6.4, one line)

deploy/plans/m4.py                                  MODIFIED  (§5.1)
deploy/plans/m8.py                                  MODIFIED  (§5.1)
deploy/schema/generate.py                           MODIFIED  (§5.2)
deploy/inspect.py                                   MODIFIED  (§5.1 item 4)
deploy/schema/SyncCommitteeVerifier.schema.json     REGENERATED
deploy/schema/TrustedRootAnchor.schema.json         REGENERATED

tests/sync_committee/harness.py                     MODIFIED  (probe-fund-create deleted)
tests/sync_committee/test_install_live.py           MODIFIED
tests/state_anchor/harness.py                       MODIFIED
tests/state_anchor/test_core.py                     MODIFIED
tests/state_anchor/test_forks.py                    MODIFIED  (+ Suite F for M8)
tests/state_anchor/test_live_e2e.py                 MODIFIED
tests/state_anchor/test_live_historical.py          MODIFIED
tests/relayer/test_live_relayer.py                  MODIFIED
tests/relayer/test_box_budget_model.py              MODIFIED
tests/relayer/test_plan_boxes.py                    MODIFIED  (P-2, P-4 numbers)
tests/harness/m4.py                                 MODIFIED
tests/harness/test_tiers.py                         MODIFIED  (T-8 rewritten)
tests/harness/test_versions.py                      MODIFIED  (V-3 marker)
tests/deploy/test_schema.py                         MODIFIED  (X-2/X-4/X-6, drift_2, drift_3)
tests/deploy/test_deploy_live.py                    MODIFIED  (+ G8-R13)
tests/sync_committee/test_forks_state.py            NEW       (Suite F for M4, §11)

docs/operating.md                                   MODIFIED  (§7.4)
docs/versioning.md                                  MODIFIED  (§7.4)
docs/security.md                                    MODIFIED  (prose)
docs/design/004,008,010 (+012 §5 table)             MODIFIED  (one-line supersession pointers)
ROADMAP.md                                          MODIFIED  (§14)
```

---

## 17. Implementer checklist (normative MUSTs)

1. **MUST NOT** change any assertion, message, encoding, field order, capacity or
   lookup rule in either `forks.py`. The only permitted changes are the ones in
   §3.3's diff. If any other line needs to move, stop and say so.
2. **MUST** use `op.AppGlobal.get_ex_bytes(0, key)` with an explicit `exists`
   assert, not `get_bytes` (§3.2), and **MUST** keep the
   `raw.length == FORK_ROW_BYTES` assert.
3. **MUST** add a module-scope `assert FORK_TABLE_CAPACITY <= 256` (plain Python,
   evaluated at compile time) beside each capacity constant, with a comment naming
   the single-index-byte key scheme as the reason (§9.1).
4. **MUST** declare `state_totals=StateTotals(...)` on both contract classes with
   the capacity constant *referenced*, never inlined as a literal (§3.4).
5. **MUST** remove the now-unused `Bytes` import from
   `contracts/state_anchor/constants.py` and re-run the linter — this is a real
   `F401` the change introduces.
6. **MUST NOT** write a literal `StateSchema(n, m)` anywhere in `deploy/`. The
   create transaction's schema **MUST** be read from the freshly compiled ARC-56
   (§5.1 item 2). A grep for `StateSchema(` returning any pair of integer literals
   for m4/m8 fails G3-R13.
7. **MUST** replace, not delete, the `forks` reference in the bootstrap group
   (`relayer/client.py:695` and the two test copies): `key_refs[:8]` keeps the
   group at 25 references (§6.4). Deleting it silently under-budgets the group.
8. **MUST** make `deploy/inspect.py` expose raw `bytes` global-state keys, and
   **MUST** filter fork-row keys out of the default human-facing dump (§5.1 item
   4, §15.2 item 6).
9. **MUST** narrow (or delete) `_read_fork_rows`'s bare `except Exception: return
   []` in both plans — it existed to catch a missing box and can no longer be
   doing that job (§8 case 5).
10. **MUST** update `tests/harness/test_versions.py::V-3`'s marker tuple to
    `("FORK_ROW_KEY_PREFIX", "FORK_TABLE_CAPACITY", "append_fork_row")`. Leaving
    `FORKS_BOX_NAME` there silently weakens a structural test.
11. **MUST** keep `choose_mode`'s popcount tie-break but comment it as
    provably unreachable under the revised cost model, with the one-line reason
    (`3k_d = 3k_c + 1` has no integer solutions) — and **MUST NOT** leave any test
    asserting that a tie occurs (§6.3c).
12. **MUST** regenerate and commit both ARC-56 artifacts and both
    `*.schema.json` artifacts in the same commit as the contract change, so
    `tests/deploy/test_schema.py::X-1` never sees a split state.
13. **MUST** rewrite `tests/sync_committee/harness.py::create`'s docstring rather
    than leaving it describing the probe-fund-create dance it no longer performs.
    That docstring is currently the clearest description of the defect in the
    repository, and leaving it in place after the defect is gone is how the next
    reader gets misled.
14. **MUST** re-run the full M4 and M8 live suites against real dev-mode algod and
    report the real counts (§15.1). A green offline run is not evidence for
    G2/G4/G7/G9-R13.
15. **MUST** record, in the implementation report, the real measured answer to
    the three open items in §13 (the `k = 5` filler behaviour, the over-schema
    error string, the 64-byte value cap) — or state plainly that they were not
    reached.
16. **MUST NOT** deploy to mainnet as part of the implementation pass. This
    document ends at a re-verified, re-pinned pair of contracts; the mainnet
    create is a separate, human-initiated step.
