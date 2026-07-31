# 005 — M5: MPT path-walker / node verifier

Status: **Design Drafted** (awaiting human approval)
Module: **M5** (`contracts/mpt/`)
Depends on: M2 (`contracts/primitives/rlp/`, Implemented), M4 (trusted root, Implemented)
Blocks: M6 (account/storage composer), M7 (receipt/log), M9 (relayer)
Spike evidence: `tests/fixtures/spike-reference/mpt_bench.py` (`build_verifier` — the
defect this module exists to fix), `tests/fixtures/spike-reference/MPT_RESULTS.md` §1–§5
Measured dependencies: `docs/design/002-rlp-decoder.md` §16, `bench/rlp_results.json`

---

## 0. The bug, stated first

The research spike's verifier (`mpt_bench.py:build_verifier`, lines 301–329) is:

```python
for i, st in enumerate(steps):
    lines += [f"bytec {i}", "keccak256", "load 0", "==", "assert"]   # hash chain OK
    if "extract" in st:
        lines += [f"bytec {i}", f"int {st['extract']}", "callsub rlp_item", "store 0"]
```

`steps` is a **Python-side list supplied by whoever builds the program**. The contract
verifies that node *i* hashes to the reference extracted from node *i*−1, and nothing
else. It never asks *which key* this path spells. A relayer holding any honest,
fully hash-chained mainnet proof can therefore present it as a proof about **any key
it likes**: every `assert` passes, because every `assert` is about hashes, and the
key never enters the computation at all.

That is the same defect class M3's design doc found in SSZ generalized-index handling
— a gindex taken from untrusted data proves nothing about *which field* it names.
"Same shape, different tree." M5 is where the MPT version gets fixed.

The fix, in one sentence: **the descent index at every branch hop is computed on-chain
from the key's own nibbles, and every extension/leaf path segment is compared on-chain
against the corresponding slice of the key, so a proof is bound to exactly one key.**
M5's public interface contains **no caller-supplied step list, child index, or path
parameter of any kind** — that absence is a design invariant, enforced by test S2.

---

## 1. Scope and non-goals

### 1.1 In scope

M5 ships a **library of Puya `@subroutine`s** in `contracts/mpt/` (plus a
measurement/reference app that is not the production app) implementing exactly one
statement:

> Given a **trusted root** `R`, a **key** `K` derived on-chain from a preimage, and a
> caller-supplied list of MPT node byte strings, decide whether `K` is present under
> `R`, and if so return the span of its value — verifying at every hop both that the
> node hashes into the chain **and** that the descent follows `K`'s own nibbles.

Concretely:

1. **On-chain key derivation** for both real conventions: `keccak256(preimage)` for
   state/storage tries, minimal-RLP-of-index for the receipts trie (§4).
2. **Per-node-type verified descent** — branch (17 items), extension (2 items,
   non-terminating hex-prefix), leaf (2 items, terminating hex-prefix) — §5.
3. **Embedded/inline child handling** — a child whose RLP encoding is under 32 bytes is
   inlined in the parent rather than hash-referenced; M5 continues walking inside the
   same buffer without consuming a supplied node (§5.5). Ethereum-real, and the spike
   never handled it.
4. **Inclusion and exclusion**, as one walk producing a status discriminator (§6).
5. **A segmented, group-internal walk driver** that solves the "a real account proof is
   3,732 bytes and one transaction can carry 2,048 bytes of arguments" problem, with the
   inter-transaction hand-off cryptographically bound rather than caller-asserted (§7).
6. A **Python reference walker** (`tests/reference/mpt_ref.py`) that is the differential
   authority, plus a bench app so every budget number traces to a real
   `/v2/transactions/simulate` response.

### 1.2 Non-goals (explicit)

- **No account, storage, or receipt semantics.** M5 returns "the value at key `K` under
  root `R` is the span `(off, len)` of node `N`". Naming its fields
  `nonce`/`balance`/`storageRoot`/`codeHash` is M6; `status`/`cumGas`/`bloom`/`logs` is
  M7. M5 never calls `receipt_envelope`.
- **No root anchoring.** Where `R` comes from and whether it is trusted is M8's; M5
  takes it as a parameter and states TP-M5-1 (§1.3) about it.
- **No chaining of one trie into another.** `stateRoot → account leaf → storageRoot →
  storage leaf` is two independent M5 walks glued by M6, which extracts `storageRoot`
  from the account leaf's value and feeds it back in as a new `R`.
- **No solution to the >4096-byte receipt leaf.** Still M7's (`ROADMAP.md`). §7.6 states
  precisely which part of M5 that problem does and does not touch.
- **No production app class.** M5 is a library; the deployable app's ABI, root lookup,
  and access control belong to M6/M8. M5 ships a reference app only so its own numbers
  can be measured and its own tests can run.
- **No untrusted-RLP hardening** — M5 inherits M2's TP-1 unchanged.

### 1.3 Trust preconditions

**TP-M5-1 (root).** `R` must be a root the caller already trusts — from M8's anchor,
itself produced by M4/M3. M5 makes no claim about `R`'s provenance. Everything M5
proves is conditional on `R`.

**TP-M5-2 (key preimage binding) — load-bearing, and the whole point of the module.**
M5 must be given the **preimage** (a 20-byte address, a 32-byte storage slot, a
`uint64` transaction index), never a pre-derived 32-byte trie key. Accepting a
pre-derived key would re-open the original defect one level up: a relayer that can
choose the "key hash" can choose which account the proof is about. §4 makes this
structural — there is no entry point that takes a derived key from outside.

**TP-M5-3 (node bytes).** Node bytes are untrusted on arrival and become trusted
exactly when `keccak256(node) == expected`. Every node is hashed **before** any of its
bytes are parsed. This is what licenses M2's TP-1 downstream of M5.

---

## 2. Where M5 sits, and which M2 entry points it uses

`docs/design/002-rlp-decoder.md` §16.5 requires this doc to "state which entry point it
uses per call site and why". Answer:

| M5 call site | M2 entry point | Why |
|---|---|---|
| arity discrimination + 2-item decode | `rlp_list_header` + 2 × `rlp_item_header` (via M5's `mpt_descend`, §5.1) | one code path that both classifies the node and decodes ext/leaf; equals `rlp_scan2`'s work exactly when the node *is* 2-item |
| branch child at derived index | M5's own fused skip loop, continuing from item 2 (§5.1) | `rlp_scan_upto` would re-walk items 0–1 the discriminator already walked (~90 budget/hop, ~25 % of baseline); the fused loop reuses that work |
| branch value slot (item 16) | same loop, walking to payload_end | reaching payload_end also yields a free arity check for this one case |
| hex-prefix path decode | `hp_decode` | absolute-nibble-index return is exactly what §5.3/§5.4 need |
| path-vs-key comparison | `nibbles_equal` | the core security comparison; byte-aligned fast path (measured G4) |
| key nibble at a depth | `nibble_at` (already `inline=True` in M2) | 3-opcode body, called once per branch hop |
| materialising a child hash | `rlp_bytes` | must be `extract3`, never immediate `extract` (M2 E1) |
| **not used** | `rlp_scan` / `rlp_table_item` / `mpt_node_scan` | M5 reads at most two items from any node and never revisits one; the flat table's cost is pure loss here (M2 §16.4 measured this exactly: 5,302 vs 2,566 on the same 8-node walk) |
| **not used** | `receipt_envelope` | M7's, not M5's (§1.2) |

**M5 duplicates M2's per-item skip arithmetic once** (in the fused branch loop). M2
§2.4 established the rule for that: duplication is permitted **only** with a mandatory
differential test asserting the duplicate agrees with the canonical path on every item
of every fixture node. M5 inherits that obligation as test **D1** (§9.5). Do not ship
the loop without it.

**Program size.** M2 §16.5 records that its own headroom shrank to 61 B against its
900 B gate, and warns M5/M6 to budget their share of the 8,192 B per-call cap. M5's
share is gate **G5-M5**: ≤ 1,400 B compiled for `contracts/mpt/` on top of M2's 839 B,
leaving ≈ 5,900 B for M6/M7/M8 and ARC-4 glue in a program that must hold all of them.

---

## 3. Data model

### 3.1 Status discriminator

```python
WALK_CONTINUE            = 0   # this segment ended mid-path; `expected` is the next node's hash
WALK_INCLUDED            = 1   # key present; value span returned
WALK_ABSENT_EMPTY_SLOT   = 2   # branch child slot for the key's nibble is the empty string
WALK_ABSENT_EXT_DIVERGE  = 3   # extension path diverges from the key
WALK_ABSENT_LEAF_DIVERGE = 4   # leaf path length or content differs from the key remainder
WALK_ABSENT_BRANCH_TERM  = 5   # key ends exactly at a branch whose item 16 is empty
```

`WALK_ABSENT_*` are *terminal* — a caller may never continue a walk from one.

### 3.2 Walk state `W` — fixed 101 bytes

```
offset  size  field
  0       1   status      (uint8, §3.1)
  1      32   root        R, the trusted root this walk is anchored to   [IMMUTABLE]
 33      32   expected    keccak of the next node to supply              [cursor]
 65       2   depth       big-endian uint16, key nibbles consumed        [cursor]
 67       2   key_nibs    big-endian uint16, total nibbles in the key    [IMMUTABLE]
 69      32   key         the derived trie key, right-zero-padded        [IMMUTABLE]
```

Design notes:

- **Fixed width, not variable.** 101 bytes always. Slicing is constant-offset
  `extract3`; there is no length arithmetic anywhere in the hot path. Keys are ≤ 32
  bytes for every trie M5's consumers walk (state/storage: exactly 32; receipts: 1–3,
  §4.2). A future trie with longer keys widens `W` and re-measures — noted, not
  designed for.
- **`root` and `key` travel with the cursor.** This is what makes a completed walk
  *self-describing*: the terminal `W` asserts "under root `R`, key `K` resolves to this
  value". M6 checks `W.root` against its own anchor and `W.key` against
  `keccak256(the address it actually wants)`. Without this, a segmented walk could in
  principle be cross-linked to a different walk in the same group (§7.4); with it,
  cross-linking is a no-op because the linked state names its own root and key.
- **`key_nibs` is carried, not recomputed.** It is `2 × len(key_bytes)` and is the
  quantity every §5 length check compares against.
- A `W` with `status != WALK_CONTINUE` is terminal; §7.3's driver refuses to extend it.

---

## 4. Key derivation — on-chain, both conventions

### 4.1 State and storage tries: hashed keys

```python
@subroutine
def mpt_key_from_address(addr: Bytes) -> Bytes:
    """State-trie key for an Ethereum account. assert addr.length == 20 -> "W1"."""
    assert addr.length == 20, "W1"
    return op.keccak256(addr)

@subroutine
def mpt_key_from_slot(slot: Bytes) -> Bytes:
    """Storage-trie key for a storage slot. assert slot.length == 32 -> "W2".
    The caller (M6) is responsible for having computed `slot` itself — e.g.
    keccak256(pad32(holder) || pad32(mapping_slot)) for a Solidity mapping — and
    for that computation also being on-chain if the holder is untrusted."""
    assert slot.length == 32, "W2"
    return op.keccak256(slot)
```

**Decision: M5 hashes on-chain; it never accepts a pre-hashed key.** Justification:

- **Cost is negligible and measured.** `MPT_RESULTS.md` §1 measured `keccak256` at a
  **flat 130 budget regardless of input size** (32 B and 4096 B are identical). One
  extra hash is 130 against a ~2,600 baseline — **5.1 %** of one walk, ~0.5 % of a full
  account+storage read once donor calls are counted.
- **Moving it off-chain destroys the module's entire purpose.** If the caller supplies
  `keccak256(address)`, a relayer picks which account is proven — the original defect,
  relocated from "which child index" to "which key". There is no cheaper place to put
  this that keeps the guarantee.
- **The 20/32-byte length asserts are not decoration.** They stop a caller from passing
  a 32-byte *already-hashed* value to `mpt_key_from_address` (rejected: length 32 ≠ 20)
  and make the two conventions non-interchangeable at the type level.

Real vectors (recomputed from `tests/fixtures/spike-reference/eth_data.json` while
writing this doc, all verified against the real proofs):

| preimage | derived key | first 8 nibbles |
|---|---|---|
| `0xdAC17F958D2ee523a2206206994597C13D831ec7` (USDT) | `ab14d68802a763f7db875346d03fbf86f137de55814b191c069e721f47474733` | `a b 1 4 d 6 8 8` |
| `0x0be16d71963429204d70543701f859c43526c316ac005c10114f4694ca405f36` (slot) | `aa2813d62366783a4fc90e52c8cc595ba9fd2b278bc52248117c14c07e5394d8` | `a a 2 8 1 3 d 6` |

### 4.2 Receipts trie: un-hashed, variable-length RLP index

The receipts (and transactions) trie is keyed by `RLP(tx_index)` — **not** hashed, and
**not** fixed length. `eth_data.json` records the real case directly:
`receipt_proof.index = 31`, `receipt_proof.key_rlp = "1f"` — a single byte, because
RLP encodes `0x00..0x7f` as itself.

**Decision: M5 owns the encoding and takes a `UInt64` index. It does not accept
pre-encoded key bytes.**

```python
@subroutine
def mpt_key_from_tx_index(index: UInt64) -> Bytes:
    """Receipts/transactions-trie key = minimal RLP of the index.
       index == 0            -> 0x80             (RLP of the empty byte string)
       1 <= index <= 0x7f    -> the single byte   (RLP single-byte self-encoding)
       0x80 <= index <= 0xff -> 0x81 || byte
       0x100 <= i <= 0xffff  -> 0x82 || be2(i)
       0x10000 <= i <= 0xffffff -> 0x83 || be3(i)
       index > 0xffffff      -> assert -> "W3"
    """
```

Justification for encoding rather than accepting bytes:

- Accepting bytes would require asserting they are **canonical minimal RLP** anyway
  (`0x81 0x05` and `0x05` must not both be accepted for index 5 — they are different
  keys, and only one exists in the trie). That check costs about as much as just doing
  the encoding, and gets it wrong more easily.
- Accepting bytes reintroduces exactly the defect class: a caller choosing the key bytes
  is a caller choosing which receipt is proven. `mpt_key_from_tx_index(31)` binds the
  proof to "the transaction at index 31", which is a statement the application layer can
  actually reason about.
- The `0xffffff` cap (16,777,215) is far above any physically possible transaction count
  in a block (today's gas limit / 21,000 ≈ 1.7 × 10³) and keeps the encoder to four
  compile-time-unrolled branches with no loop.

**Note the `index == 0` trap.** `RLP(0)` is `0x80` (the empty string), **not** `0x00`.
Getting this wrong makes every proof about the first transaction in a block fail, and it
is invisible unless tested — test R3 (§9.4) pins it.

Real cross-check: `mpt_key_from_tx_index(31)` must equal `0x1f`, which is
`eth_data.json receipt_proof.key_rlp` verbatim. Its two nibbles `1, f` are exactly the
two branch descents the real 3-node receipt proof takes (§5.6).

**Derived observation, recorded but not relied upon.** Minimal-RLP receipt keys are
prefix-free: single-byte keys are `0x00..0x7f` (first nibble 0–7) plus `0x80` (nibbles
`8,0`), while every multi-byte key begins `0x81`/`0x82`/`0x83` (nibbles `8,1` / `8,2` /
`8,3`). So no receipt key is a prefix of another, and the "leaf path is a strict prefix
of the key remainder" case cannot arise from real receipt keys. **M5 still implements
the exact-length leaf check (§5.4) unconditionally** — the check is what makes the
walker correct for *any* trie, and a security property that holds only because of a
side observation about one key encoding is not a security property.

---

## 5. The verified descent — the security fix, spelled out

### 5.1 Node arity discrimination (must come first, and must not be clever)

M5 must know whether it is looking at a 17-item branch or a 2-item extension/leaf
before it can do anything. This cannot be sniffed from item 0's shape: a branch child
is `0xa0 ‖ 32 bytes`, and a leaf with a 63- or 64-nibble path also encodes as
`0xa0 ‖ 32 bytes`. A shape-based discriminator has an ambiguous row.

**Decision: discriminate unconditionally by "does item 1 end exactly at payload_end".**

```python
@subroutine
def mpt_descend(node: Bytes, start: UInt64, want: UInt64
                ) -> tuple[UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64]:
    """Returns (arity, o0, l0, k0, ow, lw, kw).
       arity == 2  -> (o0,l0,k0) is item 0 (the compact path), (ow,lw,kw) is item 1;
                      `want` is ignored.
       arity == 17 -> (o0,l0,k0) is item 0, (ow,lw,kw) is item `want`.
    """
    payload_off, payload_end = rlp_list_header(node, start)      # M2
    o0, l0, k0 = rlp_item_header(node, payload_off)              # M2
    o1, l1, k1 = rlp_item_header(node, o0 + l0)                  # M2
    if o1 + l1 == payload_end:
        return 2, o0, l0, k0, o1, l1, k1                         # == rlp_scan2's result
    # branch: items 0 and 1 already decoded; walk on from item 2.
    if want == 0: return 17, o0, l0, k0, o0, l0, k0
    if want == 1: return 17, o0, l0, k0, o1, l1, k1
    pos = o1 + l1
    n = UInt64(2)
    while n < want:
        assert pos < payload_end, "W9"
        pos += <M2's per-item stride arithmetic, duplicated — see §2 and test D1>
        n += 1
    assert pos < payload_end, "W9"
    ow, lw, kw = rlp_item_header(node, pos)
    return 17, o0, l0, k0, ow, lw, kw
```

Why unconditional and not the cheaper shape test:

- It is **one code path with no ambiguous row**. The shape discriminator needs a
  decision table with a `len == 32` special case resolved by this same payload-end test
  anyway — i.e. cleverness that saves ~15 budget/hop and adds a row that can only be
  tested with a hand-derived fixture. Not a trade worth making in the module whose
  entire reason for existing is a subtle verification bug.
- Every misclassification is **fail-closed**, both ways: a branch misread as 2-item
  fails the payload-end equality; a 2-item node misread as a branch fails `"W9"` at
  `want >= 2`. So the cost of being wrong is a rejected transaction, never a wrong
  answer. That is a nice property but it is a backstop, not the reason.
- Measured cost: one extra `rlp_item_header` per branch hop versus a bare
  `rlp_scan_upto`, and **zero** versus `rlp_scan2` for 2-item nodes. §8 budgets it at
  ≈ 15/hop, ≈ 105 on the real 8-node account proof (**4 %**).

The shape-based fast discriminator is recorded in §11 as deferred optimisation
**O-M5-1**, to be revisited only if gate G6-M5 fails.

Two properties of `mpt_descend` the implementer must not "fix":

- For `arity == 17` it does **not** verify the node has exactly 17 items (it early-exits
  at `want`). This is the identical trade `rlp_scan_upto` documents (M2 §16.3): under
  TP-M5-3 the bytes are hash-committed, so arity is corroborated by the root, and the
  redundant check is defence-in-depth rather than load-bearing. The one case that *does*
  reach payload_end — `want == 16`, §5.2 — gets the arity check for free.
- Item 0 is returned even in the branch case. Costs nothing (already decoded) and lets
  §5.2 assert the branch's own well-formedness cheaply if a future pass wants it.

### 5.2 Branch node (arity 17) — where the spike's bug lived

```
Given: node, start, expected(already checked), key, key_nibs, depth

1. TERMINAL CHECK, FIRST.
   assert depth <= key_nibs                                        -> "W4"
   if depth == key_nibs:
       # the key ends exactly at this branch; its value, if any, is item 16.
       arity, _, _, _, ov, lv, kv = mpt_descend(node, start, 16)
       assert arity == 17                                          -> "W5"
       if lv == 0:  return WALK_ABSENT_BRANCH_TERM
       return WALK_INCLUDED with value span (ov, lv)

2. DERIVE THE INDEX FROM THE KEY — never from an argument.
   nib = nibble_at(key, depth)          # M2, inline; 0 <= nib <= 15 by construction

3. FETCH THAT CHILD, AND ONLY THAT CHILD.
   arity, _, _, _, oc, lc, kc = mpt_descend(node, start, nib)
   assert arity == 17                                              -> "W5"

4. CLASSIFY THE CHILD REFERENCE.
   if kc == KIND_STR and lc == 0:   return WALK_ABSENT_EMPTY_SLOT   # 0x80, empty slot
   if kc == KIND_STR and lc == 32:  next_expected = rlp_bytes(node, oc, 32)
                                    depth += 1
                                    return WALK_CONTINUE
   if kc == KIND_LIST:              # embedded child, < 32 B encoded -- §5.5
                                    depth += 1
                                    continue walking IN THIS BUFFER at offset oc
   otherwise:                       assert False                    -> "W6"
```

The load-bearing lines are 2 and 3. `nib` is a function of `key` and `depth` **only**.
There is no parameter, no argument, and no field of `W` that a caller can set to change
which child is read. `depth` is itself not caller-settable across a segment boundary
(§7.4). This is the entire fix, and it is four opcodes.

Step 1 must come **before** step 2, because `nibble_at(key, depth)` at `depth ==
key_nibs` would read past the key. Ordering is load-bearing.

Real-data confirmation (recomputed from `eth_data.json` while writing this doc; every
`keccak256` link verified, every branch index derived purely from the key nibble):

| proof | derived branch indices, hop by hop | key nibbles consumed |
|---|---|---|
| account (8 nodes) | 10, 11, 1, 4, 13, 6, 8 | `a b 1 4 d 6 8` |
| storage (9 nodes) | 10, 10, 2, 8, 1, 3, 13, 6 | `a a 2 8 1 3 d 6` |
| receipt (3 nodes) | 1, 15 | `1 f` |

The account row is **exactly the `child_indices` list baked into M2's gate-G6 bench
contract** (`contracts/primitives/rlp/bench_app.py`, derived there offline by matching
`keccak256(next node)` against each slot). M5 derives the same seven indices from the
key alone, on-chain. That is why M2's measured 2,566 is a true baseline for M5's descent
work rather than an analogy (§8).

**Item 16 in real data.** All 17 branch nodes across the three fixture proofs have item
16 = span `(len(node), 0)` — offset *equal to the node length*, length zero. M2 E2 already
records the consequence: `extract3(node, 532, 0)` is legal, `getbyte(node, 532)` is not.
M5 must therefore test `lv == 0` and never index into an empty value span.

**Reachability of the `depth == key_nibs` branch-terminal case, stated honestly.** It is
structurally unreachable in all three tries M5's consumers walk: state and storage keys
are all exactly 64 nibbles, so no key is a prefix of another and no branch can sit at
depth 64; receipt keys are prefix-free (§4.2). M5 implements it anyway, because (a) the
cost is one comparison per hop, (b) the *code* must be correct for a general MPT or the
next trie someone points this at is a vulnerability, and (c) unimplemented-but-reachable
is exactly the shape of the bug this module exists to fix. It is covered by a derived
fixture (test E2, §9.4), not by real data.

### 5.3 Extension node (arity 2, hex-prefix non-terminating)

```
1. arity, o0, l0, k0, oc, lc, kc = mpt_descend(node, start, 0)   # arity == 2
   is_leaf, n_path, nib_index = hp_decode(node, o0, l0)          # M2
   (this branch runs when is_leaf is False)

2. BOUNDS FIRST -- an extension can only match if the key has room for it.
   if depth + n_path > key_nibs:   return WALK_ABSENT_EXT_DIVERGE

3. THE COMPARISON -- the security check.
   if not nibbles_equal(node, nib_index, key, depth, n_path):
       return WALK_ABSENT_EXT_DIVERGE

4. depth += n_path
   classify (oc, lc, kc) exactly as branch step 4 (§5.2): 32-byte hash -> CONTINUE,
   KIND_LIST -> inline descent (§5.5), empty -> "W7" (an extension's child is never
   empty in a well-formed trie), anything else -> "W6".
```

Step 2 before step 3 is mandatory. Without it, `nibbles_equal` reads past the end of
`key` — which the AVM would reject with an out-of-bounds panic, so it is fail-closed,
but a panic is not a *verdict*: exclusion mode must be able to answer "absent" rather
than aborting the transaction, and a walk that aborts cannot distinguish "key absent"
from "relayer sent garbage". Do the bounds test explicitly.

`nibbles_equal` returns `False` at the **first** mismatching nibble (M2's implementation:
the misaligned fallback loop `return False` inside the loop; the aligned path is a
single `extract3` comparison). So "must reject at the mismatch point, not silently
continue" is satisfied by construction — but test S5 (§9.3) pins it by asserting the
divergence position, not merely the rejection.

**Alignment, and why extension nodes are the expensive case.** M2 §5.4 proves that for
*leaves* the key-side and path-side nibble indices always share parity, so the comparison
takes the byte-aligned fast path (gate G4: measured 42 raw / 2 isolated for a 57-nibble
compare). **Extension nodes have no such invariant**: `n_path` is unconstrained relative
to `depth`, so `nib_index` and `depth` can differ in parity and M2's per-nibble fallback
loop runs. Extension paths are short in practice (a handful of nibbles), so this is
acceptable — but it is real code on a real path and §8 budgets it, and §9 requires the
derived extension fixtures to exercise it. Do not assume the leaf invariant here.

### 5.4 Leaf node (arity 2, hex-prefix terminating) — the second place the bug can hide

```
1. arity, o0, l0, k0, ov, lv, kv = mpt_descend(node, start, 0)   # arity == 2
   is_leaf, n_path, nib_index = hp_decode(node, o0, l0)
   (this branch runs when is_leaf is True)

2. EXACT LENGTH -- not >=, not <=.
   if depth + n_path != key_nibs:   return WALK_ABSENT_LEAF_DIVERGE

3. EXACT CONTENT over the whole remainder.
   if not nibbles_equal(node, nib_index, key, depth, n_path):
       return WALK_ABSENT_LEAF_DIVERGE

4. return WALK_INCLUDED with value span (ov, lv), depth = key_nibs
```

Step 2 is the leaf-side instance of the module's whole thesis. A leaf whose path is a
**strict prefix** of the key remainder must be rejected: it is a leaf for a *different,
shorter* key that happens to share a prefix with the one asked about, and accepting it
would prove the wrong key's value — the original defect relocated to the terminal hop.
`!=` on the total length is what rejects it; a `<=` or a "compare `n_path` nibbles and
stop" would accept it. Test S4 (§9.3) is the regression.

The converse — key remainder longer than the leaf path — is the same `!=`, and is the
case that arises naturally when asking about a key that is absent from the trie
(the trie's leaf for that subtree belongs to a different key). That is `WALK_ABSENT_LEAF_DIVERGE`
and is a *sound exclusion proof* (§6).

Real-data confirmation (all three recomputed while writing this doc):

| leaf | hp flag | `n_path` | `nib_index` | depth on arrival | `depth + n_path` | value span |
|---|---|---|---|---|---|---|
| `accountProof[7]` (104 B) | `f = 3` leaf/odd | 57 | 7 | 7 | 64 ✓ | (34, 70) |
| `storageProof[0].proof[8]` (40 B) | `f = 2` leaf/even | 56 | 6 | 8 | 64 ✓ | (32, 8) |
| `receipt_proof.nodes[2]` (690 B) | `f = 2` leaf/even | 0 | 8 | 2 | 2 ✓ | (7, 683) |

In each case the path nibbles were extracted and compared byte-for-byte against the key
remainder and matched exactly. The third row is the zero-nibble leaf — `n_path == 0`,
`nibbles_equal` returns `True` immediately on `count == 0`, and the length test
`2 + 0 == 2` is what actually does the work. Worth noting: for that leaf, step 3 proves
nothing at all and step 2 proves everything. A design that only implemented step 3 would
accept `receipt_proof.nodes[2]` as the leaf for **any** key of any length whose path
happened to arrive here. That is not hypothetical — it is the exact input the fixture set
already contains.

### 5.5 Embedded (inline) children

An MPT child whose RLP encoding is under 32 bytes is stored **inline** in the parent
instead of being hash-referenced (`kc == KIND_LIST`). Three consequences:

1. **Do not hash it.** It is already committed by the parent's own hash. Hashing the
   span would produce a value that matches nothing.
2. **Do not consume a supplied node.** `eth_getProof` does not list embedded children as
   separate proof nodes. A walker that expects one node per hop desynchronises the whole
   node list from the path the moment it meets one.
3. **Continue in the same buffer.** M2's copy-free `(data, start)` span discipline makes
   this free: the walk cursor is `(node, offset)`, and an inline descent is `offset =
   oc`. No slicing, no second buffer.

`mpt_walk_node` (§7.1) therefore contains an inner loop over `start` within one node
buffer, bounded by `assert inline_steps <= 8 -> "W8"`. The bound is generous (an
embedded node is < 32 bytes, so a chain of them inside one ≤ 4096-byte buffer is short)
and exists only so a malformed-but-hash-committed input cannot loop.

`eth_data.json` contains **no embedded child** (M2 §8.2 E14 recorded the same gap). The
fixture must be derived — §9.2.

### 5.6 Worked real example: the 3-node receipt proof, end to end

```
R = receiptsRoot 0x6490277f4254f8d51780f05201c5a9a9985a5d4c3d207a68eda643dc099e710b
key = mpt_key_from_tx_index(31) = 0x1f       key_nibs = 2      nibbles: 1, f

hop 0  node[0] (308 B).  keccak256(node) == R                            ✓
       mpt_descend -> item1 does not end at payload_end -> arity 17
       depth(0) < key_nibs(2)  ->  nib = nibble_at(key, 0) = 1
       item 1 span = (37, 32), KIND_STR len 32 -> next_expected, depth = 1

hop 1  node[1] (532 B).  keccak256(node) == expected                     ✓
       arity 17;  nib = nibble_at(key, 1) = 0xf = 15
       item 15 span = (499, 32) -> next_expected, depth = 2

hop 2  node[2] (690 B).  keccak256(node) == expected                     ✓
       mpt_descend -> item1 ends at payload_end -> arity 2
       item 0 = (3, 1) = the single byte 0x20  ->  hp_decode: leaf, n_path 0, nib_index 8
       depth(2) + n_path(0) == key_nibs(2)                               ✓  (§5.4 step 2)
       nibbles_equal(count=0) -> True                                    ✓
       WALK_INCLUDED, value span (7, 683)
```

The value at `(7, 683)` begins `02 f902a7 01 83 6f1cbb b90100…` — the EIP-2718 typed
envelope M7 will strip with `receipt_envelope`. M5 hands over the span and stops.

---

## 6. Exclusion proofs — M5's answer

**Decision: M5 v1 proves inclusion *and* computes exclusion, as one walk, returning a
status. The asserting entry point `mpt_verify_inclusion` is what M6/M7 use by default;
exclusion is opt-in via `mpt_walk`. M5 makes no claim about what absence *means*
semantically — that is M6/M7.**

Rationale:

- **The four absent forms are already the walker's assert sites.** §5.2 step 4's empty
  slot, §5.2 step 1's empty item 16, §5.3 step 2/3's divergence, §5.4 step 2/3's
  divergence. Returning a status instead of asserting costs approximately nothing, and
  *refusing* to return them would force M6 to re-derive them — which means re-writing
  the walker, badly, one module later.
- **Each form is individually sound given the hash chain.** The node exhibiting the
  terminal condition is itself hash-linked to `R`, so its contents are as trusted as `R`.
  An empty slot at the key's nibble means no key with this prefix exists; a diverging
  leaf means the unique terminus of this trie position belongs to another key. This is
  the standard Ethereum exclusion proof; nothing novel is being invented.
- **The one real trap is "ran out of nodes" masquerading as absence.** A relayer that
  supplies the first three nodes of an eight-node path and claims exclusion must be
  rejected. §7.3's driver therefore distinguishes three outcomes explicitly:
  terminal status reached (verdict), `WALK_CONTINUE` with nodes remaining in this
  segment (impossible — a bug), and `WALK_CONTINUE` with the segment's nodes exhausted
  (**not a verdict** — the caller must supply another segment or the group fails). A
  walk that never reaches a terminal status yields no result at all. Test X5 (§9.4) is
  the regression.
- **Unconsumed trailing nodes are rejected** (`"W10"`). Not a soundness issue, but
  strictness is free and removes ambiguity about which nodes the verdict rests on.

What M5 explicitly does **not** decide, flagged for M6/M7 (§11):

- Whether `WALK_ABSENT_*` under the **state** trie means "this account does not exist" —
  M6's, and it must distinguish that from an account that exists with zero balance.
- Whether `WALK_ABSENT_*` under a **storage** trie means "this slot is zero" — it does,
  because Ethereum stores no entry for a zero slot, but the mapping from "absent" to the
  integer 0 is a semantic claim M6 owns, and it is exactly the sort of claim that must be
  written down rather than assumed. Note also M2 E15: a *present* zero storage value is
  the empty string `0x80`, not `0x00`.
- Whether exclusion is meaningful at all for **receipts** — M7's; a "receipt at index *i*
  does not exist" claim is only useful alongside a transaction-count bound M5 has no
  access to.

---

## 7. Delivering the nodes: args vs. boxes — decided, with the arithmetic

### 7.1 The pure core (transaction-unaware)

```python
@subroutine
def mpt_walk_node(node: Bytes, w: Bytes) -> tuple[Bytes, UInt64, UInt64]:
    """Verify keccak256(node) == w.expected, then walk as far as possible INSIDE
    this one buffer (following inline children, §5.5).
    Returns (w_out, value_off, value_len); value_* are meaningful only when
    w_out.status == WALK_INCLUDED, and index into `node`.
    assert keccak256(node) == w[33:65]   -> "W11"
    assert w[0] == WALK_CONTINUE          -> "W12" (cannot extend a terminal walk)
    """
```

This subroutine, `mpt_descend`, the three node-type handlers, and the key derivations are
the whole of M5's security content, and none of them touch `Txn`. They are unit-testable
offline against the Python reference walker with no transaction context at all — which is
the point of separating them.

### 7.2 Why one transaction cannot carry a real proof — measured

Both limits below were measured live against dev-mode algod (build 4.7.3, the same
localnet recipe as `bench/rlp_bench.py`), by submitting deliberately oversized
application-call arguments and reading the literal protocol rejection:

| limit | measured value | literal error at the boundary |
|---|---|---|
| total application-argument bytes **per transaction** | **2,048** | `tx.ApplicationArgs total length is too long. 2049 > 2048` |
| application arguments **per transaction** | **16** | `tx.ApplicationArgs has too many arguments. 17 > 16` |
| log bytes **per app call** | **1,024** | `program logs too large` at 1,025 |

2,048 total is a **per-transaction** cap on the sum of all arguments — splitting one
blob into 16 arguments does not help (2,049 in 16 args fails identically). Against real
proof sizes from `eth_data.json`:

| proof | node sizes | total bytes |
|---|---|---|
| account | 532×6, 436, 104 | **3,732** |
| storage | 532×5, 468, 83, 83, 40 | **3,334** |
| receipt | 308, 532, 690 | **1,530** |
| account + storage (a full state read) | — | **7,066** |

**A real 8-node account proof is 1.82× a single transaction's entire argument budget.**
Single-call, args-only verification of a real proof is not merely expensive — it is
impossible. That fact, not a preference, is what drives the rest of this section.

### 7.3 Decision: raw app-args, segmented walk, one atomic group. No boxes.

Each node is its **own raw application argument** (not an ARC-4 `byte[][]`, whose
`2 + 4n` bytes of framing and per-element decode cost buy nothing here). A segment call's
arguments are:

```
arg 0 : method selector                                   4 B
arg 1 : W_in, the 101-byte walk state (§3.2)            101 B
arg 2 : group index of the transaction that produced W_in  1 B   (ignored on segment 0)
arg 3..15 : proof nodes, one per argument            <= 1,942 B total, <= 13 nodes
```

Usable node capacity per transaction: `2048 − 4 − 101 − 1 = ` **1,942 bytes**, in at most
13 arguments. Segmenting the real proofs greedily:

| proof | segment 1 | segment 2 | segment 3 | calls |
|---|---|---|---|---|
| account | nodes 0–2 (1,596 B) | nodes 3–5 (1,596 B) | nodes 6–7 (540 B) | **3** |
| storage | nodes 0–2 (1,596 B) | nodes 3–8 (1,738 B) | — | **2** |
| receipt | nodes 0–2 (1,530 B) | — | — | **1** |
| account + storage | — | — | — | **5** |

Segment 0 builds `W` from `(R, preimage)`; each later segment resumes from the previous
segment's `W`. All segments live in **one atomic group**, so nothing is ever observable
half-walked: if any segment fails, the group fails.

### 7.4 Binding the hand-off — the part that would otherwise re-open the bug

If segment *k*+1 simply accepted `W_in` as an argument, a relayer could forge `depth`,
`expected`, or `key` between segments and the entire §5 apparatus would be worthless.
The hand-off must be **verified**, not asserted.

Mechanism: segment *k* returns `W_out`, which ARC-4 logs as
`0x151f7c75 ‖ <2-byte length> ‖ W_out` (107 bytes — well inside the measured 1,024-byte
log cap). Segment *k*+1 reads its predecessor's log directly out of the group:

```python
@subroutine
def mpt_state_from_prev(gi: UInt64) -> Bytes:
    """Recover the walk state that transaction `gi` of THIS group actually produced."""
    assert gi < Txn.group_index,                              "W13"   # must precede us
    prev = gtxn.ApplicationCallTransaction(gi)
    assert prev.app_id == Global.current_application_id,      "W14"
    assert prev.app_args(0) == <this method's selector>,      "W15"
    log = prev.last_log
    assert log.length == 107 and log[:4] == ARC4_RETURN_PREFIX, "W16"
    return op.extract(log, UInt64(6), UInt64(101))
```

`W_in` is thus **not** trusted from the caller; it is read from a transaction the AVM
itself executed. The caller chooses only *which* transaction to point at, and pointing at
the wrong one yields a `W` that names a different `(root, key)` — which §3.2 makes
self-evident to the final consumer.

**Measured, live, on dev-mode algod:** an honest hand-off (`gtxn i LastLog` matching the
predecessor's real log) passes; a forged hand-off is rejected with
`logic eval error: assert failed`. The verification glue costs **8 opcode budget**
measured in hand-written TEAL (22 consumed with the two checks vs. 14 without, same
group shape) — effectively free. The Puya-compiled version will cost more and §8 budgets
40; the implementation must measure it.

Why not the two alternatives:

- **Caller-passed `W` with no verification** — reopens the defect at the segment
  boundary. Non-starter, listed only because it is the obvious wrong answer.
- **Global/local state hand-off** — works, and `W` fits the 128-byte global byte-slice
  limit, but it leaves real state on-chain between transactions and therefore needs a
  generation/nonce guard and a stale-session discipline. M4 §16 is a first-hand account
  of how much design that costs. The log chain leaves **no persistent state at all**: a
  failed group leaves nothing behind because logs are not state.

### 7.5 Why not box staging — four reasons, strongest first

**(a) Boxes do not solve the delivery problem; they add to it.** Bytes enter the chain
through application arguments regardless of destination. Staging 3,732 bytes into a box
still costs the same two argument-carrying transactions, *plus* the box writes, *plus*
the box reads. It is strictly the args path with extra steps.

**(b) M4's measured box economics are worse than they look.** M4 §16 established, by
direct measurement against real algod: the box-reference cap is exactly **8 per
transaction** (structural), there is a **2,048-byte budget per box reference pooled
across the whole atomic group** (not the 1,024 B/ref the docs suggest, and not
per-transaction), and — §16.5 — `box_extract`/`box_replace` on an existing box charges
the pool the box's **full declared size** once per box per group, not the touched slice.
A 3,732-byte staging box therefore burns ≈ 2 references written and ≈ 2 read, on top of
the argument transactions that fed it.

**(c) Minimum-balance cost.** A 3,732-byte box locks `2,500 + 400 × (3,732 + keylen)`
µAlgo ≈ **1.5 ALGO** for as long as it exists. Per-verification create/delete cycles
make that transient, but it must be funded, and a failed cleanup strands it.

**(d) Boxes are persistent state, and persistent state is a stale-session hazard.** M4
needed an `inst_state` machine *plus* group atomicity to make a multi-transaction box
build-up safe. M5's args+log-chain design needs neither: there is nothing to leave
behind, nothing to reuse, and nothing to guard.

**When boxes genuinely are required — and who owns each case:**

- **M7**: the >4,096-byte receipt leaf. It cannot be an application argument (2,048 cap),
  cannot be an AVM stack value (4,096 cap), and cannot be `keccak256`'d (no streaming
  hash). Boxes do not fix it either — this is the structural problem `ROADMAP.md`
  already flags as a hard stop. M5's contribution is to confirm the boundary is
  unchanged: M5 walks *nodes*, and every node on the path to such a leaf is a normal
  ≤ 532-byte branch node. Only the terminal node is the problem.
- **M8**: root-history storage. Its own decision, unaffected by this one.
- **A future proof exceeding one group.** §7.6 shows the realistic worst case does not.

### 7.6 Does it fit one group? — the arithmetic

`MPT_RESULTS.md` §4 sets the realistic worst case at **account depth ~10 + storage depth
~12 = 22 nodes**. Two ceilings:

**Argument space.** 16 transactions × 1,942 usable bytes = **31,072 B**, ≈ 58 branch
nodes at 532 B each.

**Opcode budget, top-level calls only.** 700 per app call, `⌈budget/700⌉` calls needed
(no `extra-opcode-budget` on-chain — `MPT_RESULTS.md` §5.4). At §8's per-node figure of
≈ 350, `n` nodes need ≈ `n/2` transactions, so 16 transactions ⇒ **n ≤ 32 nodes**.

**Opcode budget, with inner-transaction donors.** `MPT_RESULTS.md` §2 measured the real
ceiling at 16 top-level + 256 inner app calls = 272 × 700 = **190,400 pooled**. With
donors issued as inner transactions, budget stops binding entirely and argument space
(58 nodes) becomes the limit.

| workload | nodes | node bytes | segment calls | budget (§8) | donor calls | txns in group |
|---|---|---|---|---|---|---|
| receipt proof | 3 | 1,530 | 1 | ~1,150 | 1 | **2** of 16 |
| account proof | 8 | 3,732 | 3 | ~3,230 | 2 | **5** of 16 |
| account + storage | 17 | 7,066 | 5 | ~6,050 | 4 | **9** of 16 |
| pathological (§4 of MPT_RESULTS) | 22 | ~11,700 | 8 | ~8,000 | 4 | **12** of 16 |

The realistic worst case uses 12 of 16 transactions and 38 % of one group's argument
space. **One atomic group, no boxes, is sufficient with headroom at every realistic
depth**, and the mechanism that runs out first (top-level budget at ~32 nodes) has a
known escape hatch (inner donors) before argument space (~58 nodes) binds.

---

## 8. Budget arithmetic

### 8.1 The measured baseline M5 builds on

M2's gate **G6** measured a real, live `simulate` composition of the **exact walk M5
performs** on the real 8-node account proof — 7 branch hops via `rlp_scan_upto` at the
real child indices `10, 11, 1, 4, 13, 6, 8`, one leaf hop via `rlp_scan2`, `keccak256`
on every node, chained to the real `stateRoot`:

> **2,566 opcode budget** (`bench/rlp_results.json`, `G6_composition.bare_consumed_fast_16`;
> reproduced across two independent live-algod runs), against the spike's **3,276** and
> M2's own pre-§16 **5,302**.

§5.2 shows M5 derives those same seven indices from the key, so this is a baseline, not
an analogy. Of the 2,566, `8 × 130 = 1,040` is `keccak256` (flat, `MPT_RESULTS.md` §1).

**Do not compose the per-index microbenchmarks instead.** `G1_scan_upto_fast`'s isolated
costs (112 at `want=0`, 422 at `want=10`, 577 at `want=15`) sum to ~3,600 for these
seven indices — well above the 2,566 the same walk actually measured in situ. The
microbenchmark is per-call-shape and does not compose linearly. G6 is the number.

### 8.2 What M5 adds, per hop

| addition | per unit | account proof (7 branch + 1 leaf) | basis |
|---|---|---|---|
| key derivation `keccak256(preimage)` | 130 | 130 | **measured**, flat (`MPT_RESULTS.md` §1) |
| arity discriminator: one extra `rlp_item_header` per branch hop (§5.1) | ~15 | ~105 | target; M2's G3 (164 isolated for header + 2 item decodes + assert) bounds it |
| `nibble_at(key, depth)` + `depth <= key_nibs` + `depth == key_nibs` tests | ~15 | ~105 | target; `nibble_at` is 3 opcodes, forced `inline=True` in M2 |
| child-reference classification (kind/length tests, §5.2 step 4) | ~10 | ~80 | target |
| leaf: `hp_decode` + exact-length test + `nibbles_equal` (57 nibbles, aligned) | ~80 | ~80 | `nibbles_equal` **measured** at G4 = 42 raw / 2 isolated; `hp_decode` unmeasured |
| segment hand-off verification × 2 boundaries (§7.4) | ≤ 40 | ~80 | **measured floor 8** in hand-TEAL; Puya target 40 |
| raw-arg reads for 8 nodes (`Txn.application_args(i)`) | ~10 | ~80 | target; deliberately raw args, not ARC-4 arrays, to keep this small |
| **M5 total addition** | | **~660** | |
| **M5 full 8-node account inclusion proof** | | **≈ 3,230** | |

**Gate G6-M5: a complete, key-bound account inclusion proof must measure below the
spike's 3,276** — i.e. M5 must be *cheaper than the broken verifier while actually being
correct*. Target ≈ 3,230: +26 % on M2's measured 2,566, and only **1.4 % under** the
spike's 3,276.

**That margin is thin, and this doc says so rather than rounding it away.** If any two
of the four ~80–105 target rows come in at double their estimate, G6-M5 fails. The named
lever if it does is **O-M5-1** (§11.3, the shape-based arity discriminator, −105), and
after that the segment hand-off row (measured floor 8 in hand-TEAL against a 40 target,
so there may be ~60 of slack there). Neither lever touches §5's security content — that
is the constraint on any optimisation pass here.

Per `ARCHITECTURE.md`, **every "target" in the table above is unmeasured and none of them
may be quoted in the README or a downstream design doc until `bench/mpt_results.json`
contains a real simulate response for it.** The three rows marked *measured* (130, 42,
8) and the 2,566 baseline are the only numbers here that are currently defensible.

### 8.3 Full workloads

| workload | nodes | budget (target) | `⌈b/700⌉` app calls | ALGO at 0.001/call |
|---|---|---|---|---|
| receipt inclusion | 3 | ~1,150 | 2 | 0.002 |
| account inclusion | 8 | ~3,230 | 5 | 0.005 |
| account + storage | 17 | ~6,050 | 9 | 0.009 |
| pathological (22 nodes) | 22 | ~8,000 | 12 | 0.012 |

The account+storage figure derives from the spike's measured composite 6,827 scaled by
M2's measured 2,566/3,276 ratio (≈ 5,350) plus M5's per-hop additions (≈ 700). It is an
estimate built on measurements, and it is a **target**, not a claim.

### 8.4 Acceptance gates

| gate | requirement |
|---|---|
| **G1-M5** | Real 3-node receipt inclusion proof verifies and beats the spike's measured 1,121. |
| **G2-M5** | Real 8-node account inclusion proof verifies; cost independent of *which* nibbles the key has, beyond the intrinsic O(index) of `mpt_descend` — reported per-hop, not hidden in a total. |
| **G3-M5** | Extension-node hop (derived fixture) through the misaligned `nibbles_equal` fallback: cost reported, and shown to scale with `n_path`, not with key length. |
| **G4-M5** | Segment hand-off verification (§7.4), Puya-compiled: ≤ 40 budget. |
| **G5-M5** | Compiled size of `contracts/mpt/` ≤ 1,400 B (§2). |
| **G6-M5** | **The headline.** Full 8-node account inclusion proof, live simulate, real fixture, key derived on-chain: **< 3,276** (the spike's insecure number). |
| **G7-M5** | The account+storage composite fits one 16-transaction atomic group end to end, demonstrated live, not computed. |

---

## 9. Test plan

Fixtures are real mainnet bytes from `tests/fixtures/spike-reference/eth_data.json`
(block 25,639,768) wherever real bytes exist, exactly as M2 §8.1 requires. Everything in
§9.1's table below was recomputed from that file while writing this doc — every
`keccak256` link verified, every branch index derived from the key alone, every leaf path
compared nibble-for-nibble against the key remainder.

### 9.1 Suite A — real inclusion walks (the happy path, pinned)

| test | input | pinned expectation |
|---|---|---|
| A1 | `stateRoot`, `mpt_key_from_address(0xdAC17F95…31ec7)`, 8 account nodes | derived indices `[10,11,1,4,13,6,8]`; leaf `(is_leaf=True, n_path=57, nib_index=7)`; `depth+n_path == 64`; `WALK_INCLUDED`, value span `(34, 70)` |
| A2 | `proof.storageHash`, `mpt_key_from_slot(0x0be16d71…f36)`, 9 storage nodes | derived indices `[10,10,2,8,1,3,13,6]`; leaf `(True, 56, 6)`; `WALK_INCLUDED`, value span `(32, 8)`, content `0x873f1ca131081cf8` |
| A3 | `receiptsRoot`, `mpt_key_from_tx_index(31)`, 3 receipt nodes | derived indices `[1,15]`; leaf `(True, 0, 8)`; `WALK_INCLUDED`, value span `(7, 683)`; cross-check `value_len` against `eth_data.json receipt_proof.value_len` |
| A4 | A1 then A2 chained through the account leaf's `storageRoot` | reproduces the spike's composite `stateRoot → account → storageRoot → slot` verification |

A1–A3 must additionally assert the derived indices **equal the values above**, not merely
that the walk succeeds — the indices are the security-relevant output of §5.2 and a walk
can succeed for the wrong reason.

### 9.2 Fixture derivation for what real data lacks

`eth_data.json` contains no **extension node**, no **embedded child**, and no
**exclusion** case. Fill them the way M2 §8.2 did — by *deriving* from real key/value
pairs with the reference MPT builder, never by hand-writing RLP:

- **F1 — extension node**: a small trie over real mainnet keys chosen so a shared multi-
  nibble prefix forces an extension node; assert the computed root; pin the bytes.
  Must include at least one extension whose `nib_index` and `depth` have **different**
  parity, to exercise M2's misaligned fallback (§5.3).
- **F2 — embedded child**: a trie whose child encodes under 32 bytes (§5.5).
- **F3 — prefix-sharing key pair**: two real keys agreeing on ≥ 3 leading nibbles, for
  S4/S6.
- **F4 — branch with a non-empty item 16**: requires a key that is a strict prefix of
  another, which no real Ethereum trie M5 walks can produce (§5.2). Derived only.
- **F5 — non-existent account/slot**: obtainable from real data — `eth_getProof` for an
  address with no state returns a genuine exclusion proof. Add to `ci-live.yml` and pin.

Label all derived fixtures `derived-real` in the fixture JSON and never
`mainnet-observed`, per M2's precedent.

### 9.3 Suite S — the security fix (the reason this module exists)

Every S-test must assert **two** things: that M5 rejects, *and* — via the Python
reference's hash-chain-only verifier, which reimplements `build_verifier`'s logic — that
**the spike's check would have accepted the same input**. A rejection test that does not
demonstrate the old code passing is not a regression test for this bug.

| test | construction | required result |
|---|---|---|
| **S1** | The real, complete, honest 8-node account proof for USDT, presented as a proof about a *different* real address (`0xF977814e90dA44bFA03b6295A0616a897441aceC`). Every `keccak256` link holds. | Reject at hop 0: `nibble_at(key', 0) != 10`. Spike-oracle: **accepts**. This is the direct M5 analogue of M1's T12 and M4's adversarial-update tests. |
| **S2** | Structural: assert M5's public surface contains no parameter named/shaped like a step list, child index, or path. | Enforced by a test that inspects the ARC-4 method signatures and the `contracts/mpt/` subroutine signatures. The absence is the invariant. |
| **S3** | The real account proof, with the target key's **last nibble** flipped. All 7 branch hops match (nibbles 0–6 unchanged). | Reject at the **leaf**, `WALK_ABSENT_LEAF_DIVERGE`. Proves the leaf compares content, not just length, and that the branch hops alone are not sufficient. |
| **S4** | F3: honest proof for the longer key, presented for a key of which the leaf path is a **strict prefix**. | Reject, `WALK_ABSENT_LEAF_DIVERGE`, from the **length** test (§5.4 step 2) — assert the length test fired, not the content test. |
| **S5** | F1: extension node whose path matches the key for *j* nibbles then diverges. | Reject, `WALK_ABSENT_EXT_DIVERGE`. Assert the divergence is detected at nibble *j* (instrument `nibbles_equal`'s reference implementation) — "rejects at the mismatch point, not silently at the end". |
| **S6** | F3: an honest, complete, root-verified proof for key A, presented for key B, where A and B share 3 nibbles. | Reject at the branch where they diverge — **not** earlier and **not** at the leaf. Spike-oracle: **accepts**. This is the strongest form: the input is a genuine, valid, correctly-hashed Ethereum proof, and only the key binding rejects it. |
| **S7** | Correct nodes, correct key, but node list **reordered**. | Reject at the first hop whose hash does not chain (TP-M5-3 backstop). |
| **S8** | Correct proof, but `W_in` to segment 2 forged with a different `depth` / `expected` / `key`. | Reject at `mpt_state_from_prev` (§7.4). Already demonstrated live in hand-written TEAL; must be re-demonstrated against the real contract. |

### 9.4 Suite E/X/R — edge cases, exclusion, key encoding

| test | case | required |
|---|---|---|
| E1 | Branch item 16 span is `(len(node), 0)` in all 17 real branch nodes | walker never `getbyte`s at that offset (M2 E2) |
| E2 | F4: key ends exactly at a branch, item 16 non-empty | `WALK_INCLUDED` with item 16's span |
| E3 | F4 variant: key ends at a branch, item 16 empty | `WALK_ABSENT_BRANCH_TERM` |
| E4 | F2: embedded child | walk continues in-buffer, consumes **no** extra node, and the node list length assertion still balances |
| E5 | Leaf with `n_path == 0` (real: `receipt_proof.nodes[2]`) | `nibbles_equal(count=0)` returns True and the **length** test carries the proof |
| E6 | Branch child reference of length ≠ 0, 32 and not `KIND_LIST` | assert `"W6"` |
| E7 | Extension whose child slot is empty | assert `"W7"` |
| E8 | Inline-descent chain longer than 8 | assert `"W8"` |
| E9 | Depth extremes: a 1-node proof (root is the leaf) and a 22-node synthetic proof | both walk correctly; 22-node case exercises §7.6's segmentation |
| X1–X4 | The four `WALK_ABSENT_*` forms, one test each (F5 for the real one) | correct discriminator, and `mpt_verify_inclusion` asserts on each |
| **X5** | **Truncated node list** presented as an exclusion proof | **no verdict** — the walk ends `WALK_CONTINUE` with nodes exhausted, and the driver rejects rather than reporting absence. The one real trap in §6. |
| X6 | Extra unused trailing nodes | reject `"W10"` |
| R1 | `mpt_key_from_tx_index(31) == 0x1f` | matches `eth_data.json receipt_proof.key_rlp` verbatim |
| **R2** | `mpt_key_from_tx_index(0) == 0x80` | **not** `0x00` — §4.2's trap |
| R3 | `127 → 0x7f`, `128 → 0x8180`, `255 → 0x81ff`, `256 → 0x820100`, `65536 → 0x83010000` | minimal RLP, all boundaries |
| R4 | `mpt_key_from_address` on a 32-byte input | assert `"W1"` — blocks passing an already-hashed key |

### 9.5 Suite D — differential (mandatory, gates §5.1's duplication)

**D1**: M5's fused branch skip loop and M2's `rlp_scan` + `rlp_table_item` must return
identical `(content_off, content_len, kind)` for **every item of every one of the 20 real
fixture nodes**, plus every derived fixture. This is the same obligation M2 §2.4 imposed
on its own duplicated loop, and it is not optional — it is the price of §5.1's fused
descent.

**D2**: the Puya walker and `tests/reference/mpt_ref.py` must agree — status, depth,
derived index at every hop, and value span — on all real and derived fixtures, and on a
property-based corpus of tries built by the reference MPT builder over random real-shaped
keys.

### 9.6 Suite B — budget, live

`bench/mpt_bench.py`, following `bench/rlp_bench.py` exactly (minimal program per
operation, `/v2/transactions/simulate` with `extra_opcode_budget`, real
`app-budget-consumed` minus a push-only baseline), emitting `bench/mpt_results.json` with
per-hop and per-proof costs beside M2's 2,566 and the spike's 1,121 / 3,276 / 6,827. Also
records compiled program size for G5-M5. G7-M5 requires a real submitted (not simulated)
16-transaction group.

---

## 10. Error codes

Two-character codes, not prose — program size is the binding per-call constraint
(`MPT_RESULTS.md` §5.5) and assert strings land in program bytes. Mirrored into
`contracts/mpt/__init__.py`'s docstring.

| code | meaning |
|---|---|
| W1 | `mpt_key_from_address`: preimage is not 20 bytes |
| W2 | `mpt_key_from_slot`: preimage is not 32 bytes |
| W3 | `mpt_key_from_tx_index`: index > 0xffffff |
| W4 | branch hop: `depth > key_nibs` (walk overran the key) |
| W5 | node arity is not 17 where a branch was required |
| W6 | child reference is neither empty, nor 32 bytes, nor an embedded list |
| W7 | extension node's child slot is empty |
| W8 | inline-descent chain exceeded 8 steps within one node buffer |
| W9 | `mpt_descend`: requested item does not exist within the list payload |
| W10 | segment finished with unconsumed trailing node arguments |
| W11 | `keccak256(node) != expected` — the hash-chain check |
| W12 | attempted to extend a walk whose status is already terminal |
| W13 | hand-off: referenced group index does not precede this transaction |
| W14 | hand-off: referenced transaction is not a call to this application |
| W15 | hand-off: referenced transaction did not invoke the segment method |
| W16 | hand-off: referenced transaction's last log is not a well-formed walk state |

---

## 11. ROADMAP open questions resolved, and what is handed on

`ROADMAP.md`'s M5 row lists three inherited open questions. All three are resolved.

**(1) "Spike's verifier never checks extracted child index against real key nibbles —
must derive expected path from the key on-chain, not trust a caller-supplied step
list."** — **Resolved, and specified to the opcode.** The branch descent index is
`nibble_at(key, depth)`, computed on-chain from a key that was itself derived on-chain
from a preimage (§4); extension paths are compared against the key slice with
`nibbles_equal` after an explicit bounds test (§5.3); leaf paths are compared against the
**entire** key remainder after an **exact-length** test that rejects strict prefixes
(§5.4). M5's public surface contains no step list, child index, or path parameter, and
test S2 enforces that absence structurally. Across a segment boundary the cursor is
recovered from the predecessor transaction's own log rather than from an argument (§7.4,
demonstrated live: honest hand-off passes, forged hand-off rejects). Tests S1 and S6
present genuine, fully hash-chained mainnet proofs for the wrong key and require both
that M5 rejects and that the spike's hash-only check accepts the identical input.

**(2) "Support hashed (state/storage) and un-hashed (receipt) keys."** — **Resolved: both,
derived on-chain, from preimages only.** `mpt_key_from_address` / `mpt_key_from_slot` do
`keccak256` on-chain at a **measured flat 130 budget** — 5 % of one walk, and the only
place the guarantee can live. `mpt_key_from_tx_index` performs minimal RLP encoding
on-chain from a `UInt64`, correctly handling `index == 0 → 0x80` (not `0x00`) and the
single-byte `0x01..0x7f` self-encoding that makes the real fixture's key the lone byte
`0x1f`. Accepting pre-derived keys or pre-encoded index bytes is structurally impossible;
the 20/32-byte length asserts additionally prevent passing an already-hashed value.

**(3) "Args-vs-box staging for nodes."** — **Resolved: raw application arguments, a
segmented walk, one atomic group, no boxes.** Driven by measurement, not preference: the
per-transaction argument cap is **2,048 bytes total** and the argument count cap is
**16**, both measured live against real algod with the literal protocol errors quoted
(§7.2), while a real account proof is **3,732 bytes** — 1.82× one transaction's entire
budget. Nodes are therefore delivered one per raw argument (1,942 usable bytes, ≤ 13
nodes per transaction), the walk is segmented (**3** calls for the account proof, **2**
for storage, **1** for the receipt proof, **5** for a full account+storage read), and the
cursor is handed between segments through the group's own execution record. Boxes are
rejected because they do not remove the argument-delivery cost (bytes still arrive as
arguments), because M4's measured box economics — 8 references per transaction, 2,048 B
of pooled budget per reference, full-box-size charged per touch — make them more
expensive than the path they would replace, because a staging box locks ≈ 1.5 ALGO of
minimum balance, and because persistent state carries a stale-session hazard that an
args+log design simply does not have. §7.6 shows the realistic pathological case (22
nodes) using **12 of 16 transactions** and 38 % of one group's argument space.

### 11.1 Flagged for M6

- **Semantics of absence.** M5 returns *which* terminal form was reached; M6 must define
  what `WALK_ABSENT_*` means for an account (non-existent vs. existent-with-zero-balance)
  and for a storage slot (absent ⇒ zero — true, but a semantic claim that must be written
  down). Note M2 E15: a *present* zero storage value is the empty string `0x80`.
- **Consuming the value.** The terminal segment's value span is a span into a node buffer
  that exists only inside that transaction. The clean layering is that **M6/M7's field
  extraction runs in the same call as the terminal hop** — the value never crosses a
  transaction boundary. If M6 needs it to, the escape hatch is for the terminal segment
  to log `keccak256(value) ‖ len(value)` and have the consuming transaction re-supply the
  bytes; that works up to the 2,048-byte argument cap and no further. M6 chooses.
- **Two-trie chaining.** `stateRoot → account → storageRoot → slot` is two M5 walks; M6
  extracts `storageRoot` from the account leaf's 70-byte value and feeds it in as a new
  root. M5 deliberately does not do this (§1.2). Test A4 pins the composition.
- **Root freshness.** M5 proves a statement relative to whatever `R` it was handed. M6/M8
  must ensure `R` is the root the application actually intends (block number binding,
  reorg/finality policy).

### 11.2 Flagged for M7

- The **>4,096-byte receipt leaf** is unchanged by this design and remains M7's hard
  stop. M5 confirms the boundary is narrow: every node *on the path* to such a leaf is an
  ordinary ≤ 532-byte branch node that M5 walks normally; only the terminal node cannot be
  delivered (2,048-byte argument cap), materialised (4,096-byte stack cap), or hashed (no
  streaming keccak). §7.5 records that boxes do not help.
- **EIP-2718 envelope stripping** is M7's, using M2's `receipt_envelope` on the span M5
  returns. M5 never calls it.
- **Exclusion for receipts** is only meaningful alongside a transaction-count bound M5
  cannot see.

### 11.3 Deferred within M5, measurement-gated

- **O-M5-1 — shape-based arity discriminator.** Classify branch vs. 2-item from item 0's
  kind/length, falling back to the payload-end test only for the ambiguous 32-byte row.
  Saves ≈ 15 budget/branch hop (≈ 105 on the account proof, ~3 %). Deliberately **not**
  shipped in v1: it trades a single unambiguous code path for a decision table with a row
  reachable only by a hand-derived fixture, in the module whose reason for existing is a
  subtle verification bug. Revisit only if G6-M5 fails.
- **O-M5-2 — fusing the hash check into the descent.** `keccak256` is flat 130 and 33 %
  of the baseline; there is nothing to optimise there, but the surrounding
  compare/assert/`Bytes` traffic has not been profiled. Measure before touching.
- **O-M5-3 — wider keys in `W`.** `W`'s 32-byte key field is sized for the tries M5's
  consumers walk. A trie with longer keys widens `W` and re-measures §7.3's per-segment
  node capacity. Recorded so it is a known consequence rather than a surprise.
