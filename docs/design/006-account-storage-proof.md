# 006 — M6: Account & storage proof composer

Status: **Design Drafted** (awaiting human approval)
Module: **M6** (`contracts/composer/`)
Depends on: M5 (`contracts/mpt/`, Implemented — real-submission-capable, §16 landed),
M2 (`contracts/primitives/rlp/`, Implemented)
Blocks: M7 (receipt/log), M8 (trusted-root anchor), M9 (relayer)
Spike evidence: `tests/fixtures/spike-reference/MPT_RESULTS.md` §1–§5 (the insecure
composite storage verifier, 8+9 = 17 nodes, **6,827** budget)
Measured dependencies: `docs/design/005-mpt-walker.md` §7, §16 and
`bench/mpt_results.json`; `docs/design/002-rlp-decoder.md` §16 and
`bench/rlp_results.json`; `tests/fixtures/spike-reference/RESULTS.md` §
"group/pooling"

---

## 0. The question, stated first

M5 answers *"is key `K` present under root `R`, and if so where is its value"*. That
is not a question a light client asks. The question a light client asks is:

> **What is the value of storage slot `S` of contract `C`, given a trusted state root
> `R_state`?**

Answering it requires **two** MPT walks joined by **one** RLP decode:

```
  R_state  --walk 1 (M5, key = keccak256(C))-->  account leaf
                                                      |
                                          value = rlp([nonce, balance,
                                                       storageRoot, codeHash])
                                                      |
                                          decode item 2  -->  R_storage
                                                      |
  R_storage --walk 2 (M5, key = keccak256(S))-->  storage leaf  -->  value
```

The research spike did exactly this composition (`MPT_RESULTS.md`: "the composite
storage verifier links `stateRoot → account leaf → storageRoot → storage leaf` and
every `assert` holds", 17 nodes, 6,827 budget) — **informally, and on top of the
hash-chain-only walker whose defect M5 exists to fix**. M6 is that composition rebuilt
on M5's key-bound walker, with the join itself made a verified step rather than a
trusted one.

**The one new security property M6 owns, in one sentence:** `R_storage` is read out of
a transaction the AVM itself executed, never out of a caller argument — because a
relayer that could hand M6 an arbitrary `storageRoot` would make walk 2 prove
something about a trie of its own choosing, with M5's entire §5 apparatus intact and
worthless. §5 is that mechanism.

---

## 1. Scope, non-goals, trust preconditions

### 1.1 In scope

1. **Composition of two M5 walks** across one atomic group, with the phase transition
   between them cryptographically bound (§5).
2. **The account-body decode** — `rlp([nonce, balance, storageRoot, codeHash])` — with
   an exact-arity check and a defensive 32-byte validation of the extracted
   `storageRoot` (§4).
3. **A composite result shape** that is self-describing in M5 §3.2's sense: it names
   the `(state_root, address, slot)` it is an answer *about*, so a consumer can check
   it against what it actually asked (§3.3, TP-M6-3).
4. **Composite-level exclusion semantics** — the two genuinely different flavours of
   absence, and the two flavours' distinct meanings (§8). This is `ROADMAP.md`'s
   listed M6 open question.
5. **Storage-value normalisation** — the trie value is `rlp(uint256)`, not the value;
   M6 returns a 32-byte big-endian word (§4.4).
6. **The segmented, raw-args, one-atomic-group delivery sequence** for 17 nodes across
   two walks, with real arithmetic (§6, §7).

### 1.2 Non-goals (explicit)

- **No MPT walking.** Every hop goes through M5's `mpt_walk_node` unchanged. M6 adds
  no node-type handler, no nibble comparison, no hash-chain check. If a change to
  `contracts/mpt/` looks necessary while implementing M6, that is a signal to stop and
  revise this doc, not to edit M5.
- **No RLP decoding logic.** §4's account-body decode is composed **exclusively** from
  M2's public `rlp_list_header` / `rlp_item_header` / `rlp_bytes`. M6 copies none of
  M2's stride arithmetic, and therefore — unlike M5's fused branch loop — carries **no
  differential-test obligation** (M2 §2.4's rule is triggered by duplication, and M6
  duplicates nothing).
- **No receipt or log semantics.** `[status, cumGas, bloom, logs]`, `receipt_envelope`,
  and the >4,096-byte receipt leaf are M7's. M6 never calls `receipt_envelope`, and
  never invokes `mpt_key_from_tx_index`.
- **No root anchoring or freshness policy.** `R_state` arrives as an argument. Where it
  comes from, whether it is final, and how long it is retained are M8's (§13.2 states
  the exact swap point).
- **No mapping-key derivation.** M6 takes the 32-byte storage **slot** as its
  preimage. Computing `keccak256(pad32(holder) ‖ pad32(mapping_slot))` for a Solidity
  mapping is the caller's, exactly as M5 §4.1's `mpt_key_from_slot` docstring already
  states. §13.3 flags this for M9.
- **No proof-of-multiple-slots batching.** One composite call sequence answers about
  one `(C, S)` pair. §14 records batching as deferred **O-M6-2**.

### 1.3 Trust preconditions

**TP-M6-1 (state root).** `R_state` must be a root the caller already trusts — M5's
TP-M5-1, inherited verbatim and unchanged. Everything M6 proves is conditional on it.

**TP-M6-2 (preimages, not derived keys).** M6 takes the 20-byte **address** and the
32-byte **slot**, and both trie keys are derived on-chain by M5's
`mpt_key_from_address` / `mpt_key_from_slot`. There is no entry point that accepts a
derived key. This is M5's TP-M5-2 lifted to the composite: a relayer that could choose
`keccak256(address)` could choose which account the whole composite is about.

**TP-M6-3 (the consumer must check the result's own header) — load-bearing.** A
terminal composite result `C` names `C.state_root`, `C.address` and `C.slot`. A
consumer (M8 in-group, or M9 off-chain) **must** compare all three against what it
intended before believing `C.value`. M6 cannot do this check for the consumer: the
composite is a conditional statement, and the condition is exactly those three fields.
§5.4 shows the concrete substitution attack that this check — and only this check —
defeats. `mpt6_result_from_group` (§6.6) is the subroutine that makes it hard to skip.

**TP-M6-4 (account bodies are hash-committed).** The account leaf whose body §4 decodes
was verified `keccak256(node) == expected` by M5 before any of its bytes were parsed
(M5 TP-M5-3), and `expected` chains to `R_state`. So the body is as trusted as
`R_state`, and M2's TP-1 (no untrusted-RLP hardening) is licensed here the same way it
is licensed inside M5. §9.3 says precisely which defensive checks M6 nevertheless
keeps, and why.

---

## 2. Where M6 sits, and which M5/M2 entry points it uses

| M6 call site | entry point | why |
|---|---|---|
| derive the account trie key | M5 `mpt_key_from_address` | TP-M6-2; on-chain `keccak256`, measured flat 130 |
| derive the storage trie key | M5 `mpt_key_from_slot` | same; the 32-byte assert (W2) also blocks passing an already-hashed key |
| build either walk's `W0` | M5 `mpt_init_state` | phase A: `root = R_state`; phase B: `root = C.storage_root` (§5) |
| every hop of both walks | M5 `mpt_walk_node` | unchanged; M6 adds nothing to the descent |
| recover a cursor across a segment | M5 `mpt_state_from_prev` | §5.2 extends the *payload* it recovers, not the mechanism |
| log a segment's outcome | M5 `mpt_log_state` shape | M6 uses the same `0x151f7c75 ‖ len ‖ payload` convention with a longer payload (§6.5) |
| account-body list header + 4 items | M2 `rlp_list_header` + 4 × `rlp_item_header` | §4.2; loop-free, exact-arity — the 4-item analogue of M2's `rlp_scan2` |
| materialise `storageRoot`/`codeHash`/`nonce`/`balance`/value | M2 `rlp_bytes` | must be `extract3`, never immediate `extract` (M2 E1) |
| decode `rlp(uint256)` inside the storage-leaf value span | M2 `rlp_item_header` | §4.4; one call |
| **not used** | M2 `rlp_scan` / `rlp_table_item` | §4.3 measures the alternative and rejects it |
| **not used** | M2 `rlp_scan_upto` | §4.3: it *is* cheaper (~80) but buys no arity check; decision and number stated there |
| **not used** | M5 `mpt_key_from_tx_index`, M2 `receipt_envelope` | M7's (§1.2) |
| **not used** | M5 `mpt_descend`, `mpt_branch_hop`, `mpt_extension_hop`, `mpt_leaf_hop` | internal to `mpt_walk_node`; M6 calls only the composed walker |

**Program size — the constraint most likely to bite.** `bench/rlp_results.json` records
M2 at **839 B**; `bench/mpt_results.json` records M5 at **1,969 B** (against its own
1,400 B target — M5 §16.4 reports that miss honestly). M6's deployed app must hold
**M2 + M5 + M6 + the segment driver** in one program under the 8,192 B cap
(`extra_pages = 3`, `MPT_RESULTS.md` §7). Current consumption is 2,808 B before M6
writes a line. Gates **G5-M6** and **G6-M6** (§12) split this into "M6's own bytes" and
"the whole deployable program", and G6-M6 is the one that can actually fail.

---

## 3. Data model

### 3.1 Composite status discriminator

```python
C_PENDING_ACCOUNT        = 0   # phase A in progress; NOT a verdict
C_PENDING_STORAGE        = 1   # account proven present, phase B in progress; NOT a verdict
C_INCLUDED               = 2   # slot present; C.value is its 32-byte value
C_ABSENT_ACCOUNT         = 3   # no state-trie entry for the address (§8.1)
C_ABSENT_SLOT            = 4   # account present, no storage-trie entry for the slot (§8.2)
C_ABSENT_SLOT_EMPTY_TRIE = 5   # account present with an EMPTY storage trie (§9.1)
C_ZERO_ENTRY             = 6   # slot present but its RLP value is the empty string (§9.2)
```

Codes **2–6 are terminal verdicts**; 0 and 1 are not. `C_INCLUDED`, `C_ZERO_ENTRY`,
`C_ABSENT_SLOT` and `C_ABSENT_SLOT_EMPTY_TRIE` all carry a meaningful `C.value` (the
last three carry 32 zero bytes). `C_ABSENT_ACCOUNT` carries 32 zero bytes and its
account fields are *also* the well-defined non-existent-account values (§8.1).

### 3.2 Phase

```python
PHASE_A    = 0   # walking the state trie
PHASE_A_OK = 1   # account leaf proven and decoded; storage_root extracted; phase B not started
PHASE_B    = 2   # walking the storage trie
PHASE_DONE = 3   # terminal
```

`PHASE_DONE` is reached **only** from a terminal M5 walk status. A relayer that stops
the group early leaves the last log at `PHASE_A` / `PHASE_A_OK` / `PHASE_B`, and
`mpt6_result_from_group` (§6.6) refuses it. This is M5 §6's X5 trap ("ran out of nodes
masquerading as absence") lifted to the composite, and it now has **two** instances —
one per walk (§8.3).

### 3.3 Composite state `C` — fixed 248 bytes

```
offset  size  field           mutability                 meaning
   0      1   cstatus         per-step                   §3.1
   1      1   phase           per-step                   §3.2
   2     32   state_root      IMMUTABLE (set at A_INIT)  R_state, TP-M6-1
  34     20   address         IMMUTABLE (set at A_INIT)  account preimage, TP-M6-2
  54     32   slot            IMMUTABLE (set at A_INIT)  storage-slot preimage, TP-M6-2
  86     32   storage_root    write-once (bridge, §5.1)  extracted from the account body
 118     32   code_hash       write-once (bridge)        account body item 3
 150     32   nonce           write-once (bridge)        account body item 0, 32-byte BE
 182     32   balance         write-once (bridge)        account body item 1, 32-byte BE
 214     32   value           write-once (terminal)      storage value, 32-byte BE
 246      1   awalk           write-once (bridge/absent) phase-A terminal WALK_* code
 247      1   swalk           write-once (terminal)      phase-B terminal WALK_* code
```

Design notes, mirroring M5 §3.2's reasoning:

- **Fixed width, always 248 bytes.** Every access is a constant-offset `extract3`, and
  every update is an `op.replace` splice of only the field that changes — this is M5
  §16.2's measured lesson (full-buffer reconstruction cost 20% of the headline walk),
  applied from line one rather than after a bench run.
- **`state_root`, `address`, `slot` travel with the cursor and are immutable.** This is
  what makes a terminal `C` self-describing, and it is the entire basis of TP-M6-3. It
  is also why `slot` is fixed at `A_INIT` and never taken as an argument later: phase B
  derives its key from `C.slot`, so there is no argument a relayer can vary to redirect
  the storage walk (§5.4).
- **`nonce` / `balance` / `code_hash` are carried because §4.2 already decodes them.**
  The account body is decoded once and completely; extracting three more spans that are
  already in hand costs three `extract3`s and three left-pads (~60 budget) and 96 log
  bytes. `code_hash` in particular lets a consumer answer "is this address a contract"
  by comparing against `keccak256("")` (§9.4) without a second proof.
- **`awalk` / `swalk` preserve *which* M5 absence form was reached.** M5 §6 deliberately
  returns four distinct `WALK_ABSENT_*` codes; collapsing them all into `C_ABSENT_SLOT`
  would throw away information a debugging relayer (M9) and a future policy layer (M8)
  will want. Two bytes.

### 3.4 The segment log payload

A segment logs `W ‖ C` — M5's 101-byte walk cursor followed by M6's 248-byte composite
— using M5 §7.4's exact envelope:

```
0x151f7c75 ‖ <2-byte big-endian length = 349> ‖ W(101) ‖ C(248)      = 355 bytes
```

355 B is well under the **1,024-byte per-app-call log cap** M5 §7.2 measured live
(literal error `program logs too large` at 1,025). The payload offset is 6, identical
to M5's, so `mpt_state_from_prev`'s recovery arithmetic is reused unchanged (§5.2).

`W` and `C` deliberately carry redundant information (`W.root` duplicates
`C.state_root` in phase A and `C.storage_root` in phase B; `W.key` is
`keccak256(C.address)` or `keccak256(C.slot)`). M5 §3.2 argues explicitly for that
redundancy — it makes each recovered state self-evidently about one `(root, key)` — and
M6 does not fight it. §5.3 turns the redundancy into two cheap cross-check asserts.

---

## 4. The account-body decode

### 4.1 Real bytes, real offsets

From `tests/fixtures/spike-reference/eth_data.json`, recomputed while writing this doc.
The account leaf is `proof.accountProof[7]`, **104 bytes**:

```
f866 9d 3802a763f7db875346d03fbf86f137de55814b191c069e721f47474733
     b846 f844 01 2a a0 261898dc…d33291 a0 b44fb4e9…c1ea55
```

M5's leaf hop (`mpt_leaf_hop`, `A1` in `005`'s §9.1) returns value span **`(34, 70)`**
into that node buffer. The 70 bytes at offset 34 are the account body:

```
f844 01 2a a0 261898dc12c926b33218d29afad898be487e821e8b4474465b62d802f7d33291
              a0 b44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55
```

Decoded (offsets **relative to the body**, i.e. relative to `value_off = 34`):

| | field | header @ | `content_off` | `content_len` | kind | content |
|---|---|---|---|---|---|---|
| list | `0xf8 0x44` | 0 | payload_off **2** | payload_end **70** | LIST | — |
| item 0 | `nonce` | 2 | **2** | **1** | `KIND_BYTE` | `01` |
| item 1 | `balance` | 3 | **3** | **1** | `KIND_BYTE` | `2a` (= 42) |
| item 2 | **`storageRoot`** | 4 (`0xa0`) | **5** | **32** | `KIND_STR` | `261898dc…7d33291` |
| item 3 | `codeHash` | 37 (`0xa0`) | **38** | **32** | `KIND_STR` | `b44fb4e9…2ac1ea55` |

`item3.content_off + item3.content_len = 38 + 32 = 70 = payload_end` — the exact-arity
check, free (§4.2).

**Node-absolute offsets** (add `value_off = 34`), verified byte-for-byte against the
fixture:

- `node[39:71]` = `261898dc12c926b33218d29afad898be487e821e8b4474465b62d802f7d33291`
  ≡ `eth_data.json proof.storageHash` ✓
- `node[72:104]` = `b44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55`
  ≡ `eth_data.json proof.codeHash` ✓
- nonce `01` ≡ `proof.nonce = 0x1` ✓ · balance `2a` ≡ `proof.balance = 0x2a` ✓

**Note the two `KIND_BYTE` rows.** `nonce = 1` and `balance = 42` are both below `0x80`
and so RLP-encode as *themselves*, with no header byte. M2's `rlp_item_header` returns
`(pos, 1, KIND_BYTE)` for these. Any implementation that assumes an account body's
items always carry a header byte (as the `0xa0` rows do) reads the wrong byte for both
fields. A real mainnet account is the fixture for this; it is not a hypothetical.

### 4.2 The decode subroutine

```python
@subroutine
def mpt6_account_body(node: Bytes, value_off: UInt64, value_len: UInt64
                      ) -> tuple[UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, Bytes, Bytes]:
    """Decode rlp([nonce, balance, storageRoot, codeHash]) at `value_off`.
    Returns (nonce_off, nonce_len, bal_off, bal_len, /*unused pad*/ ...,
             storage_root(32 B), code_hash(32 B)).

    Loop-free, exactly four items: the 4-item analogue of M2's `rlp_scan2`
    (002 §16 / `G3_scan2_fast`), composed purely from M2's public
    rlp_list_header / rlp_item_header / rlp_bytes. No M2 stride arithmetic is
    copied, so §1.2's "no differential-test obligation" holds.

    assert item3 ends exactly at payload_end       -> "A2"   (arity == 4, free)
    assert storageRoot is a 32-byte KIND_STR       -> "A3"   (§4.5)
    assert codeHash    is a 32-byte KIND_STR       -> "A3"
    assert nonce_len <= 32 and bal_len <= 32       -> "A4"
    """
    payload_off, payload_end = rlp_list_header(node, value_off)
    o0, l0, k0 = rlp_item_header(node, payload_off)          # nonce
    o1, l1, k1 = rlp_item_header(node, o0 + l0)              # balance
    o2, l2, k2 = rlp_item_header(node, o1 + l1)              # storageRoot
    o3, l3, k3 = rlp_item_header(node, o2 + l2)              # codeHash
    assert o3 + l3 == payload_end, "A2"
    assert l2 == 32 and k2 == KIND_STR, "A3"
    assert l3 == 32 and k3 == KIND_STR, "A3"
    assert l0 <= 32 and l1 <= 32, "A4"
    assert payload_end <= value_off + value_len, "A1"
    return o0, l0, o1, l1, rlp_bytes(node, o2, 32), rlp_bytes(node, o3, 32)
```

(The tuple shape above is illustrative; the implementer may return a packed
`Bytes` instead — Puya tuple arity is a style choice, not a design decision. What is
load-bearing is the four asserts and the fact that item 2 is reached by *decoding items
0 and 1*, not by a fixed offset. Real account bodies vary: a contract with a large
balance has a multi-byte `balance` item and the whole body shifts.)

`assert payload_end <= value_off + value_len -> "A1"` pins the decode inside the span
M5 handed over. Without it a malformed body's length-of-length field could point past
the leaf's own value and into whatever follows in the node buffer — still hash-committed
bytes, so not a soundness break, but a confusing one, and the check is two opcodes.

### 4.3 Why not `rlp_scan_upto`, and why not `rlp_scan` — with the numbers

The task for this module is "get item 2 of 4". Three real options, costed against M2's
own measured curves in `bench/rlp_results.json`:

| option | cost basis | estimated isolated cost | arity check? | other fields? |
|---|---|---|---|---|
| `rlp_scan_upto(node, value_off, 2)` | `G1_scan_upto_fast` is **exactly** `112 + 31·want` at all 10 measured indices ⇒ `112 + 62` | **~174** | **no** (M2 §16.3: `rlp_scan_upto` deliberately learns no arity) | no |
| `rlp_scan` + `rlp_table_item(2)` | `G1_scan_branch_node_table` = 646 isolated for 17 items ⇒ ~35/item; 4 items + header + table finalise + one `rlp_table_item` (~90) | **~350–390** | yes (`R3`/`R4`) | yes, via more `rlp_table_item` calls (~90 each) |
| **`mpt6_account_body` (§4.2)** | `G3_scan2_fast` isolated = **164** for header + 2 `rlp_item_header` + 1 assert; +2 more `rlp_item_header` at ~45 each | **~255** | **yes** — `o3+l3 == payload_end`, free | yes, all three, free |

**Decision: `mpt6_account_body`.** So the answer to "is there an early-exit saving the
way M5's branch descent had?" is **yes, ~80 budget (~31%), and M6 declines to take
it** — the number is stated rather than hidden. The trade bought:

1. **A genuine exact-arity check for free.** `o3 + l3 == payload_end` is precisely the
   trick M2's `rlp_scan2` uses to prove `n == 2` without a separate count (002 §16's
   `rlp_scan2` docstring: "a 3rd item, were one present, would make item 1 end before
   payload_end and this assert would catch it"). Applied at arity 4 it costs one
   comparison, and it is the only structural check that a 3-item or 5-item blob is not
   being read as an account.
2. **Three extra account fields at zero marginal decode cost**, which §3.3 carries and
   §13 hands to M8/M9.
3. **80 budget is 0.6% of the composite's ~12,500** (§7.3). Spending it to remove a
   silent-wrong-answer mode in the module whose entire job is "extract the *right*
   field from the *right* place" is the same trade M5 §5.1 made when it chose the
   unconditional arity discriminator over the cheaper shape test, for the same stated
   reason. Consistency with that precedent is deliberate.

`rlp_scan` + `rlp_table_item` is rejected on cost (~1.4× `mpt6_account_body` for the
same guarantees) — this is the same finding M2 §16 already recorded at gate G6, where
the flat-table path lost to the early-exit path on a real proof by more than 2×.

### 4.4 The storage value is `rlp(value)`, not the value

**M5 returns the leaf's item-1 span, whose content is itself an RLP encoding.** Real
fixture, `proof.storageProof[0].proof[8]`, 40 bytes:

```
e7 9d 202366783a4fc90e52c8cc595ba9fd2b278bc52248117c14c07e5394d8 88 873f1ca131081cf8
```

M5's `mpt_leaf_hop` returns span `(32, 8)`, content `873f1ca131081cf8` — which is
`rlp(0x3f1ca131081cf8)`. `eth_data.json proof.storageProof[0].value` is
`0x3f1ca131081cf8`. So M6 must decode **one more level**:

```python
vo, vl, vk = rlp_item_header(node, value_off)      # M2, one call
assert vo + vl == value_off + value_len, "A6"      # canonical: exactly one item, fills the span
assert vl <= 32, "A5"
if vl == 0:
    value32 = op.bzero(32);  cstatus = C_ZERO_ENTRY        # §9.2
else:
    value32 = op.bzero(32 - vl) + rlp_bytes(node, vo, vl)  # left-pad to 32-byte BE
```

`A6` is the same free-canonicality trick as `A2`: a well-formed trie value is exactly
one RLP item filling the whole span, so "the item ends where the span ends" proves
there is no trailing garbage and no truncation. Two opcodes.

The same normalisation applies to `nonce` and `balance` from §4.2 (`op.bzero(32 - l) +
rlp_bytes(...)`), including the `l == 0` case: a zero nonce or zero balance encodes as
the empty string `0x80`, `content_len == 0`, and normalises to 32 zero bytes.

**This is not a cosmetic choice.** Returning the raw span would make every consumer
re-implement RLP integer decoding off-chain, and would make "the slot is zero" ambiguous
between three different byte strings (`0x80` present, absent, and a leading-zero-stripped
short encoding). A 32-byte big-endian word has exactly one representation for every
uint256, which is what an on-chain consumer (M8) can actually compare.

### 4.5 The defensive 32-byte assert — decided, with the reasoning

**Decision: assert `l2 == 32 and k2 == KIND_STR` (code `A3`), and the same for
`codeHash`.** Under TP-M6-4 a real Ethereum account body is well-formed by consensus,
so this check is provably redundant *given a real Ethereum state root*. It is kept
anyway, for three reasons that are not "defence in depth" hand-waving:

1. **The failure mode without it is silent, not loud.** `rlp_bytes(node, o2, 32)` on a
   20-byte item reads 32 bytes starting at `o2` — i.e. the 20-byte item plus the
   `0xa0` header and 11 bytes of the following `codeHash`. That is a well-formed
   32-byte value, it becomes `W.expected` for phase B, and the group then fails at
   `mpt_walk_node`'s `W11` with a hash-chain error that points at the *storage* proof.
   The relayer, and anyone debugging, is sent to the wrong place. `A3` names the actual
   fault.
2. **`R_state`'s provenance is M8's, and M8 is not written yet.** TP-M6-1 is a
   *precondition*, not a proof. A misconfigured or test anchor could hand M6 a root
   that is not a real Ethereum state root, at which point "well-formed by consensus"
   simply does not hold. `ARCHITECTURE.md`'s fail-closed posture, and M4's own
   experience of finding three independent instances of the same unchecked assumption
   (004 §16), both argue for making the check explicit at the boundary where the
   assumption is used rather than where it is stated.
3. **It costs ~6 opcodes**, 0.05% of the composite.

The `A2` arity check earns its keep by the same argument, and additionally rules out
the case a length check cannot: a 4-item list whose items happen to have the right
lengths but the wrong *count* of trailing items.

---

## 5. The inter-walk hand-off — the security-critical part

### 5.1 The bridge, and where it runs

**Decision: the bridge runs in the same transaction as the account walk's terminal
hop.** M5 §11.1 already identified this as the clean layering ("M6/M7's field
extraction runs in the same call as the terminal hop — the value never crosses a
transaction boundary"), and it is also the only cheap option: the account leaf's value
span `(34, 70)` is an offset into a `Bytes` buffer that exists only inside the
transaction that supplied that node as an argument. Carrying the *span* across a
transaction boundary would be meaningless; carrying the *bytes* would need them
re-supplied and re-hash-bound.

So, in whichever segment the phase-A walk reaches `WALK_INCLUDED`:

```
1. status = w_status(W_A)
2. if status is WALK_ABSENT_*:      C.cstatus = C_ABSENT_ACCOUNT
                                    C.awalk   = status
                                    C.phase   = PHASE_DONE          # §8.1, no phase B
3. if status == WALK_INCLUDED:
       (n_off,n_len, b_off,b_len, storage_root, code_hash)
             = mpt6_account_body(node, value_off, value_len)        # §4.2, SAME buffer
       C.storage_root = storage_root
       C.code_hash    = code_hash
       C.nonce        = pad32(node[n_off : n_off+n_len])
       C.balance      = pad32(node[b_off : b_off+b_len])
       C.awalk        = WALK_INCLUDED
       if storage_root == EMPTY_TRIE_ROOT:                          # §9.1
              C.cstatus = C_ABSENT_SLOT_EMPTY_TRIE
              C.value   = 32 zero bytes
              C.phase   = PHASE_DONE                                 # no phase B
       else:  C.cstatus = C_PENDING_STORAGE
              C.phase   = PHASE_A_OK
4. log(0x151f7c75 ‖ 349 ‖ W_A ‖ C)
```

`storage_root` is now a value the **AVM computed**, inside a transaction, from bytes it
had already verified `keccak256(node) == expected` against a chain rooted at
`C.state_root`. It is written into `C` and logged. It never existed as an argument.

### 5.2 Recovering it — `MODE_B_INIT`

Phase B's first segment reconstructs `storage_root` by reading its predecessor's log
out of the group, using M5 §7.4's mechanism with a longer payload:

```python
@subroutine
def mpt6_state_from_prev(gi: UInt64) -> tuple[Bytes, Bytes]:
    """Recover (W, C) that transaction `gi` of THIS group actually produced.
    Structurally identical to M5's mpt_state_from_prev -- same four checks,
    same log envelope, longer payload.

    assert gi < Txn.group_index                            -> "A11"
    assert prev.app_id == Global.current_application_id     -> "A12"
    assert prev.app_args(0) == SEGMENT_SELECTOR             -> "A13"
    assert prev.last_log.length == 355                      -> "A14"
    assert prev.last_log[0:4] == 0x151f7c75                 -> "A14"
    """
    assert gi < Txn.group_index, "A11"
    prev = gtxn.ApplicationCallTransaction(gi)
    assert prev.app_id == Global.current_application_id, "A12"
    assert prev.app_args(0) == Bytes(SEGMENT_SELECTOR), "A13"
    log = prev.last_log
    assert log.length == UInt64(LOG_LEN_M6), "A14"          # 355
    assert op.extract(log, UInt64(0), UInt64(4)) == Bytes(ARC4_RETURN_PREFIX), "A14"
    return op.extract(log, UInt64(6), UInt64(W_LEN)), \
           op.extract(log, UInt64(6 + W_LEN), UInt64(C_LEN))
```

`MODE_B_INIT` then, before touching a single storage node:

```
1. W_A, C = mpt6_state_from_prev(prev_gi)
2. assert C.phase == PHASE_A_OK                                   -> "A15"
3. assert w_status(W_A) == WALK_INCLUDED                          -> "A16"
4. assert w_root(W_A) == C.state_root                             -> "A7"   (§5.3)
5. assert C.storage_root != EMPTY_TRIE_ROOT                       -> "A8"   (§9.1)
6. skey  = mpt_key_from_slot(C.slot)          # ON-CHAIN, from C -- not an argument
7. W_B   = mpt_init_state(C.storage_root, skey, 64)
8. C.phase = PHASE_B
9. walk this segment's node arguments with W_B; log (W_B, C)
```

Step 6 is the second load-bearing line of this module (the first being §5.1's step 3).
`C.slot` came out of the group's own execution record; `C.storage_root` likewise; and
`mpt_key_from_slot` re-derives the trie key on-chain. **`MODE_B_INIT` takes no root
argument, no key argument and no slot argument.** Like M5's §5.2 step 2, the absence is
the design, and test **S-M6-1** enforces it structurally.

Step 2 is what makes the phase machine non-bypassable: `PHASE_A_OK` is written only by
§5.1 step 3, which runs only after `mpt_walk_node` returned `WALK_INCLUDED` on a node
whose hash chained to `C.state_root`.

### 5.3 The redundant-field cross-checks (`A7`, `A9`)

`W.root` and `C.state_root` / `C.storage_root` are set by M6 itself, so steps 4 and the
phase-B analogue (`assert w_root(W_B) == C.storage_root -> "A9"`, checked on every
`MODE_B_NEXT` recovery) are structurally guaranteed for correct code. They are kept
because they are two `extract3`s and a comparison each (~10 opcodes total), and because
they convert any future mode/phase-dispatch mistake — the single most likely
implementation bug in a four-mode state machine — from a wrong answer into a named
assert. They are **not** part of the security argument against a relayer; §5.4 is.

### 5.4 The attack this actually defeats, traced

**Attack.** A relayer wants to prove that slot `S` of USDT holds a value of its
choosing. It holds an honest, complete, fully hash-chained mainnet storage proof for
slot `S` of a *different* contract `D` whose storage trie happens to contain a
convenient value at the same trie key.

**Against a naive composer** that takes `storageRoot` as an argument to phase B: the
relayer runs an honest USDT account walk (every M5 check passes — the proof *is*
honest), then starts phase B with `root = D.storageHash` and supplies `D`'s honest
storage proof. Every hash chains. Every nibble comparison passes: the storage key is
`keccak256(S)` in both tries, and M5 verifies the descent against that key correctly.
M5's §5 apparatus is **fully intact and completely bypassed** — because it was pointed
at the wrong trie. The composer reports "slot `S` of USDT = `D`'s value".

**Against M6 (§5.2):** `MODE_B_INIT` never reads a root argument. `W_B.expected` is
`C.storage_root = 0x261898dc…`, extracted from the verified USDT account body. The
relayer's first `D` storage node fails `keccak256(node) == expected` — M5's `W11` — and
the group fails. There is no argument, field, or transaction the relayer can vary to
change `W_B.expected` short of producing a preimage collision on keccak256. This is
test **S-M6-4**, and it uses the real fixture proofs for both contracts.

**The residual, and why TP-M6-3 exists.** The relayer *can* aim `prev_gi` at a
different M6 segment in the same group — e.g. run two account walks (USDT and `D`) and
point `MODE_B_INIT` at `D`'s. `A11`–`A16` all pass: it is a genuine, complete,
correctly-executed M6 phase A. The composite that results is **true** — it correctly
states `D`'s slot value — but it is an answer to a different question, and it says so:
`C.address` is `D`, not USDT. Nothing on-chain can distinguish "the relayer meant to
prove `D`" from "the relayer substituted `D`", because both produce the identical group.
The check that resolves it belongs to whoever asked the question, which is exactly
TP-M6-3, and `mpt6_result_from_group` (§6.6) makes it a parameter the consumer cannot
forget to pass. This is M5 §7.4's own conclusion ("pointing at the wrong one yields a
`W` that names a different `(root, key)` — which §3.2 makes self-evident to the final
consumer"), restated at composite scale. Test **S-M6-3** demonstrates both halves.

### 5.5 Rejected alternatives

- **Pass `storageRoot` as an argument to phase B.** The attack in §5.4. Listed only
  because it is what the spike effectively did (it composed the two walks inside one
  hand-written program with the account body's storage root loaded from a Python-side
  constant) and because it is the obvious wrong answer.
- **Stage `storageRoot` in a box between the two phases.** All four of M5 §7.5's
  objections apply unchanged, plus one specific to M6: a 32-byte box would be
  persistent state naming no session, so a second composite in a later group could read
  a stale root. M4 §16 is the first-hand account of what guarding that costs. The log
  chain leaves nothing behind, because logs are not state.
- **Global state hand-off.** Same stale-session objection; `C` is 248 bytes and does not
  fit the 128-byte global byte-slice limit anyway.
- **Re-supply the account leaf's bytes to phase B and re-decode there.** Works, and is
  sound (the bytes would be re-hash-checked against `W_A.expected`), but costs 104 bytes
  of argument space, a redundant `keccak256`, a redundant body decode, and a *second*
  place where the storage root is derived — i.e. a second place to get it wrong. The
  log chain already carries a verified value; re-deriving it is strictly worse.

---

## 6. Interface

### 6.1 Shape: raw app-args, one selector, a mode byte — following M5 §7.3

M6's deployable app follows `contracts/mpt/bench_app.py`'s **implemented** driver shape
exactly: one 4-byte raw selector in `arg 0`, a mode byte in `arg 1`, no ARC-4 method
routing. Reasons, in order:

1. **`mpt6_state_from_prev` compares `prev.app_args(0)` against a literal.** A uniform
   selector across all four modes is what makes that check work regardless of which
   mode the predecessor was — M5's driver comment already spells this out, and M6
   inherits the constraint.
2. **ARC-4 argument marshalling is a large measured tax.** `bench/rlp_results.json`
   records `arc4_overhead_reference.scan = 680` against `baseline_bare = 13` for the
   same underlying work, and M2's own G6 note explains that an ARC-4 caller
   "additionally pays real `byte[][]`/`uint64[]` ABI array-decoding for receiving all 8
   nodes as call arguments". Nodes arrive one per raw argument with zero framing.
3. **`2 + 4n` bytes of ARC-4 array framing is argument space** — and §7.1 shows the
   argument cap is what sets the segment count, to within 13 bytes.

**Deviation from M5 recorded honestly:** M5 §7.3's *doc* describes `arg 1` as carrying
`W_in` (101 B). M5's *implementation* does not — `MODE_NEXT` carries only an 8-byte
predecessor group index and recovers `W` from the log. M6 follows the **implementation**,
which is both cheaper and strictly safer, and notes the doc/code divergence here so the
implementer is not confused by 005 §7.3's table.

### 6.2 The four modes

```
SEGMENT_SELECTOR = b"ACS1"          # Account + Contract Storage, v1

MODE_A_INIT = 0     # open the composite; start the state-trie walk
MODE_A_NEXT = 1     # continue the state-trie walk (bridge fires here if it terminates)
MODE_B_INIT = 2     # open the storage-trie walk from the bridged storage_root
MODE_B_NEXT = 3     # continue the storage-trie walk
```

The bridge (§5.1) is **not** a mode. It fires automatically in whichever of
`MODE_A_INIT` / `MODE_A_NEXT` sees the phase-A walk go terminal. Likewise phase B's
finalisation (§4.4's value normalisation) fires in whichever of `MODE_B_INIT` /
`MODE_B_NEXT` sees the phase-B walk go terminal. Making these separate modes would add
two dispatch arms whose only distinguishing condition is a value the contract already
computes — M5's `MptSegmentApp` makes the same call with its two modes and it is the
right precedent.

### 6.3 Argument layouts

Field widths match M5's implemented driver exactly (`donor_count` and `donor_app_id`
both `uint64`, big-endian; `prev_gi` `uint64`). §7.1 shows why tightening them buys
nothing in v1, and §14's **O-M6-1** shows the one shape where it would.

```
arg 0   SEGMENT_SELECTOR                                4 B    (all modes)
arg 1   mode                                            1 B    (all modes)
arg 2   donor_count      (uint64 BE)                    8 B    (all modes)
arg 3   donor_app_id     (uint64 BE)                    8 B    (all modes)

MODE_A_INIT (0):
arg 4   state_root                                     32 B
arg 5   address          (20 B, asserted by W1)        20 B
arg 6   slot             (32 B, asserted by W2)        32 B
arg 7…  account proof nodes, one per argument, in path order

MODE_A_NEXT (1) / MODE_B_INIT (2) / MODE_B_NEXT (3):
arg 4   prev_gi          (uint64 BE)                     8 B
arg 5…  proof nodes, one per argument, in path order
```

Fixed overhead and usable node capacity per transaction (2,048-byte total-argument cap
and 16-argument cap, both measured live in M5 §7.2 with the literal protocol errors):

| mode | fixed bytes | usable node bytes | max node args |
|---|---:|---:|---:|
| `MODE_A_INIT` | 105 | **1,943** | 9 |
| `MODE_A_NEXT` / `MODE_B_INIT` / `MODE_B_NEXT` | 29 | **2,019** | 11 |

Every mode ends by logging `0x151f7c75 ‖ 349 ‖ W ‖ C` (§3.4).

### 6.4 The composite result

The final segment's log holds the terminal `C`. There is no separate "finalise"
transaction: adding one would cost a transaction slot and a boundary (~211 budget,
§7.2) to produce a value already sitting in the previous log.

| `C.cstatus` | meaning | `C.value` | phase-B segments needed |
|---|---|---|---|
| `C_INCLUDED` | slot present with a non-zero RLP value | the 32-byte value | yes |
| `C_ZERO_ENTRY` | slot present, RLP value is the empty string (§9.2) | 32 zero bytes | yes |
| `C_ABSENT_SLOT` | account present, slot has no trie entry (§8.2) | 32 zero bytes | yes |
| `C_ABSENT_SLOT_EMPTY_TRIE` | account present with an empty storage trie (§9.1) | 32 zero bytes | **no** |
| `C_ABSENT_ACCOUNT` | address has no state-trie entry (§8.1) | 32 zero bytes | **no** |
| `C_PENDING_*` | **not a verdict** — the group is incomplete (§8.3) | meaningless | — |

All five terminal codes are *positive claims about the storage value*: four of them
claim it is zero, by four distinct and individually sound routes.

### 6.5 The real 5-transaction group (USDT / Binance-8 fixture)

| # | mode | args carried | node bytes | arg count | inner donors |
|---:|---|---|---:|---:|---:|
| 0 | `A_INIT` | `state_root`, `0xdAC1…1ec7`, `0x0be1…5f36`, account nodes 0–2 | 1,596 | 3 + 7 = 10 | 15 |
| 1 | `A_NEXT` | `prev_gi = 0`, account nodes 3–5 | 1,596 | 3 + 5 = 8 | 0 |
| 2 | `A_NEXT` | `prev_gi = 1`, account nodes 6–7 · **bridge fires** | 540 | 2 + 5 = 7 | 0 |
| 3 | `B_INIT` | `prev_gi = 2`, storage nodes 0–2 | 1,596 | 3 + 5 = 8 | 0 |
| 4 | `B_NEXT` | `prev_gi = 3`, storage nodes 3–8 · **value normalised, `PHASE_DONE`** | 1,738 | 6 + 5 = 11 | 0 |

**5 top-level transactions of 16, 15 inner donor calls of 256.** Argument bytes used:
`1,701 + 1,625 + 569 + 1,625 + 1,767 = 7,287` of the `5 × 2,048 = 10,240` those five
transactions can carry (71%), delivering all `3,732 + 3,334 = 7,066` real node bytes
(M5 §7.2's own account+storage figure).

All donors are issued in transaction 0, before any walk work, per M5 §16.3's measured
ordering requirement ("the pool must already be raised by the time the heavy work
starts consuming it") and its empirical finding that **the donor callee must be a
separate deployed app** — an app cannot inner-call itself (`attempt to self-call`).

### 6.6 What a consumer calls

```python
@subroutine
def mpt6_result_from_group(gi: UInt64, want_state_root: Bytes,
                           want_address: Bytes, want_slot: Bytes
                           ) -> tuple[UInt64, Bytes]:
    """Recover and validate a TERMINAL composite result produced by transaction
    `gi` of this group. Returns (cstatus, value32).

    assert C.phase == PHASE_DONE                     -> "A17"  (§8.3: no verdict
                                                                from an incomplete walk)
    assert C.state_root == want_state_root           -> "A18"  } TP-M6-3, and the
    assert C.address    == want_address              -> "A18"  } reason this subroutine
    assert C.slot       == want_slot                 -> "A18"  } takes three arguments
    """
```

The three `want_*` parameters are **mandatory, not optional**. TP-M6-3 is a check the
consumer must perform, and the cheapest way to make it unforgettable is to refuse to
compile without it. An M8 anchor contract passes its own anchored root as
`want_state_root`; an M9 off-chain client parses the 355-byte log directly against the
§3.3 layout and performs the identical three comparisons.

---

## 7. Budget and group arithmetic — one group or two?

`ARCHITECTURE.md`'s rule applies to everything below: **the only defensible numbers
here are the ones marked *measured*.** Every derived figure is explicitly a prediction
to be replaced by a real `simulate`/`send` response in `bench/composer_results.json`.

### 7.1 Segment count — the argument cap, to within 13 bytes

The structural fact that sets everything: **`4 × 532 = 2,128 > 2,048`.** A transaction
can carry **at most three 532-byte branch nodes**, whatever the framing. The composite
proof contains 17 nodes of which **eleven** are 532 B (six account, five storage), so
the 532-byte nodes alone need `⌈11/3⌉ = 4` transactions — and because nodes must arrive
in **path order**, the split is a sequential prefix cut, not a bin-packing:

```
account : 532 532 532 | 532 532 532 | 436 104          (cap 1,943 then 2,019, 2,019)
storage : 532 532 532 | 532 532 468 83 83 40           (cap 2,019, 2,019)
```

- `A_INIT` cap 1,943: `3 × 532 = 1,596` fits; a fourth would be 2,128.
- `A_NEXT` cap 2,019: `1,596` fits; adding node 6 (436 B) gives **2,032 — over by 13
  bytes.** So account node 6 is pushed into a third segment. This 13-byte miss is worth
  recording precisely, because it is the entire reason phase A needs three segments
  rather than two, and it is what §14's **O-M6-1** attacks.
- `B_INIT` cap 2,019: `1,596` fits; a fourth 532 gives 2,128.
- `B_NEXT` cap 2,019: `532 + 532 + 468 + 83 + 83 + 40 = 1,738` fits, 6 args.

**⇒ 3 + 2 = 5 segments**, matching M5 §7.3's own account (3) and storage (2) split and
its "account + storage → 5 calls" row, and matching the 3-segment account group M5 §16.3
actually submitted live.

### 7.2 A calibrated per-hop cost model, built only on measured numbers

Four real measurements from `bench/mpt_results.json` and `bench/rlp_results.json`:

| quantity | value | source |
|---|---:|---|
| G6-M5, bare 8-node account walk (incl. on-chain `keccak256(address)`) | **5,116** | `mpt_results.json` `G6_M5_account_inclusion.consumed` |
| G1-M5, bare 3-node receipt walk (incl. on-chain minimal-RLP key) | **1,813** | `G1_M5_receipt_inclusion.consumed` |
| 3-segment account group, live, no donors | **5,538** = [2155, 2060, 1323] | `G7_M5_real_submission.account_group_no_donors_simulated` |
| 2-segment receipt group, live, no donors | **2,024** = [544, 1480] | `G4_M5_handoff_and_G7_M5_group` |

plus `keccak256` flat at **130** (`MPT_RESULTS.md` §1) and M2's `rlp_scan_upto` marginal
cost of exactly **31 per skipped item** (`G1_scan_upto_fast` is `112 + 31·want` at all
ten measured indices — M5's `mpt_branch_item_at` runs the same duplicated stride body).

Branch indices are derived on-chain from the key (005 §5.2's table, reproduced by
`tests/unit/test_mpt_real_walks.py`), so the skip-loop iteration counts are known:

| walk | derived indices | skip iterations `Σ max(want−2, 0)` |
|---|---|---:|
| account (7 branch + leaf) | 10, 11, 1, 4, 13, 6, 8 | **40** |
| storage (8 branch + leaf) | 10, 10, 2, 8, 1, 3, 13, 6 | **38** |
| receipt (2 branch + leaf) | 1, 15 | **13** |

Let `B` = per-branch-hop fixed cost, `L` = leaf-hop cost, `I` = init cost:

```
account:  I_a + 8·130 + 7B + 40·31 + L = 5116   ⇒  I_a + 7B + L = 2836
receipt:  I_r + 3·130 + 2B + 13·31 + L = 1813   ⇒  I_r + 2B + L = 1020
subtract: (I_a − I_r) + 5B = 1816
I_a − I_r ≈ 100  (keccak256 130 + length assert, vs mpt_key_from_tx_index's
                  4-way branch + itob/extract ≈ 30)
⇒ B ≈ 343 ,  I_a + L ≈ 435
```

**Independent bottom-up cross-check of `B ≈ 343`:** `mpt_arity_discriminate` ≈ M2's
`G3_scan2_fast` isolated 164 less one assert ≈ 160; `w_depth`/`w_key_nibs`/`w_key`
inline extracts ≈ 15; `nibble_at` (inline, 3 opcodes); `mpt_branch_item_at` frame +
`want` compares ≈ 30; child classification ≈ 25; `w_with_continue` (3 `op.replace`, 2
`itob`/`extract`, frame) ≈ 60; `rlp_bytes` ≈ 20; `mpt_walk_node` loop control +
`mpt_branch_hop`'s 9-argument frame ≈ 40. **Sum ≈ 350.** The two derivations agree to
2%, which is why the model is used below rather than a flat per-node average.

**Storage walk, predicted:**
`(I_a + L) + 9·130 + 8B + 38·31 = 435 + 1,170 + 2,744 + 1,178 =` **≈ 5,527**.

Sanity: `5,527 / 9 = 614/node` vs the account walk's `5,116 / 8 = 640/node`; the storage
walk has one more hop but two fewer skip iterations. Consistent.

**Segment-boundary overhead, from the two live group measurements:**
solve `a·segments + b·boundaries` against `3a + 2b = 5,538 − 5,116 = 422` and
`2a + b = 2,024 − 1,813 = 211` ⇒ **`a = 0`, `b = 211`**. Two equations, two unknowns —
exactly determined, not over-determined, and this doc says so rather than presenting it
as a fit. Operationally: **≈ 211 budget per additional segment**, covering
`mpt_state_from_prev`, `mpt_log_state`, and raw-argument marshalling. (Note this is
5× M5's own G4-M5 target of ≤ 40 for the hand-off check alone; M5's bench never isolated
it, and G4-M6 in §12 requires M6 to.)

### 7.3 Predicted composite cost

| component | budget | basis |
|---|---:|---|
| phase-A walk, 8 nodes | 5,116 | **measured** (G6-M5) |
| phase-B walk, 9 nodes | ~5,527 | §7.2 model |
| 4 segment boundaries × 211 | ~844 | §7.2, from two live group measurements |
| `mpt6_account_body` (§4.2) | ~255 | M2 `G3_scan2_fast` 164 + 2 × `rlp_item_header` |
| `storage_root` extract + `EMPTY_TRIE_ROOT` compare | ~25 | target |
| `nonce`/`balance`/`code_hash` normalise (3 × pad32) | ~60 | target |
| storage value: `rlp_item_header` + `A5`/`A6` + pad32 | ~70 | target |
| `C` unpack/repack × 5 segments | ~300 | target; `op.replace` splices only (M5 §16.2's lesson) |
| mode dispatch + `A7`–`A18` binding asserts | ~100 | target |
| donor-issue loop, 15 inner calls | ~225 | target; ~15/call |
| **predicted composite total** | **≈ 12,500** | |

Reference points, all real:

- **Two-walk floor** (what the same two walks cost with *no* composition overhead):
  `5,116 + 5,527 = 10,643`. M6's own overhead is therefore **≈ 1,880, or 17.7%**.
- **Spike's insecure composite: 6,827** (`MPT_RESULTS.md`). Predicted ratio **1.83×**.
- For scale, M5's own account-level ratios are `5,116 / 3,276 = 1.56×` bare and
  `5,538 / 3,276 = 1.69×` for the real segmented group. M6's 1.83× is that same
  security-fix cost plus four segment boundaries the spike never paid (it baked all 17
  nodes into one 7,649-byte program). **M6 cannot and should not target 6,827** — M5
  §16.4 already established that a genuinely key-bound walker costs ~1.6× the spike's
  hash-chain-only one per node, and §12's gates are set against the two-walk floor
  instead.

### 7.4 One atomic group or two? — every ceiling checked

| ceiling | value | composite needs | headroom |
|---|---:|---:|---|
| top-level transactions per group | **16** (measured, M5 §7.2) | **5** | 3.2× |
| inner transactions per group | **256** (`RESULTS.md`: 16×16 succeeds, 16×17 fails) | **15** | 17× |
| pooled opcode budget | `700 × (16 + 256) = 190,400` (`MPT_RESULTS.md` §2) | ~12,500 | 15× |
| pooled budget actually provisioned | `700 × (5 + 15) = 14,000` | ~12,500 | 12% |
| argument bytes across the 5 segments | `5 × 2,048 = 10,240` | 7,287 | 1.4× |
| argument bytes group-wide | `16 × 2,048 = 32,768` | 7,287 | 4.5× |
| log bytes per app call | **1,024** (measured, M5 §7.2) | 355 | 2.9× |
| box references | — | **0** (no boxes, §5.5) | n/a |
| foreign app references per txn | 8 | 1 (`donor_app_id`) | 8× |

**Decision: ONE atomic group, and unlike M4's 1-vs-2 question this one is not close.**

The mechanism that binds *first* as depth grows is top-level argument capacity: at most
three 532-byte nodes per transaction (§7.1) × 16 transactions = **~48 nodes**. Budget
does not bind until ~258 nodes (`190,400 / ~736 per node`), and inner donors do not bind
until ~256. So the ordering is: **arguments (48 nodes) → donors (~256) → budget
(~258)**, with the realistic pathological case at **22 nodes** (`MPT_RESULTS.md` §4:
account depth ~10 + storage depth ~12) sitting at **46% of the first ceiling**.

Pathological case, worked: 22 nodes ≈ `⌈22/3⌉ = 8` segments; budget ≈
`22 × 736 + 7 × 211 = 17,670`; donors `⌈(17,670 − 8·700)/700⌉ = 18`.
**8 of 16 top-level, 18 of 256 inner.** Still one group, with 2× headroom on the
binding constraint.

**What would force two groups**, stated so a future pass recognises it: a composite path
deeper than ~48 nodes (≈ 2.2× the pathological case, which would require an Ethereum
state trie roughly 16× larger than today's), or a per-node cost regression of ~7× that
pushed budget past 190,400. Neither is reachable from here. Note that **program size is
per-call, not per-group** — a program-size overflow (§2, G6-M6) forces a *smaller
program*, e.g. splitting M6 and M7 into separate deployed apps, not a second group.

### 7.5 ALGO cost

`5 top-level + 15 inner = 20 app calls × 1,000 µAlgo = ` **0.020 ALGO** per composite
storage read. Transaction 0 must be funded for `(1 + 15) × 1,000 = 16,000 µAlgo` to
pool its inner-transaction fees (M5 `_issue_donors` sets `fee = 0` on each inner call);
the other four segments pay one min fee each.

For context: `MPT_RESULTS.md` §3 priced the spike's insecure composite at 0.010 ALGO
(10 app calls). The security fix and segmentation double it. It remains ~5–14× cheaper
than one sync-committee BLS update (0.11–0.28 ALGO, M1/M4).

### 7.6 Donor sizing, in practice

`donor_count` is not a constant in the contract; it is an argument the relayer sizes
from a prior `simulate` of the same group with zero donors, then verifies with a real
`send_transactions` — exactly M5 §16.3's procedure ("donor counts are sized from a prior
`simulate` reading … then verified by an **actual** `send_transactions` call, not
`simulate`"). 15 is the recommended starting value for the fixture workload:
`⌈(12,500 − 5·700) / 700⌉ = 13` is the minimum, and 15 gives 12% headroom against the
prediction being optimistic — which, on M3's and M5's track record with Puya-compiled
cost estimates, it probably is.

---

## 8. Exclusion at the composite level — `ROADMAP.md`'s M6 open question, answered

M5 §6 resolved exclusion **per walk**: one walk, four `WALK_ABSENT_*` forms, each
individually sound because the node exhibiting the terminal condition is itself
hash-linked to the walk's root. M5 §11.1 then handed M6 the *semantic* question. M6
answers it in three parts, building on M5's answer rather than re-deriving it.

### 8.1 Account absent — `C_ABSENT_ACCOUNT`

**Trigger.** The phase-A walk reaches any `WALK_ABSENT_*` status.

**Meaning, stated precisely.** There is **no entry at `keccak256(address)` in the state
trie rooted at `R_state`**. In Ethereum this is not "we could not find it"; it is the
definition of a non-existent account, and it has exact consequences fixed by consensus:

```
nonce        = 0
balance      = 0
codeHash     = keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
storageRoot  = keccak256(rlp("")) = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
every storage slot = 0
```

So the composite terminates immediately: `C.value = 32 zero bytes`, `C.phase =
PHASE_DONE`, `C.awalk` = the specific M5 absence form, and **no phase-B segment is
issued or accepted**. There is no storage trie to walk against, and asking for one would
be asking the relayer to invent a root.

**Decision — does M6 populate the account fields with those constants?** Yes for
`storage_root` and `code_hash` (write `EMPTY_TRIE_ROOT` and `EMPTY_CODE_HASH`
respectively, both compile-time constants), zero for `nonce`/`balance`. Cost: two
32-byte splices. The alternative — leaving them zero and documenting "meaningless when
`cstatus == C_ABSENT_ACCOUNT`" — creates a shape where `code_hash == 0x00…00` is a
*third* value distinct from both "is a contract" and "is an EOA", which every consumer
would then have to special-case. Filling them makes `C` uniformly readable.

**M5 §11.1's specific question — "non-existent vs. existent-with-zero-balance" —
answered.** These are genuinely different and M6 distinguishes them structurally, not by
convention. An account that *exists* with zero balance **has a state-trie entry**; its
walk returns `WALK_INCLUDED`, its body decodes, and its `balance` item is the empty
string `0x80` (`content_len == 0`), normalising to 32 zero bytes with
`cstatus ∈ {C_INCLUDED, C_ABSENT_SLOT, …}` and `awalk == WALK_INCLUDED`. A non-existent
account has `cstatus == C_ABSENT_ACCOUNT` and `awalk ∈ WALK_ABSENT_*`. The
discriminator is `C.awalk`, and it is exact.

### 8.2 Slot absent — `C_ABSENT_SLOT`

**Trigger.** The account walk returned `WALK_INCLUDED`, `storage_root !=
EMPTY_TRIE_ROOT`, and the phase-B walk reaches any `WALK_ABSENT_*` status.

**Meaning.** There is no entry at `keccak256(slot)` in the storage trie rooted at
`C.storage_root`. **⇒ the slot's value is 0.** This is a *normal, meaningful, positive*
result — the overwhelmingly common case, since a contract's storage trie contains only
its non-zero slots.

**The semantic claim, written down as M5 §11.1 asked.** Ethereum's `SSTORE` **deletes**
a slot's trie entry when it is set to zero; there is no encoding of "present and zero"
in canonical execution. Therefore *absent ⇔ zero* for storage, and the mapping is
total: every slot of an existing account has a defined value, and every one that is
absent from the trie is 0. M6 returns `C.value = 32 zero bytes` with
`cstatus = C_ABSENT_SLOT` and `swalk` = the M5 form, so a consumer that wants only the
value treats `C_INCLUDED` / `C_ZERO_ENTRY` / `C_ABSENT_SLOT` /
`C_ABSENT_SLOT_EMPTY_TRIE` uniformly and reads `C.value`, while a consumer that wants
to distinguish "explicitly stored" from "proven-by-absence" reads `cstatus`.

This is where **M2 E15** lands: a *present* zero storage value would be the empty string
`0x80`, not `0x00`. §9.2 handles that case and gives it its own code so the distinction
is auditable rather than assumed away.

### 8.3 The trap, twice — an incomplete walk is not an exclusion proof

M5 §6 named the one real hazard: "a relayer that supplies the first three nodes of an
eight-node path and claims exclusion must be rejected". M6 has **two** paths on which
that can happen, and one structural defence covering both:

`PHASE_DONE` is written **only** from a terminal M5 walk status. A truncated phase-A
node list leaves the walk at `WALK_CONTINUE`; §5.1's step 2/3 dispatch does not fire;
`C.phase` stays `PHASE_A`. A truncated phase-B list leaves `C.phase == PHASE_B`.
Either way the final log is non-terminal and `mpt6_result_from_group`'s
`assert C.phase == PHASE_DONE -> "A17"` refuses it. **A walk that never reaches a
terminal status yields no result at all** — M5's X5, twice. Tests **X-M6-1** and
**X-M6-2**.

The converse strictness is inherited unchanged: M5's `_walk_remaining_args` asserts
`w_status == WALK_CONTINUE` before consuming each node argument, so trailing unused
nodes are rejected (`W10`). M6 adds the phase-level analogue: a segment whose recovered
`C.phase == PHASE_DONE` is rejected (`A10`) — the composite cannot be extended past its
own verdict.

---

## 9. Edge cases

### 9.1 The empty storage trie — this does **not** "just work", and here is why

An account with no storage (every EOA, and any contract that has never written a slot)
has `storageRoot = EMPTY_TRIE_ROOT = keccak256(rlp("")) = keccak256(0x80) =
0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`
(recomputed while writing this doc).

**Traced through M5's actual code**, what happens if phase B is started against that
root: `mpt_init_state` sets `W.expected = EMPTY_TRIE_ROOT`. The relayer must supply a
node with `keccak256(node) == EMPTY_TRIE_ROOT`, i.e. the single byte `0x80`.
`mpt_walk_node`'s `W11` hash check **passes**. It then calls
`mpt_arity_discriminate(node, 0)` → M2's `rlp_list_header(0x80, 0)` →
`assert p >= 0xC0` → **fails with `"R1"`**.

That is fail-closed, but it is **not a verdict**. It is exactly the distinction M5 §5.3
insisted on: "a panic is not a *verdict*: exclusion mode must be able to answer 'absent'
rather than aborting the transaction, and a walk that aborts cannot distinguish 'key
absent' from 'relayer sent garbage'." An empty storage trie is the single most common
account shape on Ethereum, and against it the composite would abort with an RLP error
from a *different module* rather than returning "the slot is zero".

**Decision: M6 special-cases it, at the bridge, before phase B exists.** §5.1 step 3
compares the extracted `storage_root` against the `EMPTY_TRIE_ROOT` compile-time
constant; on equality the composite terminates with `C_ABSENT_SLOT_EMPTY_TRIE`,
`C.value = 32 zero bytes`, `C.phase = PHASE_DONE`, and **zero phase-B segments**.
`MODE_B_INIT` additionally asserts `C.storage_root != EMPTY_TRIE_ROOT -> "A8"`, so the
case is closed from both sides.

Cost: one 32-byte comparison against a constant, once per composite. Correctness gain:
the most common real input stops being an abort. This is a genuine finding of this
design pass, not a formality — the naive composition is broken for the majority of
Ethereum addresses.

### 9.2 A present-but-zero storage entry — `C_ZERO_ENTRY`

If the storage leaf's value span decodes (§4.4) to `content_len == 0` — the RLP empty
string `0x80` — the slot is present in the trie with value zero. Canonical Ethereum
execution never produces this (zero writes delete the entry), so it should be
unreachable on mainnet data; a non-canonical or hand-constructed trie could contain it.
M6 returns `C_ZERO_ENTRY` with `C.value = 32 zero bytes`. Semantically identical to
`C_ABSENT_SLOT`; distinguished so that a consumer auditing §8.2's "absent ⇔ zero" claim
can see which route produced the zero. Derived fixture only (**E-M6-4**).

### 9.3 A malformed account body — assert, and why

Resolved in §4.5: **assert** (`A2`, `A3`, `A4`, `A1`), do not trust the hash chain alone.
The short version of the argument: the hash chain proves the bytes are the ones Ethereum
committed *to that root*, which is only equivalent to "well-formed account body" if the
root really is an Ethereum state root — and that is TP-M6-1, an unproven precondition
owned by a module (M8) that does not exist yet. Six opcodes to turn a
silent-wrong-`expected` into a named failure.

### 9.4 EOA vs. contract

`C.code_hash == keccak256("") =
0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` identifies an
externally-owned account. M6 does not act on this — it has no reason to reject a proof
about an EOA's storage (the answer is simply zero, via §9.1) — but it carries
`code_hash` so a consumer can make the distinction without a second proof. The constant
is defined alongside `EMPTY_TRIE_ROOT` for consumers to compare against.

### 9.5 A one-node proof

If `R_state` is itself a leaf (a state trie with a single account — reachable on
testnets and in derived fixtures, not on mainnet), `MODE_A_INIT` walks one node, the
phase-A walk terminates, the bridge fires **in `MODE_A_INIT`**, and — if the storage
trie is non-empty — `MODE_B_INIT` points at `prev_gi = 0`. The mode machine handles it
with no special case; **E-M6-5** pins it, because "the bridge fires in `A_INIT`" is the
arm an implementer is most likely to leave unwired.

### 9.6 Extension nodes and embedded children

Both live entirely inside `mpt_walk_node` and are M5's (005 §5.3, §5.5, fixtures F1/F2).
M6 inherits them with no code. One consequence worth stating: an **embedded** account
leaf (a state trie so small the leaf encodes under 32 bytes and is inlined in its
parent) still ends the walk with `value_off`/`value_len` pointing into the *parent's*
buffer — which is exactly the buffer §5.1's bridge decodes, since `mpt_walk_node`
returns spans into the node argument it was given. Nothing special is required; the
bridge must simply use the returned `(value_off, value_len)` rather than assuming they
index a node it identified itself.

### 9.7 `key_nibs` is always 64 in both phases

Both tries are keccak-keyed, so both keys are exactly 32 bytes / 64 nibbles.
`mpt_init_state(root, key, UInt64(64))` in both phases. M6 never touches
`mpt_key_from_tx_index` or its variable-length key handling (§1.2) — and consequently
M5 §5.2's branch-terminal case (`depth == key_nibs` at a branch) remains structurally
unreachable here, exactly as 005 §5.2 argues.

---

## 10. Error codes

Two-character codes, prefix `A`, following M5 §10's convention (program size is a
binding constraint and assert strings land in program bytes). Mirrored into
`contracts/composer/__init__.py`'s docstring.

| code | meaning |
|---|---|
| A1 | account body decode ran past the value span M5 returned |
| A2 | account body is not exactly 4 items (`item3` does not end at `payload_end`) |
| A3 | `storageRoot` / `codeHash` is not a 32-byte RLP string |
| A4 | `nonce` / `balance` item longer than 32 bytes |
| A5 | storage value longer than 32 bytes after RLP decode |
| A6 | storage value span is not exactly one RLP item filling the span |
| A7 | phase A: recovered `W.root != C.state_root` |
| A8 | `MODE_B_INIT` against `EMPTY_TRIE_ROOT` (§9.1 already terminated the composite) |
| A9 | phase B: recovered `W.root != C.storage_root` |
| A10 | attempted to extend a composite whose `phase` is already `PHASE_DONE` |
| A11 | hand-off: referenced group index does not precede this transaction |
| A12 | hand-off: referenced transaction is not a call to this application |
| A13 | hand-off: referenced transaction did not use `SEGMENT_SELECTOR` |
| A14 | hand-off: referenced transaction's last log is not a well-formed 355-byte composite log |
| A15 | `MODE_B_INIT` from a predecessor whose `phase != PHASE_A_OK` |
| A16 | `MODE_B_INIT` from a predecessor whose phase-A walk did not reach `WALK_INCLUDED` |
| A17 | `mpt6_result_from_group`: composite is not `PHASE_DONE` — no verdict (§8.3) |
| A18 | `mpt6_result_from_group`: `state_root` / `address` / `slot` does not match what the consumer asked (TP-M6-3) |
| A19 | unknown mode byte |

M5's `W1`–`W19` and M2's `R1`–`R9` remain reachable through M6 unchanged; a `W11` from
phase B specifically means "the first storage node does not hash to the extracted
`storageRoot`", which is §5.4's attack being caught.

---

## 11. Test plan

Real mainnet bytes from `tests/fixtures/spike-reference/eth_data.json` (block
25,639,768) wherever real bytes exist, per M2 §8.1 / M5 §9. Everything in §11.1 was
recomputed from that file while writing this doc.

### 11.1 Suite A — the real composite (pinned)

**A-M6-1 — the headline.** `R_state = 0xde97a834…d2c53329`, address
`0xdAC17F958D2ee523a2206206994597C13D831ec7`, slot
`0x0be16d71963429204d70543701f859c43526c316ac005c10114f4694ca405f36`, 8 account nodes +
9 storage nodes. Every field pinned:

| assertion | expected |
|---|---|
| phase-A derived branch indices | `[10, 11, 1, 4, 13, 6, 8]` |
| phase-A key | `keccak256(addr)` = `ab14d68802a763f7db875346d03fbf86f137de55814b191c069e721f47474733` |
| account leaf value span | `(34, 70)` |
| body arity | exactly 4, `item3` ends at `payload_end` |
| body item offsets (body-relative) | nonce `(2,1,KIND_BYTE)`, balance `(3,1,KIND_BYTE)`, storageRoot `(5,32,KIND_STR)`, codeHash `(38,32,KIND_STR)` |
| `C.storage_root` | `261898dc12c926b33218d29afad898be487e821e8b4474465b62d802f7d33291` ≡ `proof.storageHash` |
| `C.code_hash` | `b44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55` ≡ `proof.codeHash` |
| `C.nonce` | `0x00…01` (32-byte BE of `proof.nonce = 0x1`) |
| `C.balance` | `0x00…2a` (32-byte BE of `proof.balance = 0x2a`) |
| phase-B key | `keccak256(slot)` = `aa2813d62366783a4fc90e52c8cc595ba9fd2b278bc52248117c14c07e5394d8` |
| phase-B derived branch indices | `[10, 10, 2, 8, 1, 3, 13, 6]` |
| storage leaf value span | `(32, 8)`, content `873f1ca131081cf8` |
| after §4.4 decode | `(33, 7)`, content `3f1ca131081cf8` ≡ `proof.storageProof[0].value` |
| `C.value` | `0x00000000000000000000000000000000000000000000000000` `3f1ca131081cf8` (32-byte BE) |
| `C.cstatus` / `C.phase` | `C_INCLUDED` / `PHASE_DONE` |
| `C.awalk` / `C.swalk` | `WALK_INCLUDED` / `WALK_INCLUDED` |

The derived-index assertions are not decoration: M5 §9.1 requires them because *a walk
can succeed for the wrong reason*, and the same applies to a composite.

**A-M6-2 — offline reference.** Extend `tests/unit/test_mpt_real_walks.py`'s existing
`test_a4_account_then_storage_composite` (which already chains the two walks through
`rlp_scan`) to go through `mpt6_account_body` instead, and to assert the four body item
spans above. That test already proves the composition works; A-M6-2 proves M6's *own*
decode path produces the identical `storageRoot`.

**A-M6-3 — live 5-transaction group.** The §6.5 group, submitted for **real** (not
`simulate`) against dev-mode algod with sized donors, following
`bench/mpt_bench.py`'s `G7_M5_real_submission` procedure exactly. Assert the final
transaction's `LastLog` decodes to the A-M6-1 field set.

### 11.2 Suite S — security

Every S-test asserts M6 **rejects**, and where the spike's composite would have accepted
the same input, asserts that too (M5 §9.3's rule: "a rejection test that does not
demonstrate the old code passing is not a regression test for this bug").

| test | construction | required result |
|---|---|---|
| **S-M6-1** | Structural: M6's public surface contains no root, key, `storageRoot`, or path parameter for phase B. | Enforced by inspecting the `MODE_B_*` argument layout and every `contracts/composer/` subroutine signature. The absence is the invariant. M5 S2's analogue. |
| **S-M6-2** | §5.4's attack: honest USDT account proof (phase A) + an honest, fully hash-chained storage proof from a **different** contract's storage trie (phase B). | Reject at phase B node 0 with `W11` — `keccak256(node) != C.storage_root`. Spike-oracle: **accepts** (its composite took the storage root from a program constant). **This is the test M6 exists for.** |
| **S-M6-3** | Two complete phase-A walks in one group (USDT and a second real address); `MODE_B_INIT` points `prev_gi` at the **wrong** one. | The group **succeeds** and produces a *true* composite about the other address; `mpt6_result_from_group(gi, R, USDT_addr, slot)` then rejects with `A18`. Both halves must be asserted — this is TP-M6-3 being load-bearing, not decorative. |
| **S-M6-4** | `MODE_B_INIT` with `prev_gi` pointing at: (a) a later transaction, (b) a call to a different app, (c) a non-M6 transaction, (d) an M6 segment still in `PHASE_A`. | `A11`, `A12`, `A13`, `A15` respectively. |
| **S-M6-5** | Forged log: a predecessor's log truncated / re-prefixed / 107 bytes (M5's shape) instead of 355. | `A14`. Must be demonstrated live, as M5's S8 was. |
| **S-M6-6** | Derived fixture: a hash-committed account leaf whose body item 2 is 20 bytes. | `A3`. Documented as unreachable via a real Ethereum root — this tests the §4.5 fail-closed backstop, not a live threat. |
| **S-M6-7** | Derived fixture: a 3-item and a 5-item account body. | `A2` both. |
| **S-M6-8** | The real composite presented for a different `slot` (`MODE_A_INIT`'s `slot` argument changed, everything else identical). | Phase B rejects at the first hop whose derived nibble differs, or at the leaf with `WALK_ABSENT_LEAF_DIVERGE` — and `C.slot` names the substituted slot, so `A18` fires at the consumer. Inherits M5's S1/S6 property one trie down. |

### 11.3 Suite X/E — exclusion and edge cases

| test | case | required |
|---|---|---|
| **X-M6-1** | Truncated phase-A node list presented as an account-exclusion proof | `C.phase == PHASE_A`; `mpt6_result_from_group` rejects with `A17`. **No verdict.** |
| **X-M6-2** | Truncated phase-B node list presented as a slot-exclusion proof | `C.phase == PHASE_B`; `A17`. |
| **X-M6-3** | Real `eth_getProof` exclusion proof for an address with no state (M5 fixture F5) | `C_ABSENT_ACCOUNT`, `C.value` = 32 zeros, `C.awalk ∈ WALK_ABSENT_*`, `C.storage_root == EMPTY_TRIE_ROOT`, `C.code_hash == EMPTY_CODE_HASH`, **zero phase-B segments in the group**. |
| **X-M6-4** | Real `eth_getProof` for USDT with a slot that has never been written | `C_ABSENT_SLOT`, `C.value` = 32 zeros, `C.swalk ∈ WALK_ABSENT_*`, account fields all correct. Add to `ci-live.yml` and pin. |
| **X-M6-5** | Trailing unused node arguments in either phase | `W10` (inherited from M5's `_walk_remaining_args`). |
| **X-M6-6** | A segment whose recovered `C.phase == PHASE_DONE` | `A10`. |
| **E-M6-1** | Real EOA with `storageRoot == EMPTY_TRIE_ROOT` (§9.1) | `C_ABSENT_SLOT_EMPTY_TRIE` at the **bridge**, `PHASE_DONE`, zero phase-B segments. Additionally assert that *starting* phase B against that root would have aborted with `"R1"` — i.e. that the special case is load-bearing, not cosmetic. |
| **E-M6-2** | `MODE_B_INIT` forced against `EMPTY_TRIE_ROOT` | `A8`. |
| **E-M6-3** | Account with a zero balance (`balance` item = `0x80`, `content_len == 0`) | `C.balance` = 32 zeros **and** `C.awalk == WALK_INCLUDED` — the §8.1 discriminator against a non-existent account. Derived or live fixture. |
| **E-M6-4** | Storage leaf whose value item is `0x80` (§9.2) | `C_ZERO_ENTRY`, `C.value` = 32 zeros. Derived. |
| **E-M6-5** | 1-node account proof: the bridge fires inside `MODE_A_INIT` (§9.5) | Composite completes; `MODE_B_INIT` recovers from `prev_gi = 0`. Derived. |
| **E-M6-6** | Account with a multi-byte `balance` (real: any large holder), shifting `storageRoot`'s offset | Body decode still finds item 2 correctly — proves §4.2 decodes items 0/1 rather than using fixed offsets. Real fixture from a second `eth_getProof`. |
| **E-M6-7** | Embedded account leaf (§9.6, M5 fixture F2 shape) | Bridge decodes from the parent buffer using M5's returned span. Derived. |

### 11.4 Suite B — budget, live

`bench/composer_bench.py`, following `bench/mpt_bench.py` exactly (minimal program per
operation, real `/v2/transactions/simulate` for isolation, real `send_transactions` for
the group demonstration), emitting `bench/composer_results.json` with:

- the bare composite total, beside M5's measured 5,116 + the newly-measured phase-B walk
  (replacing §7.2's predicted 5,527) and the spike's 6,827;
- `mpt6_account_body` isolated, against §4.3's ~255 estimate **and** against a
  `rlp_scan_upto(…, 2)` control, so §4.3's claimed ~80 trade is a measured number rather
  than an argued one;
- the segment-boundary cost isolated (M5's G4-M5 never was — §7.2 note);
- per-transaction consumed for the real 5-transaction group, with and without donors;
- compiled program size for G5-M6 and **G6-M6**;
- the pathological 22-node synthetic composite (§7.4), to confirm the one-group verdict
  at real depth rather than by arithmetic alone.

---

## 12. Acceptance gates

| gate | requirement |
|---|---|
| **G1-M6** | The real USDT/Binance-8 composite verifies end to end and reproduces every pinned field in §11.1's table. Correctness; must pass. |
| **G2-M6** | **The headline.** The full composite fits **one** 16-transaction atomic group, demonstrated by a **real, non-simulated** submission with sized donors — M5's G7-M5 analogue, and the gate that actually decides whether M6 is usable. |
| **G3-M6** | Measured composite budget ≤ **1.25 ×** the two-walk floor (`G6-M5 + the measured phase-B walk`), i.e. M6's own composition overhead stays under 25%. Predicted 17.7% (§7.3). **Deliberately not set against the spike's 6,827** — M5 §16.4 established that a key-bound walker costs ~1.6× the spike per node, and a gate M6 provably cannot pass is not a gate. |
| **G4-M6** | Segment-boundary cost (`mpt6_state_from_prev` + `mpt6_log_state` + argument marshalling) measured **in isolation** and reported. §7.2 derives ~211 from M5's group totals; M5's own G4-M5 never isolated it. No pass/fail target until there is one measurement. |
| **G5-M6** | `contracts/composer/`'s own incremental compiled size ≤ **900 B**, measured M5-style (a combined probe diffed against an M2+M5 probe, so M5's 1,969 B is not double-counted). |
| **G6-M6** | **The structural risk.** The full deployable composite app — M2 (839 B) + M5 (1,969 B) + M6 + driver + dispatch — compiles under the **8,192 B** per-call cap with `extra_pages = 3`. Estimated ~4,300 B, leaving ~3,900 B for M7/M8. M5 missed its own size gate by 40%; this one must be measured early, not at the end. |
| **G7-M6** | Both absence flavours (§8.1, §8.2) and the empty-storage-trie case (§9.1) produce terminal composite verdicts on real fixtures, and every truncated-list variant produces **no verdict** (X-M6-1/2). |
| **G8-M6** | S-M6-2 (the §5.4 substitution attack) rejects, **and** the spike-oracle accepts the identical input. |

---

## 13. `ROADMAP.md` resolved, and what is handed on

### 13.1 The M6 open question

> *"Exclusion-proof support decision (spike only did inclusion)"*

**Resolved: M6 supports exclusion at the composite level, in two structurally distinct
flavours, plus a third for the empty storage trie — and it refuses to produce any
verdict from an incomplete walk.**

- **Account absent** (`C_ABSENT_ACCOUNT`, §8.1): no state-trie entry at
  `keccak256(address)`. The storage slot is *trivially* zero — there is no storage trie
  to walk, and **no phase-B segment is issued or accepted**. `C` is filled with the
  consensus-defined non-existent-account values (`nonce = 0`, `balance = 0`,
  `codeHash = keccak256("")`, `storageRoot = keccak256(rlp(""))`). M5 §11.1's
  "non-existent vs. existent-with-zero-balance" question is answered exactly: the
  discriminator is `C.awalk` (`WALK_ABSENT_*` vs `WALK_INCLUDED`), not a heuristic on
  the balance field.
- **Slot absent** (`C_ABSENT_SLOT`, §8.2): account present, no storage-trie entry at
  `keccak256(slot)`. A normal, common, *meaningful* result. The semantic claim
  *absent ⇔ zero* is written down with its justification (`SSTORE` to zero deletes the
  entry, so canonical execution produces no "present and zero" encoding), and M2 E15's
  `0x80` case is given its own code (`C_ZERO_ENTRY`, §9.2) so the claim stays auditable.
- **Empty storage trie** (`C_ABSENT_SLOT_EMPTY_TRIE`, §9.1): a genuinely new finding —
  walking a slot against `keccak256(rlp(""))` **aborts inside M2 with `"R1"`** rather
  than returning an M5 absence code, because the empty trie's only node is `0x80`, which
  is not an RLP list. This is the most common account shape on Ethereum and it does
  **not** work naturally. M6 terminates at the bridge on a 32-byte constant comparison.
- **No verdict from a truncated walk** (§8.3): `PHASE_DONE` is written only from a
  terminal M5 status, and `mpt6_result_from_group` refuses anything else (`A17`). M5's
  X5 trap, lifted, twice.

M6 does **not** re-decide M5's per-walk exclusion question — M5 §6 already established
that each `WALK_ABSENT_*` form is individually sound given the hash chain, and M6 builds
on that rather than relitigating it.

### 13.2 Flagged for M8 (trusted-root anchor)

- **The swap point is `MODE_A_INIT`'s `arg 4`.** M6 v1 takes `R_state` as an argument
  under TP-M6-1. M8's contract replaces that read with a lookup in its own root history
  and asserts the result — a one-line change at exactly one site. Design M8's anchor
  read to return a 32-byte root so this stays a substitution.
- **TP-M6-3 is M8's to enforce on-chain.** `mpt6_result_from_group`'s three `want_*`
  arguments are where M8 supplies its anchored root and the application's intended
  address/slot. §5.4's residual attack is defeated there and nowhere else.
- **Root freshness/reorg policy is unchanged by M6** and remains M8's (M5 §11.1's last
  bullet).
- **Program size**: after M2 + M5 + M6 (~4,300 B est.), M8 and M7 share ~3,900 B of the
  8,192 B per-call cap. If that proves insufficient, the split is into separate deployed
  *apps*, not separate groups (§7.4) — but note that `mpt6_state_from_prev` asserts
  `prev.app_id == Global.current_application_id`, so splitting M6 across two apps would
  require rethinking the hand-off. Flagging this now rather than discovering it later.

### 13.3 Flagged for M9 (relayer)

- **The M6 ABI is frozen by §6.3** (raw args, `SEGMENT_SELECTOR = "ACS1"`, four modes)
  and **§3.3** (the 248-byte `C` layout) and **§3.4** (the 355-byte log envelope). M9
  can start against these ahead of M6's implementation landing, per `ROADMAP.md`'s M9
  row.
- **The relayer owns segmentation.** It must split the node list in **path order**
  under the per-mode caps in §6.3, and the caps differ between `A_INIT` (1,943 B / 9
  args) and the rest (2,019 B / 11 args). §7.1's 13-byte finding means a naive
  "2,048 minus a round number" heuristic produces a different (and sometimes invalid)
  split.
- **The relayer owns donor sizing** — `simulate` with zero donors, then size, then
  submit for real (M5 §16.3, §7.6). And it must fund transaction 0 for
  `(1 + donor_count)` min fees.
- **The relayer owns Solidity mapping-key derivation** (§1.2). M6 takes the final
  32-byte slot. For `mapping(address => uint256) balances` at declaration slot `k`, the
  slot is `keccak256(pad32(holder) ‖ pad32(k))` — the fixture's
  `0x0be16d71…5f36` is exactly that for Binance-8 at USDT's `balances` slot 2. If the
  holder is itself untrusted input, the derivation must be on-chain too, and that is a
  new (small) M9/M8 surface, not M6's.
- **Off-chain verification of the result** is three byte comparisons against the §3.3
  layout at offsets 2, 34 and 54, plus a `phase == 3` check at offset 1.

### 13.4 Flagged for M7 (receipt/log)

- **M7 does not need M6's bridge.** A receipt proof is a *single* walk from
  `receiptsRoot`; there is no second trie. M7 needs M6's **segment driver shape** (§6)
  and `C`-style self-describing result, not §5's hand-off.
- **The >4,096-byte receipt leaf is untouched by M6** and remains M7's hard stop
  (`ROADMAP.md`). M6 confirms the boundary is unchanged: M6 never handles a value larger
  than a 70-byte account body or a 33-byte storage value.
- **If M7 shares M6's deployed app**, §13.2's program-size arithmetic is the binding
  constraint — M7 should measure G6-M6's headroom before designing, not after.
- **`receipt_envelope` is still unused by M5 and M6** (§2), so M7 inherits it clean.

---

## 14. Deferred optimisations, measurement-gated

**O-M6-1 — fuse the phase transition into one transaction, and tighten the fixed
argument fields.** There is no *security* reason for phase B to start in a new
transaction: `storage_root` never leaves the AVM's memory within the bridging call, so
the account-terminal segment could decode the body and immediately begin the storage
walk with whatever node arguments remain. Combined with narrowing `donor_count` to 1
byte (the group inner-txn cap is 256, so one byte is exactly right) and `prev_gi` to 1
byte (a group index is 0–15), the fixed overhead falls from 29 B to 15 B and the caps
rise to 1,950 / 2,033. The real workload then packs as:

```
S0 A_INIT  acct 0,1,2                      1,596 / 1,950
S1 A_NEXT  acct 3,4,5,6                     2,032 / 2,033      <- the 13-byte finding, recovered
S2 A_NEXT  acct 7 · bridge · stor 0,1,2     1,700 / 2,033
S3 B_NEXT  stor 3–8                         1,738 / 2,033
```

**4 segments instead of 5** — saving one transaction slot, one boundary (~211 budget)
and ~0.001 ALGO. **Deliberately not shipped in v1**: it costs a phase-aware node loop
(the trailing-node strictness check must distinguish "walk terminal, phase `A_OK`,
continue with `W_B`" from "walk terminal, phase `DONE`, reject trailing"), which is a
real correctness surface in the module whose job is joining two proofs. The saving is
1.7% of budget and one of sixteen transaction slots. This is the same trade M5 §5.1 made
when it chose the unconditional arity discriminator over the cheaper shape test, and it
is recorded here so the v1 implementer does not "helpfully" add it. Revisit only if
G2-M6 or G3-M6 fails.

Note both halves are needed: with M5's current field widths the fusion saves nothing
(the packing still lands on 5 segments), which is why v1 keeps M5's widths verbatim.

**O-M6-2 — batched multi-slot reads.** Several slots of the *same* contract share one
account walk and one `storage_root`; only phase B repeats. `n` slots would cost
`account_walk + n × storage_walk` instead of `n × (account + storage)` — a ~46% saving
at `n = 2` and asymptotically ~54%. It needs `C` to carry `n` slots and `n` values (or a
digest), a per-slot phase-B sub-cursor, and a careful re-derivation of §7.4's argument
arithmetic (`n × 3,334` node bytes hits the 48-node argument ceiling at `n ≈ 4`).
Recorded, not designed. `MPT_RESULTS.md` §2's "~27 independent full storage reads per
group" is the naive alternative and is already adequate for v1.

**O-M6-3 — drop `nonce` / `balance` / `code_hash` from `C`.** Saves ~60 budget, 96 log
bytes, and some compiled size if G6-M6 comes in tight. Only worth doing if G6-M6 (the
8,192 B program cap) actually fails, since the fields are genuinely useful to M8/M9
(§9.4) and the decode that produces them is paid for anyway (§4.3).

**O-M6-4 — `mpt6_account_body` via `rlp_scan_upto`.** §4.3's rejected option, worth ~80
budget (0.6% of the composite) at the cost of the `A2` arity check and the three extra
fields. Revisit only if G3-M6 fails and O-M6-1 was not enough. Listed so the trade is on
record with its number rather than being rediscovered.
