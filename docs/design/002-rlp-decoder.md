# 002 — M2: On-chain optimized RLP decoder

Status: **Design Drafted** (awaiting human approval)
Module: **M2** (`contracts/primitives/rlp/`)
Depends on: scaffold
Blocks: M5 (path walker), M6 (account/storage composer), M7 (receipt/log)
Spike evidence: `tests/fixtures/spike-reference/MPT_RESULTS.md` §1, §5;
`tests/fixtures/spike-reference/mpt_bench.py` (`RLP_ITEM_SUB`, `rlp_split`)

---

## 1. Scope and non-goals

### 1.1 In scope

M2 ships a **library of Puya `@subroutine`s** — not a deployable application —
that turn a hash-committed Ethereum MPT node (or any RLP blob) held in a single
AVM `Bytes` value into offsets and lengths that callers can act on:

1. **RLP list-header decode** — short (`0xc0..0xf7`) and long (`0xf8..0xff`)
   forms, including length-of-length.
2. **RLP item-header decode** — single-byte (`0x00..0x7f`), short string
   (`0x80..0xb7`), long string (`0xb8..0xbf`), and *embedded list*
   (`0xc0..0xff`, i.e. an inlined MPT node under 32 bytes).
3. **Single-pass span scan** producing a reusable **offset table**, so that the
   cost of reading item *i* no longer depends on *i* (the spike's core defect —
   §1 of `MPT_RESULTS.md`: 62 / 318 / 542 budget for item 0 / 8 / 15).
4. **Hex-prefix (compact) nibble-path decode** for 2-item extension/leaf nodes,
   plus nibble addressing and a nibble-range comparator with a byte-aligned fast
   path. (Did not exist in the spike at all.)
5. **EIP-2718 typed-receipt envelope stripping**. (Did not exist in the spike;
   `MPT_RESULTS.md` §5.6 found the receipts-trie root only reproduces once the
   leading `0x01`/`0x02`/`0x03` byte is removed.)
6. A **strict Python reference oracle** (`tests/reference/rlp_ref.py`) that is
   the differential-test authority for every on-chain path, and a
   **measurement-only bench app** so every budget number in this module traces
   to a real `/v2/transactions/simulate` response.

### 1.2 Non-goals (explicit)

- **No MPT path walking, no key-nibble derivation, no hash linking.** M2 never
  calls `keccak256` and never decides which child to descend into. That is M5.
  M2 supplies the nibble primitives M5's security fix needs; it does not
  implement the check.
- **No account/receipt semantic layer.** M2 will happily hand you the four
  spans of an account RLP list or the four spans of a receipt payload; naming
  them `nonce`/`balance`/`storageRoot`/`codeHash` or
  `status`/`cumGas`/`bloom`/`logs` is M6/M7's job.
- **No solution to the >4096-byte receipt leaf.** That is M7's, and per
  `ROADMAP.md` M7 "may force revision of M2". §4 of this doc states precisely
  what M2 does and does not pre-commit so that revision stays cheap.
- **No exclusion proofs, no trie *building*, no RLP *encoding* on-chain.**
  Encoding is only needed off-chain (relayer, M9) and in the test oracle.
- **Not a hardened parser for untrusted bytes.** See trust precondition TP-1
  below — this is a load-bearing scope decision, not a hand-wave.

### 1.3 Trust precondition TP-1 (load-bearing)

> **Every byte string M2 parses is already hash-committed to a root the caller
> trusts, and the caller MUST verify that commitment *before* calling M2.**

In the M5/M6/M7 flow the node bytes arrive as app-call arguments and the caller
executes `assert keccak256(node) == parent_ref` before decoding — exactly as the
spike's `build_verifier` does. Consequently:

- Non-canonical RLP (e.g. `0x81 0x05` for the byte `0x05`, a long-form length
  with a leading zero byte, a short-form used for a >55-byte payload) **is not
  an attack surface**: an attacker cannot substitute it without breaking the
  keccak link to the trusted root, and a real Ethereum client never emits it.
- Therefore M2 **omits per-item canonicality checks from the hot loop** (they
  would cost 2–4 opcodes on every one of the 17 items of every branch node) and
  keeps only **structural bounds checks**, which are required for determinism
  and clean failure. The strict Python oracle *does* enforce canonicality, so
  every fixture is proven canonical off-chain in CI.
- Failure mode is **fail-closed**: any structural violation is an `assert`, and
  every out-of-range read the AVM itself rejects (`getbyte`/`extract3` panic on
  out-of-bounds), so a malformed input aborts the transaction rather than
  yielding a wrong span. There is no path where M2 returns a "best-effort" span.

A caller that wants to parse genuinely untrusted RLP must not use M2 as-is;
this is documented in the module docstring. If a future module needs that, it
gets a `strict=True` variant with its own measured cost — not a silent change
here.

---

## 2. Concrete interface

### 2.1 File layout

```
contracts/primitives/rlp/
  __init__.py        # re-exports the public subroutines
  core.py            # §2.3 list header, item header, scan, table lookup
  nibbles.py         # §5 hex-prefix decode, nibble addressing, comparison
  eip2718.py         # §6 typed-envelope stripping
  bench_app.py       # measurement-only ARC-4 app (never deployed to mainnet)
tests/reference/rlp_ref.py   # strict Python oracle (§8)
bench/rlp_bench.py           # simulate harness, mpt_bench.py pattern (§8.4)
```

Everything in `core.py`/`nibbles.py`/`eip2718.py` is a module-level
`@subroutine`; there is no class, no global state, and no scratch-slot
convention. (The spike's `RLP_ITEM_SUB` reserved scratch 100–108 and documented
"single-threaded, non-recursive use only" — that hazard disappears because Puya
allocates locals and we never hand-manage scratch.)

### 2.2 Type conventions

- Offsets, lengths, nibble indices, item counts: `UInt64`.
- Buffers: `algopy.Bytes` (AVM-guaranteed ≤ 4096 bytes — see §4).
- **Spans, not slices.** Every primitive returns `(offset, length)` *into the
  caller's buffer*. Nothing copies. `extract3` is called only when a caller
  explicitly materialises a value (`rlp_bytes`, §2.3.6). This is both the
  cheapest option and the M7-forward-compatible shape (§4).
- Kind discriminator (`UInt64`), returned by item decode:

  | value | name | first byte | span covers |
  |---|---|---|---|
  | 0 | `KIND_BYTE` | `0x00..0x7f` | the single byte itself (length 1) |
  | 1 | `KIND_STR` | `0x80..0xbf` | string content (length may be 0) |
  | 2 | `KIND_LIST` | `0xc0..0xff` | **the whole encoding, header included** |

  `KIND_LIST` covering the header (not the payload) is deliberate: an
  MPT child under 32 bytes is *embedded* rather than hash-referenced, and the
  consumer's only sensible next move is `rlp_scan(data, span_offset)` on it.
  Returning payload-only — which the spike's `rlp_item` did — silently strips
  the list header and produces a wrong recursive parse. Recorded here because
  no fixture in `eth_data.json` exercises it (§8.2).

### 2.3 Signatures (`core.py`)

```python
from algopy import Bytes, UInt64, subroutine, op

KIND_BYTE = 0
KIND_STR  = 1
KIND_LIST = 2

@subroutine
def rlp_list_header(data: Bytes, start: UInt64) -> tuple[UInt64, UInt64]:
    """Decode the RLP list header at `start`.
    Returns (payload_off, payload_end) as absolute offsets into `data`.
    Asserts data[start] >= 0xc0            -> error "R1" (not a list)
    Asserts payload_end <= len(data)       -> error "R2" (truncated)
    """

@subroutine
def rlp_item_header(data: Bytes, pos: UInt64) -> tuple[UInt64, UInt64, UInt64]:
    """Decode one RLP item header at `pos` (works standalone or inside a list).
    Returns (content_off, content_len, kind).
    For KIND_LIST, content_off == pos and content_len == total encoded size.
    Asserts content_off + content_len <= len(data)  -> "R2"
    """

@subroutine
def rlp_scan(data: Bytes, start: UInt64) -> tuple[Bytes, UInt64]:
    """SINGLE-PASS scan of the RLP list at `start`.
    Returns (table, n_items) where `table` holds n_items+1 big-endian uint16
    HEADER offsets: table[i] = offset of item i's first byte, and
    table[n_items] = payload_end.
    Asserts n_items <= 17                 -> "R3" (arity cap, see below)
    Asserts the last item ends exactly at payload_end -> "R4"
    """

@subroutine
def rlp_table_item(data: Bytes, table: Bytes, i: UInt64
                   ) -> tuple[UInt64, UInt64, UInt64]:
    """O(1) lookup: (content_off, content_len, kind) for item i.
    Asserts 2*i + 2 <= len(table)         -> "R5" (index out of range)
    """

@subroutine
def rlp_table_count(table: Bytes) -> UInt64:
    """len(table)//2 - 1. Provided so callers need not carry n_items around."""

@subroutine
def rlp_bytes(data: Bytes, off: UInt64, length: UInt64) -> Bytes:
    """Materialise a span. Always compiles to `extract3` — NEVER the immediate
    `extract` form, whose length==0 immediate means 'to end of array' and would
    silently return the rest of the node for an empty RLP string."""

@subroutine
def mpt_node_scan(data: Bytes, start: UInt64) -> tuple[Bytes, UInt64]:
    """rlp_scan + MPT arity check: asserts n_items == 2 or n_items == 17
    -> "R6". The single entry point M5 should use on a node."""
```

Notes for the implementer:

- The `n_items <= 17` cap in `rlp_scan` bounds the table to 36 bytes and the
  loop to 17 iterations. It is **wrong for M7**, which must scan a receipt
  payload (4 items) and then a logs list (arbitrary arity) — so make the cap a
  compile-time constant `MAX_ITEMS` on `rlp_scan` and expose a second entry
  `rlp_scan_n(data, start, max_items)` taking it as a parameter, with
  `rlp_scan` = `rlp_scan_n(..., 17)`. Cost delta is one extra frame argument.
- Do **not** write a `rlp_item(data, start, i)` convenience that scans and
  discards the table. That is the spike's API and it is what invites the
  O(index) re-walk back in. If a caller genuinely wants one item and nothing
  else, it writes `t, _n = rlp_scan(...)` then `rlp_table_item(data, t, i)` —
  two lines, and the table is right there for the next access.

### 2.4 `Op`-level justification (ARCHITECTURE.md exception policy)

ARCHITECTURE.md permits dropping to `algopy.op` in budget-critical inner loops
"when a design doc explicitly justifies it with a measured budget comparison."
The justification for M2:

| Evidence | Number | Source |
|---|---|---|
| RLP decode share of per-node cost | **67 %** (2,202 of 3,277) | `MPT_RESULTS.md` §1 |
| keccak256 share (the alternative target) | 33 %, and **flat 130** at any size | `MPT_RESULTS.md` §1 |
| spike item[15] extraction | **542** budget | `MPT_RESULTS.md` §1 |
| per-item skip cost implied | (542−62)/15 ≈ **32 budget/item** | derived from the two rows above |

32 opcodes to advance a cursor past one `0xa0 ‖ 32-byte-hash` item is roughly
3× what the arithmetic needs; the spike's loop spends most of it on
`store`/`load` traffic around scratch slots 100–108. The scan loop is therefore
the one place in M2 where opcode-level control is warranted.

**Scope of the exception — exactly two loop bodies:**

1. the `while` body inside `rlp_scan` (§3.2), and
2. the per-nibble fallback loop inside `nibbles_equal` (§5.4).

Everything else in M2 — `rlp_list_header`, `rlp_item_header`,
`rlp_table_item`, `hp_decode`, `eip2718.receipt_envelope`, all asserts — is
ordinary typed Puya. Within those two loop bodies the rules are:

- Use `op.getbyte`, `op.extract3`, `op.extract_uint16`, `op.itob`, `op.btoi`,
  `op.concat` directly instead of Puya slicing/indexing sugar, so the emitted
  opcode is not left to the compiler's discretion.
- **Do not** call a subroutine per item. `rlp_item_header`'s logic is inlined
  into the scan loop body: at ~5 opcodes of `callsub`/`retsub`/frame overhead
  per call, 17 calls is ~85 budget of pure glue. This creates one duplicated
  ~15-line block between `rlp_item_header` and the scan loop; it is mandatory
  that a differential test asserts both paths return identical
  `(content_off, content_len, kind)` for **every item of every fixture node**
  (§8.3, test D1). That test is the price of the duplication and is not
  optional.
- No manual `store`/`load` scratch management. Let Puya place locals; the
  spike's scratch discipline is what made its loop expensive, and it also made
  the subroutine non-reentrant.

If measurement (§8.4) shows the plain-Puya loop already lands inside the
acceptance gates, **prefer the plain-Puya version and record the measured
comparison** — the exception is permission to go low-level, not an obligation.

---

## 3. Fixing the O(child-index) re-walk

### 3.1 What is and is not fixable (stated honestly)

RLP is a length-prefixed sequential format with **no index**. The offset of
item *i* is a function of the encoded lengths of items 0..*i*−1, so *one*
extraction of item *i* from a cold buffer is irreducibly Θ(*i*). Any claim to
make a single cold lookup index-independent would be false.

What is actually wrong with the spike, and what this design fixes:

| Defect | Spike | This design |
|---|---|---|
| Repeated re-walk: *k* extractions from one node cost *k* walks | yes — `RLP_ITEM_SUB` restarts at byte 0 every call | **one** walk per node, regardless of *k* |
| Cost of reading item *i* depends on *i* | 62 → 542, ~9× | **flat**: whole-node scan cost is a function of node arity/size only; per-item retrieval afterwards is O(1) |
| Per-item step cost | ~32 budget | target ≤ 12 budget (§3.4) |

So the deliverable property is: **`cost(read item 15) − cost(read item 0) ≤ 10
budget`**, enforced as a measured acceptance gate (§8.4, gate G2), achieved by
paying one flat scan up front rather than by making indexing free.

An "early-exit at item *i*+1" variant (which would be cheaper on average —
~145 vs ~250 for uniform *i* — but still index-scaling, ~6×) is **explicitly
rejected for M2 v1**: it reintroduces index-dependence, it needs a second code
path (program size is the binding per-call constraint at 8192 B —
`MPT_RESULTS.md` §5.5), and it cannot answer "is this a 2-item or a 17-item
node?", which M5 needs on every hop and which requires reaching payload end
anyway. It is recorded in §9 as a deferred, measurement-gated optimisation.

### 3.2 The scan loop, concretely

Table format: `n_items+1` big-endian `uint16`s, entry *i* = absolute offset of
item *i*'s **first (header) byte**, final entry = `payload_end`. Header offsets
rather than content spans, because they are monotone, they need only one number
per item, and item *i*'s content span is recovered from one `getbyte` + a
compare or two (`rlp_table_item`). 17-item branch node → 36-byte table.

```python
@subroutine
def rlp_scan_n(data: Bytes, start: UInt64, max_items: UInt64
               ) -> tuple[Bytes, UInt64]:
    payload_off, payload_end = rlp_list_header(data, start)

    table = Bytes()          # accumulates 2 bytes per item
    pos = payload_off
    n = UInt64(0)

    while pos < payload_end:
        assert n < max_items, "R3"
        # --- emit table entry for item n: 2 big-endian bytes of `pos` ---
        table += op.extract3(op.itob(pos), UInt64(6), UInt64(2))
        n += 1

        # --- advance `pos` past item n (the hot path; see ordering note) ---
        p = op.getbyte(data, pos)
        if p < 0x80:                       # KIND_BYTE
            pos += 1
        elif p < 0xb8:                     # short string: 0x80..0xb7
            pos += 1 + p - 0x80            # p==0x80 -> +1 ; p==0xa0 -> +33
        elif p < 0xc0:                     # long string: 0xb8..0xbf
            ll = p - 0xb7
            pos += 1 + ll + _read_len(data, pos + 1, ll)
        elif p < 0xf8:                     # embedded short list
            pos += 1 + p - 0xc0
        else:                              # embedded long list
            ll = p - 0xf7
            pos += 1 + ll + _read_len(data, pos + 1, ll)

    assert pos == payload_end, "R4"        # last item ends exactly at the end
    table += op.extract3(op.itob(payload_end), UInt64(6), UInt64(2))
    return table, n
```

Loop-body notes the implementer must honour:

- **Branch ordering is chosen by real-data frequency.** Every non-empty child
  of every one of the 17 real branch nodes in `eth_data.json` is exactly
  `0xa0 ‖ 32 bytes`, and every empty slot is `0x80` — both land in the
  `0x80..0xb7` arm, and both are handled by the *same* branchless
  `pos += 1 + p - 0x80` (`0x80` → +1, `0xa0` → +33). So order the tests so this
  arm is reached in the fewest comparisons: test `p < 0xb8` first, then `p <
  0x80` inside it. That is 2 comparisons for the 100 % case in the fixture set.
  Do **not** reorder to put `p < 0x80` outermost.
- `p - 0x80` must only be evaluated on the arm where `p >= 0x80`; AVM `-`
  panics on underflow. This is a real trap in a rearranged loop.
- `_read_len(data, off, ll)` is a small `@subroutine` (called only on the rare
  long-form arms, so subroutine overhead is fine there):
  `ll == 1 → op.getbyte`; `ll == 2 → op.extract_uint16`;
  `3 <= ll <= 4 → op.extract_uint32`-with-shift or
  `op.btoi(op.extract3(data, off, ll))`; `ll > 8 → assert "R7"`. Using
  `btoi(extract3(...))` uniformly for `ll >= 1` is one opcode more but one code
  path — prefer it unless measurement says otherwise.
- Table growth uses `concat` (1 opcode, flat-metered). The alternative —
  `op.bzero(2*(max_items+1))` pre-allocated plus `op.replace3` — is the same
  opcode count and adds an unused-tail hazard, so `concat` wins on simplicity.
- Table-write overhead is 3 opcodes/item (`itob`, `extract3`, `concat`) = ~51
  for a branch node. That is the price of index-independence and of free
  re-access; it is the number to attack first if gate G1 (§8.4) fails, e.g. by
  fusing "capture the two spans the caller asked for" into the scan and
  skipping the table (see §9, deferred O-2).

### 3.3 O(1) retrieval

```python
@subroutine
def rlp_table_item(data: Bytes, table: Bytes, i: UInt64
                   ) -> tuple[UInt64, UInt64, UInt64]:
    assert 2 * i + 2 <= table.length, "R5"
    pos = op.extract_uint16(table, 2 * i)          # 1 opcode
    return rlp_item_header(data, pos)              # ~6-10 opcodes
```

Roughly 10–14 budget per retrieval, independent of *i*. Callers that read two
items from one node (M5's ext/leaf hop: path + child; M5's terminal branch:
child + value slot) pay one scan and two of these.

### 3.4 Expected effect (targets, not claims)

Per ARCHITECTURE.md, **no number below ships until `bench/rlp_bench.py`
produces it from a real simulate response.** These are the design targets that
the acceptance gates in §8.4 test:

| Quantity | Spike measured | M2 target |
|---|---|---|
| per-item advance in scan loop | ~32 | ≤ 12 |
| full 17-item branch scan (table built) | n/a (542 for item 15 alone) | ≤ 300 |
| retrieval of item *i* after scan | n/a | ≤ 15, flat in *i* |
| `cost(item 15) − cost(item 0)` | 480 | **≤ 10** |
| 2-item ext/leaf scan + both items | ~124 (2 × 62) | ≤ 90 |

If the branch-node total lands near 300 against the spike's 542-for-one-item,
the RLP share of the ~410 budget/node figure in `MPT_RESULTS.md` §1 drops
materially and per-node cost becomes dominated by keccak's flat 130 — which is
the healthy end state.

---

## 4. Single blob vs. data-source abstraction — decision

### 4.1 Recommendation

> **M2 commits to a single in-stack `Bytes` blob.** No reader/data-source
> abstraction, no box-backed variant, no virtual dispatch. But **every
> primitive is offset-addressable and copy-free** — signatures are
> `(data, start)` and returns are `(offset, length)` pairs into `data`; nothing
> in M2 assumes parsing begins at byte 0, and nothing recurses by slicing out a
> sub-buffer.

### 4.2 Why (four reasons, strongest first)

**(a) An abstraction now would not unblock M7, because decoding is not M7's
blocker.** M7's blocker is *hashing*: a receipts-trie leaf embeds the whole
receipt, 9 of the 137 receipts in the spike's real test block RLP-encode past
4096 B (max **157,274 B**), `keccak256` takes a single ≤4096 B stack value, and
the AVM has no streaming/incremental hash opcode. So M7 **cannot materialise or
hash that leaf at all**, with or without a chunk-reading decoder — it needs a
structural answer (a sub-commitment, a different trust route to the log, a
re-hash proven elsewhere). Until that structure is chosen, we do not know which
ranges M7 will read or in what order, so any reader interface designed today is
a guess. `MPT_RESULTS.md` §5.3 says exactly this ("naive log proofs are
infeasible … without restructuring"), and `ROADMAP.md` already flags M7 as a
hard-stop design review that "may force revision of M2". Guessing now buys
nothing and costs a wrong guess.

**(b) The unbounded object is a leaf *value*, never a node *structure*.** This
decomposition matters and it holds structurally, not just in the fixtures. A
branch node is 17 items each ≤ 33 bytes → ≤ ~566 B (real: 532). An extension
node is a ≤ 33-byte path plus a ≤ 33-byte reference → ≤ ~70 B. A leaf is a
≤ 33-byte path plus a value. Measured, in `eth_data.json`: account proof nodes
`[532,532,532,532,532,532,436,104]`, storage proof `[532,…,83,83,40]`, receipt
proof `[308,532,690]`. **Only the leaf value is unbounded, and only in the
receipts trie** — accounts are a fixed ~70 B 4-item list, storage values are
≤ 33 B. So the *item-span scan* — the thing M2 is actually optimising — never
needs more than 4096 B for any trie M2's consumers walk. Making the scan
abstract would be paying an abstraction tax on the bounded 100 % to accommodate
a case that lives entirely inside one item of one trie.

**(c) The cost tradeoff is real and lands on the hot loop.** The scan's inner
loop is ~10 opcodes per item, of which `op.getbyte(data, pos)` is *one*.
Routing that read through an abstraction means, per byte read: a source-kind
test plus a branch (≥ 2 opcodes, i.e. **+20 % on the loop**), or a Puya
subroutine call per read (≈ 5 opcodes of frame glue, **+50 %**) — Puya has no
free dynamic dispatch to hide it. Worse, the abstraction only pays off if the
backing store is boxes, and box reads are metered on *bytes*, not just
opcodes: the documented box-IO read budget is 1024 bytes per box reference with
at most 8 references per app call (≈ 8 KB per call — **documented, unmeasured;
per ARCHITECTURE.md this must be measured before any design leans on it**). A
157 KB receipt is then ~20 app calls of read budget for a *single* pass, and a
scan that re-reads is worse. So the abstraction adds cost to the common case
and still does not make the pathological case work.

**(d) The 4096 cap is what makes the design cheap, and it is free.** Because
any AVM `Bytes` is ≤ 4096 B *by construction*, every offset fits in 16 bits, so
the offset table is `uint16` and reads with a single `extract_uint16`. No
runtime length check is needed to justify it. A generic reader would force
`uint32` or `uint64` table entries (2× the table bytes, and `extract_uint32`
plus shifting or `btoi(extract3(...))` per read) to support a case nothing in
M2's dependency set has.

### 4.3 What the copy-free span discipline buys M7 anyway

The concession that makes this decision cheap to reverse: because M2's format
logic is expressed as **arithmetic over `(buffer, start)` pairs** rather than
over sliced sub-buffers, all of it is *already* the pure-function core a chunked
reader would need. Concretely, if M7 later needs box-backed reads:

- The only thing that must be re-implemented is the ~3 byte-fetch sites
  (`op.getbyte`, `op.extract_uint16`, `op.extract3`) — the byte-fetch layer.
- The format logic — prefix classification, the five stride rules,
  length-of-length, the table layout, hex-prefix decode, envelope stripping —
  is unchanged, because none of it looks at `len(data)` except in bounds
  asserts and none of it re-bases offsets to zero.
- The Python oracle (`tests/reference/rlp_ref.py`) is written the same way and
  is reusable as M7's oracle verbatim.
- Nested decode already works through this discipline today: an account leaf's
  value at `eth_data.json` `accountProof[7]` offset 34 is decoded by
  `rlp_scan(node, 34)` with no copy and no second buffer. That is the same
  capability a chunked reader would provide, minus the abstraction.

So: **no parallel decoder** for M7, and **no speculative interface** in M2. The
honest cost of this choice, stated plainly: if M7's eventual structure does turn
out to need range reads over a >4096 B buffer, M7 pays for a new byte-fetch
layer plus new measurements — an estimated few hundred lines — while reusing
M2's format logic and oracle. That is a smaller bet than shipping an abstraction
whose shape we would be inventing before its only consumer exists.

---

## 5. Hex-prefix (compact) nibble-path decoding

### 5.1 The rule, exactly

Compact encoding (Yellow Paper HP; go-ethereum `hexToCompact`). A path is a
nibble sequence plus a terminator flag (present ⇔ leaf). Let
`t = 1` if leaf else `0`, and `oddlen = len(nibbles) mod 2`. The flag nibble is
`f = 2*t + oddlen`. Then:

- **odd length**: first byte `= (f << 4) | nibbles[0]`; the remaining nibbles
  pack two-per-byte from byte 1.
- **even length**: first byte `= f << 4` (exactly `0x00` or `0x20`, low nibble
  zero); all nibbles pack two-per-byte from byte 1.

Decode table on the high nibble of byte 0:

| high nibble | terminator | length parity | node kind | first path nibble |
|---|---|---|---|---|
| `0x0` | no | even | **extension** | byte 1 high nibble |
| `0x1` | no | odd | **extension** | **low nibble of byte 0** |
| `0x2` | yes | even | **leaf** | byte 1 high nibble |
| `0x3` | yes | odd | **leaf** | **low nibble of byte 0** |
| `0x4..0xf` | — | — | **invalid** → assert | — |

With `L` = compact length in bytes and `odd = f & 1`:

```
is_leaf      = (f & 2) != 0
skip         = 1 if odd else 2          # compact-nibbles to skip
nibble_count = 2*L - skip               # == 2*(L-1) + odd
```

### 5.2 Signature (`nibbles.py`)

```python
@subroutine
def hp_decode(data: Bytes, off: UInt64, length: UInt64
              ) -> tuple[bool, UInt64, UInt64]:
    """Decode the hex-prefix header of the compact path at data[off:off+length].
    Returns (is_leaf, nibble_count, nib_index) where `nib_index` is the ABSOLUTE
    nibble index into `data` of path nibble 0 (== 2*off + skip).

    assert length >= 1                              -> "H1"
    f = getbyte(data, off) >> 4
    assert f <= 3                                   -> "H2" (bad flag nibble)
    if f & 1 == 0:  assert getbyte(data,off) & 0x0f == 0  -> "H3"
    if f & 2 == 0:  assert nibble_count >= 1        -> "H4" (empty extension)
    """
```

Design notes on the four asserts:

- **H1**: `length >= 1` is guaranteed by the format — even a zero-nibble path
  encodes as the single byte `0x20`. A zero-length path item means the node is
  not a 2-item MPT node; fail closed. (Real example of the 1-byte case:
  `eth_data.json receipt_proof.nodes[2]`, whose item 0 is the lone byte `0x20`.)
- **H3** (even-flag ⇒ low nibble of byte 0 is zero) is the one canonicality
  check M2 keeps despite TP-1, because it is not about encoding economy — a
  non-zero low nibble under an even flag has **no defined meaning**, and
  silently ignoring it would let two distinct byte strings decode to the same
  path. Cost: 3 opcodes, on the 2-item path only (≤ 1 node per proof).
- **H4**: extension nodes must carry ≥ 1 nibble (a zero-nibble extension is not
  emitted by any client and would make M5's descent a no-op / potential loop).
  Leaves may legitimately have 0 nibbles.
- **`nib_index` is returned as an absolute nibble index into `data`** rather
  than a byte offset plus a parity flag. This is the single most useful
  simplification for M5: after `hp_decode`, path nibble *j* is
  `nibble_at(data, nib_index + j)`, with no parity bookkeeping at the call site.

```python
@subroutine
def nibble_at(data: Bytes, k: UInt64) -> UInt64:
    """Nibble k of `data` (k=0 is the HIGH nibble of byte 0)."""
    b = op.getbyte(data, k // 2)
    return b >> 4 if k % 2 == 0 else b & 15
```

### 5.3 Worked vectors from real mainnet bytes

All three from `tests/fixtures/spike-reference/eth_data.json`, block
25,639,768. These become the primary hex-prefix unit tests.

**(1) Account leaf — odd, leaf.** `proof.accountProof[7]` (104 B):
`f8669d38 02a763f7db875346d03fbf86f137de55814b191c069e721f47474733 b846f844…`
Item 0 span = `(3, 29)`, first byte `0x38` → `f = 3` → **leaf, odd**;
`nibble_count = 2*29 − 1 = 57`; `nib_index = 2*3 + 1 = 7`; first path nibble
`= 0x38 & 0x0f = 8`.
Cross-check against the real key: `keccak256(0xdAC17F95…31ec7)` =
`ab14d68802a763f7db875346d03fbf86f137de55814b191c069e721f47474733`. Seven
branch hops consumed nibbles `a,b,1,4,d,6,8`; key nibble 7 is `8` ✓ matches the
odd leading nibble; key bytes from index 4 (`02a763f7…4733`, 28 B) equal
compact bytes 1.. ✓; `7 + 57 = 64` nibbles total ✓.

**(2) Storage leaf — even, leaf.** `proof.storageProof[0].proof[8]` (40 B):
`e79d20 2366783a4fc90e52c8cc595ba9fd2b278bc52248117c14c07e5394d8 8787…`
Item 0 span = `(2, 29)`, first byte `0x20` → `f = 2` → **leaf, even**;
`nibble_count = 2*29 − 2 = 56`; `nib_index = 2*2 + 2 = 6`.
Cross-check: `keccak256(storage_key)` =
`aa2813d62366783a4fc90e52c8cc595ba9fd2b278bc52248117c14c07e5394d8`; 8 branch
hops consumed `a,a,2,8,1,3,d,6`; remaining 28 key bytes equal compact bytes
1.. ✓; `8 + 56 = 64` ✓.

**(3) Receipt leaf — even, leaf, zero-length path, single-byte RLP item.**
`receipt_proof.nodes[2]` (690 B): `f902af 20 b902ab 02f902a7…`
Item 0 is the **single byte `0x20`** (`< 0x80`, so it is its own encoding —
span `(3, 1)`, `KIND_BYTE`). `f = 2` → leaf, even, `nibble_count = 0`,
`nib_index = 8`. Cross-check: receipt key is `rlp(31) = 0x1f` → 2 nibbles
`1,f`; two branch hops consumed both; 0 remaining ✓. This one fixture
simultaneously exercises the single-byte RLP case, the zero-nibble leaf, and
(via its value) the EIP-2718 envelope of §6.

### 5.4 Nibble comparison, with the alignment fast path

M5's security fix ("derive the expected path from the key on-chain, not from a
caller-supplied step list") needs to compare a node's path against a slice of
the key. Doing that nibble-by-nibble is expensive: a 57-nibble leaf at ~6
opcodes/nibble is ~350 budget — worse than everything else in the hop combined.
So M2 provides the comparator, with a byte-aligned fast path:

```python
@subroutine
def nibbles_equal(a: Bytes, a_nib: UInt64,
                  b: Bytes, b_nib: UInt64, count: UInt64) -> bool:
    """Compare `count` nibbles starting at absolute nibble index a_nib in `a`
    against b_nib in `b`."""
```

Algorithm:

1. If `count == 0` → `True`.
2. **Aligned fast path**: if `a_nib % 2 == 0` and `b_nib % 2 == 0` and
   `count % 2 == 0` → return
   `op.extract3(a, a_nib//2, count//2) == op.extract3(b, b_nib//2, count//2)`.
   **~5 opcodes total, independent of length.**
3. Aligned-with-odd-tail: same as (2) for `count-1` nibbles, then one
   `nibble_at` comparison.
4. Otherwise (relative misalignment): the per-nibble loop — 2 × `nibble_at`
   + compare per nibble. This is the second sanctioned `Op`-level loop (§2.4).

**Why the fast path is the one that actually runs, for leaves.** Let `c` be the
key nibbles consumed on arrival at a leaf, and `n` the leaf's path length. Trie
keys are byte strings, so total key nibbles is always even (64 for a
keccak-hashed account/storage key; `2*len(rlp(index))` for a receipt index).
Hence `c + n` is even, so `n mod 2 = c mod 2`, i.e. **`odd ⇔ c is odd`**. The
compact remainder always begins at compact byte 1 (nibble index `2*off+2`,
even), and on the key side it begins at nibble `c + odd`, which is even in both
cases. So for leaves the remainder comparison is **always** byte-aligned and
always hits case (2) — one `extract3`-pair compare instead of ~57 nibble
compares. Vectors (1) and (2) in §5.3 both demonstrate it (both remainders are
exactly the tail of the hashed key).

For **extension** nodes there is no such invariant (`n` is unconstrained
relative to `c`), so cases (3)/(4) are genuinely reachable and must be
implemented and tested — do not "optimise" them away on the strength of the
leaf argument. Branch on the runtime parity; never assume it.

---

## 6. EIP-2718 typed-receipt handling

### 6.1 The ambiguity, and the resolution

A typed transaction's receipt is stored in the receipts trie as
`type_byte ‖ rlp(payload)` (EIP-2718), **not** as pure RLP. `MPT_RESULTS.md`
§5.6 recorded this the hard way: the rebuilt receipts trie only reproduced the
real `receiptsRoot` once the leading type byte was stripped.

The ambiguity to resolve: a lone leading `0x01`/`0x02`/`0x03` is itself a
perfectly valid single-byte RLP string (the `0x00..0x7f` self-encoding range),
so **in the general case RLP's own first byte cannot tell you whether a payload
is typed.** Sniffing is unsound in general.

**Resolution — a layered answer, not a single choice:**

> **The general RLP core never sniffs.** `rlp_list_header` asserts
> `data[start] >= 0xc0` and fails otherwise ("R1"). A caller that forgets to
> strip a type byte gets a deterministic failure, never a misparse — the same
> fail-closed behaviour the spike observed, now with an error code.
>
> **A separate, explicitly named helper in `eip2718.py` does sniff**, and is
> sound *because of a context invariant that only holds for receipts*: a
> receipt payload is always an RLP **list** (`[status, cumGas, bloom, logs]`),
> and it is always > 55 bytes because the bloom filter alone is 256 bytes, so a
> legacy receipt's first byte is always in `0xf8..0xff`. Therefore, **within
> the receipts trie**, `first byte < 0xc0 ⇔ typed envelope` with no ambiguity.

This is the cleaner split than either alternative. Putting the sniff in the
core would make the core unsound for any other RLP. Pushing the whole decision
to the caller would mean M7 re-derives this non-obvious invariant itself — and
the invariant is exactly the kind of thing that gets lost, since the spike
already tripped over it once. So: the sniff is allowed, it lives in a
receipt-specific module, and the invariant that licenses it is asserted in code
rather than assumed.

### 6.2 Signature

```python
# contracts/primitives/rlp/eip2718.py
@subroutine
def receipt_envelope(data: Bytes, off: UInt64, length: UInt64
                     ) -> tuple[UInt64, UInt64, UInt64]:
    """Strip an EIP-2718 type byte from a RECEIPTS-TRIE leaf value.

    Returns (tx_type, payload_off, payload_len):
      tx_type == 0            -> legacy, span returned unchanged
      tx_type in 0x01..0x7f   -> typed, span advanced by one byte

    assert length >= 1                     -> "T1"
    t = getbyte(data, off)
    if t >= 0xc0:  return (0, off, length)                  # legacy RLP list
    assert 0x01 <= t <= 0x7f               -> "T2" (not a valid envelope)
    assert length >= 2                     -> "T3" (type byte with no payload)
    assert getbyte(data, off+1) >= 0xc0    -> "T4" (payload is not a list)
    return (t, off + 1, length - 1)
    """
```

Decisions embedded above:

- **Accepts the whole `0x01..0x7f` type range**, not just the currently defined
  `0x01` (EIP-2930), `0x02` (EIP-1559), `0x03` (EIP-4844), `0x04` (EIP-7702).
  Rationale: EIP-2718 reserves `[0x00, 0x7f]` for transaction types, and the
  *receipt* payload shape has been `[status, cumGas, bloom, logs]` for every
  type defined so far (4844 adds no receipt field). Rejecting unknown types
  would make the verifier break on a future fork for no security benefit — the
  bytes are hash-committed to a trusted receipts root either way. **M7 owns any
  tighter policy** (e.g. an on-chain allow-list of accepted types); M2 returns
  `tx_type` precisely so M7 *can* enforce one.
- **Rejects `0x00`** — EIP-2718 does not permit it as a transaction type, and
  accepting it would make `tx_type == 0` ambiguous between "legacy" and "type
  zero".
- **Rejects `0x80..0xbf`** (`T2`): a string prefix cannot begin a receipt
  envelope, and it cannot be a legacy receipt either.
- **`T4` asserts the post-strip byte is a list prefix**, which is what makes
  the sniff auditable: the invariant the sniff relies on is checked, not
  assumed. Cost: 2 opcodes, once per receipt proof.
- Note for M7 (not M2's problem): `0xc0..0xf7` — a legacy list under 56 bytes —
  is accepted here as legacy, though a *real* receipt can never be that small
  (256-byte bloom). Any tighter minimum-size check belongs with the semantic
  layer that knows it is looking at a receipt.

Real vector: `receipt_proof.nodes[2]` item 1 has span `(7, 683)` with content
beginning `02 f902a7 01 83 6f1cbb b90100…`. `receipt_envelope` returns
`(2, 8, 682)`; `rlp_scan(node, 8)` then yields the four receipt items —
`status = 0x01` (single byte), `cumGas = 0x6f1cbb` (3-byte short string),
`bloom` (256-byte long string, `b90100`), `logs` (a list). `eth_data.json`
independently records `receipt_proof.value_len = 683` and `num_logs = 2`.

---

## 7. Edge cases (each one gets a test in §8)

| # | Case | Encoding | Required behaviour |
|---|---|---|---|
| E1 | Empty string item | `0x80` | span `(pos+1, 0)`, `KIND_STR`. `rlp_bytes` must return empty — **must use `extract3`**, since immediate `extract` with a literal length of 0 means "to the end of the array" and would return the rest of the node. |
| E2 | Branch value slot at end of node | item 16 of every real branch node | Span offset **equals `len(node)`** with length 0 (verified: `accountProof[0]` item 16 = `(532, 0)`). `extract3(node, 532, 0)` is legal (`B+C <= len`); a `getbyte` at that offset is **not**. The scan loop must therefore test `pos < payload_end` *before* reading a prefix byte — never after. |
| E3 | Empty list | `0xc0` | `n_items == 0`, table = 1 entry (`payload_end`). `mpt_node_scan` rejects it ("R6"). |
| E4 | Single-byte value `< 0x80` | the byte itself | span `(pos, 1)`, `KIND_BYTE`. Real: `receipt_proof.nodes[2]` item 0 = `0x20`; account RLP `nonce = 0x01`, `balance = 0x2a` (`eth_data.json proof.nonce/balance`). |
| E5 | Byte `0x00` vs. empty string | `0x00` vs `0x80` | Distinct: `0x00` is a 1-byte string, `0x80` is a 0-byte string. Never conflate; `KIND_BYTE` with length 1 vs `KIND_STR` with length 0. |
| E6 | Long string, 1-byte length | `0xb8 0x46 …` | `ll = 1`; real: `accountProof[7]` item 1 = `b846` → 70 bytes at offset 34. |
| E7 | Long string, 2-byte length | `0xb9 0x02ab …` | `ll = 2`; real: `receipt_proof.nodes[2]` item 1 = `b902ab` → 683 bytes. Also the 256-byte bloom `b90100`. |
| E8 | Long list, 2-byte length | `0xf9 0x0211` | Real: every 532-byte branch node (`f90211`, payload 529, starts at 3... note payload_off = 3, item 0 header at 3, item 0 content at 4). |
| E9 | Long list, 1-byte length | `0xf8 0x66` / `0xf8 0x51` | Real: `accountProof[7]` (`f866`), `storageProof[0].proof[6]` (`f851`). |
| E10 | Length-of-length > 8 | `0xbf` with `ll = 8` is max representable | `ll > 8` → assert "R7" (`btoi` would fail anyway; explicit is better). Unreachable with a ≤4096 B blob but must not be UB. |
| E11 | Zero-length input | `Bytes()` | `rlp_list_header` must fail cleanly. `op.getbyte` on an empty `Bytes` panics; add `assert data.length > start` → "R8" for a diagnosable error. |
| E12 | Truncated node | header claims more than is present | `payload_end > len(data)` → assert "R2". Test by truncating a real 532-byte node to 400 bytes. |
| E13 | Trailing garbage / short last item | last item ends before `payload_end` | The scan's `assert pos == payload_end` ("R4") catches both over- and under-run. |
| E14 | Embedded node child (MPT child whose encoding is < 32 B) | item prefix ≥ `0xc0` | `KIND_LIST`, span = **whole encoding including header**, so `rlp_scan(data, span_off)` parses it. See §8.2 — no fixture in `eth_data.json` exercises this; a fixture must be sourced. |
| E15 | Nested RLP inside a leaf value | storage value `0x87 3f1ca131081cf8` | `storageProof[0].proof[8]` item 1 content (8 B) is *itself* RLP: the trie stores `rlp(value)`. Consumers call `rlp_item_header(node, 32)` to unwrap to the 7-byte `0x3f1ca131081cf8`, matching `eth_data.json proof.storageProof[0].value`. Also: a zero storage value is `0x80` (empty), **not** `0x00`. |
| E16 | Many empty slots in a branch | `f851 8080…a0…` | Real: `storageProof[0].proof[6]` has 15 empty items with non-empty children only at indices 9 and 13; `proof[7]` at 6 and 7. Best available regression for the empty-item stride. |
| E17 | `hp_decode` bad flag nibble | first byte `0x40..0xff` | assert "H2". |
| E18 | `hp_decode` even flag with dirty low nibble | e.g. `0x21 …` | assert "H3" (§5.2). |
| E19 | Zero-nibble extension | `0x00` alone | assert "H4". |
| E20 | `receipt_envelope` type `0x00` | `00 f9…` | assert "T2". |
| E21 | `receipt_envelope` lone type byte | `0x02` with length 1 | assert "T3". |
| E22 | AVM `-` underflow trap | `p - 0x80` when `p < 0x80` | Structural: the subtraction must be unreachable on that arm. Covered by E4 plus a code-review checklist item. |

Error-code discipline: assert messages are the **two/three-character codes**
above (`"R1"`…`"R8"`, `"H1"`…`"H4"`, `"T1"`…`"T4"`), not prose. Program size is
the binding per-call constraint at 8192 B (`MPT_RESULTS.md` §5.5) and assert
strings land in the program bytes. The code → meaning table lives in
`contracts/primitives/rlp/__init__.py`'s docstring and is mirrored in this doc.

---

## 8. Test plan

### 8.1 Principle

**Fixtures are real mainnet bytes, not synthetic RLP.**
`tests/fixtures/spike-reference/eth_data.json` holds block **25,639,768**
(`stateRoot 0xde97a834…3329`, `receiptsRoot 0x6490277f…710b`) with the real USDT
account proof (8 nodes), the real Binance-8 balance storage proof (9 nodes), and
a real receipts-trie proof (3 nodes, tx index 31, 2 logs). Every node in it is
hash-chained to a real root — `keccak256(accountProof[0]) == stateRoot` was
re-verified while writing this doc, as were `accountProof[7]`, `proof[8]` and
`nodes[2]` against their parents' references.

### 8.2 Fixture derivation

- `tests/fixtures/rlp/extract_fixtures.py` reads `eth_data.json` and emits
  `tests/fixtures/rlp/nodes.json`: for each of the **20 real nodes** (8 account
  + 9 storage + 3 receipt), the node hex, its keccak, `n_items`, the full
  expected span/kind table from the oracle, and — for 2-item nodes — the
  expected `(is_leaf, nibble_count, nib_index)`.
- Distribution in the fixture set: **17 branch nodes** (arity 17, sizes
  308–532 B), **3 two-item nodes** (one odd leaf, one even leaf, one
  zero-nibble leaf), header forms `f90211` / `f901b1` / `f901d1` / `f866` /
  `f851` / `f902af` / `e7`, item forms `0x80` / `0xa0` / `0x9d` / `0x20` /
  `0xb846` / `0xb902ab` / `0x87` / `0x01` / `0x2a`.
- **Known gaps, and how they are filled** (be explicit — these are the two
  cases real data does not cover):
  - **No extension node** and **no embedded child (E14)** anywhere in
    `eth_data.json`. Fill both by *deriving* fixtures from real mainnet
    key/value pairs rather than hand-writing RLP: build a small trie with the
    reference MPT builder over real keys/values (a contract with a 2–3 slot
    storage trie forces both an extension node and embedded children), assert
    the computed root, and pin the resulting node bytes. Additionally, add a
    `ci-live.yml` step that `eth_getProof`s a small-storage-trie contract and
    diffs the pinned fixtures, so the derived bytes are continuously
    corroborated against a real node. Label these fixtures `derived-real` in
    `nodes.json` and never label them `mainnet-observed`.
  - No `ll >= 3` long-form length (E10 boundary) — unreachable with a ≤4096 B
    blob; test the assert with a constructed header in the oracle-negative
    suite only.

### 8.3 Test suites

**A. Oracle conformance (offline CI, `algorand-python-testing`).** For all 20
fixture nodes: `mpt_node_scan` → `(table, n_items)` must equal
`rlp_ref.scan(node)`; then for **every** item index, `rlp_table_item` must equal
the oracle's `(content_off, content_len, kind)`. This is the test that directly
supersedes the spike's `rlp_split`.

**B. Hex-prefix.** The three §5.3 vectors, asserting
`(is_leaf, nibble_count, nib_index)` and the first nibble; plus the key
cross-checks (leaf remainder equals the tail of `keccak256(address)` /
`keccak256(storage_key)`, and consumed + path == 64 nibbles), which is what
proves the decode is right against Ethereum and not merely self-consistent.

**C. Nibble comparison.** `nibbles_equal` on the two hashed-key leaves via the
aligned path; forced-misaligned cases (case 3 and case 4) against the derived
extension fixtures and against the oracle over exhaustive small
`(a_nib, b_nib, count)` triples on real key bytes; mismatch-detection at the
first, middle and last nibble of each range.

**D. Differential (mandatory, gates the §2.4 duplication).**
**D1**: for every item of every fixture node, the inlined scan-loop step and the
standalone `rlp_item_header` subroutine must return identical triples. **D2**:
the Puya implementation and `rlp_ref.py` must agree on every fixture, every
nested decode (`rlp_scan(accountProof[7], 34)` → the 4-item account list;
`rlp_item_header(proof[8], 32)` → the unwrapped storage value; the stripped
receipt payload → 4 items), and on a property-based corpus of RLP produced by
the oracle's *strict* encoder (supplementary only — real fixtures remain the
gate).

**E. Negative (each must fail with the documented code).** E10–E13 and
E17–E21 from §7, plus: `rlp_list_header` on a non-list first byte; a 4-item RLP
list through `mpt_node_scan` (must be "R6"); a 532-byte node truncated to 400 B;
`rlp_scan` on the raw typed receipt value without stripping (must be "R1" — this
is the spike's §5.6 failure, now pinned as a regression test).

**F. Composition smoke test (ci-live).** Re-run the spike's account and storage
paths end to end using M2's primitives in place of `RLP_ITEM_SUB` — with
`keccak256` linking supplied by the test, not by M2 — and assert the same real
roots verify. Cost must be **strictly below** the spike's 3,276 (account) and
6,827 (storage). This is the honest apples-to-apples check that M2 is a win in
situ and not just in microbenchmark.

### 8.4 Budget measurement and acceptance gates

`bench/rlp_bench.py` follows `mpt_bench.py` exactly: minimal AVM program per
operation, `/v2/transactions/simulate` with `extra_opcode_budget = 320_000`,
`extra_pages = 3`, read back the real `app-budget-consumed`, subtract a
push-only baseline. Localnet bring-up recipe is unchanged from
`tests/fixtures/spike-reference/README.md`. It emits `bench/rlp_results.json`
plus a markdown table, and it must also record **compiled program size** for
each subroutine set.

Reported for each of the 20 real nodes: scan cost, per-item retrieval cost for
every index, `hp_decode` cost, `nibbles_equal` cost on both the aligned and
misaligned paths, `receipt_envelope` cost — each beside the spike's
corresponding number where one exists (62 / 318 / 542).

Acceptance gates (a failing gate blocks "Implemented" in `ROADMAP.md`):

- **G1** — full scan of a real 532-byte 17-item branch node: **≤ 300** budget.
- **G2 (the headline)** — `cost(read item 15) − cost(read item 0)`, both after
  one scan: **≤ 10** budget. This is the O(child-index) fix, measured. Spike
  baseline: **480**.
- **G3** — 2-item ext/leaf node: scan + both items ≤ **90** budget.
- **G4** — `nibbles_equal` on the 57-nibble aligned account-leaf path:
  **≤ 20** budget, and demonstrably flat as path length grows (compare against
  the 56-nibble storage leaf).
- **G5** — total compiled TEAL for `core.py + nibbles.py + eip2718.py`:
  **≤ 900 bytes**, since program size, not budget, is the binding per-call
  constraint (`MPT_RESULTS.md` §5.5) and M5/M6 must fit a whole proof alongside.
- **G6** — suite F beats the spike's in-situ 3,276 / 6,827 totals.

No number from this document is quotable in the README or in any downstream
design doc until `rlp_results.json` contains it.

---

## 9. ROADMAP open questions resolved

`ROADMAP.md`'s M2 row lists three inherited open questions. All three are
resolved here:

**(1) "Fix O(child-index) re-walk in spike's `RLP_ITEM_SUB`."** — **Resolved,
with a precise restatement.** A single cold lookup of item *i* is irreducibly
Θ(*i*) because RLP carries no index; claiming otherwise would be false (§3.1).
What is fixed: (a) one **single-pass scan** per node builds a 36-byte `uint16`
header-offset table, so *k* accesses cost one walk instead of *k* walks; (b)
post-scan retrieval is **O(1)** (`extract_uint16` + one header decode); (c)
whole-node scan cost is **flat in the child index**, enforced by measured gate
**G2** (`cost(item 15) − cost(item 0) ≤ 10`, against the spike's 480); (d) the
per-item step is cut from ~32 to a target ≤ 12 budget by a frequency-ordered,
branchless-in-the-common-case stride rule (`pos += 1 + p − 0x80` covers both
`0x80` empty slots and `0xa0` hash children, which is 100 % of the items in all
17 real branch nodes) and by eliminating the spike's scratch-slot traffic. The
`Op`-level exception is scoped to exactly two loop bodies with a mandatory
differential test (§2.4).

**(2) "Add hex-prefix nibble decode + EIP-2718 type-byte stripping (neither
existed)."** — **Resolved.** Hex-prefix is specified against the real
compact-encoding rules with the full flag-nibble table, the
`nibble_count = 2L − skip` formula, four named asserts including the
canonicality check H3 that prevents two byte strings decoding to one path, and
an absolute-nibble-index return that keeps parity bookkeeping out of M5 (§5.1–
5.2). It is validated against three real leaves cross-checked to
`keccak256(address)` and `keccak256(storage_key)` (§5.3). A derived invariant —
for any trie leaf, byte-string keys force `odd ⇔ consumed-nibbles odd`, so the
path remainder is always byte-aligned — turns the dominant path comparison into
a single `extract3` pair (gate G4), while extension nodes retain the tested
misaligned fallback (§5.4). EIP-2718 gets `receipt_envelope` accepting types
`0x01..0x7f` plus legacy, rejecting `0x00` and string prefixes, and asserting
the post-strip list prefix (§6.2).

**(3) "Single-blob vs. data-source interface (gates M7)."** — **Resolved:
single in-stack `Bytes` blob, with a copy-free offset-addressable span
discipline.** No reader abstraction. Justification (§4.2): an abstraction would
not unblock M7, whose actual blocker is the absence of a streaming keccak (a
157,274-byte leaf cannot be hashed at all, chunked reads or not); the unbounded
object is a leaf *value* in one trie, never a node *structure* (all 20 real
nodes are ≤ 690 B and branch nodes are structurally ≤ ~566 B); the abstraction
costs **+20 % to +50 % on the scan loop** for the bounded 100 % case; and the
≤4096 B guarantee is what makes the `uint16` table and its single-opcode reads
possible. The concession that keeps the decision cheap to reverse: every
primitive is `(data, start) → (offset, length)` with no slicing, so if M7 needs
range reads it re-implements only the ~3-site byte-fetch layer and reuses all
format logic plus the Python oracle — no parallel decoder. Nested decode already
works this way today (`rlp_scan(accountProof[7], 34)`).

### 9.1 Additionally resolved for downstream modules

- **M5's security fix is unblocked**: `hp_decode` + `nibble_at` +
  `nibbles_equal` give M5 everything it needs to derive the expected path from
  the key on-chain instead of trusting a caller-supplied step list. M2 supplies
  the primitives; M5 owns the check.
- **The embedded-node correctness bug in the spike's `rlp_item` is fixed**:
  `KIND_LIST` spans include the list header, so a recursive scan of an inlined
  child is correct (§2.2, E14). The spike's payload-only return would have
  mis-parsed it.

### 9.2 Deferred, with named owners

- **O-1 (M11)** — early-exit `rlp_scan_upto(data, start, want)`. Cheaper on
  average (~145 vs ~250 for uniform *i*) but reintroduces ~6× index-dependence
  and a second code path against a tight program-size budget. Revisit only if
  G1 fails or if profiling of a full M6 composition says so.
- **O-2 (M11)** — table-free "capture the two spans the caller asked for"
  fusion, saving the ~51 budget of table writes on branch nodes at the cost of
  generality. First thing to try if G1 fails.
- **O-3 (M7)** — the >4096 B receipt leaf. Out of scope here; per `ROADMAP.md`
  it may force a revision of M2, and §4.3 defines exactly which layer that
  revision touches (byte-fetch only).
- **O-4 (M7)** — any allow-list policy on EIP-2718 transaction types. M2
  returns `tx_type` so the policy has somewhere to live.
- **O-5 (M2 implementation)** — whether the plain-Puya scan loop already meets
  G1/G2. If it does, ship it and record the measured comparison; the `Op`
  exception is permission, not obligation (§2.4).
