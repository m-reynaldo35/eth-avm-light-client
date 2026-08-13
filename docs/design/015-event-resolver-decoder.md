# 015 — Well-known event resolver & decoded verification output

**Status**: Design drafted, awaiting human review.
**Type**: **A pre-step and a post-step around the already-live T1/T2 verify
path.** No contract code. No change to any proof, hash chain, or trust
boundary. M1–M13 are untouched, in the literal sense that this design does not
edit a single file under `contracts/`.
**Closes**: `ROADMAP.md`'s M14 row and its four named open questions (§5).
**Extends**: [007](007-receipt-log-proof.md) (the `R` envelope this decoder
reads), [009](009-relayer-client.md) (`ReceiptResult`, the RPC source layer),
[014](014-t2-against-anchor.md) (the anchored payload, `decode_against_anchor`),
and the live service `service/x402_endpoint/main.py`.
**Depends on**: nothing new on-chain.

**Design-time convention, inherited from 013 and 014**: every number below is
labelled **measured** (a real command run during this design pass against real
Ethereum mainnet, cited to its real output — see §15) or **projected** (an
estimate this document owns, which the implementation pass must replace with a
real result). No number is copied from another document without being
re-derived here.

**On `CONTRIBUTING.md`'s "no cost claim without evidence" rule**: that rule is
scoped to opcode-budget behavior and demands a real
`/v2/transactions/simulate` response. **This module changes no opcode-budget
behavior at all** — it adds no contract, no mode, no transaction to any group —
so no `simulate` evidence is offered, because none would be meaningful. The
rule's *spirit* is honored instead where this module does incur real cost: the
RPC cost claims in §3.2 and §6 are backed by real, cited RPC responses, and the
one number this pass could not obtain honestly (a paid RPC provider's real
price) is left explicitly unset in §6.2 rather than invented.

---

## 0. The answer, stated first

**What was asked**: design a resolver (find `(block, tx_index, log_index)` from
a contract + event + filter, so callers don't need Etherscan first) and a
decoder (turn verified raw log bytes into named ABI fields).

Both are buildable, neither is hard, and the honest headline is that **the
design pass found three real problems that matter more than the feature
itself**. All three are measured, none was in the ROADMAP brief, and two of
them would have shipped as live bugs if this module had been implemented
straight from that brief.

**Finding 1 — the index the resolver naturally produces is the wrong index,
and feeding it in fails *quietly*.** Ethereum's `eth_getLogs` returns a
**block-scoped** `logIndex`. This project's `/verify-receipt/{block}/{tx}/{log}`
takes a **receipt-scoped** log index. They are almost never equal. Measured on
real mainnet block 25745000 (264 receipts, 790 logs): **789 of 790 logs have
`logIndex != receipt-local index`**. Piping one into the other yields, measured
on that same block:

| naive resolver result | count |
|---|---:|
| correct by luck | **1** |
| **a verified proof of the *wrong log*** | **29** |
| `R_NO_SUCH_LOG` (loud, harmless, but a wasted paid call) | 760 |

The 29 are the problem. They are not errors. They are successful, genuine,
cryptographically valid proofs — **of a log the caller did not ask about**.
Every guarantee in M1–M13 holds perfectly while the answer is wrong, because
the wrongness is in the *question*. §4.2 makes the index conversion mandatory
and §10 pins it with an offline fixture.

**Finding 2 — the events people actually want to verify are the ones this
verifier most often cannot prove.** The project's published coverage figure is
**97.5 % of receipts are T1+T2** (012 §N-4, measured over 94,667 receipts).
That figure is over *unselected* receipts, which are dominated by small simple
transfers. Selecting a log *because it is an interesting DeFi event* selects,
with it, the fat multi-log transaction it was emitted from. Measured this pass
on real Morpho Blue events, deduplicated to distinct transactions:

| event | distinct txs sampled | T1 | T2 | **T3 — unprovable** |
|---|---:|---:|---:|---:|
| Morpho Blue `Supply` | 10 | 1 | 5 | **4** |
| Morpho Blue `Borrow` | 10 | 1 | 1 | **8** |

At the log level across four event types (47 logs), **27 were T3_UNSUPPORTED —
57 %**, against the 2.5 % unprovable rate of the unselected corpus. The very
first real `Borrow` event this pass sampled sat in a **5,017-byte leaf** and is
unprovable by this light client (§15, M-7).

This inverts the module's value proposition, in a good way: **the resolver's
most valuable output is not the index — it is telling the caller, before they
pay to verify, that the thing they want cannot be verified at all.** §4.2 makes
tier classification part of resolution, not a surprise 501 afterwards.

**Finding 3 — the resolver is a sound-but-not-complete step, and it puts an
RPC-trusted input in front of a route whose entire selling point is zero RPC
trust.** A malicious or merely stale RPC cannot make the resolver point at a
fabricated event (verification would fail), but it *can silently omit* a real
matching one. Verification proves what you point at; it cannot prove you were
pointed at everything. This is the mechanical reason — not merely a scoping
preference — behind the boundary this project has already drawn publicly: **a
single verified fact, never "all matching events happened."** §7.1 states it in
full, and §1.2 makes completeness an explicit non-goal.

**The two design questions with clean, evidence-backed answers:**

* **Decoding is free and should be bundled into the existing routes at no extra
  charge.** `prove_receipt` already calls `get_block_receipts(block)`
  (`relayer/client.py:376`) and therefore *already holds the full log — topics
  and data — in memory* before it proves anything. Decoding costs one keccak
  and a dictionary lookup. **Marginal RPC cost: zero.** Charging for it would
  be charging for arithmetic this service already performs.
* **Resolution is not free and cannot be, because the RPC capability it needs
  does not exist in this project's current infrastructure.** Measured: of the
  five public endpoints in `relayer/sources/eth_rpc.py:17`'s `DEFAULT_RPCS`,
  **three refuse `eth_getLogs` outright** and the two that serve it cap the
  block range **between 100 and 200 blocks** — a *range* cap, not a result cap
  (a quiet address returning ~100 results over 1,000 blocks fails too).
  100 blocks is ~20 minutes of Ethereum history. Any useful resolver needs a
  keyed/paid RPC provider, which is a real new recurring cost. §5.3 prices it
  as its own route.

**Implementation size**: small, and almost entirely in `relayer/` and
`service/`. One new RPC method, one registry JSON file with its fixtures, one
resolver module, one decoder module, two new routes, and a `decoded` block
added to two existing responses. No contract work. The real work is the fixture
corpus (§10) and the registry admission rule (§5.1), not the code.

---

## 1. Scope, non-goals, trust preconditions

### 1.1 In scope

1. A **static, checked-in event registry** keyed by
   `(chain_id, emitting_address, topic0)`, with an admission rule that bounds
   its maintenance cost (§4.1, §5.1).
2. A **resolver** that turns `(registry entry, filter)` into a concrete,
   tier-classified `(block_number, tx_index, log_index)` — with `log_index`
   **receipt-scoped**, converted from RPC's block-scoped value (§4.2).
3. An **ABI decoder** that turns a verified log's bytes into named fields,
   with **per-field provenance** distinguishing cryptographically verified
   bytes from hash-bound RPC bytes (§4.3).
4. A **response shape** in which decoded output is strictly additive and never
   replaces or reformats the raw verified result (§4.4).
5. Two new service routes and their pricing rationale (§4.5, §5.3).
6. A **fixture discipline** for decoded correctness, in three distinct classes,
   because they test three different things (§10).

### 1.2 Non-goals (explicit)

* **No change to verification or cryptography.** M1–M13 are untouched. This
  design edits nothing under `contracts/`, changes no group layout, no opcode
  budget, no trust precondition of M7 or M8. If a reviewer finds a line of this
  document that implies otherwise, that line is wrong and this bullet wins.
* **No completeness or semantic claim.** This module never asserts "these are
  all the matching events," "no other event occurred," or "this event means X
  happened economically." It resolves *one* pointer and decodes *one* verified
  log. §7.1 explains why this is a mechanical limit, not a scoping preference.
* **The resolution step is not itself verified.** It is an RPC lookup. It is
  not a proof, it is not anchored, and it must never be presented as either.
  §4.4's response shape enforces that typographically as well as structurally.
* **No T3.** Unchanged from 007 §2.2 / 009 §1.2. What is *new* here is that
  §0's Finding 2 makes T3 far more visible on this path, so the resolver
  reports it as a first-class verdict rather than letting the caller discover
  it as a 501 after payment.
* **No runtime ABI fetching.** No Etherscan call, no 4byte lookup, no
  on-the-fly ABI download. The registry is a checked-in file. §5.1 argues this
  is what bounds the maintenance burden rather than causing it.
* **No indexer, no history service, no backfill.** The resolver answers over a
  bounded recent window (§4.2's `max_span`), because §3.2 measured that a wider
  window is not available. Building an index is a different module.
* **No new event *watching*.** Polling, subscriptions, and policy evaluation
  are M15. This module is strictly request/response.
* **No writes, no state.** The registry is read-only at runtime; the resolver
  caches nothing that affects correctness.

### 1.3 Trust preconditions

Inherited whole from 007 §5.4, 008 §1.3, 009 §11 and 014 §1.3. Two additions,
both specific to this module and both load-bearing:

> **TP-M14-1 — resolution is RPC-trusted, verification is not.** A caller who
> uses `/resolve-event` or the resolve half of `/verify-event` has accepted an
> RPC-trusted *selection* step, even when the subsequent verification runs on
> the zero-RPC-trust anchored route. The verified fact remains exactly as
> trustworthy as before; the *choice of which fact to verify* does not. A
> caller who cannot accept this must keep using
> `/verify-receipt-trustless/{block}/{tx}/{log}` with an index obtained by
> their own means.

> **TP-M14-2 — the registry is a label, never a trust input.** A registry entry
> supplies a human name and an ABI shape. It cannot make a false proof true.
> The emitting `address`, all four `topics` (and therefore `topic0`, the event
> signature hash itself), `data_len` and `keccak256(data)` are **all
> cryptographically verified on-chain** by the existing M7 path
> (`contracts/receipt/decode.py:118-135`). A wrong registry entry produces a
> wrong *label* or a *failed decode* — never a wrong verified fact. §5.1 turns
> this property directly into the bound on registry maintenance cost.

---

## 2. What exists today — measured or read this pass

| Component | File | State today |
|---|---|---|
| Receipt verify route (RPC-rooted) | `service/x402_endpoint/main.py:225` | live, `$0.01` (`PRICE_MICRO_USDC`, `main.py:91`) |
| Receipt verify route (anchored) | `service/x402_endpoint/main.py:246` | live, `$0.01` |
| `prove_receipt` | `relayer/client.py:345` | live; fetches `get_block_receipts(block)` at `:378` |
| Result type | `relayer/client.py:68` `ReceiptResult(rstatus_name, fields, confirmed_round, tx_ids)` | live; `fields` is passed to the caller verbatim by both routes |
| T1/T2 payload decode | `relayer/drivers/m7_receipt.py:189` `decode_r` | live; returns full `topics` list, `data_hash`, `data_len`, `n_logs`, `tx_index`, `log_index` |
| Anchored payload decode | `relayer/drivers/m7_receipt.py:285` `decode_against_anchor` | live; returns `topics128`, `data_hash`, `data_len` — **no** `tx_index`/`n_logs` |
| Tier classifier | `relayer/proofs/classify.py:34` | live; `T1 ≤ 1942 B`, `T2 ≤ 4096 B`, else `T3_UNSUPPORTED` (`:21`, `:24`) |
| RPC source layer | `relayer/sources/eth_rpc.py` | live; `eth_getBlockReceipts`, `eth_getBlockByNumber`, `eth_getTransactionReceipt`, `eth_getProof` |
| **`eth_getLogs`** | — | **does not exist anywhere in this repo** |
| Log-data commitment | `contracts/receipt/decode.py:133` | `data_hash = op.keccak256(...)` — the data itself is **never** returned |

Three facts from this table do most of the work below.

**(a) The raw log is already in memory before any proof runs.** `prove_receipt`
fetches the whole block's receipts to build the trie. Topics and data for the
target log are therefore already available, at zero marginal cost, at the exact
moment the verified result comes back. This is what makes decoding free (§5.3).

**(b) Topics are verified; data is only *committed to*.** The on-chain payload
carries all four 32-byte topic slots verbatim, but for `data` it carries only
`keccak256(data)` and `data_len`. So **indexed** ABI parameters decode from
bytes the AVM itself verified, while **non-indexed** parameters must come from
the RPC's copy of the data and be bound to the verified commitment by
re-hashing. That asymmetry is real, is not a defect, and §4.3 makes it visible
in the output rather than papering over it.

**(c) `eth_getLogs` is genuinely new here.** It is not a small addition in
practice — §3.2 measures that this project's existing free RPC pool largely
cannot serve it.

---

## 3. The findings that reshape this module

### 3.1 Finding 1 — block-scoped vs receipt-scoped `log_index` (measured)

`eth_getLogs` / `eth_getBlockReceipts` return a `logIndex` field that counts
logs **from the start of the block**. The M7 walk decodes the log at position
`log_index` **within one receipt's own log list**
(`contracts/receipt/decode.py:86`, `rlp_scan_n(node, o3, MAX_LOGS_T1T2)`), and
`prove_receipt(block, tx_index, log_index)` passes the caller's value straight
into it.

**Measured**, real mainnet block 25745000 (264 receipts, 790 logs):

```
total logs 790  where receipt-local index != rpc logIndex: 789
examples (tx_index, receipt_local_i, rpc_logIndex, addr):
  (3, 0, 1, '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48')
  (3, 1, 2, '0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb')
  (3, 2, 3, '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48')
```

**Measured**, same block, classifying what a naive resolver would produce:

```
naive block-logIndex fed to /verify-receipt:
  correct by luck      : 1
  SILENTLY WRONG log   : 29
  R_NO_SUCH_LOG (loud) : 760
```

**Why the 29 matter far more than the 760.** `R_NO_SUCH_LOG` is a *verdict
delivered by a successful transaction* (007 §5.4/§6.3) — the caller paid, got a
useless but honest answer, and knows it. The 29 are different: the block-scoped
index landed inside the receipt's real log range, so the group verifies
perfectly and returns a genuine `R_INCLUDED` for a **different log** — a
different address, different topics, different meaning. Nothing in M1–M13
detects this, correctly, because nothing is wrong with the proof.

**Normative consequence (§4.2, R-3)**: the resolver MUST convert to a
receipt-scoped index by locating the log within its own receipt, and MUST
carry the block-scoped value in the response under a *differently named* field
so the two can never be confused by a downstream caller (or by M15).

### 3.2 Finding 3 — the existing RPC pool cannot serve range queries (measured)

**Method**: each of the five URLs in `relayer/sources/eth_rpc.py:17`
`DEFAULT_RPCS`, driven individually through this repo's own
`relayer.sources.pool.EndpointPool`, `eth_getLogs` for one address across four
spans, at head ≈ 25745143.

| endpoint | span 10 | span 100 | span 1000 | span 10000 |
|---|---|---|---|---|
| `ethereum-rpc.publicnode.com` | OK (43) | OK (421) | **403** | **403** |
| `eth.drpc.org` | OK (43) | OK (421) | **400** | **400** |
| `eth.merkle.io` | **429** | **429** | **429** | **429** |
| `1rpc.io/eth` | **conn reset** | **conn reset** | **conn reset** | **conn reset** |
| `eth-mainnet.public.blastapi.io` | **400** | **400** | **400** | **400** |

**Narrowing the cap** on the two endpoints that work at all — measured:

```
publicnode  100:OK(394)  200:FAIL  500:FAIL  700:FAIL  999:FAIL
drpc        100:OK(394)  200:FAIL  500:FAIL  700:FAIL  999:FAIL
```

**Is it a range cap or a result-count cap?** Decisive, and it is a *range* cap
— measured against a deliberately quiet address (a MetaMorpho vault, ~10 logs
per 100 blocks, so ~100 results over 1,000 blocks):

```
quiet-vault  publicnode  1000:FAIL  10000:FAIL  50000:FAIL
quiet-vault  drpc        1000:FAIL  10000:FAIL  50000:FAIL
```

**Conclusions, all load-bearing:**

1. **Three of the five endpoints this project ships cannot serve `eth_getLogs`
   at all.** The pool's failover therefore does not help: it degrades from two
   usable endpoints to zero, not from five to four.
2. **The usable window is ~100 blocks — about 20 minutes of chain history.**
   A "find me the latest `Reallocate`" filter over anything longer than that
   cannot be served by the current infrastructure.
3. **This, not abstract "RPC costs money," is the real reason resolution must
   be its own paid call** (§5.3). The service needs an RPC tier it does not
   currently have.
4. `default_pool()` must **not** be reused for resolution. §4.2 gives the
   resolver its own configured pool so that a resolver misconfiguration cannot
   degrade the proof path's RPC availability.

### 3.3 Finding 2 — event-selected logs are disproportionately T3 (measured)

**Method**: `eth_getLogs` for one `(address, topic0)` over a 100-block window
at head ≈ 25745143; for each match, fetch the block's receipts, rebuild the
receipts trie with this repo's own
`relayer.proofs.receipts_trie.build_receipts_trie_and_path`, verify the
reconstructed root against the real block header, and classify the leaf with
`relayer.proofs.classify.classify`.

**Log-level sample** (first 12 matches per event, not deduplicated):

| event | sampled | T1 | T2 | **T3** | leaf min–max (B) |
|---|---:|---:|---:|---:|---|
| Morpho Blue `Supply` | 12 | 0 | 7 | **5** | 2,672 – 10,703 |
| Morpho Blue `Borrow` | 11 | 1 | 1 | **9** | 1,037 – 11,120 |
| Morpho Blue `AccrueInterest` | 12 | 0 | 3 | **9** | 3,201 – 12,331 |
| USDC `Transfer` | 12 | 8 | 0 | **4** | 433 – 7,537 |
| **total** | **47** | **9** | **11** | **27 (57 %)** | |

**Deduplicated to distinct transactions** (guarding against one fat transaction
emitting many matches and skewing the count) — the finding survives:

| event | matches / 100 blk | distinct txs | T1 | T2 | **T3** |
|---|---:|---:|---:|---:|---:|
| Morpho Blue `Supply` | 64 | 10 | 1 | 5 | **4** |
| Morpho Blue `Borrow` | 13 | 10 | 1 | 1 | **8** |

**Against this project's own published baseline**: 012 §N-4, measured over
94,667 real receipts, T1 93.729 % + T2 3.775 % = **97.5 %**, unprovable ~2.5 %.

**The two numbers are both correct and are not in conflict.** 97.5 % is a
*per-receipt* figure over an unselected corpus dominated by small, simple
transactions. Selecting a log because its event is interesting co-selects the
large aggregator/router/solver transaction that emitted it, and those are
exactly the receipts whose RLP leaf exceeds the 4,096-byte AVM ceiling.

**Normative consequences:**

1. **Resolution MUST classify tier** and return it (§4.2, R-4). A caller must
   learn "unprovable" *before* paying for verification, not as a 501 after.
2. **Registry admission MUST be gated on a measured provable rate** (§5.1),
   not on how well-known the protocol is. This is what actually decides §5.1's
   v1 registry contents, and it disqualifies two of the three candidates named
   in the ROADMAP brief.
3. The published coverage figure **must not be reused** in any M14 user-facing
   copy. 97.5 % is true of receipts; it is measured false of event-selected
   logs. Reusing it here would be exactly the kind of unbacked claim
   `CONTRIBUTING.md` exists to prevent.

**Honest limits of this sample** (handed to the implementation pass, §13): one
100-block window, one day, one protocol plus one token, 10 distinct
transactions per deduplicated row. Directionally decisive; not a corpus. §5.1's
admission rule therefore requires ≥ 30 distinct transactions, which is more
than this pass itself gathered.

### 3.4 The v1 candidates in the ROADMAP brief, checked against real chain data

The brief named EigenLayer's `AllocationManager` and Morpho Blue MetaMorpho
vault `Reallocate`-style events as starting candidates, and explicitly left the
final choice to this pass. Checked:

| candidate | measured | verdict |
|---|---|---|
| **EigenLayer `AllocationManager`** `0x948a…bc39` | code present (2,115 B, proxy-shaped); **0 logs across six consecutive 100-block windows (~600 blocks)** | **rejected for v1** — §3.5 |
| **MetaMorpho vault** `0xBEEF…64CB` | code present; 10 logs / 100 blk in one window, **0 in another** | **rejected for v1** — §3.5 |
| **Morpho Blue** `0xBBBB…FFCb` | 329–404 logs / 100 blk, 8–10 distinct `topic0` | **admitted, selectively** — §5.1 |
| **Chainlink ETH/USD** `0x5f4e…8419` | `aggregator()` returns **`0x7d4e742018fb52e48b08be73d041c18b21de6fb5` — a different address**; the proxy emitted 0 logs in the sampled window | **rejected for v1** — §3.5 |
| **USDC** `0xA0b8…eB48` | `Transfer` measured 8/12 T1 | **admitted** — §5.1 |

**ABI-derived `topic0` matched real chain data 8 out of 8** for Morpho Blue —
every distinct `topic0` observed in a 100-block window was reproduced exactly by
hashing the event signature this pass derived from the ABI:

```
 136  0x9d9bd501d0..  AccrueInterest(bytes32,uint256,uint256,uint256)
  73  0xedf8870433..  Supply(bytes32,address,address,uint256,uint256)
  50  0xa56fc0ad57..  Withdraw(bytes32,address,address,address,uint256,uint256)
  29  0xc76f1b4fe4..  FlashLoan(address,address,uint256)
  13  0xa3b9472a13..  SupplyCollateral(bytes32,address,address,uint256)
  10  0x570954540b..  Borrow(bytes32,address,address,address,uint256,uint256)
   9  0x52acb05ceb..  Repay(bytes32,address,address,uint256,uint256)
   9  0xe80ebd7cc9..  WithdrawCollateral(bytes32,address,address,address,uint256)
```

This is the positive control for §4.1's registry format: `topic0` is derivable
offline from a signature string and is confirmed correct against real chain
data, so the registry can store the signature and derive the hash, rather than
storing a hash nobody can audit by eye.

### 3.5 Why three named candidates are rejected, specifically

* **EigenLayer `AllocationManager` — untestable, therefore unshippable.** This
  project's standing discipline is that a claim ships only with a real fixture
  behind it. Measured: **zero events in ~600 recent blocks**. There is no real
  captured event to check in, and the resolver's usable window is ~100 blocks
  (§3.2), so the resolver could essentially never find one live either. The
  blocker is not that the contract is uninteresting; it is that neither the
  fixture discipline nor the resolver's own range can be satisfied. Revisit
  when §13's wider-window RPC exists.
* **MetaMorpho `Reallocate` — the unbounded-registry failure mode, exactly.**
  MetaMorpho is a *vault factory*: each vault is its own address, and there are
  hundreds. Since the registry is keyed on the emitting address (§4.1), "support
  MetaMorpho reallocations" means enrolling every vault, forever, as new ones
  deploy — the precise unbounded maintenance burden the ROADMAP row worried
  about. §5.1's admission rule bans this shape structurally: an entry must name
  a **fixed** address, so a family of addresses cannot be admitted as one entry.
  A future factory-aware registry is a real design, but it is not v1 and it is
  not free — it needs a verified way to know an address is a genuine vault of
  that factory, which is itself a proof problem.
* **Chainlink price feeds — a real proxy trap, measured.** The address every
  consumer knows (`0x5f4e…8419`) is a proxy; `aggregator()` resolves to a
  *different* address, and the proxy emitted no logs in the sampled window. A
  registry keyed on the address users recognize would therefore match nothing.
  Worse, Chainlink rotates the underlying aggregator on feed upgrades, so the
  correct entry has a shelf life. **Generalized rule for §4.1: the registry
  keys the *emitting* address, which for proxy architectures is not necessarily
  the address the protocol's users would name.** The implementation pass MUST
  confirm emission empirically for every entry rather than trusting
  documentation — the measured 0-log result on a "known" feed address is the
  cautionary case.

---

## 4. The proposed mechanism

### 4.1 The registry

A single checked-in file, `relayer/events/registry.json`, loaded once at
import. **No network access, no ABI download, ever.**

```json
{
  "version": 1,
  "entries": [
    {
      "key": "morpho-blue/supply",
      "chain_id": 1,
      "address": "0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb",
      "protocol": "Morpho Blue",
      "contract_note": "immutable, non-upgradeable singleton",
      "signature": "Supply(bytes32,address,address,uint256,uint256)",
      "topic0": "0xedf8870433c83823eb071d3df1caa8d008f12f6440918c20d75a3602cda30fe0",
      "inputs": [
        {"name": "id",       "type": "bytes32", "indexed": true},
        {"name": "caller",   "type": "address", "indexed": true},
        {"name": "onBehalf", "type": "address", "indexed": true},
        {"name": "assets",   "type": "uint256", "indexed": false},
        {"name": "shares",   "type": "uint256", "indexed": false}
      ],
      "provable_rate": {
        "measured_at_block": 25745143,
        "distinct_txs": 10,
        "t1": 1, "t2": 5, "t3": 4,
        "sample_status": "PRELIMINARY — below the 30-tx admission minimum"
      },
      "fixtures": ["tests/fixtures/events/decode/morpho-blue-supply-25745120.json"]
    }
  ]
}
```

**Normative rules on the registry:**

* **N-1.** `topic0` is stored **and** independently derived from `signature` at
  load time; a mismatch is a hard startup failure, not a warning. §3.4 measured
  this derivation correct 8/8 against real chain data, so a mismatch means the
  file is wrong.
* **N-2.** `address` is a **single fixed address**. A registry entry may not
  name a family, a factory, or a wildcard. This is what structurally forbids
  the MetaMorpho shape (§3.5).
* **N-3.** `address` is the **emitting** address, confirmed empirically
  (§3.5's Chainlink case), not the address a protocol's docs advertise.
* **N-4.** Every entry carries at least one **decoder fixture** (§10). An entry
  with no fixture does not load. This is the mechanism that makes the marginal
  cost of an entry payable by whoever adds it, rather than by the maintainer.
* **N-5.** Every entry carries a **measured** `provable_rate` (§5.1's admission
  rule). The service surfaces it so callers see the real odds before paying.
* **N-6.** For a contract behind a proxy, the entry records the implementation
  address it was validated against and the block, so ABI drift is detectable.
  Morpho Blue is preferred for v1 precisely because it is a non-upgradeable
  singleton and has no such drift.

### 4.2 The resolver

New module `relayer/events/resolve.py`, plus one new RPC method
`get_logs(...)` in `relayer/sources/eth_rpc.py`.

```
resolve(entry, *, from_block, to_block, topics_filter=None, select="reject")
    -> ResolveResult(matches=[Match, ...], n_matches, truncated, ...)

Match(block_number, tx_index, log_index,          # receipt-scoped — R-3
      rpc_log_index,                              # block-scoped, DIFFERENT NAME
      tx_hash, tier, leaf_len, provable,          # R-4
      topics, data)
```

**Normative rules on the resolver:**

* **R-1 — its own pool.** The resolver takes a dedicated `EndpointPool`
  (configured via a new `RESOLVER_RPC_URLS`), never `default_pool()`. §3.2
  measured that only two of the five default endpoints serve `eth_getLogs` at
  all; the proof path's RPC availability must not be entangled with the
  resolver's.
* **R-2 — bounded window, enforced client-side.** `to_block - from_block` is
  capped by a configured `max_span`, defaulting to the **measured-safe 100**
  (§3.2). Exceeding it is a 400 with the real reason, never a silent truncation
  and never a retry storm against endpoints that will 403.
* **R-3 — index conversion is mandatory.** For each candidate log, fetch the
  block's receipts (`get_block_receipts`, already in the source layer), locate
  the receipt with the matching `transactionIndex`, and find the log's position
  **within that receipt's own `logs` list**. That position is `log_index`. The
  RPC's block-scoped value is carried as `rpc_log_index` and is never passed to
  `prove_receipt`. §3.1 is why; §10's `RF-1` pins it offline forever.
* **R-4 — tier classification is part of resolution.** Because R-3 already
  fetched the block's receipts, the trie and leaf are available at zero
  additional RPC cost: build the path, classify, and return
  `tier`/`leaf_len`/`provable`. §3.3 measured that this is the single most
  useful thing resolution can tell a caller.
* **R-5 — no verification.** The resolver submits no Algorand transaction and
  makes no claim of truth. It returns pointers.
* **R-6 — reorg honesty.** Every result carries the `block_number` it resolved
  at and how many blocks behind head that was. A resolution against an
  unfinalized block may not survive a reorg; the response says so. The anchored
  route is unaffected in *soundness* (M8 only anchors what the sync committee
  signed) but a caller resolving at head and verifying later may find the block
  no longer canonical.

### 4.3 The decoder

New module `relayer/events/decode.py`. Pure function, no I/O.

```
decode_log(entry, *, verified: dict, raw_topics: list[str], raw_data: str)
    -> DecodedResult(fields=[DecodedField(name, type, value, provenance), ...],
                     binding="verified-hash-match" | "topics-only" | "refused")
```

**The provenance split is the whole point.** From §2(b):

| ABI parameter | source bytes | provenance label |
|---|---|---|
| `indexed` (in `topics[1..3]`) | the on-chain verified payload | **`verified`** |
| non-`indexed` (in `data`) | the RPC's copy of `data`, re-hashed | **`hash-bound`** |

**Normative rules on the decoder:**

* **D-1 — the hash binding is mandatory and fail-closed.** Before decoding any
  non-indexed field, assert
  `keccak256(raw_data) == verified["data_hash"]` **and**
  `len(raw_data) == verified["data_len"]`. On mismatch the decoder MUST refuse
  (`binding="refused"`) and return **no** non-indexed fields. It must never
  fall back to decoding unbound bytes. Indexed fields may still be returned,
  since they came from verified bytes.
* **D-2 — `topic0` must match the entry.** The verified `topics[0]` is compared
  to the entry's derived `topic0`. A mismatch means the caller resolved or
  addressed the wrong log; refuse rather than mislabel. Note this check is
  *verified-side*, per TP-M14-2 — the event's identity is a cryptographic fact,
  not a registry assertion.
* **D-3 — `address` must match the entry.** Same argument; also verified.
* **D-4 — dynamic types are v1-refused, not guessed.** `string`, `bytes`, and
  dynamic arrays in the non-indexed section require full ABI head/tail
  decoding, and an `indexed` dynamic parameter is only ever a *hash* of its
  value on-chain (a real Solidity rule with a real trap: an indexed `string`
  topic cannot be decoded back to the string at all). v1 supports the static
  word types (`uintN`, `intN`, `address`, `bool`, `bytesN`) and refuses the
  rest with a named error. Every event in §5.1's v1 registry is fully static —
  measured: `Supply` has `data_len` 64 for two `uint256`, exactly two words.
* **D-5 — decoding never gates the verified result.** If decoding refuses for
  any reason, the response still carries the complete raw verified result. A
  decoder bug must never be able to withhold a proof the caller paid for.

### 4.4 The response shape

Strictly additive. `result` is byte-for-byte what the routes return today —
`ReceiptResult.fields`, unmodified, unreordered, unrenamed.

```json
{
  "block_number": 25745120,
  "trust_model": "sync-committee-anchored",
  "verified_by": "Algorand apps m7=…, m8=…, round …",
  "result": { "...": "UNCHANGED — the raw verified payload" },

  "decoded": {
    "event": "Supply",
    "protocol": "Morpho Blue",
    "signature": "Supply(bytes32,address,address,uint256,uint256)",
    "binding": "verified-hash-match",
    "fields": [
      {"name": "id",       "type": "bytes32", "value": "0xd570c19c…af93d",  "provenance": "verified"},
      {"name": "caller",   "type": "address", "value": "0xcc0f95e6…78b41",  "provenance": "verified"},
      {"name": "onBehalf", "type": "address", "value": "0xcc0f95e6…78b41",  "provenance": "verified"},
      {"name": "assets",   "type": "uint256", "value": "5132593584",        "provenance": "hash-bound"},
      {"name": "shares",   "type": "uint256", "value": "5017568215610987",  "provenance": "hash-bound"}
    ]
  },

  "resolution": {
    "trusted": false,
    "note": "Resolution is an RPC lookup, not a proof (TP-M14-1). It selects which fact to verify; it does not verify anything.",
    "n_matches": 1,
    "rpc_log_index": 1266,
    "log_index": 11,
    "searched": {"from_block": 25745043, "to_block": 25745143}
  }
}
```

**Normative rules on the shape:**

* **S-1.** `result` is never modified, never flattened into `decoded`, never
  omitted. The cryptographic result stays the primary claim.
* **S-2.** `decoded` is absent — not empty, not null-filled — when no registry
  entry matches. Silence is honest; a half-decoded object is not.
* **S-3.** `resolution.trusted` is literally `false` and the note is literally
  present on every response that used the resolver. §7.1 is why.
* **S-4.** `rpc_log_index` and `log_index` always appear together when
  resolution ran, so §3.1's confusion is visible rather than latent.

### 4.5 Routes

| route | resolves? | verifies? | new? |
|---|---|---|---|
| `GET /verify-receipt/{block}/{tx}/{log}` | no | yes | existing — gains `decoded` |
| `GET /verify-receipt-trustless/{block}/{tx}/{log}` | no | yes | existing — gains `decoded` |
| `GET /resolve-event/{key}` | yes | **no** | **new** |
| `GET /verify-event/{key}` | yes | yes | **new** |

`/verify-event/{key}` exists so the common path is one paid round trip rather
than two. `/resolve-event/{key}` exists because §3.3 measured that "can this
even be proven?" is a genuinely valuable standalone answer — and because a
caller who wants to resolve once and verify many times should not be forced to
re-resolve.

**Both new routes return their verdict as a *successful, paid* response**, even
when the verdict is "no match," "ambiguous," or "T3, unprovable." This
deliberately mirrors the project's existing and load-bearing discipline that
`R_ABSENT`/`R_NO_SUCH_LOG`/`R_ZERO_LOGS` are verdicts delivered by a successful
transaction and never failures (007 §5.4). A resolver that 404s on "no match"
would be both inconsistent with that discipline and, under x402, unrefundable
anyway.

---

## 5. The four open questions from the ROADMAP row, resolved

### 5.1 "What counts as well-known, and how is it extended without unbounded maintenance burden?"

**Resolved: admission is by *measured provability plus a committed fixture*,
not by fame — and the maintenance burden is bounded by TP-M14-2, which makes a
stale registry entry harmless.**

**The admission rule (normative).** An entry is admitted only if all five hold:

1. **A fixed, single emitting address** (N-2), empirically confirmed to emit
   (N-3). This alone rejects MetaMorpho's vault family and Chainlink's proxy.
2. **A measured provable rate over ≥ 30 distinct real transactions**, recorded
   in the entry. An entry below **50 % T1+T2** is either rejected or admitted
   with a `low_provable_rate` flag that the API surfaces before payment.
3. **At least one real captured event, hand-decoded, checked into
   `tests/fixtures/events/`** (N-4, §10).
4. **All parameters are v1-decodable static types** (D-4), or the entry
   declares which fields it cannot decode.
5. **`topic0` derives from `signature`** (N-1).

**Why this bounds the burden — the actual argument, not a hope.** The
conventional fear is that a registry rots: ABIs change, addresses migrate,
entries go stale, and someone must chase them forever. That fear assumes the
registry is *trusted*. Here it is not (TP-M14-2). The emitting address, all
topics including the event-signature hash, `data_len` and `keccak256(data)` are
**verified on-chain by machinery that does not consult the registry at all**.
So the failure modes of a stale entry are exactly two, and both are safe:

* the entry no longer matches anything → `decoded` is **absent** (S-2), the
  verified result is returned unchanged;
* the entry mismatches a real log → D-1/D-2/D-3 **refuse**, the verified result
  is returned unchanged.

**A stale registry entry cannot produce a wrong verified fact. It can only
produce less decoration.** That is what makes a static, human-maintained,
deliberately small registry the right answer rather than a liability — and it
is why the alternative (runtime ABI fetching from a block explorer, §8) is
worse on every axis including trust.

**Recommended v1 registry** — decided by §3.3/§3.4's measurements, which is why
it differs from the ROADMAP brief's starting candidates:

| entry | rationale |
|---|---|
| **ERC-20 `Transfer`** on USDC, USDT, WETH, DAI | frozen standard ABI (zero drift, zero maintenance by construction); highest real demand; measured best provable rate (USDC 8/12 T1) |
| **Morpho Blue `Supply`, `Withdraw`, `SupplyCollateral`, `WithdrawCollateral`** | one immutable non-upgradeable singleton (no proxy drift); measured real activity (329–404 logs/100 blk); ABI-derived `topic0` confirmed 8/8 against chain |
| **Morpho Blue `Borrow`, `Repay`, `AccrueInterest`** | admitted **flagged `low_provable_rate`** — measured 8/10 and 9/12 T3. Decodable and resolvable; the caller is warned before paying |
| ~~EigenLayer `AllocationManager`~~ | **rejected**, §3.5 — 0 events in ~600 blocks; no fixture obtainable |
| ~~MetaMorpho `Reallocate`~~ | **rejected**, §3.5 — factory shape, violates N-2 |
| ~~Chainlink feeds~~ | **rejected**, §3.5 — proxy/aggregator indirection, rotating implementation |

Extension path: a PR that adds an entry must add its fixture and its measured
`provable_rate` in the same PR. That is the whole process, and it is
self-limiting because the evidence requirement is the cost.

### 5.2 "How is ambiguity handled when a filter matches more than one event?"

**Resolved: reject by default, return the full candidate list, and require the
caller to choose explicitly. Never silently pick the newest.**

`select` defaults to `"reject"`. On `n_matches > 1` the resolver returns a
successful, paid response containing every match — each with its own
`(block, tx_index, log_index)`, tier and provability — and verifies **none** of
them. `/verify-event` in this state verifies nothing and charges the resolve
price only (§5.3).

Callers may opt in explicitly to `select=newest` or `select=oldest`. Even then
`n_matches` is always returned, so the caller's response records that a choice
was made among *n* candidates.

**Why not "return the newest" as the default** — three reasons, in increasing
order of seriousness:

1. **It makes the answer non-deterministic.** The same query moments later
   resolves to a different fact. A product whose output is one verified fact
   should not have a time-dependent default.
2. **"Newest" is not well-defined at the boundary.** Two matches in the same
   block, or the same transaction, must still be ordered by
   `(tx_index, log_index)` — and §3.1 just established that log ordering is
   exactly where this domain hides its traps.
3. **It poisons M15.** The watcher/policy engine is specified to evaluate rules
   against decoded events. A resolver that silently discards *n−1* matches
   would hand the policy engine a filtered view while implying completeness —
   converting §7.1's honest "sound but not complete" limitation into a
   misleading one. M15 must see the ambiguity, not a default.

### 5.3 "Is resolution a free pre-step or its own paid call?"

**Resolved, and the two halves of this module split cleanly in opposite
directions:**

**Decoding is free**, bundled into the existing routes at no price change.
`prove_receipt` already fetches `get_block_receipts(block)`
(`relayer/client.py:376`) to build the trie, so the log's topics and data are
**already in memory** when the verified result returns. Decoding adds one
`keccak256` and a dict lookup. Marginal RPC cost: **zero**. There is nothing to
charge for, and charging anyway would be indefensible under this project's own
evidence norms.

**Resolution is paid, as its own route.** The real justification is stronger
than "RPC calls cost money": §3.2 measured that **the RPC capability resolution
requires does not exist in this project's current infrastructure.** Three of
five default endpoints refuse `eth_getLogs` outright; the two that serve it cap
at ~100 blocks. Shipping a useful resolver means provisioning a keyed RPC tier —
a real, new, recurring cost, incurred per resolve call, with no Algorand
transaction to amortize it against.

Resolution also does *n+1* RPC round trips, not one: the `eth_getLogs` query
plus a `get_block_receipts` per candidate block for R-3's index conversion and
R-4's tier classification. On a busy contract that is the dominant cost of the
call.

**Recommended pricing structure** (the *structure* is this design's decision;
the *number* is deliberately not):

* `/resolve-event` — priced **below** the verify routes' `$0.01`
  (`main.py:91`), because it submits no Algorand transaction and consumes no
  ALGO.
* `/verify-event` — priced at **resolve + verify**, so bundling is never more
  expensive than doing the two calls separately.
* An ambiguous or no-match `/verify-event` charges the **resolve** price only,
  since no verification was performed.

**The number this document deliberately does not set.** No real paid-RPC
provider quote was obtained during this pass, so setting a resolve price here
would be exactly the fabricated cost claim `CONTRIBUTING.md` forbids. The
implementation pass MUST record a real provider, a real plan cost, and a real
measured RPC-calls-per-resolve figure before `RESOLVE_PRICE_MICRO_USDC` gets a
default other than "unset, route disabled." Gate **G6-015**.

### 5.4 "How does decoded output correctness get tested?"

**Resolved: three distinct fixture classes, because they test three genuinely
different things — plus a negative test for the hash binding.** Full detail in
§10. The essential rulings:

* Decoded output is **never** asserted from the ABI spec alone. Every entry
  ships a real captured event with hand-computed expected values.
* **Decoder fixtures and end-to-end fixtures are different artifacts**, and
  conflating them would silently shrink the decoder's test corpus. A **T3**
  event is a perfectly valid *decoder* fixture — decoding is tier-independent —
  even though it can never be an end-to-end one. §3.3 measured that T3 is the
  majority case for event-selected logs, so excluding those would leave the
  decoder tested only on the minority of events it will meet.
* A **resolution fixture** — a real `eth_getLogs` response paired with the real
  `eth_getBlockReceipts` for the same block — pins §3.1's index conversion
  offline, in `ci-offline.yml`, forever, with no live dependency.

---

## 6. Cost

### 6.1 What this module costs on-chain

**Nothing.** No contract, no mode, no extra transaction, no extra box
reference, no change to any group. The verify routes submit exactly the groups
they submit today. This is why §0's preamble declines to offer `simulate`
evidence: there is no opcode-budget behavior to measure.

### 6.2 What this module costs off-chain

| operation | RPC calls | measured? |
|---|---|---|
| decode, on an existing verify route | **0 additional** | measured — the data is already fetched at `relayer/client.py:376` |
| `/resolve-event`, 1 candidate | 1 × `eth_getLogs` + 1 × `eth_getBlockReceipts` | measured shape |
| `/resolve-event`, *n* candidates across *k* blocks | 1 × `eth_getLogs` + *k* × `eth_getBlockReceipts` | measured shape |
| `/verify-event` | the above, plus today's unchanged verify path | — |

Measured `eth_getLogs` latency on the two endpoints that serve it, 100-block
span: **0.12 s – 2.45 s**, varying by address and endpoint.
`eth_getBlockReceipts` on a real mainnet block returns 264 receipts and is the
heavier call.

**Not measured, and deliberately not guessed**: the currency cost of a paid RPC
tier. §5.3 and gate G6-015 require the implementation pass to establish it
before pricing.

---

## 7. Adversarial notes

### 7.1 Sound but not complete — the honest limit, stated mechanically

The resolver asks an RPC "which logs match this filter?" and the RPC answers.
Consider the two ways it can lie:

* **Fabricate a match** → the caller verifies it → **verification fails**, or
  succeeds about a real log that genuinely exists at that position. The RPC
  cannot manufacture an Ethereum fact; M1–M13 stand entirely unaffected. **This
  attack does not work.**
* **Omit a match** → the caller never asks about it → nothing fails, nothing
  alerts, and **no proof system in this repo can detect the omission**, because
  proving absence would require proving something about *every* log in a range —
  a completeness claim over the whole receipts trie, not an inclusion proof
  about one leaf. **This attack works, and it is not fixable within M14.**

So: **inclusion is trustless; selection is not.** This is precisely the
boundary this project has already drawn in its public messaging — a single
verified fact, not "did all matching events happen" — and this design pass can
now state the mechanical reason rather than the preference. §4.4's
`resolution.trusted: false` and TP-M14-1 exist to keep it visible at the point
of use rather than buried in a design document.

**Direct consequence for M15**, flagged now: an event-watcher built on this
resolver **cannot claim it will not miss events**. It can claim every event it
*does* report is cryptographically verified. Those are very different products,
and M15's design must not blur them.

### 7.2 What a malicious registry entry can do

Nothing to soundness (TP-M14-2). It can mislabel — call a `Supply` a
`Withdraw`, or name a field wrongly. D-2/D-3 catch address and `topic0`
mismatches against **verified** bytes, so a mislabel requires the entry to be
wrong about names while right about the signature hash — i.e. deliberate
mislabeling of a correctly-identified event. That is a code-review problem
(the registry is a checked-in file in a repo with a PR process), not a runtime
trust problem, and the raw verified result is present in every response for a
caller who wants to check.

### 7.3 What a malicious RPC can do to the decoder

Supply wrong `data` bytes. **D-1 catches this unconditionally**: the decoder
re-hashes and compares to the on-chain-verified `data_hash`, and refuses on
mismatch. Finding a second preimage for keccak256 is outside every threat model
this project operates in. The indexed fields are unaffected regardless, since
they come from the verified payload rather than from the RPC.

### 7.4 Reorgs

A resolution against a block near head may name a `(block, tx_index,
log_index)` that ceases to exist. Verification then fails or returns a
different fact — it never returns a false one. R-6 requires the response to
carry the distance from head. Callers who need reorg safety should resolve
against a block that is already anchored in M8's ring, which is also the
precondition for the trustless route.

---

## 8. Alternatives considered and rejected

| alternative | why rejected |
|---|---|
| **Fetch ABIs at runtime from Etherscan/4byte** | Adds a new trusted third party to a trust-minimization project; adds an API key and a rate limit to the critical path; makes responses non-reproducible; and buys nothing, because TP-M14-2 means the registry was never the trust bottleneck. Strictly worse on every axis. |
| **Return the newest match by default** | §5.2 — non-deterministic output, ill-defined at block/tx boundaries, and it would hand M15 a silently filtered view. |
| **Make decoding a separate paid call** | §5.3 — its marginal RPC cost is measured **zero**; the data is already in memory at `relayer/client.py:376`. Unjustifiable. |
| **Make resolution free** | §3.2 — the free pool measurably cannot serve it (3 of 5 endpoints refuse `eth_getLogs`; the rest cap at ~100 blocks). "Free" would mean either broken or subsidized by a real recurring bill. |
| **Replace `result` with `decoded`, or merge them** | Destroys the primary claim's shape and would let a decoder bug withhold a paid proof (D-5, S-1). |
| **Support the ROADMAP's named candidates as-is** | §3.4/§3.5 — measured 0 events (EigenLayer), factory-shaped registry (MetaMorpho), proxy indirection (Chainlink). The brief explicitly left this call to this pass. |
| **Resolve by scanning blocks with `eth_getBlockReceipts` instead of `eth_getLogs`** | Avoids the `eth_getLogs` availability problem but replaces one call with one call *per block*; at the same ~100-block window that is ~100 heavy calls (264 receipts each, measured) instead of 1. Worse cost, same coverage. Reconsider only for spans of a few blocks. |
| **Widen the resolver window with an archive/indexer** | Real, useful, and a different module. §13 hands it on. |

---

## 9. Files that change

**New (5)**
* `relayer/events/__init__.py`
* `relayer/events/registry.json` — §4.1
* `relayer/events/registry.py` — loader; enforces N-1…N-6 at import
* `relayer/events/resolve.py` — §4.2
* `relayer/events/decode.py` — §4.3

**Modified (3)**
* `relayer/sources/eth_rpc.py` — add `get_logs(...)`; **no change** to
  `DEFAULT_RPCS` (§3.2 R-1: the resolver gets its own pool, it does not degrade
  this one)
* `relayer/config.py` — `resolver_rpc_urls`, `resolver_max_span`,
  `resolve_price_micro_usdc`
* `service/x402_endpoint/main.py` — two new routes; `decoded` added to the two
  existing route responses; Bazaar discovery metadata for the new routes,
  with **real** captured examples per that file's own standing convention

**Explicitly NOT modified**
* Anything under `contracts/` — §1.2
* `relayer/client.py::prove_receipt`'s proof logic. The decode step is applied
  to its result by the caller (the service), so a decoder change can never
  affect a proof. *(Design choice: keep the decoder out of the proof client so
  the trust boundary stays legible.)*

**Docs (3)** — `ROADMAP.md` (§12), `ARCHITECTURE.md` (the new module),
`README.md` (the new routes, and **not** the 97.5 % figure — §3.3).

---

## 10. Test plan and fixtures

### 10.1 Three fixture classes

`tests/fixtures/events/` gets three subdirectories, because they pin three
different things and only the last one needs the chain.

**(a) `decode/` — decoder fixtures. Offline. Tier-independent.**
A real captured log plus its hand-computed expected decoding:

```json
{
  "source": "mainnet block 25745120, tx_index 311, receipt-local log_index 11",
  "tx_hash": "0x5b4e9b6efda790b8af7201228e0b3169014392123472e9232c0677585cf8aa31",
  "address": "0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb",
  "topics": [
    "0xedf8870433c83823eb071d3df1caa8d008f12f6440918c20d75a3602cda30fe0",
    "0xd570c19c0dc0fbe4ab7faf4a37c4150e1c141c8aada8ca3e1b4b6c1b712af93d",
    "0x000000000000000000000000cc0f95e65d2ce7fb715bfb418bf61314d0878b41",
    "0x000000000000000000000000cc0f95e65d2ce7fb715bfb418bf61314d0878b41"
  ],
  "data": "0x0000000000000000000000000000000000000000000000000000000131ed29b00000000000000000000000000000000000000000000000000011d373a320b66b",
  "expected_data_hash": "a8682b8195daa5dcd3515f0c9a6d2aafa1108ef577464d4ecdba51694149b33f",
  "expected_data_len": 64,
  "expected_fields": [
    {"name": "id",       "value": "0xd570c19c0dc0fbe4ab7faf4a37c4150e1c141c8aada8ca3e1b4b6c1b712af93d", "provenance": "verified"},
    {"name": "caller",   "value": "0xcc0f95e65d2ce7fb715bfb418bf61314d0878b41",                         "provenance": "verified"},
    {"name": "onBehalf", "value": "0xcc0f95e65d2ce7fb715bfb418bf61314d0878b41",                         "provenance": "verified"},
    {"name": "assets",   "value": "5132593584",                                                          "provenance": "hash-bound"},
    {"name": "shares",   "value": "5017568215610987",                                                    "provenance": "hash-bound"}
  ]
}
```

Every value above is **measured or hand-computed this pass** (§15, M-8/M-10),
not taken from an ABI spec. This file is offered as the first real fixture, not
as a template to be filled in later.

**(b) `resolve/` — resolution fixtures. Offline.** A real `eth_getLogs`
response plus the real `eth_getBlockReceipts` for the same block, with the
expected receipt-local index committed. This is what pins §3.1 permanently and
with no live dependency. The block-25745000 census (789/790, 29 silently wrong)
is committed as a **second** resolution fixture so the regression that would
reintroduce the bug is caught by a number, not by a single example.

**(c) `e2e/` — end-to-end fixtures. Live.** A real T1/T2 event resolved,
verified through the real path, and decoded. Requires `ci-live.yml`. The
canonical candidate found this pass: **block 25745120, tx_index 311, T2, leaf
3,176 B, receipt-local log_index 11 of 16** — receipts root verified against the
real header this pass.

### 10.2 Test matrix

| id | tier | statement |
|---|---|---|
| **RF-1** | offline | For every log in the committed block-25745000 fixture, the resolver's `log_index` equals the receipt-local position — and the census reproduces **789/790 differing, 29 silently-wrong** exactly |
| **RF-2** | offline | The resolver never emits the RPC's block-scoped index as `log_index`; a source grep confirms `rpc_log_index` is never passed to `prove_receipt` |
| **RF-3** | offline | `max_span` is enforced client-side; an over-wide request 400s and issues **zero** RPC calls |
| **RF-4** | offline | Tier classification in resolution matches `classify.classify` on the same leaf, including the T3 case |
| **RF-5** | offline | Ambiguity: a filter matching *n* > 1 returns all *n*, verifies none, and `select="reject"` is the default |
| **DF-1** | offline | Every registry entry's fixture decodes to its committed `expected_fields`, exactly |
| **DF-2** | offline | **Negative**: flip one byte of `data` ⇒ `keccak256` mismatch ⇒ `binding="refused"`, **no** non-indexed fields returned, indexed fields still returned |
| **DF-3** | offline | **Negative**: `data_len` mismatch alone (correct hash impossible, but assert both) ⇒ refused |
| **DF-4** | offline | **Negative**: `topics[0]` not matching the entry ⇒ refused (D-2) |
| **DF-5** | offline | **Negative**: `address` not matching the entry ⇒ refused (D-3) |
| **DF-6** | offline | A **T3** decoder fixture decodes correctly — proving decoding is tier-independent |
| **DF-7** | offline | A dynamic-type parameter is refused with a named error, never guessed (D-4) |
| **DF-8** | offline | `decoded` is **absent**, not empty, when no entry matches (S-2) |
| **DF-9** | offline | A decoder exception cannot suppress `result` (D-5) — inject a raising decoder, assert the raw verified result still returns |
| **RG-1** | offline | Every entry's `topic0` re-derives from its `signature` (N-1); mismatch fails startup |
| **RG-2** | offline | Every entry has ≥ 1 fixture (N-4) and a `provable_rate` (N-5); registry with a missing one fails to load |
| **RG-3** | offline | No entry names a wildcard/family address (N-2) |
| **E2E-1** | live | Block 25745120 tx 311 resolved → verified (T2) → decoded, all three, one flow |
| **E2E-2** | live | The same target through `/verify-receipt-trustless` — decoded fields identical, proving decoding is trust-model independent |
| **E2E-3** | live | A resolved **T3** target: `/resolve-event` reports `provable: false` and `/verify-event` declines to verify **without** charging the verify price |
| **E2E-4** | live | `/resolve-event` against a registered contract with no matches in the window returns a successful paid "no match," not a 404 |

---

## 11. Acceptance gates

| gate | statement | how judged |
|---|---|---|
| **G1-015** | The resolver never produces a block-scoped `log_index`. **The gate everything else is behind** — §3.1 measured 29 silently-wrong verified proofs per block from getting this wrong | RF-1, RF-2 |
| **G2-015** | Resolution reports tier/provability, and a T3 target is reported as such **before** any verification is paid for | RF-4, E2E-3 |
| **G3-015** | Non-indexed fields are returned **only** when `keccak256(data)` matches the verified `data_hash`; every negative path refuses fail-closed | DF-2, DF-3 |
| **G4-015** | `result` is byte-identical to today's for the same input, with or without `decoded` present | DF-9 + a golden-response diff against a pre-change capture |
| **G5-015** | Every registry entry ships a real hand-decoded fixture and a measured `provable_rate` over ≥ 30 distinct transactions. **No entry ships on ABI-spec-derived expectations alone** | RG-2, DF-1, and human review of the PR that adds each entry |
| **G6-015** | `RESOLVE_PRICE_MICRO_USDC` is set from a **real** RPC provider cost and a **real** measured calls-per-resolve figure — or the route stays disabled | §5.3; a cited real quote and a real measurement |
| **G7-015** | `resolution.trusted: false` and TP-M14-1's note appear on every resolver-backed response; no marketing copy anywhere claims resolution is verified or complete | S-3 + a docs/README review |
| **G8-015** | M1–M13 are untouched: no file under `contracts/` changes, and the full existing M7/M8 offline **and** live suites pass unchanged | `git diff --stat` + full suite re-run |
| **G9-015** | The 97.5 % coverage figure does not appear in any M14 user-facing copy; the event-selected provable rate is quoted from real measurement instead | §3.3 + docs review |

---

## 12. How `ROADMAP.md` should record this

M14's Status becomes **Design Drafted**, and its Design-doc column points at
this file. Two notes belong in the row's own text after review, because they
are findings about **already-live** behavior rather than about this module:

1. **The block-scoped/receipt-scoped `log_index` trap (§3.1)** is a live
   foot-gun in the *documented* API surface today — the routes take a
   `log_index` whose scoping is not stated anywhere in `README.md` or the
   Bazaar route descriptions. Any current integrator wiring `eth_getLogs` into
   this service is, measured, overwhelmingly likely to be asking the wrong
   question. **This deserves a documentation fix now, independent of whether
   M14 is ever implemented.**
2. **The published 97.5 % coverage figure needs a scope qualifier (§3.3).** It
   is correct for unselected receipts and measured misleading for
   event-selected logs. This is not a correction to 012's number — 012's number
   is right — it is a scope statement that M14's own measurements now make
   necessary.

M15's row should additionally record §7.1: a watcher built on this resolver
cannot claim completeness.

---

## 13. Questions resolved, and what is handed on

**Resolved by this pass, with real evidence:**

* *Can a resolver just pass `eth_getLogs`' `logIndex` through?* **No** —
  measured 789/790 wrong on a real block, 29 of them silently.
* *Are the ROADMAP's named candidates good v1 choices?* **Two of three are
  not** — measured: EigenLayer `AllocationManager` 0 events/600 blocks;
  MetaMorpho is factory-shaped; Chainlink's known address is a proxy that emits
  nothing.
* *Can the existing RPC pool serve the resolver?* **No** — measured, 3 of 5
  endpoints refuse `eth_getLogs`, the other 2 cap at ~100 blocks, and it is a
  range cap not a result cap.
* *Is the project's 97.5 % coverage figure applicable here?* **No** — measured
  57 % T3 on event-selected logs vs 2.5 % on unselected receipts.
* *Does decoding need extra RPC?* **No** — the data is already fetched at
  `relayer/client.py:376`. Decode is free; resolve is not.
* *Can decoded non-indexed fields be trusted?* **Only via the keccak binding**
  — the chain commits to `keccak256(data)`, never the data (`contracts/receipt/
  decode.py:133`). Indexed fields need no such step; they are verified bytes.
* *Does the ABI-derived `topic0` actually match reality?* **Yes** — measured
  8/8 against real Morpho Blue chain data.
* *Does resolution weaken the trust model?* **Yes, for selection only** — §7.1.
  Inclusion stays trustless; completeness was never available and now has a
  mechanical explanation.

**Handed on to the implementation pass:**

* **Sample size.** §3.3's tier measurements are 10–12 transactions per event,
  one 100-block window, one day. §5.1's own admission rule demands ≥ 30 distinct
  transactions — **more than this pass gathered**. Every `provable_rate` in the
  shipped registry must be re-measured to that standard; the numbers in §4.1's
  example entry are marked `PRELIMINARY` for exactly this reason.
* **Not measured: the real paid-RPC cost.** Deliberately unset (§5.3, G6-015).
* **Not measured: the exact `eth_getLogs` range cap.** Measured only as "100
  works, 200 fails" on both usable endpoints. The precise cap and whether it
  differs per endpoint were not established; `max_span` defaults to the
  measured-safe 100.
* **Projected, not measured: Chainlink's aggregator emits `AnswerUpdated`.**
  This pass confirmed `aggregator()` returns a *different* address than the
  proxy, and measured 0 logs on the proxy — enough to reject the candidate, not
  enough to assert what the aggregator does. Do not repeat it as fact.
* **A wider-window resolver needs an archive RPC or an index.** Out of scope
  here; it is the precondition for ever admitting low-frequency contracts like
  `AllocationManager`.
* **Not this document's to fix**: the undocumented `log_index` scoping in the
  live API surface (§12 item 1). It is a real documentation defect today.

---

## 14. Implementer checklist (normative MUSTs)

1. **MUST** convert to a receipt-scoped `log_index` (R-3) and **MUST NOT** pass
   the RPC's block-scoped value to `prove_receipt`. Land RF-1/RF-2 first, as
   their own commit, before any route exists — §3.1 is the whole reason this
   module is risky.
2. **MUST** classify tier during resolution and return it (R-4), so T3 is
   reported before payment, never as a post-payment 501.
3. **MUST** give the resolver its own RPC pool (R-1); **MUST NOT** add
   `eth_getLogs` traffic to `DEFAULT_RPCS`.
4. **MUST** enforce `max_span` client-side with zero RPC calls on rejection
   (R-2).
5. **MUST** verify `keccak256(data) == data_hash` **and** `len(data) ==
   data_len` before returning any non-indexed field, and refuse fail-closed
   (D-1). **MUST NOT** decode unbound bytes under any circumstance.
6. **MUST** label every decoded field `verified` or `hash-bound` (§4.3). The
   distinction is real and must not be flattened for tidiness.
7. **MUST** keep `result` byte-identical and always present (S-1, D-5).
8. **MUST** omit `decoded` entirely rather than emit a partial object (S-2).
9. **MUST** emit `resolution.trusted: false` with TP-M14-1's note on every
   resolver-backed response (S-3).
10. **MUST** default `select="reject"` on ambiguity and return all matches
    (§5.2). **MUST NOT** silently pick the newest.
11. **MUST NOT** add any runtime ABI fetch, block-explorer call, or network
    access to the registry loader.
12. **MUST** ship every registry entry with a real hand-decoded fixture and a
    `provable_rate` measured over ≥ 30 distinct transactions (§5.1, G5-015).
13. **MUST NOT** set a resolve price without a real cited RPC cost (G6-015).
14. **MUST NOT** touch anything under `contracts/`, and **MUST** re-run the
    full existing M7/M8 suites to prove it (G8-015).
15. **MUST NOT** reuse the 97.5 % coverage figure in M14 copy (G9-015).

---

## 15. Measurement appendix

Every number in this document was produced during this design pass against
**real Ethereum mainnet**, through this repo's own
`relayer.sources.eth_rpc` / `relayer.sources.pool` /
`relayer.proofs.receipts_trie` / `relayer.proofs.classify` code paths,
unmodified. **No Algorand transaction was submitted, no algod was contacted,
and no mainnet contract was touched by this pass** — consistent with §6.1: this
module has no on-chain behavior to measure.

| id | measurement | result |
|---|---|---|
| **M-1** | Chain head at the start of the pass | block **25745137**, later 25745143 |
| **M-2** | Block 25745000 log census | 264 receipts, 790 logs, **789** with `rpc logIndex != receipt-local index` |
| **M-3** | Naive block-index passthrough on block 25745000 | 1 correct, **29 silently wrong**, 760 `R_NO_SUCH_LOG` |
| **M-4** | `eth_getLogs` across all 5 `DEFAULT_RPCS`, spans 10/100/1000/10000 | 2 usable; publicnode 403 and drpc 400 above the cap; merkle.io 429 always; 1rpc.io conn-reset always; blastapi 400 always |
| **M-5** | Cap narrowing on the 2 usable endpoints | 100 OK (394 logs); 200/500/700/999 **FAIL** on both |
| **M-6** | Range-cap vs result-cap, quiet address (~10 logs/100 blk) | 1000/10000/50000 **all FAIL** ⇒ **range** cap |
| **M-7** | First real Morpho `Borrow` sampled | block 25745094, tx_index 353, **leaf 5,017 B ⇒ T3_UNSUPPORTED**; rpc logIndex 663 ⇒ receipt-local **21** of 26 logs |
| **M-8** | Canonical provable fixture | block 25745120, tx_index 311, tx `0x5b4e9b6e…aa31`, **T2, leaf 3,176 B**, reconstructed receiptsRoot **matches header**, rpc logIndex 1266 ⇒ receipt-local **11** of 16, 4 topics, data 64 B, `keccak256(data)=a8682b81…9b33f` |
| **M-9** | Tier distribution, log-level, 4 event types | 47 sampled: T1 9, T2 11, **T3 27 (57 %)** |
| **M-10** | Tier distribution, deduplicated to distinct transactions | Morpho `Supply` 10 txs → 1/5/**4**; Morpho `Borrow` 10 txs → 1/1/**8** |
| **M-11** | `topic0` derivation vs real chain data, Morpho Blue | **8/8 exact matches** |
| **M-12** | EigenLayer `AllocationManager` activity | **0 logs** across 6 × 100-block windows (~600 blocks); code present (2,115 B) |
| **M-13** | Chainlink ETH/USD proxy | `aggregator()` ⇒ `0x7d4e742018fb52e48b08be73d041c18b21de6fb5`, a **different** address; proxy emitted 0 logs in the sampled 100-block window |
| **M-14** | Hand-decoded values, M-8's fixture | `assets = 0x131ed29b0 = 5,132,593,584` (USDC 6dp ⇒ 5,132.593584); `shares = 5,017,568,215,610,987` |
| **M-15** | Hand-decoded values, M-7's T3 event | `caller = 0x5bb6aa1002466242b0bc0c63ece2cc1f747680f9`; `assets = 825,492,573`; `shares = 814,222,685,575,282` |

**Sampling caveat, stated plainly**: M-9 and M-10 are single-window,
single-day, 10–12 transactions per row. They are directionally decisive — a
57 % vs 2.5 % gap is not a sampling artifact — but they are **not** a corpus,
and §5.1's admission rule deliberately demands a larger sample than this pass
itself collected.
