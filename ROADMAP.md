# Roadmap

This file is the single source of truth for "what's next." Read this first in
any new session before doing anything else.

**Workflow for every module**: an Opus design pass writes `docs/design/NNN-*.md`
and commits it → human reviews and approves the design doc → a Sonnet
implementation pass writes code + tests against it, and commits → this table
gets updated. Implementation never starts on an unapproved design doc.

**Legend**: Not Started / Design Drafted / Design Approved / Implementing / Implemented / Tested / Released

| # | Module | Status | Design doc | Depends on | Open questions inherited from spike | Last updated | Next session should |
|---|---|---|---|---|---|---|---|
| — | Scaffold | Implemented | — | — | — | 2026-07-30 | Push scaffold to GitHub, then start M1 design |
| M1 | BLS12-381 point codec & MSM/pairing wrapper | Design Approved | [docs/design/001-bls-primitives.md](docs/design/001-bls-primitives.md) | scaffold | Resolved: trust boundary = subgroup-check + recompress-and-compare against SSZ-committed compressed bytes (bare subgroup check is provably insufficient, see doc §4.4 attack trace); G2 map-to-curve cost flagged as still unmeasured (probe P1) | 2026-07-30 | Sonnet implementation dispatched |
| M2 | On-chain optimized RLP decoder | Design Approved | [docs/design/002-rlp-decoder.md](docs/design/002-rlp-decoder.md) | scaffold | Resolved in design doc: single-pass scan table fixes re-walk (flat cost, not O(1) single lookup — that's provably impossible); hex-prefix + EIP-2718 specified against real mainnet vectors; single-blob decided over data-source abstraction (see doc §4) | 2026-07-30 | Sonnet implementation dispatched |
| M3 | SSZ Merkle branch verifier | Design Approved | [docs/design/003-ssz-verifier.md](docs/design/003-ssz-verifier.md) | scaffold | Resolved: sha256 measured at flat 35 budget (3.71x cheaper than keccak256); exact cost formula `53+61*depth+2*z` validated against 38/38 official consensus-spec test vectors across 6 forks (Altair-Gloas); fork decision = gindex is a runtime parameter, never hardcoded (spec itself is fork-parameterized at runtime) | 2026-07-30 | Sonnet implementation dispatched |
| M4 | Sync-committee update verifier | Not Started | — | M1, M3 | Real BLS domain-separation tag + signing-root vs. consensus-spec test vectors (spike never tested this); finalize 1-vs-2-group call with real G2 numbers (~282 calls / 2 groups) | 2026-07-30 | Blocked until M1 + M3 designs approved and implemented |
| M5 | MPT path-walker / node verifier | Not Started | — | M2 | **Security fix**: spike's verifier never checks extracted child index against real key nibbles — must derive expected path from the key on-chain, not trust a caller-supplied step list; support hashed (state/storage) and un-hashed (receipt) keys; args-vs-box staging for nodes | 2026-07-30 | Blocked until M2 design approved and implemented |
| M6 | Account & storage proof composer | Not Started | — | M5 | Exclusion-proof support decision (spike only did inclusion) | 2026-07-30 | Blocked until M5 |
| M7 | Receipt/log proof verifier | Not Started | — | M6 | **Owns the unsolved >4096B receipt-leaf problem** — 9/137 real receipts in the spike's own test block exceed the AVM value cap; no streaming hash opcode exists; implementation must not start until this specific design doc is explicitly approved, may force revision of M2 | 2026-07-30 | Blocked until M6; treat this design doc review as a hard stop |
| M8 | Trusted-root anchor contract | Not Started | — | M3, M6 | Root-history retention/eviction policy (real storage-cost tradeoff) | 2026-07-30 | Blocked until M3 + M6 |
| M9 | Off-chain relayer/client | Not Started | — | M5, M3 | Design can start once M4/M6/M7/M8 ABIs are frozen, ahead of their implementations landing | 2026-07-30 | Blocked until M4/M6/M7/M8 interfaces frozen |
| M10 | Deployment & box-storage schema tooling | Not Started | — | M7, M8, M9 | Mostly boilerplate once M8's retention policy is set | 2026-07-30 | Blocked |
| M11 | Real-data test harness & CI integration | Not Started | — | M9 | Live-docker-CI vs. pinned-fixture-CI split (both workflows exist from scaffold; this module ratifies the policy) | 2026-07-30 | Grows continuously from scaffold onward — revisit after every module lands |
| M12 | Docs & packaging / release prep | Not Started | — | M10, M11 | Contract-versioning story (AVM/consensus-fork-gated, not plain semver) | 2026-07-30 | Gates public v1 release |

## Locked decisions (do not relitigate without a new user conversation)
- Contracts authored in **Algorand Python (Puya)**, dropping to raw `Op`/inline TEAL only in budget-critical inner loops (RLP decode, MSM chunking).
- **Full Ethereum consensus-spec compliance from the start** — no stubbed BLS signature verification, no skipped SSZ track.
- Every module gate: Opus design doc → human approval → Sonnet implementation. No exceptions.
- No cost/budget claim ships without a real `simulate` response behind it (reuse `tests/fixtures/spike-reference/avm_bls_bench.py` / `mpt_bench.py` harness pattern).

## Full plan
See `/home/mark/.claude/plans/peppy-cuddling-snail.md` for the complete module rationale, dependency graph, and execution steps this roadmap was generated from.
