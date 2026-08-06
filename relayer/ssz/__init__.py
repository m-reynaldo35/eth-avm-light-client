"""Real SSZ merkleization (design doc §6.4), promoted from
`tests/state_anchor/real_ssz.py` and `tests/state_anchor/real_beacon_state.py`
-- a hand-rolled merkleizer that matched a real beacon node's own
`state_root` byte-for-byte across all 38 real Fulu fields (including
~2.33M real validators, ~24s), cross-validated against `remerkleable` at
small scale (`remerkleable` stays a dev/test dependency only, §4.3 item 4 --
never imported here).

Normative (§6.4, 008 §9.4/G4-M8): this subpackage MUST NOT hardcode a
branch depth or a `g_block_roots_base` for on-chain use -- those come from
the on-chain fork table's row for the right epoch at call time. The
constants defined here (e.g. `G_BLOCK_ROOTS_BASE_FULU`) are the values a
caller cross-checks the fork table's row AGAINST, and what the offline
fixture builders use when there is no live fork table to read from -- they
are never passed to a contract call in place of a real on-chain lookup.

No `algosdk` import anywhere in this subpackage (§4.3, G8-M9)."""
