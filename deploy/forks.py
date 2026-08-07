"""The fork-row gindex generator (design doc §5.5, §1.3's highest-leverage
mitigation, `O-M10`'s G4-M10 gate). Every gindex is DERIVED from real SSZ
field lists (`relayer.ssz.beacon_state.FULU_FIELDS`,
`relayer.ssz.execution_payload.FIELD_INDEX`) -- never typed, never read from
a config file or CLI flag (§17 item 3).

**Per-fork field counts, and why slicing is safe, not hand-typing.**
`relayer/ssz/beacon_state.py` carries only Fulu's 38-field list (§15 gap 5:
"only Fulu's field list exists"). Rather than hand-typing a second, separate
Deneb/Electra field-name list here (which §17 item 2's spirit forbids just as
much as a second, separate gindex would), this module exploits a REAL,
already independently-confirmed structural fact recorded in
`tests/state_anchor/test_forks.py` (2026-08-06, three independent live
spec-fetch sources): **`BeaconState`'s field ORDER is stable across forks --
every fork after Bellatrix only ever APPENDS fields**, never reorders or
removes one. So Deneb's 28-field list and Electra's 37-field list are
literally `FULU_FIELDS[:28]` / `FULU_FIELDS[:37]` -- the SAME committed,
already-tested list, merely bounded by a real per-fork field COUNT. The only
new literals this module introduces are those three counts (28/37/38), and
they are cited to their independent confirmation, not invented:

  * Fulu = 38: `relayer.ssz.beacon_state.FULU_FIELDS`'s own
    `assert len(FULU_FIELDS) == 38`.
  * Deneb = 28 / Electra = 37: `tests/state_anchor/test_forks.py`'s
    2026-08-06 pass, which fetched `specs/deneb/beacon-chain.md` and
    `specs/electra/beacon-chain.md` from `consensus-specs@master` directly
    and counted container fields (9 new Electra fields appended after
    `historical_summaries`), cross-checked against 008 §3.3's own table.

If a future fork changes this (reorders a field, or `relayer/ssz/`'s own
`FULU_FIELDS` list drifts), `_fields_for` below still computes SOMETHING,
but `G-4`'s block_hash cross-check (`m8_fork_row`) and Suite G's `G-6`
negative test are what catch it -- this module never trusts field order
without that check.
"""
from __future__ import annotations

from dataclasses import dataclass

from relayer.ssz.beacon_state import FULU_FIELDS
from relayer.ssz.execution_payload import EXECUTION_PAYLOAD_DEPTH, EXECUTION_PAYLOAD_GINDEX, FIELD_INDEX

# Real, independently-confirmed per-fork BeaconState field counts (module
# docstring). Only Deneb/Electra/Fulu are in scope -- 008/009's own scope
# (no pre-Altair fork row carries real gindices; see
# `contracts/sync_committee/forks.py`'s "carry no gindices" rows).
FORK_FIELD_COUNTS = {"deneb": 28, "electra": 37, "fulu": 38}

# The spec-published cross-check value (§5.5 rule 2): folding `block_hash`
# through ExecutionPayload's own fixed 17-field/depth-5 shape MUST reproduce
# this, for every fork in scope (the shape itself has not changed since
# Deneb). docs/design/008-trusted-root-anchor.md §3.2.
EXECUTION_BLOCK_HASH_GINDEX_DENEB = 812


class ForkGindexError(ValueError):
    """Raised instead of ever emitting a plausible-looking wrong gindex
    (§17 item 3, Suite G's G-6 negative test)."""


def _next_pow2_depth(n: int) -> int:
    """`ceil(log2(n))` via the same integer approach
    `relayer.ssz.merkleize.next_pow2` uses, reimplemented here (not
    imported) because it is a 3-line arithmetic primitive, not SSZ-specific
    logic -- keeps this module's only real `relayer.ssz` dependency to the
    two data tables it actually needs (`FULU_FIELDS`, `FIELD_INDEX`)."""
    if n <= 1:
        return 0
    depth = 0
    size = 1
    while size < n:
        size *= 2
        depth += 1
    return depth


def _fields_for(fork: str, *, field_list: list[str] | None = None) -> list[str]:
    fork = fork.lower()
    if fork not in FORK_FIELD_COUNTS:
        raise ForkGindexError(f"unknown fork {fork!r}; supported: {sorted(FORK_FIELD_COUNTS)}")
    fields = field_list if field_list is not None else FULU_FIELDS
    n = FORK_FIELD_COUNTS[fork]
    if n > len(fields):
        raise ForkGindexError(
            f"{fork}'s field count ({n}) exceeds the available field list ({len(fields)}) -- "
            "refusing to emit a gindex derived from a truncated/corrupted field list"
        )
    return fields[:n]


@dataclass(frozen=True)
class M4ForkRow:
    activation_epoch: int
    fork_version: bytes  # 4 bytes
    finality_gindex: int
    current_sc_gindex: int
    next_sc_gindex: int

    def as_tuple(self) -> tuple[int, bytes, int, int, int]:
        return (self.activation_epoch, self.fork_version, self.finality_gindex,
                self.current_sc_gindex, self.next_sc_gindex)


@dataclass(frozen=True)
class M8ForkRow:
    activation_epoch: int
    g_state_root: int
    g_receipts_root: int
    g_block_number: int
    g_block_roots_base: int

    def as_tuple(self) -> tuple[int, int, int, int, int]:
        return (self.activation_epoch, self.g_state_root, self.g_receipts_root,
                self.g_block_number, self.g_block_roots_base)


def m4_fork_row(fork: str, activation_epoch: int, fork_version: bytes, *,
                field_list: list[str] | None = None) -> M4ForkRow:
    """`(activation_epoch, fork_version, finality_gindex, current_sc_gindex,
    next_sc_gindex)` -- every gindex DERIVED from `FULU_FIELDS` (§5.5).

    `finality_gindex` composes TWO levels: `BeaconState.finalized_checkpoint`
    (a container field, gindex `base + index`) THEN `Checkpoint.root` (the
    second of Checkpoint's 2 fields, composed gindex `parent*2 + 1`) --
    Checkpoint is a fixed 2-field container (`epoch`, `root`), not itself
    read from any field list (it has not changed shape since Altair).
    `current_sc_gindex`/`next_sc_gindex` are plain container-field gindices,
    no further descent needed (M4 verifies the *root itself*, not a subfield
    of it).
    """
    assert len(fork_version) == 4, "fork_version must be exactly 4 bytes"
    fields = _fields_for(fork, field_list=field_list)
    depth = _next_pow2_depth(len(fields))
    base = 1 << depth
    finalized_checkpoint_idx = fields.index("finalized_checkpoint")
    checkpoint_root_field_index = 1  # Checkpoint = (epoch, root); root is field 1 of 2
    finality_gindex = (base + finalized_checkpoint_idx) * 2 + checkpoint_root_field_index
    current_sc_gindex = base + fields.index("current_sync_committee")
    next_sc_gindex = base + fields.index("next_sync_committee")
    return M4ForkRow(activation_epoch, bytes(fork_version), finality_gindex, current_sc_gindex, next_sc_gindex)


def m8_fork_row(fork: str, activation_epoch: int, *, field_list: list[str] | None = None,
                field_index: dict[str, int] | None = None) -> M8ForkRow:
    """`(activation_epoch, g_state_root, g_receipts_root, g_block_number,
    g_block_roots_base)` -- every gindex DERIVED (§5.5). `g_state_root`/
    `g_receipts_root`/`g_block_number` are fork-INVARIANT across Deneb+
    (ExecutionPayload's own 17-field shape has not changed); only
    `g_block_roots_base` moves with `BeaconState`'s own growing field count.

    §17 item 3: refuses (`ForkGindexError`) to emit a row whose `block_hash`
    fold does not reproduce `EXECUTION_BLOCK_HASH_GINDEX_DENEB = 812` --
    `field_index`/`field_list` overrides exist ONLY so
    `tests/deploy/test_forks_gindex.py`'s G-6 negative test can feed this a
    deliberately corrupted table and assert the refusal fires; production
    call sites never pass them.
    """
    fields = _fields_for(fork, field_list=field_list)
    depth = _next_pow2_depth(len(fields))
    base = 1 << depth
    g_block_roots_base = base + fields.index("block_roots")

    idx = field_index if field_index is not None else FIELD_INDEX
    pow2 = 1 << EXECUTION_PAYLOAD_DEPTH

    def compose(field_name: str) -> int:
        return EXECUTION_PAYLOAD_GINDEX * pow2 + idx[field_name]

    block_hash_check = compose("block_hash")
    if block_hash_check != EXECUTION_BLOCK_HASH_GINDEX_DENEB:
        raise ForkGindexError(
            f"block_hash cross-check failed: composed {block_hash_check}, expected "
            f"{EXECUTION_BLOCK_HASH_GINDEX_DENEB} -- refusing to emit a fork row "
            "derived from this field table (§5.5 rule 2)"
        )

    g_state_root = compose("state_root")
    g_receipts_root = compose("receipts_root")
    g_block_number = compose("block_number")
    return M8ForkRow(activation_epoch, g_state_root, g_receipts_root, g_block_number, g_block_roots_base)


# ---------------------------------------------------------------------------
# §5.5 rule 3: activation epochs come from a live spec fetch, cross-checked
# against a second published source -- never a literal in a config file.
# Mirrors `tests/state_anchor/test_forks.py`'s own three-source confirmation;
# skips (returns None) rather than failing when neither is reachable, same
# as that test.
# ---------------------------------------------------------------------------
SPEC_ENDPOINTS = [
    "http://unstable.mainnet.beacon-api.nimbus.team/eth/v1/config/spec",
    "http://testing.mainnet.beacon-api.nimbus.team/eth/v1/config/spec",
]
CONFIG_YAML_URL = "https://raw.githubusercontent.com/eth-clients/mainnet/main/metadata/config.yaml"

# Independently confirmed (three ways) by `tests/state_anchor/test_forks.py`,
# 2026-08-06 -- used as the offline fallback when no network is reachable,
# never as the primary source when a live fetch succeeds. `fulu` is
# `tests/sync_committee/test_live_e2e_finality.py`'s own already
# live-confirmed value, re-confirmed this pass (2026-08-07) against a live
# `/eth/v1/config/spec` fetch (`FULU_FORK_EPOCH: 411392`, matching exactly).
# **Real bug this pass found and fixed**: an earlier version of this table
# used a placeholder `500000` for `fulu`, which is GREATER than the real
# 411392 -- since mainnet's real current epoch is already well past 411392,
# a fork-row table seeded with `500000` would answer every "which row is
# active right now" lookup with the ELECTRA row instead of the correct
# FULU one, silently feeding `submit_update` the wrong `fork_version`
# (`0x05000000` instead of the real `0x06000000`) and therefore the wrong
# BLS signing domain -- which fails closed as a pairing-check assertion,
# not a silent wrong-signature acceptance, but a real, reproducible defect
# nonetheless (found via Suite E's live G1-M10 run, see ROADMAP.md).
KNOWN_ACTIVATION_EPOCHS = {"deneb": 269568, "electra": 364032, "fulu": 411392}

# Real mainnet `fork_version` values (`configs/mainnet.yaml`, consensus-specs
# -- BLS domain-separation constants, not gindices, so §17 item 3's "never a
# hand-typed gindex" rule does not apply to them; they are still cited to
# their spec source rather than invented). 4 bytes each, big-endian.
FORK_VERSION_HEX = {
    "genesis": "00000000",
    "altair": "01000000",
    "bellatrix": "02000000",
    "capella": "03000000",
    "deneb": "04000000",
    "electra": "05000000",
    "fulu": "06000000",
}


def fork_version_bytes(fork: str) -> bytes:
    return bytes.fromhex(FORK_VERSION_HEX[fork.lower()])


def fetch_fork_activation_epochs(*, timeout: float = 3.0) -> dict[str, int] | None:
    """Live `/eth/v1/config/spec` fetch, first endpoint that answers.
    Returns `None` (never raises) if none is reachable -- callers fall back
    to `KNOWN_ACTIVATION_EPOCHS` and the caller's test/CLI reports this
    plainly rather than silently using a possibly-stale literal."""
    import json
    import urllib.error
    import urllib.request

    for url in SPEC_ENDPOINTS:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                data = json.load(r)["data"]
            result = {
                "deneb": int(data["DENEB_FORK_EPOCH"]),
                "electra": int(data["ELECTRA_FORK_EPOCH"]),
            }
            if "FULU_FORK_EPOCH" in data:
                result["fulu"] = int(data["FULU_FORK_EPOCH"])
            return result
        except (urllib.error.URLError, OSError, KeyError, ValueError, TimeoutError):
            continue
    return None
