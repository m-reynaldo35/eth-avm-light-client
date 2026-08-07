"""M4 driver (design doc §6.1, §8.3): `SyncCommitteeVerifier` -- ARC-4
encoding, `DonorIssuer` sibling budget convention, a real on-chain install
session (§9.1's client-side-stateless resume).

Argument-shape transforms (`SubmitUpdateArgs`, `BootstrapArgs`,
`transform_*`) promoted from `service/x402_endpoint/eth_beacon_rpc.py`
(§2.1/§2.3) -- unchanged in behaviour, only relocated so they use
`relayer.codec.*`/`relayer.sources.beacon` instead of `tests.bls.
test_codec`/`tests.sync_committee.reference` (D-2.3's fix) and so a
deployed service module no longer imports a pytest test module.

`install_chunks` here is the FIXED version (§18 item 13, D1): chunk_size is
now fixed at 8 members (not the unusable default `chunk_size=64`, which
produced a 6,144-byte blob against the 2,048-byte total app-argument cap)
-- `chunk_size` values that would exceed that cap are rejected by this
function itself, not left to fail against algod.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from algosdk.abi import Method

from relayer.codec.bls import g1_compressed_to_avm, g2_compressed_to_avm
from relayer.codec.committee import committee_root
from relayer.codec.header import decode_branch, decode_header, hash_tree_root_beacon_block_header
from relayer.group.boxes import choose_mode, key_box_indices_for_mode, m4_submit_update_box_sizes, plan_box_refs
from relayer.sources import beacon

# ---------------------------------------------------------------------------
# `SyncCommitteeVerifier`'s real ARC-4 method signatures (design doc §8.2's
# "drivers are thin, and their job is precisely to encode the differences").
# Built via `Method.from_signature` rather than a compiled ARC-56 artifact --
# `relayer` targets an ALREADY-DEPLOYED app (M9 does not compile/deploy,
# §1.2), so it needs only the ABI signature, not a fresh puyapy compile.
# Selectors independently cross-checked against a real `puyapy` compile of
# `contracts/sync_committee/verifier.py`'s own `arc56.json` before being
# trusted here (each of the 6 selectors below matched byte-for-byte).
# ---------------------------------------------------------------------------
_SIGNATURES = {
    "bootstrap": "bootstrap(byte[112],byte[32],byte[],byte[32])void",
    "install_open_keys": "install_open_keys()void",
    "install_open_session": "install_open_session()void",
    "install_chunk": "install_chunk(uint64,byte[],byte[])void",
    "install_finalize": "install_finalize(byte[48],byte[96])void",
    "submit_update": (
        "submit_update(byte[112],byte[112],byte[],byte[32],byte[],byte[64],byte[192],uint64,uint8)void"
    ),
    "noop_budget": "noop_budget()void",
    "retire": "retire(uint64)void",
}
METHODS: dict[str, Method] = {name: Method.from_signature(sig) for name, sig in _SIGNATURES.items()}

# §18 item 13, D1: fixed at 8 members/txn -- 8 * 144 B (48 compressed + 96
# uncompressed) = 1,152 B, comfortably under the 2,048 B app-argument cap.
# The unusable prior default was `chunk_size=64` (`KEYS_PER_BOX`), which
# produces a 3,072 B compressed blob + 6,144 B uncompressed blob -- far
# past the cap. `test_live_e2e_finality.py`'s own hand-rolled loop already
# uses 8, matching 64 real live submissions; this function makes that the
# API's own only supported chunk size rather than a caller-adjustable
# default nobody could safely raise.
INSTALL_CHUNK_SIZE = 8
_BYTES_PER_MEMBER = 48 + 96  # compressed + uncompressed
_MAX_ARG_BYTES = 2048


@dataclass
class SubmitUpdateArgs:
    """Positional shape of `SyncCommitteeVerifier.submit_update`. `mode` is
    a pure relayer hint (never security-relevant, §1.3's trust table)."""

    attested_header: bytes
    finalized_header: bytes
    finality_branch: bytes
    next_committee_root: bytes
    next_committee_branch: bytes
    sync_committee_bits: bytes
    signature: bytes
    signature_slot: int
    mode: int = 0

    def abi_args(self) -> tuple:
        return (
            self.attested_header, self.finalized_header, self.finality_branch,
            self.next_committee_root, self.next_committee_branch,
            self.sync_committee_bits, self.signature, self.signature_slot, self.mode,
        )


def transform_finality_update(resp: dict) -> SubmitUpdateArgs:
    data = resp["data"]
    attested_header = decode_header(data["attested_header"])
    finalized_header = decode_header(data["finalized_header"])
    finality_branch = decode_branch(data["finality_branch"])
    sync_committee_bits = bytes.fromhex(
        data["sync_aggregate"]["sync_committee_bits"][2:]
        if data["sync_aggregate"]["sync_committee_bits"].startswith("0x")
        else data["sync_aggregate"]["sync_committee_bits"]
    )
    assert len(sync_committee_bits) == 64, (
        f"expected a 64-byte Bitvector[512] (mainnet SYNC_COMMITTEE_SIZE), got {len(sync_committee_bits)}"
    )
    signature = g2_compressed_to_avm(data["sync_aggregate"]["sync_committee_signature"])
    signature_slot = int(data["signature_slot"])
    return SubmitUpdateArgs(
        attested_header=attested_header, finalized_header=finalized_header,
        finality_branch=finality_branch, next_committee_root=bytes(32), next_committee_branch=b"",
        sync_committee_bits=sync_committee_bits, signature=signature, signature_slot=signature_slot,
    )


def transform_light_client_update(update_entry: dict) -> SubmitUpdateArgs:
    args = transform_finality_update(update_entry)
    data = update_entry["data"]
    if "next_sync_committee" in data:
        nsc = data["next_sync_committee"]
        args.next_committee_root = committee_root(nsc["pubkeys"], nsc["aggregate_pubkey"])
        args.next_committee_branch = decode_branch(data["next_sync_committee_branch"])
    return args


def transform_optimistic_update(resp: dict) -> dict:
    """Never a `submit_update`-ready tuple (§5.3/§18 item: `transform_
    optimistic_update`'s result MUST NOT be accepted where a
    `SubmitUpdateArgs` is expected, S-3)."""
    data = resp["data"]
    return {
        "attested_header": decode_header(data["attested_header"]),
        "sync_committee_bits": bytes.fromhex(data["sync_aggregate"]["sync_committee_bits"].lstrip("0x")),
        "signature": g2_compressed_to_avm(data["sync_aggregate"]["sync_committee_signature"]),
        "signature_slot": int(data["signature_slot"]),
    }


@dataclass
class BootstrapArgs:
    header: bytes
    committee_root: bytes
    current_sc_branch: bytes
    pubkey_pairs: list[tuple[bytes, bytes]] = field(repr=False)
    aggregate_compressed: bytes = b""
    aggregate_uncompressed: bytes = b""

    def bootstrap_abi_args(self, trusted_block_root: bytes) -> tuple:
        assert len(trusted_block_root) == 32
        return (self.header, self.committee_root, self.current_sc_branch, trusted_block_root)


def transform_bootstrap(resp: dict) -> BootstrapArgs:
    data = resp["data"]
    header = decode_header(data["header"])
    csc = data["current_sync_committee"]
    root = committee_root(csc["pubkeys"], csc["aggregate_pubkey"])
    branch = decode_branch(data["current_sync_committee_branch"])
    pairs = [g1_compressed_to_avm(pk) for pk in csc["pubkeys"]]
    agg_compressed, agg_uncompressed = g1_compressed_to_avm(csc["aggregate_pubkey"])
    return BootstrapArgs(
        header=header, committee_root=root, current_sc_branch=branch, pubkey_pairs=pairs,
        aggregate_compressed=agg_compressed, aggregate_uncompressed=agg_uncompressed,
    )


def install_chunks(pairs: list[tuple[bytes, bytes]], chunk_size: int = INSTALL_CHUNK_SIZE
                    ) -> list[tuple[int, bytes, bytes]]:
    """Splits a committee's `(compressed, uncompressed)` pairs into
    `install_chunk`-sized `(index, compressed_blob, uncompressed_blob)`
    triples. §18 item 13: rejects a `chunk_size` whose argument bytes would
    exceed the 2,048 B cap HERE, in the API, not by letting algod reject
    it."""
    if chunk_size * _BYTES_PER_MEMBER > _MAX_ARG_BYTES:
        raise ValueError(
            f"chunk_size={chunk_size} needs {chunk_size * _BYTES_PER_MEMBER} B of app args, "
            f"exceeding the {_MAX_ARG_BYTES} B cap -- use {INSTALL_CHUNK_SIZE} or smaller"
        )
    out = []
    for start in range(0, len(pairs), chunk_size):
        chunk = pairs[start:start + chunk_size]
        compressed_blob = b"".join(c for c, _u in chunk)
        uncompressed_blob = b"".join(u for _c, u in chunk)
        out.append((start, compressed_blob, uncompressed_blob))
    return out


# ---------------------------------------------------------------------------
# Wall-clock sanity (§1.3, §6.1, §18 item 7) -- the one genuinely normative
# soundness-adjacent duty M9 carries, per the design doc's own framing: M4
# has no clock and cannot check `current_slot >= signature_slot` itself.
# ---------------------------------------------------------------------------
GENESIS_TIME_MAINNET = 1606824023  # real mainnet genesis (fetched from /eth/v1/beacon/genesis)
SECONDS_PER_SLOT = 12


def slot_now(genesis_time: int, *, now: int | None = None) -> int:
    import time

    now = now if now is not None else int(time.time())
    return max(0, (now - genesis_time) // SECONDS_PER_SLOT)


# Real, live finding (this pass): a freshly-fetched real mainnet
# `finality_update`'s own `signature_slot` was observed 3-4 slots (~36-48s)
# "ahead" of `slot_now()` computed on this machine at the moment of the
# check -- real public beacon-API endpoints can serve an attestation for a
# slot that is still in flight from this process's own wall-clock vantage
# (ordinary distributed-systems latency/clock skew), not evidence of a
# malicious or buggy far-future claim. §1.3's actual concern is a GROSS
# future-dated lie (hours/days), not sub-minute jitter -- MARGIN_SLOTS
# absorbs the former while still catching the latter as a hard assert.
MARGIN_SLOTS = 12  # ~144s of tolerance


def assert_not_future_dated(signature_slot: int, genesis_time: int = GENESIS_TIME_MAINNET,
                             margin_slots: int = MARGIN_SLOTS) -> None:
    """§18 item 7 (normative, hard assert not a warning): M9 must not
    forward an update it knows to be from the future."""
    current = slot_now(genesis_time)
    if signature_slot > current + margin_slots:
        raise ValueError(
            f"signature_slot {signature_slot} is in the future relative to slot_now()={current} "
            f"(margin={margin_slots} slots) -- refusing to forward (§1.3 item 3)"
        )


# ---------------------------------------------------------------------------
# Mode/box-plan selection for `submit_update` (§7.4/§7.5/§18 items 2-3).
# ---------------------------------------------------------------------------


def plan_submit_update_boxes(sync_committee_bits: bytes, gen: int):
    """§7.5's corrected rule: real pooled box-reference cost, not box
    count. Returns `(mode, BoxRefPlan)`. §18 item 3: the caller MUST size
    the group's transaction count from `plan.txns_required`, never assume
    2 transactions suffice."""
    return choose_mode(sync_committee_bits, gen)


# ---------------------------------------------------------------------------
# §9.1's client-side-stateless resume needs a real, live earlier checkpoint
# to bootstrap from (so a genesis install genuinely ADVANCES finalized state
# past the checkpoint). Promoted from `tests/sync_committee/
# test_live_e2e_finality.py::_fetch_live_checkpoint_and_update` (pure
# fetching/decoding orchestration, no `tests.*` import needed once
# `hash_tree_root_beacon_block_header` lives in `relayer.codec.header`) --
# this is the ONE piece of "the checkpoint policy" (§6.1) this pass
# generalises out of the test tree into the library itself, since every
# live sync() driver needs it, not just a test fixture.
# ---------------------------------------------------------------------------
def fetch_checkpoint_and_update(max_attempts: int = 3) -> dict:
    """Fetches a REAL, live `finality_update` to submit, plus a REAL,
    strictly-EARLIER real checkpoint from the SAME sync-committee period to
    bootstrap from. Retries a couple of times for the rare period-boundary
    race (§10.4)."""
    last_err = None
    for _ in range(max_attempts):
        try:
            fu_now = beacon.fetch_finality_update()
            fu_now_args = transform_finality_update(fu_now)
            fu_now_finalized_slot = int.from_bytes(fu_now_args.finalized_header[0:8], "little")
            fu_now_attested_slot = int.from_bytes(fu_now_args.attested_header[0:8], "little")
            period = fu_now_attested_slot // 8192

            checkpoint_update = beacon.fetch_updates(period, 1)[0]
            checkpoint_args = transform_light_client_update(checkpoint_update)
            checkpoint_finalized_slot = int.from_bytes(checkpoint_args.finalized_header[0:8], "little")

            if checkpoint_finalized_slot >= fu_now_finalized_slot:
                last_err = AssertionError(
                    f"checkpoint finalized_slot {checkpoint_finalized_slot} not "
                    f"earlier than submission update's {fu_now_finalized_slot}"
                )
                time.sleep(2)
                continue

            checkpoint_root = hash_tree_root_beacon_block_header(checkpoint_args.finalized_header)
            boot_resp = beacon.fetch_bootstrap(checkpoint_root.hex())
            boot_args = transform_bootstrap(boot_resp)
            assert hash_tree_root_beacon_block_header(boot_args.header) == checkpoint_root
            assert len(boot_args.pubkey_pairs) == 512

            return {
                "fu_now": fu_now, "fu_now_args": fu_now_args,
                "checkpoint_root": checkpoint_root, "boot_args": boot_args,
                "checkpoint_update": checkpoint_update, "checkpoint_args": checkpoint_args,
            }
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(2)
    raise RuntimeError(f"could not assemble a live checkpoint+update pair: {last_err}")
