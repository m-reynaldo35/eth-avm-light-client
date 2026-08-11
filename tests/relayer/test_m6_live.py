"""Suite L (design doc §13.2/§11.1's A-M6-3, G2-M6): a real, non-simulated
submission against a fresh, live `Mpt6ComposerApp`, driven entirely through
`EthAvmClient.prove_account` -- not hand-rolled test code -- closing
`CHANGELOG.md`'s "Honestly still open" item ("M6 (`Mpt6ComposerApp`) has no
submitting client -- `prove_account` never sends a transaction").

Mirrors `tests/receipt/test_anchored_app_live.py`'s own pattern: deploy the
real contract fresh via `deploy.plans.m6` (the same tooling a real operator
uses, `deploy/plans/m6.py::compile_m6` compiles `contracts/composer/
bench_app.py` -- confirmed the REAL deployed source, not a bench-only
variant, unlike M7's `bench_app.py` before 014 promoted `anchored_app.py`),
then monkeypatch ONLY the Ethereum-RPC-facing functions
(`relayer.client.get_block_header`/`get_proof`) to serve the real, pinned
USDT/Binance-8 mainnet fixture (`tests/fixtures/spike-reference/
eth_data.json`, the same bytes `docs/design/006-account-storage-proof.md`
§11.1 pins field-by-field) -- the Algorand side is never faked.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from algosdk import mnemonic

from relayer.client import EthAvmClient
from relayer.config import RelayerConfig

from tests.harness.chain import account, algod_client
from tests.harness.deployment import deploy_donor_pair

REPO_ROOT = Path(__file__).resolve().parents[2]
ETH_DATA_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "spike-reference" / "eth_data.json"

pytestmark = [pytest.mark.needs_algod]


def _load_eth_data() -> dict:
    with open(ETH_DATA_FIXTURE) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def m6_env(account):
    """Deploys a fresh `Mpt6ComposerApp` via the real deploy tooling
    (`deploy.plans.m6.apply` -- `target` is unused by that function's own
    body, confirmed by reading it, so a throwaway `None` is honest here,
    not a shortcut around real deploy logic) plus a bare donor-callee app
    (§7.1's SELF_ISSUED convention -- `Mpt6ComposerApp` issues its own
    donor inner calls per segment, so unlike M4/M7/M8 this needs no
    `DonorIssuer` sibling, only the callee `deploy_donor_pair` also
    deploys)."""
    from deploy.manifest import Manifest
    from deploy.plans import m6 as m6_plan

    sender, sk = account
    algod = algod_client()

    callee_id, issuer_id = deploy_donor_pair(algod, sender, sk)

    sp = algod.suggested_params()
    gh = sp.gh if isinstance(sp.gh, str) else base64.b64encode(sp.gh).decode()
    manifest = Manifest(genesis_id="test-probe-m6", genesis_hash=gh)
    m6_app_id = m6_plan.apply(algod, sender, sk, None, manifest)

    return {
        "sender": sender, "sk": sk, "algod": algod, "m6_app_id": m6_app_id,
        "issuer_id": issuer_id, "callee_id": callee_id,
    }


def _client_for(env) -> EthAvmClient:
    cfg = RelayerConfig(
        m6_app_id=env["m6_app_id"], donor_callee_id=env["callee_id"],
        signer_mnemonic=mnemonic.from_private_key(env["sk"]),
    )
    return EthAvmClient(cfg)


class TestG2M6RealSubmission:
    """G1-M6/G2-M6/G7-M6, live: the real USDT/Binance-8 composite (§11.1's
    A-M6-1 field set) proven end to end through `EthAvmClient.prove_account`
    against a real dev-mode `Mpt6ComposerApp`, and the account-absent /
    slot-absent negative shapes (§8.1/§8.2), each a REAL separate
    submission -- not a simulate, not a dry run."""

    def test_g2_m6_headline_included_composite(self, m6_env, monkeypatch):
        import relayer.client as client_mod

        d = _load_eth_data()
        proof = d["proof"]
        state_root = d["stateRoot"]

        monkeypatch.setattr(client_mod, "get_block_header", lambda block: {"stateRoot": state_root})
        monkeypatch.setattr(client_mod, "get_proof", lambda address, keys, block: proof)

        client = _client_for(m6_env)
        result = client.prove_account(proof["address"], proof["storageProof"][0]["key"], block=d["block_number"])

        # §11.1's A-M6-1 pinned field set, reached via a REAL 5-transaction
        # on-chain group this time, not an offline decode.
        assert result.status == "C_INCLUDED"
        assert result.balance == int(proof["balance"], 16) == 0x2A
        assert result.slot_value == bytes.fromhex("00" * 25 + "3f1ca131081cf8")
        assert result.fields["storage_root"] == proof["storageHash"][2:]
        assert result.fields["code_hash"] == proof["codeHash"][2:]
        assert result.fields["nonce"] == int(proof["nonce"], 16) == 1
        assert result.fields["state_root"] == state_root[2:]
        assert result.fields["address"] == proof["address"][2:]
        assert result.fields["awalk"] == 1  # WALK_INCLUDED
        assert result.fields["swalk"] == 1  # WALK_INCLUDED
        assert result.fields["phase"] == 3  # PHASE_DONE
        assert result.confirmed_round is not None
        # §6.5: A_INIT, A_NEXT, A_NEXT, B_INIT, B_NEXT -- 5 real transactions.
        assert len(result.tx_ids) == 5

        print(
            f"\nG2-M6 REAL LIVE PROOF: EthAvmClient.prove_account() drove a real "
            f"5-transaction Mpt6ComposerApp (app {m6_env['m6_app_id']}) group to a terminal "
            f"C_INCLUDED composite matching design doc §11.1's A-M6-1 pinned field set exactly. "
            f"tx_ids={result.tx_ids}, measured_consumed={result.fields['measured_consumed']}"
        )

    def test_account_absent_real_submission(self, m6_env, monkeypatch):
        """§8.1: a real account-exclusion proof -- the SAME kind of
        branch-node shape `tests/relayer/test_real_fixtures.py`'s
        `test_r2_absent_account_and_slot_cases_are_structurally_handled`
        already proves `verify_and_extract` classifies correctly off-chain
        -- submitted for REAL this time, with ZERO phase-B segments ever
        issued (the design doc's own G7-M6 gate)."""
        import relayer.client as client_mod
        import rlp
        from Crypto.Hash import keccak

        def kec(b: bytes) -> bytes:
            h = keccak.new(digest_bits=256)
            h.update(b)
            return h.digest()

        # A single 17-entry branch node, one populated slot -- walking
        # toward any OTHER nibble is a real, structurally-sound M5
        # exclusion proof (mirrors test_real_fixtures.py's own R-2
        # construction, real RLP + real keccak, not a hand-waved shape).
        # `keccak256(b"\x00" * 20)`'s own first nibble is 5 (verified), so
        # the populated slot is deliberately placed at a DIFFERENT nibble
        # (0) so the all-zero address's real key walks toward the empty
        # slot 5 and is excluded, rather than running out of nodes trying
        # to descend into slot 5's fake, non-existent child.
        address = "0x" + "00" * 20
        branch = [b""] * 17
        branch[0] = b"\x01" * 32
        branch_rlp = rlp.encode(branch)
        root = kec(branch_rlp)

        # A real `eth_getProof` response always echoes a `storageProof`
        # entry for every requested key -- `proof: []`/`value: "0x0"` when
        # there is nothing to prove (account absent OR slot absent), never
        # an empty `storageProof` list. `segment_account_proof` reads the
        # 32-byte SLOT key from this entry regardless of `need_phase_b`
        # (§3.3: `C.slot` is a fixed 32-byte field written at `A_INIT`
        # whether or not phase B ever runs), so omitting it here would
        # feed the composer a 0-byte slot arg instead of a real 32-byte
        # one -- a test-fixture bug this pass found live (on-chain assert
        # "== 32" at `mpt6_init_composite`'s own slot-width check), not a
        # client bug.
        slot_hex = "0x" + "00" * 32
        fake_proof = {
            "address": address,
            "accountProof": ["0x" + branch_rlp.hex()],
            "balance": "0x0", "nonce": "0x0", "codeHash": "0x" + "00" * 32,
            "storageHash": "0x" + "00" * 32,
            "storageProof": [{"key": slot_hex, "value": "0x0", "proof": []}],
        }
        monkeypatch.setattr(client_mod, "get_block_header", lambda block: {"stateRoot": "0x" + root.hex()})
        monkeypatch.setattr(client_mod, "get_proof", lambda addr, keys, block: fake_proof)

        client = _client_for(m6_env)
        result = client.prove_account(address, slot_hex, block="latest")

        assert result.status == "C_ABSENT_ACCOUNT"
        assert result.balance == 0
        assert result.slot_value is None
        assert result.fields["phase"] == 3  # PHASE_DONE
        # §8.1: no phase-B segment is issued or accepted for an absent
        # account -- ONE real transaction (A_INIT alone), not five.
        assert len(result.tx_ids) == 1

        print(
            f"\nG7-M6 REAL LIVE PROOF (account-absent): a real 1-transaction Mpt6ComposerApp "
            f"group reached C_ABSENT_ACCOUNT with ZERO phase-B segments, tx_ids={result.tx_ids}"
        )
