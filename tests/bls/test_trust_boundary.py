"""Test T12 -- the trust-boundary attack test (docs/design/001-bls-primitives.md
§4.4, §11). This is the executable form of the module's central security
argument, and the single most important test in this suite: it must fail
loudly if anyone ever swaps `g1_bind` for a bare subgroup check.

Live tier only: needs real `ec_subgroup_check` / `ec_pairing_check`.

Attack narrative (§4.4):
  1. A relayer generates its OWN secret keys (never the real committee's).
  2. It submits `P'_i = sk'_i . G1` as the "committee pubkeys". Every one
     passes `ec_subgroup_check` -- they are perfectly valid G1 points.
  3. It picks an arbitrary message, computes the message point, and signs
     with the aggregate of its own forged secret keys.
  4. `verify_aggregate_signature` succeeds, because the signature is
     *genuinely valid* -- just under the wrong keys.
  5. If the ONLY on-chain check were `g1_validate_wellformed_only` /
     `ec_subgroup_check`, the contract would accept this forged committee.

`g1_bind`, checked against the REAL committee's committed compressed keys,
must reject every one of the forged keys -- this is what actually stops
the attack, and this test is the proof.
"""

from __future__ import annotations

from py_ecc.bls import G2ProofOfPossession as bls_pop

from . import reference as ref
from .test_codec import _g1_uncompressed
from .test_pairing import (
    _hash_to_g2_point_bytes,
    _keypair,
    _pk_bytes_to_g1_point,
    _sig_bytes_to_g2_avm,
)


def test_t12_live_forged_committee_attack_is_only_stopped_by_bind(live_harness):
    n = 4
    msg = b"attacker-chosen beacon header signing root"

    # -- Step 1: the REAL committee, whose compressed keys are what a
    # trusted SSZ root would actually commit to (§4.5 caller obligation).
    real_keys = [_keypair(seed=100 + i) for i in range(n)]
    real_pks = [pk for _, pk in real_keys]
    real_compressed = [ref.g1_compress(_pk_bytes_to_g1_point(pk)) for pk in real_pks]

    # -- Steps 1-3: the ATTACK. The relayer generates its OWN keys and signs
    # the attacker-chosen message with them. None of these secret keys is
    # any real committee member's.
    forged_keys = [_keypair(seed=900 + i) for i in range(n)]
    forged_sks = [sk for sk, _ in forged_keys]
    forged_pks = [pk for _, pk in forged_keys]

    forged_signatures = [bls_pop.Sign(sk, msg) for sk in forged_sks]
    forged_agg_sig = bls_pop.Aggregate(forged_signatures)
    forged_agg_pk = bls_pop._AggregatePKs(forged_pks)

    forged_agg_pk_point = _pk_bytes_to_g1_point(forged_agg_pk)
    msg_point_bytes = _hash_to_g2_point_bytes(msg)
    forged_sig_bytes = _sig_bytes_to_g2_avm(forged_agg_sig)

    # -- Step 4a: EVERY forged key individually passes well-formedness.
    # This is the crux of §4.4 -- subgroup check cannot distinguish "a
    # genuine committee key" from "any key the attacker just made up".
    for i, pk in enumerate(forged_pks):
        pk_point = _pk_bytes_to_g1_point(pk)
        r = live_harness.call("g1_validate_wellformed_only", pk_point)
        assert r.ok, (
            f"forged key {i} unexpectedly failed well-formedness -- test "
            f"setup is broken, not the attack"
        )

    # -- Step 4b: the forged aggregate signature verifies against the
    # forged aggregate pubkey -- because it IS a genuine, valid BLS
    # signature. This is not a bug in verify_aggregate_signature; it is
    # exactly what §4.4 says will happen, and why binding must happen
    # BEFORE aggregation, not be replaced by a check at this stage.
    r_verify = live_harness.call(
        "verify_aggregate_signature", forged_agg_pk_point, msg_point_bytes, forged_sig_bytes
    )
    assert r_verify.ok, r_verify.failure
    assert r_verify.return_value[0] & 0x80 != 0, (
        "forged signature must verify under the forged aggregate pubkey -- "
        "if this assertion fails, the attack scenario itself is broken, "
        "which would make the next assertion (g1_bind rejects it) vacuous"
    )

    # -- Step 5: THE FIX. `g1_bind` against the REAL committee's committed
    # compressed keys must reject every forged key. This is what actually
    # stops the attack -- not subgroup check, not the pairing check, which
    # both happily accepted the forgery above.
    for i, (pk, real_compressed_i) in enumerate(zip(forged_pks, real_compressed)):
        forged_pk_point = _pk_bytes_to_g1_point(pk)
        r_bind = live_harness.call("g1_bind", forged_pk_point, real_compressed_i)
        assert not r_bind.ok, (
            f"g1_bind must reject forged key {i} against the real committee's "
            f"committed compressed bytes -- if this passes, the trust boundary "
            f"is broken and the whole module's security argument (§4.5) is void"
        )

    # -- Sanity check in the other direction: g1_bind ACCEPTS each real key
    # against its own real committed compressed bytes, proving the
    # rejections above are due to key substitution, not a bug that rejects
    # everything.
    for i, (sk, pk) in enumerate(real_keys):
        pk_point = _pk_bytes_to_g1_point(pk)
        r_bind_real = live_harness.call("g1_bind", pk_point, real_compressed[i])
        assert r_bind_real.ok, (
            f"g1_bind must ACCEPT real key {i} against its own committed "
            f"compressed bytes -- {r_bind_real.failure}"
        )
