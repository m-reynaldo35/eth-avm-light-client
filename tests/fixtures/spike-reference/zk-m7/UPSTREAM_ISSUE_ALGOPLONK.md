# DRAFT — not filed. For human review before submitting to github.com/giuliop/algoplonk.

Suggested title:

> Discarded `kzg.VerifyingKey.ReadFrom` error in `setup.go` leaves `Vk.Lines`
> zeroed, making the off-chain KZG pairing check in `plonk.Verify` vacuous

## Summary

`setup/setup.go`'s `trustedSetupBN254` and `trustedSetupBLS12381` both discard
the error returned by `ReadFrom` when loading the vendored trusted-setup files
— for both the proving key (`srs.Pk.ReadFrom`) and, critically, the verifying
key (`srs.Vk.ReadFrom`):

```go
// trustedSetupBN254, setup/setup.go:188-190
var srs kzg_bn254.SRS
srs.Pk.ReadFrom(bytes.NewReader(G1s))
srs.Vk.ReadFrom(bytes.NewReader(vkData))   // <- error return value discarded
return &srs, nil
```

```go
// trustedSetupBLS12381, setup/setup.go:172-174
var srs kzg_bls12381.SRS
srs.Pk.ReadFrom(bytes.NewReader(G1s))
srs.Vk.ReadFrom(bytes.NewReader(vkData))   // <- error return value discarded
return &srs, nil
```

The vendored `vk.bin` files (`setup/PerpetualPowersOfTauBN254/vk.bin` = 160
bytes, `setup/EethereumKzgCeremonyBLS12_381/vk.bin` / `setup/DuskBLS12_381/vk.bin`
= 240 bytes) hold only the three raw KZG verifying-key points. gnark-crypto's
`kzg.VerifyingKey.ReadFrom` (v0.20.1) expects those three points *plus* 66×4
precomputed Miller-loop line evaluations per G2 point (`Lines`), and returns
`io.EOF` once the point data runs out. Because that error is discarded, the
read silently stops after the three points and `Vk.Lines` is left at its
zero value — `0/264` non-zero entries.

`plonk.Setup` (`backend/plonk/bn254/setup.go:128`, and the BLS12-381
equivalent) copies this verifying key into the PLONK `VerifyingKey.Kzg` field
verbatim; nothing downstream recomputes `Lines`. `plonk.Verify`'s final step
calls `kzg.BatchVerifyMultiPoints(..., vk.Kzg)`, which calls
`bn254.PairingCheckFixedQ(P, vk.Lines[:])` (or the BLS12-381 equivalent). With
`Lines` all zero, this pairing check no longer constrains anything — it is
computing a pairing against zeroed line evaluations, not the real trusted
setup.

## Concrete consequence

A proof with a corrupted KZG opening — the batch-opening point
`proof.BatchedProof.H` doubled, everything else honest — is **accepted** by
`plonk.Verify` when the verifying key came from any of `setup.Run`'s trusted
paths. The algebraic-relation check that runs earlier in `plonk.Verify` passes
regardless (it doesn't touch the opening proof), so this specific corruption
is caught by nothing else. This means one of the two verification layers PLONK
is supposed to provide — the polynomial-commitment opening check, as opposed
to the algebraic gate-relation check — is silently disabled for every user of
`setup.PerpetualPowersOfTauBN254`, `setup.EthereumKzgCeremonyBLS12381`, and
`setup.DuskBLS12381`.

This is an off-chain-only defect: AlgoPlonk's generated Algorand Python
verifier does its own pairing check on-chain using the AVM's native BN254
operations and the verifying key's raw G2 points, and never consumes gnark's
`Lines`. It does not affect the on-chain verifier's soundness. It does affect
every off-chain use of `plonk.Verify` against a `setup.Run`-produced verifying
key — e.g. a client verifying a proof before submitting it, or any test/CI
step that calls `plonk.Verify` directly.

## Reproduction

Real reproduction, through AlgoPlonk's own public API, no custom SRS — a
tiny cubic circuit (`x^3 + x + 5 == y`) compiled and set up via
`ap.Compile(&Cubic{}, ecc.BN254, setup.PerpetualPowersOfTauBN254)`:

```
(1) vendored vk.bin = 160 bytes
    kzg.VerifyingKey.ReadFrom -> read 160 bytes, err = EOF
    -> AlgoPlonk setup.go lines 190 / 174 DISCARD this error.
    Lines populated after the failed read: 0/264

(2) ap.Compile(..., setup.PerpetualPowersOfTauBN254)
    resulting plonk VerifyingKey.Kzg.Lines: 0/264 non-zero

(3) honest proof via cc.Verify: OK

(4) proof with CORRUPTED KZG opening -> plonk.Verify err = <nil>
    *** ACCEPTED. The off-chain KZG pairing check is VACUOUS. ***

(5) repairing Lines with bn254.PrecomputeLines and retrying:
    corrupted-opening proof -> plonk.Verify err = can't verify opening proof
    honest proof            -> plonk.Verify err = <nil>
```

Steps (1)-(4) are the bug; step (5) is the fix, applied by hand after the fact
to show the check becomes real once `Lines` is populated.

This project independently reaches the same root cause through
`github.com/mdehoog/gnark-ptau`'s `ToSRS` (used to bypass `setup.Run` for
ceremonies larger than AlgoPlonk vendors): it also never sets `Lines`, for the
same underlying reason — nothing in the naive loading pipeline calls
`bn254.PrecomputeLines`/`bls12381.PrecomputeLines` on the loaded G2 points.
Confirms this is a property of the missing step, not an artifact of one
particular loader.

## Fix

Two lines, in each of `trustedSetupBN254` and `trustedSetupBLS12381`, after
the verifying key is read:

```go
srs.Vk.Lines[0] = bn254.PrecomputeLines(srs.Vk.G2[0])
srs.Vk.Lines[1] = bn254.PrecomputeLines(srs.Vk.G2[1])
```

(`bls12381.PrecomputeLines` for the BLS12-381 path.) This is exactly what this
project's own `ptaufast` loader does
(`tests/fixtures/spike-reference/zk-m7/ptaufast/ptaufast.go`) to work around
the defect without depending on an AlgoPlonk fix.

Separately, and regardless of the above: the four discarded `ReadFrom` errors
should not be discarded. At minimum they should be checked and returned;
ideally `loadTrustedSetupBytes`'s existing length/count validation should be
extended to also validate that `vk.bin`'s declared length matches what
`kzg.VerifyingKey.ReadFrom` actually expects for the target curve, so a
truncated or malformed vendored file fails loudly at `setup.Run` time instead
of silently producing a verifying key that accepts anything.

## Scope note for whoever files this

Not reviewed as part of finding this: AlgoPlonk's generated Puya verifier
templates and BSB22 commitment handling on-chain — this report only concerns
the off-chain Go verification path (`plonk.Verify`) reached through
`setup.Run`'s trusted setups.
