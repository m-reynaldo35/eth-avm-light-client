"""Pure byte-codec helpers (design doc §5.3): BLS point (de)compression in
AVM limb order, `BeaconBlockHeader`/Merkle-branch decoding, and SSZ
`SyncCommittee` root computation. Promoted out of `service/x402_endpoint/
eth_beacon_rpc.py` and, for the BLS helpers, out of `tests.bls.test_codec`
-- fixing D-2.3 (009 §2.3): a production module importing a pytest test
module. No `algosdk` import anywhere in this subpackage (§4.3, G8-M9)."""
