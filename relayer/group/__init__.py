"""The group-assembly layer (design doc §7) -- the genuinely new work in
M9: box-reference/budget planning against the real, measured AVM caps,
replacing four divergent copy-pasted implementations. This subpackage
(along with `relayer.drivers` and `relayer.client`/`relayer.cli`) is the
only part of `relayer/` allowed to import `algosdk` (§4.3 rule 3)."""
