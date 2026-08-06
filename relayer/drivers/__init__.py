"""ABI-specific drivers (design doc §8.3) -- deliberately NOT unified. The
four target contracts differ in argument encoding, budget-donation
convention, box requirements, statefulness and result envelope; a forced-
uniform `submit(proof)` would hide exactly the things an operator has to
reason about. What IS unified is everything beneath (`relayer.group.*`,
`relayer.sources.*`, `relayer.codec.*`, `relayer.ssz.*`, `relayer.proofs.*`)
-- the drivers are thin, and their job is precisely to encode the
differences §8.3's table names.
"""
