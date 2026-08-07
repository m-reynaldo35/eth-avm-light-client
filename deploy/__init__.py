"""`deploy` -- M10: deployment & box-storage schema tooling.

docs/design/010-deployment-tooling.md. This package compiles, deploys, funds,
governs and inspects the four deployable contracts (`SyncCommitteeVerifier`
(M4), `Mpt6ComposerApp` (M6), `Mpt7ReceiptApp` (M7), `TrustedRootAnchor`
(M8)) plus the `DonorIssuer`/`DonorCallee` budget pair.

Dependency direction (§8.1, §17 item 1): `deploy` imports `relayer` (for
`relayer.group.donors`, `relayer.group.boxes.plan_box_refs`, `relayer.ssz.*`)
and `contracts.*`/`algopy` (for the schema generator). `relayer` MUST NEVER
import `deploy` -- enforced by `tests/deploy/test_security_matrix.py`'s
AST-based G8-M10 test, mirroring `tests/relayer/test_security.py`'s G8-M9.

Shape (§8.1): a library with a thin `argparse` CLI over it. `deploy.plan`/
`deploy.apply`/`deploy.verify` are the product; `python -m deploy` just
wires argv to them.
"""
