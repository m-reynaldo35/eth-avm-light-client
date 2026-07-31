"""M3 -- SSZ Merkle-branch verifier. Public surface (design doc §5, §10).

The generic SSZ Merkle-branch primitive: given a leaf hash, a sibling array,
and a generalized index, fold to a root and compare it against a
caller-supplied expected root. See docs/design/003-ssz-verifier.md for the
full design.

NORMATIVE, repeated here because it is the single most important thing a
caller of this module must not miss (design doc §6): a successful call to
`assert_valid_merkle_branch` or `assert_valid_normalized_merkle_branch`
proves only that `leaf` sits at the tree position named by `gindex`. It
proves nothing about which field of the underlying SSZ container that
position represents. `gindex` MUST be supplied by the calling module (M4,
M8) from a fork-gated constant table it controls itself, resolved from the
update's slot -- it MUST NOT come from relayer-supplied calldata, from a box
a relayer can write, or from any value derived from the proof itself. Every
entry point below takes `gindex` as a required parameter with no default
for exactly this reason: a default is how a fork constant sneaks back into
a module that is deliberately fork-agnostic (design doc §4.4, §6).

This module never names a specific generalized index, never contains
fork-conditional code, and never carries SSZ container field layouts --
that is out of scope by design (§1.2, §4.3).
"""
from .merkle import (
    assert_valid_merkle_branch,
    assert_valid_normalized_merkle_branch,
    compute_merkle_branch_root,
)
from .merkleize import (
    merkleize_stack_finalize,
    merkleize_stack_push,
    mix_in_length,
    zero_hash,
)

__all__ = [
    "assert_valid_merkle_branch",
    "assert_valid_normalized_merkle_branch",
    "compute_merkle_branch_root",
    "merkleize_stack_finalize",
    "merkleize_stack_push",
    "mix_in_length",
    "zero_hash",
]
