"""SSZ Merkle-branch verification primitives (M3).

Implements docs/design/003-ssz-verifier.md §5.1-§5.3: the core fold
(`compute_merkle_branch_root`), its asserting wrapper
(`assert_valid_merkle_branch`), and the normalized-branch wrapper
(`assert_valid_normalized_merkle_branch`) that M4/M8 are expected to call.

Representation decisions (design doc §5, both load-bearing, not stylistic):

  * `branch` is a packed `Bytes` blob of `32*n`, NOT an ARC-4 array type.
    `arc4.DynamicArray[...]` carries a length prefix and per-element decode
    cost that the measured budget numbers in §2.4/§2.5 do not include.
    Callers convert once at the ARC-4 boundary (see `harness.py`) and pass
    packed `Bytes` inward.
  * `gindex` is a native `algopy.UInt64`, not `arc4.UInt64` and not `Bytes`:
    `bitlen` and bit tests need a native integer.

Every entry point below takes `gindex` as a required, un-defaulted parameter.
Do not add a default value for it under any circumstance -- see the module
docstring in `__init__.py` and design doc §6 for why.
"""
from algopy import Bytes, UInt64, subroutine, urange, op


@subroutine
def compute_merkle_branch_root(leaf: Bytes, branch: Bytes, gindex: UInt64) -> Bytes:
    """Fold `leaf` up through `branch` to a root.

    Bit-exact with the consensus spec's `compute_merkle_branch_root`
    (`specs/phase0/beacon-chain.md`), restated in design doc §3.3:

        depth := bitlen(gindex) - 1
        require len(branch) == depth * 32
        node  := leaf
        for i in 0 .. depth-1:
            sibling := branch[32*i : 32*i+32]
            if (gindex >> i) & 1 == 1:      # node is a RIGHT child
                node := sha256(sibling || node)
            else:                           # node is a LEFT child
                node := sha256(node || sibling)
        return node

    `branch[0]` is the sibling of `leaf` itself (deepest level); `branch[-1]`
    is the sibling one level below the root. This leaf-to-root ordering is
    the consensus spec's convention (design doc §3.2) -- confirmed against
    all 38 official `single_merkle_proof` vectors -- and must never be
    reversed.

    Preconditions (all asserted, not assumed):
      * len(leaf) == 32
      * gindex >= 1                          (gindex == 0 underflows depth)
      * bitlen(gindex) <= 62                  (depth <= 61, design doc §7.8)
      * len(branch) % 32 == 0
      * len(branch) // 32 == bitlen(gindex) - 1   -- EXACT, not >= (see
        `assert_valid_normalized_merkle_branch` for the >= form)

    Returns the 32-byte computed root. `gindex == 1` means depth 0: the
    fold runs zero iterations and the leaf IS the root (design doc §7.1).
    A zero leaf and/or zero siblings are legitimate SSZ data and must be
    accepted without special-casing (design doc §7.5).
    """
    assert leaf.length == 32, "leaf must be 32 bytes"
    assert gindex >= 1, "gindex must be >= 1 (gindex == 0 is invalid)"

    bitlen_gindex = op.bitlen(gindex)
    assert bitlen_gindex <= 62, "gindex exceeds supported depth (depth <= 61)"
    depth = bitlen_gindex - 1

    assert branch.length % 32 == 0, "branch length must be a multiple of 32"
    assert branch.length // 32 == depth, "branch length must equal depth exactly"

    node = leaf
    for i in urange(depth):
        offset = i * 32
        sibling = branch[offset : offset + 32]
        if op.getbit(gindex, i):
            # bit i of gindex == 1 => node is a RIGHT child
            node = op.sha256(sibling + node)
        else:
            # bit i of gindex == 0 => node is a LEFT child
            node = op.sha256(node + sibling)
    return node


@subroutine
def assert_valid_merkle_branch(
    leaf: Bytes, branch: Bytes, gindex: UInt64, expected_root: Bytes
) -> None:
    """Assert `compute_merkle_branch_root(leaf, branch, gindex) == expected_root`.

    Mirrors the consensus spec's `is_valid_merkle_branch`, in `assert` form:
    this deliberately returns `None`, not `bool` (design doc §7.6) -- there is
    no legitimate caller that wants to continue after a failed Merkle check,
    and a `bool` return invites an `if not valid: ...` whose missing `else`
    is a silent total-verification bypass.

    NORMATIVE (design doc §6 -- read this before calling this function from
    anywhere): a successful call proves only that *some* 32-byte value sits
    at the tree position named by `gindex` in a tree consistent with
    `expected_root`. It proves NOTHING about which field of the underlying
    SSZ container that position represents. `gindex` MUST be supplied by the
    calling module from a fork-gated constant table it controls itself,
    resolved from the update's slot (per the spec's `*_gindex_at_slot`
    pattern) -- it MUST NOT come from relayer-supplied calldata, from a box a
    relayer can write, or from any value derived from the proof itself. If a
    relayer can choose `gindex`, it can pick any real leaf position in an
    honestly-finalized tree it likes -- e.g. a stray zero leaf or an
    unrelated field -- supply the genuine branch for that position, and pass
    this check while substituting a value of its choosing for the field the
    caller actually means to verify. `expected_root` must itself already be
    trusted through some other means (e.g. BLS-verified attestation, or an
    anchored root) -- this function has no opinion on the root's provenance.
    """
    assert expected_root.length == 32, "expected_root must be 32 bytes"
    root = compute_merkle_branch_root(leaf, branch, gindex)
    assert root == expected_root, "merkle branch does not fold to expected root"


@subroutine
def assert_valid_normalized_merkle_branch(
    leaf: Bytes, branch: Bytes, gindex: UInt64, expected_root: Bytes
) -> None:
    """Assert a *normalized* branch: `branch` may be LONGER than `depth`.

    Mirrors the light-client spec's `is_valid_normalized_merkle_branch`
    (design doc §3.5). Wire types are fixed-size vectors sized for the
    deepest supported fork (e.g. `NextSyncCommitteeBranch` has 6 slots to
    cover Electra even though Altair only needs 5); a shallower proof is
    LEFT-padded with zero `Bytes32` slots. `branch`'s leading
    `len(branch)//32 - depth` slots are that padding and MUST each be
    exactly 32 zero bytes; the trailing `depth` slots are the real,
    leaf-to-root-ordered siblings consumed by `compute_merkle_branch_root`.

    NORMATIVE (design doc §6 -- same warning as `assert_valid_merkle_branch`,
    repeated here because this is the entry point M4/M8 are expected to call
    at the module boundary): `gindex` MUST come from a fork-gated table the
    calling module controls, resolved from the update's slot, and MUST NOT
    come from relayer-supplied data. A successful call proves only that
    `leaf` sits at the position named by `gindex`; it says nothing about
    whether that position is the field the caller means to check.

    The zero-padding check is a SECURITY requirement, not tidiness (design
    doc §3.5, §6, §7.4-item-1): without it, a relayer can stuff arbitrary
    bytes into unused padding slots and mint many distinct wire encodings of
    one semantically identical update, breaking any dedup/replay/ranking
    logic a caller builds on the encoded update's hash. The padding slots
    are unused vector slots, not tree levels -- they are never folded.

    Asserted:
      * len(branch) % 32 == 0
      * len(branch) // 32 >= depth              (>= here, == in the strict
        `assert_valid_merkle_branch` form)
      * every leading padding slot == 32 zero bytes
      * the trailing `depth` slots fold to `expected_root`
    """
    assert gindex >= 1, "gindex must be >= 1 (gindex == 0 is invalid)"
    bitlen_gindex = op.bitlen(gindex)
    assert bitlen_gindex <= 62, "gindex exceeds supported depth (depth <= 61)"
    depth = bitlen_gindex - 1

    assert branch.length % 32 == 0, "branch length must be a multiple of 32"
    total_slots = branch.length // 32
    assert total_slots >= depth, "branch shorter than depth"
    num_extra = total_slots - depth

    # Compare each padding slot against 32 zero bytes using `global
    # ZeroAddress` rather than materializing a bytecblock zero constant --
    # this is what Appendix A's measured reference program does, and it is
    # cheaper (design doc §5.3 implementation note).
    zero32 = op.Global.zero_address.bytes
    for i in urange(num_extra):
        offset = i * 32
        assert (
            branch[offset : offset + 32] == zero32
        ), "non-zero byte in normalized-branch padding slot"

    real_branch = branch[num_extra * 32 : branch.length]
    assert_valid_merkle_branch(leaf, real_branch, gindex, expected_root)
