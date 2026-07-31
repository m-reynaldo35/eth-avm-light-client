"""
contracts/mpt -- Puya library implementing M5: the MPT path-walker / node
verifier. See docs/design/005-mpt-walker.md for the full design.

The fix M5 exists for, restated (§0): the research spike's verifier hash-
chained node bytes but never asked *which key* the path spells, so any
honest, fully hash-chained mainnet proof could be presented as a proof
about ANY key. M5's fix: the descent index at every branch hop is computed
on-chain from the key's own nibbles (`nibble_at(key, depth)`), and every
extension/leaf path segment is compared on-chain against the corresponding
slice of the key (`nibbles_equal`) -- so a proof is bound to exactly one
key. M5's public surface contains no caller-supplied step list, child
index, or path parameter of any kind.

This is a library of module-level `@subroutine`s -- no class, no global
state -- plus a measurement/reference app (`bench_app.py`) that is NOT a
production app (§1.2: M5 makes no account/receipt/root-anchoring claims;
that is M6/M7/M8's job).

Trust preconditions (design doc §1.3):
  TP-M5-1 (root)             -- R must already be a root the caller trusts.
  TP-M5-2 (key preimage)      -- M5 must be given the PREIMAGE, never a
                                  pre-derived key (state.py's length asserts
                                  make the two conventions non-interchangeable).
  TP-M5-3 (node bytes)        -- untrusted on arrival, trusted exactly when
                                  keccak256(node) == expected; every node is
                                  hashed BEFORE any of its bytes are parsed.

Error codes (§10), two/three-character, mirrored here:
  W1   mpt_key_from_address: preimage is not 20 bytes
  W2   mpt_key_from_slot: preimage is not 32 bytes
  W3   mpt_key_from_tx_index: index > 0xffffff
  W4   branch hop: depth > key_nibs (walk overran the key)
  W5   RETIRED (§16.2): originally "node arity is not 17 where a branch
       was required", asserted by re-deriving arity a second time inside
       mpt_branch_hop. Measured as real, avoidable duplicated work (a
       second full list-header + item-0 + item-1 decode of the SAME node
       on every branch hop) and removed -- mpt_walk_node now discriminates
       arity exactly once per hop (mpt_arity_discriminate) and routes to
       mpt_branch_hop only on arity == 17, which was already the only
       reachable case through that routing before this fix (this test
       file's own pre-existing comment said so). mpt_branch_hop's docstring
       states the precondition a direct (non-mpt_walk_node) caller must
       now uphold itself. See docs/design/005-mpt-walker.md §16.2.
  W6   child reference is neither empty, nor 32 bytes, nor an embedded list
  W7   extension node's child slot is empty
  W8   inline-descent chain exceeded 8 steps within one node buffer
  W9   mpt_descend: requested item does not exist within the list payload
  W10  segment finished with unconsumed trailing node arguments
  W11  keccak256(node) != expected -- the hash-chain check
  W12  attempted to extend a walk whose status is already terminal
  W13  hand-off: referenced group index does not precede this transaction
  W14  hand-off: referenced transaction is not a call to this application
  W15  hand-off: referenced transaction did not invoke the segment method
  W16  hand-off: referenced transaction's last log is not a well-formed
       walk state
  --- implementation additions beyond the design doc's own W1-W16 table
      (documented here, not silently invented -- see each site's docstring):
  W17  mpt_verify_inclusion: walk did not reach WALK_INCLUDED (§6 describes
       this as "the asserting entry point M6/M7 use by default" but §10
       does not assign it a code)
  W18  internal: a 32-byte W field (root/expected) was not exactly 32 bytes
  W19  internal: a derived key handed to mpt_init_state exceeded 32 bytes
"""
from contracts.mpt.descend import mpt_arity_discriminate, mpt_branch_item_at, mpt_descend
from contracts.mpt.handoff import (
    ARC4_RETURN_PREFIX,
    LOG_LEN,
    mpt_log_state,
    mpt_state_from_prev,
)
from contracts.mpt.state import (
    W_LEN,
    WALK_ABSENT_BRANCH_TERM,
    WALK_ABSENT_EMPTY_SLOT,
    WALK_ABSENT_EXT_DIVERGE,
    WALK_ABSENT_LEAF_DIVERGE,
    WALK_CONTINUE,
    WALK_INCLUDED,
    mpt_init_state,
    mpt_key_from_address,
    mpt_key_from_slot,
    mpt_key_from_tx_index,
    w_depth,
    w_expected,
    w_key,
    w_key_nibs,
    w_root,
    w_status,
    w_with_continue,
    w_with_continue_depth_only,
    w_with_terminal,
)
from contracts.mpt.walk import (
    mpt_branch_hop,
    mpt_extension_hop,
    mpt_leaf_hop,
    mpt_verify_inclusion,
    mpt_walk_node,
)

__all__ = [
    "W_LEN",
    "WALK_CONTINUE",
    "WALK_INCLUDED",
    "WALK_ABSENT_EMPTY_SLOT",
    "WALK_ABSENT_EXT_DIVERGE",
    "WALK_ABSENT_LEAF_DIVERGE",
    "WALK_ABSENT_BRANCH_TERM",
    "w_status",
    "w_root",
    "w_expected",
    "w_depth",
    "w_key_nibs",
    "w_key",
    "w_with_continue",
    "w_with_continue_depth_only",
    "w_with_terminal",
    "mpt_init_state",
    "mpt_key_from_address",
    "mpt_key_from_slot",
    "mpt_key_from_tx_index",
    "mpt_descend",
    "mpt_arity_discriminate",
    "mpt_branch_item_at",
    "mpt_branch_hop",
    "mpt_extension_hop",
    "mpt_leaf_hop",
    "mpt_walk_node",
    "mpt_verify_inclusion",
    "ARC4_RETURN_PREFIX",
    "LOG_LEN",
    "mpt_log_state",
    "mpt_state_from_prev",
]
