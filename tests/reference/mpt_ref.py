"""
tests/reference/mpt_ref.py -- strict Python reference oracle for M5's MPT
path-walker (docs/design/005-mpt-walker.md §1.1 item 6, §9.5 suite D2).

This is the differential-test authority for contracts/mpt/: the Puya
subroutines there MUST agree with this module on every fixture and every
hop (status, depth, derived branch index, value span), and this module's
own arithmetic mirrors the Puya source line-for-line (same variable names,
same order of operations -- see each function's docstring for the exact
design-doc section it implements) so a reviewer can diff the two directly.

Unlike contracts/mpt/ (which relies on TP-M5-3 -- node bytes are only
"trusted" once keccak256-verified, so this oracle does the same
hash-chain-first-then-parse discipline), this module is otherwise a literal
port: no additional canonicality checking beyond what rlp_ref.py already
does for RLP itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from tests.reference import rlp_ref
from tests.reference.rlp_ref import KIND_BYTE, KIND_LIST, KIND_STR, RlpError, keccak256

# ---------------------------------------------------------------------------
# §3.1 status discriminator
# ---------------------------------------------------------------------------
WALK_CONTINUE = 0
WALK_INCLUDED = 1
WALK_ABSENT_EMPTY_SLOT = 2
WALK_ABSENT_EXT_DIVERGE = 3
WALK_ABSENT_LEAF_DIVERGE = 4
WALK_ABSENT_BRANCH_TERM = 5

WALK_ABSENT_ALL = (
    WALK_ABSENT_EMPTY_SLOT,
    WALK_ABSENT_EXT_DIVERGE,
    WALK_ABSENT_LEAF_DIVERGE,
    WALK_ABSENT_BRANCH_TERM,
)

INLINE_STEPS_MAX = 8
W_LEN = 101


class MptError(ValueError):
    """Same two/three-character code the Puya assert would raise."""

    def __init__(self, code: str, msg: str = ""):
        super().__init__(f"{code}: {msg}" if msg else code)
        self.code = code


# ---------------------------------------------------------------------------
# §3.2 walk state W -- fixed 101 bytes. Represented here as a frozen
# dataclass for readability; `pack`/`unpack` are the wire format the Puya
# side actually manipulates, and D2 checks BOTH representations agree.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class W:
    status: int
    root: bytes      # 32 B, immutable across a walk
    expected: bytes  # 32 B, cursor
    depth: int       # nibbles consumed so far, cursor
    key_nibs: int    # total nibbles in the key, immutable
    key: bytes       # 32 B, right-zero-padded, immutable

    def pack(self) -> bytes:
        assert len(self.root) == 32 and len(self.expected) == 32 and len(self.key) == 32
        return (
            bytes([self.status])
            + self.root
            + self.expected
            + self.depth.to_bytes(2, "big")
            + self.key_nibs.to_bytes(2, "big")
            + self.key
        )

    @staticmethod
    def unpack(raw: bytes) -> "W":
        assert len(raw) == W_LEN
        return W(
            status=raw[0],
            root=raw[1:33],
            expected=raw[33:65],
            depth=int.from_bytes(raw[65:67], "big"),
            key_nibs=int.from_bytes(raw[67:69], "big"),
            key=raw[69:101],
        )


def mpt_init_state(root: bytes, key: bytes, key_nibs: int) -> W:
    """Design doc §3.2's initial state: expected := root (the first hop's
    node must hash to the trusted root itself), depth := 0, status :=
    WALK_CONTINUE. `key` is right-zero-padded to 32 bytes."""
    assert len(root) == 32, "W18"
    assert len(key) <= 32, "W19"
    return W(WALK_CONTINUE, root, root, 0, key_nibs, key + bytes(32 - len(key)))


# ---------------------------------------------------------------------------
# §4 -- on-chain key derivation, both conventions.
# ---------------------------------------------------------------------------
def mpt_key_from_address(addr: bytes) -> bytes:
    if not (len(addr) == 20):
        raise MptError("W1", "address preimage must be 20 bytes")
    return keccak256(addr)


def mpt_key_from_slot(slot: bytes) -> bytes:
    if not (len(slot) == 32):
        raise MptError("W2", "slot preimage must be 32 bytes")
    return keccak256(slot)


def mpt_key_from_tx_index(index: int) -> bytes:
    if not (index <= 0xFFFFFF):
        raise MptError("W3", "tx index too large for the 3-byte-length encoder")
    if index == 0:
        return b"\x80"
    if index <= 0x7F:
        return bytes([index])
    if index <= 0xFF:
        return bytes([0x81, index])
    if index <= 0xFFFF:
        return bytes([0x82]) + index.to_bytes(2, "big")
    return bytes([0x83]) + index.to_bytes(3, "big")


# ---------------------------------------------------------------------------
# §5.1 -- mpt_descend: unconditional arity discrimination.
# ---------------------------------------------------------------------------
def mpt_descend(node: bytes, start: int, want: int):
    """Returns (arity, o0, l0, k0, ow, lw, kw). Mirrors
    contracts/mpt/descend.py::mpt_descend exactly, including the duplicated
    per-item stride arithmetic in the branch-skip loop (§2's D1 obligation,
    §5.1's own note that this duplicates rlp_scan_n's hot-loop body)."""
    payload_off, payload_end = rlp_ref.rlp_list_header(node, start)
    o0, l0, k0 = rlp_ref.rlp_item_header(node, payload_off, canonical=False)
    o1, l1, k1 = rlp_ref.rlp_item_header(node, o0 + l0, canonical=False)
    if o1 + l1 == payload_end:
        return 2, o0, l0, k0, o1, l1, k1

    if want == 0:
        return 17, o0, l0, k0, o0, l0, k0
    if want == 1:
        return 17, o0, l0, k0, o1, l1, k1

    pos = o1 + l1
    n = 2
    while n < want:
        if not (pos < payload_end):
            raise MptError("W9", "mpt_descend: walked off the end of the branch payload")
        p = node[pos]
        if p < 0xB8:
            if p < 0x80:
                pos += 1
            else:
                pos += 1 + (p - 0x80)
        elif p < 0xC0:
            ll = p - 0xB7
            pos += 1 + ll + int.from_bytes(node[pos + 1:pos + 1 + ll], "big")
        elif p < 0xF8:
            pos += 1 + (p - 0xC0)
        else:
            ll = p - 0xF7
            pos += 1 + ll + int.from_bytes(node[pos + 1:pos + 1 + ll], "big")
        n += 1
    if not (pos < payload_end):
        raise MptError("W9", "mpt_descend: requested item does not exist")
    ow, lw, kw = rlp_ref.rlp_item_header(node, pos, canonical=False)
    return 17, o0, l0, k0, ow, lw, kw


def nibble_at(data: bytes, k: int) -> int:
    return rlp_ref.nibble_at(data, k)


# ---------------------------------------------------------------------------
# §5.2 branch, §5.3 extension, §5.4 leaf.
#
# Each hop function returns (kind, w_out, value_off, value_len, child_off):
#   kind 0 -- terminal: w_out.status is a WALK_* terminal code
#   kind 1 -- continue via hash reference: w_out has new expected/depth
#   kind 2 -- continue via embedded/inline child (§5.5): w_out has new
#             depth only; child_off is where to resume IN THIS BUFFER
# ---------------------------------------------------------------------------
def _w_continue(w: W, expected: bytes, depth: int) -> W:
    return W(WALK_CONTINUE, w.root, expected, depth, w.key_nibs, w.key)


def _w_continue_depth_only(w: W, depth: int) -> W:
    return W(WALK_CONTINUE, w.root, w.expected, depth, w.key_nibs, w.key)


def _w_terminal(w: W, status: int) -> W:
    return W(status, w.root, w.expected, w.depth, w.key_nibs, w.key)


def mpt_branch_hop(node: bytes, start: int, w: W):
    depth, key_nibs, key = w.depth, w.key_nibs, w.key

    # step 1: TERMINAL CHECK FIRST (§5.2) -- must precede nibble_at, which
    # would read past the key at depth == key_nibs.
    if not (depth <= key_nibs):
        raise MptError("W4", "branch hop: depth overran key_nibs")
    if depth == key_nibs:
        arity, _o0, _l0, _k0, ov, lv, _kv = mpt_descend(node, start, 16)
        if not (arity == 17):
            raise MptError("W5", "node arity is not 17 where a branch was required")
        if lv == 0:
            return 0, _w_terminal(w, WALK_ABSENT_BRANCH_TERM), 0, 0, 0
        return 0, _w_terminal(w, WALK_INCLUDED), ov, lv, 0

    # step 2: derive the index FROM THE KEY, never from an argument.
    nib = nibble_at(key, depth)

    # step 3: fetch that child, and only that child.
    arity, _o0, _l0, _k0, oc, lc, kc = mpt_descend(node, start, nib)
    if not (arity == 17):
        raise MptError("W5", "node arity is not 17 where a branch was required")

    # step 4: classify the child reference.
    if kc == KIND_LIST:
        return 2, _w_continue_depth_only(w, depth + 1), 0, 0, oc
    if not (kc == KIND_STR):
        raise MptError("W6", "branch child reference is neither empty, 32B, nor a list")
    if lc == 0:
        return 0, _w_terminal(w, WALK_ABSENT_EMPTY_SLOT), 0, 0, 0
    if not (lc == 32):
        raise MptError("W6", "branch child reference is neither empty, 32B, nor a list")
    next_expected = node[oc:oc + 32]
    return 1, _w_continue(w, next_expected, depth + 1), 0, 0, 0


def mpt_extension_hop(node: bytes, o0: int, l0: int, o1: int, l1: int, k1: int, w: W):
    depth, key_nibs, key = w.depth, w.key_nibs, w.key
    _is_leaf, n_path, nib_index = rlp_ref.hp_decode(node, o0, l0)

    # bounds FIRST (§5.3) -- prevents nibbles_equal reading past the key.
    if depth + n_path > key_nibs:
        return 0, _w_terminal(w, WALK_ABSENT_EXT_DIVERGE), 0, 0, 0
    if not rlp_ref.nibbles_equal(node, nib_index, key, depth, n_path):
        return 0, _w_terminal(w, WALK_ABSENT_EXT_DIVERGE), 0, 0, 0

    new_depth = depth + n_path
    if k1 == KIND_LIST:
        return 2, _w_continue_depth_only(w, new_depth), 0, 0, o1
    if not (k1 == KIND_STR):
        raise MptError("W6", "extension child reference is neither 32B nor a list")
    if l1 == 0:
        raise MptError("W7", "extension node's child slot is empty")
    if not (l1 == 32):
        raise MptError("W6", "extension child reference is not 32 bytes")
    next_expected = node[o1:o1 + 32]
    return 1, _w_continue(w, next_expected, new_depth), 0, 0, 0


def mpt_leaf_hop(node: bytes, o0: int, l0: int, o1: int, l1: int, w: W):
    depth, key_nibs, key = w.depth, w.key_nibs, w.key
    _is_leaf, n_path, nib_index = rlp_ref.hp_decode(node, o0, l0)

    # EXACT length -- not >=, not <=. §5.4, the module's central check.
    if depth + n_path != key_nibs:
        return 0, _w_terminal(w, WALK_ABSENT_LEAF_DIVERGE), 0, 0, 0
    if not rlp_ref.nibbles_equal(node, nib_index, key, depth, n_path):
        return 0, _w_terminal(w, WALK_ABSENT_LEAF_DIVERGE), 0, 0, 0
    return 0, _w_terminal(w, WALK_INCLUDED), o1, l1, 0


# ---------------------------------------------------------------------------
# §7.1 pure core: one supplied node, walked as far as possible (following
# inline children) before either needing a new node or reaching a verdict.
# ---------------------------------------------------------------------------
@dataclass
class HopTrace:
    """Recorded per-hop diagnostics -- §9.1 requires asserting the derived
    branch index at every hop, not just the final verdict."""
    kind: str              # "branch" | "extension" | "leaf"
    start: int
    depth_before: int
    branch_index: int | None = None  # only for kind == "branch"


def mpt_walk_node(node: bytes, w: W, trace: list[HopTrace] | None = None):
    """Returns (w_out, value_off, value_len). Mirrors
    contracts/mpt/walk.py::mpt_walk_node exactly."""
    if not (keccak256(node) == w.expected):
        raise MptError("W11", "keccak256(node) != w.expected")
    if not (w.status == WALK_CONTINUE):
        raise MptError("W12", "attempted to extend a terminal walk")

    start = 0
    steps = 0
    cur_w = w
    while True:
        if not (steps <= INLINE_STEPS_MAX):
            raise MptError("W8", "inline-descent chain exceeded 8 steps")
        arity, o0, l0, k0, o1, l1, k1 = mpt_descend(node, start, 0)
        if arity == 17:
            depth_before = cur_w.depth
            nib = None
            if depth_before < cur_w.key_nibs:
                nib = nibble_at(cur_w.key, depth_before)
            kind, cur_w, value_off, value_len, child_off = mpt_branch_hop(node, start, cur_w)
            if trace is not None:
                trace.append(HopTrace("branch", start, depth_before, nib))
        else:
            is_leaf, _n_path, _nib_index = rlp_ref.hp_decode(node, o0, l0)
            if is_leaf:
                depth_before = cur_w.depth
                kind, cur_w, value_off, value_len, child_off = mpt_leaf_hop(
                    node, o0, l0, o1, l1, cur_w)
                if trace is not None:
                    trace.append(HopTrace("leaf", start, depth_before))
            else:
                depth_before = cur_w.depth
                kind, cur_w, value_off, value_len, child_off = mpt_extension_hop(
                    node, o0, l0, o1, l1, k1, cur_w)
                if trace is not None:
                    trace.append(HopTrace("extension", start, depth_before))
        if kind == 2:
            start = child_off
            steps += 1
            continue
        return cur_w, value_off, value_len


def mpt_verify_inclusion(w: W, value_off: int, value_len: int):
    if not (w.status == WALK_INCLUDED):
        raise MptError("W17", "walk did not reach WALK_INCLUDED")
    return value_off, value_len


# ---------------------------------------------------------------------------
# Convenience: walk a full list of nodes (segmentation-agnostic -- the
# on-chain driver segments this across transactions per §7.3, but for the
# reference oracle and offline testing there is no transaction boundary).
# ---------------------------------------------------------------------------
@dataclass
class WalkResult:
    w: W
    value_off: int
    value_len: int
    value: bytes
    trace: list[HopTrace]
    nodes_consumed: int


def mpt_walk_full(root: bytes, key: bytes, key_nibs: int, nodes: list[bytes]) -> WalkResult:
    w = mpt_init_state(root, key, key_nibs)
    trace: list[HopTrace] = []
    last_node = b""
    value_off = value_len = 0
    i = 0
    for i, node in enumerate(nodes):
        last_node = node
        w, value_off, value_len = mpt_walk_node(node, w, trace)
        if w.status != WALK_CONTINUE:
            break
    else:
        i = len(nodes) - 1
    consumed = i + 1
    if w.status == WALK_CONTINUE:
        # ran out of supplied nodes mid-walk -- NOT a verdict (§6's "one
        # real trap"). Caller must distinguish this from a terminal result.
        value = b""
    elif w.status == WALK_INCLUDED:
        value = last_node[value_off:value_off + value_len]
    else:
        value = b""
    if consumed != len(nodes):
        raise MptError("W10", "unconsumed trailing node arguments")
    return WalkResult(w, value_off, value_len, value, trace, consumed)
