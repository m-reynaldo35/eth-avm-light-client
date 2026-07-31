"""
contracts/primitives/rlp/core.py -- RLP list/item header decode, single-pass
span scan, O(1) table retrieval. See docs/design/002-rlp-decoder.md §2.3, §3.

Trust precondition TP-1 (design doc §1.3): every `data` blob here is assumed
already hash-committed to a root the caller verified before calling in. This
is NOT a hardened parser for untrusted bytes -- per-item RLP canonicality is
deliberately not checked in the hot path (see the doc for why that is safe
given TP-1). Only structural bounds checks are kept, and every one of them
is a real `assert` so a malformed input aborts the transaction rather than
producing a wrong span.

`Op`-level exception (ARCHITECTURE.md, design doc §2.4): scoped to EXACTLY
the `while` body of `rlp_scan_n` below. Everything else in this file is
ordinary typed Puya.
"""
from algopy import Bytes, UInt64, subroutine, op

KIND_BYTE = 0
KIND_STR = 1
KIND_LIST = 2

MAX_ITEMS = 17


@subroutine
def _read_len(data: Bytes, off: UInt64, ll: UInt64) -> UInt64:
    """Decode a big-endian length-of-length field of `ll` bytes at `off`.
    Uses `btoi(extract3(...))` uniformly for all ll >= 1 -- one opcode more
    than a getbyte/extract_uint16 special case for ll in {1,2}, but one code
    path, which the design doc (§3.2) prefers absent a contrary measurement.

    assert ll <= 8 -> "R7". Structurally unreachable via any single
    length-of-length byte (max ll from a 0xb8..0xbf or 0xf8..0xff prefix
    byte is 8), but kept explicit per E10: "must not be UB".

    NOT forced inline (measured, §16): tried `inline=True` here and on
    `rlp_list_header`/`rlp_item_header` while adding `rlp_scan2`/
    `rlp_scan_upto` below -- it shaves ~10-20 opcodes of callsub/frame glue
    per call site, but since these three functions are now each used from
    multiple places (rlp_scan_n's hot loop duplicates its own copy already;
    rlp_table_item, rlp_scan2, and rlp_scan_upto each call the shared
    versions), forcing inline duplicates the body at every one of those call
    sites and blew gate G5's compiled size from 668 B to ~1,417 B --
    unacceptable against the 900 B target and the 8192 B per-call program
    cap (§2.3, §8.4). Kept as plain shared subroutines; the callsub overhead
    is paid once per `rlp_scan_upto`/`rlp_scan2` invocation (not per loop
    iteration), so it is a small, flat, size-preserving cost -- see §16 for
    the measured numbers with and without.
    """
    assert ll <= 8, "R7"
    return op.btoi(op.extract(data, off, ll))


@subroutine
def rlp_list_header(data: Bytes, start: UInt64) -> tuple[UInt64, UInt64]:
    """Decode the RLP list header at `start`.
    Returns (payload_off, payload_end) as absolute offsets into `data`.
    """
    assert data.length > start, "R8"
    p = op.getbyte(data, start)
    assert p >= 0xC0, "R1"
    if p < 0xF8:
        payload_off = start + 1
        payload_len = p - 0xC0
    else:
        ll = p - 0xF7
        payload_off = start + 1 + ll
        payload_len = _read_len(data, start + 1, ll)
    payload_end = payload_off + payload_len
    assert payload_end <= data.length, "R2"
    return payload_off, payload_end


@subroutine
def rlp_item_header(data: Bytes, pos: UInt64) -> tuple[UInt64, UInt64, UInt64]:
    """Decode one RLP item header at `pos` (works standalone or inside a
    list). Returns (content_off, content_len, kind).
    For KIND_LIST, content_off == pos and content_len == total encoded size
    (the span covers the whole encoding, header included -- §2.2).
    """
    p = op.getbyte(data, pos)
    kind = UInt64(0)
    if p < 0x80:
        content_off = pos
        content_len = UInt64(1)
        kind = UInt64(KIND_BYTE)
    elif p < 0xB8:
        content_off = pos + 1
        content_len = p - 0x80
        kind = UInt64(KIND_STR)
    elif p < 0xC0:
        ll = p - 0xB7
        content_off = pos + 1 + ll
        content_len = _read_len(data, pos + 1, ll)
        kind = UInt64(KIND_STR)
    elif p < 0xF8:
        content_off = pos
        content_len = 1 + p - 0xC0
        kind = UInt64(KIND_LIST)
    else:
        ll = p - 0xF7
        list_len = _read_len(data, pos + 1, ll)
        content_off = pos
        content_len = 1 + ll + list_len
        kind = UInt64(KIND_LIST)

    assert content_off + content_len <= data.length, "R2"
    return content_off, content_len, kind


@subroutine
def rlp_scan_n(data: Bytes, start: UInt64, max_items: UInt64
               ) -> tuple[Bytes, UInt64]:
    """SINGLE-PASS scan of the RLP list at `start`.
    Returns (table, n_items) where `table` holds n_items+1 big-endian uint16
    HEADER offsets: table[i] = offset of item i's first byte, and
    table[n_items] = payload_end.
    Asserts n_items <= max_items          -> "R3" (arity cap)
    Asserts the last item ends exactly at payload_end -> "R4"

    `Op`-level exception (design doc §2.4, scope 1 of 2): the while body
    below inlines `rlp_item_header`'s classification logic directly with
    `op.getbyte`/`op.extract`/`op.itob` rather than calling the subroutine
    per item (>= 17 calls of ~5 opcodes of callsub/retsub glue would be ~85
    budget of pure overhead on a full branch node). This duplicates the
    ~15-line classification block between here and `rlp_item_header`; suite
    D1 (tests/unit/test_rlp_differential.py) is the mandatory price of that
    duplication -- it asserts both paths agree on every item of every
    fixture node.

    Implementation note (measured, gate G1): the item count `n` is
    deliberately NOT carried as a separate loop-local. Puya's compiler keeps
    each mutable loop-local's stack POSITION live and reachable via
    dig/uncover/cover/swap every iteration (it has no frame-slot allocation
    for ordinary locals -- see §2.4's "let Puya place locals" rule, which
    forbids hand-managed scratch instead). A real compile of the earlier
    3-loop-local version (table, pos, n) showed n's own upkeep
    (`swap; intc_0; +; cover 2`, ~4 opcodes) plus the extra stack shuffle it
    forces elsewhere costs more than just recomputing n once, after the
    loop, from `table.length` (which is already being read for the "R3"
    bound check below, so that read is not new cost). Measured saving:
    ~3 opcodes/item. This does not close gate G1 by itself -- the remaining
    gap is Puya's stack-shuffle overhead for `table`/`pos` themselves, which
    is exactly the deferred O-2 (§9, table-free span fusion, owned by M11).
    """
    payload_off, payload_end = rlp_list_header(data, start)

    table = Bytes(b"")
    pos = payload_off

    while pos < payload_end:
        assert table.length < 2 * max_items, "R3"
        # --- emit table entry for item n: 2 big-endian bytes of `pos` ---
        table += op.extract(op.itob(pos), UInt64(6), UInt64(2))

        # --- advance `pos` past item n (hot path; ordering note below) ---
        # Real branch-node data is 100% 0x80 (empty) or 0xa0 (32-byte hash),
        # both of which land in the p < 0xb8 arm and both hit the SAME
        # branchless `pos += 1 + p - 0x80`. Test p < 0xb8 BEFORE p < 0x80 so
        # the 100%-of-real-data case is reached in the fewest comparisons.
        # Do NOT reorder to put p < 0x80 outermost (design doc §3.2).
        p = op.getbyte(data, pos)
        if p < 0xB8:
            if p < 0x80:                   # KIND_BYTE
                pos += 1
            else:                          # short string 0x80..0xb7
                # p - 0x80 is only evaluated here, where p >= 0x80 is
                # already established -- AVM `-` panics on underflow (E22),
                # so this subtraction must be, and is, structurally
                # unreachable on the p < 0x80 arm above.
                pos += 1 + p - 0x80
        elif p < 0xC0:                     # long string 0xb8..0xbf
            ll = p - 0xB7
            pos += 1 + ll + _read_len(data, pos + 1, ll)
        elif p < 0xF8:                     # embedded short list
            pos += 1 + p - 0xC0
        else:                              # embedded long list
            ll = p - 0xF7
            pos += 1 + ll + _read_len(data, pos + 1, ll)

    assert pos == payload_end, "R4"
    table += op.extract(op.itob(payload_end), UInt64(6), UInt64(2))
    n = table.length // 2 - 1
    return table, n


@subroutine
def rlp_scan(data: Bytes, start: UInt64) -> tuple[Bytes, UInt64]:
    """rlp_scan_n bound to the MPT arity cap (17 items -> 36-byte table)."""
    return rlp_scan_n(data, start, UInt64(MAX_ITEMS))


@subroutine
def rlp_table_item(data: Bytes, table: Bytes, i: UInt64
                    ) -> tuple[UInt64, UInt64, UInt64]:
    """O(1) lookup: (content_off, content_len, kind) for item i.
    Asserts 2*i + 2 <= len(table)         -> "R5" (index out of range)
    """
    assert 2 * i + 2 <= table.length, "R5"
    pos = op.extract_uint16(table, 2 * i)
    return rlp_item_header(data, pos)


@subroutine
def rlp_table_count(table: Bytes) -> UInt64:
    """len(table)//2 - 1. Provided so callers need not carry n_items around."""
    return table.length // 2 - 1


@subroutine
def rlp_bytes(data: Bytes, off: UInt64, length: UInt64) -> Bytes:
    """Materialise a span. Always compiles to `extract3` (op.extract with
    three explicit stack args) -- NEVER the immediate 2-arg `extract` form,
    whose length==0 immediate means 'to the end of the array' and would
    silently return the rest of the node for an empty RLP string (E1)."""
    return op.extract(data, off, length)


@subroutine
def mpt_node_scan(data: Bytes, start: UInt64) -> tuple[Bytes, UInt64]:
    """rlp_scan + MPT arity check: asserts n_items == 2 or n_items == 17
    -> "R6". The entry point for callers that need the FULL table and an
    explicit arity check -- e.g. differential testing (§8.3 suite D), or a
    caller that genuinely reads more than two items from one node. For the
    common single-hop MPT descent (one child, or a path+value pair), see
    `rlp_scan2`/`rlp_scan_upto` below (§16), which is what real M5/M6 usage
    is now measured against (gate G6)."""
    table, n = rlp_scan(data, start)
    assert n == 2 or n == 17, "R6"
    return table, n


@subroutine
def rlp_scan2(data: Bytes, start: UInt64
              ) -> tuple[UInt64, UInt64, UInt64, UInt64, UInt64, UInt64]:
    """Fully unrolled, loop-free decode of an EXACT-2-item RLP list (§16,
    follow-up to deferred O-2 §9): MPT extension and leaf nodes are always
    exactly 2 items, so unlike a 17-item branch node there is no index to
    skip past -- item 0 starts at `payload_off` (no walk needed at all) and
    item 1 starts wherever item 0's header+content end, which
    `rlp_item_header`'s own return value already gives directly. So the
    "single-pass walk" a 2-item node needs degenerates entirely into two
    `rlp_item_header` calls and one added assert -- no while loop, no table,
    no per-item classification loop overhead at all.

    Returns (off0, len0, kind0, off1, len1, kind1).
    Asserts item 1 ends exactly at payload_end -> "R4" (same check rlp_scan_n
    makes for the last item of any list; this is that check specialised to
    n==2). Does NOT assert n_items==2 as a SEPARATE check -- reaching exactly
    payload_end after decoding exactly two items on a well-formed list (R1/
    R2/R7 already enforced by the two rlp_item_header calls) is exactly the
    n==2 condition; a 3rd item, were one present, would make item 1 end
    before payload_end and this assert would catch it (fail-closed, same as
    R4 always has).

    `off + length` is "end of this item" for all three KIND_* values, not
    just KIND_STR/KIND_BYTE: for KIND_LIST, `rlp_item_header` returns
    `content_off == pos` (the item's own start, header included -- §2.2) and
    `content_len == total encoded size`, so `content_off + content_len` is
    still the item's end position. No kind-conditional arithmetic is needed
    here as a result.
    """
    payload_off, payload_end = rlp_list_header(data, start)
    o0, l0, k0 = rlp_item_header(data, payload_off)
    item1_off = o0 + l0
    o1, l1, k1 = rlp_item_header(data, item1_off)
    assert o1 + l1 == payload_end, "R4"
    return o0, l0, k0, o1, l1, k1


@subroutine
def rlp_scan_upto(data: Bytes, start: UInt64, want: UInt64
                   ) -> tuple[UInt64, UInt64, UInt64]:
    """Early-exit single-item retrieval (§16, implementation of deferred O-1
    §9): walks ONLY through item `want` -- items 0..want-1 are skipped past
    (same per-item classification cost `rlp_scan_n`'s hot loop pays, minus
    the table-write opcodes, since nothing is recorded for skipped items),
    then item `want`'s header is decoded and returned as
    (content_off, content_len, kind).

    Cost is O(want), NOT flat in the index -- this is the honest, explicitly
    accepted tradeoff §3.1 and §9 (O-1) describe: cheaper than
    `rlp_scan`+`rlp_table_item` for a SINGLE access at a low-or-mid index
    (measured: matches the spike's own hand-written per-item cost, see §16),
    more expensive for a HIGH index or for REPEATED access to the same node
    (for which `rlp_scan`+`rlp_table_item` remains the right choice -- gate
    G2's delta=0 is exactly that case and is untouched by this addition).

    Unlike `rlp_scan`/`mpt_node_scan`, this does NOT walk to payload_end and
    therefore does NOT learn n_items and does NOT verify the node's total
    arity (no R3/R6 equivalent) -- a caller that needs that structural cross
    -check must use `rlp_scan`/`mpt_node_scan`. Given TP-1 (§1.3: input is
    already hash-committed to a trusted root), a real MPT node is always
    exactly 2 or 17 items and this redundant check was defense-in-depth, not
    load-bearing; dropping it here is a documented, deliberate trade for the
    O(want) win, not an oversight.

    Asserts item `want` actually exists within the list's payload (does not
    walk off the end looking for it) -> "R9".
    """
    payload_off, payload_end = rlp_list_header(data, start)
    pos = payload_off
    n = UInt64(0)
    while n < want:
        assert pos < payload_end, "R9"
        p = op.getbyte(data, pos)
        if p < 0xB8:
            if p < 0x80:
                pos += 1
            else:
                pos += 1 + p - 0x80
        elif p < 0xC0:
            ll = p - 0xB7
            pos += 1 + ll + _read_len(data, pos + 1, ll)
        elif p < 0xF8:
            pos += 1 + p - 0xC0
        else:
            ll = p - 0xF7
            pos += 1 + ll + _read_len(data, pos + 1, ll)
        n += 1
    assert pos < payload_end, "R9"
    return rlp_item_header(data, pos)
