"""
contracts/mpt/bench_app.py -- measurement/reference apps for
bench/mpt_bench.py (docs/design/005-mpt-walker.md §8.4, §9.6) and for the
live segment-hand-off tests (S7/S8, §9.3). NEVER deploy to mainnet: M5 is a
library (§1.2), and everything here exists purely so real
`/v2/transactions/simulate` and real submitted-group numbers can be
attributed to M5's own subroutines, isolated from everything else --
exactly bench_app.py's role in contracts/primitives/rlp/.

Contracts:
  - `MptBenchBaselineBare` / `MptSizeProbeBare` -- a first-pass gate G5-M5
    probe (M5 surface only, diffed against a contentless bare baseline).
  - `MptSizeProbeCombinedBare` -- the probe gate G5-M5's pass/fail is
    actually judged on: calls the SAME M2 subroutine set
    contracts/primitives/rlp/bench_app.py's own `RlpSizeProbeBare` calls,
    PLUS M5's full public surface, so diffing against `RlpSizeProbeBare`'s
    own measured size isolates M5's incremental contribution "on top of
    M2's 839 B" the way §2/§8.1 actually specify it (see
    `MptSizeProbeBare`'s own docstring for why a plain baseline diff
    double-counts the M2 subset M5 happens to call).
  - `MptWalkBare` -- gate G6-M5, the headline number: a complete, key-bound
    account inclusion proof (real USDT address + 8 real account-proof
    nodes, all baked in as module-level literals, zero ABI/argument-
    decoding cost) measured against the spike's insecure 3,276.
  - `MptReceiptWalkBare` -- gate G1-M5: the real 3-node receipt proof,
    same bare/baked-in methodology, against the spike's 1,121.
  - `MptSegmentApp` -- the real §7.3 segmented, raw-args, group-internal
    walk driver. Used live for gate G4-M5 (hand-off verification cost),
    G7-M5 (a real submitted group demonstration), and S7/S8 (the live
    honest-hand-off-passes / forged-hand-off-rejected pair). See
    bench/mpt_bench.py and the implementation report for what these
    measured in practice, including the honest gaps.
"""
from algopy import Bytes, Contract, Txn, UInt64, itxn, log, op, subroutine

from contracts.mpt.handoff import mpt_log_state, mpt_state_from_prev
from contracts.mpt.state import (
    W_LEN,
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
)
from contracts.mpt.walk import mpt_verify_inclusion, mpt_walk_node
from contracts.primitives.rlp.bench_app import (
    _ACCOUNT_NODE_0_BYTES,
    _ACCOUNT_NODE_1_BYTES,
    _ACCOUNT_NODE_2_BYTES,
    _ACCOUNT_NODE_3_BYTES,
    _ACCOUNT_NODE_4_BYTES,
    _ACCOUNT_NODE_5_BYTES,
    _ACCOUNT_NODE_6_BYTES,
    _ACCOUNT_NODE_7_BYTES,
    _ACCOUNT_ROOT_BYTES,
    _PROBE_NODE_BYTES,
)
from contracts.primitives.rlp.core import (
    mpt_node_scan,
    rlp_bytes as rlp_bytes_m2,
    rlp_item_header,
    rlp_list_header,
    rlp_scan,
    rlp_scan2,
    rlp_scan_upto,
    rlp_table_count,
    rlp_table_item,
)
from contracts.primitives.rlp.eip2718 import receipt_envelope
from contracts.primitives.rlp.nibbles import hp_decode as hp_decode_m2
from contracts.primitives.rlp.nibbles import nibble_at as nibble_at_m2
from contracts.primitives.rlp.nibbles import nibbles_equal as nibbles_equal_m2

# Real USDT address (tests/fixtures/spike-reference/eth_data.json
# proof.address) -- the PREIMAGE, since M5 derives the key on-chain (§4).
_ACCOUNT_ADDRESS_BYTES = b"\xda\xc1\x7f\x95\x8d.\xe5#\xa2 b\x06\x99E\x97\xc1=\x83\x1e\xc7"

# Real receiptsRoot + 3-node receipt proof (index 31), same block.
_RECEIPTS_ROOT_BYTES = (
    b"d\x90'\x7fBT\xf8\xd5\x17\x80\xf0R\x01\xc5\xa9\xa9\x98Z]L= zh\xed\xa6C\xdc\t\x9eq\x0b"
)

_RECEIPT_NODE_0_BYTES = b"\xf9\x011\xa0\x98-)mdt\xf20K\xe6&\x9e\x1bbh\xa0\xfcl\xe6\xa4\x15\x7f\xc6\xfd\x8f\xb5\xeer\xc4*\xfa\x9a\xa0<\xc6\xf5]u\xd0x\xea@+\xaa\x9eK\x7f%'L)\x04\xd5\xdf\xa2'\xf0\xbe\xb4\xd8G^\x93\x07?\xa0\xd6\xff\x13\xff\xf9\xf7G\xe5\x9c\xd5W\xd1Z\xcd\xd4\xb3\xb7\x9e\\p|\xe5\x87]g\x90\x85\x16o\xb8\xaf0\xa0\xb9\xab\x1f\x1d\xb4\x98>CJ2\x0f\xecc.\r\x97`\t\xb7Y+\xd7\xa1\x9d_\xd3k\xff\xdf\xf3\x81\x06\xa0-\xc8\xcfJa\xd9\xae\xc1\x03\xf4A~\xb9@\x11ar\xcd\xd0\xf46]0\xff\xa6\xe9\xdcnG\xd24\x12\xa0\xfb\xa4'\xac\x97\xde\xfc.\xc7Ob\xbc\x9abE#<h)N\x91Q\xf6?\xfb\x96\xa8e\xc8\xac\xd7\xaf\xa0\xb7D\x0f;\xf6\xd8\xf6\xcc\x06\x87\xd6\x0f\x01c\x04\xc2\x04B9\xdb&i\xc2\xa4.w\x80\xd1`o\xbc\xdb\xa0=$\xe2\xd6a\xc8\xf8\xc9\xd9*\xb4r\xae\xf3\x1d\xf2\x01\x91\x91D\xdc\xc8\xa4\x8acF\xa3\xc7(\x0e\xad-\xa0\x15*\x9a\n\xc4 \x82\n\x7f\xb9\xfck\xe1\xe6g-\xae\x14O\x08\x8d\xb2\xa8)\x1e\x9b\xbf\xd1\x15\x17\x9d\x06\x80\x80\x80\x80\x80\x80\x80\x80"

_RECEIPT_NODE_1_BYTES = b'\xf9\x02\x11\xa0\xa9\xa1\xf1\x0chkC\x15#J\x14\x7f%\x94^_:T\x01\xdd\xe3\xfa^jy\xda\xb2\xe6\xa6>\xb9\xea\xa0]\x8a\xed\xee_k\xff\'d\tC\'\x85oy\x820\xad\xf6\xf3\xd2E\xb7\xc5@Fk{\x01\x17>\xc7\xa0\xb2QFx\xc0W\x9a\x18\x13.\xf6|\xc9Z\xf4\xd3\ti)\x00\x89J\xcaI\xfb_)\x00\xbb\xc2\n\x88\xa0\xcbg\x10\xfe\xcf+{\xfb\x0f\x82o\x18.\x16:\xc2\xa0v\xabB\xbf\xa6\x8fJ\xd0\x861\x9fq\xb3\xady\xa0\xb8A\xb5\x13a\x9c\x03\t\x0b\xc9\x84D(\xab6\t\xcf\xe2tp\x98\xdb[+y\xc0\xe2\xe7\x08\x16E;\xa0\\\xdd\xe6\xb9EB=\xd4-\xa4cG\x03\x96\xd7\xe4\xf6\xa4\x0b\x04m\x0f!3N\x05\xf5\x1cp\'\x9fy\xa0+\x82H\xd1\x9e\xfbG\xcf\x03|\xe4a[\x13v\xd4\x93\x84\xf7\xdf\xc0\xb572\xcc\xa4>s,\xf7`\x97\xa0\x87+\x91G\x9b\xcb\xbao\xc4\x11\xd9\xff\xed\xe5\x16\x9aw\xd5S\x1e\x13/#\xfao\x0e\xc4W\x80iZj\xa0\xe5\'\x94\xae[\xedA\xd2\x1fR\xaaW\xc1\x98\xf8M\xa2N\xccA\xfdT\x93\'\xee.\xe5\xc0Na\xacR\xa0\xa9=\x8e\xae\x9e\x93\x8ct\xb8\xe4\x82#\x9f\xe40\x94\xf0(\xdc\xe9!%A\x7f\xce\xbd\xdc\xc2i\xb2\x02P\xa0RS\xd4\xd7\xe7wn\x98\xe6\xf8*\xc6\x8c\\\x87S\xdaBG\xef\xc7\x17\xac\xf8\xeb\x91mY\xa5\x0fTy\xa0\xe1\xaeQ\xbd\\FMw\xe0\x91\xca\xb6"\xaeA\xcf\xe8\x083\x8c\x97G\x9b\x04VKDEv8\xfd\xc2\xa0\xbe]\x19{\x9bT\xb23?\x19c9\x7f\x98\xf2\x8bgQ\x0f6\x10\xcf\x13j\xee\xb9\x1cKI\x01\xf7\x1a\xa0\x11\xce\x0f+L\x97p\x14\x1b\xb6%\x81\x12N\x87?\xb5p\xd6\xf10\x07.Ps\xed\xf2e\xdd\x84\xd2\xac\xa0\xb6\x12\xd0A\xa8\x85C\xc8W\xa5g\xf2\xeb\x91"\xde\xc8\xdc^\xeb\xb1\xb2\x14\x01u\xe9zMpj\x07 \xa0\xce3\xd0l3q?\xff\xf5\\\x05\xfd5\xdf3)\xea\xaf\xbb\x03\xfc\xcfD\xc1\xbbI\xd3/\'\xcd\xce\x10\x80'

_RECEIPT_NODE_2_BYTES = b'\xf9\x02\xaf \xb9\x02\xab\x02\xf9\x02\xa7\x01\x83o\x1c\xbb\xb9\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x08\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x01\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x10\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x02\x00\x00\x00\x00\x00\x01\x00@\x00\x10\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x000\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00 \x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf9\x01\x9c\xf8\x9c\x94\xc7\xe6wb\x82\x1b.\xd6\xc0\xa1\xf4#T{(\x99\x82-\x86P\xf8\x84\xa0\xdd\xf2R\xad\x1b\xe2\xc8\x9bi\xc2\xb0h\xfc7\x8d\xaa\x95+\xa7\xf1c\xc4\xa1\x16(\xf5ZM\xf5#\xb3\xef\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00w\xe9\x1f\xdf\x00\xf5(!\x87\xbe\x90\x96\xdb\xd0\xdcD\x02\x82\xd4c\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb2v\xf6-\xb0\xce\x8c\xa2\xca[\xc5"i[\xe6\x04R\x1e\xac\x1c\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00/\xe4\x80\xf8\xfc\x94\xb2v\xf6-\xb0\xce\x8c\xa2\xca[\xc5"i[\xe6\x04R\x1e\xac\x1c\xf8c\xa0\x86\x84\t\x8d\xea\x97\xbe\xbcc\x8d\xe0DZ\xeez<\xd3\x92\x9b\xb8\x9a\xf1\xad\xd5g\x03\xb5\xb7!\';O\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01r\xad\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00w\xe9\x1f\xdf\x00\xf5(!\x87\xbe\x90\x96\xdb\xd0\xdcD\x02\x82\xd4c\xb8\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc7\xe6wb\x82\x1b.\xd6\xc0\xa1\xf4#T{(\x99\x82-\x86P\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00/\xe4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04)\xd0i\x18\x9e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x87;X'


class MptBenchBaselineBare(Contract):
    """Bare baseline: no reachable contracts/mpt code at all."""

    def approval_program(self) -> bool:
        return True

    def clear_state_program(self) -> bool:
        return True


class MptSizeProbeBare(Contract):
    """Gate G5-M5: one method, one hardcoded literal buffer, every public
    contracts/mpt subroutine reached exactly once, zero ABI decoding.
    size(MptSizeProbeBare) - size(MptBenchBaselineBare) is the upper-bound
    estimate of contracts/mpt/'s own compiled-byte contribution, mirroring
    RlpSizeProbeBare's methodology exactly (contracts/primitives/rlp/bench_app.py)."""

    def approval_program(self) -> bool:
        addr = Bytes(_ACCOUNT_ADDRESS_BYTES)
        root = Bytes(_ACCOUNT_ROOT_BYTES)
        key = mpt_key_from_address(addr)
        w = mpt_init_state(root, key, UInt64(64))
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_0_BYTES), w)
        status = w_status(w)
        log = mpt_log_state(w)
        total = status ^ voff ^ vlen ^ log.length
        return total >= UInt64(0)

    def clear_state_program(self) -> bool:
        return True


class MptSizeProbeCombinedBare(Contract):
    """Gate G5-M5, measured the way §2/§8.1 actually specify it: M5's OWN
    incremental compiled-byte contribution "on top of M2's 839 B" -- i.e.
    size(this) - size(RlpSizeProbeBare) (contracts/primitives/rlp/bench_app.py's
    own gate-G5 probe, 843 B / 839 B over its own bare baseline, already
    measured). This contract calls the SAME M2 subroutine set
    RlpSizeProbeBare calls (so that part of the diff is zero) PLUS every
    public contracts/mpt subroutine, so the remaining diff is M5's own
    code alone -- unlike diffing against a contentless baseline, which
    would also count the (smaller) subset of M2 code M5 happens to call
    itself, double-billing bytes M2's own gate already paid for."""

    def approval_program(self) -> bool:
        node = Bytes(_PROBE_NODE_BYTES)
        p_off, p_end = rlp_list_header(node, UInt64(0))
        table, n = rlp_scan(node, UInt64(0))
        _table2, _n2 = mpt_node_scan(node, UInt64(0))
        off, length, kind = rlp_table_item(node, table, UInt64(0))
        off2, length2, kind2 = rlp_item_header(node, off)
        count = rlp_table_count(table)
        materialised = rlp_bytes_m2(node, off2, length2)
        is_leaf, nibble_count, nib_index = hp_decode_m2(node, off, length)
        nib0 = nibble_at_m2(node, nib_index)
        eq = nibbles_equal_m2(node, nib_index, node, nib_index, nibble_count)
        tx_type, r_off, r_len = receipt_envelope(node, UInt64(0), node.length)
        u_off, u_len, u_kind = rlp_scan_upto(node, UInt64(0), UInt64(0))
        s2_off0, s2_len0, s2_kind0, s2_off1, s2_len1, s2_kind1 = rlp_scan2(node, UInt64(0))

        # --- M5's own FULL public surface (contracts/mpt/__init__.py's
        # __all__), each called once -- matching M2's own RlpSizeProbeBare
        # convention exactly, so this is the true full-library number, not
        # just what one usage path happens to reach. ---
        addr = Bytes(_ACCOUNT_ADDRESS_BYTES)
        slot = Bytes(_ACCOUNT_ROOT_BYTES)  # any 32-byte value, only shape matters here
        root = Bytes(_ACCOUNT_ROOT_BYTES)
        key = mpt_key_from_address(addr)
        _key2 = mpt_key_from_slot(slot)
        _key3 = mpt_key_from_tx_index(UInt64(31))
        w = mpt_init_state(root, key, UInt64(64))
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_0_BYTES), w)
        status = w_status(w)
        _root_field = w_root(w)
        _expected_field = w_expected(w)
        _depth_field = w_depth(w)
        _key_nibs_field = w_key_nibs(w)
        _key_field = w_key(w)
        walk_log = mpt_log_state(w)
        if status == UInt64(WALK_INCLUDED):
            _vi_off, _vi_len = mpt_verify_inclusion(w, voff, vlen)
        else:
            _vi_off, _vi_len = UInt64(0), UInt64(0)
        if Txn.group_index > UInt64(0):
            _prev_w = mpt_state_from_prev(UInt64(0), Bytes(b"XXXX"))
        else:
            _prev_w = w

        total = p_off ^ p_end ^ n ^ off ^ length ^ kind ^ off2 ^ length2 ^ kind2 ^ count
        total ^= materialised.length ^ nib0 ^ nib_index ^ nibble_count ^ tx_type ^ r_off ^ r_len
        total ^= u_off ^ u_len ^ u_kind
        total ^= s2_off0 ^ s2_len0 ^ s2_kind0 ^ s2_off1 ^ s2_len1 ^ s2_kind1
        total ^= status ^ voff ^ vlen ^ walk_log.length
        total ^= _key2.length ^ _key3.length ^ _depth_field ^ _key_nibs_field
        total ^= _root_field.length ^ _expected_field.length ^ _key_field.length
        total ^= _vi_off ^ _vi_len ^ _prev_w.length
        if is_leaf and eq:
            total ^= UInt64(1)
        return total >= UInt64(0)

    def clear_state_program(self) -> bool:
        return True


class MptWalkBare(Contract):
    """Gate G6-M5, the headline number: a complete, key-bound account
    inclusion proof over the real USDT address and the real 8-node account
    proof, entirely baked in as module-level literals (the spike's own
    bytecblock-constants methodology, mpt_bench.py) -- zero ABI/argument-
    decoding cost, so the number traces to M5's OWN work, not ARC4 or
    raw-arg marshalling. Measured against the spike's insecure 3,276."""

    def approval_program(self) -> bool:
        if Txn.application_id.id == UInt64(0):
            return True

        address = Bytes(_ACCOUNT_ADDRESS_BYTES)
        root = Bytes(_ACCOUNT_ROOT_BYTES)
        key = mpt_key_from_address(address)  # on-chain keccak256(address) -- §4.1
        w = mpt_init_state(root, key, UInt64(64))

        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_0_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_1_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_2_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_3_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_4_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_5_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_6_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_7_BYTES), w)

        assert w_status(w) == UInt64(WALK_INCLUDED), "V1"
        return vlen > UInt64(0)

    def clear_state_program(self) -> bool:
        return True


class MptReceiptWalkBare(Contract):
    """Gate G1-M5: the real 3-node receipt proof (tx index 31), on-chain
    RLP-encoded key derivation included. Measured against the spike's
    insecure 1,121."""

    def approval_program(self) -> bool:
        if Txn.application_id.id == UInt64(0):
            return True

        root = Bytes(_RECEIPTS_ROOT_BYTES)
        key = mpt_key_from_tx_index(UInt64(31))  # on-chain minimal-RLP encode -- §4.2
        key_nibs = UInt64(2) * key.length
        w = mpt_init_state(root, key, key_nibs)

        w, voff, vlen = mpt_walk_node(Bytes(_RECEIPT_NODE_0_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_RECEIPT_NODE_1_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_RECEIPT_NODE_2_BYTES), w)

        assert w_status(w) == UInt64(WALK_INCLUDED), "V1"
        return vlen > UInt64(0)

    def clear_state_program(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# MptSegmentApp -- the real §7.3 segmented, raw-args, group-internal walk
# driver. ONE raw 4-byte selector identifies "this app's segment-walk
# method" for every segment (§7.3's args table describes a single uniform
# layout for "a segment call"; init-vs-resume is a MODE byte, not a
# different method -- this is what lets mpt_state_from_prev's selector
# check work uniformly regardless of whether the predecessor was the first
# segment or a later one: every segment, including segment 0, used the
# SAME selector).
#
# Args (raw, always):
#   arg0 = SEGMENT_SELECTOR (4B)
#   arg1 = mode (1B): 0 = INIT (this is segment 0 -- build W from a fresh
#          preimage+root), 1 = NEXT (resume from a predecessor's log)
#   arg2 = donor_count (8B big-endian uint64) -- §16.3: number of no-op
#          inner app-call donors (M1 §9.1 / M4 §16's pattern) this segment
#          issues BEFORE doing any walk work, purely to raise the group's
#          pooled opcode budget (§7.6's named escape hatch, wired up in
#          this pass). 0 is valid and free (no itxn issued at all) --
#          most segments don't need any; the caller sizes this per segment
#          from a prior `simulate` reading, exactly like a relayer would
#          in production.
#   arg3 = donor_app_id (8B big-endian uint64) -- the SEPARATE, pre-
#          deployed, minimal callee app donor calls target (the AVM
#          forbids an app calling itself via inner transaction, "attempt
#          to self-call" -- discovered empirically in this pass). Ignored
#          when donor_count == 0. Must be present in this transaction's
#          `apps` foreign-app-reference array whenever donor_count > 0.
#   mode 0: arg4=key_kind(1B: 0=address,1=slot,2=txindex),
#           arg5=preimage (20B/32B, or 8B big-endian tx index),
#           arg6=root(32B), arg7..=proof nodes (>=1)
#   mode 1: arg4=predecessor group index (8B big-endian uint64),
#           arg5..=proof nodes (>=1)
# Every mode logs its resulting W via mpt_log_state (§7.4).
#
# Donor callee: the AVM forbids an app issuing an inner call to ITSELF
# ("attempt to self-call", a structural anti-reentrancy rule -- discovered
# empirically in this pass; DONOR_SELECTOR is kept only as a marker of the
# intent, MptSegmentApp does not actually dispatch on it). Donor calls
# instead target a SEPARATE, minimal, pre-deployed callee app (§16.3),
# exactly the spike's own probe_inner.py pattern ("Deploy a trivial callee
# app. Then ... issues N inner app-calls to the callee") and exactly what
# `MptBenchBaselineBare` already is (a 4-byte `return True` program) --
# reused here as the donor callee rather than deploying yet another
# contract, since it is already the cheapest body in this file and already
# gets deployed for G5-M5's size probe.
# ---------------------------------------------------------------------------
SEGMENT_SELECTOR = b"MPT1"
DONOR_SELECTOR = b"DON1"
MODE_INIT = 0
MODE_NEXT = 1

KEY_KIND_ADDRESS = 0
KEY_KIND_SLOT = 1
KEY_KIND_TXINDEX = 2


@subroutine
def _issue_donors(n: UInt64, donor_app_id: UInt64) -> None:
    """§16.3: issue `n` no-op inner app calls to a SEPARATE, pre-deployed,
    minimal callee app (`donor_app_id`), purely to raise the atomic
    group's pooled opcode budget by ~700/call (M1 §9.1's "the heavy call
    issues N cheap no-op inner app calls purely to raise the pool, then
    runs ... in a single program with a single accumulator" -- M4 §16's
    `donor()`/`noop_budget()` is the same pattern). `donor_app_id` must be
    present in this transaction's `apps` foreign-app-reference array (the
    caller's responsibility, exactly like any other cross-app reference).
    fee=0 means each inner txn's fee is pooled from THIS call's own fee
    (the outer txn must be funded to cover n extra min-fees -- the
    caller's responsibility, exactly like the spike's probe_inner.py sized
    sp.fee = (n_inner + 1) * min_fee)."""
    i = UInt64(0)
    while i < n:
        itxn.ApplicationCall(
            app_id=donor_app_id,
            fee=UInt64(0),
        ).submit()
        i += UInt64(1)


@subroutine
def _walk_remaining_args(w: Bytes, first_node_arg: UInt64) -> Bytes:
    """Walk every remaining raw application arg (from `first_node_arg` to
    Txn.num_app_args - 1) as a supplied node, in order, stopping early if a
    terminal status is reached; asserts any trailing UNUSED node arguments
    are rejected (§6's W10 -- strictness about which nodes a verdict rests
    on). Returns the final W."""
    n = Txn.num_app_args
    i = first_node_arg
    cur_w = w
    while i < n:
        assert w_status(cur_w) == UInt64(WALK_CONTINUE), "W10"
        node = Txn.application_args(i)
        cur_w, _voff, _vlen = mpt_walk_node(node, cur_w)
        i += UInt64(1)
    return cur_w


class MptSegmentApp(Contract):
    """NOT a production app (§1.2) -- reference driver only, for measuring
    and testing §7.3/§7.4's mechanism live."""

    def approval_program(self) -> bool:
        if Txn.application_id.id == UInt64(0):
            return True
        if Txn.num_app_args == UInt64(0):
            return True

        selector = Txn.application_args(0)
        assert selector == Bytes(SEGMENT_SELECTOR), "V2"
        mode = op.btoi(Txn.application_args(1))
        donor_count = op.btoi(Txn.application_args(2))
        donor_app_id = op.btoi(Txn.application_args(3))

        if mode == MODE_INIT:
            key_kind = op.btoi(Txn.application_args(4))
            preimage = Txn.application_args(5)
            root = Txn.application_args(6)
            # §16.3: issue donors BEFORE any real work -- the pool must
            # already be raised by the time the walk starts consuming it
            # (M1 §9.1's ordering).
            _issue_donors(donor_count, donor_app_id)
            if key_kind == KEY_KIND_ADDRESS:
                key = mpt_key_from_address(preimage)
                key_nibs = UInt64(64)
            elif key_kind == KEY_KIND_SLOT:
                key = mpt_key_from_slot(preimage)
                key_nibs = UInt64(64)
            else:
                index = op.btoi(preimage)
                key = mpt_key_from_tx_index(index)
                key_nibs = UInt64(2) * key.length
            w = mpt_init_state(root, key, key_nibs)
            final_w = _walk_remaining_args(w, UInt64(7))
            log(mpt_log_state(final_w))
            return True

        assert mode == MODE_NEXT, "V3"
        prev_gi = op.btoi(Txn.application_args(4))
        _issue_donors(donor_count, donor_app_id)
        w = mpt_state_from_prev(prev_gi, Bytes(SEGMENT_SELECTOR))
        final_w = _walk_remaining_args(w, UInt64(5))
        log(mpt_log_state(final_w))
        return True

    def clear_state_program(self) -> bool:
        return True
