"""
contracts/primitives/rlp/bench_app.py -- measurement-only ARC4 app for
bench/rlp_bench.py (docs/design/002-rlp-decoder.md §8.4). NEVER deploy to
mainnet: every method here exists purely so a real
`/v2/transactions/simulate` response can attribute `app-budget-consumed` to
one M2 primitive, isolated from everything else. `noop` is the push-only /
dispatch-only baseline every other method's cost is measured against
(reported cost = consumed(method) - consumed(noop)).

`RlpBenchBaseline` is a second, near-empty ARC4Contract in this same file
used only to measure ARC4-dispatch overhead: compile both contracts,
size(RlpBenchApp) - size(RlpBenchBaseline) approximates the library's own
compiled-byte contribution once the router/dispatch scaffolding common to
both is subtracted out. `RlpSizeProbe` is a THIRD, tighter contract used
specifically for gate G5 (compiled size of core.py + nibbles.py +
eip2718.py <= 900 bytes): it calls every public subroutine exactly once
with no looping/marshalling overhead beyond one method's worth of ARC4
arg-decoding, so size(RlpSizeProbe) - size(RlpBenchBaseline) is a tighter
estimate of the library's own contribution than diffing against the full
RlpBenchApp (whose methods carry extra per-call ARC4 array marshalling and,
in verify_walk's case, a real loop).
"""
from algopy import ARC4Contract, Bytes, Contract, Txn, UInt64, arc4, op, urange

from contracts.primitives.rlp.core import (
    mpt_node_scan,
    rlp_bytes,
    rlp_item_header,
    rlp_list_header,
    rlp_scan,
    rlp_scan2,
    rlp_scan_upto,
    rlp_table_count,
    rlp_table_item,
)
from contracts.primitives.rlp.eip2718 import receipt_envelope
from contracts.primitives.rlp.nibbles import hp_decode, nibble_at, nibbles_equal

# Real accountProof[7] bytes (§5.3 vector 1) -- a module-level `bytes`
# LITERAL (Puya can only constant-fold a literal at module scope, not a
# `bytes.fromhex(...)` call), per algopy.Bytes's documented init rule
# ("Bytes can be initialized with a Python bytes literal, or bytes variable
# declared at the module level"). Used only by RlpSizeProbeBare below to
# exercise every subroutine without needing any ARC4 argument decoding.
_PROBE_NODE_BYTES = (
    b"\xf8f\x9d8\x02\xa7c\xf7\xdb\x87SF\xd0?\xbf\x86\xf17\xdeU\x81K\x19\x1c"
    b"\x06\x9er\x1fGGG3\xb8F\xf8D\x01*\xa0&\x18\x98\xdc\x12\xc9&\xb32\x18"
    b"\xd2\x9a\xfa\xd8\x98\xbeH~\x82\x1e\x8bDtF[b\xd8\x02\xf7\xd32\x91\xa0"
    b"\xb4O\xb4\xe9I\xd0\xf7\x8f\x87\xf7\x9e\xe4d(\xf2:*W\x13\xceo\xc6\xe0"
    b"\xbe\xb3\xdd\xa7\x8c*\xc1\xeaU"
)

# ---------------------------------------------------------------------------
# Real block-25,639,768 USDT account proof (tests/fixtures/spike-reference/
# eth_data.json proof.accountProof / stateRoot), baked in as module-level
# `bytes` literals -- the SAME methodology mpt_bench.py used (bytecblock
# constants embedded directly in the compiled program, no ABI argument
# decoding at all). This is what makes RlpVerifyWalkBare (below) the true
# apples-to-apples gate-G6 comparison against the spike's 3,276 total: the
# ARC4 `verify_walk` method on `RlpBenchApp` is a legitimate "realistic
# caller" number, but it necessarily pays `byte[][]`/`uint64[]` ABI
# array-decoding cost for receiving 8 nodes as call arguments -- cost the
# spike's own harness never paid, since it compiled the node bytes straight
# into the program. Child indices (child_indices below) were derived
# offline the same way rlp_bench.py's live derivation does: for each hop,
# find which branch slot's 32-byte child equals keccak256(next node); the
# terminal leaf's own item 1 is the account RLP value.
_ACCOUNT_ROOT_BYTES = (
    b"\xde\x97\xa84\x9ad\x9658wY\x7f\xd3W2\xf6p^\xe86\xb2\xd0\x0bl6\x7f\xa8"
    b"\xac\xd2\xc53)"
)

_ACCOUNT_NODE_0_BYTES = (
    b"\xf9\x02\x11\xa0\x94Q\xcd\xda#3\xae\xaa\xbb ?n\xd9z\x9f\t:\x83\x04g\xcc"
    b"\xa6Z\xa6\xca\x1eLO\x8b\xdc\x8b\xf6\xa0\xdd\xfb\x0f\x16\x02\xb1\xceB\x06"
    b"\xbfMq\x0e\x17\x98\xe8\x04\x9c\x88\x05~\xb5\xa8\xd5X[K\xecOx\xec\x9a\xa0"
    b"\xc2@\xe01\xb0*0\xd2a\xdf\x9d\x91\x82{\x80y\x1a\x82KAOy\xab\xf3;0\x984"
    b"\xf6<\x8e\x9d\xa0\xc9+\xec\x06E\xdb\xcb\xb2QH\xceX\xe9`\xbf\xad\xfa\xab"
    b"\n\xe6\xb83\xec\xf6\xd6\xaf=\x08\x96!\rP\xa0C\xfd\xd0\x91\x14)k\xad\xd8"
    b"\x18\xa1\xd9v\xe2m\x0f\x079\x9c\x85+\xad\xd0\x15\xa0\x7fV7\xb3\xa3\xd2R"
    b"\xa0\xd4 Z\xbe\x8e\x88h\xb5J\xe9u\x0eF\xf0\xed\x86\x0c\x8aa\xe6!F+>9\xea"
    b"0\xf8e_\x05E\xa0\x9633\xe4\x14<\xda\xd6D\x18\xe5\x80'>\xdcKu\x80\xe3"
    b"\x8c\x9c\xaep8o\x1e4\xf1\r\xc8\x04\r\xa0\x132\xad\xf1\xd9\xb5\x97}\xcfD"
    b"\xe7\xac\x99Gs\xf0\xf0\xe0!\xc7\xa0*\x1e|T\xcb\xf7\xcc\x00\xc5\xb3\x81"
    b"\xa0D\xe0\xa1`\x80R\r \x85\xddN~\xf0\x81\xe3Xk\x10\xab\x8e\xda78\xf0$"
    b"\xbe\x06z\x9a\xda\x198\xa0j/{{\xbe<\xec\x81\x9d\xf9n)\xc0/\xb00\x14\x81"
    b"K\x98\xc9\x98\xfa+\xee\xf9\xa7K\x9ci\x17\xec\xa0\x07\xea\x16p\x06?\xd1|"
    b",\xbcj\xe7\x13\x8b\xfb^\x0e<\xe2\x9c/K~r\x1d\xbdf\xa8CD\x1c\x11\xa0\xc3"
    b",\xcf:\x99R..\xdd\x9d\xe5L\x98?\xe7\xe4q\xce\xf6\xb7\xb8\xd3\xcb\xa2?'E"
    b"\xee\xce\xf6*:\xa0|\x03\x9cal\x8d\x10\xbb\xa6\xd3\xcd\x92\xdc\xeb\x1a"
    b"\xd8{G)\x8e\xc4\xe9\x9d\xad\x08\x86A\x11\x1b\xb3\x8ev\xa0\xbe\xa4\x12F"
    b"\xaa\x04x;\x9dFL1\xeba\x9b\xd5=\xd0fJ\"\xbdT\xf9\xed\n\xe2:\xecLB4\xa0"
    b"\x85\xb1|s\x04P{\xe6Z\xcc\xad\xb4*Y{\xb5\x88\xf2\x0f\xad\xda\xd6X%.\x1d"
    b"\xcf\xeb^\x83G\x8d\xa0Y\x1f\xe6\t#\xce\xa8B\xd1\n\xff2\x88\xf4\xee\xdb"
    b"agm/\xa8\xa9\x1aw\xd8\x9e\xbc&\xf5\x9f\xfc\x11\x80"
)

_ACCOUNT_NODE_1_BYTES = (
    b"\xf9\x02\x11\xa0\xe0\xcf%\x08\xf6~\xbf\x8a\xf5\x01\xc5\xe9\xfd/\xd8\x8f"
    b"S4\xb4;1\x06\xdf;u\x94k\x83U9M>\xa0<\xae\x15\x88YR\x1f\xadb\xff \xe3E"
    b"\xc2%\xdc|*I\xd6@ *j\x99\x0c\xc9k\xc5\xdbY-\xa0k\xd6b\xe7+X\xb0\x11\x00"
    b"@N`\x15S(\x0f\x95J[K}sP\x06\x89\x03'\xffF\x9b,\"\xa0\xabC|\x17\xd90\xe1"
    b"\x03\xd4\xfd\xf1\xb5\xe6\xdf]3:\xdb\xff\x1e}b1&\x13Y\xdd0\xdeu\x15\x99"
    b"\xa0\xa4\xf4\x87\xa0=\x11\xf9\x82O\x7f\xb5*<\x03\xac\xaf\xcf;\xeb\x06"
    b"\xf9nf\xd4|\xd3O\x12\xecN\x0f\"\xa0\xe7\xad\xcc\xb9\xe7K\xd1\r\x97,H"
    b"\xf3\\\xef\xc1\x14\x12\xda\xbd\x11\x81\r\xde\xde \x12N\xde\x11|$z\xa0"
    b"\xbf\xfa3\xc0~\xc1R\x84a8\xdb\x12N\x12h\rg\xc5\xb4Qd\xc8\xc6\xc3\xf4\x82"
    b"\xd3i\xc7\xb7\x91\x95\xa0\x88\xda\xa7\xf6\x01!d {\xdc#\xd0\xd3\x92\x139"
    b"z\xce\xd6\xffq\x8fA\x8f\xb1\x97\x85\xda]\xe1\xe6g\xa0&}\xc3\x08\xc0\xdb"
    b"\xd5\x19<&\xa9\xda\x89\x95\x87N\x98|\xb6r\x04\xbe\xde\x15\xb5^!W\x1f\x07"
    b"\xca8\xa0\xb6\xb8\x7f\x11R\xeaP/\x8d \x02u^\xd7\xa8\x9aE\x90ZcWQ\xbb\x93"
    b"\xdd\x99Q\td\xb3d\xe8\xa0\xd5\x87a/\xce\xd3p\n\x03\xbey\x9a\x16\xc1\xa6X"
    b"*^\xf0\xf6\x92\xfbG\xc4\xc2\xadJ\xbaZ\x92Wz\xa0ps\x0bu\xbc\xe5\xc0N\x87"
    b"/Z\x93\xd6\x87\x9d\x9c@j\x95,\xa4tFL\x04}\xeb\xb7w\xba<l\xa0\x8b\x8e\x1c"
    b"\xa9nEt\xadb\tOE\xdb\xc7\x8d\x04\xaeK\xe0\xd8\tH+\x8b\x00\xbc\x0f\xf5"
    b"\xc7\xde\xe7g\xa0\x13\xfa'\x08\x00r\xdf\x01\xfc,\xc4K\xef4\xba\xa0\xf8"
    b"\xb0(i\x07\x1c\x8f3K\xa0\xbf\xcd\xaaa\x13Z\xa0[IJ]2\xb3t_\xe3\x93/\x10"
    b"\xeb.\x8e=\xf7\xc2[\"\xc5,\xc0\xb5+\x85w\xd7\xd3\xee\x86o\xa0\x98\x111"
    b"\x98\x1e\x02n\x88\xd4\x0b\x98\x9c\xd1\xa2\xaa?{\x93\xee\xe2&\xf9\xd1@-3"
    b"\x99'\xb4\xf8W0\x80"
)

_ACCOUNT_NODE_2_BYTES = (
    b"\xf9\x02\x11\xa0\xe2U}42\x9bF\x98\xd2\\\xf2\x87,\x7f)\xc7\xf83\x99\xff"
    b"p\x1bpm\xaaI\xf0K\x8f\x03\nC\xa03}\x94\xe1\xce\xdag\x98\xb9\xd2\xa7\xab"
    b"\xd1\xa9$\xe0.\x81l\xacX(\x7f.Q\xb5\x8a\xab[a\x1e\xa4\xa0\x9e\xaf\xf0"
    b"\xcc\xfb|\x12\xc7\xb4\x0b\x1b_}x\xdc\x1d\xf7\xce\xc4\xff\xc7\xa1\xaa"
    b"\x16\x93\x99?;p@\x10\x99\xa0\xb5\xd2\xb8\x9e?\xf2\x97\xaa\xe3b\xfes\xce"
    b"9\xd9}\x9c\xb9\xc2\xdc\xd9\xeeRONn}J\xce\x05\x1e\x7f\xa0\x92\xd3\xbe"
    b"\xb7:h\x88\x9a\xab$\x85\xdb!#\x87C\xac\xe5\xe9\xfe\x97{}\xf5;g\xec\xb4"
    b"\xf9\xb487\xa0\xf3$0\x84\xdb\x7f\xe6\xf7\xb3.\xae\xa0\xb5\xc17%\xb2\xc4"
    b"!\xe5R\x1a)\xad\x0b\xd1aH\xa9\xafkK\xa0\xde\x92L\x9e\xb4\xa3\xf8\xd9X"
    b"\xd3\x86\xe0\x1d\xe8u\xc4\xc5\xc0{\xb3\xbdB\xd3z\xae\xa7q\x11\x03\xb5"
    b"\xdd\x8a\xa0\x8e\xea\xbf\x80\xeckb\xcfb\x8b\x9e\xcf\t\xb8+\x9d&\x92r"
    b"\xca(\x04\xd9p\x1e\xfbn\xdb\xa9\x11xz\xa0\xc3\x85\x92R\x89(\xb4\xba\xc1"
    b"\xc6 \xebhI\xb5\xb4\xcfg.\x1c\n\x1fl\xe1\xb4\x97\xdd~p\xf7\xf9\xa4\xa0"
    b"\xc9\xb9\x89\xf2\xf5;\xbb\x06\xa3@@\x1c\x18\xc4I\\\xa2\x88\x03\xd6\xb8"
    b"\x8d\xb5\xdc^N\xfe\xa8\x98\x0b\x94\xa6\xa0\xd0&h[\xfe\x94d&\x95@\xdc\x94"
    b"\xde\xe3$\x8a.\xae\xd6\x92\x1cs\xd2\xeeM\xc3zz\rT\x95\xce\xa0\xd9\x89"
    b"\xdeg\xecB\xf0F\xc2G\xba-\xe3\x84\x8d\xaf\xc7\x98\x07\xa4\xf3V\xac\xd7"
    b"\x9a\xb2Y\xe9\xa8a\x8f\x8e\xa0r\xc2A+3\xa8\x97\xbc\x9cs\xbd\xaf\xb6\xb5"
    b"\xc6@\x99\xc3c\xc2\x12 \x88\xf6\x05\x97\x18Q|Sy\xdb\xa05\xa6\xba|\x00"
    b"\x93\xff\x93\xd7\xba\x8a\x9e$\xfbQ\x14:\r\x9e\xfa\xd5\x9a\xb3\x8e\x8bS"
    b"\x80SAh\rY\xa0h\xce_w\xb2\xd9l\xc3$\xc7\xf5\n\xf23\xf1\xcf\x1b\xfd\xed"
    b"\xe3\xbc\xe3\xfa\xd1V\xd0\xebZ\x82#\xe3\xdd\xa0\xa0\x86\x17\xc9\\u]\xcf"
    b'\xaen"\x90\xe1\x96\x86\x1c\xa9\x10t\x89\xaai\xbb\x8a\xa7\x90\xddq\xe3'
    b"\xc1@O\x80"
)

_ACCOUNT_NODE_3_BYTES = (
    b"\xf9\x02\x11\xa0X\xc6\x8a\x9c\xd1\xe1\xaa\xf1\xf2\x9e\x18\xa5R,.\xc1,b"
    b"@EF\xa5\xa0\t\xbf\x0b\xc8g\xbbSOD\xa0\xe5\x07\x98\x8ciAr\xf5'\xc4G\xa1"
    b"\xdb\x0c\x8d\xcb\xc9[r\xbf1g\x1c\xbd_\x94\x0bM\xec\x9a8\xda\xa0\x07\t"
    b"\xa8\xe1\xa3}\x8c\x85X))\xbb\x03\xbe\x87\xb0\xb0\x8a\"\xe9\xf5\xf3R=\xa3"
    b"L\r\x16^\x1d\x87\x9d\xa0O\x98\x80:G\xa8w,\xc0`\xabB\xc2W\xca~\x83a--\xec"
    b"X\x93\xa7\xf5;i\xc1u\xc3\xb9\x93\xa06\xb1\xf2\x0fL\xb8\xf0L_\x99\x91"
    b"\xd2\xb8\xe9\rg\x11\x99\xb7\xe5\xd1\x1fN\xd3\xc6\x963\xd9\xa7OG\xd9\xa0"
    b"i\xe6qsN\x17\xde{Bke\x98\x1bD\x0f\x83\x02\xe0\xdc#\xd3\x0c\xd13\xc6\xdb"
    b"\xec\x1a\xf5\x0e\xb8\x8e\xa0\xd8D?\xb3\xc0\x1b\x8ajOa+\x9e'\xbd\xa7.o"
    b"\x9a\x91x]$\x84E\x85P\xf8\xaaD\xfc\x8c\xf9\xa0\xb3PhV\xc3\x9f\xe2\xbf1"
    b"\x99\x9b\xb4\x06\x1a\xa6GV\xc5\x05h\xe7\x17\xcb\xda\xf9ok\xaf;_\xaab"
    b"\xa0\x9bX\xf8Z\xb0\x87\xa5\xa1\x0b+G]%\x92\x87\x82r\xd2c\xcd|`bb\x11\x1d"
    b"8d\x1c\xc1\x8av\xa0\x00\xa9M\xdb\xc9,0S|h\xde<R\xbex ^\x80Wo~\xd7o\x0e"
    b"\xb7\x1c\x95n\xfd]\xd8W\xa0\x13\xc9m\xdb3\xff\x8a\xd8q\x00\xb5\x01|<lj"
    b"\xe1U3m\x9d\xbcb\x13\x14\x85\xca\x84\x9f=W\xce\xa0h\x0c\x96\xb1\xcc\x97"
    b"\x0b\xbe\x01h\xf1\xb3=H\xff\x18\"\xd9\xd3l\x02\x8c\x80\x9at\x9f\xe4~y}"
    b"\xf8\xa0\xa0n\x17\xc9\xcc\xcb\xcb_\x8a\x18\x1dv\xca\xd4\x1d\x96\x19\x8bC"
    b"q\xa8\x95\xe5\x8f\xe9\xffB?C\x14\x17\xab,\xa0\x16\x86\x86\xe0\x1b\xbeD"
    b"\x0b\x1b \x82gL\x98\xf7\xb1\xa9\xf79\x99\xc7\xe7\x98\xbf2\x8e\xed\x95"
    b"\x1aj8^\xa0\x82y\xbbh`\x17>\xc0\xe1)\xe0\x82\xfagN\xce\x00]vD\x17W\x9c"
    b"\xd4\x14\xb0\xc0!\xffvt\xe1\xa0\xb1\xc1\xf0\xc2\xb7\x91BZ`\xc6,j\xe7"
    b"\x91\xc9t\xfa\xddRY!-\xf7\xb5b0\\\xf8\x96\xa2\xe8V\x80"
)

_ACCOUNT_NODE_4_BYTES = (
    b"\xf9\x02\x11\xa0~\x9a\xf3\x07\x86\xe0\x84\r\xffTS\xd0\x16\xe2\xdc\x08@"
    b"\xd4\xa6\xc4\x9a\xa9\t4(\x8cj\xf5\xe2qj\xf7\xa0\x92l\xaf\n\xe8l_\xa1c"
    b"\xe9\xff|T\xc1so{*\x0f\x15\x83\xd4@,<n\x97(\\^\xb4^\xa0iB\xdd\xe6=\x12"
    b"\xe4\xac\xb4\xdc\x8c\xb1>\x04\xddas\xb8\xe8\xff\xf2\xa0K\x14\xbb\xbe"
    b"\x07/\x01b\xe0f\xa0\xcc\x88\x9dp\xcc\x83\x99\xfd\xa3\xf0\xd4!1Q\xaeF"
    b"\x17\x96\n\xf5\xf0\xfeWeY!#'|m\x89q\xa0\x0c\xf2l\xe7]\xa4\xb0\xfd\x9cA"
    b"0\x93\xa2\t\x8c6\xa7\xe3\x9b\x91\x9b\xf5%\xbe\x93ZG\xad\xb0\xbf\xb8\x9c"
    b"\xa0\xb5+\xf62X\x8ek7\xfbsa\x98\x92\xe9\x8e\xfd\xaa\x9f{\xd3\x01\xe8"
    b"\xa3B\xf6Fw\x8b\xf1\x0b\xed \xa0\xfc\x1a\xa5UD\x00t\x8d*.O\xe5w#\xb3\xad"
    b"3\x04\xbd\xa8`!T4lg\xa6>\xf4\xb7\x1a\x8d\xa0\x11g\xa3/n\x00\x92\xc8\x85"
    b"\x8fee\xda\r\xb0D\xe8\x8a\xe8(\x8c\xb0\xc2o&|L\x95PU\x11\xfe\xa0\x0e\xf4"
    b"g\xf5\xa9\xbcG\xacJs\xf5\x82\xd7\x91\x1d\xb1\xcc\xb5\xb9G_p\xc4\xa5\xd9"
    b"F\xff5J\x00\x03F\xa0\xad\x10\t\x05\xc4\xfd)\xd8\xe9H\x07w\x93\x7fyu\x1c"
    b"C\xd3\xbdd\xb8\xf6;\x05\xc4\x15\x1dV\x18\xd9v\xa0\xa4\x97)\x11\xeem_"
    b"\xdd\xea/\x1eP?\x88\xf6\xf4\x94/\xfd\x86\x99\xcaR\xdb\xbd[H\x85\xcc=\x1a"
    b"\x92\xa085\xc8A\xf3.\x8fd\xa1\x99\x8eg1\xe5]\xad\x8bL'+\x9e\xfe:\x9f\x8a"
    b"i\xcf\xbd\x81\xa1\x92q\xa0d\x84O\x893u\x07A\xf1;8'sI\xc2\r\xd5\xc0\xadW"
    b"P\xa7cZs\xda\xb8r\xe7\xd1j0\xa0\xfdZ\xc2\x0c\xd99\x9e\x0b\x03\xfbP&B\xf0"
    b"\xdb\xd8\xe4\x91c?\xad\xa8\xd0\xc8\xcf\xf5\x8e3W\xd2\xd4\xe0\xa0\x979"
    b"\xef\xd6\x8a0P\xb7b\xa9\x85\x1eyP\xab\xac\xf7\xbc\x8e\x00P\x0c\xe6/IJv"
    b"\x0e\xc9\xbc\x98\x8f\xa0\x08\x1a\n3\xbe\xcekCV\xf5\xf4\xcda\xd5\xd9X\xe3"
    b"\xbf\xf9\x91\xa0V\xb6!\xab\xd2G{\x7f\xf0\xb5\x1e\x80"
)

_ACCOUNT_NODE_5_BYTES = (
    b"\xf9\x02\x11\xa0i\xca\"\x94s\xc2\xb4\xa0\xda\xc5\xba\x90w\xe8Xhx\xd9\x1c"
    b"\x10[C~|\xfd\nA\xe8\x90\xb4\x98I\xa0\xf3\xfb\xeb\xcf\xf5\xe9]v\x819\xbe"
    b"x\xb51\xe0\x14\xddg\x8e\x8c\xd2\x99(Ya\xbc5\xe9\x0ck\xbcC\xa0\xce\x1f"
    b"\xb7>\x9a\xd9\xf6\xf6\x9e+\x90D\xed\x13r\xeb\x8e}v\xd4b0E\xb4\xb9(\xf8"
    b"\x9d\xc4:\xd6$\xa0r\xd0\x0c\xac\xb3\xf9k\xc9\xff\x12)\x95\x08\t\xec\xcc"
    b" l\xcd?\xaa\x84\x9b\xba$\x1c\x87\x13[\xfb\xff\r\xa0\xa2\x8d7<\x87\xeb~"
    b"\xe0\xfd\xfc\xef\xdd\x96\xdd\xa2\xcd\x96\xc5\xd3s\x17\xaa\xd7g(\xecFqvo"
    b"\xe9\x11\xa0\xe4)\x0c3`/3\xb9\xd9\x19\xdf'\x06\xadbT\xb0,\xed\x93C\x11T"
    b"W\x07\xde-\xecA4 \x88\xa0\xc7q\x12b\xde3]\x7f\xad\xb8\xd0\x14j\x8fN\xe7"
    b"\x15{U\x90\xe6\xca\xa1\xad\x19y\xf6\x04nv\x89\xf8\xa0\xc1/\xccD\xd1\tE>"
    b"hW\x83\x80\x1a\xd4\xcf\x8e0\x02:\x18\xc9\x1e/\x90\x00\x15c\xc9\xe2\xb2)"
    b"\x8f\xa0\xb6g\x1f\xbe\xd1\x82\x18\xf0\xae\x88E\x01\xe3\xbb\x80\x18\x10"
    b"WQ\xd1\x1d\x81\xc4\x8f\xbe\xc2d\xbe\x96\xf6w\xce\xa0\x85_\x10\xb0\xafOZ"
    b"\x81\x1e\xf4\xc6\xd4\r\xcf \x82JE\x98\xf1\x88T\x11\xf1\xe6H\xfb\xe7g\xfe"
    b"j\xa8\xa0\x97&y\xe8\xcdP*\x9fo^\xeb4o\xa3\xd9*\xe0\xb1\xc94\x11\xbd\rH"
    b"\xbb\xd4\x00Q\xb4@i\x98\xa0\xc8\xb5I\x15\x7fA\xe8\xda\x8bO\xe8\xeb\x90"
    b"\t\xe6\x87\x95\xa3h\xe8\xf5\x8f\x10=\xbc,\xe6\x10\xfc\x8b\x89\xb9\xa0"
    b"\xed\x13b,2\xce\x9e\x8f\x7f\xb6\x8c\xeb\x02\xd7\xf0\xe7\x91\xc0\xd8\xb7"
    b"W\x13_\x0f\x1b\xdd\x9b\t\xaaQ\xf3\xbf\xa0\x1a\x19b.\xa0e\xda\xebC\x9di"
    b"\xe8\x17x\ry%i\xea\xd6\xa6g\x99\xe2\x12\xf8K\xac\xed\xe0T\xba\xa0,CNLO"
    b"\xd9k-\x0b\x9c\x06v\x7f\x07\xa6O\xcd)e\xf9\xa2\xaa\x15\x85I)\xf9\x03\xaa"
    b"\xab?l\xa0^\xdd\x90j\xe6C+_%7y\x98o\x12\x91\xa5\x85\x8d\xc7\x16G&\x11"
    b"\xb4O\x7f\xb4\xf7/=\x11'\x80"
)

_ACCOUNT_NODE_6_BYTES = (
    b"\xf9\x01\xb1\xa0\xba\xfd\x0b\x8fM\x9anL\xce'\xa1R\x8cR,\xf8t\x97\xd5&I"
    b"<!\xef\x13XXv\xb5\xf9(\x17\x80\xa0\x857\xf2\xe2Hp*j\xe2\xa5~\x91\x10\xa5"
    b"t\x0fWr\xc8v8\x979\xac\x90\xde\xbdj\x06\x92q>\xa0\x0b:&\xa0[T\x94\xfb?"
    b"\xf6\xf0\xb3\x89v\x88\xa5X\x10f\xb2\x0b\x07\xeb\xab\x92R\xd1i\xd9(q\x7f"
    b"\xa0\x8d\x8c\xfe/Q\xb8\xe8\x8f\x81\x08\x80\xea*\xdby,@\xfa\x11T\xc9\xd4"
    b"\xc4\x98\xce=\xfen\x14\xf2\xcdE\xa0\x1e*\x1e\xd3\xd1W+\x87+\xbf\t\xeeD"
    b"\xd2\xeds}\xa3\x1f\x01\xde<\x0fKN\x1f\x04g@\x06da\xa0`\xa9\xf1\xea\xb9"
    b"\xf6/\xa72\x8cz3g\xd6\x859\xcc;\x92\xa0\x15\x80\rOZ\x11nE#\xaf\xfa\x7f"
    b"\xa0\x8cX\xd5\x1b\xfc\xb2H\xf3U\xe2\x0eH\x19\xf6\xf8\t\xbe\x1d\xee\xc1"
    b"\xe8o\x16\xe1\x08\xd144V\xbc\xb7\x0f\xa0j\x84\xf2\xcd\xb1'\xf6\xce\x8f"
    b"\xe9i\x98\x9c\x19\xbb\xfc\xd7V\x01\xe2\x8e9a\x14\x9fN\xfc\xef\xb6\x10wl"
    b"\xa0\xc8\xd7\x1d\xd1=(\x06\xe2\x86Z\\,\xfaD\x7fbdq\xbf\x0bf\x18*\x8f\xd0"
    b"r0CN\x1c\xad&\xa0\xd1\x9bl\xcch\x0e6\"\x04!c\xfd8\xbb\xa7e\xbd\x1d\x1b"
    b"\xc8qS\xfbF\x0f\xe7\xcb\xcf,\xfc\\:\xa0\xe9\x86O\xdf\xaf6\x93\xb2`/V\xcd"
    b"\x93\x8c\xcdIK\x864\xb1\xf9\x18\x00\xef\x02 :6\t\xcaL!\xa0\xc6\x9d\x17J"
    b"\xd6\xb6\xe5\x8b\x0b\xd0Y\x145(9\xec`\x91\\\xd0f\xdd+\xee*H\x01a9h\x7f!"
    b"\xa0Q=\xd5QO\xd6\xba\xd5hqq\x14A\xd3\x8d\xe2\x82\x1c\xc6\x91<\xb1\x92Ak"
    b"\x03\x85\xf0%e\x071\x80\x80\x80"
)

_ACCOUNT_NODE_7_BYTES = _PROBE_NODE_BYTES


class RlpBenchBaseline(ARC4Contract):
    """Baseline for gates G5/library-overhead: an ARC4Contract with ONLY a
    no-op method, so its compiled size is pure ARC4 dispatch/router
    overhead with none of M2's library code reachable."""

    @arc4.abimethod
    def noop(self) -> None:
        pass


class RlpSizeProbe(ARC4Contract):
    """Gate G5 probe: one method, ONE input buffer (to minimise ARC4
    arg-decoding overhead that isn't part of the library itself), reaching
    every public subroutine in core.py, nibbles.py and eip2718.py exactly
    once. size(RlpSizeProbe) - size(RlpBenchBaseline) is the tightest
    available estimate of the library's own compiled-byte contribution;
    it still includes one buffer's worth of ARC4 decoding and this
    method's own glue arithmetic, so it is an upper bound on the true
    core+nibbles+eip2718 size, not an exact isolation of it."""

    @arc4.abimethod
    def probe(self, data: arc4.DynamicBytes) -> arc4.UInt64:
        node = data.native
        p_off, p_end = rlp_list_header(node, UInt64(0))
        table, n = rlp_scan(node, UInt64(0))
        _table2, _n2 = mpt_node_scan(node, UInt64(0))
        off, length, kind = rlp_table_item(node, table, UInt64(0))
        off2, length2, kind2 = rlp_item_header(node, off)
        count = rlp_table_count(table)
        materialised = rlp_bytes(node, off2, length2)

        is_leaf, nibble_count, nib_index = hp_decode(node, off, length)
        nib0 = nibble_at(node, nib_index)
        eq = nibbles_equal(node, nib_index, node, nib_index, nibble_count)

        tx_type, r_off, r_len = receipt_envelope(node, UInt64(0), node.length)

        # §16 fast paths (O-1/O-2 follow-up): included so gate G5's size
        # estimate covers the library's full public surface, not just the
        # original table-based path. _PROBE_NODE_BYTES (accountProof[7]) is
        # a real 2-item leaf, so rlp_scan2 is a valid call here too.
        u_off, u_len, u_kind = rlp_scan_upto(node, UInt64(0), UInt64(0))
        s2_off0, s2_len0, s2_kind0, s2_off1, s2_len1, s2_kind1 = rlp_scan2(node, UInt64(0))

        total = p_off ^ p_end ^ n ^ off ^ length ^ kind ^ off2 ^ length2 ^ kind2 ^ count
        total ^= materialised.length ^ nib0 ^ nib_index ^ nibble_count ^ tx_type ^ r_off ^ r_len
        total ^= u_off ^ u_len ^ u_kind
        total ^= s2_off0 ^ s2_len0 ^ s2_kind0 ^ s2_off1 ^ s2_len1 ^ s2_kind1
        if is_leaf and eq:
            total ^= UInt64(1)
        return arc4.UInt64(total)


class RlpBenchBaselineBare(Contract):
    """Bare (non-ARC4) baseline: no selector/router/ABI-decode scaffolding
    at all, just `int 1; return`-equivalent. This isolates the library's
    compiled size far more tightly than any ARC4Contract diff can, since
    ARC4 dispatch overhead (method selector table, arg tuple decoding) is
    entirely absent from both sides of the diff."""

    def approval_program(self) -> bool:
        return True

    def clear_state_program(self) -> bool:
        return True


class RlpSizeProbeBare(Contract):
    """Gate G5's tightest available estimate: a bare Contract (no ARC4
    dispatch at all) whose approval_program calls every public subroutine
    in core.py, nibbles.py and eip2718.py exactly once against a single
    hardcoded literal buffer (no ABI arg-decoding of any kind).
    size(RlpSizeProbeBare) - size(RlpBenchBaselineBare) is the closest
    approximation this repo can produce, without a live simulate, to "the
    compiled size of core.py + nibbles.py + eip2718.py alone" (gate G5,
    <= 900 bytes) -- see bench/rlp_bench.py for the numbers this produced
    and the honest caveat that it still includes this method's own glue
    arithmetic (a handful of xors), which a real M5/M6 caller would also
    pay in some form, so it is a reasonable, not a perfect, isolation."""

    def approval_program(self) -> bool:
        node = Bytes(_PROBE_NODE_BYTES)  # real accountProof[7] (§5.3 vector 1)
        p_off, p_end = rlp_list_header(node, UInt64(0))
        table, n = rlp_scan(node, UInt64(0))
        _table2, _n2 = mpt_node_scan(node, UInt64(0))
        off, length, kind = rlp_table_item(node, table, UInt64(0))
        off2, length2, kind2 = rlp_item_header(node, off)
        count = rlp_table_count(table)
        materialised = rlp_bytes(node, off2, length2)

        is_leaf, nibble_count, nib_index = hp_decode(node, off, length)
        nib0 = nibble_at(node, nib_index)
        eq = nibbles_equal(node, nib_index, node, nib_index, nibble_count)

        tx_type, r_off, r_len = receipt_envelope(node, UInt64(0), node.length)

        u_off, u_len, u_kind = rlp_scan_upto(node, UInt64(0), UInt64(0))
        s2_off0, s2_len0, s2_kind0, s2_off1, s2_len1, s2_kind1 = rlp_scan2(node, UInt64(0))

        total = p_off ^ p_end ^ n ^ off ^ length ^ kind ^ off2 ^ length2 ^ kind2 ^ count
        total ^= materialised.length ^ nib0 ^ nib_index ^ nibble_count ^ tx_type ^ r_off ^ r_len
        total ^= u_off ^ u_len ^ u_kind
        total ^= s2_off0 ^ s2_len0 ^ s2_kind0 ^ s2_off1 ^ s2_len1 ^ s2_kind1
        return (total ^ (UInt64(1) if (is_leaf and eq) else UInt64(0))) >= UInt64(0)

    def clear_state_program(self) -> bool:
        return True


class RlpVerifyWalkBareTable(Contract):
    """Gate G6 PRE-§16 baseline: the original table-based composition (kept,
    renamed, for historical/comparison reporting -- see RlpVerifyWalkBare
    below, which is what G6's pass/fail is now judged on).

    8 unrolled hops (not a loop -- arity is a compile-time constant here,
    same as the spike's own unrolled-per-node style), each doing exactly
    what an M5 caller using the FULL-TABLE API would do: assert
    keccak256(node) == expected, rlp_scan, one rlp_table_item retrieval at
    the real derived child index, materialise the child span, chain to the
    next hop. Final hop's span is the raw account-RLP value (matching the
    spike's build_verifier 'value' step). This measured 5,302 pre-§16 --
    see docs/design/002-rlp-decoder.md §16 for why a flat full-table scan
    per hop loses to the spike's O(index) walk on this proof's low/mid
    real indices, and why RlpVerifyWalkBare (below) fixes that.
    """

    def approval_program(self) -> bool:
        # This contract takes zero call arguments (everything it needs is a
        # module-level literal), so, unlike RlpBenchBareOps, `num_app_args`
        # can't distinguish the app-CREATE call from the real measured NoOp
        # call -- both have zero args. Use `Txn.application_id` instead (0
        # on the create call, per Algorand's own idiom for this exact
        # check): the create transaction only carries the base 700-opcode
        # budget (no `extra_opcode_budget`, which is a simulate-only
        # parameter), so the full 8-hop walk below must not run at create
        # time.
        if Txn.application_id.id == UInt64(0):
            return True

        expected = Bytes(_ACCOUNT_ROOT_BYTES)

        node0 = Bytes(_ACCOUNT_NODE_0_BYTES)
        assert op.keccak256(node0) == expected, "V1"
        table0, _n0 = rlp_scan(node0, UInt64(0))
        off0, len0, _k0 = rlp_table_item(node0, table0, UInt64(10))
        expected = rlp_bytes(node0, off0, len0)

        node1 = Bytes(_ACCOUNT_NODE_1_BYTES)
        assert op.keccak256(node1) == expected, "V1"
        table1, _n1 = rlp_scan(node1, UInt64(0))
        off1, len1, _k1 = rlp_table_item(node1, table1, UInt64(11))
        expected = rlp_bytes(node1, off1, len1)

        node2 = Bytes(_ACCOUNT_NODE_2_BYTES)
        assert op.keccak256(node2) == expected, "V1"
        table2, _n2 = rlp_scan(node2, UInt64(0))
        off2, len2, _k2 = rlp_table_item(node2, table2, UInt64(1))
        expected = rlp_bytes(node2, off2, len2)

        node3 = Bytes(_ACCOUNT_NODE_3_BYTES)
        assert op.keccak256(node3) == expected, "V1"
        table3, _n3 = rlp_scan(node3, UInt64(0))
        off3, len3, _k3 = rlp_table_item(node3, table3, UInt64(4))
        expected = rlp_bytes(node3, off3, len3)

        node4 = Bytes(_ACCOUNT_NODE_4_BYTES)
        assert op.keccak256(node4) == expected, "V1"
        table4, _n4 = rlp_scan(node4, UInt64(0))
        off4, len4, _k4 = rlp_table_item(node4, table4, UInt64(13))
        expected = rlp_bytes(node4, off4, len4)

        node5 = Bytes(_ACCOUNT_NODE_5_BYTES)
        assert op.keccak256(node5) == expected, "V1"
        table5, _n5 = rlp_scan(node5, UInt64(0))
        off5, len5, _k5 = rlp_table_item(node5, table5, UInt64(6))
        expected = rlp_bytes(node5, off5, len5)

        node6 = Bytes(_ACCOUNT_NODE_6_BYTES)
        assert op.keccak256(node6) == expected, "V1"
        table6, _n6 = rlp_scan(node6, UInt64(0))
        off6, len6, _k6 = rlp_table_item(node6, table6, UInt64(8))
        expected = rlp_bytes(node6, off6, len6)

        node7 = Bytes(_ACCOUNT_NODE_7_BYTES)
        assert op.keccak256(node7) == expected, "V1"
        table7, _n7 = rlp_scan(node7, UInt64(0))
        off7, len7, _k7 = rlp_table_item(node7, table7, UInt64(1))
        result = rlp_bytes(node7, off7, len7)

        return result.length > UInt64(0)

    def clear_state_program(self) -> bool:
        return True


class RlpVerifyWalkBare(Contract):
    """Gate G6, re-pointed to the §16 fast paths (docs/design/002-rlp-decoder
    .md §16, O-1/O-2 follow-up): each of the 7 branch-node hops uses
    `rlp_scan_upto` (early exit straight to the real derived child index --
    no table, no walking past it) instead of `rlp_scan` + `rlp_table_item`
    (no table is built at all, and items after the wanted one are never
    visited); the final 2-item leaf hop uses `rlp_scan2` (loop-free exact-
    2-item decode). This is the entry-point M5/M6 callers should use for the
    "one node, one access" descent pattern that a real MPT proof walk
    actually is -- see RlpVerifyWalkBareTable above for the pre-§16 full-
    table number this replaces (5,302), and the design doc §16 for the full
    before/after measurement and the honest tradeoff (this path is index-
    dependent -- gate G2's flat-cost property is about rlp_scan/
    rlp_table_item, which remain unchanged and are still the right choice
    for repeated access to the same node).
    """

    def approval_program(self) -> bool:
        if Txn.application_id.id == UInt64(0):
            return True

        expected = Bytes(_ACCOUNT_ROOT_BYTES)

        node0 = Bytes(_ACCOUNT_NODE_0_BYTES)
        assert op.keccak256(node0) == expected, "V1"
        off0, len0, _k0 = rlp_scan_upto(node0, UInt64(0), UInt64(10))
        expected = rlp_bytes(node0, off0, len0)

        node1 = Bytes(_ACCOUNT_NODE_1_BYTES)
        assert op.keccak256(node1) == expected, "V1"
        off1, len1, _k1 = rlp_scan_upto(node1, UInt64(0), UInt64(11))
        expected = rlp_bytes(node1, off1, len1)

        node2 = Bytes(_ACCOUNT_NODE_2_BYTES)
        assert op.keccak256(node2) == expected, "V1"
        off2, len2, _k2 = rlp_scan_upto(node2, UInt64(0), UInt64(1))
        expected = rlp_bytes(node2, off2, len2)

        node3 = Bytes(_ACCOUNT_NODE_3_BYTES)
        assert op.keccak256(node3) == expected, "V1"
        off3, len3, _k3 = rlp_scan_upto(node3, UInt64(0), UInt64(4))
        expected = rlp_bytes(node3, off3, len3)

        node4 = Bytes(_ACCOUNT_NODE_4_BYTES)
        assert op.keccak256(node4) == expected, "V1"
        off4, len4, _k4 = rlp_scan_upto(node4, UInt64(0), UInt64(13))
        expected = rlp_bytes(node4, off4, len4)

        node5 = Bytes(_ACCOUNT_NODE_5_BYTES)
        assert op.keccak256(node5) == expected, "V1"
        off5, len5, _k5 = rlp_scan_upto(node5, UInt64(0), UInt64(6))
        expected = rlp_bytes(node5, off5, len5)

        node6 = Bytes(_ACCOUNT_NODE_6_BYTES)
        assert op.keccak256(node6) == expected, "V1"
        off6, len6, _k6 = rlp_scan_upto(node6, UInt64(0), UInt64(8))
        expected = rlp_bytes(node6, off6, len6)

        node7 = Bytes(_ACCOUNT_NODE_7_BYTES)
        assert op.keccak256(node7) == expected, "V1"
        _o0, _l0, _k0, off7, len7, _k7 = rlp_scan2(node7, UInt64(0))
        result = rlp_bytes(node7, off7, len7)

        return result.length > UInt64(0)

    def clear_state_program(self) -> bool:
        return True


class RlpBenchBareOps(Contract):
    """Bare (non-ARC4) per-operation benchmarking harness, deliberately
    mirroring mpt_bench.py's raw-argument style (no ABI method dispatch, no
    ARC4 tuple/array encoding overhead) -- ARC4Contract methods (RlpBenchApp
    below) carry real per-call ABI marshalling cost (selector match, dynamic
    array length-prefix + offset-table decode per `arc4.DynamicBytes` /
    `arc4.DynamicArray` argument) that is NOT part of what design doc gates
    G1-G4 measure: those targets trace to the spike's bare-TEAL harness,
    which read raw application args with no ABI wrapper at all. Using this
    bare harness for G1-G4 keeps the comparison against the spike's
    62/318/542/480 numbers apples-to-apples; RlpBenchApp's ARC4 numbers are
    still reported separately since a real M5/M6 caller MAY go through ARC4
    dispatch, but they should not be read as the subroutines' own cost.

    Dispatch: application_args(0) is a raw big-endian uint64 selector.
    Every other arg is a raw byte string / big-endian uint64, no ABI
    encoding at all -- exactly `Txn.application_args(i)`, optionally
    `op.btoi`'d.
    """

    def approval_program(self) -> bool:
        if Txn.num_app_args == UInt64(0):
            return True  # app-create call carries no args -- allow it
        selector = op.btoi(Txn.application_args(0))
        if selector == UInt64(0):
            return True  # noop baseline
        if selector == UInt64(1):  # scan(node)
            node = Txn.application_args(1)
            _table, _n = rlp_scan(node, UInt64(0))
            return True
        if selector == UInt64(2):  # scan_and_get(node, index)
            node = Txn.application_args(1)
            index = op.btoi(Txn.application_args(2))
            table, _n = rlp_scan(node, UInt64(0))
            _off, _length, _kind = rlp_table_item(node, table, index)
            return True
        if selector == UInt64(3):  # scan_two_items(node, i0, i1)
            node = Txn.application_args(1)
            i0 = op.btoi(Txn.application_args(2))
            i1 = op.btoi(Txn.application_args(3))
            table, _n = rlp_scan(node, UInt64(0))
            _o0, _l0, _k0 = rlp_table_item(node, table, i0)
            _o1, _l1, _k1 = rlp_table_item(node, table, i1)
            return True
        if selector == UInt64(4):  # hp_decode(node, off, length)
            node = Txn.application_args(1)
            off = op.btoi(Txn.application_args(2))
            length = op.btoi(Txn.application_args(3))
            _is_leaf, _nibble_count, _nib_index = hp_decode(node, off, length)
            return True
        if selector == UInt64(5):  # nib_eq(a, a_nib, b, b_nib, count)
            a = Txn.application_args(1)
            a_nib = op.btoi(Txn.application_args(2))
            b = Txn.application_args(3)
            b_nib = op.btoi(Txn.application_args(4))
            count = op.btoi(Txn.application_args(5))
            _eq = nibbles_equal(a, a_nib, b, b_nib, count)
            return True
        if selector == UInt64(6):  # receipt_envelope(data, off, length)
            data = Txn.application_args(1)
            off = op.btoi(Txn.application_args(2))
            length = op.btoi(Txn.application_args(3))
            _tx_type, _p_off, _p_len = receipt_envelope(data, off, length)
            return True
        # --- arg-shape baselines (no RLP primitive call at all) ---
        # `noop` (selector 0) only reads the selector itself, so subtracting
        # it from a gate's cost also bakes in that gate's OWN
        # `Txn.application_args`/`op.btoi` argument-reading cost, which is
        # harness plumbing, not the subroutine's own cost, and grows with
        # the number/type of arguments a gate's call shape needs (worst
        # case: nib_eq's 5 args). These selectors read the SAME argument
        # shape as the corresponding gate call and do nothing else, so
        # `cost(gate) - cost(matching baseline)` isolates the primitive's
        # own contribution from that per-call argument-marshalling tax.
        # See bench/rlp_bench.py's "isolated_cost" fields.
        if selector == UInt64(7):  # baseline shape for scan(node) [G1]
            _node = Txn.application_args(1)
            return True
        if selector == UInt64(8):  # baseline shape for scan_and_get(node, index) [G2]
            _node = Txn.application_args(1)
            _index = op.btoi(Txn.application_args(2))
            return True
        if selector == UInt64(9):  # baseline shape for scan_two_items(node, i0, i1) [G3]
            _node = Txn.application_args(1)
            _i0 = op.btoi(Txn.application_args(2))
            _i1 = op.btoi(Txn.application_args(3))
            return True
        if selector == UInt64(10):  # baseline shape for nib_eq(a, a_nib, b, b_nib, count) [G4]
            _a = Txn.application_args(1)
            _a_nib = op.btoi(Txn.application_args(2))
            _b = Txn.application_args(3)
            _b_nib = op.btoi(Txn.application_args(4))
            _count = op.btoi(Txn.application_args(5))
            return True
        # --- §16 fast paths (O-1/O-2 follow-up) ---
        # scan_upto's call shape (1 bytes + 1 uint64) matches selector 8's
        # baseline exactly, and scan2's (1 bytes) matches selector 7's --
        # reused rather than duplicated.
        if selector == UInt64(11):  # scan_upto(node, want) -- new G1 candidate
            node = Txn.application_args(1)
            want = op.btoi(Txn.application_args(2))
            _off, _length, _kind = rlp_scan_upto(node, UInt64(0), want)
            return True
        if selector == UInt64(12):  # scan2(node) -- new G3 candidate
            node = Txn.application_args(1)
            _o0, _l0, _k0, _o1, _l1, _k1 = rlp_scan2(node, UInt64(0))
            return True
        return True

    def clear_state_program(self) -> bool:
        return True


class RlpBenchApp(ARC4Contract):
    """One method per measured operation (§8.4's per-operation isolation)."""

    @arc4.abimethod
    def noop(self) -> None:
        """Push-only / dispatch-only baseline -- every other method's cost
        is consumed(method) - consumed(noop)."""
        pass

    @arc4.abimethod
    def scan(self, node: arc4.DynamicBytes) -> arc4.UInt64:
        """Full single-pass scan of a node starting at offset 0 (gate G1:
        a real 17-item 532-byte branch node <= 300 budget)."""
        _table, n = rlp_scan(node.native, UInt64(0))
        return arc4.UInt64(n)

    @arc4.abimethod
    def scan_and_get(self, node: arc4.DynamicBytes, index: arc4.UInt64) -> arc4.UInt64:
        """Full scan + one O(1) retrieval of item `index` -- drive with
        index in {0, 8, 15} to measure gate G2:
        cost(scan_and_get(15)) - cost(scan_and_get(0)) <= 10."""
        table, _n = rlp_scan(node.native, UInt64(0))
        off, length, kind = rlp_table_item(node.native, table, index.native)
        return arc4.UInt64(off + length + kind)

    @arc4.abimethod
    def scan_two_items(self, node: arc4.DynamicBytes, i0: arc4.UInt64,
                        i1: arc4.UInt64) -> arc4.UInt64:
        """2-item ext/leaf scan + both items (gate G3: <= 90 budget)."""
        table, _n = rlp_scan(node.native, UInt64(0))
        off0, len0, _k0 = rlp_table_item(node.native, table, i0.native)
        off1, len1, _k1 = rlp_table_item(node.native, table, i1.native)
        return arc4.UInt64(off0 + len0 + off1 + len1)

    @arc4.abimethod
    def hp(self, path: arc4.DynamicBytes) -> arc4.UInt64:
        """hp_decode cost in isolation."""
        _is_leaf, nibble_count, _nib_index = hp_decode(
            path.native, UInt64(0), path.native.length)
        return arc4.UInt64(nibble_count)

    @arc4.abimethod
    def nib_eq(self, a: arc4.DynamicBytes, a_nib: arc4.UInt64,
               b: arc4.DynamicBytes, b_nib: arc4.UInt64,
               count: arc4.UInt64) -> arc4.Bool:
        """nibbles_equal cost -- drive with aligned vs. misaligned indices
        for gate G4 (aligned 57/56-nibble leaf paths <= 20 budget, flat in
        length)."""
        return arc4.Bool(nibbles_equal(a.native, a_nib.native, b.native, b_nib.native,
                                        count.native))

    @arc4.abimethod
    def envelope(self, data: arc4.DynamicBytes) -> arc4.UInt64:
        """receipt_envelope cost in isolation."""
        tx_type, _off, _len = receipt_envelope(data.native, UInt64(0), data.native.length)
        return arc4.UInt64(tx_type)

    @arc4.abimethod
    def verify_walk(
        self,
        nodes: arc4.DynamicArray[arc4.DynamicBytes],
        child_index: arc4.DynamicArray[arc4.UInt64],
        root: arc4.DynamicBytes,
    ) -> arc4.DynamicBytes:
        """Suite F / gate G6 composition smoke test: re-run the spike's
        account/storage path end to end using M2's primitives in place of
        the spike's RLP_ITEM_SUB, with keccak256 hash-chaining supplied
        here (not by M2 -- M2 never calls keccak256, TP-1). For each node i:
        assert keccak256(nodes[i]) == expected; expected = the materialised
        span at child_index[i] of nodes[i] (rlp_table_item after one
        rlp_scan). The final node's span at its child_index is returned
        (the leaf's raw account-RLP or raw storage-value bytes, matching
        the spike's build_verifier 'value' step). This is a benchmarking
        scaffold for measuring an in-situ M2 composition against the
        spike's 3,276/6,827 totals -- it is NOT account/receipt semantic
        decoding (that is M6/M7's job).

        KNOWN LIMITATION (not an M2 defect): the real account proof is 8
        nodes totalling ~3.87 KB; algod enforces a protocol-level cap on
        total ApplicationArgs bytes per transaction (observed: 2048 B on
        this localnet) that is independent of `extra_opcode_budget` and
        cannot be raised from the client side. Calling this method with the
        full real account proof therefore fails with "ApplicationArgs
        total length is too long" before a single opcode of M2's code runs
        -- this is a call-argument-transport ceiling, not an RLP-decoding
        cost. `bench/rlp_bench.py` reports this as a hard failure (not a
        budget number) and uses `RlpVerifyWalkBare` below -- same node
        bytes, baked in as compiled-in literals instead of call arguments,
        so no ApplicationArgs are needed at all -- for gate G6's actual
        pass/fail measurement."""
        expected = root.native
        result = Bytes(b"")
        for i in urange(nodes.length):
            node = nodes[i].native
            assert op.keccak256(node) == expected, "V1"
            table, _n = rlp_scan(node, UInt64(0))
            off, length, _kind = rlp_table_item(node, table, child_index[i].native)
            result = rlp_bytes(node, off, length)
            expected = result
        return arc4.DynamicBytes(result)
