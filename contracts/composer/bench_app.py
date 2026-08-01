"""
contracts/composer/bench_app.py -- design doc §6: the real segmented,
raw-args, one-atomic-group M6 driver (`Mpt6ComposerApp`), plus
measurement/reference apps for `bench/composer_bench.py`, mirroring
`contracts/mpt/bench_app.py`'s role for M5 exactly. NEVER deploy to
mainnet: like M5, M6 is a library (no root-anchoring policy of its own,
§13.2 -- that is M8's), and everything here exists purely so real
`/v2/transactions/simulate` and real submitted-group numbers can be
attributed to M6's own subroutines.

Contracts:
  - `Mpt6BenchBaselineBare` / `Mpt6SizeProbeBare` -- gate G5-M6 probe
    (M6 surface only, diffed against a contentless bare baseline).
  - `Mpt6SizeProbeCombinedBare` -- what G6-M6 (the deployable-program-size
    gate) is actually judged on: M2 + M5's own full public surface PLUS
    every public `contracts/composer` subroutine, so the diff against
    M5's own `MptSizeProbeCombinedBare` isolates M6's incremental bytes.
  - `Mpt6ComposerBare` -- the bare, baked-in, single-transaction, zero-ABI
    full composite: the real USDT/Binance-8 account+storage proof (17
    nodes total), walked end to end (phase A -> bridge -> phase B ->
    storage-value normalisation) with no segmentation and no argument
    marshalling at all -- the "two-walk floor + bridge overhead" number,
    measured the same way `MptWalkBare` measured M5's headline G6-M5.
  - `Mpt6ComposerApp` -- the real §6 segmented driver: SEGMENT_SELECTOR
    `"ACS1"`, a 1-byte mode (`MODE_A_INIT`/`MODE_A_NEXT`/`MODE_B_INIT`/
    `MODE_B_NEXT`), raw app-args exactly per §6.3's table, one atomic
    group. This is the contract G2-M6 (a real, non-simulated 5-transaction
    submission) and the §5.4 security tests (S-M6-2/3/4) exercise live.
"""
from algopy import Bytes, Contract, Txn, UInt64, itxn, log, op, subroutine

from contracts.composer.account import mpt6_account_body, mpt6_storage_value
from contracts.composer.bridge import (
    EMPTY_CODE_HASH,
    EMPTY_TRIE_ROOT,
    mpt6_bridge_account,
    mpt6_bridge_storage,
)
from contracts.composer.handoff import (
    ARC4_RETURN_PREFIX,
    LOG_LEN_M6,
    SEGMENT_SELECTOR,
    mpt6_log_state,
    mpt6_result_from_group,
    mpt6_state_from_prev,
)
from contracts.composer.state import (
    C_ABSENT_ACCOUNT,
    C_ABSENT_SLOT,
    C_ABSENT_SLOT_EMPTY_TRIE,
    C_INCLUDED,
    C_LEN,
    C_PENDING_ACCOUNT,
    C_PENDING_STORAGE,
    C_ZERO_ENTRY,
    PHASE_A,
    PHASE_A_OK,
    PHASE_B,
    PHASE_DONE,
    c_address,
    c_awalk,
    c_balance,
    c_code_hash,
    c_cstatus,
    c_nonce,
    c_phase,
    c_slot,
    c_state_root,
    c_storage_root,
    c_swalk,
    c_value,
    c_with_phase,
    mpt6_init_composite,
)
from contracts.mpt.state import (
    W_LEN,
    WALK_CONTINUE,
    WALK_INCLUDED,
    mpt_init_state,
    mpt_key_from_address,
    mpt_key_from_slot,
    w_root,
    w_status,
)
from contracts.mpt.walk import mpt_walk_node
from contracts.primitives.rlp.core import rlp_scan_upto
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
)

# Real USDT address (tests/fixtures/spike-reference/eth_data.json
# proof.address) -- the PREIMAGE (M6 derives the key on-chain, TP-M6-2).
_ACCOUNT_ADDRESS_BYTES = b"\xda\xc1\x7f\x95\x8d.\xe5#\xa2 b\x06\x99E\x97\xc1=\x83\x1e\xc7"

# Real storage slot preimage (Binance-8's balance slot under USDT's
# `balances` mapping, eth_data.json storage_key) and the real 9-node
# storage proof + storageHash for that slot, same block.
_STORAGE_KEY_BYTES = b"\x0b\xe1mq\x964) MpT7\x01\xf8Y\xc45&\xc3\x16\xac\x00\\\x10\x11OF\x94\xca@_6"
_STORAGE_ROOT_BYTES = (
    b"\x26\x18\x98\xdc\x12\xc9\x26\xb3\x32\x18\xd2\x9a\xfa\xd8\x98\xbe"
    b"\x48\x7e\x82\x1e\x8b\x44\x74\x46\x5b\x62\xd8\x02\xf7\xd3\x32\x91"
)

_STORAGE_NODE_0_BYTES = b'\xf9\x02\x11\xa0w\xde\x06\x1f\x80[-\x05`\xf8\x15\xd9\xc0\xd4x\xceR\x12\x05\x9b\x14\x158>l\xfb\xeb7\xebQ\x07!\xa0\xc1;VQWw\xe3/\x04\xeda\xff\x1a\x8e\xcb\x15m\xa9&\xa021\xe2\x80\xea<\xc6\x14\x9c{\x10v\xa0\xff\x05\x8f\x17w\x8ce>\xe4\x0c\xfe\xc4\x86\x91\t\x0f\x89\xd3\xb1<\x89,\x9b\xe80\x9f\xa4\xceq\xfb\xbcg\xa0\x10*\xb9I5\x14\xecf"`\xca\xa8f\xa1\xf1\xbc\xf2D\x06\x87]O\xf4\xd4.\xee\xfe\x14\xa8\xa5!)\xa0\xb3\xdd}A\xdb\x81Dp\x19\xbd~\x86\x1b\xca&\xf7\x95\xe5G\xd6PJ\xbd\x89\xaf}\x1a\xb38\xa6\x80\x89\xa0\x16\x1c\xdd6\xa0\'w\xab\xff\xb7\xf2r<M\x9c\xb6\x8f\x8c(g\xfc\xf5v\x89\xba\x05\x15&\x1en\xf1S\xa0\t#\xa8\x8c\xdc\t7Xnw\x0cT\xaa^8\xf5\xc5n\xc6R\xccb"c\xf5HB\xf5\xb2\x17\xd7\x00\xa0m\xc3\xe53\xcf\xfd,\t\xdb\xb1\xd9,Q\x8a\xba2\xcc\x07\x19\x0e\x19~l\x95\x82\xfd\xd7\xa0I\x80\xb9\xa4\xa0\xc97\xd7\x84\xbf\xe9~+*\xe3\x126V\xb4e\x0e\x91\xeak\xa3F\xa7@R%\x03K"\xe5\xffo\xc9\xa0\xf1X\xd5&\xd9\xc3d265\xf5\x928\xd1\xfb\x03\x90\xa2,\x85NB]~\xa8\xeb\xce\xfbd\xdd\x9aP\xa0\xde\x15D\xc3\xc8I\x7fBX\xcd\xae\xf5\xb0~\t\x9b\xf9\xbd[%yp\xb8u\x8cX\xa1\xd5\xf5\xac\x18j\xa0-l\x07\xb0\xab\xb2)\xa8\xa9\xcb\x19\xe0\xed\xd0\\\x8a\xc01%\xdd\x16\xfd\xd7\n\x98\xff\xb2tZ\xb4\x9d0\xa0\xed\xbdS\xf5~\xf4?\xf1/\xe88X\xe7\x0e\xdecP\xa9.K%J\xd5D(E\xd4\x15\x9cK\xb7\x00\xa0\x82\xe0EP",02\xcf.\xa8@\x87A\xc4\x08\xee\xe2\rU\xdb\xa2p\xcb\xa04\xeaC\xdd\xa7T\x81\xa0\x93\xfaP\xdf\xd7\xd1\xe5S\xc7\x1eiz[pw\x03\x0e\r]!\x943\xb2\x88 \xf1\x8eiu|m\x94\xa0E&<M~\x11\xb7\xe9\xae\xc0\xe7\xf1\xc4\x07Ge<\x8b\xaa7`\xb6i\xa5\x97\xb2\xefv\x9f\xb8\x00\xb1\x80'
_STORAGE_NODE_1_BYTES = b'\xf9\x02\x11\xa0|9\xcd\xa2\x11\x0e\xebw\x1f\xf0\x10\xb8eQ\x9f\xe0\xf3/\xf4ot>\x08\x19f\xb4E\xf4U\xb2\xee\x8a\xa0\xb44\xdaV6\xd6tO\x10\x1b9\xfe.\x84\xbb\x1cMD\rI37A~\xc8\x8fd?\xd5\xff\xda\xa0\xa0\xea\x83k\xd4l}\xd2\x05\x12\x94\xbe\x93\xeb?S\xe2\x90\x14k\x9013\xa7c\x04\x91<\x94\xc2\r\x16\x91\xa0\x13\xff\xf1+\xb6q\xaay\x89Jfg\x9f}"_\x83\xc0F\xae=I\xda(]\xb3\xf9\xcd\xc2\xbd]\x1b\xa0#\x1d\xf8T\x04&\xa7\xb3\x8f\x0b\xfe9\x14\xa4~\x17\x08\x80\x01/=\x02\x14#\xd9\xc6\x84\xbeY|#;\xa0mO\x86^\x86\x0cf\xd9\xe7Nds\xa1\xb2\xfe(\xb1\x03d\x93\xe2o9\xce&\x93\xb7\xf4\x82\xeeJ\x85\xa0\x8d\xba\x1f\xd8\xe8\x1d\xe3\x85m\xe4\xd8\xf1^\x06\x1c\xd4\xe4B\x8d\x1e0\xf8wZkv\x1a\xcf\xcc\x02VF\xa0)\xc8\xb3\xff\r\xae\x00^\x90\xe9\x88(\x83\x89t\x94\xf4-Ah\xda\xff\x8e\xdaqT\xc9\x0f\xb9$\xff\x1d\xa0\xc3{\x96@@\xaf77\x93\x9b\x9a\x7f,D\xc5\xd0\x7f\x7f\t\xe8\xbb\xdfI\xcd\xd9J\xf4\xdb\xbf\xf5N\x1f\xa0\x11\x18\xfd\xc5q\xbe\xfe1\x18b&A|\xbf`\xb6\x9cJes\xe7\xa6\x92\xc4\xf0hV\xb1\xbf\x82)\xcf\xa0\xd8\xcd\x13\xac\x83\xc1%a\x92P\xfc{\x1f\xa2\xe6\xae\x8eL\tnE\x176\xf0#L\x8ct7sXq\xa0\x16\xb4:\x7fAx\xedxL\xefg*y\x85\xb8>\x85\'\x9a\xff\xf6\xfe\x81\xe5YVK\xc0\xb0\xf1\xbd\t\xa0\x19h1\xd0?\xcfi\xdc6\xfb\x9f\xdeI\xae\x0c7\xebX\xd6\xc94!\xb6\xa6\xeb\x839)"A\xcas\xa0\xd6\x08\nLtW\x91\xdf\xb5X\x02\xc1KL\xfb\xf5v<.\xeb\xf3\x12\xe1Ve\xb0\x97\xf3\xa1\x17f\x1b\xa0}!\x7f1l\xa7uV<\xcbg\x15{XL\xca#2V\x98=\x98\xe4\x9e\xff\x94}\xc8\xaf\x99N[\xa0\x88\x96|.D\xc5O\x18\x82)\xd2\xdfcP\xfb/Z\xe1\x08\x96\x97E>@5\xbaE\xf1\xcc\x96\x07*\x80'
_STORAGE_NODE_2_BYTES = b'\xf9\x02\x11\xa0h2\x8a!\x8cy\xd3\xf0%%.EB\x1dP\x8d\xd3?(\xf6\xd6\x8e\xf2\x065\x05g\xcf\xf00\xf3\xfa\xa0`\xc0\xcd\xf6ho \x86\x90\x9a\xbd@\x85\x15\xff5\xa9H\xa7\xd4\xf46J\xac\xe7\xfb@\xd4\x11\r\xf8}\xa0g\xf5\x8dE\xe2u\x1a\x1d*{\xfdv\x14\x87V\x9a<5\x0c\xbf\x10X)\x82^\xcb\xcca+1r\x8c\xa0vq{\xab\t\t\'\xc0\xf6~I\xcf`K2\x8b\xbfl\xc2D>$g\x8cw\xd6\x1a*i"\xc5\x94\xa0\x9b\xe9\x1d\xc0h\n(\x11+F\x1e\x7f\x10[\xd2\xe4\xfc\xc3\x0f}=\xbdH4\xa5\x1e<\x10\xcc92q\xa0\xb6Z9\x97\xa0G\xb4\xee\xd2 \x1c\x1e\xae\xeb\xca\xd6B\x82\xb2l5\x83T\xaaC\x914\x05\x82\xfc\xc6j\xa0}\xfc\xae)\xe7\x8a\x11H`g\xfc\xa2\xc8\x0e\xfe^\x93\xd8\xdbc\xd3s\xb0\x7f )(fp\x08\xd4\xe0\xa0\x84\x1b\x1c\xdd\xcbZ\xab<\xe7u%\'o\xef4c\xc8H)^\\\xc6/]\x05%u1R\xde\xa5\x8b\xa0\x8a\x87(:\xaf\xb6\x01\xbd\x18\x1e\x80\x02\xde\xa7\xa3\xce\xfb<\xb6\xcbPG)\xe3\xd06\x04\xdd\xf9\x11\x00i\xa0\\[\xfaj7\xcb\x00&-\xae\x01u~\x02\xedP\x90\x0c)\xca.\xf7\x86W3\xf9\xfeJ\xad5)\x12\xa0\xf5\x16"m\xda\xbdty-\x06/\xf0\xaf\xfc\xe4\x0bki\x93\xda\xddn|\xd14\x87\xf6]\x98\x07\xb7\xfc\xa0\xf1\xd0\x04\x92\x90!\xbc\xe1\xe4\xcf\xfe\x9d]\xc4\x10\x8c\x80\x8a4\xdf\xefV\r\x8c)J\xf7\xeb\x12\xce\x92\t\xa0\t\x8e\xe7\xbb\x0e\xfcf\xffEa\xfcd\x9d~\xb2B\x18e\xc8\xcb6\xc7\xea\x14\x9b\xeb^=vcjK\xa0n\xe3W\x8e\x17\x8c\xc4\x83\xdc"K\x02\xd8t\xb7X\x94a4\x1e\x8a\xc2\xb0\xc3\x19\x0e\xfdY\x85\xf8j\x00\xa0]\xbes\x8d\xd1\x8c\xbbT\xcd\xbfU\x96\x92\xc05Hs$\n&\xf8m}\xa8P[\xaeO\xa8Z\xb0\xc9\xa0*\x03\x06\x193,\xf8\x103\xad\xbe\xd7L\x96\xb4E\xfehM\xf9\x11\x8e3H\xa4\x18\xd4\xa4\xec\xa0\n\xae\x80'
_STORAGE_NODE_3_BYTES = b'\xf9\x02\x11\xa0!{T\xf8\x9b\x11\x91(\xfa9\xff^\xbd\xa2}*\xe9\xc2\xa3+L\xfd\xbb\xfcK\xd4B\x1d\xf4\x0f\x9b1\xa0\x8e\xd9\xc6\x8b\xe6\x1c\x9a\xa0\xeb\xb5\xa2\xa8H\xbd0\x1e0\xb5"\xef\xd4h\xcf\x04\x9a\x13\xa7\xcbx\x93A\xfd\xa08\xbbG\xd7\x19/Hd9\x8e^\t|\xc3(\'\xac\x02\xde\r\xf2-\x06\x9d\x9aH\xe9\xfdI\x10\xeck\xa08\x7f\xed\xc0\xa98\xc2\x9fK\xd9\xcb\xd7;\xb7\xb7\x96K}?\xf1c\x99)\xdd\x19\x01\xc7P\xd7\x07^\xe8\xa0\xa9a(\xe2\xb6\x17\x89[G2\xfc\xf0\x0b\'\xbb\xaa\x0b3\\\xbe\x98\r\xad\x9a\x9a\x84\x10D\x90\xd6o\xb9\xa0D\x17\xcd\xa4\xd5H\x13\xd1\x1a\x85q\xa3s\x1d\xe4\xa4\x80\xb4\xdeM&%7\xb8X\xd1j\x14A^\x95d\xa0\x80<\xf8\xf3\x88?i\xb3\xb5`\x86\xfaP#~\x00F \x03G\xf5g\xe7\xf3\x88\x9c\x9b\xa6\x01se\x1e\xa0\xa2\x0f\xe2d\x9ez\xcdkg\xf1\xcb\x14\xd2\x8c~\x05\xa6Ar\x02\xa4\xf6\xd5\xb5\xcaBS\x00\x9fo\xc1\xa6\xa04[\xdbp\xa5j(p\x884\xa4&x\x8d\x80[\xd1\xeea\x0b\xda\xb4Jd1\x8eZ\x91\x9b\x15\xc1\xfa\xa0\x00\x93(\x97\x03\x1a\xd8X\xbe\xd9{X\xc7\xd4\xb3\xcd\xb3F;\x03\x1bB"X*[\xb3\xcd\xea\xc6\x0b\xa5\xa0\xca\x05\x8c\xb0\x9d\xb5\x7f6h%\xf1n\x12?\xbf\xfe\xc3se\xc4\n\xaa\xa4\xc1\xa7\xc8\x01R\xe9N\xe6\x01\xa0\xe3\xe0v\x0b\x9c4\n_\x86\xcbzr\xa7\x089\xa3\xcd6\x0b\x94\xe3yg\'\x16/\x83\x8a\xd3\\ %\xa0\xc3\xd8\xcbf\x9b\xf1#\x82\x9axw\x94&\xd2\xb2\xc9\xec`\xe4\xd9\x95\xf6\xf4\x19\x14k\x06?\x85\xf4\x00\r\xa0\xecf\x8f\xea\xb3D\x15o"\x89\xaeX\xe5K1\xb6\xb7\xdc6K\xd2\xfen\xcc\xf8\x07Wak\xe5\xb1u\xa0\xef\x19\x84=\x83\xb5v\x80\xc7\xa5N\x89hq`\x9a~\xd8_j\xcf\xd4\x9b\x89\xad\xd1\xb3_\xe0a7e\xa0l\xc6z\x06\xa4\xe71\xad(\xa5\xb2\xee\xca\xc6\xb5Z\xd29\xb3\x97\x8b\xc8Kk\xce\xf4h\n5\xb9\x90F\x80'
_STORAGE_NODE_4_BYTES = b'\xf9\x02\x11\xa0\x8b+j\xcc\xaa\x8es7\x8bW\xf0`\xd7\x12N\xef\x16![i\x0c\x97\x0c5\x96\xc7\xf9L\x0fLa\xc8\xa0\xd6gD\xbf\x87\xf7m\x9cQ(|\xc3\x00\xcc\xb8\x89AG\\\xb5\xa8\x9a\x95\x1f\x87\x00\xde\xbbn\x10n\xf3\xa0\xbe\xdf\x1e\xfa-Z\xd0\xda\x98;\xadv\x83\xd9"\xfe\x99\xba\x85H\xc4?=\xbb\x06\x1a\x00\x9e\xbe\xa1\xe9\xe1\xa0\xb0\xa5\x1d]h\xed\xf0Y\x8b\x0f\xc62\x9c\xd4I\xd3\xd8\xcai\x86\xee\xe5n\x99ti\xbf\x05\xc5\'\xfd\xd4\xa0\xc3|\xcbQ\xaf\x02\x89\x19x\xb6[,\x12Z\x96*\x8b-\x1d\xa1PH\xf7;\x92\x16\x1e\xf9#\xbaT\x0c\xa0\xfa\xafB\x80\xac\xab\xdc\x04j\xd9\xb6\xfd\xc4\x92\xf6S\xf2y\x05\xf5\x15q\xfa\x99\x94X\x1az\xed\xcc\xfe\xeb\xa01t\x11\x90\xe1p\xad0\x9a\n\xfa\x95\xde\xc2\xc7\x9a\x16\xe5\x8e\xd8;\x1c\x05\xc9\xfb\x81\xc9?\xd6\x0f\xc3h\xa0:\x8f7\xebZnr\xc0Ei\x8eM\xb1\x01\x04b\x05\xc8{Ac\xf3\x0en"k\x9f%%;\x89\xc3\xa0/\xa1\xd7\xacn\x15\\m\xd4\xdd\xbf7=\xbf\xdf\x14\x85Hv\x04\x9c\x07\x0bh\xdc\x84\xf6\x8d\xa4e\x99\xbb\xa0D\xec\xb4\xe3\x87\x93\x841~_1\x0f|\x0b\xbf\x99\xb0\x02\xe7\x94\xd1\x97y\x1biG\xeb\xafB2\xf2\xae\xa0\xc6\xed\x18\x02\xe2\xf0\xe0e\xf4\x9d\xa5f\xa5\xe7\xd1\x01\xa4-\xf1\x93\xa3\xed\xf08\xd1\xda\'\xa3\x8a\x12\x9aG\xa0\xce\x7f\\g}f\x9c-s?l\x16\xc1\x92=\xeb\x85\x9eFXd\x91k\xf6qm\x82\xa6\xfd\xf8c\'\xa06Cz\x10dC\xbb\xe2.T\xfa\x99\x8aD=\xf6Y!\xb3\xac\xdeu\xa5\t6\xc5!\xa7*\x16V\xfd\xa04o\x04\x1a#2\x0c\xe5\'N\x02\xdeH\xee*V\x1bG\x97\xf7QBJ\x1d\x1c,\x90\xe9\x9f;\xf6}\xa0%u\x84\xbe\xc8|\xc4\xe2\xd3\xdd\x8a\xd6J\x93\xdc9\x00\xdc\xbc\xe5\xdc[\xa8.\xb1\xb5\xb8\x9ck\xd0j\xb1\xa0{\xa8\xed&u\x0cN}h\xb1{]{\xd6O\xa7\x1d\xeb\xe1g\x08\x91V\xbc\x9a\xc4\xf4\xf9#\xd7\x8a\x8f\x80'
_STORAGE_NODE_5_BYTES = b'\xf9\x01\xd1\xa0\x1dJ\x8e\xe3\xaf\x14j\x916d\t\xc1\xe2\xc5\x9bEi\xac\x87/v\xadFw\xc83z\x1f>\x12 \x11\xa0\'\xf0F\x91\xa9\xa3\xbd\xbc{]\r\xf0\xb3\x89\x13\x1d\xe4\\\xf92\xcf\xceM\xa1\x82\'\xc3\xc2?8\x16\x1a\xa0\x9cx\\\x01\xa8\xbaU\xe5E4\x89\xe9Q\x1eJ\x18\xea\xabpk\xc7\xed\x85|\xdeQn\x86rY\x94C\xa0p\xcc\x0f\xdf\xbb\x9a\xbf\xb5\x0e.\xa9\x93\xd8\xebu\x9auxR\xab\x0c\xad\xfcm\x02\xbcz\x9f\xd0\x89)q\xa0\xb3P\x06\xe3\x9b\xc0\x82\x1b\r6\x07T\x04mYW\x1c3\xff\x01b\xc7\xceF\x05yx\x8c\xbfK\xcf\xb1\xa0\xffOO\xb8\r\x8e\xec\xf4k4\x8e\x93\x92DW\x05\x91\xf0\xb0\xbe\xa4\x10\xaf\x88k\x0f\x1c\xd5\x03F\'\xb0\xa0\xd6$\xbeY\x15\x1c\x7f\xec\x94\x06(\xa0\xa8\x19\xecpU\xc4\x89N\xa6\xaf\x0e\x0b\x8a\x03\x02\xbf\xe5\n\x02\xcc\xa0\xb0\xd4#2\x12\x92\xca7\x8e(0\xd5K\x90\x87\xb6\xbf\x8dN-\xb0\xc4\x97\x90\xd7\x9e\xc46\x15\xd8(\x0c\xa0H\xb2MT6Z\x0e\xe9\xf2\xcf;md\x0c\x9c\xa8\xe1\x8ee\x1c\xa5\xc0\x81[\xb0\x88\xe6\xad \xbaK\\\xa0I\x1e\x1b\xa5\xbb\x87OK\xcf\xa1\\\x99\xbd?\xf0P$\x97\xbf_\xb6w<T\xfes\x81\x8d\xc7\xa6\x87\\\xa0\xa4\x0cp\x1e:<-\x88\xf6\xc2j9\xe0X\xe0\xa3{\xa6|\xb6\xdb"\xf0x\xb1\xb9\xab\xec\xf0\xb7\x95\xe4\xa0)X\xdc\xaf\xd1\xef\xdc\xa3\xeei\xbc\xc2\x7f\xc4\x89mu\xf2B\x9e^vl\xd3\x83\xfa\x11f\xb4#\xaf\xa1\xa04G\xf9\xf5\xefN\xe0\x14\x12\xd4w\xa9.\x88\x8a\xaa9\xb6\x87\xcf{\xcfg\xeb\xe1\xeb\xc7\x87>\x8a(\x14\x80\x80\xa098r\x85\x1f\xa9\xc3\xae/\xe1\xef\xe3T>\xc1\x94\x1e\xb8\x95.\x98\x11\xcf\xaf\xee\xd3)N\xa1SLg\x80'
_STORAGE_NODE_6_BYTES = b'\xf8Q\x80\x80\x80\x80\x80\x80\x80\x80\x80\xa01^"Xx\xd1$\xadt\xa2(\xbd\xc9\xf8.\x0e\x8b\tc\xa0\xb8\xd3\x91\xebT\xb4\x84\xba\xadSj\xcf\x80\x80\x80\xa0\x14\x9eHA\x15\xcb\x89,\x0e{*\xfcf\x9bsE:\xefq>\x8b\xd1\xa5*=\xed\x9f\xfa\xf9\x9as\\\x80\x80\x80'
_STORAGE_NODE_7_BYTES = b'\xf8Q\x80\x80\x80\x80\x80\x80\xa0HR\xd1\xc9\xc0y\xb3\xb5\xb1\x0f\xe1\xbd\x87\x9a\x9eBT\xa0\xe1\xfa\xb1)\xe1\x16\xca\xf0?\xc8\xb4\xfckK\xa0Z\xc0G\xcdxo\x87\x98\x93(n\xb4\x13\xcc(\xeb\xe1\x8aAj\xf7\x05\x86\x1d\xf4_\xc9e\xcc\x19\xcdt\x80\x80\x80\x80\x80\x80\x80\x80\x80'
_STORAGE_NODE_8_BYTES = b"\xe7\x9d #fx:O\xc9\x0eR\xc8\xccY[\xa9\xfd+'\x8b\xc5\"H\x11|\x14\xc0~S\x94\xd8\x88\x87?\x1c\xa11\x08\x1c\xf8"


class Mpt6BenchBaselineBare(Contract):
    """Bare baseline: no reachable contracts/composer code at all."""

    def approval_program(self) -> bool:
        return True

    def clear_state_program(self) -> bool:
        return True


class Mpt6SizeProbeBare(Contract):
    """Gate G5-M6: one method, hardcoded literals, every public
    contracts/composer subroutine reached exactly once, zero ABI decoding.
    size(Mpt6SizeProbeBare) - size(Mpt6BenchBaselineBare) is the
    upper-bound estimate of contracts/composer/'s own compiled-byte
    contribution, mirroring M5's `MptSizeProbeBare` methodology exactly."""

    def approval_program(self) -> bool:
        state_root = Bytes(_ACCOUNT_ROOT_BYTES)
        address = Bytes(_ACCOUNT_ADDRESS_BYTES)
        slot = Bytes(_STORAGE_KEY_BYTES)
        c = mpt6_init_composite(state_root, address, slot)
        w = mpt_init_state(state_root, mpt_key_from_address(address), UInt64(64))
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_0_BYTES), w)
        c = mpt6_bridge_account(c, w_status(w), Bytes(_ACCOUNT_NODE_0_BYTES), voff, vlen)
        c = mpt6_bridge_storage(c, w_status(w), Bytes(_ACCOUNT_NODE_0_BYTES), voff, vlen)
        total = c.length ^ w.length
        log_bytes = mpt6_log_state(w, c)
        total ^= log_bytes.length
        return total >= UInt64(0)

    def clear_state_program(self) -> bool:
        return True


class Mpt6SizeProbeCombinedBare(Contract):
    """Gate G6-M6, measured the way §12 actually specifies it: every
    public contracts/composer subroutine, called once, on top of nothing
    else -- diffed externally (bench/composer_bench.py) against M5's own
    `MptSizeProbeCombinedBare` (which already carries M2's + M5's full
    surface), so the remaining diff is M6's OWN incremental bytes, and
    separately against the true deployable-program estimate (M2 + M5 + M6
    all reachable from one entry point) for the 8,192 B cap check."""

    def approval_program(self) -> bool:
        state_root = Bytes(_ACCOUNT_ROOT_BYTES)
        address = Bytes(_ACCOUNT_ADDRESS_BYTES)
        slot = Bytes(_STORAGE_KEY_BYTES)
        c = mpt6_init_composite(state_root, address, slot)
        node = Bytes(_ACCOUNT_NODE_0_BYTES)
        w = mpt_init_state(state_root, mpt_key_from_address(address), UInt64(64))
        w, voff, vlen = mpt_walk_node(node, w)

        c_a = mpt6_bridge_account(c, w_status(w), node, voff, vlen)
        c_s = mpt6_bridge_storage(c, w_status(w), node, voff, vlen)

        storage_root, code_hash, nonce32, balance32 = mpt6_account_body(node, voff, vlen)
        value32, is_zero = mpt6_storage_value(node, voff, vlen)

        _status = c_cstatus(c_a)
        _phase = c_phase(c_a)
        _sr = c_state_root(c_a)
        _addr = c_address(c_a)
        _slot = c_slot(c_a)
        _stor_root = c_storage_root(c_a)
        _ch = c_code_hash(c_a)
        _nonce = c_nonce(c_a)
        _bal = c_balance(c_a)
        _val = c_value(c_a)
        _awalk = c_awalk(c_a)
        _swalk = c_swalk(c_a)
        c_a2 = c_with_phase(c_a, UInt64(PHASE_B))

        log_bytes = mpt6_log_state(w, c_a2)
        if Txn.group_index > UInt64(0):
            _w2, _c2 = mpt6_state_from_prev(UInt64(0))
            _status2, _val2 = mpt6_result_from_group(UInt64(0), state_root, address, slot)
        else:
            _w2, _c2 = w, c_a2
            _status2, _val2 = UInt64(0), value32

        total = c_s.length ^ log_bytes.length ^ storage_root.length ^ code_hash.length
        total ^= nonce32.length ^ balance32.length ^ value32.length
        total ^= _status ^ _phase ^ _sr.length ^ _addr.length ^ _slot.length
        total ^= _stor_root.length ^ _ch.length ^ _nonce.length ^ _bal.length ^ _val.length
        total ^= _awalk ^ _swalk ^ c_a2.length ^ _w2.length ^ _c2.length ^ _status2 ^ _val2.length
        if is_zero:
            total ^= UInt64(1)
        return total >= UInt64(0)

    def clear_state_program(self) -> bool:
        return True


class Mpt6StorageWalkBare(Contract):
    """The "phase-B walk" half of §7.3's two-walk floor
    (`G6-M5 + the measured phase-B walk`), measured the same bare/baked-in,
    zero-ABI-overhead way `MptWalkBare` (contracts/mpt/bench_app.py)
    measured G6-M5: the real 9-node Binance-8-under-USDT storage proof,
    walked against the real, independently-known `storageHash` from
    `eth_data.json` (baked in here purely so THIS isolated probe fits
    comfortably under the 8,192 B cap alone -- `Mpt6ComposerBare` above,
    which bakes in BOTH proofs to demonstrate the full bridge end to end,
    does not fit that cap and is not deployed live; see
    bench/composer_bench.py's notes). Pure M5 walk cost -- no M6 code
    reachable here at all -- exactly mirroring how G6-M5 itself carries no
    M6 code."""

    def approval_program(self) -> bool:
        if Txn.application_id.id == UInt64(0):
            return True

        slot = Bytes(_STORAGE_KEY_BYTES)
        storage_root = Bytes(_STORAGE_ROOT_BYTES)
        key = mpt_key_from_slot(slot)
        w = mpt_init_state(storage_root, key, UInt64(64))

        w, voff, vlen = mpt_walk_node(Bytes(_STORAGE_NODE_0_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_STORAGE_NODE_1_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_STORAGE_NODE_2_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_STORAGE_NODE_3_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_STORAGE_NODE_4_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_STORAGE_NODE_5_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_STORAGE_NODE_6_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_STORAGE_NODE_7_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_STORAGE_NODE_8_BYTES), w)

        assert w_status(w) == UInt64(WALK_INCLUDED), "V1"
        return vlen > UInt64(0)

    def clear_state_program(self) -> bool:
        return True


class Mpt6AccountBodyBare(Contract):
    """§4.3/§11.4 Suite B: `mpt6_account_body` isolated against a
    `rlp_scan_upto(..., 2)` control on the SAME real account leaf node --
    turning §4.3's argued ~80-budget trade into a measured one. Both calls
    reach into the real account leaf's value span (34, 70) baked in from
    `eth_data.json proof.accountProof[7]`."""

    def approval_program(self) -> bool:
        node = Bytes(_ACCOUNT_NODE_7_BYTES)
        storage_root, code_hash, nonce32, balance32 = mpt6_account_body(node, UInt64(34), UInt64(70))
        total = storage_root.length ^ code_hash.length ^ nonce32.length ^ balance32.length
        return total >= UInt64(0)

    def clear_state_program(self) -> bool:
        return True


class Mpt6AccountBodyControlBare(Contract):
    """The `rlp_scan_upto(node, value_off, 2)` control §4.3 costs against --
    same node, same value span, retrieving only item 2 (storageRoot) with
    no arity check and no other fields."""

    def approval_program(self) -> bool:
        node = Bytes(_ACCOUNT_NODE_7_BYTES)
        off, length, kind = rlp_scan_upto(node, UInt64(34), UInt64(2))
        total = off ^ length ^ kind
        return total >= UInt64(0)

    def clear_state_program(self) -> bool:
        return True


class Mpt6ComposerBare(Contract):
    """§7.3/§11.4 Suite B: the bare, baked-in, zero-ABI-overhead full
    composite -- the real USDT account proof (8 nodes) chained through the
    bridge into the real Binance-8 storage proof (9 nodes) against USDT,
    entirely module-level literals. This is the "two-walk floor + M6's own
    overhead" number, measured the same way `MptWalkBare` measured M5's
    G6-M5 headline: no segmentation, no hand-off, no donor mechanics --
    purely M6's own composition cost on top of two back-to-back M5 walks."""

    def approval_program(self) -> bool:
        if Txn.application_id.id == UInt64(0):
            return True

        state_root = Bytes(_ACCOUNT_ROOT_BYTES)
        address = Bytes(_ACCOUNT_ADDRESS_BYTES)
        slot = Bytes(_STORAGE_KEY_BYTES)
        c = mpt6_init_composite(state_root, address, slot)

        w = mpt_init_state(state_root, mpt_key_from_address(address), UInt64(64))
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_0_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_1_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_2_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_3_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_4_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_5_BYTES), w)
        w, voff, vlen = mpt_walk_node(Bytes(_ACCOUNT_NODE_6_BYTES), w)
        last_node = Bytes(_ACCOUNT_NODE_7_BYTES)
        w, voff, vlen = mpt_walk_node(last_node, w)
        assert w_status(w) == UInt64(WALK_INCLUDED), "V1"
        c = mpt6_bridge_account(c, w_status(w), last_node, voff, vlen)
        assert c_phase(c) == UInt64(PHASE_A_OK), "V2"

        skey = mpt_key_from_slot(slot)  # slot preimage, TP-M6-2
        w2 = mpt_init_state(c_storage_root(c), skey, UInt64(64))
        w2, voff2, vlen2 = mpt_walk_node(Bytes(_STORAGE_NODE_0_BYTES), w2)
        w2, voff2, vlen2 = mpt_walk_node(Bytes(_STORAGE_NODE_1_BYTES), w2)
        w2, voff2, vlen2 = mpt_walk_node(Bytes(_STORAGE_NODE_2_BYTES), w2)
        w2, voff2, vlen2 = mpt_walk_node(Bytes(_STORAGE_NODE_3_BYTES), w2)
        w2, voff2, vlen2 = mpt_walk_node(Bytes(_STORAGE_NODE_4_BYTES), w2)
        w2, voff2, vlen2 = mpt_walk_node(Bytes(_STORAGE_NODE_5_BYTES), w2)
        w2, voff2, vlen2 = mpt_walk_node(Bytes(_STORAGE_NODE_6_BYTES), w2)
        w2, voff2, vlen2 = mpt_walk_node(Bytes(_STORAGE_NODE_7_BYTES), w2)
        last_storage_node = Bytes(_STORAGE_NODE_8_BYTES)
        w2, voff2, vlen2 = mpt_walk_node(last_storage_node, w2)
        assert w_status(w2) == UInt64(WALK_INCLUDED), "V1"
        c = mpt6_bridge_storage(c, w_status(w2), last_storage_node, voff2, vlen2)
        assert c_cstatus(c) == UInt64(C_INCLUDED), "V3"
        return c_value(c).length > UInt64(0)

    def clear_state_program(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Mpt6ComposerApp -- the real §6 segmented, raw-args, group-internal
# composite driver. One SEGMENT_SELECTOR ("ACS1") for every mode -- exactly
# M5's MptSegmentApp precedent, restated in §6.1: `mpt6_state_from_prev`
# compares the predecessor's app_args(0) against this literal regardless of
# which mode the predecessor used, so init-vs-resume-vs-bridge-vs-phase-B is
# a MODE byte, never a different method.
#
# Args (raw, always, §6.3):
#   arg0 = SEGMENT_SELECTOR (4B)
#   arg1 = mode (1B)
#   arg2 = donor_count (8B BE) -- §7.6/§16.3's inner-txn budget-donor lever,
#          same mechanism M5's MptSegmentApp wired up (a SEPARATE donor
#          callee app; the AVM forbids an app inner-calling itself).
#   arg3 = donor_app_id (8B BE)
#   MODE_A_INIT (0): arg4=state_root(32B), arg5=address(20B), arg6=slot(32B),
#                    arg7..=account proof nodes
#   MODE_A_NEXT/B_INIT/B_NEXT: arg4=prev_gi(8B BE), arg5..=proof nodes
# Every mode logs (W, C) via mpt6_log_state (§3.4).
# ---------------------------------------------------------------------------
MODE_A_INIT = 0
MODE_A_NEXT = 1
MODE_B_INIT = 2
MODE_B_NEXT = 3


@subroutine
def _issue_donors(n: UInt64, donor_app_id: UInt64) -> None:
    """§7.6/§16.3, identical mechanism to M5's own `_issue_donors`
    (contracts/mpt/bench_app.py) -- issue `n` no-op inner app calls to a
    SEPARATE, pre-deployed, minimal callee app, purely to raise the atomic
    group's pooled opcode budget by ~700/call before the heavy walk work
    consumes it. Kept as its own small copy (not imported from M5's
    bench-app module) so contracts/composer/ has no dependency on
    contracts/mpt/'s own non-production reference driver -- only on M5's
    real library surface (state.py/descend.py/walk.py/handoff.py)."""
    i = UInt64(0)
    while i < n:
        itxn.ApplicationCall(app_id=donor_app_id, fee=UInt64(0)).submit()
        i += UInt64(1)


@subroutine
def _walk6(c: Bytes, w: Bytes, first_node_arg: UInt64, is_phase_a: bool) -> tuple[Bytes, Bytes]:
    """Walk every remaining raw application arg as a supplied node (M5's
    `_walk_remaining_args` pattern, contracts/mpt/bench_app.py), and --
    THE SAME TRANSACTION, THE SAME node buffer -- fire the account bridge
    (§5.1) or the storage-finalisation bridge (§4.4/§8.2) the instant the
    walk this segment is driving reaches a terminal M5 status. This is
    what makes §5.1's "bridge runs in the same transaction as the account
    walk's terminal hop" a structural property of the driver rather than a
    convention a caller could violate: there is no code path here that logs
    a terminal W without also having just called the matching bridge on
    the exact node/voff/vlen that produced it.

    Trailing unconsumed node arguments after a terminal status are
    rejected -> "W10" (inherited from M5, unchanged, X-M6-5)."""
    n = Txn.num_app_args
    i = first_node_arg
    cur_w = w
    cur_c = c
    while i < n:
        assert w_status(cur_w) == UInt64(WALK_CONTINUE), "W10"
        node = Txn.application_args(i)
        cur_w, voff, vlen = mpt_walk_node(node, cur_w)
        status = w_status(cur_w)
        if status != UInt64(WALK_CONTINUE):
            if is_phase_a:
                cur_c = mpt6_bridge_account(cur_c, status, node, voff, vlen)
            else:
                cur_c = mpt6_bridge_storage(cur_c, status, node, voff, vlen)
        i += UInt64(1)
    return cur_w, cur_c


class Mpt6ComposerApp(Contract):
    """NOT a production app (mirrors M5 §1.2) -- reference driver only,
    for measuring and testing §5/§6/§7's mechanism live."""

    def approval_program(self) -> bool:
        if Txn.application_id.id == UInt64(0):
            return True
        if Txn.num_app_args == UInt64(0):
            return True

        selector = Txn.application_args(0)
        assert selector == Bytes(SEGMENT_SELECTOR), "D1"
        mode = op.btoi(Txn.application_args(1))
        donor_count = op.btoi(Txn.application_args(2))
        donor_app_id = op.btoi(Txn.application_args(3))

        if mode == MODE_A_INIT:
            state_root = Txn.application_args(4)
            address = Txn.application_args(5)
            slot = Txn.application_args(6)
            _issue_donors(donor_count, donor_app_id)
            key = mpt_key_from_address(address)
            w = mpt_init_state(state_root, key, UInt64(64))
            c = mpt6_init_composite(state_root, address, slot)
            final_w, final_c = _walk6(c, w, UInt64(7), True)
            log(mpt6_log_state(final_w, final_c))
            return True

        if mode == MODE_A_NEXT:
            prev_gi = op.btoi(Txn.application_args(4))
            w, c = mpt6_state_from_prev(prev_gi)
            # §8.3/A10: this mode may only continue a phase-A walk that is
            # genuinely still in progress -- not one whose bridge has
            # already fired (PHASE_A_OK), not phase B (PHASE_B), and
            # certainly not a terminal composite (PHASE_DONE, X-M6-6).
            assert c_phase(c) == UInt64(PHASE_A), "A10"
            _issue_donors(donor_count, donor_app_id)
            final_w, final_c = _walk6(c, w, UInt64(5), True)
            log(mpt6_log_state(final_w, final_c))
            return True

        if mode == MODE_B_INIT:
            # ---------------------------------------------------------------
            # §5.2, THE SECURITY-CRITICAL ENTRY POINT. No root argument, no
            # key argument, no slot argument: `storage_root` and `slot` come
            # EXCLUSIVELY from `C`, which itself came from reading the
            # group's own execution record (mpt6_state_from_prev), never
            # from anything this transaction's own app_args carry. This is
            # the one property the whole module exists to guarantee (§0,
            # §5.4) -- see test_mpt6_security.py's S-M6-1/S-M6-2/S-M6-4 for
            # the structural and live regression tests.
            # ---------------------------------------------------------------
            prev_gi = op.btoi(Txn.application_args(4))
            w_a, c = mpt6_state_from_prev(prev_gi)
            assert c_phase(c) == UInt64(PHASE_A_OK), "A15"
            assert w_status(w_a) == UInt64(WALK_INCLUDED), "A16"
            assert w_root(w_a) == c_state_root(c), "A7"
            assert c_storage_root(c) != Bytes(EMPTY_TRIE_ROOT), "A8"
            skey = mpt_key_from_slot(c_slot(c))  # ON-CHAIN, from C -- not an argument
            w_b = mpt_init_state(c_storage_root(c), skey, UInt64(64))
            c2 = c_with_phase(c, UInt64(PHASE_B))
            _issue_donors(donor_count, donor_app_id)
            final_w, final_c = _walk6(c2, w_b, UInt64(5), False)
            log(mpt6_log_state(final_w, final_c))
            return True

        assert mode == MODE_B_NEXT, "A19"
        prev_gi = op.btoi(Txn.application_args(4))
        w, c = mpt6_state_from_prev(prev_gi)
        assert c_phase(c) == UInt64(PHASE_B), "A10"
        assert w_root(w) == c_storage_root(c), "A9"  # §5.3's redundant cross-check
        _issue_donors(donor_count, donor_app_id)
        final_w, final_c = _walk6(c, w, UInt64(5), False)
        log(mpt6_log_state(final_w, final_c))
        return True

    def clear_state_program(self) -> bool:
        return True
