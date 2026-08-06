"""Rebuild the real receipts trie of block 25,639,768 from the pinned fixture's
raw block_receipts, verify it against the fixture receiptsRoot, and emit the
real leaf nodes (the exact objects M7's circuit must hash)."""
import json
from Crypto.Hash import keccak
import rlp

def kec(b):
    h = keccak.new(digest_bits=256); h.update(b); return h.digest()

FIX='/home/mark/eth-avm-verifier/tests/fixtures/spike-reference/eth_data.json'
d = json.load(open(FIX)); rcpts = d['block_receipts']
def hx(s): return bytes.fromhex(s[2:] if s.startswith('0x') else s)
def qi(s): return int(s, 16)

def encode_receipt(r):
    logs = [[hx(l['address']), [hx(t) for t in l['topics']], hx(l['data'])] for l in r['logs']]
    status = qi(r['status']) if 'status' in r else None
    body = [b'' if status == 0 else bytes([1]), qi(r['cumulativeGasUsed']), hx(r['logsBloom']), logs]
    enc = rlp.encode(body); ty = qi(r.get('type', '0x0'))
    return (bytes([ty]) + enc if ty else enc), ty

def nib(b):
    o=[]
    for x in b: o += [x>>4, x&15]
    return o
def hp(nb, leaf):
    f = 2 if leaf else 0
    if len(nb)%2: first=(f+1)*16+nb[0]; rest=nb[1:]
    else: first=f*16; rest=nb
    out=bytes([first])
    for i in range(0,len(rest),2): out+=bytes([rest[i]*16+rest[i+1]])
    return out

items={}
for i,r in enumerate(rcpts):
    enc,_=encode_receipt(r); items[tuple(nib(rlp.encode(i)))]=enc

LEAVES={}   # key-tuple -> (leaf_encoding, depth, path_nibbles)
def ref(node):
    e=rlp.encode(node); return kec(e) if len(e)>=32 else node
def build(keys, depth):
    if len(keys)==1:
        k=keys[0]; path=list(k[depth:]); node=[hp(path,True), items[k]]
        LEAVES[k]=(rlp.encode(node), depth, path); return node
    pref=0
    while all(len(k)>depth+pref for k in keys) and len({k[depth+pref] for k in keys})==1: pref+=1
    if pref>0:
        return [hp(list(keys[0][depth:depth+pref]),False), ref(build(keys,depth+pref))]
    br=[b'']*17
    for n in range(16):
        sub=[k for k in keys if len(k)>depth and k[depth]==n]
        if sub: br[n]=ref(build(sub,depth+1))
    ex=[k for k in keys if len(k)==depth]
    if ex: br[16]=items[ex[0]]
    return br

keys=sorted(items.keys())
root_node=build(keys,0); root=kec(rlp.encode(root_node))
assert '0x'+root.hex()==d['receiptsRoot'], f"TRIE MISMATCH {root.hex()} vs {d['receiptsRoot']}"
print('receiptsRoot reproduced OK:', d['receiptsRoot'])

rows=[]
for i,r in enumerate(rcpts):
    k=tuple(nib(rlp.encode(i))); enc,depth,path=LEAVES[k]
    val=items[k]
    rows.append(dict(tx=i, leaf_len=len(enc), value_len=len(val), depth=depth,
                     path_nibbles=path, n_logs=len(r['logs']),
                     tx_type=int(r.get('type','0x0'),16),
                     leaf_hash='0x'+kec(enc).hex(),
                     leaf_hex=enc.hex()))
json.dump(rows, open('/home/mark/.cache/m7-zk-spike/work/leaves.json','w'))

over=[x for x in rows if x['leaf_len']>4096]
print(f"n_receipts={len(rows)}  n_over_4096={len(over)}  max={max(x['leaf_len'] for x in rows)}")
print("oversized:", [(x['tx'],x['leaf_len'],x['n_logs']) for x in over])
import statistics
srt=sorted(rows,key=lambda x:x['leaf_len'])
print("smallest 3:", [(x['tx'],x['leaf_len']) for x in srt[:3]])
p=[x for x in rows if x['tx'] in (7,31,35)]
for x in p: print(f"  tx {x['tx']}: leaf_len={x['leaf_len']} value_len={x['value_len']} depth={x['depth']} path={x['path_nibbles']} n_logs={x['n_logs']} type={x['tx_type']} hash={x['leaf_hash']}")
