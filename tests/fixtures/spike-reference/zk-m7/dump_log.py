import json,sys,rlp
tx=int(sys.argv[1]); idx=int(sys.argv[2]); out=sys.argv[3]
rows=json.load(open('leaves.json')); r=[x for x in rows if x['tx']==tx][0]
leaf=bytes.fromhex(r['leaf_hex']); d=rlp.decode(leaf); val=d[1]
body=rlp.decode(val[1:] if val[0]<0xc0 else val)
enc=rlp.encode(body[3][idx])
open(out,'wb').write(enc)
from Crypto.Hash import keccak
h=keccak.new(digest_bits=256); h.update(enc)
print(f"tx {tx} log {idx}: {len(enc)} bytes, keccak={h.hexdigest()}")
h2=keccak.new(digest_bits=256); h2.update(leaf)
print(f"leaf keccak = 0x{h2.hexdigest()}  (fixture says {r['leaf_hash']})")
