import json, urllib.request, time
from Crypto.Hash import keccak
RPCS = ["https://ethereum-rpc.publicnode.com","https://eth.drpc.org","https://eth.merkle.io","https://1rpc.io/eth","https://eth-mainnet.public.blastapi.io"]
def kec(b):
    h=keccak.new(digest_bits=256); h.update(b); return h.digest()
def rpc(method, params):
    payload=json.dumps({"jsonrpc":"2.0","method":method,"params":params,"id":1}).encode()
    last=None
    for attempt in range(4):
        for u in RPCS:
            try:
                req=urllib.request.Request(u,data=payload,headers={"content-type":"application/json"})
                with urllib.request.urlopen(req,timeout=25) as r:
                    d=json.load(r)
                if d.get("result") is not None: return d["result"]
                last=d
            except Exception as e:
                last=str(e)
            time.sleep(0.4)
        time.sleep(1.5)
    raise RuntimeError(f"all rpc failed: {last}")

head=int(rpc("eth_blockNumber",[]),16)
bn=head-32; bhex=hex(bn)
blk=rpc("eth_getBlockByNumber",[bhex,False])
USDT="0xdAC17F958D2ee523a2206206994597C13D831ec7"
holder="0xF977814e90dA44bFA03b6295A0616a897441aceC"
slot=(2).to_bytes(32,'big')
key=bytes.fromhex(holder[2:].rjust(64,'0'))
storage_key="0x"+kec(key+slot).hex()
proof=rpc("eth_getProof",[USDT,[storage_key],bhex])
out={"head":head,"block_number":bn,"block_hex":bhex,
     "stateRoot":blk["stateRoot"],"receiptsRoot":blk["receiptsRoot"],"transactionsRoot":blk["transactionsRoot"],
     "contract":USDT,"holder":holder,"storage_key":storage_key,"block_header":blk,"proof":proof}
json.dump(out,open("eth_data.json","w"))
print("saved core. block",bn,"acctdepth",len(proof["accountProof"]),"stordepth",len(proof["storageProof"][0]["proof"]))
print("stateRoot",blk["stateRoot"]); print("receiptsRoot",blk["receiptsRoot"])
print("storage value",proof["storageProof"][0]["value"])
# receipt proof source
blkfull=rpc("eth_getBlockByNumber",[bhex,True])
out["tx_count"]=len(blkfull["transactions"])
out["block_full_txs"]=blkfull["transactions"]
# pick a tx with logs
chosen=None
for i,tx in enumerate(blkfull["transactions"][:40]):
    r=rpc("eth_getTransactionReceipt",[tx["hash"]])
    if r and r.get("logs"):
        chosen=(i,tx["hash"],r); break
    time.sleep(0.2)
if chosen:
    out["receipt_tx_index"]=chosen[0]; out["receipt_tx_hash"]=chosen[1]; out["sample_receipt"]=chosen[2]
    print("receipt tx idx",chosen[0],"logs",len(chosen[2]["logs"]),"txcount",out["tx_count"])
json.dump(out,open("eth_data.json","w"))
print("DONE")
