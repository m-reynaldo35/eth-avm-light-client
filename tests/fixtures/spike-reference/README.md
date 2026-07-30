# AVM opcode-budget measurement harness (BLS12-381 focus)

Measures the REAL `app-budget-consumed` for AVM opcodes by compiling a minimal
one-opcode program and reading it back from `/v2/transactions/simulate`.
Generic enough to bench any opcode; ships with BLS12-381 point construction
(via py_ecc — real subgroup-valid points) and the sync-committee sizing probes.

## Files
- `avm_bls_bench.py`  -- reusable core: clients, funded-account fetch, TEAL
  assembly, compile, simulate-with-extra-budget, BLS point encoders.
- `run_measurements.py` -- measures every BLS op, isolates opcode-only cost,
  probes the 42/43-point MSM boundary. Prints the results table.
- `probe_encoding.py` -- determines G2 limb order + MSM arg order empirically.
- `probe_pooling.py`  -- top-level group budget pooling (G app calls -> G*700).
- `probe_inner.py`    -- inner-app-call budget pooling + the 256 inner cap.

## Prereqs
- Docker. Python venv with `py_ecc` and `py-algorand-sdk`.

## Bring up a fresh localnet (dev mode, developer API on)
The BLS `ec_*` opcodes need the "future" consensus protocol (dev-mode private
net provides it) and the compile endpoint needs `EnableDeveloperAPI`.

```bash
TOK=$(printf 'a%.0s' {1..64})
docker create --name bls_algod -p 4051:8080 -p 4052:7833 \
  -e DEV_MODE=1 -e START_KMD=1 \
  -e TOKEN=$TOK -e ADMIN_TOKEN=$TOK -e KMD_TOKEN=$TOK \
  algorand/algod:latest
docker start bls_algod && sleep 12
# enable compile endpoint, then restart to apply
docker exec bls_algod algocfg -d /algod/data set -p EnableDeveloperAPI -v true
docker restart bls_algod && sleep 12
```

`avm_bls_bench.py` defaults to algod `http://localhost:4051`, kmd
`http://localhost:4052`, token = 64x'a'. Adjust the constants at the top if your
localnet differs (e.g. algokit's 4001/4002).

## Run
```bash
python -m venv venv && ./venv/bin/pip install py_ecc py-algorand-sdk
./venv/bin/python run_measurements.py     # results table
./venv/bin/python probe_encoding.py        # encoding determination
./venv/bin/python probe_pooling.py         # top-level pooling
./venv/bin/python probe_inner.py           # inner-call pooling + caps
```

## Key facts this harness established (localnet go-algorand 4.7.3)
- AVM byte value cap = 4096 bytes -> max 42 G1 points per `ec_multi_scalar_mul`.
- Base opcode budget per app call = 700; simulate `extra-opcode-budget` cap =
  320000; each top-level AND inner app call pools +700.
- Inner txns are capped at 256 per GROUP (shared) -> one 16-txn group tops out
  at 16 + 256 = 272 app calls = 190,400 opcode budget.
- G1 encoding = 96B uncompressed X||Y big-endian; G2 = 192B, Fp2 as c0||c1.
