# M7 T3 zero-knowledge spike — reference material

This directory is **spike reference material, not shipped code**, in the same spirit as
its parent directory: it exists so the numbers in
`docs/design/007-receipt-log-proof.md` §4.5, §4.12, §4.13, §4.14 and §13 can be
reproduced, not as a style to imitate. `ROADMAP.md`'s rule stands — M7 is not approved
and nothing here is an implementation of it.

It was produced by the spike revision 2 of the design doc asked for, to close blockers
**ZK-B1** (no M7 circuit had ever been compiled) and **ZK-B2** (no Perpetual Powers of
Tau ceremony above 2¹⁷ was usable with AlgoPlonk).

## What it does

`circuit/` is the real M7 receipt-leaf circuit of design doc §4.3/§4.4, in gnark:

- `receipt.go` — the statement: `keccak256(R) == expected_leaf_hash`, `R` is canonical
  `RLP([hp_path, value])` closing exactly on `leaf_len`, `hp_path` is a **leaf** path
  whose nibbles equal `path_tail` exactly, EIP-2718 envelope handling mirroring
  `contracts/primitives/rlp/eip2718.py`, a body of exactly
  `[status, cumGas, bloom(256 B), logs]`, and `logs[log_index]` committed as a public
  output.
- `rlp.go` — an in-circuit RLP reader shaped to match
  `contracts/primitives/rlp/core.py`. Where `core.py` `assert`s, `header()` returns an
  `ok` flag the caller asserts, because a circuit has no data-dependent control flow.
  It also enforces the two canonicality obligations §4.4 names, which `core.py`
  deliberately skips under TP-1.
- `assign.go` — the off-circuit witness builder. It is a deliberate second
  implementation of the same walk, so a disagreement shows up as an unsatisfiable
  circuit.

`cmd/` holds the drivers:

| command | what it establishes |
|---|---|
| `measure` | real `nbConstraints` at any `(N, LogMax, MaxLogs)` — the 28 compiles behind §4.5.1's formula |
| `ptau` | `-mode=audit` reproduces AlgoPlonk's vendored `PerpetualPowersOfTauBN254/pk.bin` **byte for byte** from the published ceremony file (§4.12); `-mode=convert` writes `pk.bin`/`vk.bin` for any power |
| `prove` | the whole pipeline: real leaf → circuit → **real PPOT SRS** → `plonk.Setup` → AlgoPlonk logicsig codegen → real proof (§4.13) |
| `circuittest` | §4.14 — the 97-receipt real-corpus differential and the negative tests, via gnark's `test.IsSolved` |
| `blsmeasure` | §13.1's in-circuit cost table for BLS12-381 / sha256 / keccak256 |
| `aptest` | exercises all four of AlgoPlonk's vendored setups end to end |

`build_trie.py` rebuilds block 25,639,768's receipts trie from `../eth_data.json`,
asserts the root reproduces `0x6490277f…099e710b`, and emits `leaves.json` — the real
leaf bytes and hashes everything else consumes. `onchain.py` verifies a generated proof
against the project's dev-mode algod (`:4051`/`:4052`, same recipe as `../README.md`),
reports the real logicsig/app budgets, runs the tampered-public-input negative test, and
does a **real, non-simulated submission**.

## Reproducing

Needs a Go toolchain (this pass used 1.25.7; the project has none by default — see
design doc §8.7, this is exactly the second-language question flagged for
`ARCHITECTURE.md`) and the dev-mode algod from `../README.md`.

```bash
python3 build_trie.py                       # writes leaves.json

# ZK-B2 / ZK-B7: reproduce AlgoPlonk's own vendored setup from the real ceremony
curl -LO https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_18.ptau
go run ./cmd/ptau -mode=audit -in=powersOfTau28_hez_final_18.ptau \
    -ref=$(go env GOMODCACHE)/github.com/giuliop/algoplonk@v0.3.1/setup/PerpetualPowersOfTauBN254

# ZK-B1: the real constraint counts
go run ./cmd/measure -sizes=8567 -logmax=640 -maxlogs=48      # -> 16,293,891

# §4.14: constraints only, no proving — the real-corpus differential + negatives
go run ./cmd/circuittest x 4300                                # -> 97/97 satisfied

# §4.13: the real end-to-end (needs ~4 GB RAM and ~4.5 minutes)
curl -LO https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau
python3 dump_log.py 85 0 generated/tx85/M7VerifierTx85.log_bytes
go run ./cmd/prove -tx=85 -n=384 -logmax=96 -maxlogs=4 \
    -ptau=powersOfTau28_hez_final_21.ptau -outdir=generated/tx85 -name=M7VerifierTx85
python3 onchain.py generated/tx85 M7VerifierTx85 --submit
```

## What is NOT here

The ceremony files (2.4 GB and 4.6 GB), the derived proving keys, and the generated
`Verifier.py`/`.teal`/`.proof` blobs. They are reproducible from the commands above and
must not be committed — design doc §4.6 makes the same point about the 537 MB 2²⁴
`pk.bin`, and M10 owns fetch-and-checksum rather than vendoring.

Measured results are pinned in `bench/receipt_zk_results.json`.
