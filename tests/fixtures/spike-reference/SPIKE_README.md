# Spike reference (read-only)

This directory is a verbatim copy of the original benchmarking spike
(`avm-bls12-381-benchmark`) that proved the empirical AVM opcode-budget facts
this project's design docs are built on. It is **not** part of the library —
nothing here is imported by `contracts/` or `relayer/`.

Keep it here, unmodified, so every design doc's citations of a specific
measured number (e.g. "42-point MSM boundary", "keccak256 flat at 130",
"receipt >4096B problem") can be checked against the actual harness and raw
data that produced it.

Source findings: `RESULTS.md` (BLS12-381 opcode budgets) and `MPT_RESULTS.md`
(MPT/RLP opcode budgets, the >4096B receipt-leaf problem, the MPT verifier's
key-membership gap). `eth_data.json` / `results.json` are the raw pulled
mainnet data and simulate results referenced by those two files.
