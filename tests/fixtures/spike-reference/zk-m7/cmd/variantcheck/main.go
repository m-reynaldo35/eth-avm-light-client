// Command variantcheck re-runs design doc 007 §9.5's ZK-1 (every real receipt
// in block 25,639,768 with >=1 log) against the O-M7-4 circuit VARIANTS, so a
// constraint-count saving is only reported if the variant is actually
// satisfiable on real data.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"m7zk/circuit"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

type leafRow struct {
	Tx      int    `json:"tx"`
	LeafLen int    `json:"leaf_len"`
	NLogs   int    `json:"n_logs"`
	LeafHex string `json:"leaf_hex"`
}

func main() {
	b, err := os.ReadFile("leaves.json")
	must(err)
	var rows []leafRow
	must(json.Unmarshal(b, &rows))

	variants := []struct {
		name string
		mk   func(leaf []byte, nlogs int) circuit.Params
	}{
		{"base (keccak log, no minlen)", func(l []byte, n int) circuit.Params {
			return circuit.Params{N: len(l) + 8, LogMax: 1024, MaxLogs: n + 1}
		}},
		{"sha256 log commitment", func(l []byte, n int) circuit.Params {
			return circuit.Params{N: len(l) + 8, LogMax: 1024, MaxLogs: n + 1, LogSHA256: true}
		}},
		{"sha256 log + WithMinimalLength", func(l []byte, n int) circuit.Params {
			return circuit.Params{N: len(l) + 8, LogMax: 1024, MaxLogs: n + 1,
				LogSHA256: true, MinLeaf: len(l) - 64, MinLog: 32}
		}},
	}

	for _, v := range variants {
		ok, skip, fail := 0, 0, 0
		var firstErr error
		for _, r := range rows {
			if r.NLogs == 0 || r.LeafLen > 1200 {
				skip++
				continue
			}
			leaf, _ := hex.DecodeString(r.LeafHex)
			p := v.mk(leaf, r.NLogs)
			a, err := circuit.Witness(p, leaf, 0)
			if err != nil {
				skip++
				continue
			}
			if err := test.IsSolved(circuit.New(p), a, ecc.BN254.ScalarField()); err != nil {
				fail++
				if firstErr == nil {
					firstErr = fmt.Errorf("tx %d: %w", r.Tx, err)
				}
			} else {
				ok++
			}
		}
		fmt.Printf("%-34s  satisfied %3d   failed %3d   skipped %3d\n", v.name, ok, fail, skip)
		if firstErr != nil {
			fmt.Printf("    first failure: %v\n", firstErr)
		}
	}
}

func must(err error) {
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}
