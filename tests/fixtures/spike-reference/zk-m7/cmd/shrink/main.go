// Command shrink measures O-M7-4: can the T3 circuit be made cheaper?
//
// It compiles the real M7 circuit at real tier configurations under three
// variants and reports real nbConstraints and the PLONK domain each implies:
//
//	base       status quo (keccak256 log commitment, no length lower bound)
//	sha256-log log commitment by sha256 instead of keccak256
//	minlen     hash.WithMinimalLength on both hashes (a tier only ever serves
//	           leaves above the previous tier's bound, so a bound is known)
package main

import (
	"fmt"

	"m7zk/circuit"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

func compile(p circuit.Params) int {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit.New(p))
	if err != nil {
		panic(err)
	}
	return ccs.GetNbConstraints()
}

func domainOf(n int) int {
	d, e := 1, 0
	for d < n {
		d <<= 1
		e++
	}
	return e
}

type tier struct {
	name               string
	N, LogMax, MaxLogs int
	MinLeaf, MinLog    int
}

func main() {
	tiers := []tier{
		{"tx 85 (real, proved on-chain)", 384, 96, 4, 256, 64},
		{"tx 8  (real, proved on-chain)", 440, 160, 1, 384, 128},
		{"tx 31 (pinned fixture)", 704, 256, 4, 512, 128},
		{"tx 35 (smallest oversized)", 4224, 928, 20, 4096, 512},
	}
	fmt.Printf("%-32s %6s %6s %6s | %11s | %11s %7s | %11s %7s | domain\n",
		"tier", "N", "LOGMAX", "MAXLOG", "base", "sha256-log", "delta", "minlen", "delta")
	for _, t := range tiers {
		base := compile(circuit.Params{N: t.N, LogMax: t.LogMax, MaxLogs: t.MaxLogs})
		sha := compile(circuit.Params{N: t.N, LogMax: t.LogMax, MaxLogs: t.MaxLogs, LogSHA256: true})
		ml := compile(circuit.Params{N: t.N, LogMax: t.LogMax, MaxLogs: t.MaxLogs,
			MinLeaf: t.MinLeaf, MinLog: t.MinLog})
		fmt.Printf("%-32s %6d %6d %6d | %11d | %11d %6.2f%% | %11d %6.2f%% | 2^%d/2^%d/2^%d\n",
			t.name, t.N, t.LogMax, t.MaxLogs, base, sha,
			100*float64(sha-base)/float64(base), ml,
			100*float64(ml-base)/float64(base),
			domainOf(base+8), domainOf(sha+8), domainOf(ml+8))
	}
}
