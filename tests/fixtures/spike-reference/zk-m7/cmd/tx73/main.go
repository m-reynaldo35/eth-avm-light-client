// One-shot: does the combined O-M7-4 shrink (sha256 log commitment +
// WithMinimalLength) bring tx 73 -- the receipt that forces a 2^25 tier purely
// because of its 2,368-byte log -- under the 2^24 ceiling of 16,777,216?
package main

import (
	"flag"
	"fmt"

	"m7zk/circuit"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

func main() {
	sha := flag.Bool("sha", true, "")
	minlen := flag.Bool("minlen", true, "")
	flag.Parse()
	p := circuit.Params{N: 7552, LogMax: 2368, MaxLogs: 24}
	if *sha {
		p.LogSHA256 = true
	}
	if *minlen {
		p.MinLeaf, p.MinLog = 7168, 2048
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit.New(p))
	if err != nil {
		panic(err)
	}
	n := ccs.GetNbConstraints()
	const ceil = 1 << 24
	fmt.Printf("tx 73  sha256-log=%v minlen=%v -> nbConstraints = %d\n", *sha, *minlen, n)
	fmt.Printf("  base (measured earlier)                = 17757682\n")
	fmt.Printf("  2^24 ceiling                           = %d\n", ceil)
	if n+8 <= ceil {
		fmt.Printf("  *** FITS 2^24 *** (margin %d constraints)\n", ceil-n-8)
	} else {
		fmt.Printf("  does NOT fit 2^24: over by %d constraints (%.2f%%)\n",
			n+8-ceil, 100*float64(n+8-ceil)/float64(ceil))
	}
}
