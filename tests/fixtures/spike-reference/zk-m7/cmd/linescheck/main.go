// Command linescheck answers a security-relevant question about the SRS this
// project loads: gnark-crypto's kzg.VerifyingKey carries PRECOMPUTED PAIRING
// LINES, and kzg.Verify uses them via PairingCheckFixedQ. gnark-ptau's ToSRS
// builds the SRS by hand and never populates them. Does that break, or silently
// weaken, off-chain verification?
package main

import (
	"flag"
	"fmt"
	"os"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	kzgbn "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	gp "github.com/mdehoog/gnark-ptau"
)

func main() {
	ptau := flag.String("ptau", "", "ptau file")
	flag.Parse()

	f, err := os.Open(*ptau)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	srs, err := gp.ToSRS(f)
	f.Close()
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}

	var zero bn254.LineEvaluationAff
	nz := 0
	total := 0
	for k := 0; k < 2; k++ {
		for j := 0; j < 2; j++ {
			for i := range srs.Vk.Lines[k][j] {
				total++
				if srs.Vk.Lines[k][j][i] != zero {
					nz++
				}
			}
		}
	}
	fmt.Printf("gnark-ptau ToSRS -> Vk.Lines: %d/%d entries non-zero\n", nz, total)

	// what the lines SHOULD be
	want0 := bn254.PrecomputeLines(srs.Vk.G2[0])
	want1 := bn254.PrecomputeLines(srs.Vk.G2[1])
	match := srs.Vk.Lines[0] == want0 && srs.Vk.Lines[1] == want1
	fmt.Printf("Vk.Lines == PrecomputeLines(Vk.G2): %v\n", match)

	// does a pairing check with the loaded (possibly zero) lines behave?
	_, _ = kzgbn.NewSRS(8, nil)
	fmt.Println()
	if nz == 0 {
		fmt.Println("FINDING: Lines are entirely zero after ToSRS.")
		fmt.Println("  kzg.Verify -> PairingCheckFixedQ would use zeroed lines.")
	}
}
