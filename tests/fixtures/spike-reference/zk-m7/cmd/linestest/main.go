// Command linestest checks, end to end on a tiny circuit, whether a PLONK
// proof set up against a gnark-ptau-loaded SRS (whose Vk.Lines are all zero)
// really verifies -- and, critically, whether a TAMPERED proof is still
// rejected. A verifier that accepts everything would be a silent, total loss
// of off-chain soundness checking.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	kzgbn "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	gp "github.com/mdehoog/gnark-ptau"
)

// tiny circuit: x^3 + x + 5 == y
type Cubic struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *Cubic) Define(api frontend.API) error {
	x3 := api.Mul(c.X, c.X, c.X)
	api.AssertIsEqual(c.Y, api.Add(x3, c.X, 5))
	return nil
}

func run(label string, fixLines bool, ptau string) {
	fmt.Printf("\n===== %s =====\n", label)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &Cubic{})
	must(err)
	size := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()+ccs.GetNbPublicVariables())) + 3

	f, err := os.Open(ptau)
	must(err)
	srsFull, err := gp.ToSRS(f)
	f.Close()
	must(err)

	srs := &kzgbn.SRS{Vk: srsFull.Vk}
	srs.Pk.G1 = make([]bn254.G1Affine, size)
	copy(srs.Pk.G1, srsFull.Pk.G1[:size])

	if fixLines {
		srs.Vk.Lines[0] = bn254.PrecomputeLines(srs.Vk.G2[0])
		srs.Vk.Lines[1] = bn254.PrecomputeLines(srs.Vk.G2[1])
	}
	var zero bn254.LineEvaluationAff
	nz := 0
	for k := 0; k < 2; k++ {
		for j := 0; j < 2; j++ {
			for i := range srs.Vk.Lines[k][j] {
				if srs.Vk.Lines[k][j][i] != zero {
					nz++
				}
			}
		}
	}
	fmt.Printf("Vk.Lines non-zero entries: %d/264\n", nz)

	lag := &kzgbn.SRS{Vk: srs.Vk}
	lagG1, err := kzgbn.ToLagrangeG1(srs.Pk.G1[:len(srs.Pk.G1)-3])
	must(err)
	lag.Pk.G1 = lagG1

	pk, vk, err := plonk.Setup(ccs, srs, lag)
	must(err)

	// honest proof
	w, err := frontend.NewWitness(&Cubic{X: 3, Y: 35}, ecc.BN254.ScalarField())
	must(err)
	pub, err := w.Public()
	must(err)
	proof, err := plonk.Prove(ccs, pk, w)
	must(err)
	err = plonk.Verify(proof, vk, pub)
	fmt.Printf("honest proof  -> Verify err = %v\n", err)

	// WRONG public input: claim y = 36 for the same proof.
	// NOTE: this is caught by the algebraic-relation check, which runs BEFORE
	// the KZG pairing, so it does not exercise Vk.Lines at all.
	wBad, err := frontend.NewWitness(&Cubic{X: 3, Y: 36}, ecc.BN254.ScalarField())
	must(err)
	pubBad, err := wBad.Public()
	must(err)
	err = plonk.Verify(proof, vk, pubBad)
	fmt.Printf("wrong public  -> Verify err = %v   %s\n", err,
		verdict(err != nil))

	// THE DECISIVE TEST: corrupt ONLY the KZG batch-opening proof point.
	// Nothing but the final pairing check (which consumes Vk.Lines) can catch
	// this. If it is accepted, the pairing check is vacuous.
	tampered := *proof.(*plonkbn254.Proof)
	var g1jac bn254.G1Jac
	g1jac.FromAffine(&tampered.BatchedProof.H)
	g1jac.Double(&g1jac)
	tampered.BatchedProof.H.FromJacobian(&g1jac)
	err = plonk.Verify(&tampered, vk, pub)
	fmt.Printf("bad KZG open  -> Verify err = %v   %s\n", err,
		verdict(err != nil))

	// And corrupt the shifted opening proof too.
	tampered2 := *proof.(*plonkbn254.Proof)
	g1jac.FromAffine(&tampered2.ZShiftedOpening.H)
	g1jac.Double(&g1jac)
	tampered2.ZShiftedOpening.H.FromJacobian(&g1jac)
	err = plonk.Verify(&tampered2, vk, pub)
	fmt.Printf("bad Z open    -> Verify err = %v   %s\n", err,
		verdict(err != nil))
}

func verdict(rejected bool) string {
	if rejected {
		return "(REJECTED - good)"
	}
	return "(ACCEPTED - SOUNDNESS FAILURE)"
}

func main() {
	ptau := flag.String("ptau", "", "ptau file")
	flag.Parse()
	run("as this project loads it (gnark-ptau, Lines left zero)", false, *ptau)
	run("with Lines correctly precomputed", true, *ptau)
}

func must(err error) {
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}
