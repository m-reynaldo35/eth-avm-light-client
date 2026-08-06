// Command aptest exercises AlgoPlonk's own vendored trusted setups end to end
// on a trivial circuit, to establish whether the shipped BN254 PPOT path
// actually works with the gnark-crypto version AlgoPlonk pins.
package main

import (
	"fmt"

	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type tiny struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable
}

func (c *tiny) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.Y, c.Y), c.X)
	return nil
}

func main() {
	cases := []struct {
		name  string
		curve ecc.ID
		s     setup.Name
	}{
		{"PerpetualPowersOfTauBN254", ecc.BN254, setup.PerpetualPowersOfTauBN254},
		{"DuskBLS12381", ecc.BLS12_381, setup.DuskBLS12381},
		{"EthereumKzgCeremonyBLS12381", ecc.BLS12_381, setup.EthereumKzgCeremonyBLS12381},
		{"TestOnlyBN254", ecc.BN254, setup.TestOnlyBN254},
	}
	for _, c := range cases {
		cc, err := ap.Compile(&tiny{}, c.curve, c.s)
		if err != nil {
			fmt.Printf("%-32s COMPILE/SETUP FAIL: %v\n", c.name, err)
			continue
		}
		_, err = cc.Verify(&tiny{X: 49, Y: 7})
		if err != nil {
			fmt.Printf("%-32s PROVE/VERIFY FAIL: %v\n", c.name, err)
			continue
		}
		fmt.Printf("%-32s OK (nbConstraints=%d)\n", c.name, cc.Ccs.GetNbConstraints())
	}
}
