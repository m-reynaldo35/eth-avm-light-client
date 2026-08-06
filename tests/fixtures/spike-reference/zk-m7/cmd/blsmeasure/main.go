// Command blsmeasure prices, in real compiled constraints, what it would cost
// to move M4's sync-committee BLS12-381 aggregate-signature check into a gnark
// circuit proved on BN254 — the Part-4 question of the M7 ZK spike.
//
// It measures three pieces separately so the cost model is transparent:
//   - agg:   n emulated BLS12-381 G1 point additions (participation aggregation)
//   - pair:  one 2-point BLS12-381 PairingCheck (the actual signature check)
//   - sub:   AssertIsOnG1 subgroup checks
package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// aggCircuit: n G1 additions (M4 aggregates participating pubkeys).
type aggCircuit struct {
	P []sw_bls12381.G1Affine
	N int `gnark:"-"`
}

func (c *aggCircuit) Define(api frontend.API) error {
	g, err := sw_emulated.New[sw_bls12381.BaseField, sw_bls12381.ScalarField](
		api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return err
	}
	acc := &c.P[0]
	for i := 1; i < len(c.P); i++ {
		acc = g.AddUnified(acc, &c.P[i])
	}
	g.AssertIsEqual(acc, acc)
	return nil
}

// pairCircuit: the 2-pairing check e(-G1, sig) * e(aggPk, H(m)) == 1.
type pairCircuit struct {
	P0, P1 sw_bls12381.G1Affine
	Q0, Q1 sw_bls12381.G2Affine
}

func (c *pairCircuit) Define(api frontend.API) error {
	pr, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return err
	}
	return pr.PairingCheck([]*sw_bls12381.G1Affine{&c.P0, &c.P1},
		[]*sw_bls12381.G2Affine{&c.Q0, &c.Q1})
}

// subCircuit: n G1 subgroup checks (M1 §4.4's trust boundary).
type subCircuit struct {
	P []sw_bls12381.G1Affine
}

func (c *subCircuit) Define(api frontend.API) error {
	pr, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return err
	}
	for i := range c.P {
		pr.AssertIsOnG1(&c.P[i])
	}
	return nil
}

// mapCircuit: hash_to_G2 of the 32-byte signing root under the Ethereum DST.
type mapCircuit struct {
	In [2]emulated.Element[sw_bls12381.BaseField]
}

func (c *mapCircuit) Define(api frontend.API) error {
	g, err := sw_bls12381.NewG2(api)
	if err != nil {
		return err
	}
	p, err := g.MapToG2(&fields_bls12381.E2{A0: c.In[0], A1: c.In[1]})
	if err != nil {
		return err
	}
	g.AssertIsEqual(p, p)
	return nil
}

// shaCircuit: n SHA-256 compressions — M3's SSZ Merkle branch, in-circuit.
type shaCircuit struct {
	In []uints.U8
}

func (c *shaCircuit) Define(api frontend.API) error {
	h, err := sha2.New(api)
	if err != nil {
		return err
	}
	h.Write(c.In)
	_ = h.Sum()
	return nil
}

// kecCircuit: n bytes through keccak256 — the MPT-node hash M5/M6 do on-chain.
type kecCircuit struct {
	In []uints.U8
}

func (c *kecCircuit) Define(api frontend.API) error {
	h, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		return err
	}
	h.Write(c.In)
	_ = h.Sum()
	return nil
}

func compile(name string, c frontend.Circuit) {
	t0 := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, c)
	if err != nil {
		fmt.Printf("%-28s COMPILE ERROR: %v\n", name, err)
		return
	}
	fmt.Printf("%-28s nbConstraints=%-12d commitments=%d  compile=%.1fs\n",
		name, ccs.GetNbConstraints(), len(ccs.GetCommitments().CommitmentIndexes()),
		time.Since(t0).Seconds())
}

func main() {
	which := flag.String("which", "all", "agg|pair|sub|all")
	ns := flag.String("n", "2,8,32", "point counts for agg/sub")
	flag.Parse()

	var counts []int
	cur := -1
	for i := 0; i <= len(*ns); i++ {
		if i == len(*ns) || (*ns)[i] == ',' {
			if cur >= 0 {
				counts = append(counts, cur)
			}
			cur = -1
			continue
		}
		cur = max(cur, 0)*10 + int((*ns)[i]-'0')
	}

	if *which == "pair" || *which == "all" {
		compile("bls12381 PairingCheck(2)", &pairCircuit{})
	}
	if *which == "agg" || *which == "all" {
		for _, n := range counts {
			compile(fmt.Sprintf("bls12381 G1 AddUnified x%d", n-1),
				&aggCircuit{P: make([]sw_bls12381.G1Affine, n)})
		}
	}
	if *which == "map" || *which == "all" {
		compile("bls12381 MapToG2 x1", &mapCircuit{})
	}
	if *which == "sha" || *which == "all" {
		for _, n := range []int{64, 512} {
			compile(fmt.Sprintf("sha256 over %d B", n),
				&shaCircuit{In: make([]uints.U8, n)})
		}
		for _, n := range []int{136, 544} {
			compile(fmt.Sprintf("keccak256 over %d B", n),
				&kecCircuit{In: make([]uints.U8, n)})
		}
	}
	if *which == "sub" || *which == "all" {
		for _, n := range counts {
			compile(fmt.Sprintf("bls12381 AssertIsOnG1 x%d", n),
				&subCircuit{P: make([]sw_bls12381.G1Affine, n)})
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
