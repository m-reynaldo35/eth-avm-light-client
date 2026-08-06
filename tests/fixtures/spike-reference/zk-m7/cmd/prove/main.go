// Command prove runs the whole M7 T3 pipeline for real:
//
//	real receipt leaf  ->  gnark circuit  ->  PLONK setup against a REAL
//	Perpetual-Powers-of-Tau SRS (not a TestOnly setup)  ->  proof  ->
//	AlgoPlonk logicsig verifier source + proof/public-input blobs for the AVM.
//
// It deliberately bypasses AlgoPlonk's setup.Run, because that function can
// only reach ceremony files that were go:embed-ed at AlgoPlonk build time.
// Everything downstream of the setup (verifier codegen, proof/public-input
// marshalling) is AlgoPlonk's own code, unmodified.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"m7zk/circuit"

	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/verifier"

	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	kzgbn "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	gp "github.com/mdehoog/gnark-ptau"
)

type leafRow struct {
	Tx       int    `json:"tx"`
	LeafLen  int    `json:"leaf_len"`
	NLogs    int    `json:"n_logs"`
	TxType   int    `json:"tx_type"`
	LeafHash string `json:"leaf_hash"`
	LeafHex  string `json:"leaf_hex"`
}

type report struct {
	Tx, LeafLen, NLogs, TxType, LogIndex int
	N, LogMax, MaxLogs                   int
	NbConstraints, NbPublic              int
	Commitments                          int
	DomainSize                           uint64
	Ptau                                 string
	PtauPower                            int
	SRSPoints                            int
	CompileSec, SRSLoadSec, LagrangeSec  float64
	SetupSec, ProveSec, VerifySec        float64
	PeakRSSMB                            uint64
	ProofBytes, PublicInputBytes         int
	LeafHash                             string
	PublicInputsHex                      []string
}

func main() {
	leavesPath := flag.String("leaves", "leaves.json", "")
	tx := flag.Int("tx", 85, "transaction index in block 25,639,768")
	logIndex := flag.Int("logindex", 0, "")
	n := flag.Int("n", 384, "circuit N")
	logmax := flag.Int("logmax", 96, "circuit LogMax")
	maxlogs := flag.Int("maxlogs", 4, "circuit MaxLogs")
	ptau := flag.String("ptau", "", "path to a real powersOfTau .ptau file")
	outDir := flag.String("outdir", "generated", "")
	name := flag.String("name", "M7Verifier", "verifier name")
	flag.Parse()

	must(os.MkdirAll(*outDir, 0o755))
	rep := report{Tx: *tx, LogIndex: *logIndex, N: *n, LogMax: *logmax, MaxLogs: *maxlogs, Ptau: *ptau}

	// ---- real leaf ----
	var rows []leafRow
	b, err := os.ReadFile(*leavesPath)
	must(err)
	must(json.Unmarshal(b, &rows))
	var row *leafRow
	for i := range rows {
		if rows[i].Tx == *tx {
			row = &rows[i]
		}
	}
	if row == nil {
		fatal("tx %d not found", *tx)
	}
	leaf, err := hex.DecodeString(row.LeafHex)
	must(err)
	rep.LeafLen, rep.NLogs, rep.TxType, rep.LeafHash = row.LeafLen, row.NLogs, row.TxType, row.LeafHash
	fmt.Printf("real receipt-trie leaf: tx=%d len=%d n_logs=%d tx_type=%d hash=%s\n",
		row.Tx, len(leaf), row.NLogs, row.TxType, row.LeafHash)

	p := circuit.Params{N: *n, LogMax: *logmax, MaxLogs: *maxlogs}

	// ---- compile ----
	t0 := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit.New(p))
	must(err)
	rep.CompileSec = time.Since(t0).Seconds()
	rep.NbConstraints = ccs.GetNbConstraints()
	rep.NbPublic = ccs.GetNbPublicVariables()
	rep.Commitments = len(ccs.GetCommitments().CommitmentIndexes())
	size := ecc.NextPowerOfTwo(uint64(rep.NbConstraints+rep.NbPublic)) + 3
	rep.DomainSize = size
	fmt.Printf("compiled: nbConstraints=%d nbPublic=%d commitments=%d -> SRS size needed %d (domain 2^%d)\n",
		rep.NbConstraints, rep.NbPublic, rep.Commitments, size, log2(size-3))

	// ---- real trusted setup from the ceremony file ----
	if *ptau == "" {
		fatal("-ptau is required: this pass does not accept a TestOnly setup")
	}
	f, err := os.Open(*ptau)
	must(err)
	t0 = time.Now()
	srsFull, err := gp.ToSRS(f)
	must(err)
	f.Close()
	rep.SRSLoadSec = time.Since(t0).Seconds()
	rep.SRSPoints = len(srsFull.Pk.G1)
	rep.PtauPower = log2(uint64((len(srsFull.Pk.G1) + 1) / 2))
	fmt.Printf("ptau: %d G1 points (power 2^%d), loaded in %.1fs\n",
		rep.SRSPoints, rep.PtauPower, rep.SRSLoadSec)
	if uint64(len(srsFull.Pk.G1)) < size {
		fatal("ceremony too small: %d points < %d needed", len(srsFull.Pk.G1), size)
	}

	// truncate to exactly what PLONK needs and release the rest
	srs := &kzgbn.SRS{Vk: srsFull.Vk}
	srs.Pk.G1 = make([]bn254.G1Affine, size)
	copy(srs.Pk.G1, srsFull.Pk.G1[:size])
	srsFull.Pk.G1 = nil
	srsFull = nil
	runtime.GC()

	t0 = time.Now()
	lag := &kzgbn.SRS{Vk: srs.Vk}
	lagG1, err := kzgbn.ToLagrangeG1(srs.Pk.G1[:len(srs.Pk.G1)-3])
	must(err)
	lag.Pk.G1 = lagG1
	rep.LagrangeSec = time.Since(t0).Seconds()
	fmt.Printf("lagrange SRS built in %.1fs\n", rep.LagrangeSec)

	t0 = time.Now()
	pk, vk, err := plonk.Setup(ccs, srs, lag)
	must(err)
	rep.SetupSec = time.Since(t0).Seconds()
	fmt.Printf("plonk.Setup in %.1fs\n", rep.SetupSec)

	cc := &ap.CompiledCircuit{Ccs: ccs, Pk: pk, Vk: vk, Curve: ecc.BN254}

	// ---- AlgoPlonk verifier codegen (unmodified AlgoPlonk code) ----
	pyPath := *outDir + "/" + *name + ".py"
	must(cc.WritePuyaPyVerifier(pyPath, verifier.LogicSig))
	fmt.Printf("wrote AlgoPlonk logicsig verifier source: %s\n", pyPath)

	// ---- witness from the real leaf, then a real proof ----
	asg, err := circuit.Witness(p, leaf, *logIndex)
	must(err)
	t0 = time.Now()
	vp, err := cc.Verify(asg) // Prove + Verify
	must(err)
	el := time.Since(t0).Seconds()
	rep.ProveSec = el
	fmt.Printf("plonk.Prove + plonk.Verify OK in %.1fs\n", el)

	proofPath := *outDir + "/" + *name + ".proof"
	piPath := *outDir + "/" + *name + ".public_inputs"
	must(vp.ExportProofAndPublicInputs(proofPath, piPath))
	pb, _ := os.ReadFile(proofPath)
	pib, _ := os.ReadFile(piPath)
	rep.ProofBytes, rep.PublicInputBytes = len(pb), len(pib)
	for i := 0; i+32 <= len(pib); i += 32 {
		rep.PublicInputsHex = append(rep.PublicInputsHex, hex.EncodeToString(pib[i:i+32]))
	}
	fmt.Printf("proof=%d bytes public_inputs=%d bytes (%d field elements)\n",
		len(pb), len(pib), len(pib)/32)

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	rep.PeakRSSMB = m.Sys / 1024 / 1024

	rb, _ := json.MarshalIndent(rep, "", "  ")
	must(os.WriteFile(*outDir+"/"+*name+".report.json", rb, 0o644))
	fmt.Println("report written")
}

func log2(x uint64) int {
	n := 0
	for x > 1 {
		x >>= 1
		n++
	}
	return n
}

func must(err error) {
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}
func fatal(f string, a ...interface{}) { fmt.Printf("ERROR: "+f+"\n", a...); os.Exit(1) }
