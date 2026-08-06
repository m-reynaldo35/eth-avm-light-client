// Command setupkeys runs the ONE-TIME, per-tier part of the M7 T3 pipeline:
// compile the circuit, load the real ceremony, build the Lagrange SRS, run
// plonk.Setup, and persist the resulting ConstraintSystem/ProvingKey/VerifyingKey
// to disk -- plus the AlgoPlonk verifier source, which is also witness-independent.
//
// This is the split cmd/prove never had: cmd/prove redid this every single time,
// bundling a ~30-70 minute one-time cost into every "per proof" measurement.
// cmd/provewith is the fast counterpart that loads what this command writes and
// only pays the real per-receipt marginal cost (witness + Prove + Verify).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
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

type setupReport struct {
	N, LogMax, MaxLogs                  int
	NbConstraints, NbPublic             int
	Commitments                         int
	DomainSize                          uint64
	Ptau                                string
	PtauPower, SRSPoints                int
	CompileSec, SRSLoadSec, LagrangeSec float64
	SetupSec                            float64
	TotalSec                            float64
	PeakRSSMB                           uint64
}

func main() {
	n := flag.Int("n", 384, "circuit N")
	logmax := flag.Int("logmax", 96, "circuit LogMax")
	maxlogs := flag.Int("maxlogs", 4, "circuit MaxLogs")
	ptau := flag.String("ptau", "", "path to a real powersOfTau .ptau file")
	outDir := flag.String("outdir", "keys", "")
	name := flag.String("name", "M7Verifier", "verifier name")
	flag.Parse()

	must(os.MkdirAll(*outDir, 0o755))
	rep := setupReport{N: *n, LogMax: *logmax, MaxLogs: *maxlogs, Ptau: *ptau}
	tStart := time.Now()

	p := circuit.Params{N: *n, LogMax: *logmax, MaxLogs: *maxlogs}

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

	// ---- persist ccs/pk/vk to disk: the whole point of this command ----
	writeFile(*outDir+"/"+*name+".ccs", ccs.WriteTo)
	writeFile(*outDir+"/"+*name+".pk", pk.WriteTo)
	writeFile(*outDir+"/"+*name+".vk", vk.WriteTo)
	fmt.Printf("wrote %s.{ccs,pk,vk} to %s\n", *name, *outDir)

	// ---- AlgoPlonk verifier codegen: also witness-independent, also cacheable ----
	cc := &ap.CompiledCircuit{Ccs: ccs, Pk: pk, Vk: vk, Curve: ecc.BN254}
	pyPath := *outDir + "/" + *name + ".py"
	must(cc.WritePuyaPyVerifier(pyPath, verifier.LogicSig))
	fmt.Printf("wrote AlgoPlonk logicsig verifier source: %s\n", pyPath)

	rep.TotalSec = time.Since(tStart).Seconds()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	rep.PeakRSSMB = m.Sys / 1024 / 1024

	rb, _ := json.MarshalIndent(rep, "", "  ")
	must(os.WriteFile(*outDir+"/"+*name+".setup_report.json", rb, 0o644))
	fmt.Printf("ONE-TIME setup done in %.1fs total. Run cmd/provewith against %s to prove any number of receipts.\n",
		rep.TotalSec, *outDir)
}

func writeFile(path string, writeTo func(w io.Writer) (int64, error)) {
	f, err := os.Create(path)
	must(err)
	defer f.Close()
	_, err = writeTo(f)
	must(err)
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
