// Command measure compiles the real M7 receipt-leaf circuit at a range of
// sizes and reports the REAL constraint counts, so §4.5's projected formula can
// be replaced with a measured one.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"m7zk/circuit"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

type row struct {
	N, LogMax, MaxLogs        int
	Curve                     string
	NbConstraints             int
	NbInternal, NbSecret, NbP int
	Commitments               int
	Blocks                    int
	CompileSec                float64
	PeakHeapMB                uint64
}

func main() {
	sizes := flag.String("sizes", "256,512,1024,2048", "comma list of N")
	logmax := flag.Int("logmax", 320, "LogMax bytes")
	maxlogs := flag.Int("maxlogs", 8, "MaxLogs")
	curve := flag.String("curve", "bn254", "bn254|bls12381")
	out := flag.String("out", "", "json output path")
	flag.Parse()

	id := ecc.BN254
	if *curve == "bls12381" {
		id = ecc.BLS12_381
	}

	var ns []int
	if _, err := fmt.Sscan(""); err != nil {
		_ = err
	}
	for _, s := range splitInts(*sizes) {
		ns = append(ns, s)
	}

	var rows []row
	for _, n := range ns {
		p := circuit.Params{N: n, LogMax: *logmax, MaxLogs: *maxlogs}
		t0 := time.Now()
		ccs, err := frontend.Compile(id.ScalarField(), scs.NewBuilder, circuit.New(p))
		if err != nil {
			fmt.Printf("N=%d COMPILE ERROR: %v\n", n, err)
			continue
		}
		el := time.Since(t0).Seconds()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		nbC := ccs.GetNbConstraints()
		comm := len(ccs.GetCommitments().CommitmentIndexes())
		r := row{N: n, LogMax: *logmax, MaxLogs: *maxlogs, Curve: id.String(),
			NbConstraints: nbC, NbInternal: ccs.GetNbInternalVariables(),
			NbSecret: ccs.GetNbSecretVariables(), NbP: ccs.GetNbPublicVariables(),
			Commitments: comm, Blocks: (n + 1 + 135) / 136,
			CompileSec: el, PeakHeapMB: m.TotalAlloc / 1024 / 1024}
		rows = append(rows, r)
		fmt.Printf("N=%-6d logmax=%-4d maxlogs=%-3d  nbConstraints=%-10d commitments=%d  pub=%d secret=%d  compile=%.1fs\n",
			n, *logmax, *maxlogs, nbC, comm, r.NbP, r.NbSecret, el)
		ccs = nil
		runtime.GC()
	}
	if *out != "" {
		b, _ := json.MarshalIndent(rows, "", "  ")
		os.WriteFile(*out, b, 0644)
	}
}

func splitInts(s string) []int {
	var out []int
	cur := -1
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if cur >= 0 {
				out = append(out, cur)
			}
			cur = -1
			continue
		}
		if s[i] >= '0' && s[i] <= '9' {
			if cur < 0 {
				cur = 0
			}
			cur = cur*10 + int(s[i]-'0')
		}
	}
	return out
}
