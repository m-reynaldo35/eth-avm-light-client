// Command provewith is the fast, repeatable counterpart to cmd/setupkeys: it
// LOADS an already-computed ConstraintSystem/ProvingKey/VerifyingKey from disk
// (produced once by cmd/setupkeys) and only pays the real per-receipt marginal
// cost -- witness generation + plonk.Prove + plonk.Verify -- instead of redoing
// compile/SRS-load/Lagrange-build/Setup every single time the way cmd/prove does.
//
// This is what answers the real question: does proving a NEW receipt after the
// one-time setup cost ~3 minutes, or ~30-70 minutes? cmd/prove could never answer
// that because it always bundled both costs together.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"m7zk/circuit"

	ap "github.com/giuliop/algoplonk"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
)

type leafRow struct {
	Tx       int    `json:"tx"`
	LeafLen  int    `json:"leaf_len"`
	NLogs    int    `json:"n_logs"`
	TxType   int    `json:"tx_type"`
	LeafHash string `json:"leaf_hash"`
	LeafHex  string `json:"leaf_hex"`
}

type marginalReport struct {
	Tx, LogIndex                 int
	KeysDir                      string
	LoadKeysSec                  float64
	ProveSec                     float64
	TotalMarginalSec             float64
	ProofBytes, PublicInputBytes int
	LeafHash                     string
	PublicInputsHex              []string
}

func main() {
	leavesPath := flag.String("leaves", "leaves.json", "")
	tx := flag.Int("tx", 85, "transaction index in block 25,639,768")
	logIndex := flag.Int("logindex", 0, "")
	n := flag.Int("n", 384, "circuit N (must match the cached keys)")
	logmax := flag.Int("logmax", 96, "circuit LogMax (must match the cached keys)")
	maxlogs := flag.Int("maxlogs", 4, "circuit MaxLogs (must match the cached keys)")
	keysDir := flag.String("keysdir", "keys", "directory cmd/setupkeys wrote to")
	keysName := flag.String("keysname", "M7Verifier", "the -name cmd/setupkeys was given")
	outDir := flag.String("outdir", "generated", "")
	name := flag.String("name", "M7Proof", "")
	flag.Parse()

	must(os.MkdirAll(*outDir, 0o755))
	rep := marginalReport{Tx: *tx, LogIndex: *logIndex, KeysDir: *keysDir}
	tMarginalStart := time.Now()

	// ---- real leaf (per-receipt, always needed) ----
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
	rep.LeafHash = row.LeafHash
	fmt.Printf("real receipt-trie leaf: tx=%d len=%d n_logs=%d tx_type=%d hash=%s\n",
		row.Tx, len(leaf), row.NLogs, row.TxType, row.LeafHash)

	// ---- load the cached ccs/pk/vk: THE step this whole command exists to measure ----
	t0 := time.Now()
	ccs := plonk.NewCS(ecc.BN254)
	readFile(*keysDir+"/"+*keysName+".ccs", ccs.ReadFrom)
	pk := plonk.NewProvingKey(ecc.BN254)
	readFile(*keysDir+"/"+*keysName+".pk", pk.ReadFrom)
	vk := plonk.NewVerifyingKey(ecc.BN254)
	readFile(*keysDir+"/"+*keysName+".vk", vk.ReadFrom)
	rep.LoadKeysSec = time.Since(t0).Seconds()
	fmt.Printf("loaded cached ccs/pk/vk from %s in %.2fs (no compile, no SRS, no Lagrange, no Setup)\n",
		*keysDir, rep.LoadKeysSec)

	cc := &ap.CompiledCircuit{Ccs: ccs, Pk: pk, Vk: vk, Curve: ecc.BN254}

	// ---- witness from the real leaf, then a real proof: the only work that must
	// happen per receipt ----
	p := circuit.Params{N: *n, LogMax: *logmax, MaxLogs: *maxlogs}
	asg, err := circuit.Witness(p, leaf, *logIndex)
	must(err)
	t0 = time.Now()
	vp, err := cc.Verify(asg) // Prove + Verify
	must(err)
	rep.ProveSec = time.Since(t0).Seconds()
	fmt.Printf("plonk.Prove + plonk.Verify OK in %.1fs\n", rep.ProveSec)

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

	rep.TotalMarginalSec = time.Since(tMarginalStart).Seconds()
	fmt.Printf("TOTAL MARGINAL TIME (this is the real per-customer-request cost): %.1fs\n", rep.TotalMarginalSec)

	rb, _ := json.MarshalIndent(rep, "", "  ")
	must(os.WriteFile(*outDir+"/"+*name+".marginal_report.json", rb, 0o644))
	fmt.Println("report written")
}

func readFile(path string, readFrom func(r io.Reader) (int64, error)) {
	f, err := os.Open(path)
	must(err)
	defer f.Close()
	_, err = readFrom(f)
	must(err)
}

func must(err error) {
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}
func fatal(f string, a ...interface{}) { fmt.Printf("ERROR: "+f+"\n", a...); os.Exit(1) }
