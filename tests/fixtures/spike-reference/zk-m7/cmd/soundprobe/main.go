// Command soundprobe tests specific UNDER-CONSTRAINED-witness hypotheses about
// M7's circuit, using gnark's test engine (every constraint evaluated on a
// concrete witness, no setup/proving).
//
// Each probe states what a malicious prover would try and what the circuit
// SHOULD do. A probe that reports "SATISFIED" is a witness the circuit accepts
// that an honest prover would never produce.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"m7zk/circuit"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/test"
)

type leafRow struct {
	Tx      int    `json:"tx"`
	LeafLen int    `json:"leaf_len"`
	NLogs   int    `json:"n_logs"`
	LeafHex string `json:"leaf_hex"`
}

func solved(p circuit.Params, a *circuit.ReceiptLeafCircuit) error {
	return test.IsSolved(circuit.New(p), a, ecc.BN254.ScalarField())
}

func report(name, expect string, err error) {
	status := "SATISFIED"
	if err != nil {
		status = "rejected"
	}
	flag := ""
	if (expect == "reject") != (err != nil) {
		flag = "   <<< UNEXPECTED"
	}
	fmt.Printf("  %-58s %-10s (want %s)%s\n", name, status, expect, flag)
	if err != nil && os.Getenv("VERBOSE") != "" {
		fmt.Printf("      %v\n", err)
	}
}

func main() {
	b, err := os.ReadFile("leaves.json")
	must(err)
	var rows []leafRow
	must(json.Unmarshal(b, &rows))

	// pick a real receipt with several logs so LogIndex probes are meaningful
	var leaf []byte
	var row leafRow
	for _, r := range rows {
		if r.NLogs >= 2 && r.LeafLen <= 700 {
			row = r
			leaf, _ = hex.DecodeString(r.LeafHex)
			break
		}
	}
	if leaf == nil {
		fmt.Println("no suitable receipt")
		os.Exit(1)
	}
	p := circuit.Params{N: 704, LogMax: 320, MaxLogs: 8}
	fmt.Printf("base receipt: tx=%d leaf=%d B n_logs=%d   circuit N=%d LogMax=%d MaxLogs=%d\n\n",
		row.Tx, row.LeafLen, row.NLogs, p.N, p.LogMax, p.MaxLogs)

	base, err := circuit.Witness(p, leaf, 0)
	must(err)
	fmt.Println("control:")
	report("honest witness", "satisfy", solved(p, base))

	modulus := fr.Modulus()

	fmt.Println("\nprobe A -- LogIndex is a public input; is it range-constrained?")
	// A1: LogIndex = p-1 (i.e. -1 in the field). The bounded comparator used by
	// AssertIsLess(LogIndex, nLogs) is only guaranteed correct when
	// |LogIndex - nLogs| <= 2^34.
	a1, _ := circuit.Witness(p, leaf, 0)
	a1.LogIndex = new(big.Int).Sub(modulus, big.NewInt(1))
	// with no matching k, logOff/logLen stay 0, so the log commitment the
	// circuit computes is keccak256("")
	empty := circuit.Keccak256(nil)
	a1.LogCommitHi = new(big.Int).SetBytes(empty[0:16])
	a1.LogCommitLo = new(big.Int).SetBytes(empty[16:32])
	report("LogIndex = P-1, LogCommit = keccak256(\"\")", "reject", solved(p, a1))

	// A2: LogIndex just above the real log count but small
	a2, _ := circuit.Witness(p, leaf, 0)
	a2.LogIndex = row.NLogs
	a2.LogCommitHi = new(big.Int).SetBytes(empty[0:16])
	a2.LogCommitLo = new(big.Int).SetBytes(empty[16:32])
	report(fmt.Sprintf("LogIndex = n_logs (=%d), out of range", row.NLogs), "reject", solved(p, a2))

	// A3: LogIndex = 2^34 (just past the comparator's bound)
	a3, _ := circuit.Witness(p, leaf, 0)
	a3.LogIndex = new(big.Int).Lsh(big.NewInt(1), 34)
	a3.LogCommitHi = new(big.Int).SetBytes(empty[0:16])
	a3.LogCommitLo = new(big.Int).SetBytes(empty[16:32])
	report("LogIndex = 2^34 (past comparator bound)", "reject", solved(p, a3))

	fmt.Println("\nprobe B -- LeafLen is a free private witness; is it pinned?")
	b1, _ := circuit.Witness(p, leaf, 0)
	b1.LeafLen = new(big.Int).Sub(modulus, big.NewInt(1))
	report("LeafLen = P-1", "reject", solved(p, b1))

	fmt.Println("\nprobe C -- hex-prefix canonicality: even path with non-zero low nibble")
	// For an EVEN-length hp_path the low nibble of byte 0 must be 0. The circuit
	// does api.Select(odd, lo0, 0) -- it IGNORES the nibble rather than
	// asserting it is zero. Flip it and recompute the leaf hash so assertion (1)
	// still holds, i.e. a DIFFERENT byte string that the circuit still accepts.
	c1 := make([]byte, len(leaf))
	copy(c1, leaf)
	// locate hp_path first byte the same way assign.go does
	lo, _, _ := hdr(c1, 0)
	pOff, _, _ := hdr(c1, lo)
	if c1[pOff]>>4 == 2 && c1[pOff]&0x0f == 0 {
		c1[pOff] |= 0x0d // even path, low nibble now 0xd instead of 0
		w, werr := circuit.Witness(p, c1, 0)
		if werr != nil {
			fmt.Printf("  (witness builder rejected it: %v)\n", werr)
		} else {
			report("even hp_path with low nibble = 0xd (hash recomputed)", "reject", solved(p, w))
			fmt.Println("      note: the leaf hash is recomputed, so assertion (1) still holds.")
			fmt.Println("      This is a canonicality gap, not a forgery: the attacker would")
			fmt.Println("      still need this byte string to be the REAL trie leaf.")
		}
	} else {
		fmt.Printf("  (base receipt's path is odd or already non-zero; skipped)\n")
	}

	fmt.Println("\nprobe D -- span containment (the constraint §4.4 calls most important)")
	d1, _ := circuit.Witness(p, leaf, 0)
	d1.LogIndex = 0
	// point the log commitment at bloom-filter bytes
	report("re-run of §4.14's ZK-6 shape (control)", "satisfy", solved(p, d1))
}

func hdr(b []byte, pos int) (payOff, payLen int, isList bool) {
	x := int(b[pos])
	switch {
	case x < 0x80:
		return pos, 1, false
	case x < 0xb8:
		return pos + 1, x - 0x80, false
	case x < 0xc0:
		ll := x - 0xb7
		n := 0
		for j := 0; j < ll; j++ {
			n = n*256 + int(b[pos+1+j])
		}
		return pos + 1 + ll, n, false
	case x < 0xf8:
		return pos + 1, x - 0xc0, true
	default:
		ll := x - 0xf7
		n := 0
		for j := 0; j < ll; j++ {
			n = n*256 + int(b[pos+1+j])
		}
		return pos + 1 + ll, n, true
	}
}

func must(err error) {
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}
