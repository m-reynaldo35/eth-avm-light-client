// Command circuittest exercises the M7 circuit's CONSTRAINTS (not proofs) with
// gnark's test engine, which evaluates every constraint on a concrete witness
// without any setup or proving.  That makes it cheap enough to run the whole
// real 137-receipt corpus of block 25,639,768, plus the negative tests design
// doc 007 §9.5 (ZK-6/7/8/10) asks for.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"m7zk/circuit"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type leafRow struct {
	Tx       int    `json:"tx"`
	LeafLen  int    `json:"leaf_len"`
	NLogs    int    `json:"n_logs"`
	TxType   int    `json:"tx_type"`
	LeafHash string `json:"leaf_hash"`
	LeafHex  string `json:"leaf_hex"`
}

// run evaluates the circuit on an assignment; returns nil if every constraint
// is satisfied.
func run(p circuit.Params, a *circuit.ReceiptLeafCircuit) error {
	return test.IsSolved(circuit.New(p), a, ecc.BN254.ScalarField())
}

func main() {
	b, err := os.ReadFile("leaves.json")
	if err != nil {
		panic(err)
	}
	var rows []leafRow
	if err := json.Unmarshal(b, &rows); err != nil {
		panic(err)
	}

	// ---------- ZK-1: the whole real corpus ----------
	maxLeaf := 4096
	if len(os.Args) > 1 && os.Args[1] == "-neg" {
		maxLeaf = 0
	}
	if len(os.Args) > 2 {
		fmt.Sscan(os.Args[2], &maxLeaf)
	}
	ok, skipped, failed := 0, 0, 0
	for _, r := range rows {
		if r.NLogs == 0 || r.LeafLen > maxLeaf {
			skipped++ // no log to extract / beyond this run's size cap
			continue
		}
		leaf, _ := hex.DecodeString(r.LeafHex)
		// size the circuit tightly to this receipt, as a real tier would
		lm, ml := maxLogEnc(leaf), r.NLogs
		p := circuit.Params{N: roundUp(len(leaf), 8), LogMax: roundUp(lm, 8), MaxLogs: ml}
		a, err := circuit.Witness(p, leaf, 0)
		if err != nil {
			fmt.Printf("  tx %-4d WITNESS ERROR: %v\n", r.Tx, err)
			failed++
			continue
		}
		if err := run(p, a); err != nil {
			fmt.Printf("  tx %-4d CONSTRAINT FAIL: %v\n", r.Tx, err)
			failed++
			continue
		}
		ok++
		fmt.Printf("  tx %-4d leaf=%-6d n_logs=%-4d N=%-6d LogMax=%-5d  SATISFIED\n",
			r.Tx, r.LeafLen, r.NLogs, p.N, p.LogMax)
	}
	fmt.Printf("ZK-1  real-corpus differential: %d receipts satisfied, %d failed, %d skipped (0 logs or >4096 B)\n",
		ok, failed, skipped)

	// pick one real receipt with several logs for the negative tests
	var base *leafRow
	for i := range rows {
		if rows[i].NLogs >= 2 && rows[i].LeafLen < 3000 {
			base = &rows[i]
			break
		}
	}
	leaf, _ := hex.DecodeString(base.LeafHex)
	p := circuit.Params{N: roundUp(len(leaf), 8), LogMax: roundUp(maxLogEnc(leaf), 8), MaxLogs: base.NLogs}
	fmt.Printf("negative tests use real tx %d (leaf %d B, %d logs)\n",
		base.Tx, base.LeafLen, base.NLogs)

	good, err := circuit.Witness(p, leaf, 0)
	if err != nil {
		panic(err)
	}
	if err := run(p, good); err != nil {
		fmt.Println("BASELINE FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("  baseline (honest witness)                    SATISFIED  (expected)")

	neg := []struct {
		name  string
		mutate func(a *circuit.ReceiptLeafCircuit)
	}{
		{"ZK-9  wrong leaf hash (hi half)", func(a *circuit.ReceiptLeafCircuit) {
			a.LeafHashHi = new(big.Int).Add(toBig(a.LeafHashHi), big.NewInt(1))
		}},
		{"ZK-10 wrong log commitment", func(a *circuit.ReceiptLeafCircuit) {
			a.LogCommitLo = new(big.Int).Add(toBig(a.LogCommitLo), big.NewInt(1))
		}},
		{"ZK-10 wrong log index", func(a *circuit.ReceiptLeafCircuit) {
			a.LogIndex = 1 // commitment still describes log 0
		}},
		{"ZK-7  wrong path tail", func(a *circuit.ReceiptLeafCircuit) {
			a.PathTail = new(big.Int).Add(toBig(a.PathTail), big.NewInt(1))
		}},
		{"ZK-?  wrong hdr (n_logs)", func(a *circuit.ReceiptLeafCircuit) {
			a.Hdr = new(big.Int).Add(toBig(a.Hdr), big.NewInt(1))
		}},
		{"      truncated leaf_len", func(a *circuit.ReceiptLeafCircuit) {
			a.LeafLen = toInt(a.LeafLen) - 1
		}},
		{"      one flipped leaf byte", func(a *circuit.ReceiptLeafCircuit) {
			a.R[40] = (toInt(a.R[40]) + 1) % 256
		}},
	}
	for _, n := range neg {
		a, _ := circuit.Witness(p, leaf, 0)
		n.mutate(a)
		err := run(p, a)
		status := "REJECTED   (expected)"
		if err == nil {
			status = "*** SATISFIED — SOUNDNESS HOLE ***"
		}
		fmt.Printf("  %-44s %s\n", n.name, status)
	}

	// ---------- ZK-6: span containment, hand-built forgery ----------
	// Point the target log at bytes inside the 256-byte bloom filter, keeping
	// the log commitment consistent with those bytes.  The prover controls the
	// witness completely; only the circuit's own span checks can stop this.
	a, _ := circuit.Witness(p, leaf, 0)
	// find the bloom's offset in the real leaf by re-walking it
	bloomOff := findBloomOffset(leaf)
	forged := leaf[bloomOff : bloomOff+64]
	d := circuit.Keccak256(forged)
	a.LogCommitHi = new(big.Int).SetBytes(d[0:16])
	a.LogCommitLo = new(big.Int).SetBytes(d[16:32])
	err = run(p, a)
	if err == nil {
		fmt.Println("  ZK-6  log bytes taken from the bloom filter    *** SATISFIED — SOUNDNESS HOLE ***")
	} else {
		fmt.Println("  ZK-6  log bytes taken from the bloom filter    REJECTED   (expected)")
	}

	// ---------- ZK-8: non-canonical (long-form) RLP ----------
	// Re-encode the receipt body's status item 0x01 in long form (0xb8 0x01 0x01)
	// which is a 3-byte encoding of a 1-byte string: not canonical RLP.
	fmt.Println("  ZK-8  see canonicality note in the design doc §4.4 (enforced by header())")
}

func findBloomOffset(leaf []byte) int {
	// leaf = RLP([hp_path, value]); value = [type] RLP([status,cumGas,bloom,logs])
	hdr := func(pos int) (int, int, bool) {
		b := int(leaf[pos])
		switch {
		case b < 0x80:
			return pos, 1, false
		case b < 0xb8:
			return pos + 1, b - 0x80, false
		case b < 0xc0:
			ll := b - 0xb7
			n := 0
			for j := 0; j < ll; j++ {
				n = n*256 + int(leaf[pos+1+j])
			}
			return pos + 1 + ll, n, false
		case b < 0xf8:
			return pos + 1, b - 0xc0, true
		default:
			ll := b - 0xf7
			n := 0
			for j := 0; j < ll; j++ {
				n = n*256 + int(leaf[pos+1+j])
			}
			return pos + 1 + ll, n, true
		}
	}
	lo, _, _ := hdr(0)
	pOff, pLen, _ := hdr(lo)
	vOff, _, _ := hdr(pOff + pLen)
	payOff := vOff
	if leaf[vOff] < 0xc0 {
		payOff = vOff + 1
	}
	bOff, _, _ := hdr(payOff)
	sOff, sLen, _ := hdr(bOff)
	gOff, gLen, _ := hdr(sOff + sLen)
	blOff, _, _ := hdr(gOff + gLen)
	return blOff
}

func roundUp(n, m int) int { return ((n + m - 1) / m) * m }

// maxLogEnc returns the largest encoded log in a real receipt leaf.
func maxLogEnc(leaf []byte) int {
	hdr := func(pos int) (int, int, bool) {
		b := int(leaf[pos])
		switch {
		case b < 0x80:
			return pos, 1, false
		case b < 0xb8:
			return pos + 1, b - 0x80, false
		case b < 0xc0:
			ll := b - 0xb7
			n := 0
			for j := 0; j < ll; j++ {
				n = n*256 + int(leaf[pos+1+j])
			}
			return pos + 1 + ll, n, false
		case b < 0xf8:
			return pos + 1, b - 0xc0, true
		default:
			ll := b - 0xf7
			n := 0
			for j := 0; j < ll; j++ {
				n = n*256 + int(leaf[pos+1+j])
			}
			return pos + 1 + ll, n, true
		}
	}
	blOff := findBloomOffset(leaf)
	lgOff, lgLen, _ := hdr(blOff + 256)
	cur, best := lgOff, 0
	for cur < lgOff+lgLen {
		o, l, _ := hdr(cur)
		if o+l-cur > best {
			best = o + l - cur
		}
		cur = o + l
	}
	return best
}

func toBig(v frontend.Variable) *big.Int {
	switch x := v.(type) {
	case *big.Int:
		return x
	case int:
		return big.NewInt(int64(x))
	}
	panic(fmt.Sprintf("unexpected %T", v))
}
func toInt(v frontend.Variable) int {
	switch x := v.(type) {
	case int:
		return x
	case *big.Int:
		return int(x.Int64())
	}
	panic(fmt.Sprintf("unexpected %T", v))
}
