package circuit

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"golang.org/x/crypto/sha3"
)

// Keccak256 is the real (legacy, 0x01-padded) Keccak-256, for witness building.
func Keccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return h.Sum(nil)
}

func halves(d []byte) (*big.Int, *big.Int) {
	return new(big.Int).SetBytes(d[0:16]), new(big.Int).SetBytes(d[16:32])
}

// Witness is the off-circuit RLP walk that produces the assignment.  It is a
// deliberate second implementation of the same structure the circuit enforces:
// if the two disagree, the proof simply fails, which is the cheap differential
// test the design doc §9.5 asks for.
func Witness(p Params, leaf []byte, logIndex int) (*ReceiptLeafCircuit, error) {
	if len(leaf) > p.N {
		return nil, fmt.Errorf("leaf %d bytes > circuit N=%d", len(leaf), p.N)
	}
	rd := func(off int) byte { return leaf[off] }

	// header decode, same five cases as rlp.go / core.py
	header := func(pos int) (payOff, payLen int, isList bool) {
		b := int(rd(pos))
		switch {
		case b < 0x80:
			return pos, 1, false
		case b < 0xb8:
			return pos + 1, b - 0x80, false
		case b < 0xc0:
			ll := b - 0xb7
			n := 0
			for j := 0; j < ll; j++ {
				n = n*256 + int(rd(pos+1+j))
			}
			return pos + 1 + ll, n, false
		case b < 0xf8:
			return pos + 1, b - 0xc0, true
		default:
			ll := b - 0xf7
			n := 0
			for j := 0; j < ll; j++ {
				n = n*256 + int(rd(pos+1+j))
			}
			return pos + 1 + ll, n, true
		}
	}

	lo, ll, isL := header(0)
	if !isL || lo+ll != len(leaf) {
		return nil, fmt.Errorf("leaf is not a well-formed 2-item RLP list")
	}
	pOff, pLen, _ := header(lo)
	b0 := rd(pOff)
	if b0>>4 != 2 && b0>>4 != 3 {
		return nil, fmt.Errorf("hp_path prefix %x is not a leaf", b0>>4)
	}
	odd := int(b0>>4) & 1
	var nibs []int
	if odd == 1 {
		nibs = append(nibs, int(b0&0xf))
	}
	for j := 1; j < pLen; j++ {
		bj := rd(pOff + j)
		nibs = append(nibs, int(bj>>4), int(bj&0xf))
	}
	accPath := big.NewInt(0)
	for _, x := range nibs {
		accPath.Mul(accPath, big.NewInt(16))
		accPath.Add(accPath, big.NewInt(int64(x)))
	}
	pathTail := new(big.Int).Lsh(big.NewInt(int64(len(nibs))), 60)
	pathTail.Add(pathTail, accPath)

	vOff, vLen, _ := header(pOff + pLen)
	if vOff+vLen != lo+ll {
		return nil, fmt.Errorf("value span does not close the leaf")
	}
	txType := 0
	payOff := vOff
	if rd(vOff) < 0xc0 {
		txType = int(rd(vOff))
		payOff = vOff + 1
	}
	bOff, bLen, bIsL := header(payOff)
	if !bIsL || bOff+bLen != vOff+vLen {
		return nil, fmt.Errorf("receipt body is not a closing RLP list")
	}
	sOff, sLen, _ := header(bOff)
	status := 0
	if sLen == 1 {
		status = int(rd(sOff))
	}
	gOff, gLen, _ := header(sOff + sLen)
	cumGas := new(big.Int).SetBytes(leaf[gOff : gOff+gLen])
	blOff, blLen, _ := header(gOff + gLen)
	if blLen != 256 {
		return nil, fmt.Errorf("bloom is %d bytes, want 256", blLen)
	}
	lgOff, lgLen, lgIsL := header(blOff + blLen)
	if !lgIsL || lgOff+lgLen != bOff+bLen {
		return nil, fmt.Errorf("logs list does not close the body")
	}
	cur := lgOff
	nLogs := 0
	logStart, logSpan := 0, 0
	for cur < lgOff+lgLen {
		o, l, isl := header(cur)
		if !isl {
			return nil, fmt.Errorf("log %d is not a list", nLogs)
		}
		if nLogs == logIndex {
			logStart, logSpan = cur, o+l-cur
		}
		nLogs++
		cur = o + l
	}
	if nLogs > p.MaxLogs {
		return nil, fmt.Errorf("receipt has %d logs > circuit MaxLogs=%d", nLogs, p.MaxLogs)
	}
	if logIndex >= nLogs {
		return nil, fmt.Errorf("log_index %d >= n_logs %d", logIndex, nLogs)
	}
	if logSpan > p.LogMax {
		return nil, fmt.Errorf("log is %d bytes > circuit LogMax=%d", logSpan, p.LogMax)
	}
	// gnark's hash.WithMinimalLength ASSERTS minimalLength <= length, so a
	// receipt below a tier's declared minimum genuinely cannot use that tier.
	if p.MinLeaf > 0 && len(leaf) < p.MinLeaf {
		return nil, fmt.Errorf("leaf %d bytes < circuit MinLeaf=%d", len(leaf), p.MinLeaf)
	}
	if p.MinLog > 0 && logSpan < p.MinLog {
		return nil, fmt.Errorf("log %d bytes < circuit MinLog=%d", logSpan, p.MinLog)
	}

	hdr := big.NewInt(int64(txType*2 + status))
	hdr.Lsh(hdr, 64)
	hdr.Add(hdr, cumGas)
	hdr.Lsh(hdr, 16)
	hdr.Add(hdr, big.NewInt(int64(nLogs)))

	lh, ll2 := halves(Keccak256(leaf))
	logBytes := leaf[logStart : logStart+logSpan]
	var logCommit []byte
	if p.LogSHA256 {
		sum := sha256.Sum256(logBytes)
		logCommit = sum[:]
	} else {
		logCommit = Keccak256(logBytes)
	}
	ch, cl := halves(logCommit)

	a := New(p)
	a.LeafHashHi, a.LeafHashLo = lh, ll2
	a.LogCommitHi, a.LogCommitLo = ch, cl
	a.LogIndex = logIndex
	a.PathTail = pathTail
	a.Hdr = hdr
	a.LeafLen = len(leaf)
	for i := 0; i < p.N; i++ {
		if i < len(leaf) {
			a.R[i] = int(leaf[i])
		} else {
			a.R[i] = 0
		}
	}
	return a, nil
}

// Public returns the 7 public inputs in circuit order, for cross-checking
// against what the AVM verifier is handed.
func (c *ReceiptLeafCircuit) Public() []frontend.Variable {
	return []frontend.Variable{c.LeafHashHi, c.LeafHashLo, c.LogCommitHi,
		c.LogCommitLo, c.LogIndex, c.PathTail, c.Hdr}
}
