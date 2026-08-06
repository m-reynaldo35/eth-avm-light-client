package circuit

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

// MaxPathBytes bounds the hex-prefix path of the receipt-trie leaf.  A receipt
// key is RLP(tx_index), at most 4 bytes = 8 nibbles for any plausible block, so
// 8 bytes of hp_path (15 nibbles) is generous.
const MaxPathBytes = 8

// Params are the compile-time sizes of one circuit tier.
type Params struct {
	N       int // max receipt-leaf-node encoding length, bytes
	LogMax  int // max encoded length of the single extracted log, bytes
	MaxLogs int // max number of logs the circuit will scan past

	// LogSHA256 switches the LOG commitment (assertion 7) from keccak256 to
	// sha256. The LEAF hash (assertion 1) can never change: it is fixed by
	// Ethereum's trie. The log commitment is free to change, because its only
	// consumer is M7's own contract, which has native AVM opcodes for both
	// (keccak256 = 130 budget, sha256 = 35). Measured in O-M7-4.
	LogSHA256 bool

	// MinLeaf / MinLog are lower bounds on LeafLen / the extracted log's
	// length. A tier (N, LOGMAX) only ever serves receipts whose leaf exceeds
	// the previous tier's bound, so a real lower bound is always known.
	// gnark's hash.WithMinimalLength uses it to prune FixedLengthSum's padding
	// selection, and ASSERTS minimalLength <= length itself
	// (std/hash/sha3/sha3.go paddingFixedWidth), so it is safe to pass.
	MinLeaf int
	MinLog  int
}

// ReceiptLeafCircuit proves, for a receipt-trie leaf node R:
//
//	(1) keccak256(R[0:LeafLen]) == (LeafHashHi, LeafHashLo)
//	(2) R is canonical RLP([hp_path, value]) closing exactly on LeafLen
//	(3) hp_path is a LEAF path whose nibbles == PathTail exactly
//	(4) value is an EIP-2718 envelope (mirroring rlp/eip2718.py) whose payload
//	    is an RLP list of exactly 4 items [status, cumGas, bloom(256B), logs]
//	(5) logs[LogIndex] exists; its full encoding hashes to (LogCommitHi, LogCommitLo)
//	(6) (tx_type, status, cumulative_gas_used, n_logs) == Hdr
//
// Public inputs are ordered exactly as design doc §4.3 specifies.
type ReceiptLeafCircuit struct {
	LeafHashHi  frontend.Variable `gnark:",public"`
	LeafHashLo  frontend.Variable `gnark:",public"`
	LogCommitHi frontend.Variable `gnark:",public"`
	LogCommitLo frontend.Variable `gnark:",public"`
	LogIndex    frontend.Variable `gnark:",public"`
	PathTail    frontend.Variable `gnark:",public"`
	Hdr         frontend.Variable `gnark:",public"`

	R       []frontend.Variable // private: the leaf bytes, zero-padded to N
	LeafLen frontend.Variable   // private

	P Params `gnark:"-"`
}

// New allocates a circuit shell for compilation with the given params.
func New(p Params) *ReceiptLeafCircuit {
	return &ReceiptLeafCircuit{R: make([]frontend.Variable, p.N), P: p}
}

func (c *ReceiptLeafCircuit) Define(api frontend.API) error {
	p := c.P
	if len(c.R) != p.N {
		return fmt.Errorf("R has %d entries, want %d", len(c.R), p.N)
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	cp := cmp.NewBoundedComparator(api, cmpBound, false)

	// ---- range-check every byte, once ----
	rb := make([]uints.U8, p.N)
	for i := range c.R {
		rb[i] = bapi.ValueOf(c.R[i]) // enforces 0 <= R[i] < 256
	}

	// ---- (1) keccak over the leaf, variable length ----
	cp.AssertIsLessEq(c.LeafLen, p.N)
	var kopts []hash.Option
	if p.MinLeaf > 0 {
		kopts = append(kopts, hash.WithMinimalLength(p.MinLeaf))
	}
	kh, err := sha3.NewLegacyKeccak256(api, kopts...)
	if err != nil {
		return err
	}
	kh.Write(rb)
	leafDigest := kh.FixedLengthSum(c.LeafLen)
	assertDigest(api, bapi, leafDigest, c.LeafHashHi, c.LeafHashLo)

	// ---- lookup table for O(1) random access into R ----
	tbl := logderivlookup.New(api)
	for i := range c.R {
		tbl.Insert(c.R[i])
	}
	r := newReader(api, tbl, p.N)

	// ---- (2) R = RLP([hp_path, value]) ----
	lo, ll, isList, ok := r.header(0)
	api.AssertIsEqual(ok, 1)
	api.AssertIsEqual(isList, 1)
	end := api.Add(lo, ll)
	api.AssertIsEqual(end, c.LeafLen) // header arithmetic closes exactly

	// ---- (3) item 0: hp_path, must be a LEAF path equal to PathTail ----
	pOff, pLen, pIsList, ok0 := r.header(lo)
	api.AssertIsEqual(ok0, 1)
	api.AssertIsEqual(pIsList, 0)
	cp.AssertIsLessEq(1, pLen)
	cp.AssertIsLessEq(pLen, MaxPathBytes)

	b0 := r.at(pOff)
	b0bits := api.ToBinary(b0, 8)
	hi0 := api.FromBinary(b0bits[4:8]...)
	lo0 := api.FromBinary(b0bits[0:4]...)
	// leaf prefix nibble must be 2 (even) or 3 (odd); 0/1 = extension.
	odd := api.Sub(hi0, 2)
	api.AssertIsBoolean(odd) // hi0 in {2,3}

	// FIXED (rev. 5, doc 007 §14.5; originally flagged rev. 4 §14.3.2(b)):
	// for an EVEN-length hp_path (hi0 == 2) the hex-prefix encoding requires
	// lo0 == 0. The line below used to silently IGNORE lo0 via
	// api.Select(odd, lo0, 0) instead of asserting it, accepting a leaf
	// beginning 0x2d.. where only 0x20.. is canonical. Assert it explicitly.
	api.AssertIsEqual(api.Select(odd, 0, lo0), 0)
	acc := api.Select(odd, lo0, 0)
	n := frontend.Variable(odd)
	for j := 1; j < MaxPathBytes; j++ {
		bj := r.at(api.Add(pOff, j))
		bits := api.ToBinary(bj, 8)
		hj := api.FromBinary(bits[4:8]...)
		lj := api.FromBinary(bits[0:4]...)
		inR := cp.IsLess(j, pLen)
		acc = api.Select(inR, api.Add(api.Mul(acc, 256), api.Mul(hj, 16), lj), acc)
		n = api.Select(inR, api.Add(n, 2), n)
	}
	// packed = nibble_count * 2^60 + nibbles (big-endian, 15 nibbles max)
	shift := new(big.Int).Lsh(big.NewInt(1), 60)
	api.AssertIsEqual(api.Add(api.Mul(n, shift), acc), c.PathTail)

	// ---- item 1: value ----
	pTotal := api.Sub(api.Add(pOff, pLen), lo)
	vOff, vLen, vIsList, ok1 := r.header(api.Add(lo, pTotal))
	api.AssertIsEqual(ok1, 1)
	api.AssertIsEqual(vIsList, 0) // a trie leaf value is always a byte string
	api.AssertIsEqual(api.Add(vOff, vLen), end)

	// ---- (4) EIP-2718 envelope, mirroring rlp/eip2718.py ----
	t0 := r.at(vOff)
	isTyped := cp.IsLess(t0, 0xc0)
	// typed  => 1 <= t0 <= 0x7f  (eip2718.py "T2")
	api.AssertIsEqual(api.Select(isTyped, cp.IsLessEq(1, t0), 1), 1)
	api.AssertIsEqual(api.Select(isTyped, cp.IsLessEq(t0, 0x7f), 1), 1)
	// typed  => length >= 2      ("T3")
	api.AssertIsEqual(api.Select(isTyped, cp.IsLessEq(2, vLen), 1), 1)
	// typed  => payload is a list ("T4")
	nxt := r.at(api.Add(vOff, 1))
	api.AssertIsEqual(api.Select(isTyped, cp.IsLessEq(0xc0, nxt), 1), 1)
	txType := api.Select(isTyped, t0, 0)
	payOff := api.Add(vOff, isTyped)

	// ---- receipt body: RLP list of exactly 4 ----
	bOff, bLen, bIsList, ok2 := r.header(payOff)
	api.AssertIsEqual(ok2, 1)
	api.AssertIsEqual(bIsList, 1)
	bEnd := api.Add(bOff, bLen)
	api.AssertIsEqual(bEnd, api.Add(vOff, vLen)) // body closes on the value

	// item A: status (empty string = 0, or single byte 0x01)
	sOff, sLen, sIsList, ok3 := r.header(bOff)
	api.AssertIsEqual(ok3, 1)
	api.AssertIsEqual(sIsList, 0)
	cp.AssertIsLessEq(sLen, 1)
	status := api.Select(api.IsZero(sLen), 0, r.at(sOff))
	api.AssertIsBoolean(status)

	// item B: cumulativeGasUsed (<= 8 bytes)
	gPos := api.Add(sOff, sLen)
	gOff, gLen, gIsList, ok4 := r.header(gPos)
	api.AssertIsEqual(ok4, 1)
	api.AssertIsEqual(gIsList, 0)
	cp.AssertIsLessEq(gLen, 8)
	cumGas := r.readUint(gOff, gLen, 8)

	// item C: logsBloom, exactly 256 bytes
	blPos := api.Add(gOff, gLen)
	blOff, blLen, blIsList, ok5 := r.header(blPos)
	api.AssertIsEqual(ok5, 1)
	api.AssertIsEqual(blIsList, 0)
	api.AssertIsEqual(blLen, 256)

	// item D: the logs list; it must close the body exactly (=> exactly 4 items)
	lgPos := api.Add(blOff, blLen)
	lgOff, lgLen, lgIsList, ok6 := r.header(lgPos)
	api.AssertIsEqual(ok6, 1)
	api.AssertIsEqual(lgIsList, 1)
	lgEnd := api.Add(lgOff, lgLen)
	api.AssertIsEqual(lgEnd, bEnd)

	// ---- (5) walk the logs list ----
	cur := frontend.Variable(lgOff)
	nLogs := frontend.Variable(0)
	logOff := frontend.Variable(0)
	logLen := frontend.Variable(0)
	for k := 0; k < p.MaxLogs; k++ {
		active := cp.IsLess(cur, lgEnd)
		o, l, isL, okk := r.header(cur)
		// a log is itself an RLP list [address, topics, data]
		api.AssertIsEqual(api.Select(active, okk, 1), 1)
		api.AssertIsEqual(api.Select(active, isL, 1), 1)
		next := api.Add(o, l)
		// span containment — the single most important constraint (§4.4)
		api.AssertIsEqual(api.Select(active, cp.IsLessEq(next, lgEnd), 1), 1)

		isTarget := api.Mul(active, cmp.IsEqual(api, k, c.LogIndex))
		logOff = api.Select(isTarget, cur, logOff)
		logLen = api.Select(isTarget, api.Sub(next, cur), logLen)

		nLogs = api.Add(nLogs, active)
		cur = api.Select(active, next, cur)
	}
	// the loop must have consumed the whole logs list: otherwise MaxLogs was
	// too small for this receipt and nLogs would be a lie.
	api.AssertIsEqual(cur, lgEnd)
	// FIXED (rev. 5, doc 007 §14.5; originally flagged rev. 4 §14.3.2(a)).
	// LogIndex is a PUBLIC input and was not range-constrained anywhere.
	// cmp.BoundedComparator is only sound while |a-b| <= its absDiffUpp (here
	// 2^34); gnark documents that beyond P - 2^35 it "wrongly produces
	// reversed results". With LogIndex = P-1 the old AssertIsLess(LogIndex,
	// nLogs) alone would pass, no loop index k would match, logOff/logLen
	// would stay 0, and the circuit would commit to keccak256("").
	//
	// §14.3.2(a)'s literal suggested fix, cp.AssertIsLessEq(c.LogIndex,
	// p.MaxLogs), does NOT close this: it is the SAME BoundedComparator `cp`,
	// so for LogIndex = P-1 the check computes p.MaxLogs - LogIndex mod P,
	// which wraps to a small non-negative number (e.g. MaxLogs+1) and passes
	// for the same reason the original bug exists. Verified empirically: it
	// still lets the P-1 forgery through (see doc §14.5). The comparator
	// cannot be used to bound an adversarial, potentially-huge public input
	// against a small constant -- that is exactly the class of input it is
	// unsound for. api.AssertIsLessOrEqual decomposes LogIndex into the
	// field's full bit width and is sound for any LogIndex in [0, P), which
	// is what an unconstrained public input requires.
	api.AssertIsLessOrEqual(c.LogIndex, p.MaxLogs)
	cp.AssertIsLess(c.LogIndex, nLogs)
	cp.AssertIsLessEq(logLen, p.LogMax)

	// ---- extract the log's full encoding and hash it ----
	lb := make([]uints.U8, p.LogMax)
	for j := 0; j < p.LogMax; j++ {
		inR := cp.IsLess(j, logLen)
		idx := api.Select(inR, api.Add(logOff, j), 0)
		v := api.Select(inR, tbl.Lookup(idx)[0], 0)
		lb[j] = bapi.ValueOf(v)
	}
	var lopts []hash.Option
	if p.MinLog > 0 {
		lopts = append(lopts, hash.WithMinimalLength(p.MinLog))
	}
	var lh hash.BinaryFixedLengthHasher
	if p.LogSHA256 {
		lh, err = sha2.New(api, lopts...)
	} else {
		lh, err = sha3.NewLegacyKeccak256(api, lopts...)
	}
	if err != nil {
		return err
	}
	lh.Write(lb)
	logDigest := lh.FixedLengthSum(logLen)
	assertDigest(api, bapi, logDigest, c.LogCommitHi, c.LogCommitLo)

	// ---- (6) hdr = ((txType*2 + status) * 2^64 + cumGas) * 2^16 + nLogs ----
	hdr := api.Add(api.Mul(txType, 2), status)
	hdr = api.Add(api.Mul(hdr, new(big.Int).Lsh(big.NewInt(1), 64)), cumGas)
	hdr = api.Add(api.Mul(hdr, 1<<16), nLogs)
	api.AssertIsEqual(hdr, c.Hdr)

	return nil
}

// assertDigest checks a 32-byte in-circuit digest against two 16-byte
// big-endian public halves.
func assertDigest(api frontend.API, bapi *uints.Bytes, d []uints.U8, hi, lo frontend.Variable) {
	packHalf := func(bs []uints.U8) frontend.Variable {
		acc := frontend.Variable(0)
		for _, b := range bs {
			acc = api.Add(api.Mul(acc, 256), bapi.Value(b))
		}
		return acc
	}
	api.AssertIsEqual(packHalf(d[0:16]), hi)
	api.AssertIsEqual(packHalf(d[16:32]), lo)
}
