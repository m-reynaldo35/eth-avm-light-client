// Package circuit implements M7's receipt-leaf verification circuit in gnark.
//
// rlp.go — an in-circuit RLP reader shaped to match, constraint for constraint
// of behaviour, the on-chain decoder in contracts/primitives/rlp/core.py and
// contracts/primitives/rlp/eip2718.py.  Where core.py `assert`s, this file
// returns an `ok` flag that the caller must assert (possibly conditionally),
// because a circuit has no data-dependent control flow.
package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/cmp"
)

// maxLenBytes caps an RLP long-form length-of-length at 4 bytes, so every
// decoded length is < 2^32 by construction.  Real Ethereum receipt leaves are
// far below this; the cap is what lets every downstream comparison use one
// 33-bit-bounded comparator instead of a full-field one.
const maxLenBytes = 4

// bound for the bounded comparator: all offsets/lengths live in [0, 2^33).
var cmpBound = new(big.Int).Lsh(big.NewInt(1), 34)

// reader is an RLP cursor over a logderivlookup table of the leaf's bytes.
type reader struct {
	api frontend.API
	t   logderivlookup.Table
	cmp *cmp.BoundedComparator
	n   int // table size (bytes of R, padded)
}

func newReader(api frontend.API, t logderivlookup.Table, n int) *reader {
	return &reader{api: api, t: t, cmp: cmp.NewBoundedComparator(api, cmpBound, false), n: n}
}

// at reads R[off], clamping the index into range so an out-of-span probe
// cannot make the lookup hint fail.  Callers gate correctness with `ok`.
func (r *reader) at(off frontend.Variable) frontend.Variable {
	inRange := r.cmp.IsLess(off, r.n)
	idx := r.api.Select(inRange, off, 0)
	return r.t.Lookup(idx)[0]
}

// header decodes one RLP item header at `pos`.
//
// Returns:
//
//	payOff  offset of the item's payload (content) first byte
//	payLen  length of the payload
//	isList  1 if the item is a list, else 0
//	ok      1 if the header is structurally valid AND canonical
//
// Semantics mirror core.py's rlp_item_header, except:
//   - for a list, (payOff,payLen) is the PAYLOAD span, not the whole encoding;
//     the caller recovers the total span as payOff+payLen-pos.
//   - canonicality (minimal-length encoding) is enforced here.  core.py
//     deliberately skips it under TP-1 (the bytes are already hash-committed
//     when it runs); in-circuit it must be enforced because the circuit is the
//     only checker on this path (design doc §4.4).
func (r *reader) header(pos frontend.Variable) (payOff, payLen, isList, ok frontend.Variable) {
	api := r.api
	p := r.at(pos)

	isSingle := r.cmp.IsLess(p, 0x80)             // 0x00..0x7f
	isShortS := r.cmp.IsLess(p, 0xb8)             // .. minus isSingle
	isLongS := r.cmp.IsLess(p, 0xc0)              // .. minus the above
	isShortL := r.cmp.IsLess(p, 0xf8)             // .. minus the above
	shortS := api.Sub(isShortS, isSingle)         // 0x80..0xb7
	longS := api.Sub(isLongS, isShortS)           // 0xb8..0xbf
	shortL := api.Sub(isShortL, isLongS)          // 0xc0..0xf7
	longL := api.Sub(1, isShortL)                 // 0xf8..0xff
	isLong := api.Add(longS, longL)               // long form (either kind)
	isList = api.Add(shortL, longL)               //

	// length-of-length nibble: p-0xb7 for long string, p-0xf7 for long list.
	ll := api.Select(longS, api.Sub(p, 0xb7), api.Sub(p, 0xf7))
	ll = api.Select(isLong, ll, 0)

	// Read up to maxLenBytes big-endian length bytes at pos+1.  Also capture
	// the FIRST length byte, which canonical RLP forbids from being zero.
	acc := frontend.Variable(0)
	first := frontend.Variable(0)
	for j := 0; j < maxLenBytes; j++ {
		b := r.at(api.Add(pos, 1+j))
		inR := r.cmp.IsLess(j, ll)
		acc = api.Select(inR, api.Add(api.Mul(acc, 256), b), acc)
		if j == 0 {
			first = b
		}
	}
	llOk := r.cmp.IsLessEq(ll, maxLenBytes)

	// short-form payload lengths
	shortSLen := api.Sub(p, 0x80)
	shortLLen := api.Sub(p, 0xc0)

	payLen = api.Select(isSingle, 1, 0)
	payLen = api.Add(payLen, api.Mul(shortS, shortSLen))
	payLen = api.Add(payLen, api.Mul(shortL, shortLLen))
	payLen = api.Add(payLen, api.Mul(isLong, acc))

	// payload offset: pos for a single byte, pos+1 short form, pos+1+ll long.
	payOff = api.Select(isSingle, pos, api.Add(pos, 1, ll))

	// ---- canonicality (design doc §4.4, "two canonicality obligations") ----
	// (a) long form must encode a length >= 56.
	longMinOk := r.cmp.IsLessEq(56, acc)
	// (b) long form's first length byte must be non-zero (no leading zeros).
	firstNZ := api.Sub(1, api.IsZero(first))
	canonLong := api.Mul(longMinOk, firstNZ)
	// (c) a 1-byte short string whose content is < 0x80 should have been a
	//     single byte.  Enforced by the caller-visible flag below.
	is1 := api.IsZero(api.Sub(payLen, 1))
	contentB := r.at(payOff)
	shortNotSingle := r.cmp.IsLessEq(0x80, contentB)
	canonShort1 := api.Select(api.Mul(shortS, is1), shortNotSingle, 1)

	ok = api.Mul(llOk, canonShort1)
	ok = api.Mul(ok, api.Select(isLong, canonLong, 1))
	return payOff, payLen, isList, ok
}

// readUint reads a big-endian unsigned integer of `n` bytes at `off`, where n
// is a circuit variable bounded by `maxN` (a compile-time constant).
func (r *reader) readUint(off, n frontend.Variable, maxN int) frontend.Variable {
	api := r.api
	acc := frontend.Variable(0)
	for j := 0; j < maxN; j++ {
		b := r.at(api.Add(off, j))
		inR := r.cmp.IsLess(j, n)
		acc = api.Select(inR, api.Add(api.Mul(acc, 256), b), acc)
	}
	return acc
}
