// Command lagcheck tests a hypothesis about snarkjs .ptau files:
//
//	Section 12 of a "prepared for phase 2" powersOfTau file already contains the
//	Lagrange-basis G1 evaluations, concatenated for p = 0 .. power+1
//	(2^p points each). If those points are identical to what
//	gnark-crypto's kzg.ToLagrangeG1 computes from section 2, then the
//	expensive group-domain iFFT can be replaced by a sequential disk read.
//
// It reads BOTH and compares them point-for-point.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	kzgbn "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

type section struct {
	id     uint32
	offset int64
	length uint64
}

func readSections(f *os.File) (uint32, []section, error) {
	var hdr [12]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return 0, nil, err
	}
	if string(hdr[0:4]) != "ptau" {
		return 0, nil, fmt.Errorf("not a ptau file")
	}
	st, _ := f.Stat()
	total := st.Size()
	var secs []section
	off := int64(12)
	for off < total {
		var sh [12]byte
		if _, err := f.ReadAt(sh[:], off); err != nil {
			break
		}
		id := binary.LittleEndian.Uint32(sh[0:4])
		l := binary.LittleEndian.Uint64(sh[4:12])
		secs = append(secs, section{id, off + 12, l})
		off += 12 + int64(l)
	}
	// power lives in section 1: n8(4) + prime(n8) + power(4) + ceremonyPower(4)
	var power uint32
	for _, s := range secs {
		if s.id == 1 {
			b := make([]byte, s.length)
			if _, err := f.ReadAt(b, s.offset); err != nil {
				return 0, nil, err
			}
			n8 := binary.LittleEndian.Uint32(b[0:4])
			power = binary.LittleEndian.Uint32(b[4+n8 : 8+n8])
		}
	}
	return power, secs, nil
}

func find(secs []section, id uint32) *section {
	for i := range secs {
		if secs[i].id == id {
			return &secs[i]
		}
	}
	return nil
}

// readG1At reads n G1Affine points starting at byte offset off.
// snarkjs stores each coordinate as 4 little-endian uint64 limbs already in
// Montgomery form -- the same convention gnark-ptau's readElement assumes.
func readG1At(f *os.File, off int64, n int) ([]bn254.G1Affine, error) {
	buf := make([]byte, 64*1024)
	out := make([]bn254.G1Affine, n)
	got := 0
	for got < n {
		want := len(buf) / 64
		if n-got < want {
			want = n - got
		}
		b := buf[:want*64]
		if _, err := f.ReadAt(b, off); err != nil {
			return nil, err
		}
		for i := 0; i < want; i++ {
			out[got+i].X = elem(b[i*64 : i*64+32])
			out[got+i].Y = elem(b[i*64+32 : i*64+64])
		}
		off += int64(want * 64)
		got += want
	}
	return out, nil
}

func elem(b []byte) fp.Element {
	var z fp.Element
	z[0] = binary.LittleEndian.Uint64(b[0:8])
	z[1] = binary.LittleEndian.Uint64(b[8:16])
	z[2] = binary.LittleEndian.Uint64(b[16:24])
	z[3] = binary.LittleEndian.Uint64(b[24:32])
	return z
}

func main() {
	path := flag.String("ptau", "", "ptau file")
	d := flag.Int("d", 16, "domain exponent to compare (domain = 2^d)")
	flag.Parse()

	f, err := os.Open(*path)
	must(err)
	defer f.Close()
	power, secs, err := readSections(f)
	must(err)
	fmt.Printf("%s: power=%d, sections:", *path, power)
	for _, s := range secs {
		fmt.Printf(" %d(%d)", s.id, s.length)
	}
	fmt.Println()

	s2, s12 := find(secs, 2), find(secs, 12)
	if s2 == nil || s12 == nil {
		fmt.Println("ERROR: need sections 2 and 12")
		os.Exit(1)
	}
	fmt.Printf("section 2  : %d G1 points (expect 2^%d-1 = %d)\n",
		s12.length/64, power+1, (1<<(power+1))-1)
	fmt.Printf("section 12 : %d G1 points (expect sum_{p=0..%d} 2^p = %d)\n",
		s12.length/64, power+1, (1<<(power+2))-1)

	n := 1 << *d
	if uint64(n) > s2.length/64 {
		fmt.Println("ERROR: d too large for section 2")
		os.Exit(1)
	}

	// --- path A: gnark's ToLagrangeG1 over section 2's first 2^d points ---
	t := time.Now()
	canon, err := readG1At(f, s2.offset, n)
	must(err)
	fmt.Printf("read %d canonical points from section 2 in %.2fs\n", n, time.Since(t).Seconds())
	t = time.Now()
	computed, err := kzgbn.ToLagrangeG1(canon)
	must(err)
	fftSec := time.Since(t).Seconds()
	fmt.Printf("kzg.ToLagrangeG1(2^%d) took %.2fs\n", *d, fftSec)

	// --- path B: read section 12's block for this exact power ---
	// blocks are concatenated for p = 0,1,...: block p starts at 2^p - 1 points.
	blockStart := s12.offset + int64((1<<*d)-1)*64
	t = time.Now()
	fromFile, err := readG1At(f, blockStart, n)
	must(err)
	readSec := time.Since(t).Seconds()
	fmt.Printf("read %d Lagrange points from section 12 in %.2fs\n", n, readSec)

	// --- compare ---
	bad := 0
	firstBad := -1
	for i := 0; i < n; i++ {
		if !computed[i].Equal(&fromFile[i]) {
			bad++
			if firstBad < 0 {
				firstBad = i
			}
		}
	}
	if bad == 0 {
		fmt.Printf("\nMATCH: all %d points identical.\n", n)
		fmt.Printf("speedup of read-from-file vs recompute: %.0fx (%.2fs -> %.2fs)\n",
			fftSec/readSec, fftSec, readSec)
	} else {
		fmt.Printf("\nMISMATCH: %d of %d points differ, first at index %d\n", bad, n, firstBad)
		fmt.Printf("  computed[%d].X = %s\n", firstBad, computed[firstBad].X.String())
		fmt.Printf("  fromfile[%d].X = %s\n", firstBad, fromFile[firstBad].X.String())
		// is it a permutation? check whether fromFile[bitrev(i)] == computed[i]
		fmt.Printf("  computed[0].X = %s\n  fromfile[0].X = %s\n",
			computed[0].X.String(), fromFile[0].X.String())
	}
}

func must(err error) {
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}
