// Package ptaufast loads exactly the KZG SRS that gnark's PLONK backend needs
// out of a snarkjs powersOfTau .ptau file, reading it in fixed-size chunks
// straight from disk.
//
// It exists because the obvious pipeline
//
//	gnark_ptau.ToSRS(file)  ->  kzg.ToLagrangeG1(srs.Pk.G1)  ->  plonk.Setup
//
// does two expensive and avoidable things:
//
//  1. ToSRS materialises the WHOLE ceremony's G1 section -- 2^(power+1)-1
//     points -- even though PLONK only needs domain+3 of them. For a 2^24
//     circuit that is 2.15 GB read and held to use 1.07 GB.
//
//  2. kzg.ToLagrangeG1 recomputes the Lagrange-basis SRS with a group-domain
//     inverse FFT. That costs (n/2)*log2(n) full scalar multiplications on G1
//     and a ~530 bytes/point transient. Measured: 169.8 s and 1.11 GB at 2^21.
//
// Neither is necessary. A "prepared for phase 2" ptau file (which every
// powersOfTau28_hez_final_NN.ptau is) already carries section 12: the
// Lagrange-basis G1 evaluations, concatenated for p = 0 .. power+1, 2^p points
// each. Those points are BYTE-IDENTICAL to kzg.ToLagrangeG1's output --
// verified point-for-point at 2^14, 2^18 and 2^21 by cmd/lagcheck. So the FFT
// can be replaced by a sequential read.
//
// This package also fixes a real bug that the naive pipeline inherits: it
// populates kzg.VerifyingKey.Lines. gnark-ptau leaves them zeroed, which makes
// gnark's off-chain KZG pairing check vacuously true (cmd/linestest,
// cmd/aplines).
package ptaufast

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	kzgbn "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

const (
	g1Size = 64  // two 32-byte Fp coordinates, little-endian Montgomery limbs
	g2Size = 128 // four
	// chunkPoints is how many G1 points are decoded per disk read. 64 Ki
	// points = 4 MiB, which is enough to saturate sequential read bandwidth
	// while keeping the loader's own working set negligible.
	chunkPoints = 64 * 1024
)

type Section struct {
	ID     uint32
	Offset int64
	Length uint64
}

type File struct {
	f        *os.File
	Power    uint32
	Sections []Section
}

// Open parses a .ptau file's section table without reading any point data.
func Open(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var hdr [12]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		f.Close()
		return nil, err
	}
	if string(hdr[0:4]) != "ptau" {
		f.Close()
		return nil, fmt.Errorf("ptaufast: %s is not a .ptau file", path)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	total := st.Size()
	pf := &File{f: f}
	off := int64(12)
	for off < total {
		var sh [12]byte
		if _, err := f.ReadAt(sh[:], off); err != nil {
			break
		}
		id := binary.LittleEndian.Uint32(sh[0:4])
		l := binary.LittleEndian.Uint64(sh[4:12])
		if l > uint64(total) {
			f.Close()
			return nil, fmt.Errorf("ptaufast: section %d declares length %d in a %d-byte file", id, l, total)
		}
		pf.Sections = append(pf.Sections, Section{id, off + 12, l})
		off += 12 + int64(l)
	}
	s1 := pf.Section(1)
	if s1 == nil {
		f.Close()
		return nil, fmt.Errorf("ptaufast: no header section")
	}
	b := make([]byte, s1.Length)
	if _, err := f.ReadAt(b, s1.Offset); err != nil {
		f.Close()
		return nil, err
	}
	n8 := binary.LittleEndian.Uint32(b[0:4])
	if uint64(8+n8) > s1.Length {
		f.Close()
		return nil, fmt.Errorf("ptaufast: malformed header section")
	}
	pf.Power = binary.LittleEndian.Uint32(b[4+n8 : 8+n8])
	return pf, nil
}

func (p *File) Close() error { return p.f.Close() }

func (p *File) Section(id uint32) *Section {
	for i := range p.Sections {
		if p.Sections[i].ID == id {
			return &p.Sections[i]
		}
	}
	return nil
}

// LoadPlonkSRS returns the canonical and Lagrange SRS for a PLONK domain of
// size `domain` (which must be a power of two), reading only what is needed.
//
// gnark's plonk.Setup wants len(canonical.Pk.G1) >= domain+3 and
// len(lagrange.Pk.G1) == domain.
func (p *File) LoadPlonkSRS(domain uint64) (canonical, lagrange *kzgbn.SRS, err error) {
	if domain == 0 || domain&(domain-1) != 0 {
		return nil, nil, fmt.Errorf("ptaufast: domain %d is not a power of two", domain)
	}
	s2, s3, s12 := p.Section(2), p.Section(3), p.Section(12)
	if s2 == nil || s3 == nil {
		return nil, nil, fmt.Errorf("ptaufast: file lacks tauG1/tauG2 sections")
	}
	if s12 == nil {
		return nil, nil, fmt.Errorf("ptaufast: file lacks section 12 (Lagrange evaluations); " +
			"it has not been through `snarkjs powersoftau preparephase2`")
	}

	nCanon := domain + 3
	if have := s2.Length / g1Size; have < nCanon {
		return nil, nil, fmt.Errorf("ptaufast: ceremony too small: section 2 has %d G1 points, need %d", have, nCanon)
	}
	// Section 12 is the concatenation, for p = 0..power+1, of 2^p points.
	// The block for 2^d therefore begins at point index 2^d - 1.
	if domain > 1<<(p.Power+1) {
		return nil, nil, fmt.Errorf("ptaufast: domain 2^%d exceeds ceremony power %d", log2(domain), p.Power)
	}
	lagStart := s12.Offset + int64(domain-1)*g1Size
	if uint64(lagStart-s12.Offset)+domain*g1Size > s12.Length {
		return nil, nil, fmt.Errorf("ptaufast: section 12 too short for domain 2^%d", log2(domain))
	}

	canonG1, err := p.readG1Chunked(s2.Offset, int(nCanon))
	if err != nil {
		return nil, nil, fmt.Errorf("ptaufast: reading canonical G1: %w", err)
	}
	lagG1, err := p.readG1Chunked(lagStart, int(domain))
	if err != nil {
		return nil, nil, fmt.Errorf("ptaufast: reading Lagrange G1: %w", err)
	}

	var vk kzgbn.VerifyingKey
	vk.G1 = canonG1[0]
	g2buf := make([]byte, 2*g2Size)
	if _, err := p.f.ReadAt(g2buf, s3.Offset); err != nil {
		return nil, nil, fmt.Errorf("ptaufast: reading tauG2: %w", err)
	}
	for i := 0; i < 2; i++ {
		b := g2buf[i*g2Size:]
		vk.G2[i].X.A0 = elem(b[0:32])
		vk.G2[i].X.A1 = elem(b[32:64])
		vk.G2[i].Y.A0 = elem(b[64:96])
		vk.G2[i].Y.A1 = elem(b[96:128])
		if !vk.G2[i].IsOnCurve() {
			return nil, nil, fmt.Errorf("ptaufast: tauG2[%d] is not on the curve", i)
		}
		if !vk.G2[i].IsInSubGroup() {
			return nil, nil, fmt.Errorf("ptaufast: tauG2[%d] is not in the prime-order subgroup", i)
		}
	}
	// gnark-ptau does NOT do this, and gnark's plonk.Setup copies Vk verbatim
	// into the verifying key, so leaving Lines zeroed makes the off-chain KZG
	// pairing check vacuously true. See cmd/linestest / cmd/aplines.
	vk.Lines[0] = bn254.PrecomputeLines(vk.G2[0])
	vk.Lines[1] = bn254.PrecomputeLines(vk.G2[1])

	canonical = &kzgbn.SRS{Vk: vk}
	canonical.Pk.G1 = canonG1
	lagrange = &kzgbn.SRS{Vk: vk}
	lagrange.Pk.G1 = lagG1
	return canonical, lagrange, nil
}

// readG1Chunked decodes n G1 points starting at byte offset off, using a fixed
// chunkPoints-sized staging buffer regardless of n.
func (p *File) readG1Chunked(off int64, n int) ([]bn254.G1Affine, error) {
	out := make([]bn254.G1Affine, n)
	buf := make([]byte, chunkPoints*g1Size)
	for done := 0; done < n; {
		want := chunkPoints
		if n-done < want {
			want = n - done
		}
		b := buf[:want*g1Size]
		if _, err := p.f.ReadAt(b, off); err != nil {
			return nil, err
		}
		for i := 0; i < want; i++ {
			q := b[i*g1Size:]
			out[done+i].X = elem(q[0:32])
			out[done+i].Y = elem(q[32:64])
			// Same on-curve check gnark-ptau performs. The subgroup check is
			// free on BN254 G1 (cofactor 1) given a point is on the curve.
			if !out[done+i].IsOnCurve() {
				return nil, fmt.Errorf("G1 point %d is not on the curve", done+i)
			}
		}
		off += int64(want * g1Size)
		done += want
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

func log2(x uint64) int {
	n := 0
	for x > 1 {
		x >>= 1
		n++
	}
	return n
}
