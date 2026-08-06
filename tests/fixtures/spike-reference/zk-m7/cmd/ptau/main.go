// Command ptau converts a real Perpetual-Powers-of-Tau .ptau file (snarkjs
// format, BN254) into the gnark KZG SRS that PLONK's Setup consumes, and into
// AlgoPlonk's own pk.bin/vk.bin on-disk shape.
//
// Mode "audit" reproduces AlgoPlonk's vendored PerpetualPowersOfTauBN254
// setup byte-for-byte from the published ceremony file, which is the procedure
// AlgoPlonk's own setup/PerpetualPowersOfTauBN254/audit.go documents but that
// design doc 007 §4.11/ZK-B7 records as "read but not run".
//
// Mode "convert" writes pk.bin/vk.bin for an arbitrary power.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	gp "github.com/mdehoog/gnark-ptau"
)

func main() {
	mode := flag.String("mode", "convert", "audit|convert")
	in := flag.String("in", "", "input .ptau")
	outDir := flag.String("outdir", "", "output directory for pk.bin/vk.bin")
	refDir := flag.String("ref", "", "reference dir containing pk.bin/vk.bin (audit mode)")
	flag.Parse()

	f, err := os.Open(*in)
	must(err)
	defer f.Close()
	st, _ := f.Stat()
	fmt.Printf("input: %s (%d bytes)\n", *in, st.Size())

	t0 := time.Now()
	srs, err := gp.ToSRS(f)
	must(err)
	fmt.Printf("ToSRS ok in %.1fs: %d G1 points, Vk.G2[0..1] loaded\n",
		time.Since(t0).Seconds(), len(srs.Pk.G1))

	var pk, vk bytes.Buffer
	_, err = srs.Pk.WriteTo(&pk)
	must(err)
	_, err = srs.Vk.WriteTo(&vk)
	must(err)
	fmt.Printf("serialized: pk=%d bytes vk=%d bytes\n", pk.Len(), vk.Len())
	fmt.Printf("declared G1 count in pk header: %d\n", binary.BigEndian.Uint32(pk.Bytes()[:4]))
	fmt.Printf("pk sha256: %s\nvk sha256: %s\n",
		hex.EncodeToString(sh(pk.Bytes())), hex.EncodeToString(sh(vk.Bytes())))

	switch *mode {
	case "audit":
		rpk, err := os.ReadFile(*refDir + "/pk.bin")
		must(err)
		rvk, err := os.ReadFile(*refDir + "/vk.bin")
		must(err)
		fmt.Printf("reference pk=%d bytes sha256=%s\n", len(rpk), hex.EncodeToString(sh(rpk)))
		fmt.Printf("reference vk=%d bytes sha256=%s\n", len(rvk), hex.EncodeToString(sh(rvk)))
		if !bytes.Equal(rpk, pk.Bytes()) {
			fmt.Println("RESULT: pk.bin MISMATCH")
			os.Exit(1)
		}
		if !bytes.Equal(rvk, vk.Bytes()) {
			fmt.Println("RESULT: vk.bin MISMATCH")
			os.Exit(1)
		}
		fmt.Println("RESULT: AUDIT PASS — vendored setup reproduced byte-for-byte from the ceremony file")
	case "convert":
		must(os.MkdirAll(*outDir, 0o755))
		must(os.WriteFile(*outDir+"/pk.bin", pk.Bytes(), 0o644))
		must(os.WriteFile(*outDir+"/vk.bin", vk.Bytes(), 0o644))
		fmt.Printf("wrote %s/{pk.bin,vk.bin}\n", *outDir)
	}
}

func sh(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func must(err error) {
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}
