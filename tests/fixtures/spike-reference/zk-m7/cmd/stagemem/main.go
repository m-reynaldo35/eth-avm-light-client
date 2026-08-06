// Command stagemem measures REAL peak RSS (VmHWM) per pipeline stage.
//
// Linux lets a process reset its own VmHWM high-water mark by writing "5" to
// /proc/self/clear_refs, so each stage below reports a genuine peak-RSS delta
// rather than a cumulative number or a Go-heap approximation.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"m7zk/circuit"
	"m7zk/ptaufast"

	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	kzgbn "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	gp "github.com/mdehoog/gnark-ptau"
)

func procKB(field string) uint64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, field+":") {
			f := strings.Fields(ln)
			v, _ := strconv.ParseUint(f[1], 10, 64)
			return v
		}
	}
	return 0
}

// resetHWM resets VmHWM to the current VmRSS.
func resetHWM() {
	f, err := os.OpenFile("/proc/self/clear_refs", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	f.WriteString("5\n")
	f.Close()
}

var t0 time.Time

func heapGB() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.HeapAlloc) / 1e9
}

func begin(name string) {
	// FreeOSMemory forces a GC *and* returns free pages to the OS, so the
	// VmHWM we reset below measures this stage's real transient, not the
	// previous stage's un-scavenged garbage.
	debug.FreeOSMemory()
	resetHWM()
	t0 = time.Now()
	fmt.Printf("--- %-22s start  rss=%6.2f GB  live_heap=%5.2f GB\n",
		name, float64(procKB("VmRSS"))/1048576, heapGB())
}

func end(name string) {
	el := time.Since(t0)
	hwm := procKB("VmHWM")
	rss := procKB("VmRSS")
	live := heapGB()
	fmt.Printf("=== %-22s %8.1fs  PEAK_RSS=%6.2f GB  rss_after=%6.2f GB  live_heap_after=%5.2f GB\n",
		name, el.Seconds(), float64(hwm)/1048576, float64(rss)/1048576, live)
}

func main() {
	n := flag.Int("n", 384, "circuit N")
	logmax := flag.Int("logmax", 96, "circuit LogMax")
	maxlogs := flag.Int("maxlogs", 4, "circuit MaxLogs")
	ptau := flag.String("ptau", "", "path to a real .ptau")
	doSetup := flag.Bool("setup", true, "run plonk.Setup")
	doProve := flag.Bool("prove", false, "run plonk.Prove (memory heavy)")
	fast := flag.Bool("fast", false, "use ptaufast chunked loader instead of gnark-ptau+ToLagrangeG1")
	leaf := flag.String("leafhex", "", "hex leaf for proving")
	flag.Parse()

	fmt.Printf("baseline rss=%.2f GB\n", float64(procKB("VmRSS"))/1048576)

	begin("frontend.Compile")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder,
		circuit.New(circuit.Params{N: *n, LogMax: *logmax, MaxLogs: *maxlogs}))
	must(err)
	end("frontend.Compile")
	size := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()+ccs.GetNbPublicVariables())) + 3
	fmt.Printf("    nbConstraints=%d  srs points needed=%d (domain %d)\n",
		ccs.GetNbConstraints(), size, size-3)

	if *ptau == "" {
		return
	}

	if *fast {
		begin("ptaufast.Open+Load")
		pf, err := ptaufast.Open(*ptau)
		must(err)
		srs, lag, err := pf.LoadPlonkSRS(size - 3)
		must(err)
		pf.Close()
		end("ptaufast.Open+Load")
		fmt.Printf("    canonical=%d pts  lagrange=%d pts  (no ToLagrangeG1, no full-ceremony load)\n",
			len(srs.Pk.G1), len(lag.Pk.G1))

		if !*doSetup {
			return
		}
		begin("plonk.Setup")
		_, _, err = plonk.Setup(ccs, srs, lag)
		must(err)
		end("plonk.Setup")
		return
	}

	begin("gnark-ptau.ToSRS")
	f, err := os.Open(*ptau)
	must(err)
	srsFull, err := gp.ToSRS(f)
	must(err)
	f.Close()
	end("gnark-ptau.ToSRS")
	fmt.Printf("    loaded %d G1 points (%.2f GB of G1Affine)\n",
		len(srsFull.Pk.G1), float64(len(srsFull.Pk.G1))*64/1e9)

	begin("truncate+GC")
	srs := &kzgbn.SRS{Vk: srsFull.Vk}
	srs.Pk.G1 = make([]bn254.G1Affine, size)
	copy(srs.Pk.G1, srsFull.Pk.G1[:size])
	srsFull.Pk.G1 = nil
	srsFull = nil
	runtime.GC()
	end("truncate+GC")

	begin("kzg.ToLagrangeG1")
	lag := &kzgbn.SRS{Vk: srs.Vk}
	lagG1, err := kzgbn.ToLagrangeG1(srs.Pk.G1[:len(srs.Pk.G1)-3])
	must(err)
	lag.Pk.G1 = lagG1
	end("kzg.ToLagrangeG1")

	if !*doSetup {
		return
	}
	begin("plonk.Setup")
	pk, vk, err := plonk.Setup(ccs, srs, lag)
	must(err)
	end("plonk.Setup")
	_ = vk

	if !*doProve || *leaf == "" {
		return
	}
	_ = pk
	fmt.Println("prove stage not wired in this tool")
}

func must(err error) {
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}
