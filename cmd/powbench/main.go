// powbench measures the PoW solve pipeline against a real hsw.js bundle
// (downloaded once, replayed from disk) so CPU time, Go and V8 heap, and
// retained-value growth can be compared across code changes without hitting
// hCaptcha's network endpoints.
//
// Usage:
//
//	go run ./cmd/powbench -jwt /tmp/jwt.txt -bundle /tmp/hsw_real.js -runs 20
//	go run ./cmd/powbench -jwt /tmp/jwt.txt -bundle /tmp/hsw_real.js -runs 20 -solvers 4
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	"glm52-nvidia/internal/hcaptcha"
	"glm52-nvidia/internal/hcaptchapow"
	"glm52-nvidia/internal/hsw"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	jwtPath := flag.String("jwt", "", "file containing the PoW challenge JWT")
	bundlePath := flag.String("bundle", "", "file containing the raw hsw.js bundle")
	runs := flag.Int("runs", 10, "number of solves")
	solvers := flag.Int("solvers", 1, "number of cached solvers to spread runs over")
	fingerprintOnly := flag.Bool("fingerprint-only", false, "benchmark only BuildFingerprint (no V8)")
	flag.Parse()

	if *jwtPath == "" || *bundlePath == "" {
		return fmt.Errorf("both -jwt and -bundle are required")
	}
	jwtBytes, err := os.ReadFile(*jwtPath)
	if err != nil {
		return err
	}
	rawBundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	jwt := string(jwtBytes)

	pow, err := hcaptchapow.ParsePow(jwt)
	if err != nil {
		return fmt.Errorf("parse jwt: %w", err)
	}
	fmt.Printf("bundle=%dKB location=%s difficulty=%.0f runs=%d solvers=%d\n",
		len(rawBundle)/1024, pow.Location, pow.Difficulty, *runs, *solvers)

	if *fingerprintOnly {
		return benchFingerprint(pow, *runs)
	}

	bundles := make([]*hsw.Bundle, *solvers)
	for i := range bundles {
		b, err := hsw.Prepare(rawBundle)
		if err != nil {
			return fmt.Errorf("prepare: %w", err)
		}
		bundles[i] = b
	}

	ctx := context.Background()

	// Warmup: one solve per solver (first solve pays wasm compile).
	warmStart := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < *solvers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := hsw.New(bundles[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "warmup solver %d: %v\n", i, err)
				return
			}
			defer s.Close()
			fp, err := hcaptcha.BuildFingerprint(pow)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warmup fp %d: %v\n", i, err)
				return
			}
			if _, err := s.SolveN(ctx, jwt, fp); err != nil {
				fmt.Fprintf(os.Stderr, "warmup solve %d: %v\n", i, err)
			}
		}(i)
	}
	wg.Wait()
	fmt.Printf("warmup (New+SolveN x%d): %s\n", *solvers, time.Since(warmStart).Round(time.Millisecond))

	solverSet := make([]*hsw.Solver, *solvers)
	for i := 0; i < *solvers; i++ {
		s, err := hsw.New(bundles[i])
		if err != nil {
			return fmt.Errorf("solver %d: %w", i, err)
		}
		solverSet[i] = s
	}
	defer func() {
		for _, s := range solverSet {
			s.Close()
		}
	}()

	// Pre-build fingerprints so the V8 part is measured separately from
	// stamp minting.
	fps := make([]string, *runs)
	fpMs := benchFingerprintTimed(pow, fps)

	times := make([]float64, *runs)
	var cpuBefore, cpuAfter [2]float64
	readCPU(&cpuBefore)
	totalStart := time.Now()
	var next int
	var mu sync.Mutex
	wg = sync.WaitGroup{}
	for w := 0; w < *solvers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				i := next
				next++
				mu.Unlock()
				if i >= *runs {
					return
				}
				s := solverSet[i%len(solverSet)]
				t0 := time.Now()
				if _, err := s.SolveN(ctx, jwt, fps[i]); err != nil {
					fmt.Fprintf(os.Stderr, "solve %d: %v\n", i, err)
				}
				d := time.Since(t0).Seconds() * 1000
				mu.Lock()
				times[i] = d
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	readCPU(&cpuAfter)
	total := time.Since(totalStart)

	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	sort.Float64s(times)
	med := times[len(times)/2]
	p95 := times[(len(times)*95)/100]
	cpu := (cpuAfter[0] - cpuBefore[0]) + (cpuAfter[1] - cpuBefore[1])

	fmt.Printf("solve: n=%d median=%.1fms p95=%.1fms min=%.1fms max=%.1fms wall=%.2fs throughput=%.1f/s\n",
		*runs, med, p95, times[0], times[len(times)-1],
		total.Seconds(), float64(*runs)/total.Seconds())
	fmt.Printf("solve cpu: user=%.2fs sys=%.2fs (%.1f ms cpu/solve)\n",
		cpuAfter[0]-cpuBefore[0], cpuAfter[1]-cpuBefore[1], cpu*1000/float64(*runs))
	fmt.Printf("fingerprint: avg=%.2fms\n", fpMs)
	fmt.Printf("go mem: heapAlloc=%.1fMB sys=%.1fMB numGC=%d\n",
		float64(m.HeapAlloc)/1e6, float64(m.Sys)/1e6, m.NumGC)

	// Leak probe: 20 more solves on solver 0, then report V8 growth.
	n0 := solverSet[0].RetainedValueCount()
	h0 := solverSet[0].HeapStats()
	for i := 0; i < 20; i++ {
		if _, err := solverSet[0].SolveN(ctx, jwt, fps[i%len(fps)]); err != nil {
			return fmt.Errorf("leak probe solve: %w", err)
		}
	}
	runtime.GC()
	h1 := solverSet[0].HeapStats()
	n1 := solverSet[0].RetainedValueCount()
	fmt.Printf("leak probe (+20 solves on solver 0): retainedValues %d -> %d (delta %d), v8 used %.2f -> %.2fMB (delta %+.3fMB)\n",
		n0, n1, n1-n0, float64(h0.UsedHeapSize)/1e6, float64(h1.UsedHeapSize)/1e6,
		float64(int64(h1.UsedHeapSize)-int64(h0.UsedHeapSize))/1e6)
	return nil
}

func benchFingerprintTimed(pow *hcaptchapow.Pow, out []string) float64 {
	t0 := time.Now()
	for i := range out {
		fp, err := hcaptcha.BuildFingerprint(pow)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fingerprint: %v\n", err)
			continue
		}
		out[i] = fp
	}
	return time.Since(t0).Seconds() * 1000 / float64(len(out))
}

func benchFingerprint(pow *hcaptchapow.Pow, runs int) error {
	t0 := time.Now()
	for i := 0; i < runs; i++ {
		if _, err := hcaptcha.BuildFingerprint(pow); err != nil {
			return err
		}
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("fingerprint: avg=%.2fms runs=%d heapAlloc=%.2fMB\n",
		time.Since(t0).Seconds()*1000/float64(runs), runs, float64(m.HeapAlloc)/1e6)
	return nil
}

func readCPU(out *[2]float64) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return
	}
	out[0] = float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6
	out[1] = float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
}
