// Pipeline orchestration: challenge fetch -> PoW JWT parse -> fingerprint
// build -> hsw solve, with a process-lifetime solver cache keyed by the
// bundle location.
package hcaptcha

import (
	"context"
	"fmt"
	"sync"
	"time"

	"glm52-nvidia/internal/hcaptchapow"
	"glm52-nvidia/internal/hsw"
)

// fetchChallenge and loadSolver are package-level indirections over the hsw
// network entry points so SolveN can be exercised fully offline in tests.
var (
	fetchChallenge = hsw.FetchChallenge
	loadSolver     = hsw.LoadSolver
)

// solverCache caches one hsw.Solver per bundle location: consecutive
// challenges for the same site reuse the downloaded/patched bundle and its
// V8 isolate. Isolates are single-threaded; hsw.Solver serializes access.
// Solvers are kept for the process lifetime and released via CloseSolvers;
// a solver that loses the cache race is closed immediately.
var solverCache sync.Map // location -> *hsw.Solver

// SolveResult carries the SolveN pipeline outputs.
type SolveResult struct {
	JWT         string // challenge jwt from checksiteconfig
	Location    string // hsw.js bundle location (solver cache key / download URL)
	Fingerprint string // base64 fingerprint sent to the hsw solver
	N           string // solved proof-of-work n value
	Elapsed     time.Duration
}

// SolveN runs the full hCaptcha solve pipeline for a sitekey/host:
// checksiteconfig -> JWT parse -> fingerprint build -> hsw solve.
//
// On error, the fields produced before the failing stage are still populated
// (e.g. JWT/Location/Fingerprint when only the solve failed), and the error
// carries the failing stage as a prefix.
func SolveN(ctx context.Context, sitekey, host string) (SolveResult, error) {
	start := time.Now()
	var res SolveResult

	var err error
	res.JWT, res.Location, err = fetchChallenge(ctx, sitekey, host)
	if err != nil {
		res.Elapsed = time.Since(start)
		return res, fmt.Errorf("hcaptcha: fetch challenge: %w", err)
	}
	pow, err := hcaptchapow.ParsePow(res.JWT)
	if err != nil {
		res.Elapsed = time.Since(start)
		return res, fmt.Errorf("hcaptcha: parse pow: %w", err)
	}
	res.Fingerprint, err = BuildFingerprint(pow)
	if err != nil {
		res.Elapsed = time.Since(start)
		return res, fmt.Errorf("hcaptcha: build fingerprint: %w", err)
	}
	solver, err := solverFor(ctx, res.Location)
	if err != nil {
		res.Elapsed = time.Since(start)
		return res, fmt.Errorf("hcaptcha: load solver: %w", err)
	}
	res.N, err = solver.SolveN(ctx, res.JWT, res.Fingerprint)
	if err != nil {
		res.Elapsed = time.Since(start)
		return res, fmt.Errorf("hcaptcha: solve: %w", err)
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

// solverFor returns the cached solver for location, downloading, patching and
// wrapping the hsw.js bundle on a cache miss. Only one solver wins per
// location; losers are closed to avoid leaking V8 isolates.
func solverFor(ctx context.Context, location string) (*hsw.Solver, error) {
	if v, ok := solverCache.Load(location); ok {
		return v.(*hsw.Solver), nil
	}
	s, err := loadSolver(ctx, location)
	if err != nil {
		return nil, err
	}
	actual, loaded := solverCache.LoadOrStore(location, s)
	if loaded {
		s.Close()
		return actual.(*hsw.Solver), nil
	}
	return s, nil
}

// CloseSolvers closes every cached solver, releasing its V8 isolate. The
// cache is populated lazily and otherwise kept for the process lifetime; call
// this at shutdown or between tests.
func CloseSolvers() {
	solverCache.Range(func(k, v any) bool {
		solverCache.Delete(k)
		v.(*hsw.Solver).Close()
		return true
	})
}
