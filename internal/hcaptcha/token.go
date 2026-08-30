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

// SolveN runs the full hCaptcha solve pipeline for a sitekey/host:
// checksiteconfig -> JWT parse -> fingerprint build -> hsw solve.
//
// It returns the challenge jwt, the bundle location (used as the solver cache
// key and for hsw.js download), the base64 fingerprint, the solved n and the
// total wall-clock time. On error, the values produced before the failing
// stage are still returned (e.g. jwt/location/fpB64 when only the solve
// failed), and the error carries the failing stage as a prefix.
func SolveN(ctx context.Context, sitekey, host string) (jwt, location, fpB64, n string, elapsed time.Duration, err error) {
	start := time.Now()

	jwt, location, err = fetchChallenge(ctx, sitekey, host)
	if err != nil {
		return "", "", "", "", time.Since(start), fmt.Errorf("hcaptcha: fetch challenge: %w", err)
	}
	pow, err := hcaptchapow.ParsePow(jwt)
	if err != nil {
		return jwt, location, "", "", time.Since(start), fmt.Errorf("hcaptcha: parse pow: %w", err)
	}
	fpB64, err = BuildFingerprint(pow)
	if err != nil {
		return jwt, location, "", "", time.Since(start), fmt.Errorf("hcaptcha: build fingerprint: %w", err)
	}
	solver, err := solverFor(ctx, location)
	if err != nil {
		return jwt, location, fpB64, "", time.Since(start), fmt.Errorf("hcaptcha: load solver: %w", err)
	}
	n, err = solver.SolveN(ctx, jwt, fpB64)
	if err != nil {
		return jwt, location, fpB64, "", time.Since(start), fmt.Errorf("hcaptcha: solve: %w", err)
	}
	return jwt, location, fpB64, n, time.Since(start), nil
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
