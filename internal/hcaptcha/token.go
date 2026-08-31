// Solver-cache ownership for the hCaptcha pipeline: one cached hsw.Solver
// per bundle location, lazily loaded via loadSolver, released via
// CloseSolvers.
package hcaptcha

import (
	"context"
	"sync"

	"glm52-nvidia/internal/hsw"
)

// loadSolver is a package-level indirection over the hsw network entry
// point so the solve pipeline is exercisable offline in tests.
var loadSolver = hsw.LoadSolver

// solverCache caches one hsw.Solver per bundle location: consecutive
// challenges for the same site reuse the downloaded/patched bundle and its
// V8 isolate. Isolates are single-threaded; hsw.Solver serializes access.
// Solvers are kept for the process lifetime and released via CloseSolvers;
// a solver that loses the cache race is closed immediately.
var solverCache sync.Map // location -> *hsw.Solver

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
