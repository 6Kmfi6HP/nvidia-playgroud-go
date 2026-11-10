// Solver-cache ownership for the hCaptcha pipeline: one cached hsw.Solver
// per bundle location, lazily loaded via loadSolver, released via
// CloseSolvers.
package hcaptcha

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"nvidia-playgroud-go/internal/hsw"
)

// loadSolver is a package-level indirection over the hsw network entry
// point so the solve pipeline is exercisable offline in tests.
var loadSolver = hsw.LoadSolver

// pinnedLocation, when set, overrides the bundle location the challenge
// JWT names: every solve loads the pinned hsw.js instead of the assigned
// one. The submitted challenge spec still carries the original JWT, so the
// server's verdict tells whether an n minted by a different bundle variant
// validates — the compatibility question behind datacenter bundle rotation.
var pinnedLocation string

// SetPinnedBundleLocation pins all subsequent solves to one hsw.js bundle
// location ("" clears the pin). Diagnostic and fallback hook: hCaptcha
// assigns different bundle locations per exit-IP reputation, and a pinned
// known-good bundle sidesteps variants that break the V8 runner.
func SetPinnedBundleLocation(loc string) { pinnedLocation = loc }

// pinOverrides reports whether solves for location are redirected to the
// pinned bundle.
func pinOverrides(location string) bool {
	return pinnedLocation != "" && pinnedLocation != location
}

// hCaptcha rotates hsw.js bundle variants by exit-IP reputation: a datacenter
// exit is assigned a different location on nearly every checksiteconfig call.
// A variant that fails to evaluate or whose proof never settles (compile-poison
// wasm, environment traps) is broken for every future assignment — the
// location hash addresses immutable content — so re-assignments are cut
// short for brokenBundleTTL instead of paying a full eval/10s-solve cycle.
const brokenBundleTTL = 10 * time.Minute

var (
	brokenBundlesMu sync.Mutex
	brokenBundles   = map[string]time.Time{} // location -> broken until
)

// markBundleBroken records location as unusable when err is attributable to
// the bundle itself (hsw.ErrBundleBroken). Transport-level download failures
// and solve rejections do not mark anything: they can be transient or
// fingerprint-related, and a fresh attempt should retry the load.
func markBundleBroken(location string, err error) {
	if location == "" || err == nil || !errors.Is(err, hsw.ErrBundleBroken) {
		return
	}
	brokenBundlesMu.Lock()
	brokenBundles[location] = time.Now().Add(brokenBundleTTL)
	brokenBundlesMu.Unlock()
}

// bundleBroken reports whether location is currently in the broken-bundle
// negative cache; expired entries are dropped on read.
func bundleBroken(location string) bool {
	brokenBundlesMu.Lock()
	defer brokenBundlesMu.Unlock()
	until, ok := brokenBundles[location]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(brokenBundles, location)
		return false
	}
	return true
}

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
	if pinnedLocation != "" {
		location = pinnedLocation
	}
	return solverForExact(ctx, location)
}

// solverForExact loads the solver for the exact location given, bypassing
// any pin. The encrypted getcaptcha wire is encrypted and decrypted with
// the key embedded in the ASSIGNED bundle's wasm, so the crypto side must
// always use the assigned variant even when the PoW solve is redirected.
func solverForExact(ctx context.Context, location string) (*hsw.Solver, error) {
	if bundleBroken(location) {
		return nil, fmt.Errorf("hcaptcha: hsw bundle %s marked broken (failed eval/solve within the last %s)", location, brokenBundleTTL)
	}
	if v, ok := solverCache.Load(location); ok {
		return v.(*hsw.Solver), nil
	}
	s, err := loadSolver(ctx, location)
	if err != nil {
		// A bundle-attributable load failure (eval CompileError etc.) marks
		// the location so repeated assignments fail fast.
		markBundleBroken(location, err)
		return nil, err
	}
	actual, loaded := solverCache.LoadOrStore(location, s)
	if loaded {
		s.Close()
		return actual.(*hsw.Solver), nil
	}
	return s, nil
}

// CloseSolvers closes every cached solver, releasing its V8 isolate, and
// clears the broken-bundle negative cache. The solver cache is populated
// lazily and otherwise kept for the process lifetime; call this at shutdown
// or between tests.
func CloseSolvers() {
	solverCache.Range(func(k, v any) bool {
		solverCache.Delete(k)
		v.(*hsw.Solver).Close()
		return true
	})
	closeMintSolvers()
	brokenBundlesMu.Lock()
	brokenBundles = map[string]time.Time{}
	brokenBundlesMu.Unlock()
}
