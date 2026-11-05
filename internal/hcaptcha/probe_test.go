package hcaptcha

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestProbeChallengeLocations fetches several fresh challenges and prints the
// hsw.js location each one references, to observe hCaptcha's bundle rotation.
func TestProbeChallengeLocations(t *testing.T) {
	if !strings.EqualFold(os.Getenv("HSW_LIVE"), "1") {
		t.Skip("set HSW_LIVE=1")
	}
	n := 6
	if v := os.Getenv("HSW_PROBE_N"); v != "" {
		n = 6
	}
	seen := map[string]int{}
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		jwt, location, _, _, err := fetchChecksiteLive(ctx, "0c6a1e45-75d7-43cc-b836-a0c9d886b8ee", "build.nvidia.com")
		cancel()
		if err != nil {
			t.Logf("round %d: err=%v", i, err)
			continue
		}
		seen[location]++
		t.Logf("round %d: loc=%s jwt_len=%d", i, location, len(jwt))
	}
	for loc, c := range seen {
		t.Logf("LOCATION %s x%d", loc, c)
	}
}
