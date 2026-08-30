// hswprobe downloads the hCaptcha hsw.js bundle for a sitekey/host, runs the
// hsw proof-of-work through the in-process V8 runner (internal/hsw) and
// prints the resulting n value.
//
// Usage:
//
//	go run ./cmd/hswprobe -sitekey 0c6a1e45-75d7-43cc-b836-a0c9d886b8ee -host build.nvidia.com
//
// When -location is omitted, the challenge JWT is fetched from
// checksiteconfig and the bundle location is read from its "l" claim via
// internal/hcaptchapow. Passing a JWT as -location also works.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"glm52-nvidia/internal/hcaptchapow"
	"glm52-nvidia/internal/hsw"
)

// defaultFingerprint returns a minimal fingerprint payload, base64-encoded,
// matching the shape hsw expects for its second argument.
func defaultFingerprint() string {
	fp := map[string]any{
		"st": time.Now().Unix(),
		"md": "",
	}
	b, _ := json.Marshal(fp)
	return base64.StdEncoding.EncodeToString(b)
}

func main() {
	sitekey := flag.String("sitekey", "0c6a1e45-75d7-43cc-b836-a0c9d886b8ee", "hCaptcha sitekey")
	host := flag.String("host", "build.nvidia.com", "host the captcha is served for")
	location := flag.String("location", "", "hsw.js location (default: from checksiteconfig JWT)")
	fp := flag.String("fp", "", "fingerprint base64 (default: minimal stub)")
	timeout := flag.Duration("timeout", 90*time.Second, "total timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	jwt := ""
	switch {
	case *location == "":
		// Default: fetch the challenge; the JWT's "l" claim is the location.
		var err error
		jwt, *location, err = hsw.FetchChallenge(ctx, *sitekey, *host)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		fmt.Printf("challenge jwt: %s... (len %d)\n", clipped(jwt, 40), len(jwt))
	case strings.Count(*location, ".") == 2:
		// -location was given a JWT token instead; parse it with the
		// proof-of-work core and use the payload's location claim.
		jwt = *location
		pow, err := hcaptchapow.ParsePow(jwt)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		*location = pow.Location
	default:
		// -location pins the bundle; the challenge JWT still comes from the
		// config endpoint (its own location claim is ignored).
		var err error
		jwt, _, err = hsw.FetchChallenge(ctx, *sitekey, *host)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		fmt.Printf("challenge jwt: %s... (len %d)\n", clipped(jwt, 40), len(jwt))
	}

	fpB64 := *fp
	if fpB64 == "" {
		fpB64 = defaultFingerprint()
	}

	fmt.Printf("downloading hsw.js: %s\n", hsw.AssetURL(*location))
	t0 := time.Now()
	solver, err := hsw.LoadSolver(ctx, *location)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer solver.Close()
	fmt.Printf("bundle version=%s size=%d download=%s\n", solver.Bundle().Version, len(solver.Bundle().Source), time.Since(t0).Round(time.Millisecond))

	fmt.Println("solving hsw...")
	t1 := time.Now()
	n, err := solver.SolveN(ctx, jwt, fpB64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "solve error:", err)
		os.Exit(1)
	}
	fmt.Printf("n: len=%d prefix=%q elapsed=%s\n", len(n), clipped(n, 80), time.Since(t1).Round(time.Millisecond))
}

func clipped(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
