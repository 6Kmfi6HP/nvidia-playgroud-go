package hsw

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// A miniature v1-style bundle: defines window.hsw(jwt, fp) returning a
// Promise, like the real build does after Prepare wraps it.
const fakeV1Body = `/* { "version": "v1", "hash": "sha256-xx" } */
!function(){"use strict";
window.hsw = function(vv, aSj) {
  return Promise.resolve("N:" + String(vv) + ":" + String(aSj));
};
}();`

func mustPrepare(t *testing.T, raw string) *Bundle {
	t.Helper()
	b, err := Prepare([]byte(raw))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return b
}

func TestPatchStrings(t *testing.T) {
	raw := `J(I).language; x instanceof Window; y instanceof PerformanceResourceTiming;`
	b := mustPrepare(t, raw)
	for _, want := range []string{`"en-US"`, "instanceof Object", "instanceof Object"} {
		if !strings.Contains(b.Source, want) {
			t.Errorf("patched source missing %q", want)
		}
	}
	if !strings.Contains(b.Source, "module.exports = hsw;") {
		t.Errorf("default export line missing")
	}
}

func TestExportDetectionV1(t *testing.T) {
	b := mustPrepare(t, fakeV1Body)
	if !strings.Contains(b.Source, "module.exports = window.hsw;") {
		t.Errorf("v1 export line missing, got tail: %s", tail(b.Source))
	}
	if b.Version != "v1" {
		t.Errorf("version = %q, want v1", b.Version)
	}
}

func TestPatchWasmInstantiate(t *testing.T) {
	const raw = `Lc=WebAssembly.instantiate(vv,afs).then(function(vv){ajz(vv)})`
	out, n := syncWasmInstantiate(raw)
	if n != 1 {
		t.Fatalf("syncWasmInstantiate did not apply")
	}
	for _, want := range []string{"new WebAssembly.Module(vv)", "new WebAssembly.Instance(__m,afs)", "queueMicrotask(function(){ajz(__r)})"} {
		if !strings.Contains(out, want) {
			t.Errorf("replacement missing %q: %s", want, out)
		}
	}
	if strings.Contains(out, "WebAssembly.instantiate") {
		t.Errorf("promise instantiate still present: %s", out)
	}
}

func TestPatchWasmInstantiateNewShape(t *testing.T) {
	const raw = `NN=WebAssembly.instantiate(cl,_l).then(function(cl){xL(cl)})}`
	out, n := syncWasmInstantiate(raw)
	if n != 1 {
		t.Fatalf("syncWasmInstantiate did not apply to the new bundle shape")
	}
	for _, want := range []string{"new WebAssembly.Module(cl)", "new WebAssembly.Instance(__m,_l)", "queueMicrotask(function(){xL(__r)})"} {
		if !strings.Contains(out, want) {
			t.Errorf("replacement missing %q: %s", want, out)
		}
	}
	if strings.Contains(out, "WebAssembly.instantiate") {
		t.Errorf("promise instantiate still present: %s", out)
	}
}

func TestLocationFromJWT(t *testing.T) {
	jwt := "eyJoZWFkZXIiOiJqIn0.eyJsIjoiL2MvOGFmNTUzMTUwMTVlMTdmYThjOTY0YmUzNGFlOTNkNTNiN2Y5YzM2ZWRhZmNjY2RjN2ZjOWE0NjkxY2JkOWU0MyIsIm4iOiJoc3cifQ.sig"
	loc, err := LocationFromJWT(jwt)
	if err != nil {
		t.Fatalf("LocationFromJWT: %v", err)
	}
	want := "/c/8af55315015e17fa8c964be34ae93d53b7f9c36edafcccdc7fc9a4691cbd9e43"
	if loc != want {
		t.Errorf("loc = %q, want %q", loc, want)
	}
}

// TestSolveLocal exercises the whole local pipeline: shim eval, atob
// injection, module.exports lookup and promise resolution via microtask
// checkpoint — no network, no real wasm.
func TestSolveLocal(t *testing.T) {
	b := mustPrepare(t, fakeV1Body)
	s, err := New(b)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := s.SolveN(ctx, "jwt.abc", "c2k=")
	if err != nil {
		t.Fatalf("SolveN: %v", err)
	}
	if want := "N:jwt.abc:c2k="; got != want {
		t.Errorf("SolveN = %q, want %q", got, want)
	}
}

// TestAtobBinary verifies atob returns a true binary string (charCodeAt ==
// byte): the regression that broke v1 wasm assembly when v8go mangled bytes
// >= 0x80 through UTF-8 conversion.
func TestAtobBinary(t *testing.T) {
	// "3ijvFddf0qhU" decodes to bytes 0xDE 0x28 0xEF ... — all >= 0x80
	// must survive the Go->JS string round trip.
	raw := `window.hsw = function(vv, aSj) {
  var b = atob("3ijvFddf0qhU");
  return Promise.resolve("" + b.charCodeAt(0) + ":" + b.charCodeAt(1) + ":" + b.charCodeAt(2));
};`
	b := mustPrepare(t, raw)
	s, err := New(b)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	got, err := s.SolveN(context.Background(), "j", "f")
	if err != nil {
		t.Fatalf("SolveN: %v", err)
	}
	if want := "222:40:239"; got != want {
		t.Errorf("atob binary = %q, want %q", got, want)
	}
}

// TestSolveLocalTwice checks isolate reuse across two solves in the same
// solver (fresh v8 context per solve).
func TestSolveLocalTwice(t *testing.T) {
	b := mustPrepare(t, fakeV1Body)
	s, err := New(b)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	for i := 0; i < 2; i++ {
		got, err := s.SolveN(context.Background(), "jwt.abc", "c2k=")
		if err != nil {
			t.Fatalf("SolveN #%d: %v", i, err)
		}
		if got != "N:jwt.abc:c2k=" {
			t.Fatalf("SolveN #%d = %q", i, got)
		}
	}
}

// TestLiveSolve is an end-to-end solve against hCaptcha's live endpoints.
// Disabled by default; enable with HSW_LIVE=1 when network is available.
func TestLiveSolve(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	if !strings.EqualFold(lookupEnv("HSW_LIVE"), "1") {
		t.Skip("set HSW_LIVE=1 to run the live solve")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	const (
		sitekey = "0c6a1e45-75d7-43cc-b836-a0c9d886b8ee"
		host    = "build.nvidia.com"
	)
	jwt, loc, err := FetchChallenge(ctx, sitekey, host)
	if err != nil {
		t.Fatalf("FetchChallenge: %v", err)
	}
	s, err := LoadSolver(ctx, loc)
	if err != nil {
		t.Fatalf("LoadSolver: %v", err)
	}
	defer s.Close()
	start := time.Now()
	n, err := s.SolveN(ctx, jwt, "e30=")
	if err != nil {
		t.Fatalf("SolveN: %v", err)
	}
	t.Logf("location=%s version=%s n_len=%d n_prefix=%q elapsed=%s",
		loc, s.Bundle().Version, len(n), clip(n, 80), time.Since(start))
	if len(n) < 100 {
		t.Errorf("n suspiciously short: %d", len(n))
	}
}

// TestCryptoModes verifies the base64-adapter path for the bundle's crypto
// modes with an echo bundle: mode 1 (encrypt) and mode 0 (decrypt) must both
// round-trip the input bytes through the promise-resolution loop.
func TestCryptoModes(t *testing.T) {
	const echo = `window.hsw = function(mode, data) {
  if (mode === 1 || mode === 0) {
    var u = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i++) u[i] = data[i];
    return Promise.resolve(u);
  }
  return Promise.resolve("N:" + String(mode) + ":" + String(data));
};`
	s, err := New(mustPrepare(t, echo))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	in := []byte{0x00, 0x01, 0xfe, 0xff, 'a', 'b', 0x80}
	for _, mode := range []int{1, 0} {
		out, err := s.Crypto(ctx, mode, in)
		if err != nil {
			t.Fatalf("Crypto(%d): %v", mode, err)
		}
		if len(out) != len(in) {
			t.Fatalf("Crypto(%d) len = %d, want %d", mode, len(out), len(in))
		}
		for i := range in {
			if out[i] != in[i] {
				t.Errorf("Crypto(%d)[%d] = %#x, want %#x", mode, i, out[i], in[i])
			}
		}
	}
}

func lookupEnv(k string) string {
	v, _ := os.LookupEnv(k)
	return v
}

func tail(s string) string {
	if len(s) <= 120 {
		return s
	}
	return s[len(s)-120:]
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
