package hcaptcha

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"glm52-nvidia/internal/hcaptchapow"
	"glm52-nvidia/internal/hsw"
)

// testPowData is a fixed base64 resource (hCaptcha PoW "d" claims are always
// base64, so it is JSON-safe inside the "data":"..." string).
const testPowData = "VGhpcyBpcyB0aGUgdGVzdCBwb3cgZGF0YQ=="

// fakeJWT builds a well-formed PoW JWT (unvalidated signature) for the given
// claims, mirroring checksiteconfig responses.
func fakeJWT(t *testing.T, difficulty float64, data, loc string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"f": 0.0, "s": difficulty, "t": "w", "d": data, "l": loc,
		"i": "sha256-test-signature", "e": 1712552328.0, "n": "hsw", "c": 1000.0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return "eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// reRandElem matches the fingerprint's rand second element (a float), which
// depends on the random stamp salt through the CRC and therefore varies
// between builds.
var reRandElem = regexp.MustCompile(`"rand":\[[0-9.]+,[0-9.]+\]`)

// fpDoc mirrors the fingerprint JSON fields the offline tests assert on.
type fpDoc struct {
	ProofSpec struct {
		Difficulty      float64 `json:"difficulty"`
		FingerprintType float64 `json:"fingerprint_type"`
		Type            string  `json:"_type"`
		Data            string  `json:"data"`
		Location        string  `json:"_location"`
		TimeoutValue    float64 `json:"timeout_value"`
	} `json:"proof_spec"`
	Rand       []float64 `json:"rand"`
	Components struct {
		WebGLHash       string `json:"web_gl_hash"`
		CanvasHash      string `json:"canvas_hash"`
		AudioHash       string `json:"audio_hash"`
		ParentWinHash   string `json:"parent_win_hash"`
		WebRTCHash      string `json:"webrtc_hash"`
		PerformanceHash string `json:"performance_hash"`
	} `json:"components"`
	Stamp string `json:"stamp"`
}

func decodeFingerprint(t *testing.T, fpB64 string) ([]byte, fpDoc) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(fpB64)
	if err != nil {
		t.Fatalf("fingerprint is not standard base64: %v", err)
	}
	if !json.Valid(raw) {
		t.Fatalf("fingerprint is not valid JSON")
	}
	var doc fpDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("fingerprint JSON does not match expected shape: %v", err)
	}
	return raw, doc
}

// TestBuildFingerprint verifies the fingerprint offline: proof_spec is
// back-filled from the fields ParsePow decoded from a challenge JWT, the JSON
// is valid, the rand second element is the CRC-32 (=RandHash) of the payload
// with that element removed, hash-class component fields use HashString, and
// the output is deterministic.
func TestBuildFingerprint(t *testing.T) {
	const (
		dif = 2.0
		loc = "/c/282d0ff"
	)
	jwt := fakeJWT(t, dif, testPowData, loc)
	pow, err := hcaptchapow.ParsePow(jwt)
	if err != nil {
		t.Fatalf("ParsePow: %v", err)
	}

	fpB64, err := BuildFingerprint(pow)
	if err != nil {
		t.Fatalf("BuildFingerprint: %v", err)
	}
	raw, doc := decodeFingerprint(t, fpB64)

	// proof_spec comes from the JWT claims (round-trip through ParsePow).
	if doc.ProofSpec.Difficulty != pow.Difficulty || doc.ProofSpec.Difficulty != dif {
		t.Errorf("difficulty = %v, want %v", doc.ProofSpec.Difficulty, dif)
	}
	if doc.ProofSpec.Data != pow.PowData || doc.ProofSpec.Data != testPowData {
		t.Errorf("data = %q, want %q", doc.ProofSpec.Data, testPowData)
	}
	if doc.ProofSpec.Location != AssetBase+loc {
		t.Errorf("_location = %q, want %q", doc.ProofSpec.Location, AssetBase+loc)
	}
	if doc.ProofSpec.Type != "w" || doc.ProofSpec.FingerprintType != 0 || doc.ProofSpec.TimeoutValue != 1000 {
		t.Errorf("proof_spec statics = %+v", doc.ProofSpec)
	}

	// rand: [Math.random sample, CRC-32 * 2^-32 of fp minus the 2nd element].
	if len(doc.Rand) != 2 {
		t.Fatalf("rand has %d elements, want 2", len(doc.Rand))
	}
	if doc.Rand[0] != 0.960537614638231 {
		t.Errorf("rand[0] = %v, want the template's Math.random sample", doc.Rand[0])
	}
	withoutSecond := strings.Replace(string(raw), ","+strconv.FormatFloat(doc.Rand[1], 'f', -1, 64)+"]", "]", 1)
	if withoutSecond == string(raw) {
		t.Fatal("could not strip the rand second element for CRC check")
	}
	if _, want := hcaptchapow.RandHash([]byte(withoutSecond)); doc.Rand[1] != want {
		t.Errorf("rand[1] = %v, want RandHash(fp minus rand[1]) = %v", doc.Rand[1], want)
	}

	// hash-class component fields are deterministic HashString outputs over
	// the phase-1 placeholder raw content; the "-1" sentinels stay put.
	if doc.Components.CanvasHash != hcaptchapow.HashString(hashRawByField["canvas_hash"]) {
		t.Errorf("canvas_hash = %q, want HashString(placeholder)", doc.Components.CanvasHash)
	}
	if doc.Components.ParentWinHash != hcaptchapow.HashString(hashRawByField["parent_win_hash"]) {
		t.Errorf("parent_win_hash = %q, want HashString(placeholder)", doc.Components.ParentWinHash)
	}
	if doc.Components.PerformanceHash != hcaptchapow.HashString(hashRawByField["performance_hash"]) {
		t.Errorf("performance_hash = %q, want HashString(placeholder)", doc.Components.PerformanceHash)
	}
	for field, want := range map[string]string{
		"web_gl_hash": "-1", "audio_hash": "-1", "webrtc_hash": "-1",
	} {
		if got := doc.Components.WebGLHash; field == "web_gl_hash" && got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
		if got := doc.Components.AudioHash; field == "audio_hash" && got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
		if got := doc.Components.WebRTCHash; field == "webrtc_hash" && got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
	}
	// stamp is a freshly minted hashcash stamp satisfying the challenge's
	// full leading-zero difficulty (JWT s * 2 bits), with the reference
	// hashcash layout (7 colon-separated fields).
	if !hcaptchapow.CheckStamp(doc.Stamp, uint(pow.Difficulty*2)) {
		t.Errorf("stamp = %q does not satisfy CheckStamp(%d bits)", doc.Stamp, uint(pow.Difficulty*2))
	}
	if len(strings.Split(doc.Stamp, ":")) != 7 {
		t.Errorf("stamp = %q, want 7 colon-separated hashcash fields", doc.Stamp)
	}

	// Determinism: RandHash and HashString are seeded/fixed, so the same pow
	// yields byte-identical output apart from the random stamp salt.
	again, err := BuildFingerprint(pow)
	if err != nil {
		t.Fatalf("BuildFingerprint (2nd): %v", err)
	}
	raw2, doc2 := decodeFingerprint(t, again)
	// Mask the random stamp salt and the rand CRC it feeds into (rand[1] is
	// the CRC-32 of the payload, which embeds the stamp), then compare.
	norm := func(raw []byte, doc fpDoc) string {
		s := strings.ReplaceAll(string(raw), doc.Stamp, "STAMP")
		s = reRandElem.ReplaceAllString(s, "RAND1")
		return s
	}
	if norm(raw, doc) != norm(raw2, doc2) {
		t.Error("BuildFingerprint is not deterministic apart from stamp salt")
	}
	if !hcaptchapow.CheckStamp(doc2.Stamp, uint(pow.Difficulty*2)) {
		t.Errorf("2nd stamp = %q does not satisfy CheckStamp(%d bits)", doc2.Stamp, uint(pow.Difficulty*2))
	}
}

// TestLocationURL covers the three "l" claim conventions.
func TestLocationURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://newassets.hcaptcha.com/c/282d0ff", "https://newassets.hcaptcha.com/c/282d0ff"},
		{"/c/282d0ff", "https://newassets.hcaptcha.com/c/282d0ff"},
		{"/c/282d0ff/", "https://newassets.hcaptcha.com/c/282d0ff"},
		{"282d0ff", "https://newassets.hcaptcha.com/c/282d0ff"},
	}
	for _, c := range cases {
		if got := locationURL(c.in); got != c.want {
			t.Errorf("locationURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSolveNStopsAtFingerprint drives SolveN through the offline stages only:
// a fake challenge fetch feeds ParsePow and BuildFingerprint, then the fake
// solver loader fails (no network, no V8). The error must carry the solver
// stage prefix and the fingerprint must already be populated.
func TestSolveNStopsAtFingerprint(t *testing.T) {
	oldFetch, oldLoad := fetchChallenge, loadSolver
	defer func() { fetchChallenge, loadSolver = oldFetch, oldLoad }()

	const loc = "/c/282d0ff"
	fetchChallenge = func(ctx context.Context, sitekey, host string) (string, string, error) {
		return fakeJWT(t, 2, testPowData, loc), loc, nil
	}
	loadSolver = func(ctx context.Context, location string) (*hsw.Solver, error) {
		return nil, errors.New("offline: solver download disabled")
	}

	jwt, location, fpB64, n, elapsed, err := SolveN(context.Background(), "sitekey", "host")
	if err == nil || !strings.Contains(err.Error(), "load solver") {
		t.Fatalf("SolveN err = %v, want stage prefix \"load solver\"", err)
	}
	if jwt == "" || location != loc || fpB64 == "" {
		t.Errorf("partial results jwt=%q location=%q fpB64=%q", jwt, location, fpB64)
	}
	if n != "" {
		t.Errorf("n = %q, want empty (solve stage never reached)", n)
	}
	_, doc := decodeFingerprint(t, fpB64)
	if doc.ProofSpec.Data != testPowData {
		t.Errorf("fingerprint data = %q, want %q", doc.ProofSpec.Data, testPowData)
	}
	if elapsed <= 0 {
		t.Errorf("elapsed = %v, want > 0", elapsed)
	}
}

// fakeV1Body is a miniature hsw v1 bundle: window.hsw(jwt, fpB64) resolves
// to "n:<jwt-len>:<fpB64-len>"; crypto modes (vv === 1|0) echo the input
// bytes unchanged. Exercises the same prepare/wrap/dispatch path as the real
// bundle without any network or heavy assembly.
const fakeV1Body = `window.hsw = function(vv, aSj) {
  if (vv === 1 || vv === 0) {
    var u = new Uint8Array(aSj.length);
    for (var i = 0; i < aSj.length; i++) u[i] = aSj[i];
    return Promise.resolve(u);
  }
  return Promise.resolve("n:" + String(vv).length + ":" + String(aSj).length);
};`

// TestSolveNWithFakeSolver runs the full pipeline offline with a stubbed
// solver and verifies the solver cache: two solves for the same bundle
// location reuse the cached solver (loader called once).
func TestSolveNWithFakeSolver(t *testing.T) {
	oldFetch, oldLoad := fetchChallenge, loadSolver
	defer func() { fetchChallenge, loadSolver = oldFetch, oldLoad }()
	defer CloseSolvers()

	const loc = "/c/282d0ff"
	fetchChallenge = func(ctx context.Context, sitekey, host string) (string, string, error) {
		return fakeJWT(t, 2, testPowData, loc), loc, nil
	}
	loads := 0
	loadSolver = func(ctx context.Context, location string) (*hsw.Solver, error) {
		loads++
		b, err := hsw.Prepare([]byte(fakeV1Body))
		if err != nil {
			return nil, err
		}
		return hsw.New(b)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	jwt, location, fpB64, n, _, err := SolveN(ctx, "sitekey", "host")
	if err != nil {
		t.Fatalf("SolveN #1: %v", err)
	}
	want := "n:" + strconv.Itoa(len(jwt)) + ":" + strconv.Itoa(len(fpB64))
	if n != want {
		t.Fatalf("SolveN #1 n = %q, want %q", n, want)
	}
	if location != loc {
		t.Errorf("location = %q, want %q", location, loc)
	}
	if loads != 1 {
		t.Fatalf("solver loads after #1 = %d, want 1", loads)
	}

	if _, _, fpB642, n2, _, err := SolveN(ctx, "sitekey", "host"); err != nil {
		t.Fatalf("SolveN #2: %v", err)
	} else if want2 := "n:" + strconv.Itoa(len(jwt)) + ":" + strconv.Itoa(len(fpB642)); n2 != want2 {
		// fpB64 length varies between solves: the mined stamp's counter hex
		// width depends on the random salt, so compare against run #2's own
		// expected value instead of run #1's.
		t.Errorf("SolveN #2 n = %q, want %q", n2, want2)
	}
	if loads != 1 {
		t.Errorf("solver loads after #2 = %d, want 1 (cache miss)", loads)
	}
}

// TestLive runs the real pipeline against hCaptcha for build.nvidia.com:
// checksiteconfig -> fingerprint -> hsw solve. Disabled by default; enable
// with HSW_LIVE=1 when network is available.
func TestLive(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	if !strings.EqualFold(os.Getenv("HSW_LIVE"), "1") {
		t.Skip("set HSW_LIVE=1 to run the live solve")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	defer CloseSolvers()

	const (
		sitekey = "0c6a1e45-75d7-43cc-b836-a0c9d886b8ee"
		host    = "build.nvidia.com"
	)
	jwt, location, fpB64, n, elapsed, err := SolveN(ctx, sitekey, host)
	t.Logf("jwt_len=%d location=%q fpB64_len=%d n_len=%d n_prefix=%q elapsed=%s err=%v",
		len(jwt), location, len(fpB64), len(n), clip(n, 60), elapsed, err)
	if err != nil {
		t.Fatalf("SolveN: %v", err)
	}
	if jwt == "" || fpB64 == "" || location == "" {
		t.Fatalf("incomplete solve results: jwt=%d fpB64=%d location=%q", len(jwt), len(fpB64), location)
	}
	if len(n) < 100 {
		t.Errorf("n suspiciously short: %d", len(n))
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
