package hcaptcha

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
// claims, mirroring checksiteconfig responses. The difficulty and PoW data
// claims are fixed at 2.0 and testPowData, matching every offline challenge
// the tests build.
func fakeJWT(t *testing.T, loc string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"f": 0.0, "s": 2.0, "t": "w", "d": testPowData, "l": loc,
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
	jwt := fakeJWT(t, loc)
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

// TestSolverCacheReusesSolver runs the full offline solve pipeline through
// the production CaptchaToken path and verifies the solver cache: two solves
// for the same bundle location reuse the cached solver (loader called once).
func TestSolverCacheReusesSolver(t *testing.T) {
	oldFetch, oldLoad, oldPost, oldOctet := fetchChecksite, loadSolver, postGetCaptcha, postGetCaptchaOctetFn
	defer func() {
		fetchChecksite, loadSolver, postGetCaptcha, postGetCaptchaOctetFn = oldFetch, oldLoad, oldPost, oldOctet
		CloseSolvers()
	}()

	const loc = "/c/282d0ff"
	fetchChecksite = func(ctx context.Context, sitekey, host string) (string, string, string, error) {
		return fakeJWT(t, loc), loc, "key", nil
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
	const tok = "P1_offline.cache-test"
	postGetCaptcha = func(ctx context.Context, params map[string]string) (int, []byte, error) {
		return 200, []byte(`{"generated_pass_UUID":"` + tok + `"}`), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got1, err := CaptchaToken(ctx, "sitekey", "host")
	if err != nil {
		t.Fatalf("CaptchaToken #1: %v", err)
	}
	if got1 != tok {
		t.Fatalf("CaptchaToken #1 = %q, want %q", got1, tok)
	}
	if loads != 1 {
		t.Fatalf("solver loads after #1 = %d, want 1", loads)
	}

	got2, err := CaptchaToken(ctx, "sitekey", "host")
	if err != nil {
		t.Fatalf("CaptchaToken #2: %v", err)
	}
	if got2 != tok {
		t.Errorf("CaptchaToken #2 = %q, want %q", got2, tok)
	}
	if loads != 1 {
		t.Errorf("solver loads after #2 = %d, want 1 (cache miss)", loads)
	}
}

// TestLiveCaptchaToken runs the real production path against hCaptcha for
// build.nvidia.com through CaptchaTokenDetail. Disabled by default; enable
// with HSW_LIVE=1 when network is available.
func TestLiveCaptchaToken(t *testing.T) {
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
	token, solve, err := CaptchaTokenDetail(ctx, sitekey, host)
	t.Logf("token_len=%d jwt_len=%d location=%q fpB64_len=%d elapsed=%s err=%v",
		len(token), len(solve.JWT), solve.Location, len(solve.Fingerprint), solve.Elapsed, err)
	if err != nil {
		t.Fatalf("CaptchaTokenDetail: %v", err)
	}
	if token == "" || solve.JWT == "" || solve.Fingerprint == "" || solve.Location == "" {
		t.Fatalf("incomplete solve results: token=%d jwt=%d fpB64=%d location=%q",
			len(token), len(solve.JWT), len(solve.Fingerprint), solve.Location)
	}
}
