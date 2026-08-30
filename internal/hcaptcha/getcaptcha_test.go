package hcaptcha

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"glm52-nvidia/internal/hsw"
)

func TestFindP1Token(t *testing.T) {
	const tok = "P1_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"
	cases := []struct {
		name string
		body string
		want string
	}{
		{"generated_pass_UUID", `{"pass":true,"generated_pass_UUID":"` + tok + `"}`, tok},
		{"captcha_token", `{"captcha_token":"` + tok + `"}`, tok},
		{"nested data", `{"data":{"token":"` + tok + `"}}`, tok},
		{"raw text body", tok, tok},
		{"no token", `{"pass":false,"error":"invalid or missing n"}`, ""},
		{"short P1 junk", `{"error":"bad P1_abc"}`, ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FindP1Token([]byte(c.body)); got != c.want {
				t.Errorf("FindP1Token(%q) = %q, want %q", c.body, got, c.want)
			}
		})
	}
}

// TestPostGetCaptcha drives PostGetCaptcha against a local server: browser
// headers must be present, the JSON attempt must come first and, when the
// endpoint rejects it with a non-2xx status, the request must be retried with
// x-www-form-urlencoded.
func TestPostGetCaptcha(t *testing.T) {
	old := getcaptchaURL
	defer func() { getcaptchaURL = old }()

	var (
		mu      sync.Mutex
		gotReq  []string // "content-type|origin|referer|ua|path" per request
		gotBody []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		mu.Lock()
		gotReq = append(gotReq, r.Header.Get("Content-Type")+"|"+r.Header.Get("Origin")+"|"+r.Header.Get("Referer")+"|"+r.Header.Get("User-Agent")+"|"+r.URL.Path)
		gotBody = append(gotBody, string(body))
		mu.Unlock()
		if r.Header.Get("Content-Type") == "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			writeTestBody(t, w, []byte(`{"success":false,"error":"json not supported"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		writeTestBody(t, w, []byte(`{"pass":false,"error":"no passcode yet"}`))
	}))
	defer srv.Close()
	getcaptchaURL = srv.URL

	status, body, err := PostGetCaptcha(t.Context(), map[string]string{
		"sitekey": "sk", "host": "build.nvidia.com", "n": "solved-n",
	})
	if err != nil {
		t.Fatalf("PostGetCaptcha: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200 (form fallback should win)", status)
	}
	if !strings.Contains(string(body), "no passcode yet") {
		t.Errorf("body = %q, want the form attempt's response", body)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(gotReq) != 2 {
		t.Fatalf("server saw %d requests, want 2 (json then form)", len(gotReq))
	}
	if !strings.HasPrefix(gotReq[0], "application/json|") {
		t.Errorf("request 1 content-type = %q, want application/json first", gotReq[0])
	}
	parts := strings.SplitN(gotReq[0], "|", 5)
	if len(parts) != 5 || parts[1] != "https://newassets.hcaptcha.com" || parts[2] != "https://newassets.hcaptcha.com/" {
		t.Errorf("request 1 headers = %q, want Origin/Referer pinned to newassets", gotReq[0])
	}
	// The endpoint is versioned by sitekey path: /getcaptcha/<sitekey>.
	for i, req := range gotReq {
		reqParts := strings.Split(req, "|")
		if got := reqParts[4]; got != "/sk" {
			t.Errorf("request %d path = %q, want /sk (sitekey path segment)", i+1, got)
		}
	}
	if !strings.HasPrefix(gotReq[1], "application/x-www-form-urlencoded|") {
		t.Errorf("request 2 content-type = %q, want form fallback", gotReq[1])
	}
	// JSON body must round-trip the params; form body must too.
	var gotJSON map[string]string
	if err := json.Unmarshal([]byte(gotBody[0]), &gotJSON); err != nil {
		t.Fatalf("json body %q: %v", gotBody[0], err)
	}
	if len(gotJSON) != 3 || gotJSON["sitekey"] != "sk" || gotJSON["n"] != "solved-n" {
		t.Errorf("json params = %v, want the posted map", gotJSON)
	}
	formVals, err := url.ParseQuery(gotBody[1])
	if err != nil {
		t.Fatalf("form body %q: %v", gotBody[1], err)
	}
	if formVals.Get("sitekey") != "sk" || formVals.Get("n") != "solved-n" {
		t.Errorf("form params = %v, want the posted map", formVals)
	}
}

// offlineCaptchaEnv installs the offline overrides the getcaptcha tests use:
// a fake checksiteconfig (jwt + location + key), a fake solver and a fake
// postGetCaptcha. It returns the jwt/key plus a cleanup function the test
// must call to restore the package overrides and drop cached solvers.
func offlineCaptchaEnv(t *testing.T, post func(ctx context.Context, params map[string]string) (int, []byte, error)) (jwt, key string, cleanup func()) {
	t.Helper()
	oldFetch, oldLoad, oldPost, oldOctet := fetchChecksite, loadSolver, postGetCaptcha, postGetCaptchaOctetFn
	cleanup = func() {
		fetchChecksite, loadSolver, postGetCaptcha, postGetCaptchaOctetFn = oldFetch, oldLoad, oldPost, oldOctet
		CloseSolvers()
	}

	const location = "/c/getcaptcha-test-loc"
	jwt = fakeJWT(t, location)
	key = "c0ffee-0000-4000-8000-000000000000"
	fetchChecksite = func(ctx context.Context, sitekey, host string) (string, string, string, error) {
		return jwt, location, key, nil
	}
	loadSolver = func(ctx context.Context, l string) (*hsw.Solver, error) {
		b, err := hsw.Prepare([]byte(fakeV1Body))
		if err != nil {
			return nil, err
		}
		return hsw.New(b)
	}
	postGetCaptcha = post
	return jwt, key, cleanup
}

// TestCaptchaTokenVariantLoop verifies the full offline getcaptcha flow:
// checksiteconfig -> fingerprint -> solve -> ordered parameter variants,
// stopping at the first P1_ passcode. The c=jwt variants fail (no passcode),
// the c=key variant succeeds.
func TestCaptchaTokenVariantLoop(t *testing.T) {
	const tok = "P1_eyJjaGFsbGVuZ2UudG9rZW4ifQ.offline"
	var key string // referenced by the POST fake below; declared before it
	jwt, key, cleanup := offlineCaptchaEnv(t, func(ctx context.Context, params map[string]string) (int, []byte, error) {
		if params["c"] == key {
			return 200, []byte(`{"pass":true,"generated_pass_UUID":"` + tok + `"}`), nil
		}
		return 200, []byte(`{"pass":false,"error":"invalid challenge c"}`), nil
	})
	defer cleanup()

	solve, attempts, err := CaptchaAttempts(context.Background(), "sitekey", "host")
	if err != nil {
		t.Fatalf("CaptchaAttempts: %v", err)
	}
	if solve.JWT != jwt || solve.Key != key || solve.N == "" {
		t.Errorf("solve info jwt=%q key=%q n_len=%d", solve.JWT, solve.Key, len(solve.N))
	}
	// Six base variants (phase-A bare, c=jwt, c=spec, legacy v, motion,
	// location-v) then the c=key one; the loop must stop at the first P1.
	if len(attempts) != 7 {
		t.Fatalf("attempts = %d, want 7 (loop must stop at first P1)", len(attempts))
	}
	last := attempts[len(attempts)-1]
	if last.Token != tok {
		t.Errorf("last attempt token = %q, want %q", last.Token, tok)
	}
	if last.Params["c"] != key {
		t.Errorf("last attempt c = %q, want key %q", last.Params["c"], key)
	}
	for i, a := range attempts {
		if a.Params["sitekey"] != "sitekey" || a.Params["host"] != "host" {
			t.Errorf("attempt %d sitekey/host = %q/%q", i, a.Params["sitekey"], a.Params["host"])
		}
		if i == 0 {
			// phaseA-bare claims a challenge: no n, no c yet.
			if a.Params["n"] != "" || a.Params["c"] != "" {
				t.Errorf("attempt 0 (phaseA-bare) n/c = %q/%q, want empty", a.Params["n"], a.Params["c"])
			}
			continue
		}
		if a.Params["n"] != solve.N {
			t.Errorf("attempt %d n param = %q, want the solved n", i, a.Params["n"])
		}
	}

	token, err := CaptchaToken(context.Background(), "sitekey", "host")
	if err != nil {
		t.Fatalf("CaptchaToken: %v", err)
	}
	if token != tok {
		t.Errorf("CaptchaToken = %q, want %q", token, tok)
	}
}

// TestCaptchaTokenErrorAggregation verifies the no-passcode error path: the
// error is prefixed by stage, carries every variant's status and clips the raw
// response bodies at 800 characters.
func TestCaptchaTokenErrorAggregation(t *testing.T) {
	longBody := strings.Repeat("x", 2000)
	_, _, cleanup := offlineCaptchaEnv(t, func(ctx context.Context, params map[string]string) (int, []byte, error) {
		return http.StatusBadRequest, []byte(longBody), nil
	})
	defer cleanup()

	token, err := CaptchaToken(context.Background(), "sitekey", "host")
	if err == nil {
		t.Fatalf("CaptchaToken = %q, want error", token)
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "hcaptcha: getcaptcha:") {
		t.Errorf("error prefix = %q, want stage prefix", msg[:min(len(msg), 40)])
	}
	if !strings.Contains(msg, "status=400") {
		t.Error("error does not mention variant statuses")
	}
	if !strings.Contains(msg, "(+1200 bytes)") {
		t.Errorf("error body not clipped at 800 bytes: %.120s", msg)
	}
}

// TestCaptchaTokenEncrypted covers the wasm-encrypted submission path: no
// plaintext variant yields a passcode, the octet-stream POST receives the
// msgpack [spec, ext18] wire, and the (echo) decrypted response carries the
// P1_ token.
func TestCaptchaTokenEncrypted(t *testing.T) {
	const tok = "P1_eyJlbmNyeXB0ZWQudG9rZW4ifQ.offline"
	_, _, cleanup := offlineCaptchaEnv(t, func(ctx context.Context, params map[string]string) (int, []byte, error) {
		// The encrypted flow claims via getcaptcha: first call (no n) must
		// return a challenge spec; later plaintext variants fail.
		if params["n"] == "" && params["c"] == "" {
			return 200, []byte(`{"c":{"type":"hsw","req":"` + fakeJWT(t, "/c/getcaptcha-test-loc") + `"}}`), nil
		}
		return 200, []byte(`{"pass":false,"error-codes":["invalid-data"]}`), nil
	})
	defer cleanup()
	oldOctet := postGetCaptchaOctetFn
	defer func() { postGetCaptchaOctetFn = oldOctet }()

	// Fake octet POST: parse the [spec, ext18(cipher)] wire and answer with a
	// msgpack-encoded passcode payload.
	postGetCaptchaOctetFn = func(ctx context.Context, sitekey string, body []byte) (int, []byte, error) {
		v, rest, err := msgpackDecode(body)
		if err != nil {
			return 0, nil, err
		}
		arr, ok := v.([]any)
		if !ok || len(arr) != 2 || len(rest) != 0 {
			return 0, nil, errors.New("wire is not [spec, cipher]")
		}
		cSpec, ok := arr[0].(string)
		if !ok || !strings.Contains(cSpec, `"type":"hsw"`) {
			return 0, nil, errors.New("wire spec is not the hsw challenge spec")
		}
		cipher, ok := arr[1].([]byte)
		if !ok || len(cipher) == 0 {
			return 0, nil, errors.New("wire cipher missing")
		}
		resp := msgpackEncodeMapString(map[string]string{"pass": "true"})
		// append the token as a sibling key via a tiny hand-built map is
		// overkill; instead encode a fresh map with both entries:
		return 200, appendMsgpackKV(resp, "generated_pass_UUID", tok), nil
	}

	token, err := CaptchaToken(context.Background(), "sitekey", "host")
	if err != nil {
		t.Fatalf("CaptchaToken (encrypted): %v", err)
	}
	if token != tok {
		t.Errorf("CaptchaToken = %q, want %q", token, tok)
	}
}

// appendMsgpackKV appends map16-style key/value entries to a fixmap of n<=3
// keys by re-encoding; small helper for the encrypted-response fake.
func appendMsgpackKV(orig []byte, key, val string) []byte {
	m := map[string]string{}
	if v, _, err := msgpackDecode(orig); err == nil {
		if mm, ok := v.(map[string]any); ok {
			for k, vv := range mm {
				if s, ok := vv.(string); ok {
					m[k] = s
				}
			}
		}
	}
	m[key] = val
	return msgpackEncodeMapString(m)
}

// TestCaptchaAttemptsStageErrors checks the layered error prefixes: a solver
// failure must surface as "solve" and stop before any getcaptcha round trip.
func TestCaptchaAttemptsStageErrors(t *testing.T) {
	oldFetch, oldLoad, oldPost := fetchChecksite, loadSolver, postGetCaptcha
	defer func() { fetchChecksite, loadSolver, postGetCaptcha = oldFetch, oldLoad, oldPost }()
	defer CloseSolvers()

	fetchChecksite = func(ctx context.Context, sitekey, host string) (string, string, string, error) {
		return "", "", "", errors.New("offline checksite")
	}
	loadSolver = func(ctx context.Context, l string) (*hsw.Solver, error) { return nil, errors.New("unused") }
	postGetCaptcha = func(ctx context.Context, params map[string]string) (int, []byte, error) {
		return 0, nil, errors.New("must not be called")
	}

	_, _, err := CaptchaAttempts(context.Background(), "sitekey", "host")
	if err == nil || !strings.Contains(err.Error(), "fetch challenge") {
		t.Fatalf("err = %v, want stage prefix \"fetch challenge\"", err)
	}
}

// TestLocationVersion covers version derivation from hsw bundle locations.
func TestLocationVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/c/8af55315015e17fa8c964be34ae93d53b7f9c36e", "8af5531"},
		{"/c/8af5531", "8af5531"},
		{"8af55315015e17fa", "8af5531"},
		{"/c/nothex", getCaptchaVersion},
		{"", getCaptchaVersion},
	}
	for _, c := range cases {
		if got := locationVersion(c.in); got != c.want {
			t.Errorf("locationVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// writeTestBody writes b from an httptest handler; a write failure cannot
// fail the test directly, so it is reported and the handler continues.
func writeTestBody(t *testing.T, w http.ResponseWriter, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Errorf("write test response: %v", err)
	}
}
