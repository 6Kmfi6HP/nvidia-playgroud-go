package hcaptcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nvidia-playgroud-go/internal/hsw"
)

func pinVersion(t *testing.T, v string) {
	t.Helper()
	oldV, oldT := versionValue, versionFetched
	versionValue, versionFetched = v, time.Now()
	t.Cleanup(func() { versionValue, versionFetched = oldV, oldT })
}

// mintEnv stubs the minter seams: one challenge, a fake hsw, and a getcaptcha
// POST the test supplies. n from the fake solver ends in ":15" when the
// second argument is an object ("[object Object]"), which is how the test
// tells the options-object call from a prebuilt fingerprint string.
func mintEnv(t *testing.T, spec string, post func(ctx context.Context, sitekey string, body []byte) (mintPost, error)) (jwt string, cleanup func()) {
	t.Helper()
	pinVersion(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	oldFetch, oldLoad, oldPost := fetchMintChallenge, loadMintBundle, postMint
	cleanup = func() {
		fetchMintChallenge, loadMintBundle, postMint = oldFetch, oldLoad, oldPost
		CloseSolvers()
	}
	jwt = fakeJWT(t, "/c/mint-test-loc")
	if spec == "" {
		spec = `{"type":"hsw","req":"` + jwt + `","extra":1}`
	}
	fetchMintChallenge = func(ctx context.Context, sitekey, host string) (mintChallenge, error) {
		if err := ctx.Err(); err != nil {
			return mintChallenge{}, err
		}
		return mintChallenge{
			SpecJSON: spec,
			JWT:      jwt,
			Location: "/c/mint-test-loc",
			Name:     "hsw",
		}, nil
	}
	loadMintBundle = func(ctx context.Context, assetURL, referer, sri string) (*hsw.Solver, error) {
		b, err := hsw.Prepare([]byte(fakeV1Body))
		if err != nil {
			return nil, err
		}
		return hsw.New(b)
	}
	postMint = post
	return jwt, cleanup
}

func passBody(tok string) []byte {
	return msgpackEncodeMapString(map[string]string{"generated_pass_UUID": tok})
}

func TestMintSubmitsRawSpecAndObjectSolve(t *testing.T) {
	const tok = "P1_eyJtaW50ZXIifQ.offline"
	var specGot string
	var payload map[string]any
	jwt, cleanup := mintEnv(t, "", func(ctx context.Context, sitekey string, body []byte) (mintPost, error) {
		v, rest, err := msgpackDecode(body)
		if err != nil || len(rest) != 0 {
			t.Fatalf("wire decode: %v rest=%d", err, len(rest))
		}
		arr, ok := v.([]any)
		if !ok || len(arr) != 2 {
			t.Fatalf("wire = %T %v, want [spec, cipher]", v, v)
		}
		specGot, _ = arr[0].(string)
		cipher, ok := arr[1].([]byte)
		if !ok {
			t.Fatalf("cipher = %T", arr[1])
		}
		solver, err := openSolver(ctx, "/c/mint-test-loc", "", "", "")
		if err != nil {
			t.Fatalf("solver: %v", err)
		}
		plain, err := solver.Crypto(ctx, 0, cipher)
		if err != nil {
			t.Fatalf("decrypt payload: %v", err)
		}
		m, rest, err := msgpackDecode(plain)
		if err != nil || len(rest) != 0 {
			t.Fatalf("payload decode: %v rest=%d", err, len(rest))
		}
		payload, _ = m.(map[string]any)
		return mintPost{Status: 200, CType: "application/octet-stream", Body: passBody(tok)}, nil
	})
	defer cleanup()

	solve, attempts, err := CaptchaAttempts(context.Background(), "sitekey", "build.nvidia.com")
	if err != nil {
		t.Fatalf("CaptchaAttempts: %v", err)
	}
	if len(attempts) != 1 || attempts[0].Token != tok {
		t.Fatalf("attempts = %+v, want one token %s", attempts, tok)
	}
	wantSpec := `{"type":"hsw","req":"` + jwt + `","extra":1}`
	if specGot != wantSpec {
		t.Fatalf("wire spec = %s, want raw c %s", specGot, wantSpec)
	}
	if solve.N == "" || !strings.HasSuffix(solve.N, ":15") {
		t.Fatalf("n = %q, want object-call suffix :15", solve.N)
	}
	for k, w := range map[string]string{
		"v": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sitekey": "sitekey",
		"host": "build.nvidia.com", "hl": "en", "motionData": "{}", "n": solve.N,
	} {
		if got, _ := payload[k].(string); got != w {
			t.Errorf("payload %s = %q, want %q", k, got, w)
		}
	}
	if got, ok := payload["e"]; !ok || got != nil {
		t.Errorf("payload e = %#v present=%v, want null", got, ok)
	}
}

func TestMintRejectsNonOctetEvenWithPasscode(t *testing.T) {
	_, cleanup := mintEnv(t, "", func(ctx context.Context, sitekey string, body []byte) (mintPost, error) {
		return mintPost{
			Status: 400,
			CType:  "application/json",
			Body:   []byte(`{"generated_pass_UUID":"P1_eyJub3Rhd2lyZSJ9.offline"}`),
		}, nil
	})
	defer cleanup()
	tok, err := CaptchaToken(context.Background(), "sitekey", "host")
	if err == nil || tok != "" {
		t.Fatalf("CaptchaToken = %q err=%v, want rejection", tok, err)
	}
	if !strings.Contains(err.Error(), "getcaptcha rejected") {
		t.Fatalf("err = %v, want content-type rejection", err)
	}
}

func TestMintRotatesConnectionsOnFailure(t *testing.T) {
	oldReset := resetConns
	defer func() { resetConns = oldReset }()
	rotated := 0
	resetConns = func() { rotated++ }

	_, cleanup := mintEnv(t, "", func(ctx context.Context, sitekey string, body []byte) (mintPost, error) {
		return mintPost{Status: 400, CType: "application/json", Body: []byte(`{"pass":false}`)}, nil
	})
	defer cleanup()
	if _, err := CaptchaToken(context.Background(), "sitekey", "host"); err == nil {
		t.Fatal("want failure")
	}
	if rotated != 1 {
		t.Fatalf("rotations after failure = %d, want 1", rotated)
	}

	rotated = 0
	postMint = func(ctx context.Context, sitekey string, body []byte) (mintPost, error) {
		return mintPost{Status: 200, CType: "application/octet-stream", Body: passBody("P1_eyJ3YXJtLmNvbm4ifQ.offline")}, nil
	}
	tok, err := CaptchaToken(context.Background(), "sitekey", "host")
	if err != nil || tok == "" {
		t.Fatalf("success path: token=%q err=%v", tok, err)
	}
	if rotated != 0 {
		t.Fatalf("rotations after success = %d, want 0", rotated)
	}

	rotated = 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CaptchaToken(ctx, "sitekey", "host"); err == nil {
		t.Fatal("canceled context should fail")
	}
	if rotated != 0 {
		t.Fatalf("rotations after cancel = %d, want 0", rotated)
	}
}

func TestFetchMintChallengePreservesSpec(t *testing.T) {
	pinVersion(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Query().Get("hl") != "" {
			t.Errorf("hl = %q, want absent", r.URL.Query().Get("hl"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"c":{"type":"hsw","req":"a.b.c","extra":1},"l":"/c/x"}`))
	}))
	defer srv.Close()
	old := checksiteBase
	checksiteBase = srv.URL
	defer func() { checksiteBase = old }()

	ch, err := fetchMintChallengeLive(context.Background(), "sk", "build.nvidia.com")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if ch.SpecJSON != `{"type":"hsw","req":"a.b.c","extra":1}` {
		t.Fatalf("spec = %s", ch.SpecJSON)
	}
	if ch.Location != "/c/x" {
		t.Fatalf("location = %q", ch.Location)
	}
	if !strings.Contains(gotQuery, "sc=1") || strings.Contains(gotQuery, "hl=") {
		t.Fatalf("query = %s", gotQuery)
	}
}

func TestRequireAssetVersionFailsClosed(t *testing.T) {
	oldV, oldT := versionValue, versionFetched
	versionValue, versionFetched = "", time.Time{}
	defer func() { versionValue, versionFetched = oldV, oldT }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	oldURL := assetAPIVersionURL
	assetAPIVersionURL = srv.URL
	defer func() { assetAPIVersionURL = oldURL }()

	if _, err := RequireAssetVersion(context.Background()); err == nil {
		t.Fatal("want error when api.js scrape fails")
	}
}

func TestSolverCacheReusesSolver(t *testing.T) {
	pinVersion(t, "cccccccccccccccccccccccccccccccccccccccc")
	oldFetch, oldLoad, oldPost := fetchMintChallenge, loadMintBundle, postMint
	defer func() {
		fetchMintChallenge, loadMintBundle, postMint = oldFetch, oldLoad, oldPost
		CloseSolvers()
	}()
	const loc = "/c/282d0ff"
	jwt := fakeJWT(t, loc)
	fetchMintChallenge = func(ctx context.Context, sitekey, host string) (mintChallenge, error) {
		return mintChallenge{SpecJSON: `{"type":"hsw","req":"` + jwt + `"}`, JWT: jwt, Location: loc, Name: "hsw"}, nil
	}
	loads := 0
	loadMintBundle = func(ctx context.Context, assetURL, referer, sri string) (*hsw.Solver, error) {
		loads++
		b, err := hsw.Prepare([]byte(fakeV1Body))
		if err != nil {
			return nil, err
		}
		return hsw.New(b)
	}
	const tok = "P1_offline.cache-test"
	postMint = func(ctx context.Context, sitekey string, body []byte) (mintPost, error) {
		return mintPost{Status: 200, CType: "application/octet-stream", Body: passBody(tok)}, nil
	}
	ctx := context.Background()
	if got, err := CaptchaToken(ctx, "sitekey", "host"); err != nil || got != tok {
		t.Fatalf("first = %q err=%v", got, err)
	}
	if loads != 1 {
		t.Fatalf("loads after first = %d, want 1", loads)
	}
	if got, err := CaptchaToken(ctx, "sitekey", "host"); err != nil || got != tok {
		t.Fatalf("second = %q err=%v", got, err)
	}
	if loads != 1 {
		t.Fatalf("loads after second = %d, want 1", loads)
	}
}

func TestParseMintChallengeCompactsWhitespace(t *testing.T) {
	ch, err := parseMintChallenge([]byte("{\n  \"c\": { \"type\" : \"hsw\", \"req\" : \"a.b.c\" }, \"l\": \"/c/z\"\n}"))
	if err != nil {
		t.Fatal(err)
	}
	if ch.SpecJSON != `{"type":"hsw","req":"a.b.c"}` {
		t.Fatalf("spec = %s", ch.SpecJSON)
	}
	var probe map[string]any
	if err := json.Unmarshal([]byte(ch.SpecJSON), &probe); err != nil {
		t.Fatal(err)
	}
}
