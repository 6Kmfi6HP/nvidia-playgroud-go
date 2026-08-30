package waftoken

// AWS WAF challenge-token solver: pure Go + embedded V8, no browser and no
// Node.js. Ported from kareeen133/AWS-WAF-Solver (MIT) with the Node
// subprocess replaced by v8go, proxy support kept, and the CLI stripped to
// a library API.
//
// Flow:
//
//	1. GET the protected URL -> HTTP 202 challenge page containing
//	   aws-waf-token script URL + gokuProps.
//	2. Fetch challenge.js (~700KB obfuscated).
//	3. extractCryptoConfig (V8) -> AES-256 key, identifier (e.g. "Zoey"),
//	   challenge type hashes (mp_verify / verify), signal version.
//	4. Parse challenge inputs embedded in the script (b64 challenge JSON,
//	   hmac, region; difficulty from parseInt literals).
//	5. Build browser signals, encrypt with AES-256-GCM.
//	6. Solve the proof-of-work (NetworkBandwidth zeroed buffer, scrypt, or
//	   SHA-256 hashcash depending on challenge type).
//	7. POST the solution to <challenge-base>/<type> -> aws-waf-token.
//
// All requests go through tls-client with a Chrome 131 fingerprint so the
// Akamai/AWS WAF edge does not reject them at TLS/HTTP2 level, and through
// the configured proxy when one is set (see SetProxy).

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// ---- package-level proxy configuration ----

var (
	proxyMu  sync.RWMutex
	proxyURL string
)

// SetProxy configures the proxy used for all solver HTTP traffic. Accepts
// the same URL forms as the gateway -proxy flag (socks5://, socks5h://,
// http:// with optional user:pass). Call once at startup; safe anytime.
func SetProxy(p string) {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	proxyURL = strings.TrimSpace(p)
}

func getProxy() string {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	return proxyURL
}

// ---- transport: tls-client (Chrome 131) + optional proxy ----

var (
	transportMu    sync.RWMutex
	transportCache = map[string]tls_client.HttpClient{}
)

func getClient(proxy string) (tls_client.HttpClient, error) {
	transportMu.RLock()
	c, ok := transportCache[proxy]
	transportMu.RUnlock()
	if ok {
		return c, nil
	}

	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(90),
		tls_client.WithClientProfile(profiles.Chrome_131),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithInsecureSkipVerify(),
	}
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("waftoken: invalid proxy %q: %w", proxy, err)
		}
		u.Scheme = strings.ReplaceAll(u.Scheme, "socks5h", "socks5")
		opts = append(opts, tls_client.WithProxyUrl(u.String()))
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, err
	}
	transportMu.Lock()
	transportCache[proxy] = client
	transportMu.Unlock()
	return client, nil
}

type httpResponse struct {
	status  int
	headers http.Header
	body    []byte
}

func doRequest(ctx context.Context, rawURL, method string, headers map[string]string, body []byte, proxy string) (*httpResponse, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := fhttp.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(headers))
	for k, v := range headers {
		req.Header.Set(k, v)
		keys = append(keys, strings.ToLower(k))
	}
	req.Header[fhttp.HeaderOrderKey] = keys
	req.Header[fhttp.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}

	client, err := getClient(proxy)
	if err != nil {
		return nil, fmt.Errorf("waftoken: tls client: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		client.CloseIdleConnections()
		return nil, err
	}
	defer resp.Body.Close()

	stdHeaders := make(http.Header)
	for k, vs := range resp.Header {
		if k == fhttp.HeaderOrderKey || k == fhttp.PHeaderOrderKey {
			continue
		}
		stdHeaders[k] = vs
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	switch stdHeaders.Get("Content-Encoding") {
	case "gzip":
		if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
			if gr, e := gzip.NewReader(bytes.NewReader(raw)); e == nil {
				if dec, e2 := io.ReadAll(gr); e2 == nil {
					raw = dec
				}
				closeBody(gr)
			}
		}
	case "deflate":
		if dr := flate.NewReader(bytes.NewReader(raw)); dr != nil {
			if dec, e := io.ReadAll(dr); e == nil {
				raw = dec
			}
		}
	case "br":
		if dec, e := io.ReadAll(brotli.NewReader(bytes.NewReader(raw))); e == nil && len(dec) > 0 {
			raw = dec
		}
	}
	return &httpResponse{status: resp.StatusCode, headers: stdHeaders, body: raw}, nil
}

// ---- cookie jar (Akamai ak_bmsc / bm_mi + aws-waf-token) ----

type cookieJar struct {
	mu      sync.Mutex
	cookies map[string]map[string]string // domain -> name -> value
}

func newCookieJar() *cookieJar {
	return &cookieJar{cookies: make(map[string]map[string]string)}
}

func (j *cookieJar) set(domain, name, value string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cookies[domain] == nil {
		j.cookies[domain] = make(map[string]string)
	}
	if value != "" {
		j.cookies[domain][name] = value
	}
}

func (j *cookieJar) get(domain string) string {
	j.mu.Lock()
	defer j.mu.Unlock()
	m := j.cookies[domain]
	if len(m) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "; ")
}

func (j *cookieJar) parseSetCookie(domain string, headers http.Header) {
	for _, sc := range headers.Values("Set-Cookie") {
		nv := strings.SplitN(sc, ";", 2)[0]
		eq := strings.Index(nv, "=")
		if eq <= 0 {
			continue
		}
		j.set(domain, nv[:eq], nv[eq+1:])
	}
}

// ---- session ----

type cryptoConfigFull struct {
	key        []byte
	identifier string
	typeNames  map[string]string
	signalVer  string
}

// challengeInputs carries one challenge: input/hmac/region arrive in the
// telemetry "inputs" JSON (unmarshal), while cType/diff/mem are extracted
// from the challenge script (see extractChallengeInputs).
type challengeInputs struct {
	Input  string `json:"input"`
	Hmac   string `json:"hmac"`
	Region string `json:"region"`
	CType  string
	Diff   int
	Mem    int
}

type telemetryResponse struct {
	Token    string          `json:"token,omitempty"`
	Inputs   json.RawMessage `json:"inputs,omitempty"`
	Response *innerResponse  `json:"response,omitempty"`
}

type innerResponse struct {
	Token              string          `json:"token,omitempty"`
	Inputs             json.RawMessage `json:"inputs,omitempty"`
	AWSWAFSessionStore string          `json:"awswaf_session_storage,omitempty"`
}

type session struct {
	targetURL   string
	domain      string
	proxy       string
	jar         *cookieJar
	userAgent   string
	chromeVer   string
	screenW     int
	screenH     int
	scriptURL   string
	baseURL     string
	sessionStor string
	crypto      *cryptoConfigFull
	token       string
}

func newSession(targetURL, proxy string) *session {
	screens := [][2]int{{1920, 1080}, {2560, 1440}, {1366, 768}, {1536, 864},
		{1440, 900}, {1680, 1050}, {1280, 720}, {1600, 900}}
	scr := screens[mrand.Intn(len(screens))]
	major := []string{"131", "132", "133"}[mrand.Intn(3)]
	ua := fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36", major)
	return &session{
		targetURL: targetURL,
		domain:    extractHost(targetURL),
		proxy:     proxy,
		jar:       newCookieJar(),
		userAgent: ua,
		chromeVer: major,
		screenW:   scr[0],
		screenH:   scr[1],
	}
}

func (s *session) browserHeaders() map[string]string {
	h := map[string]string{
		"Host":                      s.domain,
		"sec-ch-ua":                 fmt.Sprintf(`"Chromium";v=%q, "Google Chrome";v=%q, "Not-A.Brand";v="8"`, s.chromeVer, s.chromeVer),
		"sec-ch-ua-mobile":          "?0",
		"sec-ch-ua-platform":        `"Windows"`,
		"upgrade-insecure-requests": "1",
		"user-agent":                s.userAgent,
		"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		"sec-fetch-site":            "none",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-user":            "?1",
		"sec-fetch-dest":            "document",
		"accept-encoding":           "gzip, deflate, br",
		"accept-language":           "en-US,en;q=0.9",
	}
	if c := s.jar.get(s.domain); c != "" {
		h["Cookie"] = c
	}
	return h
}

func (s *session) challengeHeaders() map[string]string {
	chHost := extractHost(s.baseURL)
	h := map[string]string{
		"Host":               chHost,
		"user-agent":         s.userAgent,
		"accept":             "*/*",
		"accept-encoding":    "gzip, deflate, br",
		"accept-language":    "en-US,en;q=0.9",
		"content-type":       "text/plain;charset=UTF-8",
		"origin":             "https://" + s.domain,
		"referer":            "https://" + s.domain + "/",
		"sec-ch-ua":          fmt.Sprintf(`"Chromium";v=%q, "Google Chrome";v=%q, "Not-A.Brand";v="8"`, s.chromeVer, s.chromeVer),
		"sec-ch-ua-mobile":   "?0",
		"sec-ch-ua-platform": `"Windows"`,
		"sec-fetch-dest":     "empty",
		"sec-fetch-mode":     "cors",
		"sec-fetch-site":     "cross-site",
	}
	return h
}

// Solve runs the full flow and returns the aws-waf-token cookie value.
func (s *session) solve(ctx context.Context) (string, error) {
	// 1. challenge page (202 + gokuProps)
	pageResp, err := doRequest(ctx, s.targetURL, "GET", s.browserHeaders(), nil, s.proxy)
	if err != nil {
		return "", fmt.Errorf("waftoken: fetch page: %w", err)
	}
	s.jar.parseSetCookie(s.domain, pageResp.headers)
	page := string(pageResp.body)

	scriptURL, ok := extractChallengeScriptURL(page)
	if !ok {
		return "", fmt.Errorf("waftoken: no awswaf challenge script in page (status %d, %d bytes)", pageResp.status, len(page))
	}
	s.scriptURL = scriptURL
	s.baseURL = extractChallengeBase(scriptURL)

	// 2. challenge.js
	scriptHeaders := map[string]string{
		"Host":            extractHost(s.scriptURL),
		"user-agent":      s.userAgent,
		"accept":          "*/*",
		"accept-encoding": "gzip, deflate, br",
		"accept-language": "en-US,en;q=0.9",
		"sec-fetch-dest":  "script",
		"sec-fetch-mode":  "no-cors",
		"sec-fetch-site":  "cross-site",
		"referer":         "https://" + s.domain + "/",
	}
	scriptResp, err := doRequest(ctx, s.scriptURL, "GET", scriptHeaders, nil, s.proxy)
	if err != nil {
		return "", fmt.Errorf("waftoken: fetch challenge.js: %w", err)
	}
	if scriptResp.status != 200 {
		return "", fmt.Errorf("waftoken: challenge.js status %d", scriptResp.status)
	}
	script := string(scriptResp.body)

	// 3. crypto config via embedded V8
	cfg, err := extractCryptoConfig(script)
	if err != nil {
		return "", err
	}
	key, err := hex.DecodeString(cfg.Key)
	if err != nil {
		return "", fmt.Errorf("waftoken: bad AES key: %w", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("waftoken: bad AES key: got %d bytes, want 32", len(key))
	}
	s.crypto = &cryptoConfigFull{
		key:        key,
		identifier: cfg.Identifier,
		typeNames:  cfg.TypeNames,
		signalVer:  cfg.SignalVersion,
	}
	if s.crypto.signalVer == "" {
		s.crypto.signalVer = "2.4.0"
	}

	// 4. challenge inputs
	ci := extractChallengeInputs(script)
	if ci == nil {
		return "", fmt.Errorf("waftoken: could not extract challenge inputs")
	}

	// 5-7. solve + post
	resp, err := s.solveAndPost(ctx, ci)
	if err != nil {
		return "", err
	}
	return s.processResponse(ctx, resp, ci)
}

func (s *session) solveAndPost(ctx context.Context, ci *challengeInputs) (*telemetryResponse, error) {
	start := time.Now()
	signals := buildSignals(s)
	arr, checksum, err := encodeSignals(signals, s.crypto)
	if err != nil {
		return nil, fmt.Errorf("waftoken: encode signals: %w", err)
	}
	sigTime := time.Since(start)

	solStart := time.Now()
	solution, err := s.solveChallenge(ctx, ci, checksum)
	if err != nil {
		return nil, fmt.Errorf("waftoken: solve: %w", err)
	}

	metrics := []map[string]interface{}{
		{"name": "ExistingTokenFound", "value": boolInt(s.jar.get(s.domain) != ""), "unit": "Count"},
		{"name": "SignalAcquisitionTime", "value": int(sigTime.Milliseconds()), "unit": "Milliseconds"},
		{"name": "ChallengeExecutionTime", "value": int(time.Since(solStart).Milliseconds()), "unit": "Milliseconds"},
		{"name": "CookieFetchLatency", "value": 0, "unit": "Milliseconds"},
		{"name": "TotalTime", "value": int(time.Since(start).Milliseconds()), "unit": "Milliseconds"},
	}

	payload := map[string]interface{}{
		"challenge": map[string]interface{}{
			"input":  ci.Input,
			"hmac":   ci.Hmac,
			"region": ci.Region,
		},
		"solution":   solution,
		"signals":    arr,
		"checksum":   checksum,
		"client":     "Browser",
		"domain":     s.domain,
		"metrics":    metrics,
		"goku_props": nil,
	}
	if tok := s.jar.get(s.domain); strings.Contains(tok, "aws-waf-token=") {
		payload["existing_token"] = strings.TrimPrefix(strings.Split(tok, ";")[0], "aws-waf-token=")
	}

	typeName := challengeTypeName(s.crypto.typeNames, ci.CType)
	submitURL := s.baseURL + "/" + typeName
	headers := s.challengeHeaders()

	var body []byte
	if typeName == "verify" {
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("waftoken: marshal verify payload: %w", err)
		}
	} else {
		solutionData := solution
		payload["solution"] = nil
		meta, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("waftoken: marshal solution metadata: %w", err)
		}
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		if err := w.WriteField("solution_data", solutionData); err != nil {
			return nil, fmt.Errorf("waftoken: multipart solution_data: %w", err)
		}
		if err := w.WriteField("solution_metadata", string(meta)); err != nil {
			return nil, fmt.Errorf("waftoken: multipart solution_metadata: %w", err)
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("waftoken: close multipart: %w", err)
		}
		body = buf.Bytes()
		headers["content-type"] = w.FormDataContentType()
	}

	resp, err := doRequest(ctx, submitURL, "POST", headers, body, s.proxy)
	if err != nil {
		return nil, fmt.Errorf("waftoken: POST %s: %w", typeName, err)
	}
	if resp.status != 200 {
		return nil, fmt.Errorf("waftoken: POST %s status %d: %.200s", typeName, resp.status, string(resp.body))
	}
	var tel telemetryResponse
	if err := json.Unmarshal(resp.body, &tel); err != nil {
		return nil, fmt.Errorf("waftoken: parse response: %w (%.200s)", err, string(resp.body))
	}
	return &tel, nil
}

func (s *session) processResponse(ctx context.Context, resp *telemetryResponse, inputs *challengeInputs) (string, error) {
	switch {
	case resp.Token != "":
		s.token = resp.Token
		return resp.Token, nil
	case resp.Response != nil && resp.Response.Token != "":
		s.token = resp.Response.Token
		return resp.Response.Token, nil
	case resp.Response != nil && resp.Response.AWSWAFSessionStore != "":
		s.sessionStor = resp.Response.AWSWAFSessionStore
	}

	if (resp.Response != nil && resp.Response.Inputs != nil) || resp.Inputs != nil {
		var ci challengeInputs
		raw := resp.Inputs
		if resp.Response != nil && resp.Response.Inputs != nil {
			raw = resp.Response.Inputs
		}
		if err := json.Unmarshal(raw, &ci); err != nil {
			return "", fmt.Errorf("waftoken: parse new inputs: %w", err)
		}
		if ci.Mem == 0 {
			ci.Mem = inputs.Mem
		}
		retry, err := s.solveAndPost(ctx, &ci)
		if err != nil {
			return "", err
		}
		return s.processResponse(ctx, retry, inputs)
	}
	return "", fmt.Errorf("waftoken: no token and no challenge in response")
}

// Mint solves the AWS WAF challenge for targetURL and returns the
// aws-waf-token cookie value. It reuses the package-level proxy configured
// with SetProxy; pass "" for direct connection (e.g. in tests).
func Mint(ctx context.Context, targetURL string) (string, error) {
	return MintProxy(ctx, targetURL, getProxy())
}

// MintProxy is Mint with an explicit proxy string ("" = direct).
func MintProxy(ctx context.Context, targetURL, proxy string) (string, error) {
	if targetURL == "" {
		return "", fmt.Errorf("waftoken: empty target URL")
	}
	if proxy != "" {
		if _, err := url.Parse(proxy); err != nil {
			return "", fmt.Errorf("waftoken: invalid proxy %q: %w", proxy, err)
		}
	}
	s := newSession(targetURL, proxy)
	return s.solve(ctx)
}

// ---- helpers ----

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func extractHost(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.TrimPrefix(rawURL, "http://")
	return strings.SplitN(rawURL, "/", 2)[0]
}

func extractChallengeScriptURL(html string) (string, bool) {
	re := regexp.MustCompile(`(?:src\s*=\s*['"]|script\.src\s*=\s*['"])(https://[^'"]*\.sdk\.awswaf\.com/[^'"]*challenge\.js[^'"]*)['"]`)
	if m := re.FindStringSubmatch(html); m != nil {
		return m[1], true
	}
	re2 := regexp.MustCompile(`['"]?(https://[^'"]*awswaf\.com[^'"]*challenge[^'"]*\.js)['"]?`)
	if m := re2.FindStringSubmatch(html); m != nil {
		return m[1], true
	}
	return "", false
}

func extractChallengeBase(scriptURL string) string {
	if m := regexp.MustCompile(`^(.+)/challenge.*\.js`).FindStringSubmatch(scriptURL); m != nil {
		return m[1]
	}
	return scriptURL
}

func extractChallengeInputs(script string) *challengeInputs {
	difficultyRe := regexp.MustCompile(`parseInt\(['"](\d+)['"]\).*?parseInt\(['"](\d+)['"]\)`)
	var difficulty, memory int
	if m := difficultyRe.FindStringSubmatch(script); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			difficulty = n
		}
		if n, err := strconv.Atoi(m[2]); err == nil {
			memory = n
		}
	}

	cType := ""
	if m := regexp.MustCompile(`'(ha[0-9a-f]{60,})'`).FindStringSubmatch(script); m != nil {
		cType = m[1]
	}

	input := ""
	if m := regexp.MustCompile(`'(eyJ[A-Za-z0-9+/=]{50,})'`).FindStringSubmatch(script); m != nil {
		input = m[1]
	}

	hmacVal := ""
	if m := regexp.MustCompile(`['"]hmac['"]\]?\s*[=:]\s*['"]([A-Za-z0-9+/=]+)['"]`).FindStringSubmatch(script); m != nil {
		hmacVal = m[1]
	}
	if hmacVal == "" && input != "" {
		if idx := strings.Index(script, input); idx > 0 {
			after := script[idx+len(input):]
			if m := regexp.MustCompile(`='([A-Za-z0-9+/]{30,50}=*)'`).FindStringSubmatch(after[:min(len(after), 500)]); m != nil {
				hmacVal = m[1]
			}
		}
	}

	region := ""
	if input != "" {
		if decoded, err := base64.StdEncoding.DecodeString(input); err == nil {
			var inner struct {
				Region string `json:"region"`
			}
			if json.Unmarshal(decoded, &inner) == nil && inner.Region != "" {
				region = inner.Region
			}
		}
	}
	if region == "" {
		if m := regexp.MustCompile(`['"]region['"]\]?\s*[=:]\s*['"]([a-z0-9-]+)['"]`).FindStringSubmatch(script); m != nil {
			region = m[1]
		}
	}
	if region == "" && input != "" {
		if idx := strings.Index(script, input); idx > 0 {
			after := script[idx+len(input):]
			if m := regexp.MustCompile(`='([a-z]{2}-[a-z]+-\d+)'`).FindStringSubmatch(after[:min(len(after), 500)]); m != nil {
				region = m[1]
			}
		}
	}

	if cType == "" && input == "" {
		return nil
	}
	return &challengeInputs{Input: input, Hmac: hmacVal, Region: region, CType: cType, Diff: difficulty, Mem: memory}
}

func challengeTypeName(typeNames map[string]string, hash string) string {
	if n, ok := typeNames[hash]; ok {
		return n
	}
	switch {
	case strings.HasPrefix(hash, "ha9faaffd"):
		return "mp_verify"
	case strings.HasPrefix(hash, "h72f957df"), strings.HasPrefix(hash, "h7b0c470f"):
		return "verify"
	default:
		return "mp_verify"
	}
}

// closeBody closes c after the body has been read or is being discarded; a
// close failure has no effect on the data already consumed.
func closeBody(c io.Closer) {
	if err := c.Close(); err != nil {
		_ = err
	}
}
