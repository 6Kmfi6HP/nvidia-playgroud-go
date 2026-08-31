// getcaptcha: submitting the solved hsw proof-of-work and extracting the
// P1_ passcode.
//
// The pipeline starts where SolveN ends: checksiteconfig hands a PoW JWT, the
// fingerprint + hsw solve produce n, and getcaptcha turns (n, c) into the
// passcode that build.nvidia.com accepts as nv-captcha-token. hCaptcha does
// not document the getcaptcha field layout. When checksiteconfig reports
// features.enc_get_req, submissions must be wasm-encrypted: the hsw bundle's
// window.hsw(1|0, bytes) modes encrypt/decrypt with a key embedded in its
// WASM, and the wire body is msgpack([<c spec JSON>, ext18(cipher)]) sent as
// application/octet-stream. This file implements plaintext variants (raw
// diagnostics) plus the encrypted submission through the same V8 runner.
package hcaptcha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"glm52-nvidia/internal/hcaptchapow"
	"glm52-nvidia/internal/hsw"
)

const (
	// getcaptchaEndpoint is the hCaptcha endpoint that issues challenges and,
	// given a solved challenge, a passcode.
	getcaptchaEndpoint = "https://api.hcaptcha.com/getcaptcha"

	// getCaptchaVersion is the current hCaptcha challenge-frontend build id:
	// the widget's own getcaptcha requests carry "v" set to the asset build
	// hash (observed as fb397a861c3c93968ee7c496f82ce990e67c959e in
	// hcaptcha_challenge.html getTaskData). Older widget builds sent shorter
	// ids like "540c361"; the variant loop covers both.
	getCaptchaVersion = "fb397a861c3c93968ee7c496f82ce990e67c959e"

	// legacyCaptchaVersion is an older widget build id kept as a compatibility
	// probe: some endpoint generations tie validation to the client build.
	legacyCaptchaVersion = "540c361"

	// getCaptchaBodyLimit caps getcaptcha response bodies.
	getCaptchaBodyLimit = 1 << 20

	// getCaptchaErrorClip is how much of a getcaptcha response body goes into
	// error messages and per-variant diagnostics.
	getCaptchaErrorClip = 800
)

// getCaptchaUA matches the browser headers hCaptcha's asset frontend sends.
const getCaptchaUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// getcaptchaURL is the getcaptcha endpoint; overridable in tests.
var getcaptchaURL = getcaptchaEndpoint

// gcClient is the shared HTTP client for checksiteconfig and getcaptcha calls.
var gcClient = &http.Client{Timeout: 60 * time.Second}

// SetHTTPClient replaces the client used for checksiteconfig and getcaptcha
// calls. cmd/serve uses it to route pure-Go PoW solving through the upstream
// proxy. Must be called before solving starts.
func SetHTTPClient(c *http.Client) { gcClient = c }

// reP1Token matches an hCaptcha passcode anywhere in raw text. Tokens are
// long opaque strings starting with "P1_" (base64url payloads with ".").
var reP1Token = regexp.MustCompile(`P1_[A-Za-z0-9._~-]{20,}`)

// SolveInfo describes the solved challenge that getcaptcha variants are built
// from: the challenge JWT and hsw bundle location (as in SolveN), plus the
// checksiteconfig challenge key and the solved n.
type SolveInfo struct {
	JWT         string
	Location    string
	Key         string // checksiteconfig c.key, "" on legacy responses
	Fingerprint string // base64 fingerprint
	N           string // solved proof-of-work
	Elapsed     time.Duration
}

// CaptchaAttempt records one getcaptcha parameter-variant attempt: the params
// that were posted, the effective HTTP response and any P1_ passcode found in
// it.
type CaptchaAttempt struct {
	Name    string            // diagnostic label
	Params  map[string]string // params posted (copy)
	Status  int               // HTTP status; 0 when the transport failed
	Body    []byte            // raw response body
	Err     error             // transport-level failure of the effective attempt
	Elapsed time.Duration     // wall time of the attempt
	Token   string            // P1_ passcode found in Body, "" if none
}

// Summary renders one attempt for diagnostics: name, HTTP status, transport
// error and the raw response body clipped to 800 characters.
func (a *CaptchaAttempt) Summary() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "variant %s: status=%d elapsed=%s", a.Name, a.Status, a.Elapsed.Round(time.Millisecond))
	if a.Err != nil {
		fmt.Fprintf(&sb, " err=%v", a.Err)
	}
	fmt.Fprintf(&sb, " body=%s", clipBytes(a.Body))
	return sb.String()
}

// FindP1Token scans a getcaptcha response body for an hCaptcha passcode.
// Passcodes are opaque strings starting with "P1_"; the JSON field that
// carries them has varied (generated_pass_UUID, captcha_token, pass, ...), so
// the whole body is walked for P1_ string values first and then matched as
// raw text. Returns "" when no passcode is present.
func FindP1Token(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err == nil {
		if tok := walkToken(doc); tok != "" {
			return tok
		}
	}
	return reP1Token.FindString(string(body))
}

// walkToken recursively finds the first P1_ string value in a decoded JSON
// document.
func walkToken(v any) string {
	switch t := v.(type) {
	case string:
		if strings.HasPrefix(t, "P1_") && len(t) >= 20 {
			return t
		}
	case map[string]any:
		for _, e := range t {
			if s := walkToken(e); s != "" {
				return s
			}
		}
	case []any:
		for _, e := range t {
			if s := walkToken(e); s != "" {
				return s
			}
		}
	}
	return ""
}

// gcEncoding selects the request body encoding for a getcaptcha attempt.
type gcEncoding int

const (
	gcEncodingJSON gcEncoding = iota
	gcEncodingForm
)

func (e gcEncoding) String() string {
	if e == gcEncodingForm {
		return "x-www-form-urlencoded"
	}
	return "application/json"
}

// PostGetCaptcha POSTs params to the hCaptcha getcaptcha endpoint with
// browser headers (UA, Origin and Referer pinned to the hCaptcha assets host).
// The endpoint is versioned by sitekey path: the current frontend calls
// api.hcaptcha.com/getcaptcha/<sitekey>, so the "sitekey" param is appended
// to the URL (a bare sitekey-less URL is used when the param is absent).
//
// It tries a JSON body (Content-Type application/json) first; when that
// attempt fails at the transport level or the endpoint answers with a non-2xx
// status, it retries with an x-www-form-urlencoded body, the encoding older
// hCaptcha clients used.
//
// The returned status/body belong to the last attempt performed. err is
// non-nil only when every attempt failed before producing a full HTTP
// response, so callers can treat status/body as the server's raw answer even
// for non-2xx codes (the usual diagnosis path).
func PostGetCaptcha(ctx context.Context, params map[string]string) (status int, body []byte, err error) {
	status, body, err = postGetCaptchaOnce(ctx, params, gcEncodingJSON)
	if err == nil && status >= 200 && status < 300 {
		return status, body, nil
	}
	var jsonSummary string
	if err != nil {
		jsonSummary = err.Error()
	} else {
		jsonSummary = fmt.Sprintf("status=%d body=%s", status, clipBytes(body))
	}
	status, body, err = postGetCaptchaOnce(ctx, params, gcEncodingForm)
	if err != nil {
		return 0, nil, fmt.Errorf("hcaptcha: getcaptcha: json (%s); form: %w", jsonSummary, err)
	}
	return status, body, nil
}

// postGetCaptchaOnce posts params with one encoding and returns the complete
// HTTP response. err is non-nil only when no full HTTP response was received.
func postGetCaptchaOnce(ctx context.Context, params map[string]string, enc gcEncoding) (status int, raw []byte, err error) {
	var body io.Reader
	contentType := ""
	switch enc {
	case gcEncodingJSON:
		b, err := json.Marshal(params)
		if err != nil {
			return 0, nil, fmt.Errorf("hcaptcha: getcaptcha: marshal params: %w", err)
		}
		body = bytes.NewReader(b)
		contentType = "application/json"
	default:
		form := url.Values{}
		for k, v := range params {
			form.Set(k, v)
		}
		body = strings.NewReader(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	}
	return postGetCaptchaBody(ctx, params["sitekey"], body, contentType, enc.String())
}

// postGetCaptchaOctet posts a prebuilt binary body (the encrypted msgpack
// wire) as application/octet-stream, exactly like the widget's encrypted
// submissions.
func postGetCaptchaOctet(ctx context.Context, sitekey string, body []byte) (status int, raw []byte, err error) {
	return postGetCaptchaBody(ctx, sitekey, bytes.NewReader(body), "application/octet-stream", "octet-stream")
}

// postGetCaptchaBody performs one POST against /getcaptcha/<sitekey> with the
// given body and content type, pinning the browser headers the widget sends.
// err is non-nil only when no full HTTP response was received.
func postGetCaptchaBody(ctx context.Context, sitekey string, body io.Reader, contentType, label string) (status int, respBody []byte, err error) {
	endpoint := getcaptchaURL
	if sitekey != "" {
		endpoint = strings.TrimSuffix(getcaptchaURL, "/") + "/" + url.PathEscape(sitekey)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return 0, nil, fmt.Errorf("hcaptcha: getcaptcha: build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json, application/octet-stream")
	req.Header.Set("User-Agent", getCaptchaUA)
	req.Header.Set("Origin", "https://newassets.hcaptcha.com")
	req.Header.Set("Referer", "https://newassets.hcaptcha.com/")

	resp, err := gcClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("hcaptcha: getcaptcha (%s): %w", label, err)
	}
	defer hsw.CloseBody(resp.Body)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, getCaptchaBodyLimit))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("hcaptcha: getcaptcha (%s): read body: %w", label, err)
	}
	return resp.StatusCode, raw, nil
}

// fetchChecksite fetches checksiteconfig and returns the challenge jwt, the
// hsw bundle location, the challenge key and whether the site declares
// features.enc_get_req (encrypted-only getcaptcha). Overridable in tests.
var fetchChecksite = fetchChecksiteLive

// fetchChecksiteLive mirrors hsw.FetchChallenge but also surfaces the
// checksiteconfig c.key: modern getcaptcha endpoints expect that key in the
// "c" parameter (legacy responses put the JWT itself in key, detected by the
// "." of a JWT payload). It also reports features.enc_get_req so the caller
// can route straight to the encrypted submission when the site demands it.
func fetchChecksiteLive(ctx context.Context, sitekey, host string) (jwt, location, key string, encGetReq bool, err error) {
	u := fmt.Sprintf("%s?host=%s&sitekey=%s&sc=1&swa=0&spst=0&hl=en",
		hsw.ChecksiteBase, url.QueryEscape(host), url.QueryEscape(sitekey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return "", "", "", false, fmt.Errorf("checksiteconfig: %w", err)
	}
	req.Header.Set("User-Agent", getCaptchaUA)
	resp, err := gcClient.Do(req)
	if err != nil {
		return "", "", "", false, fmt.Errorf("checksiteconfig: %w", err)
	}
	defer hsw.CloseBody(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", "", false, fmt.Errorf("checksiteconfig: HTTP %d", resp.StatusCode)
	}
	var out hsw.ChecksiteResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, getCaptchaBodyLimit)).Decode(&out); err != nil {
		return "", "", "", false, fmt.Errorf("checksiteconfig decode: %w", err)
	}
	jwt = out.C.Req
	if jwt == "" {
		jwt = out.C.JWT
	}
	key = out.C.Key
	if jwt == "" && strings.Contains(key, ".") {
		jwt, key = key, "" // legacy body where c.key carried the jwt itself
	}
	if jwt == "" {
		return "", "", "", false, fmt.Errorf("checksiteconfig: no challenge jwt in response")
	}
	location = out.L
	if location == "" {
		location, err = hsw.LocationFromJWT(jwt)
		if err != nil {
			return "", "", "", false, fmt.Errorf("checksiteconfig: %w", err)
		}
	}
	return jwt, location, key, out.Features.EncGetReq, nil
}

// postGetCaptcha is the per-attempt POST indirection (overridable in tests).
var postGetCaptcha = PostGetCaptcha

// postGetCaptchaOctetFn is the encrypted octet-stream POST indirection
// (overridable in tests).
var postGetCaptchaOctetFn = postGetCaptchaOctet

// claimResult carries one phase-A getcaptcha challenge claim (no n).
type claimResult struct {
	status int
	body   []byte
	err    error
}

// CaptchaAttempts solves the hCaptcha challenge for sitekey/host and submits
// it to getcaptcha, returning the raw per-attempt results.
//
// Both routes share a speculative phase-A claim fired at t=0, concurrent with
// checksiteconfig: the claim POST only carries static params (v, sitekey,
// host, hl), so it is safe to start before the site's feature set is known
// and has no side effects when discarded.
//
//   - features.enc_get_req (encrypted-only site): skip the checksiteconfig
//     challenge solve and the plaintext variants entirely and submit the
//     speculatively claimed challenge over the wasm-encrypted wire.
//   - otherwise: solve the checksiteconfig challenge and try the plaintext
//     parameter variants in order, stopping at the first P1_ passcode, then
//     fall back to a freshly claimed encrypted submission. The speculative
//     claim is discarded on this route: by the time the variant loop
//     finishes, its challenge timeout (~1s) has usually expired.
//
// Errors are prefixed with the failing stage.
func CaptchaAttempts(ctx context.Context, sitekey, host string) (solve SolveInfo, attempts []CaptchaAttempt, err error) {
	start := time.Now()

	// Speculative phase-A claim, concurrent with checksiteconfig.
	claimCh := make(chan claimResult, 1)
	go func() {
		status, body, cerr := postGetCaptcha(ctx, map[string]string{
			"v":       getCaptchaVersion,
			"sitekey": sitekey,
			"host":    host,
			"hl":      "en",
		})
		claimCh <- claimResult{status: status, body: body, err: cerr}
	}()

	jwt, location, key, encGetReq, err := fetchChecksite(ctx, sitekey, host)
	if err != nil {
		<-claimCh // join the speculative claim before returning
		return SolveInfo{}, nil, fmt.Errorf("hcaptcha: getcaptcha: fetch challenge: %w", err)
	}

	if encGetReq {
		// Encrypted-only fast path: adopt the speculative claim (or claim
		// fresh if it failed) and skip the plaintext variants.
		claim := <-claimCh
		var pclaim *claimResult
		if claim.err == nil {
			pclaim = &claim
		}
		at, info := runEncryptedAttempt(ctx, sitekey, host, pclaim)
		info.Elapsed = time.Since(start)
		return info, []CaptchaAttempt{at}, nil
	}

	// Legacy route: discard the speculative claim and solve the
	// checksiteconfig challenge for the plaintext variants.
	<-claimCh

	pow, err := hcaptchapow.ParsePow(jwt)
	if err != nil {
		return SolveInfo{JWT: jwt, Location: location, Key: key}, nil,
			fmt.Errorf("hcaptcha: getcaptcha: parse pow: %w", err)
	}
	fpB64, err := BuildFingerprint(pow)
	if err != nil {
		return SolveInfo{JWT: jwt, Location: location, Key: key}, nil,
			fmt.Errorf("hcaptcha: getcaptcha: build fingerprint: %w", err)
	}
	solver, err := solverFor(ctx, location)
	if err != nil {
		return SolveInfo{JWT: jwt, Location: location, Key: key, Fingerprint: fpB64}, nil,
			fmt.Errorf("hcaptcha: getcaptcha: load solver: %w", err)
	}
	n, err := solver.SolveN(ctx, jwt, fpB64)
	if err != nil {
		return SolveInfo{JWT: jwt, Location: location, Key: key, Fingerprint: fpB64}, nil,
			fmt.Errorf("hcaptcha: getcaptcha: solve: %w", err)
	}
	solve = SolveInfo{
		JWT: jwt, Location: location, Key: key,
		Fingerprint: fpB64, N: n, Elapsed: time.Since(start),
	}

	for i, v := range getCaptchaVariants(sitekey, host, &solve) {
		if ctx.Err() != nil {
			return solve, attempts, fmt.Errorf("hcaptcha: getcaptcha: context done: %w", ctx.Err())
		}
		t0 := time.Now()
		status, body, perr := postGetCaptcha(ctx, v.params)
		at := CaptchaAttempt{
			Name:    fmt.Sprintf("%d-%s", i+1, v.name),
			Params:  v.params,
			Status:  status,
			Body:    body,
			Err:     perr,
			Elapsed: time.Since(t0),
			Token:   FindP1Token(body),
		}
		attempts = append(attempts, at)
		if at.Token != "" {
			return solve, attempts, nil
		}
	}

	// Encrypted fallback on a fresh claim (the speculative one was discarded
	// above). When features.enc_get_req is set the widget claims a challenge
	// through getcaptcha itself, solves it, wraps the params (minus c) with
	// the hsw WASM (mode 1) and submits msgpack [c-spec, ext18(cipher)] as
	// octet-stream; the answer arrives wasm-encrypted (mode 0) or as
	// plaintext JSON on failure.
	at, _ := runEncryptedAttempt(ctx, sitekey, host, nil)
	attempts = append(attempts, at)
	return solve, attempts, nil
}

// runEncryptedAttempt performs the widget-faithful encrypted getcaptcha
// submission: phase-A claim via getcaptcha (no n), solve the claimed jwt,
// encrypt the params and submit the [spec, ext18(cipher)] wire.
//
// claim, when non-nil, is a pre-fetched phase-A claim (the speculative one
// fired at t=0); when nil a fresh claim is POSTed. The solver is derived from
// the claimed challenge's own bundle location, so this path is independent of
// the checksiteconfig challenge. The returned SolveInfo describes the claimed
// challenge (JWT/location/fingerprint/n) so callers can surface its decode
// timing and difficulty.
func runEncryptedAttempt(ctx context.Context, sitekey, host string, claim *claimResult) (at CaptchaAttempt, info SolveInfo) {
	params := map[string]string{
		"v":       getCaptchaVersion,
		"sitekey": sitekey,
		"host":    host,
		"hl":      "en",
	}
	at = CaptchaAttempt{Name: "encrypted-claim", Params: params}
	t0 := time.Now()
	defer func() { at.Elapsed = time.Since(t0) }()

	// Phase A: claim a challenge from getcaptcha (n absent), like the widget.
	var status int
	var claimBody []byte
	var err error
	if claim != nil {
		status, claimBody, err = claim.status, claim.body, claim.err
	} else {
		status, claimBody, err = postGetCaptcha(ctx, params)
	}
	at.Status, at.Body = status, claimBody
	if err != nil {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: claim: %w", err)
		return
	}
	spec, jwt, perr := specFromClaim(claimBody)
	if perr != nil {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: claim: %w", perr)
		return
	}

	// Solve the claimed challenge with the in-process pipeline. The solver is
	// keyed by the claimed JWT's own bundle location.
	location, perr := hsw.LocationFromJWT(jwt)
	if perr != nil {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: claim location: %w", perr)
		return
	}
	solver, perr := solverFor(ctx, location)
	if perr != nil {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: load solver: %w", perr)
		return
	}
	pow, perr := hcaptchapow.ParsePow(jwt)
	if perr != nil {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: parse claimed pow: %w", perr)
		return
	}
	fpB64, perr := BuildFingerprint(pow)
	if perr != nil {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: build claimed fingerprint: %w", perr)
		return
	}
	n, perr := solver.SolveN(ctx, jwt, fpB64)
	if perr != nil {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: solve claimed challenge: %w", perr)
		return
	}
	info = SolveInfo{JWT: jwt, Location: location, Fingerprint: fpB64, N: n}

	sub := map[string]string{"n": n}
	for k, v := range params {
		sub[k] = v
	}
	at.Params = sub
	plain := msgpackEncodeMapString(sub)
	cipher, cerr := solver.Crypto(ctx, 1, plain)
	if cerr != nil {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: encrypt: %w", cerr)
		return
	}
	body := msgpackEncodeWire(spec, cipher)
	status, resp, err := postGetCaptchaOctetFn(ctx, sitekey, body)
	at.Status, at.Body = status, resp
	if err != nil {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: %w", err)
		return
	}
	at.Token = FindP1Token(resp)
	if at.Token != "" || status != http.StatusOK {
		return
	}
	// A 200 answer to an encrypted submission is the wasm-encrypted response;
	// decrypt (mode 0) and msgpack-decode before scanning for a passcode.
	dec, derr := solver.Crypto(ctx, 0, resp)
	if derr != nil {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: decrypt: %w", derr)
		return
	}
	msg, rest, merr := msgpackDecode(dec)
	if merr != nil {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: decode response: %w", merr)
		return
	}
	if len(rest) > 0 {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: decode response: %d trailing bytes", len(rest))
		return
	}
	j, jerr := json.Marshal(msg)
	if jerr != nil {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: marshal decoded response: %w", jerr)
		return
	}
	at.Token = FindP1Token(j)
	if at.Token == "" {
		at.Err = fmt.Errorf("hcaptcha: getcaptcha: encrypted response carries no passcode: %s", clipBytes(j))
	}
	return
}

// specFromClaim extracts the challenge spec from a getcaptcha (or
// checksiteconfig) claim response and returns it as the JSON string the
// submission's c parameter must carry, plus the challenge jwt inside it.
func specFromClaim(body []byte) (spec, jwt string, err error) {
	var doc struct {
		C *struct {
			Type string `json:"type"`
			Req  string `json:"req"`
		} `json:"c"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", "", fmt.Errorf("decode claim: %w", err)
	}
	if doc.C == nil || doc.C.Req == "" {
		return "", "", fmt.Errorf("no challenge in claim: %s", clipBytes(body))
	}
	specRaw, err := json.Marshal(doc.C)
	if err != nil {
		return "", "", fmt.Errorf("encode claim spec: %w", err)
	}
	return string(specRaw), doc.C.Req, nil
}

// gcVariant is one getcaptcha parameter variant.
type gcVariant struct {
	name   string
	params map[string]string
}

// specJSON renders the challenge spec getcaptcha expects in its "c" parameter:
// the widget echoes the challenge state object it claimed (the checksiteconfig
// "c" object {"type":"hsw","req":<jwt>}) as a JSON string.
func specJSON(solve *SolveInfo) string {
	return fmt.Sprintf(`{"type":"hsw","req":%s}`, mustJSONString(solve.JWT))
}

// mustJSONString quotes s as a JSON string value.
func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// getCaptchaVariants builds the ordered getcaptcha parameter variants for a
// solved challenge. The current widget sends {v, sitekey, host, hl, n, c}
// where c is the JSON-stringified challenge spec; variants cover the phase-A
// bare claim, c as raw JWT vs spec JSON, current vs legacy client builds and a
// motionData-carrying submission.
func getCaptchaVariants(sitekey, host string, solve *SolveInfo) []gcVariant {
	base := map[string]string{
		"v":       getCaptchaVersion,
		"sitekey": sitekey,
		"host":    host,
		"hl":      "en",
	}
	sub := gcParams(base, map[string]string{"n": solve.N})
	vs := []gcVariant{
		{name: "phaseA-bare", params: base},
		{name: "build c=jwt", params: gcParams(sub, map[string]string{"c": solve.JWT})},
		{name: "build c=spec", params: gcParams(sub, map[string]string{"c": specJSON(solve)})},
		{name: "legacy v c=spec", params: gcParams(sub, map[string]string{"v": legacyCaptchaVersion, "c": specJSON(solve)})},
		{name: "build c=spec motion", params: gcParams(sub, map[string]string{"c": specJSON(solve), "motionData": minimalMotionData()})},
		{name: "locv c=spec legacy-flags", params: gcParams(sub, map[string]string{"v": locationVersion(solve.Location), "c": specJSON(solve), "sc": "true", "swa": "0", "spst": "0"})},
	}
	if solve.Key != "" {
		vs = append(vs, gcVariant{name: "build c=key", params: gcParams(sub, map[string]string{"c": solve.Key})})
	}
	return vs
}

// gcParams merges maps into a fresh param map.
func gcParams(parts ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, p := range parts {
		for k, v := range p {
			out[k] = v
		}
	}
	return out
}

// minimalMotionData returns a structurally plausible motionData blob. Real
// widgets send the output of their obfuscated motion VM; this static stand-in
// is only there so the server's response with and without the field is
// observable.
func minimalMotionData() string {
	return fmt.Sprintf(`{"v":1,"st":%d,"md":[]}`, time.Now().UnixMilli())
}

// locationVersion derives a plausible hCaptcha client build id from the hsw
// bundle location (e.g. "/c/8af55315..." -> "8af5531"); falls back to the
// reference version when the location has no usable hex id.
func locationVersion(location string) string {
	loc := strings.TrimSuffix(location, "/")
	hash := loc
	if i := strings.LastIndex(hash, "/"); i >= 0 {
		hash = hash[i+1:]
	}
	if len(hash) >= 7 && isHex(hash) {
		return hash[:7]
	}
	return getCaptchaVersion
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

// CaptchaToken solves the hCaptcha challenge for sitekey/host, submits it to
// getcaptcha under several parameter variants and returns the first P1_
// passcode found. When no variant yields a passcode, the error is layered by
// stage and lists every variant's HTTP status plus its raw response body
// (truncated to 800 characters), so protocol drift against hCaptcha can be
// diagnosed from the error alone.
func CaptchaToken(ctx context.Context, sitekey, host string) (string, error) {
	token, _, err := CaptchaTokenDetail(ctx, sitekey, host)
	return token, err
}

// CaptchaTokenDetail is CaptchaToken plus the solved-challenge metadata, so
// callers can surface decode timing and difficulty (parse SolveInfo.JWT with
// hcaptchapow.ParsePow) in their own logs. The SolveInfo is the one produced
// by the solve stage, even when no passcode came back.
func CaptchaTokenDetail(ctx context.Context, sitekey, host string) (string, SolveInfo, error) {
	solve, attempts, err := CaptchaAttempts(ctx, sitekey, host)
	if err != nil {
		return "", solve, err // already prefixed with the failing stage
	}
	for _, a := range attempts {
		if a.Token != "" {
			return a.Token, solve, nil
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "hcaptcha: getcaptcha: no passcode from %d variants (jwt_len=%d location=%q n_len=%d)",
		len(attempts), len(solve.JWT), solve.Location, len(solve.N))
	for _, a := range attempts {
		sb.WriteString("\n  - ")
		sb.WriteString(a.Summary())
	}
	return "", solve, fmt.Errorf("%s", sb.String())
}

// clipBytes renders b as a string, truncated at getCaptchaErrorClip bytes
// with a size note.
func clipBytes(b []byte) string {
	const n = getCaptchaErrorClip
	if len(b) <= n {
		return string(b)
	}
	return fmt.Sprintf("%s…(+%d bytes)", string(b[:n]), len(b)-n)
}
