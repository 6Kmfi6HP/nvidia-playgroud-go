// getcaptcha: submitting the solved hsw proof and extracting the passcode.
//
// The production path is the nvidia-playground.mjs minter (see widget.go):
// one checksiteconfig challenge, hsw(jwt, {href, ardata:null}), one encrypted
// getcaptcha submission, and generated_pass_UUID from the decrypted answer.
// Plaintext parameter variants and a second getcaptcha claim are not used.
package hcaptcha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"nvidia-playgroud-go/internal/hsw"
)

const (
	// getcaptchaEndpoint is the hCaptcha endpoint that issues the passcode.
	getcaptchaEndpoint = "https://api.hcaptcha.com/getcaptcha"

	// getCaptchaVersion is the compiled-in frontend build id used only when
	// AssetVersion cannot scrape api.js. The mint path does not use it.
	getCaptchaVersion = "fb397a861c3c93968ee7c496f82ce990e67c959e"

	// getCaptchaBodyLimit caps getcaptcha and checksiteconfig response bodies.
	getCaptchaBodyLimit = 1 << 20

	// getCaptchaErrorClip is how much of a response body goes into error messages.
	getCaptchaErrorClip = 800
)

// widgetUA is the user agent the reference minter (nvidia-playground.mjs)
// sends on every captcha request.
const widgetUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

// getcaptchaURL is the getcaptcha endpoint; overridable in tests.
var getcaptchaURL = getcaptchaEndpoint

// gcClient is the shared HTTP client for api.js, checksiteconfig and getcaptcha.
var gcClient = &http.Client{Timeout: 60 * time.Second}

func init() {
	if jar, err := cookiejar.New(nil); err == nil {
		gcClient.Jar = jar
	}
}

// SetHTTPClient replaces the client used for api.js, checksiteconfig and
// getcaptcha. cmd/serve uses it to route solving through the upstream proxy.
// A nil jar is installed so Set-Cookie is replayed, matching the reference
// minter's per-host cookie jar. Must be called before solving starts.
func SetHTTPClient(c *http.Client) {
	if c != nil && c.Jar == nil {
		if jar, err := cookiejar.New(nil); err == nil {
			c.Jar = jar
		}
	}
	gcClient = c
}

// resetConns is the failure-rotation indirection (overridable in tests).
var resetConns = ResetConnections

// ResetConnections closes every idle captcha-pipeline connection (this
// package's client plus the hsw downloader's), so the next request dials
// fresh. Through a rotating proxy pool a fresh connection carries a fresh
// exit IP: the pool worker's retry ladder calls this after every failed
// extraction to abandon a risk-flagged or poisoned exit instead of hammering
// the same one until its 120s idle timeout recycles it. Successful solves
// keep their connection warm — a working exit is exactly what not to give
// up. No-op without a proxy (the next dial comes from the same local IP).
func ResetConnections() {
	gcClient.CloseIdleConnections()
	hsw.ResetConnections()
}

// SolveInfo describes the challenge the mint submitted.
type SolveInfo struct {
	JWT         string
	Location    string
	Key         string // unused by the minter; kept so callers can print it
	Fingerprint string // unused: hsw collects the fingerprint itself
	N           string // solved proof-of-work
	Elapsed     time.Duration
}

// CaptchaAttempt records the single getcaptcha submission.
type CaptchaAttempt struct {
	Name    string
	Params  map[string]string
	Status  int
	Body    []byte
	Err     error
	Elapsed time.Duration
	Token   string
}

// Summary renders one attempt for diagnostics.
func (a *CaptchaAttempt) Summary() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "attempt %s: status=%d elapsed=%s", a.Name, a.Status, a.Elapsed.Round(time.Millisecond))
	if a.Err != nil {
		fmt.Fprintf(&sb, " err=%v", a.Err)
	}
	fmt.Fprintf(&sb, " body=%s", summarizeBody(a.Body))
	return sb.String()
}

func summarizeBody(b []byte) string {
	if !isTextBody(b) {
		if len(b) == 0 {
			return ""
		}
		return fmt.Sprintf("(binary body, %d bytes)", len(b))
	}
	return clipBytes(b)
}

func isTextBody(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if c < 0x20 && c != '\n' && c != '\t' && c != '\r' {
			return false
		}
	}
	return true
}

// postGetCaptchaOctet posts the encrypted msgpack wire as
// application/octet-stream and returns the response content-type. The minter
// rejects any answer that is not octet-stream.
func postGetCaptchaOctet(ctx context.Context, sitekey string, body []byte) (status int, ctype string, respBody []byte, err error) {
	endpoint := getcaptchaURL
	if sitekey != "" {
		endpoint = strings.TrimSuffix(getcaptchaURL, "/") + "/" + url.PathEscape(sitekey)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, "", nil, fmt.Errorf("hcaptcha: getcaptcha: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json, application/octet-stream")
	req.Header.Set("User-Agent", widgetUA)
	req.Header.Set("Origin", "https://newassets.hcaptcha.com")
	req.Header.Set("Referer", "https://newassets.hcaptcha.com/")

	resp, err := gcClient.Do(req)
	if err != nil {
		return 0, "", nil, fmt.Errorf("hcaptcha: getcaptcha: %w", err)
	}
	defer hsw.CloseBody(resp.Body)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, getCaptchaBodyLimit))
	if err != nil {
		return resp.StatusCode, resp.Header.Get("Content-Type"), nil, fmt.Errorf("hcaptcha: getcaptcha: read body: %w", err)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), raw, nil
}

// fetchChecksiteLive is the live checksiteconfig probe used by diagnostics.
// The query matches the minter: no hl parameter, and a failed api.js scrape
// fails the call.
func fetchChecksiteLive(ctx context.Context, sitekey, host string) (jwt, location, key string, encGetReq bool, err error) {
	v, err := RequireAssetVersion(ctx)
	if err != nil {
		return "", "", "", false, err
	}
	u := fmt.Sprintf("%s?v=%s&host=%s&sitekey=%s&sc=1&swa=1&spst=1",
		checksiteBase, url.QueryEscape(v), url.QueryEscape(host), url.QueryEscape(sitekey))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, http.NoBody)
	if err != nil {
		return "", "", "", false, fmt.Errorf("checksiteconfig: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", "https://newassets.hcaptcha.com")
	req.Header.Set("Referer", "https://newassets.hcaptcha.com/")
	req.Header.Set("User-Agent", widgetUA)
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
		jwt, key = key, ""
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

// CaptchaAttempts solves one hCaptcha challenge the way nvidia-playground.mjs
// does and returns that single submission. A failure before checksiteconfig
// returns an error; a failure after it is recorded on the attempt.
func CaptchaAttempts(ctx context.Context, sitekey, host string) (solve SolveInfo, attempts []CaptchaAttempt, err error) {
	start := time.Now()
	ch, err := fetchMintChallenge(ctx, sitekey, host)
	if err != nil {
		return SolveInfo{}, nil, fmt.Errorf("hcaptcha: getcaptcha: fetch challenge: %w", err)
	}
	at, info := runMint(ctx, sitekey, host, ch)
	info.Elapsed = time.Since(start)
	return info, []CaptchaAttempt{at}, nil
}

// CaptchaToken solves the hCaptcha challenge for sitekey/host and returns the
// generated_pass_UUID. A missing passcode includes the attempt status and body.
func CaptchaToken(ctx context.Context, sitekey, host string) (string, error) {
	token, _, err := CaptchaTokenDetail(ctx, sitekey, host)
	return token, err
}

// CaptchaTokenDetail is CaptchaToken plus the challenge metadata.
func CaptchaTokenDetail(ctx context.Context, sitekey, host string) (string, SolveInfo, error) {
	solve, attempts, err := CaptchaAttempts(ctx, sitekey, host)
	if err != nil {
		if ctx.Err() == nil {
			resetConns()
		}
		return "", solve, err
	}
	for _, a := range attempts {
		if a.Token != "" {
			return a.Token, solve, nil
		}
	}
	if ctx.Err() == nil {
		resetConns()
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "hcaptcha: getcaptcha: no passcode (jwt_len=%d location=%q n_len=%d)",
		len(solve.JWT), solve.Location, len(solve.N))
	for _, a := range attempts {
		sb.WriteString("\n  - ")
		sb.WriteString(a.Summary())
	}
	return "", solve, fmt.Errorf("%s", sb.String())
}

func clipBytes(b []byte) string {
	const n = getCaptchaErrorClip
	if len(b) <= n {
		return string(b)
	}
	return fmt.Sprintf("%s…(+%d bytes)", string(b[:n]), len(b)-n)
}
