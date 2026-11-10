package hcaptcha

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"nvidia-playgroud-go/internal/hsw"
)

// The mint follows nvidia-playground.mjs ll().mint:
//
//	api.js version (fail if the scrape fails)
//	POST checksiteconfig?v&host&sitekey&sc=1&swa=1&spst=1   (no hl)
//	hsw(jwt, {href, ardata:null})                           (hsw collects n)
//	wasm-encrypt msgpack{v, sitekey, host, hl, motionData, n, e:null}
//	POST msgpack([JSON.stringify(c), ext18(cipher)])
//	require octet-stream, decrypt, read generated_pass_UUID
//
// There is no prebuilt fingerprint, no plaintext variant ladder, and no
// second challenge claim.

// mintChallenge is one checksiteconfig answer. SpecJSON is the compact form
// of the raw c object, key order preserved, which is what JSON.stringify
// emits after JSON.parse.
type mintChallenge struct {
	SpecJSON string
	JWT      string
	Location string
	Name     string
	SRI      string
}

// mintPost is one getcaptcha HTTP result, including the content-type the
// minter uses to decide whether the body is an encrypted answer.
type mintPost struct {
	Status int
	CType  string
	Body   []byte
}

type mintEntry struct {
	solver *hsw.Solver
	sri    string
}

var (
	// checksiteBase is the checksiteconfig URL; tests point it at httptest.
	checksiteBase = hsw.ChecksiteBase

	fetchMintChallenge = fetchMintChallengeLive
	loadMintBundle     = loadMintBundleLive
	openSolver         = openSolverLive
	postMint           = postMintLive

	mintSolvers sync.Map // location -> *mintEntry
)

func fetchMintChallengeLive(ctx context.Context, sitekey, host string) (mintChallenge, error) {
	v, err := RequireAssetVersion(ctx)
	if err != nil {
		return mintChallenge{}, err
	}
	u := fmt.Sprintf("%s?v=%s&host=%s&sitekey=%s&sc=1&swa=1&spst=1",
		checksiteBase, url.QueryEscape(v), url.QueryEscape(host), url.QueryEscape(sitekey))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, http.NoBody)
	if err != nil {
		return mintChallenge{}, fmt.Errorf("checksiteconfig: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", "https://newassets.hcaptcha.com")
	req.Header.Set("Referer", "https://newassets.hcaptcha.com/")
	req.Header.Set("User-Agent", widgetUA)
	resp, err := gcClient.Do(req)
	if err != nil {
		return mintChallenge{}, fmt.Errorf("checksiteconfig: %w", err)
	}
	defer hsw.CloseBody(resp.Body)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, getCaptchaBodyLimit))
	if err != nil {
		return mintChallenge{}, fmt.Errorf("checksiteconfig: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return mintChallenge{}, fmt.Errorf("checksiteconfig: HTTP %d: %s", resp.StatusCode, clipBytes(raw))
	}
	return parseMintChallenge(raw)
}

func parseMintChallenge(raw []byte) (mintChallenge, error) {
	var doc struct {
		C json.RawMessage `json:"c"`
		L string          `json:"l"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return mintChallenge{}, fmt.Errorf("checksiteconfig decode: %w", err)
	}
	if len(bytes.TrimSpace(doc.C)) == 0 || string(bytes.TrimSpace(doc.C)) == "null" {
		return mintChallenge{}, fmt.Errorf("checksiteconfig: no c object")
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, doc.C); err != nil {
		return mintChallenge{}, fmt.Errorf("checksiteconfig: c: %w", err)
	}
	var c struct {
		Req string `json:"req"`
		JWT string `json:"jwt"`
		Key string `json:"key"`
	}
	if err := json.Unmarshal(doc.C, &c); err != nil {
		return mintChallenge{}, fmt.Errorf("checksiteconfig: c: %w", err)
	}
	jwt := c.Req
	if jwt == "" {
		jwt = c.JWT
	}
	if jwt == "" && strings.Contains(c.Key, ".") {
		jwt = c.Key
	}
	if jwt == "" {
		return mintChallenge{}, fmt.Errorf("checksiteconfig: no challenge jwt in response")
	}
	loc, name, sri := jwtAssetFields(jwt)
	if loc == "" {
		loc = doc.L
	}
	if loc == "" {
		var err error
		loc, err = hsw.LocationFromJWT(jwt)
		if err != nil {
			return mintChallenge{}, fmt.Errorf("checksiteconfig: %w", err)
		}
	}
	if name == "" {
		name = "hsw"
	}
	return mintChallenge{SpecJSON: buf.String(), JWT: jwt, Location: loc, Name: name, SRI: sri}, nil
}

func jwtAssetFields(jwt string) (loc, name, sri string) {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return "", "", ""
	}
	payload, err := decodeB64(parts[1])
	if err != nil {
		return "", "", ""
	}
	var m struct {
		L string `json:"l"`
		N string `json:"n"`
		I string `json:"i"`
	}
	if err := json.Unmarshal(payload, &m); err != nil {
		return "", "", ""
	}
	return m.L, m.N, m.I
}

func decodeB64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func assetURL(location, name string) string {
	loc := strings.TrimSuffix(location, "/")
	if !strings.HasPrefix(loc, "/") {
		loc = "/c/" + loc
	}
	if name == "" {
		name = "hsw"
	}
	return hsw.AssetBase + loc + "/" + name + ".js"
}

func widgetHTML(version string) string {
	return "https://newassets.hcaptcha.com/captcha/v1/" + version + "/static/hcaptcha.html"
}

func loadMintBundleLive(ctx context.Context, assetURL, referer, sri string) (*hsw.Solver, error) {
	raw, err := hsw.FetchAsset(ctx, assetURL, referer, sri, widgetUA)
	if err != nil {
		return nil, err
	}
	b, err := hsw.Prepare(raw)
	if err != nil {
		return nil, err
	}
	b.URL = assetURL
	return hsw.New(b)
}

func openSolverLive(ctx context.Context, location, assetURL, referer, sri string) (*hsw.Solver, error) {
	if bundleBroken(location) {
		return nil, fmt.Errorf("hcaptcha: hsw bundle %s marked broken (failed eval/solve within the last %s)", location, brokenBundleTTL)
	}
	if v, ok := mintSolvers.Load(location); ok {
		e := v.(*mintEntry)
		if sri == "" || e.sri == "" || e.sri == sri {
			return e.solver, nil
		}
		e.solver.Close()
		mintSolvers.Delete(location)
	}
	s, err := loadMintBundle(ctx, assetURL, referer, sri)
	if err != nil {
		markBundleBroken(location, err)
		return nil, err
	}
	actual, loaded := mintSolvers.LoadOrStore(location, &mintEntry{solver: s, sri: sri})
	if loaded {
		s.Close()
		return actual.(*mintEntry).solver, nil
	}
	return s, nil
}

func closeMintSolvers() {
	mintSolvers.Range(func(k, v any) bool {
		mintSolvers.Delete(k)
		v.(*mintEntry).solver.Close()
		return true
	})
}

func postMintLive(ctx context.Context, sitekey string, body []byte) (mintPost, error) {
	status, ctype, raw, err := postGetCaptchaOctet(ctx, sitekey, body)
	return mintPost{Status: status, CType: ctype, Body: raw}, err
}

// runMint is one reference-minter solve. A transport or protocol failure is
// recorded on the attempt; CaptchaToken turns a missing token into an error.
func runMint(ctx context.Context, sitekey, host string, ch mintChallenge) (at CaptchaAttempt, info SolveInfo) {
	at = CaptchaAttempt{Name: "widget"}
	t0 := time.Now()
	defer func() { at.Elapsed = time.Since(t0) }()
	info = SolveInfo{JWT: ch.JWT, Location: ch.Location}

	if ctx.Err() != nil {
		at.Err = fmt.Errorf("hcaptcha: widget: context done: %w", ctx.Err())
		return
	}
	v, err := RequireAssetVersion(ctx)
	if err != nil {
		at.Err = fmt.Errorf("hcaptcha: widget: %w", err)
		return
	}
	solver, err := openSolver(ctx, ch.Location, assetURL(ch.Location, ch.Name), widgetHTML(v), ch.SRI)
	if err != nil {
		at.Err = fmt.Errorf("hcaptcha: widget: load solver: %w", err)
		return
	}
	href := "https://" + host + "/"
	n, err := solver.SolveRequest(ctx, ch.JWT, href)
	if err != nil {
		markBundleBroken(ch.Location, err)
		at.Err = fmt.Errorf("hcaptcha: widget: solve: %w", err)
		return
	}
	info.N = n

	plain := msgpackEncodeOrdered(
		[]string{"v", "sitekey", "host", "hl", "motionData", "n", "e"},
		[]any{v, sitekey, host, "en", "{}", n, nil},
	)
	at.Params = map[string]string{
		"v": v, "sitekey": sitekey, "host": host, "hl": "en",
		"motionData": "{}", "n": n,
	}
	cipher, err := solver.Crypto(ctx, 1, plain)
	if err != nil {
		markBundleBroken(ch.Location, err)
		at.Err = fmt.Errorf("hcaptcha: widget: encrypt: %w", err)
		return
	}
	wire := msgpackEncodeWire(ch.SpecJSON, cipher)
	posted, err := postMint(ctx, sitekey, wire)
	at.Status, at.Body = posted.Status, posted.Body
	if err != nil {
		at.Err = fmt.Errorf("hcaptcha: widget: %w", err)
		return
	}
	if !strings.Contains(strings.ToLower(posted.CType), "octet-stream") {
		at.Err = fmt.Errorf("hcaptcha: widget: getcaptcha rejected: HTTP %d %s", posted.Status, clipBytes(posted.Body))
		return
	}
	dec, err := solver.Crypto(ctx, 0, posted.Body)
	if err != nil {
		at.Err = fmt.Errorf("hcaptcha: widget: decrypt: %w", err)
		return
	}
	token, err := passUUID(dec)
	if err != nil {
		at.Err = fmt.Errorf("hcaptcha: widget: %w", err)
		return
	}
	at.Token = token
	return
}

func passUUID(dec []byte) (string, error) {
	msg, rest, err := msgpackDecode(dec)
	if err != nil || len(rest) != 0 {
		return "", fmt.Errorf("no pass token in response")
	}
	m, ok := msg.(map[string]any)
	if !ok {
		return "", fmt.Errorf("no pass token in response")
	}
	tok, _ := m["generated_pass_UUID"].(string)
	if tok == "" {
		return "", fmt.Errorf("no pass token in response")
	}
	return tok, nil
}
