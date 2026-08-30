package hcaptchapow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// checksiteconfigURL is the hCaptcha checksiteconfig endpoint; overridable in
// tests.
var checksiteconfigURL = "https://api.hcaptcha.com/checksiteconfig"

// httpClient is the shared client for checksiteconfig calls. cmd/serve
// replaces it via SetHTTPClient to route PoW solving through the upstream
// proxy.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// SetHTTPClient replaces the client used for checksiteconfig calls. Must be
// called before solving starts.
func SetHTTPClient(c *http.Client) { httpClient = c }

// CheckSiteConfigChallenge mirrors the "c" object of a checksiteconfig
// response. Req is the PoW JWT consumed by MintStamp.
type CheckSiteConfigChallenge struct {
	Req string `json:"req"`
	Key string `json:"key"`
}

// CheckSiteConfigResponse is the JSON envelope returned by checksiteconfig.
type CheckSiteConfigResponse struct {
	C CheckSiteConfigChallenge `json:"c"`
}

// CheckSiteConfig fetches the PoW JWT (.c.req) for the given sitekey/host.
// The request mirrors the browser payload: POST with Content-Type text/plain
// and query parameters sitekey, host, v, sc=1, swa=1, spst=1.
func CheckSiteConfig(ctx context.Context, sitekey, host, v string) (string, error) {
	if sitekey == "" || host == "" || v == "" {
		return "", errors.New("hcaptchapow: checksiteconfig requires non-empty sitekey, host and v")
	}
	q := url.Values{}
	q.Set("sitekey", sitekey)
	q.Set("host", host)
	q.Set("v", v)
	q.Set("sc", "1")
	q.Set("swa", "1")
	q.Set("spst", "1")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, checksiteconfigURL+"?"+q.Encode(), http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Origin", "https://newassets.hcaptcha.com")
	req.Header.Set("Referer", "https://newassets.hcaptcha.com/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
	req.Header.Set("sec-ch-ua", `"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "same-site")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hcaptchapow: checksiteconfig status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if cerr := resp.Body.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	var out CheckSiteConfigResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("hcaptchapow: decode checksiteconfig response: %w", err)
	}
	if out.C.Req == "" {
		return "", errors.New("hcaptchapow: checksiteconfig response has no c.req")
	}
	return out.C.Req, nil
}
