package hcaptcha

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

// assetAPIVersionURL serves the widget loader; its path embeds the current
// frontend build hash that the checksiteconfig and getcaptcha "v" parameter
// must carry.
var assetAPIVersionURL = "https://js.hcaptcha.com/1/api.js"

var reAssetVersion = regexp.MustCompile(`captcha/v1/([0-9a-f]{40})/`)

var (
	versionMu      sync.Mutex
	versionValue   string
	versionFetched time.Time
)

// assetVersionTTL bounds how long a discovered build id is reused. hCaptcha
// rotates the frontend every few weeks, so a stale id is worse than one extra
// fetch per hour.
const assetVersionTTL = time.Hour

// AssetVersion returns the current hCaptcha frontend build id. It scrapes the
// widget loader once per TTL and falls back to the compiled-in id when the
// loader cannot be fetched. The mint path uses RequireAssetVersion instead:
// the reference minter fails the solve when the loader cannot be read.
func AssetVersion(ctx context.Context) string {
	v, err := RequireAssetVersion(ctx)
	if err != nil {
		return getCaptchaVersion
	}
	return v
}

// RequireAssetVersion returns the frontend build id scraped from api.js.
// A fresh cache hit does not hit the network. A failed scrape is an error;
// there is no compiled-in fallback.
func RequireAssetVersion(ctx context.Context) (string, error) {
	versionMu.Lock()
	v, at := versionValue, versionFetched
	versionMu.Unlock()
	if v != "" && time.Since(at) < assetVersionTTL {
		return v, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetAPIVersionURL, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("hcaptcha: api.js: %w", err)
	}
	req.Header.Set("User-Agent", widgetUA)
	req.Header.Set("Accept", "*/*")
	resp, err := gcClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("hcaptcha: api.js: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hcaptcha: api.js: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", fmt.Errorf("hcaptcha: api.js: %w", err)
	}
	m := reAssetVersion.FindSubmatch(body)
	if len(m) != 2 {
		return "", fmt.Errorf("hcaptcha: api.js: cannot determine hcaptcha asset version")
	}
	found := string(m[1])
	versionMu.Lock()
	versionValue, versionFetched = found, time.Now()
	versionMu.Unlock()
	return found, nil
}
