package hcaptcha

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

// assetAPIVersionURL serves the widget loader; its path embeds the current
// frontend build hash that the checksiteconfig and getcaptcha "v" parameter
// must carry.
const assetAPIVersionURL = "https://js.hcaptcha.com/1/api.js"

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
// loader cannot be fetched, so a solve never fails just because the version
// probe did.
func AssetVersion(ctx context.Context) string {
	versionMu.Lock()
	v, at := versionValue, versionFetched
	versionMu.Unlock()
	if v != "" && time.Since(at) < assetVersionTTL {
		return v
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetAPIVersionURL, http.NoBody)
	if err != nil {
		return getCaptchaVersion
	}
	req.Header.Set("User-Agent", widgetUA)
	req.Header.Set("Accept", "*/*")
	resp, err := gcClient.Do(req)
	if err != nil {
		return getCaptchaVersion
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return getCaptchaVersion
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return getCaptchaVersion
	}
	m := reAssetVersion.FindSubmatch(body)
	if len(m) != 2 {
		return getCaptchaVersion
	}
	found := string(m[1])
	versionMu.Lock()
	versionValue, versionFetched = found, time.Now()
	versionMu.Unlock()
	return found
}
