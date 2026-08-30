package models

// Live scraping of the build.nvidia.com playground model catalog.
//
// This ports scripts/scrape_playground_models.py into the Go binary so the
// gateway can refresh its registry at runtime instead of relying solely on
// the compiled-in snapshot:
//
//  1. GET ModelsURL — SSR-rendered list of models with interactive
//     playgrounds, filtered to NIM previews. The page is served behind
//     Akamai + AWS WAF: pass a browser-minted aws-waf-token via
//     SetCatalogCookie to see the full filtered catalog. When the token is
//     absent or rejected (HTTP 202 challenge page), fetching falls back to
//     FallbackModelsURL (unfiltered, no WAF) with fewer model cards.
//  2. GET {playgroundURL} per model — the playground page inlines the NVCF
//     invocation parameters ("nvcfFunctionId", "namespace").
//
// All HTTP traffic uses the package httpClient, which cmd/serve replaces
// via SetHTTPClient with a Transport configured for the upstream proxy
// (-proxy / CHROME_PROXY), same as the captcha solver packages.
//
// Models whose playground page inline no function id are skipped (e.g. ids
// resolved at runtime behind an extra NVCF query). A Fetch that yields zero
// usable models is treated as failed, and Refresh keeps the old registry.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	neturl "net/url"
	"regexp"
	"sort"
	"sync"
	"time"
)

var (
	// ModelsHost is the host of the catalog pages (used to scope
	// the WAF cookie to catalog fetches only).
	ModelsHost = "build.nvidia.com"

	// ModelsURL is the SSR-rendered catalog of models with interactive
	// playgrounds, filtered to NIM previews. The filtered catalog surfaces
	// more playground models than the unfiltered page, but is served behind
	// an AWS WAF JS challenge: without a valid aws-waf-token cookie it
	// answers HTTP 202 with a challenge page instead of the catalog (see
	// SetCatalogCookie). Fetch falls back to the unfiltered page (no WAF)
	// whenever the filtered one yields no catalog.
	ModelsURL = "https://build.nvidia.com/models?filters=nimType%3Anim_type_preview&pageSize=100"

	// FallbackModelsURL is the unfiltered catalog page. It embeds the
	// catalog in Next flight data (see resIDRe) and is served without a
	// WAF challenge, at the cost of fewer model cards.
	FallbackModelsURL = "https://build.nvidia.com/models"

	// fetchUserAgent mirrors the scraper: the catalog page returns an empty
	// body for non-browser user agents.
	fetchUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

	// PlaygroundURLTemplate renders the playground page for a model; the
	// nvcfFunctionId/namespace are inlined into its SSR HTML.
	PlaygroundURLTemplate = "https://build.nvidia.com/%s/%s/playground"

	fetchRetries      = 3
	fetchConcurrency  = 12
	defaultHTTPBudget = 25 * time.Second
)

// catalogCookie is an optional Cookie header value (e.g.
// "aws-waf-token=...") sent with catalog-page fetches to pass the AWS WAF
// JS challenge on the filtered catalog URL. Empty disables it. The token
// must be minted by the WAF challenge itself (e.g. exported from a browser
// session); arbitrary values are rejected with HTTP 202.
var catalogCookie string

// cookieJar keeps cookies learned from catalog responses (Akamai ak_bmsc /
// bm_mi, refreshed aws-waf-token) and replays them on later fetches, so a
// multi-request scrape behaves like one browser session.
var cookieJar, _ = cookiejar.New(nil)

// SetCatalogCookie sets the Cookie header sent with catalog-page fetches.
// Call before Fetch/Refresh. Passing "" restores cookie-less fetching.
// The value is also seeded into the package cookie jar (domain
// build.nvidia.com) so it is replayed on every fetch, including playground
// probes.
func SetCatalogCookie(c string) {
	catalogCookie = c
	cookieJar, _ = cookiejar.New(nil)
	if c == "" {
		return
	}
	// c is a raw Cookie header ("k=v; k2=v2"); parse it into cookies on the
	// catalog host only.
	u := &neturl.URL{Scheme: "https", Host: ModelsHost}
	if req, err := http.NewRequest(http.MethodGet, "https://"+ModelsHost+"/", nil); err == nil {
		req.Header.Set("Cookie", c)
		for _, ck := range req.Cookies() {
			cookieJar.SetCookies(u, []*http.Cookie{ck})
		}
	}
}

// Doer is the minimal HTTP interface used by the scraper. Both
// *http.Client (standard net/http transport) and
// tls_client.HttpClient (browser TLS/HTTP2 fingerprint impersonation,
// see SetTLSClient) satisfy it.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

var (
	// httpClient is the shared standard client for catalog and playground
	// fetches. cmd/serve replaces it via SetHTTPClient to route scraping
	// through the upstream proxy, like the captcha solver packages do.
	httpClient Doer = &http.Client{Timeout: defaultHTTPBudget}

	// tlsClient, when set, takes precedence over httpClient in Fetch:
	// requests are sent with an impersonated Chrome TLS/HTTP2 fingerprint
	// (tls-client + utls) instead of Go's own fingerprint, which Akamai
	// and the AWS WAF treat as non-browser.
	tlsClient Doer
)

// SetHTTPClient replaces the client used for catalog/playground fetches.
// Pass a client whose Transport carries the proxy configuration. Must be
// called before Fetch/Refresh starts; safe to call once at startup.
func SetHTTPClient(c *http.Client) { httpClient = c }

// SetTLSClient installs a browser-fingerprint client (e.g.
// github.com/bogdanfinn/tls-client with a Chrome profile) used for all
// catalog/playground fetches. It takes precedence over the client set by
// SetHTTPClient. Pass nil to disable and use only the standard client.
func SetTLSClient(c Doer) { tlsClient = c }

// autoWAF is enabled by default: when the filtered catalog responds with
// the AWS WAF challenge page, Fetch solves the challenge automatically with
// internal/waftoken and retries with the minted aws-waf-token. Disable with
// SetAutoWAF(false) to always fall back to the unfiltered page.
var autoWAF = true

// mintWAFToken is internal/waftoken.Mint; set in init to avoid an import
// cycle concerns and to keep the models package free of the solver when
// unused. It is swapped in by waftoken via RegisterMinter.
var mintWAFToken = func(ctx context.Context, targetURL string) (string, error) {
	return "", fmt.Errorf("models: waftoken solver not registered")
}

// RegisterMinter installs the automatic AWS WAF token solver (see
// internal/waftoken). cmd/serve wires it at startup.
func RegisterMinter(fn func(ctx context.Context, targetURL string) (string, error)) {
	if fn == nil {
		mintWAFToken = func(ctx context.Context, targetURL string) (string, error) {
			return "", fmt.Errorf("models: waftoken solver not registered")
		}
		return
	}
	mintWAFToken = fn
}

// SetAutoWAF toggles automatic AWS WAF challenge solving.
func SetAutoWAF(on bool) { autoWAF = on }

func autoWAFEnabled() bool { return autoWAF }

func mintToken(ctx context.Context, _ string) (string, error) {
	tok, err := mintWAFToken(ctx, ModelsURL)
	if err != nil {
		return "", err
	}
	if tok == "" {
		return "", fmt.Errorf("models: empty minted token")
	}
	// Seed the jar so the retry (and playground probes) send it.
	SetCatalogCookie("aws-waf-token=" + tok)
	return tok, nil
}

var (
	// resIDRe matches endpoint resource ids in the flight data, e.g.
	// "resourceId":"qc69jvmznzxy/kimi-k3" (quotes may be \-escaped).
	resIDRe = regexp.MustCompile(`qc69jvmznzxy/([A-Za-z0-9_.+~\-]+)`)
	hrefRe  = regexp.MustCompile(`href="/([a-zA-Z0-9_.-]+)/([A-Za-z0-9_.+~\-]+)"`)
	fnIDRe  = regexp.MustCompile(`"nvcfFunctionId\\?":\\?"([a-f0-9-]{36})\\"?`)
	nsRe    = regexp.MustCompile(`"namespace\\?":\\?"([0-9a-z]+)\\"?"`)
	uuidRe  = regexp.MustCompile(`^[a-f0-9-]{36}$`)
)

// FetchResult describes one scrape of the live playground catalog.
type FetchResult struct {
	// Models is the fresh registry (may be empty when Ok is false).
	Models map[string]ModelInfo
	// Total is how many model links the catalog page rendered.
	Total int
	// Skipped lists models whose playground page inlined no function id.
	Skipped []string
}

// Ok reports whether the fetch produced a usable registry.
func (r *FetchResult) Ok() bool { return len(r.Models) > 0 }

// Fetch fetches the live playground catalog. On success the returned
// FetchResult.Models contains every playground-callable model with its NVCF
// slug/namespace/function id. Capability hints are carried over from the
// current registry for ids that already exist there (the scrape cannot infer
// capabilities). The current registry is NOT modified — use Refresh for that.
//
// client may be nil, in which case the package client is used: the
// browser-fingerprint client (SetTLSClient) when installed, else the
// standard client (SetHTTPClient). Errors from individual playground probes
// are collected into Skipped, not returned: only a catalog-page failure or
// an empty result produces an error.
func Fetch(ctx context.Context, client Doer) (*FetchResult, error) {
	if client == nil {
		if tlsClient != nil {
			client = tlsClient
		} else {
			client = httpClient
		}
	}
	ids, err := fetchCatalogIDs(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("models: fetch catalog page: %w", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("models: catalog page rendered no model links (%s)", ModelsURL)
	}

	prev := All()
	res := &FetchResult{Models: make(map[string]ModelInfo, len(ids)), Total: len(ids)}

	sem := make(chan struct{}, fetchConcurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			info, ok := probePlayground(ctx, client, id)
			mu.Lock()
			defer mu.Unlock()
			if !ok {
				res.Skipped = append(res.Skipped, id)
				return
			}
			// Preserve hand-tuned capability hints from the current registry.
			if old, exists := prev[id]; exists && old.Capability != nil {
				info.Capability = old.Capability
			}
			res.Models[id] = info
		}(id)
	}
	wg.Wait()
	sort.Strings(res.Skipped)

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !res.Ok() {
		return res, fmt.Errorf("models: 0/%d playground pages inlined an nvcfFunctionId", res.Total)
	}
	return res, nil
}

// Refresh fetches the live catalog and atomically swaps the registry on
// success. On failure the previous registry is kept untouched. On success
// the fresh registry is also persisted to the JSON cache configured via
// SetCacheFile (automatic, atomic; a write failure only logs — the refresh
// itself succeeds).
func Refresh(ctx context.Context, client Doer) (*FetchResult, error) {
	res, err := Fetch(ctx, client)
	if err != nil {
		return res, err
	}
	Replace(res.Models)
	if err := saveCache(res.Models); err != nil {
		log.Printf("models: cache write failed (%v)", err)
	}
	return res, nil
}

// fetchCatalogIDs returns the {publisher}/{slug} ids rendered on the catalog
// page. It first tries ModelsURL (filtered; requires an aws-waf-token cookie
// when the WAF challenge is up — see SetCatalogCookie); when that yields no
// catalog it falls back to FallbackModelsURL, which is served without the
// challenge. Dedup keeps the first publisher seen for a slug.
func fetchCatalogIDs(ctx context.Context, client Doer) ([]string, error) {
	body, err := get(ctx, client, ModelsURL)
	if err != nil || len(body) == 0 || httpStatusChallenge(body) {
		// Filtered page is behind the AWS WAF challenge. Before falling
		// back to the smaller unfiltered page, try to mint an aws-waf-token
		// automatically (pure-Go challenge solver; no browser, no manual
		// cookie) and retry the filtered URL with it.
		if autoWAFEnabled() {
			if _, terr := mintToken(ctx, ModelsHost); terr == nil {
				log.Printf("models: auto-solved AWS WAF challenge, retrying filtered catalog")
				if body2, err2 := get(ctx, client, ModelsURL); err2 == nil && len(body2) > 0 && !httpStatusChallenge(body2) {
					body = body2
				} else {
					log.Printf("models: filtered catalog still challenged after token (err=%v), falling back", err2)
					body, err = get(ctx, client, FallbackModelsURL)
					if err != nil {
						return nil, err
					}
				}
			} else {
				log.Printf("models: auto WAF token failed (%v), falling back to %s", terr, FallbackModelsURL)
				total := len(body)
				if err != nil {
					total = -1
				}
				log.Printf("models: filtered catalog unavailable (err=%v bytes=%d), falling back to %s", err, total, FallbackModelsURL)
				body, err = get(ctx, client, FallbackModelsURL)
				if err != nil {
					return nil, err
				}
			}
		} else {
			total := len(body)
			if err != nil {
				total = -1
			}
			log.Printf("models: filtered catalog unavailable (err=%v bytes=%d), falling back to %s", err, total, FallbackModelsURL)
			body, err = get(ctx, client, FallbackModelsURL)
			if err != nil {
				return nil, err
			}
		}
	}
	slugs := map[string]bool{}
	for _, m := range resIDRe.FindAllStringSubmatch(string(body), -1) {
		slugs[m[1]] = true
	}
	slugToPub := map[string]string{}
	for _, m := range hrefRe.FindAllStringSubmatch(string(body), -1) {
		pub, slug := m[1], m[2]
		switch pub {
		case "models", "explore", "blueprints", "skills", "_next", "":
			continue
		}
		switch slug {
		case "playground", "community", "":
			continue
		}
		if len(slugs) > 0 && !slugs[slug] {
			continue // only catalog endpoints, not nav links
		}
		if _, dup := slugToPub[slug]; !dup {
			slugToPub[slug] = pub
		}
	}
	ids := make([]string, 0, len(slugToPub))
	for slug, pub := range slugToPub {
		ids = append(ids, pub+"/"+slug)
	}
	sort.Strings(ids)
	return ids, nil
}

// probePlayground fetches one playground page and extracts the NVCF function
// id and namespace.
func probePlayground(ctx context.Context, client Doer, id string) (ModelInfo, bool) {
	pub, slug := splitID(id)
	body, err := get(ctx, client, fmt.Sprintf(PlaygroundURLTemplate, pub, slug))
	if err != nil {
		return ModelInfo{}, false
	}
	m := fnIDRe.FindSubmatch(body)
	if m == nil || !uuidRe.Match(m[1]) {
		return ModelInfo{}, false
	}
	ns := Namespace
	if n := nsRe.FindSubmatch(body); n != nil {
		ns = string(n[1])
	}
	return ModelInfo{Slug: slug, Namespace: ns, FunctionID: string(m[1])}, true
}

func splitID(id string) (pub, slug string) {
	for i := 0; i < len(id); i++ {
		if id[i] == '/' {
			return id[:i], id[i+1:]
		}
	}
	return "", id
}

// httpStatusChallenge reports whether body looks like the AWS WAF JS
// challenge page (HTTP 202 with a small page carrying gokuProps), which the
// catalog endpoint serves instead of content when the token is missing or
// invalid.
func httpStatusChallenge(body []byte) bool {
	return len(body) > 0 && len(body) < 64<<10 && bytes.Contains(body, []byte("gokuProps"))
}

// get fetches url with a browser-ish user agent and retries transient
// failures a few times. Catalog-page fetches also send the configured WAF
// cookie (see SetCatalogCookie).
func get(ctx context.Context, client Doer, url string) ([]byte, error) {
	var last error
	for attempt := 0; attempt < fetchRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		// Chrome-ish fingerprint: the catalog is behind Akamai + AWS WAF and
		// answers 202 to requests that do not look like a browser.
		req.Header.Set("User-Agent", fetchUserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Referer", "https://build.nvidia.com/")
		req.Header.Set("Sec-CH-UA", `"Not A(Brand";v="99", "Google Chrome";v="131", "Chromium";v="131"`)
		req.Header.Set("Sec-CH-UA-Mobile", "?0")
		req.Header.Set("Sec-CH-UA-Platform", `"macOS"`)
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		// Replay cookies from the session jar (SeededCatalog cookie plus any
		// Set-Cookie learned from earlier catalog responses).
		if u, perr := neturl.Parse(url); perr == nil {
			for _, ck := range cookieJar.Cookies(u) {
				req.AddCookie(ck)
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		// Absorb Akamai/WAF cookies so subsequent fetches continue the same
		// session (Akamai tracks ak_bmsc/bm_mi across requests).
		if u, perr := neturl.Parse(url); perr == nil {
			cookieJar.SetCookies(u, resp.Cookies())
		}
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			last = fmt.Errorf("GET %s: %s", url, resp.Status)
			continue
		}
		return body, nil
	}
	return nil, last
}
