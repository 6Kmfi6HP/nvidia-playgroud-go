package models

// Live scraping of the build.nvidia.com playground model catalog.
//
// This ports scripts/scrape_playground_models.py into the Go binary so the
// gateway can refresh its registry at runtime instead of relying solely on
// the compiled-in snapshot:
//
//  1. GET ModelsURL — SSR-rendered list of models with interactive
//     playgrounds; every model card is an <a href="/{publisher}/{slug}">.
//  2. GET {playgroundURL} per model — the playground page inlines the NVCF
//     invocation parameters ("nvcfFunctionId", "namespace").
//
// Models whose playground page inline no function id are skipped (e.g. ids
// resolved at runtime behind an extra NVCF query). A Fetch that yields zero
// usable models is treated as failed, and Refresh keeps the old registry.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"sync"
	"time"
)

const (
	// ModelsURL is the SSR-rendered catalog of models with interactive
	// playgrounds. The legacy ?pageSize=200&filters=... URL has returned an
	// empty body since 2026-08; the unfiltered page embeds the catalog in
	// Next flight data (see resIDRe).
	ModelsURL = "https://build.nvidia.com/models"

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
// client may be nil. Errors from individual playground probes are collected
// into Skipped, not returned: only a catalog-page failure or an empty result
// produces an error.
func Fetch(ctx context.Context, client *http.Client) (*FetchResult, error) {
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPBudget}
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
// success. On failure the previous registry is kept untouched.
func Refresh(ctx context.Context, client *http.Client) (*FetchResult, error) {
	res, err := Fetch(ctx, client)
	if err != nil {
		return res, err
	}
	Replace(res.Models)
	return res, nil
}

// fetchCatalogIDs returns the {publisher}/{slug} ids rendered on the catalog
// page. Dedup keeps the first publisher seen for a slug.
func fetchCatalogIDs(ctx context.Context, client *http.Client) ([]string, error) {
	body, err := get(ctx, client, ModelsURL)
	if err != nil {
		return nil, err
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
func probePlayground(ctx context.Context, client *http.Client, id string) (ModelInfo, bool) {
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

// get fetches url with a browser-ish user agent and retries transient
// failures a few times.
func get(ctx context.Context, client *http.Client, url string) ([]byte, error) {
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
		req.Header.Set("User-Agent", fetchUserAgent)
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
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
